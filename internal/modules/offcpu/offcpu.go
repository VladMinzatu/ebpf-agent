package offcpu

import (
	"context"
	"flag"
	"fmt"
	"log"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf/link"

	"github.com/VladMinzatu/ebpf-agent/internal/agent"
	"github.com/VladMinzatu/ebpf-agent/internal/stacks"
)

const (
	Name = "offcpu"

	commLen = 16 // COMM_LEN in offcpu.c

	taskUninterruptible = 0x2 // TASK_UNINTERRUPTIBLE in offcpu.c
)

func init() {
	agent.Register(Name, func(args []string) (agent.Module, error) {
		fs := flag.NewFlagSet(Name, flag.ContinueOnError)
		containerID := fs.String("container", "", "container id (full, or a unique prefix) to measure off-CPU time for")
		interval := fs.Duration("interval", 5*time.Second, "how often to emit the top off-CPU stacks")
		cumulative := fs.Bool("cumulative", false, "report totals since the module started instead of per interval")
		top := fs.Int("top", 20, "number of stacks to report per interval, by total off-CPU time (0 for all)")
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if *containerID == "" {
			return nil, fmt.Errorf("-container is required")
		}
		if *interval <= 0 {
			return nil, fmt.Errorf("-interval must be positive")
		}
		if *top < 0 {
			return nil, fmt.Errorf("-top must not be negative")
		}
		return NewOffcpuModule(*containerID, *interval, *cumulative, *top), nil
	})
}

// countKey must match struct count_key in offcpu.c.
type countKey struct {
	Tgid        uint32
	State       uint32
	KernStackID int32
	UserStackID int32
	Comm        [commLen]byte
}

// startInfo must match struct start_info in offcpu.c.
type startInfo struct {
	Ts          uint64
	Tgid        uint32
	State       uint32
	KernStackID int32
	UserStackID int32
	Comm        [commLen]byte
}

// countValue must match struct count_value in offcpu.c.
type countValue struct {
	TotalNs uint64
	Count   uint64
}

type OffcpuModule struct {
	containerID string
	interval    time.Duration
	cumulative  bool
	top         int

	objs  offcpuObjects
	links []link.Link

	resolver *stacks.Resolver

	events chan agent.Event
	done   chan struct{}
	wg     sync.WaitGroup
}

func NewOffcpuModule(containerID string, interval time.Duration, cumulative bool, top int) *OffcpuModule {
	return &OffcpuModule{containerID: containerID, interval: interval, cumulative: cumulative, top: top}
}

func (o *OffcpuModule) Name() string {
	return Name
}

func (o *OffcpuModule) Load(ctx context.Context) error {
	cgroupID, err := agent.CgroupID(o.containerID)
	if err != nil {
		return fmt.Errorf("resolving container: %w", err)
	}

	pidnsIno, err := agent.PidNamespaceInode()
	if err != nil {
		return err
	}
	// Kernel frames are still reported (as raw addresses) without this.
	ksyms, err := stacks.LoadKernelSymbols()
	if err != nil {
		log.Printf("%s: kernel stacks won't be symbolized: %v", Name, err)
	}

	if err := loadOffcpuObjects(&o.objs, nil); err != nil {
		return err
	}
	if err := o.objs.TargetCgroup.Put(uint32(0), cgroupID); err != nil {
		o.objs.Close()
		return err
	}
	if err := o.objs.AgentPidns.Put(uint32(0), pidnsIno); err != nil {
		o.objs.Close()
		return err
	}
	o.resolver = stacks.NewResolver(o.objs.Stacks, ksyms)

	// The attach point comes from the program's SEC() name in offcpu.c.
	l, err := link.AttachTracing(link.TracingOptions{Program: o.objs.HandleSchedSwitch})
	if err != nil {
		o.objs.Close()
		return fmt.Errorf("attaching %s: %w", o.objs.HandleSchedSwitch, err)
	}
	o.links = append(o.links, l)

	o.events = make(chan agent.Event)
	o.done = make(chan struct{})
	o.wg.Add(1)
	go o.pollLoop()
	return nil
}

// pollLoop drains the counts map every interval and emits the top stacks
// as one agent.Event, until Close signals done, at which point it closes
// the events channel.
func (o *OffcpuModule) pollLoop() {
	defer o.wg.Done()
	defer close(o.events)

	ticker := time.NewTicker(o.interval)
	defer ticker.Stop()

	totals := map[stackKey]*stackEntry{} // only used with -cumulative
	for {
		select {
		case <-ticker.C:
		case <-o.done:
			return
		}

		counts, err := stacks.Drain[countKey, countValue](o.objs.Counts)
		if err != nil {
			log.Printf("%s: reading counts: %v", Name, err)
			continue
		}
		entries := o.symbolize(counts)
		o.pruneStacks(counts)

		if o.cumulative {
			for k, e := range entries {
				if t, ok := totals[k]; ok {
					t.totalNs += e.totalNs
					t.count += e.count
				} else {
					totals[k] = e
				}
			}
			entries = totals
		}

		select {
		case o.events <- agent.Event{Module: Name, Timestamp: time.Now(), Data: o.toData(entries)}:
		case <-o.done:
			return
		}
	}
}

// pruneStacks deletes the stack ids used by drained counts from the stacks
// map, so it doesn't fill up over time - except for ids still referenced by
// threads that are blocked right now, whose counts are yet to come. If a
// thread blocks with one of the deleted stacks between the two reads, that
// sample's stack shows up as [missing]; any later capture of the same stack
// puts it back.
func (o *OffcpuModule) pruneStacks(counts map[countKey]countValue) {
	inFlight := map[int32]bool{}
	var tid uint32
	var info startInfo
	it := o.objs.Start.Iterate()
	for it.Next(&tid, &info) {
		inFlight[info.KernStackID] = true
		inFlight[info.UserStackID] = true
	}
	if it.Err() != nil {
		return // better to keep stacks around than to delete in-flight ones
	}

	deleted := map[int32]bool{}
	for k := range counts {
		for _, id := range []int32{k.KernStackID, k.UserStackID} {
			if !inFlight[id] && !deleted[id] {
				o.resolver.Delete(id)
				deleted[id] = true
			}
		}
	}
}

// stackKey identifies a symbolized stack. Different stack ids can
// symbolize to the same stack (see stacks.Resolver.UserFrames), so this,
// not countKey, is what entries are merged and reported by.
type stackKey struct {
	pid    uint32
	comm   string
	state  uint32
	folded string
}

type stackEntry struct {
	kernel, user   []string
	totalNs, count uint64
}

func (o *OffcpuModule) symbolize(counts map[countKey]countValue) map[stackKey]*stackEntry {
	// Memory maps are re-read every interval: processes come and go.
	o.resolver.Refresh()
	entries := map[stackKey]*stackEntry{}
	for k, v := range counts {
		comm := strings.TrimRight(string(k.Comm[:]), "\x00")
		kernel := o.resolver.KernelFrames(k.KernStackID)
		user := o.resolver.UserFrames(k.Tgid, k.UserStackID)
		key := stackKey{pid: k.Tgid, comm: comm, state: k.State, folded: stacks.Folded(comm, user, kernel)}
		if e, ok := entries[key]; ok {
			e.totalNs += v.TotalNs
			e.count += v.Count
		} else {
			entries[key] = &stackEntry{kernel: kernel, user: user, totalNs: v.TotalNs, count: v.Count}
		}
	}
	return entries
}

func (o *OffcpuModule) toData(entries map[stackKey]*stackEntry) map[string]any {
	keys := make([]stackKey, 0, len(entries))
	var totalNs uint64
	for k, e := range entries {
		keys = append(keys, k)
		totalNs += e.totalNs
	}
	slices.SortFunc(keys, func(a, b stackKey) int {
		switch ta, tb := entries[a].totalNs, entries[b].totalNs; {
		case ta > tb:
			return -1
		case ta < tb:
			return 1
		}
		return strings.Compare(a.folded, b.folded)
	})
	if o.top > 0 && len(keys) > o.top {
		keys = keys[:o.top]
	}

	reported := []map[string]any{}
	for _, k := range keys {
		e := entries[k]
		reported = append(reported, map[string]any{
			"pid":          k.pid,
			"comm":         k.comm,
			"state":        stateName(k.state),
			"total_us":     e.totalNs / 1000,
			"count":        e.count,
			"kernel_stack": e.kernel,
			"user_stack":   e.user,
			"folded":       k.folded,
		})
	}

	return map[string]any{
		"interval_ms": o.interval.Milliseconds(),
		"cumulative":  o.cumulative,
		"total_us":    totalNs / 1000,
		"num_stacks":  len(entries),
		"stacks":      reported,
	}
}

// stateName uses ps's letters: S for interruptible sleep (waiting on an
// event - a timer, a socket, a futex), D for uninterruptible (typically
// disk I/O or a kernel lock).
func stateName(s uint32) string {
	if s == taskUninterruptible {
		return "D"
	}
	return "S"
}

func (o *OffcpuModule) Close() error {
	if o.done != nil {
		close(o.done)
		o.wg.Wait()
	}
	for _, l := range o.links {
		l.Close()
	}
	return o.objs.Close()
}

func (o *OffcpuModule) Events() <-chan agent.Event {
	return o.events
}
