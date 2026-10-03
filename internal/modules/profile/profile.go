package profile

import (
	"context"
	"flag"
	"fmt"
	"log"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/VladMinzatu/ebpf-agent/internal/agent"
	"github.com/VladMinzatu/ebpf-agent/internal/stacks"
)

const (
	Name = "profile"

	commLen = 16 // COMM_LEN in profile.c
)

func init() {
	agent.Register(Name, func(args []string) (agent.Module, error) {
		fs := flag.NewFlagSet(Name, flag.ContinueOnError)
		containerID := fs.String("container", "", "container id (full, or a unique prefix) to profile")
		freq := fs.Uint64("freq", 99, "samples per second of CPU time")
		interval := fs.Duration("interval", 5*time.Second, "how often to emit the top on-CPU stacks")
		cumulative := fs.Bool("cumulative", false, "report totals since the module started instead of per interval")
		top := fs.Int("top", 20, "number of stacks to report per interval, by number of samples (0 for all)")
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if *containerID == "" {
			return nil, fmt.Errorf("-container is required")
		}
		if *freq == 0 {
			return nil, fmt.Errorf("-freq must be positive")
		}
		if *interval <= 0 {
			return nil, fmt.Errorf("-interval must be positive")
		}
		if *top < 0 {
			return nil, fmt.Errorf("-top must not be negative")
		}
		return NewProfileModule(*containerID, *freq, *interval, *cumulative, *top), nil
	})
}

// countKey must match struct count_key in profile.c.
type countKey struct {
	Tgid        uint32
	KernStackID int32
	UserStackID int32
	Comm        [commLen]byte
}

type ProfileModule struct {
	containerID string
	freq        uint64
	interval    time.Duration
	cumulative  bool
	top         int

	objs     profileObjects
	perfFDs  []int
	links    []link.Link
	resolver *stacks.Resolver

	events chan agent.Event
	done   chan struct{}
	wg     sync.WaitGroup
}

func NewProfileModule(containerID string, freq uint64, interval time.Duration, cumulative bool, top int) *ProfileModule {
	return &ProfileModule{containerID: containerID, freq: freq, interval: interval, cumulative: cumulative, top: top}
}

func (p *ProfileModule) Name() string {
	return Name
}

func (p *ProfileModule) Load(ctx context.Context) error {
	cgroupPath, err := agent.CgroupPath(p.containerID)
	if err != nil {
		return fmt.Errorf("resolving container: %w", err)
	}
	cgroupID, err := agent.CgroupID(p.containerID)
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

	if err := loadProfileObjects(&p.objs, nil); err != nil {
		return err
	}
	if err := p.objs.TargetCgroup.Put(uint32(0), cgroupID); err != nil {
		p.Close()
		return err
	}
	if err := p.objs.AgentPidns.Put(uint32(0), pidnsIno); err != nil {
		p.Close()
		return err
	}
	p.resolver = stacks.NewResolver(p.objs.Stacks, ksyms)

	p.perfFDs, err = openPerfEvents(cgroupPath, p.freq)
	if err != nil {
		p.Close()
		return err
	}
	for _, fd := range p.perfFDs {
		// A BPF link for a perf event (kernel 5.15+): closing the link
		// detaches the program, like with the other attach types.
		l, err := link.AttachRawLink(link.RawLinkOptions{
			Target:  fd,
			Program: p.objs.HandleSample,
			Attach:  ebpf.AttachPerfEvent,
		})
		if err != nil {
			p.Close()
			return fmt.Errorf("attaching %s: %w", p.objs.HandleSample, err)
		}
		p.links = append(p.links, l)
	}

	p.events = make(chan agent.Event)
	p.done = make(chan struct{})
	p.wg.Add(1)
	go p.pollLoop()
	return nil
}

// pollLoop drains the counts map every interval and emits the top stacks
// as one agent.Event, until Close signals done, at which point it closes
// the events channel.
func (p *ProfileModule) pollLoop() {
	defer p.wg.Done()
	defer close(p.events)

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	totals := map[stackKey]*stackEntry{} // only used with -cumulative
	for {
		select {
		case <-ticker.C:
		case <-p.done:
			return
		}

		counts, err := stacks.Drain[countKey, uint64](p.objs.Counts)
		if err != nil {
			log.Printf("%s: reading counts: %v", Name, err)
			continue
		}
		entries := p.symbolize(counts)
		p.pruneStacks(counts)

		if p.cumulative {
			for k, e := range entries {
				if t, ok := totals[k]; ok {
					t.samples += e.samples
				} else {
					totals[k] = e
				}
			}
			entries = totals
		}

		select {
		case p.events <- agent.Event{Module: Name, Timestamp: time.Now(), Data: p.toData(entries)}:
		case <-p.done:
			return
		}
	}
}

// pruneStacks deletes the stack ids used by drained counts from the stacks
// map, so it doesn't fill up over time. Unlike offcpu, no stack ids are held
// across intervals - each sample is counted the moment it's taken - but a
// sample landing between the drain and this can still find its stack
// deleted and show up as [missing]; any later sample of the same stack puts
// it back.
func (p *ProfileModule) pruneStacks(counts map[countKey]uint64) {
	deleted := map[int32]bool{}
	for k := range counts {
		for _, id := range []int32{k.KernStackID, k.UserStackID} {
			if !deleted[id] {
				p.resolver.Delete(id)
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
	folded string
}

type stackEntry struct {
	kernel, user []string
	samples      uint64
}

func (p *ProfileModule) symbolize(counts map[countKey]uint64) map[stackKey]*stackEntry {
	// Memory maps are re-read every interval: processes come and go.
	p.resolver.Refresh()
	entries := map[stackKey]*stackEntry{}
	for k, n := range counts {
		comm := strings.TrimRight(string(k.Comm[:]), "\x00")
		kernel := p.resolver.KernelFrames(k.KernStackID)
		user := p.resolver.UserFrames(k.Tgid, k.UserStackID)
		key := stackKey{pid: k.Tgid, comm: comm, folded: stacks.Folded(comm, user, kernel)}
		if e, ok := entries[key]; ok {
			e.samples += n
		} else {
			entries[key] = &stackEntry{kernel: kernel, user: user, samples: n}
		}
	}
	return entries
}

func (p *ProfileModule) toData(entries map[stackKey]*stackEntry) map[string]any {
	keys := make([]stackKey, 0, len(entries))
	var total uint64
	for k, e := range entries {
		keys = append(keys, k)
		total += e.samples
	}
	slices.SortFunc(keys, func(a, b stackKey) int {
		switch sa, sb := entries[a].samples, entries[b].samples; {
		case sa > sb:
			return -1
		case sa < sb:
			return 1
		}
		return strings.Compare(a.folded, b.folded)
	})
	if p.top > 0 && len(keys) > p.top {
		keys = keys[:p.top]
	}

	reported := []map[string]any{}
	for _, k := range keys {
		e := entries[k]
		reported = append(reported, map[string]any{
			"pid":          k.pid,
			"comm":         k.comm,
			"samples":      e.samples,
			"cpu_ms":       p.cpuMs(e.samples),
			"kernel_stack": e.kernel,
			"user_stack":   e.user,
			"folded":       k.folded,
		})
	}

	return map[string]any{
		"interval_ms":   p.interval.Milliseconds(),
		"cumulative":    p.cumulative,
		"freq_hz":       p.freq,
		"total_samples": total,
		"cpu_ms":        p.cpuMs(total),
		"num_stacks":    len(entries),
		"stacks":        reported,
	}
}

// cpuMs estimates the CPU time behind a number of samples: the events'
// clocks only run while the container's tasks do, at freq samples per
// second of that time.
func (p *ProfileModule) cpuMs(samples uint64) uint64 {
	return samples * 1000 / p.freq
}

func (p *ProfileModule) Close() error {
	if p.done != nil {
		close(p.done)
		p.wg.Wait()
	}
	for _, l := range p.links {
		l.Close()
	}
	closePerfEvents(p.perfFDs)
	return p.objs.Close()
}

func (p *ProfileModule) Events() <-chan agent.Event {
	return p.events
}
