package runqlat

import (
	"context"
	"flag"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/VladMinzatu/ebpf-agent/internal/agent"
)

const (
	Name = "runqlat"

	maxSlots = 27 // MAX_SLOTS in runqlat.c
)

func init() {
	agent.Register(Name, func(args []string) (agent.Module, error) {
		fs := flag.NewFlagSet(Name, flag.ContinueOnError)
		containerID := fs.String("container", "", "container id (full, or a unique prefix) to measure run queue latency for")
		interval := fs.Duration("interval", time.Second, "how often to emit a histogram")
		cumulative := fs.Bool("cumulative", false, "emit totals since the module started instead of per-interval histograms")
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if *containerID == "" {
			return nil, fmt.Errorf("-container is required")
		}
		if *interval <= 0 {
			return nil, fmt.Errorf("-interval must be positive")
		}
		return NewRunqlatModule(*containerID, *interval, *cumulative), nil
	})
}

// histValue must match struct hist in runqlat.c.
type histValue struct {
	Slots   [maxSlots]uint64
	TotalNs uint64
}

type RunqlatModule struct {
	containerID string
	interval    time.Duration
	cumulative  bool

	objs  runqlatObjects
	links []link.Link

	events chan agent.Event
	done   chan struct{}
	wg     sync.WaitGroup
}

func NewRunqlatModule(containerID string, interval time.Duration, cumulative bool) *RunqlatModule {
	return &RunqlatModule{containerID: containerID, interval: interval, cumulative: cumulative}
}

func (r *RunqlatModule) Name() string {
	return Name
}

func (r *RunqlatModule) Load(ctx context.Context) error {
	cgroupID, err := agent.CgroupID(r.containerID)
	if err != nil {
		return fmt.Errorf("resolving container: %w", err)
	}

	if err := loadRunqlatObjects(&r.objs, nil); err != nil {
		return err
	}
	if err := r.objs.TargetCgroup.Put(uint32(0), cgroupID); err != nil {
		r.objs.Close()
		return err
	}

	for _, prog := range []*ebpf.Program{
		r.objs.HandleSchedWakeup,
		r.objs.HandleSchedWakeupNew,
		r.objs.HandleSchedSwitch,
	} {
		// The attach point (tp_btf + tracepoint name) comes from each
		// program's SEC() name in runqlat.c.
		l, err := link.AttachTracing(link.TracingOptions{Program: prog})
		if err != nil {
			r.Close()
			return fmt.Errorf("attaching %s: %w", prog, err)
		}
		r.links = append(r.links, l)
	}

	r.events = make(chan agent.Event)
	r.done = make(chan struct{})
	r.wg.Add(1)
	go r.pollLoop()
	return nil
}

// pollLoop reads the histogram map every interval and emits it as an
// agent.Event until Close signals done, at which point it closes the events
// channel. Unlike the ring buffer modules there's one event per interval,
// not per observation - wakeups happen far too often to ship individually.
func (r *RunqlatModule) pollLoop() {
	defer r.wg.Done()
	defer close(r.events)

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	var prev histValue
	for {
		select {
		case <-ticker.C:
		case <-r.done:
			return
		}

		cur, err := r.readHist()
		if err != nil {
			log.Printf("%s: reading histogram: %v", Name, err)
			continue
		}
		out := cur
		if !r.cumulative {
			out = cur.sub(prev)
			prev = cur
		}

		select {
		case r.events <- agent.Event{Module: Name, Timestamp: time.Now(), Data: r.toData(out)}:
		case <-r.done:
			return
		}
	}
}

// readHist sums the per-CPU histograms. The kernel side only ever
// increments them, so these are running totals since Load.
func (r *RunqlatModule) readHist() (histValue, error) {
	var perCPU []histValue
	if err := r.objs.Hist.Lookup(uint32(0), &perCPU); err != nil {
		return histValue{}, err
	}
	var total histValue
	for _, h := range perCPU {
		for i := range total.Slots {
			total.Slots[i] += h.Slots[i]
		}
		total.TotalNs += h.TotalNs
	}
	return total, nil
}

func (h histValue) sub(o histValue) histValue {
	var d histValue
	for i := range d.Slots {
		d.Slots[i] = h.Slots[i] - o.Slots[i]
	}
	d.TotalNs = h.TotalNs - o.TotalNs
	return d
}

func (r *RunqlatModule) toData(h histValue) map[string]any {
	var count uint64
	// Only non-empty buckets are reported. Bucket i holds latencies in
	// [2^i, 2^(i+1)) us (bucket 0 is 0-1us), and the last one is open-ended.
	buckets := []map[string]any{}
	for i, n := range h.Slots {
		if n == 0 {
			continue
		}
		count += n
		b := map[string]any{"count": n}
		if i > 0 {
			b["min_us"] = uint64(1) << i
		} else {
			b["min_us"] = 0
		}
		if i < maxSlots-1 {
			b["max_us"] = uint64(1)<<(i+1) - 1
		}
		buckets = append(buckets, b)
	}

	data := map[string]any{
		"interval_ms": r.interval.Milliseconds(),
		"cumulative":  r.cumulative,
		"count":       count,
		"buckets":     buckets,
	}
	if count > 0 {
		data["avg_us"] = float64(h.TotalNs) / float64(count) / 1000
	}
	return data
}

func (r *RunqlatModule) Close() error {
	if r.done != nil {
		close(r.done)
		r.wg.Wait()
	}
	for _, l := range r.links {
		l.Close()
	}
	return r.objs.Close()
}

func (r *RunqlatModule) Events() <-chan agent.Event {
	return r.events
}
