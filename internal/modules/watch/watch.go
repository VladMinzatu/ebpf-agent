//go:build linux

package watch

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/VladMinzatu/ebpf-agent/internal/agent"
)

const (
	Name = "watch"

	commLen = 16 // COMM_LEN in watch.c
)

func init() {
	agent.Register(Name, func(args []string) (agent.Module, error) {
		fs := flag.NewFlagSet(Name, flag.ContinueOnError)
		containerID := fs.String("container", "", "container id (full, or a unique prefix) the process is in")
		pid := fs.Uint("pid", 0, "pid of the process to watch, as seen on the host (docker inspect -f '{{.State.Pid}}')")
		sym := fs.String("sym", "", "what to watch: a package-level variable, optionally with struct fields, e.g. main.cfg.MaxConns")
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if *containerID == "" {
			return nil, fmt.Errorf("-container is required")
		}
		if *pid == 0 {
			return nil, fmt.Errorf("-pid is required")
		}
		if *sym == "" {
			return nil, fmt.Errorf("-sym is required")
		}
		return NewWatchModule(*containerID, uint32(*pid), *sym), nil
	})
}

// watchCfg must match struct watch_cfg in watch.c.
type watchCfg struct {
	Addr uint64
	Len  uint64
}

// event must match struct event in watch.c.
type event struct {
	Value uint64
	Pid   uint32
	Tid   uint32
	Comm  [commLen]byte
}

type WatchModule struct {
	containerID string
	pid         uint32
	sym         string

	target  Target
	objs    watchObjects
	perfFDs []int
	links   []link.Link
	reader  *ringbuf.Reader

	events chan agent.Event
	done   chan struct{}
	wg     sync.WaitGroup
}

func NewWatchModule(containerID string, pid uint32, sym string) *WatchModule {
	return &WatchModule{containerID: containerID, pid: pid, sym: sym}
}

func (w *WatchModule) Name() string {
	return Name
}

func (w *WatchModule) Load(ctx context.Context) error {
	cgroupPath, err := agent.CgroupPath(w.containerID)
	if err != nil {
		return fmt.Errorf("resolving container: %w", err)
	}
	// So -pid can't point the module at a process outside the container.
	if err := checkInCgroup(cgroupPath, w.pid); err != nil {
		return err
	}
	pidnsIno, err := agent.PidNamespaceInode()
	if err != nil {
		return err
	}
	w.target, err = Resolve(w.pid, w.sym)
	if err != nil {
		return fmt.Errorf("resolving %s: %w", w.sym, err)
	}
	log.Printf("%s: watching %s (%s, %d bytes) at %#x in pid %d", Name, w.sym, w.target.Type, w.target.Size, w.target.Addr, w.pid)

	if err := loadWatchObjects(&w.objs, nil); err != nil {
		return err
	}
	cfg := watchCfg{Addr: w.target.Addr, Len: uint64(w.target.Size)}
	if err := w.objs.WatchCfg.Put(uint32(0), cfg); err != nil {
		w.Close()
		return err
	}
	if err := w.objs.AgentPidns.Put(uint32(0), pidnsIno); err != nil {
		w.Close()
		return err
	}

	w.perfFDs, err = openBreakpoints(w.pid, w.target.Addr, w.target.Size)
	if err != nil {
		w.Close()
		return err
	}
	for _, fd := range w.perfFDs {
		// A BPF link for a perf event (kernel 5.15+), as in profile.
		l, err := link.AttachRawLink(link.RawLinkOptions{
			Target:  fd,
			Program: w.objs.HandleWrite,
			Attach:  ebpf.AttachPerfEvent,
		})
		if err != nil {
			w.Close()
			return fmt.Errorf("attaching %s: %w", w.objs.HandleWrite, err)
		}
		w.links = append(w.links, l)
	}

	w.reader, err = ringbuf.NewReader(w.objs.Events)
	if err != nil {
		w.Close()
		return err
	}
	w.events = make(chan agent.Event)
	w.done = make(chan struct{})
	w.wg.Add(1)
	go w.readLoop()
	return nil
}

// checkInCgroup checks that process pid is in the cgroup at cgroupPath.
// cgroup.procs lists pids as seen from the reader's pid namespace, which is
// the one -pid is given in.
func checkInCgroup(cgroupPath string, pid uint32) error {
	data, err := os.ReadFile(filepath.Join(cgroupPath, "cgroup.procs"))
	if err != nil {
		return err
	}
	want := strconv.FormatUint(uint64(pid), 10)
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		if sc.Text() == want {
			return nil
		}
	}
	return fmt.Errorf("pid %d is not in the container's cgroup (%s)", pid, cgroupPath)
}

// readLoop emits one agent.Event per ringbuf record, until Close closes the
// reader, at which point it closes the events channel.
func (w *WatchModule) readLoop() {
	defer w.wg.Done()
	defer close(w.events)

	var rec ringbuf.Record
	for {
		if err := w.reader.ReadInto(&rec); err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("%s: reading events: %v", Name, err)
			continue
		}
		var e event
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.NativeEndian, &e); err != nil {
			log.Printf("%s: decoding event: %v", Name, err)
			continue
		}
		data := map[string]any{
			"pid":   e.Pid,
			"tid":   e.Tid,
			"comm":  strings.TrimRight(string(e.Comm[:]), "\x00"),
			"addr":  fmt.Sprintf("%#x", w.target.Addr),
			"value": w.value(e.Value),
		}
		select {
		case w.events <- agent.Event{Module: Name, Timestamp: time.Now(), Data: data}:
		case <-w.done:
			return
		}
	}
}

// value converts the bytes read at the address to the watched type's
// value. watch.c reads Size bytes into a zeroed u64, so that's already the
// value for anything but a signed integer, which needs sign-extending.
func (w *WatchModule) value(raw uint64) any {
	if !w.target.Signed {
		return raw
	}
	shift := 64 - uint(w.target.Size)*8
	return int64(raw<<shift) >> shift
}

func (w *WatchModule) Close() error {
	if w.done != nil {
		close(w.done)
	}
	if w.reader != nil {
		w.reader.Close() // unblocks ReadInto
	}
	w.wg.Wait()
	for _, l := range w.links {
		l.Close()
	}
	closePerfEvents(w.perfFDs)
	return w.objs.Close()
}

func (w *WatchModule) Events() <-chan agent.Event {
	return w.events
}
