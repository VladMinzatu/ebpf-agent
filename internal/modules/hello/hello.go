package hello

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/VladMinzatu/ebpf-agent/internal/agent"
)

const (
	Name    = "hello"
	commLen = 16 // TASK_COMM_LEN
)

func init() {
	agent.Register(Name, func(args []string) (agent.Module, error) {
		fs := flag.NewFlagSet(Name, flag.ContinueOnError)
		containerID := fs.String("container", "", "container id (full, or a unique prefix) to report writes for")
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if *containerID == "" {
			return nil, fmt.Errorf("-container is required")
		}
		return NewHelloModule(*containerID), nil
	})
}

type HelloModule struct {
	containerID string

	objs   helloObjects
	links  []link.Link
	reader *ringbuf.Reader
	events chan agent.Event
}

func NewHelloModule(containerID string) *HelloModule {
	return &HelloModule{containerID: containerID}
}

func (h *HelloModule) Name() string {
	return Name
}

func (h *HelloModule) Load(ctx context.Context) error {
	cgroupID, err := agent.CgroupID(h.containerID)
	if err != nil {
		return fmt.Errorf("resolving container: %w", err)
	}

	if err := loadHelloObjects(&h.objs, nil); err != nil {
		return err
	}

	if err := h.objs.TargetCgroup.Put(uint32(0), cgroupID); err != nil {
		h.objs.Close()
		return err
	}

	tp, err := link.Tracepoint(
		"syscalls",
		"sys_enter_write",
		h.objs.helloPrograms.HandleTp,
		nil,
	)
	if err != nil {
		h.objs.Close()
		return err
	}
	h.links = append(h.links, tp)

	rd, err := ringbuf.NewReader(h.objs.Events)
	if err != nil {
		h.Close()
		return err
	}
	h.reader = rd
	h.events = make(chan agent.Event)

	go h.readLoop()

	return nil
}

// readLoop forwards ring buffer records as agent.Events until the reader is
// closed by Close, at which point it closes the events channel.
func (h *HelloModule) readLoop() {
	defer close(h.events)

	var raw struct {
		Pid  uint32
		Comm [commLen]byte
	}

	for {
		record, err := h.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}

		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
			continue
		}

		h.events <- agent.Event{
			Module:    Name,
			Timestamp: time.Now(),
			Data: map[string]any{
				"pid":  raw.Pid,
				"comm": strings.TrimRight(string(raw.Comm[:]), "\x00"),
			},
		}
	}
}

func (h *HelloModule) Close() error {
	if h.reader != nil {
		h.reader.Close()
	}
	for _, l := range h.links {
		l.Close()
	}
	return h.objs.Close()
}

func (h *HelloModule) Events() <-chan agent.Event {
	return h.events
}
