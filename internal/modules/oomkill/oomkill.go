package oomkill

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
	Name    = "oomkill"
	commLen = 16 // TASK_COMM_LEN
)

func init() {
	agent.Register(Name, func(args []string) (agent.Module, error) {
		fs := flag.NewFlagSet(Name, flag.ContinueOnError)
		containerID := fs.String("container", "", "container id (full, or a unique prefix) to report OOM kills for")
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if *containerID == "" {
			return nil, fmt.Errorf("-container is required")
		}
		return NewOOMKillModule(*containerID), nil
	})
}

type OOMKillModule struct {
	containerID string

	objs   oomkillObjects
	links  []link.Link
	reader *ringbuf.Reader
	events chan agent.Event
}

func NewOOMKillModule(containerID string) *OOMKillModule {
	return &OOMKillModule{containerID: containerID}
}

func (o *OOMKillModule) Name() string {
	return Name
}

func (o *OOMKillModule) Load(ctx context.Context) error {
	cgroupID, err := agent.CgroupID(o.containerID)
	if err != nil {
		return fmt.Errorf("resolving container: %w", err)
	}

	if err := loadOomkillObjects(&o.objs, nil); err != nil {
		return err
	}

	if err := o.objs.TargetCgroup.Put(uint32(0), cgroupID); err != nil {
		o.objs.Close()
		return err
	}

	tp, err := link.Tracepoint(
		"oom",
		"mark_victim",
		o.objs.oomkillPrograms.HandleTp,
		nil,
	)
	if err != nil {
		o.objs.Close()
		return err
	}
	o.links = append(o.links, tp)

	rd, err := ringbuf.NewReader(o.objs.Events)
	if err != nil {
		o.Close()
		return err
	}
	o.reader = rd
	o.events = make(chan agent.Event)

	go o.readLoop()

	return nil
}

// readLoop forwards ring buffer records as agent.Events until the reader is
// closed by Close, at which point it closes the events channel.
func (o *OOMKillModule) readLoop() {
	defer close(o.events)

	// Field order must match oomkill.c's struct event layout exactly - see
	// the comment there.
	var raw struct {
		TotalVM     uint64
		Pid         uint32
		OOMScoreAdj int16
		Comm        [commLen]byte
	}

	for {
		record, err := o.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}

		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
			continue
		}

		o.events <- agent.Event{
			Module:    Name,
			Timestamp: time.Now(),
			Data: map[string]any{
				"pid":            raw.Pid,
				"comm":           strings.TrimRight(string(raw.Comm[:]), "\x00"),
				"total_vm_pages": raw.TotalVM,
				"oom_score_adj":  raw.OOMScoreAdj,
			},
		}
	}
}

func (o *OOMKillModule) Close() error {
	if o.reader != nil {
		o.reader.Close()
	}
	for _, l := range o.links {
		l.Close()
	}
	return o.objs.Close()
}

func (o *OOMKillModule) Events() <-chan agent.Event {
	return o.events
}
