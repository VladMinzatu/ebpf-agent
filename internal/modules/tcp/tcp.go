package tcp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/VladMinzatu/ebpf-agent/internal/agent"
)

const (
	Name    = "tcp"
	commLen = 16 // TASK_COMM_LEN

	afInet = 2
)

// Must match the EVENT_* values in tcp.c.
var eventTypes = []string{"connect", "accept", "close"}

func init() {
	agent.Register(Name, func(args []string) (agent.Module, error) {
		fs := flag.NewFlagSet(Name, flag.ContinueOnError)
		containerID := fs.String("container", "", "container id (full, or a unique prefix) to trace TCP connections for")
		events := fs.String("events", strings.Join(eventTypes, ","), "comma-separated event types to report (connect, accept, close)")
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if *containerID == "" {
			return nil, fmt.Errorf("-container is required")
		}
		enabled, err := parseEvents(*events)
		if err != nil {
			return nil, err
		}
		return NewTCPModule(*containerID, enabled), nil
	})
}

func parseEvents(s string) (map[string]bool, error) {
	enabled := map[string]bool{}
	for _, name := range strings.Split(s, ",") {
		name = strings.TrimSpace(name)
		valid := false
		for _, t := range eventTypes {
			if name == t {
				valid = true
			}
		}
		if !valid {
			return nil, fmt.Errorf("unknown event type %q in -events, expected any of %s", name, strings.Join(eventTypes, ", "))
		}
		enabled[name] = true
	}
	return enabled, nil
}

type TCPModule struct {
	containerID string
	enabled     map[string]bool

	objs   tcpObjects
	links  []link.Link
	reader *ringbuf.Reader
	events chan agent.Event
}

func NewTCPModule(containerID string, enabled map[string]bool) *TCPModule {
	return &TCPModule{containerID: containerID, enabled: enabled}
}

func (t *TCPModule) Name() string {
	return Name
}

func (t *TCPModule) Load(ctx context.Context) error {
	cgroupID, err := agent.CgroupID(t.containerID)
	if err != nil {
		return fmt.Errorf("resolving container: %w", err)
	}

	if err := loadTcpObjects(&t.objs, nil); err != nil {
		return err
	}

	if err := t.objs.TargetCgroup.Put(uint32(0), cgroupID); err != nil {
		t.objs.Close()
		return err
	}

	// Event types that weren't asked for simply don't get their programs
	// attached, so they cost nothing in the kernel.
	var progs []*ebpf.Program
	if t.enabled["connect"] {
		progs = append(progs, t.objs.HandleConnectV4, t.objs.HandleConnectV6)
	}
	if t.enabled["accept"] {
		progs = append(progs, t.objs.HandleAccept)
	}
	if t.enabled["close"] {
		progs = append(progs, t.objs.HandleClose)
	}
	for _, prog := range progs {
		// The attach point (fentry/fexit + kernel function) comes from
		// each program's SEC() name in tcp.c.
		l, err := link.AttachTracing(link.TracingOptions{Program: prog})
		if err != nil {
			t.Close()
			return fmt.Errorf("attaching %s: %w", prog, err)
		}
		t.links = append(t.links, l)
	}

	rd, err := ringbuf.NewReader(t.objs.Events)
	if err != nil {
		t.Close()
		return err
	}
	t.reader = rd
	t.events = make(chan agent.Event)

	go t.readLoop()

	return nil
}

// readLoop forwards ring buffer records as agent.Events until the reader is
// closed by Close, at which point it closes the events channel.
func (t *TCPModule) readLoop() {
	defer close(t.events)

	// Field order must match tcp.c's struct event layout exactly - see the
	// comment there.
	var raw struct {
		BytesAcked    uint64
		BytesReceived uint64
		Saddr         [16]byte
		Daddr         [16]byte
		Pid           uint32
		Family        uint16
		Sport         uint16
		Dport         uint16
		Type          uint8
		Comm          [commLen]byte
	}

	for {
		record, err := t.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}

		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
			continue
		}
		if int(raw.Type) >= len(eventTypes) {
			continue
		}

		data := map[string]any{
			"type":  eventTypes[raw.Type],
			"pid":   raw.Pid,
			"comm":  strings.TrimRight(string(raw.Comm[:]), "\x00"),
			"saddr": formatAddr(raw.Family, raw.Saddr),
			"sport": raw.Sport,
			"daddr": formatAddr(raw.Family, raw.Daddr),
			"dport": raw.Dport,
		}
		if eventTypes[raw.Type] == "close" {
			data["bytes_acked"] = raw.BytesAcked
			data["bytes_received"] = raw.BytesReceived
		}

		t.events <- agent.Event{
			Module:    Name,
			Timestamp: time.Now(),
			Data:      data,
		}
	}
}

func formatAddr(family uint16, b [16]byte) string {
	if family == afInet {
		return netip.AddrFrom4([4]byte(b[:4])).String()
	}
	return netip.AddrFrom16(b).String()
}

func (t *TCPModule) Close() error {
	if t.reader != nil {
		t.reader.Close()
	}
	for _, l := range t.links {
		l.Close()
	}
	return t.objs.Close()
}

func (t *TCPModule) Events() <-chan agent.Event {
	return t.events
}
