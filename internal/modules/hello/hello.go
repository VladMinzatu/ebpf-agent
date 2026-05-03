package hello

import (
	"context"

	"github.com/cilium/ebpf/link"

	"github.com/VladMinzatu/ebpf-agent/internal/domain/module"
)

type HelloModule struct {
	targetPid int

	objs  helloObjects
	links []link.Link
}

func NewHelloModule(targetPid int) *HelloModule {
	return &HelloModule{targetPid: targetPid}
}

func (h *HelloModule) Name() string {
	return module.HelloModule
}

func (h *HelloModule) Load(ctx context.Context) error {
	// Load the BPF objects
	if err := loadHelloObjects(&h.objs, nil); err != nil {
		return err
	}

	// Load targetPid in map
	if err := h.objs.PidFilter.Put(uint32(h.targetPid), uint8(1)); err != nil {
		h.objs.Close()
		return err
	}

	// Attach program
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

	return nil
}

func (h *HelloModule) Close() error {
	for _, l := range h.links {
		l.Close()
	}
	return h.objs.Close()
}

func (h *HelloModule) Events() <-chan module.Event {
	return nil
}
