package agent

import (
	"context"
	"time"
)

// Module is an eBPF-backed unit of work: it loads and attaches one or more
// programs, streams out whatever it observes, and unloads cleanly on Close.
type Module interface {
	Name() string

	Load(ctx context.Context) error
	Close() error

	// Events returns the channel this module publishes observations on.
	// It is closed by the module once no more events will be sent.
	Events() <-chan Event
}

type Event struct {
	Module    string
	Timestamp time.Time
	Data      any
}
