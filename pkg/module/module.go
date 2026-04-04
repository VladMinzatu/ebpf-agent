package module

import (
	"context"
	"time"
)

const (
	HelloModule = "hello"
)

type Module interface {
	Name() string

	Load(ctx context.Context) error
	Close() error

	Events() <-chan Event
}

type Event struct {
	Module    string
	Timestamp time.Time
	Data      any
}
