package module

import (
	"context"
	"time"
)

type Module interface {
	Name() string

	Load(ctx context.Context) error
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Close() error

	Events() <-chan Event
}

type Event struct {
	Module    string
	Timestamp time.Time
	Data      any
}
