package agent

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// Runner owns the lifecycle of a set of modules: construct from config,
// load, stream events into sinks until stopped, then unload everything.
type Runner struct {
	sinks   []Sink
	modules []Module
}

func NewRunner(sinks ...Sink) *Runner {
	return &Runner{sinks: sinks}
}

// Load constructs the named module from its CLI args and loads it. On
// failure, any modules already loaded are closed before returning.
func (r *Runner) Load(ctx context.Context, name string, args []string) error {
	m, err := newModule(name, args)
	if err != nil {
		return err
	}

	if err := m.Load(ctx); err != nil {
		_ = r.Close()
		return fmt.Errorf("loading module %q: %w", name, err)
	}

	r.modules = append(r.modules, m)
	return nil
}

// Run streams events from every loaded module into the configured sinks
// until ctx is cancelled, then returns once all module event channels have
// drained or closed.
func (r *Runner) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, m := range r.modules {
		wg.Add(1)
		go func(m Module) {
			defer wg.Done()
			for {
				select {
				case ev, ok := <-m.Events():
					if !ok {
						return
					}
					for _, s := range r.sinks {
						_ = s.Write(ev)
					}
				case <-ctx.Done():
					return
				}
			}
		}(m)
	}
	<-ctx.Done()
	wg.Wait()
}

// Close unloads every loaded module, in reverse load order, and joins any
// errors encountered along the way.
func (r *Runner) Close() error {
	var errs []error
	for i := len(r.modules) - 1; i >= 0; i-- {
		m := r.modules[i]
		if err := m.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing module %q: %w", m.Name(), err))
		}
	}
	r.modules = nil
	return errors.Join(errs...)
}
