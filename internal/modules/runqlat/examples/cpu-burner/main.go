package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"sync/atomic"
	"time"
)

func main() {
	workers := flag.Int("workers", 4, "number of worker threads")
	work := flag.Duration("work", 5*time.Millisecond, "CPU time each worker burns per iteration")
	sleep := flag.Duration("sleep", 5*time.Millisecond, "time each worker sleeps between iterations")
	flag.Parse()

	// One OS thread per worker, regardless of what the Go runtime would pick
	// from the container's CPU limit - otherwise workers would queue up in
	// Go's own scheduler, where the kernel (and runqlat) can't see them.
	runtime.GOMAXPROCS(*workers)

	fmt.Printf("Starting cpu burner. PID=%d workers=%d work=%s sleep=%s\n", os.Getpid(), *workers, *work, *sleep)

	var iterations atomic.Uint64
	for i := 0; i < *workers; i++ {
		go func() {
			runtime.LockOSThread()
			for {
				spin(*work)
				time.Sleep(*sleep)
				iterations.Add(1)
			}
		}()
	}

	// With no CPU contention, each worker manages 1/(work+sleep)
	// iterations/s; anything less is time spent waiting for a CPU.
	for range time.Tick(5 * time.Second) {
		fmt.Printf("%.0f iterations/s\n", float64(iterations.Swap(0))/5)
	}
}

// spin burns CPU (rather than sleeping) until d has elapsed.
func spin(d time.Duration) {
	for start := time.Now(); time.Since(start) < d; {
	}
}
