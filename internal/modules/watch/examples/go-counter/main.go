package main

import (
	"fmt"
	"os"
	"time"
	"unsafe"
)

type Stats struct {
	Ticks  int64
	Resets int64
}

// The globals watch is pointed at. They're written with plain stores from
// two goroutines, so the writes can come from different threads.
var (
	counter int64
	stats   Stats
)

//go:noinline
func tick() {
	counter++
	stats.Ticks++
}

//go:noinline
func reset() {
	counter = 0
	stats.Resets++
}

func main() {
	fmt.Printf("go-counter: pid=%d &counter=%#x &stats.Resets=%#x\n",
		os.Getpid(), uintptr(unsafe.Pointer(&counter)), uintptr(unsafe.Pointer(&stats.Resets)))

	go func() {
		for range time.Tick(10 * time.Second) {
			reset()
			fmt.Println("reset")
		}
	}()

	for range time.Tick(time.Second) {
		tick()
		fmt.Printf("counter=%d\n", counter)
	}
}
