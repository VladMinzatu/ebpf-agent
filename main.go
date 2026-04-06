package main

import (
	"context"
	"log"
	"time"

	"github.com/VladMinzatu/ebpf-agent/modules/hello"
)

func main() {
	hm := hello.NewHelloModule(12345)
	ctx := context.Background()
	if err := hm.Load(ctx); err != nil {
		log.Fatalf("Failed to load BPF program. Err=%v", err)
	}
	defer hm.Close()

	time.Sleep(50 * time.Second)
}
