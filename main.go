package main

import (
	"context"
	"time"

	"github.com/VladMinzatu/ebpf-agent/modules/hello"
)

func main() {
	hm := hello.HelloModule{}
	ctx := context.Background()
	hm.Load(ctx)
	defer hm.Close()

	time.Sleep(5 * time.Second)
}
