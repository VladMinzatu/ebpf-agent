package main

import (
	"fmt"
	"os"
	"time"
)

const (
	chunkSize  = 10 * 1024 * 1024 // 10MB
	pageStride = 4096             // touch one byte per page, so it counts toward RSS
)

func main() {
	pid := os.Getpid()
	fmt.Printf("Starting memory eater. PID=%d\n", pid)
	fmt.Println("Waiting 15s before allocating, so there's time to attach the oomkill module")
	time.Sleep(15 * time.Second)

	var chunks [][]byte
	for i := 1; ; i++ {
		chunk := make([]byte, chunkSize)
		for j := 0; j < len(chunk); j += pageStride {
			chunk[j] = 1
		}
		chunks = append(chunks, chunk)
		fmt.Printf("allocated %dMB total (pid=%d)\n", i*10, pid)
		time.Sleep(200 * time.Millisecond)
	}
}
