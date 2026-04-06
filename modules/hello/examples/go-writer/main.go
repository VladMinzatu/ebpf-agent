package main

import (
	"fmt"
	"os"
	"time"
)

func main() {
	pid := os.Getpid()
	fmt.Printf("Starting write spammer. PID=%d\n", pid)

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for t := range ticker.C {
		msg := fmt.Sprintf("tick at %s (pid=%d)\n", t.Format(time.RFC3339Nano), pid)

		_, err := os.Stdout.Write([]byte(msg))
		if err != nil {
			fmt.Fprintf(os.Stderr, "write error: %v\n", err)
		}
	}
}
