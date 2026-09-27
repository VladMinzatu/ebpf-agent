package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

const (
	listenAddr = ":8080"
	localURL   = "http://127.0.0.1:8080/"
	remoteURL  = "http://example.com/"
	interval   = 3 * time.Second
)

func main() {
	fmt.Printf("Starting tcp pinger. PID=%d\n", os.Getpid())

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		os.Exit(1)
	}
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "pong")
	}))

	// No keep-alives, so every request opens (and then closes) its own
	// connection - one connect/accept/close cycle per request.
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{DisableKeepAlives: true},
	}

	for {
		for _, url := range []string{localURL, remoteURL} {
			resp, err := client.Get(url)
			if err != nil {
				fmt.Printf("GET %s: %v\n", url, err)
				continue
			}
			n, _ := io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			fmt.Printf("GET %s: %s (%d bytes)\n", url, resp.Status, n)
		}
		time.Sleep(interval)
	}
}
