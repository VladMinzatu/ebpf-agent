package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/VladMinzatu/ebpf-agent/internal/agent"

	// Blank-imported so each module's init() registers it with the agent.
	// Add new modules here as they're written.
	_ "github.com/VladMinzatu/ebpf-agent/internal/modules/hello"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	moduleName := os.Args[1]
	moduleArgs := os.Args[2:]

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	runner := agent.NewRunner(agent.NewStdoutJSON())
	if err := runner.Load(ctx, moduleName, moduleArgs); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		log.Fatalf("failed to load module %q: %v", moduleName, err)
	}

	log.Printf("module %q running, press Ctrl+C to stop", moduleName)

	runner.Run(ctx)

	if err := runner.Close(); err != nil {
		log.Printf("error while unloading module: %v", err)
	}
	log.Println("module stopped, program unloaded")
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: %s <module> [module flags]\n\navailable modules: %s\n\nrun \"%s <module> -h\" for a module's flags\n",
		os.Args[0], strings.Join(agent.Names(), ", "), os.Args[0])
}
