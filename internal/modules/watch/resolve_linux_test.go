//go:build linux

package watch

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
)

// Resolves in a running process, through /proc/<pid>/exe, and checks the
// address against the one the process reports itself. For a PIE that only
// matches if the load bias was added.
func TestResolveRunningProcess(t *testing.T) {
	for _, mode := range buildModes {
		t.Run(mode.name, func(t *testing.T) {
			cmd := exec.Command(buildTarget(t, "linux", mode.flags...))
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() {
				cmd.Process.Kill()
				cmd.Wait()
			}()
			var want uint64
			if _, err := fmt.Fscan(stdout, &want); err != nil {
				t.Fatalf("reading target's address: %v", err)
			}

			got, err := Resolve(uint32(cmd.Process.Pid), "main.cfg.Limits.MaxConns")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if got.Addr != want || got.Size != 4 {
				t.Errorf("Resolve() = %+v, want Addr %#x, Size 4", got, want)
			}
		})
	}
}

func TestResolveMissingProcess(t *testing.T) {
	if _, err := Resolve(uint32(os.Getpid())+1<<22, "main.counter"); err == nil {
		t.Error("want an error for a pid that doesn't exist")
	}
}
