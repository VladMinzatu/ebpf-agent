//go:build linux

package stacks

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

// A target process for TestUserFramesResolvesOtherProcess: prints the
// address of one of its functions, then waits to be inspected.
const targetSource = `package main

import (
	"fmt"
	"reflect"
	"time"
)

//go:noinline
func blockHere() { time.Sleep(time.Hour) }

func main() {
	fmt.Println(reflect.ValueOf(blockHere).Pointer())
	blockHere()
}
`

// Resolves an address in another process, the way it works for a traced
// one: /proc/<pid>/maps to find the mapping, then the binary's ELF symbol
// table, read via /proc/<pid>/root. (The test binary itself won't do as
// the target: go test strips the symbol table from binaries it builds and
// runs right away.)
func TestUserFramesResolvesOtherProcess(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("needs the go command to build the target process")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	bin := filepath.Join(dir, "target")
	if err := os.WriteFile(src, []byte(targetSource), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(goBin, "build", "-o", bin, src).CombinedOutput(); err != nil {
		t.Fatalf("building target: %v\n%s", err, out)
	}

	cmd := exec.Command(bin)
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
	var addr uint64
	if _, err := fmt.Fscan(stdout, &addr); err != nil {
		t.Fatalf("reading target's function address: %v", err)
	}

	m := &fakeStackMap{stacks: map[uint32][]uint64{1: {addr + 4}}}
	r := NewResolver(m, nil)

	want := []string{"main.blockHere"}
	if got := r.UserFrames(uint32(cmd.Process.Pid), 1); !slices.Equal(got, want) {
		t.Errorf("UserFrames() = %q, want %q", got, want)
	}
}

// An address that's mapped from a file but isn't in any function is
// reported by file and offset.
func TestUserFramesMappedWithoutSymbol(t *testing.T) {
	maps, err := readMaps(uint32(os.Getpid()))
	if err != nil || len(maps) == 0 {
		t.Fatalf("readMaps: %v (%d mappings)", err, len(maps))
	}
	// The test binary's first mapping starts with its ELF header, which no
	// function symbol covers (and go test strips its symbols anyway).
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var first *mapping
	for i := range maps {
		if maps[i].path == exe && maps[i].offset == 0 {
			first = &maps[i]
			break
		}
	}
	if first == nil {
		t.Skipf("no mapping of %s at offset 0", exe)
	}

	m := &fakeStackMap{stacks: map[uint32][]uint64{1: {first.start}}}
	r := NewResolver(m, nil)

	got := r.UserFrames(uint32(os.Getpid()), 1)
	if len(got) != 1 || !strings.HasPrefix(got[0], "["+exe+"+0x") {
		t.Errorf("UserFrames() = %q, want [%q]", got, "["+exe+"+0x...]")
	}
}

// The vDSO has no file behind it; its addresses are reported by name.
func TestUserFramesVDSO(t *testing.T) {
	maps, err := readMaps(uint32(os.Getpid()))
	if err != nil {
		t.Fatalf("readMaps: %v", err)
	}
	i := slices.IndexFunc(maps, func(m mapping) bool { return m.path == "[vdso]" })
	if i < 0 {
		t.Skip("no [vdso] mapping")
	}

	m := &fakeStackMap{stacks: map[uint32][]uint64{1: {maps[i].start + 0x10}}}
	r := NewResolver(m, nil)

	want := []string{"[vdso]"}
	if got := r.UserFrames(uint32(os.Getpid()), 1); !slices.Equal(got, want) {
		t.Errorf("UserFrames() = %q, want %q", got, want)
	}
}

func TestDrain(t *testing.T) {
	type key struct {
		Pid     uint32
		StackID int32
	}
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    8,
		ValueSize:  8,
		MaxEntries: 16,
	})
	if err != nil {
		t.Skipf("creating a BPF map needs privileges (run the tests with --privileged): %v", err)
	}
	defer m.Close()

	want := map[key]uint64{{1, 10}: 100, {1, 11}: 110, {2, -14}: 200}
	for k, v := range want {
		if err := m.Put(k, v); err != nil {
			t.Fatalf("Put(%v): %v", k, err)
		}
	}

	got, err := Drain[key, uint64](m)
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Drain() = %v, want %v", got, want)
	}

	// Everything drained was deleted.
	again, err := Drain[key, uint64](m)
	if err != nil {
		t.Fatalf("second Drain: %v", err)
	}
	if len(again) != 0 {
		t.Errorf("second Drain() = %v, want empty", again)
	}
}
