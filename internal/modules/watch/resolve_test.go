package watch

import (
	"debug/elf"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// A target binary for the resolver tests. The layout of Config is what the
// expected offsets below are based on. It prints the address of
// cfg.Limits.MaxConns, so a test running it can check what Resolve finds.
const targetSource = `package main

import (
	"fmt"
	"time"
	"unsafe"
)

type Limits struct {
	Timeout  time.Duration // +0
	MaxConns int32         // +8
	Enabled  bool          // +12
}

type Config struct {
	Name   string  // +0
	Limits Limits  // +16
	Next   *Config // +32
}

var counter int64
var cfg = Config{Name: "x"}

func main() {
	counter++
	cfg.Next = &cfg
	fmt.Println(uintptr(unsafe.Pointer(&cfg.Limits.MaxConns)))
	time.Sleep(time.Hour)
}
`

// buildTarget builds targetSource for goos with extra go build flags and
// returns the binary's path. It keeps the binary's DWARF and symbol table,
// unlike the binaries go test and go run build.
func buildTarget(t *testing.T, goos string, flags ...string) string {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("needs the go command to build the target binary")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	bin := filepath.Join(dir, "target")
	if err := os.WriteFile(src, []byte(targetSource), 0o644); err != nil {
		t.Fatal(err)
	}
	args := append(append([]string{"build"}, flags...), "-o", bin, src)
	cmd := exec.Command(goBin, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0", "GOFLAGS=")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building target: %v\n%s", err, out)
	}
	return bin
}

func openELF(t *testing.T, path string) *elf.File {
	t.Helper()
	f, err := elf.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func symbolValue(t *testing.T, f *elf.File, name string) uint64 {
	t.Helper()
	syms, err := f.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(syms, func(s elf.Symbol) bool { return s.Name == name })
	if i < 0 {
		t.Fatalf("no symbol %s", name)
	}
	return syms[i].Value
}

func TestParseExpr(t *testing.T) {
	tests := []struct {
		expr       string
		wantVar    string
		wantFields []string
	}{
		{"main.counter", "main.counter", []string{}},
		{"main.cfg.Limits.MaxConns", "main.cfg", []string{"Limits", "MaxConns"}},
		{"github.com/acme/svc/config.cfg.Timeout", "github.com/acme/svc/config.cfg", []string{"Timeout"}},
		{"example.com/svc.v2/config.cfg", "example.com/svc.v2/config.cfg", []string{}},
	}
	for _, tt := range tests {
		v, fields, err := parseExpr(tt.expr)
		if err != nil || v != tt.wantVar || !slices.Equal(fields, tt.wantFields) {
			t.Errorf("parseExpr(%q) = %q, %q, %v; want %q, %q", tt.expr, v, fields, err, tt.wantVar, tt.wantFields)
		}
	}
	for _, expr := range []string{"", "counter", "main.", "main..x", "github.com/acme/svc/", "main.cfg."} {
		if _, _, err := parseExpr(expr); err == nil {
			t.Errorf("parseExpr(%q): want an error", expr)
		}
	}
}

// The ways the target is built, for tests that should cover both: a
// non-PIE executable (go build's default on Linux), and a PIE.
var buildModes = []struct {
	name  string
	flags []string
}{
	{"exe", nil},
	{"pie", []string{"-buildmode=pie"}},
}

// Resolves against Linux binaries, which can be cross-built anywhere, and
// checks the addresses DWARF gives against the ELF symbol table. These are
// link-time addresses: for a PIE, Resolve adds the load bias on top.
func TestResolveELF(t *testing.T) {
	for _, mode := range buildModes {
		t.Run(mode.name, func(t *testing.T) {
			testResolveELF(t, openELF(t, buildTarget(t, "linux", mode.flags...)))
		})
	}
}

func testResolveELF(t *testing.T, f *elf.File) {
	counter := symbolValue(t, f, "main.counter")
	cfg := symbolValue(t, f, "main.cfg")

	tests := []struct {
		expr string
		want Target
	}{
		{"main.counter", Target{Addr: counter, Size: 8, Type: "int64", Signed: true}},
		{"main.cfg.Limits.Timeout", Target{Addr: cfg + 16, Size: 8, Type: "time.Duration", Signed: true}},
		{"main.cfg.Limits.MaxConns", Target{Addr: cfg + 24, Size: 4, Type: "int32", Signed: true}},
		{"main.cfg.Limits.Enabled", Target{Addr: cfg + 28, Size: 1, Type: "bool"}},
		{"main.cfg.Next", Target{Addr: cfg + 32, Size: 8, Type: "*main.Config"}},
	}
	for _, tt := range tests {
		got, err := resolveELF(f, tt.expr)
		if err != nil || got != tt.want {
			t.Errorf("resolveELF(%q) = %+v, %v; want %+v", tt.expr, got, err, tt.want)
		}
	}

	errTests := []struct {
		expr    string
		wantErr string
	}{
		{"main.missing", "no variable main.missing"},
		{"main.cfg.Nope", "has no field Nope; fields: Name, Limits, Next"},
		{"main.counter.X", "main.counter is int64, not a struct"},
		{"main.cfg.Next.Name", "main.cfg.Next is a pointer"},
		{"main.cfg.Limits", "is 16 bytes"},
		{"main.cfg.Name", "is 16 bytes"},
	}
	for _, tt := range errTests {
		if _, err := resolveELF(f, tt.expr); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
			t.Errorf("resolveELF(%q) error = %v, want one containing %q", tt.expr, err, tt.wantErr)
		}
	}
}

func TestResolveELFNoDWARF(t *testing.T) {
	f := openELF(t, buildTarget(t, "linux", "-ldflags=-w"))
	if _, err := resolveELF(f, "main.counter"); err == nil || !strings.Contains(err.Error(), "DWARF") {
		t.Errorf("error = %v, want one about DWARF", err)
	}
}

func TestAuxvValue(t *testing.T) {
	var auxv []byte
	for _, v := range []uint64{
		6, 4096, // AT_PAGESZ
		atEntry, 0xaaaad4c5e2a0,
		0, 0, // AT_NULL
		atEntry, 1, // past the end, ignored
	} {
		auxv = binary.LittleEndian.AppendUint64(auxv, v)
	}
	if got, ok := auxvValue(auxv, binary.LittleEndian, atEntry); !ok || got != 0xaaaad4c5e2a0 {
		t.Errorf("auxvValue(AT_ENTRY) = %#x, %v; want 0xaaaad4c5e2a0, true", got, ok)
	}
	if _, ok := auxvValue(auxv, binary.LittleEndian, 3); ok { // AT_PHDR, not there
		t.Error("auxvValue(AT_PHDR): want not found")
	}
	if _, ok := auxvValue(auxv[:20], binary.LittleEndian, atEntry); ok {
		t.Error("auxvValue on a truncated auxv: want not found")
	}
}
