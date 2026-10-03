package stacks

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// fakeStackMap stands in for a BPF_MAP_TYPE_STACK_TRACE map, which can't be
// filled from userspace - only bpf_get_stackid() writes to it.
type fakeStackMap struct {
	stacks  map[uint32][]uint64
	deleted []uint32
}

func (m *fakeStackMap) Lookup(key, valueOut any) error {
	ips, ok := m.stacks[key.(uint32)]
	if !ok {
		return errors.New("key does not exist")
	}
	out := valueOut.(*[MaxDepth]uint64)
	*out = [MaxDepth]uint64{}
	copy(out[:], ips)
	return nil
}

func (m *fakeStackMap) Delete(key any) error {
	id := key.(uint32)
	m.deleted = append(m.deleted, id)
	delete(m.stacks, id)
	return nil
}

const kallsymsFixture = `ffff800080010000 T _text
ffff800080011000 t schedule
ffff800080012000 T futex_wait
ffff800080013000 d some_data
ffff800080014000 T bpf_trace_run4
ffff800080015000 t __bpf_trace_sched_switch
ffff800080016000 W weak_func
ffffa00000000000 t bpf_prog_6deef7357e7b4530_handle_sched_switch	[bpf]
`

func mustParseKallsyms(t *testing.T, s string) *KernelSymbols {
	t.Helper()
	ksyms, err := parseKallsyms(strings.NewReader(s))
	if err != nil {
		t.Fatalf("parseKallsyms: %v", err)
	}
	return ksyms
}

func TestKernelFrames(t *testing.T) {
	ksyms := mustParseKallsyms(t, kallsymsFixture)
	m := &fakeStackMap{stacks: map[uint32][]uint64{
		// As captured from a tp_btf program: the program and the
		// tracepoint plumbing first, then the kernel's own frames.
		1: {
			0xffffa00000000010, // bpf_prog_..._handle_sched_switch
			0xffff800080014008, // bpf_trace_run4
			0xffff800080015004, // __bpf_trace_sched_switch
			0xffff800080011010, // schedule
			0xffff800080012020, // futex_wait
			0xffff800080016000, // weak_func
		},
		// A tracing-looking frame that isn't at the leaf is a real caller.
		2: {0xffff800080011000, 0xffff800080014000},
		// Below the first symbol.
		3: {0xffff800080011000, 0xffff700000000000},
	}}
	r := NewResolver(m, ksyms)

	tests := []struct {
		name string
		id   int32
		want []string
	}{
		{"strips leading tracing frames", 1, []string{"schedule", "futex_wait", "weak_func"}},
		{"keeps tracing frames past the leaf", 2, []string{"schedule", "bpf_trace_run4"}},
		{"unknown address", 3, []string{"schedule", "[unknown 0xffff700000000000]"}},
		{"not captured", -14, []string{Missing}},
		{"not in map", 42, []string{Missing}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := r.KernelFrames(tt.id); !slices.Equal(got, tt.want) {
				t.Errorf("KernelFrames(%d) = %q, want %q", tt.id, got, tt.want)
			}
		})
	}
}

func TestKernelFramesWithoutSymbols(t *testing.T) {
	m := &fakeStackMap{stacks: map[uint32][]uint64{1: {0xffff800080011010, 0xffff800080012020}}}
	r := NewResolver(m, nil)

	want := []string{"[unknown 0xffff800080011010]", "[unknown 0xffff800080012020]"}
	if got := r.KernelFrames(1); !slices.Equal(got, want) {
		t.Errorf("KernelFrames(1) = %q, want %q", got, want)
	}
}

func TestParseKallsyms(t *testing.T) {
	ksyms := mustParseKallsyms(t, kallsymsFixture)

	// Only text symbols (t/T/w/W) are kept, so a data symbol never shows up.
	// Addresses in it resolve to the text symbol before it, since kallsyms
	// has no sizes.
	for addr, want := range map[uint64]string{
		0xffff800080011000: "schedule",
		0xffff800080011fff: "schedule",
		0xffff800080013010: "futex_wait",
		0xffff800080016000: "weak_func",
		0xffffa00000000000: "bpf_prog_6deef7357e7b4530_handle_sched_switch",
	} {
		if got, ok := ksyms.lookup(addr); !ok || got != want {
			t.Errorf("lookup(%#x) = %q, %v; want %q", addr, got, ok, want)
		}
	}
	if got, ok := ksyms.lookup(0xffff800080000000); ok {
		t.Errorf("lookup below the first symbol = %q, want no match", got)
	}
}

func TestParseKallsymsWithoutAddresses(t *testing.T) {
	// What /proc/kallsyms looks like to a reader without CAP_SYSLOG.
	restricted := `0000000000000000 T _text
0000000000000000 t schedule
`
	if _, err := parseKallsyms(strings.NewReader(restricted)); err == nil {
		t.Error("parseKallsyms of all-zero addresses: got no error")
	}
}

func TestUserFramesTrimsUnknownRoot(t *testing.T) {
	// No process has pid 0, so nothing resolves: every frame is unknown.
	// Unknown frames at the root end are dropped (see trimUserFrames), but
	// the leaf is always kept, so a stack never comes back empty.
	m := &fakeStackMap{stacks: map[uint32][]uint64{1: {0x1000, 0x2000, 0x3000}}}
	r := NewResolver(m, nil)

	want := []string{"[unknown 0x1000]"}
	if got := r.UserFrames(0, 1); !slices.Equal(got, want) {
		t.Errorf("UserFrames(0, 1) = %q, want %q", got, want)
	}
	if got := r.UserFrames(0, -14); !slices.Equal(got, []string{Missing}) {
		t.Errorf("UserFrames(0, -14) = %q, want %q", got, []string{Missing})
	}
}

func TestDelete(t *testing.T) {
	m := &fakeStackMap{stacks: map[uint32][]uint64{5: {0x1000}}}
	r := NewResolver(m, nil)

	r.Delete(-17) // not captured: nothing to delete
	r.Delete(5)

	if want := []uint32{5}; !slices.Equal(m.deleted, want) {
		t.Errorf("deleted %v, want %v", m.deleted, want)
	}
}

func TestFolded(t *testing.T) {
	user := []string{"pthread_mutex_lock", "update_shared_state", "worker"} // leaf first
	kernel := []string{"schedule", "futex_wait", "__arm64_sys_futex"}       // leaf first

	got := Folded("contender", user, kernel)
	want := "contender;worker;update_shared_state;pthread_mutex_lock;__arm64_sys_futex;futex_wait;schedule"
	if got != want {
		t.Errorf("Folded() = %q\nwant        %q", got, want)
	}
}

func ExampleFolded() {
	fmt.Println(Folded("app", []string{"read", "main"}, []string{"schedule", "sys_read"}))
	// Output: app;main;read;sys_read;schedule
}
