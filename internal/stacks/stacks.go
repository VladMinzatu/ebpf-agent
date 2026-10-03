// Package stacks turns stack traces captured in BPF with bpf_get_stackid()
// into symbolized frames, for modules that aggregate by stack (offcpu,
// profile). It's the Go side of internal/modules/bpf/stacks.h.
package stacks

import (
	"slices"
	"strings"
)

// MaxDepth is MAX_STACK_DEPTH in stacks.h: PERF_MAX_STACK_DEPTH, the most
// frames bpf_get_stackid() captures.
const MaxDepth = 127

// Missing is the single frame reported for a stack that couldn't be
// captured (a negative stack id, e.g. -EFAULT for the user stack of a
// kernel thread, or -EEXIST on a hash collision in the stacks map), or
// that's no longer in the map.
const Missing = "[missing]"

// StackMap is the part of a BPF_MAP_TYPE_STACK_TRACE map's interface a
// Resolver uses. *ebpf.Map implements it.
type StackMap interface {
	Lookup(key, valueOut any) error
	Delete(key any) error
}

// Resolver resolves stack ids from a BPF_MAP_TYPE_STACK_TRACE map to
// symbolized frames. It isn't safe for concurrent use.
type Resolver struct {
	stacks StackMap
	kernel *KernelSymbols
	user   *userSymbolizer
}

// NewResolver returns a Resolver for the given stack map. ksyms may be nil,
// in which case kernel frames are reported as raw addresses.
//
// User frames are resolved through /proc/<pid>, with pids as seen from the
// agent's own pid namespace (see agent_tgid() in pidns.h), so the agent
// needs to share a pid namespace with the traced processes, e.g. by
// running with --pid=host.
func NewResolver(stacks StackMap, ksyms *KernelSymbols) *Resolver {
	return &Resolver{stacks: stacks, kernel: ksyms, user: newUserSymbolizer()}
}

// Refresh drops cached process memory maps, so processes that exited,
// exec'd or mapped new libraries since are re-read. Parsed binaries and
// libraries stay cached. Call it once per batch of lookups, e.g. per
// reporting interval.
func (r *Resolver) Refresh() {
	r.user.resetProcs()
}

// KernelFrames returns a kernel stack's frames, leaf first.
func (r *Resolver) KernelFrames(id int32) []string {
	ips := r.ips(id)
	if ips == nil {
		return []string{Missing}
	}
	frames := make([]string, 0, len(ips))
	for _, ip := range ips {
		name, ok := r.kernel.lookup(ip)
		if !ok {
			name = unknownFrame(ip)
		}
		// A stack captured from a tracing program starts with the program
		// itself and the tracepoint plumbing that called it. How many
		// frames that is depends on the kernel, so they're dropped by name
		// rather than skipped by count in bpf_get_stackid().
		if len(frames) == 0 && isTracingFrame(name) {
			continue
		}
		frames = append(frames, name)
	}
	return frames
}

func isTracingFrame(name string) bool {
	for _, prefix := range []string{"bpf_prog_", "bpf_trace_run", "__bpf_trace_", "__traceiter_"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// UserFrames returns process pid's user stack frames, leaf first.
func (r *Resolver) UserFrames(pid uint32, id int32) []string {
	ips := r.ips(id)
	if ips == nil {
		return []string{Missing}
	}
	frames := make([]string, len(ips))
	for i, ip := range ips {
		frames[i] = r.user.lookup(pid, ip)
	}
	return trimUserFrames(frames)
}

// trimUserFrames drops frames at the root end of a user stack that aren't
// in any mapping. The kernel walks user stacks by following frame
// pointers until it finds a zero one, and not every thread entry point
// zeroes it: Go's runtime.clone on arm64, for one, leaves a stale value, so
// every stack of a thread Go started ends in one garbage "return address".
// That value changes from sample to sample, which also gives otherwise
// identical stacks different stack ids - so callers should aggregate by
// symbolized frames (e.g. Folded), not by stack id.
func trimUserFrames(frames []string) []string {
	n := len(frames)
	for n > 1 && strings.HasPrefix(frames[n-1], unknownPrefix) {
		n--
	}
	return frames[:n]
}

// ips returns a stack's instruction pointers, leaf first, or nil if it
// wasn't captured (negative id) or is no longer in the map.
func (r *Resolver) ips(id int32) []uint64 {
	if id < 0 {
		return nil
	}
	var ips [MaxDepth]uint64
	if err := r.stacks.Lookup(uint32(id), &ips); err != nil {
		return nil
	}
	n := slices.Index(ips[:], 0)
	if n < 0 {
		n = len(ips)
	}
	return ips[:n]
}

// Delete removes a stack from the stack map, so the map doesn't fill up
// with stacks that are no longer referenced. Negative (not captured) ids
// are ignored.
func (r *Resolver) Delete(id int32) {
	if id >= 0 {
		r.stacks.Delete(uint32(id))
	}
}

// Folded renders a stack in the "folded" format flame graph tools take
// (flamegraph.pl, speedscope, ...): semicolon-separated, root first, so
// comm, then user frames, then kernel frames. Frames are leaf first, as
// returned by UserFrames and KernelFrames.
func Folded(comm string, user, kernel []string) string {
	parts := []string{comm}
	for i := len(user) - 1; i >= 0; i-- {
		parts = append(parts, user[i])
	}
	for i := len(kernel) - 1; i >= 0; i-- {
		parts = append(parts, kernel[i])
	}
	return strings.Join(parts, ";")
}
