// Stack trace capture for modules that aggregate by stack. The Go side,
// which resolves stack ids from this map to symbolized frames, is
// internal/stacks.
//
// Include after vmlinux.h and <bpf/bpf_helpers.h>.

#ifndef __AGENT_STACKS_H
#define __AGENT_STACKS_H

// PERF_MAX_STACK_DEPTH, the most frames bpf_get_stackid() will capture.
// Must match stacks.MaxDepth.
#define MAX_STACK_DEPTH 127

// Stack id -> the stack's instruction pointers, leaf first, filled in by
// bpf_get_stackid(ctx, &stacks, 0) for kernel stacks and
// bpf_get_stackid(ctx, &stacks, BPF_F_USER_STACK) for user stacks.
// Identical stacks share an id, which is what makes aggregating by stack
// cheap: a counts key only needs to carry the two ids, not the frames.
//
// Nothing is ever evicted automatically - without BPF_F_REUSE_STACKID, a
// stack that hashes to an occupied slot gets -EEXIST instead of an id - so
// userspace deletes ids once it's done with them (stacks.Resolver.Delete).
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 16384);
    __uint(key_size, sizeof(u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(u64));
} stacks SEC(".maps");

#endif
