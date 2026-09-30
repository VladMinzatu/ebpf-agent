//go:build ignore

#define BPF_NO_GLOBAL_DATA
#include "../bpf/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Log2 buckets of latency in microseconds: slot 0 is 0-1us, slot i is
// [2^i, 2^(i+1)) us, and the last slot also absorbs anything longer
// (2^26us is ~67s).
#define MAX_SLOTS 27

#define TASK_RUNNING 0

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} target_cgroup SEC(".maps");

// Thread id -> time it became runnable (woken up, or preempted while still
// runnable). Only threads in the target cgroup get an entry, and it's
// removed once the thread is switched in.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, u64);
} start SEC(".maps");

// Must match histValue in runqlat.go. Never reset from the kernel side:
// userspace reads it periodically and diffs against the previous read, so
// there's no read-then-clear race with CPUs still incrementing it.
struct hist {
    u64 slots[MAX_SLOTS];
    u64 total_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct hist);
} hist SEC(".maps");

// Unlike the other modules, none of these hooks can filter on
// bpf_get_current_cgroup_id(): sched_wakeup runs in the context of the
// waker (another thread, often another container, or softirq), and
// sched_switch runs in the context of prev. So the cgroup is read off the
// task in question instead - the same ID bpf_get_current_cgroup_id() would
// return if that task were current.
static __always_inline int task_in_target_cgroup(struct task_struct *p)
{
    u32 key = 0;
    u64 *target = bpf_map_lookup_elem(&target_cgroup, &key);
    return target && BPF_CORE_READ(p, cgroups, dfl_cgrp, kn, id) == *target;
}

// task_struct::state was renamed to __state (and changed type) in 5.14.
struct task_struct___pre_5_14 {
    volatile long state;
} __attribute__((preserve_access_index));

static __always_inline long task_state(struct task_struct *p)
{
    if (bpf_core_field_exists(p->__state)) {
        return BPF_CORE_READ(p, __state);
    }
    return BPF_CORE_READ((struct task_struct___pre_5_14 *)p, state);
}

static __always_inline void mark_runnable(struct task_struct *p)
{
    if (!task_in_target_cgroup(p)) {
        return;
    }
    u32 tid = BPF_CORE_READ(p, pid);
    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start, &tid, &ts, BPF_ANY);
}

static __always_inline u64 log2_32(u32 v)
{
    u32 shift, r;
    r = (v > 0xFFFF) << 4; v >>= r;
    shift = (v > 0xFF) << 3; v >>= shift; r |= shift;
    shift = (v > 0xF) << 2; v >>= shift; r |= shift;
    shift = (v > 0x3) << 1; v >>= shift; r |= shift;
    r |= (v >> 1);
    return r;
}

static __always_inline u64 log2_64(u64 v)
{
    u32 hi = v >> 32;
    return hi ? log2_32(hi) + 32 : log2_32(v);
}

SEC("tp_btf/sched_wakeup")
int BPF_PROG(handle_sched_wakeup, struct task_struct *p)
{
    mark_runnable(p);
    return 0;
}

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(handle_sched_wakeup_new, struct task_struct *p)
{
    mark_runnable(p);
    return 0;
}

// sched_switch gained a trailing prev_state argument in 5.18; only the
// first three are declared here so this loads either way, and prev's state
// is read off the task instead.
SEC("tp_btf/sched_switch")
int BPF_PROG(handle_sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
    // prev being switched out while still TASK_RUNNING means it was
    // preempted (or yielded): it goes straight back on a run queue, so its
    // wait starts now. If it blocked instead, sched_wakeup starts it later.
    if (task_state(prev) == TASK_RUNNING) {
        mark_runnable(prev);
    }

    // No cgroup check needed for next: only target threads are in start.
    u32 tid = BPF_CORE_READ(next, pid);
    u64 *tsp = bpf_map_lookup_elem(&start, &tid);
    if (!tsp) {
        return 0;
    }
    s64 delta_ns = (s64)(bpf_ktime_get_ns() - *tsp);
    bpf_map_delete_elem(&start, &tid);
    if (delta_ns < 0) {
        return 0;
    }

    u32 key = 0;
    struct hist *h = bpf_map_lookup_elem(&hist, &key);
    if (!h) {
        return 0;
    }
    u64 slot = log2_64(delta_ns / 1000);
    if (slot >= MAX_SLOTS) {
        slot = MAX_SLOTS - 1;
    }
    // Per-CPU map, and preemption is disabled here - no atomics needed.
    h->slots[slot]++;
    h->total_ns += delta_ns;
    return 0;
}
