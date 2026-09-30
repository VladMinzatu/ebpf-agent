//go:build ignore

#define BPF_NO_GLOBAL_DATA
#include "../bpf/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define COMM_LEN 16

// PERF_MAX_STACK_DEPTH, the most frames bpf_get_stackid() will capture.
#define MAX_STACK_DEPTH 127

// Kernel macros, so not in vmlinux.h.
#define TASK_RUNNING 0
#define TASK_INTERRUPTIBLE 0x1
#define TASK_UNINTERRUPTIBLE 0x2

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} target_cgroup SEC(".maps");

// Inode number of the agent's own pid namespace (/proc/self/ns/pid).
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} agent_pidns SEC(".maps");

// Stack id -> the stack's instruction pointers, leaf first. Identical
// stacks share an id, which is what makes aggregating by stack cheap:
// the counts key only carries the two ids, not the frames.
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 16384);
    __uint(key_size, sizeof(u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(u64));
} stacks SEC(".maps");

// What a thread was doing when it blocked, keyed by thread id. Captured at
// switch-out because that's the only time the blocking thread is current,
// which bpf_get_stackid() needs.
struct start_info {
    u64 ts;
    u32 tgid;
    u32 state;
    s32 kern_stack_id;
    s32 user_stack_id;
    char comm[COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct start_info);
} start SEC(".maps");

// Must match countKey in offcpu.go. All 4-byte members, so no padding.
// Stack ids are negative when a stack couldn't be captured (e.g. -EFAULT
// for the user stack of a kernel thread, -EEXIST if the stacks map had a
// hash collision).
struct count_key {
    u32 tgid;
    u32 state;
    s32 kern_stack_id;
    s32 user_stack_id;
    char comm[COMM_LEN];
};

// Must match countValue in offcpu.go.
struct count_value {
    u64 total_ns;
    u64 count;
};

// Userspace drains this every interval (lookup-and-delete each entry), and
// then deletes the stack ids it referenced from stacks - except ones still
// held in start by threads that are blocked right now. Otherwise both maps
// would keep growing with every distinct stack ever seen.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct count_key);
    __type(value, struct count_value);
} counts SEC(".maps");

// sched_switch runs in the context of prev, so the current cgroup is prev's.
// That works for the switch-out side; the switch-in side doesn't need a
// cgroup check, since only target threads are in start.
static __always_inline int in_target_cgroup(void)
{
    u32 key = 0;
    u64 *target = bpf_map_lookup_elem(&target_cgroup, &key);
    return target && bpf_get_current_cgroup_id() == *target;
}

// How deep a pid namespace hierarchy agent_tgid() searches. The kernel
// allows 32 levels; real setups use two or three (root, maybe a VM or
// Docker-in-a-container level, then the container).
#define MAX_PIDNS_LEVEL 8

// Returns p's process id as seen from the agent's pid namespace, or 0 if
// the process isn't visible there. bpf_get_current_pid_tgid() isn't enough:
// it returns pids in the kernel's root namespace, which isn't necessarily
// the agent's even with --pid=host (e.g. when Docker itself runs in a
// container, as on OrbStack or kind), and userspace needs a pid it can find
// in its own /proc to symbolize user stacks. (bpf_get_ns_current_pid_tgid()
// doesn't help either: it only works for tasks that live directly in the
// given namespace, and container processes live in a child of it.)
//
// A struct pid holds the process's number in every namespace from the root
// down to its own: numbers[i] is its pid at level i. So this walks those
// and returns the one whose namespace is the agent's.
static __always_inline u32 agent_tgid(struct task_struct *p)
{
    u32 key = 0;
    u64 *agent_ino = bpf_map_lookup_elem(&agent_pidns, &key);
    if (!agent_ino) {
        return 0;
    }
    struct pid *pid = BPF_CORE_READ(p, group_leader, thread_pid);
    unsigned int level = BPF_CORE_READ(pid, level);
    // numbers is a flexible array member, so only its start offset gets a
    // CO-RE relocation; indexing is plain pointer arithmetic from there.
    struct upid *numbers = &pid->numbers[0];
    for (int i = 0; i < MAX_PIDNS_LEVEL; i++) {
        if (i > level) {
            break;
        }
        struct upid upid;
        if (bpf_probe_read_kernel(&upid, sizeof(upid), numbers + i)) {
            return 0;
        }
        if (BPF_CORE_READ(upid.ns, ns.inum) == *agent_ino) {
            return upid.nr;
        }
    }
    return 0;
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

// sched_switch gained a trailing prev_state argument in 5.18; only the
// first three are declared so this loads either way (see runqlat.c).
SEC("tp_btf/sched_switch")
int BPF_PROG(handle_sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
    // Switch-out: only threads that are going to sleep. A thread switched
    // out while still TASK_RUNNING was preempted - that wait is run queue
    // latency (see the runqlat module), not blocking. Exiting threads
    // (TASK_DEAD) never come back, so they're skipped too.
    long state = task_state(prev);
    if ((state & (TASK_INTERRUPTIBLE | TASK_UNINTERRUPTIBLE)) && in_target_cgroup()) {
        struct start_info info = {};
        info.ts = bpf_ktime_get_ns();
        info.tgid = agent_tgid(prev);
        // TASK_KILLABLE and friends include the UNINTERRUPTIBLE bit, so
        // they're reported as uninterruptible, same as ps's "D".
        info.state = (state & TASK_UNINTERRUPTIBLE) ? TASK_UNINTERRUPTIBLE : TASK_INTERRUPTIBLE;
        info.kern_stack_id = bpf_get_stackid(ctx, &stacks, 0);
        info.user_stack_id = bpf_get_stackid(ctx, &stacks, BPF_F_USER_STACK);
        bpf_get_current_comm(&info.comm, sizeof(info.comm));
        u32 tid = BPF_CORE_READ(prev, pid);
        bpf_map_update_elem(&start, &tid, &info, BPF_ANY);
    }

    // Switch-in: the off-CPU period ends. This includes the time spent
    // runnable after the wakeup, waiting for a CPU, as BCC's offcputime does.
    u32 tid = BPF_CORE_READ(next, pid);
    struct start_info *info = bpf_map_lookup_elem(&start, &tid);
    if (!info) {
        return 0;
    }
    s64 delta_ns = (s64)(bpf_ktime_get_ns() - info->ts);

    struct count_key key = {};
    key.tgid = info->tgid;
    key.state = info->state;
    key.kern_stack_id = info->kern_stack_id;
    key.user_stack_id = info->user_stack_id;
    __builtin_memcpy(key.comm, info->comm, sizeof(key.comm));
    bpf_map_delete_elem(&start, &tid);
    if (delta_ns < 0) {
        return 0;
    }

    struct count_value *val = bpf_map_lookup_elem(&counts, &key);
    if (!val) {
        // Another CPU may insert the same key in between; BPF_NOEXIST
        // makes that a harmless failure, and the lookup below finds
        // whichever entry won.
        struct count_value zero = {};
        bpf_map_update_elem(&counts, &key, &zero, BPF_NOEXIST);
        val = bpf_map_lookup_elem(&counts, &key);
        if (!val) {
            return 0;
        }
    }
    // Unlike runqlat's per-CPU histogram, this map is shared across CPUs.
    __sync_fetch_and_add(&val->total_ns, delta_ns);
    __sync_fetch_and_add(&val->count, 1);
    return 0;
}
