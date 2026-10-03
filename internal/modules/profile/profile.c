//go:build ignore

#define BPF_NO_GLOBAL_DATA
#include "../bpf/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../bpf/pidns.h"
#include "../bpf/stacks.h"

#define COMM_LEN 16

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} target_cgroup SEC(".maps");

// Must match countKey in profile.go. All 4-byte members, so no padding.
// The kernel stack id is -EFAULT for samples taken while running in user
// mode - there's no kernel stack to capture.
struct count_key {
    u32 tgid;
    s32 kern_stack_id;
    s32 user_stack_id;
    char comm[COMM_LEN];
};

// Number of samples per (process, thread name, stacks). Drained by
// userspace every interval, which then deletes the stack ids it used.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct count_key);
    __type(value, u64);
} counts SEC(".maps");

// Runs from the timer interrupt of a cpu-clock perf event (see profile.go),
// so the current task is whatever that CPU was running when it fired, and
// the stacks are where it was interrupted.
//
// The perf events are opened for the container's cgroup, so the kernel
// only lets them fire while one of its tasks is on the CPU. That makes this
// check almost always pass; it's kept to match the other modules' exact
// cgroup semantics, since cgroup perf events also cover child cgroups.
SEC("perf_event")
int handle_sample(struct bpf_perf_event_data *ctx)
{
    u32 zero = 0;
    u64 *target = bpf_map_lookup_elem(&target_cgroup, &zero);
    if (!target || bpf_get_current_cgroup_id() != *target) {
        return 0;
    }

    struct count_key key = {};
    key.tgid = agent_tgid((struct task_struct *)bpf_get_current_task());
    key.kern_stack_id = bpf_get_stackid(ctx, &stacks, 0);
    key.user_stack_id = bpf_get_stackid(ctx, &stacks, BPF_F_USER_STACK);
    bpf_get_current_comm(&key.comm, sizeof(key.comm));

    u64 *count = bpf_map_lookup_elem(&counts, &key);
    if (!count) {
        // Another CPU may insert the same key in between; BPF_NOEXIST
        // makes that a harmless failure, and the lookup below finds
        // whichever entry won.
        u64 init = 0;
        bpf_map_update_elem(&counts, &key, &init, BPF_NOEXIST);
        count = bpf_map_lookup_elem(&counts, &key);
        if (!count) {
            return 0;
        }
    }
    __sync_fetch_and_add(count, 1);
    return 0;
}
