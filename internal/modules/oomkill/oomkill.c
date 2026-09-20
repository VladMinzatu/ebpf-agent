//go:build ignore

#define BPF_NO_GLOBAL_DATA
#include "../bpf/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef unsigned int u32;
typedef unsigned long long u64;

#define COMM_LEN 16

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} target_cgroup SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
} events SEC(".maps");

// Field order matters: it's laid out to match the C compiler's natural
// alignment (widest members first) with no padding gaps, since the Go side
// decodes this with encoding/binary, which reads fields back-to-back and
// knows nothing about C struct padding.
struct event {
    u64 total_vm;
    u32 pid;
    short oom_score_adj;
    char comm[COMM_LEN];
};

// Fires from mark_oom_victim() once the kernel has picked its OOM victim,
// just before the kill signal is sent. This only sees the victim - the
// pid/comm of whichever task triggered the allocation/reclaim that led here
// isn't available from this tracepoint. Getting the "killer" side (plus
// the memcg constraint and pages freed, the way inspektor-gadget's
// trace_oomkill gadget does) would mean a kprobe on oom_kill_process()
// instead, trading this tracepoint's stable ABI (include/trace/events/oom.h)
// for a kernel-internal function signature that can change across versions.
SEC("tracepoint/oom/mark_victim")
int handle_tp(struct trace_event_raw_mark_victim *ctx)
{
    u32 key = 0;
    u64 *target = bpf_map_lookup_elem(&target_cgroup, &key);
    if (!target) {
        return 0;
    }

    // mark_oom_victim runs in the context of the task whose allocation
    // triggered the reclaim, which for a memcg-scoped OOM (the common
    // containerized case) is a task inside the cgroup that hit its limit -
    // same assumption CgroupID-based filtering relies on elsewhere.
    if (bpf_get_current_cgroup_id() != *target) {
        return 0;
    }

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->pid = ctx->pid;
    e->total_vm = ctx->total_vm;
    e->oom_score_adj = ctx->oom_score_adj;

    u32 loc = ctx->__data_loc_comm;
    bpf_probe_read_kernel_str(&e->comm, sizeof(e->comm), (char *)ctx + (loc & 0xffff));

    bpf_ringbuf_submit(e, 0);

    return 0;
}
