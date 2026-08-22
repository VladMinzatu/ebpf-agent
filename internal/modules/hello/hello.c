//go:build ignore

#define BPF_NO_GLOBAL_DATA
#include "../bpf/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef unsigned int u32;
typedef unsigned long long u64;
typedef int pid_t;

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

struct event {
    u32 pid;
    char comm[COMM_LEN];
};

SEC("tracepoint/syscalls/sys_enter_write")
int handle_tp(struct trace_event_raw_sys_enter *ctx)
{
    u32 key = 0;
    u64 *target = bpf_map_lookup_elem(&target_cgroup, &key);
    if (!target) {
        return 0;
    }

    if (bpf_get_current_cgroup_id() != *target) {
        return 0;
    }

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);

    return 0;
}
