//go:build ignore

#define BPF_NO_GLOBAL_DATA
#include "../bpf/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef unsigned int u32;
typedef int pid_t;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);   // PID
    __type(value, u8);  // dummy (e.g. 1)
} pid_filter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
} events SEC(".maps");

struct event {
    u32 pid;
    char comm[16];
};

SEC("tracepoint/syscalls/sys_enter_write")
int handle_tp(struct trace_event_raw_sys_enter *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u8 *exists = bpf_map_lookup_elem(&pid_filter, &pid);
    if (!exists) {
        return 0;
    }

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->pid = pid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);

    return 0;
}