//go:build ignore

#define BPF_NO_GLOBAL_DATA
#include "../../bpf/vmlinux.h"
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

SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    u8 *exists = bpf_map_lookup_elem(&pid_filter, &pid);
    if (!exists) {
        return 0; // not in filter → ignore
    }
    bpf_printk("BPF triggered sys_enter_write from PID %d.\n", pid);
    return 0;
}