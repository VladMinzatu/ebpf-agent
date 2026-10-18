//go:build ignore

#define BPF_NO_GLOBAL_DATA
#include "../bpf/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../bpf/pidns.h"

#define COMM_LEN 16

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Must match watchCfg in watch.go. The address the breakpoints are on, and
// how many bytes they cover (1, 2, 4 or 8).
struct watch_cfg {
    u64 addr;
    u64 len;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct watch_cfg);
} watch_cfg SEC(".maps");

// Must match event in watch.go. No padding: two u32s after the u64.
struct event {
    u64 value;
    u32 pid;
    u32 tid;
    char comm[COMM_LEN];
};

// One record per write, read by userspace as they come.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Runs on every hit of a hardware write breakpoint (see watch.go). The trap
// is synchronous, so the current task is the thread that writes. When it
// fires depends on the architecture: on x86 it's after the write, so the
// address holds the new value; on arm64 it's before the store executes
// (the kernel single-steps it afterwards), so the address still holds the
// old one.
SEC("perf_event")
int handle_write(struct bpf_perf_event_data *ctx)
{
    u32 zero = 0;
    struct watch_cfg *cfg = bpf_map_lookup_elem(&watch_cfg, &zero);
    if (!cfg) {
        return 0;
    }
    // The mask is for the verifier, which otherwise loses the lower bound
    // of len by the time it's passed to bpf_probe_read_user.
    u32 len = cfg->len & 0xf;
    if (len > 8) {
        return 0;
    }

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }
    // A short value lands in the low bytes of e->value on little-endian
    // (amd64, arm64); big-endian targets aren't handled.
    e->value = 0;
    bpf_probe_read_user(&e->value, len, (void *)cfg->addr);
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->pid = agent_tgid(task);
    e->tid = agent_tid(task);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}
