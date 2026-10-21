//go:build ignore

#define BPF_NO_GLOBAL_DATA
#include "../bpf/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../bpf/pidns.h"

#define COMM_LEN 16

// PERF_MAX_STACK_DEPTH, as MAX_STACK_DEPTH in ../bpf/stacks.h (not included
// here: this module doesn't use its stack map). Must match stacks.MaxDepth.
#define MAX_STACK_DEPTH 127

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

// Must match event in watch.go. No padding: everything before user_stack is
// a multiple of 8 bytes.
//
// The user stack is captured into the record itself rather than into a
// stack map by id. Records are streamed, not aggregated, so ids would have
// to be deleted as records are read, and two records still in the ring
// with the same id would race with that.
struct event {
    u64 value;
    // arm64's link register (x30) at the write, 0 on other architectures.
    // See handle_write.
    u64 lr;
    u32 pid;
    u32 tid;
    char comm[COMM_LEN];
    // Bytes of user_stack bpf_get_stack() filled, or a negative error.
    s64 user_stack_size;
    u64 user_stack[MAX_STACK_DEPTH];
};

// One record per write, read by userspace as they come. About 1KB each,
// mostly stack.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
} events SEC(".maps");

// arm64's struct pt_regs, as far as the general-purpose registers. It's a
// CO-RE "flavor": the ___arm64 suffix is ignored when it's matched against
// the running kernel's struct pt_regs, and on other architectures, whose
// pt_regs has no regs array, bpf_core_field_exists() is false and the read
// is dropped at load time.
struct pt_regs___arm64 {
    u64 regs[31];
} __attribute__((preserve_access_index));

// Returns the current task's x30 at the time it trapped into the kernel, or
// 0 if this isn't arm64.
static __always_inline u64 link_register(void)
{
    struct pt_regs___arm64 *regs = (void *)bpf_task_pt_regs(bpf_get_current_task_btf());
    if (!bpf_core_field_exists(regs->regs)) {
        return 0;
    }
    return BPF_CORE_READ(regs, regs[30]);
}

// Runs on every hit of a hardware write breakpoint (see watch.go). The trap
// is synchronous, so the current task is the thread that writes. When it
// fires depends on the architecture: on x86 it's after the write, so the
// address holds the new value; on arm64 it's before the store executes
// (the kernel single-steps it afterwards), so the address still holds the
// old one.
//
// The user stack is unwound by following frame pointers, which skips the
// caller of a leaf function on arm64: a leaf doesn't save its return
// address, it stays in x30. That's common for a write (setters, small
// helpers), so x30 goes into the record too, and userspace puts the caller
// back (see insertCaller in watch.go).
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
    e->lr = link_register();
    e->user_stack_size = bpf_get_stack(ctx, e->user_stack, sizeof(e->user_stack), BPF_F_USER_STACK);
    bpf_ringbuf_submit(e, 0);
    return 0;
}
