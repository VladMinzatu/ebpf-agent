//go:build ignore

#define BPF_NO_GLOBAL_DATA
#include "../bpf/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

#define COMM_LEN 16

// Not in vmlinux.h - these are macros, and BTF only carries types.
#define AF_INET 2
#define AF_INET6 10

#define EVENT_CONNECT 0
#define EVENT_ACCEPT 1
#define EVENT_CLOSE 2

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} target_cgroup SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} events SEC(".maps");

// Field order matters: it's laid out widest members first so there are no
// padding gaps, since the Go side decodes this with encoding/binary, which
// reads fields back-to-back and knows nothing about C struct padding.
// Addresses are raw network-order bytes; for IPv4 only the first 4 are used.
// Ports are host order.
struct event {
    u64 bytes_acked;
    u64 bytes_received;
    u8 saddr[16];
    u8 daddr[16];
    u32 pid;
    u16 family;
    u16 sport;
    u16 dport;
    u8 type;
    char comm[COMM_LEN];
};

// All hooks below run in the context of the process doing the
// connect/accept/close syscall, so the current task's cgroup is the one to
// filter on - same as the other modules. That's why this uses function
// hooks rather than the stable sock/inet_sock_set_state tracepoint: some of
// those state transitions (e.g. SYN_RECV -> ESTABLISHED on the server side)
// happen in softirq, where the current task is whatever got interrupted.
static __always_inline int in_target_cgroup(void)
{
    u32 key = 0;
    u64 *target = bpf_map_lookup_elem(&target_cgroup, &key);
    return target && bpf_get_current_cgroup_id() == *target;
}

// An IPv6 socket talking to an IPv4 peer (a dual-stack listener, or
// connect() to an IPv4 address on an AF_INET6 socket) carries the peer as
// ::ffff:a.b.c.d. The kernel keeps the plain IPv4 fields up to date for
// these too, so they get reported as IPv4.
static __always_inline int is_v4_mapped(struct in6_addr *a)
{
    return a->in6_u.u6_addr32[0] == 0 &&
           a->in6_u.u6_addr32[1] == 0 &&
           a->in6_u.u6_addr32[2] == bpf_htonl(0xffff);
}

static __always_inline void submit(struct sock *sk, u8 type)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return;
    }
    __builtin_memset(e, 0, sizeof(*e));

    e->type = type;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    e->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    struct in6_addr daddr6 = BPF_CORE_READ(sk, __sk_common.skc_v6_daddr);
    if (BPF_CORE_READ(sk, __sk_common.skc_family) == AF_INET6 && !is_v4_mapped(&daddr6)) {
        e->family = AF_INET6;
        BPF_CORE_READ_INTO(&e->saddr, sk, __sk_common.skc_v6_rcv_saddr);
        __builtin_memcpy(e->daddr, &daddr6, sizeof(daddr6));
    } else {
        e->family = AF_INET;
        BPF_CORE_READ_INTO((u32 *)e->saddr, sk, __sk_common.skc_rcv_saddr);
        BPF_CORE_READ_INTO((u32 *)e->daddr, sk, __sk_common.skc_daddr);
    }

    if (type == EVENT_CLOSE) {
        struct tcp_sock *tp = (struct tcp_sock *)sk;
        e->bytes_acked = BPF_CORE_READ(tp, bytes_acked);
        e->bytes_received = BPF_CORE_READ(tp, bytes_received);
    }

    bpf_ringbuf_submit(e, 0);
}

// tcp_v{4,6}_connect() pick the source address/port and send the SYN, so by
// the time they return the 4-tuple is complete. fexit sees both the
// arguments and the return value, so no entry/exit correlation is needed.
// A 0 return means the SYN went out, not that the handshake completed -
// non-blocking sockets (e.g. every Go net.Conn) get EINPROGRESS higher up.
SEC("fexit/tcp_v4_connect")
int BPF_PROG(handle_connect_v4, struct sock *sk, struct sockaddr *uaddr, int addr_len, int ret)
{
    if (ret != 0 || !in_target_cgroup()) {
        return 0;
    }
    submit(sk, EVENT_CONNECT);
    return 0;
}

SEC("fexit/tcp_v6_connect")
int BPF_PROG(handle_connect_v6, struct sock *sk, struct sockaddr *uaddr, int addr_len, int ret)
{
    if (ret != 0 || !in_target_cgroup()) {
        return 0;
    }
    // A v4-mapped destination makes tcp_v6_connect() call tcp_v4_connect()
    // internally, which already reported it.
    struct in6_addr daddr6 = BPF_CORE_READ(sk, __sk_common.skc_v6_daddr);
    if (is_v4_mapped(&daddr6)) {
        return 0;
    }
    submit(sk, EVENT_CONNECT);
    return 0;
}

// inet_csk_accept()'s parameters changed in 6.10 (flags/err/kern folded
// into a struct proto_accept_arg *), and fexit's return value sits right
// after the last parameter - so rather than declaring a signature that only
// matches some kernels, read the return value with bpf_get_func_ret().
SEC("fexit/inet_csk_accept")
int BPF_PROG(handle_accept)
{
    u64 ret = 0;
    bpf_get_func_ret(ctx, &ret);
    struct sock *sk = (struct sock *)ret;
    if (!sk || !in_target_cgroup()) {
        return 0;
    }
    submit(sk, EVENT_ACCEPT);
    return 0;
}

// tcp_close() runs from close() (or process exit) on any TCP socket,
// including listeners and ones that never connected - those have no peer,
// so skip them.
SEC("fentry/tcp_close")
int BPF_PROG(handle_close, struct sock *sk, long timeout)
{
    if (!in_target_cgroup()) {
        return 0;
    }
    if (BPF_CORE_READ(sk, __sk_common.skc_dport) == 0) {
        return 0;
    }
    submit(sk, EVENT_CLOSE);
    return 0;
}
