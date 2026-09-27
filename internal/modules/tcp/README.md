# tcp

Reports TCP connections made and received by a container, filtered by
cgroup ID - modeled on inspektor-gadget's `trace_tcp` gadget. Emits one
event per:

- `connect` - an outgoing connection's SYN was sent (`tcp_v4_connect()` /
  `tcp_v6_connect()` returned successfully). This is not "handshake
  completed": a refused or timed-out connection still shows up here.
- `accept` - an incoming connection was handed to the process
  (`inet_csk_accept()` returned a socket).
- `close` - a connected socket was closed (`tcp_close()`), with
  `bytes_acked` / `bytes_received` totals for its lifetime (read from
  `struct tcp_sock`; they may be off by one from the payload size since the
  kernel counts the FIN/SYN sequence numbers). Listening sockets and
  sockets that never had a peer are skipped.

Each event has `{type, pid, comm, saddr, sport, daddr, dport}` from the
point of view of the traced process (`saddr`/`sport` are always the local
end). IPv4 peers of IPv6 sockets (`::ffff:a.b.c.d`, e.g. anything
accepted by a Go server listening on `:8080`) are reported as plain IPv4.

## How it hooks in, and why

All three hooks run in the context of the process doing the syscall, so
the usual `bpf_get_current_cgroup_id()` filter works. The obvious
alternative - the stable `sock/inet_sock_set_state` tracepoint - doesn't
have that property: some transitions (e.g. SYN_RECV -> ESTABLISHED on the
server side) happen in softirq, where the "current" task is whatever
happened to be interrupted, and the socket's own cgroup would have to be
read instead.

The hooks are `fentry`/`fexit` (BPF trampolines, kernel 5.5+ on x86, 6.0+
on arm64) rather than kprobes:

- `fexit` sees a function's arguments *and* its return value, so the
  connect hooks don't need a kprobe/kretprobe pair correlated through a
  per-thread map.
- Arguments are read from the trampoline's context, not from `pt_regs`,
  so the BPF code isn't tied to the architecture `vmlinux.h` was dumped
  on.

Either way, these are kernel-internal functions, not a stable ABI. One
signature change is already handled: `inet_csk_accept()`'s parameters
changed in 6.10, so its return value is read with `bpf_get_func_ret()`
rather than by position. See [`tcp.c`](tcp.c) for details.

## Flags

- `-container <id>` (required) — container ID, full or a unique prefix, to
  trace TCP connections for.
- `-events <list>` — comma-separated subset of `connect,accept,close` to
  report (default: all). Programs for unselected event types aren't
  attached at all.

## Example

```
ebpf-agent tcp -container 9e64f2896716
```

```json
{"Module":"tcp","Timestamp":"2026-09-27T14:27:33.094484391Z","Data":{"comm":"tcp-pinger","daddr":"127.0.0.1","dport":8080,"pid":74515,"saddr":"127.0.0.1","sport":58388,"type":"connect"}}
{"Module":"tcp","Timestamp":"2026-09-27T14:27:33.094518849Z","Data":{"comm":"tcp-pinger","daddr":"127.0.0.1","dport":58388,"pid":74515,"saddr":"127.0.0.1","sport":8080,"type":"accept"}}
{"Module":"tcp","Timestamp":"2026-09-27T14:27:33.094977433Z","Data":{"bytes_acked":140,"bytes_received":114,"comm":"tcp-pinger","daddr":"127.0.0.1","dport":58388,"pid":74515,"saddr":"127.0.0.1","sport":8080,"type":"close"}}
```

See [`examples/tcp-pinger`](examples/tcp-pinger) for a runnable workload
to test this against.
