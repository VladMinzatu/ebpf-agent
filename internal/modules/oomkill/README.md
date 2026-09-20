# oomkill

Reports processes killed by the kernel OOM killer, filtered by container
(via cgroup ID). Attaches to the `oom/mark_victim` tracepoint, which fires
once the kernel has picked its victim, and reports it as a
`{pid, comm, total_vm_pages, oom_score_adj}` event.

This only sees the victim, not whichever process triggered the allocation
that led to the kill - that "killer" side (plus the memcg constraint and
pages freed) would need a kprobe on `oom_kill_process()` instead, at the
cost of depending on a kernel-internal function signature instead of a
stable tracepoint ABI. Not implemented here; see the comment in
[`oomkill.c`](oomkill.c).

## Flags

- `-container <id>` (required) — container ID, full or a unique prefix, to
  report OOM kills for.

## Example

```
ebpf-agent oomkill -container 4d7d4bab813f
```

```json
{"Module":"oomkill","Timestamp":"2026-09-20T14:18:37.042253502Z","Data":{"comm":"oom-eater","oom_score_adj":0,"pid":30012,"total_vm_pages":1291704}}
```

See [`examples/oom-eater`](examples/oom-eater) for a runnable workload to
test this against.
