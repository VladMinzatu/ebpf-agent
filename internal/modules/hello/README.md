# hello

Filters `sys_enter_write` syscalls by container (via cgroup ID) and
reports each match as a `{pid, comm}` event. The reference module — the
template to copy when starting a new one.

## Flags

- `-container <id>` (required) — container ID, full or a unique prefix, to
  report writes for.

## Example

```
ebpf-agent hello -container 4d7d4bab813f
```

```json
{"Module":"hello","Timestamp":"2026-08-22T13:34:12.933187459Z","Data":{"comm":"writer","pid":85822}}
```

See [`examples/go-writer`](examples/go-writer) for a runnable workload to
test this against.
