# hello

Filters `sys_enter_write` syscalls by PID and reports each match as a
`{pid, comm}` event. The reference module — the template to copy when
starting a new one.

## Flags

- `-target-pid <int>` (required) — PID to report writes for.

## Example

```
ebpf-agent hello -target-pid 12345
```

```json
{"Module":"hello","Timestamp":"2026-08-22T09:53:21.011248344Z","Data":{"comm":"myproc","pid":12345}}
```

See [`examples/go-writer`](examples/go-writer) for a runnable workload to
test this against, and the main README's "Testing modules" section for a
platform caveat that affects how you find the right PID.
