# watch — plan

> Status: design notes, nothing implemented yet. Once the module exists,
> this should turn into its `README.md` (same shape as the other modules'),
> and the parts that only matter for building it can go.

A hardware watchpoint module: "which code changed this memory, when, and
to what?" for a process in a container, live, without pausing it or
modifying its code.

```
$ make docker-run ARGS="watch -container 4d7d4bab813f -pid 4312 -sym main.cfg.MaxConns -when 'new == 0'"
```

```json
{"module":"watch","data":{"tid":4377,"pid":4312,"comm":"server","goid":87,
  "addr":"0x6f3a10","old":100,"new":0,
  "user_stack":["main.(*Admin).reset+0x44","main.handleAdmin+0x120","net/http.HandlerFunc.ServeHTTP"],
  "kernel_stack":[]}}
```

It's the second `perf_event` module after `profile`, but the event is a
**debug register** rather than a clock (`PERF_TYPE_BREAKPOINT`), and it
would be the first module to **stream events through a `RINGBUF`**. Every
other module aggregates in maps and drains them on an interval.

## How it works

The module asks the kernel for a hardware breakpoint on an address in the
target process (`perf_event_open`, `PERF_TYPE_BREAKPOINT`,
`bp_type = HW_BREAKPOINT_W`). The CPU traps on every write to that address,
and the BPF program attached to the event runs on each hit:

- read the new value (`bpf_probe_read_user`);
- compare it with the last value it saw, and drop writes that leave the
  value unchanged and writes that don't match `-when`;
- capture pid/tid/comm, the instruction pointer, and user and kernel stacks;
- emit one record to a ringbuf.

The Go side reads the ringbuf, symbolizes the stacks and publishes one
`agent.Event` per write.

Compared with gdb's `watch`: gdb stops the process on every hit, and each
round-trip through ptrace costs tens of microseconds or more. Here a hit
costs roughly a trap plus about a microsecond of BPF, and the condition is
evaluated in the kernel, so it's usable on a live service.

## Use cases

1. **Memory corruption.** Find who overwrites a struct field, a canary, or
   the guard word just past a buffer.
2. **Unexpected mutation.** Find who changes a global config or flag that's
   supposed to be set once. Report every writer's thread and stack.
3. **Lock-discipline checking.** On each write to a protected field, also
   read the mutex word at a known address and emit a violation if it isn't
   held. A small, targeted race detector that doesn't need `-race`.
4. **State-machine timelines.** Watch e.g. `conn.state` and get a
   time-ordered log of every transition, with stacks. The ringbuf's global
   ordering is what keeps this timeline consistent across threads.
5. **"Find out what writes to this address".** Useful when exploring an
   unfamiliar codebase.
6. **The kernel as the writer.** Writes the kernel makes to the address,
   e.g. `read()`/`recv()` copying into the buffer via `copy_to_user`, can
   trap too, depending on privileges and `exclude_kernel`. The kernel stack
   then shows which syscall did it.
7. **Kernel variables** (root, system-wide). Watch a kernel field by its
   address from `/proc/kallsyms` on every CPU. Out of scope for a
   container-scoped module, but it's the same mechanism.
8. **Execute breakpoints** (`HW_BREAKPOINT_X`). Trace hits on one
   instruction without patching code. uprobes write an `int3` into a
   copy-on-write page, which can break text checksums or anti-tamper
   checks; a debug register doesn't touch the code.

## Architecture

```
 userspace (Go)                                kernel
┌──────────────────────────┐
│ resolver: ELF/DWARF +    │  sym → addr
│ /proc/pid/maps (PIE base)│
├──────────────────────────┤  perf_event_open(BREAKPOINT, tid, addr, len)
│ arming: one event per    │──────────────────────────────►  debug register DR0-3
│ thread (+ inherit)       │  attach prog (BPF perf link)
├──────────────────────────┤                                       │ write trap
│ config → array maps      │                              ┌────────▼─────────┐
├──────────────────────────┤      RINGBUF records         │ BPF perf_event   │
│ reader + symbolizer      │◄─────────────────────────────│ prog: read value,│
│ (internal/stacks)        │                              │ filter, stacks   │
└──────────────────────────┘                              └──────────────────┘
```

### Fitting the repo

- **Targeting.** Accept `-container` like every other module. Then add
  `-pid` (host pid, which needs `--pid=host` like `offcpu`/`profile`) or
  `-comm` to pick the process inside it. Validate that the pid's cgroup
  matches `agent.CgroupID(container)`, so the module can't be pointed at
  something outside the container. Unlike `profile`, the events are opened
  **per thread**, not per cgroup: a breakpoint on a user address only means
  something in one address space.
- **Pids.** Report pids in the agent's pid namespace via `pidns.h`
  (`agent_tgid`), so `/proc` lookups for symbolization work.
- **Stacks.** There are two options:
  - **Reuse `stacks.h` + `internal/stacks`** (recommended first): the BPF
    program calls `bpf_get_stackid` into the shared `stacks` map, the record
    carries the two ids, and Go uses `Resolver.UserFrames/KernelFrames` and
    then `Delete`s the ids once it has emitted them. Nothing new to write on
    the symbolization side.
  - **Raw stacks inside the ringbuf record** (`bpf_get_stack` straight into
    reserved ring memory). This is the zero-copy reserve/commit pattern, and
    each record is self-contained, with no risk of a full stack map
    (`-EEXIST`). The cost is about 1 KB per record, plus resolver entry
    points that take raw IPs rather than ids (`Resolver.ips` already exists
    internally). A natural second step, and the more interesting one to
    learn from.
- **Config.** The other modules pass config through array maps at key 0
  (`TargetCgroup`, `AgentPidns`). Do the same here (`watch_cfg`: addr, len,
  predicate op/value), or switch to `.rodata` constants set before load
  (`const volatile`), which lets the verifier drop branches for predicates
  that aren't used.
- **Attach.** Use `link.AttachRawLink(..., ebpf.AttachPerfEvent)` per fd,
  as in `profile` (kernel 5.15+). The perf-event-opening code will be close
  to `profile/perf.go`. If a third perf module turns up, move it into a
  shared package.

### BPF side (sketch)

```c
struct event {
    u64 ts, old, new_val, ip;
    u32 pid, tid, cpu;
    u64 goid;                         // optional, Go targets
    s32 user_stack_id, kern_stack_id; // option A: ids into stacks.h
    // option B: s32 ustack_len, kstack_len; u64 ustack[64], kstack[32];
    char comm[16];
};

struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1 << 20); } events SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1); __type(key, u32); __type(value, u64); } last SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1); __type(key, u32); __type(value, u64); } drops SEC(".maps");

SEC("perf_event")
int on_write(struct bpf_perf_event_data *ctx) {
    u64 nv = 0; u32 k = 0;
    bpf_probe_read_user(&nv, cfg_len, (void *)cfg_addr);
    u64 *ov = bpf_map_lookup_elem(&last, &k);
    if (!ov || *ov == nv) { if (ov) *ov = nv; return 0; }   // unchanged value
    if (!pred_match(*ov, nv)) { *ov = nv; return 0; }

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) { u64 *d = bpf_map_lookup_elem(&drops, &k); if (d) (*d)++; *ov = nv; return 0; }
    e->old = *ov; e->new_val = nv; *ov = nv;
    e->ts = bpf_ktime_get_ns(); e->ip = PT_REGS_IP(&ctx->regs);
    /* pid via agent_tgid(), tid, cpu, comm, optional goid */
    e->user_stack_id = bpf_get_stackid(ctx, &stacks, BPF_F_USER_STACK);
    e->kern_stack_id = bpf_get_stackid(ctx, &stacks, 0);
    bpf_ringbuf_submit(e, 0);
    return 0;
}
```

- `last` is a best-effort old value. If two threads write within
  nanoseconds of each other, the old → new pairs can interleave. That's
  acceptable for a debugging tool, and a real data race is exactly what
  you'd want to see.
- Ringbuf losses are invisible to userspace unless the BPF program counts
  them, hence `drops`. Report them in the output (e.g. a periodic summary
  event, or a `dropped_since_last` field).
- The default adaptive wakeup is right at this event rate: roughly one
  wakeup per write, which is what an interactive tool wants.

### Userspace side

1. **Resolve the target address.**
   - Globals: the ELF symbol table (`debug/elf`), e.g. `main.cfg`.
   - Field paths (`main.cfg.MaxConns`): field offsets from `debug/dwarf`.
   - PIE binaries: add the load base from `/proc/<pid>/maps`.
   - Or a raw `-addr 0x...`.
2. **Arm the breakpoint on every thread.** One event per existing thread in
   `/proc/<pid>/task/*` (`pid = tid, cpu = -1`), with `attr.inherit = 1` so
   threads created later inherit the event and the attached program. Go
   creates OS threads dynamically, so this matters. Settings:
   `sample_period = 1`, `bp_type = HW_BREAKPOINT_W` (or `RW` with `-rw`),
   `bp_len` of 1/2/4/8 bytes, naturally aligned.
3. **Read** with `ringbuf.NewReader` + `ReadInto` (reusing the buffer, so no
   allocation per record), decode, symbolize, and publish an `agent.Event`.
   `Close()` closes the reader (which unblocks `Read`), the links and the
   perf fds.

## Things to watch out for

- **Only 4 slots.** x86 has 4 debug registers (DR0–3) per thread, and gdb
  and perf compete for the same ones. arm64 usually has 2–16 watchpoints.
  Each slot watches at most 8 aligned bytes, so it's one field, not a
  struct.
- **x86 reports the hit after the write.** Data breakpoints trap *after*
  the writing instruction, so `regs->ip` points at the *next* instruction.
  x86 instructions are variable-length, so you can't just step back one:
  disassemble from the function start (from the symbol) to find the
  instruction before `ip`, or report "just before ip". On arm64 the kernel
  single-steps the instruction, so the reported ip is the writer.
- **Every write traps, including writes of the same value.** Hot variables
  can trap millions of times per second and slow the target. Add a
  token-bucket rate limit in BPF, and a summary mode (`-summary`) that
  aggregates into `stacks` + `HASH(stack ids → count)` instead of streaming
  and reports the top writers on an interval. That's the same shape as
  `profile`/`offcpu`, so `stacks.Drain` can be reused.
- **User stacks need frame pointers.** Go has them on amd64 and arm64. Many
  C/C++ binaries don't (recent Fedora/Ubuntu builds enable them again).
  Same limitation as in the offcpu README's symbolization section.
- **Go specifics.**
  - Goroutine stacks move when they grow, so only globals and heap objects
    can be watched, not stack variables. Go's GC doesn't move heap objects,
    so heap addresses stay stable.
  - Goroutine id: in Go code with the register ABI, `R14` (amd64) / `R28`
    (arm64) holds the current `g`. Read `goid` at its DWARF offset in
    `runtime.g`. In runtime or cgo frames the register may not hold `g`,
    so treat it as best-effort.
- **Heap objects need arming at runtime.** You don't know the address in
  advance. A uprobe on the constructor (e.g. `newConn`) can send "arm addr
  X" to userspace through a second ringbuf, and userspace then calls
  `perf_event_open`. BPF can't create perf events itself, so there's a short
  window where early writes are missed.
- **Permissions.** `CAP_PERFMON` + `CAP_BPF`, which `--privileged` covers.
- **Docker on macOS.** Docker Desktop / OrbStack run an arm64 Linux VM on
  Apple Silicon, and it's not clear that guest hardware watchpoints are
  exposed there. **Check first**, e.g. with
  `perf stat -e mem:0x<addr>:w -p <pid>` in a privileged container, or by
  having the module's first milestone fail loudly on `perf_event_open`
  (`ENODEV`/`ENOSPC`/`EINVAL`). If they don't work, use a cloud VM or a
  bare-metal Linux box.

## Flags (proposed)

- `-container <id>` (required) — container ID, full or a unique prefix.
- `-pid <pid>` / `-comm <name>` — the process inside the container.
- `-sym <name[.field...]>` or `-addr <hex>` — what to watch.
- `-len <1|2|4|8>` — bytes to watch (default: the DWARF type size, else 8).
- `-rw` — trap on reads too (x86 has no read-only watchpoints).
- `-when '<expr>'` — kernel-side condition on `old`/`new`, e.g. `new == 0`,
  `new > 1000`, `changed`.
- `-kstack` — also capture kernel stacks.
- `-summary` + `-interval` — aggregate top writers instead of streaming.
- `-rate <n/s>` — cap on records per second (BPF token bucket).

## Milestones

1. `examples/go-counter/`: a tiny Go target with a global
   `var counter int64` that a goroutine bumps every second, packaged like
   the other examples.
2. Watch one raw address on one thread and print tid + new value. This step
   also tells you whether watchpoints work in the Docker VM.
3. Add user stacks via `stacks.h` + `internal/stacks`, and `-sym` for
   globals.
4. Cover all threads: per-tid events plus `inherit`.
5. Add old → new tracking and `-when` predicates in the kernel, plus drop
   reporting.
6. Add DWARF field paths (`main.cfg.MaxConns`) and goroutine ids.
7. Add `-kstack`, to catch writes made inside syscalls (an example with
   `read()` into a watched buffer).
8. Add `-summary` and `-rate`.
9. Switch to raw stacks in the ringbuf record (zero-copy reserve) and
   compare against stack ids.
10. Stretch: arm watches on heap objects from a uprobe on their
    constructor, and the lock-discipline check.

## Background: why RINGBUF here

This is low-volume (one record per interesting write), and records from
different threads need a coherent order, so the ringbuf beats
`PERF_EVENT_ARRAY`:

- one shared buffer and one fd instead of one per CPU;
- global ordering (by reservation order) across CPUs;
- reserve/commit, so records (and with option B, stacks) are written in
  place;
- drops are visible to the BPF program, which can count them;
- per-record wakeup control (`BPF_RB_NO_WAKEUP`/`FORCE_WAKEUP`,
  `bpf_ringbuf_query`).

What userspace does with it: one RW mmap of the `consumer_pos` page, and
one RO mmap of the `producer_pos` page plus the data pages, which are mapped
twice so records never wrap. Records are read with plain loads from shared
pages, with no copy in the kernel. cilium/ebpf copies each record into
`Record.RawSample` in userspace. epoll on the map fd is only used to sleep
when the ring is empty. The writable `consumer_pos` page is safe: it's on
its own page, the kernel only uses it in a free-space check, and the
mmap handler refuses write access to the rest (`VM_MAYWRITE` cleared).

Perfbuf would be the better choice for very high-rate NMI sources on many
cores: there ringbuf reservation is a `trylock` that can fail under
contention, while perfbuf's per-CPU buffers never contend. It would also be
the choice for flight-recorder (overwrite) semantics. Neither applies here.
