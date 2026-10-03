# profile

A sampling CPU profiler for one container: a fixed number of times per
second of the container's CPU time, it records where the running thread
was - kernel and user stack - and reports the hottest stacks
periodically, modeled on BCC's `profile`. Where `offcpu` shows where
threads *wait*, this shows where they *run*; between the two, all of a
thread's time is accounted for (plus run queue waits, see `runqlat`).

## How it works

The program isn't triggered by an event in the code, like the other
modules' tracepoints, but by a timer: it's a `perf_event` program,
attached to a sampling `cpu-clock` perf event on every CPU (99Hz by
default - slightly off 100Hz so it doesn't fire in lockstep with periodic
timers). Each sample is a timer interrupt; the program runs in it, with
the interrupted task as the current task, and records that task's pid,
thread name and kernel and user stacks (`bpf_get_stackid()`) in a counts
map.

The perf events are opened **for the container's cgroup**
(`PERF_FLAG_PID_CGROUP`, the same mechanism as `perf record -G`): the
kernel only runs an event's clock while a task from that cgroup is on the
CPU, pausing it on every switch to anything else. So:

- the rest of the host is never sampled - no samples to throw away, and
  no overhead on CPUs that aren't running the container;
- samples come at `-freq` per second of the *container's CPU time*, so
  `samples / freq` estimates how much CPU time it used - reported as
  `cpu_ms`.

Cgroup perf events also cover child cgroups, so the BPF program still
checks the exact cgroup ID, like the other modules. The pid is resolved
in the agent's pid namespace (`pidns.h`), and stacks are symbolized by
`internal/stacks` - see the [offcpu README](../offcpu/README.md#symbolization)
for how that works and its limitations (frame pointers, stripped binaries,
short-lived processes). Two things are specific to profiling:

- **User-mode samples have no kernel stack** (the CPU was in user space,
  not in the kernel), so `kernel_stack` is empty; samples taken in the
  kernel - in a syscall, a page fault, an interrupt - have both.
- **`[vdso]`** frames are code the kernel maps into every process so that
  `clock_gettime()` and a few other calls don't need a syscall. Hot loops
  around timestamps (as in the example below) spend most of their time
  there.

Every `-interval`, the counts map is drained and the stack ids it used
are deleted from the stack map, as in `offcpu`.

Requires a kernel with BPF links for perf events (5.15+).

## Output

One event per interval:

- `total_samples`, `cpu_ms` - samples across all stacks, and the CPU time
  they represent.
- `num_stacks` - number of distinct stacks.
- `freq_hz`, `interval_ms`, `cumulative` - echo the flags.
- `stacks` - the top `-top` stacks by number of samples, each with:
  - `pid`, `comm` - `comm` is the thread's name.
  - `samples`, `cpu_ms`
  - `kernel_stack`, `user_stack` - frames, leaf first.
  - `folded` - `comm;user frames;kernel frames`, root first, for flame
    graph tools (see the offcpu
    [`blocking-mix` example](../offcpu/examples/blocking-mix#as-a-flame-graph)
    for how to render one). Weight each line by `samples`.

Sampling is statistical: a stack with few samples may be noise, and one
whose code runs in bursts shorter than the sampling period can be over-
or under-represented. At the default 99Hz, a fully busy thread gets about
500 samples per 5s interval.

## Flags

- `-container <id>` (required) - container ID, full or a unique prefix.
- `-freq <hz>` - samples per second of CPU time (default 99).
- `-interval <duration>` - how often to emit (default `5s`).
- `-top <n>` - stacks to report per interval (default 20, 0 for all).
- `-cumulative` - report totals since the module started instead of per
  interval.
