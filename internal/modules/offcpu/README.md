# offcpu

Measures where a container's threads spend time blocked - off-CPU - by
stack trace, modeled on BCC's `offcputime`. Where CPU profilers show what
code is running, this shows what code is *waiting*, and on what: a futex, a
socket, a disk read, a sleep. Total off-CPU time is reported per unique
(process, kernel stack, user stack), and the top stacks are emitted
periodically, with a `folded` form ready for flame graph tools.

Filtered by cgroup ID like the other modules. It complements `runqlat`:
runqlat measures time spent runnable but waiting for a CPU, this measures
time spent not wanting one.

## How it works

One program, on `tp_btf/sched_switch`:

- **Switch-out**: if `prev` is going to sleep (`TASK_INTERRUPTIBLE` or
  `TASK_UNINTERRUPTIBLE` - not exiting, and not preempted per the
  tracepoint's `preempt` argument, since a thread preempted between setting
  a sleeping state and calling `schedule()` never actually blocks) and is
  in the target cgroup, record the time and capture its kernel and user stacks with
  `bpf_get_stackid()`. This has to happen here: stacks can only be captured
  for the current task, and at switch-out that's the one blocking.
- **Switch-in**: if `next` has a recorded start, add the elapsed time to a
  `counts` hash map keyed by (pid, state, kernel stack id, user stack id,
  comm). Like BCC's tool, this includes the time spent runnable after the
  wakeup, waiting for a CPU.

`bpf_get_stackid()` stores each distinct stack once in a
`BPF_MAP_TYPE_STACK_TRACE` map and returns its id, so counts only carry two
ids rather than up to 127 frames each.

Every `-interval`, the Go side drains `counts` (lookup-and-delete),
resolves the stacks to symbols, emits the top ones, and deletes the stack
ids it's done with - except ones still referenced by threads that are
blocked right now. Draining rather than diffing (as `runqlat` does) keeps
both maps bounded however many distinct stacks show up over time.

## Symbolization

- **Kernel frames** come from `/proc/kallsyms`. Leading frames belonging to
  the BPF program and tracepoint plumbing itself are dropped.
- **User frames** are resolved through the process's `/proc/<pid>/maps`,
  then the mapped file's ELF symbol table, read through `/proc/<pid>/root`
  (the target container's own filesystem). Parsed files are cached by
  device+inode.

This needs the agent to see the traced processes in its own `/proc`, so
it must run with `--pid=host` (included in `make docker-run`). Even then,
the kernel's root pid namespace isn't necessarily the agent's - on
OrbStack or kind, Docker itself runs inside a container - so pids aren't
taken from `bpf_get_current_pid_tgid()`. Instead the BPF side walks the
task's `struct pid`, which holds its pid at every namespace level, and
picks the one in the agent's namespace. Reported `pid`s are therefore the
ones you'd see from the agent (and, with `--pid=host`, from `docker
inspect -f '{{.State.Pid}}'`).

Limitations, all common to frame-pointer based stack walking:

- **User stacks need frame pointers.** Go binaries have them. Most C
  binaries and distro libraries don't, so their stacks are cut short -
  often to a single frame.
- **Stripped binaries** show `[path+0xoffset]` frames; shared libraries
  still resolve their exported functions (`.dynsym`).
- **Short-lived processes** may have exited by the time the interval is
  symbolized, leaving `[unknown 0x...]` frames.
- **Stale frame pointers** at thread entry make the kernel read one
  garbage frame past the real root of the stack (e.g. every thread Go
  starts on arm64). Unresolvable root frames are trimmed and identical
  stacks merged, but a garbage value that happens to land inside real code
  shows up as a spurious root frame.
- **`[missing]`** means a stack couldn't be captured, or its id was
  cleaned up between capture and read.

### Go programs

Goroutines don't block threads: a blocked goroutine is parked by Go's
scheduler, and the thread goes on to run others. So for Go, this shows
*threads* blocking - mostly inside the runtime scheduler (`runtime.park_m`,
`runtime.stopm`, `runtime.netpoll`, `runtime.futex`) when there's nothing to
run - not which goroutine was waiting on what. For that, use Go's own
block and mutex profiles. What does show up directly is anything that
does block a thread: syscalls such as file I/O, cgo calls, and
`LockOSThread` goroutines.

## Output

One event per interval:

- `total_us` - off-CPU time across all stacks, not just the reported ones.
- `num_stacks` - number of distinct stacks.
- `stacks` - the top `-top` stacks by `total_us`, each with:
  - `pid`, `comm` - `comm` is the thread's name.
  - `state` - `S` (interruptible: waiting for an event, e.g. a timer,
    socket or futex) or `D` (uninterruptible: typically disk I/O or a
    kernel lock), as in `ps`.
  - `total_us`, `count` - total off-CPU time and number of blocking events.
  - `kernel_stack`, `user_stack` - frames, leaf first.
  - `folded` - `comm;user frames;kernel frames`, root first, the format
    `flamegraph.pl` and speedscope take. With
    `jq -r '.Data.stacks[] | "\(.folded) \(.total_us)"'` the output can be
    fed straight into them.

Off-CPU time is attributed to the interval in which the thread wakes up,
so one long sleep can count for more than an interval's worth of time.
Threads already blocked when the module starts aren't counted until they
block again.

## Flags

- `-container <id>` (required) - container ID, full or a unique prefix.
- `-interval <duration>` - how often to emit (default `5s`).
- `-top <n>` - stacks to report per interval (default 20, 0 for all).
- `-cumulative` - report totals since the module started instead of per
  interval.

## Example

```
ebpf-agent offcpu -container 9b1f3c7e2a40 -interval 5s
```

See [`examples/blocking-mix`](examples/blocking-mix) for a runnable
workload to test this against: threads that sit idle, contend on a lock,
sleep on a timer and wait for disk I/O, each showing up as its own stack.
