# runqlat

Measures run queue latency for a container - how long its threads spend
runnable but waiting for a CPU - as a log2 histogram, modeled on BCC's
`runqlat`. Filtered by cgroup ID like the other modules.

A thread's wait starts when it becomes runnable and ends when it's
switched in:

- `sched_wakeup` / `sched_wakeup_new` - a blocked (or brand new) thread was
  woken up.
- `sched_switch`, for `prev` - a thread was switched out while still
  `TASK_RUNNING`, i.e. preempted (time slice used up, a higher priority
  thread woke, or its cgroup hit its CPU quota), so it goes straight back
  to waiting.
- `sched_switch`, for `next` - the wait ends; the latency goes into the
  histogram.

Time spent blocked (sleeping, on I/O, on a lock) is *not* counted - that's
off-CPU time, a different question.

## Why it's interesting for containers

CFS bandwidth control (`docker run --cpus`, Kubernetes CPU limits) throttles
a cgroup once it's used its quota for the current period (100ms by
default): its threads stay runnable but aren't scheduled until the next
period. That shows up here directly as run queue latency - typically a
cluster of waits in the tens of milliseconds - even when the host has idle
CPUs. Contention with other workloads (a noisy neighbor) shows up too, but
with a different shape.

## How it hooks in, and why

Unlike the other modules, none of these hooks can filter with
`bpf_get_current_cgroup_id()`: `sched_wakeup` runs in the context of the
*waker* (another thread, possibly in another container, or softirq), and
`sched_switch` runs in the context of `prev`. So the cgroup ID is read off
the task itself (`task->cgroups->dfl_cgrp->kn->id`, the same value
`bpf_get_current_cgroup_id()` returns for a current task). Only threads in
the target cgroup get a start timestamp, so the switch-in side just looks
the thread up without checking its cgroup.

The hooks are `tp_btf` (BTF-enabled raw tracepoints): stable tracepoints,
with typed `task_struct *` arguments and no per-event copying of the
tracepoint's fields. Two kernel differences are handled - `sched_switch`'s
extra `prev_state` argument (5.18+) isn't declared, and
`task_struct::state` / `__state` (renamed in 5.14) is picked with CO-RE.

## Output

The scheduler hooks fire far too often to stream one event per wakeup, so
the histogram is kept in a per-CPU BPF map and the module emits one event
per `-interval`. The kernel side only ever increments the map; the Go side
diffs consecutive reads, which avoids racing CPUs that are still
incrementing it while it's being cleared.

Each event has:

- `count` - number of waits that ended in this interval.
- `avg_us` - their mean latency (omitted when `count` is 0).
- `buckets` - the non-empty log2 buckets, `{min_us, max_us, count}`, both
  bounds inclusive. The last bucket (2^26us, ~67s, and up) has no `max_us`.
- `interval_ms`, `cumulative` - echo the flags.

## Flags

- `-container <id>` (required) - container ID, full or a unique prefix.
- `-interval <duration>` - how often to emit a histogram (default `1s`).
- `-cumulative` - emit totals since the module started instead of
  per-interval histograms.

## Example

A single busy-looping thread in a container started with `--cpus=0.5`:

```
ebpf-agent runqlat -container 3f1c0a9b27de -interval 2s
```

```json
{"Module":"runqlat","Timestamp":"2026-09-29T17:04:18.029785057Z","Data":{"avg_us":45310.40277272728,"buckets":[{"count":1,"max_us":31,"min_us":16},{"count":1,"max_us":127,"min_us":64},{"count":20,"max_us":65535,"min_us":32768}],"count":22,"cumulative":false,"interval_ms":2000}}
```

Twenty waits of 32-65ms per 2s: each 100ms period, the thread burns its
50ms of quota, gets throttled, and waits roughly 50ms for the next period.
