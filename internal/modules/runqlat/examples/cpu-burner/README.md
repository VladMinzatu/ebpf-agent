# Example exercising the runqlat module

A minimal Go program that runs `-workers` threads (default 4), each looping
forever: burn `-work` of CPU (default 5ms), then sleep `-sleep` (default
5ms). Every iteration is a wakeup followed by a burst of CPU, so each
worker needs half a CPU - 2 CPUs in total with the defaults. It prints its
throughput every 5s; with no contention that's close to
`workers / (work + sleep)` = 400 iterations/s, and anything less is time
spent waiting for a CPU.

The same image is run three ways below, to show what each kind of CPU
starvation looks like to runqlat. Output is shortened to one interval per
run; each run's shape is stable from interval to interval.

## Build it

```
docker build -t cpu-burner .
```

## Run it

```
docker run cpu-burner
```

## Run runqlat against it

For each scenario below: get the container ID (a short prefix, e.g. the
first 12 characters, is normally enough):
```
docker inspect -f '{{.Id}}' cpu-burner
```

then, from the repo root (assuming `make docker-build` was run before):
```
sudo make docker-run ARGS="runqlat -container <id> -interval 2s"
```

and `docker rm -f cpu-burner` before the next one.

### 1. No limit (baseline)

```
docker run -d --name cpu-burner cpu-burner
```

```json
{"Module":"runqlat","Timestamp":"2026-09-29T17:13:49.420123803Z","Data":{"avg_us":19.209062469497315,"buckets":[{"count":248,"max_us":1,"min_us":0},{"count":918,"max_us":3,"min_us":2},{"count":407,"max_us":7,"min_us":4},{"count":332,"max_us":15,"min_us":8},{"count":102,"max_us":31,"min_us":16},{"count":12,"max_us":63,"min_us":32},{"count":1,"max_us":127,"min_us":64},{"count":6,"max_us":255,"min_us":128},{"count":10,"max_us":511,"min_us":256},{"count":7,"max_us":1023,"min_us":512},{"count":6,"max_us":4095,"min_us":2048}],"count":2049,"cumulative":false,"interval_ms":2000}}
```

Nearly every wakeup gets a CPU within microseconds (average ~20us), with a
thin tail from whatever else the host happens to be running. `docker logs
cpu-burner` shows ~345 iterations/s - a bit under 400 because `time.Sleep`
overshoots slightly, not because of waiting.

### 2. CPU limit (throttling)

Half the CPU the workload needs:
```
docker run -d --name cpu-burner --cpus=1 cpu-burner
```

```json
{"Module":"runqlat","Timestamp":"2026-09-29T17:13:59.028872101Z","Data":{"avg_us":1972.468785891089,"buckets":[{"count":76,"max_us":1,"min_us":0},{"count":169,"max_us":3,"min_us":2},{"count":477,"max_us":7,"min_us":4},{"count":447,"max_us":15,"min_us":8},{"count":205,"max_us":31,"min_us":16},{"count":84,"max_us":63,"min_us":32},{"count":34,"max_us":127,"min_us":64},{"count":7,"max_us":255,"min_us":128},{"count":7,"max_us":511,"min_us":256},{"count":5,"max_us":1023,"min_us":512},{"count":7,"max_us":2047,"min_us":1024},{"count":14,"max_us":4095,"min_us":2048},{"count":4,"max_us":16383,"min_us":8192},{"count":18,"max_us":32767,"min_us":16384},{"count":62,"max_us":65535,"min_us":32768}],"count":1616,"cumulative":false,"interval_ms":2000}}
```

Bimodal. Most wakeups are still served in microseconds - the host has
plenty of idle CPUs - but there's a second cluster at 32-65ms. That's CFS
bandwidth throttling: the container burns its 100ms of quota per 100ms
period in about 50ms (it wants 2 CPUs' worth), then every
runnable thread waits for the next period. Those few, long waits are
enough to push the average up ~100x, and throughput drops to ~215
iterations/s.

### 3. Noisy neighbor (contention, no limit)

Pin the workload to one CPU, and put a second container - two threads
that never sleep - on the same CPU:
```
docker run -d --name cpu-burner --cpuset-cpus=0 cpu-burner
docker run -d --name neighbor --cpuset-cpus=0 cpu-burner -workers 2 -sleep 0s
```

```json
{"Module":"runqlat","Timestamp":"2026-09-29T17:14:12.884238628Z","Data":{"avg_us":3309.3360813236122,"buckets":[{"count":796,"max_us":1,"min_us":0},{"count":95,"max_us":3,"min_us":2},{"count":20,"max_us":7,"min_us":4},{"count":9,"max_us":15,"min_us":8},{"count":2,"max_us":31,"min_us":16},{"count":2,"max_us":63,"min_us":32},{"count":2,"max_us":255,"min_us":128},{"count":77,"max_us":1023,"min_us":512},{"count":135,"max_us":2047,"min_us":1024},{"count":171,"max_us":4095,"min_us":2048},{"count":212,"max_us":8191,"min_us":4096},{"count":191,"max_us":16383,"min_us":8192},{"count":69,"max_us":32767,"min_us":16384},{"count":2,"max_us":65535,"min_us":32768}],"count":1783,"cumulative":false,"interval_ms":2000}}
```

No quota involved, so no spike at the period length. Instead there's one
broad hump from ~0.5ms to ~32ms: six threads take turns on one CPU, and a
thread that becomes runnable waits for however many of the others' time
slices are ahead of it. Throughput drops to ~175 iterations/s.

Only `cpu-burner` is traced - the neighbor's own waits don't show up,
since it's in a different cgroup.

## Cleanup

```
docker rm -f cpu-burner neighbor
```
