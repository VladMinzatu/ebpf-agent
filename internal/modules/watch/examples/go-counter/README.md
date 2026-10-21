# Example exercising the watch module

A minimal Go program with two globals for `watch` to point at:

- `counter`: incremented every second by `tick()`, and set back to 0 every
  10s by `reset()`, which runs in another goroutine;
- `stats` (a `Stats` struct): `tick()` bumps `stats.Ticks`, `reset()` bumps
  `stats.Resets`.

There are two writers, in different functions and usually on different
threads, so the stack in each event should tell them apart.

At startup it prints the addresses of `counter` and `stats.Resets` as the
process sees them, so you can check what `-sym` resolves to.

It's built with a plain `go build`, which keeps the DWARF `watch` needs to
resolve `-sym`. A binary built with `-ldflags="-s -w"` can't be resolved.

## Run it

```
docker build -t go-counter .
docker run -d --name go-counter go-counter
docker logs -f go-counter
```

```
go-counter: pid=1 &counter=0x1b0988 &stats.Resets=0x1b0ba8
counter=1
counter=2
...
counter=9
reset
counter=1
...
```

The addresses depend on the Go version and the architecture, but they're
the same on every run: by default the binary isn't PIE, so it isn't loaded
at a random address.

To try `watch` on a PIE instead, which is loaded at a random address on
every run (as most C, C++ and Rust binaries are today):
```
docker build --build-arg BUILDMODE=pie -t go-counter-pie .
docker run -d --name go-counter-pie go-counter-pie
```

```
go-counter: pid=1 &counter=0xaaaadc3409a8 &stats.Resets=0xaaaadc340bc8
```

## Get its container ID and pid

```
docker inspect -f '{{.Id}} {{.State.Pid}}' go-counter
```

A short prefix of the ID (e.g. the first 12 characters) is normally enough.
The pid is the process's pid on the host (in the Docker VM on macOS), not
the `pid=1` it prints from inside its own pid namespace. That's the one
`watch` needs, as it runs with `--pid=host`.

## Run watch against it

From the repo root (assuming `make docker-build` was run before):
```
make docker-run ARGS="watch -container <id> -pid <pid> -sym main.counter"
```

Expect one JSON line per write to `counter`, from whichever thread the
writing goroutine was on at the time, with the stack that made the write
(timestamps left out):
```json
{"Module":"watch","Data":{"addr":"0x1b0988","comm":"go-counter","pid":401366,"tid":401366,"user_stack":["main.tick","main.main","runtime.main","runtime.goexit.abi0"],"value":8}}
{"Module":"watch","Data":{"addr":"0x1b0988","comm":"go-counter","pid":401366,"tid":401381,"user_stack":["main.reset","main.main.func1","runtime.goexit.abi0"],"value":9}}
{"Module":"watch","Data":{"addr":"0x1b0988","comm":"go-counter","pid":401366,"tid":401366,"user_stack":["main.tick","main.main","runtime.main","runtime.goexit.abi0"],"value":0}}
{"Module":"watch","Data":{"addr":"0x1b0988","comm":"go-counter","pid":401366,"tid":401383,"user_stack":["main.tick","main.main","runtime.main","runtime.goexit.abi0"],"value":1}}
```

The two writers are told apart by their stacks: `tick()`, called from
`main`, and `reset()`, called from the goroutine started in `main`
(`main.main.func1`).

On arm64 (e.g. Docker on Apple Silicon), `value` is what the address held
*before* the write: the watchpoint fires before the store executes. Above,
`9` is `reset()` about to overwrite 9 with 0, and `0` is `tick()` about to
write 1. On x86 it's the value after the write.

## Cleanup

```
docker rm -f go-counter go-counter-pie
```
