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
the same on every run: the binary isn't PIE, so it isn't loaded at a random
address.

## Get its container ID and pid

```
docker inspect -f '{{.Id}} {{.State.Pid}}' go-counter
```

A short prefix of the ID (e.g. the first 12 characters) is normally enough.
The pid is the process's pid on the host (in the Docker VM on macOS), not
the `pid=1` it prints from inside its own pid namespace. That's the one
`watch` needs, as it runs with `--pid=host`.

## Run watch against it

Not wired up yet: the module so far only resolves `-sym` to an address.
Once it is, from the repo root:
```
make docker-run ARGS="watch -container <id> -pid <pid> -sym main.counter"
```

should print one event per write to `counter`: 1, 2, ... 9 from `tick()`,
then 0 from `reset()`.

## Cleanup

```
docker rm -f go-counter
```
