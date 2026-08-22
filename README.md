# ebpf-agent

An eBPF-based agent. Currently meant for interactive sessions.
It's built around a small `Module` abstraction: each
module loads one or more eBPF programs, attaches them, streams out whatever
it observes, and unloads cleanly on exit. The CLI runs exactly one module at
a time, bpftrace-style — pick a module, pass its flags, run it, hit Ctrl+C
to unload and stop.

## Architecture

- `internal/agent` — the runtime shared by every module: the `Module`
  interface, a name-based registry, the `Runner` that loads a module, fans
  its events into output sinks, and unloads it on shutdown, and the `Sink`
  interface (currently one implementation: newline-delimited JSON to
  stdout).
- `internal/modules/<name>/` — one package per module. A module registers
  itself in an `init()`, owns its own `flag.FlagSet` for whatever params it
  needs, and contains its `.c` source plus the `bpf2go`-generated bindings.
- `internal/modules/bpf/vmlinux.h` — shared kernel type definitions used by
  CO-RE modules.
- `cmd/cli` — the entry point. It only knows how to look up a module by name
  and run it; it has zero knowledge of any specific module's params.

Adding a module means adding a new `internal/modules/<name>/` package and
blank-importing it from `cmd/cli/main.go` — nothing else in the runtime
needs to change.

## Usage

```
ebpf-agent <module> [module flags]
```

List available modules:
```
ebpf-agent
```

See a module's flags:
```
ebpf-agent hello -h
```

Run a module — it streams one JSON event per line to stdout until you stop
it (Ctrl+C / SIGTERM), at which point it unloads its eBPF programs and
exits:
```
ebpf-agent hello -target-pid 12345
```

## Build and Run with Docker

Docker is the primary (and only actively supported) way to build and run
this agent — it bundles the eBPF toolchain (`clang`, `libbpf`, kernel
headers) needed to compile modules, so you don't need it on the host.

```
make docker-build
```

Run a module (root/`--privileged` is required to load eBPF programs; the
host `/sys` mounts give the container access to tracepoints and BPF
filesystem):
```
make docker-run ARGS="hello -target-pid 12345"
```

Or without `make`:
```
docker run --rm -it \
  --privileged \
  --pid=host \
  --network=host \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v /sys/kernel/tracing:/sys/kernel/tracing \
  -v /sys/fs/bpf:/sys/fs/bpf \
  ebpf-agent hello -target-pid 12345
```

## Requirements

- Docker (build and run)
- Linux host or VM (eBPF support) — on Mac/Windows this means Docker
  Desktop's Linux VM
- Root/`--privileged` at runtime

## Adding a module

1. Create `internal/modules/<name>/`.
2. Write the eBPF program (`<name>.c`) and a `go:generate` directive for
   `bpf2go` (copy `internal/modules/hello` as a template).
3. Implement `agent.Module` (`Name`, `Load`, `Close`, `Events`).
4. In an `init()`, call `agent.Register("<name>", ctor)` where `ctor` parses
   the module's own `flag.FlagSet` from the `[]string` args it's given.
5. Blank-import the package from `cmd/cli/main.go`.
6. If the module's story is worth documenting on its own (what it traces,
   why, what a normal vs. interesting run looks like), give it a
   `README.md` — especially useful for linking a module back to whatever
   performance-lab investigation motivated it.

## vmlinux file generation

```
docker run --rm -it \
  --privileged \
  -v $(pwd):/workspace \
  -w /workspace \
  debian:bookworm \
  bash
```

inside the container:
```
apt-get update
apt-get install -y bpftool
```
then
```
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```
