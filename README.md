# ebpf-agent

An eBPF-based agent, currently meant for interactive sessions. The agent
is container-native, works with cgroup targets and is not meant for
non-containerized environments.

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
ebpf-agent hello -container 4d7d4bab813f
```

## Build and Run with Docker

Docker is the primary (and only actively supported) way to build and run
this agent — it bundles the eBPF toolchain (`clang`, `libbpf`, kernel
headers) needed to compile modules, so you don't need it on the host.

```
make docker-build
```

Run a module (root/`--privileged` is required to load eBPF programs; the
host `/sys` mounts give the container access to tracepoints, BPF
filesystem, and the host's cgroups):
```
make docker-run ARGS="hello -container 4d7d4bab813f"
```

Or without `make`:
```
docker run --rm -it \
  --privileged \
  --network=host \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v /sys/kernel/tracing:/sys/kernel/tracing \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  ebpf-agent hello -container 4d7d4bab813f
```

## Requirements

- Docker (build and run)
- Linux host or VM (eBPF support) — on Mac/Windows this means whatever
  Linux VM your Docker setup runs on (Docker Desktop, OrbStack, etc.)
- cgroup v2 (the unified hierarchy) on the host — this is how
  container-targeting modules identify a container; see "Testing modules"
  below
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

## Testing modules

Each module has an `examples/` subdirectory with one or more small,
self-contained workloads that exercise it in a specific, reproducible way —
see [`internal/modules/hello/examples/go-writer`](internal/modules/hello/examples/go-writer)
for the pattern: a minimal program packaged as its own Docker image, plus a
README describing what it does, how to run it, and what a real run should
look like as observed by the module. Give each scenario its own
subdirectory (`examples/<scenario>/`) — e.g. a module might eventually be
worth testing against workloads in different languages, or against
"normal" vs. "adversarial" patterns for a lab-specific investigation.

The general recipe:
1. Run the target workload as its own container (`docker build` / `docker
   run -d --name <name> ...`).
2. Get its container ID: `docker inspect -f '{{.Id}}' <name>` (a short
   prefix, e.g. the first 12 characters, is normally enough).
3. Run the module against it: `make docker-run ARGS="<module> -container
   <id>"`.

Modules that scope tracing to one specific container (like `hello`)
identify it by cgroup ID rather than PID or process name — every
container gets its own cgroup as a basic consequence of resource
limiting, so this works the same way under Docker, containerd, CRI-O, or
Kubernetes. See [`internal/agent/cgroup.go`](internal/agent/cgroup.go)
for the resolution logic; any future container-scoped module should reuse
`agent.CgroupID` rather than reinventing it.

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
