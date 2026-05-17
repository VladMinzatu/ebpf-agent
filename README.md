# ebpf-agent

An eBPF-based agent.

## Requirements

- Go 1.x
- Linux (eBPF support)
- Root privileges (for runtime)

### Build
```
make build
```

Binary will be located at:

```bash
./bin/ebpf-agent
```

## Run

```bash
make run
```

Or manually:

```bash
sudo ./bin/ebpf-agent
```

## Future development goals
- develop modules (ebpf tracing programs) for all kinds of tracepoints, syscall, kernel functions, user functions, etc.
- configuration (toggelable modules)
- different data formats and interop with standard observability tooling
- integration strategies with observability tools (grpc, http, etc)
- examples (system programming in different languages, asm, explore Linux internals etc.) to demonstrate modules (doc)
- testing
- cgroup, containerisation handling
- comparison of each module with BCC and bpftrace (doc)
- packaging, deployment and runtime (docker, k8s)

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
