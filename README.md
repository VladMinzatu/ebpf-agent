# ebpf-agent


### Build
After initial checkout:
```
mkdir internal/infrastructure/bpf
```


```
go generate ./... && go build -o ebpf-agent ./cmd/cli
```

### Run
```
sudo ./ebpf-agent
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
