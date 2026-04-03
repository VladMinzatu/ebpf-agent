package ebpf

//go:generate bash -c "bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h"
