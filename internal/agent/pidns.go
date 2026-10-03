package agent

import (
	"fmt"
	"syscall"
)

// PidNamespaceInode returns the inode number of the agent's own pid
// namespace - the value of ns.inum on the kernel side. Modules that need
// pids the agent can look up in its own /proc pass this to their BPF
// programs (the agent_pidns map in internal/modules/bpf/pidns.h), since
// the pids BPF helpers return are from the kernel's root namespace, which
// isn't necessarily the agent's, even with --pid=host.
func PidNamespaceInode() (uint64, error) {
	var st syscall.Stat_t
	if err := syscall.Stat("/proc/self/ns/pid", &st); err != nil {
		return 0, fmt.Errorf("identifying own pid namespace: %w", err)
	}
	return uint64(st.Ino), nil
}
