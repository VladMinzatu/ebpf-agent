// Pids as seen from the agent's own pid namespace, for modules whose
// userspace side needs to find traced processes in its /proc (e.g. to
// symbolize user stacks).
//
// Include after vmlinux.h, <bpf/bpf_helpers.h> and <bpf/bpf_core_read.h>.
// Userspace must put the agent's pid namespace inode
// (agent.PidNamespaceInode()) at key 0 of agent_pidns before attaching.

#ifndef __AGENT_PIDNS_H
#define __AGENT_PIDNS_H

// Inode number of the agent's own pid namespace (/proc/self/ns/pid).
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} agent_pidns SEC(".maps");

// How deep a pid namespace hierarchy agent_tgid() searches. The kernel
// allows 32 levels; real setups use two or three (root, maybe a VM or
// Docker-in-a-container level, then the container).
#define MAX_PIDNS_LEVEL 8

// Returns p's process id as seen from the agent's pid namespace, or 0 if
// the process isn't visible there. bpf_get_current_pid_tgid() isn't enough:
// it returns pids in the kernel's root namespace, which isn't necessarily
// the agent's even with --pid=host (e.g. when Docker itself runs in a
// container, as on OrbStack or kind). (bpf_get_ns_current_pid_tgid()
// doesn't help either: it only works for tasks that live directly in the
// given namespace, and container processes live in a child of it.)
//
// A struct pid holds the process's number in every namespace from the root
// down to its own: numbers[i] is its pid at level i. So this walks those
// and returns the one whose namespace is the agent's.
static __always_inline u32 agent_tgid(struct task_struct *p)
{
    u32 key = 0;
    u64 *agent_ino = bpf_map_lookup_elem(&agent_pidns, &key);
    if (!agent_ino) {
        return 0;
    }
    struct pid *pid = BPF_CORE_READ(p, group_leader, thread_pid);
    unsigned int level = BPF_CORE_READ(pid, level);
    // numbers is a flexible array member, so only its start offset gets a
    // CO-RE relocation; indexing is plain pointer arithmetic from there.
    struct upid *numbers = &pid->numbers[0];
    for (int i = 0; i < MAX_PIDNS_LEVEL; i++) {
        if (i > level) {
            break;
        }
        struct upid upid;
        if (bpf_probe_read_kernel(&upid, sizeof(upid), numbers + i)) {
            return 0;
        }
        if (BPF_CORE_READ(upid.ns, ns.inum) == *agent_ino) {
            return upid.nr;
        }
    }
    return 0;
}

#endif
