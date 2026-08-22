package agent

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const cgroupRoot = "/sys/fs/cgroup"

// CgroupID resolves a container ID (full, or a unique enough prefix) to the
// numeric cgroup ID the kernel reports via bpf_get_current_cgroup_id() for
// any process inside that container. It works by locating the container's
// cgroup directory under the host's cgroup v2 filesystem (expected mounted
// read-only at /sys/fs/cgroup) and reading its inode number, which is what
// the kernel uses as the cgroup's ID in the unified hierarchy.
//
// This doesn't depend on any container runtime's API - the container ID
// appears verbatim in its cgroup directory name under every runtime/driver
// combination (Docker with the systemd or cgroupfs driver, containerd,
// CRI-O, Kubernetes), so it works the same way everywhere.
func CgroupID(containerID string) (uint64, error) {
	if _, err := os.Stat(filepath.Join(cgroupRoot, "cgroup.controllers")); err != nil {
		return 0, fmt.Errorf("cgroup v2 not found at %s - this agent requires the unified cgroup hierarchy, mounted read-only into the container (-v /sys/fs/cgroup:/sys/fs/cgroup:ro): %w", cgroupRoot, err)
	}

	var matches []string
	err := filepath.WalkDir(cgroupRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip entries we can't read rather than failing the whole search
		}
		if d.IsDir() && strings.Contains(d.Name(), containerID) {
			matches = append(matches, path)
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("searching %s: %w", cgroupRoot, err)
	}

	switch len(matches) {
	case 0:
		return 0, fmt.Errorf("no cgroup under %s matches container id %q - is the container running, and is the host cgroup filesystem mounted in?", cgroupRoot, containerID)
	case 1:
		// exactly what we want
	default:
		return 0, fmt.Errorf("container id %q matches more than one cgroup, use a longer/more specific id: %v", containerID, matches)
	}

	info, err := os.Stat(matches[0])
	if err != nil {
		return 0, fmt.Errorf("stat %s: %w", matches[0], err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("cannot read inode for %s on this platform", matches[0])
	}

	return stat.Ino, nil
}
