//go:build linux

package watch

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"unsafe"

	"golang.org/x/sys/unix"
)

// HW_BREAKPOINT_W from <linux/hw_breakpoint.h>: trap on writes.
const hwBreakpointW = 2

// openBreakpoints opens a hardware write breakpoint on [addr, addr+size) for
// every thread of process pid, and returns the perf event fds. Each hit is
// an overflow of the event (sample_period 1), which is where the BPF
// program attached to it runs.
//
// A breakpoint on a user address only means something in one address
// space, so unlike profile's events these are per thread, not per cgroup.
// inherit makes threads created later get their own copy of the event,
// with the attached program. That covers a thread only if the thread that
// created it was already armed, so one that's created while this runs, by
// a thread that isn't yet, is missed. Listing again wouldn't fix it: a
// thread that did inherit an event would get a second one, and report
// every write twice.
func openBreakpoints(pid uint32, addr uint64, size int64) ([]int, error) {
	attr := unix.PerfEventAttr{
		Type:    unix.PERF_TYPE_BREAKPOINT,
		Size:    uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
		Sample:  1,
		Bits:    unix.PerfBitInherit | unix.PerfBitExcludeKernel | unix.PerfBitExcludeHv,
		Bp_type: hwBreakpointW,
		Ext1:    addr,         // bp_addr
		Ext2:    uint64(size), // bp_len
	}
	tids, err := threads(pid)
	if err != nil {
		return nil, err
	}
	var fds []int
	for _, tid := range tids {
		fd, err := unix.PerfEventOpen(&attr, tid, -1, -1, unix.PERF_FLAG_FD_CLOEXEC)
		if errors.Is(err, unix.ESRCH) {
			continue // exited since it was listed
		}
		if errors.Is(err, unix.ENOSPC) {
			closePerfEvents(fds)
			return nil, fmt.Errorf("thread %d has no free debug register (there are only a few per thread, shared with gdb and perf): %w", tid, err)
		}
		if err != nil {
			closePerfEvents(fds)
			return nil, fmt.Errorf("perf_event_open breakpoint on thread %d: %w", tid, err)
		}
		fds = append(fds, fd)
	}
	if len(fds) == 0 {
		return nil, fmt.Errorf("process %d has no threads left to watch", pid)
	}
	return fds, nil
}

// threads lists the thread ids of process pid.
func threads(pid uint32) ([]int, error) {
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		return nil, err
	}
	tids := make([]int, 0, len(entries))
	for _, e := range entries {
		if tid, err := strconv.Atoi(e.Name()); err == nil {
			tids = append(tids, tid)
		}
	}
	return tids, nil
}

func closePerfEvents(fds []int) {
	for _, fd := range fds {
		unix.Close(fd)
	}
}
