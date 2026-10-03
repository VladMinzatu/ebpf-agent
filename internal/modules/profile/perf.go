package profile

import (
	"errors"
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// openPerfEvents opens one sampling cpu-clock perf event per CPU, firing
// freq times per second of CPU time spent by tasks in the cgroup at
// cgroupPath. Each sample is a timer interrupt on that CPU, which is where
// the BPF program attached to the event runs.
//
// Opening the events for a cgroup (PERF_FLAG_PID_CGROUP, as perf record -G
// does) rather than for every task on the CPU means the kernel stops the
// event's clock whenever the CPU switches to a task outside the cgroup, and
// restarts it on the way back. So the rest of the host isn't sampled at
// all, and samples / freq is an estimate of the container's CPU time.
// Cgroup events must be per-CPU, hence one per CPU.
func openPerfEvents(cgroupPath string, freq uint64) ([]int, error) {
	cgroup, err := unix.Open(cgroupPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("opening cgroup %s: %w", cgroupPath, err)
	}
	defer unix.Close(cgroup)

	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, err
	}

	attr := unix.PerfEventAttr{
		Type:   unix.PERF_TYPE_SOFTWARE,
		Config: unix.PERF_COUNT_SW_CPU_CLOCK,
		Size:   uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
		Sample: freq,
		Bits:   unix.PerfBitFreq, // Sample is a frequency, not a period
	}
	var fds []int
	for cpu := 0; cpu < cpus; cpu++ {
		fd, err := unix.PerfEventOpen(&attr, cgroup, cpu, -1, unix.PERF_FLAG_PID_CGROUP|unix.PERF_FLAG_FD_CLOEXEC)
		if errors.Is(err, unix.ENODEV) {
			continue // possible, but offline
		}
		if err != nil {
			closePerfEvents(fds)
			return nil, fmt.Errorf("perf_event_open on cpu %d: %w", cpu, err)
		}
		fds = append(fds, fd)
	}
	if len(fds) == 0 {
		return nil, errors.New("perf_event_open: no online cpus")
	}
	return fds, nil
}

func closePerfEvents(fds []int) {
	for _, fd := range fds {
		unix.Close(fd)
	}
}
