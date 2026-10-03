package stacks

import (
	"bufio"
	"debug/elf"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

type symbol struct {
	addr uint64
	size uint64 // 0 if unknown (always, for kallsyms)
	name string
}

// symbolTable is sorted by addr.
type symbolTable []symbol

func (t symbolTable) lookup(addr uint64) (string, bool) {
	i := sort.Search(len(t), func(i int) bool { return t[i].addr > addr }) - 1
	if i < 0 {
		return "", false
	}
	s := t[i]
	if s.size != 0 && addr >= s.addr+s.size {
		return "", false
	}
	return s.name, true
}

func (t symbolTable) sort() {
	sort.Slice(t, func(i, j int) bool { return t[i].addr < t[j].addr })
}

// KernelSymbols is the kernel's symbol table, from /proc/kallsyms. A nil
// *KernelSymbols is valid and resolves nothing.
type KernelSymbols struct {
	syms symbolTable
}

func (k *KernelSymbols) lookup(addr uint64) (string, bool) {
	if k == nil {
		return "", false
	}
	return k.syms.lookup(addr)
}

// LoadKernelSymbols reads /proc/kallsyms. That file isn't namespaced, so
// this works from inside the agent's container, but it shows all-zero
// addresses unless the reader has CAP_SYSLOG (--privileged has it).
func LoadKernelSymbols() (*KernelSymbols, error) {
	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseKallsyms(f)
}

func parseKallsyms(r io.Reader) (*KernelSymbols, error) {
	var t symbolTable
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		// "<addr> <type> <name> [module]"
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		switch fields[1] {
		case "t", "T", "w", "W":
		default:
			continue // not text
		}
		addr, err := strconv.ParseUint(fields[0], 16, 64)
		if err != nil || addr == 0 {
			continue
		}
		t = append(t, symbol{addr: addr, name: fields[2]})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(t) == 0 {
		return nil, fmt.Errorf("no usable symbols in /proc/kallsyms (missing CAP_SYSLOG?)")
	}
	t.sort()
	return &KernelSymbols{syms: t}, nil
}

type mapping struct {
	start, end, offset uint64
	path               string
}

// elfFile is what's needed from a mapped file to turn a file offset into a
// symbol.
type elfFile struct {
	loads []elf.ProgHeader // PT_LOAD segments
	syms  symbolTable
}

type fileKey struct {
	dev, ino uint64
}

// userSymbolizer resolves user-space addresses of processes in other
// containers. The pids from BPF are host pids, so this needs the agent to
// share the host's pid namespace (docker run --pid=host) to find them in
// /proc. Files are read through /proc/<pid>/root, i.e. from the target's
// own mount namespace, and cached by device+inode so the same binary or
// library isn't parsed again for every process that maps it.
type userSymbolizer struct {
	procs map[uint32][]mapping
	files map[fileKey]*elfFile
}

func newUserSymbolizer() *userSymbolizer {
	return &userSymbolizer{procs: map[uint32][]mapping{}, files: map[fileKey]*elfFile{}}
}

// resetProcs drops cached memory maps, so processes that exited, exec'd or
// mapped new libraries since are re-read. Parsed files are kept.
func (s *userSymbolizer) resetProcs() {
	s.procs = map[uint32][]mapping{}
}

func (s *userSymbolizer) lookup(pid uint32, addr uint64) string {
	maps, ok := s.procs[pid]
	if !ok {
		maps, _ = readMaps(pid) // a failed read (e.g. process exited) caches as empty
		s.procs[pid] = maps
	}
	var m *mapping
	for i := range maps {
		if addr >= maps[i].start && addr < maps[i].end {
			m = &maps[i]
			break
		}
	}
	if m == nil {
		return unknownFrame(addr)
	}

	fileOff := addr - m.start + m.offset
	f := s.file(pid, m.path)
	if f != nil {
		for _, p := range f.loads {
			if fileOff >= p.Off && fileOff < p.Off+p.Filesz {
				if name, ok := f.syms.lookup(fileOff - p.Off + p.Vaddr); ok {
					return name
				}
				break
			}
		}
	}
	return fmt.Sprintf("[%s+0x%x]", m.path, fileOff)
}

func (s *userSymbolizer) file(pid uint32, path string) *elfFile {
	full := fmt.Sprintf("/proc/%d/root%s", pid, path)
	fi, err := os.Stat(full)
	if err != nil {
		return nil
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	key := fileKey{dev: uint64(st.Dev), ino: uint64(st.Ino)}
	if f, ok := s.files[key]; ok {
		return f
	}
	f, _ := readELF(full) // nil on failure, cached so it isn't retried
	s.files[key] = f
	return f
}

func readELF(path string) (*elfFile, error) {
	ef, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	defer ef.Close()

	f := &elfFile{}
	for _, p := range ef.Progs {
		if p.Type == elf.PT_LOAD {
			f.loads = append(f.loads, p.ProgHeader)
		}
	}
	// .symtab is gone from stripped binaries; .dynsym (exported symbols
	// only) is what's left for shared libraries.
	for _, get := range []func() ([]elf.Symbol, error){ef.Symbols, ef.DynamicSymbols} {
		syms, err := get()
		if err != nil {
			continue
		}
		for _, sym := range syms {
			if elf.ST_TYPE(sym.Info) == elf.STT_FUNC && sym.Value != 0 {
				f.syms = append(f.syms, symbol{addr: sym.Value, size: sym.Size, name: sym.Name})
			}
		}
	}
	f.syms.sort()
	return f, nil
}

// readMaps returns pid's file-backed mappings.
func readMaps(pid uint32) ([]mapping, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var maps []mapping
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// "<start>-<end> <perms> <offset> <dev> <inode> <path>"
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 || !strings.HasPrefix(fields[5], "/") {
			continue // anonymous, [heap], [stack], [vdso], ...
		}
		start, end, ok := strings.Cut(fields[0], "-")
		if !ok {
			continue
		}
		var m mapping
		var err1, err2, err3 error
		m.start, err1 = strconv.ParseUint(start, 16, 64)
		m.end, err2 = strconv.ParseUint(end, 16, 64)
		m.offset, err3 = strconv.ParseUint(fields[2], 16, 64)
		if err1 != nil || err2 != nil || err3 != nil {
			continue
		}
		m.path = fields[5]
		maps = append(maps, m)
	}
	return maps, sc.Err()
}

const unknownPrefix = "[unknown "

func unknownFrame(addr uint64) string {
	return fmt.Sprintf("%s0x%x]", unknownPrefix, addr)
}
