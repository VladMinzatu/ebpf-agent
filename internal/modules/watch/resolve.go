package watch

import (
	"debug/dwarf"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"slices"
	"strings"
)

// dwOpAddr is DW_OP_addr: a location expression made of this opcode
// followed by the variable's address.
const dwOpAddr = 0x03

// atEntry is AT_ENTRY from <elf.h>: the aux vector entry with the runtime
// address of the executable's entry point.
const atEntry = 9

// Target is a resolved watch expression: where to put the breakpoint, and
// how many bytes it covers.
type Target struct {
	Addr   uint64
	Size   int64
	Type   string // the watched value's type, e.g. "int64"
	Signed bool   // whether the value is a signed integer
}

// Resolve resolves expr - a package-level variable, optionally followed by
// struct fields, e.g. "main.cfg.Limits.MaxConns" or
// "github.com/acme/svc/config.cfg.Timeout" - to an address in process pid.
// The binary is read through /proc/<pid>/exe and needs its DWARF (i.e. not
// built with -ldflags=-w).
//
// Only the simplest case is handled so far: a variable in the executable
// itself (not a shared library), and a path that's stored inline in it,
// with no pointers to follow.
func Resolve(pid uint32, expr string) (Target, error) {
	f, err := elf.Open(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return Target{}, err
	}
	defer f.Close()
	t, err := resolveELF(f, expr)
	if err != nil {
		return Target{}, err
	}
	bias, err := loadBias(pid, f)
	if err != nil {
		return Target{}, err
	}
	// The bias is page-aligned, so t.Addr stays aligned to t.Size.
	t.Addr += bias
	return t, nil
}

// loadBias returns how far process pid's executable f was loaded from the
// addresses it was linked at. That's 0 for a non-PIE executable, which is
// always loaded at its link-time addresses. A PIE is linked as if at 0 and
// loaded at a random base, which the entry point gives away: the aux vector
// has its runtime address, the ELF header its link-time one. Unlike working
// it out from /proc/<pid>/maps, that also holds for .bss, which isn't
// mapped from the file.
func loadBias(pid uint32, f *elf.File) (uint64, error) {
	if f.Type == elf.ET_EXEC {
		return 0, nil
	}
	auxv, err := os.ReadFile(fmt.Sprintf("/proc/%d/auxv", pid))
	if err != nil {
		return 0, err
	}
	entry, ok := auxvValue(auxv, f.ByteOrder, atEntry)
	if !ok {
		return 0, fmt.Errorf("no AT_ENTRY in /proc/%d/auxv", pid)
	}
	return entry - f.Entry, nil
}

// auxvValue returns the value of tag in auxv, the contents of a 64-bit
// process's /proc/<pid>/auxv: (tag, value) pairs of u64s, ending with
// AT_NULL (0).
func auxvValue(auxv []byte, order binary.ByteOrder, tag uint64) (uint64, bool) {
	for i := 0; i+16 <= len(auxv); i += 16 {
		t := order.Uint64(auxv[i:])
		if t == 0 {
			break
		}
		if t == tag {
			return order.Uint64(auxv[i+8:]), true
		}
	}
	return 0, false
}

// resolveELF resolves expr in f, to its link-time address: what it is at
// runtime minus the load bias.
func resolveELF(f *elf.File, expr string) (Target, error) {
	if f.Class != elf.ELFCLASS64 {
		return Target{}, fmt.Errorf("only 64-bit binaries are supported")
	}
	if f.Type != elf.ET_EXEC && f.Type != elf.ET_DYN {
		return Target{}, fmt.Errorf("not an executable (ELF type %s)", f.Type)
	}
	varName, fields, err := parseExpr(expr)
	if err != nil {
		return Target{}, err
	}
	d, err := f.DWARF()
	if err != nil {
		return Target{}, fmt.Errorf("reading DWARF (binary built with -ldflags=-w?): %w", err)
	}
	addr, typ, err := findVariable(d, f.ByteOrder, varName)
	if err != nil {
		return Target{}, err
	}
	typ, off, err := walkFields(typ, varName, fields)
	if err != nil {
		return Target{}, err
	}
	addr += off

	// What one debug register can watch: 1, 2, 4 or 8 naturally aligned bytes.
	size := typ.Size()
	switch size {
	case 1, 2, 4, 8:
	default:
		return Target{}, fmt.Errorf("%s is %d bytes (%s); a watchpoint covers 1, 2, 4 or 8, pick a field inside it", expr, size, typeName(typ))
	}
	if addr%uint64(size) != 0 {
		return Target{}, fmt.Errorf("%s at %#x is not aligned to its size (%d)", expr, addr, size)
	}
	_, signed := typ.(*dwarf.IntType)
	return Target{Addr: addr, Size: size, Type: typeName(typ), Signed: signed}, nil
}

// parseExpr splits expr into the variable's full name (as DWARF has it,
// with the package's import path) and the fields after it. Import paths
// contain dots ("github.com/..."), so the package name is whatever follows
// the last "/" up to the next ".".
func parseExpr(expr string) (string, []string, error) {
	slash := strings.LastIndex(expr, "/") + 1
	parts := strings.Split(expr[slash:], ".")
	if len(parts) < 2 || slices.Contains(parts, "") {
		return "", nil, fmt.Errorf("%q: want <package>.<variable>[.<field>...], e.g. main.cfg.MaxConns", expr)
	}
	return expr[:slash] + parts[0] + "." + parts[1], parts[2:], nil
}

// findVariable returns the link-time address and type of the package-level
// variable name.
func findVariable(d *dwarf.Data, order binary.ByteOrder, name string) (uint64, dwarf.Type, error) {
	r := d.Reader()
	for {
		e, err := r.Next()
		if err != nil {
			return 0, nil, err
		}
		if e == nil {
			break
		}
		if e.Tag == dwarf.TagSubprogram {
			r.SkipChildren() // locals and parameters, never package-level
			continue
		}
		if e.Tag != dwarf.TagVariable {
			continue
		}
		if n, _ := e.Val(dwarf.AttrName).(string); n != name {
			continue
		}
		loc, _ := e.Val(dwarf.AttrLocation).([]byte)
		if len(loc) != 9 || loc[0] != dwOpAddr {
			return 0, nil, fmt.Errorf("%s: unsupported DWARF location %x", name, loc)
		}
		typeOff, ok := e.Val(dwarf.AttrType).(dwarf.Offset)
		if !ok {
			return 0, nil, fmt.Errorf("%s: no type in DWARF", name)
		}
		typ, err := d.Type(typeOff)
		if err != nil {
			return 0, nil, fmt.Errorf("%s: %w", name, err)
		}
		return order.Uint64(loc[1:]), typ, nil
	}
	return 0, nil, fmt.Errorf("no variable %s in the binary (misspelled, or removed by the linker because nothing uses it?)", name)
}

// walkFields follows fields from typ, a variable's type, and returns the
// last field's type and its offset in the variable.
func walkFields(typ dwarf.Type, path string, fields []string) (dwarf.Type, uint64, error) {
	var off uint64
	for _, name := range fields {
		var st *dwarf.StructType
		switch t := unwrap(typ).(type) {
		case *dwarf.StructType:
			st = t
		case *dwarf.PtrType:
			return nil, 0, fmt.Errorf("%s is a pointer (%s); following pointers is not supported yet", path, typeName(t))
		default:
			return nil, 0, fmt.Errorf("%s is %s, not a struct", path, typeName(t))
		}
		i := slices.IndexFunc(st.Field, func(f *dwarf.StructField) bool { return f.Name == name })
		if i < 0 {
			names := make([]string, len(st.Field))
			for j, f := range st.Field {
				names[j] = f.Name
			}
			return nil, 0, fmt.Errorf("%s (%s) has no field %s; fields: %s", path, typeName(st), name, strings.Join(names, ", "))
		}
		off += uint64(st.Field[i].ByteOffset)
		typ = st.Field[i].Type
		path += "." + name
	}
	return unwrap(typ), off, nil
}

func unwrap(t dwarf.Type) dwarf.Type {
	for {
		td, ok := t.(*dwarf.TypedefType)
		if !ok {
			return t
		}
		t = td.Type
	}
}

// typeName is the type's name if it has one: String() spells out a
// struct's fields.
func typeName(t dwarf.Type) string {
	if n := t.Common().Name; n != "" {
		return n
	}
	return t.String()
}
