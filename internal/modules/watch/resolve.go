package watch

import (
	"debug/dwarf"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"slices"
	"strings"
)

// dwOpAddr is DW_OP_addr: a location expression made of this opcode
// followed by the variable's address.
const dwOpAddr = 0x03

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
// Only the simplest case is handled so far: a non-PIE binary, and a path
// that's stored inline in the variable, with no pointers to follow.
func Resolve(pid uint32, expr string) (Target, error) {
	f, err := elf.Open(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return Target{}, err
	}
	defer f.Close()
	return resolveELF(f, expr)
}

func resolveELF(f *elf.File, expr string) (Target, error) {
	if f.Class != elf.ELFCLASS64 {
		return Target{}, fmt.Errorf("only 64-bit binaries are supported")
	}
	if f.Type != elf.ET_EXEC {
		// A PIE (ET_DYN) is loaded at a random base, which would need adding.
		return Target{}, fmt.Errorf("PIE binaries are not supported yet")
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
