package agent

import (
	"fmt"
	"sort"
	"strings"
)

// Constructor builds a Module from its own CLI args (everything after the
// module name on the command line). Each module owns its own flag.FlagSet,
// so the params it accepts are entirely up to it.
type Constructor func(args []string) (Module, error)

var registry = map[string]Constructor{}

// Register makes a module available under name. Modules call this from an
// init() in their own package, so importing a module for its side effect
// (blank import) is what makes it available to run.
func Register(name string, ctor Constructor) {
	if _, exists := registry[name]; exists {
		panic(fmt.Sprintf("agent: module %q already registered", name))
	}
	registry[name] = ctor
}

// Names returns the names of all registered modules, sorted, for usage output.
func Names() []string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func newModule(name string, args []string) (Module, error) {
	ctor, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unknown module %q (available: %s)", name, strings.Join(Names(), ", "))
	}
	return ctor(args)
}
