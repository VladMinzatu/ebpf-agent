package stacks

import "github.com/cilium/ebpf"

// Drain reads and deletes every entry in a hash map, so it only ever holds
// what accumulated since the previous call. It's meant for counts maps
// keyed by stack ids, which would otherwise grow with every distinct stack
// ever seen (unlike, say, a fixed-size histogram, which can just be diffed
// between reads).
//
// K and V must match the map's key and value layout. An increment landing
// on an entry just as it's deleted is lost, but that window is a few
// instructions wide. Requires lookup-and-delete support for hash maps
// (kernel 5.14+).
func Drain[K comparable, V any](m *ebpf.Map) (map[K]V, error) {
	var keys []K
	var k K
	var v V
	it := m.Iterate()
	for it.Next(&k, &v) {
		keys = append(keys, k)
	}
	if err := it.Err(); err != nil {
		return nil, err
	}

	entries := make(map[K]V, len(keys))
	for _, k := range keys {
		if err := m.LookupAndDelete(k, &v); err != nil {
			continue // deleted in between, nothing to count
		}
		entries[k] = v
	}
	return entries, nil
}
