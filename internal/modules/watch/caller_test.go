package watch

import (
	"slices"
	"testing"

	"github.com/VladMinzatu/ebpf-agent/internal/stacks"
)

func TestInsertCaller(t *testing.T) {
	tests := []struct {
		name   string
		frames []string
		caller string
		want   []string
	}{
		{
			name:   "leaf: the walk skipped its caller",
			frames: []string{"main.tick", "runtime.main", "runtime.goexit"},
			caller: "main.main",
			want:   []string{"main.tick", "main.main", "runtime.main", "runtime.goexit"},
		},
		{
			name:   "x30 saved and still pointing at the caller the walk found",
			frames: []string{"main.update", "main.main", "runtime.main"},
			caller: "main.main",
			want:   []string{"main.update", "main.main", "runtime.main"},
		},
		{
			name:   "x30 left over from a call the writer made",
			frames: []string{"main.update", "main.main", "runtime.main"},
			caller: "main.update",
			want:   []string{"main.update", "main.main", "runtime.main"},
		},
		{
			name:   "single frame",
			frames: []string{"main.tick"},
			caller: "main.main",
			want:   []string{"main.tick", "main.main"},
		},
		{
			name:   "no stack",
			frames: []string{stacks.Missing},
			caller: "main.main",
			want:   []string{stacks.Missing},
		},
	}
	for _, tt := range tests {
		if got := insertCaller(tt.frames, tt.caller); !slices.Equal(got, tt.want) {
			t.Errorf("%s: insertCaller(%q, %q) = %q, want %q", tt.name, tt.frames, tt.caller, got, tt.want)
		}
	}
}
