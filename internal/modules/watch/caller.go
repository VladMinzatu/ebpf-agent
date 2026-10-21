package watch

import "github.com/VladMinzatu/ebpf-agent/internal/stacks"

// insertCaller puts caller, the function arm64's link register (x30)
// pointed into at the write, back into a user stack (leaf first) as its
// second frame, if the frame-pointer walk skipped it. That happens when the
// write is in a leaf function, which keeps its return address in x30
// instead of saving it in a frame record. Where x30 points depends on the
// writing function:
//
//   - a leaf: into its caller, which the walk skipped;
//   - one that saved x30 on entry and hasn't called anything since: into
//     its caller too, which the walk found (frames[1]);
//   - one that has called something: just after that call, i.e. into
//     itself (frames[0]).
//
// So caller is inserted only if it's neither frames[0] nor frames[1].
func insertCaller(frames []string, caller string) []string {
	if len(frames) == 0 || frames[0] == stacks.Missing {
		return frames
	}
	if caller == frames[0] || (len(frames) > 1 && caller == frames[1]) {
		return frames
	}
	out := make([]string, 0, len(frames)+1)
	out = append(out, frames[0], caller)
	return append(out, frames[1:]...)
}
