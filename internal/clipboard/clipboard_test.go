package clipboard

import (
	"slices"
	"testing"
	"time"
)

// pasteboard stands in for the real clipboard, which no test may touch.
type pasteboard struct{ count, clears int }

func (p *pasteboard) ChangeCount() int { return p.count }
func (p *pasteboard) Clear()           { p.clears++ }

// The process is given the change count and the delay, never the value, in a
// session of its own with no terminal, so closing the terminal does not end it.
func TestClearLaterStartsADetachedProcess(t *testing.T) {
	cmd := clearCommand("/keyward", 7, 30*time.Second)
	if want := []string{"/keyward", ClearArg, "7", "30s"}; !slices.Equal(cmd.Args, want) {
		t.Errorf("args = %q, want %q", cmd.Args, want)
	}
	if cmd.SysProcAttr == nil || !cmd.SysProcAttr.Setsid {
		t.Error("the process shares the terminal's session")
	}
	if cmd.Stdin != nil || cmd.Stdout != nil || cmd.Stderr != nil {
		t.Error("the process is given stdio")
	}
}

// It clears only a clipboard that still holds what copy put there: anything
// copied since moves the change count on.
func TestClearWhenDueClearsOnlyAnUnchangedClipboard(t *testing.T) {
	const delay = 50 * time.Millisecond
	for _, tc := range []struct {
		count  int
		clears int
	}{{7, 1}, {8, 0}} {
		pb := &pasteboard{count: tc.count}
		start := time.Now()
		ClearWhenDue(pb, clearCommand("/keyward", 7, delay).Args[2:])
		if pb.clears != tc.clears {
			t.Errorf("change count %d: cleared %d times, want %d", tc.count, pb.clears, tc.clears)
		}
		if waited := time.Since(start); waited < delay {
			t.Errorf("checked after %v, before the delay", waited)
		}
	}
}

// Each count is what the arguments would match if read carelessly.
func TestClearWhenDueIgnoresMalformedArguments(t *testing.T) {
	for _, tc := range []struct {
		args  []string
		count int
	}{{nil, 7}, {[]string{"7"}, 7}, {[]string{"7", "1ms", "x"}, 7}, {[]string{"x", "1ms"}, 0}, {[]string{"7", "soon"}, 7}} {
		pb := &pasteboard{count: tc.count}
		ClearWhenDue(pb, tc.args)
		if pb.clears != 0 {
			t.Errorf("%q: cleared the clipboard", tc.args)
		}
	}
}
