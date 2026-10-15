package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// setup runs each step after its own yes, and says once at the end what to do.
func TestSetupWalksThroughEachStep(t *testing.T) {
	h := newHarness(t, "yes\nyes\n", nil, nil)
	home := homed(t, h)
	h.cli.Interactive = true
	rc := filepath.Join(home, ".zshrc")
	os.WriteFile(rc, []byte("export GITHUB_TOKEN=ghp_perfectlyFine0123456789\n"), 0o644)
	os.MkdirAll(filepath.Join(home, ".claude"), 0o755)
	if code := h.cli.Run([]string{"setup"}); code != 0 {
		t.Fatalf("exit %d:\n%s\n%s", code, h.out(), h.err())
	}
	if data, _ := os.ReadFile(rc); !strings.Contains(string(data), "cap://github-token") {
		t.Errorf("~/.zshrc was not migrated:\n%s", data)
	}
	if data, _ := os.ReadFile(filepath.Join(home, ".claude", "CLAUDE.md")); !strings.Contains(string(data), "keyward.md") {
		t.Error("Claude Code was not linked")
	}
	out := h.out()
	for _, want := range []string{"Step 1 of 4", "Step 2 of 4", "Step 3 of 4", "Step 4 of 4", "Open a new terminal"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if n := strings.Count(out, "Open a new terminal"); n != 1 {
		t.Errorf("the closing advice appears %d times:\n%s", n, out)
	}
}

// Declining a step skips it and moves on; nothing in it changes.
func TestSetupSkipsADeclinedStep(t *testing.T) {
	h := newHarness(t, "no\nyes\n", nil, nil)
	home := homed(t, h)
	h.cli.Interactive = true
	rc := filepath.Join(home, ".zshrc")
	os.WriteFile(rc, []byte("export GITHUB_TOKEN=ghp_perfectlyFine0123456789\n"), 0o644)
	os.MkdirAll(filepath.Join(home, ".claude"), 0o755)
	if code := h.cli.Run([]string{"setup"}); code != 0 {
		t.Fatalf("exit %d:\n%s", code, h.err())
	}
	if data, _ := os.ReadFile(rc); strings.Contains(string(data), "cap://") {
		t.Error("migrated after a no")
	}
	if _, err := os.Stat(filepath.Join(home, ".claude", "CLAUDE.md")); err != nil {
		t.Error("the step after the declined one did not run")
	}
}

func TestSetupNeedsATerminal(t *testing.T) {
	h := newHarness(t, "yes\n", nil, nil)
	homed(t, h)
	if code := h.cli.Run([]string{"setup"}); code != 1 || !strings.Contains(h.err(), "terminal") {
		t.Errorf("exit %d: %s", code, h.err())
	}
}
