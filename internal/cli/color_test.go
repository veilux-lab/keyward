package cli_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/veilux-lab/keyward/internal/cli"
)

const escape = "\x1b["

func TestColorNeedsATerminalAndRespectsNoColor(t *testing.T) {
	env := func(vars map[string]string) func(string) string {
		return func(name string) string { return vars[name] }
	}
	for _, tc := range []struct {
		name     string
		terminal bool
		vars     map[string]string
		want     bool
	}{
		{"terminal", true, nil, true},
		{"pipe", false, nil, false},
		{"NO_COLOR", true, map[string]string{"NO_COLOR": "1"}, false},
		{"dumb terminal", true, map[string]string{"TERM": "dumb"}, false},
	} {
		if got := cli.ColorEnabled(tc.terminal, env(tc.vars)); got != tc.want {
			t.Errorf("%s: ColorEnabled = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestMigratePlanIsColouredOnlyWhenEnabled(t *testing.T) {
	path := writeFixture(t, rcFixture)
	h := newHarness(t, "", nil, nil)
	h.cli.Run([]string{"migrate", "--dry-run", path})
	if strings.Contains(h.out()+h.err(), escape) {
		t.Fatalf("colour without a terminal:\n%q", h.out())
	}

	h = newHarness(t, "", nil, nil)
	h.cli.ColorOut = true
	h.cli.Run([]string{"migrate", "--dry-run", path})
	for _, line := range strings.Split(h.out(), "\n") {
		plain := strings.TrimPrefix(line, escape+"31m")
		if strings.HasPrefix(plain, "-") && plain == line {
			t.Errorf("removed line is not red: %q", line)
		}
	}
	if !strings.Contains(h.out(), escape+"32m+") {
		t.Errorf("added lines are not green:\n%q", h.out())
	}
	if strings.Contains(h.err(), escape) {
		t.Errorf("stderr was coloured although only stdout is a terminal:\n%q", h.err())
	}
}

func TestFailuresAreRedOnAColourTerminal(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	h.cli.ColorErr = true
	h.cli.Service = func(string) (string, error) { return "", errors.New("launchctl failed") }
	h.cli.Run([]string{"service", "status"})
	if !strings.HasPrefix(h.err(), escape+"31m") || !strings.Contains(h.err(), "launchctl failed") {
		t.Errorf("stderr = %q, want a red failure", h.err())
	}
}
