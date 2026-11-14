package cli_test

import (
	"errors"
	"os"
	"path/filepath"
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

// doctor colours its stdout only on a terminal: each check's icon by how it came
// out, headings in bold, and locations in cyan.
func TestDoctorIsColouredOnlyWhenEnabled(t *testing.T) {
	for _, colour := range []bool{false, true} {
		h := newHarness(t, "", map[string]string{"alpha": "v"}, nil)
		home := homed(t, h)
		h.cli.ColorOut = colour
		os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export A='cap://alpha'\nexport GITHUB_TOKEN="+leftoverToken+"\nexport BUILD_ID=Zx9kQm2vLp7wRt4yNb8cFj1hGd5sAe3uYo6i\n"), 0o644)

		if code := h.cli.Run([]string{"doctor"}); code != 1 {
			t.Errorf("exit code = %d, want 1", code)
		}
		if strings.Contains(h.err(), escape) {
			t.Errorf("stderr was coloured although only stdout is a terminal:\n%q", h.err())
		}
		if !colour {
			if strings.Contains(h.out(), escape) {
				t.Errorf("colour without a terminal:\n%q", h.out())
			}
			continue
		}
		for _, want := range []string{escape + "32m✓" + escape + "0m", escape + "33m!" + escape + "0m", escape + "31m✗" + escape + "0m",
			"  " + escape + "36m~/.zshrc:2" + escape + "0m  ", escape + "2ma GitHub token" + escape + "0m", escape + "1mkeyward doctor" + escape + "0m"} {
			if !strings.Contains(h.out(), want) {
				t.Errorf("stdout lacks %q:\n%q", want, h.out())
			}
		}
	}
}
