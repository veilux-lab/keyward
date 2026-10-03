package launchd_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/veilux-lab/keyward/internal/launchd"
)

func TestHomebrewServiceLifecycleDoesNotCopyOrSign(t *testing.T) {
	home := t.TempDir()
	loaded := false
	var calls []string
	m := launchd.Homebrew{Home: home, UID: 501, Brew: "/opt/homebrew/bin/brew"}
	m.Command = func(program string, args ...string) error {
		calls = append(calls, program+" "+strings.Join(args, " "))
		if program == m.Brew {
			loaded = args[1] == "restart"
			return nil
		}
		if args[1] == "gui/501/homebrew.mxcl.keyward" && loaded {
			return nil
		}
		return errors.New("not loaded")
	}
	m.Ready = func(string) error {
		if loaded {
			return nil
		}
		return errors.New("not running")
	}
	if status, err := m.Run("status"); err != nil || !strings.Contains(status, "not loaded") {
		t.Fatalf("initial status = %q, %v", status, err)
	}
	if _, err := m.Run("install"); err != nil {
		t.Fatal(err)
	}
	if status, err := m.Run("status"); err != nil || !strings.Contains(status, "running") {
		t.Fatalf("running status = %q, %v", status, err)
	}
	if _, err := m.Run("uninstall"); err != nil || loaded {
		t.Fatalf("uninstall: %v, loaded=%v", err, loaded)
	}
	commands := strings.Join(calls, "\n")
	for _, want := range []string{"services restart veilux-lab/tap/keyward", "services stop veilux-lab/tap/keyward"} {
		if !strings.Contains(commands, want) {
			t.Fatalf("missing %s", want)
		}
	}
	if strings.Contains(commands, "codesign") {
		t.Fatal("Homebrew startup requires signing")
	}
	for _, name := range []string{".local", "Applications", "Library"} {
		if _, err := os.Stat(filepath.Join(home, name)); !os.IsNotExist(err) {
			t.Fatalf("Homebrew manager copied or wrote files: %s", name)
		}
	}
}

func TestHomebrewRefusesASecondDaemonAndInvalidConfiguration(t *testing.T) {
	for _, signed := range []bool{false, true} {
		m := launchd.Homebrew{Home: t.TempDir(), UID: 501, Brew: "/opt/homebrew/bin/brew"}
		m.Command = func(program string, args ...string) error {
			if program == m.Brew {
				t.Fatal("started a second daemon")
			}
			if signed && args[1] == "gui/501/com.nwokolo24.keyward" {
				return nil
			}
			return errors.New("not loaded")
		}
		m.Ready = func(string) error { return nil }
		if _, err := m.Run("install"); err == nil {
			t.Fatal("another daemon was ignored")
		}
	}
	m := launchd.Homebrew{Home: t.TempDir(), UID: 501, Brew: "brew"}
	if _, err := m.Run("install"); err == nil {
		t.Fatal("relative brew executable accepted")
	}
}

func TestHomebrewPropagatesFailureAndChecksReadiness(t *testing.T) {
	m := launchd.Homebrew{Home: t.TempDir(), UID: 501, Brew: "/opt/homebrew/bin/brew"}
	m.Ready = func(string) error { return errors.New("unreachable") }
	m.Command = func(program string, args ...string) error {
		if program == m.Brew {
			return errors.New("restart failed")
		}
		return errors.New("not loaded")
	}
	if _, err := m.Run("install"); err == nil {
		t.Fatal("restart failure was hidden")
	}
	m.Command = func(string, ...string) error { return nil }
	if _, err := m.Run("status"); err == nil {
		t.Fatal("unreachable loaded job reported healthy")
	}
	if _, err := m.Run("unknown"); err == nil {
		t.Fatal("unknown action succeeded")
	}
}
