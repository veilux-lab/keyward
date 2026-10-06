package launchd_test

import (
	"os"
	"strings"
	"testing"

	"github.com/veilux-lab/keyward/internal/launchd"
)

func TestSignedStopHoldsUntilStartAndKeepsLoginStartup(t *testing.T) {
	h := setup(t)
	if _, err := h.m.Run("install"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.m.Run("stop"); err != nil || h.loaded {
		t.Fatalf("stop: %v, loaded=%v", err, h.loaded)
	}
	if _, err := os.Stat(h.plist()); err != nil {
		t.Fatal("stop removed the login agent")
	}
	h.calls = nil
	if err := h.m.Ensure(); err == nil || !strings.Contains(err.Error(), "service start") || len(h.calls) != 0 {
		t.Fatalf("first use after stop: %v, calls %v", err, h.calls)
	}
	if status, err := h.m.Run("status"); err != nil || !strings.Contains(status, "stopped") {
		t.Fatalf("status after stop = %q, %v", status, err)
	}
	if _, err := h.m.Run("start"); err != nil || !h.loaded {
		t.Fatalf("start: %v, loaded=%v", err, h.loaded)
	}
	if err := h.m.Ensure(); err != nil {
		t.Fatalf("first use after start: %v", err)
	}
}

func TestHomebrewStopUnloadsWithoutUnregistering(t *testing.T) {
	h := brewSetup(t)
	if _, err := h.m.Run("install"); err != nil {
		t.Fatal(err)
	}
	h.calls = nil
	if _, err := h.m.Run("stop"); err != nil || h.loaded {
		t.Fatalf("stop: %v, loaded=%v", err, h.loaded)
	}
	calls := strings.Join(h.calls, "\n")
	if !strings.Contains(calls, "launchctl bootout gui/") || strings.Contains(calls, "services stop") {
		t.Fatalf("stop should unload and keep brew's login registration: %s", calls)
	}
	if err := h.m.Ensure(); err == nil || !strings.Contains(err.Error(), "service start") {
		t.Fatalf("first use after stop: %v", err)
	}
	if _, err := h.m.Run("start"); err != nil || !h.loaded {
		t.Fatalf("start: %v, loaded=%v", err, h.loaded)
	}
}

func TestStartDoesNotUndoUninstall(t *testing.T) {
	h := brewSetup(t)
	if _, err := h.m.Run("uninstall"); err != nil {
		t.Fatal(err)
	}
	h.calls = nil
	if _, err := h.m.Run("start"); err == nil || !strings.Contains(err.Error(), "service install") || len(h.calls) != 0 {
		t.Fatalf("start after uninstall: %v, calls %v", err, h.calls)
	}
}

// A daemon started any other way, such as at login, ends the stop.
func TestClearStoppedAllowsFirstUseStartupAgain(t *testing.T) {
	h := brewSetup(t)
	if _, err := h.m.Run("stop"); err != nil {
		t.Fatal(err)
	}
	if err := launchd.ClearStopped(h.m.Home); err != nil {
		t.Fatal(err)
	}
	if err := h.m.Ensure(); err != nil {
		t.Fatalf("first use after the stop was cleared: %v", err)
	}
	if err := launchd.ClearStopped(t.TempDir()); err != nil {
		t.Fatalf("clearing with no startup state: %v", err)
	}
}

func TestUninstallMessageNamesWhatIsKeptAndHowToReturn(t *testing.T) {
	signed := setup(t)
	brew := brewSetup(t)
	for name, run := range map[string]func(string) (string, error){"signed": signed.m.Run, "homebrew": brew.m.Run} {
		message, err := run("uninstall")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, want := range []string{"Kept:", "Keychain items", "keyward service install"} {
			if !strings.Contains(message, want) {
				t.Errorf("%s uninstall message lacks %q:\n%s", name, want, message)
			}
		}
		if strings.Contains(message, "formula") || strings.Contains(message, ";") {
			t.Errorf("%s uninstall message is still terse jargon:\n%s", name, message)
		}
	}
}

func TestHomebrewRemoveUninstallsTheFormulaThenTheTap(t *testing.T) {
	h := brewSetup(t)
	if _, err := h.m.Remove(); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(h.calls, "\n"); got != "brew uninstall veilux-lab/keyward/keyward\nbrew untap veilux-lab/keyward" {
		t.Fatalf("calls:\n%s", got)
	}
}

func TestSignedRemoveDeletesTheInstalledBinary(t *testing.T) {
	h := setup(t)
	if _, err := h.m.Run("install"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.m.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(h.binary()); !os.IsNotExist(err) {
		t.Fatal("the signed binary remains")
	}
	if _, err := h.m.Remove(); err != nil {
		t.Fatalf("removing again: %v", err)
	}
}
