package launchd_test

import (
	"errors"
	"os"
	"path/filepath"
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
	if err := h.m.Ensure(); err == nil || !strings.Contains(err.Error(), "keyward start") || len(h.calls) != 0 {
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
	if err := h.m.Ensure(); err == nil || !strings.Contains(err.Error(), "keyward start") {
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
	if _, err := h.m.Run("start"); err == nil || !strings.Contains(err.Error(), "keyward start") || len(h.calls) != 0 {
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
		for _, want := range []string{"Kept:", "stored secrets", "keyward start"} {
			if !strings.Contains(message, want) {
				t.Errorf("%s uninstall message lacks %q:\n%s", name, want, message)
			}
		}
		if strings.Contains(message, "formula") || strings.Contains(message, ";") {
			t.Errorf("%s uninstall message is still terse jargon:\n%s", name, message)
		}
	}
}

// The download cache goes too, so brew leaves nothing of keyward behind.
func TestHomebrewRemoveUninstallsTheFormulaCleansItsCacheThenUntaps(t *testing.T) {
	h := brewSetup(t)
	if _, err := h.m.Remove(); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(h.calls, "\n"); got != "brew uninstall veilux-lab/keyward/keyward\nbrew cleanup --prune=all veilux-lab/keyward/keyward\nbrew untap veilux-lab/keyward" {
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

func TestHomebrewRestartReplacesTheRunningDaemon(t *testing.T) {
	h := brewSetup(t)
	if _, err := h.m.Run("install"); err != nil {
		t.Fatal(err)
	}
	h.calls = nil
	if err := h.m.Restart(); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(h.calls, "\n"); !strings.Contains(got, "brew services restart veilux-lab/keyward/keyward") {
		t.Fatalf("calls:\n%s", got)
	}
}

func TestSignedRestartKickstartsTheLoginAgent(t *testing.T) {
	h := setup(t)
	if _, err := h.m.Run("install"); err != nil {
		t.Fatal(err)
	}
	h.calls = nil
	if err := h.m.Restart(); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(h.calls, "\n"); !strings.Contains(got, "launchctl kickstart -k gui/501/com.veilux-lab.keyward.dev") {
		t.Fatalf("calls:\n%s", got)
	}
}

// brew cleanup leaves keyward's download behind on some Homebrew installs, so
// Remove deletes the exact cached files brew reports, and nothing else.
func TestHomebrewRemoveDeletesKeywardsCachedDownloads(t *testing.T) {
	h := brewSetup(t)
	cache := t.TempDir()
	downloads := filepath.Join(cache, "downloads")
	os.MkdirAll(downloads, 0o755)
	bottle := filepath.Join(downloads, "aaa--keyward--1.1.6.arm64_sequoia.bottle.tar.gz")
	source := filepath.Join(downloads, "bbb--keyward-1.1.6.tar.gz")
	other := filepath.Join(downloads, "ccc--hello-2.12.tar.gz")
	for _, f := range []string{bottle, source, other} {
		os.WriteFile(f, []byte("x"), 0o644)
	}
	link := filepath.Join(cache, "keyward--1.1.6.tar.gz")
	os.Symlink("downloads/bbb--keyward-1.1.6.tar.gz", link)
	otherLink := filepath.Join(cache, "hello--2.12.tar.gz")
	os.Symlink("downloads/ccc--hello-2.12.tar.gz", otherLink)
	h.m.Output = func(program string, args ...string) ([]byte, error) {
		switch strings.Join(args, " ") {
		case "--cache veilux-lab/keyward/keyward":
			return []byte(bottle + "\n"), nil
		case "--cache --build-from-source veilux-lab/keyward/keyward":
			return []byte(source + "\n"), nil
		}
		return nil, errors.New("unexpected brew call")
	}
	if _, err := h.m.Remove(); err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{bottle, source, link} {
		if _, err := os.Lstat(gone); !os.IsNotExist(err) {
			t.Errorf("%s remains", filepath.Base(gone))
		}
	}
	for _, kept := range []string{other, otherLink} {
		if _, err := os.Lstat(kept); err != nil {
			t.Errorf("%s was removed", filepath.Base(kept))
		}
	}
}

// A path brew reports that is not keyward's download is never deleted, and a
// failed lookup does not stop the uninstall.
func TestHomebrewRemoveDeletesOnlyKeywardCacheFiles(t *testing.T) {
	h := brewSetup(t)
	victim := filepath.Join(t.TempDir(), "downloads", "important.txt")
	os.MkdirAll(filepath.Dir(victim), 0o755)
	os.WriteFile(victim, nil, 0o644)
	h.m.Output = func(string, ...string) ([]byte, error) { return []byte(victim + "\n"), nil }
	if _, err := h.m.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(victim); err != nil {
		t.Error("deleted a file that is not keyward's download")
	}
	h.m.Output = func(string, ...string) ([]byte, error) { return nil, errors.New("brew failed") }
	if _, err := h.m.Remove(); err != nil {
		t.Errorf("a failed cache lookup stopped the uninstall: %v", err)
	}
}
