package cli_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type removal struct {
	h       *harness
	dirs    []string
	calls   []string
	removed bool
}

func uninstallFixture(t *testing.T, answer string) *removal {
	t.Helper()
	r := &removal{h: newHarness(t, answer, nil, nil)}
	root := t.TempDir()
	for _, name := range []string{"state", "logs"} {
		dir := filepath.Join(root, name)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(dir, "file"), []byte("fixture"), 0o600)
		r.dirs = append(r.dirs, dir)
	}
	r.h.cli.DataDirs = r.dirs
	r.h.cli.Service = func(action string) (string, error) {
		r.calls = append(r.calls, "service "+action)
		return "✓ stopped", nil
	}
	r.h.cli.RemovePackage = func() (string, error) {
		r.calls = append(r.calls, "package")
		for _, dir := range r.dirs {
			if _, err := os.Stat(dir); err == nil {
				t.Error("the package was removed before local data")
			}
		}
		r.removed = true
		return "brew uninstall and untap", nil
	}
	return r
}

func TestUninstallRemovesEverythingButKeychainItemsAfterYes(t *testing.T) {
	r := uninstallFixture(t, "yes\n")
	if code := r.h.cli.Run([]string{"uninstall"}); code != 0 {
		t.Fatalf("exit %d: %s", code, r.h.err())
	}
	if strings.Join(r.calls, ",") != "service uninstall,package" || !r.removed {
		t.Fatalf("calls = %v", r.calls)
	}
	for _, dir := range r.dirs {
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Errorf("%s remains", dir)
		}
	}
	for _, want := range []string{"restore", "Keychain items"} {
		if !strings.Contains(r.h.err(), want) {
			t.Errorf("the warning lacks %q:\n%s", want, r.h.err())
		}
	}
	if !strings.Contains(r.h.out(), "Keychain items were kept") {
		t.Errorf("summary lacks what was kept:\n%s", r.h.out())
	}
}

func TestUninstallChangesNothingWithoutYes(t *testing.T) {
	r := uninstallFixture(t, "y\n")
	if code := r.h.cli.Run([]string{"uninstall"}); code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
	if len(r.calls) != 0 {
		t.Fatalf("calls = %v", r.calls)
	}
	for _, dir := range r.dirs {
		if _, err := os.Stat(dir); err != nil {
			t.Errorf("%s was removed: %v", dir, err)
		}
	}
}

func TestUninstallStopsWhenTheServiceCannotBeStopped(t *testing.T) {
	r := uninstallFixture(t, "yes\n")
	r.h.cli.Service = func(string) (string, error) { return "", errors.New("launchctl failed") }
	if code := r.h.cli.Run([]string{"uninstall"}); code != 1 || !strings.Contains(r.h.err(), "launchctl failed") {
		t.Fatalf("exit %d: %s", code, r.h.err())
	}
	if r.removed {
		t.Fatal("the package was removed although the daemon may still run")
	}
	for _, dir := range r.dirs {
		if _, err := os.Stat(dir); err != nil {
			t.Errorf("%s was removed: %v", dir, err)
		}
	}
}

func TestUninstallRemovesBackupsBesideMigratedFiles(t *testing.T) {
	r := uninstallFixture(t, "yes\n")
	r.h.cli.Home = t.TempDir()
	legacy := filepath.Join(r.h.cli.Home, ".zshrc.keyward-backup-20261004T101500Z")
	if err := os.WriteFile(legacy, []byte(rcFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := r.h.cli.Run([]string{"uninstall"}); code != 0 {
		t.Fatalf("exit %d: %s", code, r.h.err())
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Error("a plaintext backup beside ~/.zshrc survived uninstall")
	}
}

func TestUninstallOfADevelopmentBuildLeavesTheBinary(t *testing.T) {
	r := uninstallFixture(t, "yes\n")
	r.h.cli.RemovePackage = nil
	if code := r.h.cli.Run([]string{"uninstall"}); code != 0 {
		t.Fatalf("exit %d: %s", code, r.h.err())
	}
	if !strings.Contains(r.h.out(), "delete this keyward binary yourself") {
		t.Errorf("output does not explain the remaining binary:\n%s", r.h.out())
	}
}

func TestUninstallIsUnavailableForIsolatedInstances(t *testing.T) {
	r := uninstallFixture(t, "yes\n")
	r.h.cli.DataDirs = nil
	if code := r.h.cli.Run([]string{"uninstall"}); code != 1 || len(r.calls) != 0 {
		t.Fatalf("exit %d, calls %v", code, r.calls)
	}
}
