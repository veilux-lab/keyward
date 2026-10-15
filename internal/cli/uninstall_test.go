package cli_test

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/veilux-lab/keyward/internal/agents"
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
			if _, err := os.Stat(dir); err == nil && !strings.HasPrefix(r.h.cli.KeepDir, dir) {
				t.Error("the package was removed before local data")
			}
		}
		r.removed = true
		return "brew uninstall and untap", nil
	}
	return r
}

func TestUninstallRemovesEverythingButStoredSecretsAfterYes(t *testing.T) {
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
	for _, want := range []string{"restore", "stored secrets"} {
		if !strings.Contains(r.h.err(), want) {
			t.Errorf("the warning lacks %q:\n%s", want, r.h.err())
		}
	}
	if !strings.Contains(r.h.out(), "Stored secrets were kept") {
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

// The keys must go while the daemon still runs; afterwards nothing can delete them.
func TestUninstallDeletesBackupKeysBeforeStoppingTheDaemon(t *testing.T) {
	r := uninstallFixture(t, "")
	migrated(t, r.h)
	r.h.cli.Stdin = strings.NewReader("yes\n")
	r.h.cli.Service = func(string) (string, error) {
		if keys := backupKeys(t, r.h.store); len(keys) != 0 {
			t.Errorf("backup keys remained when the daemon stopped: %v", keys)
		}
		return "✓ stopped", nil
	}
	if code := r.h.cli.Run([]string{"uninstall"}); code != 0 {
		t.Fatalf("exit %d: %s", code, r.h.err())
	}
}

func TestUninstallRemovesKeywardsAgentFileAndNamesConfigsThatPointAtIt(t *testing.T) {
	r := uninstallFixture(t, "yes\n")
	home := homed(t, r.h)
	if err := agents.Default(home).Write(); err != nil {
		t.Fatal(err)
	}
	claude := filepath.Join(home, ".claude", "CLAUDE.md")
	os.MkdirAll(filepath.Dir(claude), 0o755)
	os.WriteFile(claude, []byte("@~/.agents/keyward.md\n"), 0o644)
	if code := r.h.cli.Run([]string{"uninstall"}); code != 0 {
		t.Fatalf("exit %d: %s", code, r.h.err())
	}
	if _, err := os.Stat(agentFile(home)); !os.IsNotExist(err) {
		t.Error("the agent instructions survived uninstall")
	}
	if !strings.Contains(r.h.err(), agents.Display) {
		t.Errorf("the plan did not list the agent instructions:\n%s", r.h.err())
	}
	if !strings.Contains(r.h.out(), claude) {
		t.Errorf("uninstall did not name the agent config still pointing at the file:\n%s", r.h.out())
	}
}

func TestUninstallKeepsAUsersOwnAgentFile(t *testing.T) {
	r := uninstallFixture(t, "yes\n")
	home := homed(t, r.h)
	os.MkdirAll(filepath.Dir(agentFile(home)), 0o755)
	os.WriteFile(agentFile(home), []byte("my notes\n"), 0o644)
	if code := r.h.cli.Run([]string{"uninstall"}); code != 0 {
		t.Fatalf("exit %d: %s", code, r.h.err())
	}
	if _, err := os.Stat(agentFile(home)); err != nil {
		t.Error("uninstall removed a file keyward did not write")
	}
}

// Uninstall names each file that would break, with the command that fixes it.
func TestUninstallNamesFilesThatStillUseReferences(t *testing.T) {
	r := uninstallFixture(t, "")
	homed(t, r.h)
	path := migrated(t, r.h)
	r.h.cli.Stdin = strings.NewReader("no\n")
	r.h.cli.Run([]string{"uninstall"})
	if !strings.Contains(r.h.err(), path) || !strings.Contains(r.h.err(), "keyward restore "+path) {
		t.Errorf("the plan does not name the migrated file and its restore command:\n%s", r.h.err())
	}
}

func TestUninstallWithoutPurgeKeepsTheVault(t *testing.T) {
	r := uninstallFixture(t, "yes\n")
	r.h.cli.PurgeVault = func() error { t.Error("the vault was purged without --purge"); return nil }
	if code := r.h.cli.Run([]string{"uninstall"}); code != 0 {
		t.Fatalf("exit %d: %s", code, r.h.err())
	}
}

// Purging while files still hold references would strand them for good.
func TestPurgeRefusesWhileFilesStillUseReferences(t *testing.T) {
	r := uninstallFixture(t, "")
	homed(t, r.h)
	path := migrated(t, r.h)
	r.h.cli.Stdin = strings.NewReader("yes\n")
	r.h.cli.PurgeVault = func() error { t.Error("purged while a file still used the vault"); return nil }
	if code := r.h.cli.Run([]string{"uninstall", "--purge"}); code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
	if len(r.calls) != 0 {
		t.Errorf("something was removed: %v", r.calls)
	}
	if !strings.Contains(r.h.err(), "keyward restore "+path) {
		t.Errorf("the refusal does not say how to restore:\n%s", r.h.err())
	}
}

func TestPurgeDeletesTheVaultOnceFilesAreRestored(t *testing.T) {
	r := uninstallFixture(t, "")
	homed(t, r.h)
	path := migrated(t, r.h)
	r.h.cli.Stdin = strings.NewReader("yes\n")
	if code := r.h.cli.Run([]string{"restore", path}); code != 0 {
		t.Fatalf("restore: %d %s", code, r.h.err())
	}
	purged := false
	r.h.cli.PurgeVault = func() error {
		if !slices.Contains(r.calls, "service uninstall") {
			t.Error("the vault was purged while the daemon still ran")
		}
		purged = true
		return nil
	}
	r.h.cli.Stdin = strings.NewReader("yes\n")
	r.h.stderr.Reset()
	if code := r.h.cli.Run([]string{"uninstall", "--purge"}); code != 0 {
		t.Fatalf("exit %d: %s", code, r.h.err())
	}
	if !purged || !strings.Contains(r.h.err(), "permanently") {
		t.Errorf("purged=%v; the plan must say the secrets go permanently:\n%s", purged, r.h.err())
	}
}

// restore cannot rewrite an MCP config, so uninstall points at keyward mcp unwrap.
func TestUninstallSendsMCPConfigsToMCPUndo(t *testing.T) {
	r := uninstallFixture(t, "")
	home := homed(t, r.h)
	config := filepath.Join(home, ".claude.json")
	os.WriteFile(config, []byte(`{"mcpServers": {"pagerduty": {"command": "/opt/homebrew/bin/keyward", "args": ["run", "--only", "PD_KEY", "--", "uvx", "pagerduty-mcp"], "env": {"PD_KEY": "cap://pagerduty-key"}}}}`), 0o600)
	r.h.cli.Stdin = strings.NewReader("no\n")
	r.h.cli.Run([]string{"uninstall"})
	if strings.Contains(r.h.err(), "keyward restore "+config) {
		t.Errorf("the plan says to restore an MCP config:\n%s", r.h.err())
	}
	if !strings.Contains(r.h.err(), "pagerduty") || !strings.Contains(r.h.err(), "keyward mcp unwrap") {
		t.Errorf("the plan does not name the server and keyward mcp unwrap:\n%s", r.h.err())
	}
}

// The vault sits inside keyward's folder: uninstall clears the folder around it,
// and only --purge takes the vault too.
func TestUninstallKeepsOnlyTheVaultFolder(t *testing.T) {
	r := uninstallFixture(t, "yes\n")
	vaultDir := filepath.Join(r.dirs[0], "vault")
	os.MkdirAll(vaultDir, 0o700)
	os.WriteFile(filepath.Join(vaultDir, "keyward.vault"), []byte("sealed"), 0o600)
	r.h.cli.KeepDir = vaultDir
	if code := r.h.cli.Run([]string{"uninstall"}); code != 0 {
		t.Fatalf("exit %d: %s", code, r.h.err())
	}
	if _, err := os.Stat(filepath.Join(vaultDir, "keyward.vault")); err != nil {
		t.Errorf("the vault was removed without --purge: %v", err)
	}
	entries, _ := os.ReadDir(r.dirs[0])
	if len(entries) != 1 || entries[0].Name() != "vault" {
		t.Errorf("left in keyward's folder: %v", entries)
	}
	if _, err := os.Stat(r.dirs[1]); !os.IsNotExist(err) {
		t.Errorf("a data folder without the vault was kept: %v", err)
	}
}
