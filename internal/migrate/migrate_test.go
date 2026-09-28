package migrate_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nwokolo24/keyward/internal/migrate"
	"github.com/nwokolo24/keyward/internal/vault"
)

const rcFile = `# ~/.zshrc

export EDITOR=vim
export PATH="$HOME/.local/bin:$PATH"

# work
export AWS_PROFILE=dashweb
export SPLUNK_MCP_TOKEN=eyJraWQiOiJzcGx1bmsiLCJhbGciOiJIUzI1NiJ9
export GITHUB_TOKEN='ghp_exampleTokenValue0123456789'

alias gs='git status'
`

// writeRC puts content in a temp file and returns its path.
func writeRC(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".zshrc")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing the fixture: %v", err)
	}
	return path
}

func mustPlan(t *testing.T, path, content string) *migrate.Plan {
	t.Helper()
	p, err := migrate.NewPlan(path, []byte(content))
	if err != nil {
		t.Fatalf("NewPlan: %v", err)
	}
	return p
}

// ===========================================================================
// Planning
// ===========================================================================

func TestNewPlanFindsSecretsAndLeavesTheRestAlone(t *testing.T) {
	p := mustPlan(t, "/tmp/.zshrc", rcFile)

	var changed []string
	for _, c := range p.Changes {
		changed = append(changed, c.Name+"="+c.RefName)
	}
	want := []string{
		"SPLUNK_MCP_TOKEN=splunk-mcp-token",
		"GITHUB_TOKEN=github-token",
	}
	if strings.Join(changed, ",") != strings.Join(want, ",") {
		t.Errorf("Changes = %v, want %v", changed, want)
	}

	// Everything else must be accounted for, with a reason, so the plan can
	// explain itself rather than silently ignoring lines.
	var skipped []string
	for _, s := range p.Skips {
		if s.Reason == "" {
			t.Errorf("skip of %s has no reason", s.Name)
		}
		skipped = append(skipped, s.Name)
	}
	wantSkipped := []string{"EDITOR", "PATH", "AWS_PROFILE"}
	if strings.Join(skipped, ",") != strings.Join(wantSkipped, ",") {
		t.Errorf("Skips = %v, want %v", skipped, wantSkipped)
	}
}

func TestEmptyPlan(t *testing.T) {
	p := mustPlan(t, "/tmp/.zshrc", "export EDITOR=vim\n")
	if !p.Empty() {
		t.Error("Empty() = false, want true when there is nothing to move")
	}
}

// Two variables deriving the same reference name would collide on one vault
// entry, so the whole plan is refused rather than half applied.
func TestNewPlanRejectsCollidingRefNames(t *testing.T) {
	// The same variable assigned twice is the realistic way this happens — an rc
	// file that sets a token and later overrides it.
	content := "export MY_TOKEN=ghp_firstValue0123456789\nMY_TOKEN=ghp_secondValue0123456789\n"
	_, err := migrate.NewPlan("/tmp/.zshrc", []byte(content))
	if err == nil {
		t.Fatal("NewPlan accepted two assignments mapping to one reference name")
	}
	if !strings.Contains(err.Error(), "my-token") {
		t.Errorf("error = %v, want it to name the colliding reference", err)
	}
}

// A variable name that cannot become a valid reference is skipped, not fatal.
//
// Found by running against a real ~/.zshrc: one variable called oauth_client_id_
// blocked the entire file. A name that cannot be represented cannot collide with
// anything either, so leaving that one line in plaintext — the status quo — and
// migrating the rest is strictly better than migrating nothing.
func TestNewPlanSkipsUnusableNames(t *testing.T) {
	content := "export _TOKEN=ghp_unusableName0123456789\n" +
		"export oauth_client_id_=AbCdEfGhIjKlMnOpQrStUv\n" +
		"export GITHUB_TOKEN=ghp_perfectlyFine0123456789\n"

	p, err := migrate.NewPlan("/tmp/.zshrc", []byte(content))
	if err != nil {
		t.Fatalf("NewPlan: %v", err)
	}

	if len(p.Changes) != 1 || p.Changes[0].Name != "GITHUB_TOKEN" {
		t.Errorf("Changes = %+v, want only GITHUB_TOKEN", p.Changes)
	}

	skipped := map[string]string{}
	for _, s := range p.Skips {
		skipped[s.Name] = s.Reason
	}
	for _, name := range []string{"_TOKEN", "oauth_client_id_"} {
		reason, ok := skipped[name]
		if !ok {
			t.Errorf("%s was neither changed nor skipped", name)
			continue
		}
		// The reason has to be actionable: the user can rename the variable if
		// they want it migrated.
		if !strings.Contains(reason, "rename") {
			t.Errorf("skip reason for %s = %q, want it to suggest renaming", name, reason)
		}
	}
}

// ===========================================================================
// Diff
// ===========================================================================

// The diff is printed to a terminal, and may be printed by an agent running
// keyward. Showing the old line verbatim would put every secret in the file into
// scrollback and into that agent's context — the exact leak this tool exists to
// prevent.
func TestDiffRedactsValues(t *testing.T) {
	p := mustPlan(t, "/tmp/.zshrc", rcFile)
	diff := p.Diff()

	for _, secret := range []string{
		"eyJraWQiOiJzcGx1bmsiLCJhbGciOiJIUzI1NiJ9",
		"ghp_exampleTokenValue0123456789",
	} {
		if strings.Contains(diff, secret) {
			t.Errorf("diff leaked a secret value:\n%s", diff)
		}
	}

	// It must still be obvious which line changes and what it becomes.
	for _, want := range []string{
		"SPLUNK_MCP_TOKEN",
		"cap://splunk-mcp-token",
		"GITHUB_TOKEN",
		"cap://github-token",
	} {
		if !strings.Contains(diff, want) {
			t.Errorf("diff omits %q:\n%s", want, diff)
		}
	}
}

func TestDiffShowsLineNumbersAndReasons(t *testing.T) {
	p := mustPlan(t, "/tmp/.zshrc", rcFile)
	diff := p.Diff()

	// SPLUNK_MCP_TOKEN is on line 9 of rcFile.
	if !strings.Contains(diff, "line 9") {
		t.Errorf("diff does not give a line number:\n%s", diff)
	}
	if !strings.Contains(diff, "eyJ") {
		t.Errorf("diff does not explain why the line was picked:\n%s", diff)
	}
	if !strings.Contains(diff, "hidden") {
		t.Errorf("diff does not indicate the value was withheld:\n%s", diff)
	}
}

func TestDiffListsSkips(t *testing.T) {
	p := mustPlan(t, "/tmp/.zshrc", rcFile)
	diff := p.Diff()
	for _, want := range []string{"EDITOR", "AWS_PROFILE", "non-secret"} {
		if !strings.Contains(diff, want) {
			t.Errorf("diff omits skipped %q:\n%s", want, diff)
		}
	}
}

// ===========================================================================
// Apply
// ===========================================================================

func TestApply(t *testing.T) {
	path := writeRC(t, rcFile)
	store := vault.NewMemory()

	p, err := migrate.Read(path)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	applied, err := p.Apply(store)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// Secrets are in the vault.
	for name, want := range map[string]string{
		"splunk-mcp-token": "eyJraWQiOiJzcGx1bmsiLCJhbGciOiJIUzI1NiJ9",
		"github-token":     "ghp_exampleTokenValue0123456789",
	} {
		got, err := store.Get(name)
		if err != nil {
			t.Fatalf("Get(%q): %v", name, err)
		}
		if string(got.Bytes()) != want {
			t.Errorf("stored %q incorrectly", name)
		}
	}

	// The file now holds references, and nothing else changed.
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the rewritten file: %v", err)
	}
	want := strings.NewReplacer(
		"export SPLUNK_MCP_TOKEN=eyJraWQiOiJzcGx1bmsiLCJhbGciOiJIUzI1NiJ9",
		"export SPLUNK_MCP_TOKEN='cap://splunk-mcp-token'",
		"export GITHUB_TOKEN='ghp_exampleTokenValue0123456789'",
		"export GITHUB_TOKEN='cap://github-token'",
	).Replace(rcFile)
	if string(after) != want {
		t.Errorf("rewritten file =\n%s\nwant\n%s", after, want)
	}

	if len(applied.Stored) != 2 {
		t.Errorf("Stored = %v, want 2 names", applied.Stored)
	}
	if applied.BackupPath == "" {
		t.Error("Apply reported no backup path")
	}
}

func TestApplyWritesABackupOfTheOriginal(t *testing.T) {
	path := writeRC(t, rcFile)
	p, _ := migrate.Read(path)

	applied, err := p.Apply(vault.NewMemory())
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	backup, err := os.ReadFile(applied.BackupPath)
	if err != nil {
		t.Fatalf("reading the backup: %v", err)
	}
	if string(backup) != rcFile {
		t.Error("the backup does not match the original file")
	}
	if filepath.Dir(applied.BackupPath) != filepath.Dir(path) {
		t.Error("the backup was not written beside the original")
	}
}

func TestApplyPreservesFileMode(t *testing.T) {
	path := writeRC(t, rcFile)
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	p, _ := migrate.Read(path)
	if _, err := p.Apply(vault.NewMemory()); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("mode = %o, want 600 preserved", got)
	}
}

// Running migrate twice must be safe. The second pass finds only references,
// which Detect skips, so there is nothing left to do.
func TestApplyIsIdempotent(t *testing.T) {
	path := writeRC(t, rcFile)
	store := vault.NewMemory()

	p, _ := migrate.Read(path)
	if _, err := p.Apply(store); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	afterFirst, _ := os.ReadFile(path)

	p2, err := migrate.Read(path)
	if err != nil {
		t.Fatalf("second Read: %v", err)
	}
	if !p2.Empty() {
		t.Errorf("second plan has %d changes, want none", len(p2.Changes))
	}
	if _, err := p2.Apply(store); err != nil {
		t.Fatalf("second Apply: %v", err)
	}

	afterSecond, _ := os.ReadFile(path)
	if string(afterFirst) != string(afterSecond) {
		t.Error("a second Apply changed the file")
	}
}

// Re-running after a partial failure must not stop on ErrExists when the stored
// value is the one we were going to store anyway.
func TestApplyToleratesAlreadyStoredIdenticalValue(t *testing.T) {
	path := writeRC(t, rcFile)
	store := vault.NewMemory()
	if err := store.Seed(map[string]string{
		"splunk-mcp-token": "eyJraWQiOiJzcGx1bmsiLCJhbGciOiJIUzI1NiJ9",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	p, _ := migrate.Read(path)
	if _, err := p.Apply(store); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got, _ := os.ReadFile(path); !strings.Contains(string(got), "cap://splunk-mcp-token") {
		t.Error("the file was not rewritten")
	}
}

// A name already holding a different value is a conflict. Overwriting it could
// destroy a credential that something else depends on, so nothing is touched.
func TestApplyRefusesToOverwriteADifferentValue(t *testing.T) {
	path := writeRC(t, rcFile)
	store := vault.NewMemory()
	if err := store.Seed(map[string]string{"splunk-mcp-token": "a-different-token"}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	p, _ := migrate.Read(path)
	_, err := p.Apply(store)
	if err == nil {
		t.Fatal("Apply overwrote a secret that held a different value")
	}
	if !strings.Contains(err.Error(), "splunk-mcp-token") {
		t.Errorf("error = %v, want it to name the conflict", err)
	}

	if got, _ := os.ReadFile(path); string(got) != rcFile {
		t.Error("the file was modified despite the failure")
	}
}

// Storing happens before rewriting, so a vault failure leaves the file and its
// plaintext exactly as they were.
func TestApplyLeavesFileUntouchedWhenStoringFails(t *testing.T) {
	path := writeRC(t, rcFile)

	_, err := mustReadPlan(t, path).Apply(brokenPutStore{Store: vault.NewMemory()})
	if err == nil {
		t.Fatal("Apply succeeded despite the store failing")
	}
	if got, _ := os.ReadFile(path); string(got) != rcFile {
		t.Error("the file was modified despite the store failing")
	}
	if entries, _ := filepath.Glob(filepath.Join(filepath.Dir(path), "*keyward-backup*")); len(entries) != 0 {
		t.Errorf("a backup was written before the secrets were stored: %v", entries)
	}
}

// Guards against editing the file between a dry run and an apply: the plan would
// be describing lines that have moved.
func TestApplyRefusesIfTheFileChanged(t *testing.T) {
	path := writeRC(t, rcFile)
	p := mustReadPlan(t, path)

	if err := os.WriteFile(path, []byte("export EDITOR=vim\n"), 0o644); err != nil {
		t.Fatalf("rewriting the fixture: %v", err)
	}

	if _, err := p.Apply(vault.NewMemory()); err == nil {
		t.Fatal("Apply proceeded against a file that had changed")
	}
}

func TestApplyLeavesNoTemporaryFiles(t *testing.T) {
	path := writeRC(t, rcFile)
	applied, err := mustReadPlan(t, path).Apply(vault.NewMemory())
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		full := filepath.Join(filepath.Dir(path), e.Name())
		if full != path && full != applied.BackupPath {
			t.Errorf("unexpected file left behind: %s", e.Name())
		}
	}
}

func TestApplyOnEmptyPlanChangesNothing(t *testing.T) {
	path := writeRC(t, "export EDITOR=vim\n")
	applied, err := mustReadPlan(t, path).Apply(vault.NewMemory())
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if applied.BackupPath != "" {
		t.Error("a backup was written for a plan with no changes")
	}
	if got, _ := os.ReadFile(path); string(got) != "export EDITOR=vim\n" {
		t.Error("the file changed for a plan with no changes")
	}
}

// If the backup cannot be written, the file must not be rewritten. Secrets are
// already in the vault by this point, which is the safe direction: nothing is
// lost, and re-running once the directory is writable finishes the job.
func TestApplyStopsWhenTheBackupCannotBeWritten(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".zshrc")
	if err := os.WriteFile(path, []byte(rcFile), 0o644); err != nil {
		t.Fatalf("writing the fixture: %v", err)
	}

	p := mustReadPlan(t, path)
	store := vault.NewMemory()

	// Read and execute, but not write: the backup cannot be created.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })

	_, err := p.Apply(store)
	if err == nil {
		t.Fatal("Apply succeeded with an unwritable directory")
	}
	if !strings.Contains(err.Error(), "backup") {
		t.Errorf("error = %v, want it to say the backup failed", err)
	}
	if got, _ := os.ReadFile(path); string(got) != rcFile {
		t.Error("the file was rewritten despite the backup failing")
	}
	// The secrets did get stored, and saying so is what makes the failure
	// recoverable rather than mysterious.
	if names, _ := store.List(); len(names) == 0 {
		t.Error("no secrets were stored before the backup was attempted")
	}
}

// storeSecret consults the existing value to decide between "already done" and
// "conflict". If that read fails, it must not guess.
func TestApplyReportsAFailedConflictCheck(t *testing.T) {
	path := writeRC(t, rcFile)
	store := existsButUnreadable{Store: vault.NewMemory()}

	_, err := mustReadPlan(t, path).Apply(store)
	if err == nil {
		t.Fatal("Apply succeeded when the conflict check could not be made")
	}
	if got, _ := os.ReadFile(path); string(got) != rcFile {
		t.Error("the file was modified despite the failure")
	}
}

type existsButUnreadable struct{ vault.Store }

func (existsButUnreadable) Put(string, vault.Secret) error { return vault.ErrExists }
func (existsButUnreadable) Get(string) (vault.Secret, error) {
	return vault.Secret{}, errors.New("keychain read failed")
}

func TestReadMissingFile(t *testing.T) {
	if _, err := migrate.Read(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("Read succeeded for a file that does not exist")
	}
}

func mustReadPlan(t *testing.T, path string) *migrate.Plan {
	t.Helper()
	p, err := migrate.Read(path)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	return p
}

var errPutFailed = errors.New("keychain write failed")

type brokenPutStore struct{ vault.Store }

func (brokenPutStore) Put(string, vault.Secret) error { return errPutFailed }
