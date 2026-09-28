package cli_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nwokolo24/keyward/internal/cli"
	"github.com/nwokolo24/keyward/internal/vault"
)

const token = "eyJraWQiOiJzcGx1bmsiLCJhbGciOiJIUzI1NiJ9"

// execCall records what run would have handed to syscall.Exec. Exec cannot be
// tested directly because it replaces the process image, so it is injected.
type execCall struct {
	path  string
	argv  []string
	env   []string
	calls int
}

type harness struct {
	cli    *cli.CLI
	store  *vault.Memory
	stdout *bytes.Buffer
	stderr *bytes.Buffer
	exec   *execCall
}

// newHarness builds a CLI wired to an in-memory store, with stdin, both output
// streams, and exec all captured.
func newHarness(t *testing.T, stdin string, seed map[string]string, environ []string) *harness {
	t.Helper()

	store := vault.NewMemory()
	if seed != nil {
		if err := store.Seed(seed); err != nil {
			t.Fatalf("seeding: %v", err)
		}
	}

	h := &harness{
		store:  store,
		stdout: &bytes.Buffer{},
		stderr: &bytes.Buffer{},
		exec:   &execCall{},
	}
	h.cli = &cli.CLI{
		Store:   store,
		Stdin:   strings.NewReader(stdin),
		Stdout:  h.stdout,
		Stderr:  h.stderr,
		Environ: func() []string { return environ },
		ReadSecret: func() ([]byte, error) {
			return cli.TrimSecret([]byte(stdin)), nil
		},
		Exec: func(path string, argv, env []string) error {
			h.exec.path = path
			h.exec.argv = argv
			h.exec.env = env
			h.exec.calls++
			return nil
		},
	}
	return h
}

func (h *harness) out() string { return h.stdout.String() }
func (h *harness) err() string { return h.stderr.String() }

// ===========================================================================
// Dispatch
// ===========================================================================

func TestNoArgsShowsUsage(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	if code := h.cli.Run(nil); code != 2 {
		t.Errorf("exit code = %d, want 2 for a usage error", code)
	}
	if !strings.Contains(h.err(), "usage") {
		t.Errorf("stderr = %q, want usage text", h.err())
	}
}

func TestUnknownCommand(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	if code := h.cli.Run([]string{"frobnicate"}); code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if !strings.Contains(h.err(), "frobnicate") {
		t.Errorf("stderr = %q, want it to name the unknown command", h.err())
	}
}

func TestHelpGoesToStdoutAndSucceeds(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	if code := h.cli.Run([]string{"help"}); code != 0 {
		t.Errorf("exit code = %d, want 0 when help was asked for", code)
	}
	if !strings.Contains(h.out(), "usage") {
		t.Errorf("stdout = %q, want usage text on stdout", h.out())
	}
}

func TestVersion(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	if code := h.cli.Run([]string{"version"}); code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if strings.TrimSpace(h.out()) == "" {
		t.Error("version printed nothing")
	}
}

// ===========================================================================
// add
// ===========================================================================

func TestAddStoresFromStdin(t *testing.T) {
	h := newHarness(t, token, nil, nil)
	if code := h.cli.Run([]string{"add", "splunk-mcp-token"}); code != 0 {
		t.Fatalf("exit code = %d, want 0. stderr: %s", code, h.err())
	}

	got, err := h.store.Get("splunk-mcp-token")
	if err != nil {
		t.Fatalf("Get after add: %v", err)
	}
	if string(got.Bytes()) != token {
		t.Error("stored value does not match what was on stdin")
	}
}

// echo appends a newline. Users will hit this constantly, so one trailing
// newline is stripped.
func TestAddTrimsOneTrailingNewline(t *testing.T) {
	for _, in := range []string{token + "\n", token + "\r\n"} {
		h := newHarness(t, in, nil, nil)
		if code := h.cli.Run([]string{"add", "t"}); code != 0 {
			t.Fatalf("exit code = %d for %q. stderr: %s", code, in, h.err())
		}
		got, err := h.store.Get("t")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if string(got.Bytes()) != token {
			t.Errorf("stored %q from input %q, want the value without the newline", got.Bytes(), in)
		}
	}
}

// A secret that genuinely contains newlines, such as a PEM key, must survive
// with its internal structure intact.
func TestAddPreservesInternalNewlines(t *testing.T) {
	pem := "-----BEGIN KEY-----\nabc\ndef\n-----END KEY-----\n"
	h := newHarness(t, pem, nil, nil)
	if code := h.cli.Run([]string{"add", "k"}); code != 0 {
		t.Fatalf("exit code = %d. stderr: %s", code, h.err())
	}
	got, err := h.store.Get("k")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if want := strings.TrimSuffix(pem, "\n"); string(got.Bytes()) != want {
		t.Errorf("stored %q, want %q", got.Bytes(), want)
	}
}

func TestAddRequiresAName(t *testing.T) {
	h := newHarness(t, token, nil, nil)
	if code := h.cli.Run([]string{"add"}); code != 2 {
		t.Errorf("exit code = %d, want 2 for a usage error", code)
	}
}

func TestAddRejectsInvalidName(t *testing.T) {
	h := newHarness(t, token, nil, nil)
	if code := h.cli.Run([]string{"add", "bad name"}); code == 0 {
		t.Error("add accepted an invalid name")
	}
	if strings.Contains(h.err(), token) {
		t.Error("error output leaked the secret")
	}
}

func TestAddRejectsEmptyValue(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	if code := h.cli.Run([]string{"add", "t"}); code == 0 {
		t.Error("add accepted an empty value")
	}
	if !strings.Contains(strings.ToLower(h.err()), "empty") {
		t.Errorf("stderr = %q, want it to explain the value was empty", h.err())
	}
}

// Overwriting must be deliberate, and the error has to say how.
func TestAddRefusesToOverwriteWithoutForce(t *testing.T) {
	h := newHarness(t, "new", map[string]string{"t": "original"}, nil)
	code := h.cli.Run([]string{"add", "t"})
	if code == 0 {
		t.Fatal("add overwrote an existing secret without -force")
	}
	if !strings.Contains(h.err(), "-force") {
		t.Errorf("stderr = %q, want it to mention -force", h.err())
	}

	got, _ := h.store.Get("t")
	if string(got.Bytes()) != "original" {
		t.Error("the existing value was modified by a rejected add")
	}
}

func TestAddForceReplaces(t *testing.T) {
	h := newHarness(t, "new", map[string]string{"t": "original"}, nil)
	if code := h.cli.Run([]string{"add", "-force", "t"}); code != 0 {
		t.Fatalf("exit code = %d. stderr: %s", code, h.err())
	}
	got, _ := h.store.Get("t")
	if string(got.Bytes()) != "new" {
		t.Errorf("value = %q, want it replaced", got.Bytes())
	}
}

// -force on a name that does not exist should still store it, rather than
// failing with ErrNotFound from Replace.
func TestAddForceCreatesWhenAbsent(t *testing.T) {
	h := newHarness(t, "v", nil, nil)
	if code := h.cli.Run([]string{"add", "-force", "fresh"}); code != 0 {
		t.Fatalf("exit code = %d. stderr: %s", code, h.err())
	}
	if _, err := h.store.Get("fresh"); err != nil {
		t.Errorf("Get after forced add: %v", err)
	}
}

// ===========================================================================
// ls and rm
// ===========================================================================

func TestLsPrintsSortedNames(t *testing.T) {
	h := newHarness(t, "", map[string]string{"zeta": "v", "alpha": "v", "mid": "v"}, nil)
	if code := h.cli.Run([]string{"ls"}); code != 0 {
		t.Fatalf("exit code = %d. stderr: %s", code, h.err())
	}
	want := "alpha\nmid\nzeta\n"
	if h.out() != want {
		t.Errorf("stdout = %q, want %q", h.out(), want)
	}
}

// ls must never print values, only names.
func TestLsPrintsNoValues(t *testing.T) {
	h := newHarness(t, "", map[string]string{"t": token}, nil)
	h.cli.Run([]string{"ls"})
	if strings.Contains(h.out(), token) {
		t.Error("ls printed a secret value")
	}
}

func TestLsEmptyStoreSucceeds(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	if code := h.cli.Run([]string{"ls"}); code != 0 {
		t.Errorf("exit code = %d, want 0 for an empty store", code)
	}
	if h.out() != "" {
		t.Errorf("stdout = %q, want nothing so output stays pipeable", h.out())
	}
}

func TestRm(t *testing.T) {
	h := newHarness(t, "", map[string]string{"t": "v"}, nil)
	if code := h.cli.Run([]string{"rm", "t"}); code != 0 {
		t.Fatalf("exit code = %d. stderr: %s", code, h.err())
	}
	if _, err := h.store.Get("t"); !errors.Is(err, vault.ErrNotFound) {
		t.Errorf("Get after rm = %v, want ErrNotFound", err)
	}
}

func TestRmMissingFails(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	if code := h.cli.Run([]string{"rm", "absent"}); code == 0 {
		t.Error("rm of an absent secret succeeded")
	}
}

func TestRmRequiresAName(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	if code := h.cli.Run([]string{"rm"}); code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
}

// ===========================================================================
// run
// ===========================================================================

func TestRunResolvesAndExecs(t *testing.T) {
	env := []string{
		"PATH=/usr/bin:/bin",
		"SPLUNK_MCP_TOKEN=cap://splunk-mcp-token",
	}
	h := newHarness(t, "", map[string]string{"splunk-mcp-token": token}, env)

	if code := h.cli.Run([]string{"run", "--", "printenv", "SPLUNK_MCP_TOKEN"}); code != 0 {
		t.Fatalf("exit code = %d. stderr: %s", code, h.err())
	}
	if h.exec.calls != 1 {
		t.Fatalf("exec called %d times, want 1", h.exec.calls)
	}
	if !strings.HasSuffix(h.exec.path, "printenv") {
		t.Errorf("exec path = %q, want it to resolve printenv", h.exec.path)
	}
	if want := []string{"printenv", "SPLUNK_MCP_TOKEN"}; !equal(h.exec.argv, want) {
		t.Errorf("argv = %v, want %v", h.exec.argv, want)
	}
	if !contains(h.exec.env, "SPLUNK_MCP_TOKEN="+token) {
		t.Error("the child environment does not contain the resolved value")
	}
	if contains(h.exec.env, "SPLUNK_MCP_TOKEN=cap://splunk-mcp-token") {
		t.Error("the child environment still contains the unresolved reference")
	}
}

// The -- separator is conventional but should not be mandatory.
func TestRunWorksWithoutSeparator(t *testing.T) {
	h := newHarness(t, "", nil, []string{"PATH=/usr/bin:/bin"})
	if code := h.cli.Run([]string{"run", "printenv"}); code != 0 {
		t.Fatalf("exit code = %d. stderr: %s", code, h.err())
	}
	if h.exec.calls != 1 {
		t.Errorf("exec called %d times, want 1", h.exec.calls)
	}
}

func TestRunRequiresACommand(t *testing.T) {
	for _, args := range [][]string{{"run"}, {"run", "--"}} {
		h := newHarness(t, "", nil, nil)
		if code := h.cli.Run(args); code != 2 {
			t.Errorf("Run(%v) exit code = %d, want 2", args, code)
		}
		if h.exec.calls != 0 {
			t.Errorf("Run(%v) called exec", args)
		}
	}
}

// A missing reference must stop the command entirely. Executing with a literal
// cap:// value would produce an authentication failure with no visible cause.
func TestRunDoesNotExecWhenResolutionFails(t *testing.T) {
	env := []string{"SPLUNK_MCP_TOKEN=cap://splunk-mcp-token"}
	h := newHarness(t, "", nil, env)

	code := h.cli.Run([]string{"run", "--", "printenv"})
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if h.exec.calls != 0 {
		t.Fatal("exec ran despite a reference that could not be resolved")
	}
	if !strings.Contains(h.err(), "SPLUNK_MCP_TOKEN") {
		t.Errorf("stderr = %q, want it to name the variable", h.err())
	}
}

// The error should tell the reader how to fix it. This is the cooperation layer:
// a message an agent or a person can act on without further guessing.
func TestRunSuggestsHowToFixAMissingSecret(t *testing.T) {
	h := newHarness(t, "", nil, []string{"T=cap://splunk-mcp-token"})
	h.cli.Run([]string{"run", "--", "printenv"})

	if !strings.Contains(h.err(), "keyward add splunk-mcp-token") {
		t.Errorf("stderr = %q, want it to suggest `keyward add splunk-mcp-token`", h.err())
	}
}

func TestRunReportsUnknownCommand(t *testing.T) {
	h := newHarness(t, "", nil, []string{"PATH=/nonexistent"})
	code := h.cli.Run([]string{"run", "--", "definitely-not-a-real-binary-xyz"})
	if code == 0 {
		t.Error("run succeeded for a command that does not exist")
	}
	if h.exec.calls != 0 {
		t.Error("exec was called for a command that could not be found")
	}
}

// Nothing in run's own output may contain a resolved value. It goes to the child
// process and nowhere else.
func TestRunPrintsNoSecrets(t *testing.T) {
	env := []string{"PATH=/usr/bin:/bin", "T=cap://t"}
	h := newHarness(t, "", map[string]string{"t": token}, env)

	h.cli.Run([]string{"run", "--", "printenv"})
	if strings.Contains(h.out(), token) || strings.Contains(h.err(), token) {
		t.Errorf("run printed a secret.\nstdout: %s\nstderr: %s", h.out(), h.err())
	}
}

// ===========================================================================
// Failure hints
//
// These messages are the cooperation layer: an error that names the next step is
// the difference between an agent recovering and an agent guessing. They are
// tested because they are the product, not decoration.
// ===========================================================================

// denyAll stands in for a locked keychain or a dismissed prompt.
type denyAll struct{ vault.Store }

func (denyAll) Get(string) (vault.Secret, error) { return vault.Secret{}, vault.ErrDenied }

func TestRunHintForDeniedAccess(t *testing.T) {
	h := newHarness(t, "", nil, []string{"T=cap://locked"})
	h.cli.Store = denyAll{Store: h.store}

	if code := h.cli.Run([]string{"run", "--", "printenv"}); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(h.err(), "unlock your keychain") {
		t.Errorf("stderr = %q, want a hint about unlocking or approving", h.err())
	}
	if h.exec.calls != 0 {
		t.Error("exec ran despite access being denied")
	}
}

func TestRunHintForMalformedReference(t *testing.T) {
	h := newHarness(t, "", nil, []string{"T=cap://bad name"})

	if code := h.cli.Run([]string{"run", "--", "printenv"}); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(h.err(), "fix the reference where it is written") {
		t.Errorf("stderr = %q, want a hint about fixing the reference", h.err())
	}
}

// Several broken references should each get their own hint, so one run tells the
// user everything they have to fix.
func TestRunHintsForEveryFailure(t *testing.T) {
	h := newHarness(t, "", nil, []string{
		"A=cap://absent-one",
		"B=cap://absent-two",
	})
	h.cli.Run([]string{"run", "--", "printenv"})

	for _, want := range []string{
		"keyward add absent-one",
		"keyward add absent-two",
	} {
		if !strings.Contains(h.err(), want) {
			t.Errorf("stderr omits %q:\n%s", want, h.err())
		}
	}
}

// ===========================================================================
// Store failures
//
// The Keychain can fail for reasons unrelated to a missing secret. Those paths
// must report rather than crash or silently succeed.
// ===========================================================================

var errStoreBroken = errors.New("keychain unavailable")

type brokenStore struct{ vault.Store }

func (brokenStore) Get(string) (vault.Secret, error)   { return vault.Secret{}, errStoreBroken }
func (brokenStore) Put(string, vault.Secret) error     { return errStoreBroken }
func (brokenStore) Replace(string, vault.Secret) error { return errStoreBroken }
func (brokenStore) Delete(string) error                { return errStoreBroken }
func (brokenStore) List() ([]string, error)            { return nil, errStoreBroken }

func TestCommandsReportStoreFailures(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"add", []string{"add", "t"}},
		{"add -force", []string{"add", "-force", "t"}},
		{"ls", []string{"ls"}},
		{"rm", []string{"rm", "t"}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, token, nil, nil)
			h.cli.Store = brokenStore{}

			if code := h.cli.Run(tt.args); code != 1 {
				t.Errorf("exit code = %d, want 1", code)
			}
			if !strings.Contains(h.err(), "keychain unavailable") {
				t.Errorf("stderr = %q, want the underlying cause", h.err())
			}
			if strings.Contains(h.err(), token) {
				t.Error("error output leaked the secret")
			}
		})
	}
}

// A failure that is not a *resolve.Error must still be reported rather than
// falling through the type switch silently.
func TestRunReportsNonResolveError(t *testing.T) {
	h := newHarness(t, "", nil, []string{"T=cap://t"})
	h.cli.Store = brokenStore{}

	if code := h.cli.Run([]string{"run", "--", "printenv"}); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(h.err(), "keychain unavailable") {
		t.Errorf("stderr = %q, want the underlying cause", h.err())
	}
	if h.exec.calls != 0 {
		t.Error("exec ran despite a store failure")
	}
}

// Exec itself can fail — a binary that is found but not executable, for example.
func TestRunReportsExecFailure(t *testing.T) {
	h := newHarness(t, "", nil, []string{"PATH=/usr/bin:/bin"})
	h.cli.Exec = func(string, []string, []string) error { return errors.New("permission denied") }

	if code := h.cli.Run([]string{"run", "--", "printenv"}); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(h.err(), "permission denied") {
		t.Errorf("stderr = %q, want the exec failure", h.err())
	}
}

func TestAddReportsReadFailure(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	h.cli.ReadSecret = func() ([]byte, error) { return nil, errors.New("stdin closed") }

	if code := h.cli.Run([]string{"add", "t"}); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(h.err(), "stdin closed") {
		t.Errorf("stderr = %q, want the read failure", h.err())
	}
}

// -force falls back from Replace to Put when the name is absent. If that Put also
// fails, the failure has to surface rather than be swallowed by the fallback.
type absentThenBroken struct{ vault.Store }

func (absentThenBroken) Replace(string, vault.Secret) error { return vault.ErrNotFound }
func (absentThenBroken) Put(string, vault.Secret) error     { return errStoreBroken }

func TestAddForceReportsFallbackPutFailure(t *testing.T) {
	h := newHarness(t, token, nil, nil)
	h.cli.Store = absentThenBroken{Store: h.store}

	if code := h.cli.Run([]string{"add", "-force", "t"}); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(h.err(), "keychain unavailable") {
		t.Errorf("stderr = %q, want the underlying cause", h.err())
	}
}

func TestAddRejectsUnknownFlag(t *testing.T) {
	h := newHarness(t, token, nil, nil)
	if code := h.cli.Run([]string{"add", "-nonsense", "t"}); code != 2 {
		t.Errorf("exit code = %d, want 2 for a bad flag", code)
	}
}

// ===========================================================================
// migrate
//
// The bare command applies, after showing the plan and requiring the literal
// string "yes". --dry-run shows the plan and stops.
// ===========================================================================

const rcFixture = `export EDITOR=vim
export SPLUNK_MCP_TOKEN=eyJraWQiOiJzcGx1bmsiLCJhbGciOiJIUzI1NiJ9
`

func writeFixture(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".zshrc")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	return path
}

// The plan has to be on screen before the question is asked, or the user is
// approving something they have not seen.
func TestMigratePromptsAfterShowingThePlan(t *testing.T) {
	path := writeFixture(t, rcFixture)
	h := newHarness(t, "yes\n", nil, nil)

	if code := h.cli.Run([]string{"migrate", path}); code != 0 {
		t.Fatalf("exit code = %d. stderr: %s", code, h.err())
	}

	if !strings.Contains(h.out(), "cap://splunk-mcp-token") {
		t.Errorf("the plan was not printed:\n%s", h.out())
	}
	prompt := h.err()
	if !strings.Contains(prompt, "yes") {
		t.Errorf("the prompt does not say what to type:\n%s", prompt)
	}
	if !strings.Contains(prompt, "1") {
		t.Errorf("the prompt does not say how many values are involved:\n%s", prompt)
	}
}

func TestMigrateAppliesOnYes(t *testing.T) {
	path := writeFixture(t, rcFixture)
	h := newHarness(t, "yes\n", nil, nil)

	if code := h.cli.Run([]string{"migrate", path}); code != 0 {
		t.Fatalf("exit code = %d. stderr: %s", code, h.err())
	}
	got, _ := os.ReadFile(path)
	if !strings.Contains(string(got), "export SPLUNK_MCP_TOKEN='cap://splunk-mcp-token'") {
		t.Errorf("the file was not rewritten:\n%s", got)
	}
	if _, err := h.store.Get("splunk-mcp-token"); err != nil {
		t.Errorf("the secret was not stored: %v", err)
	}
	if !strings.Contains(h.out(), "keyward-backup") {
		t.Errorf("the backup location was not reported:\n%s", h.out())
	}
}

// Only the exact lowercase word counts. Anything else leaves the file alone.
func TestMigrateRefusesAnythingButYes(t *testing.T) {
	for _, answer := range []string{"no\n", "n\n", "y\n", "Yes\n", "YES\n", "yes please\n", "\n", ""} {
		t.Run(strings.TrimSpace(answer), func(t *testing.T) {
			path := writeFixture(t, rcFixture)
			h := newHarness(t, answer, nil, nil)

			if code := h.cli.Run([]string{"migrate", path}); code != 1 {
				t.Errorf("exit code = %d for %q, want 1", code, answer)
			}
			if got, _ := os.ReadFile(path); string(got) != rcFixture {
				t.Errorf("the file was modified after answering %q", answer)
			}
			if names, _ := h.store.List(); len(names) != 0 {
				t.Errorf("stored %v after answering %q", names, answer)
			}
		})
	}
}

// Surrounding whitespace is a typo, not a refusal.
func TestMigrateAcceptsYesWithSurroundingSpace(t *testing.T) {
	path := writeFixture(t, rcFixture)
	h := newHarness(t, "  yes  \n", nil, nil)

	if code := h.cli.Run([]string{"migrate", path}); code != 0 {
		t.Fatalf("exit code = %d. stderr: %s", code, h.err())
	}
	if got, _ := os.ReadFile(path); !strings.Contains(string(got), "cap://") {
		t.Error("the file was not rewritten")
	}
}

// Empty stdin means nothing can answer the question — a pipeline, or an agent with
// no terminal. Silently applying there would be the worst possible default.
func TestMigrateAbortsWhenNothingCanAnswer(t *testing.T) {
	path := writeFixture(t, rcFixture)
	h := newHarness(t, "", nil, nil)

	if code := h.cli.Run([]string{"migrate", path}); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if got, _ := os.ReadFile(path); string(got) != rcFixture {
		t.Error("the file was modified with no confirmation available")
	}
}

// --dry-run prints the plan and stops. It must not ask anything, so it is safe in
// a pipeline and safe for an agent to run.
func TestMigrateDryRunOnlyPrints(t *testing.T) {
	path := writeFixture(t, rcFixture)
	// Stdin says yes. --dry-run must ignore it entirely.
	h := newHarness(t, "yes\n", nil, nil)

	if code := h.cli.Run([]string{"migrate", "--dry-run", path}); code != 0 {
		t.Fatalf("exit code = %d. stderr: %s", code, h.err())
	}
	if !strings.Contains(h.out(), "cap://splunk-mcp-token") {
		t.Errorf("the plan was not printed:\n%s", h.out())
	}
	if got, _ := os.ReadFile(path); string(got) != rcFixture {
		t.Error("--dry-run modified the file")
	}
	if names, _ := h.store.List(); len(names) != 0 {
		t.Errorf("--dry-run stored %v", names)
	}
	if strings.Contains(strings.ToLower(h.err()), "enter a value") {
		t.Errorf("--dry-run prompted:\n%s", h.err())
	}
}

// The diff reaches a terminal and may be produced by an agent. It must not carry
// the values it is describing.
func TestMigrateDryRunPrintsNoSecrets(t *testing.T) {
	path := writeFixture(t, rcFixture)
	h := newHarness(t, "", nil, nil)
	h.cli.Run([]string{"migrate", "--dry-run", path})

	secret := "eyJraWQiOiJzcGx1bmsiLCJhbGciOiJIUzI1NiJ9"
	if strings.Contains(h.out(), secret) || strings.Contains(h.err(), secret) {
		t.Errorf("migrate printed a secret.\nstdout: %s\nstderr: %s", h.out(), h.err())
	}
}

// -auto-approve is for scripts: same as answering yes, without asking.
func TestMigrateAutoApprove(t *testing.T) {
	path := writeFixture(t, rcFixture)
	h := newHarness(t, "", nil, nil)

	if code := h.cli.Run([]string{"migrate", "-auto-approve", path}); code != 0 {
		t.Fatalf("exit code = %d. stderr: %s", code, h.err())
	}
	if got, _ := os.ReadFile(path); !strings.Contains(string(got), "cap://") {
		t.Error("-auto-approve did not rewrite the file")
	}
	if strings.Contains(strings.ToLower(h.err()), "enter a value") {
		t.Errorf("-auto-approve prompted:\n%s", h.err())
	}
}

// Asking to both preview and approve is a contradiction. Guessing is how a script
// written to preview ends up rewriting a shell config.
func TestMigrateRejectsDryRunWithAutoApprove(t *testing.T) {
	path := writeFixture(t, rcFixture)
	h := newHarness(t, "", nil, nil)

	if code := h.cli.Run([]string{"migrate", "--dry-run", "-auto-approve", path}); code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if got, _ := os.ReadFile(path); string(got) != rcFixture {
		t.Error("the file was modified despite contradictory flags")
	}
}

func TestMigrateNothingToDoDoesNotPrompt(t *testing.T) {
	path := writeFixture(t, "export EDITOR=vim\n")
	h := newHarness(t, "", nil, nil)

	if code := h.cli.Run([]string{"migrate", path}); code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if !strings.Contains(strings.ToLower(h.out()), "nothing") {
		t.Errorf("stdout = %q, want it to say there is nothing to move", h.out())
	}
	if strings.Contains(strings.ToLower(h.err()), "enter a value") {
		t.Error("prompted with nothing to do")
	}
}

func TestMigrateRequiresAPath(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	if code := h.cli.Run([]string{"migrate"}); code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
}

func TestMigrateMissingFile(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	if code := h.cli.Run([]string{"migrate", filepath.Join(t.TempDir(), "nope")}); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
}

// A collision is the one planning failure that must stop everything: two variables
// mapping to one vault entry would make one silently resolve to the other's value.
func TestMigrateReportsPlanningFailure(t *testing.T) {
	path := writeFixture(t,
		"export MY_TOKEN=ghp_firstValue0123456789\nMY_TOKEN=ghp_secondValue0123456789\n")
	h := newHarness(t, "yes\n", nil, nil)

	if code := h.cli.Run([]string{"migrate", path}); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(h.err(), "my-token") {
		t.Errorf("stderr = %q, want it to name the colliding reference", h.err())
	}
	if names, _ := h.store.List(); len(names) != 0 {
		t.Errorf("stored %v despite refusing the plan", names)
	}
}

// An unrepresentable name is skipped, so a file containing one still migrates the
// rest rather than failing outright.
func TestMigrateSkipsUnusableNameAndContinues(t *testing.T) {
	path := writeFixture(t,
		"export oauth_client_id_=AbCdEfGhIjKlMnOpQrStUv\nexport GITHUB_TOKEN=ghp_fine0123456789abcd\n")
	h := newHarness(t, "yes\n", nil, nil)

	if code := h.cli.Run([]string{"migrate", path}); code != 0 {
		t.Fatalf("exit code = %d. stderr: %s", code, h.err())
	}
	if _, err := h.store.Get("github-token"); err != nil {
		t.Errorf("the usable secret was not stored: %v", err)
	}
	got, _ := os.ReadFile(path)
	if !strings.Contains(string(got), "export oauth_client_id_=AbCdEfGhIjKlMnOpQrStUv") {
		t.Error("the unusable line was modified")
	}
	if !strings.Contains(h.out(), "rename") {
		t.Errorf("stdout does not explain the skip:\n%s", h.out())
	}
}

func TestMigrateReportsApplyFailure(t *testing.T) {
	path := writeFixture(t, rcFixture)
	h := newHarness(t, "yes\n", nil, nil)
	h.cli.Store = brokenStore{}

	if code := h.cli.Run([]string{"migrate", path}); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if got, _ := os.ReadFile(path); string(got) != rcFixture {
		t.Error("the file was modified despite the failure")
	}
}

// Someone reading help should be able to tell what the bare command does without
// running it.
func TestHelpSaysMigrateAsksFirst(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	h.cli.Run([]string{"help"})

	out := strings.ToLower(h.out())
	if !strings.Contains(out, "asks") && !strings.Contains(out, "confirm") {
		t.Errorf("help does not say migrate asks before changing anything:\n%s", h.out())
	}
	if !strings.Contains(out, "dry-run") {
		t.Errorf("help does not mention --dry-run:\n%s", h.out())
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
