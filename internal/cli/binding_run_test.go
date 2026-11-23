package cli_test

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/veilux-lab/keyward/internal/vault"
)

// progPath is a real program's path as keyward run matches it: found on PATH,
// made absolute, symlinks not followed.
func progPath(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("no %s on PATH", name)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

func bindProgram(t *testing.T, h *harness, name, program string) {
	t.Helper()
	if err := h.store.Bind(name, vault.Binding{Kind: vault.BindingProgram, Program: program}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
}

// A secret bound to the program keyward run executes resolves normally.
func TestRunResolvesSecretBoundToTheCommand(t *testing.T) {
	env := []string{"PATH=/usr/bin:/bin", "TOKEN=cap://tok"}
	h := newHarness(t, "", map[string]string{"tok": token}, env)
	bindProgram(t, h, "tok", progPath(t, "printenv"))
	if code := h.cli.Run([]string{"run", "--only", "TOKEN", "--", "printenv", "TOKEN"}); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err())
	}
	if h.exec.calls != 1 {
		t.Fatalf("exec called %d times, want 1", h.exec.calls)
	}
	if !contains(h.exec.env, "TOKEN="+token) {
		t.Error("the value was not resolved for the bound program")
	}
}

// Named with --only but bound only to another program, the secret is refused:
// the caller asked for it here, and here is not where it may go.
func TestRunRefusesBoundSecretToAnotherProgram(t *testing.T) {
	env := []string{"PATH=/usr/bin:/bin", "TOKEN=cap://tok"}
	h := newHarness(t, "", map[string]string{"tok": token}, env)
	bindProgram(t, h, "tok", "/elsewhere/gh")
	code := h.cli.Run([]string{"run", "--only", "TOKEN", "--", "printenv", "TOKEN"})
	if code != 2 {
		t.Fatalf("exit %d, want 2: %s", code, h.err())
	}
	if h.exec.calls != 0 {
		t.Error("ran the command the secret is not bound to")
	}
	if !strings.Contains(h.err(), "tok") || !strings.Contains(h.err(), "/elsewhere/gh") {
		t.Errorf("message should name the secret and its program:\n%s", h.err())
	}
}

// Without --only, a bound secret the command is not allowed is left unresolved,
// so an unrelated command keeps working while other secrets still resolve.
func TestRunLeavesBoundSecretUnresolvedWithoutOnly(t *testing.T) {
	env := []string{"PATH=/usr/bin:/bin", "TOKEN=cap://tok", "OTHER=cap://oth"}
	h := newHarness(t, "", map[string]string{"tok": token, "oth": "othervalue"}, env)
	bindProgram(t, h, "tok", "/elsewhere/gh")
	if code := h.cli.Run([]string{"run", "--", "printenv"}); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err())
	}
	if h.exec.calls != 1 {
		t.Fatalf("exec called %d times, want 1", h.exec.calls)
	}
	if !contains(h.exec.env, "TOKEN=cap://tok") {
		t.Error("the bound secret should have been left unresolved")
	}
	if !contains(h.exec.env, "OTHER=othervalue") {
		t.Error("the unbound secret should still resolve")
	}
}

// A bound secret given to a script resolves only when every command the script
// runs is allowed.
func TestRunResolvesScriptWhenEveryCommandAllowed(t *testing.T) {
	env := []string{"PATH=/usr/bin:/bin", "TOKEN=cap://tok"}
	h := newHarness(t, "", map[string]string{"tok": token}, env)
	bindProgram(t, h, "tok", progPath(t, "printenv"))
	if code := h.cli.Run([]string{"run", "--only", "TOKEN", "--", "sh", "-c", "printenv TOKEN"}); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err())
	}
	if h.exec.calls != 1 {
		t.Fatalf("exec called %d times, want 1", h.exec.calls)
	}
}

// A script that runs a command keyward run cannot name is refused when a bound
// secret would enter its environment.
func TestRunRefusesScriptWithUnnameableCommandWhenBound(t *testing.T) {
	env := []string{"PATH=/usr/bin:/bin", "TOKEN=cap://tok", "CMD=printenv"}
	h := newHarness(t, "", map[string]string{"tok": token}, env)
	bindProgram(t, h, "tok", progPath(t, "printenv"))
	code := h.cli.Run([]string{"run", "--only", "TOKEN", "--", "sh", "-c", "$CMD hello"})
	if code != 2 {
		t.Fatalf("exit %d, want 2: %s", code, h.err())
	}
	if h.exec.calls != 0 {
		t.Error("ran a script with a command it could not name")
	}
}
