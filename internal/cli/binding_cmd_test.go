package cli_test

import (
	"strings"
	"testing"

	"github.com/veilux-lab/keyward/internal/vault"
)

// bind and unbind change where a secret may go, so like copy they need a
// terminal and refuse an agent or a pipe.
func TestBindRefusesWithoutATerminal(t *testing.T) {
	h := newHarness(t, "yes\n", map[string]string{"tok": token}, nil)
	if code := h.cli.Run([]string{"bind", "tok", "--program", "printenv"}); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if bs, _ := h.store.GetBindings("tok"); len(bs) != 0 {
		t.Errorf("bound without a terminal: %v", bs)
	}
	if !strings.Contains(h.err(), "terminal") {
		t.Errorf("did not refuse to a non-terminal:\n%s", h.err())
	}
}

func TestBindStoresProgramBindingAfterYes(t *testing.T) {
	h := newHarness(t, "yes\n", map[string]string{"tok": token}, nil)
	h.cli.Interactive = true
	want := progPath(t, "printenv")
	if code := h.cli.Run([]string{"bind", "tok", "--program", "printenv"}); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err())
	}
	bs, err := h.store.GetBindings("tok")
	if err != nil {
		t.Fatal(err)
	}
	if len(bs) != 1 || bs[0] != (vault.Binding{Kind: vault.BindingProgram, Program: want}) {
		t.Errorf("bindings = %v, want a program binding to %s", bs, want)
	}
}

func TestBindCancelledLeavesNoBinding(t *testing.T) {
	h := newHarness(t, "no\n", map[string]string{"tok": token}, nil)
	h.cli.Interactive = true
	if code := h.cli.Run([]string{"bind", "tok", "--program", "printenv"}); code == 0 {
		t.Errorf("exit 0 on a cancelled bind")
	}
	if bs, _ := h.store.GetBindings("tok"); len(bs) != 0 {
		t.Errorf("bound despite cancelling: %v", bs)
	}
}

func TestBindUnknownSecretFailsWithoutPrompting(t *testing.T) {
	h := newHarness(t, "yes\n", map[string]string{"tok": token}, nil)
	h.cli.Interactive = true
	if code := h.cli.Run([]string{"bind", "missing", "--program", "printenv"}); code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if strings.Contains(h.err(), "Enter a value") {
		t.Error("prompted for a secret that does not exist")
	}
}

func TestUnbindRemovesOneBinding(t *testing.T) {
	h := newHarness(t, "yes\n", map[string]string{"tok": token}, nil)
	h.cli.Interactive = true
	pe := progPath(t, "printenv")
	for _, p := range []string{pe, "/elsewhere/gh"} {
		if err := h.store.Bind("tok", vault.Binding{Kind: vault.BindingProgram, Program: p}); err != nil {
			t.Fatal(err)
		}
	}
	if code := h.cli.Run([]string{"unbind", "tok", "--program", "/elsewhere/gh"}); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err())
	}
	bs, _ := h.store.GetBindings("tok")
	if len(bs) != 1 || bs[0].Program != pe {
		t.Errorf("bindings = %v, want only the printenv binding", bs)
	}
}

func TestUnbindAllRemovesEveryBinding(t *testing.T) {
	h := newHarness(t, "yes\n", map[string]string{"tok": token}, nil)
	h.cli.Interactive = true
	if err := h.store.Bind("tok", vault.Binding{Kind: vault.BindingProgram, Program: "/elsewhere/gh"}); err != nil {
		t.Fatal(err)
	}
	if code := h.cli.Run([]string{"unbind", "tok", "--all"}); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err())
	}
	if bs, _ := h.store.GetBindings("tok"); len(bs) != 0 {
		t.Errorf("bindings remain after --all: %v", bs)
	}
}

// Adding a program to an already-bound secret reports the whole allowlist, not
// just the program just added.
func TestBindReportsFullAllowlist(t *testing.T) {
	h := newHarness(t, "yes\n", map[string]string{"tok": token}, nil)
	h.cli.Interactive = true
	pe := progPath(t, "printenv")
	bindProgram(t, h, "tok", "/elsewhere/gh")
	if code := h.cli.Run([]string{"bind", "tok", "--program", "printenv"}); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err())
	}
	if out := h.out(); !strings.Contains(out, pe) || !strings.Contains(out, "/elsewhere/gh") {
		t.Errorf("bind should report the full allowlist:\n%s", out)
	}
}

// Removing one of several bindings reports the remaining ones, not "unbound".
func TestUnbindReportsRemaining(t *testing.T) {
	h := newHarness(t, "yes\n", map[string]string{"tok": token}, nil)
	h.cli.Interactive = true
	pe := progPath(t, "printenv")
	for _, p := range []string{pe, "/elsewhere/gh"} {
		bindProgram(t, h, "tok", p)
	}
	if code := h.cli.Run([]string{"unbind", "tok", "--program", "/elsewhere/gh"}); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err())
	}
	if out := h.out(); !strings.Contains(out, pe) || strings.Contains(out, "any program") {
		t.Errorf("unbind should report the remaining binding, not unrestricted:\n%s", out)
	}
}

// Removing the last binding says the secret is unrestricted again.
func TestUnbindAllReportsUnrestricted(t *testing.T) {
	h := newHarness(t, "yes\n", map[string]string{"tok": token}, nil)
	h.cli.Interactive = true
	bindProgram(t, h, "tok", "/elsewhere/gh")
	if code := h.cli.Run([]string{"unbind", "tok", "--all"}); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err())
	}
	if !strings.Contains(h.out(), "any program") {
		t.Errorf("unbind --all should say the secret may go anywhere again:\n%s", h.out())
	}
}

// bindings lists secrets and where they may go, never values, and needs no
// terminal: it reveals nothing an agent should not see.
func TestBindingsListsNamesAndProgramsNotValues(t *testing.T) {
	h := newHarness(t, "", map[string]string{"tok": token, "other": "v"}, nil)
	if err := h.store.Bind("tok", vault.Binding{Kind: vault.BindingProgram, Program: "/opt/homebrew/bin/gh"}); err != nil {
		t.Fatal(err)
	}
	if code := h.cli.Run([]string{"bindings"}); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err())
	}
	out := h.out()
	if !strings.Contains(out, "tok") || !strings.Contains(out, "/opt/homebrew/bin/gh") {
		t.Errorf("bindings did not list the bound secret and program:\n%s", out)
	}
	if strings.Contains(out, token) {
		t.Error("bindings printed a value")
	}
}
