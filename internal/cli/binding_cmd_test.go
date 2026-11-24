package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/veilux-lab/keyward/internal/vault"
)

// bindingsOf reads name's bindings straight from the harness's store.
func bindingsOf(t *testing.T, h *harness, name string) []vault.Binding {
	t.Helper()
	all, err := h.store.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	return all[name]
}

// bind and unbind change where a secret may go, so like copy they need a
// terminal and refuse an agent or a pipe, in words addressed to the reader.
func TestBindRefusesWithoutATerminal(t *testing.T) {
	for _, args := range [][]string{{"bind", "tok", "--program", "printenv"}, {"unbind", "tok", "--all"}} {
		h := newHarness(t, "yes\n", map[string]string{"tok": token}, nil)
		bindProgram(t, h, "tok", "/elsewhere/gh")
		if code := h.cli.Run(args); code != 2 {
			t.Fatalf("%v: exit %d, want 2", args, code)
		}
		if bs := bindingsOf(t, h, "tok"); len(bs) != 1 || bs[0].Program != "/elsewhere/gh" {
			t.Errorf("%v changed the bindings without a terminal: %v", args, bs)
		}
		if !strings.Contains(h.err(), "run it yourself in a terminal, not through an AI agent") {
			t.Errorf("%v did not refuse to a non-terminal:\n%s", args, h.err())
		}
		speaksToTheReader(t, h.err())
	}
}

func TestBindStoresProgramBindingAfterYes(t *testing.T) {
	h := newHarness(t, "yes\n", map[string]string{"tok": token}, nil)
	h.cli.Interactive = true
	want := progPath(t, "printenv")
	if code := h.cli.Run([]string{"bind", "tok", "--program", "printenv"}); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err())
	}
	if bs := bindingsOf(t, h, "tok"); len(bs) != 1 || bs[0] != (vault.Binding{Kind: vault.BindingProgram, Program: want}) {
		t.Errorf("bindings = %v, want a program binding to %s", bs, want)
	}
}

func TestBindCancelledLeavesNoBinding(t *testing.T) {
	h := newHarness(t, "no\n", map[string]string{"tok": token}, nil)
	h.cli.Interactive = true
	if code := h.cli.Run([]string{"bind", "tok", "--program", "printenv"}); code == 0 {
		t.Errorf("exit 0 on a cancelled bind")
	}
	if bs := bindingsOf(t, h, "tok"); len(bs) != 0 {
		t.Errorf("bound despite cancelling: %v", bs)
	}
}

// A typo, a backup's key, or a program not on PATH fails before the prompt, so
// no one says yes to something that is not there.
func TestBindFailsWithoutPromptingForWhatIsNotThere(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"bind", "missing", "--program", "printenv"}, "no secret is named missing"},
		{[]string{"bind", "keyward.backup.zshrc", "--program", "printenv"}, "no secret is named keyward.backup.zshrc"},
		{[]string{"bind", "tok", "--program", "definitely-not-a-program-xyz"}, "cannot find definitely-not-a-program-xyz"},
		{[]string{"unbind", "missing", "--all"}, "no secret is named missing"},
	} {
		h := newHarness(t, "yes\n", map[string]string{"tok": token}, nil)
		h.cli.Interactive = true
		if code := h.cli.Run(tc.args); code != 1 {
			t.Errorf("%v: exit %d, want 1", tc.args, code)
		}
		if !strings.Contains(h.err(), tc.want) || strings.Contains(h.err(), "Enter a value") {
			t.Errorf("%v: want %q and no prompt:\n%s", tc.args, tc.want, h.err())
		}
	}
}

func TestUnbindRemovesOneBinding(t *testing.T) {
	h := newHarness(t, "yes\n", map[string]string{"tok": token}, nil)
	h.cli.Interactive = true
	pe := progPath(t, "printenv")
	for _, p := range []string{pe, "/elsewhere/gh"} {
		bindProgram(t, h, "tok", p)
	}
	if code := h.cli.Run([]string{"unbind", "tok", "--program", "/elsewhere/gh"}); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err())
	}
	if bs := bindingsOf(t, h, "tok"); len(bs) != 1 || bs[0].Program != pe {
		t.Errorf("bindings = %v, want only the printenv binding", bs)
	}
	// It says what is left, not that the secret may go anywhere.
	if out := h.out(); !strings.Contains(out, pe) || strings.Contains(out, "any program") {
		t.Errorf("unbind should report the remaining binding:\n%s", out)
	}
}

// Removing the last binding says the secret may go to any program again.
func TestUnbindAllRemovesEveryBinding(t *testing.T) {
	h := newHarness(t, "yes\n", map[string]string{"tok": token}, nil)
	h.cli.Interactive = true
	bindProgram(t, h, "tok", "/elsewhere/gh")
	if code := h.cli.Run([]string{"unbind", "tok", "--all"}); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err())
	}
	if bs := bindingsOf(t, h, "tok"); len(bs) != 0 {
		t.Errorf("bindings remain after --all: %v", bs)
	}
	if !strings.Contains(h.out(), "any program") {
		t.Errorf("unbind --all should say the secret may go anywhere again:\n%s", h.out())
	}
}

// Unbinding a program the secret is not bound to changes nothing, so it does not
// ask for a yes to nothing.
func TestUnbindOfABindingThatIsNotThereDoesNotPrompt(t *testing.T) {
	for _, bound := range []bool{false, true} {
		h := newHarness(t, "yes\n", map[string]string{"tok": token}, nil)
		h.cli.Interactive = true
		if bound {
			bindProgram(t, h, "tok", "/elsewhere/gh")
		}
		if code := h.cli.Run([]string{"unbind", "tok", "--program", "/elsewhere/curl"}); code != 1 {
			t.Errorf("bound=%v: exit %d, want 1", bound, code)
		}
		if strings.Contains(h.err(), "Enter a value") {
			t.Errorf("bound=%v: prompted to remove a binding that is not there:\n%s", bound, h.err())
		}
	}
}

// Adding a program to an already-bound secret reports the whole list, not just
// the program just added.
func TestBindReportsFullAllowlist(t *testing.T) {
	h := newHarness(t, "yes\n", map[string]string{"tok": token}, nil)
	h.cli.Interactive = true
	pe := progPath(t, "printenv")
	bindProgram(t, h, "tok", "/elsewhere/gh")
	if code := h.cli.Run([]string{"bind", "tok", "--program", "printenv"}); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err())
	}
	if out := h.out(); !strings.Contains(out, pe) || !strings.Contains(out, "/elsewhere/gh") {
		t.Errorf("bind should report the full list:\n%s", out)
	}
}

// keyward run gives a bound secret only to a bound program it starts directly,
// so binding one an MCP server gets through a script, or through another
// program, would stop that server. bind says which before asking.
func TestBindWarnsAboutMCPServersItWouldStop(t *testing.T) {
	home := t.TempDir()
	os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"mcpServers": {
		"script-server": {"command": "keyward", "args": ["run", "--only", "GITHUB_TOKEN", "--", "sh", "-c", "exec npx -y mcp-remote https://api.example.com/mcp/"], "env": {"GITHUB_TOKEN": "cap://tok"}},
		"launcher-server": {"command": "keyward", "args": ["run", "--only", "T", "--", "env", "printenv", "T"], "env": {"T": "cap://tok"}},
		"bound-server": {"command": "keyward", "args": ["run", "--only", "T", "--", "printenv", "T"], "env": {"T": "cap://tok"}},
		"other-secret": {"command": "keyward", "args": ["run", "--only", "O", "--", "sh", "-c", "exec npx x"], "env": {"O": "cap://oth"}}}}`), 0o600)
	h := newHarness(t, "yes\n", map[string]string{"tok": token, "oth": "v"}, nil)
	h.cli.Home, h.cli.Workdir, h.cli.Interactive = home, t.TempDir(), true
	if code := h.cli.Run([]string{"bind", "tok", "--program", "printenv"}); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err())
	}
	warning, _, prompted := strings.Cut(h.err(), "Enter a value")
	if !prompted {
		t.Fatalf("bind did not ask:\n%s", h.err())
	}
	for _, name := range []string{"script-server", "launcher-server"} {
		if !strings.Contains(warning, name) {
			t.Errorf("the warning before the prompt does not name %s:\n%s", name, warning)
		}
	}
	for _, name := range []string{"bound-server", "other-secret"} {
		if strings.Contains(h.err(), name) {
			t.Errorf("the warning names %s, which keeps getting what it uses:\n%s", name, h.err())
		}
	}
	speaksToTheReader(t, h.err())
}

// prompted returns what a command printed before asking for "yes", failing if it
// never asked.
func prompted(t *testing.T, h *harness) string {
	t.Helper()
	before, _, ok := strings.Cut(h.err(), "Enter a value")
	if !ok {
		t.Fatalf("did not ask for yes:\n%s", h.err())
	}
	return before
}

// The question names the exact paths a yes binds, since PATH may find another
// program than the one you meant.
func TestBindAsksWithThePathsItWillStore(t *testing.T) {
	h := newHarness(t, "yes\n", map[string]string{"tok": token}, nil)
	h.cli.Interactive = true
	bindProgram(t, h, "tok", "/elsewhere/gh")
	if code := h.cli.Run([]string{"bind", "tok", "--program", "printenv"}); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err())
	}
	question := prompted(t, h)
	for _, want := range []string{progPath(t, "printenv"), "/elsewhere/gh"} {
		if !strings.Contains(question, want) {
			t.Errorf("the question does not show %s:\n%s", want, question)
		}
	}
}

// Removing some bindings narrows where a secret goes, and removing the last
// lets it go anywhere; the question says which, and what is left.
func TestUnbindAsksWhatChanges(t *testing.T) {
	pe := progPath(t, "printenv")
	for _, tc := range []struct {
		args       []string
		want, deny string
	}{
		{[]string{"unbind", "tok", "--program", "/elsewhere/gh"}, "Stop giving tok to", "any program"},
		{[]string{"unbind", "tok", "--all"}, "Let tok go to any program again?", "Stop giving"},
	} {
		h := newHarness(t, "yes\n", map[string]string{"tok": token}, nil)
		h.cli.Interactive = true
		for _, p := range []string{pe, "/elsewhere/gh"} {
			bindProgram(t, h, "tok", p)
		}
		if code := h.cli.Run(tc.args); code != 0 {
			t.Fatalf("%v: exit %d: %s", tc.args, code, h.err())
		}
		question := prompted(t, h)
		if !strings.Contains(question, tc.want) || strings.Contains(question, tc.deny) || !strings.Contains(question, "/elsewhere/gh") {
			t.Errorf("%v: want %q naming /elsewhere/gh:\n%s", tc.args, tc.want, question)
		}
	}
}

// writeServers writes a Claude Code config holding servers, as JSON.
func writeServers(t *testing.T, servers string) string {
	t.Helper()
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(servers), 0o600); err != nil {
		t.Fatal(err)
	}
	return home
}

// Narrowing a binding can stop a server that runs the program being removed, so
// unbind names it before asking, as bind does.
func TestUnbindWarnsAboutMCPServersItWouldStop(t *testing.T) {
	home := writeServers(t, `{"mcpServers": {"printing-server": {"command": "keyward", "args": ["run", "--only", "T", "--", "printenv", "T"], "env": {"T": "cap://tok"}}}}`)
	h := newHarness(t, "yes\n", map[string]string{"tok": token}, nil)
	h.cli.Home, h.cli.Workdir, h.cli.Interactive = home, t.TempDir(), true
	for _, p := range []string{progPath(t, "printenv"), "/elsewhere/gh"} {
		bindProgram(t, h, "tok", p)
	}
	if code := h.cli.Run([]string{"unbind", "tok", "--program", "printenv"}); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err())
	}
	if !strings.Contains(prompted(t, h), "printing-server") {
		t.Errorf("unbind did not name the server it stops:\n%s", h.err())
	}
}

// Only a server that gets the secret now and would not afterwards is named: one
// already stopped by an earlier binding, or in a project whose folder is gone,
// is not, while one whose script starts keyward run is.
func TestBindWarnsOnlyAboutServersItWouldStop(t *testing.T) {
	home := writeServers(t, `{"mcpServers": {
		"already-stopped": {"command": "keyward", "args": ["run", "--only", "T", "--", "printenv", "T"], "env": {"T": "cap://tok"}},
		"login-shell": {"command": "zsh", "args": ["-lc", "keyward run --only T -- uvx some-server"], "env": {"T": "cap://tok"}}},
		"projects": {"/nonexistent/keyward-test-project": {"mcpServers": {
		"gone-project": {"command": "keyward", "args": ["run", "--only", "T", "--", "uvx", "x"], "env": {"T": "cap://tok"}}}}}}`)
	h := newHarness(t, "yes\n", map[string]string{"tok": token}, nil)
	h.cli.Home, h.cli.Workdir, h.cli.Interactive = home, t.TempDir(), true
	bindProgram(t, h, "tok", "/elsewhere/gh")
	if code := h.cli.Run([]string{"bind", "tok", "--program", "true"}); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err())
	}
	if question := prompted(t, h); strings.Contains(question, "already-stopped") || strings.Contains(question, "gone-project") {
		t.Errorf("named a server this bind does not stop:\n%s", question)
	}

	// Unbound, every server that uses the secret gets it, so the first binding
	// stops both, including the one that starts keyward run from its script.
	h = newHarness(t, "yes\n", map[string]string{"tok": token}, nil)
	h.cli.Home, h.cli.Workdir, h.cli.Interactive = home, t.TempDir(), true
	if code := h.cli.Run([]string{"bind", "tok", "--program", "true"}); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err())
	}
	question := prompted(t, h)
	if !strings.Contains(question, "login-shell") || !strings.Contains(question, "already-stopped") || strings.Contains(question, "gone-project") {
		t.Errorf("want login-shell and already-stopped named, not gone-project:\n%s", question)
	}
}

// A config keyward cannot read is said so, rather than taken for one with no
// servers to stop.
func TestBindSaysWhichMCPConfigsItCouldNotRead(t *testing.T) {
	home := writeServers(t, `{not json`)
	h := newHarness(t, "yes\n", map[string]string{"tok": token}, nil)
	h.cli.Home, h.cli.Workdir, h.cli.Interactive = home, t.TempDir(), true
	if code := h.cli.Run([]string{"bind", "tok", "--program", "printenv"}); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err())
	}
	if !strings.Contains(prompted(t, h), "Could not read an MCP config") {
		t.Errorf("did not say the config could not be read:\n%s", h.err())
	}
}

// unbind names what it cannot remove instead of asking for a yes to nothing.
func TestUnbindNamesWhatIsNotThere(t *testing.T) {
	for _, tc := range []struct {
		bound []string
		args  []string
		want  string
	}{
		{nil, []string{"unbind", "tok", "--all"}, "tok is not bound"},
		{[]string{"/elsewhere/gh"}, []string{"unbind", "tok", "--program", "/elsewhere/gh", "--program", "/elsewhere/curl"}, "/elsewhere/curl"},
	} {
		h := newHarness(t, "yes\n", map[string]string{"tok": token}, nil)
		h.cli.Interactive = true
		for _, p := range tc.bound {
			bindProgram(t, h, "tok", p)
		}
		if code := h.cli.Run(tc.args); code != 1 {
			t.Errorf("%v: exit %d, want 1", tc.args, code)
		}
		if !strings.Contains(h.err(), tc.want) || strings.Contains(h.err(), "Enter a value") {
			t.Errorf("%v: want %q and no prompt:\n%s", tc.args, tc.want, h.err())
		}
		if got := bindingsOf(t, h, "tok"); len(got) != len(tc.bound) {
			t.Errorf("%v: bindings changed to %v", tc.args, got)
		}
	}
}

// With no MCP server using the secret there is nothing to warn about.
func TestBindDoesNotWarnWithoutMCPServers(t *testing.T) {
	h := newHarness(t, "yes\n", map[string]string{"tok": token}, nil)
	h.cli.Home, h.cli.Workdir, h.cli.Interactive = t.TempDir(), t.TempDir(), true
	if code := h.cli.Run([]string{"bind", "tok", "--program", "printenv"}); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err())
	}
	if strings.Contains(h.err(), "MCP") {
		t.Errorf("warned with no MCP servers:\n%s", h.err())
	}
}

// bindings lists secrets and where they may go, never values, and needs no
// terminal: it reveals nothing an agent should not see.
func TestBindingsListsNamesAndProgramsNotValues(t *testing.T) {
	h := newHarness(t, "", map[string]string{"tok": token, "other": "v"}, nil)
	bindProgram(t, h, "tok", "/opt/homebrew/bin/gh")
	if code := h.cli.Run([]string{"bindings"}); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err())
	}
	out := h.out()
	if !strings.Contains(out, "tok") || !strings.Contains(out, "/opt/homebrew/bin/gh") || strings.Contains(out, "other") {
		t.Errorf("bindings should list only the bound secret and its program:\n%s", out)
	}
	if strings.Contains(out, token) {
		t.Error("bindings printed a value")
	}
}
