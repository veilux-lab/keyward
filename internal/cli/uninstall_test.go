package cli_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/veilux-lab/keyward/internal/agents"
	"github.com/veilux-lab/keyward/internal/vault"
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
	for _, want := range []string{"keyward uninstall will", "Kept: your stored secrets"} {
		if !strings.Contains(r.h.err(), want) {
			t.Errorf("the plan lacks %q:\n%s", want, r.h.err())
		}
	}
	if !strings.Contains(r.h.out(), "Nothing keyward created is left") {
		t.Errorf("summary lacks the residue check:\n%s", r.h.out())
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
	// The user added this line by hand, so it is theirs to remove; uninstall says so.
	if !strings.Contains(r.h.err(), "remove the keyward.md line you added") || !strings.Contains(r.h.out(), "~/.claude/CLAUDE.md still mentions keyward.md") {
		t.Errorf("uninstall did not name the agent config still pointing at the file:\n%s\n%s", r.h.err(), r.h.out())
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

// The plan names each file uninstall will put values back into, before the yes.
func TestUninstallPlanNamesTheFilesItWillRestore(t *testing.T) {
	r := uninstallFixture(t, "")
	homed(t, r.h)
	path := migrated(t, r.h)
	r.h.cli.Stdin = strings.NewReader("no\n")
	r.h.cli.Run([]string{"uninstall"})
	if !strings.Contains(r.h.err(), "back into these files") || !strings.Contains(r.h.err(), path) {
		t.Errorf("the plan does not name the migrated file:\n%s", r.h.err())
	}
	if data, _ := os.ReadFile(path); !strings.Contains(string(data), "cap://") {
		t.Error("restored without a yes")
	}
}

// One uninstall puts the values back, then removes keyward, then checks.
func TestUninstallRestoresMigratedFilesItself(t *testing.T) {
	r := uninstallFixture(t, "")
	homed(t, r.h)
	path := migrated(t, r.h)
	r.h.cli.Stdin = strings.NewReader("yes\n")
	if code := r.h.cli.Run([]string{"uninstall"}); code != 0 {
		t.Fatalf("exit %d: %s", code, r.h.err())
	}
	if data, _ := os.ReadFile(path); strings.Contains(string(data), "cap://") {
		t.Errorf("references remain:\n%s", data)
	}
	if !strings.Contains(r.h.out(), "Nothing keyward created is left") {
		t.Errorf("summary:\n%s", r.h.out())
	}
}

// Without the vault key nothing can be put back, so nothing is changed at all.
func TestUninstallChecksTheVaultBeforeChangingAnything(t *testing.T) {
	r := uninstallFixture(t, "")
	homed(t, r.h)
	path := migrated(t, r.h)
	r.h.cli.Store = deniedGets{r.h.store}
	r.h.cli.Stdin = strings.NewReader("yes\n")
	if code := r.h.cli.Run([]string{"uninstall"}); code != 1 || !strings.Contains(r.h.err(), "recovery restore") {
		t.Errorf("exit %d:\n%s", code, r.h.err())
	}
	if len(r.calls) != 0 {
		t.Errorf("removed %v", r.calls)
	}
	if data, _ := os.ReadFile(path); !strings.Contains(string(data), "cap://") {
		t.Error("the file changed")
	}
}

func TestUninstallWithoutPurgeKeepsTheVault(t *testing.T) {
	r := uninstallFixture(t, "yes\n")
	r.h.cli.PurgeVault = func() error { t.Error("the vault was purged without --purge"); return nil }
	if code := r.h.cli.Run([]string{"uninstall"}); code != 0 {
		t.Fatalf("exit %d: %s", code, r.h.err())
	}
}

// Purging while something would still use the vault would strand it for good.
func TestPurgeRefusesWhileAnMCPServerItCannotChangeUsesTheVault(t *testing.T) {
	r := uninstallFixture(t, "")
	home := homed(t, r.h)
	os.MkdirAll(filepath.Join(home, ".codex"), 0o755)
	os.WriteFile(filepath.Join(home, ".codex", "config.toml"), []byte("[mcp_servers.pd]\ncommand = \"keyward\"\nargs = [\"run\", \"--\", \"uvx\", \"pd\"]\nenv = { PD_KEY = \"cap://pd-key\" }\n"), 0o600)
	r.h.cli.Stdin = strings.NewReader("yes\n")
	r.h.cli.PurgeVault = func() error { t.Error("purged while a server still used the vault"); return nil }
	if code := r.h.cli.Run([]string{"uninstall", "--purge"}); code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
	if len(r.calls) != 0 {
		t.Errorf("something was removed: %v", r.calls)
	}
	if !strings.Contains(r.h.err(), "keyward mcp unwrap") {
		t.Errorf("the refusal does not say how to fix it:\n%s", r.h.err())
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

// doctor's advice for a credential in a server's env routes it through a variable
// of the same name, set to its reference in ~/.zshrc, and wrap waits for it.
// Followed, it leaves a server that uninstall changes back to read that variable,
// whose value it puts back there, so the server still gets the credential and
// nothing is left.
func TestFollowingDoctorsAdviceForACredentialInEnvSurvivesUninstall(t *testing.T) {
	const apiKey, appKey = "fa6e11fe0123456789abcdef01234567", "fa6e11fe9876543210fedcba9876543210ab"
	r := uninstallFixture(t, "")
	h := r.h
	home := homed(t, h)
	h.cli.Interactive, h.cli.Self = true, "/opt/homebrew/bin/keyward"
	rc := filepath.Join(home, ".zshrc")
	os.WriteFile(rc, []byte("export DD_API_KEY="+apiKey+"\n"), 0o644)
	config := filepath.Join(home, ".claude.json")
	os.WriteFile(config, []byte(`{"mcpServers": {"datadog": {"command": "dd-mcp", "env": {"DD_API_KEY": "${DD_API_KEY}", "DD_APP_KEY": "`+appKey+`"}}}}`), 0o600)
	fakeTools(t, h, home)
	var printed strings.Builder
	run := runner(h, &printed)
	yes := func(args ...string) {
		t.Helper()
		h.cli.Stdin = strings.NewReader("yes\n")
		if code, out := run(args...); code != 0 {
			t.Fatalf("%v exit %d:\n%s", args, code, out)
		}
	}

	yes("migrate", rc)
	h.cli.Stdin = strings.NewReader("yes\n")
	if code, out := run("mcp", "wrap"); code != 1 || !strings.Contains(out, "Skipped datadog: its env.DD_APP_KEY holds a credential") {
		t.Errorf("wrap exit %d, want 1 and datadog skipped:\n%s", code, out)
	}
	if _, out := run("doctor"); !strings.Contains(out, "Claude Code server datadog, env.DD_APP_KEY\n") ||
		!strings.Contains(out, "store it with keyward add NAME, write ${DD_APP_KEY} in its place, add export DD_APP_KEY='cap://NAME' to ~/.zshrc, and run keyward mcp wrap") {
		t.Fatalf("doctor gives no advice for env.DD_APP_KEY:\n%s", out)
	}
	// The user follows it.
	h.cli.ReadSecret = func() ([]byte, error) { return []byte(appKey), nil }
	yes("add", "dd-app-key")
	data, _ := os.ReadFile(rc)
	os.WriteFile(rc, append(data, "export DD_APP_KEY='cap://dd-app-key'\n"...), 0o644)
	data, _ = os.ReadFile(config)
	os.WriteFile(config, []byte(strings.Replace(string(data), appKey, "${DD_APP_KEY}", 1)), 0o600)
	yes("mcp", "wrap")
	if code, out := run("doctor"); code != 0 || lastLine(out) != "No problems found." {
		t.Errorf("doctor exit %d, want 0:\n%s", code, out)
	}

	h.cli.Stdin = strings.NewReader("yes\n")
	if code, out := run("uninstall"); code != 0 || !strings.Contains(out, "Nothing keyward created is left.") {
		t.Errorf("uninstall exit %d, want 0 and nothing left:\n%s", code, out)
	}
	if data, _ := os.ReadFile(config); strings.Contains(string(data), "keyward") || !strings.Contains(string(data), `"DD_APP_KEY":"${DD_APP_KEY}"`) {
		t.Errorf("config after uninstall: %s", data)
	}
	if data, _ := os.ReadFile(rc); !strings.Contains(string(data), "DD_API_KEY="+apiKey) && !strings.Contains(string(data), "DD_API_KEY='"+apiKey+"'") ||
		!strings.Contains(string(data), "DD_APP_KEY='"+appKey+"'") {
		t.Errorf("~/.zshrc does not set both values after uninstall")
	}
	if strings.Contains(printed.String(), apiKey) || strings.Contains(printed.String(), appKey) {
		t.Errorf("printed a value:\n%s", printed.String())
	}
}

// Changed back, a server reads each reference in its env from a variable of the
// same name, which only a file can set. One that no file sets, as after env.X is
// set to cap://NAME by hand, is listed among what uninstall cannot change, with
// how to set it first, --purge waits for it, uninstall says it is left, and unwrap
// warns of it.
func TestUninstallAndUnwrapNameAVariableThatNoFileSets(t *testing.T) {
	r := uninstallFixture(t, "")
	h := r.h
	home := homed(t, h)
	h.store.Seed(map[string]string{"dd-api-key": "fake-api-value", "dd-app-key": "fake-app-value"})
	h.cli.Interactive = true
	os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export DD_API_KEY='cap://dd-api-key'\n"), 0o644)
	config, _ := json.Marshal(map[string]any{"mcpServers": map[string]any{"datadog": map[string]any{"command": "/opt/homebrew/bin/keyward",
		"args": []string{"run", "--only", "DD_API_KEY,DD_APP_KEY", "--", "dd-mcp"}, "env": map[string]string{"DD_API_KEY": "cap://dd-api-key", "DD_APP_KEY": "cap://dd-app-key"}}}})
	os.WriteFile(filepath.Join(home, ".claude.json"), config, 0o600)
	fakeTools(t, h, home)
	var printed strings.Builder
	run := runner(h, &printed)
	const fix = "once changed back, it reads DD_APP_KEY, which no file sets; first add export DD_APP_KEY='cap://dd-app-key' to ~/.zshrc"

	h.cli.Stdin = strings.NewReader("no\n")
	if _, out := run("mcp", "unwrap"); !strings.Contains(out, "Warning: datadog: "+fix+".") {
		t.Errorf("unwrap does not warn of DD_APP_KEY:\n%s", out)
	}
	h.cli.PurgeVault = func() error { t.Error("purged while a server would lose its credential"); return nil }
	if code, out := run("uninstall", "--purge"); code != 1 || !strings.Contains(out, "  MCP server datadog (Claude Code, ~/.claude.json): "+fix+"\n") {
		t.Errorf("uninstall --purge exit %d, want 1 and how to set DD_APP_KEY:\n%s", code, out)
	}
	h.cli.Stdin = strings.NewReader("yes\n")
	if code, out := run("uninstall"); code != 0 || !strings.Contains(out, "  MCP server datadog (Claude Code, ~/.claude.json): "+fix+"\n") ||
		!strings.Contains(out, "MCP server datadog reads DD_APP_KEY, which no file sets (~/.claude.json)") || strings.Contains(out, "Nothing keyward created is left") {
		t.Errorf("uninstall exit %d, want 0 and DD_APP_KEY named before and after:\n%s", code, out)
	}
}

// The Claude Code and Codex configs belong to their tools, and a reference can be
// in one that holds no server, as in a prompt's history or a commented-out table.
// uninstall never puts values back into either as text, so it neither stops at
// one nor says it is left, and --purge does not wait for it.
func TestUninstallLeavesTheClaudeCodeAndCodexConfigsAlone(t *testing.T) {
	for _, purge := range []bool{false, true} {
		r := uninstallFixture(t, "yes\n")
		home := homed(t, r.h)
		r.h.store.Seed(map[string]string{"github-token": "fake-github-value"})
		rc := filepath.Join(home, ".zshrc")
		os.WriteFile(rc, []byte("export GITHUB_TOKEN='cap://github-token'\n"), 0o644)
		claude := filepath.Join(home, ".claude.json")
		history := `{"projects": {"` + filepath.Join(home, "x") + `": {"history": [{"display": "keyward run resolves cap://github-token"}]}}}`
		os.WriteFile(claude, []byte(history), 0o600)
		codex := filepath.Join(home, ".codex", "config.toml")
		os.MkdirAll(filepath.Dir(codex), 0o755)
		os.WriteFile(codex, []byte("# [mcp_servers.gh]\n# env = { GITHUB_TOKEN = \"cap://github-token\" }\n"), 0o600)
		r.h.cli.PurgeVault = func() error { return nil }
		args := []string{"uninstall"}
		if purge {
			args = append(args, "--purge")
		}
		if code := r.h.cli.Run(args); code != 0 || strings.Contains(r.h.err(), "unsupported file format") || !strings.Contains(r.h.out(), "Nothing keyward created is left.") {
			t.Errorf("%v exit %d, want 0 and nothing left:\n%s\n%s", args, code, r.h.err(), r.h.out())
		}
		if data, _ := os.ReadFile(rc); !strings.Contains(string(data), "fake-github-value") {
			t.Errorf("%v: ~/.zshrc was not restored: %s", args, data)
		}
		if data, _ := os.ReadFile(claude); string(data) != history {
			t.Errorf("%v: ~/.claude.json changed: %s", args, data)
		}
	}
}

// wrap changes another Claude Code project's servers in its folder, so uninstall,
// run anywhere, changes each back there, with Claude Code's own command, and
// leaves ~/.claude.json out of the files it puts values back into.
func TestUninstallChangesBackTheServersOfEveryClaudeCodeProject(t *testing.T) {
	for _, withUser := range []bool{true, false} {
		r := uninstallFixture(t, "")
		h := r.h
		home := homed(t, h)
		h.store.Seed(map[string]string{"github-token": "fake-github-value", "pd-key": "fake-pd-value"})
		h.cli.Interactive = true
		os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export GITHUB_TOKEN='cap://github-token'\nexport PD_KEY='cap://pd-key'\n"), 0o644)
		other := filepath.Join(home, "other-project")
		os.Mkdir(other, 0o755)
		servers := map[string]any{}
		if withUser {
			servers["pd"] = map[string]any{"command": "uvx", "args": []string{"pd-mcp"}, "env": map[string]string{"PD_KEY": "${PD_KEY}"}}
		}
		config := filepath.Join(home, ".claude.json")
		data, _ := json.Marshal(map[string]any{"mcpServers": servers, "projects": map[string]any{other: map[string]any{"mcpServers": map[string]any{
			"gh": map[string]any{"command": "gh-mcp", "env": map[string]string{"GITHUB_TOKEN": "${GITHUB_TOKEN}"}}}}}})
		os.WriteFile(config, data, 0o600)
		calls := fakeTools(t, h, home)
		var printed strings.Builder
		run := runner(h, &printed)

		h.cli.Stdin = strings.NewReader("yes\n")
		run("mcp", "wrap")
		h.cli.Workdir, h.cli.Stdin = other, strings.NewReader("yes\n")
		if code, out := run("mcp", "wrap"); code != 0 {
			t.Fatalf("wrap in the project's folder exit %d:\n%s", code, out)
		}
		if data, _ := os.ReadFile(config); strings.Count(string(data), "keyward") != len(servers)+1 {
			t.Fatalf("wrapped: %s", data)
		}
		h.cli.Workdir, h.cli.Stdin = home, strings.NewReader("yes\n")
		*calls = nil
		code, out := run("uninstall")
		if code != 0 || !strings.Contains(out, "In ~/other-project:\n       claude mcp remove gh -s local\n") || strings.Contains(out, "unsupported file format") ||
			!strings.Contains(out, "Nothing keyward created is left.") {
			t.Errorf("uninstall exit %d, want 0, gh changed back in its folder, and nothing left:\n%s", code, out)
		}
		if data, _ := os.ReadFile(config); strings.Contains(string(data), "keyward") {
			t.Errorf("a server still starts through keyward: %s", data)
		}
		if !slices.Contains(*calls, "mcp remove gh -s local") {
			t.Errorf("claude calls = %q", *calls)
		}
	}
}

// wrap run in a project's folder changes that folder's .mcp.json servers too, so
// uninstall, run anywhere, changes them back there: those of each project Claude
// Code lists, and those of a folder only the ledger names. Outside a terminal it
// lists them, --purge waits for them, and it says they are left, though the
// ledger goes with keyward's data.
func TestUninstallChangesBackTheProjectServersOfEveryFolderWrapRanIn(t *testing.T) {
	for _, interactive := range []bool{true, false} {
		r := uninstallFixture(t, "")
		h := r.h
		h.cli.Ledger.Path = filepath.Join(r.dirs[0], "ledger.json")
		home := homed(t, h)
		h.store.Seed(map[string]string{"github-token": "fake-github-value", "pd-key": "fake-pd-value"})
		h.cli.Interactive, h.cli.Self = true, "/opt/homebrew/bin/keyward"
		os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export GITHUB_TOKEN='cap://github-token'\nexport PD_KEY='cap://pd-key'\n"), 0o644)
		other, unlisted := filepath.Join(home, "other-project"), filepath.Join(home, "unlisted")
		os.Mkdir(other, 0o755)
		os.Mkdir(unlisted, 0o755)
		config := filepath.Join(home, ".claude.json")
		data, _ := json.Marshal(map[string]any{"mcpServers": map[string]any{"pd": map[string]any{"command": "uvx", "args": []string{"pd-mcp"}, "env": map[string]string{"PD_KEY": "${PD_KEY}"}}},
			"projects": map[string]any{other: map[string]any{"mcpServers": map[string]any{"gh": map[string]any{"command": "gh-mcp", "env": map[string]string{"GITHUB_TOKEN": "${GITHUB_TOKEN}"}}}}}})
		os.WriteFile(config, data, 0o600)
		team, docs := filepath.Join(other, ".mcp.json"), filepath.Join(unlisted, ".mcp.json")
		os.WriteFile(team, []byte(`{"mcpServers": {"team": {"command": "team-mcp", "env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}"}}}}`), 0o644)
		os.WriteFile(docs, []byte(`{"mcpServers": {"docs": {"command": "docs-mcp", "env": {"PD_KEY": "${PD_KEY}"}}}}`), 0o644)
		calls := fakeTools(t, h, home)
		var printed strings.Builder
		run := runner(h, &printed)

		for _, dir := range []string{home, other, unlisted} {
			h.cli.Workdir, h.cli.Stdin = dir, strings.NewReader("yes\n")
			if _, out := run("mcp", "wrap"); dir == home && !strings.Contains(out, "  team  ~/other-project\n") {
				t.Errorf("wrap does not name the folder to run it in for team:\n%s", out)
			}
		}
		for _, path := range []string{config, team, docs} {
			if data, _ := os.ReadFile(path); !strings.Contains(string(data), "/opt/homebrew/bin/keyward") {
				t.Fatalf("not wrapped: %s", data)
			}
		}
		h.cli.Workdir, h.cli.Interactive = home, interactive
		*calls = nil
		if !interactive {
			h.cli.PurgeVault = func() error { t.Error("purged while a server still used the vault"); return nil }
			if code, out := run("uninstall", "--purge"); code != 1 || !strings.Contains(out, "MCP server team (Claude Code, ~/other-project/.mcp.json): keyward mcp unwrap in ~/other-project shows the change") ||
				!strings.Contains(out, "MCP server docs (Claude Code, ~/unlisted/.mcp.json): keyward mcp unwrap in ~/unlisted shows the change") {
				t.Errorf("uninstall --purge exit %d, want 1 and both servers to change by hand:\n%s", code, out)
			}
		}
		h.cli.Stdin = strings.NewReader("yes\n")
		code, out := run("uninstall")
		if !interactive {
			if code != 0 || !strings.Contains(out, "MCP server team still starts through keyward (~/other-project/.mcp.json)") ||
				!strings.Contains(out, "MCP server docs still starts through keyward (~/unlisted/.mcp.json)") || strings.Contains(out, "Nothing keyward created is left") {
				t.Errorf("uninstall exit %d, want 0 and both servers left:\n%s", code, out)
			}
			continue
		}
		if code != 0 || !strings.Contains(out, "In ~/other-project:\n       claude mcp remove team -s project\n") || !strings.Contains(out, "In ~/unlisted:\n       claude mcp remove docs -s project\n") ||
			!strings.Contains(out, "Nothing keyward created is left.") {
			t.Errorf("uninstall exit %d, want 0, each server changed back in its folder, and nothing left:\n%s", code, out)
		}
		for _, path := range []string{config, team, docs} {
			if data, _ := os.ReadFile(path); strings.Contains(string(data), "keyward") {
				t.Errorf("a server still starts through keyward: %s", data)
			}
		}
		if !slices.Contains(*calls, "mcp remove team -s project") || !slices.Contains(*calls, "mcp remove docs -s project") {
			t.Errorf("claude calls = %q", *calls)
		}
	}
}

// Claude Code's CLI cannot change a server of a project whose folder is gone, as
// with a removed worktree, so uninstall lists it with how to remove it by hand,
// and says it is left.
func TestUninstallListsAServerWhoseProjectFolderIsGone(t *testing.T) {
	r := uninstallFixture(t, "")
	h := r.h
	home := homed(t, h)
	h.cli.Interactive = true
	gone := filepath.Join(home, "removed-worktree")
	config := filepath.Join(home, ".claude.json")
	data, _ := json.Marshal(map[string]any{"projects": map[string]any{gone: map[string]any{"mcpServers": map[string]any{"gh": map[string]any{
		"command": "/opt/homebrew/bin/keyward", "args": []string{"run", "--only", "GITHUB_TOKEN", "--", "gh-mcp"}, "env": map[string]string{"GITHUB_TOKEN": "cap://github-token"}}}}}})
	os.WriteFile(config, data, 0o600)
	calls := fakeTools(t, h, home)
	var printed strings.Builder
	run := runner(h, &printed)
	const byHand = "  MCP server gh (Claude Code, ~/.claude.json (project ~/removed-worktree)): its project's folder no longer exists; " +
		"with Claude Code closed, remove the server from ~/.claude.json\n"

	h.cli.PurgeVault = func() error { t.Error("purged while a server still used the vault"); return nil }
	if code, out := run("uninstall", "--purge"); code != 1 || !strings.Contains(out, byHand) {
		t.Errorf("uninstall --purge exit %d, want 1 and the server to remove by hand:\n%s", code, out)
	}
	h.cli.Stdin = strings.NewReader("yes\n")
	if code, out := run("uninstall"); code != 0 || !strings.Contains(out, byHand) || strings.Contains(out, "Nothing keyward created is left") ||
		!strings.Contains(out, "MCP server gh still starts through keyward") {
		t.Errorf("uninstall exit %d, want 0, the server to remove by hand, and it left:\n%s", code, out)
	}
	for _, call := range *calls {
		if !strings.Contains(call, "--help") {
			t.Errorf("ran %q for a project whose folder is gone", call)
		}
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

type deniedGets struct{ vault.Store }

func (deniedGets) Get(string) (vault.Secret, error) { return vault.Secret{}, vault.ErrDenied }
