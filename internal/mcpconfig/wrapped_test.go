package mcpconfig_test

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/veilux-lab/keyward/internal/mcpconfig"
)

// keyward bind warns about the servers that would stop getting a secret, so each
// wrapped server must name the secrets it resolves and the command it starts.
// A server that does not start through keyward, or is off, resolves nothing.
func TestWrappedServersNameTheSecretsEachResolves(t *testing.T) {
	home, work := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"mcpServers": {
		"script": {"command": "keyward", "args": ["run", "--only", "GITHUB_TOKEN", "--", "sh", "-c", "exec npx x"], "env": {"GITHUB_TOKEN": "cap://github-token"}},
		"filled": {"command": "/opt/homebrew/bin/keyward", "args": ["run", "--only", "PD", "--", "uvx", "pd-mcp"], "env": {"PD": "${PD_KEY}"}},
		"plain": {"command": "npx", "args": ["x"], "env": {"T": "cap://tok"}}}}`), 0o600)
	os.MkdirAll(filepath.Join(home, ".codex"), 0o700)
	os.WriteFile(filepath.Join(home, ".codex", "config.toml"), []byte("[mcp_servers.off]\ncommand = \"keyward\"\nargs = [\"run\", \"--\", \"printenv\"]\nenv = { T = \"cap://tok\" }\nenabled = false\n"), 0o600)
	servers, errs := mcpconfig.Load(home, work)
	if len(errs) > 0 {
		t.Fatalf("Load: %v", errs)
	}
	got := map[string]mcpconfig.Wrapped{}
	for _, w := range mcpconfig.WrappedServers(servers, map[string]string{"PD_KEY": "pagerduty-key"}) {
		got[w.Name] = w
	}
	for name, want := range map[string]struct{ secrets, command []string }{
		"script": {[]string{"github-token"}, []string{"sh", "-c", "exec npx x"}},
		"filled": {[]string{"pagerduty-key"}, []string{"uvx", "pd-mcp"}},
	} {
		w, ok := got[name]
		if !ok {
			t.Errorf("%s is missing from %v", name, got)
			continue
		}
		if !slices.Equal(w.Secrets, want.secrets) || !slices.Equal(w.Command, want.command) {
			t.Errorf("%s: secrets %v, command %v; want %v, %v", name, w.Secrets, w.Command, want.secrets, want.command)
		}
	}
	for _, name := range []string{"plain", "off"} {
		if _, ok := got[name]; ok {
			t.Errorf("%s does not start through keyward run, or is off, but is listed", name)
		}
	}
}
