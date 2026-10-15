package mcpconfig_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/veilux-lab/keyward/internal/mcpconfig"
)

// fakeClaude edits ~/.claude.json the way `claude mcp remove` and `add-json` do,
// so the applier's read-back sees a real result.
type fakeClaude struct {
	t       *testing.T
	config  string
	calls   []string
	failAdd bool
}

func (f *fakeClaude) run(dir string, argv ...string) ([]byte, error) {
	f.calls = append(f.calls, strings.Join(argv, " "))
	if len(argv) >= 3 && argv[2] == "--help" {
		return []byte("Commands:\n  add-json [options] <name> <json>\n  remove [options] <name>\n"), nil
	}
	var doc map[string]any
	data, _ := os.ReadFile(f.config)
	json.Unmarshal(data, &doc)
	servers, _ := doc["mcpServers"].(map[string]any)
	switch argv[2] {
	case "remove":
		delete(servers, argv[3])
	case "add-json":
		if f.failAdd {
			f.failAdd = false
			return []byte("bad json"), errors.New("exit status 1")
		}
		var def map[string]any
		if err := json.Unmarshal([]byte(argv[4]), &def); err != nil {
			f.t.Fatalf("add-json got invalid JSON: %v", err)
		}
		servers[argv[3]] = def
	}
	out, _ := json.Marshal(doc)
	os.WriteFile(f.config, out, 0o600)
	return nil, nil
}

func claudeHome(t *testing.T, servers string) (string, *fakeClaude, mcpconfig.Claude) {
	t.Helper()
	home := t.TempDir()
	config := write(t, filepath.Join(home, ".claude.json"), `{"numStartups": 3, "mcpServers": `+servers+`}`)
	fake := &fakeClaude{t: t, config: config}
	c, ok := mcpconfig.FindClaude("/usr/local/bin/claude", fake.run)
	if !ok {
		t.Fatal("FindClaude rejected a claude with add-json")
	}
	c.Home, c.Workdir, c.Keyward = home, home, "/opt/homebrew/bin/keyward"
	return home, fake, c
}

func claudeFinding(t *testing.T, home string, wrap bool) mcpconfig.Finding {
	t.Helper()
	servers, _ := mcpconfig.Load(home, home)
	var found []mcpconfig.Finding
	if wrap {
		found = mcpconfig.Check(servers, map[string]string{"PD_KEY": "pagerduty-key"})
	} else {
		found = mcpconfig.Undo(servers)
	}
	if len(found) != 1 {
		t.Fatalf("findings = %+v", found)
	}
	return found[0]
}

// Wrapping keeps every field keyward does not change, uses keyward's full path,
// and is checked by reading the config back.
func TestClaudeWrapKeepsOtherFieldsAndChecksTheResult(t *testing.T) {
	home, fake, c := claudeHome(t, `{"pagerduty": {"type": "stdio", "command": "uvx", "args": ["pagerduty-mcp"], "env": {"PD_KEY": "${PD_KEY}"}, "timeout": 30}}`)
	f := claudeFinding(t, home, true)
	if cmds := c.Commands(f); len(cmds) != 2 || !strings.HasPrefix(cmds[0], "claude mcp remove pagerduty -s user") || !strings.Contains(cmds[1], "add-json pagerduty") {
		t.Fatalf("commands = %q", cmds)
	}
	if err := c.Apply(f); err != nil {
		t.Fatalf("Apply: %v (calls %q)", err, fake.calls)
	}
	var doc struct {
		NumStartups int                       `json:"numStartups"`
		MCPServers  map[string]map[string]any `json:"mcpServers"`
	}
	data, _ := os.ReadFile(fake.config)
	json.Unmarshal(data, &doc)
	got := doc.MCPServers["pagerduty"]
	if got["command"] != "/opt/homebrew/bin/keyward" || got["timeout"] != float64(30) || got["type"] != "stdio" || doc.NumStartups != 3 {
		t.Errorf("after wrap: %v (startups %d)", got, doc.NumStartups)
	}
	if env, _ := got["env"].(map[string]any); env["PD_KEY"] != "cap://pagerduty-key" {
		t.Errorf("env = %v", got["env"])
	}
}

// If adding fails after the remove, the original definition is put back.
func TestClaudeApplyRestoresTheServerWhenAddingFails(t *testing.T) {
	home, fake, c := claudeHome(t, `{"pagerduty": {"command": "uvx", "args": ["pagerduty-mcp"], "env": {"PD_KEY": "${PD_KEY}"}}}`)
	fake.failAdd = true
	if err := c.Apply(claudeFinding(t, home, true)); err == nil || !strings.Contains(err.Error(), "bad json") {
		t.Fatalf("Apply error = %v, want the tool's output", err)
	}
	servers, _ := mcpconfig.Load(home, home)
	if len(servers) != 1 || servers[0].Command != "uvx" {
		t.Errorf("the original server was not restored: %+v", servers)
	}
}

// A remote server becomes a stdio one: the url, headers, and type go.
func TestClaudeWrapOfARemoteServerDropsItsURL(t *testing.T) {
	home, fake, c := claudeHome(t, `{"gh": {"type": "http", "url": "https://api.example.com/mcp/", "headers": {"Authorization": "Bearer ${PD_KEY}"}}}`)
	if err := c.Apply(claudeFinding(t, home, true)); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(fake.config)
	if s := string(data); strings.Contains(s, `"url"`) || strings.Contains(s, `"type"`) || !strings.Contains(s, "mcp-remote") {
		t.Errorf("after wrap: %s", s)
	}
}

func TestClaudeUnwrapStartsTheServerDirectlyAgain(t *testing.T) {
	home, _, c := claudeHome(t, `{"pagerduty": {"command": "/opt/homebrew/bin/keyward", "args": ["run", "--only", "PD_KEY", "--", "uvx", "pagerduty-mcp"], "env": {"PD_KEY": "cap://pagerduty-key"}}}`)
	if err := c.Apply(claudeFinding(t, home, false)); err != nil {
		t.Fatal(err)
	}
	servers, _ := mcpconfig.Load(home, home)
	if len(servers) != 1 || servers[0].Command != "uvx" || servers[0].Env["PD_KEY"] != "${PD_KEY}" {
		t.Errorf("after unwrap: %+v", servers)
	}
}

func TestFindClaudeNeedsAddJSON(t *testing.T) {
	old := func(string, ...string) ([]byte, error) { return []byte("Commands:\n  add\n"), nil }
	if _, ok := mcpconfig.FindClaude("/usr/local/bin/claude", old); ok {
		t.Error("accepted a claude without add-json")
	}
	if _, ok := mcpconfig.FindClaude("", old); ok {
		t.Error("accepted a missing claude")
	}
}

// The shown command passes the JSON literally, placeholders included.
func TestClaudeCommandsQuoteTheJSONLiterally(t *testing.T) {
	home, _, c := claudeHome(t, `{"pagerduty": {"command": "/opt/homebrew/bin/keyward", "args": ["run", "--", "uvx", "pagerduty-mcp"], "env": {"PD_KEY": "cap://pagerduty-key"}}}`)
	cmds := c.Commands(claudeFinding(t, home, false))
	if !strings.Contains(cmds[1], `'{`) || !strings.Contains(cmds[1], `"${PD_KEY}"`) {
		t.Errorf("command = %s", cmds[1])
	}
}
