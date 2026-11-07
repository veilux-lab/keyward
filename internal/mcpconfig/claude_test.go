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
	t      *testing.T
	config string
	calls  []string
	// failAdds is how many add-json calls fail next.
	failAdds int
	// edit, if set, changes each definition add-json stores.
	edit func(def map[string]any)
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
		if f.failAdds > 0 {
			f.failAdds--
			return []byte("bad json"), errors.New("exit status 1")
		}
		var def map[string]any
		if err := json.Unmarshal([]byte(argv[4]), &def); err != nil {
			f.t.Fatalf("add-json got invalid JSON: %v", err)
		}
		if f.edit != nil {
			f.edit(def)
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
	fake.failAdds = 1
	if err := c.Apply(claudeFinding(t, home, true)); err == nil || !strings.Contains(err.Error(), "bad json") {
		t.Fatalf("Apply error = %v, want the tool's output", err)
	}
	servers, _ := mcpconfig.Load(home, home)
	if len(servers) != 1 || servers[0].Command != "uvx" {
		t.Errorf("the original server was not restored: %+v", servers)
	}
}

// If the original cannot be put back either, the error shows it, with its literal
// values hidden, and says those went with the removed server. The user restores it
// in the config with Claude Code closed, so it does not write its old copy over
// the change, and not in a command typed into a shell, whose history would keep
// them. A placeholder, and an auth scheme before it, show as written.
func TestClaudeApplyHidesLiteralsWhenTheOriginalCannotBePutBack(t *testing.T) {
	home, fake, c := claudeHome(t, `{"gh": {"type": "http", "url": "https://api.example.com/mcp/", "headers": {"Authorization": "Bearer ${PD_KEY}", "X-Team": "fake-literal-header"}}}`)
	fake.failAdds = 2
	err := c.Apply(claudeFinding(t, home, true))
	if err == nil {
		t.Fatal("Apply succeeded")
	}
	for _, want := range []string{`"X-Team":"<19 bytes hidden>"`, `"Authorization":"Bearer ${PD_KEY}"`, "https://api.example.com/mcp/", "removing it deleted the values shown as hidden",
		"With Claude Code closed, put it back in the mcpServers of " + fake.config + ", with those values filled in"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Apply error lacks %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "fake-literal") || strings.Contains(err.Error(), "'{") {
		t.Errorf("Apply error shows a literal, or a command line to put it in: %v", err)
	}
}

// A literal may be a secret, whole or beside a placeholder: the commands shown hide
// it, and the definition added keeps it.
func TestClaudeCommandsHideLiteralsThatApplyKeeps(t *testing.T) {
	home, fake, c := claudeHome(t, `{"gh": {"type": "http", "url": "https://api.example.com/mcp/", "headers": {"Authorization": "Bearer ${PD_KEY}",
    "X-Api-Key": "fake-literal-prefix-${PD_KEY}", "X-Team": "fake-literal-header"}, "env": {"LEVEL": "fake-literal-env"}}}`)
	f := claudeFinding(t, home, true)
	cmds := strings.Join(c.Commands(f), "\n")
	if strings.Contains(cmds, "fake-literal") || !strings.Contains(cmds, `"KW_HDR_1":"<20 bytes hidden>"`) || !strings.Contains(cmds, `"KW_HDR_2":"<19 bytes hidden>"`) || !strings.Contains(cmds, `"LEVEL":"<16 bytes hidden>"`) {
		t.Errorf("commands = %s", cmds)
	}
	if err := c.Apply(f); err != nil {
		t.Fatalf("Apply: %v (calls %q)", err, fake.calls)
	}
	servers, _ := mcpconfig.Load(home, home)
	if len(servers) != 1 || servers[0].Env["KW_HDR_1"] != "fake-literal-prefix-" || servers[0].Env["KW_HDR_2"] != "fake-literal-header" || servers[0].Env["LEVEL"] != "fake-literal-env" {
		t.Errorf("after wrap: %+v", servers)
	}
}

// A secret in a URL or an argument is hidden too: in the commands wrap and unwrap
// show, in unwrap's suggestion, and in each error Apply returns, from putting the
// original back, failing to, or reading back another definition. The definition
// added keeps it. wrap quotes JSON or a quoted value again in its script, so a
// secret there is behind an escaped quote.
func TestClaudeHidesSecretsInTheURLAndArgumentsThatApplyKeeps(t *testing.T) {
	for _, tc := range []struct {
		server  string
		secrets []string
	}{
		{`{"tenant": {"type": "http", "url": "https://bot:` + urlPassword + `@mcp.example.com/mcp?api_key=` + queryKey + `", "headers": {"Authorization": "Bearer ${PD_KEY}"}}}`,
			[]string{urlPassword, queryKey}},
		{`{"tool": {"command": "uvx", "args": ["tool-mcp", "--token", "` + argToken + `", "--home", "${HOME}"], "env": {"PD_KEY": "${PD_KEY}"}}}`,
			[]string{argToken}},
		{`{"path": {"type": "http", "url": "https://bot:FakePwHead?FakePwTail@mcp.example.com/` + headerToken + `/mcp", "headers": {"Authorization": "Bearer ${PD_KEY}"}}}`,
			[]string{"FakePwHead", headerToken}},
		{`{"cfg": {"command": "npx", "args": ["-y", "@smithery/cli", "run", "@org/server", "--config", "{\"apiKey\": \"` + anthropicKey + `\", \"pdKey\": \"${PD_KEY}\"}"]}}`,
			[]string{anthropicKey}},
		{`{"script": {"command": "sh", "args": ["-c", "API_KEY=\"` + anthropicKey + `\" exec some-mcp --root \"${HOME}\""], "env": {"PD_KEY": "${PD_KEY}"}}}`,
			[]string{anthropicKey}},
		{`{"compact": {"command": "npx", "args": ["-y", "@smithery/cli@latest", "run", "@smithery-ai/github", "--config", "{\"githubPersonalAccessToken\":\"` + compactToken + `\"}"], "env": {"PD_KEY": "${PD_KEY}"}}}`,
			[]string{compactToken}},
		{`{"list": {"command": "npx", "args": ["-y", "@org/server", "--config", "{'apiKey':'` + openAIKey + `'}", "--keys", "[\"` + anthropicKey + `\"]", "--key", "${PD_KEY}"]}}`,
			[]string{openAIKey, anthropicKey}},
		// mcp-remote's headers as arguments, put in a script or each kept apart.
		{`{"remote": {"command": "npx", "args": ["-y", "mcp-remote", "https://api.example.com/mcp", "--header", "Authorization: Bearer ${PD_KEY}", "--header", "X-Api-Key: ` + opaqueHeader +
			`", "--header", "X-Other-Key:` + noSpaceKey + `", "--header=X-Auth: Token ` + schemeToken + `", "--header", "DD-API-KEY: ` + hexHeader + `"]}}`,
			[]string{opaqueHeader, noSpaceKey, schemeToken, hexHeader}},
		{`{"apart": {"command": "npx", "args": ["-y", "mcp-remote", "https://api.example.com/mcp", "--header", "X-Api-Key:` + opaqueHeader + `", "--header=DD-API-KEY: ` + hexHeader + `"],
			"env": {"PD_KEY": "${PD_KEY}"}}}`,
			[]string{opaqueHeader, hexHeader}},
	} {
		home, fake, c := claudeHome(t, tc.server)
		f := claudeFinding(t, home, true)
		printed := strings.Join(c.Commands(f), "\n")
		if !strings.Contains(printed, "bytes hidden") {
			t.Errorf("commands = %s", printed)
		}
		if err := c.Apply(f); err != nil {
			t.Fatalf("Apply: %v (calls %q)", err, fake.calls)
		}
		data, _ := os.ReadFile(fake.config)
		undo := claudeFinding(t, home, false)
		printed += "\n" + strings.Join(c.Commands(undo), "\n") + "\n" + undo.Suggestion + "\n" + undo.Note
		fake.failAdds = 2
		if err := c.Apply(undo); err == nil {
			t.Error("unwrap succeeded")
		} else {
			printed += "\n" + err.Error()
		}
		for _, failing := range []func(*fakeClaude){
			func(fake *fakeClaude) { fake.failAdds = 1 },
			func(fake *fakeClaude) { fake.failAdds = 2 },
			func(fake *fakeClaude) {
				fake.edit = func(def map[string]any) { def["args"] = append(def["args"].([]any), "--verbose") }
			},
		} {
			home, fake, c := claudeHome(t, tc.server)
			failing(fake)
			err := c.Apply(claudeFinding(t, home, true))
			if err == nil {
				t.Fatal("Apply succeeded")
			}
			printed += "\n" + err.Error()
		}
		for _, value := range tc.secrets {
			if !strings.Contains(string(data), value) {
				t.Errorf("the definition added lost %q: %s", value, data)
			}
			if strings.Contains(printed, value) {
				t.Errorf("printed %q:\n%s", value, printed)
			}
		}
	}
}

// A bridge from an earlier keyward holds its headers' text in its script, where
// only a header's name marks it as a credential. The commands wrap and unwrap show,
// and each error that shows a definition, print that text only as its length, and
// the definitions applied keep it.
func TestClaudeHidesTheHeaderTextInAnEarlierBridgesScript(t *testing.T) {
	script := `exec npx -y mcp-remote https://api.example.com/mcp/ --header "Authorization: Bearer "'$''{PD_KEY}'"" --header "X-Api-Key: ` + namedValue + `" --transport http-only`
	server, err := json.Marshal(map[string]any{"team": map[string]any{"command": "/opt/homebrew/bin/keyward",
		"args": []string{"run", "--only", "PD_KEY", "--", "sh", "-c", script}, "env": map[string]string{"PD_KEY": "cap://pagerduty-key"}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, wrap := range []bool{true, false} {
		for _, failing := range []func(*fakeClaude){
			nil,
			func(fake *fakeClaude) { fake.failAdds = 2 },
			func(fake *fakeClaude) {
				fake.edit = func(def map[string]any) { def["args"] = append(def["args"].([]any), "--verbose") }
			},
		} {
			home, fake, c := claudeHome(t, string(server))
			f := claudeFinding(t, home, wrap)
			printed := strings.Join(c.Commands(f), "\n")
			if failing != nil {
				failing(fake)
			}
			err := c.Apply(f)
			if (err != nil) != (failing != nil) {
				t.Fatalf("wrap %v: Apply = %v", wrap, err)
			}
			if err != nil {
				printed += "\n" + err.Error()
			}
			if strings.Contains(printed, namedValue) {
				t.Errorf("wrap %v printed the header's text:\n%s", wrap, printed)
			}
			if data, _ := os.ReadFile(fake.config); failing == nil && !strings.Contains(string(data), namedValue) {
				t.Errorf("wrap %v lost the header's text: %s", wrap, data)
			}
		}
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
