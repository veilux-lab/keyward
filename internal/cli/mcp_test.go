package cli_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/veilux-lab/keyward/internal/exposure"
	"github.com/veilux-lab/keyward/internal/ledger"
	"github.com/veilux-lab/keyward/internal/mcpconfig"
)

func TestMCPShowsTheFixForEachServerThatNeedsKeyward(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	home := homed(t, h)
	os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export GITHUB_TOKEN='cap://github-token'\n"), 0o644)
	os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"mcpServers": {"github": {"type": "http", "url": "https://api.example.com/mcp/", "headers": {"Authorization": "Bearer ${GITHUB_TOKEN}"}}, "aws": {"command": "uvx", "args": ["aws"]}}}`), 0o600)
	if code := h.cli.Run([]string{"mcp"}); code != 1 {
		t.Errorf("exit %d, want 1 while a server needs a change", code)
	}
	out := h.out()
	for _, want := range []string{"github", "GITHUB_TOKEN", `"command": "keyward"`, "mcp-remote", "cap://github-token", "Replace the"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "aws") {
		t.Errorf("listed a server that needs no change:\n%s", out)
	}
}

func TestMCPSaysWhenNothingNeedsAChange(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	homed(t, h)
	if code := h.cli.Run([]string{"mcp"}); code != 0 {
		t.Errorf("exit %d, want 0", code)
	}
	if !strings.Contains(h.out(), "No MCP server needs a change") {
		t.Errorf("output:\n%s", h.out())
	}
}

func TestDoctorPointsAtMCPWhenAServerNeedsKeyward(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	home := homed(t, h)
	os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export GITHUB_TOKEN='cap://github-token'\n"), 0o644)
	os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"mcpServers": {"gh": {"command": "gh-mcp", "env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}"}}}}`), 0o600)
	h.cli.Run([]string{"doctor"})
	if !strings.Contains(flat(h.out()), "; see keyward mcp") {
		t.Errorf("doctor did not point at keyward mcp:\n%s", h.out())
	}
}

// A bridge from an earlier keyward is reported for what it does: it already runs
// through keyward, but would put its token in mcp-remote's command line, so
// keyward run refuses to start it, and keyward mcp says so as keyward run does.
func TestMCPAndDoctorReportABridgeThatExposesItsToken(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	home := homed(t, h)
	os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"mcpServers": {"github": {"command": "keyward", "args": ["run", "--only", "GITHUB_TOKEN", "--", "sh", "-c", "exec npx -y mcp-remote https://api.example.com/mcp/ --header \"Authorization: Bearer $GITHUB_TOKEN\" --transport http-only"], "env": {"GITHUB_TOKEN": "cap://github-token"}}}}`), 0o600)
	if code := h.cli.Run([]string{"mcp"}); code != 1 {
		t.Errorf("exit %d, want 1 while a server exposes a secret", code)
	}
	for _, want := range []string{refusedProblem, "keyward run refuses to start it (Claude Code", "npx would get GITHUB_TOKEN in its command line (line 1)", "'$''{GITHUB_TOKEN}'"} {
		if !strings.Contains(h.out(), want) {
			t.Errorf("mcp output lacks %q:\n%s", want, h.out())
		}
	}
	if strings.Contains(h.out(), "would receive cap://") {
		t.Errorf("mcp says the server would receive a reference:\n%s", h.out())
	}

	h = newHarness(t, "", nil, nil)
	h.cli.Home = home
	h.cli.Run([]string{"doctor"})
	if !strings.Contains(flat(h.out()), refusedProblem+"; see keyward mcp") {
		t.Errorf("doctor output:\n%s", h.out())
	}
}

// From 1.1.4 mcp-remote fills in a bridge's headers, but a secret in its URL, or a
// credential written in a header, is still in mcp-remote's command line. keyward
// mcp reports such a bridge, as doctor does, instead of finding nothing to change:
// keyward run refuses to start one for a secret it resolves, and starts one with
// a header's text written out, as it resolves none.
func TestMCPAndDoctorReportACurrentBridgeThatStillExposesASecret(t *testing.T) {
	const exposed = "1 MCP server(s) put a secret in a command line, which any process can read"
	for _, tc := range []struct{ script, exposes, problem string }{
		{`exec npx -y mcp-remote "https://mcp.example.com/mcp?key=$PD_KEY" --transport http-only`, "keyward run refuses to start it", refusedProblem},
		{`exec npx -y mcp-remote https://mcp.example.com/mcp --header "Authorization: Bearer "'$''{PD_KEY}'"" --header "X-Team-Token: fake-literal-header" --transport http-only`,
			"exposes the X-Team-Token header", exposed},
	} {
		h := newHarness(t, "", nil, nil)
		home := homed(t, h)
		config, _ := json.Marshal(map[string]any{"mcpServers": map[string]any{"team": map[string]any{
			"command": "keyward", "args": []string{"run", "--only", "PD_KEY", "--", "sh", "-c", tc.script}, "env": map[string]string{"PD_KEY": "cap://pagerduty-key"}}}})
		os.WriteFile(filepath.Join(home, ".claude.json"), config, 0o600)
		if code := h.cli.Run([]string{"mcp"}); code != 1 || !strings.Contains(h.out(), tc.problem) || !strings.Contains(h.out(), tc.exposes) {
			t.Errorf("exit %d, want 1, %q and %q:\n%s", code, tc.problem, tc.exposes, h.out())
		}
		if strings.Contains(h.out(), "fake-literal") {
			t.Errorf("mcp printed a literal:\n%s", h.out())
		}

		h = newHarness(t, "", nil, nil)
		h.cli.Home = home
		h.cli.Run([]string{"doctor"})
		if !strings.Contains(flat(h.out()), tc.problem+"; see keyward mcp") {
			t.Errorf("doctor output:\n%s", h.out())
		}
	}
}

// An earlier keyward wrote a remote server's ordinary headers, such as Accept,
// into its bridge as they were. They hold no secret, so keyward mcp and doctor
// find nothing wrong with the bridge.
func TestMCPAndDoctorPassABridgeWithAnOrdinaryHeader(t *testing.T) {
	h := newHarness(t, "", map[string]string{"github-token": "v"}, nil)
	home := homed(t, h)
	os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export GITHUB_TOKEN='cap://github-token'\n"), 0o644)
	config, _ := json.Marshal(map[string]any{"mcpServers": map[string]any{"github": map[string]any{"command": "keyward",
		"args": []string{"run", "--only", "GITHUB_TOKEN", "--", "sh", "-c", `exec npx -y mcp-remote https://api.example.com/mcp/ --header "Accept: application/json, text/event-stream" ` +
			`--header "Authorization: Bearer "'$''{GITHUB_TOKEN}'"" --header "X-Client-Name: claude-code" --transport http-only`},
		"env": map[string]string{"GITHUB_TOKEN": "cap://github-token"}}}})
	os.WriteFile(filepath.Join(home, ".claude.json"), config, 0o600)
	var printed strings.Builder
	run := runner(h, &printed)

	if code, out := run("mcp"); code != 0 || !strings.Contains(out, "No MCP server needs a change.") {
		t.Errorf("mcp exit %d, want 0:\n%s", code, out)
	}
	if code, out := run("doctor"); code != 0 || verdict(out) != "✓ No problems found. 1 check needs attention." {
		t.Errorf("doctor exit %d, want 0:\n%s", code, out)
	}
}

// keyward restore puts a value back in the file it came from, but a server that
// starts through keyward run still resolves it from the reference in its env. So
// doctor counts a reference in each MCP config it reads servers from, and never
// offers keyward rm for a secret a server still uses; once that secret is gone,
// it reports the server's reference to it.
func TestDoctorNeverOffersToRemoveASecretAServerStillUses(t *testing.T) {
	const value = "lin_api_FakeLinearKey0000000000000000"
	args := []string{"run", "--only", "LINEAR_API_KEY", "--", "sh", "-c",
		`exec npx -y mcp-remote https://mcp.example.com/mcp --header "Authorization: Bearer "'$''{LINEAR_API_KEY}'"" --transport http-only`}
	server, _ := json.Marshal(map[string]any{"mcpServers": map[string]any{"linear": map[string]any{
		"command": "keyward", "args": args, "env": map[string]string{"LINEAR_API_KEY": "cap://linear-api-key"}}}})
	list, _ := json.Marshal(args)
	codex := "[mcp_servers.linear]\ncommand = \"keyward\"\nargs = " + string(list) + "\nenv = { LINEAR_API_KEY = \"cap://linear-api-key\" }\n"
	for _, tc := range []struct{ name, in, path, config string }{
		{"Cursor", "home", ".cursor/mcp.json", string(server)},
		{"a Cursor project", "workdir", ".cursor/mcp.json", string(server)},
		{"Codex", "home", ".codex/config.toml", codex},
		{"this Claude Code project", "workdir", ".mcp.json", string(server)},
		{"another Claude Code project", "project", ".mcp.json", string(server)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, "yes\n", nil, nil)
			home := homed(t, h)
			h.cli.Workdir = t.TempDir()
			project := t.TempDir()
			os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"projects": {"`+project+`": {}}}`), 0o600)
			rc := filepath.Join(home, ".zshrc")
			os.WriteFile(rc, []byte("export LINEAR_API_KEY="+value+"\n"), 0o644)
			config := filepath.Join(map[string]string{"home": home, "workdir": h.cli.Workdir, "project": project}[tc.in], tc.path)
			os.MkdirAll(filepath.Dir(config), 0o755)
			var printed strings.Builder
			run := runner(h, &printed)
			shown := strings.Replace(config, home+"/", "~/", 1)
			read := func(out string) string {
				_, list, _ := strings.Cut(flat(out), "keyward doctor read ")
				list, _, _ = strings.Cut(list, " not read ")
				return " " + strings.ReplaceAll(list, ",", "") + " "
			}

			if code, out := run("migrate", rc); code != 0 {
				t.Fatalf("migrate exit %d:\n%s", code, out)
			}
			os.WriteFile(config, []byte(tc.config), 0o600)
			if code, out := run("mcp"); code != 0 || !strings.Contains(out, "No MCP server needs a change.") {
				t.Fatalf("mcp exit %d, want 0 for the fix it prints:\n%s", code, out)
			}
			h.cli.Stdin = strings.NewReader("yes\n")
			if code, out := run("restore", rc); code != 0 {
				t.Fatalf("restore exit %d:\n%s", code, out)
			}
			if _, out := run("doctor"); strings.Contains(out, "keyward rm") || !strings.Contains(read(out), " "+shown+" ") || !strings.Contains(out, "1 secret(s) stored and referenced") {
				t.Errorf("doctor does not count the server's reference:\n%s", out)
			}
			h.cli.Environ = func() []string { return []string{"LINEAR_API_KEY=cap://linear-api-key"} }
			if code, out := run(args...); code != 0 || !slices.Contains(h.exec.env, "LINEAR_API_KEY="+value) {
				t.Errorf("the server's keyward run exit %d, want 0 and its secret:\n%s", code, out)
			}
			if code, out := run("rm", "linear-api-key"); code != 0 {
				t.Fatalf("rm exit %d:\n%s", code, out)
			}
			if code, out := run("doctor"); code != 1 || !strings.HasPrefix(row(out, shown+":"), shown+":") || !strings.HasSuffix(row(out, shown+":"), " cap://linear-api-key keyward add linear-api-key") {
				t.Errorf("doctor exit %d, want 1 and the server's reference to the removed secret:\n%s", code, out)
			}
			if strings.Contains(printed.String(), value) {
				t.Errorf("printed the value:\n%s", printed.String())
			}
		})
	}
}

// runner runs a command with fresh output, returning its exit code and output, and
// keeps everything printed in printed.
func runner(h *harness, printed *strings.Builder) func(args ...string) (int, string) {
	return func(args ...string) (int, string) {
		h.stdout.Reset()
		h.stderr.Reset()
		code := h.cli.Run(args)
		printed.WriteString(h.out() + h.err())
		return code, h.out() + h.err()
	}
}

// A remote server's URL is in mcp-remote's command line, so a migrated secret it
// reads would be readable by any process: keyward mcp warns, and wrap skips the
// server unless told to allow it. Literal env and header values are never printed,
// but are kept when applied.
func TestMCPWrapSkipsAServerWhoseURLReadsAMigratedSecretUnlessAllowed(t *testing.T) {
	h := newHarness(t, "yes\n", map[string]string{"pagerduty-key": "fake-pagerduty-value", "github-token": "fake-github-value"}, nil)
	home := homed(t, h)
	h.cli.Interactive, h.cli.Self = true, "/opt/homebrew/bin/keyward"
	os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export PD_KEY='cap://pagerduty-key'\nexport GITHUB_TOKEN='cap://github-token'\n"), 0o644)
	os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"mcpServers": {"mixed": {"type": "http", "url": "https://mcp.example.com/mcp?key=${PD_KEY}",
    "headers": {"Authorization": "Bearer ${GITHUB_TOKEN}", "X-Api-Key": "fake-literal-prefix-${GITHUB_TOKEN}", "X-Team": "fake-literal-header"},
    "env": {"LEVEL": "fake-literal-env", "DSN": "fake-literal-dsn@${DB_HOST}"}}}}`), 0o600)
	calls := fakeTools(t, h, home)
	var printed strings.Builder
	run := runner(h, &printed)

	if code, out := run("mcp"); code != 1 || !strings.Contains(out, "its URL holds PD_KEY") || !strings.Contains(out, "use header authentication if the server supports it") ||
		!strings.Contains(out, "keyward mcp wrap skips it. To start it anyway, with PD_KEY in a command line, where any process can read it, run keyward mcp wrap --allow-command-line mixed.") ||
		strings.Contains(out, "Replace the") {
		t.Errorf("mcp exit %d, want 1, a warning and no change keyward run would refuse:\n%s", code, out)
	}
	if code, out := run("mcp", "wrap"); code != 1 || !strings.Contains(out, "Skipped mixed: its URL holds PD_KEY") || !strings.Contains(out, "keyward mcp wrap --allow-command-line mixed") {
		t.Errorf("wrap exit %d, want 1 and the server skipped:\n%s", code, out)
	}
	for _, call := range *calls {
		if !strings.Contains(call, "--help") {
			t.Errorf("ran %q for a skipped server", call)
		}
	}
	if code, out := run("mcp", "wrap", "--allow-command-line"); code != 0 || !strings.Contains(out, "Warning: its URL holds PD_KEY") {
		t.Fatalf("wrap --allow-command-line exit %d, want 0 and the warning:\n%s", code, out)
	}
	data, _ := os.ReadFile(filepath.Join(home, ".claude.json"))
	if !strings.Contains(string(data), "mcp-remote") || !strings.Contains(string(data), `"KW_HDR_1":"fake-literal-prefix-"`) || !strings.Contains(string(data), `"KW_HDR_2":"fake-literal-header"`) {
		t.Errorf("config after wrap: %s", data)
	}
	if code, out := start(t, h, run, filepath.Join(home, ".claude.json"), "mixed"); code != 0 {
		t.Errorf("the server's keyward run exit %d, want 0:\n%s", code, out)
	}
	if strings.Contains(printed.String(), "fake-") {
		t.Errorf("printed a literal or value:\n%s", printed.String())
	}
}

// claude mcp add-json takes a server's definition in its command line, which any
// process can read. So wrap, unwrap and uninstall never run it for a definition,
// to add or to put back, that holds a credential doctor reports in env or headers,
// written or moved there from a header: they skip the server, saying to move the
// credential out first, as doctor advises, and --purge waits for it. A value that
// is no credential is applied.
func TestNoCredentialGoesInClaudesCommandLine(t *testing.T) {
	const appKey, headerKey = "fa6e11fe9876543210fedcba9876543210ab", "FakeOpaqueTeamHeader0000"
	r := uninstallFixture(t, "")
	h := r.h
	home := homed(t, h)
	h.store.Seed(map[string]string{"dd-api-key": "fake-api-value", "pd-key": "fake-pd-value"})
	h.cli.Interactive, h.cli.Self = true, "/opt/homebrew/bin/keyward"
	os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export DD_API_KEY='cap://dd-api-key'\nexport PD_KEY='cap://pd-key'\n"), 0o644)
	config := filepath.Join(home, ".claude.json")
	data, _ := json.Marshal(map[string]any{"mcpServers": map[string]any{
		"datadog": map[string]any{"command": "dd-mcp", "env": map[string]string{"DD_API_KEY": "${DD_API_KEY}", "DD_APP_KEY": appKey}},
		"team":    map[string]any{"type": "http", "url": "https://mcp.example.com/mcp", "headers": map[string]string{"Authorization": "Bearer ${DD_API_KEY}", "X-Api-Key": headerKey}},
		"pd":      map[string]any{"command": "pd-mcp", "env": map[string]string{"PD_KEY": "${PD_KEY}", "LOG_LEVEL": "debug"}},
		"wrapped": map[string]any{"command": "/opt/homebrew/bin/keyward", "args": []string{"run", "--only", "DD_API_KEY,KW_HDR_1", "--", "sh", "-c",
			`exec npx -y mcp-remote https://mcp.example.com/mcp --header "Authorization: Bearer "'$''{DD_API_KEY}'"" --header "X-Api-Key: "'$''{KW_HDR_1}'"" --transport http-only`},
			"env": map[string]string{"DD_API_KEY": "cap://dd-api-key", "KW_HDR_1": headerKey}},
	}})
	os.WriteFile(config, data, 0o600)
	calls := fakeTools(t, h, home)
	var printed strings.Builder
	run := runner(h, &printed)
	const skips = "claude mcp add-json would get it in its command line, where any process can read it; move it out first, as keyward doctor says"

	if code, out := run("mcp"); code != 1 || !strings.Contains(out, "It skips datadog until the credential in its env.DD_APP_KEY is moved out") ||
		!strings.Contains(out, "It skips team until the credential in its headers.X-Api-Key is moved out") {
		t.Errorf("mcp exit %d, want 1 and which servers wrap skips:\n%s", code, out)
	}
	h.cli.Stdin = strings.NewReader("yes\n")
	if code, out := run("mcp", "wrap"); code != 1 || !strings.Contains(out, "Skipped datadog: its env.DD_APP_KEY holds a credential, and "+skips+", then run keyward mcp wrap again.") ||
		!strings.Contains(out, "Skipped team: its headers.X-Api-Key holds a credential") || !strings.Contains(out, "✓ pd") {
		t.Errorf("wrap exit %d, want 1, datadog and team skipped, and pd changed:\n%s", code, out)
	}
	if _, out := run("doctor"); !strings.Contains(out, "Claude Code server datadog, env.DD_APP_KEY\n") || !strings.Contains(out, "Claude Code server team, headers.X-Api-Key\n") {
		t.Errorf("doctor does not say where each credential is:\n%s", out)
	}
	h.cli.Stdin = strings.NewReader("yes\n")
	if code, out := run("mcp", "unwrap"); code != 1 || !strings.Contains(out, "Skipped wrapped: its env.KW_HDR_1 (from its X-Api-Key header) holds a credential, and "+skips+", then run keyward mcp unwrap again.") {
		t.Errorf("unwrap exit %d, want 1 and wrapped skipped:\n%s", code, out)
	}
	h.cli.PurgeVault = func() error { t.Error("purged while a server still used the vault"); return nil }
	if code, out := run("uninstall", "--purge"); code != 1 || !strings.Contains(out, "MCP server wrapped (Claude Code, ~/.claude.json): its env.KW_HDR_1 (from its X-Api-Key header) holds a credential, and "+skips+", then run keyward uninstall again") {
		t.Errorf("uninstall --purge exit %d, want 1 and wrapped left to change:\n%s", code, out)
	}
	for _, call := range *calls {
		if strings.Contains(call, appKey) || strings.Contains(call, headerKey) {
			t.Errorf("claude got a credential in its command line: %s", call)
		}
	}
	if !slices.ContainsFunc(*calls, func(call string) bool { return strings.Contains(call, "LOG_LEVEL") }) {
		t.Errorf("pd was not applied: %q", *calls)
	}
}

// A server's own script that reads a migrated variable as "$VAR" would read its
// reference, so keyward mcp and doctor report it until wrap starts it through
// keyward run, which resolves the variable.
func TestMCPReportsAScriptThatReadsAMigratedVariableAsShDoes(t *testing.T) {
	h := newHarness(t, "", map[string]string{"github-token": "fake-github-value"}, nil)
	home := homed(t, h)
	h.cli.Interactive, h.cli.Self = true, "/opt/homebrew/bin/keyward"
	os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export GITHUB_TOKEN='cap://github-token'\n"), 0o644)
	os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"mcpServers": {"gh": {"command": "sh", "args": ["-c", "GITHUB_PERSONAL_ACCESS_TOKEN=\"$GITHUB_TOKEN\" exec github-mcp-server stdio"]}}}`), 0o600)
	fakeTools(t, h, home)
	var printed strings.Builder
	run := runner(h, &printed)

	if code, out := run("mcp"); code != 1 || !strings.Contains(out, "uses GITHUB_TOKEN") {
		t.Errorf("mcp exit %d, want 1 and the server:\n%s", code, out)
	}
	if code, out := run("doctor"); code != 1 || verdict(out) != "✗ Problems found: 1 MCP server(s) would receive cap:// references instead of values." {
		t.Errorf("doctor exit %d, want 1 and the server reported:\n%s", code, out)
	}
	h.cli.Stdin = strings.NewReader("yes\n")
	if code, out := run("mcp", "wrap"); code != 0 || !strings.Contains(out, "✓ gh") {
		t.Fatalf("wrap exit %d:\n%s", code, out)
	}
	if code, out := run("doctor"); code != 0 || verdict(out) != "✓ No problems found." {
		t.Errorf("doctor exit %d, want 0:\n%s", code, out)
	}
}

// A server that takes its token as an argument would get it in its command line
// once wrapped, as it did before keyward, which keyward run refuses. So keyward
// mcp shows no change for it, and wrap skips it, saying to pass the token in env
// if the server reads it from there, unless given --allow-command-line, which it
// gives the server's keyward run. keyward mcp and doctor then list it as a
// warning, so doctor's advice for the token it finds in a running program's
// command line, to see keyward mcp, leads somewhere.
func TestMCPAndDoctorWarnOfAServerThatTakesItsTokenAsAnArgument(t *testing.T) {
	h := newHarness(t, "", map[string]string{"slack-bot-token": "fake-slack-value"}, nil)
	home := homed(t, h)
	h.cli.Interactive, h.cli.Self = true, "/opt/homebrew/bin/keyward"
	os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export SLACK_BOT_TOKEN='cap://slack-bot-token'\n"), 0o644)
	config := filepath.Join(home, ".claude.json")
	os.WriteFile(config, []byte(`{"mcpServers": {"slack": {"command": "npx", "args": ["-y", "slack-mcp", "--token", "${SLACK_BOT_TOKEN}"]}}}`), 0o600)
	calls := fakeTools(t, h, home)
	var printed strings.Builder
	run := runner(h, &printed)
	const (
		argument = "its script passes SLACK_BOT_TOKEN as an argument, which any process can read in its command line; pass it in env instead, if the server reads it from there"
		refused  = "wrapped, it would pass SLACK_BOT_TOKEN as an argument, which keyward run refuses; pass it in env instead, if the server reads it from there"
		anyway   = "to start it anyway, with SLACK_BOT_TOKEN in a command line, where any process can read it, run keyward mcp wrap --allow-command-line slack."
	)

	if code, out := run("mcp"); code != 1 || !strings.Contains(out, "Warning: "+refused+".") || !strings.Contains(out, "keyward mcp wrap skips it. T"+anyway[1:]) ||
		strings.Contains(out, `"command": "keyward"`) {
		t.Errorf("mcp exit %d, want 1, the warning and no change keyward run would refuse:\n%s", code, out)
	}
	if code, out := run("mcp", "wrap"); code != 1 || !strings.Contains(out, "Skipped slack: "+refused+", or, "+anyway) {
		t.Errorf("wrap exit %d, want 1 and the server skipped:\n%s", code, out)
	}
	for _, call := range *calls {
		if !strings.Contains(call, "--help") {
			t.Errorf("ran %q for a skipped server", call)
		}
	}
	h.cli.Stdin = strings.NewReader("yes\n")
	if code, out := run("mcp", "wrap", "--allow-command-line"); code != 0 || !strings.Contains(out, "✓ slack") {
		t.Fatalf("wrap --allow-command-line exit %d:\n%s", code, out)
	}
	if code, out := run("mcp"); code != 0 || !strings.Contains(out, "No MCP server needs a change.") || !strings.Contains(out, allowedSection+":") ||
		!strings.Contains(out, "slack (Claude Code, ~/.claude.json): "+argument+".") {
		t.Errorf("mcp exit %d, want 0 and the warning:\n%s", code, out)
	}
	if code, out := run("doctor"); code != 0 || verdict(out) != "✓ No problems found. 1 check needs attention." ||
		!slices.Contains(checklist(out), "! MCP servers "+allowedSection+"; see keyward mcp") || strings.Contains(out, "finds nothing to change") {
		t.Errorf("doctor exit %d, want 0 and the warning alone:\n%s", code, out)
	}
	if code, out := start(t, h, run, config, "slack"); code != 0 || h.exec.calls != 1 {
		t.Errorf("the server's keyward run exit %d, want 0 and the server started:\n%s", code, out)
	}
	h.cli.Exposures = func() ([]exposure.Exposure, error) {
		return []exposure.Exposure{{Secret: "slack-bot-token", PID: 4242, Program: "node"}}, nil
	}
	if code, out := run("doctor"); code != 1 || !strings.Contains(out, "keyward mcp shows how for MCP servers") || !strings.Contains(flat(out), allowedSection+"; see keyward mcp") {
		t.Errorf("doctor exit %d, want 1 and the warning beside the exposure:\n%s", code, out)
	}
	if strings.Contains(printed.String(), "fake-slack-value") {
		t.Errorf("printed the value:\n%s", printed.String())
	}
}

// A server the user allowed with --allow-command-line before 1.5.0 runs through
// keyward already, and needs only the option in its keyward run, so keyward mcp
// does not say to run it through keyward, but says the option is there because
// the user allowed it, as wrap does when it prints the change, unless given the
// option now.
func TestAnOptionTheUserAllowedBeforeIsSaidToBeWhy(t *testing.T) {
	h := newHarness(t, "", map[string]string{"pagerduty-key": "fake-pagerduty-value"}, nil)
	home := homed(t, h)
	config := filepath.Join(home, ".cursor", "mcp.json")
	os.MkdirAll(filepath.Dir(config), 0o755)
	data, _ := json.Marshal(map[string]any{"mcpServers": map[string]any{"team": map[string]any{"command": "keyward",
		"args": []string{"run", "--only", "PD_KEY", "--", "sh", "-c", `exec npx -y mcp-remote "https://mcp.example.com/mcp?key=$PD_KEY" --transport http-only`},
		"env":  map[string]string{"PD_KEY": "cap://pagerduty-key"}}}})
	os.WriteFile(config, data, 0o600)
	h.cli.Ledger.Add(ledger.Record{Kind: ledger.Allowed, Path: config, Name: "team", Text: "PD_KEY"})
	var printed strings.Builder
	run := runner(h, &printed)
	const before = "You allowed this with --allow-command-line before, and keyward run now needs the option in its args. Make this change"

	for _, args := range [][]string{{"mcp"}, {"mcp", "wrap"}} {
		if code, out := run(args...); code != 1 || !strings.Contains(out, before) || !strings.Contains(out, `In args, add "--allow-command-line" after "run".`) || strings.Contains(out, "like this") {
			t.Errorf("%v exit %d, want 1 and why the option is added:\n%s", args, code, out)
		}
	}
	if code, out := run("mcp", "wrap", "--allow-command-line"); code != 1 || strings.Contains(out, "before") || !strings.Contains(out, `In args, add "--allow-command-line" after "run".`) {
		t.Errorf("wrap --allow-command-line exit %d, want 1 and the change alone:\n%s", code, out)
	}
}

// wrap changes another Claude Code project's servers only in its folder, so it
// names the folder, with the command to run there, which keeps the option it was
// given. keyward mcp marks each such server that keyward run refuses.
func TestAServerOfAnotherProjectIsNamedWithTheCommandForIt(t *testing.T) {
	h := newHarness(t, "", map[string]string{"slack-bot-token": "fake-slack-value"}, nil)
	home := homed(t, h)
	other := filepath.Join(home, "other")
	os.Mkdir(other, 0o755)
	os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export SLACK_BOT_TOKEN='cap://slack-bot-token'\n"), 0o644)
	data, _ := json.Marshal(map[string]any{"projects": map[string]any{other: map[string]any{"mcpServers": map[string]any{
		"slack": map[string]any{"command": "npx", "args": []string{"-y", "slack-mcp", "--token", "${SLACK_BOT_TOKEN}"}},
		"wrapped": map[string]any{"command": "keyward", "args": []string{"run", "--only", "SLACK_BOT_TOKEN", "--", "sh", "-c", `exec npx -y slack-mcp --token "$SLACK_BOT_TOKEN"`},
			"env": map[string]string{"SLACK_BOT_TOKEN": "cap://slack-bot-token"}}}}}})
	os.WriteFile(filepath.Join(home, ".claude.json"), data, 0o600)
	fakeTools(t, h, home)
	var printed strings.Builder
	run := runner(h, &printed)

	if code, out := run("mcp"); code != 1 || !strings.Contains(out, "\n  slack  ~/other\n") || !strings.Contains(out, "\n  wrapped  ~/other  (keyward run refuses to start it)\n") {
		t.Errorf("mcp exit %d, want 1 and both servers:\n%s", code, out)
	}
	for _, args := range [][]string{{"mcp", "wrap", "--allow-command-line"}, {"mcp", "wrap", "--allow-command-line", "slack"}} {
		if code, out := run(args...); code != 1 || !strings.Contains(out, "run keyward mcp wrap --allow-command-line ") || strings.Contains(out, "run keyward mcp wrap in") || strings.Contains(out, "wrap there") {
			t.Errorf("%v exit %d, want 1 and the command with its option:\n%s", args, code, out)
		}
	}
}

// Upgraded, keyward run refuses to start a server that an earlier keyward wrapped
// to put a secret in a command line. keyward mcp and doctor report each with its
// fix: one the ledger says the user allowed gets --allow-command-line in its
// keyward run on the next wrap, and one that passes its token as an argument
// waits for the user to allow it, or for the server to take the token from env.
func TestAServerKeywardRunRefusesIsReportedWithItsFix(t *testing.T) {
	h := newHarness(t, "", map[string]string{"pagerduty-key": "fake-pagerduty-value", "slack-bot-token": "fake-slack-value"}, nil)
	home := homed(t, h)
	h.cli.Interactive = true
	config := filepath.Join(home, ".claude.json")
	data, _ := json.Marshal(map[string]any{"mcpServers": map[string]any{
		"team": map[string]any{"command": "keyward", "args": []string{"run", "--only", "PD_KEY", "--", "sh", "-c", `exec npx -y mcp-remote "https://mcp.example.com/mcp?key=$PD_KEY" --transport http-only`},
			"env": map[string]string{"PD_KEY": "cap://pagerduty-key"}},
		"slack": map[string]any{"command": "keyward", "args": []string{"run", "--only", "SLACK_BOT_TOKEN", "--", "sh", "-c", `exec npx -y slack-mcp --token "$SLACK_BOT_TOKEN"`},
			"env": map[string]string{"SLACK_BOT_TOKEN": "cap://slack-bot-token"}},
	}})
	os.WriteFile(config, data, 0o600)
	h.cli.Ledger.Add(ledger.Record{Kind: ledger.Allowed, Path: config, Name: "team", Text: "PD_KEY"})
	fakeTools(t, h, home)
	var printed strings.Builder
	run := runner(h, &printed)
	started := func(name string) int {
		t.Helper()
		code, _ := start(t, h, run, config, name)
		return code
	}
	const refused = "2 MCP server(s) would put a secret in a command line, so keyward run refuses to start them"

	if code, out := run("mcp"); code != 1 || !strings.Contains(out, refused+".") || !strings.Contains(out, `In args, add "--allow-command-line" after "run".`) ||
		!strings.Contains(out, "npx would get SLACK_BOT_TOKEN in its command line (line 1)") ||
		!strings.Contains(out, "To start it anyway, with SLACK_BOT_TOKEN in a command line, where any process can read it, run keyward mcp wrap --allow-command-line slack.") {
		t.Errorf("mcp exit %d, want 1 and each server's fix:\n%s", code, out)
	}
	if code, out := run("doctor"); code != 1 || verdict(out) != "✗ Problems found: "+refused+"." {
		t.Errorf("doctor exit %d, want 1 and both servers reported:\n%s", code, out)
	}
	if started("team") != 2 || started("slack") != 2 {
		t.Fatal("keyward run started a server it should refuse")
	}
	h.cli.Stdin = strings.NewReader("yes\n")
	if code, out := run("mcp", "wrap"); code != 1 || !strings.Contains(out, "✓ team") ||
		!strings.Contains(out, "Skipped slack: it already runs through keyward, but keyward run refuses to start it.\n  npx would get SLACK_BOT_TOKEN in its command line (line 1)") {
		t.Errorf("wrap exit %d, want 1, team given the option and slack skipped:\n%s", code, out)
	}
	if code := started("team"); code != 0 {
		t.Errorf("team's keyward run exit %d, want 0", code)
	}
	h.cli.Stdin = strings.NewReader("yes\n")
	if code, out := run("mcp", "wrap", "--allow-command-line", "slack"); code != 0 || !strings.Contains(out, "✓ slack") {
		t.Errorf("wrap --allow-command-line slack exit %d:\n%s", code, out)
	}
	if code := started("slack"); code != 0 {
		t.Errorf("slack's keyward run exit %d, want 0", code)
	}
	if code, out := run("doctor"); code != 0 || verdict(out) != "✓ No problems found. 1 check needs attention." ||
		!strings.Contains(flat(out), "2 MCP server(s) put a secret in a command line, as allowed with --allow-command-line; see keyward mcp") {
		t.Errorf("doctor exit %d, want 0 and both servers listed as allowed:\n%s", code, out)
	}
	if strings.Contains(printed.String(), "fake-") {
		t.Errorf("printed a value:\n%s", printed.String())
	}
}

// For a wrapped server keyward run refuses, keyward mcp and wrap say what keyward
// run says when the server starts: each reason, with its fix, such as a header
// mcp-remote fills in for a bridge written by hand, or why it cannot read the
// script. A fix never sends the value on stdin, where a server reads the
// protocol. --allow-command-line comes last, said to leave the secret where any
// process can read it, or for a script keyward run cannot read, to start the
// server unchecked. Nothing calls the server exposed, as it does not start.
func TestMCPSaysWhatKeywardRunSaysOfAServerItRefuses(t *testing.T) {
	for name, tc := range map[string]struct{ shell, script, fix string }{
		"a bridge written by hand": {"sh", `npx -y mcp-remote https://mcp.example.com/mcp --header "Authorization: Bearer $JIRA"`, ""},
		"a script in another":      {"sh", `exec sh -c "GITHUB_PERSONAL_ACCESS_TOKEN=$JIRA exec github-mcp-server stdio"`, ""},
		"a token as an argument":   {"sh", `exec npx -y slack-mcp --token "$JIRA"`, "Pass it to npx in an environment variable it reads instead."},
		"a script it cannot read":  {"zsh", `for x (a b) print $x; T="$JIRA" exec some-mcp`, ""},
	} {
		h := newHarness(t, "", map[string]string{"jira-token": "fake-jira-value"}, nil)
		home := homed(t, h)
		h.cli.Interactive = true
		config := filepath.Join(home, ".claude.json")
		data, _ := json.Marshal(map[string]any{"mcpServers": map[string]any{"jira": map[string]any{"command": "keyward",
			"args": []string{"run", "--only", "JIRA", "--", tc.shell, "-c", tc.script}, "env": map[string]string{"JIRA": "cap://jira-token"}}}})
		os.WriteFile(config, data, 0o600)
		fakeTools(t, h, home)
		var printed strings.Builder
		run := runner(h, &printed)
		anyway, problem := "To start it anyway, with JIRA in a command line, where any process can read it, run keyward mcp wrap --allow-command-line jira.",
			"1 MCP server(s) would put a secret in a command line, so keyward run refuses to start them."
		if tc.shell == "zsh" {
			anyway, problem = "To start it anyway, unchecked, run keyward mcp wrap --allow-command-line jira.",
				"1 MCP server(s) start a script keyward run cannot read, so it refuses to start them."
		}

		code, said := start(t, h, run, config, "jira")
		if code != 2 {
			t.Fatalf("%s: keyward run exit %d, want 2:\n%s", name, code, said)
		}
		_, mcp := run("mcp")
		h.cli.Stdin = strings.NewReader("yes\n")
		_, wrap := run("mcp", "wrap")
		for _, out := range []string{mcp, wrap} {
			// Each line keyward run prints, but its last, about the option, and a
			// fix that sends the value on stdin.
			lines := strings.Split(strings.TrimSpace(said), "\n")
			for _, line := range lines[:len(lines)-1] {
				if line = strings.TrimSpace(strings.TrimPrefix(line, "keyward run: ")); !strings.Contains(line, "stdin") && !strings.Contains(out, line) {
					t.Errorf("%s: output lacks %q:\n%s", name, line, out)
				}
			}
			if strings.Contains(out, "stdin") || !strings.Contains(out, tc.fix) {
				t.Errorf("%s: output lacks the fix %q, or sends the value on stdin:\n%s", name, tc.fix, out)
			}
			if !strings.Contains(out, "keyward run refuses to start it") || !strings.HasSuffix(strings.TrimSpace(out), anyway) ||
				strings.Contains(out, "exposes") || strings.Contains(out, "which any process can read") {
				t.Errorf("%s: output does not say keyward run refuses it, with the option last:\n%s", name, out)
			}
		}
		if !strings.HasPrefix(mcp, problem) {
			t.Errorf("%s: keyward mcp does not start with %q:\n%s", name, problem, mcp)
		}
	}
}

// keyward run cannot see where the script of a server it cannot read puts a
// secret, so nothing says the server puts one in a command line: refused, it
// would start unchecked, and once allowed, it does.
func TestAServerKeywardRunCannotReadIsSaidToStartUnchecked(t *testing.T) {
	h := newHarness(t, "", map[string]string{"pagerduty-key": "fake-pagerduty-value"}, nil)
	home := homed(t, h)
	h.cli.Interactive = true
	config := filepath.Join(home, ".claude.json")
	data, _ := json.Marshal(map[string]any{"mcpServers": map[string]any{"pd": map[string]any{"command": "keyward",
		"args": []string{"run", "--only", "PD_KEY", "--", "zsh", "-c", `for x (a b) print $x; PD="$PD_KEY" exec some-mcp`},
		"env":  map[string]string{"PD_KEY": "cap://pagerduty-key"}}}})
	os.WriteFile(config, data, 0o600)
	fakeTools(t, h, home)
	var printed strings.Builder
	run := runner(h, &printed)
	const problem = "1 MCP server(s) start a script keyward run cannot read, so it refuses to start them"

	if code, out := run("mcp"); code != 1 || !strings.Contains(out, problem+".") ||
		!strings.Contains(out, "To start it anyway, unchecked, run keyward mcp wrap --allow-command-line pd.") || strings.Contains(out, "command line,") {
		t.Errorf("mcp exit %d, want 1, and the server said to start unchecked:\n%s", code, out)
	}
	if code, out := run("doctor"); code != 1 || verdict(out) != "✗ Problems found: "+problem+"." {
		t.Errorf("doctor exit %d, want 1 and the server counted:\n%s", code, out)
	}
	h.cli.Stdin = strings.NewReader("yes\n")
	if code, out := run("mcp", "wrap", "--allow-command-line"); code != 0 || !strings.Contains(out, "✓ pd") {
		t.Fatalf("wrap --allow-command-line exit %d:\n%s", code, out)
	}
	const allowed = "1 MCP server(s) start unchecked, as allowed with --allow-command-line"
	if code, out := run("mcp"); code != 0 || !strings.Contains(out, allowed+":") ||
		!strings.Contains(out, "pd (Claude Code, ~/.claude.json): keyward run cannot read its script, so it starts it unchecked.") {
		t.Errorf("mcp exit %d, want 0 and the server listed as allowed:\n%s", code, out)
	}
	if code, out := run("doctor"); code != 0 || !strings.Contains(flat(out), allowed+"; see keyward mcp") {
		t.Errorf("doctor exit %d, want 0 and the server listed as allowed:\n%s", code, out)
	}
	// One given the option by hand, which the ledger does not record.
	data, _ = json.Marshal(map[string]any{"mcpServers": map[string]any{"hand": map[string]any{"command": "keyward",
		"args": []string{"run", "--allow-command-line", "--only", "PD_KEY", "--", "zsh", "-c", `for x (a b) print $x; PD="$PD_KEY" exec some-mcp`},
		"env":  map[string]string{"PD_KEY": "cap://pagerduty-key"}}}})
	os.WriteFile(config, data, 0o600)
	if code, out := run("mcp"); code != 1 || !strings.HasPrefix(out, "1 MCP server(s) start unchecked, as keyward run cannot read their script.") ||
		!strings.Contains(out, "starts unchecked, as keyward run cannot read its script") || strings.Contains(out, "exposes") || strings.Contains(out, "command line,") {
		t.Errorf("mcp exit %d, want 1 and the server said to start unchecked:\n%s", code, out)
	}
	if strings.Contains(printed.String(), "fake-") {
		t.Errorf("printed a value:\n%s", printed.String())
	}
}

// keyward mcp and doctor count servers, so one that keyward run refuses and
// whose --only also leaves out a reference is one server to change, listed once.
func TestAServerWithTwoProblemsIsCountedOnce(t *testing.T) {
	h := newHarness(t, "", map[string]string{"slack-bot-token": "fake-slack-value", "pagerduty-key": "fake-pagerduty-value"}, nil)
	home := homed(t, h)
	data, _ := json.Marshal(map[string]any{"mcpServers": map[string]any{"slack": map[string]any{"command": "keyward",
		"args": []string{"run", "--only", "SLACK_BOT_TOKEN", "--", "sh", "-c", `exec npx -y slack-mcp --token "$SLACK_BOT_TOKEN"`},
		"env":  map[string]string{"SLACK_BOT_TOKEN": "cap://slack-bot-token", "PD_KEY": "cap://pagerduty-key"}}}})
	os.WriteFile(filepath.Join(home, ".claude.json"), data, 0o600)
	var printed strings.Builder
	run := runner(h, &printed)

	if code, out := run("mcp"); code != 1 || !strings.HasPrefix(out, refusedProblem+".\n") || strings.Count(out, "\nslack\n") != 1 {
		t.Errorf("mcp exit %d, want 1 and the server once:\n%s", code, out)
	}
	if code, out := run("doctor"); code != 1 || verdict(out) != "✗ Problems found: "+refusedProblem+"." {
		t.Errorf("doctor exit %d, want 1 and the server counted once:\n%s", code, out)
	}
}

// mcp-remote takes as its URL the first argument that is neither a --header nor
// the value after one, so a migrated secret in a URL after the headers reaches
// its command line as one before them does. keyward mcp warns of it, wrap skips
// the server until given --allow-command-line, and once it is wrapped, keyward
// mcp and doctor list it as allowed.
func TestMCPWrapSkipsAServerWhoseURLAfterItsHeadersReadsAMigratedSecret(t *testing.T) {
	h := newHarness(t, "", map[string]string{"q-key": "fake-q-value", "jira-token": "fake-jira-value"}, nil)
	home := homed(t, h)
	h.cli.Interactive, h.cli.Self = true, "/opt/homebrew/bin/keyward"
	os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export Q_KEY='cap://q-key'\nexport JIRA='cap://jira-token'\n"), 0o644)
	config, _ := json.Marshal(map[string]any{"mcpServers": map[string]any{"q": map[string]any{"command": "npx",
		"args": []string{"-y", "mcp-remote", "--header", "Authorization: Bearer ${JIRA}", "https://mcp.example.com/v1/mcp?key=${Q_KEY}", "--transport", "http-only"}}}})
	os.WriteFile(filepath.Join(home, ".claude.json"), config, 0o600)
	calls := fakeTools(t, h, home)
	var printed strings.Builder
	run := runner(h, &printed)

	if code, out := run("mcp"); code != 1 || !strings.Contains(out, "Warning: its URL holds Q_KEY") ||
		!strings.Contains(out, "keyward mcp wrap skips it. To start it anyway, with Q_KEY in a command line") {
		t.Errorf("mcp exit %d, want 1 and a warning:\n%s", code, out)
	}
	h.cli.Stdin = strings.NewReader("yes\n")
	if code, out := run("mcp", "wrap"); code != 1 || !strings.Contains(out, "Skipped q: its URL holds Q_KEY") {
		t.Errorf("wrap exit %d, want 1 and the server skipped:\n%s", code, out)
	}
	for _, call := range *calls {
		if !strings.Contains(call, "--help") {
			t.Errorf("ran %q for a skipped server", call)
		}
	}
	h.cli.Stdin = strings.NewReader("yes\n")
	if code, out := run("mcp", "wrap", "--allow-command-line"); code != 0 {
		t.Fatalf("wrap --allow-command-line exit %d:\n%s", code, out)
	}
	if code, out := run("mcp"); code != 0 || !strings.Contains(out, allowedSection+":") {
		t.Errorf("mcp exit %d, want 0 and the server listed as allowed:\n%s", code, out)
	}
	if code, out := run("doctor"); code != 0 || verdict(out) != "✓ No problems found. 1 check needs attention." || !strings.Contains(flat(out), allowedSection+"; see keyward mcp") {
		t.Errorf("doctor exit %d, want 0 and the server listed as allowed:\n%s", code, out)
	}
	if code, out := start(t, h, run, filepath.Join(home, ".claude.json"), "q", "Q_KEY=cap://q-key", "JIRA=cap://jira-token"); code != 0 {
		t.Errorf("the server's keyward run exit %d, want 0:\n%s", code, out)
	}
}

// A server's own mcp-remote, allowed with --allow-command-line, is written as it
// was, with no --transport if it named none, which leaves mcp-remote's default.
// keyward mcp and doctor then list it as allowed, and wrap changes nothing more,
// though a callback port after the URL keeps keyward from reading it as a bridge.
func TestAnAllowedServersOwnMCPRemoteIsListedAsAllowedAndKeepsItsTransport(t *testing.T) {
	for _, port := range [][]string{nil, {"3334"}} {
		h := newHarness(t, "", map[string]string{"q-key": "fake-q-value", "jira-token": "fake-jira-value"}, nil)
		home := homed(t, h)
		h.cli.Interactive, h.cli.Self = true, "/opt/homebrew/bin/keyward"
		os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export Q_KEY='cap://q-key'\nexport JIRA='cap://jira-token'\n"), 0o644)
		args := slices.Concat([]string{"-y", "mcp-remote", "https://mcp.example.com/sse?key=${Q_KEY}"}, port, []string{"--header", "Authorization: Bearer ${JIRA}"})
		config := filepath.Join(home, ".claude.json")
		data, _ := json.Marshal(map[string]any{"mcpServers": map[string]any{"q": map[string]any{"command": "npx", "args": args}}})
		os.WriteFile(config, data, 0o600)
		fakeTools(t, h, home)
		var printed strings.Builder
		run := runner(h, &printed)

		h.cli.Stdin = strings.NewReader("yes\n")
		if code, out := run("mcp", "wrap", "--allow-command-line"); code != 0 {
			t.Fatalf("%v: wrap --allow-command-line exit %d:\n%s", port, code, out)
		}
		applied, _ := os.ReadFile(config)
		if code, out := run("doctor"); code != 0 || verdict(out) != "✓ No problems found. 1 check needs attention." || !strings.Contains(flat(out), allowedSection+"; see keyward mcp") {
			t.Errorf("%v: doctor exit %d, want 0 and the server listed as allowed:\n%s", port, code, out)
		}
		if code, out := run("mcp"); code != 0 || !strings.Contains(out, allowedSection+":") || !strings.Contains(out, "its URL holds Q_KEY") {
			t.Errorf("%v: mcp exit %d, want 0 and the server listed as allowed:\n%s", port, code, out)
		}
		h.cli.Stdin = strings.NewReader("yes\n")
		if code, out := run("mcp", "wrap"); code != 0 || !strings.Contains(out, "No MCP server needs a change.") {
			t.Errorf("%v: wrap exit %d, want 0 and nothing to change:\n%s", port, code, out)
		}
		if data, _ := os.ReadFile(config); string(data) != string(applied) || strings.Contains(string(data), "--transport") {
			t.Errorf("%v: config after wrap: %s", port, data)
		}
		if code, out := start(t, h, run, config, "q", "Q_KEY=cap://q-key", "JIRA=cap://jira-token"); code != 0 {
			t.Errorf("%v: the server's keyward run exit %d, want 0:\n%s", port, code, out)
		}
	}
}

// wrap skips a server only if it would put a migrated secret in a command line,
// as the README says, so the flag's own usage says so too, not any secret.
// Help's one line for the flag says the same of run and wrap.
func TestHelpSaysWhatAllowCommandLineAllows(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	h.cli.Run([]string{"help"})
	h.cli.Run([]string{"mcp", "wrap", "-h"})
	for name, tc := range map[string]struct{ out, want string }{
		"help":        {h.out(), "\n  --allow-command-line   run, mcp wrap: allow a migrated secret in a program's command line\n"},
		"mcp wrap -h": {h.err(), "also wrap a server that would put a migrated secret in a command line, from its URL or as an argument"},
	} {
		if !strings.Contains(tc.out, tc.want) {
			t.Errorf("%s does not say what --allow-command-line allows:\n%s", name, tc.out)
		}
	}
}

// Codex and Cursor users apply by hand the entries keyward mcp prints, so every
// one it prints starts through keyward run. One that keyward run would refuse,
// as its URL or arguments would put a secret in a command line, is not printed,
// until wrap --allow-command-line prints it with the option.
func TestEveryEntryKeywardMCPPrintsStarts(t *testing.T) {
	h := newHarness(t, "", map[string]string{"pagerduty-key": "fake-pagerduty-value", "slack-bot-token": "fake-slack-value", "github-token": "fake-github-value"}, nil)
	home := homed(t, h)
	os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export PD_KEY='cap://pagerduty-key'\nexport SLACK_BOT_TOKEN='cap://slack-bot-token'\nexport GITHUB_TOKEN='cap://github-token'\n"), 0o644)
	os.MkdirAll(filepath.Join(home, ".cursor"), 0o755)
	os.WriteFile(filepath.Join(home, ".cursor", "mcp.json"), []byte(`{"mcpServers": {
    "keyed": {"url": "https://mcp.example.com/mcp?key=${env:PD_KEY}"},
    "other": {"command": "npx", "args": ["-y", "other-mcp", "--token", "${env:SLACK_BOT_TOKEN}"]},
    "gh": {"command": "npx", "args": ["-y", "gh-mcp"], "env": {"GITHUB_TOKEN": "${env:GITHUB_TOKEN}"}},
    "remote": {"url": "https://api.example.com/mcp/", "headers": {"Authorization": "Bearer ${env:GITHUB_TOKEN}"}}}}`), 0o600)
	var printed strings.Builder
	run := runner(h, &printed)
	// starts reports whether the entry for name in out, if printed, starts.
	starts := func(out, name string) (bool, bool) {
		t.Helper()
		start := strings.Index(out, "\n    "+strconv.Quote(name)+": {\n")
		if start < 0 {
			return false, false
		}
		end := strings.Index(out[start:], "\n    }\n")
		var entry map[string]struct {
			Args []string
			Env  map[string]string
		}
		if err := json.Unmarshal([]byte("{"+strings.ReplaceAll(out[start:start+end+6], "\n    ", "\n")+"}"), &entry); err != nil {
			t.Fatalf("%s: %v:\n%s", name, err, out)
		}
		var env []string
		for k, v := range entry[name].Env {
			env = append(env, k+"="+v)
		}
		h.cli.Environ = func() []string { return env }
		code, said := run(entry[name].Args...)
		if code != 0 {
			t.Logf("%s's keyward run exit %d:\n%s", name, code, said)
		}
		return true, code == 0
	}

	_, out := run("mcp")
	for name, want := range map[string]bool{"keyed": false, "other": false, "gh": true, "remote": true} {
		if shown, started := starts(out, name); shown != want || shown && !started {
			t.Errorf("%s: printed %v, want %v, and started %v:\n%s", name, shown, want, started, out)
		}
	}
	_, out = run("mcp", "wrap", "--allow-command-line", "keyed", "other")
	for _, name := range []string{"keyed", "other"} {
		if shown, started := starts(out, name); !shown || !started {
			t.Errorf("%s: with --allow-command-line, printed %v and started %v:\n%s", name, shown, started, out)
		}
	}
	if strings.Contains(printed.String(), "fake-") {
		t.Errorf("printed a value:\n%s", printed.String())
	}
}

// Without a terminal, wrap prints the changes and says to run it again in one.
// That command keeps --allow-command-line, or it would skip the same servers.
func TestMCPWrapWithoutATerminalSaysToRunItAgainWithItsFlag(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	home := homed(t, h)
	os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export PD_KEY='cap://pagerduty-key'\n"), 0o644)
	os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"mcpServers": {"pd": {"command": "uvx", "env": {"PD_KEY": "${PD_KEY}"}},
    "keyed": {"type": "http", "url": "https://mcp.example.com/mcp?key=${PD_KEY}"}}}`), 0o600)
	fakeTools(t, h, home)
	var printed strings.Builder
	run := runner(h, &printed)

	for _, tc := range []struct {
		args  []string
		rerun string
	}{
		{[]string{"mcp", "wrap"}, "run keyward mcp wrap in one)"},
		{[]string{"mcp", "wrap", "--allow-command-line"}, "run keyward mcp wrap --allow-command-line in one)"},
	} {
		if code, out := run(tc.args...); code != 1 || !strings.Contains(out, tc.rerun) {
			t.Errorf("%v exit %d, want 1 and %q:\n%s", tc.args, code, tc.rerun, out)
		}
	}
}

// Wrapping a bridge again puts nothing new in a command line, as the secret in its
// URL is there already, and takes out what else it exposes. So wrap does it
// without --allow-command-line, as it rewrites any earlier keyward's bridge, but
// keyward run still refuses to start it for the URL's secret. keyward mcp and
// wrap say so, and wrap fails, giving it no check mark, until given
// --allow-command-line.
func TestMCPWrapRewrapsABridgeWhoseURLHoldsASecret(t *testing.T) {
	const anyway = "To start it anyway, with PD_KEY in a command line, where any process can read it, run keyward mcp wrap --allow-command-line team."
	for _, script := range []string{
		`exec npx -y mcp-remote "https://mcp.example.com/mcp?key=$PD_KEY" --header "Authorization: Bearer $GITHUB_TOKEN" --transport http-only`,
		`exec npx -y mcp-remote "https://mcp.example.com/mcp?key=$PD_KEY" --header "Authorization: Bearer "'$''{GITHUB_TOKEN}'"" --header "X-Team: fake-literal-header" --transport http-only`,
	} {
		h := newHarness(t, "yes\n", map[string]string{"github-token": "fake-github-value", "pagerduty-key": "fake-pagerduty-value"}, nil)
		home := homed(t, h)
		h.cli.Interactive, h.cli.Self = true, "/opt/homebrew/bin/keyward"
		config := filepath.Join(home, ".claude.json")
		data, _ := json.Marshal(map[string]any{"mcpServers": map[string]any{"team": map[string]any{
			"command": "/opt/homebrew/bin/keyward", "args": []string{"run", "--only", "GITHUB_TOKEN,PD_KEY", "--", "sh", "-c", script},
			"env": map[string]string{"GITHUB_TOKEN": "cap://github-token", "PD_KEY": "cap://pagerduty-key"}}}})
		os.WriteFile(config, data, 0o600)
		fakeTools(t, h, home)
		var printed strings.Builder
		run := runner(h, &printed)

		if code, out := run("mcp"); code != 1 || !strings.Contains(out, "keyward run would still refuse to start it once changed, as it would put PD_KEY in a command line. "+anyway) ||
			strings.Contains(out, "like this") {
			t.Errorf("mcp exit %d, want 1 and that the change leaves it refused:\n%s", code, out)
		}
		if code, out := run("mcp", "wrap"); code != 1 || !strings.Contains(out, "Warning: keyward run would still refuse to start it once changed") ||
			!strings.Contains(out, "team changed, but keyward run still refuses to start it. "+anyway) ||
			strings.Contains(out, "✓") || strings.Contains(out, "Restart Claude Code") || strings.Contains(out, "Skipped") {
			t.Errorf("wrap exit %d, want 1 and the server changed but not started:\n%s", code, out)
		}
		if data, _ := os.ReadFile(config); !strings.Contains(string(data), `'$''{GITHUB_TOKEN}'`) {
			t.Errorf("config after wrap: %s", data)
		}
		// What is left exposed is the URL's secret alone.
		if code, out := run("mcp"); code != 1 || !strings.Contains(out, "keyward run refuses to start it (") || strings.Count(out, " would get ") != 1 ||
			!strings.Contains(out, "npx would get PD_KEY in its command line (line 1)") {
			t.Errorf("mcp after wrap exit %d:\n%s", code, out)
		}
		if code, out := start(t, h, run, config, "team"); code != 2 || !strings.Contains(out, "would get PD_KEY in its command line") {
			t.Errorf("the server's keyward run exit %d, want 2 and PD_KEY refused:\n%s", code, out)
		}
		h.cli.Stdin = strings.NewReader("yes\n")
		if code, out := run("mcp", "wrap", "--allow-command-line"); code != 0 || !strings.Contains(out, "✓ team") {
			t.Errorf("wrap --allow-command-line exit %d:\n%s", code, out)
		}
		if code, out := start(t, h, run, config, "team"); code != 0 {
			t.Errorf("the allowed server's keyward run exit %d, want 0:\n%s", code, out)
		}
		if strings.Contains(printed.String(), "fake-literal") {
			t.Errorf("printed a literal:\n%s", printed.String())
		}
	}
}

// wrap skips such a bridge until a credential in its header is moved out, as
// claude mcp add-json would get it in its command line. It says only that, as
// --allow-command-line would not change it.
func TestMCPWrapSkipsARefusedBridgeForItsCredentialAlone(t *testing.T) {
	const headerKey = "FakeOpaqueTeamHeader0000"
	h := newHarness(t, "yes\n", map[string]string{"pagerduty-key": "fake-pagerduty-value"}, nil)
	home := homed(t, h)
	h.cli.Interactive, h.cli.Self = true, "/opt/homebrew/bin/keyward"
	data, _ := json.Marshal(map[string]any{"mcpServers": map[string]any{"team": map[string]any{"command": "keyward",
		"args": []string{"run", "--only", "PD_KEY", "--", "sh", "-c", `exec npx -y mcp-remote "https://mcp.example.com/mcp?key=$PD_KEY" --header "X-Api-Key: ` + headerKey + `" --transport http-only`},
		"env":  map[string]string{"PD_KEY": "cap://pagerduty-key"}}}})
	os.WriteFile(filepath.Join(home, ".claude.json"), data, 0o600)
	fakeTools(t, h, home)
	var printed strings.Builder
	run := runner(h, &printed)

	if code, out := run("mcp", "wrap"); code != 1 || !strings.Contains(out, "Skipped team: its env.KW_HDR_1 (from its X-Api-Key header) holds a credential") ||
		strings.Contains(out, "start it anyway") {
		t.Errorf("wrap exit %d, want 1 and the server skipped for its credential alone:\n%s", code, out)
	}
	if strings.Contains(printed.String(), headerKey) {
		t.Errorf("printed the header's text:\n%s", printed.String())
	}
}

// Wrapping a stdio mcp-remote keeps the transport it names, and leaves the
// header's variable to mcp-remote, out of its command line. One an earlier keyward
// wrapped has sh expand it there: keyward mcp and doctor report that, as they do
// for keyward's own transport, and wrap writes it again the same way.
func TestMCPReportsABridgeWithAnotherTransportThatExposesASecret(t *testing.T) {
	h := newHarness(t, "yes\n", map[string]string{"atlassian-token": "v"}, nil)
	home := homed(t, h)
	h.cli.Interactive = true
	os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export ATLASSIAN_TOKEN='cap://atlassian-token'\n"), 0o644)
	config := filepath.Join(home, ".claude.json")
	os.WriteFile(config, []byte(`{"mcpServers": {"atlassian": {"command": "npx",
    "args": ["-y", "mcp-remote", "https://mcp.example.com/v1/sse", "--transport", "sse-only", "--header", "Authorization: Bearer ${ATLASSIAN_TOKEN}"]}}}`), 0o600)
	fakeTools(t, h, home)
	var printed strings.Builder
	run := runner(h, &printed)
	wrapped := func(when string) {
		t.Helper()
		if data, _ := os.ReadFile(config); !strings.Contains(string(data), `'$''{ATLASSIAN_TOKEN}'`) || !strings.Contains(string(data), "--transport sse-only") {
			t.Errorf("config %s: %s", when, data)
		}
		if code, out := run("mcp"); code != 0 || !strings.Contains(out, "No MCP server needs a change.") {
			t.Errorf("mcp %s exit %d, want 0:\n%s", when, code, out)
		}
	}

	if code, out := run("mcp", "wrap"); code != 0 {
		t.Fatalf("wrap exit %d:\n%s", code, out)
	}
	wrapped("after wrap")
	earlier, _ := json.Marshal(map[string]any{"mcpServers": map[string]any{"atlassian": map[string]any{"command": "keyward",
		"args": []string{"run", "--only", "ATLASSIAN_TOKEN", "--", "sh", "-c", `exec npx -y mcp-remote https://mcp.example.com/v1/sse --transport sse-only --header "Authorization: Bearer $ATLASSIAN_TOKEN"`},
		"env":  map[string]string{"ATLASSIAN_TOKEN": "cap://atlassian-token"}}}})
	os.WriteFile(config, earlier, 0o600)
	if code, out := run("mcp"); code != 1 || !strings.Contains(out, "keyward run refuses to start it") || !strings.Contains(out, "npx would get ATLASSIAN_TOKEN in its command line") {
		t.Errorf("mcp exit %d, want 1 and the exposure:\n%s", code, out)
	}
	if code, out := run("doctor"); code != 1 || !strings.Contains(flat(out), refusedProblem) {
		t.Errorf("doctor exit %d, want 1 and the exposure:\n%s", code, out)
	}
	h.cli.Stdin = strings.NewReader("yes\n")
	if code, out := run("mcp", "wrap"); code != 0 {
		t.Fatalf("wrap again exit %d:\n%s", code, out)
	}
	wrapped("after wrapping again")
}

// mcp-remote's http-only never falls back to SSE, so wrap bridges a server whose
// type is sse with sse-only, which unwrap and uninstall keep, as they keep the
// bridge.
func TestMCPWrapBridgesAnSSEServerOverSSE(t *testing.T) {
	r := uninstallFixture(t, "")
	h := r.h
	home := homed(t, h)
	h.store.Seed(map[string]string{"linear-api-key": "fake-linear-value"})
	h.cli.Interactive = true
	os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export LINEAR_API_KEY='cap://linear-api-key'\n"), 0o644)
	config := filepath.Join(home, ".claude.json")
	os.WriteFile(config, []byte(`{"mcpServers": {"linear": {"type": "sse", "url": "https://mcp.example.com/sse", "headers": {"Authorization": "Bearer ${LINEAR_API_KEY}"}}}}`), 0o600)
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
	overSSE := func(when string) {
		t.Helper()
		if data, _ := os.ReadFile(config); !strings.Contains(string(data), "exec npx -y mcp-remote https://mcp.example.com/sse ") ||
			!strings.Contains(string(data), " --transport sse-only") || strings.Contains(string(data), "http-only") {
			t.Errorf("config after %s: %s", when, data)
		}
	}

	yes("mcp", "wrap")
	overSSE("wrap")
	if code, out := run("mcp"); code != 0 || !strings.Contains(out, "No MCP server needs a change.") {
		t.Errorf("mcp exit %d, want 0:\n%s", code, out)
	}
	yes("mcp", "unwrap")
	overSSE("unwrap")
	yes("mcp", "wrap")
	yes("uninstall")
	overSSE("uninstall")
}

// A server whose own script starts keyward run is checked as keyward run checks
// it, so one keyward run refuses does not stop starting unreported: keyward mcp
// and doctor report it, with what keyward run says, and wrap leaves it to the
// user, as it does not rewrite such a script. One keyward run starts is left
// alone, not wrapped again.
func TestMCPReportsAKeywardRunInAServersOwnScript(t *testing.T) {
	h := newHarness(t, "", map[string]string{"jira-token": "fake-jira-value"}, nil)
	home := homed(t, h)
	h.cli.Interactive = true
	os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export JIRA='cap://jira-token'\n"), 0o644)
	config := filepath.Join(home, ".claude.json")
	write := func(script string) {
		data, _ := json.Marshal(map[string]any{"mcpServers": map[string]any{"jira": map[string]any{"command": "/bin/zsh", "args": []string{"-lc", script}}}})
		os.WriteFile(config, data, 0o600)
	}
	write(`keyward run --only JIRA -- sh -c 'exec npx -y mcp-remote https://mcp.example.com/mcp --header "Authorization: Bearer $JIRA"'`)
	calls := fakeTools(t, h, home)
	var printed strings.Builder
	run := runner(h, &printed)
	const (
		why    = "npx would get JIRA in its command line (line 1), where other programs and security logs can read it."
		byHand = "Its own script starts keyward run, which keyward mcp wrap does not change, so change the script as keyward run says, " +
			"or, to start it anyway, with JIRA in a command line, where any process can read it, give that keyward run --allow-command-line."
	)

	if code, out := run("mcp"); code != 1 || !strings.Contains(out, refusedProblem) || !strings.Contains(out, "keyward run refuses to start it (") ||
		!strings.Contains(out, why) || !strings.Contains(out, byHand) || strings.Contains(out, "mcp wrap --allow-command-line") {
		t.Errorf("mcp exit %d, want 1 and the server reported:\n%s", code, out)
	}
	if code, out := run("doctor"); code != 1 || verdict(out) != "✗ Problems found: "+refusedProblem+"." {
		t.Errorf("doctor exit %d, want 1 and the server reported:\n%s", code, out)
	}
	h.cli.Stdin = strings.NewReader("yes\n")
	if code, out := run("mcp", "wrap"); code != 1 || !strings.Contains(out, "Skipped jira: keyward run refuses to start it.\n  "+why) || !strings.HasSuffix(out, "\n  "+byHand+"\n") {
		t.Errorf("wrap exit %d, want 1 and the server left to the user:\n%s", code, out)
	}
	for _, call := range *calls {
		if !strings.Contains(call, "--help") {
			t.Errorf("ran %q for a server it leaves to the user", call)
		}
	}
	write(`keyward run --only JIRA -- sh -c 'JIRA_TOKEN="$JIRA" exec jira-mcp'`)
	if code, out := run("mcp"); code != 0 || !strings.Contains(out, "No MCP server needs a change.") {
		t.Errorf("mcp exit %d, want 0 for a server keyward run starts:\n%s", code, out)
	}
}

// A server whose script keyward cannot rewrite safely is reported, with a note to
// change it by hand and no change to apply: wrap skips it, and an earlier
// --allow-command-line for it does not list it as allowed.
func TestMCPLeavesAScriptItCannotRewriteToTheUser(t *testing.T) {
	h := newHarness(t, "yes\n", map[string]string{"github-token": "v"}, nil)
	home := homed(t, h)
	h.cli.Interactive = true
	os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export GITHUB_TOKEN='cap://github-token'\n"), 0o644)
	config := filepath.Join(home, ".claude.json")
	os.WriteFile(config, []byte(`{"mcpServers": {"tool": {"command": "sh", "args": ["-c", "exec some-mcp --token \"$(cat /dev/null)${GITHUB_TOKEN}\""]}}}`), 0o600)
	h.cli.Ledger.Add(ledger.Record{Kind: ledger.Allowed, Path: config, Name: "tool"})
	calls := fakeTools(t, h, home)
	var printed strings.Builder
	run := runner(h, &printed)
	const note = "keyward cannot rewrite its script safely, so change it by hand"

	if code, out := run("mcp"); code != 1 || !strings.Contains(out, "uses GITHUB_TOKEN") || !strings.Contains(out, note) ||
		strings.Contains(out, "--allow-command-line") || strings.Contains(out, "like this") || strings.Contains(out, allowedSection) {
		t.Errorf("mcp exit %d, want 1 and the note:\n%s", code, out)
	}
	if code, out := run("mcp", "wrap"); code != 1 || !strings.Contains(out, "Skipped tool: "+note) {
		t.Errorf("wrap exit %d, want 1 and the server skipped:\n%s", code, out)
	}
	for _, call := range *calls {
		if !strings.Contains(call, "--help") {
			t.Errorf("ran %q for a server it cannot rewrite", call)
		}
	}
	if code, out := run("doctor"); code != 1 || verdict(out) != "✗ Problems found: 1 MCP server(s) would receive cap:// references instead of values." {
		t.Errorf("doctor exit %d, want 1 and the server reported:\n%s", code, out)
	}
}

// The section keyward mcp and doctor list a server under once the user has
// allowed it to put a secret in a command line.
const allowedSection = "1 MCP server(s) put a secret in a command line, as allowed with --allow-command-line"

// The problem keyward mcp and doctor report for a server that keyward run
// refuses to start.
const refusedProblem = "1 MCP server(s) would put a secret in a command line, so keyward run refuses to start them"

// A bridge whose only exposure is the secret in its URL would be wrapped again
// unchanged, and keyward run refuses to start it. keyward mcp reports it, with no
// replacement to apply, and wrap leaves it alone and fails, until
// --allow-command-line records that the user accepts it and gives its keyward
// run the option. keyward mcp and doctor then list it as a warning, and wrap
// passes over it.
func TestMCPLeavesABridgeThatExposesOnlyItsURL(t *testing.T) {
	h := newHarness(t, "yes\nyes\n", map[string]string{"pagerduty-key": "v"}, nil)
	home := homed(t, h)
	h.cli.Interactive = true
	config, _ := json.Marshal(map[string]any{"mcpServers": map[string]any{"team": map[string]any{
		"command": "keyward", "args": []string{"run", "--only", "PD_KEY", "--", "sh", "-c", `exec npx -y mcp-remote "https://mcp.example.com/mcp?key=$PD_KEY" --transport http-only`},
		"env": map[string]string{"PD_KEY": "cap://pagerduty-key"}}}})
	os.WriteFile(filepath.Join(home, ".claude.json"), config, 0o600)
	calls := fakeTools(t, h, home)
	var printed strings.Builder
	run := runner(h, &printed)

	if code, out := run("mcp"); code != 1 || !strings.Contains(out, "keyward run refuses to start it") || !strings.Contains(out, "npx would get PD_KEY in its command line") || !strings.Contains(out, "already runs through keyward") ||
		!strings.Contains(out, "To start it anyway, with PD_KEY in a command line, where any process can read it, run keyward mcp wrap --allow-command-line team.") ||
		strings.Contains(out, "like this") || strings.Contains(out, "makes these changes") {
		t.Errorf("mcp exit %d:\n%s", code, out)
	}
	if code, out := run("mcp", "wrap"); code != 1 || !strings.Contains(out, "Skipped team: it already runs through keyward") ||
		!strings.Contains(out, "\n  To start it anyway, with PD_KEY in a command line, where any process can read it, run keyward mcp wrap --allow-command-line team.") {
		t.Errorf("wrap exit %d:\n%s", code, out)
	}
	if code, out := run("doctor"); code != 1 || !strings.Contains(flat(out), refusedProblem) {
		t.Errorf("doctor exit %d, want 1 and the server reported:\n%s", code, out)
	}
	for _, call := range *calls {
		if !strings.Contains(call, "--help") {
			t.Errorf("ran %q for a server it skips", call)
		}
	}
	if code, out := run("mcp", "wrap", "--allow-command-line"); code != 0 || !strings.Contains(out, `"run","--allow-command-line","--only","PD_KEY"`) || !strings.Contains(out, "✓ team") {
		t.Errorf("wrap --allow-command-line exit %d:\n%s", code, out)
	}
	applied := len(*calls)
	if code, out := run("mcp"); code != 0 || !strings.Contains(out, allowedSection+":") || !strings.Contains(out, "its URL holds PD_KEY") {
		t.Errorf("mcp exit %d, want 0 and the server listed:\n%s", code, out)
	}
	if code, out := run("mcp", "wrap"); code != 0 || !strings.Contains(out, "No MCP server needs a change.") {
		t.Errorf("wrap exit %d, want 0:\n%s", code, out)
	}
	if code, out := run("doctor"); code != 0 || verdict(out) != "✓ No problems found. 1 check needs attention." || !strings.Contains(flat(out), allowedSection+"; see keyward mcp") {
		t.Errorf("doctor exit %d, want 0 and the server listed:\n%s", code, out)
	}
	for _, call := range (*calls)[applied:] {
		if !strings.Contains(call, "--help") {
			t.Errorf("ran %q for a server that would not change", call)
		}
	}
	if code, out := start(t, h, run, filepath.Join(home, ".claude.json"), "team"); code != 0 || h.exec.calls != 1 {
		t.Errorf("the server's keyward run exit %d, want 0 and the server started:\n%s", code, out)
	}
}

// start runs the server name in config through its keyward run, as Claude Code
// starts it, with the server's env added to client's, and returns how it ended:
// 0 once the server starts, 2 if keyward run refuses it.
func start(t *testing.T, h *harness, run func(...string) (int, string), config, name string, client ...string) (int, string) {
	t.Helper()
	s := server(t, config, name)
	env := slices.Clone(client)
	for k, v := range s.Env {
		env = append(env, k+"="+v)
	}
	h.cli.Environ = func() []string { return env }
	return run(s.Args...)
}

// server reads the definition of the server name in a Claude Code config.
func server(t *testing.T, config, name string) (s struct {
	Command string
	Args    []string
	Env     map[string]string
}) {
	t.Helper()
	var doc struct {
		MCPServers map[string]json.RawMessage `json:"mcpServers"`
	}
	data, err := os.ReadFile(config)
	if err == nil {
		err = json.Unmarshal(data, &doc)
	}
	if err == nil {
		err = json.Unmarshal(doc.MCPServers[name], &s)
	}
	if err != nil {
		t.Fatalf("reading %s from %s: %v", name, config, err)
	}
	return s
}

// A bridge allowed in its project's folder is listed as allowed wherever keyward
// mcp and doctor run, not as one that still needs a change there.
func TestAnAllowedBridgeInAnotherProjectIsListedAsAllowed(t *testing.T) {
	h := newHarness(t, "yes\n", map[string]string{"pagerduty-key": "v"}, nil)
	home := homed(t, h)
	h.cli.Interactive = true
	other := filepath.Join(home, "other-project")
	os.Mkdir(other, 0o755)
	config, _ := json.Marshal(map[string]any{"projects": map[string]any{other: map[string]any{"mcpServers": map[string]any{"team": map[string]any{
		"command": "keyward", "args": []string{"run", "--only", "PD_KEY", "--", "sh", "-c", `exec npx -y mcp-remote "https://mcp.example.com/mcp?key=$PD_KEY" --transport http-only`},
		"env": map[string]string{"PD_KEY": "cap://pagerduty-key"}}}}}})
	os.WriteFile(filepath.Join(home, ".claude.json"), config, 0o600)
	fakeTools(t, h, home)
	var printed strings.Builder
	run := runner(h, &printed)

	h.cli.Workdir = other
	if code, out := run("mcp", "wrap", "--allow-command-line"); code != 0 || !strings.Contains(out, "✓ team") {
		t.Fatalf("wrap --allow-command-line in the project's folder exit %d:\n%s", code, out)
	}
	h.cli.Workdir = home
	if code, out := run("mcp"); code != 0 || !strings.Contains(out, allowedSection+":") || strings.Contains(out, "other Claude Code projects") {
		t.Errorf("mcp exit %d, want 0 and the server listed as allowed:\n%s", code, out)
	}
	if code, out := run("doctor"); code != 0 || !strings.Contains(flat(out), allowedSection+"; see keyward mcp") {
		t.Errorf("doctor exit %d, want 0 and the server listed as allowed:\n%s", code, out)
	}
}

// Cursor keeps a project's servers in its folder's .cursor/mcp.json, and lists
// the folders nowhere keyward reads. So keyward mcp and doctor read it in each
// folder they know of, wherever they run: those of Claude Code's projects, and
// those the ledger names, as where the user allowed a Cursor server. They say
// that a project elsewhere is not read.
func TestMCPAndDoctorReadTheCursorServersOfEveryKnownFolder(t *testing.T) {
	h := newHarness(t, "", map[string]string{"slack-bot-token": "fake-slack-value", "pagerduty-key": "fake-pagerduty-value"}, nil)
	home := homed(t, h)
	project, allowed := filepath.Join(home, "dev", "project"), filepath.Join(home, "dev", "allowed")
	os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"projects": {"`+project+`": {}}}`), 0o600)
	// Cursor makes this folder when installed.
	os.Mkdir(filepath.Join(home, ".cursor"), 0o755)
	cursor := func(dir, name, script, env, ref string) string {
		config := filepath.Join(dir, ".cursor", "mcp.json")
		os.MkdirAll(filepath.Dir(config), 0o755)
		data, _ := json.Marshal(map[string]any{"mcpServers": map[string]any{name: map[string]any{"command": "keyward",
			"args": []string{"run", "--only", env, "--", "sh", "-c", script}, "env": map[string]string{env: ref}}}})
		os.WriteFile(config, data, 0o600)
		return config
	}
	cursor(project, "slack", `exec npx -y slack-mcp --token "$SLACK_BOT_TOKEN"`, "SLACK_BOT_TOKEN", "cap://slack-bot-token")
	config := cursor(allowed, "team", `exec npx -y mcp-remote "https://mcp.example.com/mcp?key=$PD_KEY" --transport http-only`, "PD_KEY", "cap://pagerduty-key")
	h.cli.Ledger.Add(ledger.Record{Kind: ledger.Allowed, Path: config, Name: "team", Text: "PD_KEY"})
	var printed strings.Builder
	run := runner(h, &printed)
	const unread = "keyward reads a Cursor project's .cursor/mcp.json only in this folder and in those of Claude Code's projects, so run keyward mcp in any other folder you open in Cursor."

	if code, out := run("mcp"); code != 1 || !strings.HasPrefix(out, "2 MCP server(s) would put a secret in a command line") ||
		!strings.Contains(out, "(Cursor, ~/dev/project/.cursor/mcp.json)") || !strings.Contains(out, "(Cursor, ~/dev/allowed/.cursor/mcp.json)") || !strings.HasSuffix(out, "\n"+unread+"\n") {
		t.Errorf("mcp exit %d, want 1 and both servers:\n%s", code, out)
	}
	if code, out := run("doctor"); code != 1 || verdict(out) != "✗ Problems found: 2 MCP server(s) would put a secret in a command line, so keyward run refuses to start them." ||
		!strings.Contains(flat(out), "Note: "+unread) {
		t.Errorf("doctor exit %d, want 1 and both servers:\n%s", code, out)
	}
	os.RemoveAll(filepath.Join(home, ".cursor"))
	os.RemoveAll(filepath.Join(project, ".cursor"))
	os.RemoveAll(filepath.Join(allowed, ".cursor"))
	if _, out := run("mcp"); strings.Contains(out, "Cursor") {
		t.Errorf("mcp speaks of Cursor to one who does not use it:\n%s", out)
	}
}

// Copilot CLI keeps its servers in ~/.copilot and a project's in its folder's
// .github/mcp.json, read as Cursor's are, in each folder keyward knows of. wrap
// prints the changes, saying why, and keyward mcp says which projects it reads.
func TestMCPReadsCopilotsServersInEveryKnownFolder(t *testing.T) {
	h := newHarness(t, "", map[string]string{"pagerduty-key": "fake-pagerduty-value"}, nil)
	home := homed(t, h)
	project, allowed := filepath.Join(home, "dev", "project"), filepath.Join(home, "dev", "allowed")
	os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"projects": {"`+project+`": {}}}`), 0o600)
	os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export PD_KEY='cap://pagerduty-key'\n"), 0o644)
	server := `{"mcpServers": {"pd": {"command": "pd-mcp", "env": {"PD_KEY": "${PD_KEY}"}}}}`
	for _, config := range []string{filepath.Join(home, ".copilot", "mcp-config.json"), filepath.Join(project, ".github", "mcp.json"), filepath.Join(allowed, ".github", "mcp.json")} {
		os.MkdirAll(filepath.Dir(config), 0o755)
		os.WriteFile(config, []byte(server), 0o600)
	}
	h.cli.Ledger.Add(ledger.Record{Kind: ledger.Allowed, Path: filepath.Join(allowed, ".github", "mcp.json"), Name: "pd", Text: "PD_KEY"})
	fakeTools(t, h, home)
	var printed strings.Builder
	run := runner(h, &printed)
	const unread = "keyward reads a Copilot CLI project's .github/mcp.json only in this folder and in those of Claude Code's projects, so run keyward mcp in any other folder you open in Copilot CLI."

	code, out := run("mcp")
	for _, want := range []string{"(Copilot CLI, ~/.copilot/mcp-config.json)", "(Copilot CLI, ~/dev/project/.github/mcp.json)", "(Copilot CLI, ~/dev/allowed/.github/mcp.json)", "\n" + unread + "\n"} {
		if code != 1 || !strings.Contains(out, want) {
			t.Errorf("mcp exit %d, want 1 and %q:\n%s", code, want, out)
		}
	}
	if code, out := run("mcp", "wrap"); code != 1 || !strings.Contains(out, "Change these yourself (Copilot CLI's mcp command takes env values as arguments, where any process can read them):") {
		t.Errorf("wrap exit %d, want 1 and why it prints the changes:\n%s", code, out)
	}
}

// With Cursor and Copilot CLI both installed, one note names the project files of
// each that keyward reads.
func TestTheProjectsNoteNamesCursorsAndCopilotsFilesTogether(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	home := homed(t, h)
	os.Mkdir(filepath.Join(home, ".cursor"), 0o755)
	os.Mkdir(filepath.Join(home, ".copilot"), 0o755)
	var printed strings.Builder
	const note = "keyward reads a Cursor project's .cursor/mcp.json and a Copilot CLI project's .github/mcp.json only in this folder and in those of " +
		"Claude Code's projects, so run keyward mcp in any other folder you open in either."
	if code, out := runner(h, &printed)("mcp"); code != 0 || !strings.HasSuffix(out, "\n"+note+"\n") {
		t.Errorf("mcp exit %d, want 0 and %q:\n%s", code, note, out)
	}
}

// Claude Code's CLI cannot run in the folder of a project that no longer exists,
// as a removed worktree's, and Claude Code would not start its servers. So doctor,
// keyward mcp and wrap pass over such a project, saying so once.
func TestMCPAndDoctorSkipAProjectWhoseFolderIsGone(t *testing.T) {
	h := newHarness(t, "", map[string]string{"github-token": "v"}, nil)
	home := homed(t, h)
	os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export GITHUB_TOKEN='cap://github-token'\n"), 0o644)
	server := map[string]any{"gh": map[string]any{"command": "gh-mcp", "env": map[string]string{"GITHUB_TOKEN": "${GITHUB_TOKEN}"}}}
	config, _ := json.Marshal(map[string]any{"projects": map[string]any{
		filepath.Join(home, "removed-worktree"): map[string]any{"mcpServers": server},
		filepath.Join(home, "old-clone"):        map[string]any{"mcpServers": server},
	}})
	os.WriteFile(filepath.Join(home, ".claude.json"), config, 0o600)
	calls := fakeTools(t, h, home)
	var printed strings.Builder
	run := runner(h, &printed)
	const skipped = "Skipped Claude Code projects whose folders no longer exist: ~/old-clone, ~/removed-worktree. " +
		"Their MCP servers can be removed from ~/.claude.json by hand, with Claude Code closed.\n"

	for _, args := range [][]string{{"mcp"}, {"mcp", "wrap"}} {
		if code, out := run(args...); code != 0 || !strings.Contains(out, skipped+"No MCP server needs a change.\n") || strings.Contains(out, "run keyward mcp wrap in") {
			t.Errorf("%v exit %d, want 0 and the projects skipped:\n%s", args, code, out)
		}
	}
	if code, out := run("doctor"); code != 0 || verdict(out) != "✓ No problems found." || strings.Count(flat(out), "Note: "+flat(skipped)) != 1 {
		t.Errorf("doctor exit %d, want 0 and the projects skipped:\n%s", code, out)
	}
	for _, call := range *calls {
		if !strings.Contains(call, "--help") {
			t.Errorf("ran %q for a project whose folder is gone", call)
		}
	}
}

// wrap --allow-command-line records that the user accepts a migrated secret in a
// server's URL, which the bridge puts in mcp-remote's command line. keyward mcp
// and doctor then list the server as a warning, not a problem, so a later wrap of
// another server succeeds. Unwrapped, it is no longer allowed.
func TestAServerWrappedWithAllowCommandLineIsListedAsAWarning(t *testing.T) {
	h := newHarness(t, "yes\n", map[string]string{"smithery-api-key": "v", "pagerduty-key": "v"}, nil)
	home := homed(t, h)
	h.cli.Interactive = true
	rc := filepath.Join(home, ".zshrc")
	os.WriteFile(rc, []byte("export SMITHERY_API_KEY='cap://smithery-api-key'\n"), 0o644)
	config := filepath.Join(home, ".claude.json")
	os.WriteFile(config, []byte(`{"mcpServers": {"exa": {"type": "http", "url": "https://server.smithery.ai/exa/mcp?api_key=${SMITHERY_API_KEY}"}}}`), 0o600)
	fakeTools(t, h, home)
	var printed strings.Builder
	run := runner(h, &printed)

	if code, out := run("mcp", "wrap", "--allow-command-line"); code != 0 || !strings.Contains(out, "✓ exa") {
		t.Fatalf("wrap --allow-command-line exit %d:\n%s", code, out)
	}
	if code, out := run("mcp"); code != 0 || !strings.Contains(out, allowedSection+":") || !strings.Contains(out, "its URL holds SMITHERY_API_KEY") {
		t.Errorf("mcp exit %d, want 0 and the server listed:\n%s", code, out)
	}
	if code, out := run("doctor"); code != 0 || verdict(out) != "✓ No problems found. 2 checks need attention." || !strings.Contains(flat(out), allowedSection+"; see keyward mcp") {
		t.Errorf("doctor exit %d, want 0 and the server listed:\n%s", code, out)
	}
	if code, out := start(t, h, run, config, "exa"); code != 0 {
		t.Errorf("the server's keyward run exit %d, want 0:\n%s", code, out)
	}
	os.WriteFile(rc, []byte("export SMITHERY_API_KEY='cap://smithery-api-key'\nexport PD_KEY='cap://pagerduty-key'\n"), 0o644)
	var doc map[string]map[string]any
	data, _ := os.ReadFile(config)
	json.Unmarshal(data, &doc)
	doc["mcpServers"]["pd"] = map[string]any{"command": "uvx", "args": []string{"pd-mcp"}, "env": map[string]string{"PD_KEY": "${PD_KEY}"}}
	data, _ = json.Marshal(doc)
	os.WriteFile(config, data, 0o600)
	h.cli.Stdin = strings.NewReader("yes\n")
	if code, out := run("mcp", "wrap"); code != 0 || !strings.Contains(out, "✓ pd") || strings.Contains(out, "exa") {
		t.Errorf("wrap exit %d, want 0 and only pd changed:\n%s", code, out)
	}
	h.cli.Stdin = strings.NewReader("yes\n")
	if code, out := run("mcp", "unwrap", "exa"); code != 0 {
		t.Fatalf("unwrap exit %d:\n%s", code, out)
	}
	records, _ := h.cli.Ledger.Records()
	for _, r := range records {
		if r.Kind == ledger.Allowed {
			t.Errorf("unwrapped, exa is still allowed: %+v", r)
		}
	}
}

// A query string or user info may hold a secret written out, and a segment of a
// URL's path may be a credential, which wrapping puts in mcp-remote's command line
// too: keyward mcp and wrap warn of it, and wrap does not skip the server.
func TestMCPWrapWarnsOfWhatMayBeASecretInAURL(t *testing.T) {
	const warning = "Warning: its URL may hold a secret in plaintext, and mcp-remote puts the URL in its command line"
	for _, url := range []string{"https://mcp.example.com/mcp?tenant=fake-tenant", "https://mcp.example.com/ghp_FakeUrlPathToken00000000000000000000/mcp"} {
		h := newHarness(t, "yes\n", nil, nil)
		home := homed(t, h)
		h.cli.Interactive = true
		os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export GITHUB_TOKEN='cap://github-token'\n"), 0o644)
		config, _ := json.Marshal(map[string]any{"mcpServers": map[string]any{"tenant": map[string]any{"type": "http", "url": url,
			"headers": map[string]string{"Authorization": "Bearer ${GITHUB_TOKEN}"}}}})
		os.WriteFile(filepath.Join(home, ".claude.json"), config, 0o600)
		fakeTools(t, h, home)
		if code := h.cli.Run([]string{"mcp"}); code != 1 || !strings.Contains(h.out(), warning) {
			t.Errorf("%s: mcp exit %d, want 1 and a warning:\n%s", url, code, h.out())
		}
		h.stdout.Reset()
		if code := h.cli.Run([]string{"mcp", "wrap"}); code != 0 || !strings.Contains(h.out(), warning) {
			t.Errorf("%s: wrap exit %d, want 0 and a warning:\n%s\n%s", url, code, h.out(), h.err())
		}
	}
}

// doctor reports a token in a server's URL or arguments and points at keyward mcp,
// so keyward mcp, wrap and unwrap print it only as its length. wrap and unwrap
// keep it in the definitions they apply.
func TestMCPNeverPrintsASecretFromAURLOrArgument(t *testing.T) {
	const (
		urlPassword = "FakeUrlPassw0rd"
		urlToken    = "ghp_FakeUrlQueryToken0000000000000000000"
		pathToken   = "ghp_FakeUrlPathToken00000000000000000000"
	)
	h := newHarness(t, "yes\nyes\n", nil, nil)
	home := homed(t, h)
	h.cli.Interactive, h.cli.Self = true, "/opt/homebrew/bin/keyward"
	os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export GITHUB_TOKEN='cap://github-token'\n"), 0o644)
	os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"mcpServers": {
    "tenant": {"type": "http", "url": "https://bot:`+urlPassword+`@mcp.example.com/mcp?api_key=`+urlToken+`", "headers": {"Authorization": "Bearer ${GITHUB_TOKEN}"}},
    "path": {"type": "http", "url": "https://mcp.example.com/`+pathToken+`/mcp", "headers": {"Authorization": "Bearer ${GITHUB_TOKEN}"}},
    "tool": {"command": "uvx", "args": ["tool-mcp", "--token", "`+mcpToken+`", "--home", "${HOME}"], "env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}"}}}}`), 0o600)
	fakeTools(t, h, home)
	var printed strings.Builder
	run := runner(h, &printed)

	if code, out := run("doctor"); code != 1 || !strings.Contains(out, "Claude Code server path, url") || !strings.Contains(out, "Claude Code server tenant, url") {
		t.Errorf("doctor exit %d, want 1 and both URLs reported:\n%s", code, out)
	}
	if code, out := run("mcp"); code != 1 || !strings.Contains(out, "bytes hidden") {
		t.Errorf("mcp exit %d, want 1 and hidden values:\n%s", code, out)
	}
	for _, args := range [][]string{{"mcp", "wrap"}, {"mcp", "unwrap"}} {
		if code, out := run(args...); code != 0 {
			t.Fatalf("%v exit %d:\n%s", args, code, out)
		}
		data, _ := os.ReadFile(filepath.Join(home, ".claude.json"))
		for _, value := range []string{urlPassword, urlToken, pathToken, mcpToken} {
			if !strings.Contains(string(data), value) {
				t.Errorf("%v lost %q: %s", args, value, data)
			}
		}
	}
	for _, value := range []string{urlPassword, urlToken, pathToken, mcpToken} {
		if strings.Contains(printed.String(), value) {
			t.Errorf("printed %q:\n%s", value, printed.String())
		}
	}
}

// A bridge from an earlier keyward holds its headers' text in its script, where
// doctor finds it by the header's name and points at keyward mcp. Nothing prints
// it: not uninstall's plan, nor unwrap, shown or made through Claude Code, nor
// keyward mcp once the bridge is unwrapped.
func TestMCPNeverPrintsTheHeaderTextInAnEarlierBridge(t *testing.T) {
	const (
		opaque = "FakeOpaqueHeaderValue0000"
		hexKey = "0123456789abcdef0123456789abcdef01234567"
	)
	r := uninstallFixture(t, "")
	h := r.h
	home := homed(t, h)
	h.store.Seed(map[string]string{"github-token": "v"})
	h.cli.Interactive = true
	os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export GITHUB_TOKEN='cap://github-token'\n"), 0o644)
	config, _ := json.Marshal(map[string]any{"mcpServers": map[string]any{"team": map[string]any{
		"command": "/opt/homebrew/bin/keyward", "args": []string{"run", "--only", "GITHUB_TOKEN", "--", "sh", "-c",
			`exec npx -y mcp-remote https://api.example.com/mcp/ --header "Authorization: Bearer "'$''{GITHUB_TOKEN}'"" --header "DD-API-KEY: ` + hexKey +
				`" --header "X-Api-Key: ` + opaque + `" --transport http-only`},
		"env": map[string]string{"GITHUB_TOKEN": "cap://github-token"}}}})
	os.WriteFile(filepath.Join(home, ".claude.json"), config, 0o600)
	fakeTools(t, h, home)
	var printed strings.Builder
	run := runner(h, &printed)

	if _, out := run("doctor"); !strings.Contains(out, "Claude Code server team, args[6] (its DD-API-KEY header)") || !strings.Contains(out, "Claude Code server team, args[6] (its X-Api-Key header)") {
		t.Errorf("doctor does not report both headers:\n%s", out)
	}
	if code, out := run("uninstall", "--dry-run"); code != 0 || !strings.Contains(out, "claude mcp add-json team") {
		t.Errorf("uninstall --dry-run exit %d, want 0 and the commands:\n%s", code, out)
	}
	h.cli.Interactive = false
	if code, out := run("mcp", "unwrap"); code != 1 || !strings.Contains(out, "Change these yourself") {
		t.Errorf("unwrap exit %d, want 1 and the change to make:\n%s", code, out)
	}
	h.cli.Interactive, h.cli.Stdin = true, strings.NewReader("yes\n")
	if code, out := run("mcp", "unwrap"); code != 0 {
		t.Fatalf("unwrap through Claude Code exit %d:\n%s", code, out)
	}
	// Unwrapped, it reads GITHUB_TOKEN from Claude Code again, which holds a reference.
	if code, out := run("mcp"); code != 1 || !strings.Contains(out, "bytes hidden") {
		t.Errorf("mcp exit %d, want 1 and hidden values:\n%s", code, out)
	}
	data, _ := os.ReadFile(filepath.Join(home, ".claude.json"))
	for _, value := range []string{opaque, hexKey} {
		if !strings.Contains(string(data), value) {
			t.Errorf("unwrap lost %q: %s", value, data)
		}
		if strings.Contains(printed.String(), value) {
			t.Errorf("printed %q:\n%s", value, printed.String())
		}
	}
}

// everyPrintPath runs doctor, and each command that prints the definition of server,
// a Claude Code server that reads GITHUB_TOKEN: keyward mcp, wrap and unwrap, shown
// and made through Claude Code, and uninstall's plan. doctor must report each
// field in want: before wrap, after it, and after unwrap, failing if known says the
// values are of a known shape. It returns all that was printed, and the config
// after wrap and after unwrap.
func everyPrintPath(t *testing.T, server map[string]any, want [3][]string, known bool) (string, [2]string) {
	t.Helper()
	h := uninstallFixture(t, "").h
	home := homed(t, h)
	h.store.Seed(map[string]string{"github-token": "v"})
	os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export GITHUB_TOKEN='cap://github-token'\n"), 0o644)
	config, _ := json.Marshal(map[string]any{"mcpServers": map[string]any{"tool": server}})
	os.WriteFile(filepath.Join(home, ".claude.json"), config, 0o600)
	fakeTools(t, h, home)
	var printed strings.Builder
	run := runner(h, &printed)
	doctor := func(when string, fields []string) {
		t.Helper()
		code, out := run("doctor")
		for _, field := range fields {
			if known && code != 1 || !strings.Contains(out, "Claude Code server tool, "+field+"\n") {
				t.Errorf("doctor %s exit %d, want %s reported:\n%s", when, code, field, out)
			}
		}
	}
	var configs [2]string
	read := func(i int) {
		data, _ := os.ReadFile(filepath.Join(home, ".claude.json"))
		configs[i] = string(data)
	}

	doctor("before wrap", want[0])
	if code, out := run("mcp"); code != 1 || !strings.Contains(out, "bytes hidden") {
		t.Errorf("mcp exit %d, want 1 and hidden values:\n%s", code, out)
	}
	if code, out := run("mcp", "wrap"); code != 1 || !strings.Contains(out, "Change these yourself") {
		t.Errorf("wrap outside a terminal exit %d, want 1 and the change to make:\n%s", code, out)
	}
	h.cli.Interactive, h.cli.Stdin = true, strings.NewReader("yes\n")
	if code, out := run("mcp", "wrap"); code != 0 {
		t.Fatalf("wrap through Claude Code exit %d:\n%s", code, out)
	}
	read(0)
	doctor("after wrap", want[1])
	if code, out := run("uninstall", "--dry-run"); code != 0 || !strings.Contains(out, "claude mcp add-json tool") {
		t.Errorf("uninstall --dry-run exit %d, want 0 and the commands:\n%s", code, out)
	}
	h.cli.Interactive = false
	if code, out := run("mcp", "unwrap"); code != 1 || !strings.Contains(out, "Change these yourself") {
		t.Errorf("unwrap outside a terminal exit %d, want 1 and the change to make:\n%s", code, out)
	}
	h.cli.Interactive, h.cli.Stdin = true, strings.NewReader("yes\n")
	if code, out := run("mcp", "unwrap"); code != 0 {
		t.Fatalf("unwrap through Claude Code exit %d:\n%s", code, out)
	}
	read(1)
	doctor("after unwrap", want[2])
	// Unwrapped, it reads GITHUB_TOKEN from Claude Code again, which holds a reference.
	if code, out := run("mcp"); code != 1 || !strings.Contains(out, "bytes hidden") {
		t.Errorf("mcp after unwrap exit %d, want 1 and hidden values:\n%s", code, out)
	}
	return printed.String(), configs
}

// A credential in JSON, a dict or a list, spaced or not, is reported by doctor in
// the field that holds it, before and after wrap and unwrap, which keep it, and
// nothing prints it.
func TestMCPNeverPrintsACredentialInJSONOrAList(t *testing.T) {
	for _, tc := range []struct {
		args  []string
		value string
		want  [3][]string
	}{
		// Smithery's form. Its args read no variable, so wrap keeps each one apart.
		{[]string{"-y", "@smithery/cli@latest", "run", "@smithery-ai/github", "--config", `{"githubPersonalAccessToken":"` + compactToken + `"}`},
			compactToken, [3][]string{{"args[5]"}, {"args[10]"}, {"args[5]"}}},
		{[]string{"-y", "@org/server", "--config", `{ "apiKey" :"` + anthropicKey + `" }`}, anthropicKey, [3][]string{{"args[3]"}, {"args[8]"}, {"args[3]"}}},
		// These read one, so wrap puts them in a script, which quotes them again.
		{[]string{"-y", "@org/server", "--config", `{'apiKey':'` + mcpToken + `'}`, "--root", "${HOME}"}, mcpToken, [3][]string{{"args[3]"}, {"args[6]"}, {"args[1]"}}},
		{[]string{"-y", "@org/server", "--keys", `["` + anthropicKey + `"]`, "--root", "${HOME}"}, anthropicKey, [3][]string{{"args[3]"}, {"args[6]"}, {"args[1]"}}},
	} {
		printed, configs := everyPrintPath(t, map[string]any{"command": "npx", "args": tc.args, "env": map[string]string{"GITHUB_TOKEN": "${GITHUB_TOKEN}"}}, tc.want, true)
		for i, config := range configs {
			if !strings.Contains(config, tc.value) {
				t.Errorf("%s lost %q: %s", []string{"wrap", "unwrap"}[i], tc.value, config)
			}
		}
		if strings.Contains(printed, tc.value) {
			t.Errorf("printed %q:\n%s", tc.value, printed)
		}
	}
}

// A value after an option named like a credential, such as --api-key, and a token
// shaped like a key, in an argument or a segment of a URL's path, may be one with
// no prefix to mark it. doctor lists each where it is, before and after wrap and
// unwrap, which keep it, and nothing prints it.
func TestMCPNeverPrintsAValueAnOptionsNameOrItsShapeMarks(t *testing.T) {
	const (
		hexKey = "0123456789abcdef0123456789abcdef"
		appKey = "Zx8Kq2Lm9Pw4Rt7Yv1Nb5Hc3Jd6Fg0Sa"
		uuid   = "3f2a9c1e-7b4d-4e8f-9a6b-2c1d0e5f7a8b"
		named  = "FakeOpaqueOptionValue"
	)
	for _, tc := range []struct {
		server map[string]any
		values []string
		want   [3][]string
	}{
		{map[string]any{"command": "npx", "args": []string{"-y", "dd-mcp", "--api-key", hexKey, "--app-key=" + appKey, "--key", uuid, "--token", named, "--root", "${HOME}"},
			"env": map[string]string{"GITHUB_TOKEN": "${GITHUB_TOKEN}"}},
			[]string{hexKey, appKey, uuid, named}, [3][]string{{"args[3]", "args[4]", "args[6]", "args[8]"}, {"args[6]"}, {"args[1]"}}},
		{map[string]any{"type": "http", "url": "https://mcp.example.com/" + uuid + "/sse", "headers": map[string]string{"Authorization": "Bearer ${GITHUB_TOKEN}"}},
			[]string{uuid}, [3][]string{{"url"}, {"args[6] (its mcp-remote URL)"}, {"args[1] (its mcp-remote URL)"}}},
	} {
		printed, configs := everyPrintPath(t, tc.server, tc.want, false)
		for _, value := range tc.values {
			for i, config := range configs {
				if !strings.Contains(config, value) {
					t.Errorf("%s lost %q: %s", []string{"wrap", "unwrap"}[i], value, config)
				}
			}
			if strings.Contains(printed, value) {
				t.Errorf("printed %q:\n%s", value, printed)
			}
		}
	}
}

// The README says keyward mcp hides the value after an option such as --api-key.
// It does so however short the value is, alone or in a script, on every path that
// prints it, though doctor needs a longer one to list it.
func TestMCPNeverPrintsAShortValueAfterAnOptionNamedLikeACredential(t *testing.T) {
	values := []string{"Fk9pw2xQ", "Zq3vLm7Rt", "Short7Sec", "shortkey99"}
	args := []string{"--host", "db.internal", "--password", values[0], "--db-password=" + values[1], "--secret", values[2], "--api-key", values[3]}
	for _, args := range [][]string{args, append(args, "--root", "${HOME}")} {
		printed, configs := everyPrintPath(t, map[string]any{"command": "postgres-mcp", "args": args, "env": map[string]string{"GITHUB_TOKEN": "${GITHUB_TOKEN}"}},
			[3][]string{}, false)
		for _, value := range values {
			for i, config := range configs {
				if !strings.Contains(config, value) {
					t.Errorf("%s lost %q: %s", []string{"wrap", "unwrap"}[i], value, config)
				}
			}
			if strings.Contains(printed, value) {
				t.Errorf("printed %q:\n%s", value, printed)
			}
		}
		if strings.Contains(printed, "may be credentials") || !strings.Contains(printed, "db.internal") {
			t.Errorf("doctor listed the values, or a value no option marks was hidden:\n%s", printed)
		}
	}
}

// Header values given to mcp-remote as arguments. Only its header's name marks
// each but the one with a known prefix.
const (
	opaqueHeader = "FakeOpaqueArgHeader0000"
	noSpaceKey   = "sk-ant-api03-FakeNoSpaceHeader0000000000"
	schemeToken  = "FakeOpaqueTokenScheme0000"
	hexHeader    = "abcdef0123456789abcdef0123456789abcdef01"
)

// A client without remote support runs mcp-remote with each header as an argument.
// doctor judges each by its name and scheme, as it does a bridge's, before wrap and
// in the script that wrap writes and unwrap leaves. Nothing prints the headers'
// text, while their names, schemes and placeholders show.
func TestMCPNeverPrintsAHeaderGivenToMCPRemoteAsAnArgument(t *testing.T) {
	args := []string{"-y", "mcp-remote", "https://api.example.com/mcp", "--header", "Authorization: Bearer ${GITHUB_TOKEN}", "--header", "X-Api-Key: " + opaqueHeader,
		"--header", "X-Other-Key:" + noSpaceKey, "--header", "X-Auth: Token " + schemeToken, "--header", "DD-API-KEY: " + hexHeader}
	printed, configs := everyPrintPath(t, map[string]any{"command": "npx", "args": args},
		[3][]string{{"args[6]", "args[8]", "args[10]", "args[12]"}, {"args[6]"}, {"args[1]"}}, true)
	for _, value := range []string{opaqueHeader, noSpaceKey, schemeToken, hexHeader} {
		for i, config := range configs {
			if !strings.Contains(config, value) {
				t.Errorf("%s lost %q: %s", []string{"wrap", "unwrap"}[i], value, config)
			}
		}
		if strings.Contains(printed, value) {
			t.Errorf("printed %q:\n%s", value, printed)
		}
	}
	for _, want := range []string{`Authorization: Bearer \"'$''{GITHUB_TOKEN}'`, "X-Other-Key:<40 bytes hidden>", "X-Auth: Token <25 bytes hidden>"} {
		if !strings.Contains(printed, want) {
			t.Errorf("printed nothing holding %q:\n%s", want, printed)
		}
	}
}

// Cursor's servers are changed by hand, from what keyward mcp, wrap and unwrap
// print, so each form of one is checked as the user leaves it.
func TestMCPNeverPrintsAHeaderArgumentInACursorServer(t *testing.T) {
	script := `exec npx -y mcp-remote https://api.example.com/mcp --header "Authorization: Bearer $GITHUB_TOKEN" --header X-Api-Key:` + noSpaceKey
	for _, tc := range []struct {
		server   map[string]any
		field    string
		commands [][]string
	}{
		{map[string]any{"command": "npx", "args": []string{"-y", "mcp-remote", "https://api.example.com/mcp", "--header", "Authorization: Bearer ${env:GITHUB_TOKEN}", "--header", "X-Api-Key:" + noSpaceKey}},
			"args[6]", [][]string{{"mcp"}, {"mcp", "wrap"}}},
		// As wrap prints it, with its hidden text copied in, and then as unwrap does.
		{map[string]any{"command": "keyward", "args": []string{"run", "--only", "GITHUB_TOKEN", "--", "sh", "-c", script}, "env": map[string]string{"GITHUB_TOKEN": "cap://github-token"}},
			"args[6]", [][]string{{"mcp", "unwrap"}}},
		// Its own script puts the token in mcp-remote's command line, which wrap
		// keeps only if given --allow-command-line, and only then prints it.
		{map[string]any{"command": "sh", "args": []string{"-c", script}, "env": map[string]string{"GITHUB_TOKEN": "${env:GITHUB_TOKEN}"}},
			"args[1]", [][]string{{"mcp", "wrap", "--allow-command-line"}}},
	} {
		h := newHarness(t, "", map[string]string{"github-token": "v"}, nil)
		home := homed(t, h)
		os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export GITHUB_TOKEN='cap://github-token'\n"), 0o644)
		os.MkdirAll(filepath.Join(home, ".cursor"), 0o755)
		config, _ := json.Marshal(map[string]any{"mcpServers": map[string]any{"tool": tc.server}})
		os.WriteFile(filepath.Join(home, ".cursor", "mcp.json"), config, 0o600)
		var printed strings.Builder
		run := runner(h, &printed)
		if code, out := run("doctor"); code != 1 || !strings.Contains(out, "Cursor server tool, "+tc.field+"\n") {
			t.Errorf("doctor exit %d, want 1 and %s reported:\n%s", code, tc.field, out)
		}
		for _, args := range tc.commands {
			if code, out := run(args...); code != 1 || !strings.Contains(out, "X-Api-Key:<40 bytes hidden>") {
				t.Errorf("%v exit %d, want 1 and the header's text hidden:\n%s", args, code, out)
			}
		}
		if strings.Contains(printed.String(), noSpaceKey) {
			t.Errorf("printed %q:\n%s", noSpaceKey, printed.String())
		}
	}
}

const wrappedServer = `{"mcpServers": {"pagerduty":{"command": "/opt/homebrew/bin/keyward", "args": ["run", "--only", "PD_KEY", "--", "uvx", "pagerduty-mcp"], "env": {"PD_KEY": "cap://pagerduty-key"}}}}`

func TestMCPUndoShowsHowToStartEachServerWithoutKeyward(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	home := homed(t, h)
	os.WriteFile(filepath.Join(home, ".claude.json"), []byte(wrappedServer), 0o600)
	if code := h.cli.Run([]string{"mcp", "unwrap"}); code != 1 {
		t.Errorf("exit %d, want 1 while a server starts through keyward", code)
	}
	for _, want := range []string{"pagerduty", "PD_KEY", `"command": "uvx"`, "${PD_KEY}", "Replace the", "keyward restore"} {
		if !strings.Contains(h.out(), want) {
			t.Errorf("output lacks %q:\n%s", want, h.out())
		}
	}
}

// Unwrapped, a server reads its variables from its client's environment again,
// which holds references until the files that set them are restored. So unwrap
// says to restore them first, before it asks to make the change, as it does when
// it prints the change.
func TestMCPUnwrapThroughClaudeSaysToRestoreTheFilesFirst(t *testing.T) {
	h := newHarness(t, "yes\n", nil, nil)
	home := homed(t, h)
	h.cli.Interactive = true
	os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export PD_KEY='cap://pagerduty-key'\n"), 0o644)
	os.WriteFile(filepath.Join(home, ".claude.json"), []byte(wrappedServer), 0o600)
	fakeTools(t, h, home)
	if code := h.cli.Run([]string{"mcp", "unwrap"}); code != 0 {
		t.Fatalf("unwrap exit %d:\n%s\n%s", code, h.out(), h.err())
	}
	if out := h.out(); !strings.Contains(out, "restore the files that set\nthem first, for example: keyward restore ~/.zshrc.") ||
		strings.Index(out, "keyward restore") > strings.Index(out, "✓ pagerduty") {
		t.Errorf("unwrap does not say to restore the files before it changes the server:\n%s", out)
	}
}

func TestMCPUndoSaysWhenNoServerUsesKeyward(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	homed(t, h)
	if code := h.cli.Run([]string{"mcp", "unwrap"}); code != 0 || !strings.Contains(h.out(), "No MCP server starts through keyward") {
		t.Errorf("exit %d:\n%s", code, h.out())
	}
}

// fakeTools stands in for the claude CLI, editing ~/.claude.json as it would: a
// local server is one of the project in the folder it runs in, and a project
// server is in that folder's .mcp.json.
func fakeTools(t *testing.T, h *harness, home string) *[]string {
	t.Helper()
	var calls []string
	h.cli.LookPath = func(name string) (string, error) {
		if name == "claude" {
			return "/usr/local/bin/claude", nil
		}
		return "", os.ErrNotExist
	}
	h.cli.RunTool = func(dir string, argv ...string) ([]byte, error) {
		calls = append(calls, strings.Join(argv[1:], " "))
		if argv[2] == "--help" {
			return []byte("add-json"), nil
		}
		config := filepath.Join(home, ".claude.json")
		if argv[len(argv)-1] == "project" {
			config = filepath.Join(dir, ".mcp.json")
		}
		doc := map[string]any{}
		data, _ := os.ReadFile(config)
		json.Unmarshal(data, &doc)
		scope := doc
		if argv[len(argv)-1] == "local" {
			projects, _ := doc["projects"].(map[string]any)
			if scope, _ = projects[dir].(map[string]any); scope == nil {
				return nil, fmt.Errorf("no project %s", dir)
			}
		}
		servers, _ := scope["mcpServers"].(map[string]any)
		if servers == nil {
			servers = map[string]any{}
			scope["mcpServers"] = servers
		}
		switch argv[2] {
		case "remove":
			delete(servers, argv[3])
		case "add-json":
			var def any
			json.Unmarshal([]byte(argv[4]), &def)
			servers[argv[3]] = def
		}
		out, _ := json.Marshal(doc)
		os.WriteFile(config, out, 0o600)
		return nil, nil
	}
	return &calls
}

const unwrappedServer = `{"mcpServers": {"pagerduty": {"command": "uvx", "args": ["pagerduty-mcp"], "env": {"PD_KEY": "${PD_KEY}"}}}}`

func TestMCPWrapAppliesThroughClaudeAfterYesAndUnwrapReverses(t *testing.T) {
	h := newHarness(t, "yes\n", nil, nil)
	home := homed(t, h)
	h.cli.Interactive, h.cli.Self = true, "/opt/homebrew/bin/keyward"
	os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export PD_KEY='cap://pagerduty-key'\n"), 0o644)
	os.WriteFile(filepath.Join(home, ".claude.json"), []byte(unwrappedServer), 0o600)
	calls := fakeTools(t, h, home)
	if code := h.cli.Run([]string{"mcp", "wrap"}); code != 0 {
		t.Fatalf("exit %d: %s\n%s", code, h.out(), h.err())
	}
	if !strings.Contains(h.out(), "claude mcp remove pagerduty -s user") {
		t.Errorf("the commands were not shown:\n%s", h.out())
	}
	data, _ := os.ReadFile(filepath.Join(home, ".claude.json"))
	if !strings.Contains(string(data), "/opt/homebrew/bin/keyward") {
		t.Errorf("config after wrap: %s (calls %q)", data, *calls)
	}
	if records, _ := h.cli.Ledger.Records(); len(records) != 1 || records[0].Kind != ledger.Server || records[0].Name != "pagerduty" {
		t.Errorf("records = %+v", records)
	}

	h.cli.Stdin = strings.NewReader("yes\n")
	if code := h.cli.Run([]string{"mcp", "unwrap"}); code != 0 {
		t.Fatalf("unwrap exit %d: %s", code, h.err())
	}
	data, _ = os.ReadFile(filepath.Join(home, ".claude.json"))
	if strings.Contains(string(data), "keyward") {
		t.Errorf("config after unwrap: %s", data)
	}
	if records, _ := h.cli.Ledger.Records(); len(records) != 0 {
		t.Errorf("records after unwrap = %+v", records)
	}
}

func TestMCPWrapWithoutYesChangesNothing(t *testing.T) {
	h := newHarness(t, "no\n", nil, nil)
	home := homed(t, h)
	h.cli.Interactive = true
	os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export PD_KEY='cap://pagerduty-key'\n"), 0o644)
	os.WriteFile(filepath.Join(home, ".claude.json"), []byte(unwrappedServer), 0o600)
	calls := fakeTools(t, h, home)
	h.cli.Run([]string{"mcp", "wrap"})
	for _, call := range *calls {
		if !strings.Contains(call, "--help") {
			t.Errorf("ran %q without a yes", call)
		}
	}
}

// A server that runs through keyward but whose --only leaves out a reference in its
// env is reported by keyward mcp and doctor. Outside a terminal, wrap prints it
// with the variable added to --only, as it does for Codex and Cursor always. Both
// say why it needs the change, as it already runs through keyward.
func TestMCPWrapPrintsAVariableAddedToOnly(t *testing.T) {
	for _, tc := range []struct{ client, path, config, references, only string }{
		{"Claude Code", ".claude.json", `{"mcpServers": {"pd": {"command": "keyward", "args": ["run", "--only", "PD_KEY", "--", "uvx", "pd-mcp"],
      "env": {"PD_KEY": "cap://pagerduty-key", "OTHER_KEY": "cap://other-key"}}}}`, "reference in OTHER_KEY", `"PD_KEY,OTHER_KEY"`},
		{"Codex", ".codex/config.toml", "[mcp_servers.pd]\ncommand = \"keyward\"\nargs = [\"run\", \"--only=PD_KEY\", \"--\", \"uvx\", \"pd-mcp\"]\n" +
			"env = { PD_KEY = \"cap://pagerduty-key\", OTHER_KEY = \"cap://other-key\" }\nenv_vars = [\"GITHUB_TOKEN\"]\n",
			"references in GITHUB_TOKEN, OTHER_KEY", `"--only=PD_KEY,GITHUB_TOKEN,OTHER_KEY"`},
		{"Cursor", ".cursor/mcp.json", `{"mcpServers": {"pd": {"command": "keyward", "args": ["run", "--only", "PD_KEY", "--", "uvx", "pd-mcp"],
      "env": {"PD_KEY": "cap://pagerduty-key", "OTHER": "${env:OTHER_KEY}"}}}}`, "reference in OTHER", `"PD_KEY,OTHER"`},
		{"Copilot CLI", ".copilot/mcp-config.json", `{"mcpServers": {"pd": {"command": "keyward", "args": ["run", "--only", "PD_KEY", "--", "uvx", "pd-mcp"],
      "env": {"PD_KEY": "cap://pagerduty-key", "OTHER": "${OTHER_KEY}"}}}}`, "reference in OTHER", `"PD_KEY,OTHER"`},
	} {
		why := "  would receive the cap:// " + tc.references + ", which keyward run is not told to resolve (" + tc.client + ", ~/" + tc.path + ")\n"
		h := newHarness(t, "", map[string]string{"pagerduty-key": "v", "other-key": "v", "github-token": "v"}, nil)
		home := homed(t, h)
		os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export OTHER_KEY='cap://other-key'\nexport GITHUB_TOKEN='cap://github-token'\n"), 0o644)
		os.MkdirAll(filepath.Dir(filepath.Join(home, tc.path)), 0o755)
		os.WriteFile(filepath.Join(home, tc.path), []byte(tc.config), 0o600)
		fakeTools(t, h, home)
		var printed strings.Builder
		run := runner(h, &printed)

		if code, out := run("mcp"); code != 1 || !strings.Contains(out, "1 MCP server(s) would receive cap:// references instead of values.") || !strings.Contains(out, why) || !strings.Contains(out, tc.only) {
			t.Errorf("%s: mcp exit %d, want 1, %q and %s:\n%s", tc.client, code, why, tc.only, out)
		}
		if code, out := run("mcp", "wrap"); code != 1 || !strings.Contains(out, "Change these yourself") || !strings.Contains(out, why) || !strings.Contains(out, tc.only) {
			t.Errorf("%s: wrap exit %d, want 1, %q and %s:\n%s", tc.client, code, why, tc.only, out)
		}
		if code, out := run("doctor"); code != 1 || verdict(out) != "✗ Problems found: 1 MCP server(s) would receive cap:// references instead of values." {
			t.Errorf("%s: doctor exit %d, want 1 and the server reported:\n%s", tc.client, code, out)
		}
	}
}

// Copilot CLI passes a server no GITHUB_TOKEN and leaves ${GITHUB_TOKEN} in env
// as written, so keyward mcp and doctor say a wrapped server that reads it there
// would not get it, naming any other key it reads it in, and print the change
// that sets its reference instead. For a project's server, they say Copilot
// starts it too.
func TestMCPSaysACopilotServerWouldNotGetGitHubToken(t *testing.T) {
	const because = ", as Copilot CLI passes a server none and fills in no ${GITHUB_TOKEN} in env"
	for _, tc := range []struct{ path, server, why, change string }{
		{".copilot/mcp-config.json", `{"command": "keyward", "args": ["run", "--", "gh-mcp"], "env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}"}}`,
			"would not get GITHUB_TOKEN" + because + " (Copilot CLI, ~/.copilot/mcp-config.json)",
			`In env, change "GITHUB_TOKEN": "${GITHUB_TOKEN}" to "GITHUB_TOKEN": "cap://github-token".`},
		{".copilot/mcp-config.json", `{"command": "keyward", "args": ["run", "--", "gh-mcp"], "env": {"GH": "${GITHUB_TOKEN}"}}`,
			"would not get GITHUB_TOKEN in GH" + because + " (Copilot CLI, ~/.copilot/mcp-config.json)",
			`In env, change "GH": "${GITHUB_TOKEN}" to "GH": "cap://github-token".`},
		{".mcp.json", `{"command": "keyward", "args": ["run", "--only", "GITHUB_TOKEN", "--", "gh-mcp"]}`,
			"Copilot CLI starts the servers in this project's .mcp.json too, and would not give this one GITHUB_TOKEN, as it passes a server none " +
				"and fills in no ${GITHUB_TOKEN} in env (Claude Code, ~/.mcp.json)",
			`In env, add "GITHUB_TOKEN": "cap://github-token".`},
	} {
		h := newHarness(t, "", map[string]string{"github-token": "fake-github-value"}, nil)
		home := homed(t, h)
		os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export GITHUB_TOKEN='cap://github-token'\n"), 0o644)
		os.MkdirAll(filepath.Join(home, ".copilot"), 0o755)
		os.WriteFile(filepath.Join(home, tc.path), []byte(`{"mcpServers": {"gh": `+tc.server+`}}`), 0o600)
		fakeTools(t, h, home)
		var printed strings.Builder
		run := runner(h, &printed)
		const problem = "1 MCP server(s) would not get GITHUB_TOKEN" + because

		if code, out := run("mcp"); code != 1 || !strings.Contains(out, problem+".\n") || !strings.Contains(out, "\n  "+tc.why+"\n") || !strings.Contains(out, "\n    "+tc.change+"\n") {
			t.Errorf("%s: mcp exit %d, want 1, %q, %q and %q:\n%s", tc.path, code, problem, tc.why, tc.change, out)
		}
		if code, out := run("doctor"); code != 1 || verdict(out) != "✗ Problems found: "+problem+"." {
			t.Errorf("%s: doctor exit %d, want 1 and the server reported:\n%s", tc.path, code, out)
		}
	}
}

// Codex passes an env_vars variable only when it has it, and keyward run stops on
// an --only name that is not set. So once the printed changes are made, the server
// starts even when Codex was started without the variable, as from the Dock.
func TestTheCodexOnlyFixStartsAServerWhoseCodexLacksTheVariable(t *testing.T) {
	h := newHarness(t, "", map[string]string{"pagerduty-key": "fake-pagerduty-value", "github-token": "fake-github-value"}, nil)
	home := homed(t, h)
	os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export GITHUB_TOKEN='cap://github-token'\n"), 0o644)
	config := filepath.Join(home, ".codex", "config.toml")
	os.MkdirAll(filepath.Dir(config), 0o755)
	original := "[mcp_servers.gh]\ncommand = \"keyward\"\nargs = [\"run\", \"--only\", \"PD_KEY\", \"--\", \"/usr/bin/true\", \"gh-mcp\"]\n" +
		"env = { PD_KEY = \"cap://pagerduty-key\" }\nenv_vars = [\"GITHUB_TOKEN\", \"EDITOR\"]\n"
	os.WriteFile(config, []byte(original), 0o600)
	var printed strings.Builder
	run := runner(h, &printed)

	changes := `In args, change "PD_KEY" to "PD_KEY,GITHUB_TOKEN".` + "\n    " + `In env, add GITHUB_TOKEN = "cap://github-token".` + "\n    " + `In env_vars, remove "GITHUB_TOKEN".`
	if code, out := run("mcp"); code != 1 || !strings.Contains(out, changes) {
		t.Fatalf("mcp exit %d, want 1 and %s:\n%s", code, changes, out)
	}
	edited := strings.NewReplacer(`"PD_KEY", "--"`, `"PD_KEY,GITHUB_TOKEN", "--"`, `" }`, `", GITHUB_TOKEN = "cap://github-token" }`, `"GITHUB_TOKEN", "EDITOR"`, `"EDITOR"`).Replace(original)
	os.WriteFile(config, []byte(edited), 0o600)
	if code, out := run("mcp"); code != 0 {
		t.Errorf("mcp exit %d once changed, want 0:\n%s", code, out)
	}
	// Codex gives the server its env, and each env_vars variable it has itself.
	servers, _ := mcpconfig.Load(home, home)
	env := []string{"PATH=/usr/bin:/bin", "EDITOR=vim"}
	for k, v := range servers[0].Env {
		env = append(env, k+"="+v)
	}
	h.cli.Environ = func() []string { return env }
	if code, out := run(servers[0].Args...); code != 0 || !slices.Contains(h.exec.env, "GITHUB_TOKEN=fake-github-value") || !slices.Contains(h.exec.env, "EDITOR=vim") {
		t.Errorf("keyward run exit %d, want 0 with GITHUB_TOKEN resolved and EDITOR passed:\n%s", code, out)
	}
}

// Codex and Cursor are printed: Codex's command cannot keep every setting.
func TestMCPWrapPrintsWhatItCannotApply(t *testing.T) {
	h := newHarness(t, "yes\n", nil, nil)
	home := homed(t, h)
	h.cli.Interactive = true
	os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export PD_KEY='cap://pagerduty-key'\n"), 0o644)
	os.MkdirAll(filepath.Join(home, ".codex"), 0o755)
	os.WriteFile(filepath.Join(home, ".codex", "config.toml"), []byte("[mcp_servers.pagerduty]\ncommand = \"uvx\"\nenv_vars = [\"PD_KEY\"]\n"), 0o600)
	fakeTools(t, h, home)
	if code := h.cli.Run([]string{"mcp", "wrap"}); code != 1 {
		t.Errorf("exit %d, want 1 while a change is left to the user", code)
	}
	if !strings.Contains(h.out(), "[mcp_servers.pagerduty]") || !strings.Contains(h.out(), "Codex") {
		t.Errorf("output:\n%s", h.out())
	}
}
