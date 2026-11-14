package cli_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/veilux-lab/keyward/internal/exposure"
)

// Fake credentials. doctor names where each one is and must never print it.
const (
	leftoverToken = "ghp_FakeLeftoverToken0000000000000000000"
	mcpToken      = "sk-proj-FakeMCPServerToken00000000000000"
	// Only the Bearer before it marks this one.
	opaqueToken = "FakeOpaqueBearerToken0000"
	urlPassword = "FakeUrlPassw0rd"
	// One in a JSON or quoted argument, which a script quotes again.
	anthropicKey = "sk-ant-api03-FakeJsonCfgKey0000000000000000"
	// One in JSON written without spaces.
	compactToken = "ghp_FakeSmitheryCompact0000000000000000"
)

// A token can outlast migration in a line migrate skipped, or in an MCP config it
// never rewrites, here in another project's servers. doctor names each place and
// fails, without printing either value.
func TestDoctorFailsOnACredentialInPlaintext(t *testing.T) {
	h := newHarness(t, "", map[string]string{"alpha": "v"}, nil)
	dir := homed(t, h)
	rc := filepath.Join(dir, ".zshrc")
	if err := os.WriteFile(rc, []byte("export A='cap://alpha'\nexport GITHUB_TOKEN="+leftoverToken+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "other-project")
	config := `{"projects": {"` + other + `": {"mcpServers": {"openai": {"command": "uvx", "args": ["openai-mcp"], "env": {"OPENAI_API_KEY": "` + mcpToken + `"}}}}}}`
	if err := os.WriteFile(filepath.Join(dir, ".claude.json"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}

	if code := h.cli.Run([]string{"doctor"}); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	for _, want := range []string{
		"~/.zshrc:2 migrate GITHUB_TOKEN a GitHub token",
		"move it with keyward migrate ~/.zshrc (preview with --dry-run), or store it with keyward add NAME and set the variable to 'cap://NAME' " +
			"e.g. keyward add github-token and set GITHUB_TOKEN to 'cap://github-token'",
		"~/.claude.json mcp Claude Code server openai, env.OPENAI_API_KEY (project ~/other-project)",
		"Then rotate each one, and store its new value with keyward add --force NAME.",
	} {
		if !strings.Contains(flat(h.out()), want) {
			t.Errorf("stdout lacks %q:\n%s", want, h.out())
		}
	}
	if got, want := verdict(h.out()), "✗ Problems found: 2 credential(s) in plaintext."; got != want {
		t.Errorf("last line = %q, want %q", got, want)
	}
	for _, value := range []string{leftoverToken, mcpToken} {
		if strings.Contains(h.out()+h.err(), value) {
			t.Errorf("doctor printed a value:\n%s\n%s", h.out(), h.err())
		}
	}
}

// keyward add only stores a copy, so doctor's advice says to set the variable to its
// reference too. Following it, and then storing the rotated value, leaves nothing
// to report.
func TestFollowingDoctorsAdviceForAShellVariableClearsIt(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	rc := filepath.Join(homed(t, h), ".zshrc")
	os.WriteFile(rc, []byte("export GITHUB_TOKEN="+leftoverToken+"\n"), 0o644)
	var printed strings.Builder
	run := runner(h, &printed)

	if code, out := run("doctor"); code != 1 || !strings.Contains(out, "e.g. keyward add github-token and set GITHUB_TOKEN to 'cap://github-token'") {
		t.Fatalf("doctor exit %d, want 1 and the advice:\n%s", code, out)
	}
	h.cli.ReadSecret = func() ([]byte, error) { return []byte(leftoverToken), nil }
	if code, out := run("add", "github-token"); code != 0 {
		t.Fatalf("add exit %d:\n%s", code, out)
	}
	os.WriteFile(rc, []byte("export GITHUB_TOKEN='cap://github-token'\n"), 0o644)
	h.cli.ReadSecret = func() ([]byte, error) { return []byte("ghp_FakeRotatedToken00000000000000000000"), nil }
	if code, out := run("add", "--force", "github-token"); code != 0 {
		t.Fatalf("add --force exit %d:\n%s", code, out)
	}
	if code, out := run("doctor"); code != 0 || verdict(out) != "✓ No problems found." {
		t.Errorf("doctor exit %d, want 0:\n%s", code, out)
	}
	if strings.Contains(printed.String(), leftoverToken) {
		t.Errorf("printed the token:\n%s", printed.String())
	}
}

// A token migrate --dry-run reports as text it cannot move fails doctor too, which
// names the line as migrate does. Neither prints the token.
func TestDoctorFailsOnACredentialMigrateCannotMove(t *testing.T) {
	for _, tc := range []struct{ name, line, kind string }{
		{"comment", "# export GITHUB_TOKEN=" + leftoverToken, "comment"},
		{"launchctl", "launchctl setenv GITHUB_TOKEN " + leftoverToken, "launchctl"},
		{"alias", "alias gh='GITHUB_TOKEN=" + leftoverToken + " gh'", "alias"},
		{"declare", "declare -x GITHUB_TOKEN=" + leftoverToken, "unsupported syntax"},
		{"several assignments", "export B=1 GITHUB_TOKEN=" + leftoverToken, "unsupported syntax"},
		{"trailer", "export A='cap://alpha' # old: " + leftoverToken, "trailer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, "", map[string]string{"alpha": "v"}, nil)
			rc := filepath.Join(homed(t, h), ".zshrc")
			if err := os.WriteFile(rc, []byte("export A='cap://alpha'\n"+tc.line+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}

			h.cli.Run([]string{"migrate", "--dry-run", rc})
			migrated := h.out()
			h.stdout.Reset()
			code := h.cli.Run([]string{"doctor"})
			// Checked first, so no failure below prints the token.
			if strings.Contains(migrated+h.out()+h.err(), leftoverToken) {
				t.Fatal("migrate or doctor printed the fake token")
			}
			if want := "line 2 (" + tc.kind + ")"; !strings.Contains(migrated, want) {
				t.Fatalf("migrate --dry-run does not report %q, which this test relies on:\n%s", want, migrated)
			}
			if code != 1 {
				t.Errorf("exit code = %d, want 1", code)
			}
			if got, want := row(h.out(), "~/.zshrc:2 "), "~/.zshrc:2 edit "+tc.kind+" a GitHub token"; got != want {
				t.Errorf("the row reads %q, want %q:\n%s", got, want, h.out())
			}
			if want := "To fix each: edit remove it by hand in an editor Then rotate"; !strings.Contains(flat(h.out()), want) {
				t.Errorf("stdout lacks %q:\n%s", want, h.out())
			}
			if got, want := verdict(h.out()), "✗ Problems found: 1 credential(s) in plaintext."; got != want {
				t.Errorf("last line = %q, want %q", got, want)
			}
		})
	}
}

// migrate keeps the comment beside a value it moves, and that comment often holds
// the token the value replaced. doctor fails until it is removed.
func TestDoctorFailsOnATokenMigrateLeftInARewrittenLine(t *testing.T) {
	const old = "ghp_FakeReplacedToken0000000000000000000"
	h := newHarness(t, "", nil, nil)
	rc := filepath.Join(homed(t, h), ".zshrc")
	if err := os.WriteFile(rc, []byte("export GITHUB_TOKEN="+leftoverToken+" # was "+old+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	h.cli.Run([]string{"migrate", "-auto-approve", rc})
	migrated := h.out()
	h.stdout.Reset()
	code := h.cli.Run([]string{"doctor"})
	// Checked first, so no failure below prints a token.
	for _, value := range []string{leftoverToken, old} {
		if strings.Contains(migrated+h.out()+h.err(), value) {
			t.Fatal("migrate or doctor printed a fake token")
		}
	}
	content, err := os.ReadFile(rc)
	if err != nil || !strings.Contains(string(content), "cap://github-token") || !strings.Contains(string(content), old) ||
		!strings.Contains(migrated, "line 1 (trailer): it stays in the rewritten line; remove it by hand") {
		t.Fatalf("this test needs migrate to rewrite the line, keep its comment and say so:\n%s", migrated)
	}
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if got, want := row(h.out(), "~/.zshrc:1 "), "~/.zshrc:1 edit trailer a GitHub token"; got != want {
		t.Errorf("the row reads %q, want %q:\n%s", got, want, h.out())
	}
	if got, want := verdict(h.out()), "✗ Problems found: 1 credential(s) in plaintext."; got != want {
		t.Errorf("last line = %q, want %q", got, want)
	}
}

// mcp wrap moves the URL into a script, and quotes JSON or a quoted value again in
// a script, all still in ~/.claude.json, where unwrap leaves them. doctor reports
// each in the field that holds it, before and after both, which change only how
// the server gets its reference. Nothing prints it. The JSON holds ORG_TOKEN in
// an argument, so wrap is given --allow-command-line.
func TestDoctorStillReportsALiteralThatMCPWrapMoved(t *testing.T) {
	const (
		literalOnly   = "✗ Problems found: 1 credential(s) in plaintext."
		withReference = "✗ Problems found: 1 credential(s) in plaintext; 1 MCP server(s) would receive cap:// references instead of values."
	)
	for _, tc := range []struct{ server, value, before, wrapped, unwrapped string }{
		{`{"type": "http", "url": "https://bot:` + urlPassword + `@mcp.example.com/mcp", "headers": {"X-Org": "${ORG_TOKEN}"}}`, urlPassword,
			"url", "args[6] (its mcp-remote URL)", "args[1] (its mcp-remote URL)"},
		{`{"command": "npx", "args": ["-y", "@smithery/cli", "run", "@org/server", "--config", "{\"apiKey\": \"` + anthropicKey + `\", \"orgToken\": \"${ORG_TOKEN}\"}"]}`, anthropicKey,
			"args[5]", "args[7]", "args[1]"},
		{`{"command": "sh", "args": ["-c", "API_KEY=\"` + anthropicKey + `\" exec some-mcp --root \"${HOME}\""], "env": {"ORG_TOKEN": "${ORG_TOKEN}"}}`, anthropicKey,
			"args[1]", "args[6]", "args[1]"},
	} {
		h := newHarness(t, "yes\n", map[string]string{"org-token": "v"}, nil)
		dir := homed(t, h)
		h.cli.Interactive = true
		os.WriteFile(filepath.Join(dir, ".zshrc"), []byte("export ORG_TOKEN='cap://org-token'\n"), 0o644)
		os.WriteFile(filepath.Join(dir, ".claude.json"), []byte(`{"mcpServers": {"org": `+tc.server+`}}`), 0o600)
		fakeTools(t, h, dir)
		var printed strings.Builder
		run := runner(h, &printed)
		doctor := func(when, field, want string) {
			t.Helper()
			if code, out := run("doctor"); code != 1 || !strings.Contains(out, "Claude Code server org, "+field+"\n") || verdict(h.out()) != want {
				t.Errorf("doctor %s exit %d, want 1, %s reported, and %q:\n%s", when, code, field, want, out)
			}
		}

		doctor("before wrap", tc.before, withReference)
		if code, out := run("mcp", "wrap", "--allow-command-line"); code != 0 {
			t.Fatalf("wrap exit %d:\n%s", code, out)
		}
		doctor("after wrap", tc.wrapped, literalOnly)
		h.cli.Stdin = strings.NewReader("yes\n")
		if code, out := run("mcp", "unwrap"); code != 0 {
			t.Fatalf("unwrap exit %d:\n%s", code, out)
		}
		// Unwrapped, it reads ORG_TOKEN from Claude Code again, which holds a reference.
		doctor("after unwrap", tc.unwrapped, withReference)
		if strings.Contains(printed.String(), tc.value) {
			t.Errorf("printed %q:\n%s", tc.value, printed.String())
		}
	}
}

// An earlier wrap moved a header's credential into env, where doctor says to store
// it, replace it with a variable of the same name, set to the reference in
// ~/.zshrc, and run keyward mcp wrap. The bridge's --only must then name that
// variable, or keyward run passes the reference on to mcp-remote as it is.
func TestFollowingDoctorsAdviceForAnMCPLiteralLeavesAServerThatResolvesIt(t *testing.T) {
	h := newHarness(t, "yes\n", map[string]string{"org-token": "v"}, nil)
	dir := homed(t, h)
	h.cli.Interactive, h.cli.Self = true, "/opt/homebrew/bin/keyward"
	rc := filepath.Join(dir, ".zshrc")
	os.WriteFile(rc, []byte("export ORG_TOKEN='cap://org-token'\n"), 0o644)
	config := filepath.Join(dir, ".claude.json")
	wrapped, _ := json.Marshal(map[string]any{"mcpServers": map[string]any{"org": map[string]any{"command": "/opt/homebrew/bin/keyward",
		"args": []string{"run", "--only", "ORG_TOKEN", "--", "sh", "-c", `exec npx -y mcp-remote https://mcp.example.com/mcp --header "Authorization: Bearer "'$''{KW_HDR_1}'"" ` +
			`--header "X-Org: "'$''{ORG_TOKEN}'"" --transport http-only`},
		"env": map[string]string{"KW_HDR_1": opaqueToken, "ORG_TOKEN": "cap://org-token"}}}})
	os.WriteFile(config, wrapped, 0o600)
	fakeTools(t, h, dir)
	var printed strings.Builder
	run := runner(h, &printed)
	org := func() (server struct {
		Args []string
		Env  map[string]string
	}) {
		var doc struct {
			MCPServers map[string]json.RawMessage `json:"mcpServers"`
		}
		data, _ := os.ReadFile(config)
		json.Unmarshal(data, &doc)
		json.Unmarshal(doc.MCPServers["org"], &server)
		return server
	}

	if code, out := run("doctor"); code != 1 || !strings.Contains(out, "Claude Code server org, env.KW_HDR_1 (from its Authorization header)\n") ||
		!strings.Contains(flat(out), "store it with keyward add NAME, write ${KW_HDR_1} in its place, add export KW_HDR_1='cap://NAME' to ~/.zshrc, and run keyward mcp wrap") {
		t.Fatalf("doctor exit %d, want 1 and its advice for env.KW_HDR_1:\n%s", code, out)
	}
	// The user follows it: keyward add, a variable set to the reference, and the
	// value replaced by hand.
	h.cli.ReadSecret = func() ([]byte, error) { return []byte(opaqueToken), nil }
	if code, out := run("add", "org-auth"); code != 0 {
		t.Fatalf("add exit %d:\n%s", code, out)
	}
	os.WriteFile(rc, []byte("export ORG_TOKEN='cap://org-token'\nexport KW_HDR_1='cap://org-auth'\n"), 0o644)
	var doc map[string]map[string]map[string]any
	data, _ := os.ReadFile(config)
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	doc["mcpServers"]["org"]["env"].(map[string]any)["KW_HDR_1"] = "${KW_HDR_1}"
	data, _ = json.Marshal(doc)
	os.WriteFile(config, data, 0o600)

	if code, out := run("doctor"); code != 1 || verdict(out) != "✗ Problems found: 1 MCP server(s) would receive cap:// references instead of values." {
		t.Errorf("doctor exit %d, want 1 and the server reported:\n%s", code, out)
	}
	if code, out := run("mcp"); code != 1 || !strings.Contains(out, "would receive the cap:// reference in KW_HDR_1, which keyward run is not told to resolve") {
		t.Errorf("mcp exit %d, want 1 and why the server needs a change:\n%s", code, out)
	}
	h.cli.Stdin = strings.NewReader("yes\n")
	if code, out := run("mcp", "wrap"); code != 0 {
		t.Fatalf("wrap exit %d:\n%s", code, out)
	}
	if args := org().Args; len(args) < 3 || args[1] != "--only" || !slices.Contains(strings.Split(args[2], ","), "KW_HDR_1") || !slices.Contains(strings.Split(args[2], ","), "ORG_TOKEN") {
		t.Errorf("args after wrap = %q, want --only to name KW_HDR_1 and ORG_TOKEN", args)
	}
	if code, out := run("doctor"); code != 0 || verdict(out) != "✓ No problems found." {
		t.Errorf("doctor exit %d, want 0:\n%s", code, out)
	}
	if code, out := run("mcp"); code != 0 || !strings.Contains(out, "No MCP server needs a change.") {
		t.Errorf("mcp exit %d, want 0:\n%s", code, out)
	}
	// Started as its client starts it, which fills ${KW_HDR_1} in from its own
	// environment, keyward run resolves the header's reference.
	server := org()
	client := map[string]string{"ORG_TOKEN": "cap://org-token", "KW_HDR_1": "cap://org-auth"}
	env := []string{"PATH=/usr/bin:/bin"}
	for k, v := range server.Env {
		if name, ok := strings.CutPrefix(v, "${"); ok {
			v = client[strings.TrimSuffix(name, "}")]
		}
		env = append(env, k+"="+v)
	}
	h.cli.Environ = func() []string { return env }
	if code, out := run(server.Args...); code != 0 || !slices.Contains(h.exec.env, "KW_HDR_1="+opaqueToken) {
		t.Errorf("keyward run exit %d, want 0 and KW_HDR_1 resolved:\n%s", code, out)
	}
	if strings.Contains(printed.String(), opaqueToken) {
		t.Errorf("printed the literal:\n%s", printed.String())
	}
}

// wrap keeps a literal in a server's args where it is. Doctor's advice is to pass
// it in env, if the server reads it from there, or else to put ${VAR} there,
// which the client fills in before keyward run starts, so the server would get
// the reference: keyward mcp and doctor report it until wrap writes it again
// through sh, which hands it the value. The value is then an argument, which
// keyward run refuses unless given --allow-command-line, so wrap gives it the
// option once the user accepts that.
func TestFollowingDoctorsAdviceForALiteralInAWrappedServersArgsLeavesAServerThatGetsIt(t *testing.T) {
	h := newHarness(t, "yes\n", map[string]string{"pagerduty-key": "fake-pagerduty-value"}, nil)
	dir := homed(t, h)
	h.cli.Interactive, h.cli.Self = true, "/opt/homebrew/bin/keyward"
	rc := filepath.Join(dir, ".zshrc")
	os.WriteFile(rc, []byte("export PD_KEY='cap://pagerduty-key'\n"), 0o644)
	config := filepath.Join(dir, ".claude.json")
	os.WriteFile(config, []byte(`{"mcpServers": {"pd": {"command": "printf", "args": ["[%s]", "--token", "`+leftoverToken+`"], "env": {"PD_KEY": "${PD_KEY}"}}}}`), 0o600)
	fakeTools(t, h, dir)
	var printed strings.Builder
	run := runner(h, &printed)
	var doc map[string]map[string]map[string]any
	read := func() {
		data, _ := os.ReadFile(config)
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatal(err)
		}
	}

	if code, out := run("mcp", "wrap"); code != 0 {
		t.Fatalf("wrap exit %d:\n%s", code, out)
	}
	if code, out := run("doctor"); code != 1 || !strings.Contains(out, "Claude Code server pd, args[7]\n") ||
		!strings.Contains(flat(out), "and pass it in env as VAR, if the server reads it from there, or else write ${VAR} in its place, which wrap puts in the server's command line only if given --allow-command-line") {
		t.Fatalf("doctor exit %d, want 1 and the literal in args[7]:\n%s", code, out)
	}
	// The user follows it: keyward add, a variable set to the reference, and ${VAR}
	// in the literal's place.
	h.cli.ReadSecret = func() ([]byte, error) { return []byte(leftoverToken), nil }
	if code, out := run("add", "gh-token"); code != 0 {
		t.Fatalf("add exit %d:\n%s", code, out)
	}
	os.WriteFile(rc, []byte("export PD_KEY='cap://pagerduty-key'\nexport GH_TOKEN='cap://gh-token'\n"), 0o644)
	read()
	doc["mcpServers"]["pd"]["args"].([]any)[7] = "${GH_TOKEN}"
	data, _ := json.Marshal(doc)
	os.WriteFile(config, data, 0o600)

	if code, out := run("doctor"); code != 1 || verdict(out) != "✗ Problems found: 1 MCP server(s) would receive cap:// references instead of values." {
		t.Errorf("doctor exit %d, want 1 and the server reported:\n%s", code, out)
	}
	if code, out := run("mcp"); code != 1 || !strings.Contains(out, "reads GH_TOKEN in its arguments, which keyward run does not resolve") {
		t.Errorf("mcp exit %d, want 1 and why the server needs a change:\n%s", code, out)
	}
	if code, out := run("mcp", "wrap"); code != 1 || !strings.Contains(out, "Skipped pd: wrapped, it would pass GH_TOKEN as an argument, which keyward run refuses") {
		t.Errorf("wrap exit %d, want 1 and the server skipped:\n%s", code, out)
	}
	h.cli.Stdin = strings.NewReader("yes\n")
	if code, out := run("mcp", "wrap", "--allow-command-line"); code != 0 {
		t.Fatalf("wrap --allow-command-line exit %d:\n%s", code, out)
	}
	if code, out := run("doctor"); code != 0 || verdict(out) != "✓ No problems found. 1 check needs attention." || !strings.Contains(flat(out), allowedSection+"; see keyward mcp") {
		t.Errorf("doctor exit %d, want 0:\n%s", code, out)
	}
	if code, out := run("mcp"); code != 0 || !strings.Contains(out, "No MCP server needs a change.") {
		t.Errorf("mcp exit %d, want 0:\n%s", code, out)
	}
	// Started as its client starts it, with each ${VAR} in its args filled in from
	// the client's environment, which holds the references, the server gets the value.
	read()
	client := map[string]string{"PATH": "/usr/bin:/bin", "PD_KEY": "cap://pagerduty-key", "GH_TOKEN": "cap://gh-token"}
	var args, env []string
	for _, a := range doc["mcpServers"]["pd"]["args"].([]any) {
		args = append(args, regexp.MustCompile(`\$\{[A-Za-z_][A-Za-z0-9_]*\}`).ReplaceAllStringFunc(a.(string), func(p string) string { return client[p[2:len(p)-1]] }))
	}
	for k, v := range client {
		env = append(env, k+"="+v)
	}
	for k, v := range doc["mcpServers"]["pd"]["env"].(map[string]any) {
		env = append(env, k+"="+v.(string))
	}
	h.cli.Environ = func() []string { return env }
	if code, out := run(args...); code != 0 {
		t.Fatalf("keyward run exit %d:\n%s", code, out)
	}
	cmd := exec.Command(h.exec.path, h.exec.argv[1:]...)
	cmd.Env = h.exec.env
	if out, err := cmd.Output(); err != nil || string(out) != "[--token]["+leftoverToken+"]" {
		t.Errorf("the server did not get the value (%v)", err)
	}
	if strings.Contains(printed.String(), leftoverToken) {
		t.Errorf("printed the literal:\n%s", printed.String())
	}
}

// Following doctor's advice for a literal in a bridge's URL puts ${VAR} in its
// script. wrap rewrites the script in place, not in another sh -c, whose sh would
// expand the value into mcp-remote's command line with nothing reporting it. The
// URL then reads a migrated secret, so wrap skips the server until given
// --allow-command-line, after which keyward mcp and doctor list it as allowed,
// and mcp-remote gets that secret alone in its command line.
func TestFollowingDoctorsAdviceForALiteralInABridgesURLRewritesItsScriptInPlace(t *testing.T) {
	const literal = "ghp_FakeUrlQueryToken0000000000000000000"
	h := newHarness(t, "yes\n", map[string]string{"github-token": "fake-github-value"}, nil)
	home := homed(t, h)
	h.cli.Interactive, h.cli.Self = true, "/opt/homebrew/bin/keyward"
	rc := filepath.Join(home, ".zshrc")
	os.WriteFile(rc, []byte("export GITHUB_TOKEN='cap://github-token'\n"), 0o644)
	config := filepath.Join(home, ".claude.json")
	os.WriteFile(config, []byte(`{"mcpServers": {"q": {"type": "http", "url": "https://mcp.example.com/mcp?key=`+literal+`", "headers": {"Authorization": "Bearer ${GITHUB_TOKEN}"}}}}`), 0o600)
	calls := fakeTools(t, h, home)
	var printed strings.Builder
	run := runner(h, &printed)
	q := func() (server struct {
		Args []string
		Env  map[string]string
	}) {
		var doc struct {
			MCPServers map[string]json.RawMessage `json:"mcpServers"`
		}
		data, _ := os.ReadFile(config)
		json.Unmarshal(data, &doc)
		json.Unmarshal(doc.MCPServers["q"], &server)
		return server
	}

	if code, out := run("mcp", "wrap"); code != 0 {
		t.Fatalf("wrap exit %d:\n%s", code, out)
	}
	if code, out := run("doctor"); code != 1 || !strings.Contains(out, "Claude Code server q, args[6] (its mcp-remote URL)\n") ||
		!strings.Contains(flat(out), "or else write ${VAR} in its place, which wrap puts in mcp-remote's command line and log only if given --allow-command-line; then run keyward mcp wrap") {
		t.Fatalf("doctor exit %d, want 1 and its advice for the URL:\n%s", code, out)
	}
	// The user follows it: keyward add, a variable set to the reference, and ${VAR}
	// in the literal's place.
	h.cli.ReadSecret = func() ([]byte, error) { return []byte(literal), nil }
	if code, out := run("add", "q-key"); code != 0 {
		t.Fatalf("add exit %d:\n%s", code, out)
	}
	os.WriteFile(rc, []byte("export GITHUB_TOKEN='cap://github-token'\nexport Q_KEY='cap://q-key'\n"), 0o644)
	data, _ := os.ReadFile(config)
	os.WriteFile(config, []byte(strings.Replace(string(data), literal, "${Q_KEY}", 1)), 0o600)

	if code, out := run("mcp"); code != 1 || !strings.Contains(out, "reads Q_KEY in its arguments") || !strings.Contains(out, "npx would get Q_KEY in its command line (line 1)") ||
		!strings.Contains(out, "keyward mcp wrap skips it. To start it anyway, with Q_KEY in a command line") {
		t.Errorf("mcp exit %d, want 1, the server and the URL's warning:\n%s", code, out)
	}
	before := len(*calls)
	if code, out := run("mcp", "wrap"); code != 1 || !strings.Contains(out, "Skipped q: keyward run would refuse to start it as wrap would change it.\n  npx would get Q_KEY") || len(*calls) != before+1 {
		t.Errorf("wrap exit %d, want 1 and the server skipped (ran %q):\n%s", code, (*calls)[before:], out)
	}
	if code, out := run("doctor"); code != 1 || verdict(out) != "✗ Problems found: 1 MCP server(s) would receive cap:// references instead of values." {
		t.Errorf("doctor exit %d, want 1 and the server reported:\n%s", code, out)
	}
	h.cli.Stdin = strings.NewReader("yes\n")
	if code, out := run("mcp", "wrap", "--allow-command-line"); code != 0 {
		t.Fatalf("wrap --allow-command-line exit %d:\n%s", code, out)
	}
	server := q()
	if script := server.Args[len(server.Args)-1]; script != `exec npx -y mcp-remote "https://mcp.example.com/mcp?key=$Q_KEY" --header "Authorization: Bearer "'$''{GITHUB_TOKEN}'"" --transport http-only` {
		t.Errorf("script after wrap = %s", script)
	}
	if code, out := run("mcp"); code != 0 || !strings.Contains(out, allowedSection+":") {
		t.Errorf("mcp exit %d, want 0 and the server listed as allowed:\n%s", code, out)
	}
	if code, out := run("doctor"); code != 0 || verdict(out) != "✓ No problems found. 1 check needs attention." || !strings.Contains(flat(out), allowedSection+"; see keyward mcp") {
		t.Errorf("doctor exit %d, want 0 and the server listed as allowed:\n%s", code, out)
	}
	// Started as Claude Code starts it, mcp-remote gets the header to fill in itself.
	bin := t.TempDir()
	os.WriteFile(filepath.Join(bin, "npx"), []byte("#!/bin/sh\nprintf '[%s]' \"$@\"\n"), 0o755)
	env := []string{"PATH=" + bin + ":/usr/bin:/bin", "GITHUB_TOKEN=cap://github-token", "Q_KEY=cap://q-key"}
	for k, v := range server.Env {
		env = append(env, k+"="+v)
	}
	h.cli.Environ = func() []string { return env }
	if code, out := run(server.Args...); code != 0 {
		t.Fatalf("keyward run exit %d:\n%s", code, out)
	}
	cmd := exec.Command(h.exec.path, h.exec.argv[1:]...)
	cmd.Env = h.exec.env
	want := "[-y][mcp-remote][https://mcp.example.com/mcp?key=" + literal + "][--header][Authorization: Bearer ${GITHUB_TOKEN}][--transport][http-only]"
	if out, err := cmd.Output(); err != nil || string(out) != want {
		t.Errorf("mcp-remote got other arguments (%v)", err)
	}
	if strings.Contains(printed.String(), literal) {
		t.Errorf("printed the literal:\n%s", printed.String())
	}
}

// mcp-remote puts a remote server's URL in its command line. So doctor's advice for
// a credential in a URL is to send it in a header, if the server takes it there,
// which leaves a server wrap changes and nothing reports, and that keeps the value
// out of every command line.
func TestFollowingDoctorsAdviceForACredentialInAURLLeavesAServerWrapChanges(t *testing.T) {
	const key = "3f2a9c1e-7b4d-4e8f-9a6b-2c1d0e5f7a8b"
	h := newHarness(t, "", nil, nil)
	home := homed(t, h)
	h.cli.Interactive, h.cli.Self = true, "/opt/homebrew/bin/keyward"
	config := filepath.Join(home, ".claude.json")
	os.WriteFile(config, []byte(`{"mcpServers": {"exa": {"type": "http", "url": "https://mcp.exa.example/mcp?exaApiKey=`+key+`"}}}`), 0o600)
	fakeTools(t, h, home)
	var printed strings.Builder
	run := runner(h, &printed)

	if _, out := run("doctor"); !strings.Contains(out, "Claude Code server exa, url\n") || !strings.Contains(flat(out), "and send it in a header as ${VAR}, if the server takes it there") {
		t.Fatalf("doctor gives no advice for the URL:\n%s", out)
	}
	// The user follows it, as the server takes the key in a header.
	h.cli.ReadSecret = func() ([]byte, error) { return []byte(key), nil }
	if code, out := run("add", "exa-key"); code != 0 {
		t.Fatalf("add exit %d:\n%s", code, out)
	}
	os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export EXA_KEY='cap://exa-key'\n"), 0o644)
	os.WriteFile(config, []byte(`{"mcpServers": {"exa": {"type": "http", "url": "https://mcp.exa.example/mcp", "headers": {"x-api-key": "${EXA_KEY}"}}}}`), 0o600)
	h.cli.Stdin = strings.NewReader("yes\n")
	if code, out := run("mcp", "wrap"); code != 0 {
		t.Fatalf("wrap exit %d:\n%s", code, out)
	}
	if code, out := run("doctor"); code != 0 || verdict(out) != "✓ No problems found." {
		t.Errorf("doctor exit %d, want 0:\n%s", code, out)
	}
	if code, out := run("mcp"); code != 0 || !strings.Contains(out, "No MCP server needs a change.") || strings.Contains(out, "command line") {
		t.Errorf("mcp exit %d, want 0 and nothing in a command line:\n%s", code, out)
	}
	if strings.Contains(printed.String(), key) {
		t.Errorf("printed the key:\n%s", printed.String())
	}
}

// Codex fills no variable in http_headers. So doctor's advice for a literal there
// is to move it to env_http_headers, which keyward mcp then wraps, and a ${VAR}
// written in http_headers instead, which Codex would send as it is, is reported
// as well.
func TestFollowingDoctorsAdviceForALiteralInCodexHTTPHeadersLeavesAServerKeywardWraps(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	home := homed(t, h)
	codex := filepath.Join(home, ".codex", "config.toml")
	os.MkdirAll(filepath.Dir(codex), 0o755)
	const table = "[mcp_servers.team]\nurl = \"https://mcp.example.com/mcp\"\n"
	os.WriteFile(codex, []byte(table+`http_headers = { "X-Team-Key" = "`+leftoverToken+`" }`+"\n"), 0o600)
	var printed strings.Builder
	run := runner(h, &printed)

	if code, out := run("doctor"); code != 1 || !strings.Contains(flat(out), `move it to env_http_headers = { "X-Team-Key" = "VAR" }, add export VAR='cap://NAME' to ~/.zshrc, and run keyward mcp wrap`) {
		t.Fatalf("doctor exit %d, want 1 and its advice for the header:\n%s", code, out)
	}
	// The user follows it, or writes the variable in http_headers.
	h.cli.ReadSecret = func() ([]byte, error) { return []byte(leftoverToken), nil }
	if code, out := run("add", "team-key"); code != 0 {
		t.Fatalf("add exit %d:\n%s", code, out)
	}
	os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export TEAM_KEY='cap://team-key'\n"), 0o644)
	for _, headers := range []string{`env_http_headers = { "X-Team-Key" = "TEAM_KEY" }`, `http_headers = { "X-Team-Key" = "${TEAM_KEY}" }`} {
		os.WriteFile(codex, []byte(table+headers+"\n"), 0o600)
		if code, out := run("mcp"); code != 1 || !strings.Contains(out, "uses TEAM_KEY") || !strings.Contains(out, `--header \"X-Team-Key: \"'$''{TEAM_KEY}'\"\"`) {
			t.Errorf("%s: mcp exit %d, want 1 and the bridge:\n%s", headers, code, out)
		}
		if code, out := run("doctor"); code != 1 || verdict(out) != "✗ Problems found: 1 MCP server(s) would receive cap:// references instead of values." {
			t.Errorf("%s: doctor exit %d, want 1 and the server reported:\n%s", headers, code, out)
		}
	}
	if strings.Contains(printed.String(), leftoverToken) {
		t.Errorf("printed the literal:\n%s", printed.String())
	}
}

// doctor reads every Claude Code project's servers, but wrap changes a project's
// local servers only from its folder, where Claude Code's CLI finds them. So the
// advice for a literal in another project's server names that folder, and from
// anywhere else doctor, keyward mcp and wrap report the server, with the folder,
// until wrap has changed it there.
func TestFollowingDoctorsAdviceForALiteralInAnotherProjectLeavesAServerThatResolvesIt(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	home := homed(t, h)
	h.cli.Self = "/opt/homebrew/bin/keyward"
	other := filepath.Join(home, "other-project")
	os.Mkdir(other, 0o755)
	config := filepath.Join(home, ".claude.json")
	os.WriteFile(config, []byte(`{"projects": {"`+other+`": {"mcpServers": {"openai": {"command": "uvx", "args": ["openai-mcp"], "env": {"OPENAI_API_KEY": "`+mcpToken+`"}}}}}}`), 0o600)
	calls := fakeTools(t, h, home)
	var printed strings.Builder
	run := runner(h, &printed)

	if code, out := run("doctor"); code != 1 || !strings.HasSuffix(row(out, "server openai, env.OPENAI_API_KEY"), " store it with keyward add NAME, write ${OPENAI_API_KEY} in its place, "+
		"add export OPENAI_API_KEY='cap://NAME' to ~/.zshrc, and run keyward mcp wrap in ~/other-project") {
		t.Fatalf("doctor exit %d, want 1 and the folder to run wrap in:\n%s", code, out)
	}
	// The user follows it: keyward add, a variable set to the reference, and the
	// value replaced by hand.
	h.cli.ReadSecret = func() ([]byte, error) { return []byte(mcpToken), nil }
	if code, out := run("add", "openai-key"); code != 0 {
		t.Fatalf("add exit %d:\n%s", code, out)
	}
	os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export OPENAI_API_KEY='cap://openai-key'\n"), 0o644)
	data, _ := os.ReadFile(config)
	os.WriteFile(config, []byte(strings.Replace(string(data), mcpToken, "${OPENAI_API_KEY}", 1)), 0o600)

	if code, out := run("doctor"); code != 1 || verdict(out) != "✗ Problems found: 1 MCP server(s) would receive cap:// references instead of values." {
		t.Errorf("doctor exit %d, want 1 and the server reported:\n%s", code, out)
	}
	for _, args := range [][]string{{"mcp"}, {"mcp", "wrap"}} {
		if code, out := run(args...); code != 1 || !strings.Contains(out, "1 MCP server(s) in other Claude Code projects need a change; run keyward mcp wrap in the project's folder:\n  openai  ~/other-project\n") {
			t.Errorf("%v exit %d, want 1 and the folder to run wrap in:\n%s", args, code, out)
		}
	}
	if code, out := run("mcp", "wrap", "openai"); code != 1 || !strings.Contains(out, "openai is a server of the Claude Code project in ~/other-project; run keyward mcp wrap there") {
		t.Errorf("wrap openai exit %d, want 1 and the folder to run it in:\n%s", code, out)
	}
	for _, call := range *calls {
		if !strings.Contains(call, "--help") {
			t.Errorf("ran %q outside the project's folder", call)
		}
	}
	h.cli.Workdir, h.cli.Interactive, h.cli.Stdin = other, true, strings.NewReader("yes\n")
	if code, out := run("mcp", "wrap"); code != 0 {
		t.Fatalf("wrap in the project's folder exit %d:\n%s", code, out)
	}
	h.cli.Workdir = home
	if code, out := run("doctor"); code != 0 || verdict(out) != "✓ No problems found." {
		t.Errorf("doctor exit %d, want 0:\n%s", code, out)
	}
	if code, out := run("mcp"); code != 0 || !strings.Contains(out, "No MCP server needs a change.") {
		t.Errorf("mcp exit %d, want 0:\n%s", code, out)
	}
	if strings.Contains(printed.String(), mcpToken) {
		t.Errorf("printed the literal:\n%s", printed.String())
	}
}

// The verdict comes after every other section, so it is what the reader is left
// with, and it counts every problem found, not just the report's. keyward mcp
// fails on a server that would receive a reference or exposes a secret, so
// doctor does too.
func TestDoctorPrintsItsVerdictLast(t *testing.T) {
	const (
		wrapped  = `{"mcpServers": {"tool": {"command": "keyward", "args": ["run", "--only", "A", "--", "tool"]}}}`
		mcpIssue = `{"mcpServers": {"tool": {"command": "tool", "env": {"A": "${A}"}},
  "github": {"command": "keyward", "args": ["run", "--only", "GITHUB_TOKEN", "--", "sh", "-c", "exec npx -y mcp-remote https://api.example.com/mcp/ --header \"Authorization: Bearer $GITHUB_TOKEN\" --transport http-only"], "env": {"GITHUB_TOKEN": "cap://github-token"}}}}`
	)
	for _, tc := range []struct {
		name, rc, claude string
		exposed          []exposure.Exposure
		code             int
		verdict          string
	}{
		{"clean", "export A='cap://alpha'\n", wrapped, nil, 0, "✓ No problems found. 2 checks need attention."},
		{"problems", "export A='cap://alpha'\nexport GITHUB_TOKEN=" + leftoverToken + "\n", mcpIssue,
			[]exposure.Exposure{{Secret: "alpha", PID: 42, Program: "node"}}, 1,
			"✗ Problems found: 1 credential(s) in plaintext; 1 MCP server(s) would receive cap:// references instead of values; " +
				"1 MCP server(s) would put a secret in a command line, so keyward run refuses to start them; 1 secret(s) in a running program's command line."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, "", map[string]string{"alpha": "v", "github-token": "v"}, nil)
			dir := homed(t, h)
			// The recovery reminder needs attention, which the verdict counts.
			h.cli.RecoveryMarker = filepath.Join(dir, "recovery-shown")
			h.cli.Exposures = func() ([]exposure.Exposure, error) { return tc.exposed, nil }
			os.WriteFile(filepath.Join(dir, ".zshrc"), []byte(tc.rc), 0o644)
			os.WriteFile(filepath.Join(dir, ".claude.json"), []byte(tc.claude), 0o600)

			if code := h.cli.Run([]string{"doctor"}); code != tc.code {
				t.Errorf("exit code = %d, want %d", code, tc.code)
			}
			if !strings.Contains(flat(h.out()), "keyward recovery show") {
				t.Fatalf("a check this test relies on is missing:\n%s", h.out())
			}
			if got := verdict(h.out()); got != tc.verdict {
				t.Errorf("last line = %q, want %q\n%s", got, tc.verdict, h.out())
			}
		})
	}
}

// A value only its name suggests, or one that only starts like a key, as a list of
// locales or regions or a public key in the folder's .env does, is listed with a
// way to silence it, but does not fail doctor, commented out or not.
func TestDoctorListsPossibleCredentialsWithoutFailing(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	dir := homed(t, h)
	rc := filepath.Join(dir, ".zshrc")
	os.WriteFile(rc, []byte("export GIT_AUTHOR_EMAIL=someone@example.com\n# export GIT_AUTHOR_EMAIL=someone@example.com\n"), 0o644)
	os.WriteFile(filepath.Join(dir, ".env"), []byte("SUPPORTED_LOCALES=sk-SK,cs-CZ,de-DE,en-US\nDEPLOY_REGIONS=ASIA,EUROPE,AMERICAS,AFRICA\n"+
		`JWT_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A-----END PUBLIC KEY-----"`+"\n"), 0o644)

	if code := h.cli.Run([]string{"doctor"}); code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if !strings.Contains(h.out(), "GIT_AUTHOR_EMAIL") || !strings.HasPrefix(row(h.out(), "~/.zshrc:2 "), "~/.zshrc:2 edit comment ") || !strings.Contains(h.out(), "# keyward:ignore") {
		t.Errorf("stdout does not list the value with a way to silence it:\n%s", h.out())
	}
	if got := verdict(h.out()); got != "✓ No problems found. 1 check needs attention." {
		t.Errorf("last line = %q", got)
	}
}

// doctor says what each line it lists holds, and lists nearby lines as one range,
// which it advises marking only where the range holds no credential of a known
// shape, as the README says.
func TestTheReadmeSaysWhatDoctorsListShows(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Join(strings.Fields(string(data)), " ")
	for _, want := range []string{"says where each one is and what it looks like, such as \"a GitHub token\"", "Nearby lines of one kind are listed as one range.",
		"end it with `# keyward:ignore`, marking each line of a range of values that may be credentials,"} {
		if !strings.Contains(text, want) {
			t.Errorf("README lacks %q", want)
		}
	}
}

// An MCP config that cannot be parsed was not checked for credentials, so doctor
// says so rather than implying it was.
func TestDoctorSaysWhichMCPConfigItCouldNotCheck(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	dir := homed(t, h)
	os.WriteFile(filepath.Join(dir, ".claude.json"), []byte("{not json"), 0o600)

	h.cli.Run([]string{"doctor"})
	if !strings.Contains(h.err(), "Could not read an MCP config") || !strings.Contains(h.err(), ".claude.json") {
		t.Errorf("stderr = %q", h.err())
	}
}
