package mcpconfig_test

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/veilux-lab/keyward/internal/mcpconfig"
)

// Fake credentials an agent's own files may hold. A finding says where each one
// is and must never hold it.
const (
	agentToken = "ghp_" + "FakeAgentFileToken000000000000000000"
	// Only the option or variable each is given with marks it.
	dbPass  = "hunter2"
	sshPass = "Tr0ub4dor3"
)

// read is what content holds, read as doctor reads an agent's file of name.
func read(t *testing.T, name, content string) ([]mcpconfig.AgentLiteral, []string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	found, passed, err := mcpconfig.AgentFile{Path: path}.Read([]byte(content))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	for _, l := range found {
		if l.File != path {
			t.Errorf("%s is in %s, want %s", l.Field, l.File, path)
		}
	}
	return found, passed
}

// fields names each finding by its field, or its line, with whether it is of a
// known shape.
func fields(found []mcpconfig.AgentLiteral) map[string]bool {
	named := map[string]bool{}
	for _, l := range found {
		where := l.Field
		if l.Line > 0 {
			where = "line " + strconv.Itoa(l.Line)
		}
		named[where] = l.KnownShape
	}
	return named
}

// Agents keep files of their own in home, in the working folder and in each of
// Claude Code's projects, each read once: home can be a project, as can the
// working folder. Claude Code saves a project's local settings at the root of its
// repository: a worktree's main checkout, or a submodule itself. A file of
// another project names that project.
func TestAgentFilesNamesEachFileOnce(t *testing.T) {
	home, workdir := t.TempDir(), t.TempDir()
	repo := filepath.Join(t.TempDir(), "repo")
	sub := filepath.Join(repo, "web")
	// git writes a worktree's gitdir in full, or relative to it if told to.
	checkouts := t.TempDir()
	main, worktree := filepath.Join(checkouts, "main"), filepath.Join(checkouts, "worktree")
	other, relative := filepath.Join(checkouts, "other"), filepath.Join(checkouts, "relative")
	third, absolute := filepath.Join(checkouts, "third"), filepath.Join(checkouts, "absolute")
	for _, dir := range []string{filepath.Join(repo, ".git"), sub, filepath.Join(main, ".git", "worktrees", "wt"), worktree, filepath.Join(other, ".git", "worktrees", "wt"), relative,
		filepath.Join(third, ".git", "worktrees", "wt"), absolute} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write(t, filepath.Join(worktree, ".git"), "gitdir: "+filepath.Join(main, ".git", "worktrees", "wt")+"\n")
	write(t, filepath.Join(main, ".git", "worktrees", "wt", "commondir"), "../..\n")
	write(t, filepath.Join(relative, ".git"), "gitdir: ../other/.git/worktrees/wt\n")
	write(t, filepath.Join(other, ".git", "worktrees", "wt", "commondir"), "../..\n")
	write(t, filepath.Join(absolute, ".git"), "gitdir: "+filepath.Join(third, ".git", "worktrees", "wt")+"\n")
	write(t, filepath.Join(third, ".git", "worktrees", "wt", "commondir"), filepath.Join(third, ".git")+"\n")
	// A submodule's git dir is in its superproject's, with no commondir.
	super := t.TempDir()
	module := filepath.Join(super, "lib")
	for _, dir := range []string{filepath.Join(super, ".git", "modules", "lib"), filepath.Join(module, "src")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write(t, filepath.Join(module, ".git"), "gitdir: ../.git/modules/lib\n")

	files := mcpconfig.AgentFiles(home, workdir, []string{home, workdir, sub, worktree, relative, absolute, filepath.Join(module, "src")})
	got := map[string]string{}
	for _, f := range files {
		if _, twice := got[f.Path]; twice {
			t.Errorf("%s is named twice", f.Path)
		}
		got[f.Path] = f.Project
	}
	for path, project := range map[string]string{
		filepath.Join(home, ".claude", "settings.json"):               "",
		filepath.Join(home, ".claude", "settings.local.json"):         "",
		filepath.Join(home, ".claude", "CLAUDE.md"):                   "",
		filepath.Join(home, ".codex", "config.toml"):                  "",
		filepath.Join(home, ".codex", "AGENTS.md"):                    "",
		filepath.Join(home, ".codex", "AGENTS.override.md"):           "",
		filepath.Join(home, ".copilot", "copilot-instructions.md"):    "",
		filepath.Join(home, ".gemini", "GEMINI.md"):                   "",
		filepath.Join(home, "CLAUDE.md"):                              home,
		filepath.Join(workdir, ".claude", "settings.json"):            "",
		filepath.Join(workdir, ".claude", "settings.local.json"):      "",
		filepath.Join(workdir, "CLAUDE.md"):                           "",
		filepath.Join(workdir, ".claude", "CLAUDE.md"):                "",
		filepath.Join(workdir, "CLAUDE.local.md"):                     "",
		filepath.Join(workdir, "AGENTS.md"):                           "",
		filepath.Join(workdir, "AGENTS.override.md"):                  "",
		filepath.Join(workdir, ".github", "copilot-instructions.md"):  "",
		filepath.Join(sub, ".claude", "settings.local.json"):          sub,
		filepath.Join(repo, ".claude", "settings.local.json"):         sub,
		filepath.Join(worktree, ".claude", "settings.local.json"):     worktree,
		filepath.Join(main, ".claude", "settings.local.json"):         worktree,
		filepath.Join(other, ".claude", "settings.local.json"):        relative,
		filepath.Join(third, ".claude", "settings.local.json"):        absolute,
		filepath.Join(module, ".claude", "settings.local.json"):       filepath.Join(module, "src"),
		filepath.Join(worktree, ".github", "copilot-instructions.md"): worktree,
	} {
		if p, ok := got[path]; !ok || p != project {
			t.Errorf("%s: named %v, in project %q, want %q", path, ok, p, project)
		}
	}
	if _, ok := got[filepath.Join(repo, "CLAUDE.md")]; ok {
		t.Errorf("a project's instructions are read only in its folder")
	}
	for _, f := range mcpconfig.AgentFiles(home, "", nil) {
		if !strings.HasPrefix(f.Path, home+string(filepath.Separator)) {
			t.Errorf("without a working folder, %s is named", f.Path)
		}
	}
}

// A personal file, local settings or instructions or an agent's login in home,
// is one a repository should not track, and only one in a work tree can be.
func TestPersonalFilesAreThoseAWorkTreeCanTrack(t *testing.T) {
	home, repo, plain := t.TempDir(), t.TempDir(), t.TempDir()
	for _, dir := range []string{home, repo} {
		if err := os.Mkdir(filepath.Join(dir, ".git"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	got := mcpconfig.Personal(home, mcpconfig.AgentFiles(home, plain, []string{repo}))
	want := []string{
		filepath.Join(home, ".claude", ".credentials.json"), filepath.Join(home, ".codex", "auth.json"), filepath.Join(home, ".claude", "settings.local.json"),
		filepath.Join(repo, ".claude", "settings.local.json"), filepath.Join(repo, "CLAUDE.local.md"),
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("Personal = %q, want %q", got, want)
	}
}

// Claude Code's projects are the folders its config names that still exist.
func TestClaudeProjectsAreTheFoldersThatStillExist(t *testing.T) {
	home, here := t.TempDir(), t.TempDir()
	gone := filepath.Join(here, "removed-worktree")
	write(t, filepath.Join(home, ".claude.json"), `{"projects": {"`+here+`": {}, "`+gone+`": {}}}`)
	if got := mcpconfig.ClaudeProjects(home); !slices.Equal(got, []string{here}) {
		t.Errorf("ClaudeProjects = %v, want %v", got, []string{here})
	}
}

// A value in a Claude Code settings file's env is judged as an MCP server's is,
// and the fix depends on who reads it. Claude Code reads its own variables itself
// and resolves no reference, so they come out or move to its helper, if one is
// for them; it passes any other to the commands it starts, where keyward run
// resolves a reference. Its project and local settings set no OAuth token or
// OpenTelemetry headers. A reference it passes on must resolve.
func TestAClaudeSettingsEnvValueIsJudgedByWhoReadsIt(t *testing.T) {
	const env = `{"env": {
		"GITHUB_TOKEN": "` + agentToken + `",
		"BUILD_SEED": "` + randomValue + `",
		"ANTHROPIC_API_KEY": "sk-ant-api03-FakeSettingsKey000000000000000",
		"OTEL_EXPORTER_OTLP_HEADERS": "x-honeycomb-team=` + randomValue + `",
		"AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"CLAUDE_CODE_OAUTH_TOKEN": "sk-ant-oat01-FakeOAuthToken0000000000000000",
		"HTTPS_PROXY": "http://proxyuser:` + urlPassword + `@proxy.example.com:8080",
		"LINEAR_API_KEY": "<your-linear-api-key>",
		"PD_KEY": "cap://pagerduty-key",
		"WEBHOOK": "https://hooks.example.com/services/T000/B000/` + agentToken + `",
		"SVC_URL": "https://api.example.com/v1?token=` + agentToken + `",
		"ANTHROPIC_MODEL": "global.anthropic.claude-opus-4-5-20251101-v1:0",
		"ANTHROPIC_DEFAULT_SONNET_MODEL": "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
		"OTEL_RESOURCE_ATTRIBUTES": "department=engineering,team.id=platform,cost_center=eng-123",
		"EDITOR": "nvim"}}`
	found, passed := read(t, filepath.Join(".claude", "settings.json"), env)
	fixes := map[string]string{}
	for _, l := range found {
		fixes[l.Field] = l.Fix
	}
	const passes = "store it with keyward add NAME and set it to cap://NAME, which only keyward run resolves and keyward uninstall does not change back"
	const own = "Claude Code reads this itself; remove it if nothing needs it"
	const noMask = " (a helper using keyward run needs --no-mask)"
	for field, want := range map[string]string{
		"env.GITHUB_TOKEN":               passes,
		"env.BUILD_SEED":                 passes,
		"env.WEBHOOK":                    passes,
		"env.SVC_URL":                    passes,
		"env.ANTHROPIC_API_KEY":          own + ", or have apiKeyHelper print it" + noMask,
		"env.OTEL_EXPORTER_OTLP_HEADERS": "remove it, as Claude Code 2.1.282 and later ignore it in project and local settings",
		"env.AWS_SECRET_ACCESS_KEY":      "Claude Code reads this itself for Bedrock, so have awsCredentialExport print the credentials" + noMask + "; if only the commands it starts need it, " + passes,
		"env.CLAUDE_CODE_OAUTH_TOKEN":    "remove it, as Claude Code ignores it in project and local settings",
		"env.HTTPS_PROXY":                own,
	} {
		if got, ok := fixes[field]; !ok || got != want {
			t.Errorf("%s: found %v, fix\n%q\nwant\n%q", field, ok, got, want)
		}
	}
	if len(found) != 9 {
		t.Errorf("found %d, want 9: a placeholder, a reference, an editor and settings of Claude Code's own hold none", len(found))
	}
	if !slices.Equal(passed, []string{"cap://pagerduty-key"}) {
		t.Errorf("passed = %v, want the reference in env", passed)
	}

	// In the user's own settings, Claude Code reads every variable it reads itself.
	// Those local to home are a project's, as Claude Code keeps them there for one
	// whose repository is home.
	home := t.TempDir()
	user, local := filepath.Join(home, ".claude", "settings.json"), filepath.Join(home, ".claude", "settings.local.json")
	fixes = map[string]string{}
	for _, f := range mcpconfig.AgentFiles(home, "", nil) {
		if f.Path == user || f.Path == local {
			found, _, err := f.Read([]byte(env))
			if err != nil {
				t.Fatal(err)
			}
			for _, l := range found {
				fixes[filepath.Base(l.File)+" "+l.Field] = l.Fix
			}
		}
	}
	for field, want := range map[string]string{
		"settings.json env.OTEL_EXPORTER_OTLP_HEADERS":    own + ", or, for HTTP protocols, have otelHeadersHelper print the headers" + noMask,
		"settings.json env.CLAUDE_CODE_OAUTH_TOKEN":       own,
		"settings.local.json env.CLAUDE_CODE_OAUTH_TOKEN": "remove it, as Claude Code ignores it in project and local settings",
	} {
		if got := fixes[field]; got != want {
			t.Errorf("%s: fix %q, want %q", field, got, want)
		}
	}
}

// Each variable Claude Code reads itself gets the fix for it, by its exact name,
// as macOS names are case-sensitive, but for a proxy, which it also reads in
// lowercase: one it reads from a helper names that helper, one its project and
// local settings cannot set comes out, and one it reads only as written is
// removed. Any other is passed to the commands it starts.
func TestEachOfClaudeCodesOwnVariablesGetsItsFix(t *testing.T) {
	const (
		own     = "Claude Code reads this itself; remove it if nothing needs it"
		noMask  = " (a helper using keyward run needs --no-mask)"
		apiKey  = own + ", or have apiKeyHelper print it" + noMask
		ignored = "remove it, as Claude Code ignores it in project and local settings"
		otlp    = "remove it, as Claude Code 2.1.282 and later ignore it in project and local settings"
		aws     = "Claude Code reads this itself for Bedrock, so have awsCredentialExport print the credentials" + noMask + "; if only the commands it starts need it, "
		passes  = "store it with keyward add NAME and set it to cap://NAME, which only keyward run resolves and keyward uninstall does not change back"
	)
	for name, want := range map[string]string{
		"ANTHROPIC_API_KEY":               apiKey,
		"ANTHROPIC_AUTH_TOKEN":            apiKey,
		"CLAUDE_CODE_OAUTH_TOKEN":         ignored,
		"CLAUDE_CODE_OAUTH_REFRESH_TOKEN": ignored,
		"OTEL_EXPORTER_OTLP_HEADERS":      otlp,
		"OTEL_EXPORTER_OTLP_LOGS_HEADERS": otlp,
		"AWS_ACCESS_KEY_ID":               aws + passes,
		"AWS_SECRET_ACCESS_KEY":           aws + passes,
		"AWS_SESSION_TOKEN":               aws + passes,
		"AWS_BEARER_TOKEN_BEDROCK":        own,
		"CLOUD_ML_TOKEN":                  own,
		"OTEL_SERVICE_TOKEN":              own,
		"HTTP_PROXY":                      own,
		"HTTPS_PROXY":                     own,
		"NO_PROXY":                        own,
		"https_proxy":                     own,
		"anthropic_api_key":               passes,
		"otel_exporter_otlp_headers":      passes,
		"GITHUB_TOKEN":                    passes,
	} {
		value := agentToken
		if strings.HasSuffix(name, "HEADERS") {
			value = "Authorization=Bearer%20" + agentToken
		}
		b, _ := json.Marshal(map[string]any{"env": map[string]string{name: value}})
		found, _ := read(t, filepath.Join(".claude", "settings.json"), string(b))
		if len(found) != 1 || found[0].Fix != want {
			t.Errorf("%s: found %+v, want the fix %q", name, found, want)
		}
	}
}

// A variable that lists headers, as OpenTelemetry's exporter headers and
// ANTHROPIC_CUSTOM_HEADERS do, is judged a header at a time, as an MCP server's
// headers are, so a token in one is of its shape, and a header that holds none,
// or a placeholder, is no credential however the list looks.
func TestAHeaderListIsJudgedAHeaderAtATime(t *testing.T) {
	found, _ := read(t, filepath.Join(".claude", "settings.json"), `{"env": {
		"OTEL_EXPORTER_OTLP_HEADERS": "x-tenant=platform-team,Authorization=Bearer%20`+agentToken+`",
		"OTEL_EXPORTER_OTLP_LOGS_HEADERS": "X-Scope-OrgID=platform-team",
		"OTEL_EXPORTER_OTLP_METRICS_HEADERS": "x-honeycomb-team=`+randomValue+`",
		"OTEL_EXPORTER_OTLP_TRACES_HEADERS": "Authorization=Bearer%20xxx",
		"ANTHROPIC_CUSTOM_HEADERS": "X-Org-Id: org-7f3a9c2e1b4d\nX-Api-Key: 4f8a2c9e1b7d3e6f0a5c9d2e7f1a4b8c"}}`)
	want := map[string]bool{"env.OTEL_EXPORTER_OTLP_HEADERS": true, "env.OTEL_EXPORTER_OTLP_METRICS_HEADERS": false, "env.ANTHROPIC_CUSTOM_HEADERS": false}
	if got := fields(found); !maps.Equal(got, want) {
		t.Errorf("found %v, want %v", got, want)
	}
	for _, l := range found {
		if want := "Claude Code reads this itself; remove it if nothing needs it"; l.Field == "env.ANTHROPIC_CUSTOM_HEADERS" && l.Fix != want {
			t.Errorf("%s: fix %q, want %q", l.Field, l.Fix, want)
		}
	}
}

// The command a saved permission rule names is judged where a credential starts
// a word, in a URL or after Bearer, and where its own option or name marks a
// password, which looks no more random than a word: after mysql's -p or sshpass's
// -p, in curl's login, or set in a variable named for one, at any length, in it
// or in a script it runs, as sh -c and ssh take one. Only a secret counts, never
// randomness, nor a placeholder or an expansion. The rule is named by its list
// and place, never its text.
func TestASavedPermissionRuleIsJudgedByItsCommand(t *testing.T) {
	for _, tc := range []struct {
		rule         string
		found, known bool
	}{
		{"Bash(psql postgresql://app:" + dbPass + "@db.internal:5432/payments -c 'select 1')", true, true},
		{"Bash(PGPASSWORD=" + dbPass + " psql -h db.internal -U app payments)", true, false},
		{"Bash(sshpass -p " + sshPass + " ssh deploy@web01)", true, false},
		{"Bash(/usr/bin/sshpass -p " + sshPass + " ssh deploy@web01)", true, false},
		{"Bash(sshpass -p" + sshPass + " ssh deploy@web01)", true, false},
		{"Bash(sshpass -p " + sshPass + " ssh deploy@web01 \"uptime", true, false},
		{"Bash(mysql -u root -p" + dbPass + " payments)", true, false},
		{"Bash(mariadb -u root -p" + dbPass + " payments)", true, false},
		{"Bash(cd /srv && sudo -u postgres mysqldump --password=" + sshPass + " ledger > /tmp/ledger.sql)", true, false},
		{`Bash(curl -H "Authorization: Bearer ` + opaqueToken + `" https://api.example.com/v1/charges)`, true, true},
		{"Bash(curl -u deploy:" + dbPass + " https://ci.example.com/job/build)", true, false},
		{"Bash(/usr/bin/curl -u deploy:" + dbPass + " https://ci.example.com/job/build)", true, false},
		{"Bash(curl --user deploy:" + dbPass + " https://ci.example.com)", true, false},
		{"Bash(curl --user=deploy:" + dbPass + " https://ci.example.com)", true, false},
		{"Bash(curl -udeploy:" + dbPass + " https://ci.example.com)", true, false},
		{"Bash(GH_TOKEN=" + agentToken + " gh pr list:*)", true, true},
		{"Bash(GH_TOKEN=" + agentToken + " ./sync --key=sk-abcdefghijklmnopqrstu)", true, true},
		{"PowerShell($env:GH_TOKEN='" + agentToken + "'; gh pr list)", true, true},
		{"Bash(sh -c 'curl -u admin:" + dbPass + " https://jenkins.example.com/api/json')", true, false},
		{"Bash(docker exec db sh -c 'mysql -uroot -p" + dbPass + " app')", true, false},
		{"Bash(ssh deploy@web01 \"mysql -uroot -p" + dbPass + " -e 'show databases'\")", true, false},
		{"Bash(npm run test:*)", false, false},
		{"Bash(git log --format=%H " + "3f9a2b7c1d8e4f6a0b5c9d2e7f1a4b8c3d6e9f02)", false, false},
		{"Bash(mysql -p payments)", false, false},
		{`Bash(mysql -u root -p"<password>" payments)`, false, false},
		{"Bash(PGPASSWORD=$DB_PASSWORD psql -h db.internal)", false, false},
		{"Bash(PGPASSWORD=cap://db-password psql -h db.internal)", false, false},
		{"Bash(curl -u deploy https://ci.example.com)", false, false},
		{"Bash(curl -u deploy: https://ci.example.com)", false, false},
		{"Bash(curl -u admin,ops https://ci.example.com)", false, false},
		{"Bash(curl -uadmin,ops https://ci.example.com)", false, false},
		{"Bash(curl --user=admin,ops https://ci.example.com)", false, false},
		{`Bash(curl -H "Authorization: Bearer <token>" https://api.example.com)`, false, false},
		{"Bash(docker run -u 1000:1000 alpine)", false, false},
		{"Bash(docker run -u1000:1000 alpine)", false, false},
		{"Bash(docker run -p8080:80 nginx)", false, false},
		{"Bash(sshpass -f ~/.ssh/pass ssh -p 2222 deploy@web01)", false, false},
		{"Bash(./tool --password=" + dbPass + ")", false, false},
		{"Bash(gh secret set TOKEN --body ghp_" + strings.Repeat("x", 36) + ":*)", false, false},
		{"Read(" + agentToken + ")", false, false},
	} {
		b, _ := json.Marshal(tc.rule)
		found, _ := read(t, filepath.Join(".claude", "settings.local.json"), `{"permissions": {"allow": [`+string(b)+`]}}`)
		if len(found) > 0 != tc.found || tc.found && found[0].KnownShape != tc.known {
			t.Errorf("%s: found %+v, want a secret %v, of a known shape %v", tc.rule, found, tc.found, tc.known)
		}
	}

	rule, _ := json.Marshal("Bash(PGPASSWORD=" + dbPass + " psql -h db.internal)")
	found, _ := read(t, filepath.Join(".claude", "settings.json"),
		`{"permissions": {"allow": ["Bash(npm test)", `+string(rule)+`], "ask": [`+string(rule)+`], "deny": [`+string(rule)+`]}}`)
	var got []string
	for _, l := range found {
		got = append(got, l.Field)
		if want := "remove the rule with /permissions in Claude Code; a command that reads the secret through keyward run saves none"; l.Fix != want {
			t.Errorf("%s: fix %q, want %q", l.Field, l.Fix, want)
		}
		if strings.Contains(l.Field+l.Reason+l.Fix, dbPass) {
			t.Errorf("%s holds a value", l.Field)
		}
	}
	if want := []string{"permissions.allow[1]", "permissions.ask[0]", "permissions.deny[0]"}; !slices.Equal(got, want) {
		t.Errorf("found %q, want %q", got, want)
	}
}

// After Bearer, only a token counts: not a placeholder, nor the format of
// keyward's own printf pattern. A variable named like a credential is judged as
// Detect judges a shell file's, so a path, a URL, a count or a flag holds none,
// but one named for a password counts at any length, as a person chooses one. A
// curl header is judged by its name, as an MCP server's is.
func TestARuleIsJudgedByWhatItsCommandSets(t *testing.T) {
	for rule, want := range map[string]bool{
		`Bash(API_TOKEN=cap://api-token keyward run --only API_TOKEN -- sh -c 'printf "header = \"Authorization: Bearer %s\"\n" "$API_TOKEN" | curl -sS -K - "$1"' _ "$URL")`: false,
		`Bash(curl -H "Authorization: Bearer TOKEN" https://api.example.com)`:                                                                                                 false,
		`Bash(curl -H "Authorization: Bearer YOUR_TOKEN" https://api.example.com)`:                                                                                            false,
		`Bash(curl -H "Authorization: Bearer {token}" https://api.example.com)`:                                                                                               false,
		`Bash(curl -H "Authorization: Bearer xxx" https://api.example.com)`:                                                                                                   false,
		`Bash(AUTH_HEADER="Bearer TOKEN" ./call.sh)`:                                                                                                                          false,
		`Bash(curl -H "X-Api-Key: $API_KEY" https://api.example.com)`:                                                                                                         false,
		`Bash(curl -H "X-Api-Key: <your-api-key>" https://api.example.com)`:                                                                                                   false,
		"Bash(GOOGLE_APPLICATION_CREDENTIALS=/path/sa.json gcloud auth list)":                                                                                                 false,
		"Bash(AWS_SHARED_CREDENTIALS_FILE=~/.aws/credentials aws s3 ls)":                                                                                                      false,
		"Bash(SSH_KEY_PATH=~/.ssh/id_ed25519 ./deploy.sh)":                                                                                                                    false,
		"Bash(GIT_AUTHOR_NAME=Bot git commit -m wip)":                                                                                                                         false,
		"Bash(DISABLE_AUTH=1 SKIP_AUTH=true npm start)":                                                                                                                       false,
		"Bash(MAX_THINKING_TOKENS=10000 CLAUDE_CODE_MAX_OUTPUT_TOKENS=64000 claude -p hi)":                                                                                    false,
		"Bash(API_KEY_FILE=key.txt TOKEN_URL=https://auth.example.com/token OAUTH_CALLBACK_PORT=8080 ./login.sh)":                                                             false,
		"Bash(export AUTHOR=x)": false,
		"Bash(REQUIRE_PASSWORD=1 DB_PASSWORD=/run/secrets/db ./serve)":                              false,
		"Bash(docker run -d -e MYSQL_ALLOW_EMPTY_PASSWORD=yes -p 3306:3306 mysql:8)":                false,
		"Bash(MYSQL_RANDOM_ROOT_PASSWORD=YES ALLOW_EMPTY_PASSWORD=True DISABLE_PASSWORD=true ./db)": false,
		"Bash(USE_PW=false TESTS_PASS=on PGPASSWORD=none NO_PASS=off REQUIRE_PWD=no ./test)":        false,
		"Bash(PASSWORD_POLICY=strict ./signup)":                                                     false,
		"Bash(PASS=" + dbPass + " ./login)":                                                         true,
		"Bash(DB_PW=" + dbPass + " ./login)":                                                        true,
		"Bash(DB_PASSWD=" + dbPass + " ./login)":                                                    true,
		"Bash(KEY_PASSPHRASE=" + dbPass + " ./sign)":                                                true,
		"Bash(db_password=" + dbPass + " ./login)":                                                  true,
		"Bash(PGPASSWORD=`cat ~/.pgpass` psql -h db.internal)":                                      false,
		"Bash(MYSQL_PWD=" + dbPass + " mysql -u root)":                                              true,
		"Bash(GH_TOKEN=" + namedValue + " gh pr list)":                                              true,
		`Bash(curl -H "X-Api-Key: ` + randomValue + `" https://api.example.com)`:                    true,
		`Bash(curl --header "Authorization: token ` + randomValue + `" https://api.example.com)`:    true,
	} {
		b, _ := json.Marshal(rule)
		found, _ := read(t, filepath.Join(".claude", "settings.local.json"), `{"permissions": {"allow": [`+string(b)+`]}}`)
		if got := len(found) > 0; got != want {
			t.Errorf("%s: found %+v, want a secret %v", rule, found, want)
		}
	}
}

// A command Claude Code runs from its settings, as a helper, a hook or the status
// line, is judged as a rule's is, by what it holds rather than by its key's name,
// which says it makes a credential. Any other key is judged as a key keyward keeps
// in a server is, by its name, a header's as a variable's, and as an argument, a
// secret only. An HTTP hook's header can read a variable instead, and one that
// does holds no value.
func TestAClaudeSettingsCommandIsJudgedByWhatItHolds(t *testing.T) {
	found, _ := read(t, filepath.Join(".claude", "settings.json"), `{
		"apiKeyHelper": "echo `+agentToken+`",
		"awsAuthRefresh": "aws sso login --profile myprofile",
		"awsCredentialExport": "curl -u deploy:`+dbPass+` https://creds.example.com",
		"gcpAuthRefresh": "gcloud auth application-default login",
		"otelHeadersHelper": "MYSQL_PWD=`+dbPass+` ~/bin/otel-headers.sh",
		"apiToken": "`+randomValue+`",
		"statusLine": {"type": "command", "command": "~/.claude/statusline.sh"},
		"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
			{"type": "command", "command": "~/.claude/hooks/check.sh"},
			{"type": "command", "command": "SLACK_TOKEN=`+agentToken+` ~/.claude/hooks/notify.sh"},
			{"type": "http", "url": "https://hooks.example.com/claude", "headers": {"X-Api-Key": "`+namedValue+`", "X-Backup-Api-Key": "<your-api-key>", "X-Trace": "token=`+agentToken+`", "X-Env-Key": "Bearer $API_TOKEN"}}]}]},
		"forceLoginOrgUUID": "3f2a9c1e-7b4d-4e8f-9a6b-2c1d0e5f7a8b",
		"companyAnnouncements": ["Welcome to `+randomValue+`"]}`)
	fixes := map[string]string{}
	for _, l := range found {
		fixes[l.Field] = l.Fix
	}
	const printed = "remove it with Claude Code closed, or have the command read it through keyward run --no-mask"
	const header = "Claude Code sends this as written; remove it with Claude Code closed if nothing needs it, or write $VAR in its place and add VAR to allowedEnvVars, " +
		"which Claude Code reads from its own environment, where cap:// does not work"
	want := map[string]string{
		"apiKeyHelper":                                   printed,
		"awsCredentialExport":                            printed,
		"otelHeadersHelper":                              printed,
		"hooks.PreToolUse[0].hooks[1].command":           "remove it with Claude Code closed, or have the command read it through keyward run",
		"hooks.PreToolUse[0].hooks[2].headers.X-Api-Key": header,
		"hooks.PreToolUse[0].hooks[2].headers.X-Trace":   header,
		"apiToken": "Claude Code reads this itself; remove it with Claude Code closed if nothing needs it",
	}
	if len(fixes) != len(want) {
		t.Errorf("found %v, want %v", fixes, want)
	}
	for field, fix := range want {
		if fixes[field] != fix {
			t.Errorf("%s: fix %q, want %q", field, fixes[field], fix)
		}
	}
}

// Codex's config outside its MCP servers is judged as a key keyward keeps is, a
// secret only, with the form, if any, that reads the value from a variable: none
// for OpenTelemetry's static headers or a provider's query, env_http_headers for
// its header, and env_key or auth.command for its token. notify is a command
// Codex runs. A key that names a variable or holds prose about one holds no
// value. shell_environment_policy.set is the env of the commands Codex starts,
// judged and fixed as Claude Code's settings env is, and a reference in it is
// passed on.
func TestCodexConfigOutsideItsServersIsJudgedAsKeptKeys(t *testing.T) {
	found, passed := read(t, filepath.Join(".codex", "config.toml"), `model = "gpt-5"
notify = ["curl", "-H", "Authorization: Bearer `+agentToken+`", "https://hooks.example.com/codex"]

[otel]
exporter = { otlp-http = {
  endpoint = "https://otel.example.com/v1/logs",
  protocol = "binary",
  headers = { "x-otlp-api-key" = "`+namedValue+`" }
}}

[model_providers.corp]
base_url = "https://llm.example.com/v1"
env_key = "CORP_LLM_API_KEY"
env_key_instructions = "Set CORP_LLM_API_KEY to the key from the corporate secrets portal"
http_headers.X-Team-Key = "`+namedValue+`"
experimental_bearer_token = "`+agentToken+`"
env_http_headers = { "X-Org-Token" = "CORP_ORG_TOKEN_VARIABLE" }
query_params = { "api-version" = "2025-04-01-preview", key = "`+agentToken+`" }

[model_providers.other]
http_headers = { Authorization = "Bearer `+opaqueToken+`" }

[model_providers.other.env_http_headers]
"X-Other-Token" = "OTHER_ORG_TOKEN_VARIABLE"

[model_providers.third]
http_headers = { note = 'a, b', quote = "a\", b", authorization = "Bearer `+opaqueToken+`" }

[shell_environment_policy]
include_only = ["PATH", "HOME", "GITHUB_PERSONAL_ACCESS_TOKEN"]
set = { BUILD_SEED = "`+randomValue+`", PD_KEY = "cap://pagerduty-key", CI = "1", LINEAR_API_KEY = "<your-linear-api-key>" }

[mcp_servers.github]
url = "https://api.example.com/mcp/"
http_headers = { Authorization = "Bearer `+agentToken+`" }
`)
	fixes := map[string]string{}
	for _, l := range found {
		fixes[l.Field] = l.Fix
	}
	const asWritten = "Codex sends this as written; remove it if nothing needs it"
	const ownEnvironment = "which Codex reads from its own environment, where cap:// does not work"
	const token = asWritten + ", or name a variable that holds the key with env_key, " + ownEnvironment +
		", or have auth.command print the token (a command using keyward run needs --no-mask)"
	want := map[string]string{
		"notify[2]": "Codex runs this as a command; remove it if nothing needs it, or have the command read it through keyward run",
		"otel.exporter.otlp-http.headers.x-otlp-api-key":   asWritten,
		"model_providers.corp.http_headers.X-Team-Key":     asWritten + `, or name a variable that holds it with env_http_headers = { "X-Team-Key" = "VAR" }, ` + ownEnvironment,
		"model_providers.corp.experimental_bearer_token":   token,
		"model_providers.other.http_headers.Authorization": token,
		"model_providers.third.http_headers.authorization": token,
		"model_providers.corp.query_params.key":            "Codex reads this itself; remove it if nothing needs it",
		"shell_environment_policy.set.BUILD_SEED":          "store it with keyward add NAME and set it to cap://NAME, which only keyward run resolves and keyward uninstall does not change back",
	}
	if len(fixes) != len(want) {
		t.Errorf("found %v, want %v", fixes, want)
	}
	for field, fix := range want {
		if fixes[field] != fix {
			t.Errorf("%s: fix %q, want %q", field, fixes[field], fix)
		}
	}
	if !slices.Equal(passed, []string{"cap://pagerduty-key"}) {
		t.Errorf("passed = %v, want the reference in set", passed)
	}
}

// An agent's instructions are read a line at a time for what is surely a
// credential, in markdown too, of a known shape or not. A reference there is an
// example, and holds none.
func TestInstructionsAreReadForSureCredentialsByLine(t *testing.T) {
	found, passed := read(t, "CLAUDE.md", "# Project\n\nStore it with `keyward add NAME`, as `cap://name`.\n"+
		"Use the token **"+agentToken+"** for the API.\n"+
		"Commit 3f9a2b7c1d8e4f6a0b5c9d2e7f1a4b8c3d6e9f02 fixed it.\n"+
		"export DB_PASSWORD=Secret-Horse-Battery\n")
	if got := fields(found); !maps.Equal(got, map[string]bool{"line 4": true, "line 6": false}) || found[0].Reason != "a GitHub token" || found[0].Fix != "" {
		t.Errorf("found %+v, want line 4's GitHub token and line 6's password", found)
	}
	if len(passed) != 0 {
		t.Errorf("passed = %v, want none", passed)
	}
}

// A settings file that is not JSON, or a config that is not TOML, went unchecked,
// which Read says. An empty one sets nothing.
func TestAnAgentFileThatDoesNotParseIsAnError(t *testing.T) {
	for name, content := range map[string]string{filepath.Join(".claude", "settings.json"): `{"env": {`, filepath.Join(".codex", "config.toml"): "model = \"gpt-5\n"} {
		if _, _, err := (mcpconfig.AgentFile{Path: name}).Read([]byte(content)); err == nil {
			t.Errorf("%s read without an error", name)
		}
	}
	for _, content := range []string{"", " \n"} {
		if found, _, err := (mcpconfig.AgentFile{Path: filepath.Join(".claude", "settings.local.json")}).Read([]byte(content)); err != nil || len(found) != 0 {
			t.Errorf("an empty settings file: found %v, error %v", found, err)
		}
	}
}

// Only a credential its agent reads itself is one keyward cannot hold: in Claude
// Code's settings, a variable of its own, as a proxy is, or a key it reads as
// written, and in Codex's config, its OpenTelemetry headers or a key it reads
// as written. One passed to the commands an agent starts, an AWS key, which
// awsCredentialExport can print, one in a command, a rule or instructions, one
// Claude Code ignores, and a header either agent can read from a variable
// instead, keyward can.
func TestOnlyWhatAnAgentReadsItselfIsUnholdable(t *testing.T) {
	home := t.TempDir()
	user, local := filepath.Join(home, ".claude", "settings.json"), filepath.Join(home, ".claude", "settings.local.json")
	const settings = `{"env": {
		"OTEL_EXPORTER_OTLP_HEADERS": "Authorization=Bearer%20` + agentToken + `",
		"HTTPS_PROXY": "http://proxyuser:` + urlPassword + `@proxy.example.com:8080",
		"AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"GITHUB_TOKEN": "` + agentToken + `"},
		"apiToken": "` + agentToken + `",
		"apiKeyHelper": "echo ` + agentToken + `",
		"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "SLACK_TOKEN=` + agentToken + ` ~/notify.sh"},
			{"type": "http", "url": "https://hooks.example.com", "headers": {"Authorization": "Bearer ` + agentToken + `"}}]}]},
		"permissions": {"allow": ["Bash(GH_TOKEN=` + agentToken + ` gh pr list)"]}}`
	got := map[string]bool{}
	for _, f := range mcpconfig.AgentFiles(home, "", nil) {
		if f.Path == user || f.Path == local {
			found, _, err := f.Read([]byte(settings))
			if err != nil {
				t.Fatal(err)
			}
			for _, l := range found {
				got[filepath.Base(l.File)+" "+l.Field] = l.Unholdable
			}
		}
	}
	codex, _ := read(t, filepath.Join(".codex", "config.toml"), `notify = ["curl", "-H", "Authorization: Bearer `+agentToken+`", "https://hooks.example.com/codex"]

[otel]
exporter = { otlp-http = { endpoint = "https://otel.example.com", headers = { Authorization = "Bearer `+agentToken+`" } } }

[model_providers.corp]
http_headers.X-Team-Key = "`+namedValue+`"
experimental_bearer_token = "`+agentToken+`"
query_params = { key = "`+agentToken+`" }

[shell_environment_policy]
set = { GITHUB_TOKEN = "`+agentToken+`" }
`)
	instructions, _ := read(t, "AGENTS.md", "export GITHUB_TOKEN="+agentToken+"\n")
	for _, l := range append(codex, instructions...) {
		got[filepath.Base(l.File)+" "+l.Field] = l.Unholdable
	}
	want := map[string]bool{
		"settings.json env.OTEL_EXPORTER_OTLP_HEADERS":                     true,
		"settings.json env.HTTPS_PROXY":                                    true,
		"settings.json env.AWS_SECRET_ACCESS_KEY":                          false,
		"settings.json env.GITHUB_TOKEN":                                   false,
		"settings.json apiToken":                                           true,
		"settings.json apiKeyHelper":                                       false,
		"settings.json hooks.Stop[0].hooks[0].command":                     false,
		"settings.json hooks.Stop[0].hooks[1].headers.Authorization":       false,
		"settings.json permissions.allow[0]":                               false,
		"settings.local.json env.OTEL_EXPORTER_OTLP_HEADERS":               false,
		"settings.local.json env.HTTPS_PROXY":                              true,
		"settings.local.json env.AWS_SECRET_ACCESS_KEY":                    false,
		"settings.local.json env.GITHUB_TOKEN":                             false,
		"settings.local.json apiToken":                                     true,
		"settings.local.json apiKeyHelper":                                 false,
		"settings.local.json hooks.Stop[0].hooks[0].command":               false,
		"settings.local.json hooks.Stop[0].hooks[1].headers.Authorization": false,
		"settings.local.json permissions.allow[0]":                         false,
		"config.toml notify[2]":                                            false,
		"config.toml otel.exporter.otlp-http.headers.Authorization":        true,
		"config.toml model_providers.corp.http_headers.X-Team-Key":         false,
		"config.toml model_providers.corp.experimental_bearer_token":       false,
		"config.toml model_providers.corp.query_params.key":                true,
		"config.toml shell_environment_policy.set.GITHUB_TOKEN":            false,
		"AGENTS.md ": false,
	}
	if !maps.Equal(got, want) {
		t.Errorf("unholdable:\n%v\nwant\n%v", got, want)
	}
}
