package doctor_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/veilux-lab/keyward/internal/doctor"
	"github.com/veilux-lab/keyward/internal/mcpconfig"
	"github.com/veilux-lab/keyward/internal/migrate"
)

// Fake credentials in agents' files.
const (
	agentToken = "ghp_" + "FakeDoctorAgentToken0000000000000000"
	rulePass   = "hunter2"
)

// agentFiles writes files, each a path under root and its content, and returns
// the agents' files of home, workdir and projects.
func agentFiles(t *testing.T, home, workdir string, projects []string, files map[string]string) []mcpconfig.AgentFile {
	t.Helper()
	for path, content := range files {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		write(t, filepath.Dir(path), filepath.Base(path), content)
	}
	return mcpconfig.AgentFiles(home, workdir, projects)
}

// An agent's own files are read for what the agent makes of them, never as shell
// files: a settings file's env and saved rules, and an instruction file's lines.
// Those in home and this folder are listed as read, those of other Claude Code
// projects counted, one that does not parse or cannot be read is not read, and a
// missing one is not mentioned.
func TestAgentFilesAreReadAsTheAgentReadsThem(t *testing.T) {
	home, workdir, project := t.TempDir(), t.TempDir(), t.TempDir()
	settings := filepath.Join(home, ".claude", "settings.json")
	instructions := filepath.Join(workdir, "CLAUDE.md")
	local := filepath.Join(project, ".claude", "settings.local.json")
	broken := filepath.Join(workdir, ".claude", "settings.json")
	unreadable := filepath.Join(workdir, "AGENTS.md")
	agents := agentFiles(t, home, workdir, []string{project}, map[string]string{
		settings:                            `{"env": {"GITHUB_TOKEN": "` + agentToken + `"}}`,
		instructions:                        "# Notes\n\nexport GITHUB_TOKEN=" + agentToken + "\n",
		local:                               `{"permissions": {"allow": ["Bash(PGPASSWORD=` + rulePass + ` psql -h db.internal)"]}}`,
		filepath.Join(project, "AGENTS.md"): "Run the tests before committing.\n",
		broken:                              `{"env": {`,
		unreadable:                          "Run the tests before committing.\n",
	})
	if err := os.Chmod(unreadable, 0); err != nil {
		t.Fatal(err)
	}

	r, err := doctor.Run(store(t, nil), nil, nil, agents...)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !slices.Equal(r.Scanned, []string{settings, instructions}) || !slices.Equal(r.Absent, []string{broken, unreadable}) {
		t.Errorf("Scanned %v, Absent %v: want home's and this folder's files read, and the broken and unreadable ones not", r.Scanned, r.Absent)
	}
	if r.OtherProjects[project] != 2 || len(r.OtherProjects) != 1 {
		t.Errorf("OtherProjects = %v, want 2 files in %s", r.OtherProjects, project)
	}
	if len(r.Plaintext) != 0 || len(r.Unmovable) != 0 {
		t.Errorf("Plaintext %+v, Unmovable %+v: an agent's file is no shell file", r.Plaintext, r.Unmovable)
	}
	var got []string
	for _, a := range r.Agents {
		got = append(got, a.File+" "+a.Field+" "+strings.Repeat("+", a.Line))
	}
	if want := []string{settings + " env.GITHUB_TOKEN ", instructions + "  +++", local + " permissions.allow[0] "}; !slices.Equal(got, want) {
		t.Errorf("Agents = %q, want %q", got, want)
	}
	if problems := r.Problems(); !slices.Equal(problems, []string{"2 credential(s) in plaintext"}) {
		t.Errorf("Problems() = %v, want the two of a known shape", problems)
	}

	out := printed(r)
	if got := flat(r.Summary(doctor.Format{}, nil, nil)); got != "keyward doctor read "+settings+", "+instructions+" and 2 agent file(s) in 1 other Claude Code project(s) not read "+broken+", "+unreadable {
		t.Errorf("the summary does not say what it read: %s", got)
	}
	for _, value := range []string{agentToken, rulePass} {
		if strings.Contains(out, value) {
			t.Errorf("the report holds a value:\n%s", out)
		}
	}
	elsewhere := &doctor.Report{OtherProjects: map[string]int{project: 3}}
	if got := elsewhere.Summary(doctor.Format{}, nil, nil); got != "keyward doctor  read 3 agent file(s) in 1 other Claude Code project(s)\n" {
		t.Errorf("Summary = %q", got)
	}
}

// A reference in an agent's file marks a secret in use, but only one its
// settings have it pass to the commands it starts breaks one, missing or
// malformed: one in its instructions or saved rules is an example, or a command
// it may run. A file read shows a secret it no longer names unused.
func TestAReferenceInAnAgentsFileBreaksOnlyWhereItIsPassedOn(t *testing.T) {
	home, workdir := t.TempDir(), t.TempDir()
	instructions := filepath.Join(workdir, "AGENTS.md")
	agents := agentFiles(t, home, workdir, nil, map[string]string{
		instructions: "Write a reference as `cap://name`, or `cap://`, as for `cap://Alpha`.\n",
		filepath.Join(home, ".claude", "settings.json"): `{"env": {"PD_KEY": "cap://absent", "BAD": "cap://-bad"},
  "permissions": {"allow": ["Bash(GITHUB_TOKEN=cap://beta gh pr list)"]}}`,
	})

	r, err := doctor.Run(store(t, map[string]string{"alpha": "", "gamma": "", "delta": instructions + ":1"}), nil, nil, agents...)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !slices.Equal(r.Referenced, []string{"alpha"}) || len(r.Unknown) != 1 || r.Unknown[0].Name != "gamma" || len(r.Orphaned) != 1 || r.Orphaned[0].Name != "delta" {
		t.Errorf("Referenced %v, Unknown %v, Orphaned %v: want alpha in use, gamma unknown and delta unused", r.Referenced, names(r.Unknown), names(r.Orphaned))
	}
	if len(r.Dangling) != 1 || r.Dangling[0].Name != "absent" || len(r.Malformed) != 1 || r.Malformed[0].Name != "-bad" {
		t.Errorf("Dangling %+v, Malformed %+v: want only env's", r.Dangling, r.Malformed)
	}
}

// An agent's file is read once, under the first path that names it, as when
// CLAUDE.md links to AGENTS.md, and only as its agent reads it, though named as
// a file to check too.
func TestAnAgentsFileIsReadOnceAsItsAgentReadsIt(t *testing.T) {
	home, workdir := t.TempDir(), t.TempDir()
	settings, claude := filepath.Join(home, ".claude", "settings.json"), filepath.Join(workdir, "CLAUDE.md")
	agents := agentFiles(t, home, workdir, nil, map[string]string{
		settings:                            `{"env": {"GITHUB_TOKEN": "` + agentToken + `"}}`,
		filepath.Join(workdir, "AGENTS.md"): "export GITHUB_TOKEN=" + agentToken + "\n",
	})
	if err := os.MkdirAll(filepath.Join(workdir, ".github"), 0o755); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{claude: "AGENTS.md", filepath.Join(workdir, ".github", "copilot-instructions.md"): filepath.Join("..", "AGENTS.md")} {
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
	}

	for _, paths := range [][]string{nil, {claude, settings}} {
		r, err := doctor.Run(store(t, nil), paths, nil, agents...)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		var got []string
		for _, a := range r.Agents {
			got = append(got, a.File+" "+a.Field+" "+strings.Repeat("+", a.Line))
		}
		if want := []string{settings + " env.GITHUB_TOKEN ", claude + "  +"}; !slices.Equal(got, want) || len(r.Plaintext) != 0 || len(r.Unmovable) != 0 {
			t.Errorf("named %v: Agents = %q, Plaintext %+v, Unmovable %+v, want %q alone", paths, got, r.Plaintext, r.Unmovable, want)
		}
		if scanned := slices.Sorted(slices.Values(r.Scanned)); !slices.Equal(scanned, slices.Sorted(slices.Values([]string{settings, claude}))) {
			t.Errorf("named %v: Scanned = %v", paths, r.Scanned)
		}
		if problems := r.Problems(); !slices.Equal(problems, []string{"2 credential(s) in plaintext"}) {
			t.Errorf("named %v: Problems() = %v", paths, problems)
		}
	}
}

// A setting's credential is listed with its fix under it, as an MCP server's is,
// and one that only may be a credential is fixed if it is one. A line of
// instructions is removed by hand, and never marked as holding no secret, which
// only a shell or .env file can be.
func TestAnAgentsFileIsListedWithItsFix(t *testing.T) {
	home := t.TempDir()
	settings, instructions := filepath.Join(home, ".claude", "settings.json"), filepath.Join(home, ".claude", "CLAUDE.md")
	possible := migrate.Detection{Possible: true, Reason: "a random 36-character token"}
	known := migrate.Detection{Secret: true, KnownShape: true, Reason: "a GitHub token"}
	r := &doctor.Report{Scanned: []string{settings, instructions}, Agents: []mcpconfig.AgentLiteral{
		{File: settings, Field: "env.BUILD_SEED", Fix: "store it with keyward add NAME and set its value to cap://NAME", Detection: possible},
		{File: settings, Field: "permissions.allow[3]", Fix: "remove the rule with /permissions in Claude Code", Detection: known},
		{File: instructions, Line: 4, Detection: known},
	}}

	out := r.Render(doctor.Format{Home: home})
	for _, want := range []string{
		"~/.claude/settings.json agent permissions.allow[3] a GitHub token remove the rule with /permissions in Claude Code",
		"~/.claude/CLAUDE.md:4 edit instructions a GitHub token",
		"~/.claude/settings.json agent env.BUILD_SEED a random 36-character token if it is one, store it with keyward add NAME and set its value to cap://NAME",
	} {
		if !slices.Contains(rows(out), want) {
			t.Errorf("the report lacks the row %q:\n%s", want, out)
		}
	}
	if !strings.Contains(flat(out), "edit remove it in an editor") || strings.Contains(out, migrate.IgnoreMarker) {
		t.Errorf("a line of instructions is not removed by hand, or is advised to be marked:\n%s", out)
	}
}

// A credential of a known shape that its agent reads itself, which keyward cannot
// hold, has a section of its own after those in plaintext, in file order, each
// row's fix under it, and a check that needs attention but no problem, so doctor
// can pass. One that only may be a credential is listed with the others that may
// be.
func TestACredentialKeywardCannotHoldIsAWarning(t *testing.T) {
	home := t.TempDir()
	rc, codex, settings := filepath.Join(home, ".zshrc"), filepath.Join(home, ".codex", "config.toml"), filepath.Join(home, ".claude", "settings.json")
	bearer := migrate.Detection{Secret: true, KnownShape: true, Reason: "a bearer token"}
	r := &doctor.Report{Scanned: []string{rc, codex, settings},
		Plaintext: []doctor.Plaintext{{File: rc, Line: 2, Name: "GITHUB_TOKEN", Detection: migrate.Detection{Secret: true, KnownShape: true, Reason: "a GitHub token"}}},
		Agents: []mcpconfig.AgentLiteral{
			{File: settings, Field: "env.OTEL_EXPORTER_OTLP_HEADERS", Fix: "Claude Code reads this itself; remove it if nothing needs it", Unholdable: true, Detection: bearer},
			{File: codex, Field: "otel.exporter.otlp-http.headers.Authorization", Fix: "Codex sends this as written; remove it if nothing needs it", Unholdable: true, Detection: bearer},
			{File: settings, Field: "apiToken", Fix: "Claude Code reads this itself; remove it if nothing needs it", Unholdable: true,
				Detection: migrate.Detection{Secret: true, Reason: "the header name suggests a credential"}},
		}}

	out := r.Render(doctor.Format{Home: home})
	want := "! 2 credential(s) keyward can't hold\n" +
		"  ~/.codex/config.toml     agent  otel.exporter.otlp-http.headers.Authorization\n" +
		"                                  a bearer token\n" +
		"                                  Codex sends this as written; remove it if nothing needs it\n" +
		"  ~/.claude/settings.json  agent  env.OTEL_EXPORTER_OTLP_HEADERS\n" +
		"                                  a bearer token\n" +
		"                                  Claude Code reads this itself; remove it if nothing needs it\n" +
		"\n" +
		"  Fix these yourself, not with an AI agent.\n\n"
	if got := section(out, "! 2 credential(s) keyward can't hold"); got != want {
		t.Errorf("the section reads\n%s\nwant\n%s", got, want)
	}
	if certain, held, possible := strings.Index(out, "✗ 1 credential(s) in plaintext"), strings.Index(out, "! 2 credential(s)"), strings.Index(out, "! 1 value(s)"); certain < 0 || held < certain || possible < held {
		t.Errorf("the sections are out of order:\n%s", out)
	}
	if want := "~/.claude/settings.json agent apiToken the header name suggests a credential if it is one, Claude Code reads this itself; remove it if nothing needs it"; !strings.Contains(flat(section(out, "! 1 value(s)")), want) {
		t.Errorf("the values that may be credentials lack %q:\n%s", want, out)
	}
	known := func(r *doctor.Report) []doctor.Check {
		return slices.DeleteFunc(r.Checks(), func(c doctor.Check) bool { return c.Label != "Known secrets" })
	}
	if problems, checks := r.Problems(), known(r); !slices.Equal(problems, []string{"1 credential(s) in plaintext"}) || !slices.Equal(checks, []doctor.Check{
		{Status: doctor.Fail, Label: "Known secrets", Text: "1 credential(s) in plaintext, listed above"},
		{Status: doctor.Attention, Label: "Known secrets", Text: "2 credential(s) keyward can't hold, listed above"},
	}) {
		t.Errorf("Problems() = %v, checks %+v", problems, checks)
	}

	r.Plaintext = nil
	if problems, checks := r.Problems(), known(r); len(problems) != 0 || !slices.Equal(checks, []doctor.Check{
		{Status: doctor.Attention, Label: "Known secrets", Text: "2 credential(s) keyward can't hold, listed above"},
	}) {
		t.Errorf("without a credential in plaintext: Problems() = %v, checks %+v", problems, checks)
	}
}

// A personal file git tracks has a section of its own, which says how to stop.
func TestTrackedPersonalFilesHaveASectionOfTheirOwn(t *testing.T) {
	home := t.TempDir()
	out := doctor.Format{Home: home}.Tracked([]string{filepath.Join(home, "app", ".claude", "settings.local.json"), filepath.Join(home, "app", "CLAUDE.local.md")})
	want := "! 2 personal file(s) git tracks\n" +
		"  ~/app/.claude/settings.local.json\n" +
		"  ~/app/CLAUDE.local.md\n" +
		"\n" +
		"  git tracks each, so a push publishes it: run git rm --cached FILE in its folder, and add FILE to\n" +
		"  the repository's .gitignore. Its earlier commits keep it, so if one was pushed, rotate any\n" +
		"  credential it held.\n"
	if out != want {
		t.Errorf("Tracked =\n%s\nwant\n%s", out, want)
	}
}

// Codex's config is read once, as an MCP config for its references and servers,
// and for its settings beside them.
func TestCodexsSettingsAreReadBesideItsServers(t *testing.T) {
	home, workdir := t.TempDir(), t.TempDir()
	codex := filepath.Join(home, ".codex", "config.toml")
	agents := agentFiles(t, home, workdir, nil, map[string]string{
		codex: "[otel]\nexporter = { otlp-http = { endpoint = \"https://otel.example.com\", headers = { \"x-otlp-api-key\" = \"" + agentToken + "\" } } }\n\n" +
			"[mcp_servers.pd]\ncommand = \"uvx\"\nenv = { PD_KEY = \"cap://absent\" }\n",
	})
	servers, errs := mcpconfig.Load(home, workdir)
	if len(errs) != 0 {
		t.Fatal(errs)
	}

	r, err := doctor.Run(store(t, nil), doctor.DefaultPaths(home, workdir), servers, agents...)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if n := slices.Index(r.Scanned, codex); n < 0 || slices.Contains(r.Scanned[n+1:], codex) {
		t.Errorf("Scanned = %v, want %s once", r.Scanned, codex)
	}
	if len(r.Agents) != 1 || r.Agents[0].Field != "otel.exporter.otlp-http.headers.x-otlp-api-key" || len(r.Dangling) != 1 {
		t.Errorf("Agents %+v, Dangling %+v: want the header, and the server's reference", r.Agents, r.Dangling)
	}
}
