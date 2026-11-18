package cli_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Fake credentials in agents' own files.
const (
	settingsToken = "ghp_FakeSettingsEnvToken000000000000000"
	rulePassword  = "hunter2"
	// Only the Bearer before it marks this one.
	otelToken = "7d3f9a1c5e8b2046c1e5a9f3b7d02468e4a8c2f6b0d395172b6f0a4e8c1d5973"
)

// put writes content to path, making its folder.
func put(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// doctor reads the agents' own files in home, this folder and every Claude Code
// project, never prints what they hold, and fails on a credential of a known
// shape there. Those of other projects are counted.
func TestDoctorReadsTheAgentsOwnFiles(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	home := homed(t, h)
	h.cli.Workdir = t.TempDir()
	project := filepath.Join(home, "app")
	put(t, filepath.Join(home, ".claude.json"), `{"projects": {"`+project+`": {}}}`)
	put(t, filepath.Join(home, ".claude", "settings.json"), `{"env": {"GITHUB_TOKEN": "`+settingsToken+`"}}`)
	put(t, filepath.Join(h.cli.Workdir, "CLAUDE.md"), "Use `"+settingsToken+"` for the API.\n")
	put(t, filepath.Join(project, ".claude", "settings.local.json"), `{"permissions": {"allow": ["Bash(PGPASSWORD=`+rulePassword+` psql -h db.internal)"]}}`)

	code := h.cli.Run([]string{"doctor"})
	out := h.out()
	if code != 1 || verdict(out) != "✗ Problems found: 2 credential(s) in plaintext." {
		t.Errorf("exit %d, want 1 for the two of a known shape:\n%s", code, out)
	}
	for _, want := range []string{
		"~/.claude/settings.json agent env.GITHUB_TOKEN a GitHub token store it with keyward add NAME and set it to cap://NAME,",
		h.cli.Workdir + "/CLAUDE.md:1 edit instructions a GitHub token",
		"~/app/.claude/settings.local.json agent permissions.allow[0] the variable name suggests a credential if it is one, remove the rule with /permissions in Claude Code",
	} {
		if !strings.Contains(row(out, strings.Fields(want)[0]), want) {
			t.Errorf("doctor lacks the row %q:\n%s", want, out)
		}
	}
	if !strings.Contains(flat(out), "~/.claude/settings.json, "+h.cli.Workdir+"/CLAUDE.md and 1 agent file(s) in 1 other Claude Code project(s)") {
		t.Errorf("doctor does not say which agent files it read:\n%s", out)
	}
	if strings.Contains(out+h.err(), settingsToken) || strings.Contains(out+h.err(), rulePassword) {
		t.Errorf("doctor printed a value:\n%s\n%s", out, h.err())
	}
}

// A credential its agent reads itself, which keyward cannot hold, as a token in
// Codex's OpenTelemetry headers or in a variable Claude Code reads itself, is
// listed apart and needs attention, but doctor passes. Its copy in a shell file
// only may be a credential, as before.
func TestDoctorPassesWithCredentialsKeywardCannotHold(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	home := homed(t, h)
	put(t, filepath.Join(home, ".codex", "config.toml"), "[otel]\nexporter = { otlp-http = { endpoint = \"https://otel.example.com\", headers = { Authorization = \"Bearer "+otelToken+"\" } } }\n")
	put(t, filepath.Join(home, ".claude", "settings.json"), `{"env": {"OTEL_EXPORTER_OTLP_HEADERS": "Authorization=Bearer%20`+otelToken+`"}}`)
	put(t, filepath.Join(home, ".zshrc"), "export OTEL_EXPORTER_OTLP_HEADERS=\"Authorization=Bearer%20"+otelToken+"\"\n")

	code := h.cli.Run([]string{"doctor"})
	out := h.out()
	if code != 0 || verdict(out) != "✓ No problems found. 2 checks need attention." {
		t.Errorf("exit %d, want 0:\n%s", code, out)
	}
	held := section(out, "! 2 credential(s) keyward can't hold")
	for _, want := range []string{
		"~/.codex/config.toml agent otel.exporter.otlp-http.headers.Authorization a bearer token Codex sends this as written; remove it if nothing needs it",
		"~/.claude/settings.json agent env.OTEL_EXPORTER_OTLP_HEADERS a bearer token Claude Code reads this itself;",
	} {
		if !strings.Contains(row(held, strings.Fields(want)[0]), want) {
			t.Errorf("doctor lacks the row %q:\n%s", want, out)
		}
	}
	if !strings.Contains(row(section(out, "! 1 value(s) that may be credentials"), "~/.zshrc:1 "), " add OTEL_EXPORTER_OTLP_HEADERS ") {
		t.Errorf("the shell file's copy is not a value that may be a credential:\n%s", out)
	}
	if !slices.Contains(checklist(out), "! Known secrets 2 credential(s) keyward can't hold, listed above") {
		t.Errorf("checklist = %q", checklist(out))
	}
	if strings.Contains(out+h.err(), otelToken) {
		t.Errorf("doctor printed a value:\n%s\n%s", out, h.err())
	}
}

// doctor asks git, where it can, whether it tracks a personal agent file, a local
// settings or instructions file or an agent's login, as a push publishes one. It
// runs git only where such a file exists in a work tree, and passes over one git
// does not know. A run that fails says nothing of its file, so doctor then says
// nothing of them all. Without git, the check is not made.
func TestDoctorSaysWhichPersonalAgentFilesGitTracks(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	home := homed(t, h)
	tracked := filepath.Join(home, "app", ".claude", "settings.local.json")
	put(t, filepath.Join(home, ".claude.json"), `{"projects": {"`+filepath.Join(home, "app")+`": {}}}`)
	put(t, tracked, "{}")
	put(t, filepath.Join(home, "CLAUDE.local.md"), "Notes for me.\n")
	put(t, filepath.Join(home, ".codex", "auth.json"), "{}")
	put(t, filepath.Join(home, ".git", "HEAD"), "ref: refs/heads/main\n")
	failing := true
	var calls []string
	h.cli.RunTool = func(dir string, argv ...string) ([]byte, error) {
		calls = append(calls, dir+" "+strings.Join(argv, " "))
		switch filepath.Join(dir, argv[len(argv)-1]) {
		case tracked:
			return []byte("settings.local.json\n"), nil
		case filepath.Join(home, ".codex", "auth.json"):
			// A run that fails says nothing, whatever it printed.
			if failing {
				return []byte("auth.json\nfatal: detected dubious ownership in repository\n"), errors.New("exit status 128")
			}
		case filepath.Join(home, "CLAUDE.local.md"):
			// Output is stderr and stdout together, so only a line that names
			// the file whole says git tracks it.
			return []byte("warning: unable to access 'CLAUDE.local.md/.gitattributes': Not a directory\n"), nil
		}
		return nil, nil
	}
	h.cli.LookPath = func(name string) (string, error) {
		if name == "git" {
			return "/usr/bin/git", nil
		}
		return "", exec.ErrNotFound
	}

	h.cli.Run([]string{"doctor"})
	out := h.out()
	if got := section(out, "! 1 personal file(s) git tracks"); !strings.Contains(got, "\n  ~/app/.claude/settings.local.json\n") ||
		!strings.Contains(flat(got), "run git rm --cached FILE in its folder") {
		t.Errorf("doctor does not list the tracked file:\n%s", out)
	}
	if !slices.Contains(checklist(out), "! Agent files 1 personal file(s) tracked by git, listed above") {
		t.Errorf("checklist = %q", checklist(out))
	}
	slices.Sort(calls)
	want := []string{
		home + "/ /usr/bin/git -c core.fsmonitor=false ls-files -- CLAUDE.local.md",
		filepath.Join(home, ".codex") + "/ /usr/bin/git -c core.fsmonitor=false ls-files -- auth.json",
		filepath.Join(home, "app", ".claude") + "/ /usr/bin/git -c core.fsmonitor=false ls-files -- settings.local.json",
	}
	if !slices.Equal(calls, want) {
		t.Errorf("git ran as\n%q\nwant\n%q", calls, want)
	}

	os.Remove(tracked)
	h.stdout.Reset()
	h.cli.Run([]string{"doctor"})
	if out := h.out(); strings.Contains(out, "Agent files") || strings.Contains(out, "git tracks") {
		t.Errorf("doctor where git failed:\n%s", out)
	}

	failing = false
	h.stdout.Reset()
	h.cli.Run([]string{"doctor"})
	if out := h.out(); !slices.Contains(checklist(out), "✓ Agent files no personal file tracked by git") || strings.Contains(out, "git tracks") {
		t.Errorf("doctor without a tracked file:\n%s", out)
	}

	h.cli.LookPath = func(string) (string, error) { return "", exec.ErrNotFound }
	h.stdout.Reset()
	calls = nil
	h.cli.Run([]string{"doctor"})
	if out := h.out(); strings.Contains(out, "Agent files") || len(calls) != 0 {
		t.Errorf("doctor without git ran %q:\n%s", calls, out)
	}
}

// Without a home there is no agent's file to find, so doctor reads none and asks
// git of none, rather than read paths relative to where it runs.
func TestDoctorWithoutAHomeReadsNoAgentsFile(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	dir := t.TempDir()
	t.Chdir(dir)
	put(t, filepath.Join(dir, ".claude", "settings.json"), `{"env": {"GITHUB_TOKEN": "`+settingsToken+`"}}`)
	put(t, filepath.Join(dir, ".codex", "auth.json"), "{}")
	ran := false
	h.cli.LookPath = func(string) (string, error) { return "/usr/bin/git", nil }
	h.cli.RunTool = func(string, ...string) ([]byte, error) { ran = true; return nil, nil }

	if code := h.cli.Run([]string{"doctor"}); code != 0 || strings.Contains(h.out(), "settings.json") || strings.Contains(h.out(), "Agent files") || ran {
		t.Errorf("exit %d, git ran %v:\n%s", code, ran, h.out())
	}
}

// Asked of a real repository, git names the personal file it tracks and no
// other. The test's git reads none of the developer's settings, ignore files or
// repositories.
func TestGitSaysWhichPersonalAgentFileItTracks(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("no git")
	}
	var env []string
	for _, kv := range os.Environ() {
		if name, _, _ := strings.Cut(kv, "="); !strings.HasPrefix(name, "GIT_") && name != "HOME" && name != "XDG_CONFIG_HOME" {
			env = append(env, kv)
		}
	}
	gitHome := t.TempDir()
	env = append(env, "HOME="+gitHome, "XDG_CONFIG_HOME="+filepath.Join(gitHome, ".config"), "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1")
	run := func(dir string, argv ...string) ([]byte, error) {
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.Dir, cmd.Env = dir, env
		return cmd.CombinedOutput()
	}
	h := newHarness(t, "", nil, nil)
	home := homed(t, h)
	h.cli.Workdir = t.TempDir()
	put(t, filepath.Join(h.cli.Workdir, ".claude", "settings.local.json"), "{}")
	put(t, filepath.Join(h.cli.Workdir, "CLAUDE.local.md"), "Notes for me.\n")
	for _, args := range [][]string{{"init", "-q"}, {"add", filepath.Join(".claude", "settings.local.json")}} {
		if out, err := run(h.cli.Workdir, append([]string{git}, args...)...); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	h.cli.LookPath, h.cli.RunTool = exec.LookPath, run

	h.cli.Run([]string{"doctor"})
	if got := section(h.out(), "! 1 personal file(s) git tracks"); !strings.Contains(got, "\n  "+filepath.Join(h.cli.Workdir, ".claude", "settings.local.json")+"\n") || strings.Contains(got, "CLAUDE.local.md") {
		t.Errorf("doctor does not list just the tracked file, with home %s:\n%s", home, h.out())
	}
}

// section is doctor's output from heading up to the next heading or the summary,
// or empty if there is no such heading.
func section(out, heading string) string {
	_, rest, ok := strings.Cut("\n"+out, "\n"+heading)
	if !ok {
		return ""
	}
	for _, next := range []string{"\n✗ ", "\n! ", "\nkeyward doctor  "} {
		if i := strings.Index(rest, next); i >= 0 {
			rest = rest[:i+1]
		}
	}
	return heading + rest
}
