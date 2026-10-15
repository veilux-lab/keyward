package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/veilux-lab/keyward/internal/agents"
	"github.com/veilux-lab/keyward/internal/ledger"
)

func agentFile(home string) string { return filepath.Join(home, ".agents", "keyward.md") }

// The file comes from installation; migrate only says how to use it.
func TestMigrateSaysHowToLinkAgentInstructions(t *testing.T) {
	h := newHarness(t, "yes\n", nil, nil)
	home := homed(t, h)
	os.MkdirAll(filepath.Join(home, ".claude"), 0o755)
	if err := agents.Default(home).Write(); err != nil {
		t.Fatal(err)
	}
	if code := h.cli.Run([]string{"migrate", writeFixture(t, rcFixture)}); code != 0 {
		t.Fatalf("migrate: %d %s", code, h.err())
	}
	if !strings.Contains(h.out(), "Claude Code") || !strings.Contains(h.out(), ">> ~/.claude/CLAUDE.md") {
		t.Errorf("no link instruction for the installed agent:\n%s", h.out())
	}
}

func TestMigrateDoesNotWriteAgentInstructions(t *testing.T) {
	h := newHarness(t, "yes\n", nil, nil)
	home := homed(t, h)
	if code := h.cli.Run([]string{"migrate", writeFixture(t, rcFixture)}); code != 0 {
		t.Fatalf("migrate: %d %s", code, h.err())
	}
	if _, err := os.Stat(agentFile(home)); !os.IsNotExist(err) {
		t.Error("migrate wrote the instructions file")
	}
	if !strings.Contains(h.out(), "keyward agents") {
		t.Errorf("migrate did not say how to create the file:\n%s", h.out())
	}
}

func TestMigrateLeavesAUsersOwnAgentFileAlone(t *testing.T) {
	h := newHarness(t, "yes\n", nil, nil)
	home := homed(t, h)
	os.MkdirAll(filepath.Dir(agentFile(home)), 0o755)
	os.WriteFile(agentFile(home), []byte("my notes\n"), 0o644)
	if code := h.cli.Run([]string{"migrate", writeFixture(t, rcFixture)}); code != 0 {
		t.Fatalf("migrate: %d %s", code, h.err())
	}
	if got, _ := os.ReadFile(agentFile(home)); string(got) != "my notes\n" {
		t.Error("migrate replaced the user's file")
	}
}

func TestAgentsCommandWritesTheFileAndListsUnlinkedAgents(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	home := homed(t, h)
	os.MkdirAll(filepath.Join(home, ".codex"), 0o755)
	if code := h.cli.Run([]string{"agents"}); code != 0 {
		t.Fatalf("agents: %d %s", code, h.err())
	}
	if _, err := os.Stat(agentFile(home)); err != nil {
		t.Fatalf("instructions not written: %v", err)
	}
	if !strings.Contains(h.out(), ">> ~/.codex/AGENTS.md") {
		t.Errorf("no link instruction for Codex:\n%s", h.out())
	}

	os.WriteFile(filepath.Join(home, ".codex", "AGENTS.md"), []byte("read ~/.agents/keyward.md\n"), 0o644)
	h.stdout.Reset()
	h.cli.Run([]string{"agents"})
	if !strings.Contains(h.out(), "already") {
		t.Errorf("did not say every agent is linked:\n%s", h.out())
	}
}

func TestDoctorMentionsAgentsThatDoNotReadTheInstructions(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	home := homed(t, h)
	os.MkdirAll(filepath.Join(home, ".claude"), 0o755)
	if err := agents.Default(home).Write(); err != nil {
		t.Fatal(err)
	}
	h.cli.Run([]string{"doctor"})
	if !strings.Contains(h.out(), "keyward agents") {
		t.Errorf("doctor did not point at keyward agents:\n%s", h.out())
	}
}

func TestAgentsLinkAddsTheLinesAfterYesAndRecordsThem(t *testing.T) {
	h := newHarness(t, "yes\n", nil, nil)
	home := homed(t, h)
	h.cli.Interactive = true
	os.MkdirAll(filepath.Join(home, ".claude"), 0o755)
	if code := h.cli.Run([]string{"agents", "link"}); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err())
	}
	claude := filepath.Join(home, ".claude", "CLAUDE.md")
	if data, _ := os.ReadFile(claude); !strings.Contains(string(data), "@~/.agents/keyward.md") {
		t.Errorf("CLAUDE.md = %q", data)
	}
	records, _ := h.cli.Ledger.Records()
	var linked bool
	for _, r := range records {
		linked = linked || (r.Kind == ledger.Link && r.Path == claude && r.Created)
	}
	if !linked {
		t.Errorf("records = %+v", records)
	}

	h.cli.Stdin = strings.NewReader("yes\n")
	if code := h.cli.Run([]string{"agents", "unlink"}); code != 0 {
		t.Fatalf("unlink exit %d: %s", code, h.err())
	}
	if _, err := os.Stat(claude); !os.IsNotExist(err) {
		t.Errorf("the CLAUDE.md keyward created remains: %v", err)
	}
}

// Without a terminal nothing is edited; the commands are printed instead.
func TestAgentsLinkWithoutATerminalOnlyPrints(t *testing.T) {
	h := newHarness(t, "yes\n", nil, nil)
	home := homed(t, h)
	os.MkdirAll(filepath.Join(home, ".claude"), 0o755)
	if code := h.cli.Run([]string{"agents", "link"}); code != 1 {
		t.Errorf("exit %d, want 1 while lines are missing", code)
	}
	if _, err := os.Stat(filepath.Join(home, ".claude", "CLAUDE.md")); !os.IsNotExist(err) {
		t.Error("edited a file without a terminal")
	}
	if !strings.Contains(h.out(), ">> ~/.claude/CLAUDE.md") {
		t.Errorf("output lacks the command:\n%s", h.out())
	}
}
