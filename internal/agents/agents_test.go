package agents_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/veilux-lab/keyward/internal/agents"
)

func TestWriteCreatesTheInstructions(t *testing.T) {
	home := t.TempDir()
	f := agents.Default(home)
	if st, err := f.Status(); err != nil || st != agents.Missing {
		t.Fatalf("Status = %v, %v; want Missing", st, err)
	}
	if err := f.Write(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(home, ".agents", "keyward.md"))
	if err != nil || string(got) != string(agents.Instructions()) {
		t.Fatalf("written file does not hold the instructions: %v", err)
	}
	if info, _ := os.Stat(f.Path); info.Mode().Perm() != 0o644 {
		t.Errorf("mode %v, want 0644", info.Mode().Perm())
	}
	if st, _ := f.Status(); st != agents.Current {
		t.Errorf("Status after Write = %v, want Current", st)
	}
}

func TestInstructionsAreMarkedAndMentionKeywardRun(t *testing.T) {
	text := string(agents.Instructions())
	if !strings.HasPrefix(text, "<!-- Written by keyward") || !strings.Contains(text, "keyward run --") {
		t.Errorf("instructions lack the marker or the run guidance:\n%s", text)
	}
}

func TestWriteReplacesAnOlderVersion(t *testing.T) {
	f := agents.Default(t.TempDir())
	os.MkdirAll(filepath.Dir(f.Path), 0o755)
	os.WriteFile(f.Path, []byte("<!-- Written by keyward, an older version -->\n"), 0o644)
	if st, _ := f.Status(); st != agents.Outdated {
		t.Fatalf("Status = %v, want Outdated", st)
	}
	if err := f.Write(); err != nil {
		t.Fatal(err)
	}
	if st, _ := f.Status(); st != agents.Current {
		t.Errorf("Status = %v, want Current", st)
	}
}

// A file keyward did not write may hold the user's own notes.
func TestWriteLeavesSomeoneElsesFileAlone(t *testing.T) {
	f := agents.Default(t.TempDir())
	os.MkdirAll(filepath.Dir(f.Path), 0o755)
	os.WriteFile(f.Path, []byte("my notes\n"), 0o644)
	if st, _ := f.Status(); st != agents.Foreign {
		t.Fatalf("Status = %v, want Foreign", st)
	}
	if err := f.Write(); err == nil {
		t.Error("Write replaced a file keyward did not write")
	}
	if got, _ := os.ReadFile(f.Path); string(got) != "my notes\n" {
		t.Error("the user's file changed")
	}
}

func TestSymlinkCountsAsForeign(t *testing.T) {
	f := agents.Default(t.TempDir())
	os.MkdirAll(filepath.Dir(f.Path), 0o755)
	target := filepath.Join(t.TempDir(), "elsewhere.md")
	os.WriteFile(target, agents.Instructions(), 0o644)
	os.Symlink(target, f.Path)
	if st, _ := f.Status(); st != agents.Foreign {
		t.Errorf("Status = %v, want Foreign", st)
	}
}

func TestUnlinkedListsInstalledAgentsThatDoNotMentionTheFile(t *testing.T) {
	home := t.TempDir()
	os.MkdirAll(filepath.Join(home, ".claude"), 0o755)
	os.MkdirAll(filepath.Join(home, ".codex"), 0o755)
	os.WriteFile(filepath.Join(home, ".codex", "AGENTS.md"), []byte("Read ~/.agents/keyward.md first.\n"), 0o644)

	got := agents.Unlinked(home)
	if len(got) != 1 || got[0].Name != "Claude Code" || got[0].Config != filepath.Join(home, ".claude", "CLAUDE.md") {
		t.Fatalf("Unlinked = %+v, want only Claude Code", got)
	}
	if !strings.Contains(got[0].Command, "@~/.agents/keyward.md") || !strings.Contains(got[0].Command, ">> ~/.claude/CLAUDE.md") {
		t.Errorf("command = %q", got[0].Command)
	}
}

func TestRemoveDeletesOnlyAFileKeywardWrote(t *testing.T) {
	f := agents.Default(t.TempDir())
	if removed, err := f.Remove(); err != nil || removed {
		t.Errorf("Remove of a missing file = %v, %v", removed, err)
	}
	if err := f.Write(); err != nil {
		t.Fatal(err)
	}
	if removed, err := f.Remove(); err != nil || !removed {
		t.Fatalf("Remove = %v, %v", removed, err)
	}
	if _, err := os.Stat(f.Path); !os.IsNotExist(err) {
		t.Error("the file remains")
	}
	os.WriteFile(f.Path, []byte("my notes\n"), 0o644)
	if removed, err := f.Remove(); err != nil || removed {
		t.Errorf("Remove of the user's file = %v, %v", removed, err)
	}
	if _, err := os.Stat(f.Path); err != nil {
		t.Error("the user's file was removed")
	}
}

func TestLinkedFindsAgentConfigsThatPointAtTheFile(t *testing.T) {
	home := t.TempDir()
	os.MkdirAll(filepath.Join(home, ".claude"), 0o755)
	os.MkdirAll(filepath.Join(home, ".codex"), 0o755)
	os.WriteFile(filepath.Join(home, ".claude", "CLAUDE.md"), []byte("@~/.agents/keyward.md\n"), 0o644)
	os.WriteFile(filepath.Join(home, ".codex", "AGENTS.md"), []byte("unrelated\n"), 0o644)
	got := agents.Linked(home)
	if len(got) != 1 || got[0] != filepath.Join(home, ".claude", "CLAUDE.md") {
		t.Errorf("Linked = %v", got)
	}
}
