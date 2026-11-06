package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/veilux-lab/keyward/internal/ledger"
)

// dotfile makes ~/.zshrc a symlink into a dotfiles folder, as stow and dotbot do.
func dotfile(t *testing.T, content string, inGit bool) (link, target string) {
	t.Helper()
	root := t.TempDir()
	repo := filepath.Join(root, "dotfiles")
	os.MkdirAll(repo, 0o755)
	if inGit {
		os.Mkdir(filepath.Join(repo, ".git"), 0o755)
	}
	target = filepath.Join(repo, "zshrc")
	os.WriteFile(target, []byte(content), 0o644)
	link = filepath.Join(root, ".zshrc")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	resolved, _ := filepath.EvalSymlinks(target)
	return link, resolved
}

// Migrating through a symlink rewrites the file it points to and keeps the link;
// replacing the link would leave the plaintext in the dotfiles folder.
func TestMigrateRewritesASymlinkedDotfileInPlace(t *testing.T) {
	h := newHarness(t, "yes\n", nil, nil)
	link, target := dotfile(t, "export GITHUB_TOKEN=ghp_perfectlyFine0123456789\n", false)
	if code := h.cli.Run([]string{"migrate", link}); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err())
	}
	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the link was replaced: %v", err)
	}
	if data, _ := os.ReadFile(target); !strings.Contains(string(data), "cap://github-token") || strings.Contains(string(data), "ghp_") {
		t.Errorf("target after migrate:\n%s", data)
	}
	if !strings.Contains(h.out(), "-> "+target) {
		t.Errorf("the plan does not show where the link points:\n%s", h.out())
	}
	records, _ := h.cli.Ledger.Records()
	if len(records) != 1 || records[0].Kind != ledger.Rewrite || records[0].Path != target {
		t.Errorf("records = %+v, want the target recorded", records)
	}
}

// A dotfile kept in git still has its old values in history, so the user must rotate.
func TestMigrateWarnsWhenTheFileIsInAGitRepository(t *testing.T) {
	h := newHarness(t, "yes\n", nil, nil)
	link, _ := dotfile(t, "export GITHUB_TOKEN=ghp_perfectlyFine0123456789\n", true)
	h.cli.Run([]string{"migrate", link})
	if all := strings.ToLower(h.out() + h.err()); !strings.Contains(all, "git repository") || !strings.Contains(all, "rotate") {
		t.Errorf("no git warning:\n%s\n%s", h.out(), h.err())
	}
}

func TestRestoreThroughASymlinkKeepsTheLink(t *testing.T) {
	h := newHarness(t, "yes\n", nil, nil)
	original := "export GITHUB_TOKEN=ghp_perfectlyFine0123456789\n"
	link, target := dotfile(t, original, false)
	if code := h.cli.Run([]string{"migrate", link}); code != 0 {
		t.Fatalf("migrate: %d %s", code, h.err())
	}
	h.cli.Stdin = strings.NewReader("yes\n")
	if code := h.cli.Run([]string{"restore", link}); code != 0 {
		t.Fatalf("restore: %d %s", code, h.err())
	}
	if info, _ := os.Lstat(link); info.Mode()&os.ModeSymlink == 0 {
		t.Error("restore replaced the link")
	}
	if data, _ := os.ReadFile(target); string(data) != original {
		t.Errorf("target after restore = %q", data)
	}
}

func TestAgentsLinkThroughASymlinkedInstructionsFile(t *testing.T) {
	h := newHarness(t, "yes\n", nil, nil)
	home := homed(t, h)
	h.cli.Interactive = true
	real := filepath.Join(t.TempDir(), "CLAUDE.md")
	os.WriteFile(real, []byte("# mine\n"), 0o644)
	os.MkdirAll(filepath.Join(home, ".claude"), 0o755)
	link := filepath.Join(home, ".claude", "CLAUDE.md")
	os.Symlink(real, link)
	if code := h.cli.Run([]string{"agents", "link"}); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err())
	}
	if info, _ := os.Lstat(link); info.Mode()&os.ModeSymlink == 0 {
		t.Error("agents link replaced the symlink")
	}
	if data, _ := os.ReadFile(real); !strings.Contains(string(data), "@~/.agents/keyward.md") {
		t.Errorf("target = %q", data)
	}
}
