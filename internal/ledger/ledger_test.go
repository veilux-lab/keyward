package ledger_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/veilux-lab/keyward/internal/ledger"
)

func book(t *testing.T) ledger.Ledger {
	t.Helper()
	return ledger.Ledger{Path: filepath.Join(t.TempDir(), "keyward", "ledger.json")}
}

func TestAnEmptyLedgerHasNoRecords(t *testing.T) {
	if got, err := book(t).Records(); err != nil || len(got) != 0 {
		t.Errorf("Records = %v, %v", got, err)
	}
}

func TestRecordsSurviveAndArePrivate(t *testing.T) {
	l := book(t)
	if err := l.Add(ledger.Record{Kind: ledger.Link, Path: "/h/.claude/CLAUDE.md", Text: "@~/.agents/keyward.md"}); err != nil {
		t.Fatal(err)
	}
	got, err := l.Records()
	if err != nil || len(got) != 1 || got[0].Text != "@~/.agents/keyward.md" || got[0].Time.IsZero() {
		t.Fatalf("Records = %+v, %v", got, err)
	}
	info, err := os.Stat(l.Path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("ledger mode = %v, %v; want 0600", info.Mode().Perm(), err)
	}
}

// Recording the same change twice keeps one record; a rewrite merges the quoting
// of every variable migrated from that file.
func TestAddReplacesTheSameChangeAndMergesQuotes(t *testing.T) {
	l := book(t)
	l.Add(ledger.Record{Kind: ledger.Rewrite, Path: "/h/.zshrc", Quotes: map[string]string{"A": `"`}})
	l.Add(ledger.Record{Kind: ledger.Rewrite, Path: "/h/.zshrc", Quotes: map[string]string{"B": ""}})
	l.Add(ledger.Record{Kind: ledger.Server, Path: "/h/.claude.json", Name: "github", Text: "local"})
	l.Add(ledger.Record{Kind: ledger.Server, Path: "/h/.claude.json", Name: "github", Text: "user"})
	got, _ := l.Records()
	if len(got) != 2 {
		t.Fatalf("Records = %+v, want 2", got)
	}
	for _, r := range got {
		if r.Kind == ledger.Rewrite && (r.Quotes["A"] != `"` || r.Quotes["B"] != "" || len(r.Quotes) != 2) {
			t.Errorf("quotes = %v", r.Quotes)
		}
		if r.Kind == ledger.Server && r.Text != "user" {
			t.Errorf("server scope = %q, want the latest", r.Text)
		}
	}
}

func TestRemoveForgetsOneChange(t *testing.T) {
	l := book(t)
	l.Add(ledger.Record{Kind: ledger.Link, Path: "/a"})
	l.Add(ledger.Record{Kind: ledger.Link, Path: "/b"})
	if err := l.Remove(ledger.Link, "/a", ""); err != nil {
		t.Fatal(err)
	}
	got, _ := l.Records()
	if len(got) != 1 || got[0].Path != "/b" {
		t.Errorf("Records = %+v", got)
	}
}

// The ledger is read by humans and support: a damaged one is an error, not empty.
func TestADamagedLedgerIsReported(t *testing.T) {
	l := book(t)
	os.MkdirAll(filepath.Dir(l.Path), 0o700)
	os.WriteFile(l.Path, []byte("{not json"), 0o600)
	if _, err := l.Records(); err == nil || !strings.Contains(err.Error(), l.Path) {
		t.Errorf("Records error = %v, want one naming the file", err)
	}
}
