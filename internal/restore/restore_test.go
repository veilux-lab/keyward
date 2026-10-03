package restore_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/veilux-lab/keyward/internal/restore"
	"github.com/veilux-lab/keyward/internal/vault"
)

type observedStore struct {
	vault.Store
	gets int
	fail map[string]error
}

func (s *observedStore) Get(name string) (vault.Secret, error) {
	s.gets++
	if err := s.fail[name]; err != nil {
		return vault.Secret{}, err
	}
	return s.Store.Get(name)
}

func fixture(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func memory(t *testing.T, values map[string]string) *vault.Memory {
	t.Helper()
	s := vault.NewMemory()
	if err := s.Seed(values); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPreviewUsesMetadataAndWithholdsValues(t *testing.T) {
	const value = "dummy-credential-never-display"
	path := fixture(t, ".zshrc", "export TOKEN='cap://token' # keep\nexport OTHER='unrelated-plaintext'\n")
	s := &observedStore{Store: memory(t, map[string]string{"token": value})}
	p, err := restore.Read(s, []string{path})
	if err != nil {
		t.Fatal(err)
	}
	preview := p.Preview()
	if len(p.Items) != 1 || s.gets != 0 || !strings.Contains(preview, "TOKEN") || !strings.Contains(preview, "cap://token") || !strings.Contains(preview, path+":1") {
		t.Fatal("preview did not describe the target using metadata only")
	}
	if strings.Contains(preview, value) || strings.Contains(preview, "unrelated-plaintext") {
		t.Fatal("preview disclosed a value")
	}
}

func TestApplyPreservesOtherContentAndKeepsVaultEntry(t *testing.T) {
	path := fixture(t, ".zshrc", "# header\n  export TOKEN=\"cap://token\" # keep\nexport EDITOR=vim\n")
	s := memory(t, map[string]string{"token": "dummy-value"})
	p, err := restore.Read(s, []string{path, path})
	if err != nil {
		t.Fatal(err)
	}
	r := p.Apply(s)
	if len(r.Restored) != 1 || len(r.Skipped) != 0 {
		t.Fatalf("restored %d, skipped %d", len(r.Restored), len(r.Skipped))
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "# header\n  export TOKEN='dummy-value' # keep\nexport EDITOR=vim\n" {
		t.Fatal("restoration changed unrelated content")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("restored file is not private")
	}
	secret, err := s.Get("token")
	if err != nil {
		t.Fatal("restoration removed the vault entry")
	}
	secret.Destroy()
	files, _ := os.ReadDir(filepath.Dir(path))
	if len(files) != 1 {
		t.Fatal("restoration left an extra plaintext file")
	}
}

func TestShellQuotingRoundTripsWithoutExpansion(t *testing.T) {
	value := "literal ' quote \" $(exit 9) `exit 9` $HOME \\ slash\nsecond line"
	path := fixture(t, ".zshrc", "TOKEN='cap://token'\n")
	s := memory(t, map[string]string{"token": value})
	p, err := restore.Read(s, []string{path})
	if err != nil {
		t.Fatal(err)
	}
	r := p.Apply(s)
	if len(r.Restored) != 1 {
		t.Fatal("shell value was not restored")
	}
	content, _ := os.ReadFile(path)
	cmd := exec.Command("/bin/sh", "-c", "eval \"$(cat)\"; printf '%s' \"$TOKEN\"")
	cmd.Stdin = bytes.NewReader(content)
	output, err := cmd.Output()
	if err != nil || sha256.Sum256(output) != sha256.Sum256([]byte(value)) {
		t.Fatal("restored shell literal expanded or lost bytes")
	}
}

func TestBestEffortReportsUnsupportedMissingAndDeniedReferences(t *testing.T) {
	path := fixture(t, ".zshrc", "A='cap://good'\nB='cap://absent'\nC='cap://denied'\nD='cap://bad name'\nexport E=$(get cap://good)\n")
	s := &observedStore{Store: memory(t, map[string]string{"good": "dummy-good", "denied": "dummy-private"}), fail: map[string]error{"denied": vault.ErrDenied}}
	p, err := restore.Read(s, []string{path, filepath.Join(t.TempDir(), "missing")})
	if err != nil {
		t.Fatal(err)
	}
	r := p.Apply(s)
	if len(r.Restored) != 1 || len(r.Skipped) != 5 {
		t.Fatalf("restored %d, skipped %d", len(r.Restored), len(r.Skipped))
	}
	got, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(got), "A='dummy-good'\nB='cap://absent'\nC='cap://denied'") {
		t.Fatal("best effort changed an unresolved reference")
	}
}

func TestEditedFileIsSkippedWhileAnotherFileRestores(t *testing.T) {
	first := fixture(t, ".zshrc", "A='cap://token'\n")
	second := fixture(t, ".bashrc", "B='cap://token'\n")
	s := &observedStore{Store: memory(t, map[string]string{"token": "dummy-value"})}
	p, err := restore.Read(s, []string{first, second})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(first, []byte("# user edit\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := p.Apply(s)
	if len(r.Restored) != 1 || len(r.Skipped) != 1 || s.gets != 1 {
		t.Fatal("changed file was not skipped independently")
	}
	got, _ := os.ReadFile(first)
	if string(got) != "# user edit\n" {
		t.Fatal("a user edit was overwritten")
	}
}

func TestEditDuringSecretRetrievalIsNotOverwritten(t *testing.T) {
	path := fixture(t, ".zshrc", "A='cap://token'\n")
	s := memory(t, map[string]string{"token": "dummy-value"})
	p, err := restore.Read(s, []string{path})
	if err != nil {
		t.Fatal(err)
	}
	r := p.Apply(editingStore{Store: s, path: path})
	got, _ := os.ReadFile(path)
	if len(r.Restored) != 0 || len(r.Skipped) != 1 || string(got) != "# changed during read\n" {
		t.Fatal("concurrent edit was overwritten")
	}
}

type editingStore struct {
	vault.Store
	path string
}

func (s editingStore) Get(name string) (vault.Secret, error) {
	if err := os.WriteFile(s.path, []byte("# changed during read\n"), 0o644); err != nil {
		return vault.Secret{}, err
	}
	return s.Store.Get(name)
}

func TestUnsafeDotenvAndBinaryValuesAreSkipped(t *testing.T) {
	path := fixture(t, ".env", "A=cap://quote\nB=cap://binary\nC=cap://good\n")
	s := memory(t, map[string]string{"quote": "has'quote", "binary": "has\x00nul", "good": "dummy-$literal"})
	p, err := restore.Read(s, []string{path})
	if err != nil {
		t.Fatal(err)
	}
	r := p.Apply(s)
	if len(r.Restored) != 1 || len(r.Skipped) != 2 {
		t.Fatal("unsupported literals were not skipped")
	}
}

func TestRefusesSymlinksAndDoesNotLeakStoreErrors(t *testing.T) {
	path := fixture(t, ".zshrc", "A=cap://token\n")
	link := filepath.Join(filepath.Dir(path), "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	s := &observedStore{Store: memory(t, map[string]string{"token": "dummy-private"}), fail: map[string]error{"token": errors.New("dummy-private")}}
	p, err := restore.Read(s, []string{link, path})
	if err != nil {
		t.Fatal(err)
	}
	r := p.Apply(s)
	if len(r.Restored) != 0 || len(r.Skipped) != 2 {
		t.Fatal("symlink or failed lookup was restored")
	}
	for _, issue := range r.Skipped {
		if strings.Contains(issue.Reason, "dummy-private") {
			t.Fatal("store error disclosed a value")
		}
	}
}

func TestTOMLIsNotRewrittenUsingShellQuoting(t *testing.T) {
	path := fixture(t, "config.toml", "TOKEN=\"cap://token\"\n")
	s := &observedStore{Store: memory(t, map[string]string{"token": "has'quote"})}
	p, err := restore.Read(s, []string{path})
	if err != nil {
		t.Fatal(err)
	}
	r := p.Apply(s)
	if len(r.Restored) != 0 || len(r.Skipped) != 1 || s.gets != 0 {
		t.Fatal("unsupported format was treated as shell syntax")
	}
}

func TestDotenvBackslashValueIsSkippedRatherThanReinterpreted(t *testing.T) {
	path := fixture(t, ".env", "TOKEN='cap://token'\n")
	s := memory(t, map[string]string{"token": `dummy\\literal`})
	p, err := restore.Read(s, []string{path})
	if err != nil {
		t.Fatal(err)
	}
	r := p.Apply(s)
	if len(r.Restored) != 0 || len(r.Skipped) != 1 {
		t.Fatal("ambiguous dotenv escape was restored")
	}
}

func TestRestoredScriptKeepsOwnerExecutePermission(t *testing.T) {
	path := fixture(t, "tool.sh", "TOKEN=cap://token\n")
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
	s := memory(t, map[string]string{"token": "dummy-value"})
	p, err := restore.Read(s, []string{path})
	if err != nil {
		t.Fatal(err)
	}
	r := p.Apply(s)
	info, err := os.Stat(path)
	if err != nil || len(r.Restored) != 1 || info.Mode().Perm() != 0o700 {
		t.Fatal("restored script lost owner execute permission or remained accessible to other users")
	}
}

func TestReferencesInsideMultilineShellTextAreNotAssignments(t *testing.T) {
	for _, content := range []string{
		"TEXT='first line\nTOKEN=cap://token\nlast line'\n",
		"printf '%s' \\\nTOKEN=cap://token\n",
		"cat <<'END'\nTOKEN=cap://token\nEND\n",
	} {
		path := fixture(t, ".zshrc", content)
		s := &observedStore{Store: memory(t, map[string]string{"token": "dummy-value"})}
		p, err := restore.Read(s, []string{path})
		if err != nil {
			t.Fatal(err)
		}
		r := p.Apply(s)
		got, _ := os.ReadFile(path)
		if len(r.Restored) != 0 || len(r.Skipped) != 1 || s.gets != 0 || string(got) != content {
			t.Fatal("text inside a multiline shell construct was treated as an assignment")
		}
	}
}
