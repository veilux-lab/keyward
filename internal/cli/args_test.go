package cli_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Options may follow the command's arguments, or precede the command itself.
func TestOptionsMayAppearBeforeOrAfterArguments(t *testing.T) {
	for _, args := range [][]string{
		{"migrate", "--dry-run", "FILE"},
		{"migrate", "FILE", "--dry-run"},
		{"--dry-run", "migrate", "FILE"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			path := writeFixture(t, rcFixture)
			h := newHarness(t, "yes\n", nil, nil)
			args = slices.Clone(args)
			args[slices.Index(args, "FILE")] = path
			if code := h.cli.Run(args); code != 0 {
				t.Fatalf("exit code = %d. stderr: %s", code, h.err())
			}
			if !strings.Contains(h.out(), "Dry run") {
				t.Errorf("not treated as a dry run:\n%s", h.out())
			}
			if got, _ := os.ReadFile(path); string(got) != rcFixture {
				t.Error("the file was modified")
			}
		})
	}
}

func TestRestoreDryRunAfterFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte("API_TOKEN=cap://api-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, "yes\n", map[string]string{"api-token": "fixture-value"}, nil)
	if code := h.cli.Run([]string{"restore", path, "--dry-run"}); code != 0 {
		t.Fatalf("exit code = %d. stderr: %s", code, h.err())
	}
	if got, _ := os.ReadFile(path); string(got) != "API_TOKEN=cap://api-token\n" {
		t.Error("--dry-run after the file restored it anyway")
	}
}

func TestAddForceAfterName(t *testing.T) {
	h := newHarness(t, "new-value", map[string]string{"api-token": "old-value"}, nil)
	if code := h.cli.Run([]string{"add", "api-token", "-force"}); code != 0 {
		t.Fatalf("exit code = %d. stderr: %s", code, h.err())
	}
}

// After a bare --, everything is an argument, even if it looks like an option.
func TestDoubleDashEndsOptions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "--dry-run")
	if err := os.WriteFile(path, []byte(rcFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	h := newHarness(t, "", nil, nil)
	h.cli.Run([]string{"migrate", "--", "--dry-run"})
	if strings.Contains(h.out(), "Dry run") || !strings.Contains(h.out(), "--dry-run:") {
		t.Errorf("-- did not make --dry-run a file name:\n%s", h.out())
	}
}

// The child command's own options belong to it, wherever they appear.
func TestRunPassesOptionsThrough(t *testing.T) {
	for _, args := range [][]string{{"run", "--", "echo", "--dry-run"}, {"run", "echo", "-n", "--dry-run"}} {
		h := newHarness(t, "", nil, nil)
		if code := h.cli.Run(args); code != 0 {
			t.Fatalf("%v: exit code = %d. stderr: %s", args, code, h.err())
		}
		if want := args[slices.Index(args, "echo"):]; !slices.Equal(h.exec.argv, want) {
			t.Errorf("%v: argv = %v, want %v", args, h.exec.argv, want)
		}
	}
}

func TestOptionsBeforeRunAreRejected(t *testing.T) {
	h := newHarness(t, "", nil, nil)
	if code := h.cli.Run([]string{"--dry-run", "run", "echo"}); code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if h.exec.calls != 0 {
		t.Error("the command ran")
	}
}
