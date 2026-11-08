package homebrew_test

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/veilux-lab/keyward/internal/homebrew"
)

// make verify can run under git rebase --exec or a hook, which export GIT_DIR and others.
// Hiding them and the developer's git config keeps every test's git on its fixtures.
func TestMain(m *testing.M) {
	for _, kv := range os.Environ() {
		if name, _, _ := strings.Cut(kv, "="); strings.HasPrefix(name, "GIT_") {
			os.Unsetenv(name)
		}
	}
	// The tests' only git config turns off background maintenance, which outlives the
	// command that starts it and can change a fixture after a test has looked at it.
	dir, err := os.MkdirTemp("", "keyward-gitconfig")
	if err == nil {
		err = os.WriteFile(filepath.Join(dir, "gitconfig"), []byte("[maintenance]\n\tauto = false\n"), 0o644)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(dir, "gitconfig"))
	os.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func repository(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("release fixture\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "-q"}, {"add", "README.md"}, {"-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "fixture"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("fixture git: %v: %s", err, out)
		}
	}
	return dir
}

// snapshot digests every file and directory under roots, so any change git makes shows.
func snapshot(t *testing.T, roots ...string) map[string]string {
	t.Helper()
	paths := map[string]string{}
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			paths[path] = info.Mode().String()
			if info.Mode().IsRegular() {
				b, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				paths[path] += fmt.Sprintf(" %x", sha256.Sum256(b))
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return paths
}

// Runs the other tests as make verify would under git rebase --exec or a hook, with the
// GIT_* that locate a repository naming a scratch one and outside git config adding a hook.
func TestFixtureGitIgnoresInheritedGitVariablesAndGlobalConfig(t *testing.T) {
	scratch, home := repository(t), t.TempDir()
	gitDir, hooks := filepath.Join(scratch, ".git"), filepath.Join(home, "hooks")
	if err := os.Mkdir(hooks, 0o755); err != nil {
		t.Fatal(err)
	}
	// The hook leaves a file beside itself if git runs it.
	if err := os.WriteFile(filepath.Join(hooks, "reference-transaction"), []byte("#!/bin/sh\ntouch \"$0.ran\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".gitconfig"), []byte("[core]\n\thooksPath = "+hooks+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, scratch, home)
	cmd := exec.Command(os.Args[0], "-test.v", "-test.skip=^"+t.Name()+"$")
	cmd.Env = append(os.Environ(), "HOME="+home, "GIT_DIR="+gitDir, "GIT_WORK_TREE="+scratch,
		"GIT_INDEX_FILE="+filepath.Join(gitDir, "index"), "GIT_COMMON_DIR="+gitDir,
		"GIT_OBJECT_DIRECTORY="+filepath.Join(gitDir, "objects"), "GIT_CONFIG_PARAMETERS='core.hooksPath'='"+hooks+"'")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "--- PASS: TestReleaseArchivesOnlyCommittedFilesAndPinsFormula") {
		t.Fatalf("the package's tests under an inherited git environment: %v\n%s", err, out)
	}
	after := snapshot(t, scratch, home)
	for path, entry := range after {
		if before[path] != entry {
			t.Errorf("%s was added or changed", path)
		}
	}
	for path := range before {
		if _, ok := after[path]; !ok {
			t.Errorf("%s was removed", path)
		}
	}
}

// No fixture commit or push may leave git maintenance running in the background.
func TestFixtureGitStartsNoBackgroundMaintenance(t *testing.T) {
	repo, remote := repository(t), filepath.Join(t.TempDir(), "remote.git")
	var trace strings.Builder
	for _, args := range [][]string{{"init", "-q", "--bare", remote},
		{"-C", repo, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-q", "--allow-empty", "-m", "again"},
		{"-C", repo, "push", "-q", remote, "HEAD:refs/heads/main"}} {
		cmd := exec.Command("git", args...)
		cmd.Env = append(os.Environ(), "GIT_TRACE=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
		trace.Write(out)
	}
	if strings.Contains(trace.String(), "maintenance run") {
		t.Errorf("fixture git started background maintenance:\n%s", trace.String())
	}
}

func TestReleaseArchivesOnlyCommittedFilesAndPinsFormula(t *testing.T) {
	repo := repository(t)
	os.WriteFile(filepath.Join(repo, "private.txt"), []byte("untracked fixture"), 0o600)
	out := t.TempDir()
	r, err := homebrew.Prepare(repo, "0.1.0", out)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := os.ReadFile(r.Archive)
	if err != nil {
		t.Fatal(err)
	}
	checksum := fmt.Sprintf("%x", sha256.Sum256(archive))
	formula, err := os.ReadFile(r.Formula)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{checksum, `version "0.1.0"`, `homepage "https://github.com/veilux-lab/keyward"`, "https://github.com/veilux-lab/keyward/releases/download/v0.1.0/keyward-0.1.0.tar.gz", "main.homebrewExecutable=", "opt_bin", "daemon", "keyward setup"} {
		if !strings.Contains(string(formula), want) {
			t.Fatalf("formula missing %s", want)
		}
	}
	f, err := os.Open(r.Archive)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	tr := tar.NewReader(z)
	found := false
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(h.Name, "private.txt") || strings.Contains(h.Name, ".git/") {
			t.Fatal("archive includes untracked files or Git metadata")
		}
		found = found || h.Name == "keyward-0.1.0/README.md"
	}
	if !found {
		t.Fatal("archive omitted committed source")
	}
	if _, err := homebrew.Prepare(repo, "0.1.0", out); err == nil {
		t.Fatal("overwrote an existing release")
	}
}

func TestReleaseRefusesDirtyTrackedFilesAndInvalidVersion(t *testing.T) {
	repo := repository(t)
	if _, err := homebrew.Prepare(repo, "../../invalid", t.TempDir()); err == nil {
		t.Fatal("invalid version accepted")
	}
	os.WriteFile(filepath.Join(repo, "README.md"), []byte("uncommitted change"), 0o644)
	if _, err := homebrew.Prepare(repo, "0.1.0", t.TempDir()); err == nil {
		t.Fatal("uncommitted source accepted")
	}
}

// Caveats print on every install; they must stay short enough to read.
func TestFormulaCaveatsAreBrief(t *testing.T) {
	r, err := homebrew.Prepare(repository(t), "0.1.0", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	formula, err := os.ReadFile(r.Formula)
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(formula), "<<~EOS")
	end := strings.Index(string(formula), "    EOS")
	if start < 0 || end < start {
		t.Fatal("formula has no caveats")
	}
	caveats := string(formula)[start:end]
	if lines := strings.Count(caveats, "\n") - 1; lines > 4 {
		t.Errorf("caveats are %d lines, want at most 4:\n%s", lines, caveats)
	}
	for _, want := range []string{"keyward setup", "Terminal.app", "keyward run --only", "keyward help", "keyward uninstall", "brew services"} {
		if !strings.Contains(caveats, want) {
			t.Errorf("caveats lack %q:\n%s", want, caveats)
		}
	}
}
