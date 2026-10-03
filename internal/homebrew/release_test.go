package homebrew_test

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/veilux-lab/keyward/internal/homebrew"
)

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
	for _, want := range []string{checksum, `version "0.1.0"`, "releases/download/v0.1.0/keyward-0.1.0.tar.gz", "main.homebrewExecutable=", "opt_bin", "daemon"} {
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
