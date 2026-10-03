// Package homebrew prepares source releases and a checksummed tap formula.
package homebrew

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

//go:embed keyward.rb.tmpl
var formulaTemplate string

type Release struct {
	Archive, Formula, Revision, SHA256 string
}

func Prepare(repo, version, output string) (Release, error) {
	var r Release
	if !regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$`).MatchString(version) {
		return r, errors.New("version must be major.minor.patch with an optional prerelease suffix")
	}
	git := func(args ...string) ([]byte, error) {
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		out, err := cmd.Output()
		if err != nil {
			return nil, errors.New("could not read the release source with git")
		}
		return out, nil
	}
	diff, err := git("diff", "HEAD", "--")
	if err != nil {
		return r, err
	}
	if len(diff) != 0 {
		return r, errors.New("commit tracked changes before preparing a release")
	}
	revision, err := git("rev-parse", "HEAD")
	if err != nil {
		return r, err
	}
	r.Revision = strings.TrimSpace(string(revision))
	source, err := git("archive", "--format=tar", "--prefix=keyward-"+version+"/", r.Revision)
	if err != nil {
		return r, err
	}
	var compressed bytes.Buffer
	z := gzip.NewWriter(&compressed)
	if _, err := z.Write(source); err != nil {
		return r, err
	}
	if err := z.Close(); err != nil {
		return r, err
	}
	r.SHA256 = fmt.Sprintf("%x", sha256.Sum256(compressed.Bytes()))
	filename := "keyward-" + version + ".tar.gz"
	url := "https://github.com/veilux-lab/homebrew-tap/releases/download/v" + version + "/" + filename
	formula := strings.NewReplacer("@VERSION@", version, "@URL@", url, "@SHA256@", r.SHA256).Replace(formulaTemplate)
	if err := os.MkdirAll(filepath.Join(output, "Formula"), 0o755); err != nil {
		return r, err
	}
	r.Archive = filepath.Join(output, filename)
	r.Formula = filepath.Join(output, "Formula", "keyward.rb")
	write := func(path string, data []byte) error {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			return err
		}
		_, err = f.Write(data)
		err = errors.Join(err, f.Close())
		if err != nil {
			os.Remove(path)
		}
		return err
	}
	if err := write(r.Archive, compressed.Bytes()); err != nil {
		return r, err
	}
	if err := write(r.Formula, []byte(formula)); err != nil {
		os.Remove(r.Archive)
		return r, err
	}
	return r, nil
}
