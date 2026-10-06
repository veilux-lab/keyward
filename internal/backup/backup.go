// Package backup keeps migrate's plaintext originals private and away from the
// directories other tools read.
package backup

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

type Dir struct{ Path string }

type Backup struct {
	Path, Original string
	Created        time.Time
	// Legacy backups sit beside the original, as earlier releases wrote them.
	Legacy bool
}

const (
	legacySuffix = ".keyward-backup-"
	stamp        = "20060102T150405Z"
)

// metadata is stored beside each backup so listing never opens the plaintext.
type metadata struct {
	Original string    `json:"original"`
	Created  time.Time `json:"created"`
}

func Default(home string) Dir {
	return Dir{Path: filepath.Join(home, "Library", "Application Support", "keyward", "backups")}
}

// Save writes data as a new private backup of original and returns its path.
func (d Dir) Save(original string, data []byte, now time.Time) (string, error) {
	abs, err := filepath.Abs(original)
	if err != nil {
		return "", err
	}
	if err := d.ensure(); err != nil {
		return "", err
	}
	meta, err := json.Marshal(metadata{Original: abs, Created: now.UTC()})
	if err != nil {
		return "", err
	}
	base := now.UTC().Format(stamp) + "-" + filepath.Base(abs)
	for i := 0; ; i++ {
		path := filepath.Join(d.Path, base)
		if i > 0 {
			path = fmt.Sprintf("%s-%d", path, i)
		}
		err := create(path, data)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		if err := create(path+".json", meta); err != nil {
			os.Remove(path)
			return "", err
		}
		return path, nil
	}
}

func (d Dir) ensure() error {
	if err := os.MkdirAll(d.Path, 0o700); err != nil {
		return fmt.Errorf("creating the backup directory: %w", err)
	}
	info, err := os.Lstat(d.Path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || !ok || stat.Uid != uint32(os.Getuid()) {
		return fmt.Errorf("%s must be a directory you own, not a symlink", d.Path)
	}
	if info.Mode().Perm() != 0o700 {
		return os.Chmod(d.Path, 0o700)
	}
	return nil
}

func create(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err = errors.Join(err, f.Close()); err != nil {
		os.Remove(path)
	}
	return err
}

// List returns the private backups, oldest first.
func (d Dir) List() ([]Backup, error) {
	entries, err := os.ReadDir(d.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var found []Backup
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(d.Path, strings.TrimSuffix(e.Name(), ".json"))
		raw, err := os.ReadFile(path + ".json")
		if err != nil {
			return nil, err
		}
		var meta metadata
		if err := json.Unmarshal(raw, &meta); err != nil {
			return nil, fmt.Errorf("reading %s: %w", e.Name(), err)
		}
		if _, err := os.Lstat(path); err == nil {
			found = append(found, Backup{Path: path, Original: meta.Original, Created: meta.Created})
		}
	}
	sort.SliceStable(found, func(i, j int) bool { return found[i].Created.Before(found[j].Created) })
	return found, nil
}

// ForFile returns every backup of original, including legacy ones beside it.
func (d Dir) ForFile(original string) ([]Backup, error) {
	abs, err := filepath.Abs(original)
	if err != nil {
		return nil, err
	}
	all, err := d.List()
	if err != nil {
		return nil, err
	}
	var found []Backup
	for _, b := range all {
		if b.Original == abs {
			found = append(found, b)
		}
	}
	legacy, err := filepath.Glob(globEscape(abs) + legacySuffix + "*")
	if err != nil {
		return nil, err
	}
	for _, path := range legacy {
		created, err := time.Parse(stamp, strings.TrimPrefix(path, abs+legacySuffix))
		if err == nil {
			found = append(found, Backup{Path: path, Original: abs, Created: created, Legacy: true})
		}
	}
	return found, nil
}

func globEscape(path string) string {
	return strings.NewReplacer(`\`, `\\`, "*", `\*`, "?", `\?`, "[", `\[`).Replace(path)
}

func Remove(b Backup) error {
	err := os.Remove(b.Path)
	if !b.Legacy {
		if metaErr := os.Remove(b.Path + ".json"); !errors.Is(metaErr, fs.ErrNotExist) {
			err = errors.Join(err, metaErr)
		}
	}
	return err
}
