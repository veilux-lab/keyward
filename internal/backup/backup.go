// Package backup keeps migrate's originals encrypted, private, and away from the
// directories other tools read.
//
// Each backup has its own key, held in the vault. A tool that reads the file gets
// ciphertext, and deleting the key makes the backup unreadable. A copy elsewhere,
// such as in Time Machine, can still be opened with a vault copy from that time.
package backup

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
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

	"github.com/veilux-lab/keyward/internal/vault"
)

type Dir struct{ Path string }

type Backup struct {
	Path, Original string
	Created        time.Time
	// Legacy backups sit beside the original, as earlier releases wrote them.
	Legacy bool
	// Key names the vault entry that decrypts the backup. Empty for plaintext
	// backups written before encryption.
	Key string
}

func (b Backup) Encrypted() bool { return b.Key != "" }

const (
	legacySuffix = ".keyward-backup-"
	stamp        = "20060102T150405Z"
	keyPrefix    = "keyward.backup."
)

// magic starts every encrypted backup and is authenticated with it.
var magic = []byte("keyward-backup-v1\n")

// IsKey reports whether a vault entry is a backup key rather than a user's secret.
func IsKey(name string) bool { return strings.HasPrefix(name, keyPrefix) }

// metadata is stored beside each backup so listing never opens the plaintext.
type metadata struct {
	Original string    `json:"original"`
	Created  time.Time `json:"created"`
	Key      string    `json:"key,omitempty"`
}

func Default(home string) Dir {
	return Dir{Path: filepath.Join(home, "Library", "Application Support", "keyward", "backups")}
}

// Save encrypts data as a new private backup of original and returns its path.
func (d Dir) Save(store vault.Store, original string, data []byte, now time.Time) (string, error) {
	abs, err := filepath.Abs(original)
	if err != nil {
		return "", err
	}
	if err := d.ensure(); err != nil {
		return "", err
	}
	key := make([]byte, 32)
	id := make([]byte, 8)
	rand.Read(key)
	rand.Read(id)
	defer clear(key)
	sealed, err := seal(key, data)
	if err != nil {
		return "", err
	}
	name := keyPrefix + hex.EncodeToString(id)
	meta, err := json.Marshal(metadata{Original: abs, Created: now.UTC(), Key: name})
	if err != nil {
		return "", err
	}
	// Hex, because a key that resolves into an environment cannot hold NUL bytes.
	secret := vault.NewSecret([]byte(hex.EncodeToString(key)))
	defer secret.Destroy()
	if err := store.Put(name, secret, "decrypts the keyward backup of "+abs); err != nil {
		return "", fmt.Errorf("storing the backup key: %w", err)
	}
	path, err := d.write(now.UTC().Format(stamp)+"-"+filepath.Base(abs), sealed, meta)
	if err != nil {
		_ = store.Delete(name)
		return "", err
	}
	return path, nil
}

func (d Dir) write(base string, data, meta []byte) (string, error) {
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

func seal(key, data []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	out := append(bytes.Clone(magic), nonce...)
	return gcm.Seal(out, nonce, data, magic), nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Open returns a backup's contents, decrypting it with its key from store.
func Open(store vault.Store, b Backup) (vault.Secret, error) {
	data, err := os.ReadFile(b.Path)
	if err != nil {
		return vault.Secret{}, err
	}
	defer clear(data)
	if !b.Encrypted() {
		return vault.NewSecret(data), nil
	}
	secret, err := store.Get(b.Key)
	if err != nil {
		return vault.Secret{}, fmt.Errorf("the key for %s: %w", b.Path, err)
	}
	key, err := hex.DecodeString(string(secret.Bytes()))
	secret.Destroy()
	defer clear(key)
	if err != nil {
		return vault.Secret{}, fmt.Errorf("the key for %s is malformed", b.Path)
	}
	gcm, err := newGCM(key)
	if err != nil {
		return vault.Secret{}, err
	}
	rest, ok := bytes.CutPrefix(data, magic)
	if !ok || len(rest) < gcm.NonceSize() {
		return vault.Secret{}, fmt.Errorf("%s is not a keyward backup", b.Path)
	}
	plain, err := gcm.Open(nil, rest[:gcm.NonceSize()], rest[gcm.NonceSize():], magic)
	if err != nil {
		return vault.Secret{}, fmt.Errorf("%s was modified or does not match its key", b.Path)
	}
	defer clear(plain)
	return vault.NewSecret(plain), nil
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
			found = append(found, Backup{Path: path, Original: meta.Original, Created: meta.Created, Key: meta.Key})
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

// Remove deletes a backup and its key. The key goes first: if that fails the file
// stays, so the removal can be retried instead of stranding the key.
func Remove(store vault.Store, b Backup) error {
	if b.Encrypted() {
		if err := store.Delete(b.Key); err != nil && !errors.Is(err, vault.ErrNotFound) {
			return fmt.Errorf("deleting the key for %s: %w", b.Path, err)
		}
	}
	err := os.Remove(b.Path)
	if !b.Legacy {
		if metaErr := os.Remove(b.Path + ".json"); !errors.Is(metaErr, fs.ErrNotExist) {
			err = errors.Join(err, metaErr)
		}
	}
	return err
}
