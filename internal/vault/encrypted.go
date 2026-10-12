package vault

import (
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
	"sync"
	"syscall"
)

// Encrypted keeps every secret in one file, each value sealed separately with
// AES-256-GCM under a master key held in Keys.
//
// The Keychain ties an item to the exact program that created it, so each
// unsigned upgrade asked once per secret. With a single key there, it asks once.
// The key is read on the first request rather than at startup, so a dialog never
// appears at login with nobody there to answer it.
type Encrypted struct {
	Path string
	// Keys holds the master key: in production, a Keychain service of its own.
	Keys Store
	// Legacy holds secrets stored before the vault existed. Each moves in when
	// first used and is then deleted from Legacy. Nil means there are none.
	Legacy Store

	mu       sync.Mutex
	gcm      cipher.AEAD
	migrated bool
}

// DefaultPath is where the daemon keeps the vault for a service. It sits outside
// keyward's data directory, so uninstall keeps stored secrets.
func DefaultPath(home, service string) string {
	return filepath.Join(home, "Library", "Application Support", "keyward-vault", service+".vault")
}

const (
	masterKey    = "master"
	vaultVersion = 1
)

// checkText is sealed into every file, so a wrong key fails before any value is read.
var checkText = []byte("keyward-vault")

type vaultFile struct {
	Version int                    `json:"version"`
	Check   []byte                 `json:"check"`
	Entries map[string]sealedEntry `json:"entries"`
}

// Names and notes stay readable, as Keychain attributes were; only values are sealed.
type sealedEntry struct {
	Note  string `json:"note,omitempty"`
	Value []byte `json:"value"`
}

// aad binds a sealed value to its name, so swapping entries in the file fails.
func aad(name string) []byte { return []byte("keyward-vault-v1:" + name) }

func (e *Encrypted) Get(name string) (Secret, error) {
	key, err := normalize(name)
	if err != nil {
		return Secret{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	f, err := e.unlock()
	if err != nil {
		return Secret{}, fmt.Errorf("vault get %q: %w", key, err)
	}
	entry, ok := f.Entries[key]
	if !ok {
		if ok, err = e.adopt(f, key); err != nil {
			return Secret{}, fmt.Errorf("vault get %q: %w", key, err)
		}
		if !ok {
			return Secret{}, fmt.Errorf("vault get %q: %w", key, ErrNotFound)
		}
		entry = f.Entries[key]
	}
	plain, err := e.open(entry.Value, key)
	if err != nil {
		return Secret{}, fmt.Errorf("vault get %q: %w", key, err)
	}
	defer clear(plain)
	return NewSecret(plain), nil
}

func (e *Encrypted) Put(name string, value Secret, note string) error {
	key, err := checkPut(name, value)
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	f, err := e.unlock()
	if err != nil {
		return fmt.Errorf("vault put %q: %w", key, err)
	}
	if _, ok := f.Entries[key]; ok || e.legacyHas(key) {
		return fmt.Errorf("vault put %q: %w", key, ErrExists)
	}
	f.Entries[key] = sealedEntry{Note: SanitizeNote(note), Value: e.seal(value.Bytes(), key)}
	if err := e.write(f); err != nil {
		return fmt.Errorf("vault put %q: %w", key, err)
	}
	return nil
}

// Replace writes the new value without reading a legacy one, so it never asks.
func (e *Encrypted) Replace(name string, value Secret, note string) error {
	key, err := checkPut(name, value)
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	f, err := e.unlock()
	if err != nil {
		return fmt.Errorf("vault replace %q: %w", key, err)
	}
	_, inFile := f.Entries[key]
	inLegacy := !inFile && e.legacyHas(key)
	if !inFile && !inLegacy {
		return fmt.Errorf("vault replace %q: %w", key, ErrNotFound)
	}
	f.Entries[key] = sealedEntry{Note: SanitizeNote(note), Value: e.seal(value.Bytes(), key)}
	if err := e.write(f); err != nil {
		return fmt.Errorf("vault replace %q: %w", key, err)
	}
	if inLegacy {
		_ = e.Legacy.Delete(key)
	}
	return nil
}

// Delete needs no key, so removing a secret never asks for one.
func (e *Encrypted) Delete(name string) error {
	key, err := normalize(name)
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	f, err := e.read()
	if err != nil {
		return fmt.Errorf("vault delete %q: %w", key, err)
	}
	if f != nil {
		if _, ok := f.Entries[key]; ok {
			delete(f.Entries, key)
			if err := e.write(f); err != nil {
				return fmt.Errorf("vault delete %q: %w", key, err)
			}
			return nil
		}
	}
	if e.Legacy != nil {
		return e.Legacy.Delete(key)
	}
	return fmt.Errorf("vault delete %q: %w", key, ErrNotFound)
}

// Entries lists the file and any legacy items not yet moved, without the key.
func (e *Encrypted) Entries() ([]Entry, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	f, err := e.read()
	if err != nil {
		return nil, fmt.Errorf("vault list: %w", err)
	}
	seen := map[string]bool{}
	entries := []Entry{}
	if f != nil {
		for name, entry := range f.Entries {
			seen[name] = true
			entries = append(entries, Entry{Name: name, Note: entry.Note})
		}
	}
	if e.Legacy != nil {
		legacy, err := e.Legacy.Entries()
		if err != nil {
			return nil, fmt.Errorf("vault list: %w", err)
		}
		for _, entry := range legacy {
			if !seen[entry.Name] {
				entries = append(entries, entry)
			}
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries, nil
}

// unlock loads the key on first use and returns the file, new if none exists.
func (e *Encrypted) unlock() (*vaultFile, error) {
	f, err := e.read()
	if err != nil {
		return nil, err
	}
	if e.gcm == nil {
		key, err := e.masterKey(f != nil)
		if err != nil {
			return nil, err
		}
		gcm, err := newGCM(key)
		clear(key)
		if err != nil {
			return nil, err
		}
		if f != nil {
			if _, err := open(gcm, f.Check, aad("")); err != nil {
				return nil, fmt.Errorf("%s does not match its key", e.Path)
			}
		}
		e.gcm = gcm
	}
	if f == nil {
		f = &vaultFile{Version: vaultVersion, Check: e.seal(checkText, ""), Entries: map[string]sealedEntry{}}
	}
	if !e.migrated {
		e.migrated = true
		e.adoptAll(f)
	}
	return f, nil
}

// masterKey reads the key, creating one only for a vault that does not exist yet:
// a new key for an existing file would orphan every value in it.
func (e *Encrypted) masterKey(fileExists bool) ([]byte, error) {
	secret, err := e.Keys.Get(masterKey)
	if errors.Is(err, ErrNotFound) && !fileExists {
		key := make([]byte, 32)
		rand.Read(key)
		encoded := NewSecret([]byte(hex.EncodeToString(key)))
		defer encoded.Destroy()
		if err := e.Keys.Put(masterKey, encoded, "decrypts "+e.Path); err != nil {
			clear(key)
			return nil, fmt.Errorf("storing the vault key: %w", err)
		}
		return key, nil
	}
	if errors.Is(err, ErrNotFound) {
		return nil, fmt.Errorf("the vault key is missing, so %s cannot be decrypted", e.Path)
	}
	if err != nil {
		return nil, fmt.Errorf("the vault key: %w", err)
	}
	defer secret.Destroy()
	key, err := hex.DecodeString(string(secret.Bytes()))
	if err != nil || len(key) != 32 {
		return nil, errors.New("the vault key is malformed")
	}
	return key, nil
}

// adoptAll moves legacy items in. One the user denies stays put, still listed,
// and moves on a later request.
func (e *Encrypted) adoptAll(f *vaultFile) {
	if e.Legacy == nil {
		return
	}
	legacy, err := e.Legacy.Entries()
	if err != nil {
		return
	}
	var moved []string
	for _, entry := range legacy {
		if _, ok := f.Entries[entry.Name]; ok {
			continue
		}
		if e.take(f, entry) == nil {
			moved = append(moved, entry.Name)
		}
	}
	e.commit(f, moved)
}

func (e *Encrypted) adopt(f *vaultFile, name string) (bool, error) {
	if e.Legacy == nil {
		return false, nil
	}
	legacy, err := e.Legacy.Entries()
	if err != nil {
		return false, err
	}
	for _, entry := range legacy {
		if entry.Name == name {
			if err := e.take(f, entry); err != nil {
				return false, err
			}
			return true, e.commit(f, []string{name})
		}
	}
	return false, nil
}

func (e *Encrypted) take(f *vaultFile, entry Entry) error {
	secret, err := e.Legacy.Get(entry.Name)
	if err != nil {
		return err
	}
	defer secret.Destroy()
	f.Entries[entry.Name] = sealedEntry{Note: entry.Note, Value: e.seal(secret.Bytes(), entry.Name)}
	return nil
}

// commit saves moved items before deleting them from Legacy, so a failure keeps
// the original.
func (e *Encrypted) commit(f *vaultFile, moved []string) error {
	if len(moved) == 0 {
		return nil
	}
	if err := e.write(f); err != nil {
		for _, name := range moved {
			delete(f.Entries, name)
		}
		return err
	}
	for _, name := range moved {
		_ = e.Legacy.Delete(name)
	}
	return nil
}

func (e *Encrypted) seal(plain []byte, name string) []byte {
	nonce := make([]byte, e.gcm.NonceSize())
	rand.Read(nonce)
	return e.gcm.Seal(nonce, nonce, plain, aad(name))
}

func (e *Encrypted) open(sealed []byte, name string) ([]byte, error) {
	plain, err := open(e.gcm, sealed, aad(name))
	if err != nil {
		return nil, fmt.Errorf("the stored value was modified or does not match the vault key")
	}
	return plain, nil
}

func open(gcm cipher.AEAD, sealed, data []byte) ([]byte, error) {
	if len(sealed) < gcm.NonceSize() {
		return nil, errors.New("truncated")
	}
	return gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], data)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// read returns nil for a vault that does not exist yet.
func (e *Encrypted) read() (*vaultFile, error) {
	info, err := os.Lstat(e.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular file, not a symlink", e.Path)
	}
	data, err := os.ReadFile(e.Path)
	if err != nil {
		return nil, err
	}
	var f vaultFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("%s is unreadable: %w", e.Path, err)
	}
	if f.Version != vaultVersion {
		return nil, fmt.Errorf("%s has version %d; this keyward reads version %d", e.Path, f.Version, vaultVersion)
	}
	if f.Entries == nil {
		f.Entries = map[string]sealedEntry{}
	}
	return &f, nil
}

// write replaces the file atomically, so a crash leaves the old vault or the new.
func (e *Encrypted) write(f *vaultFile) error {
	dir := filepath.Dir(e.Path)
	if err := ensurePrivateDir(dir); err != nil {
		return err
	}
	data, err := json.Marshal(f)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(e.Path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.Write(data)
	if err = errors.Join(err, tmp.Sync(), tmp.Close()); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), e.Path)
}

func ensurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || !ok || stat.Uid != uint32(os.Getuid()) {
		return fmt.Errorf("%s must be a directory you own, not a symlink", dir)
	}
	if info.Mode().Perm() != 0o700 {
		return os.Chmod(dir, 0o700)
	}
	return nil
}

// legacyHas checks by listing, which never asks for access.
func (e *Encrypted) legacyHas(name string) bool {
	if e.Legacy == nil {
		return false
	}
	entries, err := e.Legacy.Entries()
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if entry.Name == name {
			return true
		}
	}
	return false
}
