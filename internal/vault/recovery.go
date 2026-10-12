package vault

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// recoveryPrefix names the format, so a later version can change it.
const recoveryPrefix = "KWR1"

var recoveryEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// RecoveryCode encodes a vault key for a person to store. A checksum is included
// so a mistyped character is caught instead of restoring a wrong key.
func RecoveryCode(key []byte) string {
	sum := sha256.Sum256(key)
	raw := append(bytes.Clone(key), sum[:3]...)
	defer clear(raw)
	encoded := recoveryEncoding.EncodeToString(raw)
	groups := []string{recoveryPrefix}
	for i := 0; i < len(encoded); i += 4 {
		groups = append(groups, encoded[i:min(i+4, len(encoded))])
	}
	return strings.Join(groups, "-")
}

// ParseRecoveryCode accepts a code in any case, with or without its separators.
func ParseRecoveryCode(code string) ([]byte, error) {
	compact := strings.Map(func(r rune) rune {
		switch r {
		case '-', ' ', '\t', '\n', '\r':
			return -1
		}
		return r
	}, strings.ToUpper(code))
	rest, ok := strings.CutPrefix(compact, recoveryPrefix)
	if !ok {
		return nil, errors.New("not a keyward recovery code")
	}
	raw, err := recoveryEncoding.DecodeString(rest)
	defer clear(raw)
	if err != nil || len(raw) != 35 {
		return nil, errors.New("the recovery code is incomplete or mistyped")
	}
	key := bytes.Clone(raw[:32])
	if sum := sha256.Sum256(key); !bytes.Equal(sum[:3], raw[32:]) {
		clear(key)
		return nil, errors.New("the recovery code is mistyped")
	}
	return key, nil
}

// KeyRecovery is a store whose key can be exported as a recovery code and restored.
type KeyRecovery interface {
	ExportKey() (Secret, error)
	RestoreKey(key Secret) (bool, error)
}

// ExportKey returns the vault key, for a recovery code.
func (e *Encrypted) ExportKey() (Secret, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	f, err := e.read()
	if err != nil {
		return Secret{}, err
	}
	if f == nil {
		return Secret{}, fmt.Errorf("nothing is stored yet: %w", ErrNotFound)
	}
	key, err := e.masterKey(true)
	if err != nil {
		return Secret{}, err
	}
	defer clear(key)
	if err := opens(key, f); err != nil {
		return Secret{}, fmt.Errorf("%s does not match its key", e.Path)
	}
	return NewSecret(key), nil
}

// RestoreKey stores key as the vault key, reporting whether that changed anything.
// It accepts only a key that opens the vault, so a wrong code cannot make a lost
// vault worse.
func (e *Encrypted) RestoreKey(key Secret) (bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	f, err := e.read()
	if err != nil {
		return false, err
	}
	if f == nil {
		return false, fmt.Errorf("there is no vault at %s to recover: %w", e.Path, ErrNotFound)
	}
	if key.Len() != 32 || opens(key.Bytes(), f) != nil {
		return false, fmt.Errorf("this recovery code does not open %s", e.Path)
	}
	gcm, err := newGCM(key.Bytes())
	if err != nil {
		return false, err
	}
	encoded := NewSecret([]byte(hex.EncodeToString(key.Bytes())))
	defer encoded.Destroy()
	current, err := e.Keys.Get(masterKey)
	defer current.Destroy()
	switch {
	case errors.Is(err, ErrNotFound):
		err = e.Keys.Put(masterKey, encoded, "decrypts "+e.Path)
	case err != nil:
		return false, fmt.Errorf("the vault key: %w", err)
	case current.Equal(encoded):
		e.gcm = gcm
		return false, nil
	default:
		// The stored key does not open the vault, since only one key can.
		err = e.Keys.Replace(masterKey, encoded, "decrypts "+e.Path)
	}
	if err != nil {
		return false, fmt.Errorf("storing the vault key: %w", err)
	}
	e.gcm = gcm
	return true, nil
}

func opens(key []byte, f *vaultFile) error {
	gcm, err := newGCM(key)
	if err != nil {
		return err
	}
	_, err = open(gcm, f.Check, aad(""))
	return err
}
