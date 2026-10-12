package vault_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/veilux-lab/keyward/internal/vault"
)

func TestRecoveryCodeRoundTripsAndToleratesFormatting(t *testing.T) {
	key := bytes.Repeat([]byte{0xA7}, 32)
	code := vault.RecoveryCode(key)
	if !strings.HasPrefix(code, "KWR1-") {
		t.Fatalf("code %q lacks its prefix", code)
	}
	for _, typed := range []string{code, strings.ToLower(code), " " + strings.ReplaceAll(code, "-", " ") + "\n"} {
		got, err := vault.ParseRecoveryCode(typed)
		if err != nil || !bytes.Equal(got, key) {
			t.Errorf("ParseRecoveryCode(%q) = %v", typed, err)
		}
	}
}

func TestRecoveryCodeCatchesATypo(t *testing.T) {
	code := []byte(vault.RecoveryCode(bytes.Repeat([]byte{1}, 32)))
	i := len(code) - 3
	if code[i] == 'A' {
		code[i] = 'B'
	} else {
		code[i] = 'A'
	}
	if _, err := vault.ParseRecoveryCode(string(code)); err == nil {
		t.Error("a mistyped code was accepted")
	}
	if _, err := vault.ParseRecoveryCode("KWR1-AAAA"); err == nil {
		t.Error("a truncated code was accepted")
	}
}

func TestExportedKeyRestoresALostKey(t *testing.T) {
	s, keys, _ := encrypted(t)
	put(t, s, "token", "value-1")
	key, err := s.ExportKey()
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	if err := keys.Delete("master"); err != nil {
		t.Fatal(err)
	}

	fresh := &vault.Encrypted{Path: s.Path, Keys: keys}
	if _, err := fresh.Get("token"); err == nil {
		t.Fatal("read the vault without its key")
	}
	changed, err := fresh.RestoreKey(key)
	if err != nil || !changed {
		t.Fatalf("RestoreKey = %v, %v", changed, err)
	}
	if got, err := fresh.Get("token"); err != nil || string(got.Bytes()) != "value-1" {
		t.Errorf("Get after recovery = %v", err)
	}
	if changed, err := fresh.RestoreKey(key); err != nil || changed {
		t.Errorf("restoring the current key again = %v, %v; want no change", changed, err)
	}
}

// A corrupted key is replaced, but only by one that opens the vault.
func TestRestoreKeyReplacesACorruptedKey(t *testing.T) {
	s, keys, _ := encrypted(t)
	put(t, s, "token", "value-1")
	key, _ := s.ExportKey()
	defer key.Destroy()
	if err := keys.Replace("master", vault.NewSecret([]byte("not-hex")), ""); err != nil {
		t.Fatal(err)
	}
	fresh := &vault.Encrypted{Path: s.Path, Keys: keys}
	if changed, err := fresh.RestoreKey(key); err != nil || !changed {
		t.Fatalf("RestoreKey = %v, %v", changed, err)
	}
	if _, err := fresh.Get("token"); err != nil {
		t.Errorf("Get after recovery = %v", err)
	}
}

func TestRestoreKeyRefusesAKeyThatDoesNotOpenTheVault(t *testing.T) {
	s, keys, _ := encrypted(t)
	put(t, s, "token", "value-1")
	before, _ := keys.Get("master")
	wrong := vault.NewSecret(bytes.Repeat([]byte{9}, 32))
	if _, err := s.RestoreKey(wrong); err == nil {
		t.Fatal("restored a key that does not open the vault")
	}
	if after, _ := keys.Get("master"); !after.Equal(before) {
		t.Error("a refused recovery changed the stored key")
	}
}

func TestRestoreKeyNeedsAVault(t *testing.T) {
	s, _, _ := encrypted(t)
	if _, err := s.RestoreKey(vault.NewSecret(bytes.Repeat([]byte{9}, 32))); !errors.Is(err, vault.ErrNotFound) {
		t.Errorf("RestoreKey with no vault = %v, want ErrNotFound", err)
	}
}
