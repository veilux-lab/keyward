package cli_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/veilux-lab/keyward/internal/vault"
)

type unopenable struct{ vault.Store }

func (unopenable) Get(string) (vault.Secret, error) {
	return vault.Secret{}, errors.New("keyward.vault does not match the vault key in your Keychain; if this vault came from another Mac, run: keyward recovery restore")
}

// keyward ls lists names without the key, so only doctor proves the vault opens:
// it decrypts one stored value and says plainly when that fails.
func TestDoctorFailsWhenTheVaultDoesNotOpen(t *testing.T) {
	h := newHarness(t, "", map[string]string{"github-token": "v"}, nil)
	homed(t, h)
	h.cli.Store = unopenable{h.store}
	if code := h.cli.Run([]string{"doctor"}); code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
	if !strings.Contains(h.out(), "The vault does not open") || !strings.Contains(h.out(), "keyward recovery restore") {
		t.Errorf("output:\n%s", h.out())
	}
}

func TestDoctorSaysTheVaultOpens(t *testing.T) {
	h := newHarness(t, "", map[string]string{"github-token": "v"}, nil)
	homed(t, h)
	h.cli.Run([]string{"doctor"})
	if !strings.Contains(h.out(), "The vault opens with its key") {
		t.Errorf("output:\n%s", h.out())
	}
}
