package vault

import (
	"bytes"
	"testing"
)

// An unbound value must seal exactly as it did before bindings existed, or every
// value already in a vault would stop decrypting on upgrade.
func TestAADUnboundIsUnchanged(t *testing.T) {
	if got, want := aad("github-token", nil), []byte("keyward-vault-v1:github-token"); !bytes.Equal(got, want) {
		t.Errorf("aad(name, nil) = %q, want %q", got, want)
	}
	// The check text, sealed under the empty name with no bindings.
	if got, want := aad("", nil), []byte("keyward-vault-v1:"); !bytes.Equal(got, want) {
		t.Errorf("aad(\"\", nil) = %q, want %q", got, want)
	}
}

// The binding is part of the seal, so a value sealed with one does not open
// without it: editing the file's bindings by hand breaks decryption.
func TestAADBindingChangesTheSeal(t *testing.T) {
	bound := aad("t", []Binding{{Kind: BindingProgram, Program: "/opt/homebrew/bin/gh"}})
	if bytes.Equal(bound, aad("t", nil)) {
		t.Error("a bound value seals like an unbound one")
	}
	changed := aad("t", []Binding{{Kind: BindingProgram, Program: "/usr/bin/curl"}})
	if bytes.Equal(bound, changed) {
		t.Error("changing the program did not change the seal")
	}
}

// Order and duplicates must not change the seal, so the same bindings written in
// any order open the same value.
func TestAADCanonicalIgnoresOrderAndDuplicates(t *testing.T) {
	a := Binding{Kind: BindingProgram, Program: "/opt/homebrew/bin/gh"}
	b := Binding{Kind: BindingProgram, Program: "/usr/bin/curl"}
	one := aad("t", []Binding{a, b})
	two := aad("t", []Binding{b, a, a})
	if !bytes.Equal(one, two) {
		t.Errorf("aad depends on order or duplicates:\n %q\n %q", one, two)
	}
}

func TestBindingKnown(t *testing.T) {
	if !(Binding{Kind: BindingProgram, Program: "/usr/bin/gh"}).Known() {
		t.Error("a program binding should be known")
	}
	if (Binding{Kind: "host", Program: ""}).Known() {
		t.Error("a host binding is not known to this keyward and must fail closed")
	}
}

func TestCanonicalBindingsSortsAndDedupes(t *testing.T) {
	a := Binding{Kind: BindingProgram, Program: "/a"}
	b := Binding{Kind: BindingProgram, Program: "/b"}
	got := canonicalBindings([]Binding{b, a, b})
	if len(got) != 2 || got[0] != a || got[1] != b {
		t.Errorf("canonicalBindings = %v, want [%v %v]", got, a, b)
	}
	if canonicalBindings(nil) != nil {
		t.Error("canonicalBindings(nil) should be nil")
	}
}
