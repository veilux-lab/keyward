package vault

import "sort"

// Binding kinds. Only BindingProgram is enforced by this keyward; a kind it does
// not know allows nothing (see Binding.Known).
const (
	// BindingProgram allows a secret to reach one program, matched by the
	// absolute path PATH found when it was bound, without following symlinks.
	BindingProgram = "program"
)

// The two stores above the Keychain carry bindings; the raw Keychain store does
// not (it holds only the vault key and un-migrated legacy items).
var (
	_ Binder = (*Encrypted)(nil)
	_ Binder = (*Memory)(nil)
)

// A Binding says where a secret may go. A secret may carry several, of several
// kinds. Comparable, so bindings can be sorted, deduplicated, and used as keys.
type Binding struct {
	// Kind is the sort of destination: BindingProgram, and in later keyward
	// versions a host or an MCP server.
	Kind string `json:"kind"`
	// Program is the absolute path a program binding allows, empty otherwise.
	Program string `json:"program,omitempty"`
}

// Known reports whether this keyward understands the binding's kind. An unknown
// kind — a host binding read by a keyward too old to enforce it — allows
// nothing, so callers fail closed rather than hand the secret anywhere.
func (b Binding) Known() bool {
	return b.Kind == BindingProgram
}

// canonicalBindings returns bindings sorted and deduplicated. This is the form
// sealed into a value's associated data, so that the same bindings written in
// any order open the same value, and editing them by hand breaks decryption.
func canonicalBindings(bindings []Binding) []Binding {
	if len(bindings) == 0 {
		return nil
	}
	out := make([]Binding, len(bindings))
	copy(out, bindings)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Program < out[j].Program
	})
	deduped := out[:1]
	for _, b := range out[1:] {
		if b != deduped[len(deduped)-1] {
			deduped = append(deduped, b)
		}
	}
	return deduped
}
