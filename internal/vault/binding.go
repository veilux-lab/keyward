package vault

import (
	"encoding/json"
	"sort"
)

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

	// unknown marks a binding read with fields this keyward does not know, as a
	// later version may write.
	unknown bool
}

// Known reports whether this keyward understands the binding. One it does not,
// of a kind or with fields a later keyward wrote, allows nothing, so callers
// fail closed rather than hand the secret anywhere.
func (b Binding) Known() bool {
	return b.Kind == BindingProgram && !b.unknown
}

// UnmarshalJSON reads a binding and remembers whether it had fields this keyward
// does not know, which decoding would otherwise drop with the restriction they
// add.
func (b *Binding) UnmarshalJSON(data []byte) error {
	type plain Binding // without this method, so decoding does not recurse
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	*b = Binding(p)
	for name := range fields {
		b.unknown = b.unknown || name != "kind" && name != "program"
	}
	return nil
}

// MarshalJSON keeps a binding this keyward does not understand marked so as it
// crosses the daemon's socket, since decoding dropped the fields that made it so.
// A known binding marshals as before, so the associated data it is sealed with
// does not change.
func (b Binding) MarshalJSON() ([]byte, error) {
	type plain Binding
	if !b.unknown {
		return json.Marshal(plain(b))
	}
	return json.Marshal(struct {
		plain
		Unknown bool `json:"unknown"`
	}{plain(b), true})
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
