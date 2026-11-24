package mcpconfig

import (
	"slices"

	"github.com/veilux-lab/keyward/internal/handle"
)

// A Wrapped is a server that starts through keyward run: the secrets keyward
// run resolves for it, by name, and the command it then starts with them.
type Wrapped struct {
	Server
	Secrets []string
	Command []string
}

// WrappedServers returns the servers that are on and start through keyward run,
// directly or from their own script, as zsh -lc "keyward run ..." does, each
// with the secrets it resolves and the command keyward run starts, so keyward
// bind can say which would stop getting a secret it binds.
func WrappedServers(servers []Server, refs map[string]string) []Wrapped {
	var out []Wrapped
	for _, s := range servers {
		if s.disabled {
			continue
		}
		if !runsThroughKeyward(s) {
			run, ok := scriptedRun(s)
			if !ok {
				continue
			}
			s = run
		}
		var secrets []string
		for _, v := range resolves(s, refs) {
			if name := secretOf(s, v, refs); name != "" {
				secrets = append(secrets, name)
			}
		}
		slices.Sort(secrets)
		out = append(out, Wrapped{Server: s, Secrets: slices.Compact(secrets), Command: wrappedCommand(s)})
	}
	return out
}

// secretOf names the secret variable v holds as s starts, as handed reads it:
// the reference its env sets, or one its client fills in from a migrated
// variable, or else, for one it inherits, the reference the variable holds.
func secretOf(s Server, v string, refs map[string]string) string {
	value, set := s.Env[v]
	if !set {
		return refs[v]
	}
	if m := placeholder.FindStringSubmatch(value); m != nil && m[0] == value && !s.toml && !(s.Client == Copilot && m[1] == copilotToken) {
		return refs[m[1]]
	}
	if h, err := handle.Parse(value); err == nil {
		return h.Name
	}
	return ""
}
