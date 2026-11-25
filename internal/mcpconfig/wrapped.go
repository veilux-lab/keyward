package mcpconfig

import (
	"path/filepath"
	"slices"
	"strings"

	"github.com/veilux-lab/keyward/internal/handle"
)

// A Wrapped is a server that starts through keyward run: the secrets keyward
// run resolves for it, by name, and the command it then starts with them.
type Wrapped struct {
	Server
	Secrets []string
	Command []string
	// Unread marks a server whose script mentions keyward but cannot be read, so
	// the command it starts is not known; Secrets are the ones its env holds.
	Unread bool
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
			run, found, unread := startedRun(s)
			if unread {
				out = append(out, Wrapped{Server: s, Secrets: secretsOf(s, handed(s, refs), refs), Unread: true})
			}
			if !found {
				continue
			}
			s = run
		}
		out = append(out, Wrapped{Server: s, Secrets: secretsOf(s, resolves(s, refs), refs), Command: wrappedCommand(s)})
	}
	return out
}

// startedRun is the keyward run that s's own script starts. Unlike scriptedRun,
// it takes the words as written even when they expand a variable: only the
// secrets it resolves and the program it starts matter here, and a program a
// variable names matches no binding, which fails closed. unread is set for a
// script that mentions keyward but cannot be read.
func startedRun(s Server) (run Server, found, unread bool) {
	command := append([]string{s.Command}, s.Args...)
	at, _ := scriptAt(command)
	if at < 0 {
		return Server{}, false, false
	}
	words, ok := readScript(command[at])
	if !ok {
		return Server{}, false, strings.Contains(command[at], "keyward")
	}
	run = s
	eachCommand(words, func(_ int, texts []string) {
		i := launched(texts)
		if found || i < 0 || i+1 >= len(texts) || filepath.Base(texts[i]) != "keyward" || texts[i+1] != "run" {
			return
		}
		run.Command, run.Args, found = texts[i], texts[i+1:], true
	})
	return run, found, false
}

// secretsOf names the secrets that vars hold as s starts, sorted.
func secretsOf(s Server, vars []string, refs map[string]string) []string {
	var secrets []string
	for _, v := range vars {
		if name := secretOf(s, v, refs); name != "" {
			secrets = append(secrets, name)
		}
	}
	slices.Sort(secrets)
	return slices.Compact(secrets)
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
