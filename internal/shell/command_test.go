package shell_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/veilux-lab/keyward/internal/shell"
)

// shellCommands start a shell's script, which Command finds.
var shellCommands = []struct {
	argv          []string
	shell, script string
}{
	{[]string{"sh", "-c", "x"}, "sh", "x"},
	{[]string{"/bin/bash", "-lc", "x", "_", "https://example.com"}, "bash", "x"},
	{[]string{"zsh", "-o", "pipefail", "-c", "x"}, "zsh", "x"},
	{[]string{"bash", "-O", "extglob", "-ec", "x"}, "bash", "x"},
	{[]string{"bash", "+O", "extglob", "-xc", "x"}, "bash", "x"},
	{[]string{"bash", "--rcfile", "f", "-c", "x"}, "bash", "x"},
	{[]string{"bash", "--norc", "--noprofile", "-c", "x"}, "bash", "x"},
	{[]string{"dash", "-euc", "x"}, "dash", "x"},
	{[]string{"bash", "-Oc", "extglob", "x"}, "bash", "x"},
	// zsh's -O is a flag, and its -o takes the rest of its word.
	{[]string{"zsh", "-Oc", "x", "echo harmless"}, "zsh", "x"},
	{[]string{"zsh", "-O", "-c", "x"}, "zsh", "x"},
	{[]string{"zsh", "-c", "-O", "x"}, "zsh", "x"},
	{[]string{"zsh", "+O", "-c", "x"}, "zsh", "x"},
	{[]string{"zsh", "-opipefail", "-c", "x"}, "zsh", "x"},
	{[]string{"zsh", "-co", "nomatch", "x"}, "zsh", "x"},
	// -c takes the first word after the options, not the word after -c.
	{[]string{"sh", "-c", "-e", "x"}, "sh", "x"},
	{[]string{"sh", "-c", "--", "x"}, "sh", "x"},
	{[]string{"env", "A=1", "B=2", "sh", "-c", "x"}, "sh", "x"},
	{[]string{"/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "sh", "-c", "x"}, "sh", "x"},
	{[]string{"env", "-u", "HOME", "-", "bash", "-c", "x"}, "bash", "x"},
	{[]string{"nohup", "nice", "-n", "5", "sh", "-c", "x"}, "sh", "x"},
	{[]string{"nice", "-10", "sh", "-c", "x"}, "sh", "x"},
	{[]string{"timeout", "30", "sh", "-c", "x"}, "sh", "x"},
	{[]string{"timeout", "-k", "5", "--signal", "KILL", "30s", "zsh", "-c", "x"}, "zsh", "x"},
	{[]string{"gtimeout", "--kill-after=5", "30", "sh", "-c", "x"}, "sh", "x"},
	{[]string{"caffeinate", "-i", "-t", "60", "sh", "-c", "x"}, "sh", "x"},
	{[]string{"exec", "-a", "server", "sh", "-c", "x"}, "sh", "x"},
	// The launchers a script's commands are read past, as there.
	{[]string{"time", "bash", "-c", "x"}, "bash", "x"},
	{[]string{"/usr/bin/time", "-p", "sh", "-c", "x"}, "sh", "x"},
	{[]string{"stdbuf", "-oL", "sh", "-c", "x"}, "sh", "x"},
	{[]string{"sudo", "-E", "-u", "me", "sh", "-c", "x"}, "sh", "x"},
	{[]string{"doas", "sh", "-c", "x"}, "sh", "x"},
	{[]string{"xargs", "-0", "-n", "1", "sh", "-c", "x"}, "sh", "x"},
	{[]string{"watch", "-x", "sh", "-c", "x"}, "sh", "x"},
	{[]string{"watch", "-n", "5", "curl -s", "x"}, "sh", "curl -s x"},
	// env takes any word with an = for an assignment.
	{[]string{"env", "A.B=1", "1A=1", "A-B=1", "sh", "-c", "x"}, "sh", "x"},
	{[]string{"env", "X=/bin/sh", "bash", "-c", "x"}, "bash", "x"},
	// A shell among another program's words runs with its environment.
	{[]string{"find", ".", "-exec", "sh", "-c", "x", "_", "{}", ";"}, "sh", "x"},
	{[]string{"command", "sh", "-c", "x"}, "sh", "x"},
	{[]string{"arch", "-arm64", "zsh", "-c", "x"}, "zsh", "x"},
	{[]string{"script", "-q", "/dev/null", "sh", "-c", "x"}, "sh", "x"},
}

// otherCommands start no shell's script.
var otherCommands = [][]string{
	{},
	{"curl", "-H", "Authorization: Bearer cap://github-token", "https://api.github.com"},
	{"sh"},
	{"sh", "script.sh"},
	{"sh", "-s", "arg"},
	{"sh", "-c"},
	{"sh", "-o", "-c"},      // -c is the name -o takes
	{"zsh", "-oc", "x"},     // and c here
	{"sh", "--", "-c", "x"}, // a script file named -c
	{"ksh", "-c", "x"},
	{"env", "-S", "sh -c x"},
	{"timeout", "30"},
	{"time", "make", "build"},
	{"command", "-v", "sh"},
	{"watch", "-n", "5"},
}

func TestCommandFindsTheScriptAShellIsGiven(t *testing.T) {
	for _, tc := range shellCommands {
		sh, script, ok := shell.Command(tc.argv)
		if !ok || sh != tc.shell || script != tc.script {
			t.Errorf("Command(%q) = %q, %q, %v; want %q, %q", tc.argv, sh, script, ok, tc.shell, tc.script)
		}
	}
}

func TestCommandFindsNoScriptInOtherCommands(t *testing.T) {
	for _, argv := range otherCommands {
		if sh, script, ok := shell.Command(argv); ok {
			t.Errorf("Command(%q) = %q, %q, true; want no script", argv, sh, script)
		}
	}
}

// FuzzCommand reads command lines that go test -fuzz makes from these, split
// at NUL bytes, which no word of a command line holds. Command must not panic,
// and a script it finds is given to sh, bash, dash or zsh: a word, or watch's
// words joined.
func FuzzCommand(f *testing.F) {
	for _, tc := range shellCommands {
		f.Add(strings.Join(tc.argv, "\x00"))
	}
	for _, argv := range otherCommands {
		f.Add(strings.Join(argv, "\x00"))
	}
	for _, tc := range commandLines {
		f.Add(strings.Join(tc.argv, "\x00"))
	}
	f.Fuzz(func(t *testing.T, line string) {
		argv := strings.Split(line, "\x00")
		sh, script, ok := shell.Command(argv)
		if ok && (!slices.Contains([]string{"sh", "bash", "dash", "zsh"}, sh) || !strings.Contains(strings.Join(argv[1:], " "), script)) {
			t.Errorf("Command(%q) = %q, %q", argv, sh, script)
		}
	})
}
