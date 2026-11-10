package shell

import (
	"path"
	"slices"
	"strings"
)

// Command finds the shell and the script that a command line runs, as
// keyward run would start it: sh -c SCRIPT, bash -lc SCRIPT or zsh -o
// pipefail -c SCRIPT, also behind exec or a launcher such as env A=1, nohup,
// time, sudo or xargs, or among another program's words, as in find -exec sh
// -c SCRIPT, as Check reads a command inside a script. watch runs its words as
// an sh script. ok is false for any other command, which has no script to
// check.
func Command(argv []string) (shell, script string, ok bool) {
	if len(argv) > 0 && path.Base(argv[0]) == "exec" {
		i, _ := options(argv, 1, optionSpec{short: "a"})
		argv = argv[i:]
	}
	args := make([]arg, len(argv))
	for i, w := range argv {
		args[i] = arg{lit: w, isLit: true}
	}
	l := launched(args)
	if l.script >= 0 && l.script < len(argv) {
		return "sh", strings.Join(argv[l.script:], " "), true
	}
	at := slices.IndexFunc(argv[l.at:], func(w string) bool { return shells[path.Base(w)] })
	if at < 0 {
		return "", "", false
	}
	at += l.at
	shell = path.Base(argv[at])
	s, _ := scriptArg(shell, argv[at+1:])
	if s < 0 {
		return "", "", false
	}
	return shell, argv[at+1+s], true
}

// shellOptions are the long options of a shell that take an argument.
var shellOptions = []string{"--rcfile", "--init-file", "--emulate"}

// scriptArg returns where the words after a shell's name hold the script it
// is given with -c, or -1. fromStdin is whether the shell would read its
// script from stdin instead, as sh alone or sh -s does.
func scriptArg(shell string, words []string) (at int, fromStdin bool) {
	c, s := false, false
	i := 0
	for ; i < len(words); i++ {
		w := words[i]
		if w == "--" || w == "-" {
			i++
			break
		}
		if strings.HasPrefix(w, "--") {
			if slices.Contains(shellOptions, w) {
				i++
			}
			continue
		}
		if len(w) < 2 || w[0] != '-' && w[0] != '+' {
			break
		}
	letters:
		for j, o := range w[1:] {
			switch {
			case o == 'c':
				c = w[0] == '-'
			case o == 's':
				s = w[0] == '-'
			case o == 'o' && shell == "zsh" && j+2 < len(w):
				break letters // zsh takes the rest of the word for the option's name, as in -opipefail
			case o == 'o' || o == 'O' && shell != "zsh":
				i++ // its argument, as in -o pipefail; zsh's -O is a flag
			}
		}
	}
	switch {
	case c && i < len(words):
		return i, false
	case c:
		return -1, false
	}
	return -1, s || i >= len(words)
}
