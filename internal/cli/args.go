package cli

import (
	"flag"
	"strings"
)

// parse accepts options before or after the arguments; a bare -- ends options.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positional, nil
		}
		if consumed := len(args) - len(rest); consumed > 0 && args[consumed-1] == "--" {
			return append(positional, rest...), nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}

// hoist moves options typed before the command to just after it.
func hoist(args []string) ([]string, bool) {
	i := 0
	for i < len(args) && strings.HasPrefix(args[i], "-") && args[i] != "-h" && args[i] != "--help" && args[i] != "--" {
		i++
	}
	if i == 0 || i == len(args) {
		return args, false
	}
	moved := append([]string{args[i]}, args[:i]...)
	return append(moved, args[i+1:]...), true
}
