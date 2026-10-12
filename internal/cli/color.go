package cli

import "strings"

const (
	bold   = "1"
	red    = "31"
	green  = "32"
	yellow = "33"
	cyan   = "36"
)

// ColorEnabled follows the NO_COLOR convention and leaves dumb terminals plain.
func ColorEnabled(terminal bool, getenv func(string) string) bool {
	return terminal && getenv("NO_COLOR") == "" && getenv("TERM") != "dumb"
}

func paint(on bool, code, text string) string {
	if !on || text == "" {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

func (c *CLI) out(code, text string) string  { return paint(c.ColorOut, code, text) }
func (c *CLI) errs(code, text string) string { return paint(c.ColorErr, code, text) }

// paintLines colours each line whose prefix has a style, leaving the rest plain.
func paintLines(on bool, text string, styles map[string]string) string {
	if !on {
		return text
	}
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		for prefix, code := range styles {
			if strings.HasPrefix(line, prefix) {
				lines[i] = paint(on, code, line)
				break
			}
		}
	}
	return strings.Join(lines, "\n")
}
