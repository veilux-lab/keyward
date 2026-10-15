package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/veilux-lab/keyward/internal/doctor"
)

// setup is the first run in one command: move secrets, point agents at the
// instructions, run MCP servers through keyward, save the recovery code. Each
// step shows its changes and asks; declining skips it, and a rerun shows only
// what is still left. Files are the shell startup files and the current folder's
// .env, plus any named.
func (c *CLI) setup(args []string) int {
	if !c.Interactive {
		return c.fail("keyward setup: run it in a terminal; it asks before each change")
	}
	if c.Home == "" {
		return c.fail("keyward setup: home directory unknown")
	}
	c.inSetup = true
	defer func() { c.inSetup = false }()

	// Each step reports its own outcome; a declined or failed one does not stop
	// the rest, and running setup again picks up whatever is still left.
	step := func(n int, title string, run func() int) {
		fmt.Fprintf(c.Stdout, "\n%s\n", c.out(bold, fmt.Sprintf("Step %d of 4: %s", n, title)))
		run()
	}
	step(1, "move secrets out of your files", func() int {
		files := setupFiles(c.Home, c.Workdir, args)
		if len(files) == 0 {
			fmt.Fprintln(c.Stdout, "No shell startup file or .env here to check.")
		}
		for _, file := range files {
			c.migrate([]string{file})
		}
		return exitOK
	})
	step(2, "point your AI agents at keyward's instructions", c.agentsLink)
	step(3, "run MCP servers through keyward", func() int { return c.mcpChange(true, nil) })
	step(4, "save your recovery code", func() int {
		if _, err := os.Stat(c.RecoveryMarker); c.RecoveryMarker != "" && err == nil {
			fmt.Fprintln(c.Stdout, "Already shown once; keyward recovery show prints it again.")
			return exitOK
		}
		if c.Recovery == nil {
			fmt.Fprintln(c.Stdout, "Run keyward recovery show once the daemon is running.")
			return exitOK
		}
		return c.showRecovery()
	})

	fmt.Fprintln(c.Stdout, c.out(green, "\nDone. Open a new terminal, and restart your editor and AI tools, so they see the changes."))
	fmt.Fprintln(c.Stdout, "Then start commands that need a secret as: keyward run --only VAR -- <command>")
	return exitOK
}

// setupFiles are the files setup offers to migrate: those named, or else the
// shell startup files that exist and the current folder's .env.
func setupFiles(home, workdir string, named []string) []string {
	if len(named) > 0 {
		return named
	}
	var files []string
	for _, path := range doctor.DefaultPaths(home, workdir) {
		switch filepath.Base(path) {
		case ".claude.json", "config.toml":
			continue // MCP configs are step 3's
		}
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			files = append(files, path)
		}
	}
	return files
}
