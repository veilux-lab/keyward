package launchd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Watchdog lets a daemon notice that its program was deleted, as `brew uninstall`
// does without stopping it, so it can unregister itself instead of launchd
// retrying a missing program at every login.
type Watchdog struct {
	Program string
	// Every is the time between checks. Two misses in a row are required, since
	// `brew upgrade` relinks the program within seconds.
	Every  time.Duration
	Exists func(string) bool
	Gone   func()
}

// Run checks until ctx ends, or until it has called Gone once.
func (w Watchdog) Run(ctx context.Context) {
	ticker := time.NewTicker(w.Every)
	defer ticker.Stop()
	missed := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if w.Exists(w.Program) {
			missed = false
			continue
		}
		if missed {
			w.Gone()
			return
		}
		missed = true
	}
}

// Exists follows links, so a dangling Homebrew opt link counts as missing.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Unregister deletes the agent's plist and unloads it. Unloading stops the
// calling daemon, so it is the last thing done.
func Unregister(home string, uid int, job string) {
	_ = os.Remove(filepath.Join(home, "Library", "LaunchAgents", job+".plist"))
	_ = Manager{}.command("/bin/launchctl", "bootout", fmt.Sprintf("gui/%d/%s", uid, job))
}

// Managed reports the label launchd started this process under, if it is one of
// keyward's agents. launchd sets XPC_SERVICE_NAME for every job it starts.
func Managed(getenv func(string) string) (string, bool) {
	switch job := getenv("XPC_SERVICE_NAME"); job {
	case label, homebrewLabel:
		return job, true
	}
	return "", false
}
