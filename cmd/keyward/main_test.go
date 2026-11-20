package main

import (
	"bytes"
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/veilux-lab/keyward/internal/activity"
	"github.com/veilux-lab/keyward/internal/cli"
	"github.com/veilux-lab/keyward/internal/clipboard"
	"github.com/veilux-lab/keyward/internal/daemon"
	"github.com/veilux-lab/keyward/internal/vault"
)

func TestManagedClientStartsOnlyTheDefaultVault(t *testing.T) {
	home := t.TempDir()
	for _, brew := range []string{"", "/opt/homebrew/bin/brew"} {
		for _, tc := range []struct {
			name, socket, service string
			managed               bool
		}{
			{"default", daemon.DefaultSocket(home), vault.DefaultService, true},
			{"isolated socket", filepath.Join(home, "test.sock"), vault.DefaultService, false},
			{"isolated service", daemon.DefaultSocket(home), "keyward-test", false},
		} {
			t.Run(brew+"/"+tc.name, func(t *testing.T) {
				client := managedClient(home, tc.socket, tc.service, brew)
				if (client.Start != nil) != tc.managed {
					t.Fatal("automatic startup must stay out of isolated vaults")
				}
			})
		}
	}
}

func TestFirstRunResolvesThroughAnAutomaticallyStartedDaemon(t *testing.T) {
	home, err := os.MkdirTemp("/tmp", "kw-first-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(home) })
	client := managedClient(home, daemon.DefaultSocket(home), vault.DefaultService, "/opt/homebrew/bin/brew")
	store := vault.NewMemory()
	if err := store.Seed(map[string]string{"dummy": "first-use-fixture"}); err != nil {
		t.Fatal(err)
	}
	starts := 0
	client.Start = func() error {
		starts++
		listener, err := daemon.Listen(client.Path)
		if err != nil {
			return err
		}
		done := make(chan error, 1)
		go func() { done <- (&daemon.Server{Store: store}).Serve(listener) }()
		t.Cleanup(func() {
			listener.Close()
			if err := <-done; err != nil {
				t.Errorf("daemon: %v", err)
			}
		})
		return nil
	}
	executed := false
	c := cli.CLI{Store: client, Stdout: io.Discard, Stderr: io.Discard,
		Environ: func() []string { return []string{"KEYWARD_DUMMY=cap://dummy"} },
		Exec: func(_ string, _ []string, env []string) error {
			executed = true
			for _, entry := range env {
				if value, ok := strings.CutPrefix(entry, "KEYWARD_DUMMY="); ok {
					if sha256.Sum256([]byte(value)) == sha256.Sum256([]byte("first-use-fixture")) {
						return nil
					}
				}
			}
			t.Fatal("command did not receive the resolved fixture")
			return nil
		}}
	if code := c.Run([]string{"run", "--", "/bin/echo", "fixture"}); code != 0 || !executed || starts != 1 {
		t.Fatalf("first run: exit=%d executed=%t starts=%d", code, executed, starts)
	}
}

func TestCommandsWithoutVaultAccessDoNotStartService(t *testing.T) {
	for _, args := range [][]string{{"help"}, {"version"}, {"service", "status"}, {"run", "--", "/bin/echo", "fixture"}} {
		t.Run(args[0], func(t *testing.T) {
			home := t.TempDir()
			client := managedClient(home, daemon.DefaultSocket(home), vault.DefaultService, "/opt/homebrew/bin/brew")
			client.Start = func() error { t.Fatal("command started the daemon without needing the vault"); return nil }
			c := cli.CLI{Store: client, Stdout: io.Discard, Stderr: io.Discard,
				Environ: func() []string { return nil }, Exec: func(string, []string, []string) error { return nil },
				Service: func(string) (string, error) { return "not started", nil }}
			if code := c.Run(args); code != 0 {
				t.Fatalf("command exit = %d", code)
			}
		})
	}
}

// A tool keyward runs, git among them, sees none of git's variables, which a
// hook that runs keyward sets for its own repository.
func TestRunToolLeavesOutGitsVariables(t *testing.T) {
	t.Setenv("GIT_DIR", t.TempDir())
	t.Setenv("GIT_INDEX_FILE", filepath.Join(t.TempDir(), "index"))
	if out, err := runTool(t.TempDir(), "/bin/sh", "-c", `test -z "${GIT_DIR+set}${GIT_INDEX_FILE+set}"`); err != nil {
		t.Errorf("the tool saw git's variables: %v %s", err, out)
	}
}

// main starts the process that clears the clipboard before the CLI, which knows
// nothing of it: help does not name it, and the CLI would neither run nor record it.
func TestTheClearProcessIsNotACommand(t *testing.T) {
	var out bytes.Buffer
	recorded := false
	c := cli.CLI{Stdout: &out, Stderr: io.Discard, Record: func(activity.Event) { recorded = true }}
	c.Run([]string{"help"})
	if strings.Contains(out.String(), clipboard.ClearArg) {
		t.Error("help names the clear process")
	}
	recorded = false
	if code := c.Run([]string{clipboard.ClearArg, "7", "30s"}); code != 2 || recorded {
		t.Errorf("the CLI ran or recorded the clear process: exit %d, recorded %t", code, recorded)
	}
}
