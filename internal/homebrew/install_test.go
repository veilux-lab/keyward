package homebrew_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallerStartsOnlyAfterSuccessfulOptInInstall(t *testing.T) {
	for _, tc := range []struct {
		name       string
		args       []string
		installErr bool
		code       int
		calls      string
	}{
		{"default", nil, false, 0, "brew:install veilux-lab/keyward/keyward\n"},
		{"start", []string{"--start-daemon"}, false, 0, "brew:install veilux-lab/keyward/keyward\nbrew:--prefix veilux-lab/keyward/keyward\nkeyward:service install\n"},
		{"help", []string{"--help"}, false, 0, ""},
		{"unknown", []string{"--unknown"}, false, 2, ""},
		{"extra", []string{"--start-daemon", "extra"}, false, 2, ""},
		{"failed install", []string{"--start-daemon"}, true, 9, "brew:install veilux-lab/keyward/keyward\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			prefix := filepath.Join(dir, "prefix with spaces")
			if err := os.MkdirAll(filepath.Join(prefix, "bin"), 0o700); err != nil {
				t.Fatal(err)
			}
			brew := filepath.Join(dir, "brew with spaces")
			for path, script := range map[string]string{
				brew: `#!/bin/sh
printf 'brew:%s\n' "$*" >> "$KEYWARD_INSTALL_TEST_LOG"
case "$1" in
  install) [ "$KEYWARD_INSTALL_TEST_FAIL" != 1 ] || exit 9 ;;
  --prefix) printf '%s\n' "$KEYWARD_INSTALL_TEST_PREFIX" ;;
esac
`,
				filepath.Join(prefix, "bin", "keyward"): `#!/bin/sh
[ "$HOME" = "$KEYWARD_INSTALL_TEST_HOME" ] || exit 10
printf 'keyward:%s\n' "$*" >> "$KEYWARD_INSTALL_TEST_LOG"
`,
			} {
				if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			log := filepath.Join(dir, "calls")
			fail := "0"
			if tc.installErr {
				fail = "1"
			}
			cmd := exec.Command(filepath.Join("..", "..", "cmd", "brew-keyward-install"), tc.args...)
			cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + dir, "HOMEBREW_BREW_FILE=" + brew,
				"KEYWARD_INSTALL_TEST_HOME=" + dir, "KEYWARD_INSTALL_TEST_LOG=" + log,
				"KEYWARD_INSTALL_TEST_PREFIX=" + prefix, "KEYWARD_INSTALL_TEST_FAIL=" + fail}
			out, err := cmd.CombinedOutput()
			code := 0
			if err != nil {
				if exit, ok := err.(*exec.ExitError); ok {
					code = exit.ExitCode()
				} else {
					t.Fatal(err)
				}
			}
			if code != tc.code {
				t.Fatalf("exit = %d, want %d; %s", code, tc.code, out)
			}
			calls, err := os.ReadFile(log)
			if err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			if string(calls) != tc.calls {
				t.Fatalf("calls = %q, want %q", calls, tc.calls)
			}
			if tc.name == "help" && !strings.Contains(string(out), "--start-daemon") {
				t.Fatal("help omits the install option")
			}
		})
	}
}
