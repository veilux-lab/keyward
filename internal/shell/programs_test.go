package shell

import (
	"slices"
	"testing"
)

func TestPrograms(t *testing.T) {
	for _, tc := range []struct {
		name   string
		shell  string
		script string
		want   []string
	}{
		{"one program", "sh", "curl https://example.com", []string{"curl"}},
		{"pipe", "sh", "curl https://example.com | jq .", []string{"curl", "jq"}},
		{"builtins are skipped", "sh", "printf hi; cd /tmp; curl x", []string{"curl"}},
		{"duplicates collapse", "sh", "curl a; curl b", []string{"curl"}},
		{"absolute path kept", "sh", "/usr/bin/curl x", []string{"/usr/bin/curl"}},
		{"launcher is transparent", "sh", "sudo curl x", []string{"curl"}},
		{"env assignment is transparent", "sh", "env A=1 curl x", []string{"curl"}},
		{"function body is followed", "sh", "f() { curl x; }; f", []string{"curl"}},
		{"uncalled function is not followed", "sh", "f() { rm -rf /; }; curl x", []string{"curl"}},
		{"command substitution", "sh", "echo $(gh auth token)", []string{"gh"}},
		{"conditionals", "sh", "if true; then curl x; else wget y; fi", []string{"curl", "wget"}},
		{"nested shell is transparent, its commands collected", "sh", "sh -c 'curl x'", []string{"curl"}},
		{"command builtin names a program", "sh", "command curl x", []string{"curl"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Programs(tc.shell, tc.script)
			if err != nil {
				t.Fatalf("Programs(%q) error: %v", tc.script, err)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("Programs(%q) = %v, want %v", tc.script, got, tc.want)
			}
		})
	}
}

// A command whose name is made as the script runs cannot be checked against
// bindings, so it is refused rather than let through.
func TestProgramsRefusesWhatItCannotName(t *testing.T) {
	for _, script := range []string{
		"$CMD https://example.com",
		`eval "$payload"`,
		"cmd=curl; $cmd x",
		"curl x; (", // unparseable
		". ./setup.sh",
		"source ./setup.sh",
		"curl https://get.example | sh",
		"sh < in.txt",
		"sh script.sh",
	} {
		if got, err := Programs("sh", script); err == nil {
			t.Errorf("Programs(%q) = %v, want an error", script, got)
		}
	}
}
