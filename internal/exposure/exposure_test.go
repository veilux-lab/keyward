package exposure

import (
	"encoding/binary"
	"os/exec"
	"slices"
	"testing"

	"github.com/veilux-lab/keyward/internal/vault"
)

// procargs builds a kern.procargs2 buffer: argc, the executable path, padding,
// the arguments, then the environment.
func procargs(path string, args, env []string) []byte {
	raw := binary.NativeEndian.AppendUint32(nil, uint32(len(args)))
	raw = append(raw, path...)
	raw = append(raw, 0, 0, 0, 0)
	for _, s := range append(slices.Clone(args), env...) {
		raw = append(append(raw, s...), 0)
	}
	return raw
}

func TestParseArgsReadsTheArgumentsAndNotTheEnvironment(t *testing.T) {
	raw := procargs("/usr/local/bin/node", []string{"node", "", "--header", "Authorization: Bearer x"}, []string{"GITHUB_TOKEN=x"})
	path, args, ok := parseArgs(raw)
	if want := []string{"node", "", "--header", "Authorization: Bearer x"}; !ok || path != "/usr/local/bin/node" || !slices.Equal(args, want) {
		t.Errorf("parseArgs = %q, %q, %v; want /usr/local/bin/node, %q", path, args, ok, want)
	}
}

func TestParseArgsRejectsATruncatedBuffer(t *testing.T) {
	raw := procargs("/bin/sh", []string{"sh", "-c"}, nil)
	for _, cut := range []int{0, 3, 6, len(raw) - 1} {
		if _, _, ok := parseArgs(raw[:cut]); ok {
			t.Errorf("parseArgs accepted a buffer cut at %d of %d", cut, len(raw))
		}
	}
}

func TestFindReportsEachSecretInACommandLineByName(t *testing.T) {
	store := vault.NewMemory()
	if err := store.Seed(map[string]string{"github-token": "dummy-github-value", "jira-token": "dummy-jira-value", "short": "yes"}); err != nil {
		t.Fatal(err)
	}
	procs := []Process{
		{PID: 10, Path: "/usr/local/bin/node", Args: []string{"/usr/local/bin/node", "mcp-remote", "--header", "Authorization: Bearer dummy-github-value"}},
		{PID: 11, Path: "/usr/local/bin/node", Args: []string{"npm", "exec", "--yes"}},
		{PID: 12, Path: "/usr/bin/curl", Args: []string{"curl", "-H", "X-Token: dummy-github-value"}},
	}
	got, err := Find(store, procs)
	if err != nil {
		t.Fatal(err)
	}
	want := []Exposure{{Secret: "github-token", PID: 10, Program: "node"}, {Secret: "github-token", PID: 12, Program: "curl"}}
	if !slices.Equal(got, want) {
		t.Errorf("Find = %+v, want %+v", got, want)
	}
}

// A program can rewrite its argv[0], as npm does with its whole command line, so
// the name reported comes from the executable and never carries the value.
func TestFindNamesTheExecutableNotTheRewrittenTitle(t *testing.T) {
	store := vault.NewMemory()
	if err := store.Seed(map[string]string{"github-token": "dummy-github-value"}); err != nil {
		t.Fatal(err)
	}
	got, err := Find(store, []Process{{PID: 10, Path: "/opt/homebrew/bin/node",
		Args: []string{"npm exec mcp-remote https://example.com/mcp --header Authorization: Bearer dummy-github-value"}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Program != "node" {
		t.Errorf("Find = %+v, want one exposure in node", got)
	}
}

// The listing must read real command lines, or the check passes by seeing nothing.
func TestProcessesSeesThisUsersCommandLines(t *testing.T) {
	cmd := exec.Command("sh", "-c", "sleep 30", "keyward-exposure-probe")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	procs, err := Processes()
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(procs, func(p Process) bool { return p.PID == cmd.Process.Pid })
	if i < 0 || !slices.Contains(procs[i].Args, "keyward-exposure-probe") || procs[i].Path != "/bin/sh" {
		t.Errorf("did not see the probe's arguments among %d processes", len(procs))
	}
}
