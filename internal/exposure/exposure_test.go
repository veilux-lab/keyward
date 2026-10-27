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
	args, ok := parseArgs(raw)
	if want := []string{"node", "", "--header", "Authorization: Bearer x"}; !ok || !slices.Equal(args, want) {
		t.Errorf("parseArgs = %q, %v; want %q", args, ok, want)
	}
}

func TestParseArgsRejectsATruncatedBuffer(t *testing.T) {
	raw := procargs("/bin/sh", []string{"sh", "-c"}, nil)
	for _, cut := range []int{0, 3, 6, len(raw) - 1} {
		if _, ok := parseArgs(raw[:cut]); ok {
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
		{PID: 10, Args: []string{"/usr/local/bin/node", "mcp-remote", "--header", "Authorization: Bearer dummy-github-value"}},
		{PID: 11, Args: []string{"npm", "exec", "--yes"}},
		{PID: 12, Args: []string{"curl", "-H", "X-Token: dummy-github-value"}},
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
	if i < 0 || !slices.Contains(procs[i].Args, "keyward-exposure-probe") {
		t.Errorf("did not see the probe's arguments among %d processes", len(procs))
	}
}
