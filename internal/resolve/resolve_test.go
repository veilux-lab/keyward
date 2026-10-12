package resolve_test

import (
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/veilux-lab/keyward/internal/handle"
	"github.com/veilux-lab/keyward/internal/resolve"
	"github.com/veilux-lab/keyward/internal/vault"
)

const token = "eyJraWQiOiJzcGx1bmsiLCJhbGciOiJIUzI1NiJ9"

func newStore(t *testing.T, values map[string]string) *vault.Memory {
	t.Helper()
	m := vault.NewMemory()
	if err := m.Seed(values); err != nil {
		t.Fatalf("seeding the store: %v", err)
	}
	return m
}

// countingStore records how many times each name was fetched, so caching can be
// observed. It matters with a real Keychain, where every lookup is a syscall and
// may one day be a biometric prompt.
type countingStore struct {
	vault.Store
	mu   sync.Mutex
	gets map[string]int
}

func counting(s vault.Store) *countingStore {
	return &countingStore{Store: s, gets: map[string]int{}}
}

func (c *countingStore) Get(name string) (vault.Secret, error) {
	c.mu.Lock()
	c.gets[name]++
	c.mu.Unlock()
	return c.Store.Get(name)
}

func (c *countingStore) count(name string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gets[name]
}

// denyingStore stands in for a locked keychain or a dismissed prompt.
type denyingStore struct{ vault.Store }

func (denyingStore) Get(string) (vault.Secret, error) { return vault.Secret{}, vault.ErrDenied }

func TestEnvEmpty(t *testing.T) {
	got, err := resolve.New(newStore(t, nil)).Env(nil)
	if err != nil {
		t.Fatalf("Env(nil): %v", err)
	}
	if len(got.Env) != 0 {
		t.Errorf("Env = %v, want empty", got.Env)
	}
	if len(got.Resolved) != 0 {
		t.Errorf("Resolved = %v, want empty", got.Resolved)
	}
}

// The common case: most of an environment has nothing to do with keyward and must
// come through untouched, in order, including entries that are not key=value.
func TestEnvPassesThroughNonReferences(t *testing.T) {
	in := []string{
		"PATH=/usr/bin:/bin",
		"EDITOR=vim",
		"AWS_PROFILE=dashweb",
		"EMPTY=",
		"NOEQUALS",
		"ODD==double",
		"LOOKSLIKE=prefixed-cap://token",
		"ALSONOT=CAP://token",
	}
	got, err := resolve.New(newStore(t, nil)).Env(in)
	if err != nil {
		t.Fatalf("Env: %v", err)
	}
	if !reflect.DeepEqual(got.Env, in) {
		t.Errorf("Env changed the environment:\n got %q\nwant %q", got.Env, in)
	}
	if len(got.Resolved) != 0 {
		t.Errorf("Resolved = %v, want empty", got.Resolved)
	}
}

// The returned slice must not alias the caller's, or a caller reusing its
// environment would find secrets in it.
func TestEnvDoesNotAliasInput(t *testing.T) {
	in := []string{"SPLUNK_MCP_TOKEN=cap://splunk-mcp-token"}
	s := newStore(t, map[string]string{"splunk-mcp-token": token})

	got, err := resolve.New(s).Env(in)
	if err != nil {
		t.Fatalf("Env: %v", err)
	}
	if in[0] != "SPLUNK_MCP_TOKEN=cap://splunk-mcp-token" {
		t.Errorf("Env modified the caller's slice: %q", in[0])
	}
	if got.Env[0] == in[0] {
		t.Error("Env returned the reference unresolved")
	}
}

func TestEnvResolvesReferences(t *testing.T) {
	s := newStore(t, map[string]string{
		"splunk-mcp-token":   token,
		"github-token":       "ghp_example",
		"atlassian-mcp-auth": "Basic abc123",
	})

	in := []string{
		"PATH=/usr/bin",
		"SPLUNK_MCP_TOKEN=cap://splunk-mcp-token",
		"GITHUB_TOKEN=cap://github-token",
		"ATLASSIAN_MCP_AUTH=cap://atlassian-mcp-auth",
	}
	want := []string{
		"PATH=/usr/bin",
		"SPLUNK_MCP_TOKEN=" + token,
		"GITHUB_TOKEN=ghp_example",
		"ATLASSIAN_MCP_AUTH=Basic abc123",
	}

	got, err := resolve.New(s).Env(in)
	if err != nil {
		t.Fatalf("Env: %v", err)
	}
	if !reflect.DeepEqual(got.Env, want) {
		t.Errorf("Env =\n %q\nwant\n %q", got.Env, want)
	}

	wantResolved := []string{"atlassian-mcp-auth", "github-token", "splunk-mcp-token"}
	if !reflect.DeepEqual(got.Resolved, wantResolved) {
		t.Errorf("Resolved = %v, want %v (sorted, safe to log)", got.Resolved, wantResolved)
	}
}

// References are normalised, so an uppercase reference finds the stored secret
// rather than reporting it missing.
func TestEnvNormalisesReferences(t *testing.T) {
	s := newStore(t, map[string]string{"splunk-mcp-token": token})

	got, err := resolve.New(s).Env([]string{"T=cap://SPLUNK-MCP-TOKEN"})
	if err != nil {
		t.Fatalf("Env: %v", err)
	}
	if got.Env[0] != "T="+token {
		t.Errorf("Env = %q, want the resolved value", got.Env[0])
	}
	if !reflect.DeepEqual(got.Resolved, []string{"splunk-mcp-token"}) {
		t.Errorf("Resolved = %v, want the canonical name", got.Resolved)
	}
}

// Two variables referencing one secret must cost one lookup. With the Keychain
// every lookup is a syscall, and could become a prompt.
func TestEnvFetchesEachSecretOnce(t *testing.T) {
	s := counting(newStore(t, map[string]string{"shared": "value"}))

	got, err := resolve.New(s).Env([]string{
		"A=cap://shared",
		"B=cap://shared",
		"C=cap://SHARED",
	})
	if err != nil {
		t.Fatalf("Env: %v", err)
	}
	for i, e := range got.Env {
		if !strings.HasSuffix(e, "=value") {
			t.Errorf("entry %d = %q, want it resolved", i, e)
		}
	}
	if n := s.count("shared"); n != 1 {
		t.Errorf("store was queried %d times for one secret, want 1", n)
	}
	if !reflect.DeepEqual(got.Resolved, []string{"shared"}) {
		t.Errorf("Resolved = %v, want one entry", got.Resolved)
	}
}

// A malformed reference must never be passed through as a literal value. That
// would hand a program the string "cap://bad name" where a credential belongs,
// producing an authentication failure with no visible cause.
func TestEnvRejectsMalformedReference(t *testing.T) {
	_, err := resolve.New(newStore(t, nil)).Env([]string{"T=cap://bad name"})
	if err == nil {
		t.Fatal("Env succeeded on a malformed reference, want an error")
	}
	if !errors.Is(err, handle.ErrInvalidName) {
		t.Errorf("error = %v, want errors.Is(_, handle.ErrInvalidName)", err)
	}
	if !strings.Contains(err.Error(), "T") {
		t.Errorf("error %q does not name the variable", err)
	}
}

func TestEnvReportsMissingSecret(t *testing.T) {
	_, err := resolve.New(newStore(t, nil)).Env([]string{"SPLUNK_MCP_TOKEN=cap://splunk-mcp-token"})
	if err == nil {
		t.Fatal("Env succeeded with an empty store, want an error")
	}
	if !errors.Is(err, vault.ErrNotFound) {
		t.Errorf("error = %v, want errors.Is(_, vault.ErrNotFound)", err)
	}
	for _, want := range []string{"SPLUNK_MCP_TOKEN", "splunk-mcp-token"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestEnvPropagatesDenial(t *testing.T) {
	_, err := resolve.New(denyingStore{}).Env([]string{"T=cap://locked"})
	if !errors.Is(err, vault.ErrDenied) {
		t.Errorf("error = %v, want errors.Is(_, vault.ErrDenied)", err)
	}
}

// Failing on the first problem would make the user fix one reference, rerun, and
// hit the next. Report the whole set.
func TestEnvReportsEveryFailure(t *testing.T) {
	s := newStore(t, map[string]string{"present": "v"})

	_, err := resolve.New(s).Env([]string{
		"OK=cap://present",
		"MISSING_ONE=cap://absent-one",
		"BROKEN=cap://bad name",
		"MISSING_TWO=cap://absent-two",
	})
	if err == nil {
		t.Fatal("Env succeeded, want an error")
	}

	var rerr *resolve.Error
	if !errors.As(err, &rerr) {
		t.Fatalf("error %v is not a *resolve.Error", err)
	}
	if len(rerr.Failures) != 3 {
		t.Fatalf("reported %d failures, want 3: %v", len(rerr.Failures), rerr.Failures)
	}

	keys := make([]string, 0, len(rerr.Failures))
	for _, f := range rerr.Failures {
		keys = append(keys, f.Key)
	}
	want := []string{"MISSING_ONE", "BROKEN", "MISSING_TWO"}
	if !reflect.DeepEqual(keys, want) {
		t.Errorf("failure keys = %v, want %v in environment order", keys, want)
	}

	// Each failure carries the reference as written, so a caller can render a
	// useful hint without re-parsing the environment.
	if rerr.Failures[0].Ref != "cap://absent-one" {
		t.Errorf("Ref = %q, want the reference as written", rerr.Failures[0].Ref)
	}
}

// The multi-failure message is the most important text this package produces: it
// is what a user reads when their setup is broken in several places at once.
func TestErrorMessageFormat(t *testing.T) {
	s := newStore(t, nil)

	// One failure reads as a single line, with no count and no list.
	_, err := resolve.New(s).Env([]string{"SOLO=cap://absent"})
	if err == nil {
		t.Fatal("Env succeeded, want an error")
	}
	single := err.Error()
	if strings.Contains(single, "\n") {
		t.Errorf("single-failure message is multi-line:\n%s", single)
	}
	if !strings.Contains(single, "SOLO=cap://absent") {
		t.Errorf("single-failure message = %q, want the variable and reference", single)
	}

	// Several failures read as a counted, indented list.
	_, err = resolve.New(s).Env([]string{
		"FIRST=cap://absent-one",
		"SECOND=cap://absent-two",
		"THIRD=cap://bad name",
	})
	if err == nil {
		t.Fatal("Env succeeded, want an error")
	}
	multi := err.Error()

	if !strings.Contains(multi, "3 references") {
		t.Errorf("multi-failure message does not state the count:\n%s", multi)
	}
	for _, want := range []string{
		"FIRST=cap://absent-one",
		"SECOND=cap://absent-two",
		"THIRD=cap://bad name",
	} {
		if !strings.Contains(multi, want) {
			t.Errorf("multi-failure message omits %q:\n%s", want, multi)
		}
	}
	if lines := strings.Count(multi, "\n"); lines != 3 {
		t.Errorf("multi-failure message has %d newlines, want 3 (one per failure):\n%s", lines, multi)
	}
}

// Nothing may return a partly resolved environment. Executing with some values
// real and some still references is the confusing failure keyward exists to stop.
func TestEnvReturnsNothingOnFailure(t *testing.T) {
	s := newStore(t, map[string]string{"present": "v"})

	got, err := resolve.New(s).Env([]string{"OK=cap://present", "BAD=cap://absent"})
	if err == nil {
		t.Fatal("Env succeeded, want an error")
	}
	if got.Env != nil {
		t.Errorf("Env = %v on failure, want nil", got.Env)
	}
	if got.Resolved != nil {
		t.Errorf("Resolved = %v on failure, want nil", got.Resolved)
	}
}

// Errors travel into logs and terminals. A resolved value must never be in one,
// even when the failure happened after some references already resolved.
func TestEnvErrorsNeverContainValues(t *testing.T) {
	s := newStore(t, map[string]string{"present": token})

	_, err := resolve.New(s).Env([]string{
		"PRESENT=cap://present",
		"ABSENT=cap://absent",
	})
	if err == nil {
		t.Fatal("Env succeeded, want an error")
	}
	if strings.Contains(err.Error(), token) {
		t.Errorf("error leaked a resolved value: %v", err)
	}
}
