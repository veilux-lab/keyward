package cli_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/veilux-lab/keyward/internal/activity"
)

func TestActivityIsWrittenBeforeExecWithoutArgumentsOrEnvironment(t *testing.T) {
	h := newHarness(t, "", map[string]string{"token": "dummy-private-value"}, []string{"TOKEN=cap://token", "OTHER=dummy-private-env"})
	var events []activity.Event
	h.cli.Record = func(e activity.Event) { events = append(events, e) }
	h.cli.Exec = func(_ string, _ []string, _ []string) error {
		if len(events) < 2 || events[len(events)-1].Operation != "exec" || events[len(events)-1].Outcome != "started" {
			t.Fatal("exec happened before activity was recorded")
		}
		return nil
	}
	if code := h.cli.Run([]string{"run", "--", "/bin/echo", "dummy-private-argument"}); code != 0 {
		t.Fatal(h.err())
	}
	data, _ := json.Marshal(events)
	if strings.Contains(string(data), "dummy-private") || events[0].Name != "token" {
		t.Fatal("activity leaked arguments, environment, or values")
	}
}

// A run refused for its script is recorded as denied, an outcome the log
// accepts, with nothing resolved, nothing started, and nothing of the script;
// a typo in --only before it is still a usage error.
func TestARefusedRunIsRecordedAsDeniedWithNothingResolvedOrStarted(t *testing.T) {
	log, err := activity.New(activity.DefaultConfig(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	script := `curl -u "dummy-private-user:$TOKEN" x`
	for _, tc := range []struct {
		args    []string
		outcome string
	}{
		{[]string{"run", "--", "sh", "-c", script}, "denied"},
		{[]string{"run", "--only", "TOKEN,TYPO", "--", "sh", "-c", script}, "usage"},
	} {
		h := newHarness(t, "", map[string]string{"token": "dummy-private-value"}, []string{"PATH=/usr/bin:/bin", "TOKEN=cap://token"})
		var events []activity.Event
		h.cli.Record = func(e activity.Event) {
			if err := log.Record(e); err != nil {
				t.Errorf("the activity log rejects %v: %v", e, err)
			}
			e.DurationMS = 0
			events = append(events, e)
		}
		if code := h.cli.Run(tc.args); code != 2 {
			t.Errorf("%q: exit code = %d, want 2", tc.args, code)
		}
		if want := []activity.Event{{Command: "run", Operation: "command", Outcome: tc.outcome}}; !slices.Equal(events, want) {
			t.Errorf("%q: events = %v, want %v", tc.args, events, want)
		}
		if data, _ := json.Marshal(events); strings.Contains(string(data), "dummy-private") {
			t.Errorf("%q: activity shows the script or a value: %s", tc.args, data)
		}
	}
}

func TestCancelledRestoreRecordsNoValues(t *testing.T) {
	path := writeFixture(t, "TOKEN=cap://token\n")
	h := newHarness(t, "no\n", map[string]string{"token": "dummy-value"}, nil)
	var events []activity.Event
	h.cli.Record = func(e activity.Event) { events = append(events, e) }
	if code := h.cli.Run([]string{"restore", path}); code != 1 {
		t.Fatal("restore did not cancel")
	}
	if events[len(events)-1].Outcome != "cancelled" {
		t.Fatal("cancellation not recorded")
	}
	for _, e := range events {
		if e.Operation == "get" {
			t.Fatal("refusal read a value")
		}
	}
}
