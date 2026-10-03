package cli_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nwokolo24/keyward/internal/activity"
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
