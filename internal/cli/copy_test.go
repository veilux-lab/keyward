package cli_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/veilux-lab/keyward/internal/activity"
)

const clipValue = "dummy-clipboard-value"

// clipboard stands in for the real one, which no test may touch.
type clipboard struct {
	copied [][]byte
	// given is the slice copy passed in, to see it wiped afterwards.
	given  []byte
	clears []clearCall
}

type clearCall struct {
	count int
	after time.Duration
}

// withClipboard gives the harness a fake clipboard whose change count is 42.
func withClipboard(h *harness) *clipboard {
	fake := &clipboard{}
	h.cli.Clipboard = func(value []byte) (int, error) {
		fake.copied = append(fake.copied, bytes.Clone(value))
		fake.given = value
		return 42, nil
	}
	h.cli.ClearClipboard = func(count int, after time.Duration) error {
		fake.clears = append(fake.clears, clearCall{count, after})
		return nil
	}
	return fake
}

// An agent's tool or a pipe could read the clipboard, or answer the prompt, so
// copy refuses before it reads anything.
func TestCopyRefusesWithoutATerminal(t *testing.T) {
	h := newHarness(t, "yes\n", map[string]string{"token": clipValue}, nil)
	fake := withClipboard(h)
	var events []activity.Event
	h.cli.Record = func(e activity.Event) {
		e.DurationMS = 0
		events = append(events, e)
	}
	if code := h.cli.Run([]string{"copy", "token"}); code != 2 {
		t.Errorf("exit %d, want 2", code)
	}
	if len(fake.copied) != 0 || len(fake.clears) != 0 {
		t.Error("copied without a terminal")
	}
	if !strings.Contains(h.err(), "run it yourself in a terminal, not through an AI agent or a pipe") || strings.Contains(h.err(), "Enter a value") {
		t.Errorf("did not refuse, or asked anyway:\n%s", h.err())
	}
	if want := []activity.Event{{Command: "copy", Operation: "command", Outcome: "denied"}}; !slices.Equal(events, want) {
		t.Errorf("events = %v, want %v", events, want)
	}
}

// A typo fails before the prompt, so no one says yes to a name that is not there.
// A backup's key is not one, as keyward ls does not list it.
func TestCopyOfAnUnknownOrInvalidNameFailsWithoutAPrompt(t *testing.T) {
	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"copy", "missing"}, 1, "no secret is named missing"},
		{[]string{"copy", "keyward.backup.zshrc"}, 1, "no secret is named keyward.backup.zshrc"},
		{[]string{"copy", "not a name"}, 1, "invalid reference name"},
		{[]string{"copy"}, 2, "usage: keyward copy <name>"},
		{[]string{"copy", "token", "other"}, 2, "usage: keyward copy <name>"},
	} {
		h := newHarness(t, "yes\n", map[string]string{"token": clipValue, "keyward.backup.zshrc": clipValue}, nil)
		h.cli.Interactive = true
		fake := withClipboard(h)
		if code := h.cli.Run(tc.args); code != tc.code {
			t.Errorf("%q: exit %d, want %d", tc.args, code, tc.code)
		}
		if !strings.Contains(h.err(), tc.want) || strings.Contains(h.err(), "Enter a value") || len(fake.copied) != 0 {
			t.Errorf("%q: asked, copied, or did not say %q:\n%s", tc.args, tc.want, h.err())
		}
	}
}

func TestCopyCancelsOnAnythingButYes(t *testing.T) {
	for _, answer := range []string{"", "no\n", "y\n", "Yes\n"} {
		h := newHarness(t, answer, map[string]string{"token": clipValue}, nil)
		h.cli.Interactive = true
		fake := withClipboard(h)
		read := false
		h.cli.Record = func(e activity.Event) { read = read || e.Operation == "get" }
		if code := h.cli.Run([]string{"copy", "token"}); code != 1 {
			t.Errorf("%q: exit %d, want 1", answer, code)
		}
		if len(fake.copied) != 0 || len(fake.clears) != 0 || read {
			t.Errorf("%q: read or copied the value", answer)
		}
		for _, want := range []string{"Copy token to the clipboard? Any app can read it there until it clears, in 30 seconds.", `Only "yes" will be accepted.`, "Nothing was copied."} {
			if !strings.Contains(h.err(), want) {
				t.Errorf("%q: stderr lacks %q:\n%s", answer, want, h.err())
			}
		}
	}
}

func TestCopyPutsTheValueOnTheClipboardAndClearsItLater(t *testing.T) {
	value := clipValue + " ü\t"
	h := newHarness(t, "yes\n", map[string]string{"token": value}, nil)
	h.cli.Interactive = true
	fake := withClipboard(h)
	if code := h.cli.Run([]string{"copy", "token"}); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err())
	}
	if len(fake.copied) != 1 || string(fake.copied[0]) != value {
		t.Error("the clipboard did not get exactly the stored value")
	}
	if want := []clearCall{{42, 30 * time.Second}}; !slices.Equal(fake.clears, want) {
		t.Errorf("clears = %v, want %v", fake.clears, want)
	}
	if h.out() != "Copied token. The clipboard clears in 30 seconds.\n" {
		t.Errorf("stdout = %q", h.out())
	}
	if strings.Contains(h.out()+h.err(), clipValue) {
		t.Error("printed the value")
	}
	if bytes.Count(fake.given, []byte{0}) != len(fake.given) {
		t.Error("the value was not wiped after copying")
	}
}

// Either failure names what is left to do, without the value.
func TestCopySaysWhatTheClipboardDidNotDo(t *testing.T) {
	broken := errors.New("dummy clipboard failure")
	for _, tc := range []struct {
		copyErr, clearErr error
		want              string
	}{
		{broken, nil, "could not copy token: dummy clipboard failure"},
		{nil, broken, "token is on the clipboard, but it will not clear by itself: dummy clipboard failure. Copy something else to replace it."},
	} {
		h := newHarness(t, "yes\n", map[string]string{"token": clipValue}, nil)
		h.cli.Interactive = true
		cleared := false
		h.cli.Clipboard = func([]byte) (int, error) { return 42, tc.copyErr }
		h.cli.ClearClipboard = func(int, time.Duration) error { cleared = true; return tc.clearErr }
		if code := h.cli.Run([]string{"copy", "token"}); code != 1 {
			t.Errorf("exit %d, want 1", code)
		}
		if !strings.Contains(h.err(), tc.want) || h.out() != "" || strings.Contains(h.err(), clipValue) {
			t.Errorf("stdout %q, stderr lacks %q or shows the value:\n%s", h.out(), tc.want, h.err())
		}
		if cleared != (tc.copyErr == nil) {
			t.Errorf("asked to clear a clipboard it did not copy to, or not after copying")
		}
	}
}

// The clipboard holds text, so a value that is not UTF-8 stays where it is.
func TestCopyRefusesAValueThatIsNotText(t *testing.T) {
	h := newHarness(t, "yes\n", map[string]string{"binary": clipValue + "\xff\xfe"}, nil)
	h.cli.Interactive = true
	fake := withClipboard(h)
	if code := h.cli.Run([]string{"copy", "binary"}); code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
	if len(fake.copied) != 0 || len(fake.clears) != 0 {
		t.Error("copied a value that is not text")
	}
	if !strings.Contains(h.err(), "binary is not text") || strings.Contains(h.out()+h.err(), clipValue) {
		t.Errorf("did not name the secret, or printed its value:\n%s%s", h.out(), h.err())
	}
}

// The log shows which secret was copied, under copy, and never its value.
func TestCopyIsRecordedByNameWithoutTheValue(t *testing.T) {
	log, err := activity.New(activity.DefaultConfig(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, "yes\n", map[string]string{"token": clipValue}, nil)
	h.cli.Interactive = true
	withClipboard(h)
	var events []activity.Event
	h.cli.Record = func(e activity.Event) {
		if err := log.Record(e); err != nil {
			t.Errorf("the activity log rejects %v: %v", e, err)
		}
		e.DurationMS = 0
		events = append(events, e)
	}
	if code := h.cli.Run([]string{"copy", "token"}); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err())
	}
	want := []activity.Event{
		{Command: "copy", Operation: "list", Outcome: "ok"},
		{Command: "copy", Operation: "get", Name: "token", Outcome: "ok"},
		{Command: "copy", Operation: "command", Outcome: "ok"},
	}
	if !slices.Equal(events, want) {
		t.Errorf("events = %v, want %v", events, want)
	}
	if data, _ := json.Marshal(events); strings.Contains(string(data), clipValue) {
		t.Error("the activity shows the value")
	}
}
