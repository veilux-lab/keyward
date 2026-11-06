package cli

import (
	"os"
	"testing"
	"time"
)

// After the hidden prompt reads one line, the rest of a multi-line paste is still
// queued; drain must collect all of it, across bursts, and only stop once quiet.
func TestDrainCollectsEverythingStillQueued(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	go func() {
		defer w.Close()
		w.WriteString("MIIEvgIBADANBgkqhkiG9w0BAQEFAASC\n")
		time.Sleep(100 * time.Millisecond)
		w.WriteString("-----END PRIVATE KEY-----")
		time.Sleep(300 * time.Millisecond)
	}()
	if n, err := drain(int(r.Fd()), 200*time.Millisecond); err != nil || n != 58 {
		t.Errorf("drain = %d, %v; want all 58 bytes", n, err)
	}
}

func TestDrainReturnsNothingWhenNothingIsQueued(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	start := time.Now()
	if n, err := drain(int(r.Fd()), 50*time.Millisecond); err != nil || n != 0 {
		t.Errorf("drain = %d, %v; want 0", n, err)
	}
	if time.Since(start) > time.Second {
		t.Error("drain waited far longer than its quiet period")
	}
}

// macOS keeps at most 1023 bytes of a terminal line and silently drops the rest,
// newline included, so a value that long from the hidden prompt is a cut-off one.
func TestAValueAtTheTerminalLineLimitIsRefused(t *testing.T) {
	if !cutOff(1023) || !cutOff(1500) || cutOff(1022) || cutOff(40) {
		t.Error("cutOff disagrees with the 1023-byte terminal line limit")
	}
}
