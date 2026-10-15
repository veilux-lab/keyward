package launchd_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/veilux-lab/keyward/internal/launchd"
)

// One miss is a brew upgrade relinking; two in a row mean the program is gone.
func TestWatchdogActsOnlyAfterTwoMissesInARow(t *testing.T) {
	seen := []bool{true, false, true, false, false}
	var checks, gone atomic.Int32
	w := launchd.Watchdog{
		Program: "/opt/homebrew/opt/keyward/bin/keyward",
		Every:   time.Millisecond,
		Exists: func(string) bool {
			i := int(checks.Add(1)) - 1
			if i >= len(seen) {
				return false
			}
			return seen[i]
		},
		Gone: func() { gone.Add(1) },
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	w.Run(ctx)
	if gone.Load() != 1 || checks.Load() != 5 {
		t.Errorf("gone %d times after %d checks; want once, after the fifth", gone.Load(), checks.Load())
	}
}

func TestWatchdogStopsWithItsDaemon(t *testing.T) {
	w := launchd.Watchdog{Program: "/x", Every: time.Millisecond, Exists: func(string) bool { return true }, Gone: func() { t.Error("acted while the program exists") }}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	w.Run(ctx)
}
