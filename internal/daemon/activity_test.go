package daemon_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/veilux-lab/keyward/internal/activity"
	"github.com/veilux-lab/keyward/internal/daemon"
	"github.com/veilux-lab/keyward/internal/vault"
)

func TestDaemonStructuredActivityOmitsRejectedInputs(t *testing.T) {
	var log, events syncBuffer
	c := start(t, &daemon.Server{Store: vault.NewMemory(), Log: &log, Record: func(e activity.Event) { data, _ := json.Marshal(e); events.Write(append(data, '\n')) }})
	value := vault.NewSecret([]byte("dummy-private-value"))
	defer value.Destroy()
	if err := c.Put("token", value, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get("dummy-private-value"); err == nil {
		t.Fatal("missing item resolved")
	}
	if _, err := c.Get("dummy\nprivate-value"); err == nil {
		t.Fatal("invalid name resolved")
	}
	if strings.Contains(log.String()+events.String(), "private-value") || !strings.Contains(events.String(), "token") {
		t.Fatal("request inputs leaked or successful name was omitted")
	}
}
