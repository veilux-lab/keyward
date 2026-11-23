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
	var events syncBuffer
	c := start(t, &daemon.Server{Store: vault.NewMemory(), Record: func(e activity.Event) { data, _ := json.Marshal(e); events.Write(append(data, '\n')) }})
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
	if strings.Contains(events.String(), "private-value") || !strings.Contains(events.String(), "token") {
		t.Fatal("request inputs leaked or successful name was omitted")
	}
}

// The design logs each binding change by secret name and kind of binding.
func TestDaemonRecordsBindingChangesByNameAndKind(t *testing.T) {
	var events syncBuffer
	c := start(t, &daemon.Server{Store: vault.NewMemory(), Record: func(e activity.Event) { data, _ := json.Marshal(e); events.Write(append(data, '\n')) }})
	value := vault.NewSecret([]byte("v"))
	defer value.Destroy()
	if err := c.Put("github-token", value, ""); err != nil {
		t.Fatal(err)
	}
	binding := vault.Binding{Kind: vault.BindingProgram, Program: "/opt/homebrew/bin/gh"}
	if err := c.Bind("github-token", binding); err != nil {
		t.Fatal(err)
	}
	if err := c.Unbind("github-token", binding); err != nil {
		t.Fatal(err)
	}
	var bind, unbind bool
	for _, line := range strings.Split(strings.TrimSpace(events.String()), "\n") {
		var e activity.Event
		if json.Unmarshal([]byte(line), &e); e.Name != "github-token" || e.Detail != vault.BindingProgram {
			continue
		}
		bind = bind || e.Operation == "bind"
		unbind = unbind || e.Operation == "unbind"
	}
	if !bind || !unbind {
		t.Errorf("want bind and unbind recorded by name and kind; got:\n%s", events.String())
	}
	if strings.Contains(events.String(), "/opt/homebrew/bin/gh") {
		t.Error("the bound program's path should not be in the activity log")
	}
}
