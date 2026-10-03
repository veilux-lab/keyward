package activity_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/veilux-lab/keyward/internal/activity"
	"github.com/veilux-lab/keyward/internal/vault"
)

func TestStoreEventsContainOnlyMetadata(t *testing.T) {
	memory := vault.NewMemory()
	var events []activity.Event
	s := &activity.Store{Store: memory, Command: "run", Record: func(e activity.Event) { events = append(events, e) }}
	value := vault.NewSecret([]byte("dummy-private-value"))
	defer value.Destroy()
	if err := s.Put("token", value, "dummy-private-provenance"); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get("token")
	if err != nil {
		t.Fatal(err)
	}
	got.Destroy()
	if _, err := s.Get("dummy-private-value"); !errors.Is(err, vault.ErrNotFound) {
		t.Fatal("store error changed")
	}
	if err := s.Replace("token", value, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Entries(); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete("token"); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(events)
	if strings.Contains(string(data), "dummy-private") || len(events) != 6 || events[1].Operation != "resolve" || events[2].Outcome != "not_found" {
		t.Fatal("events leaked values, notes, or rejected input")
	}
}
