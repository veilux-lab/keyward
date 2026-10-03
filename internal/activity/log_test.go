package activity_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nwokolo24/keyward/internal/activity"
)

func config(t *testing.T) activity.Config {
	t.Helper()
	c := activity.DefaultConfig(t.TempDir())
	return c
}

func records(t *testing.T, dir string) (int, int64) {
	t.Helper()
	paths, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	count := 0
	var total int64
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		total += int64(len(data))
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if line == "" {
				continue
			}
			var event map[string]any
			if err := json.Unmarshal([]byte(line), &event); err != nil {
				t.Fatal("interleaved or malformed event")
			}
			count++
		}
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0o600 {
			t.Fatal("log is not private")
		}
	}
	return count, total
}

func TestPrivateStructuredEventsAndRejectedInputs(t *testing.T) {
	c := config(t)
	l, err := activity.New(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []activity.Event{
		{Command: "run", Operation: "resolve", Name: "github-token", Outcome: "ok", DurationMS: 24},
		{Command: "run", Operation: "get", Name: "dummy-private-value", Outcome: "not_found"},
		{Command: "add", Operation: "put", Name: "dummy\nprivate-value", Outcome: "invalid"},
	} {
		if err := l.Record(e); err != nil {
			t.Fatal(err)
		}
	}
	data, _ := os.ReadFile(filepath.Join(c.Dir, "activity.jsonl"))
	if strings.Contains(string(data), "private-value") || !strings.Contains(string(data), "github-token") {
		t.Fatal("log echoed rejected input or omitted a successful name")
	}
	if n, _ := records(t, c.Dir); n != 3 {
		t.Fatal("wrong event count")
	}
	info, _ := os.Stat(c.Dir)
	if info.Mode().Perm() != 0o700 {
		t.Fatal("directory is not private")
	}
	if err := l.Record(activity.Event{Command: "dummy-private-value", Operation: "get", Outcome: "ok"}); err == nil || strings.Contains(err.Error(), "dummy-private-value") {
		t.Fatal("untrusted fields were accepted or disclosed")
	}
}

func TestRotationRetentionAndTotalCap(t *testing.T) {
	c := config(t)
	c.RotateBytes, c.MaxBytes = 500, 1200
	now := time.Now().UTC()
	c.Now = func() time.Time { return now }
	l, err := activity.New(c)
	if err != nil {
		t.Fatal(err)
	}
	for range 30 {
		if err := l.Record(activity.Event{Command: "run", Operation: "resolve", Name: "token", Outcome: "ok"}); err != nil {
			t.Fatal(err)
		}
	}
	if n, total := records(t, c.Dir); n == 0 || n >= 30 || total > c.MaxBytes {
		t.Fatal("rotation did not enforce the total cap")
	}
	paths, _ := filepath.Glob(filepath.Join(c.Dir, "activity-*.jsonl"))
	if len(paths) == 0 {
		t.Fatal("size rotation did not create archives")
	}
	now = now.Add(31 * 24 * time.Hour)
	if err := l.Clean(); err != nil {
		t.Fatal(err)
	}
	if n, _ := records(t, c.Dir); n != 0 {
		t.Fatal("expired records were retained")
	}
}

func TestDailyRotationAndUnrelatedFiles(t *testing.T) {
	c := config(t)
	now := time.Now().UTC()
	c.Now = func() time.Time { return now }
	l, err := activity.New(c)
	if err != nil {
		t.Fatal(err)
	}
	e := activity.Event{Command: "ls", Operation: "list", Outcome: "ok"}
	if err := l.Record(e); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(c.Dir, "unrelated.txt")
	if err := os.WriteFile(other, []byte("leave alone"), 0o600); err != nil {
		t.Fatal(err)
	}
	now = now.Add(24 * time.Hour)
	if err := l.Record(e); err != nil {
		t.Fatal(err)
	}
	paths, _ := filepath.Glob(filepath.Join(c.Dir, "activity-*.jsonl"))
	if len(paths) != 1 {
		t.Fatal("daily rotation failed")
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatal("cleanup removed an unrelated file")
	}
}

func TestLegacyDaemonLogCountsTowardLimit(t *testing.T) {
	c := config(t)
	c.RotateBytes, c.MaxBytes = 500, 1200
	l, err := activity.New(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Clean(); err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(c.Dir, "daemon.log")
	if err := os.WriteFile(legacy, make([]byte, 1500), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := l.Record(activity.Event{Command: "ls", Operation: "list", Outcome: "ok"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatal("legacy daemon history escaped the total size cap")
	}
}

func TestUnsafeFilesAreRefused(t *testing.T) {
	for _, unsafe := range []string{"directory-link", "directory-mode", "file-link", "file-mode", "lock-link", "hard-link"} {
		t.Run(unsafe, func(t *testing.T) {
			c := config(t)
			if err := os.MkdirAll(c.Dir, 0o700); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(t.TempDir(), "target")
			if err := os.WriteFile(target, []byte("unchanged"), 0o600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(c.Dir, "activity.jsonl")
			switch unsafe {
			case "directory-link":
				os.Remove(c.Dir)
				os.Symlink(filepath.Dir(target), c.Dir)
			case "directory-mode":
				os.Chmod(c.Dir, 0o755)
			case "file-link":
				os.Symlink(target, path)
			case "file-mode":
				os.WriteFile(path, nil, 0o644)
			case "lock-link":
				os.Symlink(target, filepath.Join(c.Dir, "activity.lock"))
			case "hard-link":
				os.Link(target, path)
			}
			l, err := activity.New(c)
			if err == nil {
				err = l.Record(activity.Event{Command: "ls", Operation: "list", Outcome: "ok"})
			}
			if err == nil {
				t.Fatal("unsafe path accepted")
			}
			data, _ := os.ReadFile(target)
			if string(data) != "unchanged" {
				t.Fatal("unsafe target was modified")
			}
		})
	}
}

func TestConcurrentProcessesAppendWholeRecords(t *testing.T) {
	c := config(t)
	var wg sync.WaitGroup
	for range 3 {
		wg.Go(func() {
			cmd := exec.Command(os.Args[0], "-test.run=^TestAppenderChild$")
			cmd.Env = append(os.Environ(), "KEYWARD_LOG_TEST_DIR="+c.Dir)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("child: %v %s", err, out)
			}
		})
	}
	wg.Wait()
	if n, _ := records(t, c.Dir); n != 60 {
		t.Fatal("concurrent records were lost")
	}
}

func TestAppenderChild(t *testing.T) {
	dir := os.Getenv("KEYWARD_LOG_TEST_DIR")
	if dir == "" {
		t.Skip("subprocess helper")
	}
	c := activity.DefaultConfig("")
	c.Dir = dir
	l, err := activity.New(c)
	if err != nil {
		t.Fatal(err)
	}
	for range 20 {
		if err := l.Record(activity.Event{Command: "run", Operation: "get", Name: "token", Outcome: "ok"}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestConfigurationDefaultsAndOverrides(t *testing.T) {
	c, err := activity.FromEnv("/test", func(string) string { return "" })
	if err != nil || c.Retention != 30*24*time.Hour || c.MaxBytes != 50<<20 || c.RotateBytes != 10<<20 {
		t.Fatal("wrong defaults")
	}
	values := map[string]string{"KEYWARD_LOG_RETENTION_DAYS": "7", "KEYWARD_LOG_MAX_MB": "20", "KEYWARD_LOG_ROTATE_MB": "5", "KEYWARD_LOG_DIR": "/temporary"}
	c, err = activity.FromEnv("/test", func(k string) string { return values[k] })
	if err != nil || c.Retention != 7*24*time.Hour || c.MaxBytes != 20<<20 || c.RotateBytes != 5<<20 || c.Dir != "/temporary" {
		t.Fatal("overrides not applied")
	}
	values["KEYWARD_LOG_MAX_MB"] = "dummy-private-value"
	if _, err := activity.FromEnv("/test", func(k string) string { return values[k] }); err == nil || strings.Contains(err.Error(), "dummy-private-value") {
		t.Fatal("invalid setting accepted or disclosed")
	}
}
