// Package activity records bounded local activity without secret values.
package activity

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/veilux-lab/keyward/internal/handle"
	"golang.org/x/sys/unix"
)

type Config struct {
	Dir                   string
	Retention             time.Duration
	MaxBytes, RotateBytes int64
	Now                   func() time.Time
}

func DefaultConfig(home string) Config {
	return Config{Dir: filepath.Join(home, "Library", "Logs", "keyward"), Retention: 30 * 24 * time.Hour, MaxBytes: 50 << 20, RotateBytes: 10 << 20, Now: time.Now}
}

func FromEnv(home string, getenv func(string) string) (Config, error) {
	c := DefaultConfig(home)
	if dir := getenv("KEYWARD_LOG_DIR"); dir != "" {
		c.Dir = dir
	}
	for _, setting := range []struct {
		key    string
		target *int64
		unit   int64
	}{
		{"KEYWARD_LOG_MAX_MB", &c.MaxBytes, 1 << 20}, {"KEYWARD_LOG_ROTATE_MB", &c.RotateBytes, 1 << 20},
	} {
		if value := getenv(setting.key); value != "" {
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil || n <= 0 || n > 1<<20 {
				return c, fmt.Errorf("%s must be a positive integer no greater than 1048576", setting.key)
			}
			*setting.target = n * setting.unit
		}
	}
	if value := getenv("KEYWARD_LOG_RETENTION_DAYS"); value != "" {
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil || n <= 0 || n > 36500 {
			return c, errors.New("KEYWARD_LOG_RETENTION_DAYS must be an integer from 1 to 36500")
		}
		c.Retention = time.Duration(n) * 24 * time.Hour
	}
	if c.RotateBytes > c.MaxBytes && getenv("KEYWARD_LOG_ROTATE_MB") == "" {
		c.RotateBytes = c.MaxBytes
	}
	return c, validate(c)
}

// Fields are deliberately limited; argv, environment, values, and error text
// have no place in an event.
type Event struct {
	Command    string `json:"command"`
	Operation  string `json:"operation"`
	Name       string `json:"name,omitempty"`
	Outcome    string `json:"outcome"`
	DurationMS int64  `json:"duration_ms,omitempty"`
}

type Log struct{ config Config }

func validate(c Config) error {
	if c.Dir == "" || c.Retention <= 0 || c.MaxBytes <= 0 || c.RotateBytes <= 0 || c.RotateBytes > c.MaxBytes {
		return errors.New("activity log limits must be positive; rotation must not exceed the total limit")
	}
	return nil
}

func New(c Config) (*Log, error) {
	if err := validate(c); err != nil {
		return nil, err
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return &Log{config: c}, nil
}

func allowed(value, choices string) bool {
	return strings.Contains(" "+choices+" ", " "+value+" ") && value != "" && !strings.ContainsAny(value, " \t\n\r")
}

func (l *Log) Record(e Event) error {
	if !allowed(e.Command, "add ls rm run migrate restore doctor daemon service help version") ||
		!allowed(e.Operation, "command put replace get resolve delete list exec start stop shutdown connection request reply diagnostic install uninstall status") ||
		!allowed(e.Outcome, "ok error denied not_found exists invalid empty_value cancelled started interrupted usage") || e.DurationMS < 0 {
		return errors.New("invalid activity event")
	}
	name, err := handle.Normalize(e.Name)
	if err != nil || e.Outcome != "ok" {
		e.Name = ""
	} else {
		e.Name = name
	}
	now := l.config.Now().UTC()
	record := struct {
		Time string `json:"time"`
		Event
	}{now.Format(time.RFC3339Nano), e}
	data, err := json.Marshal(record)
	if err != nil {
		return errors.New("could not encode activity event")
	}
	data = append(data, '\n')
	return l.locked(func(root *os.Root) error {
		if err := l.maintain(root, now, int64(len(data))); err != nil {
			return err
		}
		file, err := privateFile(root, "activity.jsonl")
		if err != nil {
			return err
		}
		defer file.Close()
		if n, err := file.Write(data); err != nil || n != len(data) {
			return errors.New("could not append activity event")
		}
		stamp := unix.NsecToTimeval(now.UnixNano())
		if err := unix.Futimes(int(file.Fd()), []unix.Timeval{stamp, stamp}); err != nil {
			return errors.New("could not timestamp activity event")
		}
		return nil
	})
}

func (l *Log) Clean() error {
	return l.locked(func(root *os.Root) error {
		if err := l.maintain(root, l.config.Now().UTC(), 0); err != nil {
			return err
		}
		f, err := privateFile(root, "activity.jsonl")
		if err != nil {
			return err
		}
		return f.Close()
	})
}

func privateInfo(info os.FileInfo, dir bool) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	mode := os.FileMode(0o600)
	if dir {
		mode = 0o700
	}
	return ok && stat.Uid == uint32(os.Getuid()) && info.Mode().Perm() == mode &&
		((dir && info.IsDir()) || (!dir && info.Mode().IsRegular() && stat.Nlink == 1))
}

func privateFile(root *os.Root, name string) (*os.File, error) {
	dir, err := root.Open(".")
	if err != nil {
		return nil, errors.New("could not open activity directory descriptor")
	}
	defer dir.Close()
	flags := unix.O_APPEND | unix.O_RDWR | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	// Exclusive creation avoids concurrent first-open failures on this Mac.
	fd, err := unix.Openat(int(dir.Fd()), name, flags|unix.O_CREAT|unix.O_EXCL, 0o600)
	if errors.Is(err, unix.EEXIST) {
		fd, err = unix.Openat(int(dir.Fd()), name, flags, 0)
	}
	if err != nil {
		return nil, fmt.Errorf("could not safely open %s: %w", name, err)
	}
	f := os.NewFile(uintptr(fd), name)
	info, err := f.Stat()
	if err != nil || !privateInfo(info, false) {
		f.Close()
		return nil, errors.New("activity log files must be regular, owned by you, and mode 600")
	}
	return f, nil
}

func (l *Log) locked(action func(*os.Root) error) error {
	if err := os.MkdirAll(l.config.Dir, 0o700); err != nil {
		return errors.New("could not create activity log directory")
	}
	info, err := os.Lstat(l.config.Dir)
	if err != nil || !privateInfo(info, true) {
		return errors.New("activity log directory must be owned by you and mode 700; symlinks are refused")
	}
	root, err := os.OpenRoot(l.config.Dir)
	if err != nil {
		return errors.New("could not open activity log directory")
	}
	defer root.Close()
	info, err = root.Stat(".")
	if err != nil || !privateInfo(info, true) {
		return errors.New("activity log directory changed")
	}
	lock, err := privateFile(root, "activity.lock")
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return errors.New("could not lock activity log")
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	return action(root)
}

var archivePattern = regexp.MustCompile(`^activity-[0-9]{20}-[0-9]{3}\.jsonl$`)

type archive struct {
	name string
	info os.FileInfo
}

func logFiles(root *os.Root) ([]archive, error) {
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return nil, errors.New("could not list activity archives")
	}
	var files []archive
	for _, entry := range entries {
		if entry.Name() != "activity.jsonl" && entry.Name() != "daemon.log" && !archivePattern.MatchString(entry.Name()) {
			continue
		}
		info, err := root.Lstat(entry.Name())
		if err != nil || !privateInfo(info, false) {
			return nil, errors.New("unsafe activity archive")
		}
		files = append(files, archive{entry.Name(), info})
	}
	sort.Slice(files, func(i, j int) bool {
		if files[i].info.ModTime().Equal(files[j].info.ModTime()) {
			return files[i].name < files[j].name
		}
		return files[i].info.ModTime().Before(files[j].info.ModTime())
	})
	return files, nil
}

func (l *Log) maintain(root *os.Root, now time.Time, incoming int64) error {
	if incoming > l.config.RotateBytes {
		return errors.New("activity event exceeds rotation limit")
	}
	files, err := logFiles(root)
	if err != nil {
		return err
	}
	for _, f := range files {
		if f.name != "activity.jsonl" || f.info.Size() == 0 {
			continue
		}
		if f.info.ModTime().UTC().Format("2006-01-02") != now.Format("2006-01-02") || f.info.Size()+incoming > l.config.RotateBytes {
			name := ""
			for i := 0; i < 1000; i++ {
				candidate := fmt.Sprintf("activity-%020d-%03d.jsonl", now.UnixNano(), i)
				if _, err := root.Lstat(candidate); errors.Is(err, os.ErrNotExist) {
					name = candidate
					break
				}
			}
			if name == "" {
				return errors.New("could not choose activity archive name")
			}
			if err := root.Rename(f.name, name); err != nil {
				return errors.New("could not rotate activity log")
			}
		}
	}
	files, err = logFiles(root)
	if err != nil {
		return err
	}
	var total int64
	var kept []archive
	for _, f := range files {
		if f.info.ModTime().Before(now.Add(-l.config.Retention)) {
			if err := root.Remove(f.name); err != nil {
				return errors.New("could not remove expired activity log")
			}
			continue
		}
		total += f.info.Size()
		kept = append(kept, f)
	}
	for _, f := range kept {
		if total+incoming <= l.config.MaxBytes {
			break
		}
		if f.name == "activity.jsonl" {
			continue
		}
		if err := root.Remove(f.name); err != nil {
			return errors.New("could not enforce activity log size limit")
		}
		total -= f.info.Size()
	}
	if total+incoming > l.config.MaxBytes {
		return errors.New("activity log exceeds total size limit")
	}
	return nil
}
