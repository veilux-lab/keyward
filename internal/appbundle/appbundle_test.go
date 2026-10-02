package appbundle_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/nwokolo24/keyward/internal/appbundle"
)

func TestBuildPackagesBrandingAndKeepsDaemonSeparate(t *testing.T) {
	dir := t.TempDir()
	cli, app := filepath.Join(dir, "keyward"), filepath.Join(dir, "keyward-app")
	for path, content := range map[string]string{cli: "signed-cli", app: "status-app"} {
		if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	bundle := filepath.Join(dir, "Keyward.app")
	if err := appbundle.Build(bundle, cli, app); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{"Contents/Helpers/keyward": "signed-cli", "Contents/MacOS/keyward-app": "status-app"} {
		b, err := os.ReadFile(filepath.Join(bundle, path))
		if err != nil || string(b) != want {
			t.Fatalf("%s was not packaged correctly: %v", path, err)
		}
	}
	plist := filepath.Join(bundle, "Contents", "Info.plist")
	for key, want := range map[string]string{"CFBundleIdentifier": appbundle.ID, "CFBundleName": "Keyward", "CFBundleDisplayName": "Keyward by Veilux", "CFBundleExecutable": "keyward-app"} {
		out, err := exec.Command("/usr/bin/plutil", "-extract", key, "raw", "-o", "-", plist).Output()
		if err != nil || string(out) != want+"\n" {
			t.Fatalf("%s = %q, %v", key, out, err)
		}
	}
}

func TestBundleUpdateRestoresPriorApp(t *testing.T) {
	dir := t.TempDir()
	source, target := filepath.Join(dir, "source.app"), filepath.Join(dir, "installed.app")
	for path, value := range map[string]string{source: "new", target: "old"} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "marker"), []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	update, err := appbundle.Prepare(source, target)
	if err != nil {
		t.Fatal(err)
	}
	defer update.Close()
	if err := update.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := update.Restore(); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(target, "marker"))
	if string(b) != "old" {
		t.Fatal("rollback lost the old app")
	}
}

func TestBundleCopyRejectsSymlinks(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.app")
	if err := os.Mkdir(source, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/tmp", filepath.Join(source, "escape")); err != nil {
		t.Fatal(err)
	}
	if _, err := appbundle.Prepare(source, filepath.Join(dir, "target.app")); err == nil {
		t.Fatal("bundle copied a link outside the app")
	}
}
