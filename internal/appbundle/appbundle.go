// Package appbundle packages Keyward's status app separately from the CLI signer.
package appbundle

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

const ID = "com.nwokolo24.keyward.app"

const information = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.nwokolo24.keyward.app</string>
<key>CFBundleName</key><string>Keyward</string>
<key>CFBundleDisplayName</key><string>Keyward by Veilux</string>
<key>CFBundleExecutable</key><string>keyward-app</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleVersion</key><string>1</string>
<key>CFBundleShortVersionString</key><string>0.1.0</string>
<key>LSMinimumSystemVersion</key><string>13.0</string>
<key>LSUIElement</key><true/>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
`

func Build(target, cli, app string) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(filepath.Dir(target), ".keyward-build-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	for relative, source := range map[string]string{"Contents/Helpers/keyward": cli, "Contents/MacOS/keyward-app": app} {
		path := filepath.Join(stage, relative)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := copyFile(source, path, 0o755); err != nil {
			return err
		}
	}
	if err := os.WriteFile(filepath.Join(stage, "Contents", "Info.plist"), []byte(information), 0o644); err != nil {
		return err
	}
	update, err := Prepare(stage, target)
	if err != nil {
		return err
	}
	defer update.Close()
	if err := update.Apply(); err != nil {
		return err
	}
	update.Commit()
	return nil
}

// Update retains the old app until the caller has verified the new installation.
type Update struct {
	target, staging              string
	movedOld, applied, committed bool
}

func Prepare(source, target string) (*Update, error) {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(target); err == nil {
		if !info.IsDir() {
			return nil, fmt.Errorf("refusing to replace non-directory app %s", target)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	stage, err := os.MkdirTemp(filepath.Dir(target), ".keyward-update-")
	if err != nil {
		return nil, err
	}
	u := &Update{target: target, staging: stage}
	err = filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		destination := filepath.Join(stage, "new", relative)
		if entry.IsDir() {
			return os.MkdirAll(destination, 0o755)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("refusing to copy non-regular app resource %s", path)
		}
		return copyFile(path, destination, info.Mode().Perm())
	})
	if err != nil {
		os.RemoveAll(stage)
		return nil, err
	}
	return u, nil
}

func (u *Update) Apply() error {
	if _, err := os.Lstat(u.target); err == nil {
		if err := os.Rename(u.target, filepath.Join(u.staging, "old")); err != nil {
			return err
		}
		u.movedOld = true
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(filepath.Join(u.staging, "new"), u.target); err != nil {
		return err
	}
	u.applied = true
	return nil
}

func (u *Update) Restore() error {
	if u.applied {
		if err := os.RemoveAll(u.target); err != nil {
			return err
		}
		u.applied = false
	}
	if u.movedOld {
		if err := os.Rename(filepath.Join(u.staging, "old"), u.target); err != nil {
			return err
		}
		u.movedOld = false
	}
	return nil
}

func (u *Update) Commit() { u.committed = true }

func (u *Update) Close() error {
	if !u.committed {
		if err := u.Restore(); err != nil {
			return fmt.Errorf("app backup retained at %s: %w", u.staging, err)
		}
	}
	return os.RemoveAll(u.staging)
}

func copyFile(source, target string, mode os.FileMode) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	return errors.Join(err, out.Close())
}
