//go:build darwin && cgo

package appbundle

/*
#cgo LDFLAGS: -framework CoreServices -framework CoreFoundation
#include <CoreServices/CoreServices.h>
#include <stdlib.h>
#include <string.h>

static OSStatus kw_register_app(const char *path) {
	CFURLRef url = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault,
		(const UInt8 *)path, strlen(path), true);
	if (!url) return memFullErr;
	OSStatus status = LSRegisterURL(url, true);
	CFRelease(url);
	return status;
}
*/
import "C"

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
	"unsafe"
)

func Register(path string) error {
	value := C.CString(path)
	defer C.free(unsafe.Pointer(value))
	if status := C.kw_register_app(value); status != 0 {
		return fmt.Errorf("register Keyward with Launch Services: OSStatus %d", status)
	}
	return nil
}

// Team is signing metadata only; no Keychain item is read.
func Team(path string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/bin/codesign", "-dv", "--verbose=4", path).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("read signing team: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if value, ok := strings.CutPrefix(line, "TeamIdentifier="); ok && len(value) == 10 {
			return value, nil
		}
	}
	return "", fmt.Errorf("%s has no Apple signing team", path)
}
