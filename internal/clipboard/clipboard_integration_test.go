//go:build darwin && cgo && integration

package clipboard

import (
	"crypto/sha256"
	"os"
	"os/exec"
	"strconv"
	"testing"
)

// It replaces what is on the clipboard, so it runs only when asked.
func TestTheRealClipboard(t *testing.T) {
	if os.Getenv("KEYWARD_TEST_CLIPBOARD") != "1" {
		t.Skip("replaces the clipboard; set KEYWARD_TEST_CLIPBOARD=1 to run it")
	}
	pasted := func() [32]byte {
		out, err := exec.Command("pbpaste").Output()
		if err != nil {
			t.Fatal(err)
		}
		return sha256.Sum256(out)
	}
	value := []byte("keyward-clipboard-test")
	count, err := Copy(value)
	if err != nil {
		t.Fatal(err)
	}
	if got := (General{}).ChangeCount(); got != count {
		t.Errorf("change count %d, but Copy returned %d", got, count)
	}
	if pasted() != sha256.Sum256(value) {
		t.Error("the clipboard holds something else")
	}
	ClearWhenDue(General{}, []string{strconv.Itoa(count + 1), "0s"})
	if pasted() != sha256.Sum256(value) {
		t.Error("cleared a clipboard that had changed since")
	}
	ClearWhenDue(General{}, []string{strconv.Itoa(count), "0s"})
	if pasted() != sha256.Sum256(nil) {
		t.Error("did not clear the clipboard")
	}
}
