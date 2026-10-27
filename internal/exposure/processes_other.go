//go:build !darwin

package exposure

import "errors"

// Processes is implemented only on macOS.
func Processes() ([]Process, error) {
	return nil, errors.New("listing processes is only implemented on macOS")
}
