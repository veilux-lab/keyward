//go:build !darwin

package daemon

import (
	"errors"
	"net"
)

// sameUser fails closed where peer credentials have not been implemented.
func sameUser(net.Conn) error {
	return errors.New("peer credentials are only checked on macOS")
}
