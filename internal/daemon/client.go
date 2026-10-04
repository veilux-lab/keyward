package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/veilux-lab/keyward/internal/vault"
)

// ErrNotRunning means nothing is listening on the socket.
var ErrNotRunning = errors.New("the keyward daemon is not running")

// DefaultTimeout is how long a client waits for an answer. Long, because the
// daemon may be waiting on a person to approve a Keychain prompt.
const DefaultTimeout = 2 * time.Minute

// Client is a vault.Store backed by a running daemon.
type Client struct {
	Path string

	// Timeout bounds each request. Zero means DefaultTimeout.
	Timeout time.Duration

	// Start recovers a missing listener for vault requests. Ping never calls it.
	Start func() error
}

var _ vault.Store = (*Client)(nil)

// Ping checks availability without reading any Keychain item.
func (c *Client) Ping() error {
	_, err := c.do(request{Op: "ping"})
	return err
}

func (c *Client) Get(name string) (vault.Secret, error) {
	resp, err := c.do(request{Op: "get", Name: name})
	if err != nil {
		return vault.Secret{}, err
	}
	secret := vault.NewSecret(resp.Value)
	clear(resp.Value)
	return secret, nil
}

func (c *Client) Put(name string, value vault.Secret, note string) error {
	_, err := c.do(request{Op: "put", Name: name, Value: value.Bytes(), Note: note})
	return err
}

func (c *Client) Replace(name string, value vault.Secret, note string) error {
	_, err := c.do(request{Op: "replace", Name: name, Value: value.Bytes(), Note: note})
	return err
}

func (c *Client) Delete(name string) error {
	_, err := c.do(request{Op: "delete", Name: name})
	return err
}

func (c *Client) Entries() ([]vault.Entry, error) {
	resp, err := c.do(request{Op: "entries"})
	return resp.Entries, err
}

func (c *Client) do(req request) (response, error) {
	conn, err := net.DialTimeout("unix", c.Path, 2*time.Second)
	if err != nil && req.Op != "ping" && c.Start != nil && notRunning(err) {
		if err := c.Start(); err != nil {
			return response{}, fmt.Errorf("starting the keyward daemon: %w; run `keyward service install` to recover", err)
		}
		// No request was sent, so connecting once more cannot replay a write.
		conn, err = net.DialTimeout("unix", c.Path, 2*time.Second)
	}
	if err != nil {
		// No socket, or a socket left by a daemon that is gone.
		if notRunning(err) {
			hint := "run `keyward service install`"
			if c.Start == nil {
				hint += "; for development or isolated use, run `keyward daemon`"
			}
			return response{}, fmt.Errorf("%w; %s", ErrNotRunning, hint)
		}
		return response{}, fmt.Errorf("connecting to the keyward daemon: %w", err)
	}
	defer conn.Close()

	timeout := c.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	conn.SetDeadline(time.Now().Add(timeout))

	var resp response
	err = json.NewEncoder(conn).Encode(req)
	if err == nil {
		err = json.NewDecoder(io.LimitReader(conn, maxMessage)).Decode(&resp)
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return response{}, fmt.Errorf("no answer from the keyward daemon within %s; if a Keychain prompt is showing, approve it", timeout)
	}
	if err != nil {
		return response{}, fmt.Errorf("talking to the keyward daemon: %w", err)
	}
	return resp, resp.err()
}

func notRunning(err error) bool {
	return errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED)
}
