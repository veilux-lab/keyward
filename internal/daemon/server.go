package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/nwokolo24/keyward/internal/vault"
)

// ioTimeout bounds reading a request and writing a response. Not the store call
// in between, which may be waiting on a person answering a Keychain prompt.
const ioTimeout = 10 * time.Second

// Server answers requests against Store.
type Server struct {
	Store vault.Store

	// Authorize vets each connection before it is read. Nil means the peer must be
	// the same user as the daemon.
	Authorize func(net.Conn) error

	// Log receives one line per request: operation, name, outcome. Never values.
	// Nil discards.
	Log io.Writer

	wg sync.WaitGroup
}

// Run serves store on path until ctx is cancelled.
func Run(ctx context.Context, path string, store vault.Store, log io.Writer) error {
	l, err := Listen(path)
	if err != nil {
		return err
	}
	defer l.Close()
	stop := context.AfterFunc(ctx, func() { l.Close() })
	defer stop()

	s := &Server{Store: store, Log: log}
	s.logf("listening on %s", path)
	err = s.Serve(l)
	s.logf("stopped")
	return err
}

// Serve accepts connections until l is closed, then waits for requests in
// flight. A request cut off mid-write could leave a caller unsure what happened.
func (s *Server) Serve(l net.Listener) error {
	defer s.wg.Wait()
	for {
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(conn)
		}()
	}
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(ioTimeout))

	authorize := s.Authorize
	if authorize == nil {
		authorize = sameUser
	}
	if err := authorize(conn); err != nil {
		s.logf("refused a connection: %v", err)
		s.reply(conn, errorResponse(fmt.Errorf("%w: the daemon refused the connection", vault.ErrDenied)))
		return
	}

	var req request
	if err := json.NewDecoder(io.LimitReader(conn, maxMessage)).Decode(&req); err != nil {
		s.logf("unreadable request: %v", err)
		s.reply(conn, errorResponse(errors.New("the daemon could not read the request")))
		return
	}
	conn.SetReadDeadline(time.Time{})

	resp := s.dispatch(req)
	clear(req.Value)
	outcome := "ok"
	if resp.Code != "" {
		outcome = resp.Code
	}
	s.logf("%s %s: %s", req.Op, req.Name, outcome)

	s.reply(conn, resp)
	clear(resp.Value)
}

func (s *Server) dispatch(req request) response {
	var err error
	switch req.Op {
	case "get":
		var secret vault.Secret
		if secret, err = s.Store.Get(req.Name); err == nil {
			// The caller zeroes this after replying, which destroys the secret.
			return response{Value: secret.Bytes()}
		}
	case "put":
		value := vault.NewSecret(req.Value)
		err = s.Store.Put(req.Name, value, req.Note)
		value.Destroy()
	case "replace":
		value := vault.NewSecret(req.Value)
		err = s.Store.Replace(req.Name, value, req.Note)
		value.Destroy()
	case "delete":
		err = s.Store.Delete(req.Name)
	case "entries":
		var entries []vault.Entry
		if entries, err = s.Store.Entries(); err == nil {
			return response{Entries: entries}
		}
	default:
		err = fmt.Errorf("unknown operation %q", req.Op)
	}
	if err != nil {
		return errorResponse(err)
	}
	return response{}
}

func (s *Server) reply(conn net.Conn, resp response) {
	conn.SetWriteDeadline(time.Now().Add(ioTimeout))
	if err := json.NewEncoder(conn).Encode(resp); err != nil {
		s.logf("could not reply: %v", err)
	}
}

func (s *Server) logf(format string, args ...any) {
	if s.Log == nil {
		return
	}
	fmt.Fprintf(s.Log, "%s %s\n", time.Now().UTC().Format(time.RFC3339), fmt.Sprintf(format, args...))
}
