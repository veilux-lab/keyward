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

	"github.com/veilux-lab/keyward/internal/activity"
	"github.com/veilux-lab/keyward/internal/handle"
	"github.com/veilux-lab/keyward/internal/vault"
)

// ioTimeout bounds reading a request and writing a response. Not the store call
// in between, which may be waiting on a person answering a Keychain prompt.
const ioTimeout = 10 * time.Second

// A Keychain prompt cannot be cancelled through Store. Give ordinary requests
// time to finish, then let the daemon process exit even if a prompt is waiting.
const shutdownGrace = time.Second

// Server answers requests against Store.
type Server struct {
	Store vault.Store

	// Version is the build that serves; ping reports it.
	Version string

	// Authorize vets each connection before it is read. Nil means the peer must be
	// the same user as the daemon.
	Authorize func(net.Conn) error

	Record func(activity.Event)

	wg          sync.WaitGroup
	mu          sync.Mutex
	connections map[net.Conn]struct{}
}

// Version is the running build, set by main; the server reports it on ping.
var Version = "dev"

// RunLogged serves store on path until ctx is cancelled, recording each request.
func RunLogged(ctx context.Context, path string, store vault.Store, record func(activity.Event)) error {
	l, err := listen(path)
	if err != nil {
		return err
	}
	defer l.Close()
	stop := context.AfterFunc(ctx, l.stopAccepting)
	defer stop()

	s := &Server{Store: store, Record: record, Version: Version}
	s.event("start", "", "ok", 0)
	err = s.Serve(l)
	s.event("stop", "", "ok", 0)
	return err
}

// Serve accepts connections until l is closed, then gives requests one second
// to finish. A blocked Store call may remain until the daemon process exits.
func (s *Server) Serve(l net.Listener) error {
	defer s.drain()
	for {
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		s.mu.Lock()
		if s.connections == nil {
			s.connections = make(map[net.Conn]struct{})
		}
		s.connections[conn] = struct{}{}
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() {
				s.mu.Lock()
				delete(s.connections, conn)
				s.mu.Unlock()
			}()
			s.handle(conn)
		}()
	}
}

func (s *Server) drain() {
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	timer := time.NewTimer(shutdownGrace)
	defer timer.Stop()
	select {
	case <-done:
		return
	case <-timer.C:
		s.event("shutdown", "", "interrupted", 0)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for conn := range s.connections {
		conn.Close()
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
		s.event("connection", "", "denied", 0)
		s.reply(conn, errorResponse(fmt.Errorf("%w: the daemon refused the connection", vault.ErrDenied)))
		return
	}

	var req request
	if err := json.NewDecoder(io.LimitReader(conn, maxMessage)).Decode(&req); err != nil {
		s.event("request", "", "invalid", 0)
		s.reply(conn, errorResponse(errors.New("the daemon could not read the request")))
		return
	}
	conn.SetReadDeadline(time.Time{})

	start := time.Now()
	resp := s.dispatch(req)
	clear(req.Value)
	op := req.Op
	switch op {
	case "ping":
		op = "status"
	case "entries":
		op = "list"
	case "get", "put", "replace", "delete":
	default:
		op = "request"
	}
	name, invalid := handle.Normalize(req.Name)
	if invalid != nil || resp.Code != "" {
		name = ""
	}
	s.event(op, name, activity.Outcome(resp.err()), time.Since(start).Milliseconds())

	s.reply(conn, resp)
	clear(resp.Value)
}

func (s *Server) dispatch(req request) response {
	var err error
	switch req.Op {
	case "ping":
		return response{Version: s.Version}
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
		s.event("reply", "", "error", 0)
	}
}

func (s *Server) event(op, name, outcome string, duration int64) {
	if s.Record != nil {
		s.Record(activity.Event{Command: "daemon", Operation: op, Name: name, Outcome: outcome, DurationMS: duration})
	}
}
