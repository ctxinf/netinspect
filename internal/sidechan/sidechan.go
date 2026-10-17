// Package sidechan implements the Unix datagram side-channel used by the
// preload shim and the ptrace tracer to tell the proxy core which process
// owns a freshly intercepted connection.
//
// Datagram format (ASCII, space separated):
//
//	MAP <srcport> <pid> <orighost> <origport> <mode>
//
// orighost is always an IP literal (no spaces), mode is one of
// preload|ptrace.
package sidechan

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Entry is one attribution record.
type Entry struct {
	SrcPort  int
	PID      int
	OrigHost string // IP literal
	OrigPort int
	Mode     string
	SeenAt   time.Time
}

const entryTTL = 60 * time.Second

// Server receives MAP datagrams on a Unix datagram socket.
type Server struct {
	path string
	conn *net.UnixConn
	mu   sync.Mutex
	tab  map[int]Entry
	done chan struct{}
}

// New creates a side-channel server bound to path. Any stale socket file at
// path is removed first.
func New(path string) (*Server, error) {
	os.Remove(path)
	addr, err := net.ResolveUnixAddr("unixgram", path)
	if err != nil {
		return nil, err
	}
	c, err := net.ListenUnixgram("unixgram", addr)
	if err != nil {
		return nil, err
	}
	s := &Server{path: path, conn: c, tab: make(map[int]Entry), done: make(chan struct{})}
	go s.loop()
	go s.sweep()
	return s, nil
}

func (s *Server) loop() {
	buf := make([]byte, 512)
	for {
		n, err := s.conn.Read(buf)
		if err != nil {
			select {
			case <-s.done:
				return
			default:
			}
			continue
		}
		e, ok := parseMap(string(buf[:n]))
		if !ok {
			continue
		}
		e.SeenAt = time.Now()
		s.mu.Lock()
		s.tab[e.SrcPort] = e
		s.mu.Unlock()
	}
}

func parseMap(msg string) (Entry, bool) {
	f := strings.Fields(strings.TrimSpace(msg))
	if len(f) != 6 || f[0] != "MAP" {
		return Entry{}, false
	}
	src, err1 := strconv.Atoi(f[1])
	pid, err2 := strconv.Atoi(f[2])
	port, err3 := strconv.Atoi(f[4])
	if err1 != nil || err2 != nil || err3 != nil {
		return Entry{}, false
	}
	return Entry{SrcPort: src, PID: pid, OrigHost: f[3], OrigPort: port, Mode: f[5]}, true
}

func (s *Server) sweep() {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
			now := time.Now()
			s.mu.Lock()
			for k, e := range s.tab {
				if now.Sub(e.SeenAt) > entryTTL {
					delete(s.tab, k)
				}
			}
			s.mu.Unlock()
		}
	}
}

// Lookup returns the entry for srcPort, if present.
func (s *Server) Lookup(srcPort int) (Entry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.tab[srcPort]
	return e, ok
}

// LookupRetry polls for up to timeout, waiting for the interceptor to send
// its MAP datagram after the proxy accepted the connection.
func (s *Server) LookupRetry(srcPort int, timeout time.Duration) (Entry, bool) {
	deadline := time.Now().Add(timeout)
	for {
		if e, ok := s.Lookup(srcPort); ok {
			return e, true
		}
		if time.Now().After(deadline) {
			return Entry{}, false
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Path returns the socket path.
func (s *Server) Path() string { return s.path }

// Close shuts down the server and removes the socket file.
func (s *Server) Close() error {
	close(s.done)
	err := s.conn.Close()
	os.Remove(s.path)
	return err
}

// Send is a helper for interceptors (used in tests): send one MAP datagram.
func Send(sockPath string, e Entry) error {
	addr, err := net.ResolveUnixAddr("unixgram", sockPath)
	if err != nil {
		return err
	}
	c, err := net.DialUnix("unixgram", nil, addr)
	if err != nil {
		return err
	}
	defer c.Close()
	msg := fmt.Sprintf("MAP %d %d %s %d %s", e.SrcPort, e.PID, e.OrigHost, e.OrigPort, e.Mode)
	_, err = c.Write([]byte(msg))
	return err
}
