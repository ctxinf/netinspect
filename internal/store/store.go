// Package store is a pure in-memory store for the current session's
// connection-level metadata. Nothing is persisted: when the target process
// exits, all records are discarded. Only metadata is kept — never content.
package store

import (
	"strings"
	"sync"
	"time"
)

// Session is the single live session.
type Session struct {
	ID           string `json:"id"`
	StartedAt    int64  `json:"started_at"`
	EndedAt      int64  `json:"ended_at"`
	Command      string `json:"command"`
	Mode         string `json:"mode"`
	DashboardURL string `json:"dashboard_url"`
}

// Conn is one intercepted TCP connection (metadata only).
type Conn struct {
	ID        int64   `json:"id"`
	PID       int    `json:"pid"`
	Comm      string `json:"comm"`
	Mode      string `json:"mode"`
	OrigHost  string `json:"orig_host"`
	OrigIP    string `json:"orig_ip"`
	OrigPort  int    `json:"orig_port"`
	Route     string `json:"route"`
	Proto     string `json:"proto"`
	SNI       string `json:"sni"`
	ALPN      string `json:"alpn"`
	StartedAt int64  `json:"started_at"`
	EndedAt   int64  `json:"ended_at"`
	ConnectMs float64 `json:"connect_ms"`
	TLSMs     float64 `json:"tls_ms"`
	BytesUp   int64  `json:"bytes_up"`
	BytesDown int64  `json:"bytes_down"`
	Result    string `json:"result"`
	Error     string `json:"error"`
}

// DNSQuery is one observed DNS question/answer (metadata only).
type DNSQuery struct {
	ID     int64   `json:"id"`
	PID    int    `json:"pid"`
	Comm   string `json:"comm"`
	QName  string `json:"qname"`
	QType  string `json:"qtype"`
	Answer string `json:"answer"`
	Ms     float64 `json:"ms"`
	At     int64  `json:"at"`
}

// Stats aggregates the live session.
type Stats struct {
	Conns     int   `json:"conns"`
	Failed    int   `json:"failed"`
	BytesUp   int64 `json:"bytes_up"`
	BytesDown int64 `json:"bytes_down"`
	DNS       int   `json:"dns"`
}

// Store holds the current session in memory.
type Store struct {
	mu       sync.RWMutex
	session  Session
	conns    []*Conn
	dns      []*DNSQuery
	nextConn int64
	nextDNS  int64
}

// New creates a store for one session.
func New(se Session) *Store {
	return &Store{session: se, nextConn: 1, nextDNS: 1}
}

// Session returns a copy of the session record.
func (s *Store) Session() Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.session
}

// SetDashboardURL records the dashboard URL on the session.
func (s *Store) SetDashboardURL(url string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.session.DashboardURL = url
}

// EndSession stamps the session end time.
func (s *Store) EndSession() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.session.EndedAt = time.Now().UnixMilli()
}

// AddConnection appends a connection and returns its id.
func (s *Store) AddConnection(c *Conn) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	c.ID = s.nextConn
	s.nextConn++
	c.StartedAt = time.Now().UnixMilli()
	s.conns = append(s.conns, c)
	return c.ID
}

// find returns the live pointer; caller must hold the lock.
func (s *Store) find(id int64) *Conn {
	for _, c := range s.conns {
		if c.ID == id {
			return c
		}
	}
	return nil
}

// UpdateConnMeta fills proto/sni/alpn once classified.
func (s *Store) UpdateConnMeta(id int64, proto, sni, alpn string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c := s.find(id); c != nil {
		c.Proto, c.SNI, c.ALPN = proto, sni, alpn
	}
}

// SetTLSMs records the passive TLS handshake latency.
func (s *Store) SetTLSMs(id int64, ms float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c := s.find(id); c != nil {
		c.TLSMs = ms
	}
}

// FinishConnection stamps end, byte counters, result and error text.
func (s *Store) FinishConnection(id int64, up, down int64, result, errText string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c := s.find(id); c != nil {
		c.EndedAt = time.Now().UnixMilli()
		c.BytesUp, c.BytesDown = up, down
		c.Result, c.Error = result, errText
	}
}

// AddDNS records one DNS query, returning its id.
func (s *Store) AddDNS(q *DNSQuery) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	q.ID = s.nextDNS
	s.nextDNS++
	q.At = time.Now().UnixMilli()
	s.dns = append(s.dns, q)
	return q.ID
}

// Stats aggregates the session.
func (s *Store) Stats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var st Stats
	for _, c := range s.conns {
		st.Conns++
		st.BytesUp += c.BytesUp
		st.BytesDown += c.BytesDown
		if c.Result != "ok" && c.Result != "open" && c.Result != "" {
			st.Failed++
		}
	}
	st.DNS = len(s.dns)
	return st
}

// ListConnections returns copies of connections, newest first, with an
// optional substring filter over host/sni/ip/comm.
func (s *Store) ListConnections(q string, limit int) []Conn {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Conn
	for i := len(s.conns) - 1; i >= 0; i-- {
		c := s.conns[i]
		if q != "" {
			ql := strings.ToLower(q)
			hay := strings.ToLower(c.OrigHost + " " + c.SNI + " " + c.OrigIP + " " + c.Comm)
			if !strings.Contains(hay, ql) {
				continue
			}
		}
		out = append(out, *c)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

// ListDNS returns copies of DNS queries, newest first.
func (s *Store) ListDNS(limit int) []DNSQuery {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []DNSQuery
	for i := len(s.dns) - 1; i >= 0; i-- {
		out = append(out, *s.dns[i])
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

// FmtTime formats epoch millis for terminal display.
func FmtTime(ms int64) string {
	if ms == 0 {
		return "-"
	}
	return time.UnixMilli(ms).Format("15:04:05")
}
