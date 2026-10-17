// Package store is a pure in-memory store for the current session's
// connection-level metadata. Records survive target exit until the dashboard
// process exits. Only metadata is kept — never content.
package store

import (
	"cmp"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Session is the single live session.
type Session struct {
	ID            string `json:"id"`
	StartedAt     int64  `json:"started_at"`
	EndedAt       int64  `json:"ended_at"`
	Command       string `json:"command"`
	Mode          string `json:"mode"`
	DashboardURL  string `json:"dashboard_url"`
	UpstreamProxy string `json:"upstream_proxy,omitempty"` // Display address only; never credentials.
}

// Conn is one intercepted TCP connection (metadata only).
type Conn struct {
	Source    string  `json:"source"`
	Exe       string  `json:"exe"`
	Cmdline   string  `json:"cmdline"`
	ID        int64   `json:"id"`
	PID       int     `json:"pid"`
	Comm      string  `json:"comm"`
	Mode      string  `json:"mode"`
	OrigHost  string  `json:"orig_host"`
	OrigIP    string  `json:"orig_ip"`
	OrigPort  int     `json:"orig_port"`
	Route     string  `json:"route"`
	Proto     string  `json:"proto"`
	SNI       string  `json:"sni"`
	ALPN      string  `json:"alpn"`
	StartedAt int64   `json:"started_at"`
	EndedAt   int64   `json:"ended_at"`
	ConnectMs float64 `json:"connect_ms"`
	TLSMs     float64 `json:"tls_ms"`
	BytesUp   int64   `json:"bytes_up"`
	BytesDown int64   `json:"bytes_down"`
	Result    string  `json:"result"`
	Error     string  `json:"error"`
}

// DNSQuery is one observed DNS question/answer (metadata only).
type DNSQuery struct {
	Source string  `json:"source"`
	Dest   string  `json:"dest"`
	ID     int64   `json:"id"`
	PID    int     `json:"pid"`
	Comm   string  `json:"comm"`
	QName  string  `json:"qname"`
	QType  string  `json:"qtype"`
	Answer string  `json:"answer"`
	Ms     float64 `json:"ms"`
	At     int64   `json:"at"`
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
	mu          sync.RWMutex
	session     Session
	conns       []*Conn
	dns         []*DNSQuery
	nextConn    int64
	nextDNS     int64
	byID        map[int64]*Conn
	memoryLimit int64
	memoryUsed  int64
	limited     bool
	dropped     int64
	stats       Stats
	queryMu     sync.Mutex
}

// New creates a store for one session.
func New(se Session) *Store {
	return NewWithLimit(se, DefaultMemoryLimit)
}

// DefaultMemoryLimit budgets retained metadata, including reserved update space.
const DefaultMemoryLimit int64 = 128 << 20

// A slot covers bounded strings, record/index overhead, snapshot structs and
// room for classification/error updates. This is a conservative storage budget,
// not a process RSS limit; proxy buffers and the Go runtime are separate.
const recordReservation int64 = 8192

func NewWithLimit(se Session, limit int64) *Store {
	if limit <= 0 {
		limit = DefaultMemoryLimit
	}
	return &Store{session: se, nextConn: 1, nextDNS: 1, byID: make(map[int64]*Conn), memoryLimit: limit}
}

type MemoryStatus struct {
	Used    int64 `json:"used"`
	Limit   int64 `json:"limit"`
	Limited bool  `json:"limited"`
	Dropped int64 `json:"dropped"`
}

func (s *Store) Memory() MemoryStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return MemoryStatus{s.memoryUsed, s.memoryLimit, s.limited, s.dropped}
}
func (s *Store) reserve() bool {
	if s.limited || s.memoryUsed+recordReservation > s.memoryLimit {
		s.limited = true
		s.dropped++
		return false
	}
	s.memoryUsed += recordReservation
	return true
}

// Clone bounded fields so substrings cannot retain arbitrarily large buffers.
func bounded(v string, n int) string {
	if len(v) > n {
		v = v[:n-3]
		for !utf8.ValidString(v) {
			v = v[:len(v)-1]
		}
		v += "…"
	}
	return strings.Clone(v)
}
func boundedConn(c Conn) Conn {
	c.Source = bounded(c.Source, 128)
	c.Exe = bounded(c.Exe, 512)
	c.Cmdline = bounded(c.Cmdline, 1024)
	c.Comm = bounded(c.Comm, 256)
	c.Mode = bounded(c.Mode, 32)
	c.OrigHost = bounded(c.OrigHost, 256)
	c.OrigIP = bounded(c.OrigIP, 64)
	c.Route = bounded(c.Route, 256)
	c.Proto = bounded(strings.ToUpper(c.Proto), 32)
	if c.Proto == "" {
		c.Proto = "TCP"
	}
	c.SNI = bounded(c.SNI, 256)
	c.ALPN = bounded(c.ALPN, 256)
	c.Result = bounded(c.Result, 64)
	c.Error = bounded(c.Error, 1024)
	return c
}
func failed(result string) bool { return result != "ok" && result != "open" && result != "" }

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
	if !s.reserve() {
		c.ID = 0
		return 0
	}
	if c.Exe == "" && c.PID > 0 {
		c.Exe, _ = os.Readlink("/proc/" + strconv.Itoa(c.PID) + "/exe")
	}
	if c.Cmdline == "" && c.PID > 0 {
		if f, err := os.Open("/proc/" + strconv.Itoa(c.PID) + "/cmdline"); err == nil {
			raw, _ := io.ReadAll(io.LimitReader(f, 1025))
			f.Close()
			args := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
			for n, arg := range args {
				if strings.ContainsAny(arg, " \t\n\"'\\") {
					args[n] = strconv.Quote(arg)
				}
			}
			c.Cmdline = bounded(strings.Join(args, " "), 1024)
		}
	}
	c.ID = s.nextConn
	s.nextConn++
	c.StartedAt = time.Now().UnixMilli()
	copy := boundedConn(*c)
	s.conns = append(s.conns, &copy)
	s.byID[c.ID] = &copy
	s.stats.Conns++
	s.stats.BytesUp += c.BytesUp
	s.stats.BytesDown += c.BytesDown
	if failed(c.Result) {
		s.stats.Failed++
	}
	return c.ID
}

// find returns the live pointer; caller must hold the lock.
func (s *Store) find(id int64) *Conn {
	return s.byID[id]
}

// UpdateConnMeta fills proto/sni/alpn once classified.
func (s *Store) UpdateConnMeta(id int64, proto, sni, alpn string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c := s.find(id); c != nil {
		c.Proto, c.SNI, c.ALPN = bounded(strings.ToUpper(proto), 32), bounded(sni, 256), bounded(alpn, 256)
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
		s.stats.BytesUp += up - c.BytesUp
		s.stats.BytesDown += down - c.BytesDown
		if failed(c.Result) {
			s.stats.Failed--
		}
		if failed(result) {
			s.stats.Failed++
		}
		c.EndedAt = time.Now().UnixMilli()
		c.BytesUp, c.BytesDown = up, down
		c.Result, c.Error = bounded(result, 64), bounded(errText, 1024)
	}
}

// AddDNS records one DNS query, returning its id.
func (s *Store) AddDNS(q *DNSQuery) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.reserve() {
		q.ID = 0
		return 0
	}
	q.ID = s.nextDNS
	s.nextDNS++
	q.At = time.Now().UnixMilli()
	copy := *q
	copy.Source = bounded(q.Source, 128)
	copy.Dest = bounded(q.Dest, 128)
	copy.Comm = bounded(q.Comm, 256)
	copy.QName = bounded(q.QName, 256)
	copy.QType = bounded(strings.ToUpper(q.QType), 32)
	copy.Answer = bounded(q.Answer, 2048)
	s.dns = append(s.dns, &copy)
	s.stats.DNS++
	return q.ID
}

// Stats aggregates the session.
func (s *Store) Stats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.stats
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

// SetConnectMs updates latency without sharing mutable proxy-owned records.
func (s *Store) SetConnectMs(id int64, ms float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c := s.find(id); c != nil {
		c.ConnectMs = ms
	}
}

type Item struct {
	Kind string    `json:"kind"`
	Conn *Conn     `json:"conn,omitempty"`
	DNS  *DNSQuery `json:"dns,omitempty"`
}
type Query struct {
	Q, Status, Sort, Direction string
	Page, Size                 int
}
type Page struct {
	Items  []Item `json:"items"`
	Total  int    `json:"total"`
	Active int    `json:"active"`
	Closed int    `json:"closed"`
	Page   int    `json:"page"`
	Size   int    `json:"size"`
}

func (i Item) number(key string) float64 {
	if i.Conn != nil {
		c := i.Conn
		switch key {
		case "age":
			return -float64(c.StartedAt)
		case "time":
			return float64(c.StartedAt)
		case "up":
			return float64(c.BytesUp)
		case "down":
			return float64(c.BytesDown)
		case "latency":
			return c.ConnectMs
		case "pid":
			return float64(c.PID)
		case "port":
			return float64(c.OrigPort)
		}
	} else if i.DNS != nil {
		switch key {
		case "age":
			return -float64(i.DNS.At)
		case "time":
			return float64(i.DNS.At)
		case "latency":
			return i.DNS.Ms
		case "pid":
			return float64(i.DNS.PID)
		}
	}
	return 0
}
func (i Item) text(key string) string {
	if key == "kind" {
		return i.Kind
	}
	if i.Conn != nil {
		c := i.Conn
		switch key {
		case "source":
			return c.Source
		case "dest":
			return net.JoinHostPort(c.OrigIP, strconv.Itoa(c.OrigPort))
		case "host":
			if c.OrigHost != "" {
				return c.OrigHost
			}
			return c.OrigIP
		case "process":
			return c.Comm
		case "protocol":
			return c.Proto
		case "result":
			return c.Result
		case "sni":
			return c.SNI
		case "alpn":
			return c.ALPN
		case "ip":
			return c.OrigIP
		case "route":
			return c.Route
		case "mode":
			return c.Mode
		}
	} else if i.DNS != nil {
		d := i.DNS
		switch key {
		case "source":
			return d.Source
		case "dest":
			return d.Dest
		case "host":
			if d.Answer != "" {
				return d.Answer
			}
			return d.QName
		case "process":
			return d.Comm
		case "protocol":
			return d.QType
		case "result":
			return d.Answer
		}
	}
	return ""
}

// QueryItems sorts the full retained dataset before slicing a page. Serializing
// queries bounds temporary sort buffers even with multiple browser clients.
func (s *Store) QueryItems(q Query) Page {
	s.queryMu.Lock()
	defer s.queryMu.Unlock()
	s.mu.RLock()
	if q.Size < 1 {
		q.Size = 50
	}
	if q.Size > 200 {
		q.Size = 200
	}
	if q.Page < 1 {
		q.Page = 1
	}
	out := Page{Page: q.Page, Size: q.Size, Items: []Item{}}
	items := make([]Item, 0, len(s.conns)+len(s.dns))
	needle := strings.ToLower(q.Q)
	add := func(i Item, active bool) {
		if needle != "" {
			dnsName := ""
			if i.DNS != nil {
				dnsName = i.DNS.QName
			}
			hay := i.text("source") + " " + i.text("dest") + " " + dnsName + " " + i.Kind + " " + i.text("host") + " " + i.text("process") + " " + i.text("protocol") + " " + i.text("result") + " " + i.text("sni") + " " + i.text("alpn") + " " + i.text("ip")
			if !strings.Contains(strings.ToLower(hay), needle) {
				return
			}
		}
		if active {
			out.Active++
		} else {
			out.Closed++
		}
		if q.Status == "active" && !active || q.Status == "closed" && active {
			return
		}
		if i.Conn != nil {
			c := *i.Conn
			i.Conn = &c
		} else {
			d := *i.DNS
			i.DNS = &d
		}
		items = append(items, i)
	}
	for _, c := range s.conns {
		add(Item{Kind: "connection", Conn: c}, c.EndedAt == 0)
	}
	for _, d := range s.dns {
		add(Item{Kind: "dns", DNS: d}, false)
	}
	s.mu.RUnlock()
	keys := strings.Split(q.Sort, ",")
	if q.Sort == "" {
		keys = []string{"time"}
	}
	sort.Slice(items, func(a, b int) bool {
		x, y := items[a], items[b]
		for _, key := range keys {
			var order int
			switch key {
			case "time", "age", "up", "down", "latency", "pid", "port":
				order = cmp.Compare(x.number(key), y.number(key))
			default:
				order = cmp.Compare(strings.ToLower(x.text(key)), strings.ToLower(y.text(key)))
			}
			if order != 0 {
				if q.Direction == "asc" {
					return order < 0
				}
				return order > 0
			}
		}
		if x.Kind != y.Kind {
			return x.Kind < y.Kind
		}
		if x.Conn != nil {
			return x.Conn.ID > y.Conn.ID
		}
		return x.DNS.ID > y.DNS.ID
	})
	out.Total = len(items)
	pages := (out.Total + q.Size - 1) / q.Size
	if pages < 1 {
		pages = 1
	}
	if out.Page > pages {
		out.Page = pages
	}
	start := (out.Page - 1) * q.Size
	end := start + q.Size
	if end > out.Total {
		end = out.Total
	}
	for _, i := range items[start:end] {
		if i.Conn != nil {
			c := *i.Conn
			i.Conn = &c
		} else {
			d := *i.DNS
			i.DNS = &d
		}
		out.Items = append(out.Items, i)
	}
	return out
}
