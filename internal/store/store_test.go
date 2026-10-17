package store

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

func TestMemoryLimitStopsNewRecordsButAllowsCompletion(t *testing.T) {
	s := NewWithLimit(Session{}, recordReservation*2)
	c := &Conn{OrigHost: "retained", Result: "open"}
	id := s.AddConnection(c)
	s.AddDNS(&DNSQuery{QName: "retained.test"})
	if s.AddConnection(&Conn{}) != 0 || s.AddDNS(&DNSQuery{}) != 0 {
		t.Fatal("accepted records above budget")
	}
	s.UpdateConnMeta(id, "tls", "retained.test", "h2")
	s.SetConnectMs(id, 12)
	s.SetTLSMs(id, 20)
	s.FinishConnection(id, 30, 40, "ok", "")
	got := s.ListConnections("", 10)
	if len(got) != 1 || got[0].EndedAt == 0 || got[0].BytesDown != 40 || got[0].SNI != "retained.test" || got[0].ConnectMs != 12 {
		t.Fatalf("lost existing record updates: %+v", got)
	}
	if m := s.Memory(); !m.Limited || m.Dropped != 2 || m.Used > m.Limit {
		t.Fatalf("bad memory status: %+v", m)
	}
	if s.AddConnection(&Conn{}) != 0 {
		t.Fatal("resumed collection after completion")
	}
	st := s.Stats()
	if st.Conns != 1 || st.DNS != 1 || st.BytesUp != 30 || st.BytesDown != 40 {
		t.Fatalf("bad stats: %+v", st)
	}
}

func TestStoreOwnsBoundedRecords(t *testing.T) {
	s := New(Session{})
	large := strings.Repeat("域", 10000)
	c := &Conn{OrigHost: large, Error: large, Result: "open"}
	id := s.AddConnection(c)
	c.OrigHost = "caller mutated"
	c.BytesUp = 999
	s.UpdateConnMeta(id, large, large, large)
	s.FinishConnection(id, 1, 2, "error", large)
	s.FinishConnection(id, 1, 2, "error", large)
	got := s.ListConnections("", 1)[0]
	if len(got.OrigHost) > 256 || len(got.Error) > 1024 || len(got.SNI) > 256 || !utf8.ValidString(got.SNI) || got.OrigHost == c.OrigHost {
		t.Fatalf("unbounded or shared record: %+v", got)
	}
	if s.Stats().Failed != 1 || s.Stats().BytesUp != 1 {
		t.Fatal("completion double-counted")
	}
}

func TestQueryGlobalSortingFilteringAndPaging(t *testing.T) {
	s := New(Session{})
	for i := 0; i < 1200; i++ {
		c := &Conn{OrigHost: fmt.Sprintf("host-%04d", i), Comm: "client", Result: "open"}
		id := s.AddConnection(c)
		s.FinishConnection(id, 0, int64(1200-i), "ok", "")
	}
	s.AddConnection(&Conn{OrigHost: "live.test", Result: "open"})
	s.AddDNS(&DNSQuery{QName: "a-dns.test", Answer: "192.0.2.123"})
	p := s.QueryItems(Query{Status: "closed", Sort: "host", Direction: "asc", Size: 25, Page: 1})
	if p.Total != 1201 || p.Active != 1 || p.Closed != 1201 || p.Items[0].DNS == nil {
		t.Fatalf("bad unified page: %+v", p)
	}
	p = s.QueryItems(Query{Status: "closed", Sort: "down", Direction: "desc", Size: 25, Page: 1})
	if p.Items[0].Conn.OrigHost != "host-0000" {
		t.Fatal("sorted only recent rows instead of entire history")
	}
	p = s.QueryItems(Query{Status: "closed", Sort: "down", Direction: "desc", Size: 25, Page: 2})
	if p.Items[0].Conn.BytesDown != 1175 {
		t.Fatal("incorrect second page")
	}
	p = s.QueryItems(Query{Status: "closed", Q: "192.0.2.123", Page: 999999, Size: 500})
	if p.Total != 1 || p.Page != 1 || p.Size != 200 || p.Items[0].Kind != "dns" {
		t.Fatalf("bad filter or page bounds: %+v", p)
	}
	p = s.QueryItems(Query{Status: "active"})
	if p.Total != 1 || p.Items[0].Conn.OrigHost != "live.test" {
		t.Fatal("active partition incorrect")
	}
}

func TestMultiColumnSortAndConcurrentSnapshots(t *testing.T) {
	s := New(Session{})
	a := s.AddConnection(&Conn{Comm: "same", OrigHost: "z"})
	s.AddConnection(&Conn{Comm: "same", OrigHost: "a"})
	p := s.QueryItems(Query{Sort: "process,host", Direction: "asc"})
	if p.Items[0].Conn.OrigHost != "a" {
		t.Fatal("secondary sort ignored")
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		for i := 0; i < 100; i++ {
			s.UpdateConnMeta(a, "tls", "example.test", "h2")
			s.FinishConnection(a, int64(i), 0, "ok", "")
		}
	})
	wg.Go(func() {
		for i := 0; i < 100; i++ {
			p := s.QueryItems(Query{})
			_ = p.Items[0].Conn.Result
		}
	})
	wg.Wait()
	if p.Items[1].Conn.EndedAt != 0 {
		t.Fatal("snapshot mutated after query")
	}
}

func TestRelativeTimeSortAcrossConnectionsAndDNS(t *testing.T) {
	s := New(Session{})
	old := s.AddConnection(&Conn{OrigHost: "old.test"})
	recent := s.AddConnection(&Conn{OrigHost: "recent.test"})
	s.AddDNS(&DNSQuery{QName: "newest.test"})
	s.mu.Lock()
	s.byID[old].StartedAt = 1000
	s.byID[recent].StartedAt = 2000
	s.dns[0].At = 3000
	s.mu.Unlock()
	p := s.QueryItems(Query{Sort: "age", Direction: "asc"})
	if p.Items[0].DNS == nil || p.Items[2].Conn.ID != old {
		t.Fatal("ascending age must put youngest records first")
	}
	p = s.QueryItems(Query{Sort: "age", Direction: "desc"})
	if p.Items[0].Conn.ID != old || p.Items[2].DNS == nil {
		t.Fatal("descending age must put oldest records first")
	}
}

func TestQueryALPNSortAndFilter(t *testing.T) {
	s := New(Session{})
	s.AddConnection(&Conn{ALPN: "http/1.1"})
	s.AddConnection(&Conn{ALPN: "h2"})
	p := s.QueryItems(Query{Sort: "alpn", Direction: "asc"})
	if len(p.Items) != 2 || p.Items[0].Conn.ALPN != "h2" {
		t.Fatal("ALPN ordering incorrect")
	}
	p = s.QueryItems(Query{Q: "http/1.1"})
	if p.Total != 1 || p.Items[0].Conn.ALPN != "http/1.1" {
		t.Fatal("ALPN filter incorrect")
	}
}

func TestEndpointMetadataAndProcessPath(t *testing.T) {
	s := New(Session{})
	c := &Conn{PID: os.Getpid(), Source: "127.0.0.1:40000", OrigIP: "2001:db8::1", OrigPort: 443}
	s.AddConnection(c)
	s.AddDNS(&DNSQuery{Source: "192.0.2.1:53000", Dest: "8.8.8.8:53"})
	p := s.QueryItems(Query{Q: "127.0.0.1:40000", Sort: "source"})
	if p.Total != 1 || p.Items[0].text("dest") != "[2001:db8::1]:443" {
		t.Fatal("connection endpoints missing")
	}
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", os.Getpid()))
	if err == nil && p.Items[0].Conn.Exe != exe {
		t.Fatal("full process path missing")
	}
	p = s.QueryItems(Query{Q: "8.8.8.8:53", Sort: "dest"})
	if p.Total != 1 || p.Items[0].DNS.Source != "192.0.2.1:53000" {
		t.Fatal("DNS endpoints missing")
	}
}

func TestProtocolNormalizationAndCommandLine(t *testing.T) {
	s := New(Session{})
	c := &Conn{PID: os.Getpid(), Proto: "tcp"}
	id := s.AddConnection(c)
	got := s.ListConnections("", 1)[0]
	if got.Proto != "TCP" || got.Cmdline == "" {
		t.Fatalf("missing normalized protocol or command line: %+v", got)
	}
	s.UpdateConnMeta(id, "tls", "", "h2")
	if s.ListConnections("", 1)[0].Proto != "TLS" {
		t.Fatal("updated protocol not uppercase")
	}
	s.AddDNS(&DNSQuery{QType: "aaaa"})
	if s.ListDNS(1)[0].QType != "AAAA" {
		t.Fatal("DNS query type not uppercase")
	}
	s.AddConnection(&Conn{Cmdline: strings.Repeat("argument ", 1000)})
	if v := s.ListConnections("", 1)[0].Cmdline; len(v) > 1024 || !strings.HasSuffix(v, "…") {
		t.Fatal("command line not bounded")
	}
}
