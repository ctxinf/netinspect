package dashboard

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netinspect/internal/store"
)

func exportConnections(t *testing.T, d *Server) (*httptest.ResponseRecorder, []store.Conn) {
	t.Helper()
	w := httptest.NewRecorder()
	d.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/api/export?q=unmatched&size=25", nil))
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/x-ndjson" {
		t.Fatalf("unexpected response: %d %v", w.Code, w.Header())
	}
	var connections []store.Conn
	if w.Body.Len() == 0 {
		return w, connections
	}
	if !strings.HasSuffix(w.Body.String(), "\n") {
		t.Fatal("missing final newline")
	}
	for _, line := range strings.Split(strings.TrimSuffix(w.Body.String(), "\n"), "\n") {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal([]byte(line), &fields); err != nil {
			t.Fatal(err)
		}
		if _, ok := fields["orig_host"]; !ok {
			t.Fatal("non-connection record exported")
		}
		var connection store.Conn
		if err := json.Unmarshal([]byte(line), &connection); err != nil {
			t.Fatal(err)
		}
		connections = append(connections, connection)
	}
	return w, connections
}

func TestExportAllConnections(t *testing.T) {
	st := store.New(store.Session{ID: "export-test", Mode: "preload"})
	for i := 0; i < 210; i++ {
		st.AddConnection(&store.Conn{OrigHost: "example.test", Error: "first\nsecond"})
	}
	st.AddDNS(&store.DNSQuery{QName: "excluded.test"})
	before := time.Now().UTC().Truncate(time.Second)
	w, connections := exportConnections(t, New(st, NewHub()))
	if len(connections) != 210 || connections[0].Error != "first\nsecond" {
		t.Fatal("connections lost or multiline fields corrupted")
	}
	filename := strings.TrimSuffix(strings.TrimPrefix(w.Header().Get("Content-Disposition"), `attachment; filename="netinspect-preload-`), `.jsonl"`)
	timestamp, err := time.Parse("20060102T150405Z", filename)
	if err != nil || timestamp.Before(before) || timestamp.After(time.Now().UTC()) {
		t.Fatalf("unexpected filename: %s", w.Header().Get("Content-Disposition"))
	}
}

func TestExportUsesDataHandler(t *testing.T) {
	host := New(store.New(store.Session{Mode: "preload"}), NewHub())
	st := store.New(store.Session{Mode: "netns"})
	st.AddConnection(&store.Conn{OrigHost: "agent.test"})
	host.SetDataHandler(New(st, NewHub()).Handler())
	w, connections := exportConnections(t, host)
	if len(connections) != 1 || connections[0].OrigHost != "agent.test" || !strings.Contains(w.Header().Get("Content-Disposition"), "netinspect-netns-") {
		t.Fatal("export did not use agent store and mode")
	}
}

func TestExportEmptyConnections(t *testing.T) {
	st := store.New(store.Session{Mode: "observe"})
	st.AddDNS(&store.DNSQuery{QName: "excluded.test"})
	w, connections := exportConnections(t, New(st, NewHub()))
	if len(connections) != 0 || w.Body.Len() != 0 {
		t.Fatal("empty connection export must be an empty JSONL file")
	}
}
