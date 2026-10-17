// Package dashboard serves the live session view: a JSON REST API, a
// WebSocket event stream, and a single-page UI (embedded, vanilla JS).
// Everything is in-memory; only the currently running session is shown.
package dashboard

import (
	"embed"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"sync"

	"netinspect/internal/proxy"
	"netinspect/internal/store"
)

//go:embed web/*
var webFS embed.FS

// Hub fans proxy events out to WebSocket subscribers.
type Hub struct {
	mu   sync.Mutex
	subs map[chan proxy.Event]struct{}
}

// NewHub creates an event hub.
func NewHub() *Hub { return &Hub{subs: make(map[chan proxy.Event]struct{})} }

// Publish sends an event to all subscribers (non-blocking).
func (h *Hub) Publish(e proxy.Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- e:
		default:
		}
	}
}

// Subscribe returns a channel receiving events; Unsubscribe removes it.
func (h *Hub) Subscribe() chan proxy.Event {
	ch := make(chan proxy.Event, 64)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

// Unsubscribe removes a subscription.
func (h *Hub) Unsubscribe(ch chan proxy.Event) {
	h.mu.Lock()
	delete(h.subs, ch)
	h.mu.Unlock()
	close(ch)
}

// Server is the dashboard HTTP server.
type Server struct {
	store *store.Store
	hub   *Hub
	mux   *http.ServeMux
}

// New creates a dashboard server.
func New(st *store.Store, hub *Hub) *Server {
	d := &Server{store: st, hub: hub, mux: http.NewServeMux()}
	d.mux.HandleFunc("/api/session", d.handleSession)
	d.mux.HandleFunc("/api/connections", d.handleConnections)
	d.mux.HandleFunc("/api/dns", d.handleDNS)
	d.mux.HandleFunc("/api/ws", d.handleWS)
	d.mux.HandleFunc("/", d.handleUI)
	return d
}

// Serve runs the dashboard on ln.
func (d *Server) Serve(ln net.Listener) error {
	return http.Serve(ln, d.mux)
}

// Handler exposes the mux for embedding in other servers.
func (d *Server) Handler() http.Handler { return d.mux }

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func (d *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"session": d.store.Session(),
		"stats":   d.store.Stats(),
	})
}

func (d *Server) handleConnections(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 500
	}
	conns := d.store.ListConnections(q, limit)
	if conns == nil {
		conns = []store.Conn{}
	}
	writeJSON(w, conns)
}

func (d *Server) handleDNS(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 500
	}
	q := d.store.ListDNS(limit)
	if q == nil {
		q = []store.DNSQuery{}
	}
	writeJSON(w, q)
}

func (d *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	if p == "/" {
		p = "/index.html"
	}
	data, err := webFS.ReadFile("web" + p)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	switch {
	case len(p) >= 5 && p[len(p)-5:] == ".html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	case len(p) >= 3 && p[len(p)-3:] == ".js":
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	case len(p) >= 4 && p[len(p)-4:] == ".css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	}
	w.Write(data)
}
