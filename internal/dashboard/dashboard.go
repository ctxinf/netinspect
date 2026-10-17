// Package dashboard serves the live session view: a JSON REST API, a
// WebSocket event stream, and a single-page UI (embedded, vanilla JS).
// Everything is in-memory; only the currently running session is shown.
package dashboard

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"netinspect/internal/proxy"
	"netinspect/internal/store"
	"netinspect/internal/version"
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
	store        *store.Store
	hub          *Hub
	mux          *http.ServeMux
	controlToken string
	stop         func()
	end          func()
	data         http.Handler
	dataMu       sync.RWMutex
}

// New creates a dashboard server.
func New(st *store.Store, hub *Hub) *Server {
	d := &Server{store: st, hub: hub, mux: http.NewServeMux()}
	d.mux.HandleFunc("/api/shutdown", d.handleShutdown)
	d.mux.HandleFunc("/api/control", d.handleControl)
	d.mux.HandleFunc("/api/end", d.handleEnd)
	d.mux.HandleFunc("/api/session", d.handleSession)
	d.mux.HandleFunc("/api/connections", d.handleConnections)
	d.mux.HandleFunc("/api/dns", d.handleDNS)
	d.mux.HandleFunc("/api/items", d.handleItems)
	d.mux.HandleFunc("/api/ws", d.handleWS)
	d.mux.HandleFunc("/", d.handleUI)
	return d
}

// Serve runs the dashboard on ln.
func (d *Server) Serve(ln net.Listener) error {
	return http.Serve(ln, d.Handler())
}

// Handler exposes the mux for embedding in other servers.
func (d *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.dataMu.RLock()
		data := d.data
		d.dataMu.RUnlock()
		if data != nil && (r.URL.Path == "/api/session" || r.URL.Path == "/api/connections" || r.URL.Path == "/api/dns" || r.URL.Path == "/api/ws" || r.URL.Path == "/api/items") {
			data.ServeHTTP(w, r)
			return
		}
		d.mux.ServeHTTP(w, r)
	})
}

// ConfigureControl must be called before Serve. Stop is allowed after the target ends.
func (d *Server) ConfigureControl(token string, stop, end func()) {
	d.controlToken = token
	d.stop = stop
	d.end = end
}
func (d *Server) SetDataHandler(h http.Handler) { d.dataMu.Lock(); defer d.dataMu.Unlock(); d.data = h }
func (d *Server) handleControl(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Header.Get("X-Netinspect-Control") != "1" {
		http.Error(w, "control header required", 403)
		return
	}
	writeJSON(w, map[string]any{"token": d.controlToken, "available": d.stop != nil})
}
func (d *Server) authorized(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "POST required", 405)
		return false
	}
	if d.controlToken == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+d.controlToken)) != 1 {
		http.Error(w, "unauthorized", 403)
		return false
	}
	return true
}
func (d *Server) handleShutdown(w http.ResponseWriter, r *http.Request) {
	if !d.authorized(w, r) {
		return
	}
	if d.stop == nil {
		http.Error(w, "unavailable", 409)
		return
	}
	if d.store.Session().EndedAt == 0 {
		http.Error(w, "target still running", 409)
		return
	}
	writeJSON(w, map[string]bool{"stopped": true})
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	d.stop()
}
func (d *Server) handleEnd(w http.ResponseWriter, r *http.Request) {
	if !d.authorized(w, r) {
		return
	}
	if d.end == nil {
		http.Error(w, "unavailable", 409)
		return
	}
	d.end()
	writeJSON(w, map[string]bool{"ended": true})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func (d *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"session": d.store.Session(),
		"stats":   d.store.Stats(),
		"memory":  d.store.Memory(),
		"version": version.Current(),
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

func (d *Server) handleItems(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query()
	page, _ := strconv.Atoi(v.Get("page"))
	size, _ := strconv.Atoi(v.Get("size"))
	status := v.Get("status")
	if status != "active" && status != "closed" && status != "" {
		http.Error(w, "invalid status", 400)
		return
	}
	direction := v.Get("direction")
	if direction != "" && direction != "asc" && direction != "desc" {
		http.Error(w, "invalid direction", 400)
		return
	}
	sortKeys := strings.Split(v.Get("sort"), ",")
	if len(sortKeys) > 3 {
		http.Error(w, "at most three sort columns", 400)
		return
	}
	for _, key := range sortKeys {
		switch key {
		case "", "kind", "time", "age", "host", "process", "pid", "protocol", "sni", "alpn", "source", "dest", "ip", "port", "route", "mode", "latency", "down", "up", "result":
		default:
			http.Error(w, "invalid sort column", 400)
			return
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, d.store.QueryItems(store.Query{Q: v.Get("q"), Status: status, Sort: v.Get("sort"), Direction: direction, Page: page, Size: size}))
}
