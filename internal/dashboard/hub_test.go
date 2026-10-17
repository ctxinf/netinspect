package dashboard

import (
	"testing"
	"time"

	"netinspect/internal/proxy"
	"netinspect/internal/store"
)

func TestHubFanout(t *testing.T) {
	h := NewHub()
	sub := h.Subscribe()
	defer h.Unsubscribe(sub)

	c := &store.Conn{ID: 7, Comm: "curl"}
	h.Publish(proxy.Event{Type: "conn_new", Conn: c})

	select {
	case e := <-sub:
		if e.Type != "conn_new" || e.Conn.ID != 7 || e.Conn.Comm != "curl" {
			t.Fatalf("bad event: %+v", e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event received")
	}
}

func TestHubUnsubscribe(t *testing.T) {
	h := NewHub()
	sub := h.Subscribe()
	h.Unsubscribe(sub)
	// publish must not block or panic with no subscribers
	h.Publish(proxy.Event{Type: "conn_closed"})
}
