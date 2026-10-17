package dashboard

import (
	"encoding/json"
	"net/http/httptest"
	"netinspect/internal/store"
	"testing"
)

func TestItemsAPIAndForwarding(t *testing.T) {
	st := store.New(store.Session{})
	st.AddDNS(&store.DNSQuery{QName: "query.test"})
	d := New(st, NewHub())
	w := httptest.NewRecorder()
	d.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/api/items?status=closed&sort=host&direction=asc&size=25", nil))
	var p store.Page
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &p) != nil || p.Total != 1 || p.Items[0].DNS.QName != "query.test" {
		t.Fatalf("bad items response: %s", w.Body.String())
	}
	w = httptest.NewRecorder()
	d.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/api/items?status=bogus", nil))
	if w.Code != 400 {
		t.Fatal("invalid status accepted")
	}
	d.SetDataHandler(New(store.New(store.Session{}), NewHub()).Handler())
	w = httptest.NewRecorder()
	d.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/api/items?status=closed", nil))
	if json.Unmarshal(w.Body.Bytes(), &p) != nil || p.Total != 0 {
		t.Fatal("netns unified endpoint was not forwarded")
	}
}
