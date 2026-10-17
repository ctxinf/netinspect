package dashboard

import (
	"net/http"
	"net/http/httptest"
	"netinspect/internal/store"
	"testing"
)

func TestShutdownControl(t *testing.T) {
	st := store.New(store.Session{ID: "test"})
	d := New(st, NewHub())
	stopped := false
	d.ConfigureControl("secret", func() { stopped = true }, nil)
	request := func(method, token string) int {
		req := httptest.NewRequest(method, "/api/shutdown", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		d.Handler().ServeHTTP(w, req)
		return w.Code
	}
	if request("GET", "secret") != http.StatusMethodNotAllowed {
		t.Fatal("GET allowed")
	}
	if request("POST", "wrong") != http.StatusForbidden {
		t.Fatal("wrong instance token allowed")
	}
	if request("POST", "secret") != http.StatusConflict || stopped {
		t.Fatal("stopped running target")
	}
	st.EndSession()
	if request("POST", "secret") != http.StatusOK || !stopped {
		t.Fatal("failed to stop ended session")
	}
	req := httptest.NewRequest("GET", "/api/control", nil)
	w := httptest.NewRecorder()
	d.Handler().ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatal("control token accessible without custom header")
	}
}
