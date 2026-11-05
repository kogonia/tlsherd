package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kogonia/tlsherd/internal/domain"
	"github.com/kogonia/tlsherd/internal/service"
)

func newTestHandler(t *testing.T, opt Options) *Handler {
	t.Helper()
	return New(&service.Services{}, nil, opt)
}

func TestAdminAndAgentRoutes(t *testing.T) {
	h := newTestHandler(t, Options{})
	admin := h.AdminRoutes()
	agent := h.AgentRoutes()

	adminCases := []struct {
		method, path string
		want         int
	}{
		{"GET", "/healthz", http.StatusOK},
		{"GET", "/api/v1/users", http.StatusUnauthorized},
		{"POST", "/api/v1/domains", http.StatusUnauthorized},
		{"GET", "/api/v1/domains/00000000-0000-0000-0000-000000000000/certificates/current", http.StatusUnauthorized},
		{"POST", "/api/v1/agent/poll", http.StatusNotFound}, // agent API not on admin listener
		{"GET", "/api/v1/nope", http.StatusNotFound},
	}
	for _, tc := range adminCases {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		req.RemoteAddr = "192.0.2.10:1234"
		rec := httptest.NewRecorder()
		admin.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("admin %s %s = %d, want %d (%s)", tc.method, tc.path, rec.Code, tc.want, rec.Body)
		}
	}

	agentCases := []struct {
		method, path string
		want         int
	}{
		{"GET", "/healthz", http.StatusOK},
		{"POST", "/api/v1/agent/poll", http.StatusUnauthorized},
		{"GET", "/api/v1/agent/certs/abc", http.StatusUnauthorized},
		{"GET", "/api/v1/users", http.StatusNotFound}, // admin API not on agent listener
		{"GET", "/", http.StatusNotFound},
	}
	for _, tc := range agentCases {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		req.RemoteAddr = "192.0.2.10:1234"
		rec := httptest.NewRecorder()
		agent.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("agent %s %s = %d, want %d (%s)", tc.method, tc.path, rec.Code, tc.want, rec.Body)
		}
	}
}

func TestRecoverer(t *testing.T) {
	h := newTestHandler(t, Options{})
	srv := h.recoverer(h.requestID(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	})))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "boom") {
		t.Fatal("panic value leaked to client")
	}
}

func TestRateLimiter(t *testing.T) {
	l := newRateLimiter(3, time.Minute)
	now := time.Now()
	for i := 0; i < 3; i++ {
		if ok, _ := l.allow("k", now); !ok {
			t.Fatalf("attempt %d rejected", i)
		}
	}
	ok, retry := l.allow("k", now)
	if ok || retry <= 0 {
		t.Fatalf("4th attempt: ok=%v retry=%v", ok, retry)
	}
	if ok, _ := l.allow("other", now); !ok {
		t.Fatal("other key must be independent")
	}
	if ok, _ := l.allow("k", now.Add(61*time.Second)); !ok {
		t.Fatal("window should have expired")
	}
}

func TestCSRFToken(t *testing.T) {
	a, b := csrfToken("session-a"), csrfToken("session-b")
	if a == b || a != csrfToken("session-a") || strings.Contains(a, "session") {
		t.Fatal("csrf token must be deterministic per session and not leak it")
	}
}

func TestClientIP(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "[::ffff:192.0.2.1]:5555"
	req.Header.Set("X-Forwarded-For", "203.0.113.9, 198.51.100.7")

	if got := newTestHandler(t, Options{}).clientIP(req).String(); got != "192.0.2.1" {
		t.Fatalf("untrusted proxy: got %s", got)
	}
	if got := newTestHandler(t, Options{TrustProxy: true}).clientIP(req).String(); got != "198.51.100.7" {
		t.Fatalf("trusted proxy: got %s", got)
	}
}

func TestETagMatches(t *testing.T) {
	if !etagMatches(`"abc"`, `"abc"`) || !etagMatches(`W/"abc", "x"`, `"abc"`) || !etagMatches("*", `"abc"`) {
		t.Fatal("expected match")
	}
	if etagMatches(`"abd"`, `"abc"`) || etagMatches("", `"abc"`) {
		t.Fatal("unexpected match")
	}
}

func TestFailMapping(t *testing.T) {
	h := newTestHandler(t, Options{})
	cases := []struct {
		err  error
		want int
		code string
	}{
		{domain.ErrNotFound, 404, "not_found"},
		{domain.ErrForbidden, 403, "forbidden"},
		{domain.ErrLastAdmin, 400, "last_admin"},
		{domain.ErrSelfModification, 403, "self_modification"},
		{domain.ErrConfirmRequired, 409, "confirmation_required"},
		{domain.ErrKeyCertMismatch, 422, "key_mismatch"},
		{domain.ErrIdentityMismatch, 401, "identity_mismatch"},
		{&service.DomainMismatchError{RequestedDomain: "a.example"}, 409, "domain_mismatch"},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		h.fail(rec, httptest.NewRequest("GET", "/", nil), tc.err)
		var body errorBody
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("%v: %v", tc.err, err)
		}
		if rec.Code != tc.want || body.Error.Code != tc.code {
			t.Errorf("%v: got %d/%s, want %d/%s", tc.err, rec.Code, body.Error.Code, tc.want, tc.code)
		}
	}
}
