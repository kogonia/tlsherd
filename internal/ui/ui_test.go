package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/kogonia/tlsherd/internal/domain"
)

type fakeSessions map[string]*domain.User

func (f fakeSessions) LookupSession(_ context.Context, token string) (*domain.User, *domain.Session, error) {
	if u, ok := f[token]; ok {
		return u, &domain.Session{}, nil
	}
	return nil, nil, domain.ErrUnauthorized
}

func newTestUI() http.Handler {
	return New(fakeSessions{
		"admin-token": {ID: uuid.New(), Login: "root", Role: domain.RoleAdmin, IsActive: true},
		"op-token":    {ID: uuid.New(), Login: "ops", Role: domain.RoleOperator, IsActive: true},
	}, nil)
}

func get(h http.Handler, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestPagesRender(t *testing.T) {
	h := newTestUI()
	id := uuid.NewString()
	for _, p := range []string{
		"/", "/enrollments", "/groups", "/domains", "/domains/" + id, "/servers", "/servers/" + id,
		"/settings/agent-defaults", "/settings/notifications", "/notification-accounts",
		"/notification-accounts/new", "/notification-accounts/" + id, "/events", "/users", "/monitor", "/account",
	} {
		rec := get(h, p, "admin-token")
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", p, rec.Code)
			continue
		}
		if !strings.Contains(rec.Body.String(), `id="view"`) {
			t.Errorf("GET %s: missing #view", p)
		}
	}
}

func TestLoginPage(t *testing.T) {
	h := newTestUI()
	rec := get(h, "/login", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "login-form") {
		t.Fatalf("login page: %d", rec.Code)
	}
	if rec.Header().Get("Content-Security-Policy") == "" {
		t.Error("missing CSP header")
	}
	if rec := get(h, "/login", "admin-token"); rec.Code != http.StatusSeeOther {
		t.Errorf("login with session = %d, want redirect", rec.Code)
	}
}

func TestAuthRedirectAndRoles(t *testing.T) {
	h := newTestUI()
	if rec := get(h, "/domains", ""); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Errorf("anonymous: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if rec := get(h, "/users", "op-token"); rec.Code != http.StatusForbidden {
		t.Errorf("operator on admin page = %d, want 403", rec.Code)
	}
	rec := get(h, "/domains", "op-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("operator domains = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `id="sidebar"`) {
		t.Error("missing sidebar")
	}
	if !strings.Contains(body, `<a class="brand" href="/">TLS herd</a>`) {
		t.Error("missing brand → Dashboard link")
	}
	if strings.Contains(body, `href="/users"`) {
		t.Error("operator nav shows admin entries")
	}
	if strings.Contains(body, `>Dashboard</`) || strings.Contains(body, `nav-text">Dashboard`) {
		t.Error("Dashboard must not appear in sidebar nav")
	}
	if !strings.Contains(body, `nav-group-label">Fleet`) || !strings.Contains(body, `nav-group-label">Health`) {
		t.Error("operator sidebar missing Fleet/Health groups")
	}
	if strings.Contains(body, `nav-group-label">Access`) || strings.Contains(body, `nav-group-label">Settings`) {
		t.Error("operator sidebar shows empty admin groups")
	}
	adminBody := get(h, "/domains", "admin-token").Body.String()
	if !strings.Contains(adminBody, `href="/users"`) {
		t.Error("admin nav lacks Users")
	}
	if !strings.Contains(adminBody, `nav-group-label">Access`) || !strings.Contains(adminBody, `nav-group-label">Settings`) {
		t.Error("admin sidebar missing Access/Settings groups")
	}
	if strings.Contains(adminBody, `nav-text">Dashboard`) {
		t.Error("Dashboard must not appear in admin sidebar")
	}
}

func TestBadIDAndStatic(t *testing.T) {
	h := newTestUI()
	if rec := get(h, "/domains/not-a-uuid", "admin-token"); rec.Code != http.StatusNotFound {
		t.Errorf("bad id = %d, want 404", rec.Code)
	}
	for _, p := range []string{"/static/app.js", "/static/app.css", "/static/htmx.min.js"} {
		if rec := get(h, p, ""); rec.Code != http.StatusOK || rec.Body.Len() == 0 {
			t.Errorf("GET %s = %d", p, rec.Code)
		}
	}
}
