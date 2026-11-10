// Package ui is the embedded web UI of TLS herd.
//
// It serves small server-rendered HTML shells (html/template) plus static
// assets (CSS, JS, vendored HTMX), all embedded into the binary; there is no
// frontend build step. The shells carry no business data: the browser script
// (static/app.js) fills them by calling the same-origin JSON API under
// /api/v1 with the session cookie and the X-CSRF-Token header, so every
// authorization decision stays in the service layer. The UI itself only
// checks that a valid session exists (to redirect to /login) and uses the
// user's role to decide which navigation entries and pages to show.
//
// Third-party scripts are never loaded: the Content-Security-Policy allows
// only same-origin scripts and styles, which matters because the console
// controls commands that agents run as root.
package ui

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/kogonia/tlsherd/internal/domain"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// sessionCookie must match the cookie set by the login handler.
const sessionCookie = "tlsherd_session"

const csp = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"

// Sessions resolves a session token to its user (implemented by service.Services).
type Sessions interface {
	LookupSession(ctx context.Context, token string) (*domain.User, *domain.Session, error)
}

type navItem struct {
	Label      string
	Href       string
	Page       string   // primary page name for this entry
	MatchPages []string // page names that mark this item active (details)
	AdminOnly  bool
	Abbr       string // short label when sidebar is collapsed
}

type navGroup struct {
	Label string
	Items []navItem
}

// page describes one server-rendered shell.
type page struct {
	Path      string // ServeMux pattern path
	Name      string // template file (without .html) and data-page value
	Title     string
	AdminOnly bool
	HasID     bool // path contains {id}, a UUID
}

var pages = []page{
	{Path: "/{$}", Name: "dashboard", Title: "Dashboard"},
	{Path: "/enrollments", Name: "enrollments", Title: "Enrollments", AdminOnly: true},
	{Path: "/groups", Name: "groups", Title: "Groups", AdminOnly: true},
	{Path: "/domains", Name: "domains", Title: "Domains"},
	{Path: "/domains/{id}", Name: "domain", Title: "Domain", HasID: true},
	{Path: "/servers", Name: "servers", Title: "Servers"},
	{Path: "/servers/{id}", Name: "server", Title: "Server", HasID: true},
	{Path: "/settings/agent-defaults", Name: "defaults", Title: "Agent defaults", AdminOnly: true},
	{Path: "/settings/monitor", Name: "monitor-settings", Title: "Monitor settings", AdminOnly: true},
	{Path: "/settings/notifications", Name: "notify-settings", Title: "Notifications", AdminOnly: true},
	{Path: "/notification-accounts", Name: "notify-accounts", Title: "Notification accounts", AdminOnly: true},
	{Path: "/notification-accounts/new", Name: "notify-account-new", Title: "New notification account", AdminOnly: true},
	{Path: "/notification-accounts/{id}", Name: "notify-account", Title: "Notification account", AdminOnly: true, HasID: true},
	{Path: "/managed-certificates", Name: "managed-certs", Title: "Managed certificates", AdminOnly: true},
	{Path: "/managed-certificates/{id}", Name: "managed-cert", Title: "Managed certificate", AdminOnly: true, HasID: true},
	{Path: "/events", Name: "events", Title: "Events"},
	{Path: "/users", Name: "users", Title: "Users", AdminOnly: true},
	{Path: "/monitor", Name: "monitor", Title: "Monitor"},
	{Path: "/account", Name: "account", Title: "Account"},
}

// navGroups is the sidebar IA. Dashboard is the brand link in the header only.
var navGroups = []navGroup{
	{Label: "Fleet", Items: []navItem{
		{Label: "Domains", Href: "/domains", Page: "domains", MatchPages: []string{"domains", "domain"}, Abbr: "Dom"},
		{Label: "Servers", Href: "/servers", Page: "servers", MatchPages: []string{"servers", "server"}, Abbr: "Srv"},
		{Label: "Managed certs", Href: "/managed-certificates", Page: "managed-certs",
			MatchPages: []string{"managed-certs", "managed-cert"}, Abbr: "Mgt", AdminOnly: true},
		{Label: "Enrollments", Href: "/enrollments", Page: "enrollments", Abbr: "Enr", AdminOnly: true},
	}},
	{Label: "Health", Items: []navItem{
		{Label: "Monitor", Href: "/monitor", Page: "monitor", Abbr: "Mon"},
		{Label: "Events", Href: "/events", Page: "events", Abbr: "Evt"},
	}},
	{Label: "Access", Items: []navItem{
		{Label: "Groups", Href: "/groups", Page: "groups", Abbr: "Grp", AdminOnly: true},
		{Label: "Users", Href: "/users", Page: "users", Abbr: "Usr", AdminOnly: true},
	}},
	{Label: "Settings", Items: []navItem{
		{Label: "Agent defaults", Href: "/settings/agent-defaults", Page: "defaults", Abbr: "Def", AdminOnly: true},
		{Label: "Monitor", Href: "/settings/monitor", Page: "monitor-settings", Abbr: "Mon", AdminOnly: true},
		{Label: "Notifications", Href: "/settings/notifications", Page: "notify-settings", Abbr: "Ntf", AdminOnly: true},
		{Label: "Notification accounts", Href: "/notification-accounts", Page: "notify-accounts",
			MatchPages: []string{"notify-accounts", "notify-account", "notify-account-new"}, Abbr: "Acc", AdminOnly: true},
	}},
}

type pageData struct {
	Title     string
	Page      string
	ID        string
	User      *domain.User
	IsAdmin   bool
	NavGroups []navGroup
}

// IsActive reports whether page matches this nav entry (for templates).
func (n navItem) IsActive(page string) bool {
	if page == n.Page {
		return true
	}
	for _, p := range n.MatchPages {
		if p == page {
			return true
		}
	}
	return false
}

// filterNavGroups returns groups with AdminOnly items removed for non-admins
// and empty groups dropped.
func filterNavGroups(isAdmin bool) []navGroup {
	out := make([]navGroup, 0, len(navGroups))
	for _, g := range navGroups {
		items := make([]navItem, 0, len(g.Items))
		for _, n := range g.Items {
			if !n.AdminOnly || isAdmin {
				items = append(items, n)
			}
		}
		if len(items) == 0 {
			continue
		}
		out = append(out, navGroup{Label: g.Label, Items: items})
	}
	return out
}

// UI is the web UI handler.
type UI struct {
	sessions Sessions
	log      *slog.Logger
	tmpl     map[string]*template.Template
	mux      *http.ServeMux
}

// New returns the web UI handler, to be mounted at "/". It panics if the
// embedded templates are broken (a programmer error caught at startup).
func New(sessions Sessions, logger *slog.Logger) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	u := &UI{
		sessions: sessions,
		log:      logger.With("component", "ui"),
		tmpl:     make(map[string]*template.Template),
		mux:      http.NewServeMux(),
	}
	names := []string{"login"}
	for _, p := range pages {
		names = append(names, p.Name)
	}
	for _, name := range names {
		t, err := template.ParseFS(templateFS, "templates/base.html", "templates/"+name+".html")
		if err != nil {
			panic(fmt.Sprintf("ui: parse template %q: %v", name, err))
		}
		u.tmpl[name] = t
	}

	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(fmt.Sprintf("ui: static fs: %v", err))
	}
	u.mux.Handle("GET /static/", http.StripPrefix("/static/", noCache(http.FileServerFS(sub))))
	u.mux.HandleFunc("GET /login", u.login)
	for _, p := range pages {
		u.mux.HandleFunc("GET "+p.Path, u.pageHandler(p))
	}
	return secureHeaders(u.mux)
}

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

// noCache makes browsers revalidate assets so a new binary is picked up at once.
func noCache(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		next.ServeHTTP(w, r)
	})
}

// currentUser returns the user of the request's session cookie, or nil.
func (u *UI) currentUser(r *http.Request) *domain.User {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return nil
	}
	user, _, err := u.sessions.LookupSession(r.Context(), c.Value)
	if err != nil || user == nil {
		return nil
	}
	return user
}

func (u *UI) login(w http.ResponseWriter, r *http.Request) {
	if u.currentUser(r) != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	u.render(w, r, "login", pageData{Title: "Sign in", Page: "login"})
}

func (u *UI) pageHandler(p page) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := u.currentUser(r)
		if user == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if user.MustChangePassword && p.Name != "account" {
			http.Redirect(w, r, "/account", http.StatusSeeOther)
			return
		}
		isAdmin := user.Role == domain.RoleAdmin
		if p.AdminOnly && !isAdmin {
			http.Error(w, "forbidden: administrators only", http.StatusForbidden)
			return
		}
		data := pageData{
			Title: p.Title, Page: p.Name, User: user, IsAdmin: isAdmin,
			NavGroups: filterNavGroups(isAdmin),
		}
		if p.HasID {
			id, err := uuid.Parse(r.PathValue("id"))
			if err != nil {
				http.NotFound(w, r)
				return
			}
			data.ID = id.String()
		}
		u.render(w, r, p.Name, data)
	}
}

func (u *UI) render(w http.ResponseWriter, r *http.Request, name string, data pageData) {
	var sb strings.Builder
	if err := u.tmpl[name].ExecuteTemplate(&sb, "base", data); err != nil {
		u.log.Error("render page failed", "operation", "render", "page", name, "path", r.URL.Path, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(sb.String()))
}
