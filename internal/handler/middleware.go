package handler

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/netip"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/kogonia/tlsherd/internal/domain"
)

const (
	minute = time.Minute

	sessionCookie = "tlsherd_session"
	csrfCookie    = "tlsherd_csrf"
	csrfHeader    = "X-CSRF-Token"
	requestIDHdr  = "X-Request-ID"
)

type ctxKey int

const (
	ctxRequestID ctxKey = iota
	ctxLogger
)

var requestIDRe = regexp.MustCompile(`^[A-Za-z0-9._-]{8,64}$`)

// ---------------------------------------------------------------------------
// Request ID, logging, recovery

func (h *Handler) requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(requestIDHdr)
		if !requestIDRe.MatchString(id) {
			id = uuid.NewString()
		}
		w.Header().Set(requestIDHdr, id)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		ctx := context.WithValue(r.Context(), ctxRequestID, id)
		ctx = context.WithValue(ctx, ctxLogger, h.log.With("request_id", id))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// logger returns the request-scoped logger.
func (h *Handler) logger(r *http.Request) *slog.Logger {
	if l, ok := r.Context().Value(ctxLogger).(*slog.Logger); ok {
		return l
	}
	return h.log
}

type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wrote {
		w.status, w.wrote = code, true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.status, w.wrote = http.StatusOK, true
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (h *Handler) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			next.ServeHTTP(w, r)
			return
		}
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(sw, r)
		h.logger(r).Info("request",
			"operation", "http",
			"method", r.Method, "path", r.URL.Path, "status", sw.status,
			"duration_ms", time.Since(start).Milliseconds(), "ip", h.clientIP(r).String())
	})
}

// recoverer turns panics into a logged stack trace and a generic 500.
func (h *Handler) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			rec := recover()
			if rec == nil {
				return
			}
			if rec == http.ErrAbortHandler {
				panic(rec)
			}
			h.logger(r).Error("panic in handler", "operation", "recover",
				"panic", rec, "stack", string(debug.Stack()), "method", r.Method, "path", r.URL.Path)
			writeAPIError(w, http.StatusInternalServerError, "internal", "internal error")
		}()
		next.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------------------
// Client IP

// clientIP returns the peer IP, or the last X-Forwarded-For entry when a
// trusted proxy is configured.
func (h *Handler) clientIP(r *http.Request) netip.Addr {
	if h.opt.TrustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if ip, err := netip.ParseAddr(strings.TrimSpace(parts[len(parts)-1])); err == nil {
				return ip.Unmap()
			}
		}
	}
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		return ap.Addr().Unmap()
	}
	if ip, err := netip.ParseAddr(r.RemoteAddr); err == nil {
		return ip.Unmap()
	}
	return netip.Addr{}
}

// ---------------------------------------------------------------------------
// Session auth + CSRF

type authedFunc func(w http.ResponseWriter, r *http.Request, u *domain.User)

// sessionToken extracts the session token: Authorization Bearer wins over the
// cookie. viaCookie tells whether CSRF protection applies.
func sessionToken(r *http.Request) (token string, viaCookie bool) {
	if t := bearerToken(r); t != "" {
		return t, false
	}
	if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
		return c.Value, true
	}
	return "", false
}

func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	v := r.Header.Get("Authorization")
	if len(v) > len(prefix) && strings.EqualFold(v[:len(prefix)], prefix) {
		return strings.TrimSpace(v[len(prefix):])
	}
	return ""
}

// csrfToken derives the CSRF token bound to a session token. It is
// unguessable without the session token and reveals nothing about it.
func csrfToken(sessionToken string) string {
	sum := sha256.Sum256([]byte("tlsherd-csrf:" + sessionToken))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// passwordChangeAllowed paths remain usable while must_change_password is set.
func passwordChangeAllowed(r *http.Request) bool {
	switch r.URL.Path {
	case "/api/v1/auth/me":
		return r.Method == http.MethodGet
	case "/api/v1/auth/password", "/api/v1/auth/logout":
		return r.Method == http.MethodPost
	default:
		return false
	}
}

// authed requires a valid session. Cookie-authenticated mutations must carry
// a matching X-CSRF-Token (double submit); Bearer requests are exempt.
// Users with must_change_password may only call me / password / logout.
func (h *Handler) authed(fn authedFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, viaCookie := sessionToken(r)
		u, _, err := h.svc.LookupSession(r.Context(), token)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		if viaCookie && !safeMethod(r.Method) {
			got := r.Header.Get(csrfHeader)
			if subtle.ConstantTimeCompare([]byte(got), []byte(csrfToken(token))) != 1 {
				writeAPIError(w, http.StatusForbidden, "csrf", "missing or invalid CSRF token")
				return
			}
		}
		if u.MustChangePassword && !passwordChangeAllowed(r) {
			writeAPIError(w, http.StatusForbidden, "must_change_password",
				"password change required before continuing")
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		fn(w, r, u)
	})
}

func (h *Handler) setSessionCookies(w http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/", Expires: expires,
		HttpOnly: true, Secure: h.opt.SecureCookies, SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name: csrfCookie, Value: csrfToken(token), Path: "/", Expires: expires,
		HttpOnly: false, Secure: h.opt.SecureCookies, SameSite: http.SameSiteLaxMode,
	})
}

func (h *Handler) clearSessionCookies(w http.ResponseWriter) {
	for _, name := range []string{sessionCookie, csrfCookie} {
		http.SetCookie(w, &http.Cookie{
			Name: name, Value: "", Path: "/", MaxAge: -1,
			HttpOnly: name == sessionCookie, Secure: h.opt.SecureCookies, SameSite: http.SameSiteLaxMode,
		})
	}
}

// ---------------------------------------------------------------------------
// Agent auth

type agentFunc func(w http.ResponseWriter, r *http.Request, srv *domain.Server)

// agentAuthed authenticates an agent by Bearer key and source IP.
func (h *Handler) agentAuthed(fn agentFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := bearerToken(r)
		srv, err := h.svc.AuthenticateAgent(r.Context(), h.clientIP(r), key)
		if err != nil {
			w.Header().Set("WWW-Authenticate", "Bearer")
			h.fail(w, r, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		fn(w, r, srv)
	})
}

// ---------------------------------------------------------------------------
// Rate limiting

// rateLimiter is a small in-memory sliding-window limiter.
type rateLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	hits   map[string][]time.Time
	lastGC time.Time
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{limit: limit, window: window, hits: make(map[string][]time.Time)}
}

// allow records an attempt for key and reports whether it is within the
// limit; when not, retryAfter says how long until a slot frees up.
func (l *rateLimiter) allow(key string, now time.Time) (ok bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if now.Sub(l.lastGC) > l.window {
		for k, ts := range l.hits {
			if len(ts) == 0 || now.Sub(ts[len(ts)-1]) > l.window {
				delete(l.hits, k)
			}
		}
		l.lastGC = now
	}
	cutoff := now.Add(-l.window)
	ts := l.hits[key]
	i := 0
	for i < len(ts) && ts[i].Before(cutoff) {
		i++
	}
	ts = ts[i:]
	if len(ts) >= l.limit {
		l.hits[key] = ts
		return false, ts[0].Add(l.window).Sub(now)
	}
	l.hits[key] = append(ts, now)
	return true, 0
}
