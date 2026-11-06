package handler

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kogonia/tlsherd/internal/domain"
)

func (h *Handler) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) readyz(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.Ready(r.Context()); err != nil {
		h.logger(r).Error("readiness check failed", "operation", "readyz", "error", err)
		writeAPIError(w, http.StatusServiceUnavailable, "not_ready", "not ready")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (h *Handler) tooManyRequests(w http.ResponseWriter, retry time.Duration) {
	secs := max(int(retry.Seconds())+1, 1)
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	writeAPIError(w, http.StatusTooManyRequests, "rate_limited", "too many attempts, try again later")
}

type loginRequest struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token     string       `json:"token"`
	CSRFToken string       `json:"csrf_token"`
	ExpiresAt time.Time    `json:"expires_at"`
	User      *domain.User `json:"user"`
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !h.decodeJSON(w, r, &req, false) {
		return
	}
	ip := h.clientIP(r)
	now := time.Now()
	if ok, retry := h.ipLimiter.allow(ip.String(), now); !ok {
		h.tooManyRequests(w, retry)
		return
	}
	if ok, retry := h.loginLimiter.allow(ip.String()+"|"+strings.ToLower(strings.TrimSpace(req.Login)), now); !ok {
		h.tooManyRequests(w, retry)
		return
	}
	res, err := h.svc.Login(r.Context(), req.Login, req.Password, ip, r.UserAgent())
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.setSessionCookies(w, res.Token, res.Session.CreatedAt.Add(24*time.Hour))
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, loginResponse{
		Token: res.Token, CSRFToken: csrfToken(res.Token), ExpiresAt: res.ExpiresAt, User: res.User,
	})
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request, _ *domain.User) {
	token, _ := sessionToken(r)
	if err := h.svc.Logout(r.Context(), token); err != nil {
		h.fail(w, r, err)
		return
	}
	h.clearSessionCookies(w)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) me(w http.ResponseWriter, r *http.Request, u *domain.User) {
	perms, err := h.svc.MyPermissions(r.Context(), u)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	token, _ := sessionToken(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"user": u, "permissions": perms, "csrf_token": csrfToken(token),
	})
}

type patchMeRequest struct {
	Theme *string `json:"theme"`
}

func (h *Handler) patchMe(w http.ResponseWriter, r *http.Request, u *domain.User) {
	var req patchMeRequest
	if !h.decodeJSON(w, r, &req, false) {
		return
	}
	if req.Theme == nil {
		writeAPIError(w, http.StatusBadRequest, "invalid", "theme is required")
		return
	}
	out, err := h.svc.UpdateOwnPreferences(r.Context(), u, *req.Theme)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

type changePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

func (h *Handler) changePassword(w http.ResponseWriter, r *http.Request, u *domain.User) {
	var req changePasswordRequest
	if !h.decodeJSON(w, r, &req, false) {
		return
	}
	if ok, retry := h.loginLimiter.allow(h.clientIP(r).String()+"|pw|"+u.ID.String(), time.Now()); !ok {
		h.tooManyRequests(w, retry)
		return
	}
	if err := h.svc.ChangeOwnPassword(r.Context(), u, req.OldPassword, req.NewPassword); err != nil {
		h.fail(w, r, err)
		return
	}
	h.clearSessionCookies(w)
	w.WriteHeader(http.StatusNoContent)
}
