package handler

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"github.com/kogonia/tlsherd/internal/domain"
	"github.com/kogonia/tlsherd/internal/service"
)

// ---------------------------------------------------------------------------
// Enrollments

func (h *Handler) listEnrollments(w http.ResponseWriter, r *http.Request, u *domain.User) {
	out, err := h.svc.ListEnrollments(r.Context(), u, r.URL.Query().Get("status"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

type acceptEnrollmentRequest struct {
	DisplayName  *string    `json:"display_name"`
	LinkServerID *uuid.UUID `json:"link_server_id"`
}

func (h *Handler) acceptEnrollment(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	var req acceptEnrollmentRequest
	if !h.decodeJSON(w, r, &req, true) {
		return
	}
	out, err := h.svc.AcceptEnrollment(r.Context(), u, id, service.AcceptInput(req))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) rejectEnrollment(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	out, err := h.svc.RejectEnrollment(r.Context(), u, id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// ---------------------------------------------------------------------------
// Servers

func (h *Handler) listServers(w http.ResponseWriter, r *http.Request, u *domain.User) {
	out, err := h.svc.ListServers(r.Context(), u)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) getServer(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	out, err := h.svc.GetServer(r.Context(), u, id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

type patchServerRequest struct {
	DisplayName *string `json:"display_name"`
}

func (h *Handler) updateServer(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	var req patchServerRequest
	if !h.decodeJSON(w, r, &req, false) {
		return
	}
	out, err := h.svc.UpdateServer(r.Context(), u, id, req.DisplayName)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) deleteServer(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	if err := h.svc.DeleteServer(r.Context(), u, id); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) rotateKey(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	out, err := h.svc.RotateAgentKey(r.Context(), u, id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) revokeKeys(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	if err := h.svc.RevokeServerKeys(r.Context(), u, id); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// getServerConfig serves both /config and /effective-config: a server's
// document is its effective config (custom document, or the defaults).
func (h *Handler) getServerConfig(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	out, err := h.svc.GetEffectiveConfig(r.Context(), u, id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

type putServerConfigRequest struct {
	Config            json.RawMessage `json:"config"`
	Confirm           bool            `json:"confirm"`
	ForceFromDefaults bool            `json:"force_from_defaults"`
}

func (h *Handler) putServerConfig(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	var req putServerConfigRequest
	if !h.decodeJSON(w, r, &req, false) {
		return
	}
	out, err := h.svc.UpdateServerConfig(r.Context(), u, id, service.ServerConfigInput(req))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) getServerLocalConfig(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	out, err := h.svc.GetServerLocalConfig(r.Context(), u, id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) putServerLocalConfig(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	var req service.SetLocalConfigInput
	if !h.decodeJSON(w, r, &req, false) {
		return
	}
	out, err := h.svc.SetServerLocalConfig(r.Context(), u, id, req)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) listAgentServices(w http.ResponseWriter, r *http.Request, u *domain.User) {
	_ = u
	writeJSON(w, http.StatusOK, map[string]any{"services": service.ListAgentServices()})
}

// ---------------------------------------------------------------------------
// Settings

func (h *Handler) getAgentDefaults(w http.ResponseWriter, r *http.Request, u *domain.User) {
	out, err := h.svc.GetAgentDefaults(r.Context(), u)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

type putAgentDefaultsRequest struct {
	Config json.RawMessage `json:"config"`
}

func (h *Handler) putAgentDefaults(w http.ResponseWriter, r *http.Request, u *domain.User) {
	var req putAgentDefaultsRequest
	if !h.decodeJSON(w, r, &req, false) {
		return
	}
	if len(req.Config) == 0 {
		h.badRequest(w, "config is required")
		return
	}
	out, err := h.svc.UpdateAgentDefaults(r.Context(), u, req.Config)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
