package handler

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/kogonia/tlsherd/internal/domain"
	"github.com/kogonia/tlsherd/internal/service"
)

func (h *Handler) listEndpoints(w http.ResponseWriter, r *http.Request, u *domain.User) {
	out, err := h.svc.ListEndpoints(r.Context(), u)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

type createEndpointRequest struct {
	ServerID uuid.UUID  `json:"server_id"`
	DomainID *uuid.UUID `json:"domain_id"`
	Host     string     `json:"host"`
	Port     int        `json:"port"`
	Enabled  *bool      `json:"enabled"`
}

func (h *Handler) createEndpoint(w http.ResponseWriter, r *http.Request, u *domain.User) {
	var req createEndpointRequest
	if !h.decodeJSON(w, r, &req, false) {
		return
	}
	out, err := h.svc.CreateEndpoint(r.Context(), u, service.EndpointInput(req))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

type patchEndpointRequest struct {
	Host    *string `json:"host"`
	Port    *int    `json:"port"`
	Enabled *bool   `json:"enabled"`
}

func (h *Handler) updateEndpoint(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	var req patchEndpointRequest
	if !h.decodeJSON(w, r, &req, false) {
		return
	}
	out, err := h.svc.UpdateEndpoint(r.Context(), u, id, service.EndpointPatch(req))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) deleteEndpoint(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	if err := h.svc.DeleteEndpoint(r.Context(), u, id); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) listMonitorResults(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	out, err := h.svc.ListMonitorResults(r.Context(), u, id, intQuery(r, "limit", 100, 1000))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) forceCheck(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	out, err := h.svc.ForceCheck(r.Context(), u, id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// ---------------------------------------------------------------------------
// Events, audit, dashboard

func (h *Handler) listEvents(w http.ResponseWriter, r *http.Request, u *domain.User) {
	q := r.URL.Query()
	domainID, ok := h.uuidQuery(w, r, "domain_id")
	if !ok {
		return
	}
	serverID, ok := h.uuidQuery(w, r, "server_id")
	if !ok {
		return
	}
	out, err := h.svc.ListEventsWithNotify(r.Context(), u, service.ListEventsInput{
		UnresolvedOnly: q.Get("unresolved") == "true" || q.Get("unresolved") == "1",
		Type:           q.Get("type"),
		Severity:       q.Get("severity"),
		DomainID:       domainID,
		ServerID:       serverID,
		Limit:          intQuery(r, "limit", 100, 1000),
		Offset:         intQuery(r, "offset", 0, 1_000_000),
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, eventNotifyDTOs(out))
}

type dnsCheckRequest struct {
	Host string `json:"host"`
}

func (h *Handler) dnsCheck(w http.ResponseWriter, r *http.Request, u *domain.User) {
	var req dnsCheckRequest
	if !h.decodeJSON(w, r, &req, false) {
		return
	}
	out, err := h.svc.LookupEndpointDNS(r.Context(), u, req.Host)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) dismissEvent(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathInt64(w, r, "id")
	if !ok {
		return
	}
	if err := h.svc.DismissEvent(r.Context(), u, id); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) listAudit(w http.ResponseWriter, r *http.Request, u *domain.User) {
	q := r.URL.Query()
	out, err := h.svc.ListAudit(r.Context(), u, service.ListAuditInput{
		Actor:  q.Get("actor"),
		Action: q.Get("action"),
		Limit:  intQuery(r, "limit", 25, 1000),
		Offset: intQuery(r, "offset", 0, 1_000_000),
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, auditDTOs(out))
}

func (h *Handler) dashboard(w http.ResponseWriter, r *http.Request, u *domain.User) {
	out, err := h.svc.Dashboard(r.Context(), u)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
