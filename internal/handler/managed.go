package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/kogonia/tlsherd/internal/domain"
	"github.com/kogonia/tlsherd/internal/service"
)

func (h *Handler) listManagedCerts(w http.ResponseWriter, r *http.Request, u *domain.User) {
	domainID, ok := h.uuidQuery(w, r, "domain_id")
	if !ok {
		return
	}
	out, err := h.svc.ListManagedCertificates(r.Context(), u, service.ManagedCertListInput{
		Kind: r.URL.Query().Get("kind"), DomainID: domainID,
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

type createManagedCertRequest struct {
	Name        string     `json:"name"`
	DisplayName string     `json:"display_name"`
	Kind        string     `json:"kind"`
	DomainID    *uuid.UUID `json:"domain_id"`
	Notes       string     `json:"notes"`
}

func (h *Handler) createManagedCert(w http.ResponseWriter, r *http.Request, u *domain.User) {
	var req createManagedCertRequest
	if !h.decodeJSON(w, r, &req, false) {
		return
	}
	out, err := h.svc.CreateManagedCertificate(r.Context(), u, service.ManagedCertInput(req))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (h *Handler) getManagedCert(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	out, err := h.svc.GetManagedCertificate(r.Context(), u, id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

type patchManagedCertRequest struct {
	DisplayName *string `json:"display_name"`
	Notes       *string `json:"notes"`
	// DomainID is a raw value so that an explicit null detaches the domain.
	DomainID json.RawMessage `json:"domain_id"`
}

func (h *Handler) updateManagedCert(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	var req patchManagedCertRequest
	if !h.decodeJSON(w, r, &req, false) {
		return
	}
	patch := service.ManagedCertPatch{DisplayName: req.DisplayName, Notes: req.Notes}
	if len(req.DomainID) > 0 {
		if string(req.DomainID) == "null" {
			patch.ClearDomain = true
		} else if err := json.Unmarshal(req.DomainID, &patch.DomainID); err != nil {
			h.badRequest(w, "invalid domain_id")
			return
		}
	}
	out, err := h.svc.UpdateManagedCertificate(r.Context(), u, id, patch)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) deleteManagedCert(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	if err := h.svc.DeleteManagedCertificate(r.Context(), u, id); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// uploadManagedCert accepts multipart/form-data with cert, optional key
// (mtls_client only) and optional chain, plus confirm_* flags and reason.
func (h *Handler) uploadManagedCert(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBody)
	if err := r.ParseMultipartForm(maxUploadBody); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid", "expected multipart/form-data with cert, optional key and chain (max 1 MiB)")
		return
	}
	defer func() { _ = r.MultipartForm.RemoveAll() }()

	in := service.ManagedUploadInput{Reason: r.FormValue("reason")}
	var err error
	for name, dst := range map[string]*[]byte{"cert": &in.CertPEM, "key": &in.KeyPEM, "chain": &in.ChainPEM} {
		if *dst, err = formFile(r, name); err != nil {
			h.badRequest(w, "cannot read form field "+name)
			return
		}
	}
	for name, dst := range map[string]*bool{
		"confirm_identity_change": &in.ConfirmIdentityChange,
		"confirm_expired":         &in.ConfirmExpired,
		"confirm_not_yet_valid":   &in.ConfirmNotYetValid,
		"confirm_warnings":        &in.ConfirmWarnings,
	} {
		v := r.FormValue(name)
		if v == "" {
			continue
		}
		parsed, err := strconv.ParseBool(v)
		if err != nil {
			h.badRequest(w, name+" must be a boolean")
			return
		}
		*dst = parsed
	}
	res, err := h.svc.UploadManagedCertificate(r.Context(), u, id, in)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	status := http.StatusCreated
	if res.Unchanged {
		status = http.StatusOK
	}
	writeJSON(w, status, res)
}

func (h *Handler) listManagedCertVersions(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	out, err := h.svc.ListManagedCertificateVersions(r.Context(), u, id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// ---------------------------------------------------------------------------
// Managed certificate <-> server assignment

type managedCertServerDTO struct {
	domain.ManagedCertServer
	RestartOverride json.RawMessage `json:"restart_override,omitempty"`
}

func managedCertServerDTOs(in []domain.ManagedCertServer) []managedCertServerDTO {
	out := make([]managedCertServerDTO, len(in))
	for i, ms := range in {
		out[i] = managedCertServerDTO{ManagedCertServer: ms}
		if len(ms.RestartOverride) > 0 {
			out[i].RestartOverride = ms.RestartOverride
		}
	}
	return out
}

func (h *Handler) listManagedCertServers(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	out, err := h.svc.ListManagedCertServers(r.Context(), u, id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, managedCertServerDTOs(out))
}

func (h *Handler) upsertManagedCertServer(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	serverID, ok := h.pathUUID(w, r, "serverID")
	if !ok {
		return
	}
	var req domainServerRequest // same payload as domain assignments
	if !h.decodeJSON(w, r, &req, false) {
		return
	}
	out, err := h.svc.UpsertManagedCertServer(r.Context(), u, id, serverID, service.ManagedCertServerInput(req))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, managedCertServerDTOs([]domain.ManagedCertServer{*out})[0])
}

func (h *Handler) removeManagedCertServer(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	serverID, ok := h.pathUUID(w, r, "serverID")
	if !ok {
		return
	}
	if err := h.svc.RemoveManagedCertServer(r.Context(), u, id, serverID); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Monitor settings (admin)

func (h *Handler) getMonitorSettings(w http.ResponseWriter, r *http.Request, u *domain.User) {
	out, err := h.svc.GetMonitorSettings(r.Context(), u)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) putMonitorSettings(w http.ResponseWriter, r *http.Request, u *domain.User) {
	var in service.MonitorSettings
	if !h.decodeJSON(w, r, &in, false) {
		return
	}
	out, err := h.svc.UpdateMonitorSettings(r.Context(), u, in)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
