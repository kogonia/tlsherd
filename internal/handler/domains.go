package handler

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/kogonia/tlsherd/internal/domain"
	"github.com/kogonia/tlsherd/internal/service"
)

const maxUploadBody = 1 << 20 // 1 MiB per request (plan); each PEM file is capped by the service

func (h *Handler) listDomains(w http.ResponseWriter, r *http.Request, u *domain.User) {
	out, err := h.svc.ListDomains(r.Context(), u)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

type createDomainRequest struct {
	FQDN     string      `json:"fqdn"`
	Notes    string      `json:"notes"`
	GroupIDs []uuid.UUID `json:"group_ids"`
}

func (h *Handler) createDomain(w http.ResponseWriter, r *http.Request, u *domain.User) {
	var req createDomainRequest
	if !h.decodeJSON(w, r, &req, false) {
		return
	}
	out, err := h.svc.CreateDomain(r.Context(), u, req.FQDN, req.Notes, req.GroupIDs)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (h *Handler) getDomain(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	out, err := h.svc.GetDomain(r.Context(), u, id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

type patchDomainRequest struct {
	Notes    *string      `json:"notes"`
	GroupIDs *[]uuid.UUID `json:"group_ids"`
}

func (h *Handler) updateDomain(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	var req patchDomainRequest
	if !h.decodeJSON(w, r, &req, false) {
		return
	}
	out, err := h.svc.UpdateDomain(r.Context(), u, id, req.Notes, req.GroupIDs)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) deleteDomain(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	if err := h.svc.DeleteDomain(r.Context(), u, id); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) getDomainGroups(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	out, err := h.svc.GetDomainGroups(r.Context(), u, id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

type setDomainGroupsRequest struct {
	GroupIDs []uuid.UUID `json:"group_ids"`
}

func (h *Handler) setDomainGroups(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	var req setDomainGroupsRequest
	if !h.decodeJSON(w, r, &req, false) {
		return
	}
	if req.GroupIDs == nil {
		h.badRequest(w, "group_ids is required")
		return
	}
	out, err := h.svc.UpdateDomain(r.Context(), u, id, nil, &req.GroupIDs)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// ---------------------------------------------------------------------------
// Certificates

// formFile reads a bounded multipart file field; a missing field yields nil.
func formFile(r *http.Request, name string) ([]byte, error) {
	f, _, err := r.FormFile(name)
	if err != nil {
		if err == http.ErrMissingFile {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, service.MaxPEMBytes+1))
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (h *Handler) uploadCertificate(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBody)
	if err := r.ParseMultipartForm(maxUploadBody); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid", "expected multipart/form-data with cert, key and optional chain (max 1 MiB)")
		return
	}
	defer func() { _ = r.MultipartForm.RemoveAll() }()

	var in service.UploadInput
	var err error
	for name, dst := range map[string]*[]byte{"cert": &in.CertPEM, "key": &in.KeyPEM, "chain": &in.ChainPEM} {
		if *dst, err = formFile(r, name); err != nil {
			h.badRequest(w, "cannot read form field "+name)
			return
		}
	}
	boolForm := func(name string, dst *bool) bool {
		v := r.FormValue(name)
		if v == "" {
			return true
		}
		parsed, err := strconv.ParseBool(v)
		if err != nil {
			h.badRequest(w, name+" must be a boolean")
			return false
		}
		*dst = parsed
		return true
	}
	if !boolForm("confirm_domain_mismatch", &in.ConfirmDomainMismatch) ||
		!boolForm("confirm_expired", &in.ConfirmExpired) ||
		!boolForm("confirm_not_yet_valid", &in.ConfirmNotYetValid) ||
		!boolForm("confirm_ca_mismatch", &in.ConfirmCAMismatch) ||
		!boolForm("confirm_warnings", &in.ConfirmWarnings) {
		return
	}
	res, err := h.svc.UploadCertificate(r.Context(), u, id, in)
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

func (h *Handler) listCertificateVersions(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	out, err := h.svc.ListCertificateVersions(r.Context(), u, id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) getCurrentCertificate(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	out, err := h.svc.GetCurrentCertificate(r.Context(), u, id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

type rollbackRequest struct {
	Version int    `json:"version"`
	Reason  string `json:"reason"`
}

func (h *Handler) rollback(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	var req rollbackRequest
	if !h.decodeJSON(w, r, &req, false) {
		return
	}
	out, err := h.svc.Rollback(r.Context(), u, id, req.Version, req.Reason)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) deleteCertificateVersion(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	ver, err := strconv.Atoi(r.PathValue("version"))
	if err != nil || ver <= 0 {
		writeAPIError(w, http.StatusBadRequest, "invalid", "invalid version")
		return
	}
	if err := h.svc.DeleteCertificateVersion(r.Context(), u, id, ver); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) getCertificate(w http.ResponseWriter, r *http.Request, u *domain.User) {
	out, err := h.svc.GetCertificate(r.Context(), u, r.PathValue("fingerprint"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) downloadCertPart(part string) authedFunc {
	return func(w http.ResponseWriter, r *http.Request, u *domain.User) {
		fp := r.PathValue("fingerprint")
		b, err := h.svc.DownloadCertificate(r.Context(), u, fp, part)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		pemHeaders(w, fp[:12]+"-"+part+".pem")
		_, _ = w.Write(b)
	}
}

func (h *Handler) deleteCertificate(w http.ResponseWriter, r *http.Request, u *domain.User) {
	if err := h.svc.DeleteCertificate(r.Context(), u, r.PathValue("fingerprint")); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Domain <-> server assignment

func (h *Handler) listDomainServers(w http.ResponseWriter, r *http.Request, u *domain.User) {
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	out, err := h.svc.ListDomainServers(r.Context(), u, id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, domainServerDTOs(out))
}

type domainServerRequest struct {
	InstallMode     string          `json:"install_mode"`
	CertPath        string          `json:"cert_path"`
	KeyPath         string          `json:"key_path"`
	ChainPath       string          `json:"chain_path"`
	FullchainPath   string          `json:"fullchain_path"`
	RestartOverride json.RawMessage `json:"restart_override"`
}

func (h *Handler) upsertDomainServer(w http.ResponseWriter, r *http.Request, u *domain.User) {
	domainID, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	serverID, ok := h.pathUUID(w, r, "serverID")
	if !ok {
		return
	}
	var req domainServerRequest
	if !h.decodeJSON(w, r, &req, false) {
		return
	}
	out, err := h.svc.UpsertDomainServer(r.Context(), u, domainID, serverID, service.DomainServerInput(req))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, domainServerDTOs([]domain.DomainServer{*out})[0])
}

func (h *Handler) removeDomainServer(w http.ResponseWriter, r *http.Request, u *domain.User) {
	domainID, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	serverID, ok := h.pathUUID(w, r, "serverID")
	if !ok {
		return
	}
	if err := h.svc.RemoveDomainServer(r.Context(), u, domainID, serverID); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
