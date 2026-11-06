package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/kogonia/tlsherd/internal/domain"
	"github.com/kogonia/tlsherd/internal/service"
)

const maxJSONBody = 1 << 20

type errorBody struct {
	Error errorPayload `json:"error"`
}

type errorPayload struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	// Encoding errors can only come from a closed connection at this point.
	_ = json.NewEncoder(w).Encode(v)
}

func writeAPIError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, errorBody{Error: errorPayload{Code: code, Message: msg}})
}

// decodeJSON reads a bounded JSON body into v. It reports false after
// writing the error response. An empty body is accepted when allowEmpty.
func (h *Handler) decodeJSON(w http.ResponseWriter, r *http.Request, v any, allowEmpty bool) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBody)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		if errors.Is(err, io.EOF) && allowEmpty {
			return true
		}
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeAPIError(w, http.StatusRequestEntityTooLarge, "too_large", "request body too large")
			return false
		}
		writeAPIError(w, http.StatusBadRequest, "invalid", "malformed JSON body")
		return false
	}
	return true
}

func (h *Handler) badRequest(w http.ResponseWriter, msg string) {
	writeAPIError(w, http.StatusBadRequest, "invalid", msg)
}

// pathUUID parses a UUID path value; it reports false after writing a 400.
func (h *Handler) pathUUID(w http.ResponseWriter, r *http.Request, name string) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue(name))
	if err != nil {
		h.badRequest(w, "invalid "+name)
		return uuid.Nil, false
	}
	return id, true
}

func intQuery(r *http.Request, name string, def, maxV int) int {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return def
	}
	return min(n, maxV)
}

// uuidQuery parses an optional UUID query param. Empty returns (nil, true).
// Invalid values write a 400 and return false.
func (h *Handler) uuidQuery(w http.ResponseWriter, r *http.Request, name string) (*uuid.UUID, bool) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return nil, true
	}
	id, err := uuid.Parse(v)
	if err != nil {
		h.badRequest(w, "invalid "+name)
		return nil, false
	}
	return &id, true
}

// fail maps a service error to an HTTP response. Details of unexpected errors
// are logged, never returned.
func (h *Handler) fail(w http.ResponseWriter, r *http.Request, err error) {
	var confirm *service.CertConfirmationError
	var mismatch *service.DomainMismatchError
	switch {
	case errors.As(err, &confirm):
		writeJSON(w, http.StatusConflict, errorBody{Error: errorPayload{
			Code:    "confirmation_required",
			Message: "certificate has issues that need confirmation",
			Details: map[string]any{
				"problems":            confirm.Problems,
				"requested_domain":    confirm.RequestedDomain,
				"uploaded_sans":       confirm.UploadedSANs,
				"uploaded_cn":         confirm.UploadedCN,
				"not_before":          confirm.NotBefore,
				"not_after":           confirm.NotAfter,
				"current_certificate": confirm.CurrentCertificate,
				"hint":                "repeat the upload with confirm_warnings=true (or per-issue flags) to install it anyway",
			},
		}})
		return
	case errors.As(err, &mismatch):
		writeJSON(w, http.StatusConflict, errorBody{Error: errorPayload{
			Code:    "domain_mismatch",
			Message: "the certificate does not cover the requested domain",
			Details: map[string]any{
				"requested_domain":    mismatch.RequestedDomain,
				"uploaded_sans":       mismatch.UploadedSANs,
				"uploaded_cn":         mismatch.UploadedCN,
				"current_certificate": mismatch.CurrentCertificate,
				"hint":                "repeat the upload with confirm_domain_mismatch=true to install it anyway",
			},
		}})
		return
	case errors.Is(err, domain.ErrKeyCertMismatch):
		writeAPIError(w, http.StatusUnprocessableEntity, "key_mismatch", service.PublicMessage(err))
	case errors.Is(err, domain.ErrConfirmRequired):
		writeAPIError(w, http.StatusConflict, "confirmation_required", service.PublicMessage(err))
	case errors.Is(err, domain.ErrLastAdmin):
		writeAPIError(w, http.StatusBadRequest, "last_admin", service.PublicMessage(err))
	case errors.Is(err, domain.ErrSelfModification):
		writeAPIError(w, http.StatusForbidden, "self_modification", service.PublicMessage(err))
	case errors.Is(err, domain.ErrCertificateInUse):
		writeAPIError(w, http.StatusConflict, "certificate_in_use", service.PublicMessage(err))
	case errors.Is(err, domain.ErrIdentityMismatch):
		writeAPIError(w, http.StatusUnauthorized, "identity_mismatch", "agent identity mismatch; re-enrollment required")
	case errors.Is(err, domain.ErrUnauthorized):
		writeAPIError(w, http.StatusUnauthorized, "unauthorized", "unauthorized")
	case errors.Is(err, domain.ErrMustChangePassword):
		writeAPIError(w, http.StatusForbidden, "must_change_password", service.PublicMessage(err))
	case errors.Is(err, domain.ErrForbidden):
		writeAPIError(w, http.StatusForbidden, "forbidden", service.PublicMessage(err))
	case errors.Is(err, domain.ErrNotFound):
		writeAPIError(w, http.StatusNotFound, "not_found", service.PublicMessage(err))
	case errors.Is(err, domain.ErrInvalid):
		writeAPIError(w, http.StatusBadRequest, "invalid", service.PublicMessage(err))
	case errors.Is(err, domain.ErrConflict):
		writeAPIError(w, http.StatusConflict, "conflict", service.PublicMessage(err))
	default:
		h.logger(r).Error("request failed", "operation", "http", "method", r.Method, "path", r.URL.Path, "error", err)
		writeAPIError(w, http.StatusInternalServerError, "internal", "internal error")
	}
}

// ---------------------------------------------------------------------------
// Response shapes for types whose raw JSON columns are hidden in domain tags.

type eventDTO struct {
	domain.Event
	Details json.RawMessage `json:"details"`
}

func eventDTOs(in []domain.Event) []eventDTO {
	out := make([]eventDTO, len(in))
	for i, e := range in {
		out[i] = eventDTO{Event: e, Details: rawOrEmpty(e.Details)}
	}
	return out
}

type auditDTO struct {
	domain.AuditEntry
	Details json.RawMessage `json:"details"`
}

func auditDTOs(in []domain.AuditEntry) []auditDTO {
	out := make([]auditDTO, len(in))
	for i, e := range in {
		out[i] = auditDTO{AuditEntry: e, Details: rawOrEmpty(e.Details)}
	}
	return out
}

type domainServerDTO struct {
	domain.DomainServer
	RestartOverride json.RawMessage `json:"restart_override,omitempty"`
}

func domainServerDTOs(in []domain.DomainServer) []domainServerDTO {
	out := make([]domainServerDTO, len(in))
	for i, d := range in {
		out[i] = domainServerDTO{DomainServer: d}
		if len(d.RestartOverride) > 0 {
			out[i].RestartOverride = d.RestartOverride
		}
	}
	return out
}

func rawOrEmpty(b []byte) json.RawMessage {
	if len(b) == 0 {
		return json.RawMessage("{}")
	}
	return json.RawMessage(b)
}

func pemHeaders(w http.ResponseWriter, filename string) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.Header().Set("Cache-Control", "no-store")
}
