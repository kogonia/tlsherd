package handler

import (
	"net/http"
	"strings"
	"time"

	"github.com/kogonia/tlsherd/internal/agentcfg"
	"github.com/kogonia/tlsherd/internal/domain"
	"github.com/kogonia/tlsherd/internal/service"
)

type enrollRequest struct {
	ClientName      string                `json:"client_name"`
	Version         string                `json:"version"`
	LocalConfig     *agentcfg.LocalConfig `json:"local_config"`
	LocalConfigHash string                `json:"local_config_hash"`
}

// agentEnroll handles unauthenticated enrollment. An agent that already holds
// a key may present it as Bearer so that identity changes are detected.
func (h *Handler) agentEnroll(w http.ResponseWriter, r *http.Request) {
	ip := h.clientIP(r)
	if ok, retry := h.enrollLimiter.allow(ip.String(), time.Now()); !ok {
		h.tooManyRequests(w, retry)
		return
	}
	var req enrollRequest
	if !h.decodeJSON(w, r, &req, true) {
		return
	}
	res, err := h.svc.Enroll(r.Context(), ip, service.EnrollInput{
		ClientName: req.ClientName, PresentedKey: bearerToken(r),
		LocalConfig: req.LocalConfig, LocalConfigHash: req.LocalConfigHash,
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, res)
}

func (h *Handler) agentPoll(w http.ResponseWriter, r *http.Request, srv *domain.Server) {
	var in service.AgentPollInput
	if !h.decodeJSON(w, r, &in, true) {
		return
	}
	out, err := h.svc.AgentPoll(r.Context(), srv, in)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// etagMatches implements If-None-Match for a single strong ETag.
func etagMatches(header, etag string) bool {
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		part = strings.TrimPrefix(part, "W/")
		if part == "*" || part == etag {
			return true
		}
	}
	return false
}

// agentCert serves the PEM bundle of a certificate assigned to the agent.
// The ETag is the fingerprint, so unchanged bundles answer 304.
func (h *Handler) agentCert(w http.ResponseWriter, r *http.Request, srv *domain.Server) {
	fp := r.PathValue("fingerprint")
	bundle, err := h.svc.GetAgentCertBundle(r.Context(), srv, fp)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	etag := `"` + bundle.Fingerprint + `"`
	w.Header().Set("ETag", etag)
	if etagMatches(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	writeJSON(w, http.StatusOK, bundle)
}

func (h *Handler) agentApplyResult(w http.ResponseWriter, r *http.Request, srv *domain.Server) {
	var in service.ApplyResultInput
	if !h.decodeJSON(w, r, &in, false) {
		return
	}
	if err := h.svc.ReportApplyResult(r.Context(), srv, in); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
