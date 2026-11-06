// Package handler is the HTTP transport of TLS herd.
//
// It exposes the JSON API under /api/v1 for users (session cookie or Bearer
// token) and for agents (Bearer agent key bound to the source IP), plus
// /healthz and /readyz. Handlers are thin: they decode input, call
// internal/service and map domain errors to HTTP status codes.
package handler

import (
	"log/slog"
	"net/http"

	"github.com/kogonia/tlsherd/internal/service"
)

// Options configures a Handler.
type Options struct {
	// SecureCookies sets the Secure attribute on cookies. Disable only for --insecure-http.
	SecureCookies bool
	// TrustProxy takes the client IP from the last X-Forwarded-For entry
	// (appended by a trusted reverse proxy) instead of the TCP peer address.
	TrustProxy bool
	// UI is an optional handler mounted at "/" (the embedded web UI).
	UI http.Handler
}

// Handler serves the HTTP API.
type Handler struct {
	svc *service.Services
	log *slog.Logger
	opt Options

	loginLimiter  *rateLimiter // per IP+login
	ipLimiter     *rateLimiter // per IP, login endpoint
	enrollLimiter *rateLimiter // per IP, agent enroll endpoint
}

// New creates a Handler.
func New(svc *service.Services, logger *slog.Logger, opt Options) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{
		svc:           svc,
		log:           logger.With("component", "handler"),
		opt:           opt,
		loginLimiter:  newRateLimiter(5, 1*minute),
		ipLimiter:     newRateLimiter(30, 1*minute),
		enrollLimiter: newRateLimiter(30, 1*minute),
	}
}

// AdminRoutes serves the web UI and operator/admin JSON API.
// Agent endpoints are not registered here (use AgentRoutes on a separate listener).
func (h *Handler) AdminRoutes() http.Handler {
	mux := http.NewServeMux()
	h.mountHealth(mux)
	h.mountAdminAPI(mux)
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeAPIError(w, http.StatusNotFound, "not_found", "not found")
	})
	if h.opt.UI != nil {
		mux.Handle("/", h.opt.UI)
	}
	return h.recoverer(h.requestID(h.accessLog(mux)))
}

// AgentRoutes serves only the agent enroll/poll/cert API plus health checks.
func (h *Handler) AgentRoutes() http.Handler {
	mux := http.NewServeMux()
	h.mountHealth(mux)
	h.mountAgentAPI(mux)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeAPIError(w, http.StatusNotFound, "not_found", "not found")
	})
	return h.recoverer(h.requestID(h.accessLog(mux)))
}

func (h *Handler) mountHealth(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", h.healthz)
	mux.HandleFunc("GET /readyz", h.readyz)
}

func (h *Handler) mountAgentAPI(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/agent/enroll", h.agentEnroll)
	mux.Handle("POST /api/v1/agent/poll", h.agentAuthed(h.agentPoll))
	mux.Handle("GET /api/v1/agent/certs/{fingerprint}", h.agentAuthed(h.agentCert))
	mux.Handle("POST /api/v1/agent/apply-result", h.agentAuthed(h.agentApplyResult))
}

func (h *Handler) mountAdminAPI(mux *http.ServeMux) {
	// Auth
	mux.HandleFunc("POST /api/v1/auth/login", h.login)
	mux.Handle("POST /api/v1/auth/logout", h.authed(h.logout))
	mux.Handle("GET /api/v1/auth/me", h.authed(h.me))
	mux.Handle("PATCH /api/v1/auth/me", h.authed(h.patchMe))
	mux.Handle("POST /api/v1/auth/password", h.authed(h.changePassword))

	// Users (admin)
	mux.Handle("GET /api/v1/users", h.authed(h.listUsers))
	mux.Handle("POST /api/v1/users", h.authed(h.createUser))
	mux.Handle("GET /api/v1/users/{id}", h.authed(h.getUser))
	mux.Handle("PATCH /api/v1/users/{id}", h.authed(h.updateUser))
	mux.Handle("DELETE /api/v1/users/{id}", h.authed(h.deleteUser))
	mux.Handle("POST /api/v1/users/{id}/reset-password", h.authed(h.resetPassword))

	// Groups
	mux.Handle("GET /api/v1/groups", h.authed(h.listGroups))
	mux.Handle("POST /api/v1/groups", h.authed(h.createGroup))
	mux.Handle("GET /api/v1/groups/{id}", h.authed(h.getGroup))
	mux.Handle("PATCH /api/v1/groups/{id}", h.authed(h.updateGroup))
	mux.Handle("DELETE /api/v1/groups/{id}", h.authed(h.deleteGroup))
	mux.Handle("GET /api/v1/groups/{id}/permissions", h.authed(h.listGroupPermissions))
	mux.Handle("PUT /api/v1/groups/{id}/permissions", h.authed(h.setGroupPermissions))

	// Domains
	mux.Handle("GET /api/v1/domains", h.authed(h.listDomains))
	mux.Handle("POST /api/v1/domains", h.authed(h.createDomain))
	mux.Handle("GET /api/v1/domains/{id}", h.authed(h.getDomain))
	mux.Handle("PATCH /api/v1/domains/{id}", h.authed(h.updateDomain))
	mux.Handle("DELETE /api/v1/domains/{id}", h.authed(h.deleteDomain))
	mux.Handle("GET /api/v1/domains/{id}/groups", h.authed(h.getDomainGroups))
	mux.Handle("PUT /api/v1/domains/{id}/groups", h.authed(h.setDomainGroups))

	// Certificates
	mux.Handle("POST /api/v1/domains/{id}/certificates", h.authed(h.uploadCertificate))
	mux.Handle("GET /api/v1/domains/{id}/certificates", h.authed(h.listCertificateVersions))
	mux.Handle("GET /api/v1/domains/{id}/certificates/current", h.authed(h.getCurrentCertificate))
	mux.Handle("POST /api/v1/domains/{id}/rollback", h.authed(h.rollback))
	mux.Handle("DELETE /api/v1/domains/{id}/certificates/{version}", h.authed(h.deleteCertificateVersion))
	mux.Handle("GET /api/v1/certificates/{fingerprint}", h.authed(h.getCertificate))
	mux.Handle("GET /api/v1/certificates/{fingerprint}/cert", h.authed(h.downloadCertPart(service.PartCert)))
	mux.Handle("GET /api/v1/certificates/{fingerprint}/chain", h.authed(h.downloadCertPart(service.PartChain)))
	mux.Handle("GET /api/v1/certificates/{fingerprint}/key", h.authed(h.downloadCertPart(service.PartKey)))
	mux.Handle("DELETE /api/v1/certificates/{fingerprint}", h.authed(h.deleteCertificate))

	// Domain <-> server assignment
	mux.Handle("GET /api/v1/domains/{id}/servers", h.authed(h.listDomainServers))
	mux.Handle("PUT /api/v1/domains/{id}/servers/{serverID}", h.authed(h.upsertDomainServer))
	mux.Handle("DELETE /api/v1/domains/{id}/servers/{serverID}", h.authed(h.removeDomainServer))

	// Enrollments (admin)
	mux.Handle("GET /api/v1/enrollments", h.authed(h.listEnrollments))
	mux.Handle("POST /api/v1/enrollments/{id}/accept", h.authed(h.acceptEnrollment))
	mux.Handle("POST /api/v1/enrollments/{id}/reject", h.authed(h.rejectEnrollment))

	// Servers
	mux.Handle("GET /api/v1/servers", h.authed(h.listServers))
	mux.Handle("GET /api/v1/servers/{id}", h.authed(h.getServer))
	mux.Handle("PATCH /api/v1/servers/{id}", h.authed(h.updateServer))
	mux.Handle("DELETE /api/v1/servers/{id}", h.authed(h.deleteServer))
	mux.Handle("POST /api/v1/servers/{id}/rotate-key", h.authed(h.rotateKey))
	mux.Handle("DELETE /api/v1/servers/{id}/keys", h.authed(h.revokeKeys))
	mux.Handle("GET /api/v1/servers/{id}/config", h.authed(h.getServerConfig))
	mux.Handle("PUT /api/v1/servers/{id}/config", h.authed(h.putServerConfig))
	mux.Handle("GET /api/v1/servers/{id}/effective-config", h.authed(h.getServerConfig))
	mux.Handle("GET /api/v1/servers/{id}/local-config", h.authed(h.getServerLocalConfig))
	mux.Handle("PUT /api/v1/servers/{id}/local-config", h.authed(h.putServerLocalConfig))
	mux.Handle("GET /api/v1/settings/agent-services", h.authed(h.listAgentServices))

	// Settings (admin)
	mux.Handle("GET /api/v1/settings/agent-defaults", h.authed(h.getAgentDefaults))
	mux.Handle("PUT /api/v1/settings/agent-defaults", h.authed(h.putAgentDefaults))
	mux.Handle("GET /api/v1/settings/notifications", h.authed(h.getNotificationSettings))
	mux.Handle("PUT /api/v1/settings/notifications", h.authed(h.putNotificationSettings))
	mux.Handle("POST /api/v1/settings/notifications/test", h.authed(h.testNotification))

	// Notification accounts (admin)
	mux.Handle("GET /api/v1/notification-accounts", h.authed(h.listNotificationAccounts))
	mux.Handle("POST /api/v1/notification-accounts", h.authed(h.createNotificationAccount))
	mux.Handle("GET /api/v1/notification-accounts/{id}", h.authed(h.getNotificationAccount))
	mux.Handle("PUT /api/v1/notification-accounts/{id}", h.authed(h.putNotificationAccount))
	mux.Handle("DELETE /api/v1/notification-accounts/{id}", h.authed(h.deleteNotificationAccount))
	mux.Handle("GET /api/v1/notification-accounts/{id}/destinations", h.authed(h.listNotificationDestinations))
	mux.Handle("POST /api/v1/notification-accounts/{id}/destinations", h.authed(h.createNotificationDestination))
	mux.Handle("PUT /api/v1/notification-accounts/{id}/destinations/{destID}", h.authed(h.putNotificationDestination))
	mux.Handle("DELETE /api/v1/notification-accounts/{id}/destinations/{destID}", h.authed(h.deleteNotificationDestination))
	mux.Handle("GET /api/v1/notification-event-types", h.authed(h.listEventTypes))

	// Monitor, events, audit, dashboard
	mux.Handle("GET /api/v1/monitor/endpoints", h.authed(h.listEndpoints))
	mux.Handle("POST /api/v1/monitor/endpoints", h.authed(h.createEndpoint))
	mux.Handle("PATCH /api/v1/monitor/endpoints/{id}", h.authed(h.updateEndpoint))
	mux.Handle("DELETE /api/v1/monitor/endpoints/{id}", h.authed(h.deleteEndpoint))
	mux.Handle("GET /api/v1/monitor/endpoints/{id}/results", h.authed(h.listMonitorResults))
	mux.Handle("POST /api/v1/monitor/endpoints/{id}/check", h.authed(h.forceCheck))
	mux.Handle("POST /api/v1/monitor/dns-check", h.authed(h.dnsCheck))
	mux.Handle("GET /api/v1/events", h.authed(h.listEvents))
	mux.Handle("POST /api/v1/events/{id}/dismiss", h.authed(h.dismissEvent))
	mux.Handle("GET /api/v1/audit", h.authed(h.listAudit))
	mux.Handle("GET /api/v1/dashboard", h.authed(h.dashboard))
}
