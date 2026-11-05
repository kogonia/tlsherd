// Package service implements TLS herd business logic.
//
// Services sits between transport (internal/handler) and persistence
// (internal/store). Every method that acts on behalf of a user takes the
// authenticated *domain.User as "actor" and enforces authorization itself, so
// transports stay thin. Multi-step writes run inside Store.Tx.
//
// Errors returned by methods wrap the sentinels in internal/domain; use
// PublicMessage to obtain a message that is safe to show to API clients.
package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/kogonia/tlsherd/internal/authz"
	"github.com/kogonia/tlsherd/internal/domain"
	"github.com/kogonia/tlsherd/internal/store"
)

// Session limits (see plan: 12h idle, 24h absolute).
const (
	SessionIdleTimeout = 12 * time.Hour
	SessionMaxLifetime = 24 * time.Hour
)

// Services is the application service layer. Construct with New or by literal;
// only Store, Authz, DataDir and Logger are required.
type Services struct {
	Store   store.Store
	Authz   *authz.Resolver
	DataDir string
	Logger  *slog.Logger

	// Now overrides the clock (tests). Nil means time.Now.
	Now func() time.Time
}

// New wires Services with a resolver bound to st.
func New(st store.Store, dataDir string, logger *slog.Logger) *Services {
	if logger == nil {
		logger = slog.Default()
	}
	return &Services{
		Store:   st,
		Authz:   &authz.Resolver{Store: st},
		DataDir: dataDir,
		Logger:  logger,
	}
}

func (s *Services) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Services) log() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

// Ready reports whether the database is reachable.
func (s *Services) Ready(ctx context.Context) error {
	if _, err := s.Store.GetAgentDefaults(ctx); err != nil {
		return fmt.Errorf("readiness: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Errors

// userError is a domain error carrying a message safe to expose to clients.
type userError struct {
	kind error
	msg  string
}

func (e *userError) Error() string { return e.msg }
func (e *userError) Unwrap() error { return e.kind }

func invalidf(format string, args ...any) error {
	return &userError{kind: domain.ErrInvalid, msg: fmt.Sprintf(format, args...)}
}

func forbiddenf(format string, args ...any) error {
	return &userError{kind: domain.ErrForbidden, msg: fmt.Sprintf(format, args...)}
}

func notFoundf(format string, args ...any) error {
	return &userError{kind: domain.ErrNotFound, msg: fmt.Sprintf(format, args...)}
}

func conflictf(format string, args ...any) error {
	return &userError{kind: domain.ErrConflict, msg: fmt.Sprintf(format, args...)}
}

// PublicMessage returns a client-safe message for err. Errors created by the
// service carry their own text; wrapped infrastructure errors are reduced to a
// generic message derived from the domain sentinel.
func PublicMessage(err error) string {
	var ue *userError
	if errors.As(err, &ue) {
		return ue.msg
	}
	switch {
	case errors.Is(err, domain.ErrNotFound):
		return "not found"
	case errors.Is(err, domain.ErrConflict):
		return "conflict with existing data"
	case errors.Is(err, domain.ErrForbidden):
		return "forbidden"
	case errors.Is(err, domain.ErrUnauthorized), errors.Is(err, domain.ErrIdentityMismatch):
		return "unauthorized"
	case errors.Is(err, domain.ErrLastAdmin):
		return domain.ErrLastAdmin.Error()
	case errors.Is(err, domain.ErrSelfModification):
		return domain.ErrSelfModification.Error()
	case errors.Is(err, domain.ErrConfirmRequired):
		return domain.ErrConfirmRequired.Error()
	case errors.Is(err, domain.ErrCertificateInUse):
		return domain.ErrCertificateInUse.Error()
	case errors.Is(err, domain.ErrKeyCertMismatch):
		return domain.ErrKeyCertMismatch.Error()
	case errors.Is(err, domain.ErrDomainMismatch):
		return domain.ErrDomainMismatch.Error()
	case errors.Is(err, domain.ErrMustChangePassword):
		return "password change required before continuing"
	case errors.Is(err, domain.ErrInvalid):
		return "invalid request"
	}
	return "internal error"
}

// ---------------------------------------------------------------------------
// Authorization helpers

func requireAdmin(actor *domain.User) error {
	if actor == nil || actor.Role != domain.RoleAdmin {
		return forbiddenf("administrator role required")
	}
	return nil
}

func isAdmin(actor *domain.User) bool { return actor != nil && actor.Role == domain.RoleAdmin }

// requireDomainPerm loads the effective permissions of actor on a domain and
// checks them with ok. Operators without any permission get ErrForbidden.
func (s *Services) requireDomainPerm(ctx context.Context, actor *domain.User, domainID uuid.UUID, ok func(domain.EffectivePerms) bool) error {
	if actor == nil {
		return domain.ErrUnauthorized
	}
	p, err := s.Authz.DomainPerms(ctx, actor, domainID)
	if err != nil {
		return fmt.Errorf("resolve domain permissions: %w", err)
	}
	if !ok(p) {
		return forbiddenf("insufficient permissions for this domain")
	}
	return nil
}

func permRead(p domain.EffectivePerms) bool        { return p.CanRead }
func permWriteConfig(p domain.EffectivePerms) bool { return p.CanWriteConfig }
func permWriteCerts(p domain.EffectivePerms) bool  { return p.CanWriteCerts }

// requireServerWrite allows admins and operators with can_write_config on at
// least one domain assigned to the server.
func (s *Services) requireServerWrite(ctx context.Context, actor *domain.User, serverID uuid.UUID) error {
	if isAdmin(actor) {
		return nil
	}
	dss, err := s.Store.ListDomainServersByServer(ctx, serverID)
	if err != nil {
		return fmt.Errorf("list server domains: %w", err)
	}
	for _, ds := range dss {
		p, err := s.Authz.DomainPerms(ctx, actor, ds.DomainID)
		if err != nil {
			return fmt.Errorf("resolve domain permissions: %w", err)
		}
		if p.CanWriteConfig {
			return nil
		}
	}
	return forbiddenf("insufficient permissions for this server")
}

// requireServerRead allows admins and operators who can see the server.
func (s *Services) requireServerRead(ctx context.Context, actor *domain.User, serverID uuid.UUID) error {
	ok, err := s.Authz.CanSeeServer(ctx, actor, serverID)
	if err != nil {
		return fmt.Errorf("resolve server visibility: %w", err)
	}
	if !ok {
		return forbiddenf("server not accessible")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Audit and events

func jsonDetails(v any) []byte {
	if v == nil {
		return []byte("{}")
	}
	b, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}
	return b
}

func actorID(actor *domain.User) *uuid.UUID {
	if actor == nil {
		return nil
	}
	id := actor.ID
	return &id
}

func (s *Services) audit(ctx context.Context, st store.Store, actor *domain.User, action, entityType, entityID string, details any) error {
	err := st.InsertAudit(ctx, &domain.AuditEntry{
		At:          s.now(),
		ActorUserID: actorID(actor),
		Action:      action,
		EntityType:  entityType,
		EntityID:    entityID,
		Details:     jsonDetails(details),
	})
	if err != nil {
		return fmt.Errorf("audit %s: %w", action, err)
	}
	return nil
}

// Event types (see plan "События").
const (
	EvCertExpired             = "cert_expired"
	EvCertExpiringSoon        = "cert_expiring_soon"
	EvCertKeyMismatch         = "cert_key_mismatch"
	EvCertChainInvalid        = "cert_chain_invalid"
	EvCertDomainMismatchOK    = "cert_domain_mismatch_confirmed"
	EvCertExpiredUploadOK     = "cert_expired_upload_confirmed"
	EvCertNotYetValidUploadOK = "cert_not_yet_valid_upload_confirmed"
	EvCertUploadRejected      = "cert_upload_rejected"
	EvCertRollback            = "cert_rollback_performed"
	EvAgentEnrollPending      = "agent_enroll_pending"
	EvAgentAccepted           = "agent_accepted"
	EvAgentRejected           = "agent_rejected"
	EvAgentIdentityMismatch   = "agent_identity_mismatch"
	EvAgentOffline            = "agent_offline"
	EvAgentApplyFailed        = "agent_apply_failed"
	EvAgentVerifyFailed       = "agent_verify_failed"
	EvAgentPostCheckMismatch  = "agent_post_check_mismatch"
	EvAgentConfigUpdated      = "agent_config_updated"
	EvEndpointDown            = "endpoint_down"
	EvEndpointCertMismatch    = "endpoint_cert_mismatch"
	EvDomainUngrouped         = "domain_ungrouped"
)

// Event severities.
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

const (
	eventDetailResolvedByKey   = "resolved_by"
	eventDetailResolvedByAgent = "agent"
)

// DedupKey builds the dedup key for an event type and entity.
func DedupKey(eventType, entityID string) string {
	return eventType + ":" + entityID
}

// instantEventTypes are point-in-time records (already resolved). They must not
// stay in the open-events queue waiting for dismiss/resolve.
var instantEventTypes = map[string]struct{}{
	EvAgentAccepted:           {},
	EvAgentRejected:           {},
	EvAgentConfigUpdated:      {},
	EvCertRollback:            {},
	EvCertUploadRejected:      {},
	EvCertDomainMismatchOK:    {},
	EvCertExpiredUploadOK:     {},
	EvCertNotYetValidUploadOK: {},
}

// IsInstantEvent reports whether typ is a point-in-time event (no open lifecycle).
func IsInstantEvent(typ string) bool {
	_, ok := instantEventTypes[typ]
	return ok
}

// EmitEvent records an event. Instant types are stored already-resolved.
// With a DedupKey on an open type, at most one unresolved event per key exists;
// repeated emits refresh the open one.
func (s *Services) EmitEvent(ctx context.Context, ev *domain.Event) error {
	return s.emit(ctx, s.Store, ev)
}

func (s *Services) emit(ctx context.Context, st store.Store, ev *domain.Event) error {
	if ev.At.IsZero() {
		ev.At = s.now()
	}
	if ev.Severity == "" {
		ev.Severity = SeverityInfo
	}
	if len(ev.Details) == 0 {
		ev.Details = []byte("{}")
	}
	if IsInstantEvent(ev.Type) {
		if err := st.InsertInstantEvent(ctx, ev); err != nil {
			return fmt.Errorf("emit event %s: %w", ev.Type, err)
		}
		s.notifyFanout(ctx, st, ev, domain.NotifyKindOpened)
		return nil
	}
	inserted, err := st.UpsertOpenEvent(ctx, ev)
	if err != nil {
		return fmt.Errorf("emit event %s: %w", ev.Type, err)
	}
	if inserted {
		s.notifyFanout(ctx, st, ev, domain.NotifyKindOpened)
	}
	return nil
}

// ResolveEvent resolves open events with dedupKey; resolvedBy is recorded in details.
func (s *Services) ResolveEvent(ctx context.Context, dedupKey, resolvedBy string) error {
	return s.resolve(ctx, s.Store, dedupKey, resolvedBy)
}

func (s *Services) resolve(ctx context.Context, st store.Store, dedupKey, resolvedBy string) error {
	if resolvedBy == "" {
		resolvedBy = eventDetailResolvedByAgent
	}
	d := jsonDetails(map[string]any{eventDetailResolvedByKey: resolvedBy})
	evs, err := st.ResolveEventsByDedup(ctx, dedupKey, s.now(), d)
	if err != nil {
		return fmt.Errorf("resolve event %s: %w", dedupKey, err)
	}
	for i := range evs {
		s.notifyFanout(ctx, st, &evs[i], domain.NotifyKindResolved)
	}
	return nil
}

func (s *Services) resolveTypeDomain(ctx context.Context, st store.Store, eventType string, domainID uuid.UUID, resolvedBy string) error {
	if resolvedBy == "" {
		resolvedBy = eventDetailResolvedByAgent
	}
	d := jsonDetails(map[string]any{eventDetailResolvedByKey: resolvedBy})
	evs, err := st.ResolveOpenEventsByTypeDomain(ctx, eventType, domainID, s.now(), d)
	if err != nil {
		return fmt.Errorf("resolve event %s domain %s: %w", eventType, domainID, err)
	}
	for i := range evs {
		s.notifyFanout(ctx, st, &evs[i], domain.NotifyKindResolved)
	}
	return nil
}

func uuidPtr(id uuid.UUID) *uuid.UUID { return &id }

func strPtr(v string) *string { return &v }

func normalizeText(v string) string { return strings.TrimSpace(v) }
