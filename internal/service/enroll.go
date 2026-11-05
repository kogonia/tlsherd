package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/kogonia/tlsherd/internal/agentcfg"
	"github.com/kogonia/tlsherd/internal/auth"
	"github.com/kogonia/tlsherd/internal/domain"
	"github.com/kogonia/tlsherd/internal/store"
)

// Agent identity is the pair (IP, agent key). See plan "Enrollment агента".

const (
	// keyDeliveryTTL bounds how long a freshly issued key waits for the agent to pick it up.
	keyDeliveryTTL = 24 * time.Hour
	// KeyRotationOverlap is how long a rotated-out key keeps working.
	KeyRotationOverlap = 24 * time.Hour

	settingKeyDelivery = "agent_key_delivery:"
	settingDeletedIP   = "server_deleted_ip:"
)

// keyDelivery is the transient hand-over record of a freshly issued agent key.
//
// The key reaches the agent through its next enroll/poll response and is
// removed as soon as the agent authenticates with it (or after keyDeliveryTTL).
// This is the only place a plaintext agent key is ever persisted.
type keyDelivery struct {
	APIKey    string    `json:"api_key"`
	KeyID     uuid.UUID `json:"key_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

type identityKind int

const (
	idUnknown    identityKind = iota // no server known for this IP/key
	idOK                             // IP and key match an active server
	idStale                          // key is a revoked/expired key of the server at this IP
	idBlocked                        // server is blocked pending admin approval
	idIPChanged                      // known key presented from another IP
	idKeyChanged                     // known IP presented a different (or no) key
)

type identity struct {
	kind   identityKind
	server *domain.Server
	key    *domain.AgentKey
	// presentedKey is the plaintext key sent by the peer ("" if none).
	presentedKey string
}

// EnrollResult is the response to an agent enroll call.
type EnrollResult struct {
	Status            string             `json:"status"` // pending|accepted|rejected
	Reason            string             `json:"reason,omitempty"`
	EnrollmentID      *uuid.UUID         `json:"enrollment_id,omitempty"`
	ServerID          *uuid.UUID         `json:"server_id,omitempty"`
	APIKey            string             `json:"api_key,omitempty"` // only until the agent authenticates with it
	Config            *agentcfg.Config   `json:"config,omitempty"`
	ConfigVersion     int64              `json:"config_version,omitempty"`
	ConfigHash        string             `json:"config_hash,omitempty"`
	RetryAfter        agentcfg.Duration  `json:"retry_after"`
	LocalConfigUpdate *LocalConfigUpdate `json:"local_config_update,omitempty"`
}

// EnrollInput is the agent enroll request body.
type EnrollInput struct {
	ClientName      string
	PresentedKey    string
	LocalConfig     *agentcfg.LocalConfig
	LocalConfigHash string
}

// AcceptInput controls AcceptEnrollment.
type AcceptInput struct {
	DisplayName *string
	// LinkServerID re-binds an existing server to the enrollment's IP and a new key
	// (identity change). Nil creates a new server.
	LinkServerID *uuid.UUID
}

// AcceptResult is returned by AcceptEnrollment. APIKey is shown once.
type AcceptResult struct {
	Server     *domain.Server          `json:"server"`
	APIKey     string                  `json:"api_key"`
	KeyPrefix  string                  `json:"key_prefix"`
	Enrollment *domain.AgentEnrollment `json:"enrollment"`
}

func deliveryKey(serverID uuid.UUID) string { return settingKeyDelivery + serverID.String() }

func keyPrefixOf(plain string) string {
	if len(plain) < 8 {
		return plain
	}
	return plain[:8]
}

// issueAgentKey creates a new key for the server and returns its plaintext.
func (s *Services) issueAgentKey(ctx context.Context, st store.Store, serverID uuid.UUID, label string) (string, *domain.AgentKey, error) {
	plain, prefix, hash, err := auth.NewAgentKey()
	if err != nil {
		return "", nil, fmt.Errorf("generate agent key: %w", err)
	}
	k := &domain.AgentKey{ServerID: serverID, KeyPrefix: prefix, KeyHash: hash, CreatedAt: s.now(), Label: label}
	if err := st.CreateAgentKey(ctx, k); err != nil {
		return "", nil, fmt.Errorf("store agent key: %w", err)
	}
	return plain, k, nil
}

func (s *Services) putDelivery(ctx context.Context, st store.Store, serverID uuid.UUID, keyID uuid.UUID, plain string) error {
	b, err := json.Marshal(keyDelivery{APIKey: plain, KeyID: keyID, ExpiresAt: s.now().Add(keyDeliveryTTL)})
	if err != nil {
		return fmt.Errorf("encode key delivery: %w", err)
	}
	if err := st.SetSetting(ctx, deliveryKey(serverID), b); err != nil {
		return fmt.Errorf("store key delivery: %w", err)
	}
	return nil
}

// getDelivery returns the pending key hand-over for the server, or nil.
func (s *Services) getDelivery(ctx context.Context, serverID uuid.UUID) (*keyDelivery, error) {
	b, err := s.Store.GetSetting(ctx, deliveryKey(serverID))
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("get key delivery: %w", err)
	}
	var d keyDelivery
	if err := json.Unmarshal(b, &d); err != nil || d.APIKey == "" || !d.ExpiresAt.After(s.now()) {
		_ = s.Store.DeleteSetting(ctx, deliveryKey(serverID))
		return nil, nil
	}
	return &d, nil
}

func (s *Services) clearDelivery(ctx context.Context, st store.Store, serverID uuid.UUID) error {
	if err := st.DeleteSetting(ctx, deliveryKey(serverID)); err != nil {
		return fmt.Errorf("clear key delivery: %w", err)
	}
	return nil
}

// resolveIdentity classifies an (ip, key) pair against the known servers.
func (s *Services) resolveIdentity(ctx context.Context, ip netip.Addr, keyPlain string) (*identity, error) {
	id := &identity{presentedKey: keyPlain}
	var hash []byte
	if keyPlain != "" {
		hash = auth.HashToken(keyPlain)
		k, err := s.Store.GetAgentKeyByHash(ctx, hash)
		switch {
		case err == nil:
			srv, err := s.Store.GetServer(ctx, k.ServerID)
			if err != nil && !errors.Is(err, domain.ErrNotFound) {
				return nil, fmt.Errorf("resolve identity: %w", err)
			}
			if err != nil || srv.AgentStatus == domain.ServerDeleted {
				return id, nil // idUnknown
			}
			id.server, id.key = srv, k
			switch {
			case srv.LastIP == nil || *srv.LastIP != ip:
				id.kind = idIPChanged
			case srv.AgentStatus == domain.ServerBlockedIdentity:
				id.kind = idBlocked
			default:
				id.kind = idOK
			}
			return id, nil
		case !errors.Is(err, domain.ErrNotFound):
			return nil, fmt.Errorf("resolve identity: %w", err)
		}
	}

	srv, err := s.Store.GetServerByIP(ctx, ip)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return id, nil // idUnknown
		}
		return nil, fmt.Errorf("resolve identity: %w", err)
	}
	id.server = srv
	if hash != nil {
		keys, err := s.Store.ListAgentKeys(ctx, srv.ID)
		if err != nil {
			return nil, fmt.Errorf("resolve identity: %w", err)
		}
		for _, k := range keys {
			if string(k.KeyHash) == string(hash) {
				id.kind = idStale // rotated-out or revoked key: plain 401, not an incident
				return id, nil
			}
		}
	}
	if srv.AgentStatus == domain.ServerBlockedIdentity {
		id.kind = idBlocked
		return id, nil
	}
	id.kind = idKeyChanged
	return id, nil
}

// recordIdentityMismatch blocks the server, queues a pending enrollment for the
// presenting IP with an identity_* reason and raises agent_identity_mismatch.
func (s *Services) recordIdentityMismatch(ctx context.Context, id *identity, ip netip.Addr, clientName *string) (*domain.AgentEnrollment, error) {
	srv := id.server
	reason := domain.ReasonIdentityKeyChanged
	kind := "key_changed"
	if id.kind == idIPChanged {
		reason, kind = domain.ReasonIdentityIPChanged, "ip_changed"
	}
	prevPrefix := ""
	if id.key != nil {
		prevPrefix = id.key.KeyPrefix
	} else if p, err := s.Store.ActiveKeyPrefix(ctx, srv.ID); err == nil {
		prevPrefix = p
	}
	var presented *string
	if id.presentedKey != "" {
		presented = strPtr(keyPrefixOf(id.presentedKey))
	}
	var prev *string
	if prevPrefix != "" {
		prev = &prevPrefix
	}
	now := s.now()
	var enr *domain.AgentEnrollment
	err := s.Store.Tx(ctx, func(tx store.Store) error {
		if srv.AgentStatus != domain.ServerBlockedIdentity {
			blocked := *srv
			blocked.AgentStatus = domain.ServerBlockedIdentity
			if err := tx.UpdateServer(ctx, &blocked); err != nil {
				return err
			}
		}
		e, err := tx.GetPendingEnrollmentByIP(ctx, ip)
		switch {
		case err == nil:
			e.Reason, e.PreviousServerID, e.PreviousKeyPrefix = reason, uuidPtr(srv.ID), prev
			e.PresentedKeyPrefix, e.LastSeenAt = presented, now
			if clientName != nil {
				e.ClientName = clientName
			}
			if err := tx.UpdateEnrollment(ctx, e); err != nil {
				return err
			}
		case errors.Is(err, domain.ErrNotFound):
			e = &domain.AgentEnrollment{
				RemoteIP: ip, ClientName: clientName, Status: domain.EnrollPending, Reason: reason,
				PreviousServerID: uuidPtr(srv.ID), PreviousKeyPrefix: prev, PresentedKeyPrefix: presented,
				LastSeenAt: now,
			}
			if err := tx.CreateEnrollment(ctx, e); err != nil {
				return err
			}
		default:
			return err
		}
		enr = e
		key := DedupKey(EvAgentIdentityMismatch, srv.ID.String())
		return s.emit(ctx, tx, &domain.Event{
			Type: EvAgentIdentityMismatch, Severity: SeverityCritical, ServerID: &srv.ID, DedupKey: &key,
			Message: fmt.Sprintf("agent identity mismatch for %s (%s)", srv.Display(), kind),
			Details: jsonDetails(map[string]any{
				"kind": kind, "old_ip": ipPtrString(srv.LastIP), "new_ip": ip.String(),
				"key_prefix": prevPrefix, "presented_key_prefix": keyPrefixOf(id.presentedKey),
			}),
		})
	})
	if err != nil {
		return nil, fmt.Errorf("record identity mismatch: %w", err)
	}
	s.log().Warn("agent identity mismatch; blocked and queued",
		"component", "service", "operation", "identity_check",
		"server_id", srv.ID, "kind", kind, "ip", ip.String(),
		"enrollment_id", enr.ID, "reason", reason, "key_prefix", prevPrefix)
	return enr, nil
}

func ipPtrString(ip *netip.Addr) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

// AuthenticateAgent validates an agent request: the key must be valid and the
// source IP must be the one bound to the server. Identity changes block the
// server and queue a re-approval before returning domain.ErrIdentityMismatch.
// Anything else that fails yields domain.ErrUnauthorized.
func (s *Services) AuthenticateAgent(ctx context.Context, ip netip.Addr, keyPlain string) (*domain.Server, error) {
	ip = ip.Unmap()
	if !ip.IsValid() || keyPlain == "" {
		return nil, domain.ErrUnauthorized
	}
	id, err := s.resolveIdentity(ctx, ip, keyPlain)
	if err != nil {
		return nil, err
	}
	switch id.kind {
	case idOK:
		srv, err := s.touchAgent(ctx, id)
		if err != nil {
			return nil, err
		}
		s.log().Debug("agent authenticated", "component", "service", "operation", "authenticate_agent",
			"server_id", srv.ID, "ip", ip.String(), "key_prefix", id.key.KeyPrefix, "status", srv.AgentStatus)
		return srv, nil
	case idIPChanged, idKeyChanged:
		if _, err := s.recordIdentityMismatch(ctx, id, ip, nil); err != nil {
			return nil, err
		}
		return nil, domain.ErrIdentityMismatch
	case idBlocked:
		s.log().Debug("agent auth rejected; server blocked",
			"component", "service", "operation", "authenticate_agent",
			"server_id", id.server.ID, "ip", ip.String())
		return nil, domain.ErrIdentityMismatch
	default:
		s.log().Debug("agent auth unauthorized",
			"component", "service", "operation", "authenticate_agent", "ip", ip.String())
		return nil, domain.ErrUnauthorized
	}
}

// touchAgent records liveness for an authenticated agent and finishes any key hand-over.
func (s *Services) touchAgent(ctx context.Context, id *identity) (*domain.Server, error) {
	now := s.now()
	srv := id.server
	if err := s.Store.TouchAgentKey(ctx, id.key.ID, now); err != nil {
		return nil, fmt.Errorf("touch agent key: %w", err)
	}
	if d, err := s.getDelivery(ctx, srv.ID); err != nil {
		return nil, err
	} else if d != nil && d.KeyID == id.key.ID {
		if err := s.clearDelivery(ctx, s.Store, srv.ID); err != nil {
			return nil, err
		}
	}
	wasOffline := srv.AgentStatus == domain.ServerOffline
	if wasOffline || srv.LastSeenAt == nil || now.Sub(*srv.LastSeenAt) > time.Minute {
		upd := *srv
		upd.LastSeenAt = &now
		if wasOffline {
			upd.AgentStatus = domain.ServerActive
		}
		if err := s.Store.UpdateServer(ctx, &upd); err != nil {
			return nil, fmt.Errorf("touch server: %w", err)
		}
		srv = &upd
	}
	if wasOffline {
		if err := s.resolve(ctx, s.Store, DedupKey(EvAgentOffline, srv.ID.String()), "agent"); err != nil {
			return nil, err
		}
	}
	return srv, nil
}

// Enroll handles an agent enrollment request from ip. See the plan for the
// state machine: unknown IPs queue as pending; accepted agents receive their
// key once; identity changes block the server and re-queue.
func (s *Services) Enroll(ctx context.Context, ip netip.Addr, in EnrollInput) (*EnrollResult, error) {
	ip = ip.Unmap()
	if !ip.IsValid() {
		return nil, invalidf("remote address is unknown")
	}
	var name *string
	if n := truncate(normalizeText(in.ClientName), 128); n != "" {
		name = &n
	}
	retry := s.enrollRetry(ctx)

	id, err := s.resolveIdentity(ctx, ip, in.PresentedKey)
	if err != nil {
		return nil, err
	}
	switch id.kind {
	case idOK:
		return s.acceptedResult(ctx, id.server, retry, in)
	case idKeyChanged:
		if in.PresentedKey == "" && id.server.AgentStatus == domain.ServerActive {
			// An accepted agent that has not yet picked up its key.
			if d, err := s.getDelivery(ctx, id.server.ID); err != nil {
				return nil, err
			} else if d != nil {
				res, err := s.acceptedResult(ctx, id.server, retry, in)
				if err != nil {
					return nil, err
				}
				res.APIKey = d.APIKey
				return res, nil
			}
		}
		fallthrough
	case idIPChanged:
		e, err := s.recordIdentityMismatch(ctx, id, ip, name)
		if err != nil {
			return nil, err
		}
		return pendingResult(e, retry), nil
	case idBlocked:
		return s.enrollUnknown(ctx, ip, name, retry, id)
	default:
		return s.enrollUnknown(ctx, ip, name, retry, nil)
	}
}

func pendingResult(e *domain.AgentEnrollment, retry time.Duration) *EnrollResult {
	return &EnrollResult{Status: domain.EnrollPending, Reason: e.Reason, EnrollmentID: &e.ID, RetryAfter: agentcfg.Duration(retry)}
}

func (s *Services) acceptedResult(ctx context.Context, srv *domain.Server, retry time.Duration, in EnrollInput) (*EnrollResult, error) {
	if in.LocalConfig != nil {
		if err := s.ReportAgentLocalConfig(ctx, srv, *in.LocalConfig, in.LocalConfigHash, false); err != nil {
			return nil, err
		}
		fresh, err := s.Store.GetServer(ctx, srv.ID)
		if err != nil {
			return nil, err
		}
		*srv = *fresh
	}
	eff, err := s.effectiveConfig(ctx, srv)
	if err != nil {
		return nil, err
	}
	res := &EnrollResult{
		Status: domain.EnrollAccepted, ServerID: &srv.ID, Config: &eff.Config,
		ConfigVersion: eff.Version, ConfigHash: eff.Hash, RetryAfter: agentcfg.Duration(retry),
		LocalConfigUpdate: pendingLocalConfigUpdate(srv),
	}
	if d, err := s.getDelivery(ctx, srv.ID); err != nil {
		return nil, err
	} else if d != nil {
		res.APIKey = d.APIKey
	}
	return res, nil
}

// enrollRetry returns the enroll polling interval advertised to pending agents.
func (s *Services) enrollRetry(ctx context.Context) time.Duration {
	d, err := s.Store.GetAgentDefaults(ctx)
	if err == nil {
		if cfg, err := agentcfg.Parse(d.Config); err == nil {
			return cfg.EnrollInterval.Std()
		}
	}
	return agentcfg.Default().EnrollInterval.Std()
}

// enrollUnknown queues (or refreshes) a pending enrollment for an IP without an
// accepted identity. blocked is non-nil when the IP maps to an identity-blocked server.
func (s *Services) enrollUnknown(ctx context.Context, ip netip.Addr, name *string, retry time.Duration, blocked *identity) (*EnrollResult, error) {
	var res *EnrollResult
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		err = s.Store.Tx(ctx, func(tx store.Store) error {
			var txErr error
			res, txErr = s.enrollUnknownTx(ctx, tx, ip, name, retry, blocked)
			return txErr
		})
		if !errors.Is(err, domain.ErrConflict) {
			break // concurrent enrollment from the same IP: retry once, it will now find the pending row
		}
	}
	if err != nil {
		return nil, fmt.Errorf("enroll: %w", err)
	}
	return res, nil
}

func (s *Services) enrollUnknownTx(ctx context.Context, tx store.Store, ip netip.Addr, name *string, retry time.Duration, blocked *identity) (*EnrollResult, error) {
	now := s.now()
	e, err := tx.GetPendingEnrollmentByIP(ctx, ip)
	switch {
	case err == nil:
		e.LastSeenAt = now
		if name != nil {
			e.ClientName = name
		}
		if err := tx.UpdateEnrollment(ctx, e); err != nil {
			return nil, err
		}
		s.log().Debug("enrollment still pending",
			"component", "service", "operation", "enroll",
			"enrollment_id", e.ID, "ip", ip.String(), "reason", e.Reason)
		return pendingResult(e, retry), nil
	case !errors.Is(err, domain.ErrNotFound):
		return nil, err
	}

	reason := domain.ReasonFirstSeen
	switch _, mErr := tx.GetSetting(ctx, settingDeletedIP+ip.String()); {
	case mErr == nil:
		reason = domain.ReasonReEnrollAfterDelete
		if err := tx.DeleteSetting(ctx, settingDeletedIP+ip.String()); err != nil {
			return nil, err
		}
	case !errors.Is(mErr, domain.ErrNotFound):
		return nil, mErr
	default:
		latest, lErr := tx.GetLatestEnrollmentByIP(ctx, ip)
		switch {
		case lErr == nil && latest.Status == domain.EnrollRejected:
			latest.LastSeenAt = now
			if err := tx.UpdateEnrollment(ctx, latest); err != nil {
				return nil, err
			}
			return &EnrollResult{Status: domain.EnrollRejected, Reason: latest.Reason, EnrollmentID: &latest.ID,
				RetryAfter: agentcfg.Duration(retry)}, nil
		case lErr != nil && !errors.Is(lErr, domain.ErrNotFound):
			return nil, lErr
		}
	}

	e = &domain.AgentEnrollment{RemoteIP: ip, ClientName: name, Status: domain.EnrollPending, Reason: reason, LastSeenAt: now}
	if blocked != nil && blocked.server != nil {
		e.Reason = domain.ReasonIdentityKeyChanged
		e.PreviousServerID = uuidPtr(blocked.server.ID)
	}
	if err := tx.CreateEnrollment(ctx, e); err != nil {
		return nil, err
	}
	key := DedupKey(EvAgentEnrollPending, ip.String())
	if err := s.emit(ctx, tx, &domain.Event{
		Type: EvAgentEnrollPending, Severity: SeverityInfo, DedupKey: &key,
		Message: fmt.Sprintf("new agent waiting for approval from %s", ip),
		Details: jsonDetails(map[string]any{"ip": ip.String(), "reason": e.Reason}),
	}); err != nil {
		return nil, err
	}
	s.log().Info("agent queued for approval",
		"component", "service", "operation", "enroll",
		"enrollment_id", e.ID, "ip", ip.String(), "reason", e.Reason)
	return pendingResult(e, retry), nil
}

// ListEnrollments lists enrollments (status "" = all), newest first. Admin only.
func (s *Services) ListEnrollments(ctx context.Context, actor *domain.User, status string) ([]domain.AgentEnrollment, error) {
	if err := requireAdmin(actor); err != nil {
		return nil, err
	}
	switch status {
	case "", domain.EnrollPending, domain.EnrollAccepted, domain.EnrollRejected:
	default:
		return nil, invalidf("unknown status %q", status)
	}
	es, err := s.Store.ListEnrollments(ctx, status)
	if err != nil {
		return nil, fmt.Errorf("list enrollments: %w", err)
	}
	return es, nil
}

// AcceptEnrollment approves a queued agent: it creates (or re-binds) the
// server, issues an agent key and marks the enrollment accepted. The plaintext
// key is returned once and is also handed to the agent through its next
// enroll/poll response. Admin only.
func (s *Services) AcceptEnrollment(ctx context.Context, actor *domain.User, id uuid.UUID, in AcceptInput) (*AcceptResult, error) {
	if err := requireAdmin(actor); err != nil {
		return nil, err
	}
	var display *string
	if in.DisplayName != nil {
		if n := truncate(normalizeText(*in.DisplayName), 128); n != "" {
			display = &n
		}
	}
	var res *AcceptResult
	err := s.Store.Tx(ctx, func(tx store.Store) error {
		e, err := tx.GetEnrollment(ctx, id)
		if err != nil {
			return err
		}
		if e.Status == domain.EnrollAccepted {
			return conflictf("enrollment is already accepted")
		}
		now := s.now()
		defaults, err := tx.GetAgentDefaults(ctx)
		if err != nil {
			return err
		}

		var srv *domain.Server
		if in.LinkServerID != nil {
			if srv, err = tx.GetServer(ctx, *in.LinkServerID); err != nil {
				return err
			}
			if err := s.revokeAllKeys(ctx, tx, srv.ID, now); err != nil {
				return err
			}
			ip := e.RemoteIP
			srv.LastIP, srv.LastSeenAt, srv.AgentStatus = &ip, &now, domain.ServerActive
			if display != nil {
				srv.DisplayName = display
			}
			if err := tx.UpdateServer(ctx, srv); err != nil {
				return err
			}
		} else {
			ip := e.RemoteIP
			srv = &domain.Server{
				DisplayName: display, LastIP: &ip, LastSeenAt: &now, AgentStatus: domain.ServerActive,
				ConfigVersion: defaults.ConfigVersion,
			}
			if err := tx.CreateServer(ctx, srv); err != nil {
				return err
			}
			if e.PreviousServerID != nil {
				// New server replaces the blocked one: its keys stop working for good.
				if err := s.revokeAllKeys(ctx, tx, *e.PreviousServerID, now); err != nil {
					return err
				}
			}
		}

		plain, key, err := s.issueAgentKey(ctx, tx, srv.ID, "accepted")
		if err != nil {
			return err
		}
		if err := s.putDelivery(ctx, tx, srv.ID, key.ID, plain); err != nil {
			return err
		}

		e.Status, e.DecidedAt, e.DecidedBy, e.ServerID = domain.EnrollAccepted, &now, actorID(actor), &srv.ID
		if err := tx.UpdateEnrollment(ctx, e); err != nil {
			return err
		}

		resolveKeys := []string{DedupKey(EvAgentEnrollPending, e.RemoteIP.String()), DedupKey(EvAgentIdentityMismatch, srv.ID.String())}
		if e.PreviousServerID != nil {
			resolveKeys = append(resolveKeys, DedupKey(EvAgentIdentityMismatch, e.PreviousServerID.String()))
		}
		for _, k := range resolveKeys {
			if err := s.resolve(ctx, tx, k, "accept"); err != nil {
				return err
			}
		}
		if err := s.emit(ctx, tx, &domain.Event{
			Type: EvAgentAccepted, Severity: SeverityInfo, ServerID: &srv.ID, ActorUserID: actorID(actor),
			Message: fmt.Sprintf("agent %s accepted by %s", srv.Display(), actor.Login),
			Details: jsonDetails(map[string]any{"ip": e.RemoteIP.String(), "reason": e.Reason, "linked": in.LinkServerID != nil}),
		}); err != nil {
			return err
		}
		if err := s.audit(ctx, tx, actor, "enrollment.accept", "enrollment", e.ID.String(), map[string]any{
			"server_id": srv.ID, "ip": e.RemoteIP.String(), "reason": e.Reason, "key_prefix": key.KeyPrefix,
		}); err != nil {
			return err
		}
		res = &AcceptResult{Server: srv, APIKey: plain, KeyPrefix: key.KeyPrefix, Enrollment: e}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("accept enrollment: %w", err)
	}
	s.log().Info("enrollment accepted",
		"component", "service", "operation", "enrollment.accept",
		"enrollment_id", id, "server_id", res.Server.ID, "ip", res.Enrollment.RemoteIP.String(),
		"actor", actor.Login, "key_prefix", res.KeyPrefix, "linked", in.LinkServerID != nil,
		"reason", res.Enrollment.Reason)
	return res, nil
}

// revokeAllKeys revokes every still-valid key of a server.
func (s *Services) revokeAllKeys(ctx context.Context, st store.Store, serverID uuid.UUID, at time.Time) error {
	keys, err := st.ListAgentKeys(ctx, serverID)
	if err != nil {
		return err
	}
	for _, k := range keys {
		if k.RevokedAt != nil {
			continue
		}
		if err := st.RevokeAgentKey(ctx, k.ID, at); err != nil {
			return err
		}
	}
	return s.clearDelivery(ctx, st, serverID)
}

// RejectEnrollment rejects a queued agent. The agent keeps getting "rejected"
// until an admin accepts it. Blocked servers stay blocked. Admin only.
func (s *Services) RejectEnrollment(ctx context.Context, actor *domain.User, id uuid.UUID) (*domain.AgentEnrollment, error) {
	if err := requireAdmin(actor); err != nil {
		return nil, err
	}
	var out *domain.AgentEnrollment
	err := s.Store.Tx(ctx, func(tx store.Store) error {
		e, err := tx.GetEnrollment(ctx, id)
		if err != nil {
			return err
		}
		if e.Status != domain.EnrollPending {
			return conflictf("enrollment is already %s", e.Status)
		}
		now := s.now()
		e.Status, e.DecidedAt, e.DecidedBy = domain.EnrollRejected, &now, actorID(actor)
		if err := tx.UpdateEnrollment(ctx, e); err != nil {
			return err
		}
		if err := s.resolve(ctx, tx, DedupKey(EvAgentEnrollPending, e.RemoteIP.String()), "reject"); err != nil {
			return err
		}
		if err := s.emit(ctx, tx, &domain.Event{
			Type: EvAgentRejected, Severity: SeverityInfo, ServerID: e.PreviousServerID, ActorUserID: actorID(actor),
			Message: fmt.Sprintf("agent from %s rejected by %s", e.RemoteIP, actor.Login),
			Details: jsonDetails(map[string]any{"ip": e.RemoteIP.String(), "reason": e.Reason}),
		}); err != nil {
			return err
		}
		out = e
		return s.audit(ctx, tx, actor, "enrollment.reject", "enrollment", e.ID.String(),
			map[string]any{"ip": e.RemoteIP.String(), "reason": e.Reason})
	})
	if err != nil {
		return nil, fmt.Errorf("reject enrollment: %w", err)
	}
	s.log().Info("enrollment rejected",
		"component", "service", "operation", "enrollment.reject",
		"enrollment_id", out.ID, "ip", out.RemoteIP.String(),
		"actor", actor.Login, "reason", out.Reason)
	return out, nil
}
