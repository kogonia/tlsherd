package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/kogonia/tlsherd/internal/domain"
	"github.com/kogonia/tlsherd/internal/store"
)

const (
	defaultEventsLimit = 100
	maxEventsLimit     = 1000
)

const eventCols = `id, at, type, severity, domain_id, server_id, certificate_id, group_id, message,
	details, dedup_key, resolved_at, actor_user_id`

func scanEvent(r rowScanner) (domain.Event, error) {
	var e domain.Event
	err := r.Scan(&e.ID, &e.At, &e.Type, &e.Severity, &e.DomainID, &e.ServerID, &e.CertificateID,
		&e.GroupID, &e.Message, &e.Details, &e.DedupKey, &e.ResolvedAt, &e.ActorUserID)
	return e, err
}

// UpsertOpenEvent records an unresolved event.
//
// With a non-empty DedupKey, at most one unresolved event per key exists
// (events_open_dedup_idx): if one is already open, its message and details are
// refreshed and its original id/time are kept; otherwise a new row is inserted.
// Without a DedupKey the event is always inserted. On return e carries ID and At.
// inserted is true only when a new row was created.
func (s *Store) UpsertOpenEvent(ctx context.Context, e *domain.Event) (bool, error) {
	if e.Severity == "" {
		e.Severity = "info"
	}
	var dedup *string
	conflict := ""
	if e.DedupKey != nil && *e.DedupKey != "" {
		dedup = e.DedupKey
		conflict = `
		ON CONFLICT (dedup_key) WHERE resolved_at IS NULL AND dedup_key IS NOT NULL DO UPDATE
		SET message = EXCLUDED.message, details = EXCLUDED.details`
	}
	var inserted bool
	err := s.q.QueryRow(ctx, `
		INSERT INTO events (at, type, severity, domain_id, server_id, certificate_id, group_id,
			message, details, dedup_key, actor_user_id)
		VALUES (COALESCE($1, now()), $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`+conflict+`
		RETURNING id, at, (xmax = 0)`,
		timeOrNil(e.At), e.Type, e.Severity, e.DomainID, e.ServerID, e.CertificateID, e.GroupID,
		e.Message, jsonOrDefault(e.Details, "{}"), dedup, e.ActorUserID,
	).Scan(&e.ID, &e.At, &inserted)
	e.ResolvedAt = nil
	return inserted, mapErr("upsert open event", err)
}

// ResolveEventsByDedup resolves every open event with dedupKey at the given time
// and returns the rows that were closed. A non-empty details object is merged
// into the stored details. No match is not an error.
func (s *Store) ResolveEventsByDedup(ctx context.Context, dedupKey string, at time.Time, details []byte) ([]domain.Event, error) {
	return queryAll(ctx, s.q, "resolve events", scanEvent, `
		UPDATE events
		SET resolved_at = $2,
		    details = CASE WHEN $3::jsonb IS NULL THEN details ELSE details || $3::jsonb END
		WHERE dedup_key = $1 AND resolved_at IS NULL
		RETURNING `+eventCols,
		dedupKey, at, nullableJSON(details))
}

// ResolveOpenEventsByTypeDomain closes open events of the given type for a domain.
func (s *Store) ResolveOpenEventsByTypeDomain(ctx context.Context, eventType string, domainID uuid.UUID, at time.Time, details []byte) ([]domain.Event, error) {
	return queryAll(ctx, s.q, "resolve events by type/domain", scanEvent, `
		UPDATE events
		SET resolved_at = $3,
		    details = CASE WHEN $4::jsonb IS NULL THEN details ELSE details || $4::jsonb END
		WHERE type = $1 AND domain_id = $2 AND resolved_at IS NULL
		RETURNING `+eventCols,
		eventType, domainID, at, nullableJSON(details))
}

func (s *Store) GetEvent(ctx context.Context, id int64) (*domain.Event, error) {
	return queryOne(ctx, s.q, "get event", scanEvent,
		`SELECT `+eventCols+` FROM events WHERE id = $1`, id)
}

// ResolveEventByID closes a single open event by id. Already-resolved returns nil, nil.
func (s *Store) ResolveEventByID(ctx context.Context, id int64, at time.Time, details []byte) (*domain.Event, error) {
	ev, err := queryOne(ctx, s.q, "resolve event by id", scanEvent, `
		UPDATE events
		SET resolved_at = $2,
		    details = CASE WHEN $3::jsonb IS NULL THEN details ELSE details || $3::jsonb END
		WHERE id = $1 AND resolved_at IS NULL
		RETURNING `+eventCols,
		id, at, nullableJSON(details))
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return ev, nil
}

// ListEvents returns events newest first.
//
// DomainIDs, ServerIDs and GroupIDs form a visibility scope: when any of them
// is non-nil, an event matches if it references an ID from at least one of the
// non-nil lists (an empty non-nil list matches nothing). When all three are nil
// no scope restriction is applied. Limit <= 0 means 100 and is capped at 1000.
func (s *Store) ListEvents(ctx context.Context, f store.EventFilter) ([]domain.Event, error) {
	var (
		conds []string
		args  []any
	)
	arg := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}

	if f.UnresolvedOnly {
		conds = append(conds, "resolved_at IS NULL")
	}
	if f.Type != "" {
		conds = append(conds, "type = "+arg(f.Type))
	}

	var scope []string
	if f.DomainIDs != nil {
		scope = append(scope, "domain_id = ANY("+arg(f.DomainIDs)+"::uuid[])")
	}
	if f.ServerIDs != nil {
		scope = append(scope, "server_id = ANY("+arg(f.ServerIDs)+"::uuid[])")
	}
	if f.GroupIDs != nil {
		scope = append(scope, "group_id = ANY("+arg(f.GroupIDs)+"::uuid[])")
	}
	if len(scope) > 0 {
		conds = append(conds, "("+strings.Join(scope, " OR ")+")")
	}

	limit := f.Limit
	if limit <= 0 {
		limit = defaultEventsLimit
	}
	limit = min(limit, maxEventsLimit)
	offset := max(f.Offset, 0)

	sql := `SELECT ` + eventCols + ` FROM events`
	if len(conds) > 0 {
		sql += " WHERE " + strings.Join(conds, " AND ")
	}
	sql += " ORDER BY at DESC, id DESC LIMIT " + arg(limit) + " OFFSET " + arg(offset)

	return queryAll(ctx, s.q, "list events", scanEvent, sql, args...)
}

// Audit

func (s *Store) InsertAudit(ctx context.Context, a *domain.AuditEntry) error {
	err := s.q.QueryRow(ctx, `
		INSERT INTO audit_log (at, actor_user_id, action, entity_type, entity_id, details)
		VALUES (COALESCE($1, now()), $2, $3, $4, $5, $6)
		RETURNING id, at`,
		timeOrNil(a.At), a.ActorUserID, a.Action, a.EntityType, a.EntityID,
		jsonOrDefault(a.Details, "{}"),
	).Scan(&a.ID, &a.At)
	return mapErr("insert audit", err)
}

// ListAudit returns the newest audit entries first; limit <= 0 means 100, capped at 1000.
func (s *Store) ListAudit(ctx context.Context, limit int) ([]domain.AuditEntry, error) {
	if limit <= 0 {
		limit = defaultEventsLimit
	}
	limit = min(limit, maxEventsLimit)
	return queryAll(ctx, s.q, "list audit", func(r rowScanner) (domain.AuditEntry, error) {
		var a domain.AuditEntry
		err := r.Scan(&a.ID, &a.At, &a.ActorUserID, &a.Action, &a.EntityType, &a.EntityID, &a.Details)
		return a, err
	}, `
		SELECT id, at, actor_user_id, action, entity_type, entity_id, details
		FROM audit_log
		ORDER BY at DESC, id DESC
		LIMIT $1`, limit)
}

// Settings

// GetSetting returns the raw JSON value of key, or domain.ErrNotFound.
func (s *Store) GetSetting(ctx context.Context, key string) ([]byte, error) {
	var v []byte
	err := s.q.QueryRow(ctx, `SELECT value FROM system_settings WHERE key = $1`, key).Scan(&v)
	if err != nil {
		return nil, mapErr("get setting", err)
	}
	return v, nil
}

func (s *Store) SetSetting(ctx context.Context, key string, value []byte) error {
	_, err := s.q.Exec(ctx, `
		INSERT INTO system_settings (key, value) VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
		key, jsonOrDefault(value, "{}"))
	return mapErr("set setting", err)
}

func (s *Store) DeleteSetting(ctx context.Context, key string) error {
	_, err := s.q.Exec(ctx, `DELETE FROM system_settings WHERE key = $1`, key)
	return mapErr("delete setting", err)
}

// Apply results

// SaveApplyResult records the outcome of an agent apply run. It is idempotent
// per applyID: a repeated report overwrites status, message and details.
func (s *Store) SaveApplyResult(ctx context.Context, applyID string, serverID uuid.UUID, domainID *uuid.UUID, status, message string, details []byte) error {
	_, err := s.q.Exec(ctx, `
		INSERT INTO apply_results (apply_id, server_id, domain_id, status, message, details)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (apply_id) DO UPDATE
		SET server_id = EXCLUDED.server_id,
		    domain_id = EXCLUDED.domain_id,
		    status = EXCLUDED.status,
		    message = EXCLUDED.message,
		    details = EXCLUDED.details,
		    reported_at = now()`,
		applyID, serverID, domainID, status, message, jsonOrDefault(details, "{}"))
	return mapErr("save apply result", err)
}
