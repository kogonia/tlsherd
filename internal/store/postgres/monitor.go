package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/kogonia/tlsherd/internal/domain"
)

const defaultResultsLimit = 100

// Endpoints

const endpointCols = `id, server_id, domain_id, host, port, enabled, check_interval, dial_addr,
	client_cert_id, created_at`

func scanEndpoint(r rowScanner) (domain.ServerEndpoint, error) {
	var e domain.ServerEndpoint
	err := r.Scan(&e.ID, &e.ServerID, &e.DomainID, &e.Host, &e.Port, &e.Enabled,
		&e.CheckInterval, &e.DialAddr, &e.ClientCertID, &e.CreatedAt)
	return e, err
}

func (s *Store) CreateEndpoint(ctx context.Context, e *domain.ServerEndpoint) error {
	e.ID = newID(e.ID)
	err := s.q.QueryRow(ctx, `
		INSERT INTO server_endpoints (id, server_id, domain_id, host, port, enabled,
			check_interval, dial_addr, client_cert_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING created_at`,
		e.ID, e.ServerID, e.DomainID, e.Host, e.Port, e.Enabled,
		e.CheckInterval, e.DialAddr, e.ClientCertID,
	).Scan(&e.CreatedAt)
	return mapErr("create endpoint", err)
}

// ListEndpoints lists endpoints ordered by creation time; enabledOnly filters out disabled ones.
func (s *Store) ListEndpoints(ctx context.Context, enabledOnly bool) ([]domain.ServerEndpoint, error) {
	return queryAll(ctx, s.q, "list endpoints", scanEndpoint, `
		SELECT `+endpointCols+` FROM server_endpoints
		WHERE (NOT $1::boolean OR enabled)
		ORDER BY created_at, id`, enabledOnly)
}

func (s *Store) GetEndpoint(ctx context.Context, id uuid.UUID) (*domain.ServerEndpoint, error) {
	return queryOne(ctx, s.q, "get endpoint", scanEndpoint,
		`SELECT `+endpointCols+` FROM server_endpoints WHERE id = $1`, id)
}

func (s *Store) UpdateEndpoint(ctx context.Context, e *domain.ServerEndpoint) error {
	return execOne(ctx, s.q, "update endpoint", `
		UPDATE server_endpoints
		SET server_id = $2, domain_id = $3, host = $4, port = $5, enabled = $6,
		    check_interval = $7, dial_addr = $8, client_cert_id = $9
		WHERE id = $1`,
		e.ID, e.ServerID, e.DomainID, e.Host, e.Port, e.Enabled,
		e.CheckInterval, e.DialAddr, e.ClientCertID)
}

func (s *Store) DeleteEndpoint(ctx context.Context, id uuid.UUID) error {
	return execOne(ctx, s.q, "delete endpoint", `DELETE FROM server_endpoints WHERE id = $1`, id)
}

// Monitor results

const resultCols = `id, endpoint_id, checked_at, reachable, tls_ok, peer_fingerprint,
	peer_not_after, issuer, error, latency_ms, connected_ip`

func scanMonitorResult(r rowScanner) (domain.MonitorResult, error) {
	var m domain.MonitorResult
	err := r.Scan(&m.ID, &m.EndpointID, &m.CheckedAt, &m.Reachable, &m.TLSOK,
		&m.PeerFingerprint, &m.PeerNotAfter, &m.Issuer, &m.Error, &m.LatencyMS, &m.ConnectedIP)
	return m, err
}

// InsertMonitorResult stores r; a zero CheckedAt defaults to now(). On return r carries ID and CheckedAt.
func (s *Store) InsertMonitorResult(ctx context.Context, r *domain.MonitorResult) error {
	err := s.q.QueryRow(ctx, `
		INSERT INTO monitor_results (endpoint_id, checked_at, reachable, tls_ok, peer_fingerprint,
			peer_not_after, issuer, error, latency_ms, connected_ip)
		VALUES ($1, COALESCE($2, now()), $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id, checked_at`,
		r.EndpointID, timeOrNil(r.CheckedAt), r.Reachable, r.TLSOK, r.PeerFingerprint,
		r.PeerNotAfter, r.Issuer, r.Error, r.LatencyMS, r.ConnectedIP,
	).Scan(&r.ID, &r.CheckedAt)
	return mapErr("insert monitor result", err)
}

func (s *Store) LatestMonitorResult(ctx context.Context, endpointID uuid.UUID) (*domain.MonitorResult, error) {
	return queryOne(ctx, s.q, "latest monitor result", scanMonitorResult, `
		SELECT `+resultCols+` FROM monitor_results
		WHERE endpoint_id = $1
		ORDER BY checked_at DESC, id DESC
		LIMIT 1`, endpointID)
}

// ListMonitorResults returns the newest results first; limit <= 0 means 100.
func (s *Store) ListMonitorResults(ctx context.Context, endpointID uuid.UUID, limit int) ([]domain.MonitorResult, error) {
	if limit <= 0 {
		limit = defaultResultsLimit
	}
	return queryAll(ctx, s.q, "list monitor results", scanMonitorResult, `
		SELECT `+resultCols+` FROM monitor_results
		WHERE endpoint_id = $1
		ORDER BY checked_at DESC, id DESC
		LIMIT $2`, endpointID, limit)
}
