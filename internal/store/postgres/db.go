// Package postgres implements store.Store on top of PostgreSQL using pgx/v5.
//
// A Store is either pool-backed (returned by Open) or transaction-backed
// (passed to the callback of Tx). Both satisfy store.Store; transaction
// boundaries are controlled by the service layer via Tx.
//
// Conventions:
//   - pgx.ErrNoRows is mapped to domain.ErrNotFound.
//   - unique violations are mapped to domain.ErrConflict.
//   - UPDATE/DELETE of a single row that matches nothing returns domain.ErrNotFound.
//   - JSONB columns are exposed as raw []byte; a nil/empty value is stored as
//     the column default ('{}' or '[]').
package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kogonia/tlsherd/internal/domain"
	"github.com/kogonia/tlsherd/internal/store"
)

// PostgreSQL error codes used for error mapping.
const (
	pgUniqueViolation     = "23505"
	pgForeignKeyViolation = "23503"
)

// dbtx is the subset of pgxpool.Pool / pgx.Tx used by the store.
type dbtx interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// rowScanner is satisfied by pgx.Row and pgx.CollectableRow.
type rowScanner interface {
	Scan(dest ...any) error
}

// Store is a PostgreSQL-backed store.Store.
type Store struct {
	pool *pgxpool.Pool // nil for transaction-scoped stores
	tx   pgx.Tx        // nil for pool-scoped stores
	q    dbtx
}

var _ store.Store = (*Store)(nil)

// Open creates a connection pool from databaseURL and verifies connectivity.
func Open(ctx context.Context, databaseURL string) (*Store, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("postgres: open pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: ping: %w", err)
	}
	return &Store{pool: pool, q: pool}, nil
}

// Close releases the connection pool. It is a no-op for transaction-scoped stores.
func (s *Store) Close() error {
	if s.pool != nil {
		s.pool.Close()
	}
	return nil
}

// begin starts a transaction, or a savepoint when already inside one.
func (s *Store) begin(ctx context.Context) (pgx.Tx, error) {
	if s.tx != nil {
		return s.tx.Begin(ctx)
	}
	return s.pool.Begin(ctx)
}

// Tx runs fn inside a transaction. The Store passed to fn issues all queries
// on that transaction. fn's error (or a panic) rolls back; nil commits.
// Calling Tx on a transaction-scoped store creates a savepoint.
func (s *Store) Tx(ctx context.Context, fn func(store.Store) error) (err error) {
	tx, err := s.begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin tx: %w", err)
	}
	// Rollback after a successful commit is a harmless no-op (pgx.ErrTxClosed).
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	if err := fn(&Store{tx: tx, q: tx}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit tx: %w", err)
	}
	return nil
}

// withTx runs fn atomically: on the current transaction if there is one,
// otherwise on a fresh one.
func (s *Store) withTx(ctx context.Context, fn func(q dbtx) error) error {
	if s.tx != nil {
		return fn(s.q)
	}
	return s.Tx(ctx, func(ts store.Store) error {
		return fn(ts.(*Store).q)
	})
}

// mapErr translates driver errors into domain errors, wrapping with op.
func mapErr(op string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%w: %s", domain.ErrNotFound, op)
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation {
		return fmt.Errorf("%w: %s: %w", domain.ErrConflict, op, err)
	}
	return fmt.Errorf("postgres: %s: %w", op, err)
}

// isFKViolation reports whether err is a foreign key violation.
func isFKViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == pgForeignKeyViolation
}

// execOne executes a statement that must affect exactly one row.
func execOne(ctx context.Context, q dbtx, op, sql string, args ...any) error {
	tag, err := q.Exec(ctx, sql, args...)
	if err != nil {
		return mapErr(op, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: %s", domain.ErrNotFound, op)
	}
	return nil
}

// queryAll runs a query and scans every row with scan.
func queryAll[T any](ctx context.Context, q dbtx, op string, scan func(rowScanner) (T, error), sql string, args ...any) ([]T, error) {
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, mapErr(op, err)
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (T, error) { return scan(r) })
	if err != nil {
		return nil, mapErr(op, err)
	}
	return out, nil
}

// queryOne runs a query expected to return one row.
func queryOne[T any](ctx context.Context, q dbtx, op string, scan func(rowScanner) (T, error), sql string, args ...any) (*T, error) {
	v, err := scan(q.QueryRow(ctx, sql, args...))
	if err != nil {
		return nil, mapErr(op, err)
	}
	return &v, nil
}

// newID returns id, or a fresh UUID when id is the zero value.
func newID(id uuid.UUID) uuid.UUID {
	if id == uuid.Nil {
		return uuid.New()
	}
	return id
}

// timeOrNil returns nil for the zero time so SQL can COALESCE to now().
func timeOrNil(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// jsonOrDefault returns b, or def when b is empty (JSONB NOT NULL columns).
func jsonOrDefault(b []byte, def string) []byte {
	if len(b) == 0 {
		return []byte(def)
	}
	return b
}

// nullableJSON returns nil (SQL NULL) for empty b.
func nullableJSON(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}
