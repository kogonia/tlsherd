package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/kogonia/tlsherd/internal/domain"
)

const notifyAccountCols = `id, name, enabled, allow_all, include_managed, event_types, timezone,
	window_days, window_from, window_to, created_at, updated_at`

func scanNotifyAccount(r rowScanner) (domain.NotificationAccount, error) {
	var a domain.NotificationAccount
	var days []int32
	err := r.Scan(&a.ID, &a.Name, &a.Enabled, &a.AllowAll, &a.IncludeManaged, &a.EventTypes, &a.Timezone,
		&days, &a.WindowFrom, &a.WindowTo, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return a, err
	}
	a.WindowDays = int32sToInts(days)
	if a.EventTypes == nil {
		a.EventTypes = []string{}
	}
	if a.WindowDays == nil {
		a.WindowDays = []int{}
	}
	return a, nil
}

func int32sToInts(in []int32) []int {
	if in == nil {
		return nil
	}
	out := make([]int, len(in))
	for i, v := range in {
		out[i] = int(v)
	}
	return out
}

func intsToInt32s(in []int) []int32 {
	if in == nil {
		return nil
	}
	out := make([]int32, len(in))
	for i, v := range in {
		out[i] = int32(v)
	}
	return out
}

func (s *Store) CreateNotificationAccount(ctx context.Context, a *domain.NotificationAccount) error {
	a.ID = newID(a.ID)
	if a.EventTypes == nil {
		a.EventTypes = []string{}
	}
	if a.WindowDays == nil {
		a.WindowDays = []int{1, 2, 3, 4, 5, 6, 7}
	}
	if a.Timezone == "" {
		a.Timezone = "UTC"
	}
	if a.WindowFrom == "" {
		a.WindowFrom = "00:00"
	}
	if a.WindowTo == "" {
		a.WindowTo = "24:00"
	}
	err := s.q.QueryRow(ctx, `
		INSERT INTO notification_accounts
			(id, name, enabled, allow_all, include_managed, event_types, timezone, window_days, window_from, window_to)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		RETURNING created_at, updated_at`,
		a.ID, a.Name, a.Enabled, a.AllowAll, a.IncludeManaged, a.EventTypes, a.Timezone,
		intsToInt32s(a.WindowDays), a.WindowFrom, a.WindowTo,
	).Scan(&a.CreatedAt, &a.UpdatedAt)
	return mapErr("create notification account", err)
}

func (s *Store) GetNotificationAccount(ctx context.Context, id uuid.UUID) (*domain.NotificationAccount, error) {
	a, err := queryOne(ctx, s.q, "get notification account", scanNotifyAccount,
		`SELECT `+notifyAccountCols+` FROM notification_accounts WHERE id = $1`, id)
	if err != nil {
		return nil, err
	}
	scopes, err := s.ListNotificationScopes(ctx, id)
	if err != nil {
		return nil, err
	}
	a.Scopes = scopes
	return a, nil
}

func (s *Store) ListNotificationAccounts(ctx context.Context) ([]domain.NotificationAccount, error) {
	list, err := queryAll(ctx, s.q, "list notification accounts", scanNotifyAccount,
		`SELECT `+notifyAccountCols+` FROM notification_accounts ORDER BY name, id`)
	if err != nil {
		return nil, err
	}
	for i := range list {
		scopes, err := s.ListNotificationScopes(ctx, list[i].ID)
		if err != nil {
			return nil, err
		}
		list[i].Scopes = scopes
	}
	return list, nil
}

func (s *Store) UpdateNotificationAccount(ctx context.Context, a *domain.NotificationAccount) error {
	err := s.q.QueryRow(ctx, `
		UPDATE notification_accounts
		SET name = $2, enabled = $3, allow_all = $4, include_managed = $5, event_types = $6, timezone = $7,
		    window_days = $8, window_from = $9, window_to = $10, updated_at = now()
		WHERE id = $1
		RETURNING updated_at`,
		a.ID, a.Name, a.Enabled, a.AllowAll, a.IncludeManaged, a.EventTypes, a.Timezone,
		intsToInt32s(a.WindowDays), a.WindowFrom, a.WindowTo,
	).Scan(&a.UpdatedAt)
	return mapErr("update notification account", err)
}

func (s *Store) DeleteNotificationAccount(ctx context.Context, id uuid.UUID) error {
	return execOne(ctx, s.q, "delete notification account",
		`DELETE FROM notification_accounts WHERE id = $1`, id)
}

func (s *Store) SetNotificationScopes(ctx context.Context, accountID uuid.UUID, scopes []domain.NotifyScope) error {
	return s.withTx(ctx, func(q dbtx) error {
		if _, err := q.Exec(ctx, `DELETE FROM notification_scopes WHERE account_id = $1`, accountID); err != nil {
			return mapErr("clear notification scopes", err)
		}
		for _, sc := range scopes {
			if _, err := q.Exec(ctx, `
				INSERT INTO notification_scopes (account_id, kind, target_id) VALUES ($1,$2,$3)`,
				accountID, sc.Kind, sc.TargetID); err != nil {
				return mapErr("insert notification scope", err)
			}
		}
		return nil
	})
}

func (s *Store) ListNotificationScopes(ctx context.Context, accountID uuid.UUID) ([]domain.NotifyScope, error) {
	return queryAll(ctx, s.q, "list notification scopes", func(r rowScanner) (domain.NotifyScope, error) {
		var sc domain.NotifyScope
		err := r.Scan(&sc.Kind, &sc.TargetID)
		return sc, err
	}, `SELECT kind, target_id FROM notification_scopes WHERE account_id = $1 ORDER BY kind, target_id`, accountID)
}

// ListNotificationAccountsForFanout returns all accounts with scopes loaded (enabled or not).
func (s *Store) ListNotificationAccountsForFanout(ctx context.Context) ([]domain.NotificationAccount, error) {
	return s.ListNotificationAccounts(ctx)
}

func (s *Store) DomainInGroups(ctx context.Context, domainID uuid.UUID, groupIDs []uuid.UUID) (bool, error) {
	if len(groupIDs) == 0 {
		return false, nil
	}
	var ok bool
	err := s.q.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM domain_groups
			WHERE domain_id = $1 AND group_id = ANY($2::uuid[])
		)`, domainID, groupIDs).Scan(&ok)
	return ok, mapErr("domain in groups", err)
}

func (s *Store) CreateNotificationDestination(ctx context.Context, d *domain.NotificationDestination) error {
	d.ID = newID(d.ID)
	err := s.q.QueryRow(ctx, `
		INSERT INTO notification_destinations (id, account_id, channel, config, enabled)
		VALUES ($1,$2,$3,$4,$5)
		RETURNING created_at`,
		d.ID, d.AccountID, d.Channel, jsonOrDefault(d.Config, "{}"), d.Enabled,
	).Scan(&d.CreatedAt)
	return mapErr("create notification destination", err)
}

func (s *Store) GetNotificationDestination(ctx context.Context, id uuid.UUID) (*domain.NotificationDestination, error) {
	return queryOne(ctx, s.q, "get notification destination", scanNotifyDest,
		`SELECT id, account_id, channel, config, enabled, created_at FROM notification_destinations WHERE id = $1`, id)
}

func scanNotifyDest(r rowScanner) (domain.NotificationDestination, error) {
	var d domain.NotificationDestination
	err := r.Scan(&d.ID, &d.AccountID, &d.Channel, &d.Config, &d.Enabled, &d.CreatedAt)
	return d, err
}

func (s *Store) ListNotificationDestinations(ctx context.Context, accountID uuid.UUID) ([]domain.NotificationDestination, error) {
	return queryAll(ctx, s.q, "list notification destinations", scanNotifyDest,
		`SELECT id, account_id, channel, config, enabled, created_at
		 FROM notification_destinations WHERE account_id = $1 ORDER BY created_at, id`, accountID)
}

func (s *Store) UpdateNotificationDestination(ctx context.Context, d *domain.NotificationDestination) error {
	return execOne(ctx, s.q, "update notification destination", `
		UPDATE notification_destinations
		SET channel = $2, config = $3, enabled = $4
		WHERE id = $1 AND account_id = $5`,
		d.ID, d.Channel, jsonOrDefault(d.Config, "{}"), d.Enabled, d.AccountID)
}

func (s *Store) DeleteNotificationDestination(ctx context.Context, id uuid.UUID) error {
	return execOne(ctx, s.q, "delete notification destination",
		`DELETE FROM notification_destinations WHERE id = $1`, id)
}

func (s *Store) InsertNotificationOutbox(ctx context.Context, o *domain.NotificationOutbox) error {
	err := s.q.QueryRow(ctx, `
		INSERT INTO notification_outbox
			(event_id, destination_id, kind, payload, status, attempts, next_attempt_at, last_error)
		VALUES ($1,$2,$3,$4,$5,$6,COALESCE($7, now()),$8)
		ON CONFLICT (event_id, destination_id, kind) DO NOTHING
		RETURNING id, created_at, next_attempt_at`,
		o.EventID, o.DestinationID, o.Kind, jsonOrDefault(o.Payload, "{}"), o.Status,
		o.Attempts, timeOrNil(o.NextAttemptAt), o.LastError,
	).Scan(&o.ID, &o.CreatedAt, &o.NextAttemptAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil // already enqueued
		}
		return mapErr("insert notification outbox", err)
	}
	return nil
}

func (s *Store) ClaimNotificationOutbox(ctx context.Context, limit int, now time.Time) ([]domain.NotificationOutbox, error) {
	if limit <= 0 {
		limit = 50
	}
	return queryAll(ctx, s.q, "claim notification outbox", scanOutbox, `
		UPDATE notification_outbox
		SET attempts = attempts + 1,
		    next_attempt_at = $1 + interval '1 minute'
		WHERE id IN (
			SELECT id FROM notification_outbox
			WHERE status = 'pending' AND next_attempt_at <= $1
			ORDER BY next_attempt_at, id
			LIMIT $2
			FOR UPDATE SKIP LOCKED
		)
		RETURNING id, event_id, destination_id, kind, payload, status, attempts,
		          next_attempt_at, last_error, created_at, sent_at`, now, limit)
}

func scanOutbox(r rowScanner) (domain.NotificationOutbox, error) {
	var o domain.NotificationOutbox
	err := r.Scan(&o.ID, &o.EventID, &o.DestinationID, &o.Kind, &o.Payload, &o.Status,
		&o.Attempts, &o.NextAttemptAt, &o.LastError, &o.CreatedAt, &o.SentAt)
	return o, err
}

func (s *Store) UpdateNotificationOutbox(ctx context.Context, o *domain.NotificationOutbox) error {
	return execOne(ctx, s.q, "update notification outbox", `
		UPDATE notification_outbox
		SET status = $2, attempts = $3, next_attempt_at = $4, last_error = $5, sent_at = $6
		WHERE id = $1`,
		o.ID, o.Status, o.Attempts, o.NextAttemptAt, o.LastError, o.SentAt)
}

func (s *Store) ListEventNotifications(ctx context.Context, eventIDs []int64) (map[int64][]domain.EventNotification, error) {
	out := make(map[int64][]domain.EventNotification)
	if len(eventIDs) == 0 {
		return out, nil
	}
	rows, err := queryAll(ctx, s.q, "list event notifications", func(r rowScanner) (struct {
		EventID int64
		Row     domain.EventNotification
	}, error) {
		var eventID int64
		var row domain.EventNotification
		err := r.Scan(&eventID, &row.AccountID, &row.AccountName, &row.Channel, &row.Kind,
			&row.Status, &row.SentAt, &row.LastError)
		return struct {
			EventID int64
			Row     domain.EventNotification
		}{eventID, row}, err
	}, `
		SELECT o.event_id, a.id, a.name, d.channel, o.kind, o.status, o.sent_at, o.last_error
		FROM notification_outbox o
		JOIN notification_destinations d ON d.id = o.destination_id
		JOIN notification_accounts a ON a.id = d.account_id
		WHERE o.event_id = ANY($1::bigint[])
		ORDER BY o.event_id, a.name, d.channel, o.kind`, eventIDs)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		out[r.EventID] = append(out[r.EventID], r.Row)
	}
	return out, nil
}

func (s *Store) GetOutboxWithDestination(ctx context.Context, id int64) (*domain.NotificationOutbox, *domain.NotificationDestination, *domain.NotificationAccount, error) {
	o, err := queryOne(ctx, s.q, "get outbox", scanOutbox, `
		SELECT id, event_id, destination_id, kind, payload, status, attempts,
		       next_attempt_at, last_error, created_at, sent_at
		FROM notification_outbox WHERE id = $1`, id)
	if err != nil {
		return nil, nil, nil, err
	}
	d, err := s.GetNotificationDestination(ctx, o.DestinationID)
	if err != nil {
		return nil, nil, nil, err
	}
	a, err := s.GetNotificationAccount(ctx, d.AccountID)
	if err != nil {
		return nil, nil, nil, err
	}
	return o, d, a, nil
}
