package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/kogonia/tlsherd/internal/domain"
	"github.com/kogonia/tlsherd/internal/notify"
)

// NotificationSettingsView is the admin settings payload (secrets masked on GET).
type NotificationSettingsView struct {
	SMTP     notify.SMTPSettings     `json:"smtp"`
	Telegram notify.TelegramSettings `json:"telegram"`
	Worker   notify.WorkerSettings   `json:"worker"`
}

// GetNotificationSettings returns global notification config. Admin only.
func (s *Services) GetNotificationSettings(ctx context.Context, actor *domain.User) (*NotificationSettingsView, error) {
	if err := requireAdmin(actor); err != nil {
		return nil, err
	}
	set, err := s.loadNotifySettings(ctx, s.Store)
	if err != nil {
		return nil, err
	}
	if set.SMTP.Password != "" {
		set.SMTP.Password = "********"
	}
	if set.Telegram.BotToken != "" {
		set.Telegram.BotToken = "********"
	}
	return &NotificationSettingsView{SMTP: set.SMTP, Telegram: set.Telegram, Worker: set.Worker}, nil
}

// PutNotificationSettingsInput updates global notification config.
type PutNotificationSettingsInput struct {
	SMTP     notify.SMTPSettings     `json:"smtp"`
	Telegram notify.TelegramSettings `json:"telegram"`
	Worker   notify.WorkerSettings   `json:"worker"`
}

// PutNotificationSettings stores global notification config. Admin only.
// Password/bot_token of "********" or empty keep the previous secret when one exists.
func (s *Services) PutNotificationSettings(ctx context.Context, actor *domain.User, in PutNotificationSettingsInput) error {
	if err := requireAdmin(actor); err != nil {
		return err
	}
	cur, err := s.loadNotifySettings(ctx, s.Store)
	if err != nil {
		return err
	}
	next := notify.Settings{SMTP: in.SMTP, Telegram: in.Telegram, Worker: in.Worker}
	if next.SMTP.Password == "" || next.SMTP.Password == "********" {
		next.SMTP.Password = cur.SMTP.Password
	}
	if next.Telegram.BotToken == "" || next.Telegram.BotToken == "********" {
		next.Telegram.BotToken = cur.Telegram.BotToken
	}
	if next.Worker.Batch <= 0 {
		next.Worker.Batch = 50
	}
	if next.Worker.MaxAttempts <= 0 {
		next.Worker.MaxAttempts = 8
	}
	if next.Worker.Interval == "" {
		next.Worker.Interval = "15s"
	}
	if _, err := time.ParseDuration(next.Worker.Interval); err != nil {
		return invalidf("invalid worker.interval")
	}
	if next.SMTP.Port == 0 {
		next.SMTP.Port = 587
	}
	raw, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if err := s.Store.SetSetting(ctx, settingNotifications, raw); err != nil {
		return fmt.Errorf("save notification settings: %w", err)
	}
	_ = s.audit(ctx, s.Store, actor, "notifications.settings_update", "settings", settingNotifications, nil)
	return nil
}

// CreateNotificationAccountInput creates a notification account.
type CreateNotificationAccountInput struct {
	Name       string               `json:"name"`
	Enabled    *bool                `json:"enabled"`
	AllowAll   bool                 `json:"allow_all"`
	EventTypes []string             `json:"event_types"`
	Timezone   string               `json:"timezone"`
	WindowDays []int                `json:"window_days"`
	WindowFrom string               `json:"window_from"`
	WindowTo   string               `json:"window_to"`
	Scopes     []domain.NotifyScope `json:"scopes"`
}

// CreateNotificationAccount creates an account. Admin only.
func (s *Services) CreateNotificationAccount(ctx context.Context, actor *domain.User, in CreateNotificationAccountInput) (*domain.NotificationAccount, error) {
	if err := requireAdmin(actor); err != nil {
		return nil, err
	}
	name := normalizeText(in.Name)
	if name == "" {
		return nil, invalidf("name is required")
	}
	types, err := validateEventTypes(in.EventTypes, true)
	if err != nil {
		return nil, err
	}
	tz := in.Timezone
	if tz == "" {
		tz = "UTC"
	}
	if _, err := time.LoadLocation(tz); err != nil {
		return nil, invalidf("invalid timezone")
	}
	days := in.WindowDays
	if len(days) == 0 {
		days = []int{1, 2, 3, 4, 5, 6, 7}
	}
	if err := validateWindow(days, in.WindowFrom, in.WindowTo); err != nil {
		return nil, err
	}
	from, to := in.WindowFrom, in.WindowTo
	if from == "" {
		from = "00:00"
	}
	if to == "" {
		to = "24:00"
	}
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	if err := s.validateScopes(ctx, in.Scopes); err != nil {
		return nil, err
	}
	a := &domain.NotificationAccount{
		Name: name, Enabled: enabled, AllowAll: in.AllowAll, EventTypes: types,
		Timezone: tz, WindowDays: days, WindowFrom: from, WindowTo: to,
	}
	if err := s.Store.CreateNotificationAccount(ctx, a); err != nil {
		return nil, fmt.Errorf("create notification account: %w", err)
	}
	if err := s.Store.SetNotificationScopes(ctx, a.ID, in.Scopes); err != nil {
		return nil, fmt.Errorf("set notification scopes: %w", err)
	}
	a.Scopes = in.Scopes
	_ = s.audit(ctx, s.Store, actor, "notifications.account_create", "notification_account", a.ID.String(),
		map[string]any{"name": a.Name})
	return a, nil
}

// UpdateNotificationAccountInput updates an account.
type UpdateNotificationAccountInput struct {
	Name       string               `json:"name"`
	Enabled    *bool                `json:"enabled"`
	AllowAll   *bool                `json:"allow_all"`
	EventTypes []string             `json:"event_types"`
	Timezone   string               `json:"timezone"`
	WindowDays []int                `json:"window_days"`
	WindowFrom string               `json:"window_from"`
	WindowTo   string               `json:"window_to"`
	Scopes     []domain.NotifyScope `json:"scopes"`
}

// UpdateNotificationAccount updates an account. Admin only.
func (s *Services) UpdateNotificationAccount(ctx context.Context, actor *domain.User, id uuid.UUID, in UpdateNotificationAccountInput) (*domain.NotificationAccount, error) {
	if err := requireAdmin(actor); err != nil {
		return nil, err
	}
	a, err := s.Store.GetNotificationAccount(ctx, id)
	if err != nil {
		return nil, err
	}
	if in.Name != "" {
		a.Name = normalizeText(in.Name)
	}
	if a.Name == "" {
		return nil, invalidf("name is required")
	}
	if in.Enabled != nil {
		a.Enabled = *in.Enabled
	}
	if in.AllowAll != nil {
		a.AllowAll = *in.AllowAll
	}
	if in.EventTypes != nil {
		types, err := validateEventTypes(in.EventTypes, false)
		if err != nil {
			return nil, err
		}
		a.EventTypes = types
	}
	if in.Timezone != "" {
		if _, err := time.LoadLocation(in.Timezone); err != nil {
			return nil, invalidf("invalid timezone")
		}
		a.Timezone = in.Timezone
	}
	if in.WindowDays != nil {
		a.WindowDays = in.WindowDays
	}
	if in.WindowFrom != "" {
		a.WindowFrom = in.WindowFrom
	}
	if in.WindowTo != "" {
		a.WindowTo = in.WindowTo
	}
	if err := validateWindow(a.WindowDays, a.WindowFrom, a.WindowTo); err != nil {
		return nil, err
	}
	if in.Scopes != nil {
		if err := s.validateScopes(ctx, in.Scopes); err != nil {
			return nil, err
		}
	}
	if err := s.Store.UpdateNotificationAccount(ctx, a); err != nil {
		return nil, fmt.Errorf("update notification account: %w", err)
	}
	if in.Scopes != nil {
		if err := s.Store.SetNotificationScopes(ctx, a.ID, in.Scopes); err != nil {
			return nil, fmt.Errorf("set notification scopes: %w", err)
		}
		a.Scopes = in.Scopes
	}
	_ = s.audit(ctx, s.Store, actor, "notifications.account_update", "notification_account", a.ID.String(), nil)
	return a, nil
}

// ListNotificationAccounts lists accounts. Admin only.
func (s *Services) ListNotificationAccounts(ctx context.Context, actor *domain.User) ([]domain.NotificationAccount, error) {
	if err := requireAdmin(actor); err != nil {
		return nil, err
	}
	return s.Store.ListNotificationAccounts(ctx)
}

// GetNotificationAccount returns one account. Admin only.
func (s *Services) GetNotificationAccount(ctx context.Context, actor *domain.User, id uuid.UUID) (*domain.NotificationAccount, error) {
	if err := requireAdmin(actor); err != nil {
		return nil, err
	}
	return s.Store.GetNotificationAccount(ctx, id)
}

// DeleteNotificationAccount deletes an account. Admin only.
func (s *Services) DeleteNotificationAccount(ctx context.Context, actor *domain.User, id uuid.UUID) error {
	if err := requireAdmin(actor); err != nil {
		return err
	}
	if err := s.Store.DeleteNotificationAccount(ctx, id); err != nil {
		return err
	}
	_ = s.audit(ctx, s.Store, actor, "notifications.account_delete", "notification_account", id.String(), nil)
	return nil
}

// DestinationInput creates/updates a destination.
type DestinationInput struct {
	Channel string          `json:"channel"`
	Config  json.RawMessage `json:"config"`
	Enabled *bool           `json:"enabled"`
}

// CreateNotificationDestination adds a destination. Admin only.
func (s *Services) CreateNotificationDestination(ctx context.Context, actor *domain.User, accountID uuid.UUID, in DestinationInput) (*domain.NotificationDestination, error) {
	if err := requireAdmin(actor); err != nil {
		return nil, err
	}
	if _, err := s.Store.GetNotificationAccount(ctx, accountID); err != nil {
		return nil, err
	}
	cfg, err := validateDestConfig(in.Channel, in.Config)
	if err != nil {
		return nil, err
	}
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	d := &domain.NotificationDestination{
		AccountID: accountID, Channel: in.Channel, Config: cfg, Enabled: enabled,
	}
	if err := s.Store.CreateNotificationDestination(ctx, d); err != nil {
		return nil, fmt.Errorf("create destination: %w", err)
	}
	return d, nil
}

// UpdateNotificationDestination updates a destination. Admin only.
func (s *Services) UpdateNotificationDestination(ctx context.Context, actor *domain.User, accountID, destID uuid.UUID, in DestinationInput) (*domain.NotificationDestination, error) {
	if err := requireAdmin(actor); err != nil {
		return nil, err
	}
	d, err := s.Store.GetNotificationDestination(ctx, destID)
	if err != nil {
		return nil, err
	}
	if d.AccountID != accountID {
		return nil, domain.ErrNotFound
	}
	if in.Channel != "" {
		d.Channel = in.Channel
	}
	if in.Config != nil {
		cfg, err := validateDestConfig(d.Channel, in.Config)
		if err != nil {
			return nil, err
		}
		d.Config = cfg
	}
	if in.Enabled != nil {
		d.Enabled = *in.Enabled
	}
	if err := s.Store.UpdateNotificationDestination(ctx, d); err != nil {
		return nil, err
	}
	return d, nil
}

// ListNotificationDestinations lists destinations. Admin only.
func (s *Services) ListNotificationDestinations(ctx context.Context, actor *domain.User, accountID uuid.UUID) ([]domain.NotificationDestination, error) {
	if err := requireAdmin(actor); err != nil {
		return nil, err
	}
	if _, err := s.Store.GetNotificationAccount(ctx, accountID); err != nil {
		return nil, err
	}
	return s.Store.ListNotificationDestinations(ctx, accountID)
}

// DeleteNotificationDestination removes a destination. Admin only.
func (s *Services) DeleteNotificationDestination(ctx context.Context, actor *domain.User, accountID, destID uuid.UUID) error {
	if err := requireAdmin(actor); err != nil {
		return err
	}
	d, err := s.Store.GetNotificationDestination(ctx, destID)
	if err != nil {
		return err
	}
	if d.AccountID != accountID {
		return domain.ErrNotFound
	}
	return s.Store.DeleteNotificationDestination(ctx, destID)
}

// TestNotificationInput sends a test message.
type TestNotificationInput struct {
	Channel string          `json:"channel"`
	Config  json.RawMessage `json:"config"`
}

// TestNotification sends a one-off test via the given channel. Admin only.
func (s *Services) TestNotification(ctx context.Context, actor *domain.User, in TestNotificationInput) error {
	if err := requireAdmin(actor); err != nil {
		return err
	}
	set, err := s.loadNotifySettings(ctx, s.Store)
	if err != nil {
		return err
	}
	cfg, err := validateDestConfig(in.Channel, in.Config)
	if err != nil {
		return err
	}
	dest := &domain.NotificationDestination{Channel: in.Channel, Config: cfg, Enabled: true}
	msg := notify.Message{
		Subject: "[tlsherd] test notification",
		Text:    "TLS herd test notification.",
		JSON:    []byte(`{"kind":"test","message":"TLS herd test notification."}`),
	}
	return s.sendDestination(ctx, set, dest, msg)
}

func validateEventTypes(types []string, applyDefault bool) ([]string, error) {
	if len(types) == 0 {
		if applyDefault {
			out := make([]string, len(DefaultNotificationEventTypes))
			copy(out, DefaultNotificationEventTypes)
			return out, nil
		}
		return nil, invalidf("event_types must not be empty")
	}
	known := knownEventTypeSet()
	seen := map[string]struct{}{}
	out := make([]string, 0, len(types))
	for _, t := range types {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if _, ok := known[t]; !ok {
			return nil, invalidf("unknown event type %q", t)
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	if len(out) == 0 {
		return nil, invalidf("event_types must not be empty")
	}
	return out, nil
}

func validateWindow(days []int, from, to string) error {
	for _, d := range days {
		if d < 1 || d > 7 {
			return invalidf("invalid window day %d", d)
		}
	}
	if from == "" {
		from = "00:00"
	}
	if to == "" {
		to = "24:00"
	}
	if _, err := notify.InWindow(notify.Window{TZ: "UTC", Days: days, From: from, To: to}, time.Now()); err != nil {
		return invalidf("invalid window: %v", err)
	}
	return nil
}

func (s *Services) validateScopes(ctx context.Context, scopes []domain.NotifyScope) error {
	for _, sc := range scopes {
		switch sc.Kind {
		case domain.NotifyScopeDomain:
			if _, err := s.Store.GetDomain(ctx, sc.TargetID); err != nil {
				return invalidf("unknown domain scope %s", sc.TargetID)
			}
		case domain.NotifyScopeGroup:
			if _, err := s.Store.GetGroup(ctx, sc.TargetID); err != nil {
				return invalidf("unknown group scope %s", sc.TargetID)
			}
		case domain.NotifyScopeServer:
			if _, err := s.Store.GetServer(ctx, sc.TargetID); err != nil {
				return invalidf("unknown server scope %s", sc.TargetID)
			}
		default:
			return invalidf("invalid scope kind %q", sc.Kind)
		}
	}
	return nil
}

func validateDestConfig(channel string, raw json.RawMessage) ([]byte, error) {
	switch channel {
	case domain.NotifyChannelEmail:
		var c notify.EmailConfig
		if err := json.Unmarshal(raw, &c); err != nil || strings.TrimSpace(c.Address) == "" {
			return nil, invalidf("email config requires address")
		}
		return json.Marshal(c)
	case domain.NotifyChannelTelegram:
		var c notify.TelegramConfig
		if err := json.Unmarshal(raw, &c); err != nil || strings.TrimSpace(c.ChatID) == "" {
			return nil, invalidf("telegram config requires chat_id")
		}
		return json.Marshal(c)
	case domain.NotifyChannelWebhook:
		var c notify.WebhookConfig
		if err := json.Unmarshal(raw, &c); err != nil || strings.TrimSpace(c.URL) == "" {
			return nil, invalidf("webhook config requires url")
		}
		return json.Marshal(c)
	default:
		return nil, invalidf("invalid channel %q", channel)
	}
}
