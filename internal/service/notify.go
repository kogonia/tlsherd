package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/kogonia/tlsherd/internal/domain"
	"github.com/kogonia/tlsherd/internal/notify"
	"github.com/kogonia/tlsherd/internal/store"
)

const settingNotifications = "notifications"

// DefaultNotificationEventTypes are applied when creating an account without types.
var DefaultNotificationEventTypes = []string{
	EvCertExpired,
	EvCertExpiringSoon,
	EvCertKeyMismatch,
	EvCertChainInvalid,
	EvCertDomainMismatchOK,
	EvEndpointCertMismatch,
}

// KnownEventTypes returns all event type constants.
func KnownEventTypes() []string {
	return []string{
		EvCertExpired, EvCertExpiringSoon, EvCertKeyMismatch, EvCertChainInvalid,
		EvCertDomainMismatchOK, EvCertExpiredUploadOK, EvCertNotYetValidUploadOK,
		EvCertUploadRejected, EvCertRollback, EvCertCAMismatch, EvManagedCertChangeOK,
		EvAgentEnrollPending, EvAgentAccepted, EvAgentRejected, EvAgentIdentityMismatch,
		EvAgentOffline, EvAgentApplyFailed, EvAgentVerifyFailed, EvAgentPostCheckMismatch,
		EvAgentConfigUpdated, EvEndpointDown, EvEndpointCertMismatch, EvDomainUngrouped,
	}
}

func knownEventTypeSet() map[string]struct{} {
	m := make(map[string]struct{}, len(KnownEventTypes()))
	for _, t := range KnownEventTypes() {
		m[t] = struct{}{}
	}
	return m
}

// EventWithNotify is an event plus delivery status for the API.
type EventWithNotify struct {
	domain.Event
	NotifyStatus  string                     `json:"notify_status"`
	Notifications []domain.EventNotification `json:"notifications"`
}

// notifyFanout enqueues outbox rows for matching accounts. Best-effort: logs errors.
func (s *Services) notifyFanout(ctx context.Context, st store.Store, ev *domain.Event, kind string) {
	if ev == nil || ev.ID == 0 {
		return
	}
	if err := s.doNotifyFanout(ctx, st, ev, kind); err != nil {
		s.log().Error("notification fanout failed", "component", "notify", "event_id", ev.ID,
			"kind", kind, "error", err)
	}
}

func (s *Services) doNotifyFanout(ctx context.Context, st store.Store, ev *domain.Event, kind string) error {
	accounts, err := st.ListNotificationAccountsForFanout(ctx)
	if err != nil {
		return err
	}
	set, err := s.loadNotifySettings(ctx, st)
	if err != nil {
		return err
	}
	payload, err := buildNotifyPayload(ev, kind)
	if err != nil {
		return err
	}
	for i := range accounts {
		acc := &accounts[i]
		if !accountMatchesEvent(acc, ev) {
			continue
		}
		okScope, err := s.accountScopeMatches(ctx, st, acc, ev)
		if err != nil {
			return err
		}
		if !okScope {
			continue
		}
		dests, err := st.ListNotificationDestinations(ctx, acc.ID)
		if err != nil {
			return err
		}
		if len(dests) == 0 {
			continue
		}
		for j := range dests {
			d := &dests[j]
			status := domain.NotifyOutboxPending
			reason := ""
			if !acc.Enabled {
				status = domain.NotifyOutboxSkipped
				reason = "account disabled"
			} else if !d.Enabled {
				status = domain.NotifyOutboxSkipped
				reason = "destination disabled"
			} else if ok, why := notify.ChannelConfigured(set, d.Channel); !ok {
				status = domain.NotifyOutboxSkipped
				reason = why
			}
			o := &domain.NotificationOutbox{
				EventID:       ev.ID,
				DestinationID: d.ID,
				Kind:          kind,
				Payload:       payload,
				Status:        status,
				LastError:     reason,
				NextAttemptAt: s.now(),
			}
			if err := st.InsertNotificationOutbox(ctx, o); err != nil {
				return err
			}
		}
	}
	return nil
}

func accountMatchesEvent(acc *domain.NotificationAccount, ev *domain.Event) bool {
	if len(acc.EventTypes) == 0 {
		return false
	}
	for _, t := range acc.EventTypes {
		if t == ev.Type {
			return true
		}
	}
	return false
}

func (s *Services) accountScopeMatches(ctx context.Context, st store.Store, acc *domain.NotificationAccount, ev *domain.Event) (bool, error) {
	if acc.AllowAll {
		return true, nil
	}
	if len(acc.Scopes) == 0 {
		return false, nil
	}
	var groupIDs []uuid.UUID
	for _, sc := range acc.Scopes {
		switch sc.Kind {
		case domain.NotifyScopeDomain:
			if ev.DomainID != nil && *ev.DomainID == sc.TargetID {
				return true, nil
			}
		case domain.NotifyScopeServer:
			if ev.ServerID != nil && *ev.ServerID == sc.TargetID {
				return true, nil
			}
		case domain.NotifyScopeGroup:
			if ev.GroupID != nil && *ev.GroupID == sc.TargetID {
				return true, nil
			}
			groupIDs = append(groupIDs, sc.TargetID)
		}
	}
	if ev.DomainID != nil && len(groupIDs) > 0 {
		return st.DomainInGroups(ctx, *ev.DomainID, groupIDs)
	}
	return false, nil
}

func buildNotifyPayload(ev *domain.Event, kind string) ([]byte, error) {
	m := map[string]any{
		"kind":       kind,
		"event_id":   ev.ID,
		"at":         ev.At.UTC().Format(time.RFC3339),
		"type":       ev.Type,
		"severity":   ev.Severity,
		"message":    ev.Message,
		"domain_id":  ev.DomainID,
		"server_id":  ev.ServerID,
		"group_id":   ev.GroupID,
		"started_at": ev.At.UTC().Format(time.RFC3339),
	}
	if kind == domain.NotifyKindResolved && ev.ResolvedAt != nil {
		ended := ev.ResolvedAt.UTC()
		m["ended_at"] = ended.Format(time.RFC3339)
		dur := ended.Sub(ev.At.UTC())
		m["duration_seconds"] = int64(dur.Seconds())
		m["duration"] = dur.Round(time.Second).String()
	}
	if len(ev.Details) > 0 {
		var details any
		if json.Unmarshal(ev.Details, &details) == nil {
			m["details"] = details
		}
	}
	return json.Marshal(m)
}

func (s *Services) loadNotifySettings(ctx context.Context, st store.Store) (notify.Settings, error) {
	set := notify.DefaultSettings()
	raw, err := st.GetSetting(ctx, settingNotifications)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return set, nil
		}
		return set, err
	}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &set)
	}
	if set.Worker.Batch <= 0 {
		set.Worker.Batch = 50
	}
	if set.Worker.MaxAttempts <= 0 {
		set.Worker.MaxAttempts = 8
	}
	if set.Worker.Interval == "" {
		set.Worker.Interval = "15s"
	}
	if set.SMTP.Port == 0 {
		set.SMTP.Port = 587
	}
	return set, nil
}

// EnrichEventsWithNotify attaches delivery rollup to events.
func (s *Services) EnrichEventsWithNotify(ctx context.Context, evs []domain.Event) ([]EventWithNotify, error) {
	ids := make([]int64, len(evs))
	for i, e := range evs {
		ids[i] = e.ID
	}
	byEvent, err := s.Store.ListEventNotifications(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("enrich events notify: %w", err)
	}
	out := make([]EventWithNotify, len(evs))
	for i, e := range evs {
		rows := byEvent[e.ID]
		if rows == nil {
			rows = []domain.EventNotification{}
		}
		out[i] = EventWithNotify{
			Event:         e,
			NotifyStatus:  notify.RollupStatus(rows),
			Notifications: rows,
		}
	}
	return out, nil
}

// ProcessNotificationOutbox claims and delivers due outbox rows. Called by the worker.
func (s *Services) ProcessNotificationOutbox(ctx context.Context) {
	set, err := s.loadNotifySettings(ctx, s.Store)
	if err != nil {
		s.log().Error("load notification settings", "component", "notify", "error", err)
		return
	}
	rows, err := s.Store.ClaimNotificationOutbox(ctx, set.Worker.Batch, s.now())
	if err != nil {
		s.log().Error("claim notification outbox", "component", "notify", "error", err)
		return
	}
	for i := range rows {
		s.deliverOutboxRow(ctx, set, &rows[i])
	}
}

func (s *Services) deliverOutboxRow(ctx context.Context, set notify.Settings, o *domain.NotificationOutbox) {
	if o.Status != domain.NotifyOutboxPending {
		return
	}
	_, dest, acc, err := s.Store.GetOutboxWithDestination(ctx, o.ID)
	if err != nil {
		s.log().Error("load outbox destination", "component", "notify", "outbox_id", o.ID, "error", err)
		return
	}
	if !acc.Enabled || !dest.Enabled {
		o.Status = domain.NotifyOutboxSkipped
		o.LastError = "disabled"
		_ = s.Store.UpdateNotificationOutbox(ctx, o)
		return
	}
	win := notify.Window{TZ: acc.Timezone, Days: acc.WindowDays, From: acc.WindowFrom, To: acc.WindowTo}
	ok, err := notify.InWindow(win, s.now())
	if err != nil {
		o.LastError = err.Error()
		o.NextAttemptAt = s.now().Add(time.Minute)
		_ = s.Store.UpdateNotificationOutbox(ctx, o)
		return
	}
	if !ok {
		next, nerr := notify.NextWindowOpen(win, s.now())
		if nerr != nil {
			next = s.now().Add(time.Hour)
		}
		// Undo the claim attempt increment for deferral: Claim already bumped attempts.
		o.Attempts--
		if o.Attempts < 0 {
			o.Attempts = 0
		}
		o.Status = domain.NotifyOutboxPending
		o.NextAttemptAt = next
		o.LastError = "outside working window"
		_ = s.Store.UpdateNotificationOutbox(ctx, o)
		return
	}

	msg := renderNotifyMessage(o)
	sendErr := s.sendDestination(ctx, set, dest, msg)
	if sendErr != nil {
		o.LastError = sendErr.Error()
		if o.Attempts >= set.Worker.MaxAttempts {
			o.Status = domain.NotifyOutboxFailed
		} else {
			o.Status = domain.NotifyOutboxPending
			o.NextAttemptAt = s.now().Add(backoff(o.Attempts))
		}
		_ = s.Store.UpdateNotificationOutbox(ctx, o)
		return
	}
	now := s.now()
	o.Status = domain.NotifyOutboxSent
	o.SentAt = &now
	o.LastError = ""
	_ = s.Store.UpdateNotificationOutbox(ctx, o)
}

func backoff(attempts int) time.Duration {
	d := time.Duration(attempts) * time.Duration(attempts) * 30 * time.Second
	if d > 30*time.Minute {
		d = 30 * time.Minute
	}
	if d < 30*time.Second {
		d = 30 * time.Second
	}
	return d
}

func renderNotifyMessage(o *domain.NotificationOutbox) notify.Message {
	var p map[string]any
	_ = json.Unmarshal(o.Payload, &p)
	kind, _ := p["kind"].(string)
	typ, _ := p["type"].(string)
	sev, _ := p["severity"].(string)
	msg, _ := p["message"].(string)
	prefix := "OPENED"
	if kind == domain.NotifyKindResolved {
		prefix = "RESOLVED"
	}
	subject := fmt.Sprintf("[tlsherd] %s %s (%s)", prefix, typ, sev)
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s\nSeverity: %s\nMessage: %s\n", prefix, typ, sev, msg)
	if kind == domain.NotifyKindResolved {
		if v, ok := p["started_at"].(string); ok {
			fmt.Fprintf(&b, "Started: %s\n", v)
		}
		if v, ok := p["ended_at"].(string); ok {
			fmt.Fprintf(&b, "Ended: %s\n", v)
		}
		if v, ok := p["duration"].(string); ok {
			fmt.Fprintf(&b, "Duration: %s\n", v)
		}
	} else if v, ok := p["at"].(string); ok {
		fmt.Fprintf(&b, "At: %s\n", v)
	}
	payload := o.Payload
	if len(payload) == 0 {
		payload = []byte("{}")
	}
	return notify.Message{Subject: subject, Text: b.String(), JSON: payload}
}

func (s *Services) sendDestination(ctx context.Context, set notify.Settings, dest *domain.NotificationDestination, msg notify.Message) error {
	switch dest.Channel {
	case domain.NotifyChannelEmail:
		var cfg notify.EmailConfig
		_ = json.Unmarshal(dest.Config, &cfg)
		return notify.SendEmail(ctx, set.SMTP, cfg.Address, msg)
	case domain.NotifyChannelTelegram:
		var cfg notify.TelegramConfig
		_ = json.Unmarshal(dest.Config, &cfg)
		return notify.SendTelegram(ctx, set.Telegram.BotToken, cfg.ChatID, msg.Text)
	case domain.NotifyChannelWebhook:
		var cfg notify.WebhookConfig
		_ = json.Unmarshal(dest.Config, &cfg)
		return notify.SendWebhook(ctx, cfg.URL, cfg.Secret, msg.JSON)
	default:
		return fmt.Errorf("unknown channel %q", dest.Channel)
	}
}

// NotificationWorkerInterval returns the poll interval from settings.
func (s *Services) NotificationWorkerInterval(ctx context.Context) time.Duration {
	set, err := s.loadNotifySettings(ctx, s.Store)
	if err != nil {
		return 15 * time.Second
	}
	d, err := time.ParseDuration(set.Worker.Interval)
	if err != nil || d < time.Second {
		return 15 * time.Second
	}
	return d
}
