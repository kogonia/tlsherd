package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/kogonia/tlsherd/internal/domain"
)

// Bounds for the global monitor settings.
const (
	minMonitorInterval = 30 * time.Second
	maxMonitorInterval = 24 * time.Hour
	minProbeTimeout    = time.Second
	maxProbeTimeout    = 2 * time.Minute
	minExpiringSoon    = time.Hour
	maxExpiringSoon    = 365 * 24 * time.Hour
)

// MonitorSettings is the global monitor configuration (system_settings key
// "monitor"). Values are Go durations. In input an empty value selects the
// built-in default; views always carry the effective values.
type MonitorSettings struct {
	Interval     string `json:"interval"`
	Timeout      string `json:"timeout"`
	ExpiringSoon string `json:"expiring_soon"`
}

// GetMonitorSettings returns the effective global monitor settings. Admin only.
func (s *Services) GetMonitorSettings(ctx context.Context, actor *domain.User) (*MonitorSettings, error) {
	if err := requireAdmin(actor); err != nil {
		return nil, err
	}
	return monitorSettingsView(s.monitorSettings(ctx)), nil
}

func monitorSettingsView(m monitorSettings) *MonitorSettings {
	return &MonitorSettings{
		Interval: m.Interval.String(), Timeout: m.Timeout.String(), ExpiringSoon: m.ExpiringSoon.String(),
	}
}

// UpdateMonitorSettings validates and stores the global monitor settings and
// returns the effective result. Admin only.
func (s *Services) UpdateMonitorSettings(ctx context.Context, actor *domain.User, in MonitorSettings) (*MonitorSettings, error) {
	if err := requireAdmin(actor); err != nil {
		return nil, err
	}
	eff := monitorSettings{DefaultMonitorInterval, DefaultProbeTimeout, DefaultExpiringSoon}
	stored := MonitorSettings{}
	for _, f := range []struct {
		name     string
		in       string
		min, max time.Duration
		dst      *time.Duration
		out      *string
	}{
		{"interval", in.Interval, minMonitorInterval, maxMonitorInterval, &eff.Interval, &stored.Interval},
		{"timeout", in.Timeout, minProbeTimeout, maxProbeTimeout, &eff.Timeout, &stored.Timeout},
		{"expiring_soon", in.ExpiringSoon, minExpiringSoon, maxExpiringSoon, &eff.ExpiringSoon, &stored.ExpiringSoon},
	} {
		v := normalizeText(f.in)
		if v == "" {
			continue
		}
		d, err := time.ParseDuration(v)
		if err != nil || d < f.min || d > f.max {
			return nil, invalidf("%s must be a duration between %s and %s", f.name, f.min, f.max)
		}
		*f.dst, *f.out = d, d.String()
	}
	if eff.Timeout > eff.Interval {
		return nil, invalidf("timeout must not exceed interval")
	}
	raw, err := json.Marshal(stored)
	if err != nil {
		return nil, fmt.Errorf("update monitor settings: %w", err)
	}
	if err := s.Store.SetSetting(ctx, settingMonitor, raw); err != nil {
		return nil, fmt.Errorf("update monitor settings: %w", err)
	}
	view := monitorSettingsView(eff)
	if err := s.audit(ctx, s.Store, actor, "monitor.settings_update", "settings", settingMonitor,
		map[string]any{"interval": view.Interval, "timeout": view.Timeout, "expiring_soon": view.ExpiringSoon}); err != nil {
		return nil, fmt.Errorf("update monitor settings: %w", err)
	}
	return view, nil
}
