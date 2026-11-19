package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/kogonia/tlsherd/internal/domain"
)

const settingGeneral = "general"

// Bounds for general settings.
const (
	minSessionIdle = 15 * time.Minute
	maxSessionIdle = 7 * 24 * time.Hour
	minSessionMax  = time.Hour
	maxSessionMax  = 30 * 24 * time.Hour
	minPasswordLen = 8
	maxPasswordLen = 128
)

// GeneralSettings is the global installation config (system_settings key "general").
type GeneralSettings struct {
	AllowIPChange       bool   `json:"allow_ip_change"`
	SessionIdleTimeout  string `json:"session_idle_timeout"`
	SessionMaxDuration  string `json:"session_max_duration"`
	DefaultTheme        string `json:"default_theme"`
	MinAgentVersion     string `json:"min_agent_version"`
	PasswordMinLength   int    `json:"password_min_length"`
}

type generalSettings struct {
	AllowIPChange      bool
	SessionIdle        time.Duration
	SessionMax         time.Duration
	DefaultTheme       string
	MinAgentVersion    string
	PasswordMinLength  int
}

func defaultGeneralSettings() generalSettings {
	return generalSettings{
		AllowIPChange:     false,
		SessionIdle:       SessionIdleTimeout,
		SessionMax:        SessionMaxLifetime,
		DefaultTheme:      domain.ThemeLight,
		MinAgentVersion:   "",
		PasswordMinLength: minPasswordLen,
	}
}

func generalSettingsView(g generalSettings) *GeneralSettings {
	return &GeneralSettings{
		AllowIPChange:      g.AllowIPChange,
		SessionIdleTimeout: g.SessionIdle.String(),
		SessionMaxDuration: g.SessionMax.String(),
		DefaultTheme:       g.DefaultTheme,
		MinAgentVersion:    g.MinAgentVersion,
		PasswordMinLength:  g.PasswordMinLength,
	}
}

// GetGeneralSettings returns the effective general settings. Admin only.
func (s *Services) GetGeneralSettings(ctx context.Context, actor *domain.User) (*GeneralSettings, error) {
	if err := requireAdmin(actor); err != nil {
		return nil, err
	}
	return generalSettingsView(s.generalSettings(ctx)), nil
}

// UpdateGeneralSettings validates and stores general settings. Admin only.
func (s *Services) UpdateGeneralSettings(ctx context.Context, actor *domain.User, in GeneralSettings) (*GeneralSettings, error) {
	if err := requireAdmin(actor); err != nil {
		return nil, err
	}
	eff := defaultGeneralSettings()
	stored := GeneralSettings{}

	eff.AllowIPChange = in.AllowIPChange
	stored.AllowIPChange = in.AllowIPChange

	idle := normalizeText(in.SessionIdleTimeout)
	if idle != "" {
		d, err := time.ParseDuration(idle)
		if err != nil || d < minSessionIdle || d > maxSessionIdle {
			return nil, invalidf("session_idle_timeout must be a duration between %s and %s", minSessionIdle, maxSessionIdle)
		}
		eff.SessionIdle, stored.SessionIdleTimeout = d, d.String()
	}
	maxDur := normalizeText(in.SessionMaxDuration)
	if maxDur != "" {
		d, err := time.ParseDuration(maxDur)
		if err != nil || d < minSessionMax || d > maxSessionMax {
			return nil, invalidf("session_max_duration must be a duration between %s and %s", minSessionMax, maxSessionMax)
		}
		eff.SessionMax, stored.SessionMaxDuration = d, d.String()
	}
	if eff.SessionMax < eff.SessionIdle {
		return nil, invalidf("session_max_duration must be greater than or equal to session_idle_timeout")
	}

	theme := normalizeText(in.DefaultTheme)
	if theme == "" {
		theme = domain.ThemeLight
	}
	if !domain.ValidTheme(theme) {
		return nil, invalidf("default_theme must be %q or %q", domain.ThemeLight, domain.ThemeDark)
	}
	eff.DefaultTheme, stored.DefaultTheme = theme, theme

	minVer := normalizeAgentVersion(in.MinAgentVersion)
	eff.MinAgentVersion, stored.MinAgentVersion = minVer, minVer

	pwMin := in.PasswordMinLength
	if pwMin == 0 {
		pwMin = minPasswordLen
	}
	if pwMin < minPasswordLen || pwMin > maxPasswordLen {
		return nil, invalidf("password_min_length must be between %d and %d", minPasswordLen, maxPasswordLen)
	}
	eff.PasswordMinLength, stored.PasswordMinLength = pwMin, pwMin

	raw, err := json.Marshal(stored)
	if err != nil {
		return nil, fmt.Errorf("update general settings: %w", err)
	}
	if err := s.Store.SetSetting(ctx, settingGeneral, raw); err != nil {
		return nil, fmt.Errorf("update general settings: %w", err)
	}
	_ = s.audit(ctx, s.Store, actor, "settings.general.update", "settings", settingGeneral, map[string]any{
		"allow_ip_change": stored.AllowIPChange,
		"default_theme":   stored.DefaultTheme,
		"min_agent_version": stored.MinAgentVersion,
		"password_min_length": stored.PasswordMinLength,
	})
	return generalSettingsView(eff), nil
}

func (s *Services) generalSettings(ctx context.Context) generalSettings {
	eff := defaultGeneralSettings()
	b, err := s.Store.GetSetting(ctx, settingGeneral)
	if err != nil {
		return eff
	}
	var stored GeneralSettings
	if err := json.Unmarshal(b, &stored); err != nil {
		return eff
	}
	eff.AllowIPChange = stored.AllowIPChange
	if d, err := time.ParseDuration(normalizeText(stored.SessionIdleTimeout)); err == nil && d >= minSessionIdle && d <= maxSessionIdle {
		eff.SessionIdle = d
	}
	if d, err := time.ParseDuration(normalizeText(stored.SessionMaxDuration)); err == nil && d >= minSessionMax && d <= maxSessionMax {
		eff.SessionMax = d
	}
	if eff.SessionMax < eff.SessionIdle {
		eff.SessionMax = eff.SessionIdle
	}
	if domain.ValidTheme(normalizeText(stored.DefaultTheme)) {
		eff.DefaultTheme = normalizeText(stored.DefaultTheme)
	}
	eff.MinAgentVersion = normalizeAgentVersion(stored.MinAgentVersion)
	if stored.PasswordMinLength >= minPasswordLen && stored.PasswordMinLength <= maxPasswordLen {
		eff.PasswordMinLength = stored.PasswordMinLength
	}
	return eff
}

func normalizeAgentVersion(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > 64 {
		v = v[:64]
	}
	return v
}

// agentVersionBelow reports whether reported is missing/unknown or strictly
// below min. Empty min disables the check. Prefers dotted numeric compare
// when both sides look like versions (optional leading "v"); otherwise
// lexicographic.
func agentVersionBelow(reported, min string) bool {
	min = normalizeAgentVersion(min)
	if min == "" {
		return false
	}
	reported = normalizeAgentVersion(reported)
	if reported == "" || reported == "unknown" {
		return true
	}
	if cmp, ok := compareDottedVersion(reported, min); ok {
		return cmp < 0
	}
	return reported < min
}

func compareDottedVersion(a, b string) (int, bool) {
	pa, oka := splitVersionParts(a)
	pb, okb := splitVersionParts(b)
	if !oka || !okb {
		return 0, false
	}
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x < y {
			return -1, true
		}
		if x > y {
			return 1, true
		}
	}
	return 0, true
}

func splitVersionParts(v string) ([]int, bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	v = strings.TrimPrefix(v, "V")
	if v == "" {
		return nil, false
	}
	// Strip pre-release / build metadata for ordering.
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			return nil, false
		}
		n := 0
		for _, c := range p {
			if c < '0' || c > '9' {
				return nil, false
			}
			n = n*10 + int(c-'0')
		}
		out = append(out, n)
	}
	return out, true
}

func (s *Services) maybeEmitAgentVersionOutdated(ctx context.Context, srv *domain.Server) {
	if srv == nil {
		return
	}
	g := s.generalSettings(ctx)
	key := DedupKey(EvAgentVersionOutdated, srv.ID.String())
	if !agentVersionBelow(srv.AgentVersion, g.MinAgentVersion) {
		_ = s.resolve(ctx, s.Store, key, "agent")
		return
	}
	_ = s.emit(ctx, s.Store, &domain.Event{
		Type: EvAgentVersionOutdated, Severity: SeverityWarning, ServerID: &srv.ID, DedupKey: &key,
		Message: fmt.Sprintf("agent on %s reports version %q below minimum %q",
			srv.Display(), srv.AgentVersion, g.MinAgentVersion),
		Details: jsonDetails(map[string]any{
			"agent_version": srv.AgentVersion, "min_agent_version": g.MinAgentVersion,
		}),
	})
}

// EffectivePasswordMinLength returns the configured minimum password length.
func (s *Services) EffectivePasswordMinLength(ctx context.Context) int {
	return s.generalSettings(ctx).PasswordMinLength
}

// EffectiveDefaultTheme returns the installation default UI theme.
func (s *Services) EffectiveDefaultTheme(ctx context.Context) string {
	return s.generalSettings(ctx).DefaultTheme
}

// AllowIPChange reports whether IP identity changes auto-accept.
func (s *Services) AllowIPChange(ctx context.Context) bool {
	return s.generalSettings(ctx).AllowIPChange
}

// SessionLimits returns effective idle and absolute session durations.
func (s *Services) SessionLimits(ctx context.Context) (idle, max time.Duration) {
	g := s.generalSettings(ctx)
	return g.SessionIdle, g.SessionMax
}

// AgentVersionOutdated reports whether the server's reported version is below the minimum.
func (s *Services) AgentVersionOutdated(ctx context.Context, agentVersion string) bool {
	return agentVersionBelow(agentVersion, s.generalSettings(ctx).MinAgentVersion)
}
