package agentcfg

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// Config is the server-authoritative agent configuration document.
type Config struct {
	EnrollInterval     Duration          `json:"enroll_interval"`
	PollInterval       Duration          `json:"poll_interval"`
	Jitter             float64           `json:"jitter"`
	MaintenanceWindow  MaintenanceWindow `json:"maintenance_window"`
	UrgentThreshold    Duration          `json:"urgent_threshold"`
	StageOutsideWindow bool              `json:"stage_outside_window"`
	// StrictCertCheck refuses to install/activate expired, not-yet-valid, or
	// critically broken certificates (key mismatch already hard-fails parse).
	StrictCertCheck bool      `json:"strict_cert_check"`
	Install         Install   `json:"install"`
	Verify          Verify    `json:"verify"`
	Restart         Restart   `json:"restart"`
	PostCheck       PostCheck `json:"post_check"`
	Backups         Backups   `json:"backups"`
}

type MaintenanceWindow struct {
	TZ   string `json:"tz"`
	Days []int  `json:"days"` // 1=Mon .. 7=Sun
	From string `json:"from"` // HH:MM
	To   string `json:"to"`
}

type Install struct {
	Mode          string `json:"mode"` // symlink|copy
	Subdir        string `json:"subdir"`
	CertName      string `json:"cert_name"`
	KeyName       string `json:"key_name"`
	ChainName     string `json:"chain_name"`
	FullchainName string `json:"fullchain_name"` // leaf+intermediates; for nginx ssl_certificate
	Owner         string `json:"owner"`
	DirMode       string `json:"dir_mode"`
	KeyMode       string `json:"key_mode"`
	CertMode      string `json:"cert_mode"`
}

type Verify struct {
	Command []string `json:"command"`
	Timeout Duration `json:"timeout"`
}

type Restart struct {
	Type       string   `json:"type"` // systemd|docker|exec
	Name       string   `json:"name"`
	ReloadOnly bool     `json:"reload_only"`
	Command    []string `json:"command"`
}

type PostCheck struct {
	Enabled bool   `json:"enabled"`
	Addr    string `json:"addr"`
	SNI     string `json:"sni"`
}

type Backups struct {
	Keep int `json:"keep"`
}

// Duration wraps time.Duration for JSON as strings like "5m".
type Duration time.Duration

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if s == "" {
		*d = 0
		return nil
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

func (d Duration) Std() time.Duration { return time.Duration(d) }

func Default() Config {
	return Config{
		EnrollInterval: Duration(time.Minute),
		PollInterval:   Duration(12 * time.Hour),
		Jitter:         0.1,
		MaintenanceWindow: MaintenanceWindow{
			TZ:   "UTC",
			Days: []int{1, 2, 3, 4, 5, 6, 7},
			From: "02:00",
			To:   "04:00",
		},
		UrgentThreshold:    Duration(72 * time.Hour),
		StageOutsideWindow: true,
		StrictCertCheck:    true,
		Install: Install{
			Mode:          "symlink",
			CertName:      "cert.pem",
			KeyName:       "key.pem",
			ChainName:     "chain.pem",
			FullchainName: "fullchain.pem",
			DirMode:       "0750",
			KeyMode:       "0600",
			CertMode:      "0644",
		},
		Verify: Verify{
			Timeout: Duration(30 * time.Second),
		},
		Restart: Restart{
			Type: "systemd",
		},
		PostCheck: PostCheck{},
		Backups:   Backups{Keep: 5},
	}
}

// Merge overlays non-zero/non-empty fields from override onto base.
func Merge(base, override Config) Config {
	out := base
	if override.EnrollInterval != 0 {
		out.EnrollInterval = override.EnrollInterval
	}
	if override.PollInterval != 0 {
		out.PollInterval = override.PollInterval
	}
	if override.Jitter != 0 {
		out.Jitter = override.Jitter
	}
	if override.UrgentThreshold != 0 {
		out.UrgentThreshold = override.UrgentThreshold
	}
	// bool: only override if override document explicitly sets via pointer-less merge —
	// for MVP, StageOutsideWindow always taken from override when any install/window present.
	out.StageOutsideWindow = override.StageOutsideWindow || base.StageOutsideWindow
	if len(override.MaintenanceWindow.Days) > 0 || override.MaintenanceWindow.From != "" {
		out.MaintenanceWindow = override.MaintenanceWindow
		if out.MaintenanceWindow.TZ == "" {
			out.MaintenanceWindow.TZ = base.MaintenanceWindow.TZ
		}
	}
	if override.Install.Mode != "" {
		out.Install = override.Install
	}
	if len(override.Verify.Command) > 0 || override.Verify.Timeout != 0 {
		out.Verify = override.Verify
		if out.Verify.Timeout == 0 {
			out.Verify.Timeout = base.Verify.Timeout
		}
	}
	if override.Restart.Type != "" || override.Restart.Name != "" || len(override.Restart.Command) > 0 {
		out.Restart = override.Restart
	}
	if override.PostCheck.Addr != "" || override.PostCheck.Enabled {
		out.PostCheck = override.PostCheck
	}
	if override.Backups.Keep > 0 {
		out.Backups = override.Backups
	}
	return out
}

func Validate(c Config) error {
	if c.EnrollInterval.Std() <= 0 {
		return fmt.Errorf("enroll_interval must be positive")
	}
	if c.PollInterval.Std() <= 0 {
		return fmt.Errorf("poll_interval must be positive")
	}
	if c.Jitter < 0 || c.Jitter > 1 {
		return fmt.Errorf("jitter must be between 0 and 1")
	}
	switch c.Install.Mode {
	case "", "symlink", "copy":
	default:
		return fmt.Errorf("install.mode must be symlink or copy")
	}
	switch c.Restart.Type {
	case "", "systemd", "docker", "exec":
	default:
		return fmt.Errorf("restart.type must be systemd, docker, or exec")
	}
	if c.Restart.Type == "docker" && c.Restart.Name == "" {
		return fmt.Errorf("restart.name (container) required for docker")
	}
	if c.Restart.Type == "exec" && len(c.Restart.Command) == 0 {
		return fmt.Errorf("restart.command required for exec")
	}
	for _, d := range c.MaintenanceWindow.Days {
		if d < 1 || d > 7 {
			return fmt.Errorf("maintenance_window.days must be 1-7")
		}
	}
	if _, err := time.LoadLocation(c.MaintenanceWindow.TZ); err != nil && c.MaintenanceWindow.TZ != "" {
		return fmt.Errorf("maintenance_window.tz: %w", err)
	}
	return nil
}

func CanonicalJSON(c Config) ([]byte, error) {
	return json.Marshal(c)
}

func Hash(c Config) (string, error) {
	b, err := CanonicalJSON(c)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func Parse(b []byte) (Config, error) {
	if len(b) == 0 || string(b) == "{}" || string(b) == "null" {
		return Default(), nil
	}
	base := Default()
	var overlay Config
	if err := json.Unmarshal(b, &overlay); err != nil {
		return Config{}, err
	}
	merged := Merge(base, overlay)
	// Preserve explicit false for bools that default true (Merge cannot tell unset from false).
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err == nil {
		for _, key := range []string{"stage_outside_window", "strict_cert_check"} {
			if v, ok := raw[key]; ok {
				var s bool
				if json.Unmarshal(v, &s) == nil {
					switch key {
					case "stage_outside_window":
						merged.StageOutsideWindow = s
					case "strict_cert_check":
						merged.StrictCertCheck = s
					}
				}
			}
		}
	}
	if err := Validate(merged); err != nil {
		return Config{}, err
	}
	return merged, nil
}

func RenderPath(tmpl, domain string) string {
	return strings.ReplaceAll(tmpl, "{domain}", domain)
}

func JoinUnderRoot(root, rel string) (string, error) {
	if rel == "" {
		return "", fmt.Errorf("empty path")
	}
	clean := filepath.Clean(rel)
	if filepath.IsAbs(clean) {
		relClean, err := filepath.Rel(root, clean)
		if err != nil || strings.HasPrefix(relClean, "..") {
			return "", fmt.Errorf("path escapes allowed root")
		}
		return clean, nil
	}
	full := filepath.Join(root, clean)
	relClean, err := filepath.Rel(root, full)
	if err != nil || strings.HasPrefix(relClean, "..") {
		return "", fmt.Errorf("path escapes allowed root")
	}
	return full, nil
}
