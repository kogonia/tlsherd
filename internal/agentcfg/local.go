package agentcfg

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Service catalog identifiers.
const (
	ServiceNginx   = "nginx"
	ServiceHAProxy = "haproxy"
	ServiceApache2 = "apache2"
	ServiceHTTPD   = "httpd"
	ServiceCustom  = "custom"
)

// LocalConfig is the agent-priority host document (agent.local.cfg).
// It owns service identity, pre-start verify, restart, and cert/install layout.
type LocalConfig struct {
	Service       string  `json:"service"`
	Verify        Verify  `json:"verify"`
	Restart       Restart `json:"restart"`
	Install       Install `json:"install"`
	CertRoot      string  `json:"cert_root,omitempty"` // working cert tree root (overrides TLSHERD_CERT_ROOT)
	CertPath      string  `json:"cert_path,omitempty"` // extra leaf publish path ({domain} ok)
	KeyPath       string  `json:"key_path,omitempty"`
	ChainPath     string  `json:"chain_path,omitempty"`
	FullchainPath string  `json:"fullchain_path,omitempty"` // extra leaf+chain publish (nginx ssl_certificate)
	// StrictCertCheck overrides server Config when non-nil.
	StrictCertCheck *bool `json:"strict_cert_check,omitempty"`
}

// ServiceInfo describes a built-in catalog entry.
type ServiceInfo struct {
	ID      string
	Label   string
	Verify  Verify
	Restart Restart
}

// Services returns the built-in web-service catalog.
func Services() []ServiceInfo {
	timeout := Duration(30 * time.Second)
	return []ServiceInfo{
		{
			ID: ServiceNginx, Label: "nginx",
			Verify:  Verify{Command: []string{"nginx", "-t"}, Timeout: timeout},
			Restart: Restart{Type: "systemd", Name: "nginx", ReloadOnly: true},
		},
		{
			ID: ServiceHAProxy, Label: "HAProxy",
			Verify:  Verify{Command: []string{"haproxy", "-f", "/etc/haproxy/haproxy.cfg", "-c"}, Timeout: timeout},
			Restart: Restart{Type: "systemd", Name: "haproxy", ReloadOnly: true},
		},
		{
			ID: ServiceApache2, Label: "Apache (apache2)",
			Verify:  Verify{Command: []string{"apache2ctl", "configtest"}, Timeout: timeout},
			Restart: Restart{Type: "systemd", Name: "apache2", ReloadOnly: true},
		},
		{
			ID: ServiceHTTPD, Label: "Apache (httpd)",
			Verify:  Verify{Command: []string{"httpd", "-t"}, Timeout: timeout},
			Restart: Restart{Type: "systemd", Name: "httpd", ReloadOnly: true},
		},
		{
			ID: ServiceCustom, Label: "Custom",
			Verify:  Verify{Timeout: timeout},
			Restart: Restart{Type: "systemd"},
		},
	}
}

// ServiceByID returns a catalog entry or false if unknown.
func ServiceByID(id string) (ServiceInfo, bool) {
	for _, s := range Services() {
		if s.ID == id {
			return s, true
		}
	}
	return ServiceInfo{}, false
}

// DefaultLocal returns an empty custom local config.
func DefaultLocal() LocalConfig {
	inst := Default().Install
	return LocalConfig{
		Service: ServiceCustom,
		Verify:  Verify{Timeout: Duration(30 * time.Second)},
		Restart: Restart{Type: "systemd"},
		Install: inst,
	}
}

// LocalFromService fills verify/restart (and keeps install from DefaultLocal) for a catalog id.
func LocalFromService(id string) (LocalConfig, error) {
	info, ok := ServiceByID(id)
	if !ok {
		return LocalConfig{}, fmt.Errorf("unknown service %q", id)
	}
	lc := DefaultLocal()
	lc.Service = info.ID
	lc.Verify = info.Verify
	lc.Restart = info.Restart
	return lc, nil
}

// ApplyServiceDefaults resets verify and restart from the catalog for lc.Service
// (or id if non-empty). Install and path fields are left unchanged unless empty.
func ApplyServiceDefaults(lc LocalConfig, id string) (LocalConfig, error) {
	if id == "" {
		id = lc.Service
	}
	if id == "" {
		id = ServiceCustom
	}
	info, ok := ServiceByID(id)
	if !ok {
		return LocalConfig{}, fmt.Errorf("unknown service %q", id)
	}
	lc.Service = info.ID
	lc.Verify = info.Verify
	lc.Restart = info.Restart
	if lc.Install.Mode == "" {
		lc.Install = Default().Install
	}
	return lc, nil
}

// ValidateLocal checks LocalConfig invariants (restart rules match Config).
func ValidateLocal(c LocalConfig) error {
	if c.Service == "" {
		return fmt.Errorf("service is required")
	}
	if _, ok := ServiceByID(c.Service); !ok {
		return fmt.Errorf("unknown service %q", c.Service)
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
	return nil
}

// CanonicalLocalJSON marshals LocalConfig for hashing/storage.
func CanonicalLocalJSON(c LocalConfig) ([]byte, error) {
	return json.Marshal(c)
}

// HashLocal returns the hex SHA-256 of the canonical local config JSON.
func HashLocal(c LocalConfig) (string, error) {
	b, err := CanonicalLocalJSON(c)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// ParseLocal unmarshals a local config document. Empty/missing yields DefaultLocal.
func ParseLocal(b []byte) (LocalConfig, error) {
	if len(b) == 0 || string(b) == "{}" || string(b) == "null" {
		return DefaultLocal(), nil
	}
	var lc LocalConfig
	if err := json.Unmarshal(b, &lc); err != nil {
		return LocalConfig{}, err
	}
	if lc.Service == "" {
		lc.Service = ServiceCustom
	}
	if lc.Verify.Timeout == 0 {
		lc.Verify.Timeout = Duration(30 * time.Second)
	}
	if lc.Install.Mode == "" {
		base := Default().Install
		if lc.Install.CertName == "" {
			lc.Install = base
		} else {
			lc.Install.Mode = base.Mode
		}
	}
	if lc.Restart.Type == "" && lc.Restart.Name == "" && len(lc.Restart.Command) == 0 {
		lc.Restart.Type = "systemd"
	}
	if err := ValidateLocal(lc); err != nil {
		return LocalConfig{}, err
	}
	return lc, nil
}

// MergeLocal overlays non-empty fields from patch onto base.
func MergeLocal(base, patch LocalConfig) LocalConfig {
	out := base
	if patch.Service != "" {
		out.Service = patch.Service
	}
	if len(patch.Verify.Command) > 0 || patch.Verify.Timeout != 0 {
		out.Verify = patch.Verify
		if out.Verify.Timeout == 0 {
			out.Verify.Timeout = base.Verify.Timeout
		}
	}
	if patch.Restart.Type != "" || patch.Restart.Name != "" || len(patch.Restart.Command) > 0 || patch.Restart.ReloadOnly {
		// ReloadOnly alone can be meaningful when type/name already set; take whole restart if any signal.
		if patch.Restart.Type != "" || patch.Restart.Name != "" || len(patch.Restart.Command) > 0 {
			out.Restart = patch.Restart
		} else if patch.Restart.ReloadOnly {
			out.Restart.ReloadOnly = true
		}
	}
	if patch.Install.Mode != "" {
		out.Install = patch.Install
	}
	if patch.CertRoot != "" {
		out.CertRoot = patch.CertRoot
	}
	if patch.CertPath != "" {
		out.CertPath = patch.CertPath
	}
	if patch.KeyPath != "" {
		out.KeyPath = patch.KeyPath
	}
	if patch.ChainPath != "" {
		out.ChainPath = patch.ChainPath
	}
	if patch.FullchainPath != "" {
		out.FullchainPath = patch.FullchainPath
	}
	if patch.StrictCertCheck != nil {
		v := *patch.StrictCertCheck
		out.StrictCertCheck = &v
	}
	return out
}

// IsConfigured reports whether lc carries operator intent beyond empty custom defaults.
// Unconfigured local config must not wipe server-authoritative verify/restart/install.
func (lc LocalConfig) IsConfigured() bool {
	if lc.Service != "" && lc.Service != ServiceCustom {
		return true
	}
	if len(lc.Verify.Command) > 0 {
		return true
	}
	if lc.Restart.Name != "" || len(lc.Restart.Command) > 0 || lc.Restart.Type == "docker" || lc.Restart.Type == "exec" {
		return true
	}
	if lc.CertRoot != "" || lc.CertPath != "" || lc.KeyPath != "" || lc.ChainPath != "" || lc.FullchainPath != "" {
		return true
	}
	if lc.StrictCertCheck != nil {
		return true
	}
	return false
}

// ApplyLocalToConfig overlays agent-priority local fields onto a server Config.
func ApplyLocalToConfig(cfg Config, lc LocalConfig) Config {
	if !lc.IsConfigured() {
		return cfg
	}
	out := cfg
	if lc.Install.Mode != "" {
		out.Install = lc.Install
	}
	out.Verify = lc.Verify
	if out.Verify.Timeout == 0 {
		out.Verify.Timeout = cfg.Verify.Timeout
	}
	if lc.Restart.Type != "" || lc.Restart.Name != "" || len(lc.Restart.Command) > 0 {
		out.Restart = lc.Restart
	}
	if lc.StrictCertCheck != nil {
		out.StrictCertCheck = *lc.StrictCertCheck
	}
	return out
}
