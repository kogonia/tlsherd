package agentcfg

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Service catalog identifiers (web service type).
const (
	ServiceNginx   = "nginx"
	ServiceHAProxy = "haproxy"
	ServiceApache2 = "apache2"
	ServiceHTTPD   = "httpd"
	ServiceCustom  = "custom"
)

// Deploy / restart.type identifiers.
const (
	DeploySystemd = "systemd"
	DeployDocker  = "docker"
	DeployExec    = "exec"
)

// LocalConfig is the agent-priority host document (agent.local.cfg).
// It owns service identity, pre-start verify, restart, and cert/install layout.
//
// service = web software (nginx/…); restart.type = start method
// (systemd/docker/exec). Catalog presets compose verify/restart from that pair.
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

// ServiceInfo is a web-service recipe. Deploy type (restart.type) selects how
// VerifyCommand / ReloadCommand are composed into LocalConfig fields.
type ServiceInfo struct {
	ID              string
	Label           string
	DefaultName     string   // default unit/container name
	VerifyCommand   []string // in-process / in-container check (e.g. nginx -t)
	ReloadCommand   []string // soft-reload argv (e.g. nginx -s reload)
	Verify          Verify   // systemd preset (compat / API)
	Restart         Restart  // systemd preset (compat / API)
}

// Services returns the built-in web-service catalog.
func Services() []ServiceInfo {
	timeout := Duration(30 * time.Second)
	recipes := []ServiceInfo{
		{
			ID: ServiceNginx, Label: "nginx", DefaultName: "nginx",
			VerifyCommand: []string{"nginx", "-t"},
			ReloadCommand: []string{"nginx", "-s", "reload"},
		},
		{
			ID: ServiceHAProxy, Label: "HAProxy", DefaultName: "haproxy",
			VerifyCommand: []string{"haproxy", "-f", "/etc/haproxy/haproxy.cfg", "-c"},
			ReloadCommand: []string{"kill", "-USR2", "1"},
		},
		{
			ID: ServiceApache2, Label: "Apache (apache2)", DefaultName: "apache2",
			VerifyCommand: []string{"apache2ctl", "configtest"},
			ReloadCommand: []string{"apache2ctl", "graceful"},
		},
		{
			ID: ServiceHTTPD, Label: "Apache (httpd)", DefaultName: "httpd",
			VerifyCommand: []string{"httpd", "-t"},
			ReloadCommand: []string{"httpd", "-k", "graceful"},
		},
		{
			ID: ServiceCustom, Label: "Custom", DefaultName: "",
		},
	}
	for i := range recipes {
		v, r := recipes[i].Preset(DeploySystemd, recipes[i].DefaultName)
		if v.Timeout == 0 {
			v.Timeout = timeout
		}
		recipes[i].Verify = v
		recipes[i].Restart = r
	}
	return recipes
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

// Preset composes verify/restart for this web recipe and a deploy type.
// name is the systemd unit or docker container (falls back to DefaultName).
func (s ServiceInfo) Preset(deploy, name string) (Verify, Restart) {
	timeout := Duration(30 * time.Second)
	if name == "" {
		name = s.DefaultName
	}
	verifyBase := append([]string(nil), s.VerifyCommand...)
	reload := append([]string(nil), s.ReloadCommand...)
	v := Verify{Command: verifyBase, Timeout: timeout}

	switch deploy {
	case DeployDocker:
		if name != "" && len(verifyBase) > 0 {
			v.Command = append([]string{"docker", "exec", name}, verifyBase...)
		}
		return v, Restart{
			Type:       DeployDocker,
			Name:       name,
			ReloadOnly: len(reload) > 0,
			Command:    reload,
		}
	case DeployExec:
		cmd := reload
		if len(cmd) == 0 {
			cmd = verifyBase
		}
		return v, Restart{Type: DeployExec, Command: cmd}
	default: // systemd
		return v, Restart{Type: DeploySystemd, Name: name, ReloadOnly: true}
	}
}

// WrapVerifyArgv prefixes docker exec <name> when restart is docker and the
// verify argv is not already a docker invocation (legacy configs).
func WrapVerifyArgv(argv []string, r Restart) []string {
	if r.Type != DeployDocker || r.Name == "" || len(argv) == 0 {
		return argv
	}
	if argv[0] == "docker" {
		return argv
	}
	return append([]string{"docker", "exec", r.Name}, argv...)
}

// DefaultLocal returns an empty custom local config.
func DefaultLocal() LocalConfig {
	inst := Default().Install
	return LocalConfig{
		Service: ServiceCustom,
		Verify:  Verify{Timeout: Duration(30 * time.Second)},
		Restart: Restart{Type: DeploySystemd},
		Install: inst,
	}
}

// LocalFromService fills verify/restart for a web catalog id (systemd deploy).
func LocalFromService(id string) (LocalConfig, error) {
	return LocalFromWebDeploy(id, DeploySystemd, "")
}

// LocalFromWebDeploy fills verify/restart from the web×deploy catalog matrix.
func LocalFromWebDeploy(webID, deploy, name string) (LocalConfig, error) {
	info, ok := ServiceByID(webID)
	if !ok {
		return LocalConfig{}, fmt.Errorf("unknown service %q", webID)
	}
	if deploy == "" {
		deploy = DeploySystemd
	}
	lc := DefaultLocal()
	lc.Service = info.ID
	lc.Verify, lc.Restart = info.Preset(deploy, name)
	return lc, nil
}

// ApplyServiceDefaults resets verify and restart from the catalog for lc.Service
// (or id if non-empty), keeping the current deploy type and unit/container name.
func ApplyServiceDefaults(lc LocalConfig, id string) (LocalConfig, error) {
	deploy := lc.Restart.Type
	if deploy == "" {
		deploy = DeploySystemd
	}
	return ApplyWebDeployDefaults(lc, id, deploy, lc.Restart.Name)
}

// ApplyWebDeployDefaults resets verify/restart for the web×deploy pair.
func ApplyWebDeployDefaults(lc LocalConfig, webID, deploy, name string) (LocalConfig, error) {
	if webID == "" {
		webID = lc.Service
	}
	if webID == "" {
		webID = ServiceCustom
	}
	info, ok := ServiceByID(webID)
	if !ok {
		return LocalConfig{}, fmt.Errorf("unknown service %q", webID)
	}
	if deploy == "" {
		deploy = DeploySystemd
	}
	lc.Service = info.ID
	lc.Verify, lc.Restart = info.Preset(deploy, name)
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
