package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type ServerConfig struct {
	// AdminListen serves the web UI and operator/admin JSON API.
	AdminListen string
	// AgentListen serves the agent enroll/poll/cert API only.
	AgentListen  string
	DatabaseURL  string
	DataDir      string
	TLSCertFile  string
	TLSKeyFile   string
	InsecureHTTP bool
	// TrustProxy takes the client IP from X-Forwarded-For (set TLSHERD_TRUST_PROXY=1 only behind a reverse proxy).
	TrustProxy bool
	LogLevel   string
}

func LoadServer(getenv func(string) string) (ServerConfig, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	admin := getenv("TLSHERD_ADMIN_LISTEN")
	if admin == "" {
		// Backward-compatible alias.
		admin = envOr(getenv, "TLSHERD_LISTEN", ":8443")
	}
	cfg := ServerConfig{
		AdminListen:  admin,
		AgentListen:  envOr(getenv, "TLSHERD_AGENT_LISTEN", ":8444"),
		DatabaseURL:  getenv("TLSHERD_DATABASE_URL"),
		DataDir:      envOr(getenv, "TLSHERD_DATA_DIR", "/var/lib/tlsherd"),
		TLSCertFile:  getenv("TLSHERD_TLS_CERT"),
		TLSKeyFile:   getenv("TLSHERD_TLS_KEY"),
		InsecureHTTP: envBool(getenv, "TLSHERD_INSECURE_HTTP"),
		TrustProxy:   envBool(getenv, "TLSHERD_TRUST_PROXY"),
		LogLevel:     envOr(getenv, "TLSHERD_LOG_LEVEL", "info"),
	}
	var errs []string
	if cfg.DatabaseURL == "" {
		errs = append(errs, "TLSHERD_DATABASE_URL is required")
	}
	if cfg.AdminListen == "" {
		errs = append(errs, "TLSHERD_ADMIN_LISTEN is required")
	}
	if cfg.AgentListen == "" {
		errs = append(errs, "TLSHERD_AGENT_LISTEN is required")
	}
	if cfg.AdminListen == cfg.AgentListen {
		errs = append(errs, "TLSHERD_ADMIN_LISTEN and TLSHERD_AGENT_LISTEN must differ")
	}
	if !cfg.InsecureHTTP {
		if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
			errs = append(errs, "TLSHERD_TLS_CERT and TLSHERD_TLS_KEY required unless TLSHERD_INSECURE_HTTP=1 or --insecure-http")
		}
	}
	if len(errs) > 0 {
		return ServerConfig{}, fmt.Errorf("config: %s", strings.Join(errs, "; "))
	}
	return cfg, nil
}

// DefaultAgentDir is the single on-host directory for agent state and configs.
const DefaultAgentDir = "/var/lib/tlsherd-agent"

type AgentBootstrap struct {
	ServerURL       string
	CertRoot        string
	AgentDir        string // state.json, config.cfg, agent.local.cfg (and .prev siblings)
	StateDir        string // same as AgentDir; kept for callers that name the state tree
	LocalConfigPath string // AgentDir/agent.local.cfg
	CAFile          string
	Once            bool
	DryRun          bool
	LogLevel        string
}

func LoadAgentBootstrap(getenv func(string) string) (AgentBootstrap, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	agentDir := envOr(getenv, "TLSHERD_AGENT_DIR", DefaultAgentDir)
	cfg := AgentBootstrap{
		ServerURL:       getenv("TLSHERD_SERVER_URL"),
		CertRoot:        envOr(getenv, "TLSHERD_CERT_ROOT", "/etc/tls"),
		AgentDir:        agentDir,
		StateDir:        agentDir,
		LocalConfigPath: filepath.Join(agentDir, "agent.local.cfg"),
		CAFile:          getenv("TLSHERD_CA_FILE"),
		LogLevel:        envOr(getenv, "TLSHERD_LOG_LEVEL", "info"),
	}
	if cfg.ServerURL == "" {
		return AgentBootstrap{}, fmt.Errorf("TLSHERD_SERVER_URL is required")
	}
	return cfg, nil
}

func envOr(getenv func(string) string, key, def string) string {
	if v := getenv(key); v != "" {
		return v
	}
	return def
}

func envBool(getenv func(string) string, key string) bool {
	v := strings.ToLower(getenv(key))
	return v == "1" || v == "true" || v == "yes"
}

func EnvDuration(getenv func(string) string, key string, def time.Duration) time.Duration {
	v := getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

func EnvInt(getenv func(string) string, key string, def int) int {
	v := getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}
