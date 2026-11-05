package config

import (
	"path/filepath"
	"testing"
)

func TestLoadAgentBootstrapAgentDir(t *testing.T) {
	t.Parallel()
	env := map[string]string{
		"TLSHERD_SERVER_URL": "https://example.test:8444",
	}
	cfg, err := LoadAgentBootstrap(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AgentDir != DefaultAgentDir || cfg.StateDir != DefaultAgentDir {
		t.Fatalf("agent dir = %q state = %q", cfg.AgentDir, cfg.StateDir)
	}
	wantLocal := filepath.Join(DefaultAgentDir, "agent.local.cfg")
	if cfg.LocalConfigPath != wantLocal {
		t.Fatalf("local config = %q, want %q", cfg.LocalConfigPath, wantLocal)
	}

	env["TLSHERD_AGENT_DIR"] = "/opt/tlsherd-agent"
	cfg, err = LoadAgentBootstrap(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AgentDir != "/opt/tlsherd-agent" || cfg.StateDir != "/opt/tlsherd-agent" {
		t.Fatalf("custom agent dir = %+v", cfg)
	}
	if cfg.LocalConfigPath != "/opt/tlsherd-agent/agent.local.cfg" {
		t.Fatalf("local config = %q", cfg.LocalConfigPath)
	}
}
