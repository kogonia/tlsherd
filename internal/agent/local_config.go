package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/kogonia/tlsherd/internal/agentcfg"
)

const (
	defaultLocalConfigPath = "/etc/tlsherd-agent/agent.local.cfg"
	localConfigPrevSuffix  = ".prev"
)

// localConfigPath returns the active agent.local.cfg path.
func (a *Agent) localConfigPath() string {
	if p := a.opts.Bootstrap.LocalConfigPath; p != "" {
		return p
	}
	return defaultLocalConfigPath
}

func localConfigPrevPath(active string) string {
	return active + localConfigPrevSuffix
}

// loadLocalConfig reads agent.local.cfg, falling back to .prev, then defaults.
func (a *Agent) loadLocalConfig() error {
	active := a.localConfigPath()
	for i, path := range []string{active, localConfigPrevPath(active)} {
		b, err := os.ReadFile(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			a.log.Warn("cannot read local config", "operation", "load_local", "file", path, "error", err)
			continue
		}
		lc, err := agentcfg.ParseLocal(b)
		if err != nil {
			a.log.Warn("cannot parse local config", "operation", "load_local", "file", path, "error", err)
			continue
		}
		a.local = lc
		h, err := agentcfg.HashLocal(lc)
		if err != nil {
			return fmt.Errorf("hash local config: %w", err)
		}
		a.localHash = h
		if i > 0 {
			a.log.Warn("loaded local config from previous version", "operation", "load_local", "file", path)
		} else {
			a.log.Info("loaded local config", "operation", "load_local", "service", lc.Service, "hash", h)
		}
		return nil
	}
	a.local = agentcfg.DefaultLocal()
	h, err := agentcfg.HashLocal(a.local)
	if err != nil {
		return err
	}
	a.localHash = h
	a.log.Info("no local config file; using custom defaults", "operation", "load_local", "path", active)
	return nil
}

// writeLocalConfig rotates active → .prev and writes lc as the new active file.
func (a *Agent) writeLocalConfig(lc agentcfg.LocalConfig) error {
	if err := agentcfg.ValidateLocal(lc); err != nil {
		return fmt.Errorf("invalid local config: %w", err)
	}
	raw, err := agentcfg.CanonicalLocalJSON(lc)
	if err != nil {
		return err
	}
	// Pretty-print on disk for operator edits.
	var pretty []byte
	var tmp any
	if err := json.Unmarshal(raw, &tmp); err == nil {
		pretty, _ = json.MarshalIndent(tmp, "", "  ")
		pretty = append(pretty, '\n')
	}
	if pretty == nil {
		pretty = append(raw, '\n')
	}
	if a.dryRun() {
		a.local = lc
		a.localHash, _ = agentcfg.HashLocal(lc)
		a.log.Info("dry-run: would write local config", "operation", "write_local", "hash", a.localHash)
		return nil
	}
	active := a.localConfigPath()
	if err := os.MkdirAll(filepath.Dir(active), 0o755); err != nil {
		return fmt.Errorf("create local config dir: %w", err)
	}
	if old, err := os.ReadFile(active); err == nil {
		if err := writeFileAtomic(localConfigPrevPath(active), old, secretFileMode); err != nil {
			return fmt.Errorf("backup local config: %w", err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("read local config: %w", err)
	}
	if err := writeFileAtomic(active, pretty, secretFileMode); err != nil {
		return fmt.Errorf("write local config: %w", err)
	}
	a.local = lc
	a.localHash, err = agentcfg.HashLocal(lc)
	if err != nil {
		return err
	}
	a.log.Info("local config written", "operation", "write_local", "service", lc.Service, "hash", a.localHash)
	return nil
}

// acceptLocalConfigUpdate applies a server push when base_hash matches.
// Returns applied=false without error on hash conflict.
func (a *Agent) acceptLocalConfigUpdate(upd *LocalConfigUpdate) (applied bool, err error) {
	if upd == nil {
		return false, nil
	}
	if upd.BaseHash != "" && upd.BaseHash != a.localHash {
		a.log.Warn("local config update conflict", "operation", "local_config_update",
			"base_hash", upd.BaseHash, "current_hash", a.localHash, "revision", upd.Revision)
		a.localConfigConflict = true
		return false, nil
	}
	if err := a.writeLocalConfig(upd.Config); err != nil {
		return false, err
	}
	a.localConfigConflict = false
	return true, nil
}

// runtimeCFG returns server schedule config with agent-priority local overlay.
func (a *Agent) runtimeCFG() agentcfg.Config {
	return agentcfg.ApplyLocalToConfig(a.cfg, a.local)
}

func (a *Agent) certRoot() string {
	if a.local.CertRoot != "" {
		return a.local.CertRoot
	}
	return a.opts.Bootstrap.CertRoot
}
