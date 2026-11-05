package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

const (
	stateFileName   = "state.json"
	configFileName  = "config.cfg"
	configPrevName  = "config.cfg.prev"
	secretFileMode  = 0o600
	stateDirModeDef = 0o700
)

// State is the agent's persistent local state (state_dir/state.json).
type State struct {
	APIKey        string                 `json:"api_key,omitempty"`
	ConfigVersion int64                  `json:"config_version"`
	Domains       map[string]DomainState `json:"domains,omitempty"`
	LastError     string                 `json:"last_error,omitempty"`
	LastSuccess   time.Time              `json:"last_success,omitempty"`
}

// DomainState tracks what is applied and what is staged for one domain.
type DomainState struct {
	Fingerprint       string `json:"fingerprint,omitempty"`
	StagedFingerprint string `json:"staged_fingerprint,omitempty"`
}

// loadState reads state.json. A missing file yields an empty state. A corrupt
// file is moved aside and reported via corrupt=true with an empty state, so
// the caller can reconcile with files on disk.
func loadState(dir string) (st State, corrupt bool, err error) {
	path := filepath.Join(dir, stateFileName)
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return State{Domains: map[string]DomainState{}}, false, nil
	}
	if err != nil {
		return State{}, false, fmt.Errorf("read state: %w", err)
	}
	if err := json.Unmarshal(b, &st); err != nil {
		_ = os.Rename(path, path+".corrupt")
		return State{Domains: map[string]DomainState{}}, true, nil
	}
	if st.Domains == nil {
		st.Domains = map[string]DomainState{}
	}
	return st, false, nil
}

func saveState(dir string, st State) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	if err := os.MkdirAll(dir, stateDirModeDef); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(dir, stateFileName), b, secretFileMode); err != nil {
		return fmt.Errorf("write state: %w", err)
	}
	return nil
}

// writeFileAtomic writes data to a temp file in the same directory, fsyncs,
// sets mode and renames over path.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	cleanup := func(err error) error {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Chmod(mode); err != nil {
		return cleanup(err)
	}
	if _, err := f.Write(data); err != nil {
		return cleanup(err)
	}
	if err := f.Sync(); err != nil {
		return cleanup(err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
