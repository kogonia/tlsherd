// Package agent implements the tlsherd agent engine: enrollment, polling,
// server-authoritative config adoption and certificate apply (backup, install,
// verify, restart, report). It does not depend on the server or the store.
package agent

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/kogonia/tlsherd/internal/agentcfg"
	"github.com/kogonia/tlsherd/internal/config"
)

// Version is the agent version reported to the server (override with -ldflags).
var Version = "dev"

const (
	requestTimeout = 10 * time.Second
	backoffMin     = 5 * time.Second
	backoffMax     = 5 * time.Minute
	backoffJitter  = 0.1
)

// PostChecker connects to addr with SNI and returns the leaf fingerprint served.
type PostChecker func(ctx context.Context, addr, sni string) (fingerprint string, err error)

// Options configures an Agent. Zero values for optional fields select
// production defaults.
type Options struct {
	Bootstrap  config.AgentBootstrap
	Logger     *slog.Logger
	Clock      Clock
	Runner     Runner
	HTTPClient *http.Client
	PostCheck  PostChecker
	// Sleep waits for d or until ctx is done. Defaults to a real timer.
	Sleep func(ctx context.Context, d time.Duration) error
	// Name is the optional agent name sent on enroll (defaults to hostname).
	Name string
}

// Agent is the apply engine. It is not safe for concurrent use.
type Agent struct {
	opts                Options
	log                 *slog.Logger
	clock               Clock
	runner              Runner
	client              *Client
	state               State
	cfg                 agentcfg.Config // server-authoritative schedule document
	local               agentcfg.LocalConfig
	localHash           string
	localConfigConflict bool
	failures            int
}

// New validates options and builds an Agent.
func New(opts Options) (*Agent, error) {
	if opts.Bootstrap.AgentDir == "" && opts.Bootstrap.StateDir != "" {
		opts.Bootstrap.AgentDir = opts.Bootstrap.StateDir
	}
	if opts.Bootstrap.StateDir == "" && opts.Bootstrap.AgentDir != "" {
		opts.Bootstrap.StateDir = opts.Bootstrap.AgentDir
	}
	if opts.Bootstrap.LocalConfigPath == "" && opts.Bootstrap.AgentDir != "" {
		opts.Bootstrap.LocalConfigPath = filepath.Join(opts.Bootstrap.AgentDir, "agent.local.cfg")
	}
	if opts.Bootstrap.ServerURL == "" || opts.Bootstrap.CertRoot == "" || opts.Bootstrap.StateDir == "" {
		return nil, errors.New("agent: server_url, cert_root and agent_dir are required")
	}
	a := &Agent{
		opts: opts, log: opts.Logger, clock: opts.Clock, runner: opts.Runner,
		cfg: agentcfg.Default(), local: agentcfg.DefaultLocal(),
	}
	if a.log == nil {
		a.log = slog.New(slog.DiscardHandler)
	}
	if a.clock == nil {
		a.clock = SystemClock{}
	}
	if a.runner == nil {
		a.runner = ExecRunner{}
	}
	if a.opts.PostCheck == nil {
		a.opts.PostCheck = tlsPostCheck
	}
	if a.opts.Sleep == nil {
		a.opts.Sleep = sleepCtx
	}
	if a.opts.Name == "" {
		a.opts.Name, _ = os.Hostname()
	}
	hc := opts.HTTPClient
	if hc == nil {
		var err error
		if hc, err = NewHTTPClient(opts.Bootstrap.CAFile, false); err != nil {
			return nil, err
		}
	}
	a.client = NewClient(opts.Bootstrap.ServerURL, hc)
	a.log = a.log.With("component", "agent")
	return a, nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (a *Agent) dryRun() bool { return a.opts.Bootstrap.DryRun }

// Run executes the agent loop until ctx is cancelled. With Bootstrap.Once it
// performs a single enroll/poll iteration and returns its error.
func (a *Agent) Run(ctx context.Context) error {
	if err := a.load(); err != nil {
		return err
	}
	for {
		wait, err := a.step(ctx)
		if err != nil && ctx.Err() == nil {
			a.log.Warn("cycle finished with errors", "operation", "step", "error", err)
		}
		if a.opts.Bootstrap.Once {
			return err
		}
		if err := a.opts.Sleep(ctx, wait); err != nil {
			return nil
		}
	}
}

// load reads state.json, config.cfg (+ .prev), and agent.local.cfg (+ .prev).
func (a *Agent) load() error {
	dir := a.opts.Bootstrap.StateDir
	if !a.dryRun() {
		if err := os.MkdirAll(dir, stateDirModeDef); err != nil {
			return fmt.Errorf("create state dir: %w", err)
		}
	}
	st, corrupt, err := loadState(dir)
	if err != nil {
		return err
	}
	if corrupt {
		a.log.Warn("state.json corrupt; starting empty and reconciling with installed files", "operation", "load")
	}
	a.state = st
	for _, name := range []string{configFileName, configPrevName} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err == nil {
			var cfg agentcfg.Config
			if cfg, err = agentcfg.Parse(b); err == nil {
				a.cfg = cfg
				break
			}
		}
		a.log.Warn("cannot use server config file", "operation", "load", "file", name, "error", err)
	}
	return a.loadLocalConfig()
}

func (a *Agent) saveState() {
	if a.dryRun() {
		return
	}
	if err := saveState(a.opts.Bootstrap.StateDir, a.state); err != nil {
		a.log.Error("save state", "operation", "save_state", "error", err)
	}
}

// step runs one enroll-or-poll iteration and returns how long to wait next.
func (a *Agent) step(ctx context.Context) (time.Duration, error) {
	if a.state.APIKey == "" {
		wait, err := a.enroll(ctx)
		if a.state.APIKey == "" {
			return wait, err
		}
	}
	return a.poll(ctx)
}

func (a *Agent) enroll(ctx context.Context) (time.Duration, error) {
	wait := jitter(a.cfg.EnrollInterval.Std(), a.cfg.Jitter)
	if a.dryRun() {
		a.log.Info("dry-run: no api key; enrollment skipped", "operation", "enroll")
		return wait, nil
	}
	rctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	resp, err := a.client.Enroll(rctx, EnrollRequest{
		Name: a.opts.Name, Version: Version,
		LocalConfig: a.local, LocalConfigHash: a.localHash,
	})
	if err != nil {
		return wait, fmt.Errorf("enroll: %w", err)
	}
	switch resp.Status {
	case EnrollAccepted:
		if resp.APIKey == "" {
			return wait, errors.New("enroll: accepted without api_key")
		}
		a.state.APIKey = resp.APIKey
		a.state.ConfigVersion = 0
		// New server identity: drop prior domain fingerprints so disk is re-checked.
		a.state.Domains = map[string]DomainState{}
		if resp.Config != nil {
			if err := a.adoptConfig(*resp.Config, resp.ConfigVersion); err != nil {
				a.log.Error("adopt enrolled config; using defaults", "operation", "enroll", "error", err)
			}
		}
		if _, err := a.acceptLocalConfigUpdate(resp.LocalConfigUpdate); err != nil {
			a.log.Error("apply local config update from enroll", "operation", "enroll", "error", err)
		}
		a.state.LastError = ""
		a.saveState()
		a.log.Info("enrollment accepted", "operation", "enroll")
		return 0, nil
	case EnrollPending:
		a.log.Info("enrollment pending admin approval", "operation", "enroll")
		return wait, nil
	case EnrollRejected:
		a.log.Warn("enrollment rejected; will retry", "operation", "enroll")
		return wait, nil
	default:
		return wait, fmt.Errorf("enroll: unknown status %q", resp.Status)
	}
}

// dropKey clears the API key so the next iteration re-enrolls. Installed
// certificates are left untouched.
func (a *Agent) dropKey(reason string) time.Duration {
	a.log.Warn("api key rejected; re-enrolling", "operation", "poll", "reason", reason)
	a.state.APIKey = ""
	a.state.ConfigVersion = 0
	a.state.LastError = reason
	a.saveState()
	return jitter(a.cfg.EnrollInterval.Std(), a.cfg.Jitter)
}

func (a *Agent) poll(ctx context.Context) (time.Duration, error) {
	req := PollRequest{
		AgentVersion: Version, ConfigVersion: a.state.ConfigVersion,
		LocalConfig: a.local, LocalConfigHash: a.localHash,
		LocalConfigConflict: a.localConfigConflict,
	}
	for fqdn, ds := range a.state.Domains {
		req.Domains = append(req.Domains, DomainReport{FQDN: fqdn, Fingerprint: ds.Fingerprint, StagedFingerprint: ds.StagedFingerprint})
	}
	pctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	resp, err := a.client.Poll(pctx, a.state.APIKey, req)
	if errors.Is(err, ErrUnauthorized) {
		return a.dropKey("poll unauthorized"), err
	}
	if err != nil {
		a.failures++
		return backoff(a.failures), fmt.Errorf("poll: %w", err)
	}
	a.failures = 0

	if resp.NewAPIKey != "" {
		a.state.APIKey = resp.NewAPIKey
		a.log.Info("adopted rotated api key", "operation", "poll")
	}

	if resp.ConfigVersion != a.state.ConfigVersion {
		if err := a.adoptConfig(resp.Config, resp.ConfigVersion); err != nil {
			a.log.Error("reject server config", "operation", "adopt_config", "version", resp.ConfigVersion, "error", err)
			a.state.LastError = "config: " + err.Error()
		}
	}
	if _, err := a.acceptLocalConfigUpdate(resp.LocalConfigUpdate); err != nil {
		a.log.Error("apply local config update", "operation", "poll", "error", err)
		a.state.LastError = "local_config: " + err.Error()
	}

	err = a.syncDomains(ctx, resp.Domains)
	if errors.Is(err, ErrUnauthorized) {
		return a.dropKey("server returned unauthorized"), err
	}
	if err != nil {
		a.state.LastError = err.Error()
	} else {
		a.state.LastError = ""
		a.state.LastSuccess = a.clock.Now().UTC()
	}
	a.saveState()
	return jitter(a.cfg.PollInterval.Std(), a.cfg.Jitter), err
}

// adoptConfig validates cfg, rotates config.cfg to config.cfg.prev and writes
// the new document. In dry-run the config is used in memory only.
func (a *Agent) adoptConfig(cfg agentcfg.Config, version int64) error {
	if err := agentcfg.Validate(cfg); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}
	raw, err := agentcfg.CanonicalJSON(cfg)
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	pretty := prettyJSON(raw)
	if !a.dryRun() {
		dir := a.opts.Bootstrap.StateDir
		cur := filepath.Join(dir, configFileName)
		if old, err := os.ReadFile(cur); err == nil {
			if err := writeFileAtomic(filepath.Join(dir, configPrevName), old, secretFileMode); err != nil {
				return fmt.Errorf("backup config: %w", err)
			}
		} else if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("read config: %w", err)
		}
		if err := writeFileAtomic(cur, pretty, secretFileMode); err != nil {
			return fmt.Errorf("write config: %w", err)
		}
	}
	a.cfg = cfg
	a.state.ConfigVersion = version
	a.log.Info("config adopted", "operation", "adopt_config", "version", version)
	return nil
}

// jitter spreads d by ±frac.
func jitter(d time.Duration, frac float64) time.Duration {
	if frac <= 0 || d <= 0 {
		return d
	}
	return time.Duration(float64(d) * (1 + frac*(2*rand.Float64()-1)))
}

// backoff grows 5s → 5m (doubling) with ±10% jitter.
func backoff(failures int) time.Duration {
	d := backoffMin
	for i := 1; i < failures && d < backoffMax; i++ {
		d *= 2
	}
	if d > backoffMax {
		d = backoffMax
	}
	return jitter(d, backoffJitter)
}
