package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/kogonia/tlsherd/internal/agentcfg"
	"github.com/kogonia/tlsherd/internal/certutil"
)

const (
	applyDeadline     = 5 * time.Minute
	restartTimeout    = 60 * time.Second
	postCheckAttempts = 5
	postCheckDelay    = 2 * time.Second
	maxOutputInDetail = 2048
)

// syncDomains reconciles every assigned domain (one apply at a time). A
// per-domain failure does not stop other domains; ErrUnauthorized aborts.
func (a *Agent) syncDomains(ctx context.Context, assigned []Assignment) error {
	var errs []error
	for _, asg := range assigned {
		if err := a.processDomain(ctx, asg); err != nil {
			if errors.Is(err, ErrUnauthorized) {
				return err
			}
			errs = append(errs, fmt.Errorf("%s: %w", asg.FQDN, err))
		}
		if ctx.Err() != nil {
			errs = append(errs, ctx.Err())
			break
		}
	}
	return errors.Join(errs...)
}

func (a *Agent) processDomain(ctx context.Context, asg Assignment) error {
	rt := a.runtimeCFG()
	l, err := newLayout(a.certRoot(), asg.FQDN)
	if err != nil {
		return err
	}
	if !validFingerprint(asg.Fingerprint) {
		return fmt.Errorf("invalid assigned fingerprint %q", asg.Fingerprint)
	}
	ds := a.state.Domains[asg.FQDN]
	if ds.Fingerprint == "" {
		// Lost/new state: reconcile with what is on disk to avoid needless restarts.
		if fp := installedFingerprint(l, rt.Install.CertName); fp != "" {
			ds.Fingerprint = fp
			a.state.Domains[asg.FQDN] = ds
		}
	}
	if ds.Fingerprint == asg.Fingerprint {
		if ds.StagedFingerprint != "" {
			ds.StagedFingerprint = ""
			a.state.Domains[asg.FQDN] = ds
		}
		return nil
	}

	now := a.clock.Now()
	inWindow, err := agentcfg.InWindow(a.cfg.MaintenanceWindow, now)
	if err != nil {
		a.log.Warn("maintenance window unusable; treating as closed", "operation", "window", "domain", asg.FQDN, "error", err)
		inWindow = false
	}
	// Urgent: installed cert expires within threshold, or nothing is installed.
	urgent := true
	if c := readInstalledCert(l, rt.Install.CertName); c != nil {
		urgent = agentcfg.IsUrgent(c.NotAfter, a.cfg.UrgentThreshold.Std(), now)
	}
	if inWindow || urgent {
		return a.apply(ctx, l, asg, ds, urgent && !inWindow)
	}
	return a.stage(ctx, l, asg, ds)
}

// fetchValidated returns a parsed, validated bundle for the assignment. A local
// versions/<fp> copy is revalidated via If-None-Match/304.
func (a *Agent) fetchValidated(ctx context.Context, l layout, asg Assignment) (*certutil.Parsed, error) {
	cn, kn, hn, _ := installSpec{inst: a.runtimeCFG().Install}.names()
	verDir := l.versionDir(asg.Fingerprint)
	_, statErr := os.Stat(filepath.Join(verDir, kn))
	haveLocal := statErr == nil

	rctx, cancel := context.WithTimeout(ctx, requestTimeout*3)
	defer cancel()
	b, notModified, err := a.client.FetchCert(rctx, a.state.APIKey, asg.Fingerprint, haveLocal)
	if err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}
	var cert, key, chain []byte
	if notModified {
		if !haveLocal {
			return nil, errors.New("download: server replied 304 but no local copy exists")
		}
		if cert, err = os.ReadFile(filepath.Join(verDir, cn)); err != nil {
			return nil, fmt.Errorf("read staged cert: %w", err)
		}
		if key, err = os.ReadFile(filepath.Join(verDir, kn)); err != nil {
			return nil, fmt.Errorf("read staged key: %w", err)
		}
		chain, _ = os.ReadFile(filepath.Join(verDir, hn))
	} else {
		cert, key, chain = []byte(b.Cert), []byte(b.Key), []byte(b.Chain)
	}
	p, err := certutil.ParseBundle(cert, key, chain, a.clock.Now())
	if err != nil {
		return nil, fmt.Errorf("validate: %w", err)
	}
	if p.Fingerprint != asg.Fingerprint {
		return nil, fmt.Errorf("validate: fingerprint mismatch (got %s)", p.Fingerprint)
	}
	if !certutil.CoversDomain(p.SANs, p.SubjectCN, asg.FQDN) {
		return nil, errors.New("validate: certificate does not cover domain")
	}
	return p, nil
}

func (a *Agent) stage(ctx context.Context, l layout, asg Assignment, ds DomainState) error {
	log := a.log.With("domain", asg.FQDN, "fingerprint", asg.Fingerprint, "operation", "stage")
	if !a.cfg.StageOutsideWindow {
		log.Info("outside maintenance window; staging disabled")
		return nil
	}
	if ds.StagedFingerprint == asg.Fingerprint {
		return nil
	}
	res := ApplyResult{ApplyID: uuid.NewString(), FQDN: asg.FQDN, Fingerprint: asg.Fingerprint, PreviousFingerprint: ds.Fingerprint}
	p, err := a.fetchValidated(ctx, l, asg)
	if err != nil {
		return a.failed(ctx, res, "download_validate", err)
	}
	if a.dryRun() {
		log.Info("dry-run: would stage new certificate")
		return nil
	}
	spec := a.spec(asg, p)
	if _, err := writeVersion(l, spec); err != nil {
		return a.failed(ctx, res, "stage", err)
	}
	ds.StagedFingerprint = asg.Fingerprint
	a.state.Domains[asg.FQDN] = ds
	a.saveState()
	log.Info("staged outside maintenance window")
	res.Status, res.Message = StatusStaged, "staged outside maintenance window"
	return a.report(ctx, res)
}

func (a *Agent) spec(asg Assignment, p *certutil.Parsed) installSpec {
	rt := a.runtimeCFG()
	fullchain := append([]byte{}, p.CertPEM...)
	fullchain = append(fullchain, p.ChainPEM...)
	s := installSpec{
		fqdn:        asg.FQDN,
		fingerprint: asg.Fingerprint,
		mode:        rt.Install.Mode,
		inst:        rt.Install,
		cert:        p.CertPEM,
		key:         p.KeyPEM,
		chain:       p.ChainPEM,
		fullchain:   fullchain,
		extra:       map[string]string{},
	}
	if asg.InstallMode != "" {
		s.mode = asg.InstallMode
	}
	if s.mode == "" {
		s.mode = "symlink"
	}
	cn, kn, hn, fn := s.names()
	certPath, keyPath, chainPath, fullPath := asg.CertPath, asg.KeyPath, asg.ChainPath, asg.FullchainPath
	if certPath == "" {
		certPath = a.local.CertPath
	}
	if keyPath == "" {
		keyPath = a.local.KeyPath
	}
	if chainPath == "" {
		chainPath = a.local.ChainPath
	}
	if fullPath == "" {
		fullPath = a.local.FullchainPath
	}
	for name, rel := range map[string]string{cn: certPath, kn: keyPath, hn: chainPath, fn: fullPath} {
		if rel == "" {
			continue
		}
		abs, err := agentcfg.JoinUnderRoot(a.certRoot(), agentcfg.RenderPath(rel, asg.FQDN))
		if err != nil {
			a.log.Warn("ignoring unsafe extra path", "domain", asg.FQDN, "path", rel, "error", err)
			continue
		}
		s.extra[name] = abs
	}
	return s
}

// apply performs backup → install → verify → restart → post_check → report.
func (a *Agent) apply(ctx context.Context, l layout, asg Assignment, ds DomainState, urgent bool) error {
	ctx, cancel := context.WithTimeout(ctx, applyDeadline)
	defer cancel()
	log := a.log.With("domain", asg.FQDN, "fingerprint", asg.Fingerprint, "operation", "apply")
	res := ApplyResult{ApplyID: uuid.NewString(), FQDN: asg.FQDN, Fingerprint: asg.Fingerprint, PreviousFingerprint: ds.Fingerprint, Details: map[string]any{"urgent": urgent}}

	p, err := a.fetchValidated(ctx, l, asg)
	if err != nil {
		return a.failed(ctx, res, "download_validate", err)
	}
	rt := a.runtimeCFG()
	spec := a.spec(asg, p)
	if spec.mode != "symlink" && spec.mode != "copy" {
		return a.failed(ctx, res, "install", fmt.Errorf("invalid install mode %q", spec.mode))
	}
	rc := rt.Restart
	if asg.Restart != nil {
		rc = *asg.Restart
	}
	restartArgv, err := restartCommand(rc, asg.FQDN)
	if err != nil {
		return a.failed(ctx, res, "restart_config", err)
	}
	if a.dryRun() {
		log.Info("dry-run: would apply new certificate", "install_mode", spec.mode, "verify", len(rt.Verify.Command) > 0, "restart", restartArgv)
		return nil
	}

	// Mandatory backup: failure aborts before any active file changes.
	bdir, err := backup(l, asg.FQDN, ds.Fingerprint, spec.targets(l), a.clock.Now(), parseMode(rt.Install.DirMode, 0o750))
	if err != nil {
		return a.failed(ctx, res, "backup", err)
	}
	res.Details["backup"] = bdir

	rollback := func(stage string, cause error) error {
		if rerr := restore(bdir); rerr != nil {
			cause = fmt.Errorf("%w; restore failed: %v", cause, rerr)
			res.Details["restore"] = "failed"
		} else {
			res.Details["restore"] = "ok"
		}
		return a.failed(ctx, res, stage, cause)
	}

	if _, err := writeVersion(l, spec); err != nil {
		return rollback("install", err)
	}
	if err := switchActive(l, spec); err != nil {
		return rollback("install", err)
	}

	if len(rt.Verify.Command) > 0 {
		out, err := a.runVerify(ctx, asg.FQDN)
		if err != nil {
			res.Status = StatusVerifyFailed
			res.Details["verify_output"] = out
			rerr := restore(bdir)
			res.Details["restore"] = restoreStatus(rerr)
			if rerr == nil {
				// Best-effort confirmation that the previous files still verify; never restarts.
				_, rv := a.runVerify(ctx, asg.FQDN)
				res.Details["verify_after_restore"] = restoreStatus(rv)
			}
			return a.failed(ctx, res, "verify", errors.Join(err, rerr))
		}
	}

	if err := a.restart(ctx, restartArgv); err != nil {
		res.Status = StatusRestartFailed
		return rollback("restart", err)
	}

	ds.Fingerprint, ds.StagedFingerprint = asg.Fingerprint, ""
	a.state.Domains[asg.FQDN] = ds
	a.state.LastSuccess = a.clock.Now().UTC()
	a.saveState()

	res.Status, res.Message = StatusApplied, "certificate applied"
	if a.cfg.PostCheck.Enabled {
		if err := a.postCheck(ctx, asg); err != nil {
			res.Status, res.Message = StatusPostCheckMismatch, err.Error()
			log.Warn("post-check mismatch", "error", err)
		}
	}
	if err := pruneBackups(l, a.cfg.Backups.Keep); err != nil {
		log.Warn("prune backups", "error", err)
	}
	log.Info("applied", "status", res.Status)
	return a.report(ctx, res)
}

func restoreStatus(err error) string {
	if err != nil {
		return "failed: " + err.Error()
	}
	return "ok"
}

// failed logs and reports a failed attempt; res.Status defaults to StatusFailed.
func (a *Agent) failed(ctx context.Context, res ApplyResult, stage string, cause error) error {
	if res.Status == "" {
		res.Status = StatusFailed
	}
	res.Message = fmt.Sprintf("%s: %v", stage, cause)
	if res.Details == nil {
		res.Details = map[string]any{}
	}
	res.Details["stage"] = stage
	a.log.Error("apply failed", "operation", "apply", "domain", res.FQDN, "fingerprint", res.Fingerprint, "status", res.Status, "stage", stage, "error", cause)
	return errors.Join(fmt.Errorf("%s: %w", stage, cause), a.report(ctx, res))
}

// report sends the result; only ErrUnauthorized is surfaced to the caller.
func (a *Agent) report(ctx context.Context, res ApplyResult) error {
	if a.dryRun() {
		return nil
	}
	// Do not lose the report just because the apply deadline elapsed.
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), requestTimeout)
	defer cancel()
	err := a.client.ReportApply(rctx, a.state.APIKey, res)
	if errors.Is(err, ErrUnauthorized) {
		return err
	}
	if err != nil {
		a.log.Warn("report apply-result", "operation", "report", "apply_id", res.ApplyID, "error", err)
	}
	return nil
}

func (a *Agent) runVerify(ctx context.Context, fqdn string) (string, error) {
	v := a.runtimeCFG().Verify
	timeout := v.Timeout.Std()
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	vctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	argv := renderArgv(v.Command, fqdn)
	stdout, stderr, err := a.runner.Run(vctx, argv[0], argv[1:]...)
	if err != nil {
		return truncate(strings.TrimSpace(stdout + "\n" + stderr)), fmt.Errorf("verify command failed: %w", err)
	}
	return "", nil
}

func (a *Agent) restart(ctx context.Context, argv []string) error {
	rctx, cancel := context.WithTimeout(ctx, restartTimeout)
	defer cancel()
	_, stderr, err := a.runner.Run(rctx, argv[0], argv[1:]...)
	if err != nil {
		return fmt.Errorf("restart %s: %w: %s", argv[0], err, truncate(strings.TrimSpace(stderr)))
	}
	return nil
}

func truncate(s string) string {
	if len(s) > maxOutputInDetail {
		return s[:maxOutputInDetail] + "…"
	}
	return s
}

func renderArgv(argv []string, fqdn string) []string {
	out := make([]string, len(argv))
	for i, v := range argv {
		out[i] = agentcfg.RenderPath(v, fqdn)
	}
	return out
}

// restartCommand builds the argv (no shell) that reloads/restarts the service.
func restartCommand(r agentcfg.Restart, fqdn string) ([]string, error) {
	switch r.Type {
	case "", "systemd":
		if r.Name == "" {
			return nil, errors.New("restart.name required for systemd")
		}
		verb := "restart"
		if r.ReloadOnly {
			verb = "reload"
		}
		return []string{"systemctl", verb, r.Name}, nil
	case "docker":
		if r.Name == "" {
			return nil, errors.New("restart.name (container) required for docker")
		}
		if r.ReloadOnly && len(r.Command) > 0 {
			return append([]string{"docker", "exec", r.Name}, renderArgv(r.Command, fqdn)...), nil
		}
		return []string{"docker", "restart", r.Name}, nil
	case "exec":
		if len(r.Command) == 0 {
			return nil, errors.New("restart.command required for exec")
		}
		return renderArgv(r.Command, fqdn), nil
	default:
		return nil, fmt.Errorf("unknown restart.type %q", r.Type)
	}
}

// postCheck confirms the endpoint serves the new leaf (retrying while the service starts).
func (a *Agent) postCheck(ctx context.Context, asg Assignment) error {
	pc := a.cfg.PostCheck
	if pc.Addr == "" {
		return errors.New("post_check.addr is empty")
	}
	sni := pc.SNI
	if sni == "" {
		sni = asg.FQDN
	}
	var last error
	for i := 0; i < postCheckAttempts; i++ {
		if i > 0 {
			if err := a.opts.Sleep(ctx, postCheckDelay); err != nil {
				return err
			}
		}
		fp, err := a.opts.PostCheck(ctx, pc.Addr, sni)
		if err == nil && fp == asg.Fingerprint {
			return nil
		}
		if err == nil {
			err = fmt.Errorf("endpoint serves fingerprint %s, expected %s", fp, asg.Fingerprint)
		}
		last = err
	}
	return fmt.Errorf("post-check: %w", last)
}

func tlsPostCheck(ctx context.Context, addr, sni string) (string, error) {
	d := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 5 * time.Second},
		// Only the served leaf fingerprint is compared; trust is not evaluated here.
		Config: &tls.Config{ServerName: sni, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, //nolint:gosec
	}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", errors.New("no peer certificate")
	}
	return certutil.Fingerprint(certs[0].Raw), nil
}
