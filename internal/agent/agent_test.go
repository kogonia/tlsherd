package agent

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kogonia/tlsherd/internal/agentcfg"
	"github.com/kogonia/tlsherd/internal/config"
)

func TestHappyPath(t *testing.T) {
	e := newEnv(t)
	e.seedKey()
	fp1, b1 := e.srv.addCert(t, testFQDN, inWindowTime.Add(90*24*time.Hour))
	e.srv.assign(Assignment{FQDN: testFQDN, Fingerprint: fp1})

	if err := e.run(false); err != nil {
		t.Fatalf("run: %v", err)
	}

	link, err := os.Readlink(filepath.Join(e.certRoot, testFQDN, "current"))
	if err != nil || link != filepath.Join("versions", fp1) {
		t.Fatalf("current link = %q, %v", link, err)
	}
	verDir := filepath.Join(e.certRoot, testFQDN, "versions", fp1)
	for name, want := range map[string]string{"cert.pem": b1.Cert, "key.pem": b1.Key, "chain.pem": b1.Chain} {
		got, err := os.ReadFile(filepath.Join(verDir, name))
		if err != nil || string(got) != want {
			t.Fatalf("%s mismatch: %v", name, err)
		}
	}
	wantFull := b1.Cert + b1.Chain
	gotFull, err := os.ReadFile(filepath.Join(verDir, "fullchain.pem"))
	if err != nil || string(gotFull) != wantFull {
		t.Fatalf("fullchain.pem mismatch: %v", err)
	}
	if fi, _ := os.Stat(filepath.Join(verDir, "key.pem")); fi.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %v", fi.Mode().Perm())
	}
	if got, want := e.runner.Calls(), []string{"nginx -t", "systemctl restart nginx"}; strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("runner calls = %v, want %v", got, want)
	}
	res := e.srv.lastResult(t)
	if res.Status != StatusApplied || res.ApplyID == "" || res.Fingerprint != fp1 {
		t.Fatalf("result = %+v", res)
	}
	if _, err := os.Stat(filepath.Join(e.certRoot, testFQDN, "backups")); err != nil {
		t.Fatalf("backup dir missing: %v", err)
	}

	st := e.loadState()
	if st.Domains[testFQDN].Fingerprint != fp1 || st.ConfigVersion != 1 || st.LastSuccess.IsZero() || st.LastError != "" {
		t.Fatalf("state = %+v", st)
	}
	for _, f := range []string{stateFileName, configFileName} {
		if fi, err := os.Stat(filepath.Join(e.stateDir, f)); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", f, fi, err)
		}
	}

	// Second run with the same assignment is a no-op.
	n := len(e.runner.Calls())
	if err := e.run(false); err != nil {
		t.Fatal(err)
	}
	if len(e.runner.Calls()) != n || e.srv.resultCount() != 1 {
		t.Fatal("idempotent run changed something")
	}

	// New version: previous symlink is backed up, then switched.
	fp2, _ := e.srv.addCert(t, testFQDN, inWindowTime.Add(90*24*time.Hour))
	e.srv.assign(Assignment{FQDN: testFQDN, Fingerprint: fp2})
	if err := e.run(false); err != nil {
		t.Fatal(err)
	}
	if link, _ := os.Readlink(filepath.Join(e.certRoot, testFQDN, "current")); link != filepath.Join("versions", fp2) {
		t.Fatalf("current -> %s", link)
	}
	entries, _ := os.ReadDir(filepath.Join(e.certRoot, testFQDN, "backups"))
	if len(entries) != 2 {
		t.Fatalf("want 2 backups, got %d", len(entries))
	}
}

func TestVerifyFailureRestoresFilesAndSkipsRestart(t *testing.T) {
	for _, mode := range []string{"symlink", "copy"} {
		t.Run(mode, func(t *testing.T) {
			e := newEnv(t)
			cfg := testConfig()
			cfg.Install.Mode = mode
			e.srv.config = cfg
			e.seedKey()
			fp1, _ := e.srv.addCert(t, testFQDN, inWindowTime.Add(90*24*time.Hour))
			e.srv.assign(Assignment{FQDN: testFQDN, Fingerprint: fp1})
			if err := e.run(false); err != nil {
				t.Fatal(err)
			}
			certSHA, keySHA := fileSHA(t, e.current("cert.pem")), fileSHA(t, e.current("key.pem"))
			restarts := e.runner.Count("systemctl")

			e.runner.fn = func(name string, _ []string) error {
				if name == "nginx" {
					return errors.New("nginx: config test failed")
				}
				return nil
			}
			fp2, _ := e.srv.addCert(t, testFQDN, inWindowTime.Add(90*24*time.Hour))
			e.srv.assign(Assignment{FQDN: testFQDN, Fingerprint: fp2})
			if err := e.run(false); err == nil {
				t.Fatal("expected error from failed verify")
			}

			if got := fileSHA(t, e.current("cert.pem")); got != certSHA {
				t.Fatalf("cert.pem not restored: %s != %s", got, certSHA)
			}
			if got := fileSHA(t, e.current("key.pem")); got != keySHA {
				t.Fatalf("key.pem not restored")
			}
			if mode == "symlink" {
				if link, _ := os.Readlink(filepath.Join(e.certRoot, testFQDN, "current")); link != filepath.Join("versions", fp1) {
					t.Fatalf("current -> %s, want fp1", link)
				}
			}
			if e.runner.Count("systemctl") != restarts {
				t.Fatal("service restarted after failed verify")
			}
			res := e.srv.lastResult(t)
			if res.Status != StatusVerifyFailed || res.Fingerprint != fp2 || res.Details["restore"] != "ok" {
				t.Fatalf("result = %+v", res)
			}
			if st := e.loadState(); st.Domains[testFQDN].Fingerprint != fp1 || st.LastError == "" {
				t.Fatalf("state = %+v", st)
			}
		})
	}
}

func TestOutsideWindowStagesOnly(t *testing.T) {
	e := newEnv(t)
	e.seedKey()
	fp1, _ := e.srv.addCert(t, testFQDN, inWindowTime.Add(90*24*time.Hour))
	e.srv.assign(Assignment{FQDN: testFQDN, Fingerprint: fp1})
	if err := e.run(false); err != nil {
		t.Fatal(err)
	}
	calls := len(e.runner.Calls())
	certSHA := fileSHA(t, e.current("cert.pem"))

	e.clock.t = outWindowTime
	fp2, b2 := e.srv.addCert(t, testFQDN, inWindowTime.Add(90*24*time.Hour))
	e.srv.assign(Assignment{FQDN: testFQDN, Fingerprint: fp2})
	if err := e.run(false); err != nil {
		t.Fatal(err)
	}
	if len(e.runner.Calls()) != calls {
		t.Fatalf("runner invoked while staging: %v", e.runner.Calls())
	}
	if fileSHA(t, e.current("cert.pem")) != certSHA {
		t.Fatal("active cert changed outside window")
	}
	if got, err := os.ReadFile(filepath.Join(e.certRoot, testFQDN, "versions", fp2, "cert.pem")); err != nil || string(got) != b2.Cert {
		t.Fatalf("staged cert missing: %v", err)
	}
	if res := e.srv.lastResult(t); res.Status != StatusStaged || res.Fingerprint != fp2 {
		t.Fatalf("result = %+v", res)
	}
	st := e.loadState()
	if ds := st.Domains[testFQDN]; ds.Fingerprint != fp1 || ds.StagedFingerprint != fp2 {
		t.Fatalf("state = %+v", ds)
	}

	// Staging is reported once.
	n := e.srv.resultCount()
	if err := e.run(false); err != nil {
		t.Fatal(err)
	}
	if e.srv.resultCount() != n {
		t.Fatal("staged result re-reported")
	}

	// Window opens: apply from the staged copy (If-None-Match -> 304).
	e.clock.t = inWindowTime.Add(24 * time.Hour)
	if err := e.run(false); err != nil {
		t.Fatal(err)
	}
	last := e.srv.certReqs[len(e.srv.certReqs)-1]
	if last.FP != fp2 || last.IfNoneMatch != `"`+fp2+`"` {
		t.Fatalf("last cert request = %+v", last)
	}
	if e.srv.lastResult(t).Status != StatusApplied || e.runner.Count("systemctl restart") != 2 {
		t.Fatalf("apply after window failed: %+v", e.srv.lastResult(t))
	}
	if ds := e.loadState().Domains[testFQDN]; ds.Fingerprint != fp2 || ds.StagedFingerprint != "" {
		t.Fatalf("state = %+v", ds)
	}
}

func TestStrictCertCheckBlocksExpired(t *testing.T) {
	e := newEnv(t)
	cfg := testConfig()
	cfg.StrictCertCheck = true
	e.srv.config = cfg
	e.seedKey()
	fp1, _ := e.srv.addCert(t, testFQDN, inWindowTime.Add(90*24*time.Hour))
	e.srv.assign(Assignment{FQDN: testFQDN, Fingerprint: fp1})
	if err := e.run(false); err != nil {
		t.Fatal(err)
	}
	fpBad, _ := e.srv.addCert(t, testFQDN, inWindowTime.Add(-24*time.Hour))
	e.srv.assign(Assignment{FQDN: testFQDN, Fingerprint: fpBad})
	if err := e.run(false); err == nil {
		t.Fatal("expected expired cert to be rejected")
	}
	if link, _ := os.Readlink(filepath.Join(e.certRoot, testFQDN, "current")); link != filepath.Join("versions", fp1) {
		t.Fatalf("current should stay on good cert, got %s", link)
	}
	if res := e.srv.lastResult(t); res.Status != StatusFailed {
		t.Fatalf("result = %+v", res)
	}
}

func TestRollbackToKnownVersionAppliesOutsideWindow(t *testing.T) {
	e := newEnv(t)
	e.seedKey()
	fp1, _ := e.srv.addCert(t, testFQDN, inWindowTime.Add(90*24*time.Hour))
	e.srv.assign(Assignment{FQDN: testFQDN, Fingerprint: fp1})
	if err := e.run(false); err != nil {
		t.Fatal(err)
	}
	fp2, _ := e.srv.addCert(t, testFQDN, inWindowTime.Add(90*24*time.Hour))
	e.srv.assign(Assignment{FQDN: testFQDN, Fingerprint: fp2})
	if err := e.run(false); err != nil {
		t.Fatal(err)
	}
	e.clock.t = outWindowTime
	e.srv.assign(Assignment{FQDN: testFQDN, Fingerprint: fp1})
	if err := e.run(false); err != nil {
		t.Fatal(err)
	}
	if res := e.srv.lastResult(t); res.Status != StatusApplied || res.Fingerprint != fp1 {
		t.Fatalf("rollback should apply outside window: %+v", res)
	}
	if link, _ := os.Readlink(filepath.Join(e.certRoot, testFQDN, "current")); link != filepath.Join("versions", fp1) {
		t.Fatalf("current after rollback -> %s", link)
	}
}

func TestUrgentAppliesOutsideWindow(t *testing.T) {
	e := newEnv(t)
	e.seedKey()
	fp1, _ := e.srv.addCert(t, testFQDN, inWindowTime.Add(48*time.Hour)) // within 72h threshold
	e.srv.assign(Assignment{FQDN: testFQDN, Fingerprint: fp1})
	if err := e.run(false); err != nil {
		t.Fatal(err)
	}
	e.clock.t = outWindowTime
	fp2, _ := e.srv.addCert(t, testFQDN, inWindowTime.Add(90*24*time.Hour))
	e.srv.assign(Assignment{FQDN: testFQDN, Fingerprint: fp2})
	if err := e.run(false); err != nil {
		t.Fatal(err)
	}
	if res := e.srv.lastResult(t); res.Status != StatusApplied || res.Details["urgent"] != true {
		t.Fatalf("result = %+v", res)
	}
}

func TestBackupFailureAbortsApply(t *testing.T) {
	e := newEnv(t)
	e.seedKey()
	fp1, _ := e.srv.addCert(t, testFQDN, inWindowTime.Add(90*24*time.Hour))
	e.srv.assign(Assignment{FQDN: testFQDN, Fingerprint: fp1})
	if err := e.run(false); err != nil {
		t.Fatal(err)
	}
	certSHA := fileSHA(t, e.current("cert.pem"))
	calls := len(e.runner.Calls())

	// Make the backups location unusable: a regular file where the directory should be.
	backups := filepath.Join(e.certRoot, testFQDN, "backups")
	if err := os.RemoveAll(backups); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backups, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	fp2, _ := e.srv.addCert(t, testFQDN, inWindowTime.Add(90*24*time.Hour))
	e.srv.assign(Assignment{FQDN: testFQDN, Fingerprint: fp2})
	if err := e.run(false); err == nil {
		t.Fatal("expected backup failure")
	}
	if fileSHA(t, e.current("cert.pem")) != certSHA {
		t.Fatal("active cert modified despite backup failure")
	}
	if _, err := os.Stat(filepath.Join(e.certRoot, testFQDN, "versions", fp2)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("new version written despite backup failure")
	}
	if len(e.runner.Calls()) != calls {
		t.Fatal("verify/restart executed despite backup failure")
	}
	res := e.srv.lastResult(t)
	if res.Status != StatusFailed || res.Details["stage"] != "backup" {
		t.Fatalf("result = %+v", res)
	}
	if e.loadState().Domains[testFQDN].Fingerprint != fp1 {
		t.Fatal("state advanced after backup failure")
	}
}

func TestFullchainPathAndCertRootOverride(t *testing.T) {
	e := newEnv(t)
	altRoot := filepath.Join(t.TempDir(), "nginx-certs")
	localPath := filepath.Join(e.stateDir, "agent.local.cfg")
	lc := agentcfg.DefaultLocal()
	lc.Service = agentcfg.ServiceNginx
	lc.Verify.Command = []string{"nginx", "-t"}
	lc.Restart = agentcfg.Restart{Type: "systemd", Name: "nginx", ReloadOnly: true}
	lc.CertRoot = altRoot
	lc.FullchainPath = "{domain}.crt"
	lc.KeyPath = "{domain}.key"
	raw, err := agentcfg.CanonicalLocalJSON(lc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(e.stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(localPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	e.seedKey()
	fp1, b1 := e.srv.addCert(t, testFQDN, inWindowTime.Add(90*24*time.Hour))
	e.srv.assign(Assignment{FQDN: testFQDN, Fingerprint: fp1})

	opts := Options{
		Bootstrap: config.AgentBootstrap{
			ServerURL: e.srv.URL, CertRoot: e.certRoot, StateDir: e.stateDir,
			LocalConfigPath: localPath, Once: true,
		},
		Clock:  e.clock,
		Runner: e.runner,
		Sleep:  func(context.Context, time.Duration) error { return nil },
	}
	a, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}

	if entries, err := os.ReadDir(e.certRoot); err == nil && len(entries) > 0 {
		t.Fatalf("bootstrap cert_root used despite override: %v", entries)
	}
	wantFull := b1.Cert + b1.Chain
	gotFull, err := os.ReadFile(filepath.Join(altRoot, testFQDN+".crt"))
	if err != nil || string(gotFull) != wantFull {
		t.Fatalf("published fullchain: %v got %q", err, gotFull)
	}
	gotKey, err := os.ReadFile(filepath.Join(altRoot, testFQDN+".key"))
	if err != nil || string(gotKey) != b1.Key {
		t.Fatalf("published key: %v", err)
	}
	if _, err := os.Stat(filepath.Join(altRoot, testFQDN, "versions", fp1, "fullchain.pem")); err != nil {
		t.Fatalf("version fullchain missing: %v", err)
	}
}

func TestDryRunMakesNoChanges(t *testing.T) {
	e := newEnv(t)
	e.seedKey()
	fp1, _ := e.srv.addCert(t, testFQDN, inWindowTime.Add(90*24*time.Hour))
	e.srv.assign(Assignment{FQDN: testFQDN, Fingerprint: fp1})
	before, err := os.ReadFile(filepath.Join(e.stateDir, stateFileName))
	if err != nil {
		t.Fatal(err)
	}

	if err := e.run(true); err != nil {
		t.Fatalf("dry-run: %v", err)
	}

	if entries, err := os.ReadDir(e.certRoot); err == nil && len(entries) > 0 {
		t.Fatalf("cert_root modified: %v", entries)
	}
	after, _ := os.ReadFile(filepath.Join(e.stateDir, stateFileName))
	if string(after) != string(before) {
		t.Fatal("state.json modified")
	}
	if _, err := os.Stat(filepath.Join(e.stateDir, configFileName)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("config.cfg written in dry-run")
	}
	if len(e.runner.Calls()) != 0 {
		t.Fatalf("commands run in dry-run: %v", e.runner.Calls())
	}
	if e.srv.resultCount() != 0 {
		t.Fatal("apply-result reported in dry-run")
	}
}

func TestEnrollPendingThenAcceptedAndConfigBackup(t *testing.T) {
	e := newEnv(t)
	if err := e.run(false); err != nil {
		t.Fatal(err)
	}
	if st := e.loadState(); st.APIKey != "" {
		t.Fatal("key saved while pending")
	}
	if e.srv.polls != 0 {
		t.Fatal("polled without key")
	}

	e.srv.enrollStatus = EnrollAccepted
	if err := e.run(false); err != nil {
		t.Fatal(err)
	}
	st := e.loadState()
	if st.APIKey != "key-1" || st.ConfigVersion != 1 || e.srv.polls != 1 {
		t.Fatalf("state = %+v polls=%d", st, e.srv.polls)
	}
	cur, err := os.ReadFile(filepath.Join(e.stateDir, configFileName))
	if err != nil {
		t.Fatal(err)
	}
	wantHash, _ := agentcfg.Hash(testConfig())
	got, err := agentcfg.Parse(cur)
	if err != nil {
		t.Fatal(err)
	}
	gotHash, _ := agentcfg.Hash(got)
	if gotHash != wantHash {
		t.Fatalf("config.cfg hash = %s want %s", gotHash, wantHash)
	}
	if _, err := os.Stat(filepath.Join(e.stateDir, configPrevName)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("unexpected config.cfg.prev on first config")
	}

	newCfg := mustParseConfig(t, `{"poll_interval":"6h","restart":{"type":"systemd","name":"nginx"}}`)
	e.srv.config, e.srv.configVersion = newCfg, 2
	if err := e.run(false); err != nil {
		t.Fatal(err)
	}
	prev, _ := os.ReadFile(filepath.Join(e.stateDir, configPrevName))
	cur, _ = os.ReadFile(filepath.Join(e.stateDir, configFileName))
	prevParsed, _ := agentcfg.Parse(prev)
	curParsed, _ := agentcfg.Parse(cur)
	prevHash, _ := agentcfg.Hash(prevParsed)
	curHash, _ := agentcfg.Hash(curParsed)
	newHash, _ := agentcfg.Hash(newCfg)
	if prevHash != wantHash || curHash != newHash || e.loadState().ConfigVersion != 2 {
		t.Fatalf("prev=%s cur=%s version=%d", prevHash, curHash, e.loadState().ConfigVersion)
	}
}

func TestInvalidServerConfigKeepsOldConfig(t *testing.T) {
	e := newEnv(t)
	e.seedKey()
	if err := e.run(false); err != nil {
		t.Fatal(err)
	}
	bad := testConfig()
	bad.Restart.Type = "bogus"
	e.srv.config, e.srv.configVersion = bad, 2
	if err := e.run(false); err != nil {
		t.Fatal(err)
	}
	cur, _ := os.ReadFile(filepath.Join(e.stateDir, configFileName))
	parsed, _ := agentcfg.Parse(cur)
	wantHash, _ := agentcfg.Hash(testConfig())
	gotHash, _ := agentcfg.Hash(parsed)
	if gotHash != wantHash || e.loadState().ConfigVersion != 1 {
		t.Fatalf("invalid config adopted: hash=%s version=%d", gotHash, e.loadState().ConfigVersion)
	}
}

func TestUnauthorizedClearsKeyAndKeepsCerts(t *testing.T) {
	e := newEnv(t)
	e.seedKey()
	fp1, _ := e.srv.addCert(t, testFQDN, inWindowTime.Add(90*24*time.Hour))
	e.srv.assign(Assignment{FQDN: testFQDN, Fingerprint: fp1})
	if err := e.run(false); err != nil {
		t.Fatal(err)
	}
	e.srv.mu.Lock()
	e.srv.apiKey = "rotated" // stored key is now stale
	e.srv.mu.Unlock()
	if err := e.run(false); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
	st := e.loadState()
	if st.APIKey != "" || st.Domains[testFQDN].Fingerprint != fp1 {
		t.Fatalf("state = %+v", st)
	}
	if _, err := os.Stat(e.current("cert.pem")); err != nil {
		t.Fatal("certs touched on 401")
	}
}

func TestRejectsUnsafeDomainName(t *testing.T) {
	e := newEnv(t)
	e.seedKey()
	e.srv.assign(Assignment{FQDN: "../evil", Fingerprint: strings.Repeat("a", 64)})
	if err := e.run(false); err == nil {
		t.Fatal("expected error")
	}
	if entries, err := os.ReadDir(filepath.Dir(e.certRoot)); err == nil {
		for _, en := range entries {
			if en.Name() == "evil" {
				t.Fatal("escaped cert_root")
			}
		}
	}
}

func TestPostCheckMismatchStillApplied(t *testing.T) {
	e := newEnv(t)
	cfg := testConfig()
	cfg.PostCheck = agentcfg.PostCheck{Enabled: true, Addr: "127.0.0.1:443"}
	e.srv.config = cfg
	e.seedKey()
	e.postFP = func() (string, error) { return strings.Repeat("0", 64), nil }
	fp1, _ := e.srv.addCert(t, testFQDN, inWindowTime.Add(90*24*time.Hour))
	e.srv.assign(Assignment{FQDN: testFQDN, Fingerprint: fp1})
	if err := e.run(false); err != nil {
		t.Fatal(err)
	}
	if res := e.srv.lastResult(t); res.Status != StatusPostCheckMismatch {
		t.Fatalf("result = %+v", res)
	}
	if e.loadState().Domains[testFQDN].Fingerprint != fp1 {
		t.Fatal("applied fingerprint not recorded")
	}
}

func TestRestartCommand(t *testing.T) {
	tests := []struct {
		name string
		r    agentcfg.Restart
		want string
		err  bool
	}{
		{"systemd restart", agentcfg.Restart{Type: "systemd", Name: "nginx"}, "systemctl restart nginx", false},
		{"systemd reload", agentcfg.Restart{Type: "systemd", Name: "nginx", ReloadOnly: true}, "systemctl reload nginx", false},
		{"docker", agentcfg.Restart{Type: "docker", Name: "web"}, "docker restart web", false},
		{"docker exec reload", agentcfg.Restart{Type: "docker", Name: "web", ReloadOnly: true, Command: []string{"nginx", "-s", "reload"}}, "docker exec web nginx -s reload", false},
		{"exec", agentcfg.Restart{Type: "exec", Command: []string{"/usr/local/bin/reload", "{domain}"}}, "/usr/local/bin/reload app.example.com", false},
		{"systemd no name", agentcfg.Restart{Type: "systemd"}, "", true},
		{"unknown", agentcfg.Restart{Type: "x"}, "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			argv, err := restartCommand(tc.r, testFQDN)
			if (err != nil) != tc.err || strings.Join(argv, " ") != tc.want {
				t.Fatalf("got %v, %v", argv, err)
			}
		})
	}
}

func TestStaleStateReappliesWhenFilesMissing(t *testing.T) {
	e := newEnv(t)
	e.seedKey()
	fp1, b1 := e.srv.addCert(t, testFQDN, inWindowTime.Add(90*24*time.Hour))
	e.srv.assign(Assignment{FQDN: testFQDN, Fingerprint: fp1})
	if err := e.run(false); err != nil {
		t.Fatal(err)
	}
	n := e.srv.resultCount()
	// Operator removes agent-managed tree but leaves state.json claiming fp1.
	if err := os.RemoveAll(filepath.Join(e.certRoot, testFQDN)); err != nil {
		t.Fatal(err)
	}
	st := e.loadState()
	if st.Domains[testFQDN].Fingerprint != fp1 {
		t.Fatal("precondition: state still records fingerprint")
	}
	if err := e.run(false); err != nil {
		t.Fatal(err)
	}
	if e.srv.resultCount() != n+1 {
		t.Fatal("expected re-apply after files disappeared")
	}
	got, err := os.ReadFile(filepath.Join(e.certRoot, testFQDN, "current", "fullchain.pem"))
	if err != nil || string(got) != b1.Cert+b1.Chain {
		t.Fatalf("files not restored: %v", err)
	}
}

func TestLostStateReconcilesWithInstalledFiles(t *testing.T) {
	e := newEnv(t)
	e.seedKey()
	fp1, _ := e.srv.addCert(t, testFQDN, inWindowTime.Add(90*24*time.Hour))
	e.srv.assign(Assignment{FQDN: testFQDN, Fingerprint: fp1})
	if err := e.run(false); err != nil {
		t.Fatal(err)
	}
	calls := len(e.runner.Calls())
	if err := os.WriteFile(filepath.Join(e.stateDir, stateFileName), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Lost domain state (key reseeded): must reconcile from disk.
	e.seedKey()
	if err := e.run(false); err != nil {
		t.Fatal(err)
	}
	if len(e.runner.Calls()) != calls {
		t.Fatal("needless restart after state loss")
	}
	if e.loadState().Domains[testFQDN].Fingerprint != fp1 {
		t.Fatal("fingerprint not reconciled from disk")
	}
}

func TestBackoffBounds(t *testing.T) {
	for n := 1; n < 20; n++ {
		d := backoff(n)
		if d < time.Duration(float64(backoffMin)*0.89) || d > time.Duration(float64(backoffMax)*1.11) {
			t.Fatalf("backoff(%d) = %v out of bounds", n, d)
		}
	}
}
