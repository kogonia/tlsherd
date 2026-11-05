package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kogonia/tlsherd/internal/agentcfg"
	"github.com/kogonia/tlsherd/internal/config"
)

const testFQDN = "app.example.com"

var (
	inWindowTime  = time.Date(2026, 11, 4, 3, 0, 0, 0, time.UTC)  // inside default 02:00-04:00
	outWindowTime = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC) // outside
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time { return c.t }

type fakeRunner struct {
	mu    sync.Mutex
	calls []string
	fn    func(name string, args []string) error
}

func (r *fakeRunner) Run(_ context.Context, name string, args ...string) (string, string, error) {
	r.mu.Lock()
	r.calls = append(r.calls, strings.Join(append([]string{name}, args...), " "))
	fn := r.fn
	r.mu.Unlock()
	if fn != nil {
		if err := fn(name, args); err != nil {
			return "", "boom", err
		}
	}
	return "", "", nil
}

func (r *fakeRunner) Calls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

func (r *fakeRunner) Count(prefix string) int {
	n := 0
	for _, c := range r.Calls() {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

type certReq struct{ FP, IfNoneMatch string }

type fakeServer struct {
	*httptest.Server
	mu            sync.Mutex
	enrollStatus  string
	apiKey        string
	config        agentcfg.Config
	configVersion int64
	assigned      []Assignment
	bundles       map[string]CertBundle
	results       []ApplyResult
	certReqs      []certReq
	polls         int
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	s := &fakeServer{apiKey: "key-1", bundles: map[string]CertBundle{}, enrollStatus: EnrollPending}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/agent/enroll", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		resp := EnrollResponse{Status: s.enrollStatus}
		if s.enrollStatus == EnrollAccepted {
			cfg := s.config
			resp.APIKey, resp.Config, resp.ConfigVersion = s.apiKey, &cfg, s.configVersion
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	auth := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("Authorization") != "Bearer "+s.apiKey {
			http.Error(w, "no", http.StatusUnauthorized)
			return false
		}
		return true
	}
	mux.HandleFunc("POST /api/v1/agent/poll", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if !auth(w, r) {
			return
		}
		var req PollRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		s.polls++
		resp := PollResponse{ConfigVersion: s.configVersion, Config: s.config, Domains: s.assigned}
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("GET /api/v1/agent/certs/{fp}", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if !auth(w, r) {
			return
		}
		fp := r.PathValue("fp")
		inm := r.Header.Get("If-None-Match")
		s.certReqs = append(s.certReqs, certReq{fp, inm})
		b, ok := s.bundles[fp]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("ETag", `"`+fp+`"`)
		if strings.Trim(inm, `"`) == fp {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_ = json.NewEncoder(w).Encode(b)
	})
	mux.HandleFunc("POST /api/v1/agent/apply-result", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if !auth(w, r) {
			return
		}
		var res ApplyResult
		_ = json.NewDecoder(r.Body).Decode(&res)
		s.results = append(s.results, res)
		w.WriteHeader(http.StatusNoContent)
	})
	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

func (s *fakeServer) addCert(t *testing.T, fqdn string, notAfter time.Time) (fp string, b CertBundle) {
	t.Helper()
	b, fp = makeCert(t, fqdn, inWindowTime.Add(-time.Hour), notAfter)
	s.mu.Lock()
	s.bundles[fp] = b
	s.mu.Unlock()
	return fp, b
}

func (s *fakeServer) assign(asgs ...Assignment) {
	s.mu.Lock()
	s.assigned = asgs
	s.mu.Unlock()
}

func (s *fakeServer) lastResult(t *testing.T) ApplyResult {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.results) == 0 {
		t.Fatal("no apply-result reported")
	}
	return s.results[len(s.results)-1]
}

func (s *fakeServer) resultCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.results)
}

func makeCert(t *testing.T, fqdn string, notBefore, notAfter time.Time) (CertBundle, string) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"},
		NotBefore: notBefore, NotAfter: notAfter.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: fqdn}, DNSNames: []string{fqdn},
		NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return CertBundle{
		Cert:  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		Key:   string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})),
		Chain: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
	}, hex.EncodeToString(sum[:])
}

type env struct {
	t        *testing.T
	srv      *fakeServer
	clock    *fakeClock
	runner   *fakeRunner
	certRoot string
	stateDir string
	postFP   func() (string, error)
}

func testConfig() agentcfg.Config {
	cfg := agentcfg.Default()
	cfg.Verify.Command = []string{"nginx", "-t"}
	cfg.Verify.Timeout = agentcfg.Duration(5 * time.Second)
	cfg.Restart = agentcfg.Restart{Type: "systemd", Name: "nginx"}
	return cfg
}

func mustParseConfig(t *testing.T, raw string) agentcfg.Config {
	t.Helper()
	cfg, err := agentcfg.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{
		t:        t,
		srv:      newFakeServer(t),
		clock:    &fakeClock{t: inWindowTime},
		runner:   &fakeRunner{},
		certRoot: filepath.Join(t.TempDir(), "certs"),
		stateDir: filepath.Join(t.TempDir(), "state"),
	}
	e.srv.config, e.srv.configVersion = testConfig(), 1
	return e
}

// seedKey stores an API key in state so the agent goes straight to polling.
func (e *env) seedKey() {
	e.t.Helper()
	if err := saveState(e.stateDir, State{APIKey: e.srv.apiKey}); err != nil {
		e.t.Fatal(err)
	}
}

// run builds a fresh agent (state reloaded from disk) and executes one cycle.
func (e *env) run(dry bool) error {
	e.t.Helper()
	opts := Options{
		Bootstrap: config.AgentBootstrap{ServerURL: e.srv.URL, CertRoot: e.certRoot, StateDir: e.stateDir, Once: true, DryRun: dry},
		Clock:     e.clock,
		Runner:    e.runner,
		Sleep:     func(context.Context, time.Duration) error { return nil },
	}
	if e.postFP != nil {
		opts.PostCheck = func(context.Context, string, string) (string, error) { return e.postFP() }
	}
	a, err := New(opts)
	if err != nil {
		e.t.Fatal(err)
	}
	return a.Run(context.Background())
}

func (e *env) current(file string) string {
	return filepath.Join(e.certRoot, testFQDN, "current", file)
}

func fileSHA(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (e *env) loadState() State {
	e.t.Helper()
	st, _, err := loadState(e.stateDir)
	if err != nil {
		e.t.Fatal(err)
	}
	return st
}
