package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/kogonia/tlsherd/internal/certutil"
	"github.com/kogonia/tlsherd/internal/domain"
)

func newTestCA(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, key
}

func newTestLeaf(t *testing.T, cn string, ca *x509.Certificate, caKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: cn}, DNSNames: []string{cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(12 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCertChainsTo(t *testing.T) {
	root, rootKey := newTestCA(t, "root")
	other, _ := newTestCA(t, "other")
	leaf := newTestLeaf(t, "a.example.com", root, rootKey)

	if !certChainsTo(leaf, nil, []*x509.Certificate{root}) {
		t.Fatal("leaf signed directly by the CA must match")
	}
	if certChainsTo(leaf, nil, []*x509.Certificate{other}) {
		t.Fatal("leaf must not match an unrelated CA")
	}
	if !certChainsTo(root, nil, []*x509.Certificate{root}) {
		t.Fatal("a certificate equal to the anchor must match")
	}
	if caMatches([]linkedCA{{Name: "o", Anchors: []*x509.Certificate{other}}}, leaf, nil) {
		t.Fatal("unrelated CA must not match")
	}
	if !caMatches([]linkedCA{{Name: "r", Anchors: []*x509.Certificate{root}}}, leaf, nil) {
		t.Fatal("linked CA must match")
	}
	// leaf <- inter, inter <- root: the chain bridges to the anchor.
	inter, interKey := newTestCA(t, "inter")
	interLeaf := newTestLeaf(t, "b.example.com", inter, interKey)
	if certChainsTo(interLeaf, []*x509.Certificate{inter}, []*x509.Certificate{root}) {
		t.Fatal("self-signed intermediate must not chain to an unrelated root")
	}
	if !certChainsTo(interLeaf, []*x509.Certificate{inter}, []*x509.Certificate{inter}) {
		t.Fatal("leaf must chain to its intermediate anchor")
	}
}

func TestWriteCertFilesCertOnly(t *testing.T) {
	s := &Services{DataDir: t.TempDir()}
	ca, _ := newTestCA(t, "root")
	p, err := certutil.ParseCertOnly(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	paths, err := s.writeCertFiles(p)
	if err != nil {
		t.Fatal(err)
	}
	if paths.Key != "" {
		t.Fatalf("cert-only bundle must have no key path, got %q", paths.Key)
	}
	if _, err := os.Stat(paths.Cert); err != nil {
		t.Fatal(err)
	}
	if _, err := s.readCertFile(p.Fingerprint, keyFileName); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("key file must not exist, got %v", err)
	}
	if _, err := s.writeCertFiles(p); err != nil {
		t.Fatalf("second cert-only write must reuse the directory: %v", err)
	}
	stored, err := s.loadStoredCert(p.Fingerprint)
	if err != nil || stored.Fingerprint != p.Fingerprint {
		t.Fatalf("loadStoredCert: %v", err)
	}
}

func TestIdentityChanges(t *testing.T) {
	root, rootKey := newTestCA(t, "root")
	leaf := newTestLeaf(t, "a.example.com", root, rootKey)
	p, err := certutil.ParseCertOnly(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}), nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	spki, _ := certutil.PublicKeyFingerprint(p.Leaf)
	same := &domain.Certificate{SubjectCN: p.SubjectCN, SANs: p.SANs, IssuerCN: p.IssuerCN}
	if got := identityChanges(same, spki, p, spki); len(got) != 0 {
		t.Fatalf("unexpected problems: %v", got)
	}
	diff := &domain.Certificate{SubjectCN: "b", SANs: []string{"b"}, IssuerCN: "x"}
	got := identityChanges(diff, "other", p, spki)
	codes := map[string]bool{}
	for _, pr := range got {
		codes[pr.Code] = true
	}
	for _, c := range []string{CertProblemCNChanged, CertProblemSANChanged, CertProblemIssuerChanged, CertProblemKeyChanged} {
		if !codes[c] {
			t.Errorf("missing problem %s in %v", c, got)
		}
	}
}

func TestManagedNameAndEndpointInputs(t *testing.T) {
	for _, ok := range []string{"a", "partner-client", "x1"} {
		if !managedNameRe.MatchString(ok) {
			t.Errorf("%q must be valid", ok)
		}
	}
	for _, bad := range []string{"", "-a", "a-", "A", "a.b", "a/b", "../x"} {
		if managedNameRe.MatchString(bad) {
			t.Errorf("%q must be invalid", bad)
		}
	}
	if got, err := normalizeDialAddr(" 10.0.0.1 "); err != nil || got != "10.0.0.1" {
		t.Errorf("dial addr: %q %v", got, err)
	}
	for _, bad := range []string{"host:443", "a b", "[::1]"} {
		if _, err := normalizeDialAddr(bad); !errors.Is(err, domain.ErrInvalid) {
			t.Errorf("dial addr %q must be invalid, got %v", bad, err)
		}
	}
	if got, err := normalizeCheckInterval("90s"); err != nil || got != "1m30s" {
		t.Errorf("interval: %q %v", got, err)
	}
	if _, err := normalizeCheckInterval("1s"); !errors.Is(err, domain.ErrInvalid) {
		t.Errorf("1s interval must be invalid, got %v", err)
	}
	if d := endpointInterval(domain.ServerEndpoint{CheckInterval: "2m0s"}, time.Hour); d != 2*time.Minute {
		t.Errorf("endpoint interval override: %v", d)
	}
}
