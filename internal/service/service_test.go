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
	"path/filepath"
	"testing"
	"time"

	"github.com/kogonia/tlsherd/internal/certutil"
	"github.com/kogonia/tlsherd/internal/domain"
)

func TestNormalizeFQDN(t *testing.T) {
	for in, want := range map[string]string{"Example.COM.": "example.com", " a-b.example.org ": "a-b.example.org"} {
		got, err := NormalizeFQDN(in)
		if err != nil || got != want {
			t.Errorf("NormalizeFQDN(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "../etc", "a/b.example.com", "-a.example.com", "exa mple.com", "*.example.com"} {
		if _, err := NormalizeFQDN(bad); !errors.Is(err, domain.ErrInvalid) {
			t.Errorf("NormalizeFQDN(%q) err = %v, want ErrInvalid", bad, err)
		}
	}
}

func TestPublicMessageHidesInternals(t *testing.T) {
	internal := errors.New("pq: connection refused to 10.0.0.5")
	if got := PublicMessage(internal); got != "internal error" {
		t.Fatalf("got %q", got)
	}
	wrapped := errors.Join(domain.ErrNotFound, errors.New("SELECT secret FROM users"))
	if got := PublicMessage(wrapped); got != "not found" {
		t.Fatalf("got %q", got)
	}
	if got := PublicMessage(invalidf("login is bad")); got != "login is bad" {
		t.Fatalf("got %q", got)
	}
}

func TestDomainMismatchErrorWrapsSentinel(t *testing.T) {
	var err error = &DomainMismatchError{RequestedDomain: "domain.com"}
	if !errors.Is(err, domain.ErrDomainMismatch) {
		t.Fatal("must wrap domain.ErrDomainMismatch")
	}
}

func testBundle(t *testing.T) *certutil.Parsed {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com", "*.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(48 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	p, err := certutil.ParseBundle(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCertFilesAreContentAddressedAndLinked(t *testing.T) {
	s := &Services{DataDir: t.TempDir()}
	p := testBundle(t)

	paths, err := s.writeCertFiles(p)
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(paths.Key)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v mode=%v", err, st)
	}
	if want := filepath.Join(s.DataDir, "certs", p.Fingerprint, "key.pem"); paths.Key != want {
		t.Fatalf("key path %s, want %s", paths.Key, want)
	}

	// Second write of the same certificate must not touch the stored key.
	before, _ := os.ReadFile(paths.Key)
	p2 := *p
	p2.KeyPEM = []byte("different encoding")
	if _, err := s.writeCertFiles(&p2); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(paths.Key)
	if string(before) != string(after) {
		t.Fatal("immutable certificate directory was overwritten")
	}

	if err := s.linkDomainCurrent("example.com", p.Fingerprint); err != nil {
		t.Fatal(err)
	}
	if err := s.linkDomainCurrent("example.com", p.Fingerprint); err != nil {
		t.Fatalf("relinking must be idempotent: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(s.DataDir, "domains", "example.com", "current", "cert.pem"))
	if err != nil || len(got) == 0 {
		t.Fatalf("read through symlink: %v", err)
	}
	if _, err := s.readCertFile("../../etc/passwd", "x"); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("path traversal must be rejected, got %v", err)
	}
}
