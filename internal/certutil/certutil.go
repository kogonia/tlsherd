package certutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// ErrKeyMismatch is returned by ParseBundle when the private key does not match the leaf certificate.
var ErrKeyMismatch = errors.New("private key does not match certificate")

type Parsed struct {
	Leaf         *x509.Certificate
	Chain        []*x509.Certificate
	PrivateKey   crypto.PrivateKey
	Fingerprint  string
	SANs         []string
	SubjectCN    string
	IssuerCN     string
	Serial       string
	NotBefore    time.Time
	NotAfter     time.Time
	KeyAlgo      string
	KeyBits      int
	CertPEM      []byte
	KeyPEM       []byte
	ChainPEM     []byte
	ChainWarning string
	// Soft validity flags: ParseBundle does not reject these; callers may
	// require explicit confirmation before installing.
	Expired     bool
	NotYetValid bool
}

func ParseBundle(certPEM, keyPEM, chainPEM []byte, now time.Time) (*Parsed, error) {
	leaf, fromCert, err := parseCerts(certPEM)
	if err != nil {
		return nil, fmt.Errorf("cert: %w", err)
	}
	// Fullchain PEMs are common (leaf + intermediates in the cert file).
	chain := append([]*x509.Certificate{}, fromCert...)
	if len(chainPEM) > 0 {
		extra, _, err := parseAllCerts(chainPEM)
		if err != nil {
			return nil, fmt.Errorf("chain: %w", err)
		}
		chain = append(chain, extra...)
	}
	key, err := parsePrivateKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("key: %w", err)
	}
	if err := keysMatch(leaf, key); err != nil {
		return nil, err
	}
	expired := leaf.NotAfter.Before(now)
	notYet := leaf.NotBefore.After(now.Add(24 * time.Hour))
	fp := Fingerprint(leaf.Raw)
	sans := collectSANs(leaf)
	algo, bits := keyInfo(key)
	warn := ""
	if len(chain) == 0 {
		warn = "chain empty"
	} else if err := leaf.CheckSignatureFrom(chain[0]); err != nil {
		warn = "chain issuer mismatch: " + err.Error()
	}
	return &Parsed{
		Leaf:         leaf,
		Chain:        chain,
		PrivateKey:   key,
		Fingerprint:  fp,
		SANs:         sans,
		SubjectCN:    leaf.Subject.CommonName,
		IssuerCN:     leaf.Issuer.CommonName,
		Serial:       leaf.SerialNumber.Text(16),
		NotBefore:    leaf.NotBefore.UTC(),
		NotAfter:     leaf.NotAfter.UTC(),
		KeyAlgo:      algo,
		KeyBits:      bits,
		CertPEM:      encodeCertPEM(leaf),
		KeyPEM:       keyPEM,
		ChainPEM:     encodeCertsPEM(chain),
		ChainWarning: warn,
		Expired:      expired,
		NotYetValid:  notYet,
	}, nil
}

func encodeCertPEM(c *x509.Certificate) []byte {
	if c == nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func encodeCertsPEM(certs []*x509.Certificate) []byte {
	if len(certs) == 0 {
		return nil
	}
	var out []byte
	for _, c := range certs {
		out = append(out, encodeCertPEM(c)...)
	}
	return out
}

func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func CoversDomain(sans []string, cn, fqdn string) bool {
	fqdn = strings.ToLower(strings.TrimSuffix(fqdn, "."))
	names := append([]string{}, sans...)
	if len(names) == 0 && cn != "" {
		names = append(names, cn)
	}
	for _, n := range names {
		n = strings.ToLower(strings.TrimSuffix(n, "."))
		if matchDNS(n, fqdn) {
			return true
		}
	}
	return false
}

func matchDNS(pattern, name string) bool {
	if pattern == name {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // .example.com
		if !strings.HasSuffix(name, suffix) {
			return false
		}
		prefix := strings.TrimSuffix(name, suffix)
		return prefix != "" && !strings.Contains(prefix, ".")
	}
	return false
}

func collectSANs(c *x509.Certificate) []string {
	out := make([]string, 0, len(c.DNSNames))
	out = append(out, c.DNSNames...)
	return out
}

func parseCerts(pemBytes []byte) (*x509.Certificate, []*x509.Certificate, error) {
	all, restPEM, err := parseAllCerts(pemBytes)
	if err != nil {
		return nil, nil, err
	}
	_ = restPEM
	if len(all) == 0 {
		return nil, nil, fmt.Errorf("no certificates found")
	}
	return all[0], all[1:], nil
}

func parseAllCerts(pemBytes []byte) ([]*x509.Certificate, []byte, error) {
	var certs []*x509.Certificate
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, err
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, nil, fmt.Errorf("no certificates found")
	}
	return certs, rest, nil
}

func parsePrivateKey(pemBytes []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("unsupported private key")
}

func keysMatch(cert *x509.Certificate, key crypto.PrivateKey) error {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok || pub.N.Cmp(k.N) != 0 || pub.E != k.E {
			return ErrKeyMismatch
		}
	case *ecdsa.PrivateKey:
		pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok || pub.X.Cmp(k.X) != 0 || pub.Y.Cmp(k.Y) != 0 {
			return ErrKeyMismatch
		}
	case ed25519.PrivateKey:
		pub, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok || !pub.Equal(k.Public().(ed25519.PublicKey)) {
			return ErrKeyMismatch
		}
	default:
		return fmt.Errorf("unsupported key type")
	}
	return nil
}

func keyInfo(key crypto.PrivateKey) (string, int) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return "RSA", k.N.BitLen()
	case *ecdsa.PrivateKey:
		return "ECDSA", k.Curve.Params().BitSize
	case ed25519.PrivateKey:
		return "Ed25519", 255
	default:
		return "unknown", 0
	}
}

// SerialString is a helper for big.Int serials.
func SerialString(n *big.Int) string {
	if n == nil {
		return ""
	}
	return n.Text(16)
}
