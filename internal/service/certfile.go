package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"

	"github.com/kogonia/tlsherd/internal/certutil"
)

// On-disk layout (see plan "Файлы: сервер"):
//
//	<data_dir>/certs/<sha256>/{cert.pem,key.pem,chain.pem,meta.json}   immutable
//	<data_dir>/domains/<fqdn>/current -> ../../certs/<sha256>

const (
	certFileName  = "cert.pem"
	keyFileName   = "key.pem"
	chainFileName = "chain.pem"
	metaFileName  = "meta.json"

	dirMode  fs.FileMode = 0o750
	keyMode  fs.FileMode = 0o600
	certMode fs.FileMode = 0o644
)

var (
	fingerprintRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
	fqdnRe        = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
)

// ValidFingerprint reports whether fp is a lowercase hex SHA-256 digest.
func ValidFingerprint(fp string) bool { return fingerprintRe.MatchString(fp) }

func (s *Services) certsRoot() string   { return filepath.Join(s.DataDir, "certs") }
func (s *Services) domainsRoot() string { return filepath.Join(s.DataDir, "domains") }

func (s *Services) certDir(fp string) (string, error) {
	if !ValidFingerprint(fp) {
		return "", invalidf("invalid fingerprint")
	}
	return filepath.Join(s.certsRoot(), fp), nil
}

func (s *Services) domainDir(fqdn string) (string, error) {
	if len(fqdn) > 253 || !fqdnRe.MatchString(fqdn) {
		return "", invalidf("invalid domain name")
	}
	return filepath.Join(s.domainsRoot(), fqdn), nil
}

type certMeta struct {
	Fingerprint string   `json:"fingerprint_sha256"`
	SubjectCN   string   `json:"subject_cn"`
	SANs        []string `json:"sans"`
	IssuerCN    string   `json:"issuer_cn"`
	Serial      string   `json:"serial"`
	NotBefore   string   `json:"not_before"`
	NotAfter    string   `json:"not_after"`
	KeyAlgo     string   `json:"key_algo"`
	KeyBits     int      `json:"key_bits"`
}

// storedCertPaths are the absolute paths of a content-addressed certificate directory.
type storedCertPaths struct{ Cert, Key, Chain string }

// writeCertFiles stores the bundle under certs/<fingerprint>. The directory is
// immutable: if it already exists it is reused untouched, so a private key is
// never duplicated or overwritten. The write is atomic (temp dir + rename)
// and fsynced.
//
// A bundle without a private key (p.KeyPEM empty, e.g. CA or allowed_client
// managed certificates) is stored cert-only: no key file is written and an
// existing certificate directory is enough. If the directory exists without a
// key and a key is supplied later, the key is added to it. The returned Key
// path is empty when the directory holds no key.
func (s *Services) writeCertFiles(p *certutil.Parsed) (storedCertPaths, error) {
	dir, err := s.certDir(p.Fingerprint)
	if err != nil {
		return storedCertPaths{}, err
	}
	paths := storedCertPaths{
		Cert:  filepath.Join(dir, certFileName),
		Key:   filepath.Join(dir, keyFileName),
		Chain: filepath.Join(dir, chainFileName),
	}
	hasKey := len(p.KeyPEM) > 0
	hasChain := len(p.ChainPEM) > 0
	if fileExists(paths.Cert) {
		switch {
		case fileExists(paths.Key):
			if !hasChain {
				paths.Chain = ""
			}
			return paths, nil
		case !hasKey:
			paths.Key = ""
			if !hasChain {
				paths.Chain = ""
			}
			return paths, nil
		default:
			if err := writeFileSync(paths.Key, p.KeyPEM, keyMode); err != nil {
				return storedCertPaths{}, err
			}
			if !hasChain {
				paths.Chain = ""
			}
			return paths, nil
		}
	}
	if !hasKey {
		paths.Key = ""
	}
	if !hasChain {
		paths.Chain = ""
	}
	root := s.certsRoot()
	if err := os.MkdirAll(root, dirMode); err != nil {
		return storedCertPaths{}, fmt.Errorf("create certs dir: %w", err)
	}
	tmp, err := os.MkdirTemp(root, ".tmp-")
	if err != nil {
		return storedCertPaths{}, fmt.Errorf("create temp cert dir: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(tmp)
		}
	}()
	meta, err := json.MarshalIndent(certMeta{
		Fingerprint: p.Fingerprint, SubjectCN: p.SubjectCN, SANs: p.SANs, IssuerCN: p.IssuerCN,
		Serial: p.Serial, NotBefore: p.NotBefore.Format("2006-01-02T15:04:05Z"),
		NotAfter: p.NotAfter.Format("2006-01-02T15:04:05Z"), KeyAlgo: p.KeyAlgo, KeyBits: p.KeyBits,
	}, "", "  ")
	if err != nil {
		return storedCertPaths{}, fmt.Errorf("encode cert meta: %w", err)
	}
	files := []struct {
		name string
		data []byte
		mode fs.FileMode
	}{
		{certFileName, p.CertPEM, certMode},
		{metaFileName, meta, certMode},
	}
	if hasChain {
		files = append(files, struct {
			name string
			data []byte
			mode fs.FileMode
		}{chainFileName, p.ChainPEM, certMode})
	}
	if hasKey {
		files = append(files, struct {
			name string
			data []byte
			mode fs.FileMode
		}{keyFileName, p.KeyPEM, keyMode})
	}
	for _, f := range files {
		if err := writeFileSync(filepath.Join(tmp, f.name), f.data, f.mode); err != nil {
			return storedCertPaths{}, err
		}
	}
	if err := os.Chmod(tmp, dirMode); err != nil {
		return storedCertPaths{}, fmt.Errorf("chmod cert dir: %w", err)
	}
	if err := syncDir(tmp); err != nil {
		return storedCertPaths{}, err
	}
	if err := os.Rename(tmp, dir); err != nil {
		// A concurrent upload of the same certificate won the race.
		if fileExists(paths.Cert) && (!hasKey || fileExists(paths.Key)) {
			return paths, nil
		}
		return storedCertPaths{}, fmt.Errorf("publish cert dir: %w", err)
	}
	cleanup = false
	if err := syncDir(root); err != nil {
		return storedCertPaths{}, err
	}
	return paths, nil
}

// readCertFile reads one PEM file of a stored certificate.
func (s *Services) readCertFile(fp, name string) ([]byte, error) {
	dir, err := s.certDir(fp)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, notFoundf("certificate file is missing on the server")
		}
		return nil, fmt.Errorf("read certificate file: %w", err)
	}
	return b, nil
}

// removeCertFiles deletes the stored directory of a certificate.
func (s *Services) removeCertFiles(fp string) error {
	dir, err := s.certDir(fp)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("remove certificate files: %w", err)
	}
	return nil
}

// linkDomainCurrent atomically points domains/<fqdn>/current at certs/<fp>.
func (s *Services) linkDomainCurrent(fqdn, fp string) error {
	dir, err := s.domainDir(fqdn)
	if err != nil {
		return err
	}
	if !ValidFingerprint(fp) {
		return invalidf("invalid fingerprint")
	}
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return fmt.Errorf("create domain dir: %w", err)
	}
	link := filepath.Join(dir, "current")
	tmp := filepath.Join(dir, ".current.tmp")
	_ = os.Remove(tmp)
	if err := os.Symlink(filepath.Join("..", "..", "certs", fp), tmp); err != nil {
		return fmt.Errorf("create symlink: %w", err)
	}
	if err := os.Rename(tmp, link); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("activate symlink: %w", err)
	}
	return nil
}

// removeDomainDir removes domains/<fqdn> (symlinks only; certificate files stay).
func (s *Services) removeDomainDir(fqdn string) error {
	dir, err := s.domainDir(fqdn)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("remove domain dir: %w", err)
	}
	return nil
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
}

func writeFileSync(path string, data []byte, mode fs.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", filepath.Base(path), err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return fmt.Errorf("chmod %s: %w", filepath.Base(path), err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync %s: %w", filepath.Base(path), err)
	}
	return f.Close()
}

func syncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open dir for sync: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync dir: %w", err)
	}
	return nil
}
