package agent

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kogonia/tlsherd/internal/agentcfg"
	"github.com/kogonia/tlsherd/internal/certutil"
)

// layout is the on-disk tree of one domain:
//
//	<cert_root>/<fqdn>/current -> versions/<fingerprint>
//	<cert_root>/<fqdn>/versions/<fingerprint>/{cert,key,chain,fullchain}.pem
//	<cert_root>/<fqdn>/backups/<ts>/...
type layout struct {
	base, versions, backups, current string
}

func newLayout(certRoot, fqdn string) (layout, error) {
	if fqdn == "" || fqdn == "." || fqdn == ".." || filepath.Base(fqdn) != fqdn || strings.ContainsAny(fqdn, `/\`) {
		return layout{}, fmt.Errorf("invalid domain name %q", fqdn)
	}
	base, err := agentcfg.JoinUnderRoot(certRoot, fqdn)
	if err != nil {
		return layout{}, err
	}
	return layout{
		base:     base,
		versions: filepath.Join(base, "versions"),
		backups:  filepath.Join(base, "backups"),
		current:  filepath.Join(base, "current"),
	}, nil
}

func (l layout) versionDir(fp string) string { return filepath.Join(l.versions, fp) }

func validFingerprint(fp string) bool {
	if len(fp) != 64 {
		return false
	}
	for _, r := range fp {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

// installSpec describes one install: files, modes and targets.
type installSpec struct {
	fqdn        string
	fingerprint string
	mode        string // symlink|copy
	inst        agentcfg.Install
	extra       map[string]string // file name in version dir -> extra absolute target path
	cert, key   []byte
	chain       []byte
	fullchain   []byte // leaf + intermediates (always set; equals leaf when chain empty)
}

func (s installSpec) names() (cert, key, chain, fullchain string) {
	return orDefault(s.inst.CertName, "cert.pem"),
		orDefault(s.inst.KeyName, "key.pem"),
		orDefault(s.inst.ChainName, "chain.pem"),
		orDefault(s.inst.FullchainName, "fullchain.pem")
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func parseMode(s string, def os.FileMode) os.FileMode {
	if s == "" {
		return def
	}
	v, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return def
	}
	return os.FileMode(v) & os.ModePerm
}

// targets lists every path the install may modify (snapshotted by backup).
func (s installSpec) targets(l layout) []string {
	out := []string{l.current}
	cn, kn, hn, fn := s.names()
	for _, name := range []string{cn, kn, hn, fn} {
		if p, ok := s.extra[name]; ok {
			out = append(out, p)
		}
	}
	return out
}

func (s installSpec) fileSet() []struct {
	name string
	data []byte
	mode os.FileMode
} {
	cn, kn, hn, fn := s.names()
	certMode := parseMode(s.inst.CertMode, 0o644)
	set := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{cn, s.cert, certMode},
		{kn, s.key, parseMode(s.inst.KeyMode, 0o600)},
		{fn, s.fullchain, certMode},
	}
	if len(s.chain) > 0 {
		set = append(set, struct {
			name string
			data []byte
			mode os.FileMode
		}{hn, s.chain, certMode})
	}
	return set
}

// writeVersion materialises versions/<fingerprint>/ without touching active files.
func writeVersion(l layout, s installSpec) (string, error) {
	dir := l.versionDir(s.fingerprint)
	dirMode := parseMode(s.inst.DirMode, 0o750)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return "", fmt.Errorf("create version dir: %w", err)
	}
	for _, d := range []string{l.base, l.versions, dir} {
		if err := os.Chmod(d, dirMode); err != nil {
			return "", fmt.Errorf("chmod %s: %w", d, err)
		}
	}
	for _, f := range s.fileSet() {
		p := filepath.Join(dir, f.name)
		if err := writeFileAtomic(p, f.data, f.mode); err != nil {
			return "", fmt.Errorf("write %s: %w", f.name, err)
		}
	}
	// A stale chain from an earlier staging of the same fingerprint must not linger.
	if len(s.chain) == 0 {
		_, _, hn, _ := s.names()
		_ = os.Remove(filepath.Join(dir, hn))
	}
	if err := chownTree(s.inst.Owner, dir); err != nil {
		return "", err
	}
	return dir, nil
}

// switchActive points current (and optional extra targets) at the version.
func switchActive(l layout, s installSpec) error {
	dirMode := parseMode(s.inst.DirMode, 0o750)
	verDir := l.versionDir(s.fingerprint)
	cn, kn, hn, fn := s.names()
	if s.mode == "copy" {
		if fi, err := os.Lstat(l.current); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			if err := os.Remove(l.current); err != nil {
				return fmt.Errorf("remove current link: %w", err)
			}
		}
		if err := os.MkdirAll(l.current, dirMode); err != nil {
			return fmt.Errorf("create current dir: %w", err)
		}
		for _, f := range s.fileSet() {
			if err := writeFileAtomic(filepath.Join(l.current, f.name), f.data, f.mode); err != nil {
				return fmt.Errorf("copy %s: %w", f.name, err)
			}
		}
		if len(s.chain) == 0 {
			_ = os.Remove(filepath.Join(l.current, hn))
		}
		if err := chownTree(s.inst.Owner, l.current); err != nil {
			return err
		}
		for _, f := range s.fileSet() {
			if p, ok := s.extra[f.name]; ok {
				if err := os.MkdirAll(filepath.Dir(p), dirMode); err != nil {
					return err
				}
				if err := writeFileAtomic(p, f.data, f.mode); err != nil {
					return fmt.Errorf("copy %s: %w", p, err)
				}
			}
		}
		return nil
	}

	if fi, err := os.Lstat(l.current); err == nil && fi.IsDir() {
		if err := os.RemoveAll(l.current); err != nil { // copy-mode leftovers; backed up already
			return fmt.Errorf("remove current dir: %w", err)
		}
	}
	if err := replaceSymlink(l.current, filepath.Join("versions", s.fingerprint)); err != nil {
		return fmt.Errorf("switch current: %w", err)
	}
	for _, name := range []string{cn, kn, hn, fn} {
		p, ok := s.extra[name]
		if !ok || (name == hn && len(s.chain) == 0) {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(p), dirMode); err != nil {
			return err
		}
		if err := replaceSymlink(p, filepath.Join(verDir, name)); err != nil {
			return fmt.Errorf("link %s: %w", p, err)
		}
	}
	return nil
}

// replaceSymlink atomically (re)points path at target.
func replaceSymlink(path, target string) error {
	tmp := filepath.Join(filepath.Dir(path), fmt.Sprintf(".%s.tmp-%x", filepath.Base(path), rand.Uint64()))
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func chownTree(owner, root string) error {
	if owner == "" {
		return nil
	}
	uname, gname, _ := strings.Cut(owner, ":")
	uid, gid := -1, -1
	if uname != "" {
		u, err := user.Lookup(uname)
		if err != nil {
			return fmt.Errorf("owner: %w", err)
		}
		uid, _ = strconv.Atoi(u.Uid)
		if gname == "" {
			gid, _ = strconv.Atoi(u.Gid)
		}
	}
	if gname != "" {
		g, err := user.LookupGroup(gname)
		if err != nil {
			return fmt.Errorf("owner group: %w", err)
		}
		gid, _ = strconv.Atoi(g.Gid)
	}
	return filepath.WalkDir(root, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(p, uid, gid)
	})
}

// ---- backups ----

const (
	kindAbsent  = "absent"
	kindSymlink = "symlink"
	kindFile    = "file"
	kindDir     = "dir"
)

type manifestEntry struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Target string `json:"target,omitempty"` // symlink target
	Mode   uint32 `json:"mode,omitempty"`
	Store  string `json:"store,omitempty"` // name under files/
}

type manifest struct {
	FQDN        string          `json:"fqdn"`
	Fingerprint string          `json:"previous_fingerprint,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	Entries     []manifestEntry `json:"entries"`
}

// backup snapshots paths into backups/<ts>[-n]/. It is mandatory before any
// active file is modified; an error means nothing was changed.
func backup(l layout, fqdn, prevFP string, paths []string, now time.Time, dirMode os.FileMode) (string, error) {
	if err := os.MkdirAll(l.backups, dirMode); err != nil {
		return "", fmt.Errorf("create backups dir: %w", err)
	}
	ts := now.UTC().Format("20060102T150405Z")
	dir := filepath.Join(l.backups, ts)
	for n := 1; ; n++ {
		err := os.Mkdir(dir, 0o700)
		if err == nil {
			break
		}
		if !errors.Is(err, fs.ErrExist) || n > 1000 {
			return "", fmt.Errorf("create backup dir: %w", err)
		}
		dir = filepath.Join(l.backups, fmt.Sprintf("%s-%d", ts, n))
	}
	m := manifest{FQDN: fqdn, Fingerprint: prevFP, CreatedAt: now.UTC()}
	fail := func(err error) (string, error) {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("backup: %w", err)
	}
	if err := os.Mkdir(filepath.Join(dir, "files"), 0o700); err != nil {
		return fail(err)
	}
	for i, p := range paths {
		e := manifestEntry{Path: p, Store: "e" + strconv.Itoa(i)}
		fi, err := os.Lstat(p)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			e.Kind = kindAbsent
		case err != nil:
			return fail(err)
		case fi.Mode()&os.ModeSymlink != 0:
			e.Kind = kindSymlink
			if e.Target, err = os.Readlink(p); err != nil {
				return fail(err)
			}
		case fi.IsDir():
			e.Kind, e.Mode = kindDir, uint32(fi.Mode().Perm())
			if err := copyDirFlat(p, filepath.Join(dir, "files", e.Store)); err != nil {
				return fail(err)
			}
		case fi.Mode().IsRegular():
			e.Kind, e.Mode = kindFile, uint32(fi.Mode().Perm())
			if err := copyFile(p, filepath.Join(dir, "files", e.Store), fi.Mode().Perm()); err != nil {
				return fail(err)
			}
		default:
			return fail(fmt.Errorf("unsupported file type at %s", p))
		}
		m.Entries = append(m.Entries, e)
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fail(err)
	}
	if err := writeFileAtomic(filepath.Join(dir, "manifest.json"), b, secretFileMode); err != nil {
		return fail(err)
	}
	return dir, nil
}

// restore reverts every snapshotted path to its state recorded in dir.
func restore(dir string) error {
	b, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return fmt.Errorf("read backup manifest: %w", err)
	}
	var m manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return fmt.Errorf("parse backup manifest: %w", err)
	}
	var errs []error
	for _, e := range m.Entries {
		if err := os.RemoveAll(e.Path); err != nil {
			errs = append(errs, err)
			continue
		}
		store := filepath.Join(dir, "files", e.Store)
		var err error
		switch e.Kind {
		case kindAbsent:
		case kindSymlink:
			err = os.Symlink(e.Target, e.Path)
		case kindFile:
			err = copyFile(store, e.Path, os.FileMode(e.Mode))
		case kindDir:
			err = copyDirFlat(store, e.Path)
			if err == nil {
				err = os.Chmod(e.Path, os.FileMode(e.Mode))
			}
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("restore %s: %w", e.Path, err))
		}
	}
	return errors.Join(errs...)
}

func copyFile(src, dst string, mode os.FileMode) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return err
	}
	return writeFileAtomic(dst, data, mode)
}

// copyDirFlat copies regular files of src (non-recursive) into dst.
func copyDirFlat(src, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return err
	}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			continue
		}
		if err := copyFile(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name()), info.Mode().Perm()); err != nil {
			return err
		}
	}
	return nil
}

// pruneBackups keeps the newest `keep` backup directories.
func pruneBackups(l layout, keep int) error {
	if keep <= 0 {
		return nil
	}
	entries, err := os.ReadDir(l.backups)
	if err != nil {
		return err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	var errs []error
	for len(names) > keep {
		errs = append(errs, os.RemoveAll(filepath.Join(l.backups, names[0])))
		names = names[1:]
	}
	return errors.Join(errs...)
}

// readInstalledCert parses the leaf at current/<cert_name>; nil if absent or unreadable.
func readInstalledCert(l layout, certName string) *x509.Certificate {
	b, err := os.ReadFile(filepath.Join(l.current, orDefault(certName, "cert.pem")))
	if err != nil {
		return nil
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	return c
}

func installedFingerprint(l layout, certName string) string {
	if c := readInstalledCert(l, certName); c != nil {
		return certutil.Fingerprint(c.Raw)
	}
	return ""
}
