package service

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/kogonia/tlsherd/internal/certutil"
	"github.com/kogonia/tlsherd/internal/domain"
	"github.com/kogonia/tlsherd/internal/store"
)

// Monitor defaults; overridable through the "monitor" system setting.
const (
	DefaultMonitorInterval = 5 * time.Minute
	DefaultProbeTimeout    = 10 * time.Second
	DefaultExpiringSoon    = 720 * time.Hour
	probeConcurrency       = 8
	settingMonitor         = "monitor"
)

// EndpointInput describes a new monitored endpoint.
type EndpointInput struct {
	ServerID uuid.UUID
	DomainID *uuid.UUID
	Host     string
	Port     int
	Enabled  *bool
}

// EndpointPatch holds optional endpoint changes.
type EndpointPatch struct {
	Host    *string
	Port    *int
	Enabled *bool
}

// EndpointView is an endpoint with its latest probe result.
type EndpointView struct {
	domain.ServerEndpoint
	Latest  *domain.MonitorResult `json:"latest,omitempty"`
	Healthy bool                  `json:"healthy"`
	Issue   string                `json:"issue,omitempty"` // unreachable | tls_fail | cert_expired | cert_expiring | not_checked | disabled
}

type monitorSettings struct {
	Interval, Timeout, ExpiringSoon time.Duration
}

func (s *Services) monitorSettings(ctx context.Context) monitorSettings {
	out := monitorSettings{DefaultMonitorInterval, DefaultProbeTimeout, DefaultExpiringSoon}
	b, err := s.Store.GetSetting(ctx, settingMonitor)
	if err != nil {
		return out
	}
	var raw struct {
		Interval     string `json:"interval"`
		Timeout      string `json:"timeout"`
		ExpiringSoon string `json:"expiring_soon"`
	}
	if json.Unmarshal(b, &raw) != nil {
		return out
	}
	for _, f := range []struct {
		v   string
		dst *time.Duration
	}{{raw.Interval, &out.Interval}, {raw.Timeout, &out.Timeout}, {raw.ExpiringSoon, &out.ExpiringSoon}} {
		if d, err := time.ParseDuration(f.v); err == nil && d > 0 {
			*f.dst = d
		}
	}
	return out
}

func validateHost(host string) (string, error) {
	host = strings.ToLower(strings.TrimSuffix(normalizeText(host), "."))
	if host == "" || len(host) > 253 || strings.ContainsAny(host, " /\\@?#") {
		return "", invalidf("invalid host")
	}
	return host, nil
}

// normalizeEndpointHost appends domainFQDN when host does not already end with that suffix.
func normalizeEndpointHost(host, domainFQDN string) (string, error) {
	host, err := validateHost(host)
	if err != nil {
		return "", err
	}
	domainFQDN = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domainFQDN), "."))
	if domainFQDN == "" {
		return host, nil
	}
	if host == domainFQDN || strings.HasSuffix(host, "."+domainFQDN) {
		return host, nil
	}
	return validateHost(host + "." + domainFQDN)
}

// ---------------------------------------------------------------------------
// Endpoint CRUD

// requireEndpointWrite allows admins, or operators with can_write_config on
// the endpoint's domain (endpoints without a domain are admin only).
func (s *Services) requireEndpointWrite(ctx context.Context, actor *domain.User, domainID *uuid.UUID) error {
	if isAdmin(actor) {
		return nil
	}
	if domainID == nil {
		return forbiddenf("endpoints without a domain are managed by administrators")
	}
	return s.requireDomainPerm(ctx, actor, *domainID, permWriteConfig)
}

func (s *Services) requireEndpointRead(ctx context.Context, actor *domain.User, domainID *uuid.UUID) error {
	if isAdmin(actor) {
		return nil
	}
	if domainID == nil {
		return forbiddenf("endpoint not accessible")
	}
	return s.requireDomainPerm(ctx, actor, *domainID, permRead)
}

// CreateEndpoint adds a monitored endpoint. DomainID is required; Host is
// normalized against the domain FQDN (hostname becomes host.domain when needed).
func (s *Services) CreateEndpoint(ctx context.Context, actor *domain.User, in EndpointInput) (*domain.ServerEndpoint, error) {
	if in.DomainID == nil {
		return nil, invalidf("domain_id is required")
	}
	if err := s.requireEndpointWrite(ctx, actor, in.DomainID); err != nil {
		return nil, err
	}
	port := in.Port
	if port == 0 {
		port = 443
	}
	if port < 1 || port > 65535 {
		return nil, invalidf("port must be 1-65535")
	}
	ep := &domain.ServerEndpoint{ServerID: in.ServerID, DomainID: in.DomainID, Port: port, Enabled: true}
	if in.Enabled != nil {
		ep.Enabled = *in.Enabled
	}
	err := s.Store.Tx(ctx, func(tx store.Store) error {
		if _, err := tx.GetServer(ctx, in.ServerID); err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				return invalidf("server does not exist")
			}
			return err
		}
		dom, err := tx.GetDomain(ctx, *in.DomainID)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				return invalidf("domain does not exist")
			}
			return err
		}
		host, err := normalizeEndpointHost(in.Host, dom.FQDN)
		if err != nil {
			return err
		}
		ep.Host = host
		if !isAdmin(actor) {
			dss, err := tx.ListDomainServersByDomain(ctx, *in.DomainID)
			if err != nil {
				return err
			}
			linked := false
			for _, ds := range dss {
				linked = linked || ds.ServerID == in.ServerID
			}
			if !linked {
				return forbiddenf("server is not assigned to this domain")
			}
		}
		if err := tx.CreateEndpoint(ctx, ep); err != nil {
			if errors.Is(err, domain.ErrConflict) {
				return conflictf("endpoint already exists for this server, host, domain, and port")
			}
			return err
		}
		return s.audit(ctx, tx, actor, "endpoint.create", "endpoint", ep.ID.String(),
			map[string]any{"host": ep.Host, "port": port, "server_id": in.ServerID})
	})
	if err != nil {
		return nil, fmt.Errorf("create endpoint: %w", err)
	}
	return ep, nil
}

// UpdateEndpoint patches an endpoint.
func (s *Services) UpdateEndpoint(ctx context.Context, actor *domain.User, id uuid.UUID, p EndpointPatch) (*domain.ServerEndpoint, error) {
	var out *domain.ServerEndpoint
	err := s.Store.Tx(ctx, func(tx store.Store) error {
		ep, err := tx.GetEndpoint(ctx, id)
		if err != nil {
			return err
		}
		if err := s.requireEndpointWrite(ctx, actor, ep.DomainID); err != nil {
			return err
		}
		if p.Host != nil {
			host := *p.Host
			if ep.DomainID != nil {
				dom, gerr := tx.GetDomain(ctx, *ep.DomainID)
				if gerr != nil && !errors.Is(gerr, domain.ErrNotFound) {
					return gerr
				}
				if dom != nil {
					if ep.Host, err = normalizeEndpointHost(host, dom.FQDN); err != nil {
						return err
					}
				} else if ep.Host, err = validateHost(host); err != nil {
					return err
				}
			} else if ep.Host, err = validateHost(host); err != nil {
				return err
			}
		}
		if p.Port != nil {
			if *p.Port < 1 || *p.Port > 65535 {
				return invalidf("port must be 1-65535")
			}
			ep.Port = *p.Port
		}
		if p.Enabled != nil {
			ep.Enabled = *p.Enabled
		}
		if err := tx.UpdateEndpoint(ctx, ep); err != nil {
			if errors.Is(err, domain.ErrConflict) {
				return conflictf("endpoint already exists for this server, host, domain, and port")
			}
			return err
		}
		out = ep
		return s.audit(ctx, tx, actor, "endpoint.update", "endpoint", id.String(),
			map[string]any{"host": ep.Host, "port": ep.Port, "enabled": ep.Enabled})
	})
	if err != nil {
		return nil, fmt.Errorf("update endpoint: %w", err)
	}
	return out, nil
}

// DNSCheckRecord is one A-record result matched against known servers.
type DNSCheckRecord struct {
	IP          string     `json:"ip"`
	ServerID    *uuid.UUID `json:"server_id"`
	ServerLabel string     `json:"server_label,omitempty"`
}

// DNSCheckResult is the response for LookupEndpointDNS.
type DNSCheckResult struct {
	Host    string           `json:"host"`
	Records []DNSCheckRecord `json:"records"`
}

// LookupEndpointDNS resolves host to IPv4 A records and matches them to
// servers visible to actor by last_ip.
func (s *Services) LookupEndpointDNS(ctx context.Context, actor *domain.User, host string) (*DNSCheckResult, error) {
	host, err := validateHost(host)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err != nil {
		return nil, invalidf("DNS lookup failed: %v", err)
	}
	servers, err := s.ListServers(ctx, actor)
	if err != nil {
		return nil, fmt.Errorf("dns check: %w", err)
	}
	byIP := make(map[netip.Addr]ServerView, len(servers))
	for _, sv := range servers {
		if sv.LastIP != nil {
			byIP[*sv.LastIP] = sv
		}
	}
	out := &DNSCheckResult{Host: host, Records: make([]DNSCheckRecord, 0, len(ips))}
	seen := make(map[netip.Addr]struct{}, len(ips))
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if _, dup := seen[addr]; dup {
			continue
		}
		seen[addr] = struct{}{}
		rec := DNSCheckRecord{IP: addr.String()}
		if sv, ok := byIP[addr]; ok {
			id := sv.ID
			rec.ServerID = &id
			rec.ServerLabel = sv.Label
		}
		out.Records = append(out.Records, rec)
	}
	return out, nil
}

// DeleteEndpoint removes an endpoint and its results.
func (s *Services) DeleteEndpoint(ctx context.Context, actor *domain.User, id uuid.UUID) error {
	err := s.Store.Tx(ctx, func(tx store.Store) error {
		ep, err := tx.GetEndpoint(ctx, id)
		if err != nil {
			return err
		}
		if err := s.requireEndpointWrite(ctx, actor, ep.DomainID); err != nil {
			return err
		}
		if err := tx.DeleteEndpoint(ctx, id); err != nil {
			return err
		}
		for _, t := range []string{EvEndpointDown, EvEndpointCertMismatch} {
			if err := s.resolve(ctx, tx, DedupKey(t, id.String()), "endpoint_deleted"); err != nil {
				return err
			}
		}
		return s.audit(ctx, tx, actor, "endpoint.delete", "endpoint", id.String(), map[string]any{"host": ep.Host})
	})
	if err != nil {
		return fmt.Errorf("delete endpoint: %w", err)
	}
	return nil
}

// ListEndpoints returns visible endpoints with their latest result.
func (s *Services) ListEndpoints(ctx context.Context, actor *domain.User) ([]EndpointView, error) {
	eps, err := s.Store.ListEndpoints(ctx, false)
	if err != nil {
		return nil, fmt.Errorf("list endpoints: %w", err)
	}
	var visible map[uuid.UUID]struct{}
	if !isAdmin(actor) {
		ids, err := s.Authz.VisibleDomainIDs(ctx, actor)
		if err != nil {
			return nil, fmt.Errorf("list endpoints: %w", err)
		}
		visible = make(map[uuid.UUID]struct{}, len(ids))
		for _, id := range ids {
			visible[id] = struct{}{}
		}
	}
	expiringSoon := s.monitorSettings(ctx).ExpiringSoon
	now := s.now()
	out := make([]EndpointView, 0, len(eps))
	for _, ep := range eps {
		if visible != nil {
			if ep.DomainID == nil {
				continue
			}
			if _, ok := visible[*ep.DomainID]; !ok {
				continue
			}
		}
		v := EndpointView{ServerEndpoint: ep}
		res, err := s.Store.LatestMonitorResult(ctx, ep.ID)
		switch {
		case err == nil:
			v.Latest = res
		case !errors.Is(err, domain.ErrNotFound):
			return nil, fmt.Errorf("list endpoints: %w", err)
		}
		v.Healthy, v.Issue = endpointHealth(ep, res, now, expiringSoon)
		out = append(out, v)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Healthy != out[j].Healthy {
			return !out[i].Healthy && out[j].Healthy
		}
		return out[i].Host < out[j].Host
	})
	return out, nil
}

func endpointHealth(ep domain.ServerEndpoint, res *domain.MonitorResult, now time.Time, expiringSoon time.Duration) (healthy bool, issue string) {
	if !ep.Enabled {
		return true, "disabled"
	}
	if res == nil {
		return false, "not_checked"
	}
	if !res.Reachable {
		return false, "unreachable"
	}
	if !res.TLSOK {
		return false, "tls_fail"
	}
	if res.PeerNotAfter != nil {
		left := res.PeerNotAfter.Sub(now)
		if left <= 0 {
			return false, "cert_expired"
		}
		if left <= expiringSoon {
			return false, "cert_expiring"
		}
	}
	return true, ""
}

// ListMonitorResults returns probe history of an endpoint, newest first.
func (s *Services) ListMonitorResults(ctx context.Context, actor *domain.User, endpointID uuid.UUID, limit int) ([]domain.MonitorResult, error) {
	ep, err := s.Store.GetEndpoint(ctx, endpointID)
	if err != nil {
		return nil, fmt.Errorf("list monitor results: %w", err)
	}
	if err := s.requireEndpointRead(ctx, actor, ep.DomainID); err != nil {
		return nil, err
	}
	rs, err := s.Store.ListMonitorResults(ctx, endpointID, limit)
	if err != nil {
		return nil, fmt.Errorf("list monitor results: %w", err)
	}
	return rs, nil
}

// ForceCheck probes an endpoint immediately on behalf of a user.
func (s *Services) ForceCheck(ctx context.Context, actor *domain.User, endpointID uuid.UUID) (*domain.MonitorResult, error) {
	ep, err := s.Store.GetEndpoint(ctx, endpointID)
	if err != nil {
		return nil, fmt.Errorf("force check: %w", err)
	}
	if err := s.requireEndpointWrite(ctx, actor, ep.DomainID); err != nil {
		return nil, err
	}
	return s.CheckEndpoint(ctx, ep)
}

// ---------------------------------------------------------------------------
// Probing

// CheckEndpoint probes one endpoint, stores the result, and raises or
// resolves endpoint_down / endpoint_cert_mismatch. It is the helper used by
// both the monitor worker and ForceCheck.
func (s *Services) CheckEndpoint(ctx context.Context, ep *domain.ServerEndpoint) (*domain.MonitorResult, error) {
	set := s.monitorSettings(ctx)
	sni := ep.Host
	var dom *domain.Domain
	if ep.DomainID != nil {
		d, err := s.Store.GetDomain(ctx, *ep.DomainID)
		switch {
		case err == nil:
			dom, sni = d, d.FQDN
		case !errors.Is(err, domain.ErrNotFound):
			return nil, fmt.Errorf("check endpoint: %w", err)
		}
	}

	srv, err := s.Store.GetServer(ctx, ep.ServerID)
	if err != nil {
		return nil, fmt.Errorf("check endpoint: %w", err)
	}
	res := s.probe(ctx, ep, srv, sni, set.Timeout)
	if err := s.Store.InsertMonitorResult(ctx, res); err != nil {
		return nil, fmt.Errorf("check endpoint: %w", err)
	}
	latency := 0
	if res.LatencyMS != nil {
		latency = *res.LatencyMS
	}
	connected := ""
	if res.ConnectedIP != nil {
		connected = res.ConnectedIP.String()
	}
	s.log().Debug("endpoint probe",
		"component", "monitor", "operation", "check_endpoint",
		"endpoint_id", ep.ID, "host", ep.Host, "port", ep.Port, "sni", sni,
		"connected_ip", connected,
		"reachable", res.Reachable, "tls_ok", res.TLSOK, "latency_ms", latency)

	downKey := DedupKey(EvEndpointDown, ep.ID.String())
	if !res.Reachable || !res.TLSOK {
		msg := fmt.Sprintf("endpoint %s:%d is not serving TLS", ep.Host, ep.Port)
		if res.Error != nil {
			msg += ": " + *res.Error
		}
		if err := s.emit(ctx, s.Store, &domain.Event{
			Type: EvEndpointDown, Severity: SeverityCritical, DomainID: ep.DomainID, ServerID: &ep.ServerID,
			DedupKey: &downKey, Message: msg,
			Details: jsonDetails(map[string]any{"endpoint_id": ep.ID, "host": ep.Host, "port": ep.Port, "reachable": res.Reachable}),
		}); err != nil {
			return nil, err
		}
		return res, nil
	}
	if err := s.resolve(ctx, s.Store, downKey, "monitor"); err != nil {
		return nil, err
	}

	mismatchKey := DedupKey(EvEndpointCertMismatch, ep.ID.String())
	if dom == nil || res.PeerFingerprint == nil {
		return res, nil
	}
	dc, err := s.Store.GetCurrentDomainCertificate(ctx, dom.ID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return res, nil
		}
		return nil, fmt.Errorf("check endpoint: %w", err)
	}
	cert, err := s.Store.GetCertificate(ctx, dc.CertificateID)
	if err != nil {
		return nil, fmt.Errorf("check endpoint: %w", err)
	}
	if cert.FingerprintSHA256 != *res.PeerFingerprint {
		if err := s.emit(ctx, s.Store, &domain.Event{
			Type: EvEndpointCertMismatch, Severity: SeverityWarning, DomainID: &dom.ID, ServerID: &ep.ServerID,
			CertificateID: &cert.ID, DedupKey: &mismatchKey,
			Message: fmt.Sprintf("endpoint %s:%d serves a different certificate than the current one for %s", ep.Host, ep.Port, dom.FQDN),
			Details: jsonDetails(map[string]any{
				"endpoint_id": ep.ID, "expected": cert.FingerprintSHA256, "served": *res.PeerFingerprint,
			}),
		}); err != nil {
			return nil, err
		}
		return res, nil
	}
	if err := s.resolve(ctx, s.Store, mismatchKey, "monitor"); err != nil {
		return nil, err
	}
	return res, nil
}

// probe dials the server's last_ip and performs a TLS handshake with sni.
// Chain verification is intentionally skipped: the monitor compares the served
// leaf fingerprint with the expected one instead of trusting any CA.
func (s *Services) probe(ctx context.Context, ep *domain.ServerEndpoint, srv *domain.Server, sni string, timeout time.Duration) *domain.MonitorResult {
	res := &domain.MonitorResult{EndpointID: ep.ID, CheckedAt: s.now()}
	fail := func(err error) *domain.MonitorResult {
		msg := truncate(err.Error(), 512)
		res.Error = &msg
		return res
	}
	if srv == nil || srv.LastIP == nil {
		return fail(errors.New("server has no last_ip"))
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(srv.LastIP.String(), strconv.Itoa(ep.Port)))
	if err != nil {
		return fail(err)
	}
	defer conn.Close()
	res.Reachable = true
	ip := *srv.LastIP
	res.ConnectedIP = &ip

	tc := tls.Client(conn, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, //nolint:gosec // fingerprint comparison replaces chain verification
		MinVersion:         tls.VersionTLS12,
	})
	if err := tc.HandshakeContext(ctx); err != nil {
		return fail(err)
	}
	lat := int(time.Since(start).Milliseconds())
	res.LatencyMS = &lat
	peers := tc.ConnectionState().PeerCertificates
	if len(peers) == 0 {
		return fail(errors.New("no peer certificate"))
	}
	leaf := peers[0]
	fp := certutil.Fingerprint(leaf.Raw)
	na := leaf.NotAfter.UTC()
	issuer := leaf.Issuer.CommonName
	res.TLSOK, res.PeerFingerprint, res.PeerNotAfter, res.Issuer = true, &fp, &na, &issuer
	return res
}

// ---------------------------------------------------------------------------
// Worker

// MonitorTick runs one pass of background work: due endpoint probes,
// certificate expiry scan, ungrouped-domain scan and agent liveness scan.
// Errors of individual checks are logged and do not stop the pass.
func (s *Services) MonitorTick(ctx context.Context) {
	log := s.log().With("component", "monitor")
	set := s.monitorSettings(ctx)
	log.Debug("monitor tick start", "operation", "tick",
		"interval", set.Interval.String(), "timeout", set.Timeout.String())

	eps, err := s.Store.ListEndpoints(ctx, true)
	if err != nil {
		log.Error("list endpoints failed", "operation", "tick", "error", err)
	}
	sem := make(chan struct{}, probeConcurrency)
	var wg sync.WaitGroup
	due, skipped := 0, 0
	for i := range eps {
		ep := eps[i]
		last, err := s.Store.LatestMonitorResult(ctx, ep.ID)
		if err == nil && s.now().Sub(last.CheckedAt) < set.Interval {
			skipped++
			continue
		}
		due++
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			if _, err := s.CheckEndpoint(ctx, &ep); err != nil && ctx.Err() == nil {
				log.Error("endpoint check failed", "operation", "check_endpoint", "endpoint_id", ep.ID, "error", err)
			}
		}()
	}
	wg.Wait()
	log.Debug("monitor probes scheduled", "operation", "tick",
		"endpoints", len(eps), "due", due, "skipped", skipped)

	for name, scan := range map[string]func(context.Context) error{
		"scan_certificates": s.ScanCertificates,
		"scan_agents":       s.ScanAgents,
	} {
		if err := scan(ctx); err != nil && ctx.Err() == nil {
			log.Error("scan failed", "operation", name, "error", err)
		}
	}
	log.Debug("monitor tick done", "operation", "tick")
}

// ScanCertificates raises cert_expired / cert_expiring_soon for the current
// certificate of every domain (and resolves them when no longer true), and
// domain_ungrouped for domains without groups.
func (s *Services) ScanCertificates(ctx context.Context) error {
	set := s.monitorSettings(ctx)
	domains, err := s.Store.ListDomains(ctx)
	if err != nil {
		return fmt.Errorf("scan certificates: %w", err)
	}
	ungrouped, err := s.Store.ListUngroupedDomains(ctx)
	if err != nil {
		return fmt.Errorf("scan certificates: %w", err)
	}
	isUngrouped := make(map[uuid.UUID]struct{}, len(ungrouped))
	for _, d := range ungrouped {
		isUngrouped[d.ID] = struct{}{}
	}
	now := s.now()
	for _, d := range domains {
		d := d
		ugKey := DedupKey(EvDomainUngrouped, d.ID.String())
		if _, ok := isUngrouped[d.ID]; ok {
			if err := s.emit(ctx, s.Store, &domain.Event{
				Type: EvDomainUngrouped, Severity: SeverityWarning, DomainID: &d.ID, DedupKey: &ugKey,
				Message: fmt.Sprintf("domain %s belongs to no group and is visible to administrators only", d.FQDN),
			}); err != nil {
				return err
			}
		} else if err := s.resolve(ctx, s.Store, ugKey, "monitor"); err != nil {
			return err
		}

		dc, err := s.Store.GetCurrentDomainCertificate(ctx, d.ID)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				continue
			}
			return fmt.Errorf("scan certificates: %w", err)
		}
		cert, err := s.Store.GetCertificate(ctx, dc.CertificateID)
		if err != nil {
			return fmt.Errorf("scan certificates: %w", err)
		}
		expKey := DedupKey(EvCertExpired, d.ID.String())
		soonKey := DedupKey(EvCertExpiringSoon, d.ID.String())
		left := cert.NotAfter.Sub(now)
		switch {
		case left <= 0:
			if err := s.emit(ctx, s.Store, &domain.Event{
				Type: EvCertExpired, Severity: SeverityCritical, DomainID: &d.ID, CertificateID: &cert.ID, DedupKey: &expKey,
				Message: fmt.Sprintf("certificate of %s expired on %s", d.FQDN, cert.NotAfter.Format(time.RFC3339)),
				Details: jsonDetails(map[string]any{"not_after": cert.NotAfter, "fingerprint": cert.FingerprintSHA256}),
			}); err != nil {
				return err
			}
			if err := s.resolve(ctx, s.Store, soonKey, "monitor"); err != nil {
				return err
			}
		case left <= set.ExpiringSoon:
			sev := SeverityWarning
			if left <= 7*24*time.Hour {
				sev = SeverityCritical
			}
			if err := s.emit(ctx, s.Store, &domain.Event{
				Type: EvCertExpiringSoon, Severity: sev, DomainID: &d.ID, CertificateID: &cert.ID, DedupKey: &soonKey,
				Message: fmt.Sprintf("certificate of %s expires in %d days", d.FQDN, int(left.Hours()/24)),
				Details: jsonDetails(map[string]any{"not_after": cert.NotAfter, "fingerprint": cert.FingerprintSHA256}),
			}); err != nil {
				return err
			}
			if err := s.resolve(ctx, s.Store, expKey, "monitor"); err != nil {
				return err
			}
		default:
			for _, k := range []string{expKey, soonKey} {
				if err := s.resolve(ctx, s.Store, k, "monitor"); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// agentOfflineFactor is how many poll intervals of silence mark an agent offline.
const agentOfflineFactor = 2.5

// ScanAgents marks active servers offline when they have been silent for
// much longer than their poll interval and raises agent_offline.
func (s *Services) ScanAgents(ctx context.Context) error {
	servers, err := s.Store.ListServers(ctx)
	if err != nil {
		return fmt.Errorf("scan agents: %w", err)
	}
	now := s.now()
	for i := range servers {
		srv := servers[i]
		if srv.AgentStatus != domain.ServerActive || srv.LastSeenAt == nil {
			continue
		}
		eff, err := s.effectiveConfig(ctx, &srv)
		if err != nil {
			return err
		}
		limit := time.Duration(float64(eff.Config.PollInterval.Std()) * agentOfflineFactor)
		if now.Sub(*srv.LastSeenAt) <= limit {
			continue
		}
		srv.AgentStatus = domain.ServerOffline
		if err := s.Store.UpdateServer(ctx, &srv); err != nil {
			return fmt.Errorf("scan agents: %w", err)
		}
		key := DedupKey(EvAgentOffline, srv.ID.String())
		if err := s.emit(ctx, s.Store, &domain.Event{
			Type: EvAgentOffline, Severity: SeverityWarning, ServerID: &srv.ID, DedupKey: &key,
			Message: fmt.Sprintf("agent %s has not contacted the server since %s", srv.Display(), srv.LastSeenAt.Format(time.RFC3339)),
			Details: jsonDetails(map[string]any{"last_seen_at": srv.LastSeenAt}),
		}); err != nil {
			return err
		}
	}
	return nil
}
