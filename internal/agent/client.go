package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/kogonia/tlsherd/internal/agentcfg"
)

const maxResponseBody = 4 << 20

// ErrUnauthorized means the server rejected the agent API key (HTTP 401).
var ErrUnauthorized = errors.New("agent: unauthorized")

// Enrollment statuses returned by POST /api/v1/agent/enroll.
const (
	EnrollPending  = "pending"
	EnrollAccepted = "accepted"
	EnrollRejected = "rejected"
)

type EnrollRequest struct {
	Name            string              `json:"client_name,omitempty"`
	Version         string              `json:"version,omitempty"`
	LocalConfig     agentcfg.LocalConfig `json:"local_config,omitempty"`
	LocalConfigHash string              `json:"local_config_hash,omitempty"`
}

// LocalConfigUpdate is a server push that the agent writes into agent.local.cfg.
type LocalConfigUpdate struct {
	Config   agentcfg.LocalConfig `json:"config"`
	BaseHash string               `json:"base_hash,omitempty"`
	Revision int64                `json:"revision,omitempty"`
}

type EnrollResponse struct {
	Status            string             `json:"status"`
	APIKey            string             `json:"api_key,omitempty"`
	Config            *agentcfg.Config   `json:"config,omitempty"`
	ConfigVersion     int64              `json:"config_version,omitempty"`
	LocalConfigUpdate *LocalConfigUpdate `json:"local_config_update,omitempty"`
}

type PollRequest struct {
	AgentVersion        string               `json:"agent_version,omitempty"`
	ConfigVersion       int64                `json:"config_version"`
	Domains             []DomainReport       `json:"domains,omitempty"`
	LocalConfig         agentcfg.LocalConfig `json:"local_config,omitempty"`
	LocalConfigHash     string               `json:"local_config_hash,omitempty"`
	LocalConfigConflict bool                 `json:"local_config_conflict,omitempty"`
}

// DomainReport is the agent's view of one domain, sent with each poll.
type DomainReport struct {
	FQDN              string `json:"fqdn"`
	Fingerprint       string `json:"fingerprint,omitempty"`
	StagedFingerprint string `json:"staged_fingerprint,omitempty"`
}

type PollResponse struct {
	ConfigVersion     int64              `json:"config_version"`
	ConfigHash        string             `json:"config_hash,omitempty"`
	Config            agentcfg.Config    `json:"config"`
	Domains           []Assignment       `json:"domains"`
	NewAPIKey         string             `json:"new_api_key,omitempty"`
	LocalConfigUpdate *LocalConfigUpdate `json:"local_config_update,omitempty"`
}

// Assignment is a domain certificate assigned to this server.
type Assignment struct {
	FQDN        string            `json:"fqdn"`
	Fingerprint string            `json:"fingerprint_sha256"`
	NotAfter    time.Time         `json:"not_after"`
	InstallMode   string            `json:"install_mode,omitempty"`
	CertPath      string            `json:"cert_path,omitempty"`
	KeyPath       string            `json:"key_path,omitempty"`
	ChainPath     string            `json:"chain_path,omitempty"`
	FullchainPath string            `json:"fullchain_path,omitempty"`
	Restart       *agentcfg.Restart `json:"restart_override,omitempty"`
}

// CertBundle is the GET /api/v1/agent/certs/{fingerprint} payload.
type CertBundle struct {
	Fingerprint string `json:"fingerprint_sha256"`
	Cert        string `json:"cert"`
	Key         string `json:"key"`
	Chain       string `json:"chain"`
}

// Apply result statuses (wire values match the server).
const (
	StatusApplied           = "success"
	StatusStaged            = "staged"
	StatusFailed            = "failed"
	StatusVerifyFailed      = "verify_failed"
	StatusRestartFailed     = "failed"
	StatusPostCheckMismatch = "post_check_mismatch"
)

// ApplyResult is reported via POST /api/v1/agent/apply-result.
type ApplyResult struct {
	ApplyID             string         `json:"apply_id"`
	FQDN                string         `json:"domain"`
	Fingerprint         string         `json:"fingerprint_sha256"`
	PreviousFingerprint string         `json:"previous_fingerprint,omitempty"`
	Status              string         `json:"status"`
	Message             string         `json:"message,omitempty"`
	Details             map[string]any `json:"details,omitempty"`
}

// Client talks to the tlsherd server agent API.
type Client struct {
	base string
	http *http.Client
}

// NewClient builds a client for serverURL using hc (http.DefaultClient if nil).
func NewClient(serverURL string, hc *http.Client) *Client {
	if hc == nil {
		hc = http.DefaultClient
	}
	return &Client{base: strings.TrimRight(serverURL, "/"), http: hc}
}

// NewHTTPClient builds an HTTP client with an optional extra CA bundle.
// insecureSkipVerify disables server verification and is meant for labs only.
func NewHTTPClient(caFile string, insecureSkipVerify bool) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: insecureSkipVerify} //nolint:gosec // explicit lab flag
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read ca_file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ca_file %s: no certificates found", caFile)
		}
		tlsCfg.RootCAs = pool
	}
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		TLSClientConfig:       tlsCfg,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}
	return &http.Client{Transport: tr}, nil
}

// Enroll registers the agent. HTTP 401/403 map to EnrollRejected.
func (c *Client) Enroll(ctx context.Context, req EnrollRequest) (EnrollResponse, error) {
	var out EnrollResponse
	status, _, err := c.doJSON(ctx, http.MethodPost, "/api/v1/agent/enroll", "", nil, req, &out)
	if err != nil {
		if errors.Is(err, ErrUnauthorized) || status == http.StatusForbidden {
			return EnrollResponse{Status: EnrollRejected}, nil
		}
		return EnrollResponse{}, err
	}
	return out, nil
}

func (c *Client) Poll(ctx context.Context, key string, req PollRequest) (PollResponse, error) {
	var out PollResponse
	if _, _, err := c.doJSON(ctx, http.MethodPost, "/api/v1/agent/poll", key, nil, req, &out); err != nil {
		return PollResponse{}, err
	}
	return out, nil
}

// FetchCert downloads a certificate bundle. When haveLocal is true the request
// carries If-None-Match and notModified=true on 304 (caller reads local copy).
func (c *Client) FetchCert(ctx context.Context, key, fingerprint string, haveLocal bool) (b CertBundle, notModified bool, err error) {
	hdr := http.Header{}
	if haveLocal {
		hdr.Set("If-None-Match", `"`+fingerprint+`"`)
	}
	status, _, err := c.doJSON(ctx, http.MethodGet, "/api/v1/agent/certs/"+fingerprint, key, hdr, nil, &b)
	if err != nil {
		return CertBundle{}, false, err
	}
	if status == http.StatusNotModified {
		return CertBundle{}, true, nil
	}
	return b, false, nil
}

func (c *Client) ReportApply(ctx context.Context, key string, res ApplyResult) error {
	_, _, err := c.doJSON(ctx, http.MethodPost, "/api/v1/agent/apply-result", key, nil, res, nil)
	return err
}

func (c *Client) doJSON(ctx context.Context, method, path, key string, hdr http.Header, in, out any) (int, http.Header, error) {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return 0, nil, fmt.Errorf("marshal request: %w", err)
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return 0, nil, err
	}
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return resp.StatusCode, resp.Header, fmt.Errorf("%s %s: read body: %w", method, path, err)
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return resp.StatusCode, resp.Header, ErrUnauthorized
	case resp.StatusCode == http.StatusNotModified:
		return resp.StatusCode, resp.Header, nil
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return resp.StatusCode, resp.Header, fmt.Errorf("%s %s: unexpected status %d", method, path, resp.StatusCode)
	}
	if out != nil && len(bytes.TrimSpace(data)) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, resp.Header, fmt.Errorf("%s %s: decode response: %w", method, path, err)
		}
	}
	return resp.StatusCode, resp.Header, nil
}
