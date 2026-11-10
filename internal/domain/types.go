package domain

import (
	"encoding/json"
	"net/netip"
	"time"

	"github.com/google/uuid"
)

const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
)

const (
	ThemeLight = "light"
	ThemeDark  = "dark"
)

// ValidTheme reports whether t is a supported UI theme.
func ValidTheme(t string) bool {
	return t == ThemeLight || t == ThemeDark
}

const (
	ServerActive          = "active"
	ServerBlockedIdentity = "blocked_identity"
	ServerOffline         = "offline"
	ServerDeleted         = "deleted"
)

const (
	EnrollPending  = "pending"
	EnrollAccepted = "accepted"
	EnrollRejected = "rejected"
)

const (
	ReasonFirstSeen           = "first_seen"
	ReasonIdentityIPChanged   = "identity_ip_changed"
	ReasonIdentityKeyChanged  = "identity_key_changed"
	ReasonReEnrollAfterDelete = "re_enroll_after_delete"
)

type User struct {
	ID                 uuid.UUID  `json:"id"`
	Login              string     `json:"login"`
	DisplayName        string     `json:"display_name"`
	PasswordHash       string     `json:"-"`
	Role               string     `json:"role"`
	Theme              string     `json:"theme"`
	IsActive           bool       `json:"is_active"`
	MustChangePassword bool       `json:"must_change_password"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
	LastLoginAt        *time.Time `json:"last_login_at"`
}

type Session struct {
	ID         uuid.UUID   `json:"id"`
	UserID     uuid.UUID   `json:"user_id"`
	TokenHash  []byte      `json:"-"`
	CreatedAt  time.Time   `json:"created_at"`
	ExpiresAt  time.Time   `json:"expires_at"`
	LastSeenAt time.Time   `json:"last_seen_at"`
	IP         *netip.Addr `json:"ip"`
	UserAgent  string      `json:"user_agent"`
}

type Group struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

type GroupPermission struct {
	ID             uuid.UUID `json:"id"`
	UserID         uuid.UUID `json:"user_id"`
	GroupID        uuid.UUID `json:"group_id"`
	CanRead        bool      `json:"can_read"`
	CanWriteConfig bool      `json:"can_write_config"`
	CanWriteCerts  bool      `json:"can_write_certs"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type Domain struct {
	ID        uuid.UUID `json:"id"`
	FQDN      string    `json:"fqdn"`
	Notes     string    `json:"notes"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Certificate struct {
	ID                uuid.UUID  `json:"id"`
	FingerprintSHA256 string     `json:"fingerprint_sha256"`
	SubjectCN         string     `json:"subject_cn"`
	SANs              []string   `json:"sans"`
	IssuerCN          string     `json:"issuer_cn"`
	Serial            string     `json:"serial"`
	NotBefore         time.Time  `json:"not_before"`
	NotAfter          time.Time  `json:"not_after"`
	KeyAlgo           string     `json:"key_algo"`
	KeyBits           int        `json:"key_bits"`
	CertPath          string     `json:"-"`
	KeyPath           string     `json:"-"`
	ChainPath         string     `json:"-"`
	UploadedAt        time.Time  `json:"uploaded_at"`
	UploadedBy        *uuid.UUID `json:"uploaded_by"`
}

// MarshalJSON exposes has_key / has_chain without leaking filesystem paths.
func (c Certificate) MarshalJSON() ([]byte, error) {
	type certOut Certificate
	return json.Marshal(struct {
		certOut
		HasKey   bool `json:"has_key"`
		HasChain bool `json:"has_chain"`
	}{
		certOut:  certOut(c),
		HasKey:   c.KeyPath != "",
		HasChain: c.ChainPath != "",
	})
}

type DomainCertificate struct {
	ID            uuid.UUID  `json:"id"`
	DomainID      uuid.UUID  `json:"domain_id"`
	CertificateID uuid.UUID  `json:"certificate_id"`
	Version       int        `json:"version"`
	IsCurrent     bool       `json:"is_current"`
	ActivatedAt   time.Time  `json:"activated_at"`
	DeactivatedAt *time.Time `json:"deactivated_at"`
	ActivatedBy   *uuid.UUID `json:"activated_by"`
	Reason        string     `json:"reason"`
}

type Server struct {
	ID               uuid.UUID   `json:"id"`
	DisplayName      *string     `json:"display_name"`
	LastIP           *netip.Addr `json:"last_ip"`
	LastSeenAt       *time.Time  `json:"last_seen_at"`
	AgentStatus      string      `json:"agent_status"`
	UsesCustomConfig bool        `json:"uses_custom_config"`
	ConfigVersion    int64       `json:"config_version"`
	// Agent-reported local config (agent.local.cfg).
	AgentLocalConfig           []byte     `json:"-"`
	AgentLocalConfigHash       string     `json:"agent_local_config_hash,omitempty"`
	AgentLocalConfigUpdatedAt  *time.Time `json:"agent_local_config_updated_at,omitempty"`
	PendingLocalConfig         []byte     `json:"-"`
	PendingLocalConfigBaseHash string     `json:"pending_local_config_base_hash,omitempty"`
	PendingLocalConfigRevision int64      `json:"pending_local_config_revision,omitempty"`
	LocalConfigConflict        bool       `json:"local_config_conflict,omitempty"`
	CreatedAt                  time.Time  `json:"created_at"`
}

func (s Server) Display() string {
	if s.DisplayName != nil && *s.DisplayName != "" {
		return *s.DisplayName
	}
	if s.LastIP != nil {
		return s.LastIP.String()
	}
	return s.ID.String()
}

type AgentEnrollment struct {
	ID                 uuid.UUID  `json:"id"`
	RemoteIP           netip.Addr `json:"remote_ip"`
	ClientName         *string    `json:"client_name"`
	Status             string     `json:"status"`
	Reason             string     `json:"reason"`
	PreviousServerID   *uuid.UUID `json:"previous_server_id"`
	PreviousKeyPrefix  *string    `json:"previous_key_prefix"`
	PresentedKeyPrefix *string    `json:"presented_key_prefix"`
	LastSeenAt         time.Time  `json:"last_seen_at"`
	CreatedAt          time.Time  `json:"created_at"`
	DecidedAt          *time.Time `json:"decided_at"`
	DecidedBy          *uuid.UUID `json:"decided_by"`
	ServerID           *uuid.UUID `json:"server_id"`
}

type AgentKey struct {
	ID         uuid.UUID  `json:"id"`
	ServerID   uuid.UUID  `json:"server_id"`
	KeyPrefix  string     `json:"key_prefix"`
	KeyHash    []byte     `json:"-"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	Label      string     `json:"label"`
}

type AgentDefaults struct {
	Config        []byte    `json:"-"`
	ConfigVersion int64     `json:"config_version"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type ServerConfig struct {
	ServerID      uuid.UUID `json:"server_id"`
	Config        []byte    `json:"-"`
	ConfigVersion int64     `json:"config_version"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type DomainServer struct {
	DomainID        uuid.UUID `json:"domain_id"`
	ServerID        uuid.UUID `json:"server_id"`
	InstallMode     string    `json:"install_mode"`
	CertPath        string    `json:"cert_path"`
	KeyPath         string    `json:"key_path"`
	ChainPath       string    `json:"chain_path"`
	FullchainPath   string    `json:"fullchain_path"`
	RestartOverride []byte    `json:"-"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type ServerEndpoint struct {
	ID            uuid.UUID  `json:"id"`
	ServerID      uuid.UUID  `json:"server_id"`
	DomainID      *uuid.UUID `json:"domain_id"`
	Host          string     `json:"host"`
	Port          int        `json:"port"`
	Enabled       bool       `json:"enabled"`
	CheckInterval string     `json:"check_interval,omitempty"`
	DialAddr      string     `json:"dial_addr,omitempty"`
	ClientCertID  *uuid.UUID `json:"client_cert_id,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
}

// Managed certificate kinds.
const (
	ManagedKindCA            = "ca"
	ManagedKindAllowedClient = "allowed_client"
	ManagedKindMTLSClient    = "mtls_client"
)

// ManagedCertificate is inventory for CA / inbound client pins / our outbound mTLS client certs.
// Domain links live in managed_cert_domains (many-to-many); see ManagedCertView.DomainIDs.
type ManagedCertificate struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	DisplayName string    `json:"display_name"`
	Kind        string    `json:"kind"`
	Notes       string    `json:"notes"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ManagedCertificateVersion versions a managed certificate (mirrors DomainCertificate).
type ManagedCertificateVersion struct {
	ID              uuid.UUID  `json:"id"`
	ManagedCertID   uuid.UUID  `json:"managed_cert_id"`
	CertificateID   uuid.UUID  `json:"certificate_id"`
	Version         int        `json:"version"`
	IsCurrent       bool       `json:"is_current"`
	ActivatedAt     time.Time  `json:"activated_at"`
	DeactivatedAt   *time.Time `json:"deactivated_at,omitempty"`
	ActivatedBy     *uuid.UUID `json:"activated_by,omitempty"`
	Reason          string     `json:"reason"`
}

// ManagedCertServer assigns an mtls_client managed cert to a server for agent install.
type ManagedCertServer struct {
	ManagedCertID   uuid.UUID `json:"managed_cert_id"`
	ServerID        uuid.UUID `json:"server_id"`
	InstallMode     string    `json:"install_mode"`
	CertPath        string    `json:"cert_path"`
	KeyPath         string    `json:"key_path"`
	ChainPath       string    `json:"chain_path"`
	FullchainPath   string    `json:"fullchain_path"`
	RestartOverride []byte    `json:"-"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type MonitorResult struct {
	ID              int64       `json:"id"`
	EndpointID      uuid.UUID   `json:"endpoint_id"`
	CheckedAt       time.Time   `json:"checked_at"`
	Reachable       bool        `json:"reachable"`
	TLSOK           bool        `json:"tls_ok"`
	PeerFingerprint *string     `json:"peer_fingerprint"`
	PeerNotAfter    *time.Time  `json:"peer_not_after"`
	Issuer          *string     `json:"issuer"`
	Error           *string     `json:"error"`
	LatencyMS       *int        `json:"latency_ms"`
	ConnectedIP     *netip.Addr `json:"connected_ip"`
}

type Event struct {
	ID            int64      `json:"id"`
	At            time.Time  `json:"at"`
	Type          string     `json:"type"`
	Severity      string     `json:"severity"`
	DomainID      *uuid.UUID `json:"domain_id"`
	ServerID      *uuid.UUID `json:"server_id"`
	CertificateID *uuid.UUID `json:"certificate_id"`
	GroupID       *uuid.UUID `json:"group_id"`
	Message       string     `json:"message"`
	Details       []byte     `json:"-"`
	DedupKey      *string    `json:"dedup_key"`
	ResolvedAt    *time.Time `json:"resolved_at"`
	ActorUserID   *uuid.UUID `json:"actor_user_id"`
}

// Notification delivery constants.
const (
	NotifyChannelEmail    = "email"
	NotifyChannelTelegram = "telegram"
	NotifyChannelWebhook  = "webhook"

	NotifyKindOpened   = "opened"
	NotifyKindResolved = "resolved"

	NotifyOutboxPending = "pending"
	NotifyOutboxSent    = "sent"
	NotifyOutboxFailed  = "failed"
	NotifyOutboxSkipped = "skipped"

	NotifyScopeDomain = "domain"
	NotifyScopeGroup  = "group"
	NotifyScopeServer = "server"

	NotifyStatusNone    = "none"
	NotifyStatusPending = "pending"
	NotifyStatusSent    = "sent"
	NotifyStatusPartial = "partial"
	NotifyStatusFailed  = "failed"
	NotifyStatusSkipped = "skipped"
)

// NotificationAccount is a non-login recipient of event notifications.
type NotificationAccount struct {
	ID         uuid.UUID     `json:"id"`
	Name       string        `json:"name"`
	Enabled    bool          `json:"enabled"`
	AllowAll   bool          `json:"allow_all"`
	EventTypes []string      `json:"event_types"`
	Timezone   string        `json:"timezone"`
	WindowDays []int         `json:"window_days"`
	WindowFrom string        `json:"window_from"`
	WindowTo   string        `json:"window_to"`
	CreatedAt  time.Time     `json:"created_at"`
	UpdatedAt  time.Time     `json:"updated_at"`
	Scopes     []NotifyScope `json:"scopes,omitempty"`
}

// NotifyScope grants a notification account visibility to a domain, group, or server.
type NotifyScope struct {
	Kind     string    `json:"kind"`
	TargetID uuid.UUID `json:"target_id"`
}

// NotificationDestination is one delivery channel for an account.
type NotificationDestination struct {
	ID        uuid.UUID `json:"id"`
	AccountID uuid.UUID `json:"account_id"`
	Channel   string    `json:"channel"`
	Config    []byte    `json:"-"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}

// NotificationOutbox is a queued delivery attempt for one event destination.
type NotificationOutbox struct {
	ID            int64      `json:"id"`
	EventID       int64      `json:"event_id"`
	DestinationID uuid.UUID  `json:"destination_id"`
	Kind          string     `json:"kind"`
	Payload       []byte     `json:"-"`
	Status        string     `json:"status"`
	Attempts      int        `json:"attempts"`
	NextAttemptAt time.Time  `json:"next_attempt_at"`
	LastError     string     `json:"last_error"`
	CreatedAt     time.Time  `json:"created_at"`
	SentAt        *time.Time `json:"sent_at"`
}

// EventNotification is a delivery row enriched for the events API.
type EventNotification struct {
	AccountID   uuid.UUID  `json:"account_id"`
	AccountName string     `json:"account_name"`
	Channel     string     `json:"channel"`
	Kind        string     `json:"kind"`
	Status      string     `json:"status"`
	SentAt      *time.Time `json:"sent_at"`
	LastError   string     `json:"last_error"`
}

type AuditEntry struct {
	ID               int64      `json:"id"`
	At               time.Time  `json:"at"`
	ActorUserID      *uuid.UUID `json:"actor_user_id"`
	ActorLogin       string     `json:"actor_login,omitempty"`
	ActorDisplayName string     `json:"actor_display_name,omitempty"`
	Action           string     `json:"action"`
	EntityType       string     `json:"entity_type"`
	EntityID         string     `json:"entity_id"`
	EntityLabel      string     `json:"entity_label,omitempty"`
	Details          []byte     `json:"-"`
}

type EffectivePerms struct {
	CanRead        bool        `json:"can_read"`
	CanWriteConfig bool        `json:"can_write_config"`
	CanWriteCerts  bool        `json:"can_write_certs"`
	GroupIDs       []uuid.UUID `json:"group_ids"`
}
