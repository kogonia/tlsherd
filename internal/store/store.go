package store

import (
	"context"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/kogonia/tlsherd/internal/domain"
)

// Store is the persistence interface. Implementations live under store/postgres etc.
// Construct concrete stores in cmd/ main only.
type Store interface {
	Tx(ctx context.Context, fn func(Store) error) error
	Close() error

	// Users
	CreateUser(ctx context.Context, u *domain.User) error
	GetUser(ctx context.Context, id uuid.UUID) (*domain.User, error)
	GetUserByLogin(ctx context.Context, login string) (*domain.User, error)
	ListUsers(ctx context.Context) ([]domain.User, error)
	UpdateUser(ctx context.Context, u *domain.User) error
	DeleteUser(ctx context.Context, id uuid.UUID) error
	CountActiveAdmins(ctx context.Context) (int, error)

	// Sessions
	CreateSession(ctx context.Context, s *domain.Session) error
	GetSessionByTokenHash(ctx context.Context, hash []byte) (*domain.Session, error)
	TouchSession(ctx context.Context, id uuid.UUID, at time.Time, idleExtendTo time.Time) error
	DeleteSession(ctx context.Context, id uuid.UUID) error
	DeleteUserSessions(ctx context.Context, userID uuid.UUID) error

	// Groups
	CreateGroup(ctx context.Context, g *domain.Group) error
	GetGroup(ctx context.Context, id uuid.UUID) (*domain.Group, error)
	ListGroups(ctx context.Context) ([]domain.Group, error)
	UpdateGroup(ctx context.Context, g *domain.Group) error
	DeleteGroup(ctx context.Context, id uuid.UUID) error
	SetDomainGroups(ctx context.Context, domainID uuid.UUID, groupIDs []uuid.UUID) error
	ListDomainGroups(ctx context.Context, domainID uuid.UUID) ([]uuid.UUID, error)
	ListGroupDomains(ctx context.Context, groupID uuid.UUID) ([]uuid.UUID, error)

	// Permissions
	UpsertGroupPermission(ctx context.Context, p *domain.GroupPermission) error
	ListUserPermissions(ctx context.Context, userID uuid.UUID) ([]domain.GroupPermission, error)
	DeleteGroupPermission(ctx context.Context, userID, groupID uuid.UUID) error
	ListGroupPermissions(ctx context.Context, groupID uuid.UUID) ([]domain.GroupPermission, error)

	// Domains
	CreateDomain(ctx context.Context, d *domain.Domain) error
	GetDomain(ctx context.Context, id uuid.UUID) (*domain.Domain, error)
	GetDomainByFQDN(ctx context.Context, fqdn string) (*domain.Domain, error)
	ListDomains(ctx context.Context) ([]domain.Domain, error)
	UpdateDomain(ctx context.Context, d *domain.Domain) error
	DeleteDomain(ctx context.Context, id uuid.UUID) error
	ListUngroupedDomains(ctx context.Context) ([]domain.Domain, error)

	// Certificates
	UpsertCertificate(ctx context.Context, c *domain.Certificate) error
	GetCertificateByFingerprint(ctx context.Context, fp string) (*domain.Certificate, error)
	GetCertificate(ctx context.Context, id uuid.UUID) (*domain.Certificate, error)
	DeleteCertificate(ctx context.Context, id uuid.UUID) error
	// CertificateInUse reports whether id is the current certificate of a domain or managed certificate.
	CertificateInUse(ctx context.Context, id uuid.UUID) (bool, error)
	ListExpiringCertificates(ctx context.Context, before time.Time) ([]domain.Certificate, error)

	ActivateDomainCertificate(ctx context.Context, dc *domain.DomainCertificate) error
	ListDomainCertificates(ctx context.Context, domainID uuid.UUID) ([]domain.DomainCertificate, error)
	GetCurrentDomainCertificate(ctx context.Context, domainID uuid.UUID) (*domain.DomainCertificate, error)
	GetDomainCertificateByVersion(ctx context.Context, domainID uuid.UUID, version int) (*domain.DomainCertificate, error)
	// DeleteDomainCertificateVersion removes a non-current history row; returns its certificate_id.
	DeleteDomainCertificateVersion(ctx context.Context, domainID uuid.UUID, version int) (certificateID uuid.UUID, err error)
	// CertificateReferenced reports whether any domain_certificates or
	// managed_certificate_versions row points at id.
	CertificateReferenced(ctx context.Context, id uuid.UUID) (bool, error)
	MaxDomainCertVersion(ctx context.Context, domainID uuid.UUID) (int, error)

	// Managed certificates (CA, allowed_client, mtls_client)
	CreateManagedCertificate(ctx context.Context, m *domain.ManagedCertificate) error
	GetManagedCertificate(ctx context.Context, id uuid.UUID) (*domain.ManagedCertificate, error)
	GetManagedCertificateByName(ctx context.Context, name string) (*domain.ManagedCertificate, error)
	ListManagedCertificates(ctx context.Context, filter ManagedCertFilter) ([]domain.ManagedCertificate, error)
	UpdateManagedCertificate(ctx context.Context, m *domain.ManagedCertificate) error
	// DeleteManagedCertificate removes the managed certificate with its versions and
	// server assignments; underlying certificates rows are left for the caller to prune.
	DeleteManagedCertificate(ctx context.Context, id uuid.UUID) error
	// ActivateManagedCertificateVersion makes mv current (see ActivateDomainCertificate).
	ActivateManagedCertificateVersion(ctx context.Context, mv *domain.ManagedCertificateVersion) error
	ListManagedCertificateVersions(ctx context.Context, managedCertID uuid.UUID) ([]domain.ManagedCertificateVersion, error)
	GetCurrentManagedCertificateVersion(ctx context.Context, managedCertID uuid.UUID) (*domain.ManagedCertificateVersion, error)
	MaxManagedCertVersion(ctx context.Context, managedCertID uuid.UUID) (int, error)

	UpsertManagedCertServer(ctx context.Context, ms *domain.ManagedCertServer) error
	DeleteManagedCertServer(ctx context.Context, managedCertID, serverID uuid.UUID) error
	GetManagedCertServer(ctx context.Context, managedCertID, serverID uuid.UUID) (*domain.ManagedCertServer, error)
	ListManagedCertServersByCert(ctx context.Context, managedCertID uuid.UUID) ([]domain.ManagedCertServer, error)
	ListManagedCertServersByServer(ctx context.Context, serverID uuid.UUID) ([]domain.ManagedCertServer, error)

	// Servers / enrollment
	CreateServer(ctx context.Context, s *domain.Server) error
	GetServer(ctx context.Context, id uuid.UUID) (*domain.Server, error)
	ListServers(ctx context.Context) ([]domain.Server, error)
	UpdateServer(ctx context.Context, s *domain.Server) error
	DeleteServer(ctx context.Context, id uuid.UUID) error
	GetServerByIP(ctx context.Context, ip netip.Addr) (*domain.Server, error)

	CreateEnrollment(ctx context.Context, e *domain.AgentEnrollment) error
	GetPendingEnrollmentByIP(ctx context.Context, ip netip.Addr) (*domain.AgentEnrollment, error)
	// GetLatestEnrollmentByIP returns the newest enrollment of any status for ip, or domain.ErrNotFound.
	GetLatestEnrollmentByIP(ctx context.Context, ip netip.Addr) (*domain.AgentEnrollment, error)
	ListEnrollments(ctx context.Context, status string) ([]domain.AgentEnrollment, error)
	UpdateEnrollment(ctx context.Context, e *domain.AgentEnrollment) error
	GetEnrollment(ctx context.Context, id uuid.UUID) (*domain.AgentEnrollment, error)

	CreateAgentKey(ctx context.Context, k *domain.AgentKey) error
	GetAgentKeyByHash(ctx context.Context, hash []byte) (*domain.AgentKey, error)
	ListAgentKeys(ctx context.Context, serverID uuid.UUID) ([]domain.AgentKey, error)
	RevokeAgentKey(ctx context.Context, id uuid.UUID, at time.Time) error
	TouchAgentKey(ctx context.Context, id uuid.UUID, at time.Time) error
	// SetAgentKeyExpiry sets (or moves) the expiry of a key; used for rotation overlap.
	SetAgentKeyExpiry(ctx context.Context, id uuid.UUID, expiresAt time.Time) error
	ActiveKeyPrefix(ctx context.Context, serverID uuid.UUID) (string, error)

	GetAgentDefaults(ctx context.Context) (*domain.AgentDefaults, error)
	UpdateAgentDefaults(ctx context.Context, cfg []byte, version int64) error
	GetServerConfig(ctx context.Context, serverID uuid.UUID) (*domain.ServerConfig, error)
	UpsertServerConfig(ctx context.Context, sc *domain.ServerConfig) error
	DeleteServerConfig(ctx context.Context, serverID uuid.UUID) error

	UpsertDomainServer(ctx context.Context, ds *domain.DomainServer) error
	DeleteDomainServer(ctx context.Context, domainID, serverID uuid.UUID) error
	ListDomainServersByServer(ctx context.Context, serverID uuid.UUID) ([]domain.DomainServer, error)
	ListDomainServersByDomain(ctx context.Context, domainID uuid.UUID) ([]domain.DomainServer, error)

	// Endpoints / monitor
	CreateEndpoint(ctx context.Context, e *domain.ServerEndpoint) error
	ListEndpoints(ctx context.Context, enabledOnly bool) ([]domain.ServerEndpoint, error)
	GetEndpoint(ctx context.Context, id uuid.UUID) (*domain.ServerEndpoint, error)
	UpdateEndpoint(ctx context.Context, e *domain.ServerEndpoint) error
	DeleteEndpoint(ctx context.Context, id uuid.UUID) error
	InsertMonitorResult(ctx context.Context, r *domain.MonitorResult) error
	LatestMonitorResult(ctx context.Context, endpointID uuid.UUID) (*domain.MonitorResult, error)
	ListMonitorResults(ctx context.Context, endpointID uuid.UUID, limit int) ([]domain.MonitorResult, error)

	// Events / audit / settings
	// UpsertOpenEvent inserts or refreshes an open event. inserted is true only for a new row.
	UpsertOpenEvent(ctx context.Context, e *domain.Event) (inserted bool, err error)
	// InsertInstantEvent inserts a point-in-time event that is already resolved (no open lifecycle).
	InsertInstantEvent(ctx context.Context, e *domain.Event) error
	// CountOpenEventsByServer returns open-event counts and distinct types per server_id.
	CountOpenEventsByServer(ctx context.Context) (map[uuid.UUID]OpenEventCount, error)
	// CountUnhealthyEndpointsByServer counts enabled endpoints whose latest probe is unreachable or TLS-fail.
	CountUnhealthyEndpointsByServer(ctx context.Context) (map[uuid.UUID]int, error)
	// ResolveEventsByDedup closes open events with dedupKey and returns the rows that were closed.
	ResolveEventsByDedup(ctx context.Context, dedupKey string, at time.Time, details []byte) ([]domain.Event, error)
	// ResolveOpenEventsByTypeDomain closes open events of type for domainID (including those without dedup_key).
	ResolveOpenEventsByTypeDomain(ctx context.Context, eventType string, domainID uuid.UUID, at time.Time, details []byte) ([]domain.Event, error)
	GetEvent(ctx context.Context, id int64) (*domain.Event, error)
	// ResolveEventByID closes a single open event by id and returns it when a row was closed.
	ResolveEventByID(ctx context.Context, id int64, at time.Time, details []byte) (*domain.Event, error)
	ListEvents(ctx context.Context, filter EventFilter) ([]domain.Event, error)
	InsertAudit(ctx context.Context, a *domain.AuditEntry) error
	ListAudit(ctx context.Context, filter AuditFilter) ([]domain.AuditEntry, error)
	GetSetting(ctx context.Context, key string) ([]byte, error)
	SetSetting(ctx context.Context, key string, value []byte) error
	// DeleteSetting removes key; a missing key is not an error.
	DeleteSetting(ctx context.Context, key string) error

	SaveApplyResult(ctx context.Context, applyID string, serverID uuid.UUID, domainID *uuid.UUID, status, message string, details []byte) error

	// Notification accounts
	CreateNotificationAccount(ctx context.Context, a *domain.NotificationAccount) error
	GetNotificationAccount(ctx context.Context, id uuid.UUID) (*domain.NotificationAccount, error)
	ListNotificationAccounts(ctx context.Context) ([]domain.NotificationAccount, error)
	UpdateNotificationAccount(ctx context.Context, a *domain.NotificationAccount) error
	DeleteNotificationAccount(ctx context.Context, id uuid.UUID) error
	SetNotificationScopes(ctx context.Context, accountID uuid.UUID, scopes []domain.NotifyScope) error
	ListNotificationScopes(ctx context.Context, accountID uuid.UUID) ([]domain.NotifyScope, error)
	ListNotificationAccountsForFanout(ctx context.Context) ([]domain.NotificationAccount, error)
	DomainInGroups(ctx context.Context, domainID uuid.UUID, groupIDs []uuid.UUID) (bool, error)

	CreateNotificationDestination(ctx context.Context, d *domain.NotificationDestination) error
	GetNotificationDestination(ctx context.Context, id uuid.UUID) (*domain.NotificationDestination, error)
	ListNotificationDestinations(ctx context.Context, accountID uuid.UUID) ([]domain.NotificationDestination, error)
	UpdateNotificationDestination(ctx context.Context, d *domain.NotificationDestination) error
	DeleteNotificationDestination(ctx context.Context, id uuid.UUID) error

	InsertNotificationOutbox(ctx context.Context, o *domain.NotificationOutbox) error
	ClaimNotificationOutbox(ctx context.Context, limit int, now time.Time) ([]domain.NotificationOutbox, error)
	UpdateNotificationOutbox(ctx context.Context, o *domain.NotificationOutbox) error
	ListEventNotifications(ctx context.Context, eventIDs []int64) (map[int64][]domain.EventNotification, error)
	GetOutboxWithDestination(ctx context.Context, id int64) (*domain.NotificationOutbox, *domain.NotificationDestination, *domain.NotificationAccount, error)
}

// ManagedCertFilter selects managed certificates; zero fields match everything.
type ManagedCertFilter struct {
	Kind     string
	DomainID *uuid.UUID
}

type EventFilter struct {
	UnresolvedOnly bool
	Type           string
	Severity       string
	// DomainIDs, ServerIDs, GroupIDs form the OR visibility scope for operators.
	DomainIDs []uuid.UUID
	ServerIDs []uuid.UUID
	GroupIDs  []uuid.UUID
	// FilterDomainID / FilterServerID are optional user filters ANDed with scope.
	FilterDomainID *uuid.UUID
	FilterServerID *uuid.UUID
	Limit          int
	Offset         int
}

// AuditFilter selects audit log rows. Actor matches login or display_name (ILIKE),
// or exact actor_user_id when Actor is a UUID. Action matches exactly when set.
type AuditFilter struct {
	Actor  string
	Action string
	Limit  int
	Offset int
}

// OpenEventCount aggregates unresolved events for one server.
type OpenEventCount struct {
	Total       int
	Critical    int
	Warning     int
	Info        int
	Types       []string
	MaxSeverity string // critical | warning | info | ""
}
