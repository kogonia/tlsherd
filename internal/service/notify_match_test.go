package service

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/kogonia/tlsherd/internal/domain"
	"github.com/kogonia/tlsherd/internal/store"
)

func TestAccountMatchesEvent(t *testing.T) {
	acc := &domain.NotificationAccount{EventTypes: []string{EvCertExpired, EvEndpointDown}}
	if !accountMatchesEvent(acc, &domain.Event{Type: EvCertExpired}) {
		t.Fatal("expected match")
	}
	if accountMatchesEvent(acc, &domain.Event{Type: EvAgentOffline}) {
		t.Fatal("expected no match")
	}
	if accountMatchesEvent(&domain.NotificationAccount{}, &domain.Event{Type: EvCertExpired}) {
		t.Fatal("empty types must not match")
	}
}

func TestAccountScopeAllowAll(t *testing.T) {
	s := &Services{}
	acc := &domain.NotificationAccount{AllowAll: true}
	ok, err := s.accountScopeMatches(nil, nil, acc, &domain.Event{})
	if err != nil || !ok {
		t.Fatalf("allow_all: ok=%v err=%v", ok, err)
	}
}

func TestAccountScopeEmpty(t *testing.T) {
	s := &Services{}
	acc := &domain.NotificationAccount{AllowAll: false, Scopes: nil}
	ok, err := s.accountScopeMatches(nil, nil, acc, &domain.Event{DomainID: uuidPtr(uuid.New())})
	if err != nil || ok {
		t.Fatalf("empty scopes: ok=%v err=%v", ok, err)
	}
}

func TestAccountScopeDomain(t *testing.T) {
	s := &Services{}
	id := uuid.New()
	acc := &domain.NotificationAccount{
		Scopes: []domain.NotifyScope{{Kind: domain.NotifyScopeDomain, TargetID: id}},
	}
	ok, err := s.accountScopeMatches(nil, nil, acc, &domain.Event{DomainID: &id})
	if err != nil || !ok {
		t.Fatalf("domain scope: ok=%v err=%v", ok, err)
	}
	other := uuid.New()
	ok, err = s.accountScopeMatches(nil, nil, acc, &domain.Event{DomainID: &other})
	if err != nil || ok {
		t.Fatalf("wrong domain: ok=%v err=%v", ok, err)
	}
}

func TestDefaultNotificationEventTypes(t *testing.T) {
	if len(DefaultNotificationEventTypes) == 0 {
		t.Fatal("defaults empty")
	}
	known := knownEventTypeSet()
	for _, tname := range DefaultNotificationEventTypes {
		if _, ok := known[tname]; !ok {
			t.Fatalf("default type %q not in known set", tname)
		}
	}
}

func managedEvent(managedID uuid.UUID) *domain.Event {
	details, err := json.Marshal(map[string]any{"managed_cert_id": managedID.String()})
	if err != nil {
		panic(err)
	}
	return &domain.Event{Type: EvCertExpired, Details: details}
}

func TestManagedCertRequiresIncludeManaged(t *testing.T) {
	s := &Services{}
	mid := uuid.New()
	ev := managedEvent(mid)
	acc := &domain.NotificationAccount{AllowAll: true, IncludeManaged: false}
	ok, err := s.accountScopeMatches(nil, nil, acc, ev)
	if err != nil || ok {
		t.Fatalf("allow_all without include_managed must skip managed: ok=%v err=%v", ok, err)
	}
}

func TestManagedCertAllowAllWithFlag(t *testing.T) {
	s := &Services{}
	mid := uuid.New()
	acc := &domain.NotificationAccount{AllowAll: true, IncludeManaged: true}
	ok, err := s.accountScopeMatches(nil, nil, acc, managedEvent(mid))
	if err != nil || !ok {
		t.Fatalf("allow_all+include_managed: ok=%v err=%v", ok, err)
	}
}

func TestManagedCertExplicitScope(t *testing.T) {
	s := &Services{}
	mid := uuid.New()
	acc := &domain.NotificationAccount{
		IncludeManaged: true,
		Scopes:         []domain.NotifyScope{{Kind: domain.NotifyScopeManagedCert, TargetID: mid}},
	}
	ok, err := s.accountScopeMatches(nil, nil, acc, managedEvent(mid))
	if err != nil || !ok {
		t.Fatalf("managed_cert scope: ok=%v err=%v", ok, err)
	}
	other := uuid.New()
	ok, err = s.accountScopeMatches(nil, nil, acc, managedEvent(other))
	if err != nil || ok {
		t.Fatalf("wrong managed cert: ok=%v err=%v", ok, err)
	}
}

// scopeStub is a minimal store for managed-cert domain/group link matching.
type scopeStub struct {
	store.Store
	linked map[uuid.UUID][]uuid.UUID
	groups map[uuid.UUID][]uuid.UUID // domainID -> groupIDs
}

func (s *scopeStub) ListManagedCertDomainIDs(_ context.Context, managedCertID uuid.UUID) ([]uuid.UUID, error) {
	return append([]uuid.UUID(nil), s.linked[managedCertID]...), nil
}

func (s *scopeStub) DomainInGroups(_ context.Context, domainID uuid.UUID, groupIDs []uuid.UUID) (bool, error) {
	have := s.groups[domainID]
	set := make(map[uuid.UUID]struct{}, len(have))
	for _, g := range have {
		set[g] = struct{}{}
	}
	for _, g := range groupIDs {
		if _, ok := set[g]; ok {
			return true, nil
		}
	}
	return false, nil
}

func TestManagedCertDomainLinkScope(t *testing.T) {
	s := &Services{}
	mid, did, other := uuid.New(), uuid.New(), uuid.New()
	st := &scopeStub{linked: map[uuid.UUID][]uuid.UUID{mid: {did}}}
	acc := &domain.NotificationAccount{
		IncludeManaged: true,
		Scopes:         []domain.NotifyScope{{Kind: domain.NotifyScopeDomain, TargetID: did}},
	}
	ok, err := s.accountScopeMatches(nil, st, acc, managedEvent(mid))
	if err != nil || !ok {
		t.Fatalf("linked domain scope: ok=%v err=%v", ok, err)
	}
	acc.Scopes[0].TargetID = other
	ok, err = s.accountScopeMatches(nil, st, acc, managedEvent(mid))
	if err != nil || ok {
		t.Fatalf("unrelated domain: ok=%v err=%v", ok, err)
	}
}

func TestManagedCertGroupLinkScope(t *testing.T) {
	s := &Services{}
	mid, did, gid := uuid.New(), uuid.New(), uuid.New()
	st := &scopeStub{
		linked: map[uuid.UUID][]uuid.UUID{mid: {did}},
		groups: map[uuid.UUID][]uuid.UUID{did: {gid}},
	}
	acc := &domain.NotificationAccount{
		IncludeManaged: true,
		Scopes:         []domain.NotifyScope{{Kind: domain.NotifyScopeGroup, TargetID: gid}},
	}
	ok, err := s.accountScopeMatches(nil, st, acc, managedEvent(mid))
	if err != nil || !ok {
		t.Fatalf("linked group scope: ok=%v err=%v", ok, err)
	}
}

func TestEventManagedCertID(t *testing.T) {
	if eventManagedCertID(&domain.Event{}) != nil {
		t.Fatal("empty details")
	}
	id := uuid.New()
	got := eventManagedCertID(managedEvent(id))
	if got == nil || *got != id {
		t.Fatalf("got %v want %v", got, id)
	}
}
