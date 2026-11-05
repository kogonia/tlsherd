package service

import (
	"testing"

	"github.com/google/uuid"
	"github.com/kogonia/tlsherd/internal/domain"
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
