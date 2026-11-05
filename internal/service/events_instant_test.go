package service

import "testing"

func TestIsInstantEvent(t *testing.T) {
	t.Parallel()
	for _, typ := range []string{EvAgentAccepted, EvAgentRejected, EvAgentConfigUpdated, EvCertRollback} {
		if !IsInstantEvent(typ) {
			t.Fatalf("%s should be instant", typ)
		}
	}
	for _, typ := range []string{EvAgentOffline, EvAgentEnrollPending, EvCertExpired, EvEndpointDown} {
		if IsInstantEvent(typ) {
			t.Fatalf("%s must stay open until resolved", typ)
		}
	}
}
