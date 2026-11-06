package service

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/kogonia/tlsherd/internal/domain"
	"github.com/kogonia/tlsherd/internal/store"
)

// ListEventsInput filters ListEvents.
type ListEventsInput struct {
	UnresolvedOnly bool
	Type           string
	DomainID       *uuid.UUID
	ServerID       *uuid.UUID
	Limit          int
	Offset         int
}

// ExpiringDomain is a dashboard entry for a soon-to-expire certificate.
type ExpiringDomain struct {
	DomainID uuid.UUID `json:"domain_id"`
	FQDN     string    `json:"fqdn"`
	NotAfter time.Time `json:"not_after"`
	DaysLeft int       `json:"days_left"`
}

// Dashboard aggregates what the actor is allowed to see.
type Dashboard struct {
	Domains             int              `json:"domains"`
	DomainsExpired      int              `json:"domains_expired"`
	DomainsExpiringSoon int              `json:"domains_expiring_soon"`
	DomainsUngrouped    int              `json:"domains_ungrouped"` // admin only
	Servers             map[string]int   `json:"servers"`           // by agent_status
	PendingEnrollments  int              `json:"pending_enrollments"`
	IdentityAlerts      int              `json:"identity_alerts"`
	OpenEvents          map[string]int   `json:"open_events"` // by severity
	EndpointsDown       int              `json:"endpoints_down"`
	Expiring            []ExpiringDomain `json:"expiring"`
}

// eventScope builds the SQL visibility scope for actor. Admins get the zero
// filter (everything). For operators every list is non-nil so that an empty
// scope matches nothing instead of everything.
func (s *Services) eventScope(ctx context.Context, actor *domain.User) (store.EventFilter, error) {
	if isAdmin(actor) {
		return store.EventFilter{}, nil
	}
	domains, err := s.Authz.VisibleDomainIDs(ctx, actor)
	if err != nil {
		return store.EventFilter{}, err
	}
	all, _, err := s.Authz.Perms(ctx, actor)
	if err != nil {
		return store.EventFilter{}, err
	}
	seen := map[uuid.UUID]struct{}{}
	servers := make([]uuid.UUID, 0)
	for _, did := range domains {
		dss, err := s.Store.ListDomainServersByDomain(ctx, did)
		if err != nil {
			return store.EventFilter{}, err
		}
		for _, ds := range dss {
			if _, ok := seen[ds.ServerID]; !ok {
				seen[ds.ServerID] = struct{}{}
				servers = append(servers, ds.ServerID)
			}
		}
	}
	groups := append(make([]uuid.UUID, 0, len(all.GroupIDs)), all.GroupIDs...)
	if domains == nil {
		domains = make([]uuid.UUID, 0)
	}
	return store.EventFilter{DomainIDs: domains, ServerIDs: servers, GroupIDs: groups}, nil
}

// DismissEvent marks an open event resolved by the actor. Admins may dismiss
// any event; operators may dismiss events they can already see.
func (s *Services) DismissEvent(ctx context.Context, actor *domain.User, id int64) error {
	ev, err := s.Store.GetEvent(ctx, id)
	if err != nil {
		return fmt.Errorf("dismiss event: %w", err)
	}
	if ev.ResolvedAt != nil {
		return nil
	}
	if !isAdmin(actor) {
		scope, err := s.eventScope(ctx, actor)
		if err != nil {
			return err
		}
		if !eventVisibleInScope(ev, scope) {
			return forbiddenf("insufficient permissions for this event")
		}
	}
	who := "user"
	if actor != nil {
		who = actor.Login
	}
	d := jsonDetails(map[string]any{eventDetailResolvedByKey: who})
	closed, err := s.Store.ResolveEventByID(ctx, id, s.now(), d)
	if err != nil {
		return fmt.Errorf("dismiss event: %w", err)
	}
	if closed != nil {
		s.notifyFanout(ctx, s.Store, closed, domain.NotifyKindResolved)
	}
	_ = s.audit(ctx, s.Store, actor, "event.dismiss", "event", fmt.Sprintf("%d", id),
		map[string]any{"type": ev.Type, "message": ev.Message})
	return nil
}

func eventVisibleInScope(ev *domain.Event, f store.EventFilter) bool {
	// Same OR-scope semantics as ListEvents SQL (any matching non-nil list).
	if f.DomainIDs == nil && f.ServerIDs == nil && f.GroupIDs == nil {
		return true
	}
	in := func(list []uuid.UUID, id *uuid.UUID) bool {
		if id == nil || list == nil {
			return false
		}
		for _, x := range list {
			if x == *id {
				return true
			}
		}
		return false
	}
	return in(f.DomainIDs, ev.DomainID) || in(f.ServerIDs, ev.ServerID) || in(f.GroupIDs, ev.GroupID)
}

// ListEvents lists events visible to actor, newest first. Visibility is
// enforced in the SQL query: admins see everything; operators see events of
// their readable domains, groups and servers.
func (s *Services) ListEvents(ctx context.Context, actor *domain.User, in ListEventsInput) ([]domain.Event, error) {
	f, err := s.eventScope(ctx, actor)
	if err != nil {
		return nil, fmt.Errorf("list events: %w", err)
	}
	f.UnresolvedOnly, f.Type, f.Limit, f.Offset = in.UnresolvedOnly, in.Type, in.Limit, in.Offset
	f.FilterDomainID, f.FilterServerID = in.DomainID, in.ServerID
	evs, err := s.Store.ListEvents(ctx, f)
	if err != nil {
		return nil, fmt.Errorf("list events: %w", err)
	}
	return evs, nil
}

// ListEventsWithNotify is ListEvents plus delivery status for the UI/API.
func (s *Services) ListEventsWithNotify(ctx context.Context, actor *domain.User, in ListEventsInput) ([]EventWithNotify, error) {
	evs, err := s.ListEvents(ctx, actor, in)
	if err != nil {
		return nil, err
	}
	return s.EnrichEventsWithNotify(ctx, evs)
}

// ListAudit returns the newest audit entries. Admin only.
func (s *Services) ListAudit(ctx context.Context, actor *domain.User, limit, offset int) ([]domain.AuditEntry, error) {
	if err := requireAdmin(actor); err != nil {
		return nil, err
	}
	out, err := s.Store.ListAudit(ctx, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list audit: %w", err)
	}
	return out, nil
}

// Dashboard computes aggregates limited to what actor may see.
func (s *Services) Dashboard(ctx context.Context, actor *domain.User) (*Dashboard, error) {
	out := &Dashboard{Servers: map[string]int{}, OpenEvents: map[string]int{}, Expiring: []ExpiringDomain{}}
	domains, err := s.ListDomains(ctx, actor)
	if err != nil {
		return nil, err
	}
	set := s.monitorSettings(ctx)
	now := s.now()
	out.Domains = len(domains)
	for _, d := range domains {
		if len(d.GroupIDs) == 0 {
			out.DomainsUngrouped++
		}
		if d.CurrentCertificate == nil {
			continue
		}
		left := d.CurrentCertificate.NotAfter.Sub(now)
		switch {
		case left <= 0:
			out.DomainsExpired++
		case left <= set.ExpiringSoon:
			out.DomainsExpiringSoon++
		}
		if left <= set.ExpiringSoon {
			out.Expiring = append(out.Expiring, ExpiringDomain{
				DomainID: d.ID, FQDN: d.FQDN, NotAfter: d.CurrentCertificate.NotAfter, DaysLeft: int(left.Hours() / 24),
			})
		}
	}
	sort.Slice(out.Expiring, func(i, j int) bool { return out.Expiring[i].NotAfter.Before(out.Expiring[j].NotAfter) })
	if len(out.Expiring) > 10 {
		out.Expiring = out.Expiring[:10]
	}

	servers, err := s.ListServers(ctx, actor)
	if err != nil {
		return nil, err
	}
	for _, sv := range servers {
		out.Servers[sv.AgentStatus]++
	}

	if isAdmin(actor) {
		pending, err := s.Store.ListEnrollments(ctx, domain.EnrollPending)
		if err != nil {
			return nil, fmt.Errorf("dashboard: %w", err)
		}
		out.PendingEnrollments = len(pending)
		for _, e := range pending {
			if e.Reason == domain.ReasonIdentityIPChanged || e.Reason == domain.ReasonIdentityKeyChanged {
				out.IdentityAlerts++
			}
		}
	}

	evs, err := s.ListEvents(ctx, actor, ListEventsInput{UnresolvedOnly: true, Limit: 1000})
	if err != nil {
		return nil, err
	}
	for _, e := range evs {
		out.OpenEvents[e.Severity]++
	}

	eps, err := s.ListEndpoints(ctx, actor)
	if err != nil {
		return nil, err
	}
	for _, ep := range eps {
		if ep.Enabled && ep.Latest != nil && (!ep.Latest.Reachable || !ep.Latest.TLSOK) {
			out.EndpointsDown++
		}
	}
	return out, nil
}
