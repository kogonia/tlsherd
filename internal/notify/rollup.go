package notify

import "github.com/kogonia/tlsherd/internal/domain"

// RollupStatus computes the event-level notify_status from destination rows.
func RollupStatus(rows []domain.EventNotification) string {
	if len(rows) == 0 {
		return domain.NotifyStatusNone
	}
	var nPending, nSent, nFailed, nSkipped int
	for _, r := range rows {
		switch r.Status {
		case domain.NotifyOutboxPending:
			nPending++
		case domain.NotifyOutboxSent:
			nSent++
		case domain.NotifyOutboxFailed:
			nFailed++
		case domain.NotifyOutboxSkipped:
			nSkipped++
		}
	}
	total := len(rows)
	switch {
	case nSkipped == total:
		return domain.NotifyStatusSkipped
	case nSent == total:
		return domain.NotifyStatusSent
	case nPending > 0 && nFailed == 0 && nSent == 0:
		return domain.NotifyStatusPending
	case nPending == 0 && nFailed > 0 && nSent == 0:
		return domain.NotifyStatusFailed
	case nSent > 0 && (nPending > 0 || nFailed > 0):
		return domain.NotifyStatusPartial
	case nPending > 0 && nFailed > 0:
		return domain.NotifyStatusPartial
	default:
		return domain.NotifyStatusPartial
	}
}
