package notify

import (
	"testing"

	"github.com/kogonia/tlsherd/internal/domain"
)

func TestRollupStatus(t *testing.T) {
	row := func(st string) domain.EventNotification {
		return domain.EventNotification{Status: st}
	}
	cases := []struct {
		name string
		rows []domain.EventNotification
		want string
	}{
		{"empty", nil, domain.NotifyStatusNone},
		{"all sent", []domain.EventNotification{row("sent"), row("sent")}, domain.NotifyStatusSent},
		{"all skipped", []domain.EventNotification{row("skipped")}, domain.NotifyStatusSkipped},
		{"all pending", []domain.EventNotification{row("pending"), row("skipped")}, domain.NotifyStatusPending},
		{"all failed", []domain.EventNotification{row("failed"), row("skipped")}, domain.NotifyStatusFailed},
		{"partial sent+pending", []domain.EventNotification{row("sent"), row("pending")}, domain.NotifyStatusPartial},
		{"partial sent+failed", []domain.EventNotification{row("sent"), row("failed")}, domain.NotifyStatusPartial},
		{"partial pending+failed", []domain.EventNotification{row("pending"), row("failed")}, domain.NotifyStatusPartial},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := RollupStatus(tc.rows)
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}
