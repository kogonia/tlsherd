package agentcfg

import (
	"testing"
	"time"
)

func TestInWindow(t *testing.T) {
	w := MaintenanceWindow{TZ: "UTC", Days: []int{1, 2, 3, 4, 5, 6, 7}, From: "02:00", To: "04:00"}
	inside := time.Date(2026, 11, 4, 2, 30, 0, 0, time.UTC) // Wednesday
	ok, err := InWindow(w, inside)
	if err != nil || !ok {
		t.Fatalf("expected inside, ok=%v err=%v", ok, err)
	}
	outside := time.Date(2026, 11, 4, 5, 0, 0, 0, time.UTC)
	ok, err = InWindow(w, outside)
	if err != nil || ok {
		t.Fatalf("expected outside, ok=%v err=%v", ok, err)
	}
}

func TestInWindowAllDay(t *testing.T) {
	w := MaintenanceWindow{TZ: "UTC", Days: []int{1, 2, 3, 4, 5, 6, 7}, From: "00:00", To: "00:00"}
	for _, hour := range []int{0, 3, 12, 23} {
		ok, err := InWindow(w, time.Date(2026, 11, 4, hour, 15, 0, 0, time.UTC))
		if err != nil || !ok {
			t.Fatalf("hour %d: expected all-day inside, ok=%v err=%v", hour, ok, err)
		}
	}
}

func TestInWindowMidnightWrap(t *testing.T) {
	w := MaintenanceWindow{TZ: "UTC", Days: []int{1, 2, 3, 4, 5, 6, 7}, From: "23:00", To: "01:00"}
	ok, err := InWindow(w, time.Date(2026, 11, 4, 23, 30, 0, 0, time.UTC))
	if err != nil || !ok {
		t.Fatalf("expected inside wrap, ok=%v err=%v", ok, err)
	}
	ok, err = InWindow(w, time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC))
	if err != nil || ok {
		t.Fatalf("expected outside wrap, ok=%v err=%v", ok, err)
	}
}

func TestIsUrgent(t *testing.T) {
	now := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	if !IsUrgent(now.Add(24*time.Hour), 72*time.Hour, now) {
		t.Fatal("expected urgent")
	}
	if IsUrgent(now.Add(100*time.Hour), 72*time.Hour, now) {
		t.Fatal("expected not urgent")
	}
}

func TestHashStable(t *testing.T) {
	c := Default()
	h1, err := Hash(c)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := Hash(c)
	if err != nil || h1 != h2 {
		t.Fatalf("hash unstable: %s vs %s", h1, h2)
	}
}
