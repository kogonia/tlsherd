package notify

import (
	"testing"
	"time"
)

func TestInWindowAlways(t *testing.T) {
	w := Window{TZ: "UTC", Days: []int{1, 2, 3, 4, 5, 6, 7}, From: "00:00", To: "24:00"}
	ok, err := InWindow(w, time.Date(2026, 11, 5, 15, 0, 0, 0, time.UTC))
	if err != nil || !ok {
		t.Fatalf("always-on: ok=%v err=%v", ok, err)
	}
}

func TestInWindowBusinessHours(t *testing.T) {
	w := Window{TZ: "UTC", Days: []int{1, 2, 3, 4, 5}, From: "09:00", To: "17:00"}
	inside := time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC) // Thursday
	ok, err := InWindow(w, inside)
	if err != nil || !ok {
		t.Fatalf("inside: ok=%v err=%v", ok, err)
	}
	outside := time.Date(2026, 11, 5, 20, 0, 0, 0, time.UTC)
	ok, err = InWindow(w, outside)
	if err != nil || ok {
		t.Fatalf("outside hours: ok=%v err=%v", ok, err)
	}
	weekend := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC) // Saturday
	ok, err = InWindow(w, weekend)
	if err != nil || ok {
		t.Fatalf("weekend: ok=%v err=%v", ok, err)
	}
}

func TestNextWindowOpen(t *testing.T) {
	w := Window{TZ: "UTC", Days: []int{1, 2, 3, 4, 5}, From: "09:00", To: "17:00"}
	now := time.Date(2026, 11, 5, 20, 0, 0, 0, time.UTC) // Thu evening
	next, err := NextWindowOpen(w, now)
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 11, 6, 9, 0, 0, 0, time.UTC) // Friday 09:00
	if !next.Equal(want) {
		t.Fatalf("next=%s want=%s", next, want)
	}
}
