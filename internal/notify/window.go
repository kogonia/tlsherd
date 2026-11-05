// Package notify implements outbound notification delivery (SMTP, Telegram, webhook).
package notify

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Window is a working-hours schedule in an account timezone.
type Window struct {
	TZ   string
	Days []int // 1=Mon … 7=Sun; empty = all days
	From string
	To   string
}

// InWindow reports whether t is inside the working window.
// Midnight wrap (from > to) is supported. Empty days means all days.
// from==to, or 00:00–24:00, means always on.
func InWindow(w Window, t time.Time) (bool, error) {
	loc := time.UTC
	if w.TZ != "" {
		var err error
		loc, err = time.LoadLocation(w.TZ)
		if err != nil {
			return false, err
		}
	}
	local := t.In(loc)
	weekday := int(local.Weekday())
	if weekday == 0 {
		weekday = 7
	}
	if len(w.Days) > 0 {
		ok := false
		for _, d := range w.Days {
			if d == weekday {
				ok = true
				break
			}
		}
		if !ok {
			return false, nil
		}
	}
	fromM, err := parseHHMMAllow24(w.From)
	if err != nil {
		return false, err
	}
	toM, err := parseHHMMAllow24(w.To)
	if err != nil {
		return false, err
	}
	nowM := local.Hour()*60 + local.Minute()
	if fromM == toM || (fromM == 0 && toM == 24*60) {
		return true, nil
	}
	if toM == 24*60 {
		toM = 24 * 60 // exclusive end at midnight next day → include all remaining minutes
		return nowM >= fromM && nowM < toM, nil
	}
	if fromM < toM {
		return nowM >= fromM && nowM < toM, nil
	}
	return nowM >= fromM || nowM < toM, nil
}

// NextWindowOpen returns the next time t enters the window (UTC). If already
// inside or always-on, returns t.
func NextWindowOpen(w Window, t time.Time) (time.Time, error) {
	ok, err := InWindow(w, t)
	if err != nil {
		return time.Time{}, err
	}
	if ok {
		return t, nil
	}
	loc := time.UTC
	if w.TZ != "" {
		loc, err = time.LoadLocation(w.TZ)
		if err != nil {
			return time.Time{}, err
		}
	}
	local := t.In(loc)
	fromM, err := parseHHMMAllow24(w.From)
	if err != nil {
		return time.Time{}, err
	}
	toM, err := parseHHMMAllow24(w.To)
	if err != nil {
		return time.Time{}, err
	}
	if fromM == toM || (fromM == 0 && toM == 24*60) {
		return t, nil
	}
	days := w.Days
	if len(days) == 0 {
		days = []int{1, 2, 3, 4, 5, 6, 7}
	}
	daySet := map[int]bool{}
	for _, d := range days {
		daySet[d] = true
	}
	for dayOffset := 0; dayOffset <= 8; dayOffset++ {
		day := local.AddDate(0, 0, dayOffset)
		wd := int(day.Weekday())
		if wd == 0 {
			wd = 7
		}
		if !daySet[wd] {
			continue
		}
		candidate := time.Date(day.Year(), day.Month(), day.Day(), fromM/60, fromM%60, 0, 0, loc)
		if candidate.After(t) {
			return candidate.UTC(), nil
		}
	}
	return t.Add(24 * time.Hour).UTC(), nil
}

func parseHHMMAllow24(s string) (int, error) {
	if s == "24:00" {
		return 24 * 60, nil
	}
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid time %q", s)
	}
	h, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, err
	}
	m, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, err
	}
	if h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, fmt.Errorf("invalid time %q", s)
	}
	return h*60 + m, nil
}
