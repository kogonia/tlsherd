package agentcfg

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// InWindow reports whether t falls inside the maintenance window.
// Midnight wrap (from > to) is supported. Empty days means all days.
func InWindow(w MaintenanceWindow, t time.Time) (bool, error) {
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
	fromM, err := parseHHMM(w.From)
	if err != nil {
		return false, err
	}
	toM, err := parseHHMM(w.To)
	if err != nil {
		return false, err
	}
	nowM := local.Hour()*60 + local.Minute()
	if fromM == toM {
		return true, nil // whole day
	}
	if fromM < toM {
		return nowM >= fromM && nowM < toM, nil
	}
	// wraps midnight
	return nowM >= fromM || nowM < toM, nil
}

func parseHHMM(s string) (int, error) {
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

// IsUrgent reports whether notAfter is within threshold of now.
func IsUrgent(notAfter time.Time, threshold time.Duration, now time.Time) bool {
	return !notAfter.After(now.Add(threshold))
}
