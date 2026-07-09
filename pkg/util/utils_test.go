package util

import (
	"testing"
	"time"
)

func TestFormatValidityPeriodISO8601(t *testing.T) {
	day := 24 * time.Hour
	cases := []struct {
		name string
		in   time.Duration
		want string
	}{
		// Whole days -> day form (the VC-55689 fix: ZTPKI honors P<days>D, not PT<hours>H).
		{"1 day", 1 * day, "P1D"},
		{"30 days (terraform valid_days=30)", 30 * day, "P30D"},
		{"90 days", 90 * day, "P90D"},
		{"365 days", 365 * day, "P365D"},
		{"397 days", 397 * day, "P397D"},
		{"1 day via hours", 24 * time.Hour, "P1D"},
		{"30 days via hours (valid_days*24)", 720 * time.Hour, "P30D"},

		// Sub-day only -> time-only form (unchanged from previous behavior; built-in honors it).
		{"12 hours", 12 * time.Hour, "PT12H0M0S"},
		{"90 minutes", 90 * time.Minute, "PT1H30M0S"},
		{"30 seconds", 30 * time.Second, "PT30S"},

		// Days + sub-day remainder -> combined form (day component honored by ZTPKI).
		{"1 day 12 hours", day + 12*time.Hour, "P1DT12H0M0S"},
		{"1 day 1 hour", day + 1*time.Hour, "P1DT1H0M0S"},
		{"30 days 30 minutes", 30*day + 30*time.Minute, "P30DT30M0S"},
		{"1 day 2 hours 3 minutes 4 seconds", day + 2*time.Hour + 3*time.Minute + 4*time.Second, "P1DT2H3M4S"},

		// Truncated to whole seconds.
		{"30 days + sub-second", 30*day + 999*time.Millisecond, "P30D"},
		{"500ms", 500 * time.Millisecond, ""},

		// Non-positive -> empty (field omitted, server default applies).
		{"zero", 0, ""},
		{"negative", -5 * time.Hour, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := FormatValidityPeriodISO8601(c.in)
			if got != c.want {
				t.Errorf("FormatValidityPeriodISO8601(%s) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}
