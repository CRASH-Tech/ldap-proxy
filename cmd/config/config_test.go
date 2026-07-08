package config

import (
	"testing"
	"time"
)

func TestGetEnvAsDuration(t *testing.T) {
	const key = "TEST_CACHE_TTL"

	cases := []struct {
		name string
		set  bool
		val  string
		want time.Duration
	}{
		{name: "unset returns default", set: false, want: 5 * time.Minute},
		{name: "empty returns default", set: true, val: "", want: 5 * time.Minute},
		{name: "duration string", set: true, val: "30s", want: 30 * time.Second},
		{name: "minutes", set: true, val: "2m", want: 2 * time.Minute},
		{name: "bare integer is seconds", set: true, val: "1", want: 1 * time.Second},
		{name: "bare integer 30 is seconds", set: true, val: "30", want: 30 * time.Second},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.set {
				t.Setenv(key, tc.val)
			} else {
				t.Setenv(key, "")
				// t.Setenv guarantees restore; emulate "unset" via empty which
				// takes the same default path.
			}
			got := getEnvAsDuration(key, false, 5*time.Minute)
			if got != tc.want {
				t.Fatalf("getEnvAsDuration(%q) = %v, want %v", tc.val, got, tc.want)
			}
		})
	}
}
