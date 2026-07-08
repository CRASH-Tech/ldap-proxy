// Package config loads the proxy configuration from environment variables.
package config

import (
	"log"
	"os"
	"strconv"
	"time"
)

// Config holds the runtime configuration of the proxy. See the README for the
// environment variable that backs each field and its default value.
type Config struct {
	LdapServer    string
	Listen        string
	UsersDN       string
	UseTLS        bool
	CertFile      string
	CertKeyFile   string
	MaxSessions   int
	MaxConnsPerIP int
	MaxRPS        int
	ConnTimeout   time.Duration
	CacheTTL      time.Duration
}

// New reads the configuration from the environment. It terminates the process
// if a required variable is missing.
func New() *Config {
	return &Config{
		LdapServer:    getEnv("LDAP_SERVER", true, ""),
		Listen:        getEnv("LISTEN", true, ""),
		UsersDN:       getEnv("USERS_DN", true, ""),
		UseTLS:        getEnvAsBool("USE_TLS", false, false),
		CertFile:      getEnv("CERT_FILE", false, ""),
		CertKeyFile:   getEnv("CERT_KEY_FILE", false, ""),
		MaxSessions:   GetEnvAsInt("MAX_SESSIONS", false, 100),
		MaxConnsPerIP: GetEnvAsInt("MAX_CONNS_PER_IP", false, 10),
		MaxRPS:        GetEnvAsInt("MAX_RPS_PER_IP", false, 1),
		ConnTimeout:   getEnvAsDuration("CONN_TIMEOUT", false, 60*time.Second),
		CacheTTL:      getEnvAsDuration("CACHE_TTL", false, 5*time.Minute),
	}
}

func getEnv(key string, required bool, defaultVal string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}

	if required {
		log.Fatalf("%s must be set!", key)
	}

	return defaultVal
}

func getEnvAsBool(key string, required bool, defaultVal bool) bool {
	valStr := getEnv(key, false, "")
	if val, err := strconv.ParseBool(valStr); err == nil {
		return val
	}

	if required {
		log.Fatalf("%s must be set!", key)
	}

	return defaultVal
}

func GetEnvAsInt(key string, required bool, defaultVal int) int {
	valStr := getEnv(key, false, "")
	if val, err := strconv.Atoi(valStr); err == nil {
		return val
	}

	if required {
		log.Fatalf("%s must be set!", key)
	}

	return defaultVal
}

func getEnvAsDuration(key string, required bool, defaultVal time.Duration) time.Duration {
	valStr := getEnv(key, false, "")
	if valStr == "" {
		if required {
			log.Fatalf("%s must be set!", key)
		}
		return defaultVal
	}

	// A Go duration string, e.g. "500ms", "30s", "5m", "1h".
	if val, err := time.ParseDuration(valStr); err == nil {
		return val
	}

	// A bare whole number is interpreted as seconds, so "1" means 1s. This
	// matches the common expectation and avoids the surprising case where a
	// unit-less value silently falls back to the default.
	if secs, err := strconv.Atoi(valStr); err == nil {
		return time.Duration(secs) * time.Second
	}

	// A non-empty but unparseable value is a configuration error: fail loudly
	// rather than silently masking it with the default.
	log.Fatalf("%s must be a valid duration (e.g. \"5m\", \"30s\") or a whole number of seconds, got %q", key, valStr)
	return defaultVal
}
