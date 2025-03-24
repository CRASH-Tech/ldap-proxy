package config

import (
	"log"
	"os"
	"strconv"
)

type Config struct {
	LdapServer  string
	Listen      string
	UsersDN     string
	UseTLS      bool
	CertFile    string
	CertKeyFile string
	MaxSessions int
}

func New() *Config {
	return &Config{
		LdapServer:  getEnv("LDAP_SERVER", true, ""),
		Listen:      getEnv("LISTEN", true, ""),
		UsersDN:     getEnv("USERS_DN", true, ""),
		UseTLS:      getEnvAsBool("USE_TLS", false, false),
		CertFile:    getEnv("CERT_FILE", false, ""),
		CertKeyFile: getEnv("CERT_KEY_FILE", false, ""),
		MaxSessions: GetEnvAsInt("MAX_SESSIONS", false, 1000),
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
