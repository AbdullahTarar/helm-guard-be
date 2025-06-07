package config

import (
	"os"
	"time"
)

type Config struct {
	Server struct {
		Address string
	}
	GitHub struct {
		ClientID     string
		ClientSecret string
		RedirectURI  string
	}
	Helm struct {
		TempDir string
	}
	Security struct {
		CookieSecret string
	}
}

func Load() (*Config, error) {
	cfg := &Config{}

	// Server configuration
	cfg.Server.Address = getEnv("SERVER_ADDRESS", ":8080")

	// GitHub configuration
	cfg.GitHub.ClientID = getEnv("GITHUB_CLIENT_ID", "")
	cfg.GitHub.ClientSecret = getEnv("GITHUB_CLIENT_SECRET", "")
	cfg.GitHub.RedirectURI = getEnv("GITHUB_REDIRECT_URI", "")

	// Helm configuration
	cfg.Helm.TempDir = getEnv("HELM_TEMP_DIR", "/tmp/helm-scanner")

	// Security configuration
	cfg.Security.CookieSecret = getEnv("COOKIE_SECRET", "default-secret-please-change")

	return cfg, nil
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}