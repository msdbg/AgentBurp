package core

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type Config struct {
	ProxyPort     int    `json:"proxy_port" yaml:"proxy_port"`
	ProxyHost     string `json:"proxy_host" yaml:"proxy_host"`
	UpstreamProxy string `json:"upstream_proxy,omitempty" yaml:"upstream_proxy,omitempty"`

	RateLimitPerHost int      `json:"rate_limit_per_host" yaml:"rate_limit_per_host"`
	MaxRequestsTotal int      `json:"max_requests_total" yaml:"max_requests_total"`
	DeniedMethods    []string `json:"denied_methods" yaml:"denied_methods"`
	DryRunByDefault  bool     `json:"dry_run_by_default" yaml:"dry_run_by_default"`

	IgnoreExtensions []string `json:"ignore_extensions" yaml:"ignore_extensions"`
	MaxBodyBytes     int64    `json:"max_body_bytes" yaml:"max_body_bytes"`

	ActiveSessionID string `json:"active_session_id" yaml:"active_session_id"`

	TruncateBodyAt int `json:"truncate_body_at" yaml:"truncate_body_at"`
}

func DefaultConfig() Config {
	return Config{
		ProxyPort:        8080,
		ProxyHost:        "127.0.0.1",
		RateLimitPerHost: 10,
		MaxRequestsTotal: 0,
		DeniedMethods:    []string{},
		DryRunByDefault:  false,
		IgnoreExtensions: []string{
			".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
			".woff", ".woff2", ".ttf", ".eot",
			".mp4", ".mp3", ".avi", ".mov",
		},
		MaxBodyBytes:   10 * 1024 * 1024,
		TruncateBodyAt: 4096,
	}
}

func LoadConfig(projectName string) (Config, error) {
	cfg := DefaultConfig()
	path := filepath.Join(ProjectDir(projectName), "config.json")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func SaveConfig(projectName string, cfg Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(ProjectDir(projectName), "config.json")
	return os.WriteFile(path, data, 0o644)
}
