package auth

import (
	"fmt"
	"os"

	"go.yaml.in/yaml/v3"
)

type CaptureConfig struct {
	Cookies bool     `yaml:"cookies" json:"cookies"`
	Headers []string `yaml:"headers" json:"headers"`
}

type CSRFConfig struct {
	Field string `yaml:"field" json:"field"`
	URL   string `yaml:"url" json:"url,omitempty"`
}

type AuthProfile struct {
	Name    string                 `yaml:"name" json:"name"`
	Type    string                 `yaml:"type" json:"type"`
	URL     string                 `yaml:"url" json:"url"`
	Method  string                 `yaml:"method" json:"method"`
	Body    map[string]interface{} `yaml:"body" json:"body,omitempty"`
	Form    map[string]string      `yaml:"form" json:"form,omitempty"`
	Headers map[string]string      `yaml:"headers" json:"headers,omitempty"`

	Username string `yaml:"username" json:"username,omitempty"`
	Password string `yaml:"password" json:"password,omitempty"`
	Token    string `yaml:"token" json:"token,omitempty"`

	TokenFields     []string `yaml:"token_fields" json:"token_fields,omitempty"`
	TokenFromHeader string   `yaml:"token_from_header" json:"token_from_header,omitempty"`
	RefreshURL      string   `yaml:"refresh_url" json:"refresh_url,omitempty"`

	CSRF CSRFConfig `yaml:"csrf" json:"csrf,omitempty"`

	Capture CaptureConfig `yaml:"capture" json:"capture"`
}

func LoadProfile(path string) (*AuthProfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read auth profile: %w", err)
	}
	var p AuthProfile
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse auth profile %q: %w", path, err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

func (p *AuthProfile) Validate() error {
	switch p.Type {
	case "json_login", "form_login":
		if p.URL == "" {
			return fmt.Errorf("auth profile %q: --url/url is required for %s", p.Name, p.Type)
		}
	case "bearer":
		if p.Token == "" {
			return fmt.Errorf("auth profile %q: token is required for bearer", p.Name)
		}
	case "basic":
		if p.Username == "" {
			return fmt.Errorf("auth profile %q: username is required for basic", p.Name)
		}
	case "header":
		if len(p.Headers) == 0 {
			return fmt.Errorf("auth profile %q: headers are required for header type", p.Name)
		}
	default:
		return fmt.Errorf("auth profile %q: unsupported type %q — use json_login|form_login|bearer|basic|header", p.Name, p.Type)
	}
	return nil
}

func (p *AuthProfile) Substitute() *AuthProfile {
	cp := *p
	if cp.Username != "" {
		cp.Username = expandEnv(cp.Username)
	}
	if cp.Password != "" {
		cp.Password = expandEnv(cp.Password)
	}
	if cp.Token != "" {
		cp.Token = expandEnv(cp.Token)
	}
	if cp.URL != "" {
		cp.URL = expandEnv(cp.URL)
	}
	for k, v := range cp.Body {
		if s, ok := v.(string); ok {
			cp.Body[k] = expandEnv(s)
		}
	}
	for k, v := range cp.Form {
		cp.Form[k] = expandEnv(v)
	}
	for k, v := range cp.Headers {
		cp.Headers[k] = expandEnv(v)
	}
	return &cp
}

func expandEnv(s string) string {
	return os.Expand(s, func(key string) string {
		return os.Getenv(key)
	})
}
