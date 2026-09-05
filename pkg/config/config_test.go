package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := Default()
	if cfg.ListenAddr != ":8443" {
		t.Errorf("expected default listen :8443, got %q", cfg.ListenAddr)
	}
	if cfg.MetricsAddr != ":9090" {
		t.Errorf("expected default metrics :9090, got %q", cfg.MetricsAddr)
	}
	if cfg.StrictPQC {
		t.Error("expected strict_pqc default false")
	}
	if cfg.DrainTimeout != 15 {
		t.Errorf("expected drain_timeout 15s, got %d", cfg.DrainTimeout)
	}
	if err := validate(cfg); err != nil {
		t.Errorf("default config should be valid: %v", err)
	}
}

func TestLoadFromYAML(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "pq.yaml")
	content := []byte(`
listen_addr: ":443"
metrics_addr: ":9091"
upstream_url: "https://backend.example.local:8443"
cert_file: "/tmp/tls.crt"
key_file: "/tmp/tls.key"
strict_pqc: true
drain_timeout_seconds: 30
log_level: "debug"
`)
	if err := os.WriteFile(cfgPath, content, 0o644); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.ListenAddr != ":443" {
		t.Errorf("listen_addr want :443, got %q", cfg.ListenAddr)
	}
	if !cfg.StrictPQC {
		t.Error("expected strict_pqc true from YAML")
	}
	if cfg.DrainTimeout != 30 {
		t.Errorf("drain_timeout want 30, got %d", cfg.DrainTimeout)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("log_level want debug, got %q", cfg.LogLevel)
	}
}

func TestEnvOverrides(t *testing.T) {
	setEnv := map[string]string{
		"PQSHIELD_LISTEN_ADDR":        ":7443",
		"PQSHIELD_METRICS_ADDR":       ":7070",
		"PQSHIELD_UPSTREAM_URL":       "http://127.0.0.1:9000",
		"PQSHIELD_CERT_FILE":          "/tmp/env.crt",
		"PQSHIELD_KEY_FILE":           "/tmp/env.key",
		"PQSHIELD_STRICT_PQC":         "true",
		"PQSHIELD_DRAIN_TIMEOUT_SECONDS": "42",
		"PQSHIELD_LOG_LEVEL":          "warn",
	}
	for k, v := range setEnv {
		t.Setenv(k, v)
	}

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load with env overrides: %v", err)
	}
	if cfg.ListenAddr != ":7443" {
		t.Errorf("ListenAddr override: want :7443, got %q", cfg.ListenAddr)
	}
	if !cfg.StrictPQC {
		t.Error("StrictPQC env override failed")
	}
	if cfg.DrainTimeout != 42 {
		t.Errorf("DrainTimeout override: want 42, got %d", cfg.DrainTimeout)
	}
	if cfg.LogLevel != "warn" {
		t.Errorf("LogLevel override: want warn, got %q", cfg.LogLevel)
	}
}

func TestValidateMissingFields(t *testing.T) {
	cfg := &Config{}
	err := validate(cfg)
	if err == nil {
		t.Fatal("expected validation error for empty config")
	}
	msg := err.Error()
	checks := []string{"listen_addr", "metrics_addr", "upstream_url", "cert_file", "key_file", "drain_timeout_seconds"}
	for _, c := range checks {
		if !contains(msg, c) {
			t.Errorf("expected error to mention %q, got %q", c, msg)
		}
	}
}

func TestValidateUpstreamMTLSRequiresCerts(t *testing.T) {
	cfg := Default()
	cfg.UpstreamMTLS = true
	cfg.UpstreamCA = ""
	cfg.UpstreamCert = ""
	cfg.UpstreamKey = ""
	err := validate(cfg)
	if err == nil {
		t.Fatal("expected validation error for mTLS without certs")
	}
	msg := err.Error()
	for _, f := range []string{"upstream_ca_file", "upstream_cert_file", "upstream_key_file"} {
		if !contains(msg, f) {
			t.Errorf("expected mTLS error to mention %q, got %q", f, msg)
		}
	}
}

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
