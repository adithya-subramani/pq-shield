package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ListenAddr    string `yaml:"listen_addr"`
	MetricsAddr   string `yaml:"metrics_addr"`
	UpstreamURL   string `yaml:"upstream_url"`
	CertFile      string `yaml:"cert_file"`
	KeyFile       string `yaml:"key_file"`
	StrictPQC     bool   `yaml:"strict_pqc"`
	UpstreamMTLS  bool   `yaml:"upstream_mtls"`
	UpstreamCA    string `yaml:"upstream_ca_file"`
	UpstreamCert  string `yaml:"upstream_cert_file"`
	UpstreamKey   string `yaml:"upstream_key_file"`
	DrainTimeout  int    `yaml:"drain_timeout_seconds"`
	LogLevel      string `yaml:"log_level"`
}

func Default() *Config {
	return &Config{
		ListenAddr:   ":8443",
		MetricsAddr:  ":9090",
		UpstreamURL:  "http://127.0.0.1:8080",
		CertFile:     "./certs/server.crt",
		KeyFile:      "./certs/server.key",
		StrictPQC:    false,
		UpstreamMTLS: false,
		DrainTimeout: 15,
		LogLevel:     "info",
	}
}

func Load(path string) (*Config, error) {
	cfg := Default()

	if path != "" {
		if _, err := os.Stat(path); err == nil {
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("failed to read config file: %w", err)
			}
			if err := yaml.Unmarshal(data, cfg); err != nil {
				return nil, fmt.Errorf("failed to parse config YAML: %w", err)
			}
		}
	}

	applyEnvOverrides(cfg)

	if err := validate(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("PQSHIELD_LISTEN_ADDR"); v != "" {
		cfg.ListenAddr = v
	}
	if v := os.Getenv("PQSHIELD_METRICS_ADDR"); v != "" {
		cfg.MetricsAddr = v
	}
	if v := os.Getenv("PQSHIELD_UPSTREAM_URL"); v != "" {
		cfg.UpstreamURL = v
	}
	if v := os.Getenv("PQSHIELD_CERT_FILE"); v != "" {
		cfg.CertFile = v
	}
	if v := os.Getenv("PQSHIELD_KEY_FILE"); v != "" {
		cfg.KeyFile = v
	}
	if v := os.Getenv("PQSHIELD_STRICT_PQC"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.StrictPQC = b
		}
	}
	if v := os.Getenv("PQSHIELD_UPSTREAM_MTLS"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.UpstreamMTLS = b
		}
	}
	if v := os.Getenv("PQSHIELD_UPSTREAM_CA_FILE"); v != "" {
		cfg.UpstreamCA = v
	}
	if v := os.Getenv("PQSHIELD_UPSTREAM_CERT_FILE"); v != "" {
		cfg.UpstreamCert = v
	}
	if v := os.Getenv("PQSHIELD_UPSTREAM_KEY_FILE"); v != "" {
		cfg.UpstreamKey = v
	}
	if v := os.Getenv("PQSHIELD_DRAIN_TIMEOUT_SECONDS"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			cfg.DrainTimeout = i
		}
	}
	if v := os.Getenv("PQSHIELD_LOG_LEVEL"); v != "" {
		cfg.LogLevel = strings.ToLower(v)
	}
}

func validate(cfg *Config) error {
	var errs []string

	if cfg.ListenAddr == "" {
		errs = append(errs, "listen_addr is required")
	}
	if cfg.MetricsAddr == "" {
		errs = append(errs, "metrics_addr is required")
	}
	if cfg.UpstreamURL == "" {
		errs = append(errs, "upstream_url is required")
	}
	if cfg.CertFile == "" {
		errs = append(errs, "cert_file is required")
	}
	if cfg.KeyFile == "" {
		errs = append(errs, "key_file is required")
	}
	if cfg.DrainTimeout <= 0 {
		errs = append(errs, "drain_timeout_seconds must be positive")
	}
	if cfg.UpstreamMTLS {
		if cfg.UpstreamCA == "" {
			errs = append(errs, "upstream_ca_file is required when upstream_mtls=true")
		}
		if cfg.UpstreamCert == "" {
			errs = append(errs, "upstream_cert_file is required when upstream_mtls=true")
		}
		if cfg.UpstreamKey == "" {
			errs = append(errs, "upstream_key_file is required when upstream_mtls=true")
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("configuration errors: %s", strings.Join(errs, "; "))
	}
	return nil
}
