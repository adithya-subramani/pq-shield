package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/pq-shield/pq-shield/pkg/config"
	"github.com/pq-shield/pq-shield/pkg/metrics"
	"github.com/pq-shield/pq-shield/pkg/proxy"
)

func main() {
	var (
		configPath  = flag.String("config", "", "Path to YAML config file (optional)")
		certFile    = flag.String("cert", "", "TLS certificate file (overrides config)")
		keyFile     = flag.String("key", "", "TLS private key file (overrides config)")
		listenAddr  = flag.String("listen", "", "Listen address for TLS (overrides config)")
		metricsAddr = flag.String("metrics", "", "Listen address for metrics endpoint (overrides config)")
		upstream    = flag.String("upstream", "", "Upstream backend URL (overrides config)")
		strictPQC   = flag.Bool("strict-pqc", false, "Enable strict PQC-only mode (overrides config)")
	)
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("Failed to load configuration", "error", err)
		os.Exit(1)
	}

	// Apply CLI overrides
	if *certFile != "" {
		cfg.CertFile = *certFile
	}
	if *keyFile != "" {
		cfg.KeyFile = *keyFile
	}
	if *listenAddr != "" {
		cfg.ListenAddr = *listenAddr
	}
	if *metricsAddr != "" {
		cfg.MetricsAddr = *metricsAddr
	}
	if *upstream != "" {
		cfg.UpstreamURL = *upstream
	}
	if *strictPQC {
		cfg.StrictPQC = true
	}

	initLogging(cfg.LogLevel)

	slog.Info("pq-shield starting",
		"listen_addr", cfg.ListenAddr,
		"metrics_addr", cfg.MetricsAddr,
		"upstream_url", cfg.UpstreamURL,
		"strict_pqc", cfg.StrictPQC,
		"upstream_mtls", cfg.UpstreamMTLS,
	)

	var upstreamTLSConfig *tls.Config
	if cfg.UpstreamMTLS {
		upstreamTLSConfig, err = buildUpstreamTLSConfig(cfg)
		if err != nil {
			slog.Error("Failed to build upstream mTLS config", "error", err)
			os.Exit(1)
		}
	}

	revProxy, err := proxy.NewUpstreamProxy(cfg.UpstreamURL, upstreamTLSConfig)
	if err != nil {
		slog.Error("Failed to create upstream reverse proxy", "error", err)
		os.Exit(1)
	}

	tlsConfig, err := proxy.NewPQCServerConfig(cfg.CertFile, cfg.KeyFile, cfg.StrictPQC)
	if err != nil {
		slog.Error("Failed to create PQC TLS server config", "error", err)
		os.Exit(1)
	}

	// Setup Telemetry Metrics Server
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", metrics.Get().Handler())

	// Mount pprof handlers onto the custom metrics ServeMux
	metricsMux.Handle("/debug/pprof/", http.DefaultServeMux)

	metricsSrv := &http.Server{
		Addr:         cfg.MetricsAddr,
		Handler:      metricsMux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		slog.Info("Metrics endpoint listening", "addr", cfg.MetricsAddr)
		if serveErr := metricsSrv.ListenAndServe(); serveErr != nil && serveErr != http.ErrServerClosed {
			slog.Error("Metrics server failed", "error", serveErr)
		}
	}()

	// Setup Primary TLS Reverse Proxy Server
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","strict_pqc":%t,"upstream":%q}`, cfg.StrictPQC, cfg.UpstreamURL)
	})
	mux.Handle("/", revProxy)

	tlsListener, err := tls.Listen("tcp", cfg.ListenAddr, tlsConfig)
	if err != nil {
		slog.Error("Failed to start TLS listener", "error", err)
		os.Exit(1)
	}

	mainSrv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		slog.Info("TLS proxy accepting connections", "addr", cfg.ListenAddr)
		if serveErr := mainSrv.Serve(tlsListener); serveErr != nil && serveErr != http.ErrServerClosed {
			slog.Error("TLS proxy server failed", "error", serveErr)
		}
	}()

	sig := <-sigCh
	slog.Info("Shutdown signal received, initiating graceful drain", "signal", sig.String())

	drainCtx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.DrainTimeout)*time.Second)
	defer cancel()

	// Shutdown main server first (this handles listener closure cleanly)
	if shutdownErr := mainSrv.Shutdown(drainCtx); shutdownErr != nil {
		slog.Warn("Main server graceful shutdown timed out", "error", shutdownErr)
	}

	metricsShutdownCtx, metricsCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer metricsCancel()
	if shutdownErr := metricsSrv.Shutdown(metricsShutdownCtx); shutdownErr != nil {
		slog.Warn("Metrics server shutdown timed out", "error", shutdownErr)
	}

	wg.Wait()
	slog.Info("pq-shield shutdown complete")
}

func initLogging(level string) {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl})
	slog.SetDefault(slog.New(handler))
}

func buildUpstreamTLSConfig(cfg *config.Config) (*tls.Config, error) {
	caPool, err := proxy.LoadCertPool(cfg.UpstreamCA)
	if err != nil {
		return nil, err
	}
	tc := &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    caPool,
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768,
			tls.X25519,
			tls.CurveP256,
		},
	}
	if cfg.UpstreamCert != "" && cfg.UpstreamKey != "" {
		clientCert, loadErr := tls.LoadX509KeyPair(cfg.UpstreamCert, cfg.UpstreamKey)
		if loadErr != nil {
			return nil, fmt.Errorf("failed to load upstream client cert: %w", loadErr)
		}
		tc.Certificates = []tls.Certificate{clientCert}
	}
	return tc, nil
}
