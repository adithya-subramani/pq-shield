package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"

	"github.com/pq-shield/pq-shield/pkg/metrics"
)

type recorderCtxKey struct{}

func NewPQCServerConfig(certFile, keyFile string, strictMode bool) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificates: %w", err)
	}

	rootConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768,
			tls.X25519,
			tls.CurveP256,
		},
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_128_GCM_SHA256,
		},
		NextProtos: []string{"h2", "http/1.1"},
	}

	rootConfig.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		hasPQCCapability := false
		for _, curve := range chi.SupportedCurves {
			if curve == tls.X25519MLKEM768 {
				hasPQCCapability = true
				break
			}
		}

		metrics.RecordClientHello(hasPQCCapability)

		slog.Debug("ClientHello received",
			"server_name", chi.ServerName,
			"pqc_capable", hasPQCCapability,
			"remote_addr", addrString(chi),
		)

		if strictMode && !hasPQCCapability {
			slog.Warn("Strict-PQC mode: rejecting client without PQC capability",
				"server_name", chi.ServerName,
				"remote_addr", addrString(chi),
			)
			return nil, fmt.Errorf("connection rejected: client lacks PQC support in strict mode")
		}

		perConn := rootConfig.Clone()
		recorder := metrics.NewHandshakeRecorder(hasPQCCapability)

		perConn.VerifyConnection = func(state tls.ConnectionState) error {
			recorder.Complete(state)
			return nil
		}

		_ = context.WithValue(context.Background(), recorderCtxKey{}, recorder)

		return perConn, nil
	}

	return rootConfig, nil
}

func NewUpstreamTLSConfig(caFile, clientCertFile, clientKeyFile string) (*tls.Config, error) {
	tc := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768,
			tls.X25519,
			tls.CurveP256,
		},
	}

	if clientCertFile != "" && clientKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load upstream client certificate: %w", err)
		}
		tc.Certificates = []tls.Certificate{cert}
	}

	if caFile != "" {
		pool, err := LoadCertPool(caFile)
		if err != nil {
			return nil, err
		}
		tc.RootCAs = pool
	}

	return tc, nil
}

func LoadCertPool(caFile string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA file %s: %w", caFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("failed to parse CA certificate from %s", caFile)
	}
	return pool, nil
}

func WithRecorder(ctx context.Context, r *metrics.HandshakeRecorder) context.Context {
	return context.WithValue(ctx, recorderCtxKey{}, r)
}

func RecorderFromContext(ctx context.Context) *metrics.HandshakeRecorder {
	if r, ok := ctx.Value(recorderCtxKey{}).(*metrics.HandshakeRecorder); ok {
		return r
	}
	return nil
}

type addrProvider interface {
	RemoteAddr() string
}

func addrString(chi *tls.ClientHelloInfo) string {
	if chi == nil || chi.Conn == nil {
		return "<unknown>"
	}
	return chi.Conn.RemoteAddr().String()
}
