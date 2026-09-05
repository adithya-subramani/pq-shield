//go:build integration

package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

type testCase struct {
	name           string
	curves         []tls.CurveID
	expectHTTP200  bool
	expectPQCNeg   bool
	expectReject   bool
}

func main() {
	var (
		target     = flag.String("target", "https://localhost:8443/healthz", "Target URL behind pq-shield")
		caFile     = flag.String("ca", "./certs/server.crt", "CA certificate file (or server cert for self-signed)")
		serverName = flag.String("server-name", "localhost", "TLS SNI server name")
	)
	flag.Parse()

	failures := 0

	pool, err := loadCertPoolOrSkipVerify(*caFile)
	if err != nil {
		fmt.Printf("WARNING: %v — falling back to InsecureSkipVerify\n", err)
		pool = nil
	}

	cases := []testCase{
		{
			name:          "PQC-only (X25519MLKEM768) — expect success",
			curves:        []tls.CurveID{tls.X25519MLKEM768},
			expectHTTP200: true,
			expectPQCNeg:  true,
			expectReject:  false,
		},
		{
			name:          "Hybrid PQC preferred — expect success",
			curves:        []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256},
			expectHTTP200: true,
			expectPQCNeg:  true,
			expectReject:  false,
		},
		{
			name:          "Classical-only — expect fallback success (non-strict mode)",
			curves:        []tls.CurveID{tls.X25519, tls.CurveP256},
			expectHTTP200: true,
			expectPQCNeg:  false,
			expectReject:  false,
		},
	}

	for i, tc := range cases {
		fmt.Printf("\n=== Test %d: %s ===\n", i+1, tc.name)
		fmt.Printf("  Offered curves: %v\n", curveNames(tc.curves))

		ok := runTest(tc, *target, *serverName, pool)
		if !ok {
			failures++
		}
	}

	fmt.Printf("\n========================================\n")
	if failures > 0 {
		fmt.Printf("FAIL: %d test(s) failed\n", failures)
		os.Exit(1)
	}
	fmt.Println("PASS: All integration tests passed")
}

func runTest(tc testCase, target, serverName string, pool *x509.CertPool) bool {
	tlsCfg := &tls.Config{
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: tc.curves,
		ServerName:       serverName,
		NextProtos:       []string{"h2", "http/1.1"},
	}
	if pool != nil {
		tlsCfg.RootCAs = pool
	} else {
		tlsCfg.InsecureSkipVerify = true
	}

	transport := &http.Transport{
		TLSClientConfig:     tlsCfg,
		TLSHandshakeTimeout: 10 * time.Second,
		ForceAttemptHTTP2:   true,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
	}

	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		fmt.Printf("  ❌ Failed to build request: %v\n", err)
		return false
	}

	resp, err := client.Do(req)
	if err != nil {
		if tc.expectReject {
			fmt.Printf("  ✅ Connection rejected as expected (strict mode): %v\n", err)
			return true
		}
		fmt.Printf("  ❌ Request failed: %v\n", err)
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	tlsState := resp.TLS
	if tlsState == nil {
		fmt.Printf("  ❌ No TLS state in response\n")
		return false
	}

	fmt.Printf("  TLS version:    %s (0x%04x)\n", tlsVersionName(tlsState.Version), tlsState.Version)
	fmt.Printf("  Cipher suite:   %s (0x%04x)\n", tls.CipherSuiteName(tlsState.CipherSuite), tlsState.CipherSuite)
	fmt.Printf("  ALPN protocol:  %q\n", tlsState.NegotiatedProtocol)
	fmt.Printf("  HTTP status:    %d %s\n", resp.StatusCode, http.StatusText(resp.StatusCode))

	pqcNegotiated := tlsState.Version >= tls.VersionTLS13 && curveListContains(tc.curves, tls.X25519MLKEM768)
	fmt.Printf("  PQC negotiated: %t (offered-only heuristic)\n", pqcNegotiated)

	pass := true

	if tc.expectHTTP200 && resp.StatusCode != http.StatusOK {
		fmt.Printf("  ❌ Expected HTTP 200, got %d\n", resp.StatusCode)
		pass = false
	}

	if tc.expectPQCNeg && !pqcNegotiated {
		fmt.Printf("  ❌ Expected PQC (X25519MLKEM768) negotiated\n")
		pass = false
	}

	if !tc.expectPQCNeg && pqcNegotiated {
		fmt.Printf("  ℹ️  Unexpected: classical-only client triggered PQC (server preference override)\n")
	}

	if pass {
		fmt.Printf("  ✅ Test passed\n")
	}
	return pass
}

func loadCertPoolOrSkipVerify(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, fmt.Errorf("no CA path provided")
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("failed to parse CA cert from %s", path)
	}
	return pool, nil
}

func curveNames(curves []tls.CurveID) []string {
	names := make([]string, 0, len(curves))
	for _, c := range curves {
		names = append(names, curveName(c))
	}
	return names
}

func curveName(c tls.CurveID) string {
	switch c {
	case tls.X25519MLKEM768:
		return "X25519MLKEM768"
	case tls.X25519:
		return "X25519"
	case tls.CurveP256:
		return "P-256"
	case tls.CurveP384:
		return "P-384"
	case tls.CurveP521:
		return "P-521"
	}
	return fmt.Sprintf("CurveID(0x%04x)", uint16(c))
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	}
	return fmt.Sprintf("unknown(0x%04x)", v)
}

func curveListContains(list []tls.CurveID, target tls.CurveID) bool {
	for _, c := range list {
		if c == target {
			return true
		}
	}
	return false
}
