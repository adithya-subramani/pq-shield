//go:build ignore

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func main() {
	var (
		outDir = flag.String("out", "./certs", "Output directory for generated certs")
		hosts  = flag.String("hosts", "localhost,127.0.0.1", "Comma-separated SAN hosts/IPs")
		days   = flag.Int("days", 365, "Validity in days")
	)
	flag.Parse()

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create output dir: %v\n", err)
		os.Exit(1)
	}

	caCert, caKey, err := generateCA(*days)
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate CA: %v\n", err)
		os.Exit(1)
	}

	serverPEM, serverKeyPEM, err := generateServerCert(*hosts, *days, caCert, caKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate server cert: %v\n", err)
		os.Exit(1)
	}

	writeFile := func(name, data string) error {
		p := filepath.Join(*outDir, name)
		fmt.Printf("Writing %s\n", p)
		return os.WriteFile(p, []byte(data), 0o600)
	}

	if err := writeFile("ca.crt", caCert); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := writeFile("server.crt", serverPEM); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := writeFile("server.key", serverKeyPEM); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Println("Done. Certificates generated successfully.")
}

func generateCA(days int) (string, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return "", nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"PQ Shield Test CA"},
			CommonName:   "pq-shield-test-ca",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(0, 0, days),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return string(certPEM), key, nil
}

func generateServerCert(hostsCSV string, days int, caCertPEM string, caKey *ecdsa.PrivateKey) (string, string, error) {
	caCert, err := parsePEMCert(caCertPEM)
	if err != nil {
		return "", "", err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}

	sn, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			Organization: []string{"PQ Shield Test"},
			CommonName:   "localhost",
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().AddDate(0, 0, days),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	for _, h := range splitTrim(hostsCSV) {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return "", "", err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	return string(certPEM), string(keyPEM), nil
}

func parsePEMCert(pemStr string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return x509.ParseCertificate(block.Bytes)
}

func splitTrim(s string) []string {
	parts := []string{}
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			chunk := trimSpace(s[start:i])
			if chunk != "" {
				parts = append(parts, chunk)
			}
			start = i + 1
		}
	}
	return parts
}

func trimSpace(s string) string {
	start := 0
	for start < len(s) && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	end := len(s)
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}
