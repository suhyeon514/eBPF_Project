package tls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/suhyeon514/eBPF_Project/internal/config"
)

func NewBootstrapHTTPClient(cfg *config.BootstrapConfig) (*http.Client, error) {
	if cfg == nil {
		return nil, fmt.Errorf("bootstrap config is nil")
	}

	baseURL := strings.ToLower(strings.TrimSpace(cfg.Server.BaseURL))

	// HTTP 모드: TLS/mTLS 설정 없이 일반 client 반환
	if strings.HasPrefix(baseURL, "http://") {
		return &http.Client{
			Timeout: cfg.Enrollment.RequestTimeout,
		}, nil
	}

	// HTTPS 모드: 기존 TLS/mTLS 로직 유지
	caPEM, err := os.ReadFile(strings.TrimSpace(cfg.Server.CACertPath))
	if err != nil {
		return nil, fmt.Errorf("read ca cert file: %w", err)
	}

	rootCAs := x509.NewCertPool()
	if ok := rootCAs.AppendCertsFromPEM(caPEM); !ok {
		return nil, fmt.Errorf("append ca cert failed")
	}

	cert, err := tls.LoadX509KeyPair(
		strings.TrimSpace(cfg.Paths.CertificatePath),
		strings.TrimSpace(cfg.Paths.PrivateKeyPath),
	)
	if err != nil {
		return nil, fmt.Errorf("load client cert/key: %w", err)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    rootCAs,
			Certificates: []tls.Certificate{
				cert,
			},
		},
	}

	return &http.Client{
		Transport: tr,
		Timeout:   cfg.Enrollment.RequestTimeout,
	}, nil
}
