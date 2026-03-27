package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// BootstrapConfig는 agent가 최초 설치/등록(enrollment)될 때 필요한
// 중앙 서버 연결 정보, 자산 식별 정보, 인증서/상태 파일 경로 등을 담는다.
type BootstrapConfig struct {
	Server     BootstrapServerConfig     `yaml:"server"`
	Identity   BootstrapIdentityConfig   `yaml:"identity"`
	Paths      BootstrapPathsConfig      `yaml:"paths"`
	Enrollment BootstrapEnrollmentConfig `yaml:"enrollment"`
}

type BootstrapServerConfig struct {
	// 예: https://edr.example.local:8443
	BaseURL string `yaml:"base_url"`

	// 서버 TLS 인증서 검증용 CA cert 경로
	CACertPath string `yaml:"ca_cert_path"`

	// Enrollment / status / runtime API path
	EnrollRequestPath string `yaml:"enroll_request_path"`
	EnrollStatusPath  string `yaml:"enroll_status_path"`
	HeartbeatPath     string `yaml:"heartbeat_path"`
	PolicyPath        string `yaml:"policy_path"`
}

type BootstrapIdentityConfig struct {
	// 운영자가 관리하는 자산 식별자
	HostID string `yaml:"host_id"`

	// 자산 분류용 메타데이터
	Env  string `yaml:"env"`
	Role string `yaml:"role"`
}

type BootstrapPathsConfig struct {
	// 로컬 bootstrap/enrollment 상태 저장 파일
	StatePath string `yaml:"state_path"`

	// agent가 로컬에서 생성하는 private key 경로
	PrivateKeyPath string `yaml:"private_key_path"`

	// 디버깅/재시도용 CSR 저장 경로
	CSRPath string `yaml:"csr_path"`

	// 승인 후 서버에서 발급받은 client certificate 저장 경로
	CertificatePath string `yaml:"certificate_path"`

	PolicyPath string `yaml:"policy_path"`
}

type BootstrapEnrollmentConfig struct {
	// enroll request timeout
	RequestTimeout time.Duration `yaml:"request_timeout"`

	// pending 상태일 때 상태 조회 주기
	PollInterval time.Duration `yaml:"poll_interval"`

	// pending/retry 재시도 간격
	PendingRetryInterval time.Duration `yaml:"pending_retry_interval"`

	// pending 요청 만료 전 agent가 로컬에서 기다릴 최대 시간(선택)
	MaxPendingDuration time.Duration `yaml:"max_pending_duration"`
}

// LoadBootstrap는 bootstrap yaml 파일을 읽고,
// 기본값을 적용한 뒤 검증한다.
func LoadBootstrap(path string) (*BootstrapConfig, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("bootstrap config path is empty")
	}

	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read bootstrap config file: %w", err)
	}

	var cfg BootstrapConfig
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("unmarshal bootstrap config: %w", err)
	}

	cfg.ApplyDefaults()

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// ApplyDefaults는 bootstrap에 필요한 기본값을 채운다.
func (c *BootstrapConfig) ApplyDefaults() {
	//server
	c.Server.BaseURL = strings.TrimRight(strings.TrimSpace(c.Server.BaseURL), "/")
	c.Server.CACertPath = strings.TrimSpace(c.Server.CACertPath)

	if strings.TrimSpace(c.Server.EnrollRequestPath) == "" {
		c.Server.EnrollRequestPath = "/api/v1/enroll/request"
	}
	if strings.TrimSpace(c.Server.EnrollStatusPath) == "" {
		c.Server.EnrollStatusPath = "/api/v1/enroll/requests"
	}
	if strings.TrimSpace(c.Server.HeartbeatPath) == "" {
		c.Server.HeartbeatPath = "/api/v1/heartbeat"
	}

	// identity
	c.Identity.HostID = strings.TrimSpace(c.Identity.HostID)
	c.Identity.Env = strings.TrimSpace(c.Identity.Env)
	c.Identity.Role = strings.TrimSpace(c.Identity.Role)

	// paths
	c.Paths.StatePath = strings.TrimSpace(c.Paths.StatePath)
	c.Paths.PrivateKeyPath = strings.TrimSpace(c.Paths.PrivateKeyPath)
	c.Paths.CSRPath = strings.TrimSpace(c.Paths.CSRPath)
	c.Paths.CertificatePath = strings.TrimSpace(c.Paths.CertificatePath)

	if c.Paths.StatePath == "" {
		c.Paths.StatePath = "/var/lib/ebpf-edr/state.json"
	}
	if c.Paths.PrivateKeyPath == "" {
		c.Paths.PrivateKeyPath = "/etc/ebpf-edr/certs/client.key"
	}
	if c.Paths.CSRPath == "" {
		c.Paths.CSRPath = "/var/lib/ebpf-edr/client.csr"
	}
	if c.Paths.CertificatePath == "" {
		c.Paths.CertificatePath = "/etc/ebpf-edr/certs/client.crt"
	}

	// enrollment
	if c.Enrollment.RequestTimeout <= 0 {
		c.Enrollment.RequestTimeout = 10 * time.Second
	}
	if c.Enrollment.PollInterval <= 0 {
		c.Enrollment.PollInterval = 15 * time.Second
	}
	if c.Enrollment.PendingRetryInterval <= 0 {
		c.Enrollment.PendingRetryInterval = 30 * time.Second
	}
	if c.Enrollment.MaxPendingDuration <= 0 {
		c.Enrollment.MaxPendingDuration = 24 * time.Hour
	}
}

// Validate는 bootstrap config가 enrollment를 시작하기 위한 최소 조건을 만족하는지 검사한다.
func (c *BootstrapConfig) Validate() error {
	if c.Server.BaseURL == "" {
		return fmt.Errorf("server.base_url is required")
	}
	if !strings.HasPrefix(c.Server.BaseURL, "https://") && !strings.HasPrefix(c.Server.BaseURL, "http://") {
		return fmt.Errorf("server.base_url must strat with http:// or https://")
	}

	if c.Server.CACertPath == "" && strings.HasPrefix(c.Server.BaseURL, "https://") {
		return fmt.Errorf("server.ca_cert_path is required when using https")
	}

	if c.Identity.HostID == "" {
		return fmt.Errorf("identity.host_id is required")
	}
	if c.Identity.Env == "" {
		return fmt.Errorf("identity.env is required")
	}
	if c.Identity.Role == "" {
		return fmt.Errorf("identity.role is required")
	}

	if c.Paths.StatePath == "" {
		return fmt.Errorf("paths.state_path is required")
	}
	if c.Paths.PrivateKeyPath == "" {
		return fmt.Errorf("paths.private_key_path is required")
	}
	if c.Paths.CSRPath == "" {
		return fmt.Errorf("paths.csr_path is required")
	}
	if c.Paths.CertificatePath == "" {
		return fmt.Errorf("paths.certificate_path is required")
	}

	if c.Enrollment.RequestTimeout <= 0 {
		return fmt.Errorf("enrollment.request_timeout must be > 0")
	}
	if c.Enrollment.PollInterval <= 0 {
		return fmt.Errorf("enrollment.poll_interval must be > 0")
	}
	if c.Enrollment.PendingRetryInterval <= 0 {
		return fmt.Errorf("enrollment.pending_retry_interval must be > 0")
	}
	if c.Enrollment.MaxPendingDuration <= 0 {
		return fmt.Errorf("enrollment.max_pending_duration must be > 0")
	}

	return nil
}
