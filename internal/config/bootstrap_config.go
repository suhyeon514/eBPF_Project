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
	Server     ServerConfig            `yaml:"server"`
	Identity   IdentityConfig          `yaml:"identity"`
	Paths      PathsConfig             `yaml:"paths"`
	Enrollment EnrollmentConfig        `yaml:"enrollment"`
	Artifact   BootstrapArtifactConfig `yaml:"artifact"`   // 추가
	S3DumpInfo S3DumpInfoConfig        `yaml:"s3dumpinfo"` // 추가
}

type ServerConfig struct {
	// 예: https://edr.example.local:8443
	BaseURL string `yaml:"base_url"`
	// 서버 TLS 인증서 검증용 CA cert 경로
	CACertPath string `yaml:"ca_cert_path"`
	// Enrollment / status / runtime API path
	EnrollRequestPath string `yaml:"enroll_request_path"`
	EnrollStatusPath  string `yaml:"enroll_status_path"`
	HeartbeatPath     string `yaml:"heartbeat_path"`

	// 신규 에이전트 최초 정책 수령 API
	InitialRuntimePolicyPath string `yaml:"initial_runtime_policy_path"`

	// 기존 에이전트 주기적 업데이트 확인 API
	PolicyCheckUpdatePath string `yaml:"policy_check_update_path"`
	// artifact manifest path
	ArtifactManifestPath string `yaml:"artifact_manifest_path"`
	// artifact download path
	ArtifactDownloadPath string `yaml:"artifact_download_path"`
}

type IdentityConfig struct {
	// 운영자가 관리하는 자산 식별자
	HostID string `yaml:"host_id"`
	// 로컬 호스트명 힌트
	Hostname string `yaml:"hostname"`
	// 서버에 "요청값"으로만 전달되는 값
	// 최종 env/role은 서버가 배정한다.
	RequestedEnv  string `yaml:"requested_env"`
	RequestedRole string `yaml:"requested_role"`
}

type PathsConfig struct {
	// 로컬 bootstrap/enrollment 상태 저장 파일
	StatePath string `yaml:"state_path"`
	// install/dependency 상태 저장 파일
	InstallStatePath string `yaml:"install_state_path"`
	// agent가 로컬에서 생성하는 private key 경로
	PrivateKeyPath string `yaml:"private_key_path"`
	// 디버깅/재시도용 CSR 저장 경로
	CSRPath string `yaml:"csr_path"`
	// 승인 후 서버에서 발급받은 client certificate 저장 경로
	CertificatePath string `yaml:"certificate_path"`
	// 서버에서 내려받은 runtime policy 저장 경로
	PolicyPath string `yaml:"policy_path"`
	// artifact 캐시 디렉터리
	ArtifactCacheDir string `yaml:"artifact_cache_dir"`
	// 설치 스크립트나 helper 파일을 둘 수 있는 작업 디렉터리
	WorkDir string `yaml:"work_dir"`
	// runtime policy path
	RuntimePolicyPath string `yaml:"runtime_policy_path"`
}

type EnrollmentConfig struct {
	// enroll request timeout
	RequestTimeout time.Duration `yaml:"request_timeout"`
	// pending 상태일 때 상태 조회 주기
	PollInterval time.Duration `yaml:"poll_interval"`
	// pending/retry 재시도 간격
	PendingRetryInterval time.Duration `yaml:"pending_retry_interval"`
	// pending 요청 만료 전 agent가 로컬에서 기다릴 최대 시간(선택)
	MaxPendingDuration time.Duration `yaml:"max_pending_duration"`
}

type S3DumpInfoConfig struct {
	// AVML 덤프 파일 S3 업로드 시 사용할 버킷명
	S3BucketName string `yaml:"s3_bucket_name"`
	// AVML 덤프 파일 S3 업로드 시 사용할 리전
	S3Region string `yaml:"s3_region"`
	// AVML 덤프 파일 S3 업로드 시 사용할 액세스 키 ID
	S3AccessKeyID string `yaml:"s3_access_key_id"`
	// AVML 덤프 파일 S3 업로드 시 사용할 비밀 액세스 키
	S3SecretAccessKey string `yaml:"s3_secret_access_key"`
}

type BootstrapArtifactConfig struct {
	// artifact download timeout
	DownloadTimeout time.Duration `yaml:"download_timeout"`
	// 동일 artifact 재시도 간격
	RetryInterval time.Duration `yaml:"retry_interval"`
	// 다운로드 후 sha256 검증 필수 여부
	RequireSHA256 bool `yaml:"require_sha256"`
	// optional: signature verification 사용 여부
	RequireSignature bool `yaml:"require_signature"`
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
	// --------------------------------------------------
	// server
	// --------------------------------------------------
	c.Server.BaseURL = strings.TrimRight(strings.TrimSpace(c.Server.BaseURL), "/")
	c.Server.CACertPath = strings.TrimSpace(c.Server.CACertPath)
	c.Server.EnrollRequestPath = cleanPathOrDefault(c.Server.EnrollRequestPath, "/api/v1/enroll/request")
	c.Server.EnrollStatusPath = cleanPathOrDefault(c.Server.EnrollStatusPath, "/api/v1/enroll/requests")
	c.Server.HeartbeatPath = cleanPathOrDefault(c.Server.HeartbeatPath, "/api/v1/heartbeat")
	c.Server.InitialRuntimePolicyPath = cleanPathOrDefault(c.Server.InitialRuntimePolicyPath, "/api/v1/runtime/policy/current")
	c.Server.PolicyCheckUpdatePath = cleanPathOrDefault(c.Server.PolicyCheckUpdatePath, "/api/v1/policy/check-update")
	c.Server.ArtifactManifestPath = cleanPathOrDefault(c.Server.ArtifactManifestPath, "/api/v1/artifacts/manifest")
	c.Server.ArtifactDownloadPath = cleanPathOrDefault(c.Server.ArtifactDownloadPath, "/api/v1/artifacts/download")

	// --------------------------------------------------
	// identity
	// --------------------------------------------------
	c.Identity.HostID = strings.TrimSpace(c.Identity.HostID)
	c.Identity.Hostname = strings.TrimSpace(c.Identity.Hostname)
	c.Identity.RequestedEnv = strings.TrimSpace(c.Identity.RequestedEnv)
	c.Identity.RequestedRole = strings.TrimSpace(c.Identity.RequestedRole)

	// --------------------------------------------------
	// paths
	// --------------------------------------------------
	c.Paths.StatePath = strings.TrimSpace(c.Paths.StatePath)
	c.Paths.InstallStatePath = strings.TrimSpace(c.Paths.InstallStatePath)
	c.Paths.PrivateKeyPath = strings.TrimSpace(c.Paths.PrivateKeyPath)
	c.Paths.CSRPath = strings.TrimSpace(c.Paths.CSRPath)
	c.Paths.CertificatePath = strings.TrimSpace(c.Paths.CertificatePath)
	c.Paths.PolicyPath = strings.TrimSpace(c.Paths.PolicyPath) // deprecated
	c.Paths.RuntimePolicyPath = strings.TrimSpace(c.Paths.RuntimePolicyPath)
	c.Paths.ArtifactCacheDir = strings.TrimSpace(c.Paths.ArtifactCacheDir)
	c.Paths.WorkDir = strings.TrimSpace(c.Paths.WorkDir)

	if c.Paths.StatePath == "" {
		c.Paths.StatePath = "/var/lib/ebpf-edr/state.json"
	}
	if c.Paths.InstallStatePath == "" {
		c.Paths.InstallStatePath = "/var/lib/ebpf-edr/install-state.json"
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

	// deprecated fallback: policy_path -> runtime_policy_path
	if c.Paths.RuntimePolicyPath == "" && c.Paths.PolicyPath != "" {
		c.Paths.RuntimePolicyPath = c.Paths.PolicyPath
	}
	if c.Paths.RuntimePolicyPath == "" {
		c.Paths.RuntimePolicyPath = "/var/lib/ebpf-edr/policies/runtime.yaml"
	}

	if c.Paths.ArtifactCacheDir == "" {
		c.Paths.ArtifactCacheDir = "/var/lib/ebpf-edr/artifacts"
	}
	if c.Paths.WorkDir == "" {
		c.Paths.WorkDir = "/var/lib/ebpf-edr/work"
	}

	// --------------------------------------------------
	// enrollment
	// --------------------------------------------------
	if c.Enrollment.RequestTimeout <= 0 {
		c.Enrollment.RequestTimeout = 10 * time.Second
	}
	if c.Enrollment.PollInterval <= 0 {
		c.Enrollment.PollInterval = 10 * time.Second
	}
	if c.Enrollment.PendingRetryInterval <= 0 {
		c.Enrollment.PendingRetryInterval = 15 * time.Second
	}
	if c.Enrollment.MaxPendingDuration <= 0 {
		c.Enrollment.MaxPendingDuration = 30 * time.Minute
	}

	// --------------------------------------------------
	// s3dumpinfo
	// --------------------------------------------------
	c.S3DumpInfo.S3BucketName = strings.TrimSpace(c.S3DumpInfo.S3BucketName)
	c.S3DumpInfo.S3Region = strings.TrimSpace(c.S3DumpInfo.S3Region)
	c.S3DumpInfo.S3AccessKeyID = strings.TrimSpace(c.S3DumpInfo.S3AccessKeyID)
	c.S3DumpInfo.S3SecretAccessKey = strings.TrimSpace(c.S3DumpInfo.S3SecretAccessKey)

	// --------------------------------------------------
	// artifact
	// --------------------------------------------------
	if c.Artifact.DownloadTimeout <= 0 {
		c.Artifact.DownloadTimeout = 2 * time.Minute
	}
	if c.Artifact.RetryInterval <= 0 {
		c.Artifact.RetryInterval = 15 * time.Second
	}
	if !c.Artifact.RequireSHA256 {
		c.Artifact.RequireSHA256 = true
	}
}

// Validate는 bootstrap config가 enrollment를 시작하기 위한 최소 조건을 만족하는지 검사한다.
func (c *BootstrapConfig) Validate() error {
	// --------------------------------------------------
	// server
	// --------------------------------------------------
	if c.Server.BaseURL == "" {
		return fmt.Errorf("server.base_url is required")
	}

	// 변경: HTTPS일 때만 ca_cert_path 필수
	isHTTPS := strings.HasPrefix(strings.ToLower(strings.TrimSpace(c.Server.BaseURL)), "https://")
	if isHTTPS && strings.TrimSpace(c.Server.CACertPath) == "" {
		return fmt.Errorf("server.ca_cert_path is required for https")
	}

	if c.Server.EnrollRequestPath == "" {
		return fmt.Errorf("server.enroll_request_path is required")
	}
	if c.Server.EnrollStatusPath == "" {
		return fmt.Errorf("server.enroll_status_path is required")
	}
	if c.Server.HeartbeatPath == "" {
		return fmt.Errorf("server.heartbeat_path is required")
	}
	if c.Server.InitialRuntimePolicyPath == "" {
		return fmt.Errorf("server.initial_runtime_policy_path is required")
	}
	if c.Server.PolicyCheckUpdatePath == "" {
		return fmt.Errorf("server.policy_check_update_path is required")
	}
	if c.Server.ArtifactManifestPath == "" {
		return fmt.Errorf("server.artifact_manifest_path is required")
	}
	if c.Server.ArtifactDownloadPath == "" {
		return fmt.Errorf("server.artifact_download_path is required")
	}

	// --------------------------------------------------
	// paths
	// --------------------------------------------------
	if c.Paths.StatePath == "" {
		return fmt.Errorf("paths.state_path is required")
	}
	if c.Paths.InstallStatePath == "" {
		return fmt.Errorf("paths.install_state_path is required")
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
	// policy_path는 deprecated 이므로 필수 아님
	if c.Paths.RuntimePolicyPath == "" {
		return fmt.Errorf("paths.runtime_policy_path is required")
	}
	if c.Paths.ArtifactCacheDir == "" {
		return fmt.Errorf("paths.artifact_cache_dir is required")
	}
	if c.Paths.WorkDir == "" {
		return fmt.Errorf("paths.work_dir is required")
	}

	// --------------------------------------------------
	// enrollment
	// --------------------------------------------------
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

	// --------------------------------------------------
	// artifact
	// --------------------------------------------------
	if c.Artifact.DownloadTimeout <= 0 {
		return fmt.Errorf("artifact.download_timeout must be > 0")
	}
	if c.Artifact.RetryInterval <= 0 {
		return fmt.Errorf("artifact.retry_interval must be > 0")
	}

	return nil
}

func cleanPathOrDefault(value, def string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return def
	}
	if !strings.HasPrefix(value, "/") {
		return "/" + value
	}
	return value
}
