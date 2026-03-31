package app

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	bootstrapenroll "github.com/suhyeon514/eBPF_Project/internal/bootstrap/enroll"
	bootstrap_tls "github.com/suhyeon514/eBPF_Project/internal/bootstrap/tls"
	"github.com/suhyeon514/eBPF_Project/internal/config"
	transportdto "github.com/suhyeon514/eBPF_Project/internal/transport/dto"
)

type EnrollmentStatus string

const (
	EnrollmentStatusIdle     EnrollmentStatus = "idle"
	EnrollmentStatusPending  EnrollmentStatus = "pending"
	EnrollmentStatusApproved EnrollmentStatus = "approved"
	EnrollmentStatusRejected EnrollmentStatus = "rejected"
	EnrollmentStatusError    EnrollmentStatus = "error"
)

type ComponentInstallStatus string

const (
	ComponentInstallStatusUnknown   ComponentInstallStatus = "unknown"
	ComponentInstallStatusInstalled ComponentInstallStatus = "installed"
	ComponentInstallStatusFailed    ComponentInstallStatus = "failed"
)

type BootstrapState struct {
	AgentID     string `json:"agent_id,omitempty"`
	InstallUUID string `json:"install_uuid,omitempty"`

	LastRequestID string `json:"last_request_id,omitempty"`

	// agent 로컬 bootstrap lifecycle 상태
	EnrollmentStatus EnrollmentStatus `json:"enrollment_status"`

	LastServerResult     transportdto.EnrollResult `json:"last_server_result,omitempty"`
	LastServerReasonCode string                    `json:"last_server_reason_code,omitempty"`

	// 서버가 최종 배정한 값
	AssignedEnv     string `json:"assigned_env,omitempty"`
	AssignedRole    string `json:"assigned_role,omitempty"`
	HostID          string `json:"host_id,omitempty"`
	Hostname        string `json:"hostname,omitempty"`
	PolicyRawSHA256 string `json:"policy_raw_sha256,omitempty"`

	// 설치 상태 (1차는 단순 문자열로 두고, 추후 struct/map 확장 가능)
	TetragonStatus  ComponentInstallStatus `json:"tetragon_status,omitempty"`
	FluentBitStatus ComponentInstallStatus `json:"fluent_bit_status,omitempty"`

	CreatedAt time.Time `json:"created_at,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

type BootstrapResult struct {
	AgentID     string
	InstallUUID string

	AssignedEnv  string
	AssignedRole string
}

type Fingerprint struct {
	MachineID       string
	Hostname        string
	OSID            string
	OSVersion       string
	CloudInstanceID string
}

type BootstrapApp struct {
	cfg *config.BootstrapConfig
}

func NewBootstrapApp(cfg *config.BootstrapConfig) *BootstrapApp {
	return &BootstrapApp{cfg: cfg}
}

// Run은 bootstrap 전체 흐름을 수행한다.
//
// 큰 순서:
//  1. 경로 보장
//  2. bootstrap state 로드
//  3. 기존 usable identity 확인
//  4. 없으면 install_uuid / key / csr / fingerprint / enroll 수행
//  5. 승인 완료 후 mTLS 준비
//  6. dependency(Tetragon, Fluent Bit 등) 설치
//  7. 초기 runtime policy 수신/저장
//  8. BootstrapResult 반환
func (a *BootstrapApp) Run(ctx context.Context) (*BootstrapResult, error) {
	if err := a.ensurePaths(); err != nil {
		return nil, fmt.Errorf("ensure bootstrap paths: %w", err)
	}

	state, err := a.loadState()
	if err != nil {
		return nil, fmt.Errorf("load bootstrap state: %w", err)
	}

	if state.InstallUUID == "" {
		state.InstallUUID = generateInstallUUID()
	}

	// 1) identity 확보
	if !a.hasUsableIdentity(state) {
		if err := a.ensureIdentityAndEnrollment(ctx, state); err != nil {
			return nil, err
		}
	} else {
		// 기존 identity가 있으면 approved 상태로 보정
		state.EnrollmentStatus = EnrollmentStatusApproved
		state.UpdatedAt = time.Now()

		if err := a.saveState(state); err != nil {
			return nil, fmt.Errorf("save bootstrap state after usable identity check: %w", err)
		}
	}

	// 2) 승인된 identity가 있어야 이후 단계 진행 가능
	if state.EnrollmentStatus != EnrollmentStatusApproved {
		return nil, fmt.Errorf("bootstrap cannot continue: enrollment status is %q", state.EnrollmentStatus)
	}
	if state.AgentID == "" {
		return nil, fmt.Errorf("bootstrap cannot continue: approved state but agent_id is empty")
	}

	// 3) mTLS 기반 dependency 설치
	if err := a.ensureDependenciesInstalled(ctx, state); err != nil {
		state.EnrollmentStatus = EnrollmentStatusError
		_ = a.saveState(state)
		return nil, fmt.Errorf("ensure dependencies installed: %w", err)
	}

	// 4) 초기 runtime policy 수신/저장
	if err := a.ensureInitialRuntimePolicy(ctx, state); err != nil {
		state.EnrollmentStatus = EnrollmentStatusError
		_ = a.saveState(state)
		return nil, fmt.Errorf("ensure initial runtime policy: %w", err)
	}

	if err := a.saveState(state); err != nil {
		return nil, fmt.Errorf("save final bootstrap state: %w", err)
	}

	return &BootstrapResult{
		AgentID:      state.AgentID,
		InstallUUID:  state.InstallUUID,
		AssignedEnv:  state.AssignedEnv,
		AssignedRole: state.AssignedRole,
	}, nil
}

// ensureIdentityAndEnrollment은 key/csr/fingerprint/enroll/polling까지 수행한다.
func (a *BootstrapApp) ensureIdentityAndEnrollment(ctx context.Context, state *BootstrapState) error {
	if err := a.ensurePrivateKey(); err != nil {
		state.EnrollmentStatus = EnrollmentStatusError
		state.UpdatedAt = time.Now()
		_ = a.saveState(state)
		return fmt.Errorf("ensure private key: %w", err)
	}

	csrPEM, err := a.generateCSR()
	if err != nil {
		state.EnrollmentStatus = EnrollmentStatusError
		state.UpdatedAt = time.Now()
		_ = a.saveState(state)
		return fmt.Errorf("generate csr: %w", err)
	}

	fp, err := a.collectFingerprint()
	if err != nil {
		state.EnrollmentStatus = EnrollmentStatusError
		state.UpdatedAt = time.Now()
		_ = a.saveState(state)
		return fmt.Errorf("collect fingerprint: %w", err)
	}

	enrollClient, err := bootstrapenroll.NewClient(a.cfg)
	if err != nil {
		return fmt.Errorf("create enroll client: %w", err)
	}

	resp, err := enrollClient.RequestEnrollment(ctx, transportdto.EnrollRequest{
		HostID:        a.cfg.Identity.HostID,
		RequestedEnv:  a.cfg.Identity.RequestedEnv,
		RequestedRole: a.cfg.Identity.RequestedRole,
		InstallUUID:   state.InstallUUID,
		Fingerprint: &transportdto.Fingerprint{
			MachineID:       fp.MachineID,
			Hostname:        fp.Hostname,
			OSID:            fp.OSID,
			OSVersion:       fp.OSVersion,
			CloudInstanceID: fp.CloudInstanceID,
			IPAddress:       detectPrimaryIPv4(), // 추가
		},
		CSRPEM: string(csrPEM),
	})

	if err != nil {
		state.EnrollmentStatus = EnrollmentStatusError
		state.UpdatedAt = time.Now()
		_ = a.saveState(state)
		return fmt.Errorf("request enrollment: %w", err)
	}

	state.LastRequestID = resp.RequestID
	state.LastServerResult = resp.Result
	state.LastServerReasonCode = resp.ReasonCode

	switch resp.Result {
	case transportdto.EnrollResultApproved:
		if err := a.applyApprovedEnrollmentFromDTO(state, resp); err != nil {
			state.EnrollmentStatus = EnrollmentStatusError
			state.UpdatedAt = time.Now()
			_ = a.saveState(state)
			return fmt.Errorf("apply approved enrollment: %w", err)
		}
		return nil

	case transportdto.EnrollResultPending:
		state.EnrollmentStatus = EnrollmentStatusPending
		state.UpdatedAt = time.Now()

		if err := a.saveState(state); err != nil {
			return fmt.Errorf("save pending bootstrap state: %w", err)
		}

		finalResp, err := a.waitForApproval(ctx, state)
		if err != nil {
			state.EnrollmentStatus = EnrollmentStatusError
			state.UpdatedAt = time.Now()
			_ = a.saveState(state)
			return fmt.Errorf("wait for approval: %w", err)
		}

		state.LastRequestID = finalResp.RequestID
		state.LastServerResult = finalResp.Result
		state.LastServerReasonCode = finalResp.ReasonCode

		switch finalResp.Result {
		case transportdto.EnrollResultApproved:
			if err := a.applyApprovedEnrollmentFromDTO(state, finalResp); err != nil {
				state.EnrollmentStatus = EnrollmentStatusError
				state.UpdatedAt = time.Now()
				_ = a.saveState(state)
				return fmt.Errorf("save certificate: %w", err)
			}
			return nil

		case transportdto.EnrollResultRejected:
			state.EnrollmentStatus = EnrollmentStatusRejected
			state.UpdatedAt = time.Now()
			_ = a.saveState(state)
			return fmt.Errorf("enrollment rejected: %s", finalResp.Message)

		default:
			state.EnrollmentStatus = EnrollmentStatusError
			state.UpdatedAt = time.Now()
			_ = a.saveState(state)
			return fmt.Errorf("unexpected final enrollment result: %s", finalResp.Result)
		}

	case transportdto.EnrollResultRejected:
		state.EnrollmentStatus = EnrollmentStatusRejected
		state.UpdatedAt = time.Now()
		_ = a.saveState(state)
		return fmt.Errorf("enrollment rejected: %s", resp.Message)

	default:
		state.EnrollmentStatus = EnrollmentStatusError
		state.UpdatedAt = time.Now()
		_ = a.saveState(state)
		return fmt.Errorf("unknown enrollment result: %s", resp.Result)

	}
}

func (a *BootstrapApp) applyApprovedEnrollmentFromDTO(state *BootstrapState, resp *transportdto.EnrollResponse) error {
	if state == nil {
		return errors.New("bootstrap state is nil")
	}
	if resp == nil {
		return errors.New("approved enrollment dto response is nil")
	}
	if resp.AgentID == "" {
		return errors.New("approved enrollment response missing agent_id")
	}
	if resp.CertificatePEM == "" {
		return errors.New("approved enrollment response missing certificate_pem")
	}

	if err := a.saveCertificate(resp.CertificatePEM); err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}

	state.AgentID = resp.AgentID
	state.AssignedEnv = resp.AssignedEnv
	state.AssignedRole = resp.AssignedRole
	state.EnrollmentStatus = EnrollmentStatusApproved
	state.UpdatedAt = time.Now()

	if err := a.saveState(state); err != nil {
		return fmt.Errorf("save bootstrap state: %w", err)
	}
	return nil
}

func (a *BootstrapApp) ensurePaths() error {
	requireDirs := []string{
		filepath.Dir(a.cfg.Paths.StatePath),
		filepath.Dir(a.cfg.Paths.PrivateKeyPath),
		filepath.Dir(a.cfg.Paths.CSRPath),
		filepath.Dir(a.cfg.Paths.CertificatePath),
		filepath.Dir(a.cfg.Paths.RuntimePolicyPath),
	}

	for _, dir := range requireDirs {
		if dir == "" || dir == "." {
			continue
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}

	return nil
}

func (a *BootstrapApp) loadState() (*BootstrapState, error) {
	path := a.cfg.Paths.StatePath

	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			now := time.Now()
			return &BootstrapState{
				EnrollmentStatus: EnrollmentStatusIdle,
				TetragonStatus:   ComponentInstallStatusUnknown,
				FluentBitStatus:  ComponentInstallStatusUnknown,
				CreatedAt:        now,
				UpdatedAt:        now,
			}, nil
		}
		return nil, err
	}

	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var state BootstrapState
	if err := json.Unmarshal(b, &state); err != nil {
		return nil, err
	}

	if state.EnrollmentStatus == "" {
		state.EnrollmentStatus = EnrollmentStatusIdle
	}
	if state.TetragonStatus == "" {
		state.TetragonStatus = ComponentInstallStatusUnknown
	}
	if state.FluentBitStatus == "" {
		state.FluentBitStatus = ComponentInstallStatusUnknown
	}
	if state.CreatedAt.IsZero() {
		state.CreatedAt = time.Now()
	}
	state.UpdatedAt = time.Now()

	return &state, nil
}

func (a *BootstrapApp) saveState(state *BootstrapState) error {
	state.UpdatedAt = time.Now()
	if state.CreatedAt.IsZero() {
		state.CreatedAt = state.UpdatedAt
	}

	b, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(a.cfg.Paths.StatePath, b, 0o600)
}

func (a *BootstrapApp) hasUsableIdentity(state *BootstrapState) bool {
	if state == nil {
		return false
	}

	if state.AgentID == "" {
		return false
	}
	if _, err := os.Stat(a.cfg.Paths.CertificatePath); err != nil {
		return false
	}
	if _, err := os.Stat(a.cfg.Paths.PrivateKeyPath); err != nil {
		return false
	}
	return true
}

func (a *BootstrapApp) saveCertificate(certPEM string) error {
	return os.WriteFile(a.cfg.Paths.CertificatePath, []byte(certPEM), 0o600)
}

// ===== TODO =====
// ensureDependenciesInstalled는 승인 후 mTLS 기반으로 tetragon / fluent-bit 등을
// 다운로드/검증/설치/서비스 시작하는 단계다.
// 추후 bootstrap/artifact 패키지로 이동 추천.
func (a *BootstrapApp) ensureDependenciesInstalled(ctx context.Context, state *BootstrapState) error {
	if state == nil {
		return errors.New("bootstrap state is nil")
	}
	if state.EnrollmentStatus != EnrollmentStatusApproved {
		return fmt.Errorf("enrollment is not approved: %s", state.EnrollmentStatus)
	}

	// server.ca_cert_path 유효성/자동 fallback 보정 (HTTP면 내부에서 no-op)
	if err := a.ensureServerCACertPath(); err != nil {
		return fmt.Errorf("prepare server ca cert path: %w", err)
	}

	// 변경: mTLS 전제(cert/key) 체크는 HTTPS일 때만 수행
	baseURLLower := strings.ToLower(strings.TrimSpace(a.cfg.Server.BaseURL))
	isHTTPS := strings.HasPrefix(baseURLLower, "https://")
	if isHTTPS {
		if _, err := os.Stat(a.cfg.Paths.CertificatePath); err != nil {
			return fmt.Errorf("certificate not found: %w", err)
		}
		if _, err := os.Stat(a.cfg.Paths.PrivateKeyPath); err != nil {
			return fmt.Errorf("private key not found: %w", err)
		}
	}

	var errs []string

	// if err := a.ensureComponentRunning(ctx, "tetragon", "tetragon", "tetragon.service"); err != nil {
	// 	state.TetragonStatus = ComponentInstallStatusFailed
	// 	errs = append(errs, fmt.Sprintf("tetragon: %v", err))
	// } else {
	// 	state.TetragonStatus = ComponentInstallStatusInstalled
	// }

	if err := a.ensureComponentRunning(ctx, "fluent-bit", "fluent-bit", "fluent-bit.service"); err != nil {
		state.FluentBitStatus = ComponentInstallStatusFailed
		errs = append(errs, fmt.Sprintf("fluent-bit: %v", err))
	} else {
		state.FluentBitStatus = ComponentInstallStatusInstalled
	}

	state.UpdatedAt = time.Now()
	_ = a.saveState(state)

	if len(errs) > 0 {
		return fmt.Errorf("dependency install failed: %s", strings.Join(errs, "; "))
	}
	return nil
}

func (a *BootstrapApp) ensureComponentRunning(
	ctx context.Context,
	componentName string,
	binaryName string,
	serviceName string,
) error {
	var runPath string
	var ok bool

	switch componentName {
	case "fluent-bit":
		runPath, ok = a.findBundledEntrypoint(componentName)
	default:
		return fmt.Errorf("unknown component for bundled install: %s", componentName)
	}

	if !ok {
		installedPath, err := a.installComponentArtifact(ctx, componentName, binaryName)
		if err != nil {
			return err
		}
		runPath = installedPath
	}

	a.ensurePathContains(filepath.Dir(runPath))

	if _, err := exec.LookPath("systemctl"); err != nil {
		return nil
	}

	switch componentName {
	case "fluent-bit":
		if err := a.ensureBundledSystemdService(ctx, serviceName, runPath); err != nil {
			return fmt.Errorf("ensure fluent-bit bundled service: %w", err)
		}
	default:
		return fmt.Errorf("unknown component for systemd service: %s", componentName)
	}

	return nil
}

func (a *BootstrapApp) installComponentArtifact(ctx context.Context, componentName, binaryName string) (string, error) {
	if err := a.ensureServerCACertPath(); err != nil {
		return "", fmt.Errorf("prepare server ca cert path: %w", err)
	}

	httpClient, err := bootstrap_tls.NewBootstrapHTTPClient(a.cfg)
	if err != nil {
		return "", fmt.Errorf("create mtls client: %w", err)
	}

	baseURL := strings.TrimRight(a.cfg.Server.BaseURL, "/")

	manifestURL := baseURL + a.cfg.Server.ArtifactManifestPath
	u, _ := url.Parse(manifestURL)
	q := u.Query()
	q.Set("component", componentName)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("build manifest request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request manifest: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("manifest request failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	var item artifactManifestItem
	if err := json.NewDecoder(resp.Body).Decode(&item); err != nil {
		return "", fmt.Errorf("decode manifest: %w", err)
	}

	downloadURL := strings.TrimSpace(item.DownloadURL)
	if downloadURL == "" {
		du := baseURL + a.cfg.Server.ArtifactDownloadPath
		pu, _ := url.Parse(du)
		pq := pu.Query()
		pq.Set("component", componentName)
		pu.RawQuery = pq.Encode()
		downloadURL = pu.String()
	}

	downloadCtx := ctx
	if a.cfg.Artifact.DownloadTimeout > 0 {
		var cancel context.CancelFunc
		downloadCtx, cancel = context.WithTimeout(ctx, a.cfg.Artifact.DownloadTimeout)
		defer cancel()
	}

	dreq, err := http.NewRequestWithContext(downloadCtx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return "", fmt.Errorf("build download request: %w", err)
	}

	downloadClient := *httpClient
	downloadClient.Timeout = 0

	dresp, err := downloadClient.Do(dreq)
	if err != nil {
		return "", fmt.Errorf("download artifact: %w", err)
	}
	defer dresp.Body.Close()

	if dresp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(dresp.Body)
		return "", fmt.Errorf("download failed: status=%d body=%s", dresp.StatusCode, strings.TrimSpace(string(b)))
	}

	raw, err := io.ReadAll(dresp.Body)
	if err != nil {
		return "", fmt.Errorf("read artifact body: %w", err)
	}

	if a.cfg.Artifact.RequireSHA256 {
		sum := sha256.Sum256(raw)
		got := hex.EncodeToString(sum[:])
		want := strings.ToLower(strings.TrimSpace(item.SHA256))
		if want == "" {
			return "", errors.New("artifact sha256 is required but missing in manifest")
		}
		if got != want {
			return "", fmt.Errorf("artifact sha256 mismatch: got=%s want=%s", got, want)
		}
	}

	workDir, err := os.MkdirTemp("", "artifact-*")
	if err != nil {
		return "", fmt.Errorf("create temp work dir: %w", err)
	}
	defer os.RemoveAll(workDir)

	archivePath := filepath.Join(workDir, componentName+".tar.gz")
	if err := os.WriteFile(archivePath, raw, 0o600); err != nil {
		return "", fmt.Errorf("write archive temp file: %w", err)
	}

	extractDir := filepath.Join(workDir, "extract")
	if err := os.MkdirAll(extractDir, 0o755); err != nil {
		return "", fmt.Errorf("mkdir extract dir: %w", err)
	}

	if err := extractTarGz(archivePath, extractDir); err != nil {
		return "", fmt.Errorf("extract tar.gz: %w", err)
	}

	// tar.gz 내부 top-level bundle 디렉터리 찾기
	bundleRoot, err := findBundleRoot(extractDir, componentName)
	if err != nil {
		return "", fmt.Errorf("find bundle root: %w", err)
	}

	// 번들 최소 구조 검증
	if err := validateFluentBitBundle(bundleRoot); err != nil {
		return "", fmt.Errorf("validate fluent-bit bundle: %w", err)
	}

	targetDir := filepath.Join("/opt/ebpf-edr/components", componentName)
	if err := os.MkdirAll(filepath.Dir(targetDir), 0o755); err != nil {
		return "", fmt.Errorf("mkdir component parent dir: %w", err)
	}

	// 원자적 교체에 가깝게 temp -> rename
	stageDir := targetDir + ".new"
	_ = os.RemoveAll(stageDir)
	if err := copyDir(bundleRoot, stageDir); err != nil {
		return "", fmt.Errorf("stage bundle dir: %w", err)
	}

	// 실행 권한 보정
	_ = os.Chmod(filepath.Join(stageDir, "run-fluent-bit.sh"), 0o755)
	_ = os.Chmod(filepath.Join(stageDir, "bin", "fluent-bit"), 0o755)

	// 추가: 로컬 configs/fluent-bit.yaml -> stageDir/conf/fluent-bit.yaml
	if componentName == "fluent-bit" {
		if err := copyLocalFluentBitConfig(stageDir); err != nil {
			return "", fmt.Errorf("copy fluent-bit config into bundle: %w", err)
		}
	}

	oldDir := targetDir + ".old"
	_ = os.RemoveAll(oldDir)
	if _, err := os.Stat(targetDir); err == nil {
		if err := os.Rename(targetDir, oldDir); err != nil {
			return "", fmt.Errorf("backup existing bundle dir: %w", err)
		}
	}
	if err := os.Rename(stageDir, targetDir); err != nil {
		return "", fmt.Errorf("activate bundle dir: %w", err)
	}
	_ = os.RemoveAll(oldDir)

	return filepath.Join(targetDir, "run-fluent-bit.sh"), nil
}

func (a *BootstrapApp) ensurePathContains(dir string) {
	if dir == "" {
		return
	}
	cur := os.Getenv("PATH")
	for _, p := range strings.Split(cur, ":") {
		if p == dir {
			return
		}
	}
	_ = os.Setenv("PATH", dir+":"+cur)
}

// ===== TODO =====
// ensureInitialRuntimePolicy는 서버에서 runtime policy를 받아 cfg.Paths.RuntimePolicyPath 에 저장한다.
//
// 이 policy 안에는:
//   - collectors 설정
//   - output 설정
//   - allowlist
//   - focus_list
//   - 서버가 최종 배정한 env/role
//
// 등이 포함될 수 있다.
func (a *BootstrapApp) ensureInitialRuntimePolicy(ctx context.Context, state *BootstrapState) error {
	if state == nil {
		return errors.New("bootstrap state is nil")
	}
	if state.EnrollmentStatus != EnrollmentStatusApproved {
		return fmt.Errorf("enrollment is not approved: %s", state.EnrollmentStatus)
	}

	// 추가: server.ca_cert_path 유효성/자동 fallback 보정
	if err := a.ensureServerCACertPath(); err != nil {
		return fmt.Errorf("prepare server ca cert path: %w", err)
	}

	// 변경: mTLS 전제(cert/key) 체크는 HTTPS일 때만 수행
	baseURLLower := strings.ToLower(strings.TrimSpace(a.cfg.Server.BaseURL))
	isHTTPS := strings.HasPrefix(baseURLLower, "https://")
	if isHTTPS {
		if _, err := os.Stat(a.cfg.Paths.CertificatePath); err != nil {
			return fmt.Errorf("certificate not found: %w", err)
		}
		if _, err := os.Stat(a.cfg.Paths.PrivateKeyPath); err != nil {
			return fmt.Errorf("private key not found: %w", err)
		}
	}

	httpClient, err := bootstrap_tls.NewBootstrapHTTPClient(a.cfg)
	if err != nil {
		return fmt.Errorf("create mtls http client: %w", err)
	}

	// 기본 endpoint: /api/v1/runtime/policy/current
	baseURL := strings.TrimRight(a.cfg.Server.BaseURL, "/")
	initialPath := strings.TrimSpace(a.cfg.Server.InitialRuntimePolicyPath)
	if initialPath == "" {
		return errors.New("server.initial_runtime_policy_path is empty")
	}
	endpoint := baseURL + initialPath

	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("parse runtime policy endpoint: %w", err)
	}
	q := u.Query()
	if strings.TrimSpace(state.AgentID) != "" {
		q.Set("agent_id", state.AgentID)
	}
	if strings.TrimSpace(state.InstallUUID) != "" {
		q.Set("install_uuid", state.InstallUUID)
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return fmt.Errorf("build runtime policy request: %w", err)
	}
	req.Header.Set("Accept", "application/json, text/yaml, application/x-yaml, text/plain")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request runtime policy: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read runtime policy response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("runtime policy request failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	policyYAML, assignedEnv, assignedRole, err := decodeRuntimePolicyResponse(body)
	if err != nil {
		return fmt.Errorf("decode runtime policy response: %w", err)
	}

	rawPolicy := strings.TrimSpace(policyYAML)
	if rawPolicy == "" {
		return errors.New("runtime policy is empty")
	}

	// ✅ 서버 원본 그대로 저장 (불변)
	if err := writeFileAtomic(a.cfg.Paths.RuntimePolicyPath, []byte(rawPolicy+"\n"), 0o600); err != nil {
		return fmt.Errorf("write runtime policy: %w", err)
	}

	// ✅ 로컬 메타데이터는 state.json에만 저장
	state.HostID = strings.TrimSpace(a.cfg.Identity.HostID)

	hn := strings.TrimSpace(a.cfg.Identity.Hostname)
	if hn == "" {
		if osHN, err := os.Hostname(); err == nil {
			hn = strings.TrimSpace(osHN)
		}
	}
	state.Hostname = hn

	if v := strings.TrimSpace(assignedEnv); v != "" {
		state.AssignedEnv = v
	}
	if v := strings.TrimSpace(assignedRole); v != "" {
		state.AssignedRole = v
	}

	sum := sha256.Sum256([]byte(rawPolicy))
	state.PolicyRawSHA256 = hex.EncodeToString(sum[:])

	state.UpdatedAt = time.Now()
	if err := a.saveState(state); err != nil {
		return fmt.Errorf("save state after runtime policy update: %w", err)
	}

	return nil
}

type runtimePolicyResponse struct {
	PolicyYAML   string `json:"policy_yaml"`
	Policy       string `json:"policy"` // fallback key
	AssignedEnv  string `json:"assigned_env,omitempty"`
	AssignedRole string `json:"assigned_role,omitempty"`
}

func decodeRuntimePolicyResponse(body []byte) (policyYAML, assignedEnv, assignedRole string, err error) {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return "", "", "", errors.New("empty response body")
	}

	// JSON object 응답 우선 파싱
	if strings.HasPrefix(trimmed, "{") {
		var r runtimePolicyResponse
		if err := json.Unmarshal(body, &r); err != nil {
			return "", "", "", err
		}
		p := strings.TrimSpace(r.PolicyYAML)
		if p == "" {
			p = strings.TrimSpace(r.Policy)
		}
		return p, r.AssignedEnv, r.AssignedRole, nil
	}

	// 비-JSON이면 본문 자체를 YAML로 간주
	return trimmed, "", "", nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".policy-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()

	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()

	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	return os.Rename(tmpPath, path)
}

func (a *BootstrapApp) ensurePrivateKey() error {
	keyPath := strings.TrimSpace(a.cfg.Paths.PrivateKeyPath)
	if keyPath == "" {
		return errors.New("private key path is empty")
	}

	// 이미 있으면 유효성만 확인
	if _, err := os.Stat(keyPath); err == nil {
		b, err := os.ReadFile(keyPath)
		if err != nil {
			return fmt.Errorf("read private key: %w", err)
		}
		if _, err := parseECPrivateKeyFromPEM(b); err != nil {
			return fmt.Errorf("invalid private key pem: %w", err)
		}
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat private key: %w", err)
	}

	// 없으면 생성
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate ecdsa key: %w", err)
	}

	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal ecdsa private key: %w", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	})

	if err := os.WriteFile(keyPath, pemBytes, 0o600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	return nil
}

func (a *BootstrapApp) generateCSR() ([]byte, error) {
	hostID := strings.TrimSpace(a.cfg.Identity.HostID)
	if hostID == "" {
		return nil, errors.New("identity.host_id is empty")
	}

	keyPEM, err := os.ReadFile(a.cfg.Paths.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read private key for csr: %w", err)
	}

	key, err := parseECPrivateKeyFromPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse private key for csr: %w", err)
	}

	tpl := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: hostID,
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tpl, key)
	if err != nil {
		return nil, fmt.Errorf("create csr: %w", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	if csrPath := strings.TrimSpace(a.cfg.Paths.CSRPath); csrPath != "" {
		if err := os.WriteFile(csrPath, csrPEM, 0o600); err != nil {
			return nil, fmt.Errorf("write csr file: %w", err)
		}
	}

	return csrPEM, nil
}

func (a *BootstrapApp) collectFingerprint() (*Fingerprint, error) {
	machineID, err := readFirstExistingTrimmed(
		"/etc/machine-id",
		"/var/lib/dbus/machine-id",
	)
	if err != nil {
		return nil, fmt.Errorf("read machine-id: %w", err)
	}

	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("read hostname: %w", err)
	}

	osID, osVersion, err := parseOSRelease("/etc/os-release")
	if err != nil {
		return nil, fmt.Errorf("parse os-release: %w", err)
	}

	cloudInstanceID, _ := readFirstExistingTrimmed("/var/lib/cloud/data/instance-id")

	return &Fingerprint{
		MachineID:       strings.TrimSpace(machineID),
		Hostname:        strings.TrimSpace(hostname),
		OSID:            strings.TrimSpace(osID),
		OSVersion:       strings.TrimSpace(osVersion),
		CloudInstanceID: strings.TrimSpace(cloudInstanceID),
	}, nil
}

func generateInstallUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}

	// RFC4122 v4
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80

	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func parseECPrivateKeyFromPEM(keyPEM []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("invalid pem data")
	}

	switch block.Type {
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return key, nil
	case "PRIVATE KEY":
		keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key, ok := keyAny.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("private key is not ecdsa")
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported private key pem type: %s", block.Type)
	}
}

func readFirstExistingTrimmed(paths ...string) (string, error) {
	var lastErr error

	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			lastErr = err
			continue
		}
		return strings.TrimSpace(string(b)), nil
	}

	if lastErr != nil {
		return "", lastErr
	}
	return "", os.ErrNotExist
}

func parseOSRelease(path string) (string, string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", "", err
	}

	values := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		kv := strings.SplitN(line, "=", 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.TrimSpace(kv[0])
		v := strings.Trim(strings.TrimSpace(kv[1]), `"'`)
		values[k] = v
	}

	return values["ID"], values["VERSION_ID"], nil
}

func (a *BootstrapApp) waitForApproval(
	ctx context.Context,
	state *BootstrapState,
) (*transportdto.EnrollResponse, error) {
	if state == nil {
		return nil, errors.New("bootstrap state is nil")
	}

	requestID := strings.TrimSpace(state.LastRequestID)
	if requestID == "" {
		return nil, errors.New("last_request_id is empty")
	}

	enrollClient, err := bootstrapenroll.NewClient(a.cfg)
	if err != nil {
		return nil, fmt.Errorf("create enroll client: %w", err)
	}

	const pollInterval = 3 * time.Second

	for {
		statusResp, err := enrollClient.GetEnrollmentStatus(ctx, requestID)
		if err != nil {
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("wait for approval canceled: %w", ctx.Err())
			case <-time.After(pollInterval):
				continue
			}
		}
		if statusResp == nil {
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("wait for approval canceled: %w", ctx.Err())
			case <-time.After(pollInterval):
				continue
			}
		}

		resp := &transportdto.EnrollResponse{
			Result:         statusResp.Result,
			ReasonCode:     statusResp.ReasonCode,
			Message:        statusResp.Message,
			RequestID:      statusResp.RequestID,
			AgentID:        statusResp.AgentID,
			CertificatePEM: statusResp.CertificatePEM,
			AssignedEnv:    statusResp.AssignedEnv,
			AssignedRole:   statusResp.AssignedRole,
		}
		if strings.TrimSpace(resp.RequestID) == "" {
			resp.RequestID = requestID
		}

		switch resp.Result {
		case transportdto.EnrollResultApproved, transportdto.EnrollResultRejected:
			return resp, nil

		case transportdto.EnrollResultPending:
			state.LastServerResult = resp.Result
			state.LastServerReasonCode = resp.ReasonCode
			state.UpdatedAt = time.Now()
			_ = a.saveState(state)

		default:
			return nil, fmt.Errorf("unknown enrollment status result: %s", resp.Result)
		}

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("wait for approval canceled: %w", ctx.Err())
		case <-time.After(pollInterval):
		}
	}
}

type artifactManifestItem struct {
	Component   string `json:"component"`
	FileName    string `json:"file_name"`
	DownloadURL string `json:"download_url"`
	SHA256      string `json:"sha256"`
}

func (a *BootstrapApp) ensureServerCACertPath() error {
	baseURL := strings.ToLower(strings.TrimSpace(a.cfg.Server.BaseURL))
	if strings.HasPrefix(baseURL, "http://") {
		// HTTP 모드에서는 CA 파일 불필요
		return nil
	}

	cfgPath := strings.TrimSpace(a.cfg.Server.CACertPath)
	if cfgPath != "" {
		if st, err := os.Stat(cfgPath); err == nil && !st.IsDir() {
			return nil
		}
	}

	// Linux trust bundle fallback
	candidates := []string{
		"/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu
		"/etc/pki/tls/certs/ca-bundle.crt",   // RHEL/CentOS
		"/etc/ssl/cert.pem",                  // Alpine 계열
	}

	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			a.cfg.Server.CACertPath = p
			return nil
		}
	}

	return fmt.Errorf("ca cert file not found (configured: %q)", cfgPath)
}

func detectPrimaryIPv4() string {
	// 1) 기본 라우팅 기준 추정
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err == nil {
		defer conn.Close()
		if ua, ok := conn.LocalAddr().(*net.UDPAddr); ok && ua.IP != nil {
			if v4 := ua.IP.To4(); v4 != nil && !v4.IsLoopback() {
				return v4.String()
			}
		}
	}

	// 2) fallback: 모든 인터페이스 순회
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}

	for _, ifc := range ifaces {
		if (ifc.Flags&net.FlagUp) == 0 || (ifc.Flags&net.FlagLoopback) != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			if v4 := ip.To4(); v4 != nil {
				return v4.String()
			}
		}
	}

	return ""
}

func (a *BootstrapApp) ensureSystemdService(
	ctx context.Context,
	serviceName string,
	binPath string,
	configPath string,
) error {
	// serviceName 예: "fluent-bit.service"
	// binPath 예: "/usr/local/bin/fluent-bit"
	// configPath 예: "/etc/ebpf-edr/fluent-bit/fluent-bit.yaml"

	if strings.TrimSpace(serviceName) == "" {
		return fmt.Errorf("service name is empty")
	}
	if strings.TrimSpace(binPath) == "" {
		return fmt.Errorf("binary path is empty")
	}

	unitPath := filepath.Join("/etc/systemd/system", serviceName)

	unitContent := a.buildFluentBitServiceUnit(serviceName, binPath, configPath)

	// 기존 파일과 내용이 다를 때만 덮어쓰기
	needWrite := true
	if existing, err := os.ReadFile(unitPath); err == nil {
		if string(existing) == unitContent {
			needWrite = false
		}
	}

	if needWrite {
		if err := os.WriteFile(unitPath, []byte(unitContent), 0o644); err != nil {
			return fmt.Errorf("write systemd unit file %s: %w", unitPath, err)
		}
	}

	// systemd 설정 다시 읽기
	daemonReloadCmd := exec.CommandContext(ctx, "systemctl", "daemon-reload")
	if out, err := daemonReloadCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl daemon-reload failed: %v (%s)", err, strings.TrimSpace(string(out)))
	}

	// 부팅 시 자동 시작 + 즉시 시작
	enableCmd := exec.CommandContext(ctx, "systemctl", "enable", "--now", serviceName)
	if out, err := enableCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl enable --now %s failed: %v (%s)", serviceName, err, strings.TrimSpace(string(out)))
	}

	// 실제 active 상태인지 확인
	activeCmd := exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", serviceName)
	if out, err := activeCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("service %s not active: %v (%s)", serviceName, err, strings.TrimSpace(string(out)))
	}

	return nil
}

func (a *BootstrapApp) buildFluentBitServiceUnit(
	serviceName string,
	binPath string,
	configPath string,
) string {
	_ = serviceName

	// configPath가 비어 있으면 -c 옵션 없이 실행
	execStart := binPath
	if strings.TrimSpace(configPath) != "" {
		execStart = fmt.Sprintf("%s -c %s", shellEscape(binPath), shellEscape(configPath))
	} else {
		execStart = shellEscape(binPath)
	}

	return fmt.Sprintf(`[Unit]
Description=Fluent Bit
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s
Restart=always
RestartSec=3
User=root
Group=root
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`, execStart)
}

func shellEscape(s string) string {
	return `'` + strings.ReplaceAll(s, `'`, `'\''`) + `'`
}

func extractTarGz(archivePath, destDir string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("open archive: %w", err)
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("create gzip reader: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar entry: %w", err)
		}
		if hdr == nil {
			continue
		}

		name := strings.TrimSpace(hdr.Name)
		if name == "" {
			continue
		}

		targetPath := filepath.Join(destDir, name)
		cleanDest := filepath.Clean(destDir) + string(os.PathSeparator)
		cleanTarget := filepath.Clean(targetPath)

		// path traversal 방지
		if !strings.HasPrefix(cleanTarget, cleanDest) && cleanTarget != filepath.Clean(destDir) {
			return fmt.Errorf("invalid archive path: %s", hdr.Name)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(cleanTarget, os.FileMode(hdr.Mode)); err != nil {
				return fmt.Errorf("mkdir extracted dir %s: %w", cleanTarget, err)
			}

		case tar.TypeReg, tar.TypeRegA:
			parentDir := filepath.Dir(cleanTarget)
			if err := os.MkdirAll(parentDir, 0o755); err != nil {
				return fmt.Errorf("mkdir parent dir %s: %w", parentDir, err)
			}

			outFile, err := os.OpenFile(cleanTarget, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(hdr.Mode))
			if err != nil {
				return fmt.Errorf("create extracted file %s: %w", cleanTarget, err)
			}

			if _, err := io.Copy(outFile, tr); err != nil {
				outFile.Close()
				return fmt.Errorf("write extracted file %s: %w", cleanTarget, err)
			}

			if err := outFile.Close(); err != nil {
				return fmt.Errorf("close extracted file %s: %w", cleanTarget, err)
			}

		case tar.TypeSymlink:
			// 초기 버전에서는 심볼릭 링크는 안전상 막는 편이 낫다.
			return fmt.Errorf("symlink is not allowed in artifact: %s", hdr.Name)

		default:
			// 필요 없는 타입은 일단 무시
			continue
		}
	}

	return nil
}

func findFileByBaseName(rootDir, baseName string) (string, error) {
	var found string

	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if filepath.Base(path) == baseName {
			found = path
			return io.EOF // 탐색 중단용
		}
		return nil
	})

	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if strings.TrimSpace(found) == "" {
		return "", fmt.Errorf("file %q not found under %s", baseName, rootDir)
	}

	return found, nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open src file: %w", err)
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return fmt.Errorf("mkdir dst dir: %w", err)
	}

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return fmt.Errorf("open dst file: %w", err)
	}

	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return fmt.Errorf("copy file content: %w", err)
	}

	if err := out.Close(); err != nil {
		return fmt.Errorf("close dst file: %w", err)
	}

	if err := os.Chmod(dst, mode); err != nil {
		return fmt.Errorf("chmod dst file: %w", err)
	}

	return nil
}

func (a *BootstrapApp) InstallArtifactOnly(ctx context.Context, componentName, binaryName string) (string, error) {
	if strings.TrimSpace(componentName) == "" {
		return "", errors.New("componentName is empty")
	}
	if strings.TrimSpace(binaryName) == "" {
		return "", errors.New("binaryName is empty")
	}
	return a.installComponentArtifact(ctx, componentName, binaryName)
}

// EnsureDependenciesOnly는 enrollment/정책 수신 없이 dependency 설치 단계만 실행한다.
// 테스트 전용 진입점.
func (a *BootstrapApp) EnsureDependenciesOnly(ctx context.Context) error {
	if err := a.ensurePaths(); err != nil {
		return fmt.Errorf("ensure bootstrap paths: %w", err)
	}

	state, err := a.loadState()
	if err != nil {
		return fmt.Errorf("load bootstrap state: %w", err)
	}

	// 테스트 편의: dependency 단계 진입 가능하도록 상태 보정
	state.EnrollmentStatus = EnrollmentStatusApproved
	if state.CreatedAt.IsZero() {
		state.CreatedAt = time.Now()
	}
	state.UpdatedAt = time.Now()

	if err := a.saveState(state); err != nil {
		return fmt.Errorf("save bootstrap state: %w", err)
	}

	return a.ensureDependenciesInstalled(ctx, state)
}

func (a *BootstrapApp) findBundledEntrypoint(componentName string) (string, bool) {
	baseDir := filepath.Join("/opt/ebpf-edr/components", componentName)

	candidates := []string{
		filepath.Join(baseDir, "run-"+componentName+".sh"),
		filepath.Join(baseDir, "run-fluent-bit.sh"), // fluent-bit 전용
		filepath.Join(baseDir, "bin", componentName),
	}

	for _, p := range candidates {
		st, err := os.Stat(p)
		if err == nil && !st.IsDir() && (st.Mode()&0o111) != 0 {
			return p, true
		}
	}

	return "", false
}

func findBundleRoot(extractDir, componentName string) (string, error) {
	entries, err := os.ReadDir(extractDir)
	if err != nil {
		return "", err
	}

	if len(entries) == 1 && entries[0].IsDir() {
		return filepath.Join(extractDir, entries[0].Name()), nil
	}

	// top-level dir가 하나가 아닐 수도 있으니 componentName 우선 탐색
	candidate := filepath.Join(extractDir, componentName)
	if st, err := os.Stat(candidate); err == nil && st.IsDir() {
		return candidate, nil
	}

	return "", fmt.Errorf("bundle root not found under %s", extractDir)
}

func validateFluentBitBundle(root string) error {
	required := []string{
		filepath.Join(root, "run-fluent-bit.sh"),
		filepath.Join(root, "bin", "fluent-bit"),
		// filepath.Join(root, "conf", "fluent-bit.yaml"),
	}

	for _, p := range required {
		st, err := os.Stat(p)
		if err != nil {
			return fmt.Errorf("required file missing: %s", p)
		}
		if st.IsDir() {
			return fmt.Errorf("required file is directory: %s", p)
		}
	}

	return nil
}

func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)

		if info.IsDir() {
			return os.MkdirAll(target, info.Mode().Perm())
		}

		// 심볼릭 링크 금지 정책 유지
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink not allowed in bundle: %s", path)
		}

		return copyFile(path, target, info.Mode().Perm())
	})
}

func (a *BootstrapApp) ensureBundledSystemdService(
	ctx context.Context,
	serviceName string,
	runPath string,
) error {
	if strings.TrimSpace(serviceName) == "" {
		return fmt.Errorf("service name is empty")
	}
	if strings.TrimSpace(runPath) == "" {
		return fmt.Errorf("run path is empty")
	}

	unitPath := filepath.Join("/etc/systemd/system", serviceName)
	unitContent := fmt.Sprintf(`[Unit]
Description=Fluent Bit (bundled)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s
Restart=always
RestartSec=3
User=root
Group=root

[Install]
WantedBy=multi-user.target
`, shellEscape(runPath))

	needWrite := true
	if existing, err := os.ReadFile(unitPath); err == nil && string(existing) == unitContent {
		needWrite = false
	}

	if needWrite {
		if err := os.WriteFile(unitPath, []byte(unitContent), 0o644); err != nil {
			return fmt.Errorf("write systemd unit file %s: %w", unitPath, err)
		}
	}

	daemonReloadCmd := exec.CommandContext(ctx, "systemctl", "daemon-reload")
	if out, err := daemonReloadCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl daemon-reload failed: %v (%s)", err, strings.TrimSpace(string(out)))
	}

	enableCmd := exec.CommandContext(ctx, "systemctl", "enable", "--now", serviceName)
	if out, err := enableCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl enable --now %s failed: %v (%s)", serviceName, err, strings.TrimSpace(string(out)))
	}

	activeCmd := exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", serviceName)
	if out, err := activeCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("service %s not active: %v (%s)", serviceName, err, strings.TrimSpace(string(out)))
	}

	return nil
}

func copyLocalFluentBitConfig(stageDir string) error {
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}

	src := filepath.Join(cwd, "configs", "fluent-bit.yaml")
	if _, err := os.Stat(src); err != nil {
		return fmt.Errorf("source config not found: %s (%w)", src, err)
	}

	dst := filepath.Join(stageDir, "conf", "fluent-bit.yaml")
	if err := copyFile(src, dst, 0o644); err != nil {
		return fmt.Errorf("copy %s -> %s: %w", src, dst, err)
	}

	return nil
}
