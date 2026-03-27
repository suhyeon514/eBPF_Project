package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/suhyeon514/eBPF_Project/internal/config"
)

type EnrollmentStatus string

const (
	EnrollmentStatusIdle     EnrollmentStatus = "idle"
	EnrollmentStatusPending  EnrollmentStatus = "pending"
	EnrollmentStatusApproved EnrollmentStatus = "approved"
	EnrollmentStatusRejected EnrollmentStatus = "rejected"
	EnrollmentStatusError    EnrollmentStatus = "error"
)

type EnrollResult string

const (
	EnrollResultApproved EnrollResult = "approved"
	EnrollResultPending  EnrollResult = "pending"
	EnrollResultRejected EnrollResult = "rejected"
)

type BootstrapState struct {
	AgentID string `json:"agent_id,omitempty"`

	InstallUUID string `json:"install_uuid,omitempty"`

	LastRequestID string `json:"last_request_id,omitempty"`

	// agent 로컬 bootstrap lifecycle 상태
	EnrollmentStatus EnrollmentStatus `json:"enrollment_status"`

	// 마지막 서버 응답 기록
	LastServerResult     EnrollResult `json:"last_server_result,omitempty"`
	LastServerReasonCode string       `json:"last_server_reason_code,omitempty"`

	CreatedAt time.Time `json:"created_at,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

type BootstrapResult struct {
	AgentID     string
	InstallUUID string
}

type Fingerprint struct {
	MachineID       string
	Hostname        string
	OSID            string
	OSVersion       string
	CloudInstanceID string
}

type EnrollResponse struct {
	Result         EnrollResult `json:"result"`
	ReasonCode     string       `json:"reason_code"`
	Message        string       `json:"message"`
	RequestID      string       `json:"request_id"`
	AgentID        string       `json:"agent_id"`
	CertificatePEM string       `json:"certificate_pem"`
}

type BootstrapApp struct {
	cfg *config.BootstrapConfig
}

func NewBootstrapApp(cfg *config.BootstrapConfig) *BootstrapApp {
	return &BootstrapApp{cfg: cfg}
}

func (a *BootstrapApp) Run(ctx context.Context) (*BootstrapResult, error) {
	state, err := a.loadState()
	if err != nil {
		return nil, fmt.Errorf("load bootstrap state: %w", err)
	}

	if a.hasUsableIdentity(state) {
		state.EnrollmentStatus = EnrollmentStatusApproved
		state.UpdatedAt = time.Now()

		if err := a.saveState(state); err != nil {
			return nil, fmt.Errorf("save bootstrap state: %w", err)
		}

		return &BootstrapResult{
			AgentID:     state.AgentID,
			InstallUUID: state.InstallUUID,
		}, nil
	}

	if state.InstallUUID == "" {
		state.InstallUUID = generateInstallUUID()
	}

	if err := a.ensurePrivateKey(); err != nil {
		state.EnrollmentStatus = EnrollmentStatusError
		state.UpdatedAt = time.Now()
		_ = a.saveState(state)
		return nil, fmt.Errorf("ensure private key: %w", err)
	}

	csrPEM, err := a.generateCSR()
	if err != nil {
		state.EnrollmentStatus = EnrollmentStatusError
		state.UpdatedAt = time.Now()
		_ = a.saveState(state)
		return nil, fmt.Errorf("generate csr: %w", err)
	}

	fingerprint, err := a.collectFingerprint()
	if err != nil {
		state.EnrollmentStatus = EnrollmentStatusError
		state.UpdatedAt = time.Now()
		_ = a.saveState(state)
		return nil, fmt.Errorf("collect fingerprint: %w", err)
	}

	resp, err := a.requestEnrollment(ctx, state.InstallUUID, csrPEM, fingerprint)
	if err != nil {
		state.EnrollmentStatus = EnrollmentStatusError
		state.UpdatedAt = time.Now()
		_ = a.saveState(state)
		return nil, fmt.Errorf("request enrollment: %w", err)
	}

	state.LastRequestID = resp.RequestID
	state.LastServerResult = resp.Result
	state.LastServerReasonCode = resp.ReasonCode

	switch resp.Result {
	case EnrollResultApproved:
		if err := a.saveCertificate(resp.CertificatePEM); err != nil {
			state.EnrollmentStatus = EnrollmentStatusError
			state.UpdatedAt = time.Now()
			_ = a.saveState(state)
			return nil, fmt.Errorf("save certificate: %w", err)
		}
		state.AgentID = resp.AgentID
		state.EnrollmentStatus = EnrollmentStatusApproved
		state.UpdatedAt = time.Now()

		if err := a.saveState(state); err != nil {
			return nil, fmt.Errorf("save bootstrap state: %w", err)
		}

		return &BootstrapResult{
			AgentID:     state.AgentID,
			InstallUUID: state.InstallUUID,
		}, nil

	case EnrollResultPending:
		state.EnrollmentStatus = EnrollmentStatusPending
		state.UpdatedAt = time.Now()

		if err := a.saveState(state); err != nil {
			return nil, fmt.Errorf("save pending bootstrap state: %w", err)
		}

		finalResp, err := a.waitForApproval(ctx, state)
		if err != nil {
			state.EnrollmentStatus = EnrollmentStatusError
			state.UpdatedAt = time.Now()
			_ = a.saveState(state)
			return nil, fmt.Errorf("wait for approval: %w", err)
		}

		state.LastServerResult = finalResp.Result
		state.LastServerReasonCode = finalResp.ReasonCode
		state.LastRequestID = finalResp.RequestID

		switch finalResp.Result {
		case EnrollResultApproved:
			if err := a.saveCertificate(resp.CertificatePEM); err != nil {
				state.EnrollmentStatus = EnrollmentStatusError
				state.UpdatedAt = time.Now()
				_ = a.saveState(state)
				return nil, fmt.Errorf("save certificate: %w", err)
			}
			state.AgentID = resp.AgentID
			state.EnrollmentStatus = EnrollmentStatusApproved
			state.UpdatedAt = time.Now()

			if err := a.saveState(state); err != nil {
				return nil, fmt.Errorf("save bootstrap state: %w", err)
			}

			return &BootstrapResult{
				AgentID:     state.AgentID,
				InstallUUID: state.InstallUUID,
			}, nil

		case EnrollResultRejected:
			state.EnrollmentStatus = EnrollmentStatusRejected
			state.UpdatedAt = time.Now()
			_ = a.saveState(state)
			return nil, fmt.Errorf("enrollment rejected: %s", finalResp.Message)

		default:
			state.EnrollmentStatus = EnrollmentStatusError
			state.UpdatedAt = time.Now()
			_ = a.saveState(state)
			return nil, fmt.Errorf("unexpected final enrollment result: %s", finalResp.Result)
		}

	case EnrollResultRejected:
		state.EnrollmentStatus = EnrollmentStatusRejected
		state.UpdatedAt = time.Now()
		_ = a.saveState(state)
		return nil, fmt.Errorf("enrollment rejected: %s", resp.Message)

	default:
		state.EnrollmentStatus = EnrollmentStatusError
		state.UpdatedAt = time.Now()
		_ = a.saveState(state)
		return nil, fmt.Errorf("unknown enrollment result: %s", resp.Result)

	}
}

func (a *BootstrapApp) loadState() (*BootstrapState, error) {
	path := a.cfg.Paths.StatePath

	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			now := time.Now()
			return &BootstrapState{
				EnrollmentStatus: EnrollmentStatusIdle,
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
	if state.CreatedAt.IsZero() {
		state.CreatedAt = time.Now()
	}
	state.UpdatedAt = time.Now()

	return &state, nil
}

func (a *BootstrapApp) saveState(state *BootstrapState) error {
	if err := os.MkdirAll(filepath.Dir(a.cfg.Paths.StatePath), 0o755); err != nil {
		return err
	}

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

func (a *BootstrapApp) ensurePrivateKey() error {
	// TODO:
	// - private key 파일 존재 여부 확인
	// - 없으면 ECDSA P-256 key 생성 후 cfg.Paths.PrivateKeyPath 에 저장
	return nil
}

func (a *BootstrapApp) generateCSR() ([]byte, error) {
	// TODO:
	// - cfg.Identity.HostID 를 CN으로 사용
	// - 로컬 private key로 CSR 생성
	// - cfg.Paths.CSRPath에 저장(optional)
	return []byte("TODO_CSR_PEM"), nil
}

func (a *BootstrapApp) collectFingerprint() (*Fingerprint, error) {
	// TODO:
	// - machine-id
	// - hostname
	// - os-release
	// - cloud instance-id(optional)
	return &Fingerprint{}, nil
}

func (a *BootstrapApp) requestEnrollment(
	ctx context.Context,
	installUUID string,
	csrPEM []byte,
	fp *Fingerprint,
) (*EnrollResponse, error) {
	// TODO:
	// - POST {BaseURL}{EnrollRequestPath}
	// - host_id, install_uuid, fingerprint, csr_pem 전송
	_ = ctx
	_ = installUUID
	_ = csrPEM
	_ = fp

	return &EnrollResponse{
		Result:         "approved",
		ReasonCode:     "auto_approved",
		Message:        "approved",
		RequestID:      "dummy-request-id",
		AgentID:        "dummy-agent-id",
		CertificatePEM: "TODO_CERT_PEM",
	}, nil
}

func (a *BootstrapApp) waitForApproval(
	ctx context.Context,
	state *BootstrapState,
) (*EnrollResponse, error) {
	// TODO:
	// - state.LastRequestID 기반으로 GET {BaseURL}{EnrollStatusPath}/{request_id}
	// - cfg.Enrollment.PollInterval 간격으로 polling
	// - cfg.Enrollment.MaxPendingDuration 넘으면 timeout 처리
	_ = ctx
	_ = state

	return &EnrollResponse{
		Result:         "approved",
		ReasonCode:     "manually_approved",
		Message:        "approved after review",
		RequestID:      state.LastRequestID,
		AgentID:        "dummy-agent-id",
		CertificatePEM: "TODO_CERT_PEM",
	}, nil
}

func (a *BootstrapApp) saveCertificate(certPEM string) error {
	if err := os.MkdirAll(filepath.Dir(a.cfg.Paths.CertificatePath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(a.cfg.Paths.CertificatePath, []byte(certPEM), 0o600)
}

func generateInstallUUID() string {
	// TODO:
	// - google/uuid 또는 다른 UUID 라이브러리로 교체
	return "todo-install-uuid"
}
