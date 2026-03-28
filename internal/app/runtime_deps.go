package app

import (
	"fmt"
	"os"

	"github.com/suhyeon514/eBPF_Project/internal/config"
)

type RuntimeDeps struct {
	// 서버 통신 관련
	ServerBaseURL    string
	ServerCACertPath string

	// mTLS용 client identity
	ClientCertPath string
	ClientKeyPath  string

	// 로컬 policy 파일 경로
	RuntimePolicyPath string

	// bootstrap 결과
	AgentID     string
	InstallUUID string

	// host / identity
	HostID       string
	AssignedEnv  string
	AssignedRole string

	// runtime 통신
	HeartbeatPath string
}

func NewRuntimeDeps(
	bootstrapCfg *config.BootstrapConfig,
	bootstrapResult *BootstrapResult,
) RuntimeDeps {
	return RuntimeDeps{
		ServerBaseURL:    bootstrapCfg.Server.BaseURL,
		ServerCACertPath: bootstrapCfg.Server.CACertPath,

		ClientCertPath: bootstrapCfg.Paths.CertificatePath,
		ClientKeyPath:  bootstrapCfg.Paths.PrivateKeyPath,

		RuntimePolicyPath: bootstrapCfg.Paths.RuntimePolicyPath,

		AgentID:     bootstrapResult.AgentID,
		InstallUUID: bootstrapResult.InstallUUID,

		HostID:       bootstrapCfg.Identity.HostID,
		AssignedEnv:  bootstrapResult.AssignedEnv,
		AssignedRole: bootstrapResult.AssignedRole,

		HeartbeatPath: bootstrapCfg.Server.HeartbeatPath,
	}
}

// LoadRuntimeDepsFromBootstrapState는 runtime-only 실행 시
// bootstrap state + bootstrap config를 이용해 RuntimeDeps를 복원한다.
//
// 여기서 "runtime 시작 자격 검증"도 같이 수행한다.
func LoadRuntimeDepsFromBootstrapState(
	bootstrapCfg *config.BootstrapConfig,
) (RuntimeDeps, error) {
	bootstrapApp := NewBootstrapApp(bootstrapCfg)

	state, err := bootstrapApp.loadState()
	if err != nil {
		return RuntimeDeps{}, fmt.Errorf("load bootstrap state: %w", err)
	}

	if state.EnrollmentStatus != EnrollmentStatusApproved {
		switch state.EnrollmentStatus {
		case EnrollmentStatusPending:
			return RuntimeDeps{}, fmt.Errorf("runtime cannot start: enrollment is still pending approval")
		case EnrollmentStatusRejected:
			return RuntimeDeps{}, fmt.Errorf("runtime cannot start: enrollment was rejected")
		case EnrollmentStatusError:
			return RuntimeDeps{}, fmt.Errorf("runtime cannot start: bootstrap ended in error state")
		case EnrollmentStatusIdle:
			fallthrough
		default:
			return RuntimeDeps{}, fmt.Errorf("runtime cannot start: bootstrap has not completed")
		}
	}

	if state.AgentID == "" {
		return RuntimeDeps{}, fmt.Errorf("runtime cannot start: agent_id is missing")
	}
	if state.InstallUUID == "" {
		return RuntimeDeps{}, fmt.Errorf("runtime cannot start: install_uuid is missing")
	}

	if err := ensureRuntimeFileExists(bootstrapCfg.Paths.PrivateKeyPath, "client private key"); err != nil {
		return RuntimeDeps{}, err
	}
	if err := ensureRuntimeFileExists(bootstrapCfg.Paths.CertificatePath, "client certificate"); err != nil {
		return RuntimeDeps{}, err
	}
	if err := ensureRuntimeFileExists(bootstrapCfg.Paths.PolicyPath, "runtime policy file"); err != nil {
		return RuntimeDeps{}, err
	}

	// TODO:
	// 추후 여기서 tetragon / fluent-bit 설치 상태도 같이 확인 가능
	// ex) state.TetragonStatus == installed, state.FluentBitStatus == installed

	return RuntimeDeps{
		ServerBaseURL:    bootstrapCfg.Server.BaseURL,
		ServerCACertPath: bootstrapCfg.Server.CACertPath,

		ClientCertPath: bootstrapCfg.Paths.CertificatePath,
		ClientKeyPath:  bootstrapCfg.Paths.PrivateKeyPath,

		RuntimePolicyPath: bootstrapCfg.Paths.RuntimePolicyPath,

		AgentID:     state.AgentID,
		InstallUUID: state.InstallUUID,

		HostID:       bootstrapCfg.Identity.HostID,
		AssignedEnv:  state.AssignedEnv,
		AssignedRole: state.AssignedRole,

		HeartbeatPath: bootstrapCfg.Server.HeartbeatPath,
	}, nil
}

func ensureRuntimeFileExists(path, desc string) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("runtime cannot start: %s not found at %s: %w", desc, path, err)
	}
	return nil
}
