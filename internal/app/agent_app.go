package app

import (
	"context"
	"fmt"
	"os"

	"github.com/suhyeon514/eBPF_Project/internal/config"
	"github.com/suhyeon514/eBPF_Project/internal/service/policy"
)

type AgentApp struct {
	bootstrapCfg *config.BootstrapConfig

	//[임시 추가]정책 관련 서비스, checker.go 의 Service와 일치 시키기
	policyService *policy.Service
}

func NewAgentApp(bootstrapCfg *config.BootstrapConfig) *AgentApp {
	return &AgentApp{
		bootstrapCfg: bootstrapCfg,
	}
}

// Run은 전체 agent lifecycle을 실행한다.
// 순서:
//  1. bootstrap 수행 (필요 시 등록/인증/초기 정책/설치)
//  2. bootstrap 결과를 바탕으로 runtime policy 파일 로드
//  3. runtime 시작
func (a *AgentApp) Run(ctx context.Context) error {
	bootstrapApp := NewBootstrapApp(a.bootstrapCfg)

	bootstrapResult, err := bootstrapApp.Run(ctx)
	if err != nil {
		return fmt.Errorf("run bootstrap app: %w", err)
	}

	runtimePolicyPath := a.bootstrapCfg.Paths.RuntimePolicyPath
	if _, err := os.Stat(runtimePolicyPath); err != nil {
		return fmt.Errorf("runtime policy file not found after bootstrap: %s: %w", runtimePolicyPath, err)
	}

	runtimeCfg, err := config.LoadRuntime(runtimePolicyPath)
	if err != nil {
		return fmt.Errorf("load runtime config from policy path %q: %w", runtimePolicyPath, err)
	}

	runtimeDeps := NewRuntimeDeps(a.bootstrapCfg, bootstrapResult)

	runtimeApp := NewRuntimeApp(runtimeCfg, runtimeDeps)
	if err := runtimeApp.Run(ctx); err != nil {
		return fmt.Errorf("run runtime app: %w", err)
	}

	return nil
}
