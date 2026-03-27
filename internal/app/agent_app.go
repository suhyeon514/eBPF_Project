package app

import (
	"context"
	"fmt"

	"github.com/suhyeon514/eBPF_Project/internal/config"
	"github.com/suhyeon514/eBPF_Project/internal/service/policy"
)

type AgentApp struct {
	bootstrapCfg *config.BootstrapConfig
	runtimeCfg   *config.RuntimeConfig

	//[임시 추가]정책 관련 서비스, checker.go 의 Service와 일치 시키기
	policyService *policy.Service
}

func NewAgentApp(
	bootstrapCfg *config.BootstrapConfig,
	runtimeCfg *config.RuntimeConfig,
) *AgentApp {
	return &AgentApp{
		bootstrapCfg: bootstrapCfg,
		runtimeCfg:   runtimeCfg,
	}
}

func (a *AgentApp) Run(ctx context.Context) error {
	bootstrapApp := NewBootstrapApp(a.bootstrapCfg)

	bootstrapResult, err := bootstrapApp.Run(ctx)
	if err != nil {
		return fmt.Errorf("run bootstrap app: %w", err)
	}

	runtimeDeps := NewRuntimeDeps(a.bootstrapCfg, bootstrapResult)

	runtimeApp := NewRuntimeApp(a.runtimeCfg, runtimeDeps)
	if err := runtimeApp.Run(ctx); err != nil {
		return fmt.Errorf("run runtime app: %w", err)
	}

	return nil
}
