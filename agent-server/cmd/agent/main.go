package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/suhyeon514/eBPF_Project/internal/app"
	"github.com/suhyeon514/eBPF_Project/internal/config"
)

func main() {

	// ===== flag =====
	bootstrapPath := flag.String("bootstrap-config", "configs/bootstrap.lab.yaml", "path to bootstrap config file")
	runtimePath := flag.String("runtime-config", "configs/agent.lab.yaml", "path to runtime config file")
	flag.Parse()

	// ===== 절대경로 변환 (핵심) =====
	absBootstrap, err := filepath.Abs(*bootstrapPath)
	if err != nil {
		panic(fmt.Errorf("bootstrap path resolve error: %w", err))
	}

	absRuntime, err := filepath.Abs(*runtimePath)
	if err != nil {
		panic(fmt.Errorf("runtime path resolve error: %w", err))
	}


	// ===== 파일 존재 확인 =====
	if _, err := os.Stat(absBootstrap); err != nil {
		panic(fmt.Errorf("bootstrap file not found: %w", err))
	}

	if _, err := os.Stat(absRuntime); err != nil {
		panic(fmt.Errorf("runtime file not found: %w", err))
	}


	// ===== config load =====
	bootstrapcfg, err := config.LoadBootstrap(absBootstrap)
	if err != nil {
		panic(fmt.Errorf("load bootstrap config: %w", err))
	}

	runtimecfg, err := config.LoadRuntime(absRuntime)
	if err != nil {
		panic(fmt.Errorf("load runtime config: %w", err))
	}

	// ===== 디버깅 (hostname 확인) =====

	// ===== context =====
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// ===== run =====
	agentApp := app.NewAgentApp(bootstrapcfg, runtimecfg)

	if err := agentApp.Run(ctx); err != nil {
		panic(fmt.Errorf("run agent app: %w", err))
	}
}
