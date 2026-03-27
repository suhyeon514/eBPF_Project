package main

import (
	"context"
	"flag"
	"fmt"
	"os/signal"
	"syscall"

	"github.com/suhyeon514/eBPF_Project/internal/app"
	"github.com/suhyeon514/eBPF_Project/internal/config"
)

func main() {
	bootstrapPath := flag.String("bootstrap-config", "configs/bootstrap.lab.yaml", "path to bootstrap config file")
	runtimePath := flag.String("runtime-config", "configs/agent.lab.yaml", "path to runtime config file")
	flag.Parse()

	bootstrapcfg, err := config.LoadBootstrap(*bootstrapPath)
	if err != nil {
		panic(fmt.Errorf("load bootstrap config: %w", err))
	}

	runtimecfg, err := config.LoadRuntime(*runtimePath)
	if err != nil {
		panic(fmt.Errorf("load runtime config :%w", err))
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	agentApp := app.NewAgentApp(bootstrapcfg, runtimecfg)

	if err := agentApp.Run(ctx); err != nil {
		panic(fmt.Errorf("run agnet app: %w", err))
	}
}
