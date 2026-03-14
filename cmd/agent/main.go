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
	configPath := flag.String("config", "configs/agent.lab.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		panic(fmt.Errorf("load config :%w", err))
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	agentApp := app.NewAgentApp(cfg)

	if err := agentApp.Run(ctx); err != nil {
		panic(fmt.Errorf("run agnet app: %w", err))
	}
}
