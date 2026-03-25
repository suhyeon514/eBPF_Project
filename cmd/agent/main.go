package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/suhyeon514/eBPF_Project/internal/app"
	"github.com/suhyeon514/eBPF_Project/internal/config"
)

func startTetragon(ctx context.Context) {
	log.Println("[*] Killing existing tetragon...")

	exec.Command("pkill", "-9", "tetragon").Run()

	exec.Command("rm", "-f", "/var/run/tetragon/tetragon.pid").Run()

	exec.Command("rm", "-rf", "/sys/fs/bpf/tetragon").Run()

	log.Println("[*] Starting tetragon...")

	cmd := exec.CommandContext(ctx,
		"/usr/local/bin/tetragon",
		"--tracing-policy=/home/ubuntu/eBPF_Project/policies/tetragon-kprobe-policy.yaml",
		"--export-filename", "/var/log/tetragon/tetragon.log",
		"--log-format", "json",
	)


	go func() {
		if err := cmd.Run(); err != nil {
			log.Println("[!] tetragon exited:", err)
		}
	}()

	log.Println("[*] Tetragon started (managed)")

	// 초기화 대기
	time.Sleep(3 * time.Second)
}

func main() {
	configPath := flag.String("config", "configs/agent.lab.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		panic(fmt.Errorf("load config: %w", err))
	}

	// 🔥 전체 lifecycle 관리 context
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// 🔥 tetragon 시작 (context 기반)
	startTetragon(ctx)

	// 🔥 agent 실행
	agentApp := app.NewAgentApp(cfg)

	if err := agentApp.Run(ctx); err != nil {
		panic(fmt.Errorf("run agent app: %w", err))
	}
}
