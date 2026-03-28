package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/suhyeon514/eBPF_Project/internal/app"
	"github.com/suhyeon514/eBPF_Project/internal/config"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("[agent] fatal error: %v", err)
	}
}

func run() error {
	if len(os.Args) < 2 {
		return usageError("missing subcommand")
	}

	switch os.Args[1] {
	case "run":
		return runAll(os.Args[2:])
	case "bootstrap":
		return runBootstrap(os.Args[2:])
	case "runtime":
		return runRuntime(os.Args[2:])
	case "-h", "--help", "help":
		printUsage()
		return nil
	default:
		return usageError(fmt.Sprintf("unknown subcommand: %s", os.Args[1]))
	}
}

func runAll(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)

	bootstrapPath := fs.String(
		"bootstrap-config",
		"configs/bootstrap.lab.yaml",
		"path to bootstrap config file",
	)

	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("parse run flags: %w", err)
	}

	bootstrapCfg, err := config.LoadBootstrap(*bootstrapPath)
	if err != nil {
		return fmt.Errorf("load bootstrap config: %w", err)
	}

	ctx, stop := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT,
		syscall.SIGTERM,
	)
	defer stop()

	agentApp := app.NewAgentApp(bootstrapCfg)

	if err := agentApp.Run(ctx); err != nil {
		return fmt.Errorf("run agent app: %w", err)
	}

	return nil
}

func runBootstrap(args []string) error {
	fs := flag.NewFlagSet("bootstrap", flag.ContinueOnError)

	bootstrapPath := fs.String(
		"bootstrap-config",
		"configs/bootstrap.lab.yaml",
		"path to bootstrap config file",
	)

	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("parse bootstrap flags: %w", err)
	}

	bootstrapCfg, err := config.LoadBootstrap(*bootstrapPath)
	if err != nil {
		return fmt.Errorf("load bootstrap config: %w", err)
	}

	ctx, stop := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT,
		syscall.SIGTERM,
	)
	defer stop()

	bootstrapApp := app.NewBootstrapApp(bootstrapCfg)
	if _, err := bootstrapApp.Run(ctx); err != nil {
		return fmt.Errorf("run bootstrap app: %w", err)
	}

	return nil
}

func runRuntime(args []string) error {
	fs := flag.NewFlagSet("runtime", flag.ContinueOnError)

	bootstrapPath := fs.String(
		"bootstrap-config",
		"configs/bootstrap.lab.yaml",
		"path to bootstrap config file",
	)

	runtimePath := fs.String(
		"runtime-config",
		"",
		"path to runtime policy file (optional; defaults to bootstrap.paths.runtime_policy_path)",
	)

	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("parse runtime flags: %w", err)
	}

	bootstrapCfg, err := config.LoadBootstrap(*bootstrapPath)
	if err != nil {
		return fmt.Errorf("load bootstrap config: %w", err)
	}

	policyPath := bootstrapCfg.Paths.RuntimePolicyPath
	if *runtimePath != "" {
		policyPath = *runtimePath
	}

	runtimeCfg, err := config.LoadRuntime(policyPath)
	if err != nil {
		return fmt.Errorf("load runtime config from %q: %w", policyPath, err)
	}

	ctx, stop := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT,
		syscall.SIGTERM,
	)
	defer stop()

	runtimeDeps, err := app.LoadRuntimeDepsFromBootstrapState(bootstrapCfg)
	if err != nil {
		return fmt.Errorf("load runtime deps from bootstrap state: %w", err)
	}

	runtimeApp := app.NewRuntimeApp(runtimeCfg, runtimeDeps)
	if err := runtimeApp.Run(ctx); err != nil {
		return fmt.Errorf("run runtime app: %w", err)
	}

	return nil
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Usage:
  agent run [-bootstrap-config path]
      Run bootstrap if needed, then start runtime.

  agent bootstrap [-bootstrap-config path]
      Perform installation/bootstrap/enrollment only.

  agent runtime [-bootstrap-config path] [-runtime-config path]
      Start runtime only. If -runtime-config is omitted,
      bootstrap.paths.runtime_policy_path is used.

Examples:
  agent run -bootstrap-config configs/bootstrap.lab.yaml
  agent bootstrap -bootstrap-config configs/bootstrap.lab.yaml
  agent runtime -bootstrap-config configs/bootstrap.lab.yaml
`)
}

func usageError(msg string) error {
	printUsage()
	return errors.New(msg)
}
