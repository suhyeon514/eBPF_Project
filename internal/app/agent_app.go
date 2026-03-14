package app

import (
	"context"
	"fmt"

	tetragoncollector "github.com/suhyeon514/eBPF_Project/internal/collector/tetragon"
	"github.com/suhyeon514/eBPF_Project/internal/config"
	"github.com/suhyeon514/eBPF_Project/internal/model"
	tetragonnormalizer "github.com/suhyeon514/eBPF_Project/internal/normalize/tetragon"
	"github.com/suhyeon514/eBPF_Project/internal/output/jsonl"
)

type AgentApp struct {
	cfg *config.Config
}

func NewAgentApp(cfg *config.Config) *AgentApp {
	return &AgentApp{cfg: cfg}
}

func (a *AgentApp) Run(ctx context.Context) error {
	writer, err := jsonl.New(a.cfg.Output.NormalizedPath)
	if err != nil {
		return fmt.Errorf("create jsonl writer: %w", err)
	}
	defer writer.Close()

	host := model.HostMeta{
		HostID:   a.cfg.HostID,
		Hostname: a.cfg.Hostname,
		Env:      a.cfg.Env,
		Role:     a.cfg.Role,
	}

	normalizer := tetragonnormalizer.New(host)

	collector := tetragoncollector.New(tetragoncollector.Config{
		LogPath:      a.cfg.Tetragon.LogPath,
		PollInterval: a.cfg.Tetragon.PollInterval,
		ReadFromHead: a.cfg.Tetragon.ReadFromHead,
		EventsBuffer: 128,
		ErrorsBuffer: 32,
	})

	if err := collector.Start(ctx); err != nil {
		return fmt.Errorf("start tetragon collector: %w", err)
	}
	defer collector.Stop(context.Background())

	for {
		select {
		case raw := <-collector.Events():
			events, err := normalizer.Normalize(ctx, raw)
			if err != nil {
				fmt.Printf("normalize error: %v\n", err)
				continue
			}

			for _, ev := range events {
				if err := writer.WriteEvent(ev); err != nil {
					return fmt.Errorf("write normalized evnet: %w", err)
				}
			}

		case err := <-collector.Errors():
			fmt.Printf("collector error: %v\n", err)

		case <-ctx.Done():
			if err := writer.Sync(); err != nil {
				return fmt.Errorf("sync writer: %w", err)
			}
			return nil
		}
	}
}
