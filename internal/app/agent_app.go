package app

import (
	"context"
	"fmt"

	journaldcollector "github.com/suhyeon514/eBPF_Project/internal/collector/journald"
	tetragoncollector "github.com/suhyeon514/eBPF_Project/internal/collector/tetragon"
	"github.com/suhyeon514/eBPF_Project/internal/config"
	"github.com/suhyeon514/eBPF_Project/internal/model"
	"github.com/suhyeon514/eBPF_Project/internal/normalize"
	journaldnormalizer "github.com/suhyeon514/eBPF_Project/internal/normalize/journald"
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

	router := normalize.NewRouter()
	router.Register(model.RawSourceTetragon, tetragonnormalizer.New(host))
	router.Register(model.RawSourceJournald, journaldnormalizer.New(host))

	tetragonCollector := tetragoncollector.New(tetragoncollector.Config{
		LogPath:      a.cfg.Tetragon.LogPath,
		PollInterval: a.cfg.Tetragon.PollInterval,
		ReadFromHead: a.cfg.Tetragon.ReadFromHead,
		EventsBuffer: 128,
		ErrorsBuffer: 32,
	})

	journaldCollector := journaldcollector.New(journaldcollector.Config{
		Profiles:     a.cfg.Journald.Profiles,
		EventsBuffer: 128,
		ErrorsBuffer: 32,
		TailLines:    0,
	})

	if err := tetragonCollector.Start(ctx); err != nil {
		return fmt.Errorf("start tetragon collector: %w", err)
	}
	defer tetragonCollector.Stop(context.Background())

	if err := journaldCollector.Start(ctx); err != nil {
		return fmt.Errorf("start journald collector: %w", err)
	}
	defer journaldCollector.Stop(context.Background())

	tetragonEvents := tetragonCollector.Events()
	tetragonErrors := tetragonCollector.Errors()

	journaldEvents := journaldCollector.Events()
	journaldErrors := journaldCollector.Errors()

	for {
		if tetragonEvents == nil && tetragonErrors == nil &&
			journaldEvents == nil && journaldErrors == nil {
			if err := writer.Sync(); err != nil {
				return fmt.Errorf("sync writer: %w", err)
			}
			return nil
		}

		select {
		case raw, ok := <-tetragonEvents:
			if !ok {
				tetragonEvents = nil
				continue
			}

			if err := a.handleRawEvent(ctx, writer, router, raw); err != nil {
				return fmt.Errorf("handle tetragon raw event: %w", err)
			}

		case err, ok := <-tetragonErrors:
			if !ok {
				tetragonErrors = nil
				continue
			}
			fmt.Printf("[collector=tetragon] error=%v\n", err)

		case raw, ok := <-journaldEvents:
			if !ok {
				journaldEvents = nil
				continue
			}

			if err := a.handleRawEvent(ctx, writer, router, raw); err != nil {
				return fmt.Errorf("handle journald raw event: %w", err)
			}

		case err, ok := <-journaldErrors:
			if !ok {
				journaldErrors = nil
				continue
			}
			fmt.Printf("collector=journald] error=%v\n", err)

		case <-ctx.Done():
			if err := writer.Sync(); err != nil {
				return fmt.Errorf("sync writer: %w", err)
			}
			return nil
		}
	}
}

func (a *AgentApp) handleRawEvent(
	ctx context.Context,
	writer *jsonl.Writer,
	router *normalize.Router,
	raw model.RawEnvelope,
) error {
	events, err := router.Normalize(ctx, raw)
	if err != nil {
		return fmt.Errorf("normalize source=%s: %w", raw.Source, err)
	}

	if err := writeEvents(writer, events); err != nil {
		return fmt.Errorf("write normalized events: %w", err)
	}
	return nil
}

func writeEvents(writer *jsonl.Writer, events []model.Event) error {
	for _, ev := range events {
		if err := writer.WriteEvent(ev); err != nil {
			return err
		}
	}
	return nil
}
