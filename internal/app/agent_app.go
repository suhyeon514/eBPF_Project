package app

import (
	"context"
	"fmt"

	auditdcollector "github.com/suhyeon514/eBPF_Project/internal/collector/auditd"
	conntrackcollector "github.com/suhyeon514/eBPF_Project/internal/collector/conntrack"
	healthcollector "github.com/suhyeon514/eBPF_Project/internal/collector/health"
	journaldcollector "github.com/suhyeon514/eBPF_Project/internal/collector/journald"
	nftablescollector "github.com/suhyeon514/eBPF_Project/internal/collector/nftables"
	nginxcollector "github.com/suhyeon514/eBPF_Project/internal/collector/nginx"
	tetragoncollector "github.com/suhyeon514/eBPF_Project/internal/collector/tetragon"
	"github.com/suhyeon514/eBPF_Project/internal/config"
	"github.com/suhyeon514/eBPF_Project/internal/health"
	"github.com/suhyeon514/eBPF_Project/internal/model"
	"github.com/suhyeon514/eBPF_Project/internal/normalize"
	auditdnormalizer "github.com/suhyeon514/eBPF_Project/internal/normalize/auditd"
	conntracknormalizer "github.com/suhyeon514/eBPF_Project/internal/normalize/conntrack"
	healthnormalizer "github.com/suhyeon514/eBPF_Project/internal/normalize/health"
	journaldnormalizer "github.com/suhyeon514/eBPF_Project/internal/normalize/journald"
	nftablesnormalizer "github.com/suhyeon514/eBPF_Project/internal/normalize/nftables"
	nginxnormalizer "github.com/suhyeon514/eBPF_Project/internal/normalize/nginx"
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

	// 1. Health Registry 생성
	reg := health.NewRegistry()

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

	// 단일 Normalizer 생성
	router.Register(model.RawSourceHealth, healthnormalizer.New(host))
	router.Register(model.RawSourceTetragon, tetragonnormalizer.New(host))
	router.Register(model.RawSourceJournald, journaldnormalizer.New(host))
	router.Register(model.RawSourceAuditd, auditdnormalizer.New(host))
	router.Register(model.RawSourceConntrack, conntracknormalizer.New(host)) // conntrack에 등록
	router.Register(model.RawSourceNFTables, nftablesnormalizer.New(host))   // nftables에 동일 Normalizer 등록
	router.Register(model.RawSourceNginx, nginxnormalizer.New(host))

	tetragonCollector := tetragoncollector.New(tetragoncollector.Config{
		LogPath:      a.cfg.Tetragon.LogPath,
		PollInterval: a.cfg.Tetragon.PollInterval,
		ReadFromHead: a.cfg.Tetragon.ReadFromHead,
		EventsBuffer: 128,
		ErrorsBuffer: 32,
	})

	var journaldCollector *journaldcollector.Collector
	if a.cfg.Journald.Enabled {
		journaldCollector = journaldcollector.New(journaldcollector.Config{
			Profiles:     a.cfg.Journald.Profiles,
			EventsBuffer: 128,
			ErrorsBuffer: 32,
			TailLines:    0,
		})
	}

	var auditdCollector *auditdcollector.Collector
	if a.cfg.Auditd.Enabled {
		auditdCollector = auditdcollector.New(auditdcollector.Config{
			LogPath:      a.cfg.Auditd.LogPath,
			PollInterval: a.cfg.Auditd.PollInterval,
			ReadFromHead: a.cfg.Auditd.ReadFromHead,
			EventsBuffer: 128,
			ErrorsBuffer: 32,
		})
	}

	var conntrackCollector *conntrackcollector.Collector
	if a.cfg.Conntrack.Enabled {
		// 💡 수정 1: 실제 conntrack Config 구조체에 맞게 초기화
		conntrackCollector = conntrackcollector.New(conntrackcollector.Config{
			Args:          a.cfg.Conntrack.Args,
			RestartOnExit: a.cfg.Conntrack.RestartOnExit,
			RestartDelay:  a.cfg.Conntrack.RestartDelay,
		})
	}

	var nftablesCollector *nftablescollector.Collector
	if a.cfg.Nftables.Enabled {
		nftablesCollector = nftablescollector.New(nftablescollector.Config{
			LogPath:      a.cfg.Nftables.LogPath,
			PollInterval: a.cfg.Nftables.PollInterval,
			ReadFromHead: a.cfg.Nftables.ReadFromHead,
			Prefixes:     a.cfg.Nftables.Prefixes,
		})
	}
	var nginxCollector *nginxcollector.Collector
	if a.cfg.Nginx.Enabled {
		nginxCollector = nginxcollector.New(nginxcollector.Config{
			LogPath: a.cfg.Nginx.LogPath,
		})
	}

	if err := tetragonCollector.Start(ctx); err != nil {
		return fmt.Errorf("start tetragon collector: %w", err)
	}
	defer tetragonCollector.Stop(context.Background())

	// 🔥 4. Health Collector 시작
	healthChan := make(chan model.RawEnvelope, 16)
	healthcollector.Start(reg, healthChan)

	if journaldCollector != nil {
		if err := journaldCollector.Start(ctx); err != nil {
			return fmt.Errorf("start journald collector: %w", err)
		}
		defer journaldCollector.Stop(context.Background())
	}

	if auditdCollector != nil {
		if err := auditdCollector.Start(ctx); err != nil {
			return fmt.Errorf("start auditd collector: %w", err)
		}
		defer auditdCollector.Stop(context.Background())
	}

	if conntrackCollector != nil {
		if err := conntrackCollector.Start(ctx); err != nil {
			return fmt.Errorf("start conntrack collector: %w", err)
		}
		defer conntrackCollector.Stop(context.Background())
	}

	if nftablesCollector != nil {
		if err := nftablesCollector.Start(ctx); err != nil {
			return fmt.Errorf("start nftables collector: %w", err)
		}
		defer nftablesCollector.Stop(context.Background())
	}

	if nginxCollector != nil {
		if err := nginxCollector.Start(ctx); err != nil {
			return fmt.Errorf("start nginx collector: %w", err)
		}
		defer nginxCollector.Stop(context.Background())
	}

	tetragonEvents := tetragonCollector.Events()
	tetragonErrors := tetragonCollector.Errors()

	var journaldEvents <-chan model.RawEnvelope
	var journaldErrors <-chan error
	if journaldCollector != nil {
		journaldEvents = journaldCollector.Events()
		journaldErrors = journaldCollector.Errors()
	}

	var auditdEvents <-chan model.RawEnvelope
	var auditdErrors <-chan error
	if auditdCollector != nil {
		auditdEvents = auditdCollector.Events()
		auditdErrors = auditdCollector.Errors()
	}

	var conntrackEvents <-chan model.RawEnvelope
	var conntrackErrors <-chan error
	if conntrackCollector != nil {
		conntrackEvents = conntrackCollector.Events()
		conntrackErrors = conntrackCollector.Errors()
	}

	var nftablesEvents <-chan model.RawEnvelope
	var nftablesErrors <-chan error
	if nftablesCollector != nil {
		nftablesEvents = nftablesCollector.Events()
		nftablesErrors = nftablesCollector.Errors()
	}

	var nginxEvents <-chan model.RawEnvelope
	var nginxErrors <-chan error
	if nginxCollector != nil {
		nginxEvents = nginxCollector.Events()
		nginxErrors = nginxCollector.Errors()
	}

	for {
		if tetragonEvents == nil && tetragonErrors == nil &&
			journaldEvents == nil && journaldErrors == nil &&
			auditdEvents == nil && auditdErrors == nil &&
			conntrackEvents == nil && conntrackErrors == nil &&
			nftablesEvents == nil && nftablesErrors == nil &&
			nginxEvents == nil && nginxErrors == nil {
			if err := writer.Sync(); err != nil {
				return fmt.Errorf("sync writer: %w", err)
			}
			return nil
		}

		select {

		// 🔥 Health 이벤트
		case raw := <-healthChan:
			reg.MarkCollectorOK(string(model.RawSourceHealth)) // 헬스 체크용 상태 업데이트
			if err := a.handleRawEvent(ctx, writer, router, raw, reg); err != nil {
				return err
			}

		case raw, ok := <-tetragonEvents:
			if !ok {
				tetragonEvents = nil
				continue
			}

			// reg.MarkCollectorOK() // 헬스 체크용 상태 업데이트
			reg.MarkCollectorOK(string(model.RawSourceTetragon))

			if err := a.handleRawEvent(ctx, writer, router, raw, reg); err != nil {
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

			reg.MarkCollectorOK(string(model.RawSourceJournald)) // 헬스 체크용 상태 업데이트

			if err := a.handleRawEvent(ctx, writer, router, raw, reg); err != nil {
				return fmt.Errorf("handle journald raw event: %w", err)
			}

		case err, ok := <-journaldErrors:
			if !ok {
				journaldErrors = nil
				continue
			}
			fmt.Printf("collector=journald] error=%v\n", err)

		case raw, ok := <-auditdEvents:
			if !ok {
				auditdEvents = nil
				continue
			}
			reg.MarkCollectorOK(string(model.RawSourceAuditd)) // 헬스 체크용 상태 업데이트

			if err := a.handleRawEvent(ctx, writer, router, raw, reg); err != nil {
				return fmt.Errorf("handle auditd raw event: %w", err)
			}

		case err, ok := <-auditdErrors:
			if !ok {
				auditdErrors = nil
				continue
			}
			fmt.Printf("collector=auditd] error=%v\n", err)

		case raw, ok := <-conntrackEvents:
			if !ok {
				conntrackEvents = nil
				continue
			}

			reg.MarkCollectorOK(string(model.RawSourceConntrack)) // 헬스 체크용 상태 업데이트

			if err := a.handleRawEvent(ctx, writer, router, raw, reg); err != nil {
				return fmt.Errorf("handle conntrack raw event: %w", err)
			}

		case err, ok := <-conntrackErrors:
			if !ok {
				conntrackErrors = nil
				continue
			}
			fmt.Printf("[collector=conntrack] error=%v\n", err)

		case raw, ok := <-nftablesEvents:
			if !ok {
				nftablesEvents = nil
				continue
			}

			reg.MarkCollectorOK(string(model.RawSourceNFTables)) // 헬스 체크용 상태 업데이트

			if err := a.handleRawEvent(ctx, writer, router, raw, reg); err != nil {
				return fmt.Errorf("handle nftables raw event: %w", err)
			}

		case err, ok := <-nftablesErrors:
			if !ok {
				nftablesErrors = nil
				continue
			}
			fmt.Printf("[collector=nftables] error=%v\n", err)

		case raw, ok := <-nginxEvents:
			if !ok {
				nginxEvents = nil
				continue
			}
			fmt.Println("🔥 nginx RAW 들어옴")                    // 디버깅용
			reg.MarkCollectorOK(string(model.RawSourceNginx)) // 헬스 체크용 상태 업데이트
			if err := a.handleRawEvent(ctx, writer, router, raw, reg); err != nil {
				return fmt.Errorf("handle nginx raw event: %w", err)
			}

		case err, ok := <-nginxErrors:
			if !ok {
				nginxErrors = nil
				continue
			}
			fmt.Printf("[collector=nginx] error=%v\n", err)
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
	reg *health.Registry,
) error {
	events, err := router.Normalize(ctx, raw)
	if err != nil {
		reg.IncDrop()
		return fmt.Errorf("normalize source=%s: %w", raw.Source, err)
	}

	reg.MarkNormalizeOK()

	for i := range events {
		events[i].RouteTopic = routeTopic(events[i])
	}

	if err := writeEvents(writer, events); err != nil {
		reg.IncDrop()
		return fmt.Errorf("write normalized events: %w", err)
	}
	reg.MarkOutputOK()
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
