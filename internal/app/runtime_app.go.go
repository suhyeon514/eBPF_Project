package app

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/suhyeon514/eBPF_Project/internal/collector"
	auditdcollector "github.com/suhyeon514/eBPF_Project/internal/collector/auditd"
	conntrackcollector "github.com/suhyeon514/eBPF_Project/internal/collector/conntrack"
	healthcollector "github.com/suhyeon514/eBPF_Project/internal/collector/health"
	journaldcollector "github.com/suhyeon514/eBPF_Project/internal/collector/journald"
	nftablescollector "github.com/suhyeon514/eBPF_Project/internal/collector/nftables"
	nginxcollector "github.com/suhyeon514/eBPF_Project/internal/collector/nginx"
	resourcecollector "github.com/suhyeon514/eBPF_Project/internal/collector/resource"
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
	resourcenormalizer "github.com/suhyeon514/eBPF_Project/internal/normalize/resource"
	tetragonnormalizer "github.com/suhyeon514/eBPF_Project/internal/normalize/tetragon"
	"github.com/suhyeon514/eBPF_Project/internal/output/jsonl"
	"github.com/suhyeon514/eBPF_Project/internal/service/policy"
	"github.com/suhyeon514/eBPF_Project/internal/transport/api"
	websocket "github.com/suhyeon514/eBPF_Project/internal/transport/websocket"
)

type RuntimeDeps struct {
	// bootstrap / state 에서 넘어오는 런타임 의존성
	ServerBaseURL    string
	ServerCACertPath string

	ClientCertPath string
	ClientKeyPath  string

	PolicyPath string

	AgentID string
	HostID  string
	Env     string
	Role    string

	HeartbeatPath string
	InstallUUID   string
}

func NewRuntimeDeps(
	bootstrapCfg *config.BootstrapConfig,
	bootstrapResult *BootstrapResult,
) RuntimeDeps {
	return RuntimeDeps{
		ServerBaseURL:    bootstrapCfg.Server.BaseURL,
		ServerCACertPath: bootstrapCfg.Server.CACertPath,
		ClientCertPath:   bootstrapCfg.Paths.CertificatePath,
		ClientKeyPath:    bootstrapCfg.Paths.PrivateKeyPath,
		PolicyPath:       bootstrapCfg.Paths.PolicyPath,
		AgentID:          bootstrapResult.AgentID,
		HostID:           bootstrapCfg.Identity.HostID,
		Env:              bootstrapCfg.Identity.Env,
		Role:             bootstrapCfg.Identity.Role,
		HeartbeatPath:    bootstrapCfg.Server.HeartbeatPath,
		InstallUUID:      bootstrapResult.InstallUUID,
	}
}

type RuntimeApp struct {
	cfg  *config.RuntimeConfig
	deps RuntimeDeps

	policyService *policy.Service
}

func NewRuntimeApp(cfg *config.RuntimeConfig, deps RuntimeDeps) *RuntimeApp {
	apiClient := api.NewClient(deps.ServerBaseURL, 5*time.Second)
	policySvc := policy.NewService(apiClient, deps.PolicyPath)
	return &RuntimeApp{
		cfg:  cfg,
		deps: deps,

		policyService: policySvc,
	}
}

func (a *RuntimeApp) Run(ctx context.Context) error {

	// 1. Health Registry 생성
	reg := health.NewRegistry()

	writer, err := jsonl.New(a.cfg.Output.NormalizedPath)
	if err != nil {
		return fmt.Errorf("create jsonl writer: %w", err)
	}
	defer writer.Close()

	host := a.buildHostMeta()
	router := a.buildRouter(host)

	collectors, err := a.buildCollectors()
	if err != nil {
		return fmt.Errorf("build collectors: %w", err)
	}

	if len(collectors) == 0 {
		return fmt.Errorf("no collectors enabled")
	}

	if err := a.startCollectors(ctx, collectors); err != nil {
		return fmt.Errorf("start collectors: %w", err)
	}
	defer a.stopCollectors(collectors)

	// Health Collector 시작
	healthChan := make(chan model.RawEnvelope, 16)
	healthcollector.Start(reg, healthChan)

	// =========================================================================
	// [추가] WebSocket 및 AVML(Forensic) 리스너 백그라운드 실행
	// =========================================================================
	log.Printf("🚀 [WebSocket] AVML 포렌식 리스너 시작 (Target: %s) (덤프 경로: %s)", a.deps.ServerBaseURL, a.cfg.Forensic.DumpPath)
	// agentID := a.deps.AgentID // 현재 에이전트 ID 하드코딩, 인증 로직 생성된 후에는 a.deps.AgentID로 변경 필요
	agentID := "host-lab-001"
	// go websocket.StartWebSocketListener(wsBaseURL, agentID, dumpPath)
	go websocket.StartWebSocketListener(a.deps.ServerBaseURL, agentID, a.cfg.Forensic.DumpPath)

	// 메인 루프 진입 전, 주기적 정책 확인을 위한 타이머 생성 (예: 30초)
	policyTicker := time.NewTicker(30 * time.Second)
	defer policyTicker.Stop()
	log.Println("⏱️  [정책 업데이트 타이머 시작] ")

	events := fanInEvents(collectors...)
	errors := fanInErrors(collectors...)

	for {
		select {
		case raw, ok := <-events:
			if !ok {
				if err := writer.Sync(); err != nil {
					return fmt.Errorf("sync writer: %w", err)
				}
				return nil
			}

			if err := a.handleRawEvent(ctx, writer, router, raw, reg); err != nil {
				return fmt.Errorf("handle raw event: %w", err)
			}

		case err, ok := <-errors:
			if ok && err != nil {
				log.Printf("[runtime] collector error: %v", err)
			}

		case <-policyTicker.C:
			log.Println("[정책 업데이트 여부 확인] 주기적 정책 업데이트 확인 타이머 동작")
			if err := a.runPolicyCheck(ctx); err != nil {
				log.Printf("[runtime] policy check failed: %v", err)
			}

		case <-ctx.Done():
			if err := writer.Sync(); err != nil {
				return fmt.Errorf("sync writer: %w", err)
			}
			return nil
		}
	}
}

func (a *RuntimeApp) buildHostMeta() model.HostMeta {
	return model.HostMeta{
		HostID:   a.deps.HostID,
		Hostname: a.cfg.Host.Hostname,
		Env:      a.deps.Env,
		Role:     a.deps.Role,
	}
}

func (a *RuntimeApp) buildRouter(host model.HostMeta) *normalize.Router {
	router := normalize.NewRouter()

	router.Register(model.RawSourceHealth, healthnormalizer.New(host))
	router.Register(model.RawSourceTetragon, tetragonnormalizer.New(host))
	router.Register(model.RawSourceJournald, journaldnormalizer.New(host))
	router.Register(model.RawSourceAuditd, auditdnormalizer.New(host))
	router.Register(model.RawSourceConntrack, conntracknormalizer.New(host))
	router.Register(model.RawSourceNFTables, nftablesnormalizer.New(host))
	router.Register(model.RawSourceNginx, nginxnormalizer.New(host))
	router.Register(model.RawSourceResource, resourcenormalizer.New(host))

	return router
}

func (a *RuntimeApp) buildCollectors() ([]collector.Collector, error) {
	var collectors []collector.Collector

	if a.cfg.Collectors.Tetragon.Enabled {
		collectors = append(collectors, tetragoncollector.New(tetragoncollector.Config{
			LogPath:      a.cfg.Collectors.Tetragon.LogPath,
			PollInterval: a.cfg.Collectors.Tetragon.PollInterval,
			ReadFromHead: a.cfg.Collectors.Tetragon.ReadFromHead,
			EventsBuffer: 128,
			ErrorsBuffer: 32,
		}))
	}

	if a.cfg.Collectors.Journald.Enabled {
		collectors = append(collectors, journaldcollector.New(journaldcollector.Config{
			Profiles:     a.cfg.Collectors.Journald.Profiles,
			EventsBuffer: 128,
			ErrorsBuffer: 32,
			TailLines:    a.cfg.Collectors.Journald.TailLines,
		}))
	}

	if a.cfg.Collectors.Auditd.Enabled {
		collectors = append(collectors, auditdcollector.New(auditdcollector.Config{
			LogPath:      a.cfg.Collectors.Auditd.LogPath,
			PollInterval: a.cfg.Collectors.Auditd.PollInterval,
			ReadFromHead: a.cfg.Collectors.Auditd.ReadFromHead,
			EventsBuffer: 128,
			ErrorsBuffer: 32,
		}))
	}

	if a.cfg.Collectors.Conntrack.Enabled {
		collectors = append(collectors, conntrackcollector.New(conntrackcollector.Config{
			Args:          a.cfg.Collectors.Conntrack.Args,
			RestartOnExit: a.cfg.Collectors.Conntrack.RestartOnExit,
			RestartDelay:  a.cfg.Collectors.Conntrack.RestartDelay,
		}))
	}

	if a.cfg.Collectors.Nftables.Enabled {
		collectors = append(collectors, nftablescollector.New(nftablescollector.Config{
			LogPath:      a.cfg.Collectors.Nftables.LogPath,
			PollInterval: a.cfg.Collectors.Nftables.PollInterval,
			ReadFromHead: a.cfg.Collectors.Nftables.ReadFromHead,
			Prefixes:     a.cfg.Collectors.Nftables.Prefixes,
			EventsBuffer: 128,
			ErrorsBuffer: 32,
		}))
	}

	if a.cfg.Collectors.Nginx.Enabled {
		collectors = append(collectors, nginxcollector.New(nginxcollector.Config{
			LogPath:      a.cfg.Collectors.Nginx.LogPath,
			EventsBuffer: 128,
			ErrorsBuffer: 32,
		}))
	}

	collectors = append(collectors, resourcecollector.New(resourcecollector.Config{
		Interval: a.cfg.Collectors.Resource.PollInterval,
	}))

	return collectors, nil
}

func (a *RuntimeApp) startCollectors(ctx context.Context, collectors []collector.Collector) error {
	for _, c := range collectors {
		if err := c.Start(ctx); err != nil {
			return fmt.Errorf("start collector %q: %w", c.Name(), err)
		}
		log.Printf("[runtime] collector started: %s", c.Name())
	}
	return nil
}

func (a *RuntimeApp) stopCollectors(collectors []collector.Collector) {
	for _, c := range collectors {
		if err := c.Stop(context.Background()); err != nil {
			log.Printf("[runtime] stop collector %q: %v", c.Name(), err)
			continue
		}
		log.Printf("[runtime] collector stopped: %s", c.Name())
	}
}

func (a *RuntimeApp) handleRawEvent(
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

func fanInEvents(cs ...collector.Collector) <-chan model.RawEnvelope {
	out := make(chan model.RawEnvelope)

	go func() {
		defer close(out)

		type eventItem struct {
			ev model.RawEnvelope
			ok bool
		}

		merged := make(chan eventItem)

		for _, c := range cs {
			events := c.Events()

			go func(ch <-chan model.RawEnvelope) {
				for ev := range ch {
					merged <- eventItem{ev: ev, ok: true}
				}
				merged <- eventItem{ok: false}
			}(events)
		}

		closedCount := 0
		for {
			item := <-merged
			if !item.ok {
				closedCount++
				if closedCount == len(cs) {
					return
				}
				continue
			}
			out <- item.ev
		}
	}()

	return out
}

func fanInErrors(cs ...collector.Collector) <-chan error {
	out := make(chan error)

	go func() {
		defer close(out)

		type errorItem struct {
			err error
			ok  bool
		}

		merged := make(chan errorItem)

		for _, c := range cs {
			errs := c.Errors()

			go func(ch <-chan error) {
				for err := range ch {
					merged <- errorItem{err: err, ok: true}
				}
				merged <- errorItem{ok: false}
			}(errs)
		}

		closedCount := 0
		for {
			item := <-merged
			if !item.ok {
				closedCount++
				if closedCount == len(cs) {
					return
				}
				continue
			}
			out <- item.err
		}
	}()

	return out
}

// 🔥 [추가] 정책 검사 실행 및 eBPF 리로드 처리 헬퍼 함수
func (a *RuntimeApp) runPolicyCheck(ctx context.Context) error {
	// 만들어두신 CheckAndSync 로직 호출
	updated, err := a.policyService.CheckAndSync()
	if err != nil {
		log.Printf("❌ 정책 동기화 통신 실패: %v\n", err)
		return err
	}

	// 서버에서 새 정책을 받아 로컬 파일 덮어쓰기가 완료되었다면 (updated == true)
	if updated {
		log.Println("🔄 새로운 정책이 감지되어 로컬에 파일 덮어쓰기 완료.")

		// TODO: Tetragon 등 eBPF 수집기 쪽에 "설정 다시 읽어와라"라고 명령하는 함수를 호출합니다.
		// 예: a.tetragonCollector.Reload()
	} else {
		log.Println("✅ 정책 변경 사항 없음.")
	}

	return nil
}
