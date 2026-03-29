package app

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
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

type RuntimeApp struct {
	cfg  *config.RuntimeConfig
	deps RuntimeDeps

	policyService *policy.Service

	// TODO:
	// 추후 allowlist / focus_list 정책 엔진 추가
	// policyEngine *policyengine.Engine
}

func NewRuntimeApp(cfg *config.RuntimeConfig, deps RuntimeDeps) *RuntimeApp {
	apiClient := api.NewClient(deps.ServerBaseURL, 5*time.Second)
	policySvc := policy.NewService(apiClient, deps.RuntimePolicyPath)
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

	// 변경: host/env/role은 state.json에서 로드
	hostID, hostname, assignedEnv, assignedRole, err := a.loadHostIdentityFromState()
	if err != nil {
		return fmt.Errorf("load host identity from state: %w", err)
	}
	a.deps.HostID = hostID
	if strings.TrimSpace(hostname) != "" {
		a.cfg.Host.Hostname = strings.TrimSpace(hostname)
	}
	if strings.TrimSpace(assignedEnv) != "" {
		a.deps.AssignedEnv = strings.TrimSpace(assignedEnv)
	}
	if strings.TrimSpace(assignedRole) != "" {
		a.deps.AssignedRole = strings.TrimSpace(assignedRole)
	}

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

	// go websocket.StartWebSocketListener(wsBaseURL, agentID, dumpPath)
	go websocket.StartWebSocketListener(a.deps.S3DumpInfo, a.deps.ServerBaseURL, a.deps.AgentID, a.cfg.Forensic.DumpPath)

	// 메인 루프 진입 전, 주기적 정책 확인을 위한 타이머 생성 (예: 30초)
	policyTicker := time.NewTicker(30 * time.Second)
	defer policyTicker.Stop()
	log.Println("⏱️  [정책 업데이트 타이머 시작] ")

	events := fanInEventsWithExtra(collectors, healthChan)
	errors := fanInErrors(collectors)

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
			if err := a.runPolicyCheckAndMaybeReload(ctx); err != nil {
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
		Env:      a.deps.AssignedEnv,
		Role:     a.deps.AssignedRole,
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
	reg.MarkNormalizeOK()

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

// fanInEventsWithExtra는 기존 collector events + 추가 채널(health 등)을 함께 합친다.
func fanInEventsWithExtra(
	collectors []collector.Collector,
	extra ...<-chan model.RawEnvelope,
) <-chan model.RawEnvelope {
	out := make(chan model.RawEnvelope)

	go func() {
		defer close(out)

		type source struct {
			ch <-chan model.RawEnvelope
		}

		var sources []source
		for _, c := range collectors {
			sources = append(sources, source{ch: c.Events()})
		}
		for _, ch := range extra {
			sources = append(sources, source{ch: ch})
		}

		open := len(sources)
		if open == 0 {
			return
		}

		closed := make([]bool, len(sources))

		for open > 0 {
			for i, src := range sources {
				if closed[i] {
					continue
				}

				select {
				case ev, ok := <-src.ch:
					if !ok {
						closed[i] = true
						open--
						continue
					}
					out <- ev
				default:
				}
			}

			time.Sleep(10 * time.Millisecond)
		}
	}()

	return out
}

func fanInErrors(collectors []collector.Collector) <-chan error {
	out := make(chan error)

	go func() {
		defer close(out)

		type source struct {
			ch <-chan error
		}

		var sources []source
		for _, c := range collectors {
			sources = append(sources, source{ch: c.Errors()})
		}

		open := len(sources)
		if open == 0 {
			return
		}

		closed := make([]bool, len(sources))

		for open > 0 {
			for i, src := range sources {
				if closed[i] {
					continue
				}

				select {
				case err, ok := <-src.ch:
					if !ok {
						closed[i] = true
						open--
						continue
					}
					out <- err
				default:
				}
			}

			time.Sleep(10 * time.Millisecond)
		}
	}()

	return out
}

// 🔥 [추가] 정책 검사 실행 및 eBPF 리로드 처리 헬퍼 함수
func (a *RuntimeApp) runPolicyCheckAndMaybeReload(ctx context.Context) error {
	// 만들어두신 CheckAndSync 로직 호출
	updated, err := a.policyService.CheckAndSync()
	if err != nil {
		log.Printf("❌ 정책 동기화 통신 실패: %v\n", err)
		return err
	}

	if !updated {
		return nil
	}

	log.Println("[runtime] policy updated on disk. reloading runtime config...")

	newCfg, err := config.LoadRuntime(a.deps.RuntimePolicyPath)
	if err != nil {
		return fmt.Errorf("reload runtime config: %w", err)
	}
	// TODO:
	// 1. allowlist / focus_list 정책 엔진 교체
	// 2. collector diff 계산 후 필요한 collector만 재구성/재시작
	//
	// 현재 1차 단계에서는 in-memory config만 교체
	a.cfg = newCfg

	log.Println("[runtime] runtime config reloaded successfully")
	return nil
}

// loadHostIdentityFromState는 state.json에서 host/env/role을 로드합니다.
func (a *RuntimeApp) loadHostIdentityFromState() (hostID, hostname, assignedEnv, assignedRole string, err error) {
	statePath := strings.TrimSpace(os.Getenv("EBPF_AGENT_STATE_PATH"))
	if statePath == "" {
		statePath = "/var/lib/ebpf-edr/state.json"
	}

	b, err := os.ReadFile(statePath)
	if err != nil {
		return "", "", "", "", fmt.Errorf("read state file (%s): %w", statePath, err)
	}

	var st runtimeStateSnapshot
	if err := json.Unmarshal(b, &st); err != nil {
		return "", "", "", "", fmt.Errorf("decode state file (%s): %w", statePath, err)
	}

	hostID = strings.TrimSpace(st.HostID)
	hostname = strings.TrimSpace(st.Hostname)
	assignedEnv = strings.TrimSpace(st.AssignedEnv)
	assignedRole = strings.TrimSpace(st.AssignedRole)

	if hostID == "" {
		return "", "", "", "", fmt.Errorf("state.host_id is empty")
	}
	if hostname == "" {
		if hn, e := os.Hostname(); e == nil {
			hostname = strings.TrimSpace(hn)
		}
	}

	return hostID, hostname, assignedEnv, assignedRole, nil
}

type runtimeStateSnapshot struct {
	HostID       string `json:"host_id"`
	Hostname     string `json:"hostname"`
	AssignedEnv  string `json:"assigned_env"`
	AssignedRole string `json:"assigned_role"`
	AgentID      string `json:"agent_id"`
}
