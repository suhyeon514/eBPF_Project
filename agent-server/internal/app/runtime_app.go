package app

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/suhyeon514/eBPF_Project/internal/config"
	"github.com/suhyeon514/eBPF_Project/internal/model"
	"github.com/suhyeon514/eBPF_Project/internal/output/jsonl"
	"github.com/suhyeon514/eBPF_Project/internal/service/policy"
	"github.com/suhyeon514/eBPF_Project/internal/transport/api"
	websocket "github.com/suhyeon514/eBPF_Project/internal/transport/websocket"
)

type RuntimeDeps struct {
	ServerBaseURL string
	PolicyPath    string
	AgentID       string
}

func NewRuntimeDeps(
	bootstrapCfg *config.BootstrapConfig,
	bootstrapResult *BootstrapResult,
) RuntimeDeps {
	return RuntimeDeps{
		ServerBaseURL: bootstrapCfg.Server.BaseURL,
		PolicyPath:    bootstrapCfg.Paths.PolicyPath,
		AgentID:       bootstrapResult.AgentID,
	}
}

type RuntimeApp struct {
	cfg  *config.RuntimeConfig
	deps RuntimeDeps

	policyService *policy.Service
}

func NewRuntimeApp(cfg *config.RuntimeConfig, deps RuntimeDeps) *RuntimeApp {
	apiClient := api.NewClient(deps.ServerBaseURL, 5*time.Second)
	fullPolicyURL := deps.ServerBaseURL + deps.PolicyPath

	policySvc := policy.NewService(apiClient, fullPolicyURL)

	return &RuntimeApp{
		cfg:           cfg,
		deps:          deps,
		policyService: policySvc,
	}
}

// 🔥 시나리오 버퍼
var eventBuffer = struct {
	mu   sync.Mutex
	data map[string][]model.Event
}{
	data: make(map[string][]model.Event),
}

func (a *RuntimeApp) Run(ctx context.Context) error {

	writer, err := jsonl.New(a.cfg.Output.NormalizedPath)
	if err != nil {
		return fmt.Errorf("create jsonl writer: %w", err)
	}
	defer writer.Close()

	log.Println("🚀 runtime started")

	// WebSocket
	go websocket.StartWebSocketListener(a.deps.ServerBaseURL, "agent", "./dump")

	// 초기 정책 동기화
	log.Println("🔥 INITIAL POLICY SYNC")
	a.runPolicyCheck(ctx)

	policyTicker := time.NewTicker(30 * time.Second)
	defer policyTicker.Stop()

	events, err := jsonlReplay("testdata/normalized.jsonl")
	if err != nil {
		return err
	}

	for {
		select {

		case ev, ok := <-events:
			if !ok {
				log.Println("🎯 replay finished → 🔥 injecting test event")

				// 🔥 bash 이벤트로 변경 (위험도 정상 나오게)
				ev = model.Event{
					EventType: model.EventProcessExec,
					Process: &model.ProcessMeta{
						Comm: "bash",
						UID:  0,
					},
				}

				// 🔥 무한루프 방지
				time.Sleep(3 * time.Second)
			}

			log.Println("📥 EVENT RECEIVED")

			// 🔥 정책 평가
			denied, focused := policy.Evaluate(ev)

			log.Println("📌 RULE CHECK START")

			if ev.Process != nil {
				log.Println("➡️ PROCESS:", ev.Process.Comm)
			}
			if ev.File != nil {
				log.Println("➡️ FILE:", ev.File.Path)
			}

			log.Println("🚨 RESULT:",
				"DENIED=", denied,
				"FOCUSED=", focused,
			)

			// 🔥 차단
			if denied && ev.Process != nil {
				log.Println("⛔ BLOCK:", ev.Process.Comm)
				go exec.Command("pkill", "-f", ev.Process.Comm).Run()
			}

			// 🔥 Base Score
			base := policy.EvaluateBase(ev)

			// 🔥 Risk 계산
			score, severity := policy.CalculateRisk(ev, base.Score, "")

			// 🔥 Scenario 분석
			eventBuffer.mu.Lock()
			buf := eventBuffer.data["global"]
			buf = append(buf, ev)
			if len(buf) > 10 {
				buf = buf[len(buf)-10:]
			}
			eventBuffer.data["global"] = buf
			eventBuffer.mu.Unlock()

			bonus, patterns := policy.AnalyzeScenario(buf)

			finalScore := score + bonus

			log.Println("📊 RISK DETAIL:",
				"base=", base.Score,
				"rule=", base.Rule,
				"risk=", score,
				"final=", finalScore,
				"severity=", severity,
				"patterns=", patterns,
			)

			if err := writer.WriteEvent(ev); err != nil {
				log.Println("write error:", err)
			}

		case <-policyTicker.C:
			a.runPolicyCheck(ctx)
			log.Println("🔥 CURRENT RULES:", policy.GetRules())

		case <-ctx.Done():
			writer.Sync()
			return nil
		}
	}
}

// JSONL replay
func jsonlReplay(path string) (<-chan model.Event, error) {
	ch := make(chan model.Event)

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	go func() {
		defer f.Close()
		defer close(ch)

		scanner := bufio.NewScanner(f)

		for scanner.Scan() {
			var ev model.Event
			if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
				continue
			}
			ch <- ev
		}
	}()

	return ch, nil
}

// 정책 체크
func (a *RuntimeApp) runPolicyCheck(ctx context.Context) {

	updated, err := a.policyService.CheckAndSync()
	if err != nil {
		log.Println("❌ policy sync error:", err)
		return
	}

	if updated {
		log.Println("✅ policy updated")
	}
}
