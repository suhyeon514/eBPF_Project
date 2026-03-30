package conntrack

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/suhyeon514/eBPF_Project/internal/model"
)

type Config struct {
	Args          []string
	RestartOnExit bool
	RestartDelay  time.Duration
}

type Collector struct {
	cfg Config

	events chan model.RawEnvelope
	errors chan error

	// 에이전트 통합을 위한 생명주기 관리 필드 (auditd와 동일)
	mu      sync.Mutex
	started bool
	cancel  context.CancelFunc
	done    chan struct{}
}

func New(cfg Config) *Collector {
	if cfg.RestartDelay <= 0 {
		cfg.RestartDelay = 5 * time.Second
	}
	return &Collector{
		cfg:    cfg,
		events: make(chan model.RawEnvelope, 128),
		errors: make(chan error, 32),
		done:   make(chan struct{}), // 종료 신호용 채널
	}
}

func (c *Collector) Name() string {
	return "conntrack"
}

func (c *Collector) Events() <-chan model.RawEnvelope {
	return c.events
}

func (c *Collector) Errors() <-chan error {
	return c.errors
}

// Start: 에이전트에서 수집기를 안전하게 시작합니다.
func (c *Collector) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.started {
		return fmt.Errorf("conntrack collector already started")
	}

	runCtx, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	c.started = true

	go c.run(runCtx)
	return nil
}

// Stop: 에이전트에서 수집기를 안전하게 종료합니다. (고루틴 누수 방지)
func (c *Collector) Stop(_ context.Context) error {
	c.mu.Lock()
	if !c.started {
		c.mu.Unlock()
		return nil
	}
	cancel := c.cancel
	c.mu.Unlock()

	// 1. Context 취소 신호 전송 (exec.CommandContext가 이 신호를 받고 프로세스를 종료함)
	if cancel != nil {
		cancel()
	}

	// 2. run() 고루틴이 완전히 끝날 때까지 대기
	<-c.done

	c.mu.Lock()
	c.started = false
	c.mu.Unlock()

	return nil
}

// run: 백그라운드에서 동작하며 Restart 로직 및 자원 정리를 담당합니다.
func (c *Collector) run(ctx context.Context) {
	// 함수 종료 시 Stop()에서 대기 중인 채널을 닫아 종료 완료를 알림
	defer close(c.done)

	for {
		c.executeConntrack(ctx)

		// RestartOnExit 설정이 꺼져 있거나, 외부에서 취소 신호가 왔다면 루프 탈출
		if !c.cfg.RestartOnExit || ctx.Err() != nil {
			return
		}

		// 재시작 딜레이 대기 (대기 중 취소 신호가 오면 즉시 종료)
		select {
		case <-ctx.Done():
			return
		case <-time.After(c.cfg.RestartDelay):
			// 딜레이 후 다시 루프의 처음으로 돌아가 executeConntrack 실행
		}
	}
}

// executeConntrack: 실제 conntrack 프로세스를 실행하고 로그를 읽어옵니다.
func (c *Collector) executeConntrack(ctx context.Context) {
	cmd := exec.CommandContext(ctx, "conntrack", c.cfg.Args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		c.pushError(fmt.Errorf("conntrack stdout pipe: %w", err))
		return
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		c.pushError(fmt.Errorf("conntrack stderr pipe: %w", err))
		return
	}

	if err := cmd.Start(); err != nil {
		c.pushError(fmt.Errorf("start conntrack command: %w", err))
		return
	}

	go c.readCommandStderr(stderr)

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		rawType := detectConntrackRawType(line)
		raw := model.NewRawEnvelope(
			model.RawSourceConntrack,
			rawType,
			map[string]any{
				"line": line,
			},
		)

		// 이벤트 전송 중 취소 신호 확인
		if !c.pushEvent(ctx, raw) {
			return
		}
	}

	if err := scanner.Err(); err != nil && ctx.Err() == nil {
		c.pushError(fmt.Errorf("scan conntrack output: %w", err))
	}

	if err := cmd.Wait(); err != nil && ctx.Err() == nil {
		c.pushError(fmt.Errorf("conntrack command exited: %w", err))
	}
}

func (c *Collector) readCommandStderr(stderr io.Reader) {
	scanner := bufio.NewScanner(stderr)
	for scanner.Scan() {
		line := scanner.Text()
		fmt.Printf("[conntrack stderr] %s\n", line)
	}
}

func detectConntrackRawType(line string) string {
	upper := strings.ToUpper(line)

	switch {
	case strings.Contains(upper, "[NEW]"):
		return "conntrack_new"
	case strings.Contains(upper, "[UPDATE]"):
		return "conntrack_update"
	case strings.Contains(upper, "[DESTROY]"):
		return "conntrack_destroy"
	default:
		return "conntrack_event"
	}
}

// -----------------------------------------------------------------------------
// 유틸리티 함수 (auditd 구조와 동일하게 통합)
// -----------------------------------------------------------------------------

func (c *Collector) pushEvent(ctx context.Context, raw model.RawEnvelope) bool {
	select {
	case c.events <- raw:
		return true
	case <-ctx.Done():
		return false // 컨텍스트가 종료되면 false를 반환하여 안전하게 루프 탈출
	}
}

func (c *Collector) pushError(err error) {
	select {
	case c.errors <- err:
	default:
		// 에러 채널이 꽉 차 있으면(Blocking) 무시하여 메인 수집 루프가 멈추지 않도록 함
	}
}
