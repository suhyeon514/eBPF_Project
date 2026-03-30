package nginx

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/nxadm/tail"
	"github.com/suhyeon514/eBPF_Project/internal/model"
)

type Config struct {
	LogPath      string
	EventsBuffer int
	ErrorsBuffer int
}

type Collector struct {
	cfg     Config
	events  chan model.RawEnvelope
	errors  chan error
	mu      sync.Mutex
	started bool
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

func New(cfg Config) *Collector {
	if cfg.EventsBuffer <= 0 {
		cfg.EventsBuffer = 128
	}
	if cfg.ErrorsBuffer <= 0 {
		cfg.ErrorsBuffer = 32
	}

	return &Collector{
		cfg:    cfg,
		events: make(chan model.RawEnvelope, cfg.EventsBuffer),
		errors: make(chan error, cfg.ErrorsBuffer),
	}
}

// =========================
// 인터페이스 구현
// =========================
func (c *Collector) Name() string { return "nginx" }

func (c *Collector) Events() <-chan model.RawEnvelope { return c.events }

func (c *Collector) Errors() <-chan error { return c.errors }

// =========================
// 시작 / 종료
// =========================
func (c *Collector) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.started {
		return fmt.Errorf("nginx collector already started")
	}

	if strings.TrimSpace(c.cfg.LogPath) == "" {
		return fmt.Errorf("nginx log path is empty")
	}

	streamCtx, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	c.started = true
	c.wg.Add(1)

	go c.runTail(streamCtx)

	fmt.Println("nginx collector started")

	return nil
}

func (c *Collector) Stop(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.started {
		return nil
	}

	c.cancel()
	c.wg.Wait()
	c.started = false

	fmt.Println("nginx collector stopped")

	return nil
}

// =========================
// 핵심 로직 (tail)
// =========================
func (c *Collector) runTail(ctx context.Context) {
	defer c.wg.Done()

	t, err := tail.TailFile(c.cfg.LogPath, tail.Config{
		Follow:    true,
		ReOpen:    true,
		MustExist: true, // 🔥 파일 없으면 바로 에러
		Location:  &tail.SeekInfo{Offset: 0, Whence: 2}, // 끝부터 시작
	})
	if err != nil {
		c.pushError(fmt.Errorf("nginx tail error: %w", err))
		return
	}
	defer t.Cleanup()

	for {
		select {
		case <-ctx.Done():
			t.Stop()
			return

		case line, ok := <-t.Lines:
			if !ok {
				continue
			}

			if line.Err != nil {
				c.pushError(fmt.Errorf("nginx line error: %w", line.Err))
				continue
			}

			// 🔥 공백 제거
			text := strings.TrimSpace(line.Text)
			if text == "" {
				continue
			}

			// 🔥 표준화된 RawEnvelope
			raw := model.NewRawEnvelope(
				model.RawSourceNginx, // 🔥 중요 (router 연결용)
				"access",             // 🔥 확장 고려
				model.RawJSON{
					Data: []byte(text),
				},
			)

			if !c.pushEvent(ctx, raw) {
				return
			}
		}
	}
}

// =========================
// 채널 처리
// =========================
func (c *Collector) pushEvent(ctx context.Context, raw model.RawEnvelope) bool {
	select {
	case <-ctx.Done():
		return false
	case c.events <- raw:
		return true
	}
}

func (c *Collector) pushError(err error) {
	select {
	case c.errors <- err:
	default:
	}
}
