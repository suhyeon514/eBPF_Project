package nftables

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/suhyeon514/eBPF_Project/internal/model"
)

type Config struct {
	LogPath      string
	PollInterval time.Duration
	ReadFromHead bool
	Prefixes     []string // 필터링을 위한 접두사 (예: "NFT_DROP")
	EventsBuffer int
	ErrorsBuffer int
}

type Collector struct {
	cfg Config

	events chan model.RawEnvelope
	errors chan error

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
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = time.Second
	}

	return &Collector{
		cfg:    cfg,
		events: make(chan model.RawEnvelope, cfg.EventsBuffer),
		errors: make(chan error, cfg.ErrorsBuffer),
	}
}

func (c *Collector) Name() string {
	return "nftables"
}

func (c *Collector) Events() <-chan model.RawEnvelope {
	return c.events
}

func (c *Collector) Errors() <-chan error {
	return c.errors
}

func (c *Collector) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.started {
		return fmt.Errorf("nftables collector already started")
	}

	if strings.TrimSpace(c.cfg.LogPath) == "" {
		return fmt.Errorf("nftables log path is empty")
	}

	runCtx, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	c.started = true

	c.wg.Add(1)
	go c.run(runCtx)

	return nil
}

func (c *Collector) Stop(_ context.Context) error {
	c.mu.Lock()
	if !c.started {
		c.mu.Unlock()
		return nil
	}
	cancel := c.cancel
	c.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	c.wg.Wait()

	c.mu.Lock()
	c.started = false
	c.mu.Unlock()

	return nil
}

func (c *Collector) run(ctx context.Context) {
	defer c.wg.Done()

	file, err := os.Open(c.cfg.LogPath)
	if err != nil {
		c.pushError(fmt.Errorf("open nftables log file: %w", err))
		return
	}
	defer file.Close()

	// ReadFromHead 설정이 false면 파일의 끝(최신 로그)부터 읽기 시작합니다.
	if !c.cfg.ReadFromHead {
		if _, err := file.Seek(0, os.SEEK_END); err != nil {
			c.pushError(fmt.Errorf("seek nftables log end: %w", err))
			return
		}
	}

	reader := bufio.NewReader(file)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		line, err := reader.ReadString('\n')
		if err != nil {
			// 파일의 끝(EOF)에 도달한 경우 새 로그가 쌓일 때까지 대기
			if err == io.EOF {
				time.Sleep(c.cfg.PollInterval)
				continue
			}
			c.pushError(fmt.Errorf("read nftables log line: %w", err))
			time.Sleep(c.cfg.PollInterval)
			continue
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// 💡 핵심 추가 로직: Nftables 로그만 필터링 (커널 로그의 다른 텍스트는 버림)
		if !c.isNftablesLog(line) {
			continue
		}

		// RawType을 세분화하여 Normalizer가 처리하기 쉽도록 만듦
		rawType := "nftables_event"
		if strings.Contains(line, "DROP") {
			rawType = "nftables_drop"
		}

		raw := model.NewRawEnvelope(
			model.RawSourceNFTables,
			rawType,
			map[string]any{
				"line": line,
			},
		)

		if !c.pushEvent(ctx, raw) {
			return
		}
	}
}

// isNftablesLog: 문자열이 nftables 로그인지 확인합니다.
func (c *Collector) isNftablesLog(line string) bool {
	if len(c.cfg.Prefixes) > 0 {
		for _, prefix := range c.cfg.Prefixes {
			if strings.Contains(line, prefix) {
				return true
			}
		}
		return false
	}
	// 접두사 설정이 없다면 기본적으로 "NFT_"를 포함하는지 확인
	return strings.Contains(line, "NFT_")
}

func (c *Collector) pushEvent(ctx context.Context, raw model.RawEnvelope) bool {
	select {
	case c.events <- raw:
		return true
	case <-ctx.Done():
		return false
	}
}

func (c *Collector) pushError(err error) {
	select {
	case c.errors <- err:
	default:
	}
}
