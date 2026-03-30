package tetragon

import (
	"bufio"
	"context"
	"encoding/json"
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
	done    chan struct{}
}

func New(cfg Config) *Collector {
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 1 * time.Second
	}
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
		done:   make(chan struct{}),
	}
}

func (c *Collector) Name() string {
	return "tetragon"
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
		return fmt.Errorf("tetragon collector already started")
	}

	if strings.TrimSpace(c.cfg.LogPath) == "" {
		return fmt.Errorf("tetragon collector log path is empty")
	}

	runCtx, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	c.started = true

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

	<-c.done

	c.mu.Lock()
	c.started = false
	c.mu.Unlock()

	return nil
}

func (c *Collector) run(ctx context.Context) {
	defer close(c.done)

	file, err := os.Open(c.cfg.LogPath)
	if err != nil {
		c.pushError(fmt.Errorf("open tetragon log file: %w", err))
		return
	}
	defer file.Close()

	if !c.cfg.ReadFromHead {
		if _, err := file.Seek(0, io.SeekEnd); err != nil {
			c.pushError(fmt.Errorf("seek tetragon log file end: %w", err))
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

		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				time.Sleep(c.cfg.PollInterval)
				continue
			}

			c.pushError(fmt.Errorf("read tetragon log line: %w", err))
			time.Sleep(c.cfg.PollInterval)
			continue
		}

		line = trimLine(line)
		if len(line) == 0 {
			continue
		}

		rawType, err := detectRawType(line)
		if err != nil {
			c.pushError(fmt.Errorf("detect tetragon raw type: %w", err))
			continue
		}

		raw := model.NewRawEnvelope(
			model.RawSourceTetragon,
			rawType,
			model.RawJSON{
				Data: append([]byte(nil), line...),
			},
		)

		if !c.pushEvent(ctx, raw) {
			return
		}
	}
}

func detectRawType(line []byte) (string, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(line, &top); err != nil {
		return "", fmt.Errorf("unmarshal top-level json: %w", err)
	}

	switch {
	case top["process_exec"] != nil:
		return "process_exec", nil
	case top["process_exit"] != nil:
		return "process_exit", nil
	case top["process_kprobe"] != nil:
		return "process_kprobe", nil
	default:
		return "", fmt.Errorf("unsupported tetragon event type")
	}
}

func trimLine(line []byte) []byte {
	return []byte(strings.TrimSpace(string(line)))
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
