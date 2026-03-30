package auditd

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
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
		cfg.EventsBuffer = 32
	}

	return &Collector{
		cfg:    cfg,
		events: make(chan model.RawEnvelope, cfg.EventsBuffer),
		errors: make(chan error, cfg.ErrorsBuffer),
		done:   make(chan struct{}),
	}
}

func (c *Collector) Name() string {
	return "auditd"
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
		return fmt.Errorf("auditd collector already started")
	}
	if strings.TrimSpace(c.cfg.LogPath) == "" {
		return fmt.Errorf("auditd collector log path is empty")
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
		c.pushError(fmt.Errorf("open auditd log file: %w", err))
		return
	}
	defer file.Close()

	if !c.cfg.ReadFromHead {
		if _, err := file.Seek(0, io.SeekEnd); err != nil {
			c.pushError(fmt.Errorf("seek auditd log file end: %w", err))
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
			c.pushError(fmt.Errorf("read auditd log line: %w", err))
			time.Sleep(c.cfg.PollInterval)
			continue
		}

		line = trimLine(line)
		if len(line) == 0 {
			continue
		}

		rawType := detectRawType(string(line))

		raw := model.NewRawEnvelope(
			model.RawSourceAuditd,
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

var auditTypeRe = regexp.MustCompile(`\btype=([A-Z_]+)\b`)

func detectRawType(line string) string {
	m := auditTypeRe.FindStringSubmatch(line)
	if len(m) != 2 {
		return "unknown"
	}

	switch m[1] {
	case "USER_CMD":
		return "user_cmd"
	case "USER_START", "USER_END":
		return "user_session"
	case "USER_ACCT":
		return "user_acct"
	case "CRED_REFR", "CRED_DISP", "CRED_ACQ":
		return "cred"
	case "SERVICE_START", "SERVICE_STOP":
		return "service"
	case "CONFIG_CHANGE":
		return "config"
	case "BPF":
		return "bpf"
	default:
		return "unknown"
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
