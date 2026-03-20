package journald

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"

	"github.com/suhyeon514/eBPF_Project/internal/model"
)

type Config struct {
	Profiles     []string // sshd, sudo, su, systemd
	EventsBuffer int
	ErrorsBuffer int
	TailLines    int // 시작 시 최근 N줄도 같이 볼지. 0이면 follow만
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
	if len(cfg.Profiles) == 0 {
		cfg.Profiles = []string{"sshd", "sudo", "su", "systemd"}
	}

	return &Collector{
		cfg:    cfg,
		events: make(chan model.RawEnvelope, cfg.EventsBuffer),
		errors: make(chan error, cfg.ErrorsBuffer),
	}
}

func (c *Collector) Name() string {
	return "journald"
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
		return fmt.Errorf("journald collector already started")
	}

	runCtx, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	c.started = true

	for _, profile := range c.cfg.Profiles {
		p := strings.TrimSpace(profile)
		if p == "" {
			continue
		}
		c.wg.Add(1)
		go c.runProfile(runCtx, p)
	}

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

func (c *Collector) runProfile(ctx context.Context, profile string) {
	defer c.wg.Done()

	args := []string{"-o", "json", "--follow", "--no-pager"}
	if c.cfg.TailLines > 0 {
		args = append(args, "-n", fmt.Sprintf("%d", c.cfg.TailLines))
	} else {
		args = append(args, "-n", "0")
	}

	args = append(args, fmt.Sprintf("SYSLOG_IDENTIFIER=%s", profile))

	cmd := exec.CommandContext(ctx, "journalctl", args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		c.pushError(fmt.Errorf("journald(%s) stdout pipe: %w", profile, err))
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		c.pushError(fmt.Errorf("journald(%s) stderr pipe: %w", profile, err))
	}

	fmt.Printf("journald commmand: %v\n", cmd)

	if err := cmd.Start(); err != nil {
		c.pushError(fmt.Errorf("journald(%s) start journalctl: %w", profile, err))
		return
	}

	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			msg := strings.TrimSpace(scanner.Text())
			if msg != "" {
				c.pushError(fmt.Errorf("journald(%s) stderr: %s", profile, msg))
			}
		}
	}()

	scanner := bufio.NewScanner(stdout)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		raw := model.NewRawEnvelope(
			model.RawSourceJournald,
			profile,
			model.RawJSON{Data: []byte(line)},
		)

		if !c.pushEvent(ctx, raw) {
			return
		}
	}

	if err := scanner.Err(); err != nil && ctx.Err() == nil {
		c.pushError(fmt.Errorf("journald(%s) scan: %w", profile, err))
	}

	if err := cmd.Wait(); err != nil && ctx.Err() == nil {
		c.pushError(fmt.Errorf("journald(%s) wait: %w", profile, err))
	}
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
