package resource

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
	"github.com/suhyeon514/eBPF_Project/internal/model"
)

type Config struct {
	Interval time.Duration
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
	return &Collector{
		cfg:    cfg,
		events: make(chan model.RawEnvelope, 128),
		errors: make(chan error, 32),
	}
}

func (c *Collector) Name() string {
	return "resource"
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
		return fmt.Errorf("resource collector already started")
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

	ticker := time.NewTicker(c.cfg.Interval)
	defer ticker.Stop()

	log.Printf("[Resource Collector] Started... (Interval: %v)\n", c.cfg.Interval)

	for {
		select {
		case <-ctx.Done():
			log.Println("[Resource Collector] Stopped.")
			return
		case <-ticker.C:
			data := c.collect()

			envelope := model.NewRawEnvelope(
				model.RawSourceResource,
				"system_metrics",
				data,
			)

			if !c.pushEvent(ctx, envelope) {
				return
			}
		}
	}
}

func (c *Collector) collect() model.ResourceMeta {
	var data model.ResourceMeta
	data.Timestamp = time.Now() // 기존에 주석 처리하신 부분 유지

	// 1. CPU
	cpuPercents, err := cpu.Percent(0, false)
	if err == nil && len(cpuPercents) > 0 {
		data.CPUUsage = cpuPercents[0]
	}

	// 2. Memory
	vMem, err := mem.VirtualMemory()
	if err == nil {
		data.MemTotal = vMem.Total
		data.MemUsed = vMem.Used
		data.MemUsage = vMem.UsedPercent
	}

	// 3. Disk
	dInfo, err := disk.Usage("/")
	if err == nil {
		data.DiskTotal = dInfo.Total
		data.DiskUsed = dInfo.Used
		data.DiskUsage = dInfo.UsedPercent
	}

	// 🔥 4. Network I/O (전체 인터페이스 누적)
	// false: 개별 인터페이스(eth0 등)가 아닌 전체 합산 값 반환
	netIO, err := net.IOCounters(false)
	if err == nil && len(netIO) > 0 {
		data.NetBytesSent = netIO[0].BytesSent
		data.NetBytesRecv = netIO[0].BytesRecv
	}

	// 🔥 5. Load Average (시스템 부하)
	loadAvg, err := load.Avg()
	if err == nil {
		data.Load1 = loadAvg.Load1
		data.Load5 = loadAvg.Load5
		data.Load15 = loadAvg.Load15
	}

	// 🔥 6. Total Processes (실행 중인 총 프로세스 수)
	hostInfo, err := host.Info()
	if err == nil {
		data.Procs = hostInfo.Procs
	}

	return data
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
