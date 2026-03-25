package health

import (
	"sync"
	"time"
)

// model 패키지를 직접 참조하지 않는다
// Kafka/collector/normalize를 모른다
// 순수 상태 관리 모듈이다
// Snapshot 구조체는 raw payload로 사용 가능해야 한다

// Registry는 agent 내부 상태를 집계한다.
type Registry struct {
	mu sync.RWMutex

	startedAt time.Time

	// lastCollectorOK time.Time
	// 💡 단일 변수 대신 map을 사용하여 콜렉터별 마지막 수신 시간을 관리합니다.
	collectorStatus map[string]time.Time
	lastNormalizeOK time.Time
	lastOutputOK    time.Time

	totalEvents uint64
	dropCount   uint64
}

type Snapshot struct {
	StartedAt time.Time `json:"started_at"`
	// LastCollectorOK time.Time `json:"last_collector_ok"`
	// 💡 Snapshot에도 맵을 추가합니다.
	CollectorStatus map[string]time.Time `json:"collector_status"`
	LastNormalizeOK time.Time            `json:"last_normalize_ok"`
	LastOutputOK    time.Time            `json:"last_output_ok"`
	TotalEvents     uint64               `json:"total_events"`
	DropCount       uint64               `json:"drop_count"`
}

// NewRegistry 생성
func NewRegistry() *Registry {
	r := &Registry{
		startedAt:       time.Now().UTC(),
		collectorStatus: make(map[string]time.Time),
	}
	// 💡 에이전트가 사용하는 콜렉터들을 미리 zero-value(0001-01-01) 시간으로 맵에 넣어둡니다.
	r.collectorStatus["tetragon"] = time.Time{}
	r.collectorStatus["journald"] = time.Time{}
	r.collectorStatus["nftables"] = time.Time{}
	r.collectorStatus["conntrack"] = time.Time{}
	r.collectorStatus["auditd"] = time.Time{}
	r.collectorStatus["nginx"] = time.Time{}
	r.collectorStatus["health"] = time.Time{}

	return r
}

// 💡 파라미터로 콜렉터의 이름을 받도록 수정합니다.
func (r *Registry) MarkCollectorOK(collectorName string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.collectorStatus[collectorName] = time.Now().UTC()
}

func (r *Registry) MarkNormalizeOK() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastNormalizeOK = time.Now().UTC()
}

func (r *Registry) MarkOutputOK() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastOutputOK = time.Now().UTC()
	r.totalEvents++

}

func (r *Registry) IncDrop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dropCount++
}

func (r *Registry) Snapshot() Snapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// 💡 맵은 참조(Reference) 타입입니다.
	// 그대로 반환하면 Snapshot을 읽는 도중에 다른 고루틴이 맵을 수정하여 Race Condition이 발생할 수 있습니다.
	// 따라서 안전하게 깊은 복사(Deep Copy)를 수행하여 반환합니다.
	statusCopy := make(map[string]time.Time, len(r.collectorStatus))
	for k, v := range r.collectorStatus {
		statusCopy[k] = v
	}

	return Snapshot{
		StartedAt:       r.startedAt,
		CollectorStatus: statusCopy,
		LastNormalizeOK: r.lastNormalizeOK,
		LastOutputOK:    r.lastOutputOK,
		TotalEvents:     r.totalEvents,
		DropCount:       r.dropCount,
	}
}
