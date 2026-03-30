package health

import (
	"context"
	"fmt"
	"time"

	"github.com/suhyeon514/eBPF_Project/internal/health"
	"github.com/suhyeon514/eBPF_Project/internal/model"
)

// 설정 가능한 임계값을 상수로 분리 (Config에서 주입받도록 수정하면 더 좋습니다)
const (
	FailTimeoutThreshold  = 2 * time.Minute // 마지막 output OK 이후 2분이 지나면 실패로 간주
	DegradedDropThreshold = 50              // 드롭 이벤트가 50개 이상이면 성능 저하로 간주
	CollectorTimeout      = 5 * time.Minute // 콜렉터가 5분 이상 업데이트되지 않으면 비정상으로 간주
)

type Normalizer struct {
	host model.HostMeta
}

func New(host model.HostMeta) *Normalizer {
	return &Normalizer{host: host}
}

func (n *Normalizer) Normalize(ctx context.Context, raw model.RawEnvelope) ([]model.Event, error) {

	if raw.Source != model.RawSourceHealth {
		return nil, fmt.Errorf("health normalizer: unsupported raw source: %s", raw.Source)
	}

	snap, ok := raw.Payload.(health.Snapshot)
	if !ok {
		return nil, fmt.Errorf("invalid health payload")
	}

	ev := model.NewEvent(
		model.NewEventID(),
		model.EventSensorHealth,
		raw.ReceivedAt,
		n.host,
		n.collectorMeta(),
	)

	now := time.Now().UTC()
	status, reason := evaluateStatus(snap, now)

	// type SensorMeta struct {
	// 	Status     string `json:"status,omitempty"`      // ok, degraded, failed
	// 	MetricName string `json:"metric_name,omitempty"` // overflow, dropped, unhealthy ...
	// 	Value      string `json:"value,omitempty"`
	// 	Reason     string `json:"reason,omitempty"`
	// }

	ev.Labels = map[string]string{
		"total_log_events": fmt.Sprintf("%d", snap.TotalEvents),
		"drop_log_count":   fmt.Sprintf("%d", snap.DropCount),
	}

	var degradedCollectors []string

	// 개별 콜렉터 상태도 라벨로 추가 (예: collector_journald_ok=true/false)
	for collector, lastOK := range snap.CollectorStatus {
		collectorStatus := "ok"

		if lastOK.IsZero() {
			// 아직 한 번도 OK 상태가 기록되지 않은 콜렉터는 초기화 중으로 간주
			collectorStatus = "initializing"

		} else if now.Sub(lastOK) > CollectorTimeout {
			collectorStatus = "degraded"
			degradedCollectors = append(degradedCollectors, collector)
		}
		//ex :"collector_status_conntrack": "ok" or "degraded"
		ev.Labels["status_"+collector] = collectorStatus
	}

	// evaluateStatus가 "ok"를 반환했더라도, 내부 콜렉터가 죽어있다면 상태를 강등시킵니다.
	if len(degradedCollectors) > 0 && status == "ok" {
		status = "degraded"
		reason = fmt.Sprintf("quiet or degraded collectors: %v", degradedCollectors)
	}

	ev.Sensor = &model.SensorMeta{
		MetricName: "agent_health",
		Status:     status,
		Reason:     reason,
	}

	ev.RawRef = n.rawRef(raw)

	return []model.Event{ev}, nil
}
func (n *Normalizer) collectorMeta() model.CollectorMeta {
	return model.CollectorMeta{
		Name:       "health",
		SourceType: "agent_internal",
	}
}

// 에이전트의 상태를 평가하여 문자열로 반환하는 함수
func evaluateStatus(snap health.Snapshot, now time.Time) (string, string) {
	// 아직 output OK가 한 번도 없으면 초기 상태
	if snap.LastOutputOK.IsZero() {
		return "initializing", "output not yet initialized"
	}

	if now.Sub(snap.LastOutputOK) > FailTimeoutThreshold {
		return "failed", fmt.Sprintf("output timeout after %v", FailTimeoutThreshold)
	}

	if snap.DropCount > DegradedDropThreshold {
		return "degraded", fmt.Sprintf("drop count exceeded threshold: %d", snap.DropCount)
	}

	return "ok", "agent is healthy"
}

func (n *Normalizer) rawRef(raw model.RawEnvelope) *model.RawReference {
	return &model.RawReference{
		Source:  string(raw.Source),
		RawType: raw.RawType,
	}
}
