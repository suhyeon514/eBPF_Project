package resource

import (
	"context"
	"fmt"
	"time"

	"github.com/suhyeon514/eBPF_Project/internal/model"
)

// Normalizer는 Resource 메트릭(CPU, Mem, Disk, Net, Load 등)을 표준 Event로 변환합니다.
type Normalizer struct {
	host model.HostMeta
}

// New 생성자는 호스트 메타데이터를 받아 Normalizer를 초기화합니다.
func New(host model.HostMeta) *Normalizer {
	return &Normalizer{
		host: host,
	}
}

// Normalize는 RawEnvelope를 받아 1개 이상의 표준 Event로 변환합니다.
// 에이전트의 메인 라우터/파이프라인에서 호출되는 공통 인터페이스입니다.
func (n *Normalizer) Normalize(_ context.Context, raw model.RawEnvelope) ([]model.Event, error) {
	// 1. Source 검증
	if raw.Source != model.RawSourceResource {
		return nil, fmt.Errorf("unsupported raw source: %s", raw.Source)
	}

	// 2. RawType에 따른 분기 처리 (현재는 system_metrics 단일 타입)
	switch raw.RawType {
	case "system_metrics":
		ev, err := n.normalizeSystemMetrics(raw)
		if err != nil {
			return nil, err
		}
		// Resource 이벤트는 항상 1개씩 발생하므로 길이가 1인 슬라이스 반환
		return []model.Event{ev}, nil

	default:
		return nil, fmt.Errorf("unsupported resource raw type: %s", raw.RawType)
	}
}

// normalizeSystemMetrics는 실제 데이터를 꺼내어 model.Event로 조립합니다.
func (n *Normalizer) normalizeSystemMetrics(raw model.RawEnvelope) (model.Event, error) {
	// 1. Payload 타입 단언 (Type Assertion)
	// Collector에서 새롭게 추가한 NetBytesSent, Load, Procs 등의 필드가 포함된
	// 최신 model.ResourceMeta 구조체가 그대로 넘어옵니다.
	meta, ok := raw.Payload.(model.ResourceMeta)
	if !ok {
		return model.Event{}, fmt.Errorf("invalid payload type for resource: expected model.ResourceMeta, got %T", raw.Payload)
	}

	// 2. 이벤트 타임스탬프 (수집된 시점)
	eventTime := raw.ReceivedAt
	if eventTime.IsZero() {
		eventTime = time.Now().UTC()
	}

	// 3. 표준 model.Event 생성
	ev := model.NewEvent(
		model.NewEventID(),        // 공통 EventID 생성기
		model.EventSystemResource, // "edr.system.resource"
		eventTime,
		n.host,
		model.CollectorMeta{
			Name:       "resource",
			SourceType: "system_metrics", // 또는 "os"
		},
	)

	// 4. 리소스 전용 필드 매핑
	// 여기서 복사된 포인터를 넘기면, JSON 변환 시 새롭게 추가된 네트워크/Load 필드들도 알아서 포함됩니다!
	ev.Resource = &meta

	// 5. RawRef(추적 정보) 세팅
	ev.RawRef = &model.RawReference{
		Source:  string(raw.Source),
		RawType: raw.RawType,
	}

	return ev, nil
}
