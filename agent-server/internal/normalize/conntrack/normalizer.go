package conntrack

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/suhyeon514/eBPF_Project/internal/model"
)

type Normalizer struct {
	host model.HostMeta
}

// New: 통합 에이전트 형식에 맞춰 HostMeta를 주입받습니다.
func New(host model.HostMeta) *Normalizer {
	return &Normalizer{host: host}
}

// Normalize: 에이전트 표준 인터페이스 규격을 완벽히 준수합니다.
func (n *Normalizer) Normalize(_ context.Context, raw model.RawEnvelope) ([]model.Event, error) {
	if raw.Source != model.RawSourceConntrack {
		return nil, fmt.Errorf("unsupported raw source: %s", raw.Source)
	}

	line, err := extractLine(raw.Payload)
	if err != nil {
		return nil, err
	}

	line = strings.TrimSpace(line)
	if line == "" {
		return nil, nil
	}

	// Conntrack은 RawType(conntrack_new, update 등)이 다르더라도
	// 페이로드의 정규식 파싱 로직은 동일하므로 하나의 처리 함수로 보냅니다.
	ev := n.normalizeEvent(line, raw)
	if ev == nil {
		return nil, nil // 정규식 매칭 실패 등 유효하지 않은 로그는 무시
	}

	return []model.Event{*ev}, nil
}

// -----------------------------------------------------------------------------
// 핵심 정규화 로직
// -----------------------------------------------------------------------------

func (n *Normalizer) normalizeEvent(line string, raw model.RawEnvelope) *model.Event {
	matches := conntrackRegex.FindStringSubmatch(line)
	if len(matches) < 8 {
		return nil
	}

	action := matches[1]
	switch action {
	case "NEW", "UPDATE", "DESTROY", "ASSURED", "RELATED":
		// valid
	default:
		action = "unknown"
	}

	netMeta := &model.NetworkMeta{
		Action:   action,
		Protocol: strings.ToLower(matches[2]),
		TCPFlags: matches[3],
		SrcIP:    matches[4],
		DstIP:    matches[5],
		SrcPort:  parsePort(matches[6]),
		DstPort:  parsePort(matches[7]),
	}

	eventTime := raw.ReceivedAt
	if eventTime.IsZero() {
		eventTime = time.Now().UTC()
	}

	ev := model.NewEvent(
		model.NewEventID(),
		model.EventNetFlow,
		eventTime,
		n.host,
		n.collectorMeta(),
	)

	ev.Network = netMeta
	ev.RawRef = n.rawRef(raw)

	return &ev
}

// -----------------------------------------------------------------------------
// 헬퍼 함수들 (Journald 패턴 완벽 이식)
// -----------------------------------------------------------------------------

func (n *Normalizer) collectorMeta() model.CollectorMeta {
	return model.CollectorMeta{
		Name:       "conntrack",
		SourceType: "flow",
	}
}

func (n *Normalizer) rawRef(raw model.RawEnvelope) *model.RawReference {
	return &model.RawReference{
		Source:  string(raw.Source),
		RawType: raw.RawType,
	}
}

// extractLine: Payload에서 "line" 문자열을 안전하게 추출합니다.
// (메모리상 map이거나, 직렬화된 RawJSON 형태 모두 지원)
func extractLine(payload any) (string, error) {
	switch v := payload.(type) {
	// case map[string]interface{}:
	// 	if line, ok := v["line"].(string); ok {
	// 		return line, nil
	// 	}
	case map[string]any:
		if line, ok := v["line"].(string); ok {
			return line, nil
		}
	case model.RawJSON:
		var m map[string]interface{}
		if err := json.Unmarshal(v.Data, &m); err == nil {
			if line, ok := m["line"].(string); ok {
				return line, nil
			}
		}
	case *model.RawJSON:
		var m map[string]interface{}
		if err := json.Unmarshal(v.Data, &m); err == nil {
			if line, ok := m["line"].(string); ok {
				return line, nil
			}
		}
	}
	return "", fmt.Errorf("unsupported conntrack payload type or missing 'line' key: %T", payload)
}

func parsePort(portStr string) uint16 {
	portStr = strings.TrimSpace(portStr)
	if portStr == "" {
		return 0
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return 0
	}
	return uint16(port)
}

// -----------------------------------------------------------------------------
// 정규식 정의
// -----------------------------------------------------------------------------

var (
	conntrackRegex = regexp.MustCompile(`\[(NEW|UPDATE|DESTROY|ASSURED|RELATED)\].*?(tcp|udp|icmp|sctp|gre).*?(?:([A-Z_]{3,})\s+)?src=([^\s]*)\s+dst=([^\s]*)\s+sport=([0-9]*)\s+dport=([0-9]*)`)
)
