package nftables

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

// 기존 nftablesRegex 변수를 아래 코드로 완전히 교체합니다.
var nftablesRegex = regexp.MustCompile(`(NFT_[A-Z_]+|IPTABLES_[A-Z_]+|\[UFW [A-Z_]+\]).*?SRC=([^\s]+)\s+DST=([^\s]+).*?PROTO=([A-Z]+)\s+SPT=([0-9]+)\s+DPT=([0-9]+)(.*?RES=0x[0-9a-fA-F]+\s+([A-Z\s]+)\s+URGP)?`)

type Normalizer struct {
	host model.HostMeta
}

// New: 통합 에이전트 형식에 맞춰 HostMeta를 주입받습니다.
func New(host model.HostMeta) *Normalizer {
	return &Normalizer{host: host}
}

// Normalize: 에이전트 표준 인터페이스 규격을 완벽히 준수합니다.
func (n *Normalizer) Normalize(_ context.Context, raw model.RawEnvelope) ([]model.Event, error) {
	if raw.Source != model.RawSourceNFTables {
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

	ev := n.normalizeEvent(line, raw)
	if ev == nil {
		return nil, nil // 매칭 실패 등 유효하지 않은 로그 무시
	}

	return []model.Event{*ev}, nil
}

// -----------------------------------------------------------------------------
// 핵심 정규화 로직
// -----------------------------------------------------------------------------

func (n *Normalizer) normalizeEvent(line string, raw model.RawEnvelope) *model.Event {
	matches := nftablesRegex.FindStringSubmatch(line)
	if len(matches) < 7 {
		return nil
	}

	netMeta := &model.NetworkMeta{}
	rawAction := matches[1]

	// 💡 1. 여기서 원본 액션 문자열을 보고 방화벽 종류(Name)를 판별합니다.
	collectorName := "firewall" // 기본값
	if strings.HasPrefix(rawAction, "NFT_") {
		collectorName = "nftables"
	} else if strings.HasPrefix(rawAction, "IPTABLES_") {
		collectorName = "iptables"
	} else if strings.Contains(rawAction, "UFW") {
		collectorName = "ufw"
	}

	if strings.Contains(rawAction, "DROP") || strings.Contains(rawAction, "BLOCK") {
		netMeta.Action = "drop"
	} else if strings.Contains(rawAction, "ACCEPT") || strings.Contains(rawAction, "ALLOW") {
		netMeta.Action = "accept" // 정상 허용
	} else if strings.Contains(rawAction, "REJECT") {
		netMeta.Action = "reject" // 명시적 거절
	} else {
		netMeta.Action = "log" // TRACE, AUDIT 등 단순 기록용
	}

	netMeta.SrcIP = matches[2]
	netMeta.DstIP = matches[3]
	netMeta.Protocol = strings.ToLower(matches[4])

	srcPort, _ := strconv.ParseUint(matches[5], 10, 16)
	dstPort, _ := strconv.ParseUint(matches[6], 10, 16)
	netMeta.SrcPort = uint16(srcPort)
	netMeta.DstPort = uint16(dstPort)

	if len(matches) >= 9 && matches[8] != "" {
		netMeta.TCPFlags = strings.TrimSpace(matches[8])
	}

	eventTime := raw.ReceivedAt
	if eventTime.IsZero() {
		eventTime = time.Now().UTC()
	}

	ev := model.NewEvent(
		model.NewEventID(),
		model.EventNetFirewall, // 방화벽 차단도 넓은 의미의 네트워크 이벤트로 분류
		eventTime,
		n.host,
		// n.collectorMeta(),
		n.dynamicCollectorMeta(collectorName),
	)

	ev.Network = netMeta
	ev.RawRef = n.rawRef(raw)

	return &ev
}

// 💡 기존의 고정된 collectorMeta() 대신, name을 인자로 받는 함수로 변경합니다.
func (n *Normalizer) dynamicCollectorMeta(name string) model.CollectorMeta {
	return model.CollectorMeta{
		Name:       name,       // "nftables", "iptables", "ufw" 중 하나가 들어감
		SourceType: "firewall", // 분류 카테고리는 firewall로 통일
	}
}

func (n *Normalizer) rawRef(raw model.RawEnvelope) *model.RawReference {
	return &model.RawReference{
		Source:  string(raw.Source),
		RawType: raw.RawType,
	}
}

// extractLine: Payload에서 "line" 문자열을 안전하게 추출합니다.
func extractLine(payload any) (string, error) {
	switch v := payload.(type) {
	case map[string]any:
		if line, ok := v["line"].(string); ok {
			return line, nil
		}
	case model.RawJSON:
		var m map[string]any
		if err := json.Unmarshal(v.Data, &m); err == nil {
			if line, ok := m["line"].(string); ok {
				return line, nil
			}
		}
	case *model.RawJSON:
		var m map[string]any
		if err := json.Unmarshal(v.Data, &m); err == nil {
			if line, ok := m["line"].(string); ok {
				return line, nil
			}
		}
	}
	return "", fmt.Errorf("unsupported nftables payload type or missing 'line' key: %T", payload)
}
