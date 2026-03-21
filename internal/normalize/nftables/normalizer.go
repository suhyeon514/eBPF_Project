package nftables

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/suhyeon514/eBPF_Project/internal/model"
)

// Nftables 방화벽 차단 로그 패턴
var nftablesRegex = regexp.MustCompile(`(NFT_[A-Z_]+).*?SRC=([^\s]+)\s+DST=([^\s]+).*?PROTO=([A-Z]+)\s+SPT=([0-9]+)\s+DPT=([0-9]+)(.*?RES=0x[0-9a-fA-F]+\s+([A-Z\s]+)\s+URGP)?`)

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
	if strings.Contains(rawAction, "DROP") {
		netMeta.Action = "drop"
	} else {
		netMeta.Action = "reject"
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
		mustEventID(),
		model.EventNetFirewall, // 방화벽 차단도 넓은 의미의 네트워크 이벤트로 분류
		eventTime,
		n.host,
		n.collectorMeta(),
	)

	ev.Network = netMeta
	ev.RawRef = n.rawRef(raw)

	return &ev
}

// -----------------------------------------------------------------------------
// 헬퍼 함수들 (Conntrack/Journald와 동일)
// -----------------------------------------------------------------------------

func (n *Normalizer) collectorMeta() model.CollectorMeta {
	return model.CollectorMeta{
		Name:       "nftables",
		SourceType: "firewall",
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

func mustEventID() string {
	id, err := newEventID()
	if err != nil {
		return fmt.Sprintf("fallback-%d", time.Now().UTC().UnixNano())
	}
	return id
}

func newEventID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf("%d-%s", time.Now().UTC().UnixNano(), hex.EncodeToString(b[:])), nil
}
