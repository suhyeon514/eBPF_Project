package model

import (
	"encoding/json"
	"time"
)

// raw 이벤트의 출처를 구분
type RawSource string

const (
	RawSourceTetragon  RawSource = "tetragon"
	RawSourceJournald  RawSource = "journald"
	RawSourceAuditd    RawSource = "auditd"
	RawSourceNFTables  RawSource = "nftables"
	RawSourceConntrack RawSource = "conntrack"
	RawSourceNetwork   RawSource = "network"
)

// collector가 normalizer에 전달하는 공통 원시 이벤트 래퍼
type RawEnvelope struct {
	Source     RawSource         `json:"source"`
	RawType    string            `json:"raw_type"`    // agent가 이 raw를 받은 시각
	ReceivedAt time.Time         `json:"received_at"` // source별 원본 구조체 또는 RawJSON
	Payload    any               `json:"payload"`     // source별 원본 구조체 또는 RawJSON
	Meta       map[string]string `json:"meta,omitempty"`
}

// JSON 기반 source를 다룰 때 쓰는 헬퍼 타입
type RawJSON struct {
	Data json.RawMessage `json:"data"`
}

// 공통 envelope 생성 헬퍼
func NewRawEnvelope(
	source RawSource,
	rawType string,
	payload any,
) RawEnvelope {
	return RawEnvelope{
		Source:     source,
		RawType:    rawType,
		ReceivedAt: time.Now().UTC(),
		Payload:    payload,
	}
}
