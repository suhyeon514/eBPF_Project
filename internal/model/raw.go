package model

import (
	"encoding/json"
	"time"
)

type RawSource string

const (
	RawSourceTetragon  RawSource = "tetragon"
	RawSourceJournald  RawSource = "journald"
	RawSourceAuditd    RawSource = "auditd"
	RawSourceNFTables  RawSource = "nftables"
	RawSourceConntrack RawSource = "conntrack"
	RawSourceNetwork   RawSource = "network"

	// 🔥 추가
	RawSourceNginx RawSource = "nginx"
)

type RawEnvelope struct {
	Source     RawSource         `json:"source"`
	RawType    string            `json:"raw_type"`
	ReceivedAt time.Time         `json:"received_at"`
	Payload    any               `json:"payload"`
	Meta       map[string]string `json:"meta,omitempty"`
}

type RawJSON struct {
	Data json.RawMessage `json:"data"`
}

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
