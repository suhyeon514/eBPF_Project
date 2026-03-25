package tetragon

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/suhyeon514/eBPF_Project/internal/model"
)

type Normalizer struct {
	host model.HostMeta
}

func New(host model.HostMeta) *Normalizer {
	return &Normalizer{host: host}
}

func (n *Normalizer) Normalize(_ context.Context, raw model.RawEnvelope) ([]model.Event, error) {

	data, err := extractRawJSON(raw.Payload)
	if err != nil {
		return nil, err
	}

	switch raw.RawType {

	case "process_exec":
		return n.normalizeProcessExec(data, raw)

	case "process_exit":
		return n.normalizeProcessExit(data, raw)

	case "process_kprobe":
		return n.normalizeKprobe(data)

	case "unknown":
		return nil, nil

	default:
		return nil, nil
	}
}

func (n *Normalizer) normalizeProcessExec(data []byte, raw model.RawEnvelope) ([]model.Event, error) {

	ev := model.NewEvent(
		model.NewEventID(),
		model.EventProcessExec,
		time.Now().UTC(),
		n.host,
		model.CollectorMeta{Name: "tetragon", SourceType: "ebpf"},
	)

	return []model.Event{ev}, nil
}

func (n *Normalizer) normalizeProcessExit(data []byte, raw model.RawEnvelope) ([]model.Event, error) {

	ev := model.NewEvent(
		model.NewEventID(),
		model.EventProcessExit,
		time.Now().UTC(),
		n.host,
		model.CollectorMeta{Name: "tetragon", SourceType: "ebpf"},
	)

	return []model.Event{ev}, nil
}

func (n *Normalizer) normalizeKprobe(data []byte) ([]model.Event, error) {

	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, nil
	}

	k, ok := m["process_kprobe"].(map[string]interface{})
	if !ok {
		return nil, nil
	}

	rawStr := string(data)

	// 🔥 function_name 추출 (핵심)
	fn := ""
	if v, ok := k["function_name"].(string); ok {
		fn = v
	}

	// =========================
	// 🌐 NETWORK (connect)
	// =========================
	if strings.Contains(fn, "connect") || strings.Contains(rawStr, "connect") {

		ev := model.NewEvent(
			model.NewEventID(),
			model.EventNetConnect,
			time.Now().UTC(),
			n.host,
			model.CollectorMeta{Name: "tetragon", SourceType: "ebpf"},
		)

		return []model.Event{ev}, nil
	}

	// =========================
	// 📁 FILE (open / openat)
	// =========================
	if strings.Contains(fn, "open") {

		ev := model.NewEvent(
			model.NewEventID(),
			model.EventFileOpen,
			time.Now().UTC(),
			n.host,
			model.CollectorMeta{Name: "tetragon", SourceType: "ebpf"},
		)

		return []model.Event{ev}, nil
	}

	// =========================
	// 🔐 AUTH (commit_creds)
	// =========================
	if strings.Contains(fn, "commit_creds") || strings.Contains(rawStr, "commit_creds") {

		ev := model.NewEvent(
			model.NewEventID(),
			model.EventAuthSudo,
			time.Now().UTC(),
			n.host,
			model.CollectorMeta{Name: "tetragon", SourceType: "ebpf"},
		)

		return []model.Event{ev}, nil
	}

	// drop
	return nil, nil
}

func extractRawJSON(payload any) ([]byte, error) {
	switch v := payload.(type) {
	case model.RawJSON:
		return v.Data, nil
	default:
		return nil, nil
	}
}