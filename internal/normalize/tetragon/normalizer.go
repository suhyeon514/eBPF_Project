package tetragon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/suhyeon514/eBPF_Project/internal/model"
)

type Normalizer struct {
	host model.HostMeta
}

func New(host model.HostMeta) *Normalizer {
	return &Normalizer{
		host: host,
	}
}

func (n *Normalizer) Normalize(_ context.Context, raw model.RawEnvelope) ([]model.Event, error) {
	if raw.Source != model.RawSourceTetragon {
		return nil, fmt.Errorf("unsupported raw source: %s", raw.Source)
	}

	data, err := extractRawJSON(raw.Payload)
	if err != nil {
		return nil, err
	}

	switch raw.RawType {
	case "process_exec":
		ev, err := n.normalizeProcessExec(data, raw)
		if err != nil {
			return nil, err
		}
		return []model.Event{ev}, nil

	case "process_exit":
		ev, err := n.normalizeProcessExit(data, raw)
		if err != nil {
			return nil, err
		}
		return []model.Event{ev}, nil

	default:
		return nil, fmt.Errorf("unsupported tetragon raw type: %s", raw.RawType)
	}
}

type tetragonProcess struct {
	ExecID       string    `json:"exec_id"`
	PID          uint32    `json:"pid"`
	UID          uint32    `json:"uid"`
	GID          *uint32   `json:"gid,omitempty"`
	Cwd          string    `json:"cwd"`
	Binary       string    `json:"binary"`
	Arguments    string    `json:"arguments,omitempty"`
	Flags        string    `json:"flags,omitempty"`
	StartTime    time.Time `json:"start_time"`
	AUID         *uint32   `json:"auid,omitempty"`
	ParentExecID string    `json:"parent_exec_id,omitempty"`
	TID          uint32    `json:"tid,omitempty"`
	RefCnt       *uint32   `json:"refcnt,omitempty"`
	InInitTree   *bool     `json:"in_init_tree,omitempty"`
}

type tetragonProcessExecEvent struct {
	ProcessExec struct {
		Process tetragonProcess  `json:"process"`
		Parent  *tetragonProcess `json:"parent,omitempty"`
	} `json:"process_exec"`
	NodeName string    `json:"node_name"`
	Time     time.Time `json:"time"`
}

type tetragonProcessExitEvent struct {
	ProcessExit struct {
		Process tetragonProcess  `json:"process"`
		Parent  *tetragonProcess `json:"parent,omitempty"`
		Time    time.Time        `json:"time"`
	} `json:"process_exit"`
	NodeName string    `json:"node_name"`
	Time     time.Time `json:"time"`
}

func (n *Normalizer) normalizeProcessExec(data []byte, raw model.RawEnvelope) (model.Event, error) {
	var src tetragonProcessExecEvent
	if err := json.Unmarshal(data, &src); err != nil {
		return model.Event{}, fmt.Errorf("unmarshal tetragon process_exec: %w", err)
	}

	eventID, err := newEventID()
	if err != nil {
		return model.Event{}, err
	}

	host := n.host
	if host.Hostname == "" && src.NodeName != "" {
		host.Hostname = src.NodeName
	}

	ev := model.NewEvent(
		eventID,
		model.EventProcessExec,
		src.Time.UTC(),
		host,
		model.CollectorMeta{
			Name:       "tetragon",
			SourceType: "ebpf",
		},
	)

	proc := &model.ProcessMeta{
		PID:        src.ProcessExec.Process.PID,
		TGID:       src.ProcessExec.Process.PID, // 1차 버전: pid 기준
		UID:        src.ProcessExec.Process.UID,
		GID:        derefUint32(src.ProcessExec.Process.GID),
		Comm:       baseName(src.ProcessExec.Process.Binary),
		Exe:        src.ProcessExec.Process.Binary,
		Args:       splitArgs(src.ProcessExec.Process.Arguments),
		Cwd:        src.ProcessExec.Process.Cwd,
		ExecID:     src.ProcessExec.Process.ExecID,
		ParentComm: "",
		ParentExe:  "",
	}

	if src.ProcessExec.Parent != nil {
		proc.PPID = src.ProcessExec.Parent.PID
		proc.ParentComm = baseName(src.ProcessExec.Parent.Binary)
		proc.ParentExe = src.ProcessExec.Parent.Binary
	}

	ev.Process = proc
	ev.RawRef = &model.RawReference{
		Source:     string(raw.Source),
		RawType:    raw.RawType,
		RawEventID: src.ProcessExec.Process.ExecID,
	}

	if ev.Labels == nil {
		ev.Labels = map[string]string{}
	}
	if src.ProcessExec.Process.Flags != "" {
		ev.Labels["tetragon_flags"] = src.ProcessExec.Process.Flags
	}
	if src.ProcessExec.Process.AUID != nil {
		ev.Labels["auid"] = fmt.Sprintf("%d", *src.ProcessExec.Process.AUID)
	}

	return ev, nil
}

func (n *Normalizer) normalizeProcessExit(data []byte, raw model.RawEnvelope) (model.Event, error) {
	var src tetragonProcessExitEvent
	if err := json.Unmarshal(data, &src); err != nil {
		return model.Event{}, fmt.Errorf("unmarshal tetragon process_exit: %w", err)
	}

	eventID, err := newEventID()
	if err != nil {
		return model.Event{}, err
	}

	host := n.host
	if host.Hostname == "" && src.NodeName != "" {
		host.Hostname = src.NodeName
	}

	ev := model.NewEvent(
		eventID,
		model.EventProcessExit,
		src.Time.UTC(),
		host,
		model.CollectorMeta{
			Name:       "tetragon",
			SourceType: "ebpf",
		},
	)

	proc := &model.ProcessMeta{
		PID:        src.ProcessExit.Process.PID,
		TGID:       src.ProcessExit.Process.PID, // 1차 버전: pid 기준
		UID:        src.ProcessExit.Process.UID,
		GID:        derefUint32(src.ProcessExit.Process.GID),
		Comm:       baseName(src.ProcessExit.Process.Binary),
		Exe:        src.ProcessExit.Process.Binary,
		Args:       splitArgs(src.ProcessExit.Process.Arguments),
		Cwd:        src.ProcessExit.Process.Cwd,
		ExecID:     src.ProcessExit.Process.ExecID,
		ParentComm: "",
		ParentExe:  "",
	}

	if src.ProcessExit.Parent != nil {
		proc.PPID = src.ProcessExit.Parent.PID
		proc.ParentComm = baseName(src.ProcessExit.Parent.Binary)
		proc.ParentExe = src.ProcessExit.Parent.Binary
	}

	if !src.ProcessExit.Process.StartTime.IsZero() && !src.Time.IsZero() && src.Time.After(src.ProcessExit.Process.StartTime) {
		dur := uint64(src.Time.Sub(src.ProcessExit.Process.StartTime).Milliseconds())
		proc.DurationMs = &dur
	}

	ev.Process = proc
	ev.RawRef = &model.RawReference{
		Source:     string(raw.Source),
		RawType:    raw.RawType,
		RawEventID: src.ProcessExit.Process.ExecID,
	}

	if ev.Labels == nil {
		ev.Labels = map[string]string{}
	}
	if src.ProcessExit.Process.Flags != "" {
		ev.Labels["tetragon_flags"] = src.ProcessExit.Process.Flags
	}
	if src.ProcessExit.Process.AUID != nil {
		ev.Labels["auid"] = fmt.Sprintf("%d", *src.ProcessExit.Process.AUID)
	}

	return ev, nil
}

func extractRawJSON(payload any) ([]byte, error) {
	switch v := payload.(type) {
	case model.RawJSON:
		return v.Data, nil
	case *model.RawJSON:
		return v.Data, nil
	case json.RawMessage:
		return v, nil
	case []byte:
		return v, nil
	case string:
		return []byte(v), nil
	default:
		return nil, fmt.Errorf("unsupported tetragon payload type: %T", payload)
	}
}

func splitArgs(arguments string) []string {
	arguments = strings.TrimSpace(arguments)
	if arguments == "" {
		return nil
	}
	// 1차 버전: Tetragon arguments 문자열을 공백 기준으로 단순 분리한다.
	return strings.Fields(arguments)
}

func baseName(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	return filepath.Base(path)
}

func derefUint32(v *uint32) uint32 {
	if v == nil {
		return 0
	}
	return *v
}

func newEventID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate event id: %w", err)
	}
	return fmt.Sprintf("%d-%s", time.Now().UTC().UnixNano(), hex.EncodeToString(b[:])), nil
}
