package tetragon

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
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

	case "process_kprobe":
		fmt.Printf("DEBUG process_kprobe entered\n")

		ev, err := n.normalizeProcessKprobe(data, raw)
		if err != nil {
			return nil, err
		}
		if ev == nil {
			return nil, nil
		}
		return []model.Event{*ev}, nil

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

type tetragonProcessKprobeEvent struct {
	ProcessKprobe struct {
		Process      tetragonProcess  `json:"process"`
		Parent       *tetragonProcess `json:"parent,omitempty"`
		FunctionName string           `json:"function_name"`
		Action       string           `json:"action,omitempty"`
		PolicyName   string           `json:"policy_name,omitempty"`
		ReturnAction string           `json:"return_action,omitempty"`
		Args         []map[string]any `json:"args,omitempty"`
	} `json:"process_kprobe"`
	NodeName string    `json:"node_name"`
	Time     time.Time `json:"time"`
}

func (n *Normalizer) normalizeProcessExec(data []byte, raw model.RawEnvelope) (model.Event, error) {
	var src tetragonProcessExecEvent
	if err := json.Unmarshal(data, &src); err != nil {
		return model.Event{}, fmt.Errorf("unmarshal tetragon process_exec: %w", err)
	}

	ev := model.NewEvent(
		model.NewEventID(),
		model.EventProcessExec,
		src.Time.UTC(),
		n.eventHost(src.NodeName),
		n.collectorMeta(),
	)

	proc := buildProcessMeta(src.ProcessExec.Process, src.ProcessExec.Parent)

	ev.Process = proc
	ev.RawRef = rawRef(raw, src.ProcessExec.Process.ExecID)

	applyProcessCommonLabels(&ev, src.ProcessExec.Process.Flags, src.ProcessExec.Process.AUID)

	return ev, nil
}

func (n *Normalizer) normalizeProcessExit(data []byte, raw model.RawEnvelope) (model.Event, error) {
	var src tetragonProcessExitEvent
	if err := json.Unmarshal(data, &src); err != nil {
		return model.Event{}, fmt.Errorf("unmarshal tetragon process_exit: %w", err)
	}

	ev := model.NewEvent(
		model.NewEventID(),
		model.EventProcessExit,
		src.Time.UTC(),
		n.eventHost(src.NodeName),
		n.collectorMeta(),
	)

	proc := buildProcessMeta(src.ProcessExit.Process, src.ProcessExit.Parent)
	if !src.ProcessExit.Process.StartTime.IsZero() && !src.Time.IsZero() && src.Time.After(src.ProcessExit.Process.StartTime) {
		dur := uint64(src.Time.Sub(src.ProcessExit.Process.StartTime).Milliseconds())
		proc.DurationMs = &dur
	}

	ev.Process = proc
	ev.RawRef = rawRef(raw, src.ProcessExit.Process.ExecID)

	applyProcessCommonLabels(&ev, src.ProcessExit.Process.Flags, src.ProcessExit.Process.AUID)

	return ev, nil
}

func (n *Normalizer) normalizeProcessKprobe(data []byte, raw model.RawEnvelope) (*model.Event, error) {
	var src tetragonProcessKprobeEvent
	if err := json.Unmarshal(data, &src); err != nil {
		return nil, fmt.Errorf("unmarshal tetragon process_kprobe: %w", err)
	}

	fmt.Printf("DEBUG kprobe function_name=%q policy=%q action=%q\n",
		src.ProcessKprobe.FunctionName,
		src.ProcessKprobe.PolicyName,
		src.ProcessKprobe.Action)

	fn := strings.TrimSpace(src.ProcessKprobe.FunctionName)
	if fn == "" {
		return nil, nil
	}

	switch fn {
	case "__x64_sys_openat":
		ev := n.normalizeKprobeOpenAt(src, raw)
		return ev, nil

	case "__x64_sys_connect", "tcp_connect":
		ev := n.normalizeKprobeConnect(src, raw)
		return ev, nil

	case "tcp_sendmsg":
		ev := n.normalizeKprobeSendMsg(src, raw)
		return ev, nil

	case "tcp_close":
		ev := n.normalizeKprobeClose(src, raw)
		return ev, nil

	case "commit_creds":
		ev := n.normalizeKprobeCommitCreds(src, raw)
		return ev, nil

	default:
		return nil, nil
	}
}

func (n *Normalizer) normalizeKprobeOpenAt(src tetragonProcessKprobeEvent, raw model.RawEnvelope) *model.Event {
	eventTime := firstNonZeroTime(src.Time, src.ProcessKprobe.Process.StartTime)

	ev := model.NewEvent(
		model.NewEventID(),
		model.EventFileOpen,
		eventTime.UTC(),
		n.eventHost(src.NodeName),
		n.collectorMeta(),
	)

	ev.Process = buildProcessMeta(src.ProcessKprobe.Process, src.ProcessKprobe.Parent)
	ev.File = &model.FileMeta{
		Path:      extractFilePathFromArgs(src.ProcessKprobe.Args),
		Operation: "open",
		Mode:      extractOpenFlagsFromArgs(src.ProcessKprobe.Args),
	}
	ev.RawRef = rawRef(raw, src.ProcessKprobe.Process.ExecID)
	ev.Labels = buildKprobeLabels(src, "file_open")

	return &ev
}

func (n *Normalizer) normalizeKprobeConnect(src tetragonProcessKprobeEvent, raw model.RawEnvelope) *model.Event {
	eventTime := firstNonZeroTime(src.Time, src.ProcessKprobe.Process.StartTime)

	fmt.Printf("DEBUG normalizeKprobeConnect fn=%q\n", src.ProcessKprobe.FunctionName)

	ev := model.NewEvent(
		model.NewEventID(),
		model.EventNetConnect,
		eventTime.UTC(),
		n.eventHost(src.NodeName),
		n.collectorMeta(),
	)

	ev.Process = buildProcessMeta(src.ProcessKprobe.Process, src.ProcessKprobe.Parent)
	ev.Network = &model.NetworkMeta{
		Protocol: firstNonEmpty(
			extractStringLikeArg(src.ProcessKprobe.Args, "protocol"),
			extractStringLikeArg(src.ProcessKprobe.Args, "proto"),
			"tcp",
		),
		SrcIP:   extractStringLikeArg(src.ProcessKprobe.Args, "src_ip"),
		DstIP:   extractStringLikeArg(src.ProcessKprobe.Args, "dst_ip"),
		SrcPort: parseUint16Arg(src.ProcessKprobe.Args, "src_port"),
		DstPort: parseUint16Arg(src.ProcessKprobe.Args, "dst_port"),
		Action:  "connect",
	}
	ev.RawRef = rawRef(raw, src.ProcessKprobe.Process.ExecID)
	ev.Labels = buildKprobeLabels(src, "connect")

	return &ev
}

func (n *Normalizer) normalizeKprobeSendMsg(src tetragonProcessKprobeEvent, raw model.RawEnvelope) *model.Event {
	eventTime := firstNonZeroTime(src.Time, src.ProcessKprobe.Process.StartTime)

	ev := model.NewEvent(
		model.NewEventID(),
		model.EventNetFlow,
		eventTime.UTC(),
		n.eventHost(src.NodeName),
		n.collectorMeta(),
	)

	ev.Process = buildProcessMeta(src.ProcessKprobe.Process, src.ProcessKprobe.Parent)
	ev.Network = &model.NetworkMeta{
		Protocol: firstNonEmpty(
			extractStringLikeArg(src.ProcessKprobe.Args, "protocol"),
			extractStringLikeArg(src.ProcessKprobe.Args, "proto"),
			"tcp",
		),
		SrcIP:   extractStringLikeArg(src.ProcessKprobe.Args, "src_ip"),
		DstIP:   extractStringLikeArg(src.ProcessKprobe.Args, "dst_ip"),
		SrcPort: parseUint16Arg(src.ProcessKprobe.Args, "src_port"),
		DstPort: parseUint16Arg(src.ProcessKprobe.Args, "dst_port"),
		Action:  "send",
	}
	ev.RawRef = rawRef(raw, src.ProcessKprobe.Process.ExecID)
	ev.Labels = buildKprobeLabels(src, "sendmsg")

	return &ev
}

func (n *Normalizer) normalizeKprobeClose(src tetragonProcessKprobeEvent, raw model.RawEnvelope) *model.Event {
	eventTime := firstNonZeroTime(src.Time, src.ProcessKprobe.Process.StartTime)

	ev := model.NewEvent(
		model.NewEventID(),
		model.EventNetFlow,
		eventTime.UTC(),
		n.eventHost(src.NodeName),
		n.collectorMeta(),
	)

	ev.Process = buildProcessMeta(src.ProcessKprobe.Process, src.ProcessKprobe.Parent)
	ev.Network = &model.NetworkMeta{
		Protocol: firstNonEmpty(
			extractStringLikeArg(src.ProcessKprobe.Args, "protocol"),
			extractStringLikeArg(src.ProcessKprobe.Args, "proto"),
			"tcp",
		),
		SrcIP:   extractStringLikeArg(src.ProcessKprobe.Args, "src_ip"),
		DstIP:   extractStringLikeArg(src.ProcessKprobe.Args, "dst_ip"),
		SrcPort: parseUint16Arg(src.ProcessKprobe.Args, "src_port"),
		DstPort: parseUint16Arg(src.ProcessKprobe.Args, "dst_port"),
		Action:  "close",
	}
	ev.RawRef = rawRef(raw, src.ProcessKprobe.Process.ExecID)
	ev.Labels = buildKprobeLabels(src, "close")

	return &ev
}

func (n *Normalizer) normalizeKprobeCommitCreds(src tetragonProcessKprobeEvent, raw model.RawEnvelope) *model.Event {
	eventTime := firstNonZeroTime(src.Time, src.ProcessKprobe.Process.StartTime)

	ev := model.NewEvent(
		model.NewEventID(),
		model.EventProcessExec,
		eventTime.UTC(),
		n.eventHost(src.NodeName),
		n.collectorMeta(),
	)

	ev.Process = buildProcessMeta(src.ProcessKprobe.Process, src.ProcessKprobe.Parent)
	ev.RawRef = rawRef(raw, src.ProcessKprobe.Process.ExecID)
	ev.Labels = buildKprobeLabels(src, "cred_change")
	ev.Labels["event_subtype"] = "commit_creds"

	if uid := extractStringLikeArg(src.ProcessKprobe.Args, "uid"); uid != "" {
		ev.Labels["target_uid"] = uid
	}
	if gid := extractStringLikeArg(src.ProcessKprobe.Args, "gid"); gid != "" {
		ev.Labels["target_gid"] = gid
	}

	return &ev
}

func (n *Normalizer) eventHost(nodeName string) model.HostMeta {
	host := n.host
	if host.Hostname == "" && strings.TrimSpace(nodeName) != "" {
		host.Hostname = strings.TrimSpace(nodeName)
	}
	return host
}

func (n *Normalizer) collectorMeta() model.CollectorMeta {
	return model.CollectorMeta{
		Name:       "tetragon",
		SourceType: "ebpf",
	}
}

func buildProcessMeta(proc tetragonProcess, parent *tetragonProcess) *model.ProcessMeta {
	p := &model.ProcessMeta{
		PID:        proc.PID,
		TGID:       proc.PID, // 1차 버전: pid 기준
		UID:        proc.UID,
		GID:        derefUint32(proc.GID),
		Comm:       baseName(proc.Binary),
		Exe:        proc.Binary,
		Args:       splitArgs(proc.Arguments),
		Cwd:        proc.Cwd,
		ExecID:     proc.ExecID,
		ParentComm: "",
		ParentExe:  "",
	}

	if parent != nil {
		p.PPID = parent.PID
		p.ParentComm = baseName(parent.Binary)
		p.ParentExe = parent.Binary
	}

	return p
}

func buildKprobeLabels(src tetragonProcessKprobeEvent, phase string) map[string]string {
	labels := map[string]string{
		"phase":         phase,
		"function_name": strings.TrimSpace(src.ProcessKprobe.FunctionName),
	}

	if v := strings.TrimSpace(src.ProcessKprobe.Action); v != "" {
		labels["action"] = v
	}
	if v := strings.TrimSpace(src.ProcessKprobe.PolicyName); v != "" {
		labels["policy_name"] = v
	}
	if v := strings.TrimSpace(src.ProcessKprobe.ReturnAction); v != "" {
		labels["return_action"] = v
	}
	if src.ProcessKprobe.Process.Flags != "" {
		labels["tetragon_flags"] = src.ProcessKprobe.Process.Flags
	}
	if src.ProcessKprobe.Process.AUID != nil {
		labels["auid"] = fmt.Sprintf("%d", src.ProcessKprobe.Process.AUID)
	}

	return labels
}

func applyProcessCommonLabels(ev *model.Event, flags string, auid *uint32) {
	if ev.Labels == nil {
		ev.Labels = map[string]string{}
	}
	if flags != "" {
		ev.Labels["tetragon_flags"] = flags
	}
	if auid != nil {
		ev.Labels["auid"] = fmt.Sprintf("%d", *auid)
	}
}

func rawRef(raw model.RawEnvelope, rawEventID string) *model.RawReference {
	return &model.RawReference{
		Source:     string(raw.Source),
		RawType:    raw.RawType,
		RawEventID: rawEventID,
	}
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

func firstNonZeroTime(ts ...time.Time) time.Time {
	for _, t := range ts {
		if !t.IsZero() {
			return t
		}
	}
	return time.Now().UTC()
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v != "" {
			return v
		}
	}

	return ""
}

func extractFilePathFromArgs(args []map[string]any) string {
	candidates := []string{
		"path",
		"pathname",
		"filename",
		"file",
		"name",
	}

	for _, key := range candidates {
		if v := extractStringLikeArg(args, key); v != "" {
			return v
		}
	}

	return ""
}

func extractOpenFlagsFromArgs(args []map[string]any) string {
	candidates := []string{
		"flags",
		"open_flags",
		"mode",
	}

	for _, key := range candidates {
		if v := extractStringLikeArg(args, key); v != "" {
			return v
		}
	}

	return ""
}

func extractStringLikeArg(args []map[string]any, wantedLabel string) string {
	wantedLabel = strings.TrimSpace(wantedLabel)
	if wantedLabel == "" {
		return ""
	}

	for _, arg := range args {
		label := strings.TrimSpace(fmt.Sprint(arg["labels"]))
		if label != wantedLabel {
			continue
		}

		for _, key := range []string{
			"string_arg",
			"char_buf_arg",
			"path_arg",
			"file_arg",
			"sock_arg",
			"skb_arg",
			"int_arg",
			"size_arg",
			"bytes_arg",
		} {
			if rawVal, ok := arg[key]; ok {
				switch v := rawVal.(type) {
				case string:
					if strings.TrimSpace(v) != "" {
						return strings.TrimSpace(v)
					}
				case float64:
					return strconv.FormatInt(int64(v), 10)
				case json.Number:
					return v.String()
				default:
					s := strings.TrimSpace(fmt.Sprint(v))
					if s != "" && s != "<nil>" {
						return s
					}
				}
			}
		}
	}

	return ""
}

func extractUint64Arg(args []map[string]any, wantedLabel string) uint64 {
	wantedLabel = strings.TrimSpace(wantedLabel)
	if wantedLabel == "" {
		return 0
	}

	for _, arg := range args {
		label := strings.TrimSpace(fmt.Sprint(arg["label"]))
		if label != wantedLabel {
			continue
		}

		for _, key := range []string{"size_arg", "int_arg", "bytes_arg"} {
			if rawVal, ok := arg[key]; ok {
				switch v := rawVal.(type) {
				case float64:
					if v >= 0 {
						return uint64(v)
					}
				case json.Number:
					u, err := strconv.ParseUint(v.String(), 10, 64)
					if err == nil {
						return u
					}
				case string:
					u, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
					if err == nil {
						return u
					}
				}
			}
		}
	}

	return 0
}

func parseUint16Arg(args []map[string]any, wantedLabel string) uint16 {
	v := extractUint64Arg(args, wantedLabel)
	if v > 65535 {
		return 0
	}
	return uint16(v)
}
