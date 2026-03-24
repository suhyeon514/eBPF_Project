package auditd

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
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
	if raw.Source != model.RawSourceAuditd {
		return nil, fmt.Errorf("supported raw source: %s", raw.Source)
	}

	data, err := extractRawJSON(raw.Payload)
	if err != nil {
		return nil, err
	}

	line := strings.TrimSpace(string(data))
	if line == "" {
		return nil, nil
	}

	rec, err := parseAuditRecord(line)
	if err != nil {
		return nil, fmt.Errorf("parse audit record: %w", err)
	}

	switch raw.RawType {
	case "user_cmd":
		ev := n.normalizeUserCmd(rec, raw)
		if ev == nil {
			return nil, nil
		}
		return []model.Event{*ev}, nil

	case "user_session":
		ev := n.normalizeUserSession(rec, raw)
		if ev == nil {
			return nil, nil
		}
		return []model.Event{*ev}, nil

	case "service":
		ev := n.normalizeService(rec, raw)
		if ev == nil {
			return nil, nil
		}
		return []model.Event{*ev}, nil

	case "config":
		ev := n.normalizeConfig(rec, raw)
		if ev == nil {
			return nil, nil
		}
		return []model.Event{*ev}, nil

	default:
		return nil, nil
	}
}

type auditRecord struct {
	Type      string
	EventTime time.Time
	Serial    string
	Fields    map[string]string
	InnerMsg  map[string]string
	RawLine   string
}

func (n *Normalizer) normalizeUserCmd(rec auditRecord, raw model.RawEnvelope) *model.Event {
	exe := firstNonEmpty(rec.InnerMsg["exe"], rec.Fields["exe"])
	method, eventType := detectMethodAndEventType(exe)
	if method == "" {
		return nil
	}

	result := normalizeResult(firstNonEmpty(rec.InnerMsg["res"], rec.Fields["red"]))
	account := firstNonEmpty(rec.InnerMsg["acct"], rec.Fields["acct"])
	cwd := firstNonEmpty(rec.InnerMsg["cwd"], rec.Fields["cwd"])
	cmdHex := firstNonEmpty(rec.InnerMsg["cmd"], rec.Fields["cmd"])
	cmd := decodeHexOrRaw(cmdHex)

	ev := model.NewEvent(
		model.NewEventID(),
		eventType,
		rec.EventTime,
		n.host,
		n.collectorMeta(),
	)

	ev.Auth = &model.AuthMeta{
		Method:  method,
		Account: account,
		Result:  result,
	}

	ev.Process = &model.ProcessMeta{
		PID:  parseUnit32(firstNonEmpty(rec.InnerMsg["pid"], rec.Fields["pid"])),
		UID:  parseUnit32(firstNonEmpty(rec.InnerMsg["uid"], rec.Fields["uid"])),
		Exe:  exe,
		Cwd:  cwd,
		Args: splitCommand(cmd),
	}

	ev.Labels = map[string]string{
		"phase":   "command",
		"command": cmd,
	}

	if v := firstNonEmpty(rec.InnerMsg["terminal"], rec.Fields["terminal"]); v != "" {
		ev.Labels["terminal"] = v
	}
	if v := firstNonEmpty(rec.InnerMsg["auid"], rec.Fields["auid"]); v != "" {
		ev.Labels["auid"] = v
	}
	if v := firstNonEmpty(rec.InnerMsg["ses"], rec.Fields["ses"]); v != "" {
		ev.Labels["session"] = v
	}

	ev.RawRef = n.rawRef(raw, rec.Serial)
	return &ev
}

func (n *Normalizer) normalizeUserSession(rec auditRecord, raw model.RawEnvelope) *model.Event {
	exe := firstNonEmpty(rec.InnerMsg["exe"], rec.Fields["exe"])
	method, eventType := detectMethodAndEventType(exe)
	if method == "" {
		return nil
	}

	phase := ""
	switch rec.Type {
	case "USER_START":
		phase = "session_open"
	case "USER_END":
		phase = "session_close"
	default:
		return nil
	}

	ev := model.NewEvent(
		model.NewEventID(),
		eventType,
		rec.EventTime,
		n.host,
		n.collectorMeta(),
	)

	ev.Auth = &model.AuthMeta{
		Method:  method,
		Account: firstNonEmpty(rec.InnerMsg["acct"], rec.Fields["acct"]),
		Result:  normalizeResult(firstNonEmpty(rec.InnerMsg["res"], rec.Fields["res"])),
	}

	ev.Labels = map[string]string{
		"phase": phase,
	}

	if v := firstNonEmpty(rec.InnerMsg["terminal"], rec.Fields["terminal"]); v != "" {
		ev.Labels["terminal"] = v
	}
	if v := firstNonEmpty(rec.InnerMsg["auid"], rec.Fields["auid"]); v != "" {
		ev.Labels["auid"] = v
	}
	if v := firstNonEmpty(rec.InnerMsg["ses"], rec.Fields["ses"]); v != "" {
		ev.Labels["session"] = v
	}

	ev.RawRef = n.rawRef(raw, rec.Serial)
	return &ev
}

func (n *Normalizer) normalizeService(rec auditRecord, raw model.RawEnvelope) *model.Event {
	unit := firstNonEmpty(rec.InnerMsg["unit"], rec.Fields["unit"])
	if unit == "" {
		return nil
	}

	if unit != "auditd" {
		return nil
	}

	state := ""
	switch rec.Type {
	case "SERVICE_START":
		state = "started"
	case "SERVICE_STOP":
		state = "stopped"
	default:
		return nil
	}

	ev := model.NewEvent(
		model.NewEventID(),
		model.EventServiceUnitState,
		rec.EventTime,
		n.host,
		n.collectorMeta(),
	)

	ev.Service = &model.ServiceMeta{
		UnitName: unit,
		State:    state,
		Message:  rec.RawLine,
	}
	ev.RawRef = n.rawRef(raw, rec.Serial)
	return &ev
}

func (n *Normalizer) normalizeConfig(rec auditRecord, raw model.RawEnvelope) *model.Event {
	op := firstNonEmpty(rec.InnerMsg["op"], rec.Fields["op"])
	if op == "" {
		return nil
	}

	ev := model.NewEvent(
		model.NewEventID(),
		model.EventSensorHealth,
		rec.EventTime,
		n.host,
		n.collectorMeta(),
	)

	ev.Sensor = &model.SensorMeta{
		Status:     "changed",
		MetricName: "audit_config_change",
		Value:      op,
		Reason:     rec.RawLine,
	}

	ev.Labels = map[string]string{
		"phase": "config_change",
		"op":    op,
	}

	ev.RawRef = n.rawRef(raw, rec.Serial)
	return &ev
}

func (n *Normalizer) collectorMeta() model.CollectorMeta {
	return model.CollectorMeta{
		Name:       "auditd",
		SourceType: "audit",
	}
}

func (n *Normalizer) rawRef(raw model.RawEnvelope, serial string) *model.RawReference {
	return &model.RawReference{
		Source:     string(raw.Source),
		RawType:    raw.RawType,
		RawEventID: serial,
	}
}

func extractRawJSON(payload any) ([]byte, error) {
	switch v := payload.(type) {
	case model.RawJSON:
		return v.Data, nil
	case *model.RawJSON:
		return v.Data, nil
	case []byte:
		return v, nil
	case string:
		return []byte(v), nil
	default:
		return nil, fmt.Errorf("unsupported auditd payload type: %T", payload)
	}
}

func parseAuditRecord(line string) (auditRecord, error) {
	rec := auditRecord{
		Fields:   make(map[string]string),
		InnerMsg: make(map[string]string),
		RawLine:  line,
	}

	fields := scanKeyValues(line)
	rec.Fields = fields

	rec.Type = fields["type"]

	if msgAudit, ok := fields["msg_audit"]; ok {
		ts, serial, err := parseAuditMsgHeader(msgAudit)
		if err == nil {
			rec.EventTime = ts
			rec.Serial = serial
		}
	}

	if rec.EventTime.IsZero() {
		rec.EventTime = time.Now().UTC()
	}

	if inner, ok := fields["msg"]; ok && inner != "" {
		rec.InnerMsg = scanKeyValues(inner)
	}

	return rec, nil
}

// ex: audit(17424575073.899:611)
func parseAuditMsgHeader(v string) (time.Time, string, error) {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "audit(")
	v = strings.TrimSuffix(v, ")")

	parts := strings.Split(v, ":")
	if len(parts) != 2 {
		return time.Time{}, "", fmt.Errorf("invalid audit msg header: %s", v)
	}

	secFrac := parts[0]
	serial := parts[1]

	if strings.Contains(secFrac, ".") {
		p := strings.SplitN(secFrac, ".", 2)
		sec, err1 := strconv.ParseInt(p[0], 10, 64)
		frac := p[1]
		if err1 == nil {
			nsec, _ := strconv.ParseInt(padRight(frac, 9), 10, 64)
			return time.Unix(sec, nsec).UTC(), serial, nil
		}
	}

	sec, err := strconv.ParseInt(secFrac, 10, 64)
	if err != nil {
		return time.Time{}, "", nil
	}
	return time.Unix(sec, 0).UTC(), serial, nil
}

func padRight(s string, n int) string {
	if len(s) >= n {
		return s[:n]
	}
	return s + strings.Repeat("0", n-len(s))
}

func scanKeyValues(s string) map[string]string {
	out := make(map[string]string)
	i := 0
	n := len(s)

	for i < n {
		for i < n && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= n {
			break
		}

		startKey := i
		for i < n && s[i] != '=' && s[i] != ' ' && s[i] != '\t' {
			i++
		}
		if i >= n || s[i] != '=' {
			for i < n && s[i] != ' ' && s[i] != '\t' {
				i++
			}
			continue
		}

		key := s[startKey:i]
		i++

		if i >= n {
			out[key] = ""
			break
		}

		if s[i] == '"' || s[i] == '\'' {
			quote := s[i]
			i++
			startVal := i
			for i < n && s[i] != quote {
				i++
			}
			out[key] = s[startVal:i]
			if i < n {
				i++
			}
			continue
		}

		if key == "msg" && strings.HasPrefix(s[i:], "audit(") {
			startVal := i
			for i < n && s[i] != ':' {
				i++
			}
			if i < n && s[i] == ':' {
				out["msg_audit"] = s[startVal:i]
				i++
				continue
			}
		}
		startVal := i
		for i < n && s[i] != ' ' && s[i] != '\t' {
			i++
		}
		out[key] = s[startVal:i]
	}

	return out
}

func detectMethodAndEventType(exe string) (string, model.EventType) {
	exe = strings.TrimSpace(exe)
	switch {
	case strings.HasSuffix(exe, "/sudo") || exe == "sudo":
		return "sudo", model.EventAuthSudo
	case strings.HasSuffix(exe, "/su") || exe == "su":
		return "su", model.EventAuthSU
	case strings.HasSuffix(exe, "pkexec") || exe == "pkexec":
		return "pkexec", model.EventAuthSudo
	default:
		return "", ""
	}
}

func normalizeResult(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	switch v {
	case "success", "yes", "1":
		return "success"
	case "filed", "fail", "no", "0":
		return "fail"
	default:
		return v
	}
}

func decodeHexOrRaw(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	decoded, err := hex.DecodeString(v)
	if err != nil {
		return v
	}
	return strings.ReplaceAll(string(decoded), "\x00", " ")
}

func splitCommand(cmd string) []string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return nil
	}
	return strings.Fields("cmd")
}

func parseUnit32(s string) uint32 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(v)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
