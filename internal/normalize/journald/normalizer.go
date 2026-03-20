package journald

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
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
	if raw.Source != model.RawSourceJournald {
		return nil, fmt.Errorf("unsupported raw source: %s", raw.Source)
	}

	data, err := extractRawJSON(raw.Payload)
	if err != nil {
		return nil, err
	}

	var entry journalEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, fmt.Errorf("unmarshal journald entry: %w", err)
	}

	switch raw.RawType {
	case "sudo":
		evs := n.normalizeSudo(entry, raw)
		return evs, nil
	case "su":
		evs := n.normalizeSU(entry, raw)
		return evs, nil
	case "sshd":
		evs := n.normalizeSSHD(entry, raw)
		return evs, nil
	case "systemd":
		evs := n.normalizeSystemd(entry, raw)
		return evs, nil
	default:
		return nil, fmt.Errorf("unsupported journald raw type: %s", raw.RawType)
	}
}

type journalEntry struct {
	Message           string `json:"MESSAGE"`
	SyslogIdentifier  string `json:"SYSLOG_IDENTIFIER"`
	SystemdUnit       string `json:"_SYSTEMD_UNIT"`
	SystemdUserUnit   string `json:"USER_UNIT"`
	Hostname          string `json:"_HOSTNAME"`
	Comm              string `json:"_COMM"`
	Exe               string `json:"_EXE"`
	Cmdline           string `json:"_CMDLINE"`
	UID               string `json:"_UID"`
	GID               string `json:"_GID"`
	PID               string `json:"_PID"`
	RealtimeTimestamp string `json:"__REALTIME_TIMESTAMP"`
	RestartCount      string `json:"N_RESTARTS"`
}

func (n *Normalizer) normalizeSudo(e journalEntry, raw model.RawEnvelope) []model.Event {
	msg := strings.TrimSpace(e.Message)
	if msg == "" {
		return nil
	}

	host := n.entryHost(e)
	eventTime := parseJournalRealtime(e.RealtimeTimestamp)

	// sudo COMMAND 로그
	if m := sudoCommandRe.FindStringSubmatch(msg); len(m) == 4 {
		ev := model.NewEvent(
			mustEventID(),
			model.EventAuthSudo,
			eventTime,
			host,
			n.collectorMeta(),
		)
		ev.Auth = &model.AuthMeta{
			Method:  "sudo",
			Account: strings.TrimSpace(m[1]),
			Result:  "success",
		}
		ev.Labels = map[string]string{
			"phase":       "command",
			"target_user": strings.TrimSpace(m[2]),
			"command":     strings.TrimSpace(m[3]),
		}
		ev.RawRef = n.rawRef(raw)
		return []model.Event{ev}
	}

	// sudo session opened
	if m := sudoSessionOpenRe.FindStringSubmatch(msg); len(m) == 3 {
		ev := model.NewEvent(
			mustEventID(),
			model.EventAuthSudo,
			eventTime,
			host,
			n.collectorMeta(),
		)
		ev.Auth = &model.AuthMeta{
			Method: "sudo",
			Result: "success",
		}
		ev.Labels = map[string]string{
			"phase":       "session_open",
			"target_user": strings.TrimSpace(m[1]),
			"by_uid":      strings.TrimSpace(m[2]),
		}
		ev.RawRef = n.rawRef(raw)
		return []model.Event{ev}
	}

	// sudo session closed
	if m := sudoSessionCloseRe.FindStringSubmatch(msg); len(m) == 2 {
		ev := model.NewEvent(
			mustEventID(),
			model.EventAuthSudo,
			eventTime,
			host,
			n.collectorMeta(),
		)
		ev.Auth = &model.AuthMeta{
			Method: "sudo",
			Result: "success",
		}
		ev.Labels = map[string]string{
			"phase":       "session_close",
			"target_user": strings.TrimSpace(m[1]),
		}
		ev.RawRef = n.rawRef(raw)
		return []model.Event{ev}
	}

	return nil
}

func (n *Normalizer) normalizeSU(e journalEntry, raw model.RawEnvelope) []model.Event {
	msg := strings.TrimSpace(e.Message)
	if msg == "" {
		return nil
	}

	host := n.entryHost(e)
	eventTime := parseJournalRealtime(e.RealtimeTimestamp)

	// FAILED SU (to root) [user] on pts/2
	if m := suFailedRe.FindStringSubmatch(msg); len(m) == 3 {
		ev := model.NewEvent(
			mustEventID(),
			model.EventAuthSU,
			eventTime,
			host,
			n.collectorMeta(),
		)
		ev.Auth = &model.AuthMeta{
			Method:  "su",
			Account: strings.TrimSpace(m[2]),
			Result:  "fail",
		}
		ev.Labels = map[string]string{
			"phase":       "auth_fail",
			"target_user": strings.TrimSpace(m[1]),
		}
		ev.RawRef = n.rawRef(raw)
		return []model.Event{ev}
	}

	// pam_unix(su:auth): authentication failure ... user=root
	if m := suPamAuthFailRe.FindStringSubmatch(msg); len(m) == 2 {
		ev := model.NewEvent(
			mustEventID(),
			model.EventAuthSU,
			eventTime,
			host,
			n.collectorMeta(),
		)
		ev.Auth = &model.AuthMeta{
			Method: "su",
			Result: "fail",
		}
		ev.Labels = map[string]string{
			"phase":       "pam_auth_fail",
			"target_user": strings.TrimSpace(m[1]),
		}
		ev.RawRef = n.rawRef(raw)
		return []model.Event{ev}
	}

	// (to root) [user] on pts/2
	if m := suSuccessRe.FindStringSubmatch(msg); len(m) == 3 {
		ev := model.NewEvent(
			mustEventID(),
			model.EventAuthSU,
			eventTime,
			host,
			n.collectorMeta(),
		)
		ev.Auth = &model.AuthMeta{
			Method:  "su",
			Account: strings.TrimSpace(m[2]),
			Result:  "success",
		}
		ev.Labels = map[string]string{
			"phase":       "success",
			"target_user": strings.TrimSpace(m[1]),
		}
		ev.RawRef = n.rawRef(raw)
		return []model.Event{ev}
	}

	// session opened
	if m := suSessionOpenRe.FindStringSubmatch(msg); len(m) == 3 {
		ev := model.NewEvent(
			mustEventID(),
			model.EventAuthSU,
			eventTime,
			host,
			n.collectorMeta(),
		)
		ev.Auth = &model.AuthMeta{
			Method: "su",
			Result: "success",
		}
		ev.Labels = map[string]string{
			"phase":       "session_open",
			"target_user": strings.TrimSpace(m[1]),
			"by_uid":      strings.TrimSpace(m[2]),
		}
		ev.RawRef = n.rawRef(raw)
		return []model.Event{ev}
	}

	// session closed
	if m := suSessionCloseRe.FindStringSubmatch(msg); len(m) == 2 {
		ev := model.NewEvent(
			mustEventID(),
			model.EventAuthSU,
			eventTime,
			host,
			n.collectorMeta(),
		)
		ev.Auth = &model.AuthMeta{
			Method: "su",
			Result: "success",
		}
		ev.Labels = map[string]string{
			"phase":       "session_close",
			"target_user": strings.TrimSpace(m[1]),
		}
		ev.RawRef = n.rawRef(raw)
		return []model.Event{ev}
	}

	return nil
}

func (n *Normalizer) normalizeSSHD(e journalEntry, raw model.RawEnvelope) []model.Event {
	msg := strings.TrimSpace(e.Message)
	if msg == "" {
		return nil
	}

	host := n.entryHost(e)
	eventTime := parseJournalRealtime(e.RealtimeTimestamp)

	// Accepted password for [user] from [ip] port [port] ssh2
	if m := sshAcceptedRe.FindStringSubmatch(msg); len(m) == 3 {
		ev := model.NewEvent(
			mustEventID(),
			model.EventAuthSSHLogin,
			eventTime,
			host,
			n.collectorMeta(),
		)
		ev.Auth = &model.AuthMeta{
			Method:   "ssh",
			Account:  strings.TrimSpace(m[1]),
			Result:   "success",
			RemoteIP: strings.TrimSpace(m[2]),
		}
		ev.Labels = map[string]string{
			"phase": "login_success",
		}
		ev.RawRef = n.rawRef(raw)
		return []model.Event{ev}
	}

	// pam_unix(sshd:session): session opened for user [user](uid=1000) by (uid=0)
	if m := sshSessionOpenRe.FindStringSubmatch(msg); len(m) == 3 {
		ev := model.NewEvent(
			mustEventID(),
			model.EventAuthSSHLogin,
			eventTime,
			host,
			n.collectorMeta(),
		)
		ev.Auth = &model.AuthMeta{
			Method:  "ssh",
			Account: strings.TrimSpace(m[1]),
			Result:  "success",
		}
		ev.Labels = map[string]string{
			"phase":   "session_open",
			"user_id": strings.TrimSpace(m[2]),
		}
		ev.RawRef = n.rawRef(raw)
		return []model.Event{ev}
	}

	// Received disconnect from [ip] port [port]:11: disconnected by user
	if m := sshReceivedDisconnectRe.FindStringSubmatch(msg); len(m) == 2 {
		ev := model.NewEvent(
			mustEventID(),
			model.EventAuthSSHLogin,
			eventTime,
			host,
			n.collectorMeta(),
		)
		ev.Auth = &model.AuthMeta{
			Method:   "ssh",
			RemoteIP: strings.TrimSpace(m[1]),
		}
		ev.Labels = map[string]string{
			"phase": "disconnect",
		}
		ev.RawRef = n.rawRef(raw)
		return []model.Event{ev}
	}

	// Disconnected from user [user] [ip] port [port]
	if m := sshDisconnectedUserRe.FindStringSubmatch(msg); len(m) == 3 {
		ev := model.NewEvent(
			mustEventID(),
			model.EventAuthSSHLogin,
			eventTime,
			host,
			n.collectorMeta(),
		)
		ev.Auth = &model.AuthMeta{
			Method:   "ssh",
			Account:  strings.TrimSpace(m[1]),
			RemoteIP: strings.TrimSpace(m[2]),
		}
		ev.Labels = map[string]string{
			"phase": "disconnect",
		}
		ev.RawRef = n.rawRef(raw)
		return []model.Event{ev}
	}

	// pam_unix(sshd:session): session closed for user jeong
	if m := sshSessionCloseRe.FindStringSubmatch(msg); len(m) == 2 {
		ev := model.NewEvent(
			mustEventID(),
			model.EventAuthSSHLogin,
			eventTime,
			host,
			n.collectorMeta(),
		)
		ev.Auth = &model.AuthMeta{
			Method:  "ssh",
			Account: strings.TrimSpace(m[1]),
		}
		ev.Labels = map[string]string{
			"phase": "session_close",
		}
		ev.RawRef = n.rawRef(raw)
		return []model.Event{ev}
	}

	return nil
}

func (n *Normalizer) normalizeSystemd(e journalEntry, raw model.RawEnvelope) []model.Event {
	msg := strings.TrimSpace(e.Message)
	if msg == "" {
		return nil
	}

	host := n.entryHost(e)
	eventTime := parseJournalRealtime(e.RealtimeTimestamp)

	unitName := strings.TrimSpace(e.SystemdUserUnit)

	// Scheduled restart job, restart counter is at N.
	if m := systemdRestartRe.FindStringSubmatch(msg); len(m) == 3 {
		if unitName == "" {
			unitName = strings.TrimSpace(m[1])
		}
		ev := model.NewEvent(
			mustEventID(),
			model.EventServiceUnitState,
			eventTime,
			host,
			n.collectorMeta(),
		)
		ev.Service = &model.ServiceMeta{
			UnitName: unitName,
			State:    "restart_scheduled",
			Message:  msg,
		}
		ev.Labels = map[string]string{
			"restart_count": strings.TrimSpace(m[2]),
		}
		ev.RawRef = n.rawRef(raw)
		return []model.Event{ev}
	}

	// Started / Stopped ...
	if strings.HasPrefix(msg, "Started ") {
		ev := model.NewEvent(
			mustEventID(),
			model.EventServiceUnitState,
			eventTime,
			host,
			n.collectorMeta(),
		)
		ev.Service = &model.ServiceMeta{
			UnitName: unitName,
			State:    "started",
			Message:  msg,
		}
		ev.RawRef = n.rawRef(raw)
		return []model.Event{ev}
	}

	if strings.HasPrefix(msg, "Stopped ") {
		ev := model.NewEvent(
			mustEventID(),
			model.EventServiceUnitState,
			eventTime,
			host,
			n.collectorMeta(),
		)
		ev.Service = &model.ServiceMeta{
			UnitName: unitName,
			State:    "stopped",
			Message:  msg,
		}
		ev.RawRef = n.rawRef(raw)
		return []model.Event{ev}
	}

	return nil
}

func (n *Normalizer) entryHost(e journalEntry) model.HostMeta {
	host := n.host
	if host.Hostname == "" && e.Hostname != "" {
		host.Hostname = e.Hostname
	}
	return host
}

func (n *Normalizer) collectorMeta() model.CollectorMeta {
	return model.CollectorMeta{
		Name:       "journald",
		SourceType: "journal",
	}
}

func (n *Normalizer) rawRef(raw model.RawEnvelope) *model.RawReference {
	return &model.RawReference{
		Source:  string(raw.Source),
		RawType: raw.RawType,
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
		return nil, fmt.Errorf("unsupported journald payload type: %T", payload)
	}
}

func parseJournalRealtime(ts string) time.Time {
	ts = strings.TrimSpace(ts)
	if ts == "" {
		return time.Now().UTC()
	}

	// journald __REALTIME_TIMESTAMP 는 usec since epoch
	us, err := time.ParseDuration(ts + "us")
	if err == nil {
		return time.Unix(0, us.Nanoseconds()).UTC()
	}

	// fallback
	return time.Now().UTC()
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

var (
	sudoCommandRe      = regexp.MustCompile(`^\s*([^\s]+)\s+:.*USER=([^;]+)\s+;\s+COMMAND=(.+)$`)
	sudoSessionOpenRe  = regexp.MustCompile(`pam_unix\(sudo:session\): session opened for user ([^\(]+)\(uid=\d+\) by \(uid=(\d+)\)`)
	sudoSessionCloseRe = regexp.MustCompile(`pam_unix\(sudo:session\): session closed for user ([^\s]+)`)

	suFailedRe       = regexp.MustCompile(`FAILED SU \(to ([^\)]+)\)\s+([^\s]+)\s+on`)
	suPamAuthFailRe  = regexp.MustCompile(`pam_unix\(su(?:-l)?:auth\): authentication failure;.*user=([^\s]+)`)
	suSuccessRe      = regexp.MustCompile(`^\(to ([^\)]+)\)\s+([^\s]+)\s+on`)
	suSessionOpenRe  = regexp.MustCompile(`pam_unix\(su(?:-l)?:session\): session opened for user ([^\(]+)\(uid=\d+\) by \(uid=(\d+)\)`)
	suSessionCloseRe = regexp.MustCompile(`pam_unix\(su(?:-l)?:session\): session closed for user ([^\s]+)`)

	sshAcceptedRe           = regexp.MustCompile(`Accepted password for ([^\s]+) from ([^\s]+) port \d+`)
	sshSessionOpenRe        = regexp.MustCompile(`pam_unix\(sshd:session\): session opened for user ([^\(]+)\(uid=(\d+)\) by`)
	sshReceivedDisconnectRe = regexp.MustCompile(`Received disconnect from ([^\s]+) port \d+`)
	sshDisconnectedUserRe   = regexp.MustCompile(`Disconnected from user ([^\s]+)\s+([^\s]+)\s+port`)
	sshSessionCloseRe       = regexp.MustCompile(`pam_unix\(sshd:session\): session closed for user ([^\s]+)`)

	systemdRestartRe = regexp.MustCompile(`^([^:]+): Scheduled restart job, restart counter is at (\d+)\.`)
)
