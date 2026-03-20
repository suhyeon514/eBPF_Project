package model

import "time"

const SchemaVersion = "v1"

// agent 내부에서 사용하는 표준 이벤트 타입
type EventType string

const (
	EventProcessExec      EventType = "edr.process.exec"
	EventProcessExit      EventType = "edr.process.exit"
	EventNetConnect       EventType = "edr.net.connect"
	EventFileOpen         EventType = "edr.file.open"
	EventFileModify       EventType = "edr.file.modify"
	EventAuthSSHLogin     EventType = "edr.auth.ssh_login"
	EventAuthSudo         EventType = "edr.auth.sudo"
	EventAuthSU           EventType = "edr.auth.su"
	EventServiceUnitState EventType = "edr.service.unit_state"
	EventSensorHealth     EventType = "edr.sensor.health"
)

// agent 내부의 표준 정규화 이벤트
// collector 종류와 상관없이, 최종적으로는 모두 이 구조로 맞춰서 JSONL로 쓴다.
type Event struct {
	SchemaVersion string    `json:"schema_version"`
	EventID       string    `json:"event_id"`
	EventType     EventType `json:"event_type"`
	EventTime     time.Time `json:"event_time"`

	Host      HostMeta      `json:"host"`
	Collector CollectorMeta `json:"collector"`

	Process *ProcessMeta `json:"process,omitempty"`
	Network *NetworkMeta `json:"network,omitempty"`
	File    *FileMeta    `json:"file,omitempty"`
	Auth    *AuthMeta    `json:"auth,omitempty"`
	Service *ServiceMeta `json:"service,omitempty"`
	Sensor  *SensorMeta  `json:"sensor,omitempty"`

	// 간단한 태깅용
	// 예: role=web, mode=base, source=tetragon
	Labels map[string]string `json:"labels,omitempty"`

	// 이 이벤트가 어떤 raw 이벤트에서 왔는지 추적하기 위한 참조 정보
	RawRef *RawReference `json:"raw_ref,omitempty"`
}

type HostMeta struct {
	HostID   string `json:"host_id"`
	Hostname string `json:"hostname"`
	Env      string `json:"env"`
	Role     string `json:"role"`
	IP       string `json:"ip,omitempty"`
}

// 어떤 collector가 이 이벤트를 만들었는지
type CollectorMeta struct {
	Name       string `json:"name"`        // tetragon, journald, auditd ...
	SourceType string `json:"source_type"` // ebpf, journal, audit, firewall, flow
}

// 프로세스 중심 이벤트에 필요한 기본 문맥
type ProcessMeta struct {
	PID        uint32   `json:"pid"`
	TGID       uint32   `json:"tgid"`
	PPID       uint32   `json:"ppid"`
	UID        uint32   `json:"uid"`
	GID        uint32   `json:"gid"`
	Comm       string   `json:"comm"`
	Exe        string   `json:"exe,omitempty"`
	Args       []string `json:"args,omitempty"`
	ParentComm string   `json:"parent_comm,omitempty"`
	ParentExe  string   `json:"parent_exe,omitempty"`
	Cwd        string   `json:"cwd,omitempty"`
	ExecID     string   `json:"exec_id,omitempty"`
	ExitCode   *int32   `json:"exit_code,omitempty"`
	DurationMs *uint64  `json:"duration_ms,omitempty"`
}

// 네트워크 이벤트 확장용 구조다.
type NetworkMeta struct {
	Protocol string `json:"protocol"` // tcp, udp
	SrcIP    string `json:"src_ip,omitempty"`
	SrcPort  uint16 `json:"src_port,omitempty"`
	DstIP    string `json:"dst_ip,omitempty"`
	DstPort  uint16 `json:"dst_port,omitempty"`
	Action   string `json:"action,omitempty"` // connect, drop, reject
}

// 파일 이벤트 확장용 구조
type FileMeta struct {
	Path        string `json:"path"`
	Operation   string `json:"operation"` // open, write, unlink, rename
	Mode        string `json:"mode,omitempty"`
	IsSensitive bool   `json:"is_sensitive,omitempty"`
}

// 인증/권한 관련 이벤트 확장용 구조
type AuthMeta struct {
	Method   string `json:"method,omitempty"` // ssh, sudo
	Account  string `json:"account,omitempty"`
	Result   string `json:"result,omitempty"` // success, fail
	RemoteIP string `json:"remote_ip,omitempty"`
}

// journald 기반 서비스 상태 이벤트 확장용 구조
type ServiceMeta struct {
	UnitName string `json:"unit_name,omitempty"`
	State    string `json:"state,omitempty"` // started, stopped, failed
	Message  string `json:"message,omitempty"`
}

// agent/tetragon/fluent-bit 상태 이벤트 확장용 구조
type SensorMeta struct {
	Status     string `json:"status,omitempty"`      // ok, degraded, failed
	MetricName string `json:"metric_name,omitempty"` // overflow, dropped, unhealthy ...
	Value      string `json:"value,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

// 정규화 이벤트가 어떤 raw 이벤트에서 왔는지 추적하기 위한 메타데이터
type RawReference struct {
	Source     string `json:"source,omitempty"`   // tetragon, journald ...
	RawType    string `json:"raw_type,omitempty"` // process_exec, process_exit ...
	RawEventID string `json:"raw_event_id,omitempty"`
}

func NewEvent(
	eventID string,
	eventType EventType,
	eventTime time.Time,
	host HostMeta,
	collector CollectorMeta,
) Event {
	return Event{
		SchemaVersion: SchemaVersion,
		EventID:       eventID,
		EventType:     eventType,
		EventTime:     eventTime,
		Host:          host,
		Collector:     collector,
	}
}
