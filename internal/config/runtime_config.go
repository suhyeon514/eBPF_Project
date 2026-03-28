package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// yaml 파일에서 선언한 설정 구조체 정의
type RuntimeConfig struct {
	Policy     RuntimePolicyMetaConfig `yaml:"policy"`
	Host       RuntimeHostConfig       `yaml:"host"`
	Collectors RuntimeCollectorsConfig `yaml:"collectors"`
	Rules      RuntimeRulesConfig      `yaml:"rules"`
	Output     RuntimeOutputConfig     `yaml:"output"`
	Forensic   RuntimeForensicsConfig  `yaml:"forensic"`
}

// --------------------------------------------------
// Policy metadata
// --------------------------------------------------

type RuntimePolicyMetaConfig struct {
	// 서버가 관리하는 정책 버전
	Version string `yaml:"version"`

	// 서버가 계산해준 정책 해시(선택)
	Hash string `yaml:"hash"`

	// 정책 생성/배포 시각(문자열로 단순 보관)
	IssuedAt string `yaml:"issued_at"`
}

type RuntimeHostConfig struct {
	// 운영자가 관리하는 자산 식별자
	HostID string `yaml:"host_id"`

	// 이벤트 메타데이터에 넣을 hostname
	Hostname string `yaml:"hostname"`

	// 서버가 최종 배정한 값
	Env  string `yaml:"env"`
	Role string `yaml:"role"`
}

type RuntimeCollectorsConfig struct {
	Tetragon  TetragonConfig  `yaml:"tetragon"`
	Journald  JournaldConfig  `yaml:"journald"`
	Auditd    AuditdConfig    `yaml:"auditd"`
	Conntrack ConntrackConfig `yaml:"conntrack"`
	Nftables  NftablesConfig  `yaml:"nftables"`
	Nginx     NginxConfig     `yaml:"nginx"`
	Resource  ResourceConfig  `yaml:"resource"`
}

type TetragonConfig struct {
	Enabled      bool          `yaml:"enabled"`
	LogPath      string        `yaml:"log_path"`
	PollInterval time.Duration `yaml:"poll_interval"`
	ReadFromHead bool          `yaml:"read_from_head"`
}

type JournaldConfig struct {
	Enabled   bool     `yaml:"enabled"`
	Profiles  []string `yaml:"profiles"`
	TailLines int      `yaml:"tail_lines"`
}

type AuditdConfig struct {
	Enabled      bool          `yaml:"enabled"`
	LogPath      string        `yaml:"log_path"`
	PollInterval time.Duration `yaml:"poll_interval"`
	ReadFromHead bool          `yaml:"read_from_head"`
}

type ConntrackConfig struct {
	Enabled       bool          `yaml:"enabled"`
	Args          []string      `yaml:"args"`
	RestartOnExit bool          `yaml:"restart_on_exit"`
	RestartDelay  time.Duration `yaml:"restart_delay"`
}

type NftablesConfig struct {
	Enabled      bool          `yaml:"enabled"`
	LogPath      string        `yaml:"log_path"`
	PollInterval time.Duration `yaml:"poll_interval"`
	ReadFromHead bool          `yaml:"read_from_head"`
	Prefixes     []string      `yaml:"prefixes"`
}

type NginxConfig struct {
	Enabled bool   `yaml:"enabled"`
	LogPath string `yaml:"log_path"`
}

type ResourceConfig struct {
	PollInterval time.Duration `yaml:"poll_interval"`
}

// --------------------------------------------------
// Rules: allowlist / focus_list
// --------------------------------------------------

type RuntimeRulesConfig struct {
	Allowlist []RuntimeRule `yaml:"allowlist"`
	FocusList []RuntimeRule `yaml:"focus_list"`
}

type RuntimeRule struct {
	ID          string `yaml:"id"`
	Enabled     bool   `yaml:"enabled"`
	Description string `yaml:"description,omitempty"`

	// 조건
	Source    string           `yaml:"source,omitempty"`
	EventType string           `yaml:"event_type,omitempty"`
	Match     RuntimeRuleMatch `yaml:"match"`

	// 액션
	Action RuntimeRuleAction `yaml:"action"`
}

type RuntimeRuleMatch struct {
	ProcessExe  string `yaml:"process_exe,omitempty"`
	ProcessName string `yaml:"process_name,omitempty"`
	FilePath    string `yaml:"file_path,omitempty"`
	Account     string `yaml:"account,omitempty"`
	RemoteIP    string `yaml:"remote_ip,omitempty"`
	Protocol    string `yaml:"protocol,omitempty"`
	DstPort     int    `yaml:"dst_port,omitempty"`
	ServiceUnit string `yaml:"service_unit,omitempty"`
	LabelKey    string `yaml:"label_key,omitempty"`
	LabelValue  string `yaml:"label_value,omitempty"`
}

type RuntimeRuleAction struct {
	// allowlist 계열
	SuppressAlert bool   `yaml:"suppress_alert,omitempty"`
	DropEvent     bool   `yaml:"drop_event,omitempty"`
	Severity      string `yaml:"severity,omitempty"`
	Tag           string `yaml:"tag,omitempty"`
}

type RuntimeOutputConfig struct {
	NormalizedPath string `yaml:"normalized_path"`
}

type RuntimeForensicsConfig struct {
	DumpPath string `yaml:"dump_path"`
}

// LoadRuntime는 runtime yaml 파일을 읽고, 기본값을 채운 뒤 검증한다.
func LoadRuntime(path string) (*RuntimeConfig, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("runtime config path is empty")
	}

	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read runtime config: %w", err)
	}

	var cfg RuntimeConfig
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("unmarshal runtime config: %w", err)
	}

	cfg.ApplyDefaults()

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func (c *RuntimeConfig) ApplyDefaults() {
	// --------------------------------------------------
	// policy
	// --------------------------------------------------
	c.Policy.Version = strings.TrimSpace(c.Policy.Version)
	c.Policy.Hash = strings.TrimSpace(c.Policy.Hash)
	c.Policy.IssuedAt = strings.TrimSpace(c.Policy.IssuedAt)

	// // --------------------------------------------------
	// // host
	// // --------------------------------------------------
	// c.Host.HostID = strings.TrimSpace(c.Host.HostID)
	// c.Host.Hostname = strings.TrimSpace(c.Host.Hostname)
	// c.Host.Env = strings.TrimSpace(c.Host.Env)
	// c.Host.Role = strings.TrimSpace(c.Host.Role)

	// tetragon
	c.Collectors.Tetragon.LogPath = strings.TrimSpace(c.Collectors.Tetragon.LogPath)
	if c.Collectors.Tetragon.PollInterval <= 0 {
		c.Collectors.Tetragon.PollInterval = 1 * time.Second
	}

	// journald
	if c.Collectors.Journald.Enabled {
		if len(c.Collectors.Journald.Profiles) == 0 {
			c.Collectors.Journald.Profiles = []string{"sshd", "sudo", "su", "systemd"}
		}
		if c.Collectors.Journald.TailLines < 0 {
			c.Collectors.Journald.TailLines = 0
		}
	}

	// auditd
	c.Collectors.Auditd.LogPath = strings.TrimSpace(c.Collectors.Auditd.LogPath)
	if c.Collectors.Auditd.Enabled {
		if c.Collectors.Auditd.LogPath == "" {
			c.Collectors.Auditd.LogPath = "/var/log/audit/audit.log"
		}
		if c.Collectors.Auditd.PollInterval <= 0 {
			c.Collectors.Auditd.PollInterval = 1 * time.Second
		}
	}

	// conntrack
	if c.Collectors.Conntrack.Enabled {
		if len(c.Collectors.Conntrack.Args) == 0 {
			c.Collectors.Conntrack.Args = []string{"-E", "-o", "timestamp,extended"}
		}
		if c.Collectors.Conntrack.RestartDelay <= 0 {
			c.Collectors.Conntrack.RestartDelay = 2 * time.Second
		}
	}

	// nftables
	c.Collectors.Nftables.LogPath = strings.TrimSpace(c.Collectors.Nftables.LogPath)
	if c.Collectors.Nftables.Enabled {
		if c.Collectors.Nftables.PollInterval <= 0 {
			c.Collectors.Nftables.PollInterval = 1 * time.Second
		}
		if len(c.Collectors.Nftables.Prefixes) == 0 {
			c.Collectors.Nftables.Prefixes = []string{"NFT_DROP", "NFT_ACCEPT", "NFT_TRACE", "NFT_LOG"}
		}
	}

	// nginx
	c.Collectors.Nginx.LogPath = strings.TrimSpace(c.Collectors.Nginx.LogPath)

	// resource
	if c.Collectors.Resource.PollInterval <= 0 {
		c.Collectors.Resource.PollInterval = 10 * time.Second
	}

	// --------------------------------------------------
	// rules
	// --------------------------------------------------
	normalizeRules(c.Rules.Allowlist)
	normalizeRules(c.Rules.FocusList)

	// forensic
	c.Forensic.DumpPath = strings.TrimSpace(c.Forensic.DumpPath)

	// output
	c.Output.NormalizedPath = strings.TrimSpace(c.Output.NormalizedPath)
}

func (c *RuntimeConfig) Validate() error {
	// --------------------------------------------------
	// host
	// --------------------------------------------------
	// if strings.TrimSpace(c.Host.HostID) == "" {
	// 	return fmt.Errorf("host.host_id is required")
	// }
	// if strings.TrimSpace(c.Host.Hostname) == "" {
	// 	return fmt.Errorf("host.hostname is required")
	// }
	// if strings.TrimSpace(c.Host.Env) == "" {
	// 	return fmt.Errorf("host.env is required")
	// }
	// if strings.TrimSpace(c.Host.Role) == "" {
	// 	return fmt.Errorf("host.role is required")
	// }

	if strings.TrimSpace(c.Output.NormalizedPath) == "" {
		return fmt.Errorf("output.normalized_path is required")
	}

	enabledCount := 0

	if c.Collectors.Tetragon.Enabled {
		enabledCount++
		if strings.TrimSpace(c.Collectors.Tetragon.LogPath) == "" {
			return fmt.Errorf("collectors.tetragon.log_path is required when tetragon is enabled")
		}
		if c.Collectors.Tetragon.PollInterval <= 0 {
			return fmt.Errorf("collectors.tetragon.poll_interval must be > 0")
		}
	}

	if c.Collectors.Journald.Enabled {
		enabledCount++
		if len(c.Collectors.Journald.Profiles) == 0 {
			return fmt.Errorf("collectors.journald.profiles must not be empty when journald is enabled")
		}
		if c.Collectors.Journald.TailLines < 0 {
			return fmt.Errorf("collectors.journald.tail_lines must be >= 0")
		}
	}

	if c.Collectors.Auditd.Enabled {
		enabledCount++
		if strings.TrimSpace(c.Collectors.Auditd.LogPath) == "" {
			return fmt.Errorf("collectors.auditd.log_path is required when auditd is enabled")
		}
		if c.Collectors.Auditd.PollInterval <= 0 {
			return fmt.Errorf("collectors.auditd.poll_interval must be > 0")
		}
	}

	if c.Collectors.Conntrack.Enabled {
		enabledCount++
		if len(c.Collectors.Conntrack.Args) == 0 {
			return fmt.Errorf("collectors.conntrack.args must not be empty when conntrack is enabled")
		}
		if c.Collectors.Conntrack.RestartDelay <= 0 {
			return fmt.Errorf("collectors.conntrack.restart_delay must be > 0")
		}
	}

	if c.Collectors.Nftables.Enabled {
		enabledCount++
		if strings.TrimSpace(c.Collectors.Nftables.LogPath) == "" {
			return fmt.Errorf("collectors.nftables.log_path is required when nftables is enabled")
		}
		if c.Collectors.Nftables.PollInterval <= 0 {
			return fmt.Errorf("collectors.nftables.poll_interval must be > 0")
		}
		if len(c.Collectors.Nftables.Prefixes) == 0 {
			return fmt.Errorf("collectors.nftables.prefixes must not be empty when nftables is enabled")
		}
	}

	if c.Collectors.Nginx.Enabled {
		enabledCount++
		if strings.TrimSpace(c.Collectors.Nginx.LogPath) == "" {
			return fmt.Errorf("collectors.nginx.log_path is required when nginx is enabled")
		}
	}

	if c.Collectors.Resource.PollInterval <= 0 {
		return fmt.Errorf("collectors.resource.poll_interval must be > 0")
	}

	if enabledCount == 0 {
		return fmt.Errorf("at least one collector must be enabled")
	}

	// --------------------------------------------------
	// rules
	// --------------------------------------------------
	if err := validateRules("rules.allowlist", c.Rules.Allowlist); err != nil {
		return err
	}
	if err := validateRules("rules.focus_list", c.Rules.FocusList); err != nil {
		return err
	}

	return nil
}

func normalizeRules(rules []RuntimeRule) {
	for i := range rules {
		rules[i].ID = strings.TrimSpace(rules[i].ID)
		rules[i].Description = strings.TrimSpace(rules[i].Description)
		rules[i].Source = strings.TrimSpace(rules[i].Source)
		rules[i].EventType = strings.TrimSpace(rules[i].EventType)

		rules[i].Match.ProcessExe = strings.TrimSpace(rules[i].Match.ProcessExe)
		rules[i].Match.ProcessName = strings.TrimSpace(rules[i].Match.ProcessName)
		rules[i].Match.FilePath = strings.TrimSpace(rules[i].Match.FilePath)
		rules[i].Match.Account = strings.TrimSpace(rules[i].Match.Account)
		rules[i].Match.RemoteIP = strings.TrimSpace(rules[i].Match.RemoteIP)
		rules[i].Match.Protocol = strings.TrimSpace(rules[i].Match.Protocol)
		rules[i].Match.ServiceUnit = strings.TrimSpace(rules[i].Match.ServiceUnit)
		rules[i].Match.LabelKey = strings.TrimSpace(rules[i].Match.LabelKey)
		rules[i].Match.LabelValue = strings.TrimSpace(rules[i].Match.LabelValue)

		rules[i].Action.Severity = strings.TrimSpace(rules[i].Action.Severity)
		rules[i].Action.Tag = strings.TrimSpace(rules[i].Action.Tag)

		// 기본은 enabled=true
		if !rules[i].Enabled {
			// false면 그대로 두되, 명시 안 된 기본값 구분은 yaml로는 애매해서
			// 1차에서는 "enabled가 false면 비활성" 규칙 그대로 사용
		}
	}
}

func validateRules(prefix string, rules []RuntimeRule) error {
	for i, r := range rules {
		if strings.TrimSpace(r.ID) == "" {
			return fmt.Errorf("%s[%d].id is required", prefix, i)
		}

		// 최소한 하나 이상의 match 조건이 있어야 함
		if isEmptyRuleMatch(r.Match) {
			return fmt.Errorf("%s[%d].match must contain at least one condition", prefix, i)
		}

		// 액션도 최소 하나는 있어야 함
		if !r.Action.SuppressAlert &&
			!r.Action.DropEvent &&
			strings.TrimSpace(r.Action.Severity) == "" &&
			strings.TrimSpace(r.Action.Tag) == "" {
			return fmt.Errorf("%s[%d].action must contain at least one action", prefix, i)
		}
	}
	return nil
}

func isEmptyRuleMatch(m RuntimeRuleMatch) bool {
	return strings.TrimSpace(m.ProcessExe) == "" &&
		strings.TrimSpace(m.ProcessName) == "" &&
		strings.TrimSpace(m.FilePath) == "" &&
		strings.TrimSpace(m.Account) == "" &&
		strings.TrimSpace(m.RemoteIP) == "" &&
		strings.TrimSpace(m.Protocol) == "" &&
		m.DstPort == 0 &&
		strings.TrimSpace(m.ServiceUnit) == "" &&
		strings.TrimSpace(m.LabelKey) == "" &&
		strings.TrimSpace(m.LabelValue) == ""
}
