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
	Host       RuntimeHostConfig       `yaml:"host"`
	Collectors RuntimeCollectorsConfig `yaml:"collectors"`
	Output     RuntimeOutputConfig     `yaml:"output"`
}

type RuntimeHostConfig struct {
	// 이벤트 메타데이터에 넣을 hostname
	Hostname string `yaml:"hostname"`
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

type RuntimeOutputConfig struct {
	NormalizedPath string `yaml:"normalized_path"`
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
	// host
	c.Host.Hostname = strings.TrimSpace(c.Host.Hostname)

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
		c.Collectors.Tetragon.PollInterval = 10 * time.Second
	}

	// output
	c.Output.NormalizedPath = strings.TrimSpace(c.Output.NormalizedPath)
}

func (c *RuntimeConfig) Validate() error {
	if strings.TrimSpace(c.Host.Hostname) == "" {
		return fmt.Errorf("host.hostname is required")
	}

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

	if enabledCount == 0 {
		return fmt.Errorf("at least one collector must be enabled")
	}

	return nil
}
