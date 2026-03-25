package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// yaml 파일에서 선언한 설정 구조체 정의
type Config struct {
	HostID   string `yaml:"host_id"`
	Hostname string `yaml:"hostname"`
	Env      string `yaml:"env"`
	Role     string `yaml:"role"`

	Tetragon struct {
		LogPath      string        `yaml:"log_path"`
		PollInterval time.Duration `yaml:"poll_interval"`
		ReadFromHead bool          `yaml:"read_from_head"`
	} `yaml:"tetragon"`

	Journald struct {
		Enabled   bool     `yaml:"enabled"`
		Profiles  []string `yaml:"profiles"`
		TailLines int      `yaml:"tail_lines"`
	} `yaml:"journald"`

	Conntrack struct {
		Enabled       bool          `yaml:"enabled"`
		Args          []string      `yaml:"args"`
		RestartOnExit bool          `yaml:"restart_on_exit"`
		RestartDelay  time.Duration `yaml:"restart_delay"`
	} `yaml:"conntrack"`

	Nftables struct {
		Enabled      bool          `yaml:"enabled"`
		LogPath      string        `yaml:"log_path"`
		PollInterval time.Duration `yaml:"poll_interval"`
		ReadFromHead bool          `yaml:"read_from_head"`
		Prefixes     []string      `yaml:"prefixes"`
	} `yaml:"nftables"`

	Auditd struct {
		Enabled      bool          `yaml:"enabled"`
		LogPath      string        `yaml:"log_path"`
		PollInterval time.Duration `yaml:"poll_interval"`
		ReadFromHead bool          `yaml:"read_from_head"`
	} `yaml:"auditd"`

	Nginx struct {
		Enabled bool   `yaml:"enabled"`
		LogPath string `yaml:"log_path"`
	} `yaml:"nginx"`

	Resource struct {
		PollInterval time.Duration `yaml:"poll_interval"`
	} `yaml:"resource"`

	Output struct {
		NormalizedPath string `yaml:"normalized_path"`
	} `yaml:"output"`
}

func Load(path string) (*Config, error) {
	if path == "" {
		return nil, fmt.Errorf("config path is empty")
	}

	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	if cfg.HostID == "" {
		return nil, fmt.Errorf("host_id is required")
	}

	if cfg.Hostname == "" {
		return nil, fmt.Errorf("hostname is required")
	}

	if cfg.Env == "" {
		return nil, fmt.Errorf("env is required")
	}

	if cfg.Role == "" {
		return nil, fmt.Errorf("role is required")
	}

	if cfg.Tetragon.LogPath == "" {
		return nil, fmt.Errorf("tetragon.log_path is required")
	}

	if cfg.Output.NormalizedPath == "" {
		return nil, fmt.Errorf("output.normalized_path is required")
	}

	if cfg.Tetragon.PollInterval <= 0 {
		cfg.Tetragon.PollInterval = 1 * time.Second
	}

	if cfg.Journald.Enabled {
		if len(cfg.Journald.Profiles) == 0 {
			cfg.Journald.Profiles = []string{"sshd", "sudo", "su", "systemd"}
		}
		if cfg.Journald.TailLines <= 0 {
			cfg.Journald.TailLines = 0
		}
	}

	if cfg.Auditd.Enabled {
		if cfg.Auditd.LogPath == "" {
			cfg.Auditd.LogPath = "/var/log/audit/audit.log"
		}
		if cfg.Auditd.PollInterval <= 0 {
			cfg.Auditd.PollInterval = 1 * time.Second
		}
	}
	if cfg.Conntrack.Enabled {
		if cfg.Conntrack.Args == nil {
			cfg.Conntrack.Args = []string{"-E", "-o", "timestamp,extended"}
		}
		if cfg.Conntrack.RestartDelay <= 0 {
			cfg.Conntrack.RestartDelay = 2 * time.Second
		}
	}
	if cfg.Nftables.Enabled {
		if cfg.Nftables.LogPath == "" {
			cfg.Nftables.LogPath = "/var/log/kern.log"
		}
		if cfg.Nftables.PollInterval <= 0 {
			cfg.Nftables.PollInterval = 1 * time.Second
		}
		if len(cfg.Nftables.Prefixes) == 0 {
			cfg.Nftables.Prefixes = []string{"NFT_DROP", "NFT_ACCEPT", "NFT_TRACE", "NFT_LOG", "NFT_REJECT", "NFT_INVALID", "IPTABLES_DROP", "IPTABLES_REJECT", "IPTABLES_ACCEPT", "[UFW BLOCK]", "[UFW ALLOW]", "[UFW REJECT]"}
		}
	}
	if cfg.Nginx.Enabled {
		if cfg.Nginx.LogPath == "" {
			cfg.Nginx.LogPath = "/var/log/nginx/access.log"
		}
	}
	if cfg.Resource.PollInterval <= 0 {
		cfg.Resource.PollInterval = 1 * time.Minute
	}

	return &cfg, nil
}
