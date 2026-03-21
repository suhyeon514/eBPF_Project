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
		Enabled      bool          `yaml:"enabled"`
		LogPath      string        `yaml:"log_path"`
	} `yaml:"nginx"`
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

	return &cfg, nil
}
