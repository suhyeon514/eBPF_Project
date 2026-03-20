package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

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

	return &cfg, nil
}
