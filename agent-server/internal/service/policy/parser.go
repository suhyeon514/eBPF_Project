package policy

import (
	"gopkg.in/yaml.v3"
)

// 🔥 YAML 구조 대응
type PolicyFile struct {
	Deny struct {
		Process []string `yaml:"process"`
		File    []string `yaml:"file"`
	} `yaml:"deny"`

	Focus struct {
		File []string `yaml:"file"`
	} `yaml:"focus"`
}

// 🔥 YAML → Go 변환
func ParsePolicy(data string) (*PolicyFile, error) {
	var p PolicyFile

	err := yaml.Unmarshal([]byte(data), &p)
	if err != nil {
		return nil, err
	}

	return &p, nil
}
