package policy

import (
	"strings"

	"github.com/suhyeon514/eBPF_Project/internal/model"
)

// 🔴 무시 대상
var IgnoreProcesses = []string{
	"vscode-server",
}

func ShouldIgnore(event model.Event) bool {

	if event.Process != nil {
		for _, p := range IgnoreProcesses {
			if strings.Contains(event.Process.Comm, p) {
				return true
			}
		}
	}

	return false
}
