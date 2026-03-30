package policy

import (
	"strings"

	"github.com/suhyeon514/eBPF_Project/internal/model"
)

type Result struct {
	Score int
	Rule  string
}

// 🔥 이름 변경 (Evaluate → EvaluateBase)
func EvaluateBase(event model.Event) Result {

	// 1. 민감 파일
	if event.EventType == model.EventFileOpen && event.File != nil {
		path := event.File.Path

		if strings.Contains(path, "/etc/shadow") {
			return Result{Score: 90, Rule: "sensitive_file"}
		}

		if strings.Contains(path, "/etc/passwd") {
			return Result{Score: 40, Rule: "important_file"}
		}
	}

	// 2. 외부 네트워크
	if event.EventType == model.EventNetConnect && event.Network != nil {
		if !isPrivateIP(event.Network.DstIP) {
			return Result{Score: 70, Rule: "external_connection"}
		}
	}

	// 3. 쉘 실행
	if event.EventType == model.EventProcessExec && event.Process != nil {
		if strings.Contains(event.Process.Comm, "bash") ||
			strings.Contains(event.Process.Comm, "sh") {
			return Result{Score: 30, Rule: "shell_execution"}
		}
	}

	return Result{}
}

func isPrivateIP(ip string) bool {
	return strings.HasPrefix(ip, "10.") ||
		strings.HasPrefix(ip, "192.168.") ||
		strings.HasPrefix(ip, "172.")
}
