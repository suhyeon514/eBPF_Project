package policy

import "github.com/suhyeon514/eBPF_Project/internal/model"

var MITREBonus = map[string]int{
	"INITIAL_ACCESS":        2,
	"PRIVILEGE_ESCALATION": 10,
	"CREDENTIAL_ACCESS":    12,
	"EXFILTRATION":         15,
	"IMPACT":               15,
}

var SensitivePaths = []string{
	"/etc/shadow",
	"/etc/passwd",
}

var SensitivePorts = []uint16{22, 4444, 8888}

func CalculateRisk(ev model.Event, baseScore int, mitre string) (float64, string) {

	if baseScore < 1 {
		baseScore = 1
	}

	target := 1.0

	// 파일
	if ev.File != nil {
		path := ev.File.Path
		for _, p := range SensitivePaths {
			if path == p {
				target = 1.2
			}
		}
	}

	// 네트워크
	if ev.Network != nil {
		for _, port := range SensitivePorts {
			if ev.Network.DstPort == port {
				if target < 1.1 {
					target = 1.1
				}
			}
		}
	}

	// 환경
	env := 1.0
	if ev.Process != nil && ev.Process.UID == 0 {
		env = 1.1
	}

	bonus := MITREBonus[mitre]

	score := (float64(baseScore) * target * env) + float64(bonus)

	if score > 100 {
		score = 100
	}

	severity := "LOW"
	if score >= 75 {
		severity = "CRITICAL"
	} else if score >= 50 {
		severity = "HIGH"
	} else if score >= 25 {
		severity = "MEDIUM"
	}

	return score, severity
}
