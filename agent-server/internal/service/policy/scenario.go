package policy

import "github.com/suhyeon514/eBPF_Project/internal/model"

func AnalyzeScenario(events []model.Event) (float64, []string) {

	var bonus float64
	var patterns []string

	sensitiveAccess := false
	privEsc := false

	for _, ev := range events {

		if ev.File != nil {
			if ev.File.Path == "/etc/shadow" || ev.File.Path == "/etc/passwd" {
				sensitiveAccess = true
			}
		}

		if ev.Process != nil {
			if ev.Process.Comm == "sudo" || ev.Process.Comm == "su" {
				privEsc = true
			}
		}

		if sensitiveAccess && ev.Network != nil {
			bonus += 30
			patterns = append(patterns, "DATA_EXFILTRATION")
		}

		if sensitiveAccess && privEsc {
			bonus += 40
			patterns = append(patterns, "FULL_COMPROMISE")
		}
	}

	return bonus, patterns
}
