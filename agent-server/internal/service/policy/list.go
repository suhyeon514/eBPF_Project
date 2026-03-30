package policy

import (
	"log"
	"strings"
	"sync"

	"github.com/suhyeon514/eBPF_Project/internal/model"
)

type Rule struct {
	Type  string // deny / focus
	Field string // file / process / network
	Value string
}

var (
	mu    sync.RWMutex
	rules []Rule
)

// ==========================================
// 🔥 정책 업데이트 (구조 기반)
// ==========================================
func UpdatePolicy(p *PolicyFile) {
	mu.Lock()
	defer mu.Unlock()

	var newRules []Rule

	// 🔴 deny - process
	for _, v := range p.Deny.Process {
		v = strings.TrimSpace(strings.ToLower(v))
		if v == "" {
			continue
		}

		newRules = append(newRules, Rule{
			Type:  "deny",
			Field: "process",
			Value: v,
		})
	}

	// 🔴 deny - file
	for _, v := range p.Deny.File {
		v = strings.TrimSpace(strings.ToLower(v))
		if v == "" {
			continue
		}

		newRules = append(newRules, Rule{
			Type:  "deny",
			Field: "file",
			Value: v,
		})
	}

	// 🟡 focus - file
	for _, v := range p.Focus.File {
		v = strings.TrimSpace(strings.ToLower(v))
		if v == "" {
			continue
		}

		newRules = append(newRules, Rule{
			Type:  "focus",
			Field: "file",
			Value: v,
		})
	}

	rules = newRules

	log.Println("🔥 UPDATED RULES:", rules)
}

// ==========================================
// 🔥 정책 평가
// ==========================================
func Evaluate(ev model.Event) (bool, bool) {

	mu.RLock()
	defer mu.RUnlock()

	denied := false
	focused := false

	for _, r := range rules {

		switch r.Field {

		case "process":
			if ev.Process != nil {
				comm := strings.ToLower(ev.Process.Comm)

				if strings.Contains(comm, r.Value) {
					if r.Type == "deny" {
						denied = true
					}
				}
			}

		case "file":
			if ev.File != nil {
				path := strings.ToLower(ev.File.Path)

				if strings.HasPrefix(path, r.Value) {
					if r.Type == "deny" {
						denied = true
					}
					if r.Type == "focus" {
						focused = true
					}
				}
			}

		case "network":
			if ev.Network != nil {
				if ev.Network.DstIP == r.Value {
					if r.Type == "deny" {
						denied = true
					}
				}
			}
		}
	}

	return denied, focused
}

// ==========================================
// 🔥 디버깅용
// ==========================================
func GetRules() []Rule {
	mu.RLock()
	defer mu.RUnlock()
	return rules
}
