package healthcollector

import (
	"fmt"
	"time"

	"github.com/suhyeon514/eBPF_Project/internal/health"
	"github.com/suhyeon514/eBPF_Project/internal/model"
)

func Start(reg *health.Registry, out chan<- model.RawEnvelope) {
	//디버깅 용 출력
	fmt.Println("Health Collector started")

	go func() {
		// 🔥 즉시 1회 실행
		snap := reg.Snapshot()
		raw := model.NewRawEnvelope(
			model.RawSourceHealth,
			"snapshot",
			snap,
		)
		out <- raw

		ticker := time.NewTicker(30 * time.Second) // 30초마다 헬스 체크 스냅샷을 생성하여 출력
		defer ticker.Stop()

		for range ticker.C {
			snap := reg.Snapshot()

			raw := model.NewRawEnvelope(
				model.RawSourceHealth,
				"snapshot",
				snap,
			)

			out <- raw
		}
	}()
}
