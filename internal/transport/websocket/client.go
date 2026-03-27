package ws

import (
	"encoding/json"
	"log"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	forensics "github.com/suhyeon514/eBPF_Project/internal/action"
)

type CommandMessage struct {
	Action string `json:"action"`
	Reason string `json:"reason"`
}

// StartWebSocketListener는 서버와 연결을 맺고 무한히 명령을 기다립니다.
func StartWebSocketListener(wsURL string, agentID string, dumpDir string) {
	// 🔥 [추가] 일반 HTTP/HTTPS 주소가 들어오면 자동으로 WebSocket 스킴으로 변환합니다.
	wsURL = strings.Replace(wsURL, "http://", "ws://", 1)
	wsURL = strings.Replace(wsURL, "https://", "wss://", 1)

	url := wsURL + "/api/v1/forensic/websocket/" + agentID

	for { // 재연결을 위한 바깥쪽 무한 루프
		log.Printf("🔌 [WebSocket] 분석 서버(%s) 연결 시도 중. 에이전트 ID: %s\n", url, agentID)

		conn, _, err := websocket.DefaultDialer.Dial(url, nil)
		if err != nil {
			log.Printf("❌ [WebSocket] 연결 실패: %v. 5초 후 재시도합니다.\n", err)
			time.Sleep(5 * time.Second)
			continue
		}

		log.Println("✅ [WebSocket] 실시간 명령 수신 대기 통로 확보!")

		// 메시지 수신용 안쪽 무한 루프 (수화기 들고 대기)
		for {
			_, message, err := conn.ReadMessage()
			if err != nil {
				log.Printf("⚠️  [WebSocket] 서버와 연결이 끊어졌습니다: %v\n", err)
				conn.Close()
				break // 안쪽 루프를 빠져나가 바깥쪽 루프에서 재연결 시도
			}

			// 🔥 [디버그 1] 서버가 보낸 원본 메시지를 무조건 출력해 봅니다.
			log.Printf("📩 [디버그] 서버로부터 메시지 수신: %s\n", string(message))

			// 서버가 보낸 JSON 명령 파싱
			var cmd CommandMessage
			err = json.Unmarshal(message, &cmd)
			if err != nil {
				// 🔥 [디버그 2] 파싱 에러가 났을 때 로그 출력
				log.Printf("❌ [디버그] JSON 파싱 에러: %v\n", err)
				continue
			}

			// 🔥 [수정] 언더바(_)와 하이픈(-) 모두 대비하여 확인합니다!
			if cmd.Action == "avml_dump" || cmd.Action == "avml-dump" {
				log.Printf("🚨 [웹소켓 수신] AVML 덤프 즉시 실행! (사유: %s)\n", cmd.Reason)

				// eBPF 엔진이 멈추지 않도록 무조건 goroutine으로 실행
				go forensics.RunAVMLDump(cmd.Reason, dumpDir)
			} else {
				// 🔥 [디버그 3] Action 이름이 다를 때 로그 출력
				log.Printf("⚠️ [디버그] 처리할 수 없는 Action 명령입니다: '%s'\n", cmd.Action)
			}
		}
	}
}
