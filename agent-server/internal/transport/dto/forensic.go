package dto

// // 이 코드는 분석 서버(FastAPI)가 에이전트에게 내려주는 JSON 데이터의 생김새(틀)를 Go 언어에서 읽을 수 있도록 미리 정의함

// // CommandItem은 서버에서 내려주는 단일 명령 객체
// type CommandItem struct {
// 	Action string `json:"action"` // 예: "avml_dump"
// 	Reason string `json:"reason"`
// }

// // CommandFetchResponse는 폴링 시 서버가 반환하는 응답 구조체입니다.
// type CommandFetchResponse struct {
// 	AgentID  string        `json:"agent_id"`
// 	Commands []CommandItem `json:"commands"`
// }
