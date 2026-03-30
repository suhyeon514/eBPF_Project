package dto

// PolicyCheckRequest는 에이전트가 분석 서버로 정책 해시를 보낼 때 사용하는 구조체입니다.
// 파이썬 백엔드의 `schemas.PolicyCheckUpdateRequest`와 1:1로 매칭됩니다.
type PolicyCheckRequest struct {
	AgentHash string `json:"agent_hash"`
}

// PolicyCheckResponse는 분석 서버가 에이전트에게 내려주는 응답 구조체입니다.
// FastAPI 라우터의 반환값 형식에 정확히 맞췄습니다.
type PolicyCheckResponse struct {
	// 업데이트가 필요한지 여부 (백엔드의 "update_required" 필드)
	UpdateRequired bool `json:"update_required"`

	// (선택) 업데이트가 필요할 때만 내려오는 새로운 해시값
	// omitempty를 사용하여 백엔드에서 값을 주지 않으면 생략되도록 처리합니다.
	NewHash string `json:"new_hash,omitempty"`

	// (선택) 업데이트가 필요할 때만 내려오는 새로운 정책 데이터 자체 (yaml/json 형태)
	// 정책 파일의 구조(Rules, Version 등)가 유연하게 변할 수 있으므로
	// 특정 구조체로 고정하지 않고 map[string]interface{}로 받아서 범용성을 높입니다.
	NewPolicy string `json:"new_policy,omitempty"`

	// 서버에서 보내주는 상태 메시지 ("가장 최신 정책을..." 또는 "새로운 보안 정책이...")
	Message string `json:"message"`
}
