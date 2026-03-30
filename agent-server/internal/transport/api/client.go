package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/suhyeon514/eBPF_Project/internal/transport/dto"
)

// Client는 분석 서버와의 HTTP 통신을 전담하는 구조체입니다.
type Client struct {
	baseURL    string       // 예: "http://localhost:8000"
	httpClient *http.Client // 타임아웃 처리를 위한 커스텀 HTTP 클라이언트
	authToken  string       // 인증(Enrollment) 후 발급받은 JWT 토큰 (추후 사용)
}

// NewClient는 서버 주소와 타임아웃 시간을 받아 Client 구조체를 생성합니다.
func NewClient(baseURL string, timeout time.Duration) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: timeout, // 네트워크 무한 대기(Hang) 방지
		},
	}
}

// SetAuthToken은 추후 auth.Service에서 인증이 완료된 후 토큰을 주입할 때 사용합니다.
func (c *Client) SetAuthToken(token string) {
	c.authToken = token
}

// CheckPolicyUpdate는 분석 서버에 에이전트의 현재 정책 해시를 보내고, 업데이트 여부를 응답받습니다.
// (policy.APIClient 인터페이스의 구현체입니다)
func (c *Client) CheckPolicyUpdate(req dto.PolicyCheckRequest) (*dto.PolicyCheckResponse, error) {
	// 1. 요청 데이터를 JSON 바이트로 직렬화 (Marshal)
	jsonData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("요청 데이터 JSON 변환 실패: %w", err)
	}

	// 2. HTTP POST 요청 객체 생성
	endpoint := fmt.Sprintf("%s/api/v1/policy/check-update", c.baseURL)
	httpReq, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("HTTP 요청 객체 생성 실패: %w", err)
	}

	// 3. 필수 HTTP 헤더 설정 (FastAPI가 JSON으로 인식하도록)
	httpReq.Header.Set("Content-Type", "application/json")
	if c.authToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.authToken)
	}

	// 4. 실제 네트워크 요청 전송
	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("서버 API 호출 실패: %w", err)
	}
	defer httpResp.Body.Close() // 메모리 누수 방지

	// 5. 서버 응답 코드 확인 (200 OK가 아니면 에러 처리)
	if httpResp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(httpResp.Body)
		return nil, fmt.Errorf("서버 에러 응답 (상태코드: %d, 내용: %s)", httpResp.StatusCode, string(bodyBytes))
	}

	// 6. 서버의 JSON 응답을 DTO 구조체로 역직렬화 (Unmarshal)
	var resp dto.PolicyCheckResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
		return nil, fmt.Errorf("응답 데이터 파싱 실패: %w", err)
	}

	return &resp, nil
}

// // [AVML 덤프 관련 추가]
// // FetchCommands는 분석 서버에 에이전트(자신)에게 내려진 긴급 명령(예: AVML 덤프)이 있는지 확인
// func (c *Client) FetchCommands(agentID string) (*dto.CommandFetchResponse, error) {
// 	// 1. HTTP GET 요청 URL 생성 (Path Variable 방식)
// 	endpoint := fmt.Sprintf("%s/api/v1/forensic/commands/%s", c.baseURL, agentID)
// 	httpReq, err := http.NewRequest("GET", endpoint, nil) // GET 요청이므로 Body는 nil
// 	if err != nil {
// 		return nil, fmt.Errorf("명령 조회 HTTP 요청 객체 생성 실패: %w", err)
// 	}

// 	// 2. 필수 HTTP 헤더 설정 (추후 인증이 도입될 것을 대비)
// 	httpReq.Header.Set("Accept", "application/json")
// 	if c.authToken != "" {
// 		httpReq.Header.Set("Authorization", "Bearer "+c.authToken)
// 	}

// 	// 3. 실제 네트워크 요청 전송
// 	httpResp, err := c.httpClient.Do(httpReq)
// 	if err != nil {
// 		return nil, fmt.Errorf("명령 조회 API 호출 실패: %w", err)
// 	}
// 	defer httpResp.Body.Close() // 메모리 누수 방지

// 	// 4. 서버 응답 코드 확인 (200 OK가 아니면 에러 처리)
// 	if httpResp.StatusCode != http.StatusOK {
// 		bodyBytes, _ := io.ReadAll(httpResp.Body)
// 		return nil, fmt.Errorf("명령 조회 서버 에러 응답 (상태코드: %d, 내용: %s)", httpResp.StatusCode, string(bodyBytes))
// 	}

// 	// 5. 서버의 JSON 응답을 DTO 구조체로 역직렬화 (Unmarshal)
// 	var resp dto.CommandFetchResponse
// 	if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
// 		return nil, fmt.Errorf("명령 응답 데이터 파싱 실패: %w", err)
// 	}

// 	return &resp, nil
// }
