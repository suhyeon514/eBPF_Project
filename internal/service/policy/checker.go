package policy

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	// "gopkg.in/yaml.v3"

	"github.com/suhyeon514/eBPF_Project/internal/crypto"
	"github.com/suhyeon514/eBPF_Project/internal/transport/dto"
)

// APIClient 인터페이스: HTTP 통신의 구체적인 방법은 몰라도 되며, 오직 "요청을 주면 응답을 돌려준다"는 계약(Contract)만 정의
type APIClient interface {
	CheckPolicyUpdate(req dto.PolicyCheckRequest) (*dto.PolicyCheckResponse, error)
}

// Service는 정책 동기화 비즈니스 로직을 관리하는 구조체입니다.
type Service struct {
	apiClient  APIClient
	policyPath string // 예: "/opt/ebpf-agent/policies/policy.yaml"
}

// NewService는 Service 구조체를 초기화하여 반환합니다.
func NewService(client APIClient, path string) *Service {
	return &Service{
		apiClient:  client,
		policyPath: path,
	}
}

// CheckAndSync는 주기적으로(예: 60초) 호출되어 정책을 검증하고 동기화
// 반환값 bool이 true이면 정책이 변경된 것이므로, 호출자가 eBPF 룰을 리로드해야 합니다.
func (s *Service) CheckAndSync() (bool, error) {
	// 1. 로컬 정책 파일의 해시 계산
	localHash, err := crypto.CalculateFileHash(s.policyPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Println("로컬 정책 파일이 없습니다. 서버에 전체 동기화를 요청합니다.")
			localHash = "" // 빈 문자열을 보내면 서버가 무조건 업데이트를 지시합니다.
		} else {
			return false, fmt.Errorf("로컬 해시 계산 실패: %w", err)
		}
	}

	// 2. 서버에 보낼 요청 DTO 생성
	req := dto.PolicyCheckRequest{
		AgentHash: localHash,
	}

	// 3. 서버에 정책 검증 요청 (인터페이스 활용)
	resp, err := s.apiClient.CheckPolicyUpdate(req)
	if err != nil {
		return false, fmt.Errorf("분석 서버와 통신 실패: %w", err) //여기 오류
	}

	// 4. 업데이트가 필요 없는 경우 종료
	if !resp.UpdateRequired {
		log.Printf("[분석 서버 반환 값(유지)]: %s\n", resp.Message)
		return false, nil
	}

	log.Printf("[분석 서버 반환 값(업데이트)]: %s\n", resp.Message)

	// 5. 서버로부터 받은 새로운 정책을 로컬 YAML 파일로 덮어쓰기
	if err := s.savePolicyToFile(resp.NewPolicy); err != nil {
		return false, fmt.Errorf("새 정책 파일 저장 실패: %w", err)
	}

	log.Println("✅ 새로운 정책 파일이 성공적으로 적용되었습니다.")
	return true, nil // true를 반환하여 agent_app.go가 eBPF 센서를 재시작하도록 알림
}

// // savePolicyToFile은 map 데이터를 YAML 형식으로 변환하여 파일에 저장합니다.
// func (s *Service) savePolicyToFile(policyData map[string]interface{}) error {
// 	// map 데이터를 YAML 바이트 배열로 변환
// 	yamlBytes, err := yaml.Marshal(policyData)
// 	if err != nil {
// 		return err
// 	}

// 	// 저장할 디렉토리가 없으면 생성 (예: policies 폴더)
// 	dir := filepath.Dir(s.policyPath)
// 	if err := os.MkdirAll(dir, 0755); err != nil {
// 		return err
// 	}

// 	// 덮어쓰기 (권한 0644: 소유자 읽기/쓰기, 그룹/기타 읽기)
// 	return os.WriteFile(s.policyPath, yamlBytes, 0644)
// }

// savePolicyToFile은 서버에서 받은 순수 YAML 텍스트 문자열을 파일에 그대로 저장합니다.
func (s *Service) savePolicyToFile(policyData string) error {
	// 1. 저장할 디렉토리가 없으면 생성 (예: policies 폴더)
	dir := filepath.Dir(s.policyPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// 2. 서버에서 받은 순수 텍스트(string)를 바이트 배열([]byte)로 변환하여 즉시 덮어쓰기
	// (권한 0644: 소유자 읽기/쓰기, 그룹/기타 읽기)
	return os.WriteFile(s.policyPath, []byte(policyData), 0644)
}
