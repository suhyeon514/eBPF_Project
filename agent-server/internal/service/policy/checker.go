package policy

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/suhyeon514/eBPF_Project/internal/crypto"
	"github.com/suhyeon514/eBPF_Project/internal/transport/dto"
)

// ==========================================
// APIClient 인터페이스
// ==========================================
type APIClient interface {
	CheckPolicyUpdate(req dto.PolicyCheckRequest) (*dto.PolicyCheckResponse, error)
}

// ==========================================
// Service 구조체
// ==========================================
type Service struct {
	apiClient  APIClient
	policyPath string
}

// ==========================================
// 생성자
// ==========================================
func NewService(client APIClient, path string) *Service {
	return &Service{
		apiClient:  client,
		policyPath: path,
	}
}

// ==========================================
// 🔥 정책 동기화 + 즉시 반영
// ==========================================
func (s *Service) CheckAndSync() (bool, error) {

	// 1. 로컬 정책 해시 계산
	localHash, err := crypto.CalculateFileHash(s.policyPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Println("📢 로컬 정책 없음 → 전체 동기화 요청")
			localHash = ""
		} else {
			return false, fmt.Errorf("해시 계산 실패: %w", err)
		}
	}

	// 2. 서버 요청
	req := dto.PolicyCheckRequest{
		AgentHash: localHash,
	}

	resp, err := s.apiClient.CheckPolicyUpdate(req)
	if err != nil {
		return false, fmt.Errorf("서버 통신 실패: %w", err)
	}

	// 3. 업데이트 필요 없음
	if !resp.UpdateRequired {
		log.Printf("[정책 유지] %s\n", resp.Message)
		return false, nil
	}

	log.Printf("🚀 새로운 정책 수신: %s (Hash: %s)\n", resp.Message, resp.NewHash)

	if resp.NewPolicy == "" {
		return false, fmt.Errorf("NewPolicy 데이터가 비어있음")
	}

	// ==========================================
	// 4. 파일 저장
	// ==========================================
	dir := filepath.Dir(s.policyPath)

	if err := os.MkdirAll(dir, 0755); err != nil {
		return false, fmt.Errorf("디렉토리 생성 실패: %w", err)
	}

	if err := os.WriteFile(s.policyPath, []byte(resp.NewPolicy), 0644); err != nil {
		return false, fmt.Errorf("파일 저장 실패: %w", err)
	}

	// ==========================================
	// 5. 🔥 YAML 파싱 + 리스트 반영 (핵심)
	// ==========================================
	parsed, err := ParsePolicy(resp.NewPolicy)
	if err != nil {
		return false, fmt.Errorf("정책 파싱 실패: %w", err)
	}

	// 🔥🔥🔥 핵심 수정 (이거 하나가 전부)
	UpdatePolicy(parsed)

	log.Println("✅ 정책 적용 완료")
	log.Println("🔥 CURRENT POLICY:", parsed)
	log.Println("🔥 CURRENT RULES:", GetRules())

	return true, nil
}
