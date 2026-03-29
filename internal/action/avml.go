package forensics

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/suhyeon514/eBPF_Project/internal/config"
)

// type S3DumpInfoConfig struct {
// 	// AVML 덤프 파일 S3 업로드 시 사용할 버킷명
// 	S3BucketName string `yaml:"s3_bucket_name"`
// 	// AVML 덤프 파일 S3 업로드 시 사용할 리전
// 	S3Region string `yaml:"s3_region"`
// 	// AVML 덤프 파일 S3 업로드 시 사용할 액세스 키 ID
// 	S3AccessKeyID string `yaml:"s3_access_key_id"`
// 	// AVML 덤프 파일 S3 업로드 시 사용할 비밀 액세스 키
// 	S3SecretAccessKey string `yaml:"s3_secret_access_key"`
// }

// RunAVMLDump는 OS에 설치된 AVML 도구를 이용해 물리 메모리를 덤프합니다.
// 웹소켓 수신부에서 go RunAVMLDump(...) 형태로 비동기 호출되어야 합니다.
func RunAVMLDump(s3info config.S3DumpInfoConfig, reason string, dumpDir string, agentID string) {

	log.Printf("🛠️ [AVML 실행] 메모리 덤프 작업을 준비합니다. (사유: %s)\n", reason)

	// // BootstrapConfig 로드
	// cfg, err := config.LoadBootstrap(s3info)
	// if err != nil {
	// 	log.Printf("❌ [AVML 에러] 설정 파일 로드 실패: %v\n", err)
	// 	return
	// }

	// 덤프 파일을 저장할 안전한 디렉토리에 대한 검증 및 생성
	if err := os.MkdirAll(dumpDir, 0750); err != nil {
		log.Printf("❌ [AVML 에러] 덤프 저장 디렉토리 생성 실패: %v\n", err)
		return
	}

	// 덮어쓰기 방지를 위한 타임스탬프 기반 파일명 생성
	timestamp := time.Now().Format("20060102_150405")
	fileName := fmt.Sprintf("memory_dump_%s_%s.lime", agentID, timestamp)
	outputPath := filepath.Join(dumpDir, fileName)

	log.Printf("⏳ [AVML 진행] 덤프를 시작합니다. (저장 경로: %s) 용량에 따른 소요 시간 발생\n", outputPath)

	// 실제 OS 명령어 실행 준비 (Microsoft AVML 바이너리 호출)
	cmd := exec.Command("avml", outputPath)

	// 명령어 실행 및 끝날 때까지 대기
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("❌ [AVML 에러] 메모리 덤프 실패: %v\n상세 로그: %s\n", err, string(output))
		return
	}

	log.Printf("✅ [AVML 완료] 메모리 덤프 성공! (저장 경로: %s)\n파일 크기를 확인 필요\n", outputPath)

	// --- [여기서부터 S3 업로드 흐름 시작] ---
	ctx := context.Background()

	// S3로 전송 (멀티파트)
	// err = UploadDumpToS3(ctx, bucketName, region, accessKey, secretKey, outputPath, agentID)
	err = UploadDumpToS3(ctx, s3info, outputPath, agentID)
	if err != nil {
		log.Printf("❌ S3 업로드 에러: %v\n", err)
		return
	}

	rPath := filepath.Join(dumpDir, fileName)
	// 전송 완료 후 로컬 파일 삭제 (디스크 용량 확보 필수!)
	if err := os.Remove(rPath); err != nil {
		log.Printf("⚠️  로컬 덤프 파일 삭제 실패: %v\n", err)
	} else {
		log.Println("🧹  로컬 덤프 파일 정리 완료.[경로: " + rPath + "]")
	}
}
