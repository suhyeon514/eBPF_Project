package forensics

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	appconfig "github.com/suhyeon514/eBPF_Project/internal/config"
)

// UploadDumpToS3는 거대한 덤프 파일을 S3 버킷에 멀티파트로 업로드합니다.
func UploadDumpToS3(ctx context.Context, s3info appconfig.S3DumpInfoConfig, outputPath string, agentID string) error {
	// 1. 전송할 로컬 파일 열기
	file, err := os.Open(outputPath)
	if err != nil {
		return fmt.Errorf("덤프 파일 열기 실패: %w", err)
	}
	defer file.Close()

	// ⭐️ 수정: 인증 정보(Credentials) 명시적 주입
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(s3info.S3Region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			s3info.S3AccessKeyID,
			s3info.S3SecretAccessKey,
			"", // 세션 토큰이 필요한 경우 여기에 입력
		)),
	)
	if err != nil {
		return fmt.Errorf("AWS 설정 로드 실패: %w", err)
	}

	// 3. S3 클라이언트 및 Uploader(멀티파트 매니저) 생성
	client := s3.NewFromConfig(cfg)
	uploader := manager.NewUploader(client, func(u *manager.Uploader) {
		u.PartSize = 10 * 1024 * 1024 // 10MB 단위로 쪼개서 전송 (메모리 최적화)
		u.Concurrency = 5             // 5개 쓰레드로 동시 전송 (속도 극대화)
	})

	// S3에 저장될 경로 설정 (예: forensics/agent-001/20260329_dump.avml)
	fileName := filepath.Base(outputPath)
	s3Key := fmt.Sprintf("forensics/%s/%s", agentID, fileName)

	log.Printf("🚀 S3 업로드 시작... (대상: %s)\n", s3Key)

	// 4. 업로드 실행
	_, err = uploader.Upload(ctx, &s3.PutObjectInput{
		Bucket: aws.String(s3info.S3BucketName),
		Key:    aws.String(s3Key),
		Body:   file,
	})

	if err != nil {
		return fmt.Errorf("S3 멀티파트 업로드 실패: %w", err)
	}

	log.Println("✅ S3 업로드 성공!")
	return nil
}
