package forensics

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// RunAVMLDump는 OS에 설치된 AVML 도구를 이용해 물리 메모리를 덤프합니다.
// 웹소켓 수신부에서 go RunAVMLDump(...) 형태로 비동기 호출되어야 합니다.
func RunAVMLDump(reason string, dumpDir string) {
	log.Printf("🛠️ [AVML 실행] 메모리 덤프 작업을 준비합니다. (사유: %s)\n", reason)

	// 덤프 파일을 저장할 안전한 디렉토리에 대한 검증 및 생성
	// YAML에서 읽어온 dumpDir 경로로 폴더 생성 시도
	if err := os.MkdirAll(dumpDir, 0750); err != nil {
		log.Printf("❌ [AVML 에러] 덤프 저장 디렉토리 생성 실패: %v\n", err)
		return
	}
	// 2. 덮어쓰기 방지를 위한 타임스탬프 기반 파일명 생성
	timestamp := time.Now().Format("20060102_150405")
	fileName := fmt.Sprintf("memory_dump_%s.lime", timestamp)
	outputPath := filepath.Join(dumpDir, fileName)

	log.Printf("⏳ [AVML 진행] 덤프를 시작합니다. (저장 경로: %s) 용량에 따른 소요 시간 발생\n", outputPath)

	// 3. 실제 OS 명령어 실행 준비 (Microsoft AVML 바이너리 호출) 터미널에서 `avml /tmp/forensics/memory_dump_...lime` 역할.
	cmd := exec.Command("avml", outputPath)

	// 4. 명령어 실행 및 끝날 때까지 대기 (CombinedOutput은 표준 출력과 에러를 모두 캡처합니다)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("❌ [AVML 에러] 메모리 덤프 실패: %v\n상세 로그: %s\n", err, string(output))
		// (선택) 여기서 분석 서버로 "덤프 실패했습니다"라는 상태 API를 보낼 수도 있습니다.
		return
	}

	// 5. 성공 로그 출력
	log.Printf("✅ [AVML 완료] 메모리 덤프 성공! (저장 경로: %s)\n파일 크기를 확인 필요\n", outputPath)

	// (선택) 여기서 분석 서버로 "덤프 완료. 파일 업로드 대기 중" 이라는 상태 API를 보낼 수 있습니다.
}
