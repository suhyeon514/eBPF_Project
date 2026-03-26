package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

// CalculateFileHash는 지정된 경로의 파일을 청크 단위로 읽어 SHA-256 해시값을 반환합니다.
// 분석 서버(Python)의 hashlib.sha256() 및 f.read(4096) 로직과 완벽하게 호환됩니다.
func CalculateFileHash(filePath string) (string, error) {
	// 1. 바이너리 모드로 파일 열기 (Python의 "rb"와 동일)
	file, err := os.Open(filePath)
	if err != nil {
		// 파일이 없으면 에러를 반환합니다.
		// (호출하는 service 계층에서 이 에러를 받으면 "서버에 정책 업데이트 요청"을 하도록 유도)
		return "", err
	}
	defer file.Close()

	// 2. SHA-256 해시 객체 생성
	hash := sha256.New()

	// 3. 청크(Chunk) 단위로 읽어서 해시 계산 (메모리 절약)
	// io.Copy는 내부적으로 32KB 버퍼를 사용하여 파일을 안전하게 스트리밍합니다.
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	// 4. 계산된 바이트 배열을 16진수(Hex) 문자열로 변환 (Python의 .hexdigest()와 동일)
	hashInBytes := hash.Sum(nil)
	return hex.EncodeToString(hashInBytes), nil
}
