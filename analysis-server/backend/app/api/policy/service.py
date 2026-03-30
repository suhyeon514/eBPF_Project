import hashlib
from pathlib import Path

# ==========================================
# 🔥 정책 파일 경로 (고정 - env 완전 무시)
# ==========================================
POLICY_FILE_PATH = Path(__file__).resolve().parent / "policy.yaml"


# ==========================================
# 🔥 정책 해시 계산
# ==========================================
def get_current_policy_hash() -> str:
    """
    policy.yaml 파일의 SHA-256 해시값 반환
    """
    if not POLICY_FILE_PATH.exists():
        print(f"❌ policy.yaml 없음: {POLICY_FILE_PATH}")
        return ""

    sha256_hash = hashlib.sha256()

    with open(POLICY_FILE_PATH, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)

    return sha256_hash.hexdigest()


# ==========================================
# 🔥 정책 데이터 반환 (핵심)
# ==========================================
def get_policy_data() -> str:
    """
    YAML 파일을 문자열 그대로 반환 (Agent에서 파싱)
    """

    # 🔥 디버깅 로그
    print("🔥 POLICY PATH:", POLICY_FILE_PATH)
    print("🔥 EXISTS:", POLICY_FILE_PATH.exists())

    if not POLICY_FILE_PATH.exists():
        raise FileNotFoundError(f"policy.yaml 없음: {POLICY_FILE_PATH}")

    with open(POLICY_FILE_PATH, "r", encoding="utf-8") as f:
        data = f.read()

    print("🔥 POLICY CONTENT:\n", data)

    return data
