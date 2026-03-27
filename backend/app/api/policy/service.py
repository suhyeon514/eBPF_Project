import hashlib
import json
import os
import yaml
from pathlib import Path

# 개선 2: .env 파일에서 정책 파일 경로를 읽어옵니다
BASE_DIR = Path(__file__).resolve().parents[4]
policy_file_env = os.getenv("POLICY_FILE_PATH", "your_policy_path/policy.yaml")

print(f"정책 파일 경로: {BASE_DIR}/{policy_file_env}")

# .env의 경로가 상대 경로면 프로젝트 최상위 기준 절대 경로로 변환
if not Path(policy_file_env).is_absolute():
    POLICY_FILE_PATH = str(BASE_DIR / policy_file_env)
else:
    POLICY_FILE_PATH = policy_file_env

def get_current_policy_hash() -> str:
    """서버가 가지고 있는 최신 정책의 해시값을 계산합니다."""
    if os.path.exists(POLICY_FILE_PATH):
        sha256_hash = hashlib.sha256()
        with open(POLICY_FILE_PATH, "rb") as f:
            # 개선 1: 파일을 4KB(4096 bytes) 단위로 쪼개서 읽어 메모리 절약
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    # 파일이 없을 경우 개발 테스트용 임시 해시 반환
    dummy_policy = {"version": "1.0", "rules": ["block_bpfdoor_magic_packet"]}
    dummy_bytes = yaml.dump(dummy_policy).encode('utf-8')
    return hashlib.sha256(dummy_bytes).hexdigest()

def get_policy_data() -> str:
    """최신 정책 데이터를 반환합니다."""
    if os.path.exists(POLICY_FILE_PATH):
        with open(POLICY_FILE_PATH, "r", encoding="utf-8") as f:
            return f.read() # yaml 파싱 없이 원본 텍스트 그대로 반환

    dummy_policy = "version: 1.0\nrules:\n  - block_bpfdoor_magic_packet\n"
    return dummy_policy