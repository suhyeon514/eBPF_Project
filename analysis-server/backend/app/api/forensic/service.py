# backend/app/api/forensic/service.py

import yaml
import hashlib
from pathlib import Path

# ===============================
# 📌 policy.yaml 경로 설정
# ===============================
CURRENT_DIR = Path(__file__).resolve().parent
POLICY_FILE_PATH = CURRENT_DIR.parent / "policy" / "policy.yaml"

# ===============================
# 📌 AVML (기존 기능 유지)
# ===============================
def send_avml_dump_command(agent_id: str, reason: str) -> bool:
    print(f"[분석 서버 Backend 측] AVML 덤프 명령 발생 - 대상 에이전트: {agent_id}, 사유: {reason}")
    return True


# ===============================
# 📌 현재 정책 읽기
# ===============================
def get_policy_data() -> str:
    try:
        with open(POLICY_FILE_PATH, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        raise FileNotFoundError(f"policy.yaml 없음: {POLICY_FILE_PATH}")


# ===============================
# 📌 정책 해시 계산
# ===============================
def get_policy_hash() -> str:
    sha256_hash = hashlib.sha256()

    try:
        with open(POLICY_FILE_PATH, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)

        return sha256_hash.hexdigest()

    except FileNotFoundError:
        return ""


# ===============================
# 📌 정책 추가/삭제 (핵심)
# ===============================
def update_policy(category: str, item: str, action: str) -> bool:
    """
    category: 'deny' or 'focus'
    item: 문자열 (ex: "curl", "/etc/shadow")
    action: 'add' or 'delete'
    """

    if category not in ["deny", "focus"]:
        raise ValueError("category must be 'deny' or 'focus'")

    # 파일 없으면 기본 구조 생성
    if not POLICY_FILE_PATH.exists():
        data = {"version": 1.0, "deny": [], "focus": []}
    else:
        with open(POLICY_FILE_PATH, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

    # 키 없으면 생성
    if category not in data:
        data[category] = []

    # ===== add =====
    if action == "add":
        if item not in data[category]:
            data[category].append(item)

    # ===== delete =====
    elif action == "delete":
        if item in data[category]:
            data[category].remove(item)

    else:
        raise ValueError("action must be 'add' or 'delete'")

    # 파일 저장
    with open(POLICY_FILE_PATH, "w", encoding="utf-8") as f:
        yaml.dump(data, f, allow_unicode=True, sort_keys=False)

    print(f"✅ policy updated: {category} {action} → {item}")
    return True


# ===============================
# 📌 정책 리스트 조회 (대시보드용)
# ===============================
def get_policy_list() -> dict:
    if not POLICY_FILE_PATH.exists():
        return {"version": 1.0, "deny": [], "focus": []}

    with open(POLICY_FILE_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)
