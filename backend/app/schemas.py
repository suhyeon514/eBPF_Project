from pydantic import BaseModel, Field
from typing import Optional, List, Any
from datetime import datetime
from enum import Enum

# --- [1] 공통 하위 객체들 ---

class HostInfo(BaseModel):
    host_id: str
    hostname: str
    env: str
    role: str

class CollectorInfo(BaseModel):
    name: str
    source_type: str

class RawRef(BaseModel):
    source: str
    raw_type: str
    raw_event_id: Optional[str] = None

# --- [2] 이벤트 타입별 알맹이(Payload) ---

class ProcessDetails(BaseModel):
    pid: int
    ppid: int
    comm: str
    exe: str
    args: Optional[List[str]] = None
    uid: int
    gid: int
    cwd: Optional[str] = None
    duration_ms: Optional[int] = None
    exec_id: Optional[str] = None
    parent_comm: Optional[str] = None
    parent_exe: Optional[str] = None

class NetworkDetails(BaseModel):
    protocol: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    action: str
    tcp_flags: Optional[str] = None

class AuthDetails(BaseModel):
    method: str
    result: str

# --- [3] 최종 로그 스키마 (통합형) ---

class EDRLog(BaseModel):
    schema_version: str
    event_id: str
    event_type: str
    event_time: datetime
    host: HostInfo
    collector: CollectorInfo
    raw_ref: RawRef
    
    # 해당하지 않는 타입일 경우 None으로 들어옴
    process: Optional[ProcessDetails] = None
    network: Optional[NetworkDetails] = None
    auth: Optional[AuthDetails] = None
    labels: Optional[dict] = None

# --- 정책 확인 관련 스키마 ---
class PolicyCheckUpdateRequest(BaseModel):
    agent_hash: str = Field(..., description="에이전트가 현재 가지고 있는 정책 파일의 SHA-256 해시값")

# -- 포렌식 명령 관련 스키마 --
class ForensicDumpRequest(BaseModel):
    agent_id: str # 필수 입력 값, 어느 에이전트에 포렌식 덤프를 명령할지
    reason: str = "Manual Trigger via Web" 

# --- [4] 기존 로그인 관련 스키마 (유지) ---

class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    username: str
    full_name: str
    role: str

class TopAlertResponse(BaseModel):
    id: int
    event_id: str
    severity: str
    alert_name: str
    host_info: str
    event_time: datetime
    status: str
    description: Optional[str] = None

    class Config:
        from_attributes = True

# --- [5] 에이전트 등록(Enrollment) 관련 스키마 ---

class EnrollResult(str, Enum):
    approved = "approved"
    pending  = "pending"
    rejected = "rejected"

class AgentFingerprint(BaseModel):
    machine_id: str
    hostname: str
    ip_address: Optional[str] = None
    os_id: str
    os_version: str
    cloud_instance_id: Optional[str] = None

class EnrollRequest(BaseModel):
    host_id: str
    install_uuid: str
    fingerprint: AgentFingerprint
    csr_pem: str
    requested_env: Optional[str] = None
    requested_role: Optional[str] = None

class EnrollResponse(BaseModel):
    result: EnrollResult
    request_id: str
    reason_code: Optional[str] = None
    message: Optional[str] = None
    agent_id: Optional[str] = None
    certificate_pem: Optional[str] = None
    assigned_env: Optional[str] = None
    assigned_role: Optional[str] = None

class EnrollStatusResponse(EnrollResponse):
    pass

class EnrollApproveRequest(BaseModel):
    agent_id: Optional[str] = None
    assigned_env: Optional[str] = None
    assigned_role: Optional[str] = None

class EnrollRejectRequest(BaseModel):
    reason_code: Optional[str] = None
    message: Optional[str] = None

class AgentHeartbeatRequest(BaseModel):
    hostname: str
    ip_address: str
    cpu_usage: float
    memory_usage: float
    os_info: Optional[str] = None


class EnrollmentRequestItem(BaseModel):
    request_id: str
    hostname: str
    os_id: str
    os_version: str
    status: str
    requested_env: Optional[str] = None
    requested_role: Optional[str] = None
    assigned_env: Optional[str] = None
    assigned_role: Optional[str] = None
    agent_id: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


# --- [6] 런타임 정책 관련 스키마 ---

class RuntimePolicyResponse(BaseModel):
    policy_yaml: str
    assigned_env: Optional[str] = None
    assigned_role: Optional[str] = None


class DetectionRuleBase(BaseModel):
    target_topic: str
    category: Optional[str] = None
    rule_name: str
    conditions: Any  # JSONB 대응
    detection_method: str = "simple"
    base_score: int = 0
    severity: str
    mitre_technique_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    reference_url: Optional[str] = None
    is_active: bool = True
    description: Optional[str] = None

class DetectionRuleCreate(DetectionRuleBase):
    pass

class DetectionRule(DetectionRuleBase):
    rule_id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True # SQLAlchemy 모델을 Pydantic으로 자동 변환

class ProcessNode(BaseModel):
    id: str         # Neo4j의 exec_id 혹은 고유값
    label: str      # 화면에 표시될 이름 (예: comm)
    pid: int
    risk_score: float
    severity: str
    cmd: str        # 상세 정보용 인자값

class ProcessEdge(BaseModel):
    source: str     # 부모의 id
    target: str     # 자식의 id
    type: str = "CHILDREN"

class GraphResponse(BaseModel):
    nodes: List[ProcessNode]
    edges: List[ProcessEdge]