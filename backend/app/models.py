from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Text, Float, func
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from .database import Base
import datetime

class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True)
    role_name = Column(String, unique=True, nullable=False) # admin, user
    description = Column(String)

    # User와의 관계 설정
    users = relationship("User", back_populates="role")

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    role_id = Column(Integer, ForeignKey("roles.id"))
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False) # 평문이 아닌 해시값 저장
    full_name = Column(String)
    affiliation = Column(String)
    department = Column(String)
    phone = Column(String)
    email = Column(String, unique=True, index=True)
    last_login = Column(DateTime(timezone=True), onupdate=func.now())
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    role = relationship("Role", back_populates="users")

class TopAlert(Base):
    __tablename__ = "top_alerts"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String, unique=True, index=True) # OS 원본 로그 ID
    severity = Column(String)       # CRITICAL, HIGH
    alert_name = Column(String)     # 알람명 (예: 랜섬웨어 의심 행위)
    host_info = Column(String)      # 호스트명 (IP)
    event_time = Column(DateTime)   # 발생 시간
    status = Column(String, default="pending") # 관리 상태: pending, analyzing, resolved
    description = Column(Text, nullable=True)  # 분석 결과 메모

class Assets(Base):
    __tablename__ = "Assets"

    id = Column(Integer, primary_key=True, index=True)
    
    # 기본 정보
    hostname = Column(String, index=True, nullable=False)
    ip_address = Column(String, nullable=False)
    os_info = Column(String)  # 예: Ubuntu 22.04.3 LTS
    
    # 상태 및 메트릭 (목업 반영)
    # status: '정상', '주의', '위험', '오프라인' 등으로 관리
    status = Column(String, default="오프라인")
    cpu_usage = Column(Float, default=0.0)      # % 단위
    memory_usage = Column(Float, default=0.0)   # % 단위
    risk_score = Column(Integer, default=0)     # 0 ~ 100 점수
    unassigned_alerts_count = Column(Integer, default=0) # 미배정 알람 수
    
    # 통신 관련
    last_heartbeat = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    def __repr__(self):
        return f"<Agent(hostname={self.hostname}, ip={self.ip_address}, status={self.status})>"