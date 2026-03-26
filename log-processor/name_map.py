# log-processor/name_map.py

# 1. 단순 이름 변경 매핑 (Flattened Key -> Standard Key)
FIELD_MAPPING = {
    # 프로세스 관련 (Tetragon & Auditd)
    "process.exe": "target.process_path",
    "process.comm": "target.process_name",
    "process.args": "target.process_args",
    "process.parent_exe": "target.parent_path",
    
    # 네트워크 관련 (Network & Tetragon.network)
    "network.src_ip": "target.src_ip",
    "network.dst_ip": "target.dest_ip",
    "network.src_port": "target.src_port",
    "network.dst_port": "target.dest_port",
    
    # 인증 및 서비스 관련 (Auditd & Journald)
    "auth.method": "target.auth_method",
    "auth.result": "target.auth_result",
    "service.unit_name": "target.service_name",
    "service.state": "target.service_status",
    
    # 센서 및 공통
    "host.hostname": "target.hostname",
    "event_type": "target.event_type"
}

# 2. 복잡한 변환 로직 (예: IP 필드에 MAC이 들어있는 경우 등)
def transform_logic(f_log):
    # network.src_ip에 콜론(:)이 포함되어 있다면 MAC 주소로 간주하여 필드 수정
    if "network.src_ip" in f_log and ":" in str(f_log["network.src_ip"]):
        f_log["target.src_mac"] = f_log.pop("network.src_ip")
        
    # timestamp가 유닉스 타임(숫자)인 경우 읽기 좋은 포맷으로 추가
    if "@timestamp" in f_log and isinstance(f_log["@timestamp"], (int, float)):
        # 시각화 툴에서 인식하기 좋게 변환할 수 있음
        pass
        
    return f_log