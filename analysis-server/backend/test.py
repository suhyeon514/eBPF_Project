from app.seed import os_client
os_client.indices.delete(index='ebpf-logs-*', ignore=[400, 404])
print("✅ 기존 로그 데이터가 삭제되었습니다.")