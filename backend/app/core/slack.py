import os

import requests as http_requests


def _get_webhook_url() -> str:
    return os.getenv("SLACK_WEBHOOK_URL", "")


def _get_base_url() -> str:
    return os.getenv("SERVER_BASE_URL", "http://localhost:8000").rstrip("/")


def send_enroll_request_notification(record) -> None:
    """등록 요청 수신 시 Slack 채널에 알림 전송 (fire-and-forget)."""
    webhook_url = _get_webhook_url()
    if not webhook_url:
        return

    base_url = _get_base_url()
    req_id = record.request_id
    approve_url = f"{base_url}/api/v1/enroll/approve?token={record.approve_token}"
    reject_url  = f"{base_url}/api/v1/enroll/reject?token={record.reject_token}"

    text = (
        f"🔔 *새 에이전트 등록 요청*\n\n"
        f"• *요청 ID* : `{req_id}`\n"
        f"• *호스트*  : `{record.hostname}`\n"
        f"• *OS*      : `{record.os_id} {record.os_version}`\n"
        f"• *머신 ID* : `{record.machine_id}`\n"
        f"• *요청 역할* : `{record.requested_role or '-'}`\n"
        f"• *요청 환경* : `{record.requested_env or '-'}`\n\n"
        f"<{approve_url}|✅ 승인하기>   <{reject_url}|❌ 거부하기>"
    )

    payload = {
        "blocks": [
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": text},
            }
        ]
    }

    try:
        resp = http_requests.post(webhook_url, json=payload, timeout=5)
        if resp.status_code != 200:
            print(f"[Slack] 알림 전송 실패: {resp.status_code} {resp.text}")
    except Exception as e:
        print(f"[Slack] 알림 전송 오류: {e}")
