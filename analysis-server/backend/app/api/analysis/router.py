from fastapi import APIRouter
from app.models import Event
from app.services import policy_engine, risk_engine, scenario_engine
from fastapi import Depends
from sqlalchemy.orm import Session
from app.database import get_db

router = APIRouter(prefix="/analysis")

event_buffer = {}

@router.post("/event")
def analyze_event(event: Event):

    # 1. 정책
    base_score, rule, mitre = policy_engine.evaluate(event)

    # 2. 공식
    risk_score = risk_engine.calculate_risk(event, base_score, mitre)

    # 3. 버퍼
    buf = event_buffer.setdefault(event.host_id, [])
    buf.append(event.dict())
    buf = buf[-10:]
    event_buffer[event.host_id] = buf

    # 4. 시나리오
    scenario_bonus, patterns = scenario_engine.analyze_sequence(buf)

    # 5. 최종
    final_score = min(risk_score + scenario_bonus, 100)

    return {
        "risk_score": final_score,
        "rule": rule,
        "mitre": mitre,
        "patterns": patterns
    }
