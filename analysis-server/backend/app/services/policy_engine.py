from app import models

def evaluate(event, db):

    base_score = 0
    rule = "NORMAL"
    mitre = None

    rules = db.query(models.DetectionRule).filter(
        models.DetectionRule.is_active == True
    ).all()

    for r in rules:

        # file 이벤트
        if r.target_topic == "file" and event.event_type == "file":

            # conditions는 JSONB
            cond = r.conditions or {}

            if cond.get("path") == event.path:
                base_score = r.base_score
                rule = r.rule_name
                mitre = r.mitre_tactic

        # network 이벤트
        if r.target_topic == "network" and event.event_type == "network":

            cond = r.conditions or {}

            if cond.get("dest_port") == event.dest_port:
                base_score = r.base_score
                rule = r.rule_name
                mitre = r.mitre_tactic

    return base_score, rule, mitre
