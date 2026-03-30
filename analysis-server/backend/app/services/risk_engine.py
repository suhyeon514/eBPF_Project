MITRE_BONUS = {
    "CREDENTIAL_ACCESS": 12,
    "COMMAND_AND_CONTROL": 10,
}

SENSITIVE_PATHS = ["/etc/shadow", "/etc/passwd"]
SENSITIVE_PORTS = [22, 4444, 8888]

def calculate_risk(event, base_score, mitre):

    base_score = max(base_score, 1)

    target = 1.0

    if event.path and any(p in event.path for p in SENSITIVE_PATHS):
        target = 1.2

    if event.dest_port and event.dest_port in SENSITIVE_PORTS:
        target = max(target, 1.1)

    env = 1.0
    if event.uid == 0:
        env = 1.1

    bonus = MITRE_BONUS.get(mitre, 0)

    score = (base_score * target * env) + bonus
    score = min(score, 100)

    return round(score, 2)