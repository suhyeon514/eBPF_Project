def analyze_sequence(events):

    bonus = 0
    patterns = []

    accessed_sensitive = False

    for e in events:

        if e.get("path") in ["/etc/shadow", "/etc/passwd"]:
            accessed_sensitive = True

        if accessed_sensitive and e.get("event_type") == "network":
            bonus += 30
            patterns.append("DATA_EXFILTRATION")

    return bonus, patterns