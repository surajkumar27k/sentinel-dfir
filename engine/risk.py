def calculate_risk(timeline: list) -> dict:
    """
    Score an incident based on the events in its timeline.
    Weights are intentionally simple — tune per environment.
    """
    weights = {
        "FAILED_LOGIN":         20,
        "SUCCESS_LOGIN":       100,
        "PERSISTENCE_ATTEMPT":  90,
        "PROCESS_EXEC":         50,
        "SENSITIVE_FILE_ACCESS": 70,
        "PORT_ACCESS":          10,
    }

    score = sum(weights.get(e.get("type", ""), 0) for e in timeline)

    if score >= 120:
        level = "CRITICAL"
    elif score >= 80:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {"score": score, "level": level}
