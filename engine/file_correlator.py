from datetime import datetime, timezone

# Paths that warrant a HIGH-risk alert if modified
SUSPICIOUS_PATHS = ["/etc", "/usr/bin", "/usr/sbin", "/home"]


def process_file_event(event: dict) -> dict | None:
    """Return an incident if the file path falls under a sensitive directory."""
    path = event.get("path", "")

    if not any(path.startswith(p) for p in SUSPICIOUS_PATHS):
        return None

    return {
        "attack":   "FILE_TAMPERING",
        "time":     datetime.now(timezone.utc).isoformat(),
        "attacker": {"ip": "LOCAL", "user": "UNKNOWN"},
        "risk":     {"level": "HIGH", "score": 80},
        "mitre": {
            "technique_id": "T1565",
            "technique":    "Data Manipulation",
            "tactic":       "Impact",
        },
        "timeline": [event],
    }
