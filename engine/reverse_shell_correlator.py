from datetime import datetime, timezone

SUSPICIOUS_COMMANDS = [
    "nc -e",
    "nc -lvp",
    "bash -i >& /dev/tcp",
    "perl -e",
    "python -c",
    "python3 -c",
]


class ReverseShellCorrelator:
    """
    Correlates process events against known reverse-shell command patterns.
    Used when event data comes in via the event bus rather than process_monitor.
    """

    def process_event(self, event: dict) -> dict | None:
        command = event.get("command", "")

        if not any(sig in command for sig in SUSPICIOUS_COMMANDS):
            return None

        return {
            "attack": "REVERSE_SHELL",
            "time":   datetime.now(timezone.utc).isoformat(),
            "attacker": {
                "ip":   event.get("ip",   "UNKNOWN"),
                "user": event.get("user", "UNKNOWN"),
            },
            "risk":  {"level": "CRITICAL", "score": 100},
            "mitre": {
                "technique_id": "T1059",
                "technique":    "Command and Scripting Interpreter",
                "tactic":       "Execution",
            },
            "timeline": [event],
        }
