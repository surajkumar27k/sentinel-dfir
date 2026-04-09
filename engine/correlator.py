from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

from engine.base_correlator import EventCorrelator
from engine.mitre import map_mitre
from engine.risk import calculate_risk

# Tunable detection thresholds
TIME_WINDOW    = timedelta(minutes=5)
FAIL_THRESHOLD = 2


class SSHBruteForceCorrelator(EventCorrelator):
    """
    Detects brute-force SSH attacks: N failed logins from the same IP
    followed by a successful login within the time window.
    """

    def __init__(self):
        # Keep a rolling window of events per source IP
        self.events: dict = defaultdict(lambda: deque(maxlen=20))

    def process_event(self, event: dict) -> dict | None:
        if event.get("type") not in ("FAILED_LOGIN", "SUCCESS_LOGIN"):
            return None

        ip  = event["ip"]
        now = datetime.now(timezone.utc)
        self.events[ip].append(event)

        # Only look at events within the time window
        recent = [
            e for e in self.events[ip]
            if now - datetime.fromisoformat(e["time"]).astimezone(timezone.utc) <= TIME_WINDOW
        ]

        fails   = [e for e in recent if e["type"] == "FAILED_LOGIN"]
        success = [e for e in recent if e["type"] == "SUCCESS_LOGIN"]

        if len(fails) >= FAIL_THRESHOLD and success:
            incident = {
                "attack":    "SSH_BRUTE_FORCE",
                "time":      now.isoformat(),
                "attacker":  {"ip": ip, "user": success[-1]["user"]},
                "risk":      calculate_risk(recent),
                "mitre":     map_mitre("SSH_BRUTE_FORCE"),
                "timeline":  recent,
            }
            # Clear state so we don't re-fire for the same burst
            self.events[ip].clear()
            return incident

        return None
