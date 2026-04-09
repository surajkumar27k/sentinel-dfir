import socket
from datetime import datetime, timezone

from engine.base_correlator import EventCorrelator
from engine.mitre import map_mitre


class PersistenceCorrelator(EventCorrelator):
    """Wraps a raw PERSISTENCE_ATTEMPT finding into a full incident dict."""

    def process_event(self, event: dict) -> dict | None:
        if event.get("type") != "PERSISTENCE_ATTEMPT":
            return None

        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
        except OSError:
            local_ip = "127.0.0.1"

        return {
            "attack": "PERSISTENCE",
            "time":   datetime.now(timezone.utc).isoformat(),
            "attacker": {
                "ip":     local_ip,
                "user":   event.get("user", "unknown"),
                "method": event.get("method"),
            },
            "risk":     {"score": 90, "level": "HIGH"},
            "mitre":    map_mitre("PERSISTENCE"),
            "timeline": [event],
        }
