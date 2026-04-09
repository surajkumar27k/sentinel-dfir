from datetime import datetime


def normalize_event(event: dict, source: str) -> dict:
    """Convert a raw event into a unified timeline entry format."""
    entry = {
        "time":    event["time"],
        "source":  source,
        "type":    event.get("type", "UNKNOWN"),
        "details": {},
    }

    if source == "auth":
        entry["details"] = {
            "user":    event.get("user"),
            "ip":      event.get("ip"),
            "service": event.get("service", "ssh"),
            "raw":     event.get("raw"),
        }
    elif source == "process":
        entry["details"] = {
            "process": event.get("process"),
            "pid":     event.get("pid"),
            "user":    event.get("user"),
            "cmdline": event.get("cmdline"),
        }

    return entry


def build_timeline(events: list) -> list:
    """Build a time-sorted forensic timeline from a mixed list of events."""
    timeline = [normalize_event(e, e.get("source", "unknown")) for e in events]
    timeline.sort(key=lambda x: datetime.fromisoformat(x["time"]))
    return timeline
