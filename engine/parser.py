def parse_auth_log(raw_log: dict) -> dict | None:
    """
    Normalise a raw collector event into a clean auth event.
    The collector already classifies the type, so we just pass it through.
    Returns None for anything that isn't an auth event we care about.
    """
    event_type = raw_log.get("type")

    if event_type not in ("FAILED_LOGIN", "SUCCESS_LOGIN"):
        return None

    return {
        "type": event_type,
        "ip":   raw_log["ip"],
        "user": raw_log["user"],
        "time": raw_log["time"],
    }
