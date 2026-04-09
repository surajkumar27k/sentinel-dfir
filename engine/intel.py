import json
import os
from datetime import datetime, timezone

import requests

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
ABUSEIPDB_URL     = "https://api.abuseipdb.com/api/v2/check"

_PROJECT_ROOT  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CAMPAIGNS_FILE = os.environ.get(
    "SENTINEL_CAMPAIGNS_FILE",
    os.path.join(_PROJECT_ROOT, "data", "campaigns.json"),
)


def enrich_ip(ip: str) -> dict:
    """Query AbuseIPDB for reputation data on an IP address."""
    if not ABUSEIPDB_API_KEY:
        return {"error": "ABUSEIPDB_API_KEY not set"}

    try:
        resp = requests.get(
            ABUSEIPDB_URL,
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=5,
        )
        data = resp.json().get("data", {})
        return {
            "abuse_score": data.get("abuseConfidenceScore"),
            "country":     data.get("countryCode"),
            "isp":         data.get("isp"),
            "usage_type":  data.get("usageType"),
            "is_public":   data.get("isPublic"),
        }
    except Exception as e:
        return {"error": str(e)}


def save_campaign(incident: dict) -> None:
    """
    Group incidents by attacker IP into campaigns.
    A campaign is just a running record of every incident from the same source.
    """
    os.makedirs(os.path.dirname(CAMPAIGNS_FILE), exist_ok=True)

    campaigns: list = []
    if os.path.exists(CAMPAIGNS_FILE):
        try:
            with open(CAMPAIGNS_FILE, "r") as f:
                campaigns = json.load(f)
        except (json.JSONDecodeError, OSError):
            campaigns = []

    attacker_id = incident.get("attacker", {}).get("ip", "unknown")
    now = datetime.now(timezone.utc).isoformat()

    for campaign in campaigns:
        if campaign["attacker_id"] == attacker_id:
            campaign["incidents"].append(incident)
            campaign["last_seen"]      = now
            campaign["incident_count"] = len(campaign["incidents"])
            break
    else:
        campaigns.append({
            "campaign_id":    f"CAMP-{len(campaigns) + 1}",
            "attacker_id":    attacker_id,
            "first_seen":     incident["time"],
            "last_seen":      incident["time"],
            "incident_count": 1,
            "incidents":      [incident],
        })

    with open(CAMPAIGNS_FILE, "w") as f:
        json.dump(campaigns, f, indent=2)

    print(f"[*] Campaign updated: {attacker_id}")
