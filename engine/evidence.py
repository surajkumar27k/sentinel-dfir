import json
import os

# Resolve path relative to project root so it works regardless of cwd
_PROJECT_ROOT  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INCIDENTS_FILE = os.environ.get(
    "SENTINEL_INCIDENTS_FILE",
    os.path.join(_PROJECT_ROOT, "data", "incidents.json"),
)


def save_incident(incident: dict) -> None:
    """Append an incident to the JSON store, then update campaign tracking."""
    os.makedirs(os.path.dirname(INCIDENTS_FILE), exist_ok=True)

    if os.path.exists(INCIDENTS_FILE):
        try:
            with open(INCIDENTS_FILE, "r") as f:
                incidents = json.load(f)
        except (json.JSONDecodeError, OSError):
            incidents = []
    else:
        incidents = []

    incidents.append(incident)

    with open(INCIDENTS_FILE, "w") as f:
        json.dump(incidents, f, indent=2)

    try:
        from engine.intel import save_campaign
        save_campaign(incident)
    except Exception as e:
        print(f"[!] Campaign save warning: {e}")
