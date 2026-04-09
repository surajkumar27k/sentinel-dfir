_MITRE_MAP = {
    "SSH_BRUTE_FORCE": {
        "technique_id": "T1110",
        "technique":    "Brute Force",
        "tactic":       "Credential Access",
    },
    "PERSISTENCE": {
        "technique_id": "T1053.003",
        "technique":    "Scheduled Task/Job: Cron",
        "tactic":       "Persistence",
    },
    "REVERSE_SHELL": {
        "technique_id": "T1059",
        "technique":    "Command and Scripting Interpreter",
        "tactic":       "Execution",
    },
    "FILE_TAMPERING": {
        "technique_id": "T1565",
        "technique":    "Data Manipulation",
        "tactic":       "Impact",
    },
}

_UNKNOWN = {
    "technique_id": "UNKNOWN",
    "technique":    "Unknown",
    "tactic":       "Unknown",
}


def map_mitre(attack_type: str) -> dict:
    """Return MITRE ATT&CK metadata for a given attack type."""
    return _MITRE_MAP.get(attack_type, _UNKNOWN)
