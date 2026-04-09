import os
import subprocess
from datetime import datetime, timezone

# Baseline cron entries captured on first run — new entries after this are flagged
_known_cron_entries: set = set()
_initialized: bool = False


def check_persistence_mechanisms() -> list:
    """
    Poll for new crontab entries since the last check.
    On first call, just builds the baseline and returns nothing.
    """
    global _known_cron_entries, _initialized
    findings = []

    try:
        result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)

        current_entries: set = set()
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    current_entries.add(line)

        if _initialized:
            new_entries = current_entries - _known_cron_entries
            if new_entries:
                print(f"[!] {len(new_entries)} new cron entry/entries detected")
                for entry in new_entries:
                    print(f"    └─ {entry}")
                    findings.append({
                        "time":   datetime.now(timezone.utc).isoformat(),
                        "type":   "PERSISTENCE_ATTEMPT",
                        "method": "crontab",
                        "detail": entry,
                        "user":   os.getenv("USER", "unknown"),
                        "raw":    f"New cron entry: {entry}",
                    })

        _known_cron_entries = current_entries

        if not _initialized:
            _initialized = True
            print(f"[*] Persistence baseline set ({len(_known_cron_entries)} existing cron entries)")

    except Exception as e:
        print(f"[!] Cron check error: {e}")
        if not _initialized:
            _initialized = True

    return findings


def monitor_file_changes() -> None:
    """Placeholder for future inotify-based file monitoring."""
    pass
