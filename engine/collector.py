import re
import subprocess
from datetime import datetime, timezone

# Handles both regular users and "invalid user" variants in the log line
FAILED_RE  = re.compile(r"Failed password for (?:invalid user )?([^ ]+) from ([^ ]+)")
SUCCESS_RE = re.compile(r"Accepted password for ([^ ]+) from ([^ ]+)")


def collect_auth_logs():
    """Stream SSH auth events from journald in real time."""
    cmd = ["journalctl", "-u", "ssh", "-f", "-o", "cat"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)

    for line in proc.stdout:
        line = line.strip()

        if "Failed password" in line:
            m = FAILED_RE.search(line)
            if m:
                yield {
                    "time":    datetime.now(timezone.utc).isoformat(),
                    "type":    "FAILED_LOGIN",
                    "user":    m.group(1),
                    "ip":      m.group(2),
                    "service": "ssh",
                    "raw":     line,
                }

        elif "Accepted password" in line:
            m = SUCCESS_RE.search(line)
            if m:
                yield {
                    "time":    datetime.now(timezone.utc).isoformat(),
                    "type":    "SUCCESS_LOGIN",
                    "user":    m.group(1),
                    "ip":      m.group(2),
                    "service": "ssh",
                    "raw":     line,
                }
