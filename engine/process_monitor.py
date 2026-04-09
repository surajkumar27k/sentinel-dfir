import time
from datetime import datetime, timezone

import psutil

# Command substrings that indicate a potential reverse shell
SUSPICIOUS_PATTERNS = [
    "nc -lvp",
    "nc -e",
    "bash -i",
    "/dev/tcp",
    "python -c",
    "python3 -c",
]


def monitor_processes():
    """
    Continuously scan running processes for reverse-shell signatures.
    Yields an incident dict the first time a suspicious PID is seen.
    """
    seen_pids: set = set()

    while True:
        for proc in psutil.process_iter(["pid", "username", "cmdline"]):
            try:
                cmdline = proc.info.get("cmdline") or []
                cmd = " ".join(cmdline)
                if not cmd or proc.pid in seen_pids:
                    continue

                seen_pids.add(proc.pid)

                for pattern in SUSPICIOUS_PATTERNS:
                    if pattern in cmd:
                        yield {
                            "attack":   "REVERSE_SHELL",
                            "time":     datetime.now(timezone.utc).isoformat(),
                            "attacker": {
                                "ip":   "127.0.0.1",
                                "user": proc.info.get("username", "unknown"),
                            },
                            "risk":  {"level": "HIGH", "score": 85},
                            "mitre": {
                                "technique_id": "T1059",
                                "technique":    "Command and Scripting Interpreter",
                                "tactic":       "Execution",
                            },
                            "timeline": [{
                                "type":    "PROCESS_EXEC",
                                "command": cmd,
                                "pid":     proc.pid,
                            }],
                        }
                        break  # one incident per PID, don't double-fire

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        time.sleep(2)
