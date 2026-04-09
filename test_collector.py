"""
Quick smoke test for the collector → parser pipeline.
Run from the project root: python3 test_collector.py
Requires SSH service to be active (journald source).
"""
import signal
import sys

from engine.collector import collect_auth_logs
from engine.parser import parse_auth_log


def _handle_sigint(sig, frame):
    print("\n[*] Stopped.")
    sys.exit(0)


signal.signal(signal.SIGINT, _handle_sigint)

print("[*] Streaming SSH auth events — Ctrl+C to stop\n")

for raw in collect_auth_logs():
    print(f"RAW    : {raw}")
    parsed = parse_auth_log(raw)
    print(f"PARSED : {parsed}")
    print("-" * 50)
