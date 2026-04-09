import threading
import time
from engine.collector import collect_auth_logs
from engine.parser import parse_auth_log
from engine.correlator import SSHBruteForceCorrelator
from engine.process_monitor import monitor_processes
from engine.file_monitor import check_persistence_mechanisms
from engine.persistence_correlator import PersistenceCorrelator
from engine.evidence import save_incident


ssh_correlator = SSHBruteForceCorrelator()
persistence_correlator = PersistenceCorrelator()


def auth_worker():
    print("[*] SSH auth monitor started")
    for raw in collect_auth_logs():
        event = parse_auth_log(raw)
        if not event:
            continue
        incident = ssh_correlator.process_event(event)
        if incident:
            save_incident(incident)
            print(f"\n🚨 INCIDENT: {incident['attack']} from {incident['attacker']['ip']}")


def process_worker():
    print("[*] Process monitor started")
    for incident in monitor_processes():
        save_incident(incident)
        print(f"\n🚨 INCIDENT: {incident['attack']}")


def persistence_worker():
    print("[*] Persistence monitor started")
    while True:
        try:
            findings = check_persistence_mechanisms()
            for finding in findings:
                incident = persistence_correlator.process_event(finding)
                if incident:
                    save_incident(incident)
                    print(f"\n🚨 PERSISTENCE DETECTED")
                    print(f"    Method : {finding['method']}")
                    print(f"    Detail : {finding['detail']}")
            time.sleep(5)
        except Exception as e:
            print(f"[!] Persistence monitor error: {e}")
            time.sleep(5)


def run_engine():
    print("=" * 60)
    print("[+] DFIR SENTINEL — Real-Time Threat Detection Engine")
    print("=" * 60)
    print("[+] Monitoring:")
    print("    ✓ SSH Authentication (journald)")
    print("    ✓ Process Execution (psutil)")
    print("    ✓ Persistence Mechanisms (5s polling)")
    print("[+] MITRE ATT&CK mapping: enabled")
    print("=" * 60)

    t1 = threading.Thread(target=auth_worker,        daemon=True, name="SSH-Monitor")
    t2 = threading.Thread(target=process_worker,     daemon=True, name="Process-Monitor")
    t3 = threading.Thread(target=persistence_worker, daemon=True, name="Persistence-Monitor")

    t1.start()
    t2.start()
    t3.start()

    print("[+] All threads active — press Ctrl+C to stop\n")

    try:
        t1.join()
        t2.join()
        t3.join()
    except KeyboardInterrupt:
        print("\n[!] Shutting down...")


if __name__ == "__main__":
    run_engine()
