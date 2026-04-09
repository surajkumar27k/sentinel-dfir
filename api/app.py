import json
import os
import platform
import socket
import subprocess
import time
import traceback

from flask import Flask, Response, jsonify, request, send_from_directory, stream_with_context

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
UI_DIR     = os.path.join(BASE_DIR, "..", "ui")
DATA_DIR   = os.path.join(BASE_DIR, "..", "data")
DEMO_DIR   = os.path.join(BASE_DIR, "..", "demo")

app = Flask(__name__)

# ── Demo catalogue ────────────────────────────────────────────────────────────
DEMO_CATALOGUE = [
    {
        "id": "ssh_bruteforce", "name": "SSH Brute Force",
        "mitre": "T1110", "tactic": "Credential Access", "risk": "CRITICAL",
        "desc": "Simulates repeated SSH login failures triggering brute-force detection.",
        "script": "ssh_bruteforce_demo.sh",
    },
    {
        "id": "persistence", "name": "Cron Persistence",
        "mitre": "T1053.003", "tactic": "Persistence", "risk": "HIGH",
        "desc": "Plants a cron job backdoor to demonstrate persistence detection.",
        "script": "persistence_demo.sh",
    },
    {
        "id": "reverse_shell", "name": "Reverse Shell",
        "mitre": "T1059", "tactic": "Execution", "risk": "CRITICAL",
        "desc": "Launches a simulated reverse shell connection.",
        "script": "reverse_shell_demo.sh",
    },
    {
        "id": "privesc", "name": "Privilege Escalation",
        "mitre": "T1548", "tactic": "Privilege Escalation", "risk": "HIGH",
        "desc": "Attempts SUID abuse and sudo misuse to escalate privileges.",
        "script": "privesc_demo.sh",
    },
    {
        "id": "lateral_movement", "name": "Lateral Movement",
        "mitre": "T1021", "tactic": "Lateral Movement", "risk": "HIGH",
        "desc": "Simulates SSH-based lateral movement across internal hosts.",
        "script": "lateral_movement_demo.sh",
    },
    {
        "id": "defense_evasion", "name": "Defense Evasion",
        "mitre": "T1070", "tactic": "Defense Evasion", "risk": "HIGH",
        "desc": "Clears logs and tampers with audit trails.",
        "script": "defense_evasion_demo.sh",
    },
    {
        "id": "exfiltration", "name": "Data Exfiltration",
        "mitre": "T1048", "tactic": "Exfiltration", "risk": "CRITICAL",
        "desc": "Simulates data exfiltration over DNS and HTTP channels.",
        "script": "exfiltration_demo.sh",
    },
]

# Full MITRE technique catalogue tracked by the engine
MITRE_TECHNIQUES = {
    "SSH_BRUTE_FORCE":       {"technique_id": "T1110",     "tactic": "Credential Access"},
    "CRON_PERSISTENCE":      {"technique_id": "T1053.003", "tactic": "Persistence"},
    "REVERSE_SHELL":         {"technique_id": "T1059",     "tactic": "Execution"},
    "PRIV_ESC":              {"technique_id": "T1548",     "tactic": "Privilege Escalation"},
    "LATERAL_MOVEMENT":      {"technique_id": "T1021",     "tactic": "Lateral Movement"},
    "LOG_TAMPERING":         {"technique_id": "T1070",     "tactic": "Defense Evasion"},
    "DATA_EXFILTRATION":     {"technique_id": "T1048",     "tactic": "Exfiltration"},
    "ANOMALY_DETECTED":      {"technique_id": "T1190",     "tactic": "Initial Access"},
    "FILE_MODIFICATION":     {"technique_id": "T1565",     "tactic": "Impact"},
    "PROCESS_INJECTION":     {"technique_id": "T1055",     "tactic": "Defense Evasion"},
    "CREDENTIAL_DUMPING":    {"technique_id": "T1003",     "tactic": "Credential Access"},
    "PORT_SCAN":             {"technique_id": "T1046",     "tactic": "Discovery"},
    "SCHEDULED_TASK":        {"technique_id": "T1053",     "tactic": "Persistence"},
    "REGISTRY_MODIFICATION": {"technique_id": "T1112",     "tactic": "Defense Evasion"},
    "MIMIKATZ_DETECTED":     {"technique_id": "T1003.001", "tactic": "Credential Access"},
    "WEBSHELL_DETECTED":     {"technique_id": "T1505.003", "tactic": "Persistence"},
    "POWERSHELL_ENCODED":    {"technique_id": "T1059.001", "tactic": "Execution"},
}


# ── Data helpers ──────────────────────────────────────────────────────────────

def load_incidents() -> list:
    path = os.path.join(DATA_DIR, "incidents.json")
    if not os.path.exists(path):
        return []
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return []


def save_incidents(data: list) -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(os.path.join(DATA_DIR, "incidents.json"), "w") as f:
        json.dump(data, f, indent=2)


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/api/incidents")
def incidents():
    data   = load_incidents()
    limit  = request.args.get("limit",  type=int)
    level  = request.args.get("level",  "").upper()
    search = request.args.get("search", "").lower()

    if level:
        data = [i for i in data if i.get("risk", {}).get("level", "") == level]
    if search:
        data = [i for i in data if
                search in str(i.get("attack", "")).lower() or
                search in str(i.get("attacker", {}).get("ip", "")).lower() or
                search in str(i.get("attacker", {}).get("user", "")).lower() or
                search in str(i.get("mitre", {}).get("technique_id", "")).lower() or
                search in str(i.get("description", "")).lower()]
    if limit:
        data = data[-limit:]
    return jsonify(data)


@app.route("/api/stats")
def stats():
    try:
        from datetime import datetime
        data          = load_incidents()
        levels        = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        attack_counts = {}
        hourly        = [0] * 24

        for inc in data:
            lvl = inc.get("risk", {}).get("level", "LOW")
            if lvl in levels:
                levels[lvl] += 1
            atk = inc.get("attack", "UNKNOWN")
            attack_counts[atk] = attack_counts.get(atk, 0) + 1
            try:
                hourly[datetime.fromisoformat(inc.get("time", "")).hour] += 1
            except (ValueError, AttributeError):
                pass

        return jsonify({
            "total":        len(data),
            "by_level":     levels,
            "by_attack":    attack_counts,
            "timeline_24h": hourly,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/graph")
def graph():
    try:
        data  = load_incidents()
        nodes = {}
        edges = []

        def add_node(nid, label, group):
            if nid not in nodes:
                nodes[nid] = {"id": nid, "label": label, "group": group}

        for inc in data:
            ip   = inc.get("attacker", {}).get("ip",   "unknown")
            user = inc.get("attacker", {}).get("user", "unknown")
            atk  = inc.get("attack", "UNKNOWN")
            mid  = inc.get("mitre",  {}).get("technique_id", "UNKNOWN")

            add_node(f"ip_{ip}",      ip,   "ip")
            add_node(f"user_{user}",  user, "user")
            add_node(f"attack_{atk}", atk,  "attack")
            add_node(f"mitre_{mid}",  mid,  "mitre")

            edges += [
                {"from": f"ip_{ip}",      "to": f"user_{user}"},
                {"from": f"user_{user}",  "to": f"attack_{atk}"},
                {"from": f"attack_{atk}", "to": f"mitre_{mid}"},
            ]

        return jsonify({"nodes": list(nodes.values()), "edges": edges})
    except Exception as e:
        return jsonify({"error": str(e), "nodes": [], "edges": []}), 500


@app.route("/api/campaigns")
def campaigns():
    try:
        data = load_incidents()
        camp = {}

        for inc in data:
            ip = inc.get("attacker", {}).get("ip", "unknown")
            if ip not in camp:
                camp[ip] = {
                    "campaign_id":    f"CAMP-{len(camp) + 1:03d}",
                    "attacker_id":    ip,
                    "incident_count": 0,
                    "first_seen":     inc.get("time"),
                    "last_seen":      inc.get("time"),
                    "attacks":        [],
                }
            c   = camp[ip]
            c["incident_count"] += 1
            atk = inc.get("attack", "UNKNOWN")
            if atk not in c["attacks"]:
                c["attacks"].append(atk)
            t = inc.get("time")
            if t:
                if not c["first_seen"] or t < c["first_seen"]:
                    c["first_seen"] = t
                if not c["last_seen"] or t > c["last_seen"]:
                    c["last_seen"] = t

        return jsonify(sorted(camp.values(), key=lambda x: x["incident_count"], reverse=True))
    except Exception:
        return jsonify([])


@app.route("/api/mitre")
def mitre():
    try:
        data     = load_incidents()
        detected = set(inc.get("attack", "") for inc in data if inc.get("attack", "") in MITRE_TECHNIQUES)
        return jsonify({
            "techniques": {k: v for k, v in MITRE_TECHNIQUES.items()},
            "detected":   list(detected),
            "covered":    len(detected),
            "total":      len(MITRE_TECHNIQUES),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/anomalies")
def anomalies():
    try:
        data   = load_incidents()
        result = []
        for inc in data:
            score = inc.get("risk", {}).get("score", 0)
            if score >= 300:
                result.append({
                    "time":          inc.get("time"),
                    "entity":        inc.get("attacker", {}).get("ip", "unknown"),
                    "score":         min(100, int(score / 10)),
                    "features_json": json.dumps({
                        "event_type": inc.get("attack", ""),
                        "command":    inc.get("description", ""),
                    }),
                })
        result.sort(key=lambda x: x["score"], reverse=True)
        return jsonify(result[:50])
    except Exception:
        return jsonify([])


@app.route("/api/ml/status")
def ml_status():
    try:
        data = load_incidents()
        ips  = set(i.get("attacker", {}).get("ip", "") for i in data)
        return jsonify({
            "status":           "online",
            "entities_tracked": len(ips),
            "models_trained":   len(ips),
            "last_update":      data[-1]["time"] if data else None,
        })
    except Exception:
        return jsonify({"status": "offline", "entities_tracked": 0, "models_trained": 0})


@app.route("/api/system")
def system_info():
    try:
        import psutil
        cpu  = psutil.cpu_percent(interval=0.1)
        mem  = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        net  = psutil.net_io_counters()
        uptime = int(time.time() - psutil.boot_time())
        engine_running = any(
            "engine" in " ".join(p.info.get("cmdline") or [])
            for p in psutil.process_iter(["cmdline"])
        )
        return jsonify({
            "hostname":       socket.gethostname(),
            "platform":       f"{platform.system()} {platform.release()}",
            "python_version": platform.python_version(),
            "cpu_percent":    cpu,
            "memory":         {"percent": mem.percent,  "total": mem.total,  "used": mem.used},
            "disk":           {"percent": disk.percent, "total": disk.total, "used": disk.used},
            "network":        {"bytes_recv": net.bytes_recv, "bytes_sent": net.bytes_sent},
            "uptime_seconds": uptime,
            "engine_running": engine_running,
            "incident_count": len(load_incidents()),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/engine/status")
def engine_status():
    try:
        import psutil
        running = any(
            "engine" in " ".join(p.info.get("cmdline") or []) and
            "main"   in " ".join(p.info.get("cmdline") or [])
            for p in psutil.process_iter(["cmdline"])
        )
        return jsonify({"running": running, "status": "online" if running else "offline"})
    except Exception as e:
        return jsonify({"running": False, "error": str(e)}), 500


@app.route("/api/engine/<action>", methods=["POST"])
def engine_action(action):
    try:
        if action == "start":
            subprocess.Popen(
                ["python3", "-m", "engine.main"],
                cwd=os.path.join(BASE_DIR, ".."),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return jsonify({"status": "ok", "message": "Engine started"})
        elif action == "stop":
            subprocess.run(["pkill", "-f", "engine.main"])
            return jsonify({"status": "ok", "message": "Engine stopped"})
        return jsonify({"error": f"Unknown action: {action}"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/incidents/clear", methods=["POST"])
def clear_incidents():
    try:
        save_incidents([])
        return jsonify({"status": "ok", "message": "All incidents cleared"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/demo/list")
def demo_list():
    return jsonify(DEMO_CATALOGUE)


@app.route("/api/demo/run/<demo_id>", methods=["POST"])
def demo_run(demo_id):
    demo = next((d for d in DEMO_CATALOGUE if d["id"] == demo_id), None)
    if not demo:
        return jsonify({"error": "Unknown demo"}), 400

    script_path = os.path.join(DEMO_DIR, demo["script"])

    def generate():
        if os.path.exists(script_path):
            proc = subprocess.Popen(
                ["bash", script_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=os.path.join(BASE_DIR, ".."),
                text=True,
            )
            for line in proc.stdout:
                yield f"data: {line.rstrip()}\n\n"
            proc.wait()
        else:
            from datetime import datetime, timezone
            yield f"data: [SENTINEL] Simulating {demo['name']} ...\n\n"
            time.sleep(0.3)
            yield f"data: [SENTINEL] Generating attack telemetry ...\n\n"
            time.sleep(0.4)

            new_inc = {
                "id":          f"sim-{int(time.time())}",
                "attack":      demo_id.upper(),
                "description": f"Simulated {demo['name']} attack",
                "time":        datetime.now(timezone.utc).isoformat(),
                "attacker":    {"ip": "10.0.0.99", "user": "attacker"},
                "risk":        {"score": 450, "level": demo["risk"]},
                "mitre":       {
                    "technique_id": demo["mitre"],
                    "technique":    demo["name"],
                    "tactic":       demo["tactic"],
                },
                "timeline": [],
            }
            existing = load_incidents()
            existing.append(new_inc)
            save_incidents(existing)

            yield f"data: [SENTINEL] Incident created → {demo['name']}\n\n"
            time.sleep(0.2)
            yield f"data: [SENTINEL] Risk: {demo['risk']}  MITRE: {demo['mitre']} — {demo['tactic']}\n\n"

        yield "data: __DONE__\n\n"

    return Response(
        stream_with_context(generate()),
        content_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/api/report/pdf")
def report_pdf():
    return jsonify({"error": "PDF export not available in this environment"}), 501


# ── Static / UI ───────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory(UI_DIR, "index.html")

@app.route("/pages/<path:p>")
def pages(p):
    return send_from_directory(os.path.join(UI_DIR, "pages"), p)

@app.route("/<path:p>")
def static_files(p):
    return send_from_directory(UI_DIR, p)


if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    print("[+] SENTINEL DFIR API — starting")
    app.run(host="0.0.0.0", port=5000, debug=debug)
