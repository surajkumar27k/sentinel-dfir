import json
import os
import platform
import subprocess
from pathlib import Path

from flask import Blueprint, jsonify, request

control_bp = Blueprint("control", __name__)

BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"
DEMO_DIR = BASE_DIR / "demo"


@control_bp.route("/engine/status", methods=["GET"])
def get_engine_status():
    """Check whether the detection engine process is running."""
    try:
        result = subprocess.run(["pgrep", "-f", "engine.main"], capture_output=True, text=True)
        is_running = bool(result.stdout.strip())
        return jsonify({"running": is_running, "status": "online" if is_running else "offline"})
    except Exception as e:
        return jsonify({"running": False, "error": str(e)}), 500


@control_bp.route("/engine/start", methods=["POST"])
def start_engine():
    """Start the detection engine if it isn't already running."""
    try:
        result = subprocess.run(["pgrep", "-f", "engine.main"], capture_output=True, text=True)
        if result.stdout.strip():
            return jsonify({"message": "Engine already running"})

        subprocess.Popen(
            ["python3", "-m", "engine.main"],
            cwd=str(BASE_DIR),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return jsonify({"status": "success", "message": "Engine started"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@control_bp.route("/engine/stop", methods=["POST"])
def stop_engine():
    """Stop the detection engine."""
    try:
        subprocess.run(["pkill", "-f", "engine.main"])
        return jsonify({"status": "success", "message": "Engine stopped"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@control_bp.route("/demo/<attack_type>", methods=["POST"])
def run_demo(attack_type):
    """Launch an attack simulation script in the background."""
    script_map = {
        "ssh_brute_force": DEMO_DIR / "ssh_bruteforce_demo.sh",
        "persistence":     DEMO_DIR / "persistence_demo.sh",
    }
    script = script_map.get(attack_type)
    if not script:
        return jsonify({"error": f"Unknown attack type: {attack_type}"}), 400
    if not script.exists():
        return jsonify({"error": f"Demo script not found: {script}"}), 404

    subprocess.Popen(
        ["bash", str(script)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd=str(DEMO_DIR),
    )
    return jsonify({
        "status":  "success",
        "message": f"{attack_type} demo launched",
        "note":    "Check the incidents page in 5–10 seconds",
    })


@control_bp.route("/incidents/clear", methods=["POST"])
def clear_incidents():
    """
    Reset the incidents store to an empty list.
    Bug fix: original code tried to delete files from a directory that doesn't
    exist; the app stores all incidents in a single incidents.json file.
    """
    incidents_file = DATA_DIR / "incidents.json"
    try:
        if incidents_file.exists():
            incidents_file.write_text("[]")
        return jsonify({"status": "success", "message": "Incidents cleared"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@control_bp.route("/system/info", methods=["GET"])
def get_system_info():
    """Basic system and incident stats."""
    try:
        incidents_file = DATA_DIR / "incidents.json"
        incidents      = []
        if incidents_file.exists():
            try:
                incidents = json.loads(incidents_file.read_text())
            except (json.JSONDecodeError, OSError):
                pass

        attack_breakdown: dict = {}
        for inc in incidents:
            atk = inc.get("attack", "UNKNOWN")
            attack_breakdown[atk] = attack_breakdown.get(atk, 0) + 1

        return jsonify({
            "platform":         platform.system(),
            "python_version":   platform.python_version(),
            "total_incidents":  len(incidents),
            "attack_breakdown": attack_breakdown,
            "data_path":        str(DATA_DIR),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
