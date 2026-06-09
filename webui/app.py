"""
Detonation Chamber - Unified Web UI
Aggregates data from Rustinel, Fibratus, Detonator, DetonatorAgent, and LitterBox
into a single dark-themed interface inspired by the Rustinel tracing UI.

Run: python app.py
Access: http://localhost:9000
"""

import json
import os
import glob
import time
import hashlib
import math
import struct
import threading
import subprocess
from pathlib import Path
from flask import Flask, render_template, jsonify, request, send_from_directory
import requests

app = Flask(__name__)

# --- Configuration ---
RUSTINEL_ALERTS_DIR = os.environ.get("RUSTINEL_ALERTS_DIR", r"C:\tools\rustinel\logs")
RUSTINEL_INSTALL_DIR = os.environ.get("RUSTINEL_INSTALL_DIR", r"C:\tools\rustinel")
DETONATOR_API = os.environ.get("DETONATOR_API", "http://127.0.0.1:8000")
DETONATOR_AGENT_API = os.environ.get("DETONATOR_AGENT_API", "http://127.0.0.1:8080")
LITTERBOX_API = os.environ.get("LITTERBOX_API", "http://127.0.0.1:1337")
WEBUI_PORT = int(os.environ.get("WEBUI_PORT", "9000"))
SUBMISSIONS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "submissions.json")

# In-memory event store (populated from Rustinel NDJSON + Fibratus)
events_store = {
    "processes": {},
    "alerts": [],
    "dns": [],
    "files": [],
    "registry": [],
    "network": [],
    "modules": [],
    "injections": [],
    "sessions": [],
}
store_lock = threading.Lock()

# --- Submissions History ---
submissions_lock = threading.Lock()


def _load_submissions():
    """Load submission history from JSON file."""
    if os.path.isfile(SUBMISSIONS_FILE):
        try:
            with open(SUBMISSIONS_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return []
    return []


def _save_submissions(submissions):
    """Persist submission history to JSON file."""
    try:
        with open(SUBMISSIONS_FILE, "w") as f:
            json.dump(submissions, f, indent=2)
    except IOError:
        pass


def _record_submission(filename, sha256, size, target, results):
    """Record a new submission in the history."""
    import datetime
    entry = {
        "id": hashlib.md5(f"{sha256}{time.time()}".encode()).hexdigest()[:12],
        "timestamp": datetime.datetime.now().isoformat(),
        "filename": filename,
        "sha256": sha256,
        "size": size,
        "target": target,
        "agent_status": None,
        "agent_pid": None,
        "litterbox_status": None,
        "file_path": None,
    }
    # Extract results
    if "agent" in results:
        entry["agent_status"] = "success" if 200 <= results["agent"].get("status", 0) < 400 else "failed"
        agent_data = results["agent"].get("data")
        if isinstance(agent_data, dict):
            if agent_data.get("pid"):
                entry["agent_pid"] = agent_data["pid"]
            entry["file_path"] = agent_data.get("file_path") or agent_data.get("path")
    if "litterbox" in results:
        entry["litterbox_status"] = "success" if 200 <= results["litterbox"].get("status", 0) < 400 else "failed"

    # If no file_path from agent, guess the common location
    if not entry["file_path"]:
        entry["file_path"] = f"C:\\Users\\vagrant\\Desktop\\infected\\{filename}"

    with submissions_lock:
        subs = _load_submissions()
        subs.insert(0, entry)  # newest first
        # Keep max 200 entries
        subs = subs[:200]
        _save_submissions(subs)

    return entry


# --- Rustinel NDJSON Parser ---
def _get_nested(data, dotted_key, default=None):
    """Get value from dict using dotted key notation, checking flat keys first."""
    # First try flat dotted key (e.g., "process.pid")
    if dotted_key in data:
        return data[dotted_key]
    # Then try nested traversal
    parts = dotted_key.split(".")
    current = data
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return default
        if current is None:
            return default
    return current if current is not None else default


def parse_rustinel_alert(line):
    """Parse a single NDJSON line from Rustinel alerts output."""
    try:
        data = json.loads(line.strip())
    except json.JSONDecodeError:
        return None

    # Generate a stable unique ID from the line content (avoids Windows timer resolution issues)
    stable_id = _get_nested(data, "event.id") or hashlib.sha256(line.strip().encode()).hexdigest()[:16]

    alert = {
        "id": stable_id,
        "timestamp": data.get("@timestamp") or _get_nested(data, "event.timestamp", ""),
        "severity": _get_nested(data, "edr.rule.severity")
                    or _get_nested(data, "rule.severity", "unknown"),
        "rule_name": _get_nested(data, "rule.name", "Unknown Rule"),
        "rule_description": _get_nested(data, "rule.description", ""),
        "engine": _get_nested(data, "edr.rule.engine", "unknown"),
        "tags": _get_nested(data, "rule.tags", []),
        "category": _get_nested(data, "event.category", ""),
        "pid": _get_nested(data, "process.pid"),
        "process_name": _get_nested(data, "process.name", ""),
        "process_image": _get_nested(data, "process.executable", ""),
        "command_line": _get_nested(data, "process.command_line", ""),
        "parent_pid": _get_nested(data, "process.parent.pid"),
        "parent_name": _get_nested(data, "process.parent.name", ""),
        "parent_command_line": _get_nested(data, "process.parent.command_line", ""),
        "user": _get_nested(data, "user.name", ""),
        "raw": data,
    }
    return alert


def load_rustinel_alerts():
    """Load all NDJSON alert files from Rustinel alerts directory."""
    alerts = []
    if not os.path.isdir(RUSTINEL_ALERTS_DIR):
        return alerts

    for filepath in glob.glob(os.path.join(RUSTINEL_ALERTS_DIR, "*.ndjson")):
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if line.strip():
                        alert = parse_rustinel_alert(line)
                        if alert:
                            alerts.append(alert)
        except (IOError, OSError):
            continue

    # Also check for .json files (including date-suffixed like alerts.json.2026-06-08)
    for pattern in ("*.json", "alerts.json.*"):
        for filepath in glob.glob(os.path.join(RUSTINEL_ALERTS_DIR, pattern)):
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read().strip()
                    # Could be single JSON object or NDJSON
                    for line in content.split("\n"):
                        if line.strip():
                            alert = parse_rustinel_alert(line)
                            if alert:
                                alerts.append(alert)
            except (IOError, OSError):
                continue

    # Deduplicate by id
    seen = set()
    unique_alerts = []
    for alert in alerts:
        aid = alert.get("id")
        if aid and aid not in seen:
            seen.add(aid)
            unique_alerts.append(alert)
        elif not aid:
            unique_alerts.append(alert)

    return unique_alerts


# --- Fibratus Event Log Ingestion ---
# Fibratus writes alerts to Windows Event Log: Application log, Provider "Fibratus", JSON format.

_fibratus_last_read_time = None  # Track last read timestamp to avoid re-reading


def parse_fibratus_alert(data):
    """Parse a Fibratus JSON alert into the normalized alert format."""
    if not isinstance(data, dict):
        return None

    alert_id = data.get("id") or hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()[:16]

    # Get first event (Fibratus alerts contain an array of triggering events)
    events = data.get("events", [])
    first_event = events[0] if events else {}
    proc = first_event.get("proc", {})

    # Map Fibratus category to ECS-like category
    fibratus_cat = first_event.get("category", "").lower()
    category_map = {
        "process": "process",
        "file": "file",
        "registry": "registry",
        "net": "network",
        "network": "network",
        "image": "process",
        "thread": "process",
        "dns": "dns",
    }
    category = category_map.get(fibratus_cat, fibratus_cat)

    # Extract MITRE tags from labels if present
    tags = []
    labels = data.get("labels", {})
    for key, val in labels.items():
        if "mitre" in key.lower() or "attack" in key.lower():
            if isinstance(val, list):
                tags.extend(val)
            elif isinstance(val, str):
                tags.append(val)
    # Also check for tags in the title/text for common MITRE patterns
    title = data.get("title", "")

    alert = {
        "id": f"fib_{alert_id}",
        "timestamp": first_event.get("timestamp", ""),
        "severity": data.get("severity", "unknown").lower(),
        "rule_name": title or "Fibratus Detection",
        "rule_description": data.get("description", "") or data.get("text", ""),
        "engine": "fibratus",
        "tags": tags,
        "category": category,
        "pid": proc.get("pid"),
        "process_name": proc.get("name", ""),
        "process_image": proc.get("exe", ""),
        "command_line": proc.get("cmdline", ""),
        "parent_pid": proc.get("ppid"),
        "parent_name": proc.get("parent_name", ""),
        "parent_command_line": proc.get("parent_cmdline", ""),
        "user": proc.get("username", ""),
        "detonated": True,
        "detonation_source": "fibratus",
        "raw": data,
    }
    return alert


def load_fibratus_alerts():
    """Load Fibratus alerts from Windows Event Log (Application log, Provider: Fibratus)."""
    global _fibratus_last_read_time
    alerts = []

    # Build PowerShell command to query Fibratus events
    # Use Get-WinEvent with FilterHashtable for efficiency
    ps_cmd = (
        "Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='Fibratus'} "
        "-MaxEvents 500 -ErrorAction SilentlyContinue | "
        "ForEach-Object { $_.Message } "
    )

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return alerts

        # Each event message is a JSON blob; they may be separated by newlines
        # PowerShell outputs each Message on its own line(s)
        raw_output = result.stdout.strip()

        # Try to split by JSON object boundaries
        # Fibratus JSON alerts start with { and end with }
        depth = 0
        current_json = []
        for line in raw_output.split("\n"):
            line = line.rstrip()
            if not line:
                continue
            current_json.append(line)
            depth += line.count("{") - line.count("}")
            if depth <= 0 and current_json:
                json_str = "\n".join(current_json)
                current_json = []
                depth = 0
                try:
                    data = json.loads(json_str)
                    alert = parse_fibratus_alert(data)
                    if alert:
                        alerts.append(alert)
                except json.JSONDecodeError:
                    continue

        # Handle any remaining buffer
        if current_json:
            json_str = "\n".join(current_json)
            try:
                data = json.loads(json_str)
                alert = parse_fibratus_alert(data)
                if alert:
                    alerts.append(alert)
            except json.JSONDecodeError:
                pass

    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        print(f"[fibratus_loader] Error reading event log: {e}")
        return alerts

    return alerts


def load_litterbox_results():
    """Poll LitterBox API for completed analysis results and convert to alert format."""
    alerts = []
    try:
        r = requests.get(f"{LITTERBOX_API}/api/analyses", params={"status": "completed"}, timeout=5)
        if r.status_code != 200:
            return alerts
        analyses = r.json() if isinstance(r.json(), list) else r.json().get("results", [])
    except (requests.RequestException, ValueError):
        return alerts

    for analysis in analyses:
        try:
            analysis_id = analysis.get("id") or analysis.get("task_id", "")
            score = analysis.get("score", 0) or analysis.get("threat_score", 0)
            sample = analysis.get("sample", {}) or {}
            filename = sample.get("name") or analysis.get("filename", "unknown")
            sha256 = sample.get("sha256") or analysis.get("sha256", "")
            started = analysis.get("started") or analysis.get("timestamp", "")
            completed = analysis.get("completed") or started

            # Only create alert-level entries for analyses with findings
            if score <= 0:
                continue

            # Map score to severity
            if score >= 8:
                severity = "critical"
            elif score >= 5:
                severity = "high"
            elif score >= 3:
                severity = "medium"
            else:
                severity = "low"

            # Get process info from behavioral analysis if available
            behaviors = analysis.get("behaviors", []) or analysis.get("signatures", [])
            proc_name = analysis.get("process_name", "")
            proc_pid = analysis.get("pid")
            proc_image = analysis.get("process_image", "")
            cmdline = analysis.get("command_line", "")

            # Try to extract from first behavior if top-level is empty
            if not proc_name and behaviors:
                first_b = behaviors[0] if isinstance(behaviors[0], dict) else {}
                proc_name = first_b.get("process_name", "")
                proc_pid = first_b.get("pid") or proc_pid
                proc_image = first_b.get("process_image", "") or proc_image

            # Build description from signatures/behaviors
            sigs = []
            for b in (behaviors[:5] if behaviors else []):
                if isinstance(b, dict):
                    sigs.append(b.get("name") or b.get("description", ""))
                elif isinstance(b, str):
                    sigs.append(b)
            description = "; ".join(s for s in sigs if s) if sigs else f"LitterBox analysis score: {score}/10"

            # Extract tags (MITRE, etc)
            tags = analysis.get("tags", []) or []
            mitre = analysis.get("mitre_attacks", []) or analysis.get("ttps", [])
            if mitre:
                tags.extend([t.get("technique_id", t) if isinstance(t, dict) else str(t) for t in mitre])

            alert = {
                "id": f"lb_{analysis_id}",
                "timestamp": completed,
                "severity": severity,
                "rule_name": f"LitterBox: {filename}",
                "rule_description": description,
                "engine": "litterbox",
                "tags": tags,
                "category": "process",
                "pid": proc_pid,
                "process_name": proc_name or filename,
                "process_image": proc_image,
                "command_line": cmdline,
                "parent_pid": None,
                "parent_name": "",
                "parent_command_line": "",
                "user": analysis.get("user", ""),
                "detonated": True,
                "detonation_source": "litterbox",
                "litterbox_score": score,
                "litterbox_id": analysis_id,
                "sha256": sha256,
                "raw": analysis,
            }
            alerts.append(alert)
        except (KeyError, TypeError, ValueError):
            continue

    return alerts


def build_process_tree(alerts):
    """Build process tree from alerts data.
    
    Handles PID reuse: if a PID's executable changes between alerts,
    use the most recent process info (latest alert wins).
    """
    processes = {}
    for alert in alerts:
        pid = alert.get("pid")
        if pid and pid not in processes:
            processes[pid] = {
                "pid": pid,
                "name": alert.get("process_name", "unknown"),
                "image": alert.get("process_image", ""),
                "command_line": alert.get("command_line", ""),
                "user": alert.get("user", ""),
                "parent_pid": alert.get("parent_pid"),
                "parent_name": alert.get("parent_name", ""),
                "integrity": "",
                "working_dir": "",
                "first_seen": alert.get("timestamp", ""),
                "last_seen": alert.get("timestamp", ""),
                "exit_time": None,
                "exit_code": None,
                "children": [],
                "activity": {
                    "file": 0, "network": 0, "dns": 0, "http": 0,
                    "registry": 0, "modules": 0, "scripts": 0, "injection": 0,
                    "wmi": 0, "services": 0, "tasks": 0, "logons": 0,
                    "artifacts": 0, "threats": 0, "detonated": 0,
                },
                "alerts": [],
                "detonated": False,
                "detonation_sources": [],
            }
        if pid:
            # Handle PID reuse: if the executable changed, update process identity
            # (later alerts overwrite older ones so the most recent process info wins)
            proc_entry = processes.get(pid)
            if proc_entry:
                alert_image = alert.get("process_image", "")
                alert_ts = alert.get("timestamp", "")
                if alert_image and alert_image != proc_entry["image"]:
                    # Different executable on same PID = PID reuse; update to latest
                    if alert_ts >= (proc_entry.get("last_seen") or ""):
                        proc_entry["name"] = alert.get("process_name", proc_entry["name"])
                        proc_entry["image"] = alert_image
                        proc_entry["command_line"] = alert.get("command_line") or proc_entry["command_line"]
                        proc_entry["user"] = alert.get("user") or proc_entry["user"]
                        if alert.get("parent_pid"):
                            proc_entry["parent_pid"] = alert.get("parent_pid")
                            proc_entry["parent_name"] = alert.get("parent_name", "")

                proc_entry["alerts"].append(alert)

                # Count activity by category
                cat = alert.get("category", "")
                if isinstance(cat, list):
                    cat = cat[0] if cat else ""
                cat_lower = cat.lower()

                proc_entry["activity"]["threats"] += 1
                if "file" in cat_lower:
                    proc_entry["activity"]["file"] += 1
                elif "network" in cat_lower:
                    proc_entry["activity"]["network"] += 1
                    # Check if HTTP specifically (ports 80/443/8080/8443)
                    raw = alert.get("raw", {})
                    dest_port = _get_nested(raw, "destination.port") or _get_nested(raw, "network.destination.port")
                    if dest_port in (80, 443, 8080, 8443, "80", "443", "8080", "8443"):
                        proc_entry["activity"]["http"] += 1
                elif "dns" in cat_lower:
                    proc_entry["activity"]["dns"] += 1
                elif "registry" in cat_lower:
                    proc_entry["activity"]["registry"] += 1
                elif "process" in cat_lower:
                    proc_entry["activity"]["modules"] += 1

                # Count artifacts (YARA/IOC matches)
                engine = alert.get("engine", "").lower()
                if engine in ("yara", "ioc"):
                    proc_entry["activity"]["artifacts"] += 1

                # Track detonation enrichment (Fibratus / LitterBox)
                if alert.get("detonated"):
                    proc_entry["activity"]["detonated"] += 1
                    proc_entry["detonated"] = True
                    det_src = alert.get("detonation_source", "")
                    if det_src and det_src not in proc_entry["detonation_sources"]:
                        proc_entry["detonation_sources"].append(det_src)

                # Track last seen timestamp
                ts = alert.get("timestamp", "")
                if ts and ts > (proc_entry.get("last_seen") or ""):
                    proc_entry["last_seen"] = ts

                # Detect process exit events (ETW process terminate)
                raw = alert.get("raw", {})
                event_action = _get_nested(raw, "event.action", "")
                if event_action in ("process_terminated", "exit", "ProcessExit"):
                    proc_entry["exit_time"] = ts
                    proc_entry["exit_code"] = _get_nested(raw, "process.exit_code")

    # Link children to parents
    for pid, proc in processes.items():
        ppid = proc.get("parent_pid")
        if ppid and ppid in processes:
            processes[ppid]["children"].append(pid)

    # Infer exit for processes whose last_seen is significantly before session end
    # (heuristic: if no new events for this process after others continue, mark as exited)
    if processes:
        all_timestamps = [p.get("last_seen", "") for p in processes.values() if p.get("last_seen")]
        if all_timestamps:
            session_end = max(all_timestamps)
            for proc in processes.values():
                if not proc["exit_time"] and proc.get("last_seen"):
                    # If last seen is more than 5s before session end, infer exit
                    try:
                        from datetime import datetime
                        last = datetime.fromisoformat(proc["last_seen"].replace("Z", "+00:00"))
                        end = datetime.fromisoformat(session_end.replace("Z", "+00:00"))
                        if (end - last).total_seconds() > 5:
                            proc["exit_time"] = proc["last_seen"]
                    except (ValueError, TypeError):
                        pass

    return processes


# --- Background alert loader ---
def alert_loader_thread():
    """Periodically reload alerts from Rustinel, Fibratus, and LitterBox."""
    while True:
        try:
            # Load from all sources
            rustinel_alerts = load_rustinel_alerts()
            fibratus_alerts = load_fibratus_alerts()
            litterbox_alerts = load_litterbox_results()

            # Merge and deduplicate
            all_alerts = rustinel_alerts + fibratus_alerts + litterbox_alerts
            seen = set()
            unique_alerts = []
            for alert in all_alerts:
                aid = alert.get("id")
                if aid and aid not in seen:
                    seen.add(aid)
                    unique_alerts.append(alert)
                elif not aid:
                    unique_alerts.append(alert)

            # Sort by timestamp
            unique_alerts.sort(key=lambda a: a.get("timestamp", ""))

            processes = build_process_tree(unique_alerts)
            with store_lock:
                events_store["alerts"] = unique_alerts
                events_store["processes"] = processes
        except Exception as e:
            print(f"[alert_loader] Error: {e}")
        time.sleep(5)


# --- Routes: Pages ---
@app.route("/")
def index():
    return render_template("index.html")


# --- Routes: API ---
@app.route("/api/status")
def api_status():
    """Get status of all integrated services."""
    status = {}

    # Check DetonatorAgent
    try:
        r = requests.get(f"{DETONATOR_AGENT_API}/api/lock/status", timeout=1)
        status["detonator_agent"] = {"online": True, "data": r.json()}
    except Exception:
        status["detonator_agent"] = {"online": False}

    # Check Detonator (skip if known offline to save time)
    try:
        r = requests.get(f"{DETONATOR_API}/api/submissions", timeout=1)
        status["detonator"] = {"online": True}
    except Exception:
        status["detonator"] = {"online": False}

    # Check LitterBox
    try:
        r = requests.get(LITTERBOX_API, timeout=1)
        status["litterbox"] = {"online": r.status_code == 200}
    except Exception:
        status["litterbox"] = {"online": False}

    # Rustinel - check process existence via filesystem (fast)
    rustinel_online = os.path.isdir(RUSTINEL_ALERTS_DIR) and _is_rustinel_running()
    status["rustinel"] = {
        "online": rustinel_online,
        "alerts_count": len(events_store.get("alerts", [])),
    }

    # Sysmon - check if service is running
    status["sysmon"] = {"online": _is_sysmon_running()}

    return jsonify(status)


# Cache for rustinel process check (avoid spawning powershell on every request)
_rustinel_proc_cache = {"online": False, "checked_at": 0}


def _is_rustinel_running():
    """Fast check if Rustinel is running (cached for 10s)."""
    now = time.time()
    if now - _rustinel_proc_cache["checked_at"] < 10:
        return _rustinel_proc_cache["online"]
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "(Get-Process -Name rustinel -ErrorAction SilentlyContinue) -ne $null"],
            capture_output=True, text=True, timeout=3
        )
        online = "True" in result.stdout
        _rustinel_proc_cache["online"] = online
        _rustinel_proc_cache["checked_at"] = now
        return online
    except Exception:
        _rustinel_proc_cache["checked_at"] = now
        return _rustinel_proc_cache["online"]


def _get_rustinel_process():
    """Get detailed Rustinel process info (for detail panel only)."""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-Process -Name rustinel -ErrorAction SilentlyContinue | "
             "Select-Object Id, StartTime, WorkingSet64 | ConvertTo-Json"],
            capture_output=True, text=True, timeout=5
        )
        if result.stdout.strip():
            data = json.loads(result.stdout.strip())
            return data
    except Exception:
        pass
    return None


# Cache for Sysmon service check
_sysmon_proc_cache = {"online": False, "checked_at": 0}


def _is_sysmon_running():
    """Fast check if Sysmon64 service is running (cached for 30s)."""
    now = time.time()
    if now - _sysmon_proc_cache["checked_at"] < 30:
        return _sysmon_proc_cache["online"]
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "(Get-Service Sysmon64 -ErrorAction SilentlyContinue).Status -eq 'Running'"],
            capture_output=True, text=True, timeout=3
        )
        online = "True" in result.stdout
        _sysmon_proc_cache["online"] = online
        _sysmon_proc_cache["checked_at"] = now
        return online
    except Exception:
        _sysmon_proc_cache["checked_at"] = now
        return _sysmon_proc_cache["online"]


def _get_rustinel_rules():
    """Count loaded rules from Rustinel's rules directories."""
    rules_dir = os.path.join(RUSTINEL_INSTALL_DIR, "rules")
    counts = {"sigma": 0, "yara": 0, "ioc": {"hashes": 0, "ips": 0, "domains": 0, "paths": 0}}

    # Sigma rules
    sigma_dir = os.path.join(rules_dir, "sigma")
    if os.path.isdir(sigma_dir):
        for f in glob.glob(os.path.join(sigma_dir, "**", "*.yml"), recursive=True):
            counts["sigma"] += 1

    # YARA rules
    yara_dir = os.path.join(rules_dir, "yara")
    if os.path.isdir(yara_dir):
        for f in glob.glob(os.path.join(yara_dir, "**", "*.yar"), recursive=True):
            counts["yara"] += 1

    # IOC feeds
    ioc_dir = os.path.join(rules_dir, "ioc")
    if os.path.isdir(ioc_dir):
        for ioc_file, key in [("hashes.txt", "hashes"), ("ips.txt", "ips"),
                               ("domains.txt", "domains"), ("paths_regex.txt", "paths")]:
            fpath = os.path.join(ioc_dir, ioc_file)
            if os.path.isfile(fpath):
                try:
                    with open(fpath, "r") as f:
                        counts["ioc"][key] = sum(1 for line in f
                                                  if line.strip() and not line.startswith("#"))
                except IOError:
                    pass

    return counts


def _get_rustinel_version():
    """Get Rustinel version from binary."""
    exe = os.path.join(RUSTINEL_INSTALL_DIR, "rustinel.exe")
    if not os.path.isfile(exe):
        return None
    try:
        result = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=5)
        if result.stdout.strip():
            # Format: "rustinel x.y.z" or similar
            return result.stdout.strip()
    except Exception:
        pass
    return None


def _get_rustinel_etw_providers():
    """Parse config to list ETW providers Rustinel subscribes to."""
    config_path = os.path.join(RUSTINEL_INSTALL_DIR, "config.toml")
    # Known default providers from Rustinel
    providers = [
        {"name": "Microsoft-Windows-Kernel-Process", "keywords": "0x50"},
        {"name": "Microsoft-Windows-Kernel-Network", "keywords": "0x30"},
        {"name": "Microsoft-Windows-Kernel-File", "keywords": "0xE90"},
        {"name": "Microsoft-Windows-Kernel-Registry", "keywords": "0xF000"},
        {"name": "Microsoft-Windows-DNS-Client", "keywords": "all"},
        {"name": "Microsoft-Windows-PowerShell", "keywords": "all"},
        {"name": "Microsoft-Windows-WMI-Activity", "keywords": "all"},
        {"name": "Microsoft-Windows-Service-Control-Manager", "keywords": "all"},
        {"name": "Microsoft-Windows-TaskScheduler", "keywords": "all"},
    ]
    return providers


@app.route("/api/rustinel")
def api_rustinel():
    """Get detailed Rustinel engine status, loaded rules, and configuration."""
    proc_info = _get_rustinel_process()
    rules = _get_rustinel_rules()
    version = _get_rustinel_version()
    providers = _get_rustinel_etw_providers()

    # Parse log file for recent activity
    log_files = sorted(glob.glob(os.path.join(RUSTINEL_ALERTS_DIR, "rustinel.log.*")),
                       reverse=True)
    recent_log_lines = []
    if log_files:
        try:
            with open(log_files[0], "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
                recent_log_lines = [l.strip() for l in lines[-20:] if l.strip()]
        except IOError:
            pass

    info = {
        "online": proc_info is not None,
        "version": version,
        "process": proc_info,
        "install_dir": RUSTINEL_INSTALL_DIR,
        "alerts_dir": RUSTINEL_ALERTS_DIR,
        "rules": rules,
        "etw_providers": providers,
        "alerts_count": len(events_store.get("alerts", [])),
        "recent_log": recent_log_lines,
    }
    return jsonify(info)


@app.route("/api/alerts")
def api_alerts():
    """Get all Rustinel/Fibratus alerts."""
    with store_lock:
        alerts = events_store.get("alerts", [])
    # Filter by severity/engine/detonated if requested
    severity = request.args.get("severity")
    engine = request.args.get("engine")
    pid = request.args.get("pid", type=int)
    since = request.args.get("since")  # ISO timestamp - only alerts after this time
    detonated = request.args.get("detonated")

    if severity:
        alerts = [a for a in alerts if a.get("severity", "").lower() == severity.lower()]
    if engine:
        alerts = [a for a in alerts if a.get("engine", "").lower() == engine.lower()]
    if detonated and detonated.lower() in ("true", "1", "yes"):
        alerts = [a for a in alerts if a.get("detonated")]
    if pid:
        alerts = [a for a in alerts if a.get("pid") == pid]
    if since:
        # Normalize 'since' for comparison: strip timezone suffix for safe string compare
        # Both browser (UTC with Z) and Rustinel (possibly local without Z) timestamps
        # are ISO-ish; we compare by converting both to datetime
        from datetime import datetime, timezone
        try:
            since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            since_dt = None

        if since_dt:
            filtered = []
            for a in alerts:
                ts = a.get("timestamp", "")
                if not ts:
                    continue
                try:
                    # If timestamp has no tz info, assume local time
                    a_dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    if a_dt >= since_dt:
                        filtered.append(a)
                except (ValueError, TypeError):
                    # Fallback: string comparison
                    if ts >= since:
                        filtered.append(a)
            alerts = filtered

    return jsonify(alerts)


@app.route("/api/processes")
def api_processes():
    """Get process tree built from alerts."""
    with store_lock:
        processes = events_store.get("processes", {})
    return jsonify(processes)


@app.route("/api/sysmon")
def api_sysmon():
    """Get recent Sysmon events from Windows Event Log."""
    max_events = request.args.get("max", 100, type=int)
    since = request.args.get("since")
    pid = request.args.get("pid", type=int)
    event_id = request.args.get("event_id", type=int)

    events = _read_sysmon_events(max_events=max_events, since=since, pid=pid, event_id=event_id)
    return jsonify(events)


@app.route("/api/sysmon/stats")
def api_sysmon_stats():
    """Get Sysmon event counts by type."""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 500 -ErrorAction SilentlyContinue | "
             "Group-Object Id | Select-Object Name, Count | ConvertTo-Json"],
            capture_output=True, text=True, timeout=10
        )
        if result.stdout.strip():
            data = json.loads(result.stdout.strip())
            if isinstance(data, dict):
                data = [data]
            # Map event IDs to names
            event_names = {
                "1": "ProcessCreate", "2": "FileCreateTime", "3": "NetworkConnect",
                "4": "SysmonStateChange", "5": "ProcessTerminate", "6": "DriverLoad",
                "7": "ImageLoad", "8": "CreateRemoteThread", "9": "RawAccessRead",
                "10": "ProcessAccess", "11": "FileCreate", "12": "RegistryEvent",
                "13": "RegistryValueSet", "14": "RegistryRename", "15": "FileCreateStreamHash",
                "17": "PipeCreated", "18": "PipeConnected", "22": "DNSQuery",
                "23": "FileDelete", "25": "ProcessTampering", "26": "FileDeleteDetected",
            }
            stats = []
            for item in data:
                eid = str(item.get("Name", ""))
                stats.append({
                    "event_id": eid,
                    "name": event_names.get(eid, f"Event {eid}"),
                    "count": item.get("Count", 0),
                })
            return jsonify({"online": True, "stats": stats})
    except Exception as e:
        return jsonify({"online": False, "error": str(e), "stats": []})
    return jsonify({"online": False, "stats": []})


def _read_sysmon_events(max_events=100, since=None, pid=None, event_id=None):
    """Read Sysmon events from Windows Event Log with full XML field extraction."""
    # Build PowerShell script that parses XML and returns structured JSON
    filter_parts = "LogName='Microsoft-Windows-Sysmon/Operational'"
    if event_id:
        filter_parts += f";Id={event_id}"

    ps_cmd = (
        f"Get-WinEvent -FilterHashtable @{{{filter_parts}}} "
        f"-MaxEvents {max_events} -ErrorAction SilentlyContinue | "
        "ForEach-Object {"
        "  $xml = [xml]$_.ToXml();"
        "  $data = @{};"
        "  $xml.Event.EventData.Data | ForEach-Object {"
        "    $data[$_.Name] = $_.'#text'"
        "  };"
        "  $data['_EventId'] = $_.Id;"
        "  $data['_TimeCreated'] = $_.TimeCreated.ToString('o');"
        "  [PSCustomObject]$data"
        "} | ConvertTo-Json -Depth 3 -Compress"
    )

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=20
        )
        if result.stdout.strip():
            data = json.loads(result.stdout.strip())
            if isinstance(data, dict):
                data = [data]

            # Filter by PID if requested
            if pid:
                data = [e for e in data if str(e.get("ProcessId", "")) == str(pid)]

            # Structure events with key fields promoted
            events = []
            for item in data:
                eid = item.get("_EventId", 0)
                event = {
                    "timestamp": item.get("_TimeCreated", ""),
                    "event_id": eid,
                    "pid": item.get("ProcessId"),
                    "image": item.get("Image", ""),
                    "user": item.get("User", ""),
                }
                # Add type-specific fields
                if eid == 1:  # ProcessCreate
                    event["type"] = "ProcessCreate"
                    event["commandline"] = item.get("CommandLine", "")
                    event["parent_image"] = item.get("ParentImage", "")
                    event["parent_pid"] = item.get("ParentProcessId")
                    event["hashes"] = item.get("Hashes", "")
                    event["integrity"] = item.get("IntegrityLevel", "")
                elif eid == 3:  # NetworkConnect
                    event["type"] = "NetworkConnect"
                    event["dst_ip"] = item.get("DestinationIp", "")
                    event["dst_port"] = item.get("DestinationPort", "")
                    event["dst_hostname"] = item.get("DestinationHostname", "")
                    event["protocol"] = item.get("Protocol", "")
                elif eid == 5:  # ProcessTerminate
                    event["type"] = "ProcessTerminate"
                elif eid == 11:  # FileCreate
                    event["type"] = "FileCreate"
                    event["target"] = item.get("TargetFilename", "")
                elif eid == 12 or eid == 13 or eid == 14:  # Registry
                    event["type"] = "RegistryEvent"
                    event["target"] = item.get("TargetObject", "")
                    event["details"] = item.get("Details", "")
                elif eid == 22:  # DNSQuery
                    event["type"] = "DNSQuery"
                    event["query"] = item.get("QueryName", "")
                    event["result"] = item.get("QueryResults", "")
                elif eid == 7:  # ImageLoad
                    event["type"] = "ImageLoad"
                    event["loaded_image"] = item.get("ImageLoaded", "")
                    event["hashes"] = item.get("Hashes", "")
                elif eid == 8:  # CreateRemoteThread
                    event["type"] = "CreateRemoteThread"
                    event["source_pid"] = item.get("SourceProcessId")
                    event["target_pid"] = item.get("TargetProcessId")
                    event["target_image"] = item.get("TargetImage", "")
                elif eid == 10:  # ProcessAccess
                    event["type"] = "ProcessAccess"
                    event["source_image"] = item.get("SourceImage", "")
                    event["target_image"] = item.get("TargetImage", "")
                    event["access"] = item.get("GrantedAccess", "")
                else:
                    event["type"] = f"Event_{eid}"
                    # Include raw data for unknown types
                    event["raw"] = {k: v for k, v in item.items()
                                    if not k.startswith("_")}
                events.append(event)
            return events
    except Exception as e:
        return [{"error": str(e)}]
    return []


@app.route("/api/processes/<int:pid>")
def api_process_detail(pid):
    """Get details for a specific process."""
    with store_lock:
        processes = events_store.get("processes", {})
    proc = processes.get(pid) or processes.get(str(pid))
    if not proc:
        return jsonify({"error": "Process not found"}), 404
    return jsonify(proc)


@app.route("/api/sessions")
def api_sessions():
    """Get tracing sessions (grouped by execution)."""
    with store_lock:
        alerts = events_store.get("alerts", [])
    # Group alerts into sessions by time proximity
    sessions = []
    if alerts:
        sorted_alerts = sorted(alerts, key=lambda a: a.get("timestamp", ""))
        current_session = {"alerts": [], "start": "", "end": "", "processes": set()}
        for alert in sorted_alerts:
            current_session["alerts"].append(alert)
            if not current_session["start"]:
                current_session["start"] = alert.get("timestamp", "")
            current_session["end"] = alert.get("timestamp", "")
            if alert.get("pid"):
                current_session["processes"].add(alert["pid"])

        if current_session["alerts"]:
            current_session["processes"] = list(current_session["processes"])
            current_session["count"] = len(current_session["alerts"])
            sessions.append(current_session)

    return jsonify(sessions)


# --- Proxy routes to downstream services ---
@app.route("/api/detonator/<path:path>", methods=["GET", "POST", "PUT", "DELETE"])
def proxy_detonator(path):
    """Proxy requests to Detonator API."""
    url = f"{DETONATOR_API}/api/{path}"
    try:
        if request.method == "GET":
            r = requests.get(url, params=request.args, timeout=10)
        elif request.method == "POST":
            r = requests.post(url, json=request.get_json(silent=True),
                            data=request.form if not request.is_json else None,
                            files=request.files, timeout=30)
        elif request.method == "PUT":
            r = requests.put(url, json=request.get_json(silent=True), timeout=10)
        elif request.method == "DELETE":
            r = requests.delete(url, timeout=10)
        else:
            return jsonify({"error": "Method not allowed"}), 405
        return (r.content, r.status_code, {"Content-Type": r.headers.get("Content-Type", "application/json")})
    except requests.RequestException as e:
        return jsonify({"error": f"Detonator unavailable: {e}"}), 502


@app.route("/api/agent/<path:path>", methods=["GET", "POST"])
def proxy_agent(path):
    """Proxy requests to DetonatorAgent API."""
    url = f"{DETONATOR_AGENT_API}/api/{path}"
    try:
        if request.method == "GET":
            r = requests.get(url, params=request.args, timeout=10)
        else:
            r = requests.post(url, data=request.form, files=request.files, timeout=60)
        return (r.content, r.status_code, {"Content-Type": r.headers.get("Content-Type", "application/json")})
    except requests.RequestException as e:
        return jsonify({"error": f"DetonatorAgent unavailable: {e}"}), 502


@app.route("/api/litterbox/<path:path>", methods=["GET", "POST"])
def proxy_litterbox(path):
    """Proxy requests to LitterBox API."""
    url = f"{LITTERBOX_API}/api/{path}"
    try:
        if request.method == "GET":
            r = requests.get(url, params=request.args, timeout=10)
        else:
            r = requests.post(url, data=request.form, files=request.files, timeout=120)
        return (r.content, r.status_code, {"Content-Type": r.headers.get("Content-Type", "application/json")})
    except requests.RequestException as e:
        return jsonify({"error": f"LitterBox unavailable: {e}"}), 502


@app.route("/api/submit", methods=["POST"])
def api_submit():
    """Unified submission endpoint - sends to DetonatorAgent and optionally LitterBox.
    When LitterBox is targeted, also triggers static + dynamic analysis automatically."""
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    target = request.form.get("target", "agent")  # agent, litterbox, both
    results = {}

    file_bytes = file.read()
    filename = file.filename

    # Compute file hash and auto-feed to Rustinel IOC list
    file_sha256 = hashlib.sha256(file_bytes).hexdigest()
    ioc_result = _add_hash_to_ioc(file_sha256, filename)
    results["ioc_feed"] = ioc_result

    # Submit to DetonatorAgent
    agent_pid = None
    if target in ("agent", "both"):
        try:
            r = requests.post(
                f"{DETONATOR_AGENT_API}/api/execute/exec",
                files={"file": (filename, file_bytes)},
                timeout=60,
            )
            results["agent"] = {"status": r.status_code, "data": r.json() if r.ok else r.text}
            if r.ok:
                agent_data = r.json() if r.ok else {}
                if isinstance(agent_data, dict):
                    agent_pid = agent_data.get("pid")
        except Exception as e:
            results["agent"] = {"status": 502, "error": str(e)}

    # Submit to LitterBox + trigger analysis
    lb_hash = None
    if target in ("litterbox", "both"):
        try:
            # Step 1: Upload file to LitterBox
            r = requests.post(
                f"{LITTERBOX_API}/upload",
                files={"file": (filename, file_bytes)},
                timeout=120,
            )
            lb_upload = {"status": r.status_code}
            if r.ok:
                lb_data = r.json()
                lb_upload["data"] = lb_data
                lb_hash = lb_data.get("file_info", {}).get("sha256") or lb_data.get("file_info", {}).get("hash")
            else:
                lb_upload["error"] = r.text
            results["litterbox"] = lb_upload

            # Step 2: Trigger static analysis (non-blocking for response, but fire it)
            if lb_hash:
                try:
                    rs = requests.post(
                        f"{LITTERBOX_API}/analyze/static/{lb_hash}",
                        timeout=180,
                    )
                    results["litterbox_static"] = {
                        "status": rs.status_code,
                        "triggered": rs.status_code < 500,
                    }
                except Exception as e:
                    results["litterbox_static"] = {"status": 502, "error": str(e), "triggered": False}

                # Step 3: Trigger dynamic analysis (uses PID from agent if available, else file hash)
                if agent_pid:
                    try:
                        rd = requests.post(
                            f"{LITTERBOX_API}/analyze/dynamic/{agent_pid}",
                            timeout=300,
                        )
                        results["litterbox_dynamic"] = {
                            "status": rd.status_code,
                            "triggered": rd.status_code < 500,
                            "target": f"pid:{agent_pid}",
                        }
                    except Exception as e:
                        results["litterbox_dynamic"] = {"status": 502, "error": str(e), "triggered": False}
                else:
                    try:
                        rd = requests.post(
                            f"{LITTERBOX_API}/analyze/dynamic/{lb_hash}",
                            timeout=300,
                        )
                        results["litterbox_dynamic"] = {
                            "status": rd.status_code,
                            "triggered": rd.status_code < 500,
                            "target": f"hash:{lb_hash}",
                        }
                    except Exception as e:
                        results["litterbox_dynamic"] = {"status": 502, "error": str(e), "triggered": False}

        except Exception as e:
            results["litterbox"] = {"status": 502, "error": str(e)}

    # Include file metadata in response
    results["file_info"] = {
        "name": filename,
        "size": len(file_bytes),
        "sha256": file_sha256,
        "litterbox_hash": lb_hash,
        "agent_pid": agent_pid,
    }

    # Record submission in history
    _record_submission(filename, file_sha256, len(file_bytes), target, results)

    return jsonify(results)


@app.route("/api/submissions")
def api_submissions():
    """Return submission history list."""
    with submissions_lock:
        subs = _load_submissions()
    return jsonify(subs)


@app.route("/api/detonation/results")
def api_detonation_results():
    """Poll for combined detonation results: LitterBox static/dynamic + Fibratus/Rustinel alerts.
    Query params: sha256 (file hash), pid (agent PID), litterbox_hash (LB hash if different)."""
    sha256 = request.args.get("sha256", "")
    pid = request.args.get("pid", "")
    lb_hash = request.args.get("litterbox_hash", "") or sha256

    results = {"sha256": sha256, "pid": pid, "ready": {}}

    # --- LitterBox Static Results ---
    if lb_hash:
        try:
            r = requests.get(f"{LITTERBOX_API}/api/results/static/{lb_hash}", timeout=5)
            if r.status_code == 200:
                results["litterbox_static"] = r.json()
                results["ready"]["static"] = True
            else:
                results["ready"]["static"] = False
        except Exception:
            results["ready"]["static"] = False

    # --- LitterBox Dynamic Results ---
    if pid:
        try:
            r = requests.get(f"{LITTERBOX_API}/api/results/dynamic/{pid}", timeout=5)
            if r.status_code == 200:
                results["litterbox_dynamic"] = r.json()
                results["ready"]["dynamic"] = True
            else:
                results["ready"]["dynamic"] = False
        except Exception:
            results["ready"]["dynamic"] = False
    elif lb_hash:
        try:
            r = requests.get(f"{LITTERBOX_API}/api/results/dynamic/{lb_hash}", timeout=5)
            if r.status_code == 200:
                results["litterbox_dynamic"] = r.json()
                results["ready"]["dynamic"] = True
            else:
                results["ready"]["dynamic"] = False
        except Exception:
            results["ready"]["dynamic"] = False

    # --- LitterBox File Info (includes basic PE info, hashes) ---
    if lb_hash:
        try:
            r = requests.get(f"{LITTERBOX_API}/api/results/info/{lb_hash}", timeout=5)
            if r.status_code == 200:
                results["litterbox_info"] = r.json()
        except Exception:
            pass

    # --- Fibratus / Rustinel Alerts matching this detonation ---
    matching_alerts = []
    search_terms = set()
    if pid:
        search_terms.add(str(pid))
    if sha256:
        search_terms.add(sha256[:16])  # Partial match on hash prefix

    for alert in events_store.get("alerts", []):
        # Match by PID
        alert_pid = str(alert.get("process", {}).get("pid", ""))
        alert_hash = alert.get("file", {}).get("hash", {}).get("sha256", "") or ""
        alert_name = alert.get("process", {}).get("name", "") or ""

        if pid and alert_pid == str(pid):
            matching_alerts.append(alert)
        elif sha256 and sha256.lower() in alert_hash.lower():
            matching_alerts.append(alert)

    results["fibratus_alerts"] = matching_alerts[:50]
    results["fibratus_alert_count"] = len(matching_alerts)
    results["ready"]["fibratus"] = len(matching_alerts) > 0

    return jsonify(results)


def _add_hash_to_ioc(sha256_hash, filename=""):
    """Add a file hash to Rustinel's IOC hash feed for real-time detection."""
    # Try multiple possible IOC paths
    ioc_paths = [
        os.path.join(RUSTINEL_INSTALL_DIR, "rules", "ioc", "hashes.txt"),
        r"C:\tools\detection-rules\ioc\hashes.txt",
    ]

    for hashes_file in ioc_paths:
        if os.path.isfile(hashes_file):
            try:
                # Check if hash already exists
                with open(hashes_file, "r") as f:
                    existing = f.read()
                if sha256_hash in existing:
                    return {"status": "exists", "path": hashes_file}

                # Append hash with comment
                with open(hashes_file, "a") as f:
                    comment = f"  # {filename}" if filename else ""
                    f.write(f"{sha256_hash}{comment}\n")
                return {"status": "added", "path": hashes_file, "hash": sha256_hash}
            except (IOError, OSError) as e:
                return {"status": "error", "error": str(e)}

    # No IOC file found - create one in the default location
    default_path = os.path.join(RUSTINEL_INSTALL_DIR, "rules", "ioc", "hashes.txt")
    try:
        os.makedirs(os.path.dirname(default_path), exist_ok=True)
        with open(default_path, "a") as f:
            comment = f"  # {filename}" if filename else ""
            f.write(f"{sha256_hash}{comment}\n")
        return {"status": "created", "path": default_path, "hash": sha256_hash}
    except (IOError, OSError) as e:
        return {"status": "error", "error": str(e)}


@app.route("/api/file/download")
def api_file_download():
    """Serve a file for download given its path (only from monitored directories)."""
    filepath = request.args.get("path", "")
    if not filepath:
        return jsonify({"error": "No path specified"}), 400

    # Security: only allow files from known monitored directories
    allowed_prefixes = [
        os.path.normpath(RUSTINEL_ALERTS_DIR),
        r"C:\Users",
        r"C:\Windows\Temp",
        r"C:\Temp",
    ]
    norm_path = os.path.normpath(filepath)
    if not any(norm_path.startswith(prefix) for prefix in allowed_prefixes):
        return jsonify({"error": "Access denied: path outside allowed directories"}), 403

    if not os.path.isfile(norm_path):
        return jsonify({"error": "File not found"}), 404

    directory = os.path.dirname(norm_path)
    filename = os.path.basename(norm_path)
    return send_from_directory(directory, filename, as_attachment=True)


@app.route("/api/file/hex")
def api_file_hex():
    """Return hex dump of a file's bytes starting from a given offset."""
    filepath = request.args.get("path", "")
    num_bytes = min(request.args.get("bytes", 8192, type=int), 65536)
    start_offset = max(request.args.get("offset", 0, type=int), 0)

    if not filepath:
        return jsonify({"error": "No path specified"}), 400

    norm_path = os.path.normpath(filepath)
    if not os.path.isfile(norm_path):
        return jsonify({"error": "File not found", "hex": ""}), 404

    try:
        file_size = os.path.getsize(norm_path)
        with open(norm_path, "rb") as f:
            f.seek(start_offset)
            data = f.read(num_bytes)

        # Generate hex dump
        lines = []
        for line_offset in range(0, len(data), 16):
            chunk = data[line_offset:line_offset + 16]
            hex_part = " ".join(f"{b:02x}" for b in chunk[:8])
            hex_part += "  " + " ".join(f"{b:02x}" for b in chunk[8:])
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            abs_offset = start_offset + line_offset
            lines.append(f"{abs_offset:08x}  {hex_part:<49s} |{ascii_part}|")

        # Also provide raw bytes as list for the data inspector
        raw_bytes = list(data)

        return jsonify({
            "hex": "\n".join(lines),
            "size": file_size,
            "bytes_shown": len(data),
            "offset": start_offset,
            "raw_bytes": raw_bytes,
        })
    except (IOError, OSError) as e:
        return jsonify({"error": str(e), "hex": ""}), 500


@app.route("/api/file/hex/upload", methods=["POST"])
def api_file_hex_upload():
    """Accept a file upload, save to temp, return hex dump + path for further pagination."""
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    filename = file.filename or "uploaded_file"
    file_bytes = file.read()

    # Save to a temp directory for subsequent pagination requests
    import tempfile
    hex_temp_dir = os.path.join(tempfile.gettempdir(), "hex_uploads")
    os.makedirs(hex_temp_dir, exist_ok=True)

    # Use hash-based name to avoid conflicts but keep extension
    file_hash = hashlib.sha256(file_bytes).hexdigest()[:16]
    safe_name = "".join(c for c in filename if c.isalnum() or c in ".-_")[:80]
    dest_path = os.path.join(hex_temp_dir, f"{file_hash}_{safe_name}")

    with open(dest_path, "wb") as f:
        f.write(file_bytes)

    # Generate initial hex dump
    num_bytes = min(request.form.get("bytes", 512, type=int), 65536)
    lines = []
    for line_offset in range(0, min(len(file_bytes), num_bytes), 16):
        chunk = file_bytes[line_offset:line_offset + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk[:8])
        hex_part += "  " + " ".join(f"{b:02x}" for b in chunk[8:])
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{line_offset:08x}  {hex_part:<49s} |{ascii_part}|")

    return jsonify({
        "hex": "\n".join(lines),
        "size": len(file_bytes),
        "bytes_shown": min(len(file_bytes), num_bytes),
        "offset": 0,
        "raw_bytes": list(file_bytes[:num_bytes]),
        "path": dest_path,
        "filename": filename,
    })


@app.route("/api/file/hex/write", methods=["POST"])
def api_file_hex_write():
    """Write modified bytes back to a file at a specific offset (hex editor save)."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "No JSON body provided"}), 400

    filepath = data.get("path", "")
    offset = data.get("offset", 0)
    byte_values = data.get("bytes", [])  # List of int values 0-255

    if not filepath:
        return jsonify({"error": "No path specified"}), 400
    if not byte_values:
        return jsonify({"error": "No bytes to write"}), 400

    norm_path = os.path.normpath(filepath)

    # Security: only allow writes to user-writable directories
    allowed_write_prefixes = [
        r"C:\Users",
        r"C:\Temp",
        r"C:\Windows\Temp",
    ]
    if not any(norm_path.startswith(prefix) for prefix in allowed_write_prefixes):
        return jsonify({"error": "Access denied: write not allowed to this path"}), 403

    if not os.path.isfile(norm_path):
        return jsonify({"error": "File not found"}), 404

    try:
        # Validate byte values
        raw_bytes = bytes([b & 0xFF for b in byte_values])

        with open(norm_path, "r+b") as f:
            f.seek(offset)
            f.write(raw_bytes)

        return jsonify({
            "status": "ok",
            "path": norm_path,
            "offset": offset,
            "bytes_written": len(raw_bytes),
        })
    except (IOError, OSError) as e:
        return jsonify({"error": str(e)}), 500


# --- ThreatCheck / DefenderCheck Integration ---
THREATCHECK_EXE = r"C:\tools\ThreatCheck\bin\ThreatCheck.exe"
DEFENDERCHECK_EXE = r"C:\tools\DefenderCheck\bin\DefenderCheck.exe"


@app.route("/api/scan/threatcheck", methods=["POST"])
def api_scan_threatcheck():
    """Run ThreatCheck on an uploaded file or a VM path."""
    engine = request.form.get("engine", "Defender")  # Defender or AMSI
    file_type = request.form.get("type", "Bin")  # Bin or Script
    filepath = request.form.get("path", "")

    if not os.path.isfile(THREATCHECK_EXE):
        return jsonify({"error": "ThreatCheck not installed"}), 500

    # If file uploaded, save to temp
    if "file" in request.files:
        file = request.files["file"]
        file_bytes = file.read()
        import tempfile
        temp_dir = os.path.join(tempfile.gettempdir(), "scan_uploads")
        os.makedirs(temp_dir, exist_ok=True)
        filepath = os.path.join(temp_dir, file.filename or "scan_target")
        with open(filepath, "wb") as f:
            f.write(file_bytes)
    elif not filepath or not os.path.isfile(filepath):
        return jsonify({"error": "No file provided or path not found"}), 400

    try:
        args = [THREATCHECK_EXE, "-f", filepath, "-e", engine]
        if file_type == "Script":
            args.extend(["-t", "Script"])
        result = subprocess.run(
            args, capture_output=True, text=True, timeout=120,
            cwd=os.path.dirname(THREATCHECK_EXE)
        )
        output = (result.stdout or "") + (result.stderr or "")
        detected = "Identified" in output or "DETECTED" in output.upper()
        clean = "No threat found" in output

        return jsonify({
            "tool": "ThreatCheck",
            "engine": engine,
            "file_type": file_type,
            "filepath": filepath,
            "output": output.strip(),
            "detected": detected,
            "clean": clean,
            "exit_code": result.returncode,
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": "ThreatCheck timed out (120s)"}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/scan/defendercheck", methods=["POST"])
def api_scan_defendercheck():
    """Run DefenderCheck on an uploaded file or a VM path."""
    filepath = request.form.get("path", "")

    if not os.path.isfile(DEFENDERCHECK_EXE):
        return jsonify({"error": "DefenderCheck not installed"}), 500

    # If file uploaded, save to temp
    if "file" in request.files:
        file = request.files["file"]
        file_bytes = file.read()
        import tempfile
        temp_dir = os.path.join(tempfile.gettempdir(), "scan_uploads")
        os.makedirs(temp_dir, exist_ok=True)
        filepath = os.path.join(temp_dir, file.filename or "scan_target")
        with open(filepath, "wb") as f:
            f.write(file_bytes)
    elif not filepath or not os.path.isfile(filepath):
        return jsonify({"error": "No file provided or path not found"}), 400

    try:
        result = subprocess.run(
            [DEFENDERCHECK_EXE, filepath],
            capture_output=True, text=True, timeout=120,
            cwd=os.path.dirname(DEFENDERCHECK_EXE)
        )
        output = (result.stdout or "") + (result.stderr or "")
        detected = "Identified" in output or "detected" in output.lower()
        clean = "No threat found" in output

        return jsonify({
            "tool": "DefenderCheck",
            "filepath": filepath,
            "output": output.strip(),
            "detected": detected,
            "clean": clean,
            "exit_code": result.returncode,
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": "DefenderCheck timed out (120s)"}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/scan/status")
def api_scan_status():
    """Return availability status of scanning tools."""
    return jsonify({
        "threatcheck": {
            "installed": os.path.isfile(THREATCHECK_EXE),
            "path": THREATCHECK_EXE,
        },
        "defendercheck": {
            "installed": os.path.isfile(DEFENDERCHECK_EXE),
            "path": DEFENDERCHECK_EXE,
        },
    })


# --- PE Analysis ---
# Suspicious API calls grouped by category (IOC indicators)
SUSPICIOUS_IMPORTS = {
    "process_injection": [
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "NtCreateThreadEx", "QueueUserAPC", "SetThreadContext",
        "NtUnmapViewOfSection", "NtWriteVirtualMemory", "RtlCreateUserThread",
    ],
    "process_hollowing": [
        "NtUnmapViewOfSection", "ZwUnmapViewOfSection", "NtWriteVirtualMemory",
    ],
    "code_injection": [
        "VirtualAlloc", "VirtualProtect", "VirtualProtectEx",
        "NtProtectVirtualMemory", "WriteProcessMemory",
    ],
    "privilege_escalation": [
        "AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValue",
        "ImpersonateLoggedOnUser", "DuplicateToken",
    ],
    "defense_evasion": [
        "NtSetInformationThread", "CheckRemoteDebuggerPresent",
        "IsDebuggerPresent", "OutputDebugString", "NtQueryInformationProcess",
        "GetTickCount", "QueryPerformanceCounter",
    ],
    "persistence": [
        "RegSetValueEx", "RegCreateKeyEx", "CreateService",
        "StartServiceCtrlDispatcher", "RegisterServiceCtrlHandler",
    ],
    "credential_access": [
        "CredEnumerate", "CryptUnprotectData", "LsaEnumerateLogonSessions",
        "SamIConnect", "SamrQueryInformationUser",
    ],
    "networking": [
        "InternetOpen", "InternetOpenUrl", "HttpSendRequest",
        "URLDownloadToFile", "WinHttpOpen", "WinHttpConnect",
        "WSAStartup", "connect", "send", "recv", "socket",
    ],
    "crypto": [
        "CryptEncrypt", "CryptDecrypt", "CryptCreateHash",
        "CryptHashData", "CryptDeriveKey", "CryptGenKey",
        "BCryptEncrypt", "BCryptDecrypt",
    ],
    "shellcode": [
        "GetProcAddress", "LoadLibrary", "LoadLibraryA", "LoadLibraryW",
        "GetModuleHandle", "GetModuleHandleA",
    ],
}

# Known packer/protector section names
PACKER_SECTIONS = {
    "UPX0": "UPX", "UPX1": "UPX", "UPX2": "UPX",
    ".aspack": "ASPack", ".adata": "ASPack",
    ".nsp0": "NsPack", ".nsp1": "NsPack",
    ".themida": "Themida", ".tls": "Possible Themida/VMProtect",
    ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".vmp2": "VMProtect",
    "pec": "PECompact", "pec2": "PECompact",
    ".petite": "Petite", ".shrink": "Shrinker",
    ".enigma1": "Enigma Protector", ".enigma2": "Enigma Protector",
    "MEW": "MEW Packer", ".mpress1": "MPRESS", ".mpress2": "MPRESS",
    ".rpcsscn": "RPCScan", ".packed": "Generic Packer",
    ".RLPack": "RLPack",
}

ENTROPY_HIGH_THRESHOLD = 7.0  # Shannon entropy indicating encrypted/compressed
ENTROPY_WARN_THRESHOLD = 6.5


def calculate_entropy(data):
    """Calculate Shannon entropy of a byte sequence."""
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


@app.route("/api/file/pe")
def api_file_pe():
    """Parse PE header and return structured analysis with IOC indicators."""
    filepath = request.args.get("path", "")
    if not filepath:
        return jsonify({"error": "No path specified"}), 400

    norm_path = os.path.normpath(filepath)
    if not os.path.isfile(norm_path):
        return jsonify({"error": "File not found"}), 404

    try:
        import pefile
    except ImportError:
        return jsonify({"error": "pefile module not installed"}), 500

    try:
        pe = pefile.PE(norm_path, fast_load=False)
    except pefile.PEFormatError as e:
        return jsonify({"error": f"Not a valid PE file: {e}"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    result = {"valid": True, "path": filepath}

    # --- DOS Header ---
    result["dos_header"] = {
        "e_magic": hex(pe.DOS_HEADER.e_magic),
        "e_lfanew": hex(pe.DOS_HEADER.e_lfanew),
    }

    # --- File Header ---
    machine_map = {0x14c: "i386", 0x8664: "AMD64", 0xaa64: "ARM64", 0x1c0: "ARM"}
    fh = pe.FILE_HEADER
    result["file_header"] = {
        "machine": machine_map.get(fh.Machine, hex(fh.Machine)),
        "machine_raw": hex(fh.Machine),
        "num_sections": fh.NumberOfSections,
        "timestamp": fh.TimeDateStamp,
        "timestamp_utc": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(fh.TimeDateStamp)),
        "characteristics": hex(fh.Characteristics),
        "is_dll": bool(fh.Characteristics & 0x2000),
        "is_exe": bool(fh.Characteristics & 0x0002),
        "is_large_address_aware": bool(fh.Characteristics & 0x0020),
        "symbols_stripped": bool(fh.Characteristics & 0x0008),
    }

    # --- Optional Header ---
    oh = pe.OPTIONAL_HEADER
    result["optional_header"] = {
        "magic": hex(oh.Magic),
        "is_pe32_plus": oh.Magic == 0x20b,
        "linker_version": f"{oh.MajorLinkerVersion}.{oh.MinorLinkerVersion}",
        "entry_point": hex(oh.AddressOfEntryPoint),
        "image_base": hex(oh.ImageBase),
        "section_alignment": oh.SectionAlignment,
        "file_alignment": oh.FileAlignment,
        "os_version": f"{oh.MajorOperatingSystemVersion}.{oh.MinorOperatingSystemVersion}",
        "subsystem": oh.Subsystem,
        "subsystem_name": pefile.SUBSYSTEM_TYPE.get(oh.Subsystem, "Unknown"),
        "dll_characteristics": hex(oh.DllCharacteristics),
        "aslr": bool(oh.DllCharacteristics & 0x0040),
        "dep_nx": bool(oh.DllCharacteristics & 0x0100),
        "no_seh": bool(oh.DllCharacteristics & 0x0400),
        "cfg": bool(oh.DllCharacteristics & 0x4000),
        "size_of_image": oh.SizeOfImage,
        "size_of_headers": oh.SizeOfHeaders,
        "checksum": hex(oh.CheckSum),
        "checksum_valid": pe.verify_checksum(),
    }

    # --- Sections with entropy ---
    sections = []
    file_data = open(norm_path, "rb").read()
    total_entropy = calculate_entropy(file_data)
    result["total_entropy"] = total_entropy

    for section in pe.sections:
        sec_name = section.Name.decode("utf-8", errors="replace").rstrip("\x00")
        sec_data = section.get_data()
        entropy = calculate_entropy(sec_data)
        sec_info = {
            "name": sec_name,
            "virtual_address": hex(section.VirtualAddress),
            "virtual_size": section.Misc_VirtualSize,
            "raw_size": section.SizeOfRawData,
            "raw_offset": hex(section.PointerToRawData),
            "characteristics": hex(section.Characteristics),
            "executable": bool(section.Characteristics & 0x20000000),
            "writable": bool(section.Characteristics & 0x80000000),
            "readable": bool(section.Characteristics & 0x40000000),
            "entropy": entropy,
            "entropy_status": "high" if entropy >= ENTROPY_HIGH_THRESHOLD else "warn" if entropy >= ENTROPY_WARN_THRESHOLD else "normal",
            "size_ratio": round(section.SizeOfRawData / max(section.Misc_VirtualSize, 1), 3) if section.Misc_VirtualSize > 0 else 0,
        }
        # Check for packer section names
        for packer_name, packer_label in PACKER_SECTIONS.items():
            if sec_name.lower().startswith(packer_name.lower()):
                sec_info["packer_indicator"] = packer_label
                break
        # Flag if section is both writable and executable (RWX)
        if sec_info["executable"] and sec_info["writable"]:
            sec_info["rwx_warning"] = True
        sections.append(sec_info)

    result["sections"] = sections

    # --- Imports analysis ---
    imports = []
    suspicious_found = {}
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode("utf-8", errors="replace")
            funcs = []
            for imp in entry.imports:
                func_name = imp.name.decode("utf-8", errors="replace") if imp.name else f"Ordinal_{imp.ordinal}"
                funcs.append({"name": func_name, "address": hex(imp.address) if imp.address else None})
                # Check against suspicious list
                for category, api_list in SUSPICIOUS_IMPORTS.items():
                    if func_name in api_list:
                        if category not in suspicious_found:
                            suspicious_found[category] = []
                        suspicious_found[category].append({"dll": dll_name, "function": func_name})
            imports.append({"dll": dll_name, "functions": funcs, "count": len(funcs)})

    result["imports"] = imports
    result["suspicious_imports"] = suspicious_found
    result["import_count"] = sum(i["count"] for i in imports)
    result["dll_count"] = len(imports)

    # --- Exports ---
    exports = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            exp_name = exp.name.decode("utf-8", errors="replace") if exp.name else f"Ordinal_{exp.ordinal}"
            exports.append({"name": exp_name, "ordinal": exp.ordinal, "address": hex(exp.address)})
    result["exports"] = exports

    # --- Resources (brief) ---
    resources = []
    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        def _walk_resources(entries, level=0):
            for entry in entries:
                r = {"id": entry.id, "name": entry.name.string.decode() if entry.name else None}
                if hasattr(entry, "directory"):
                    _walk_resources(entry.directory.entries, level + 1)
                else:
                    data_entry = entry.data
                    r["size"] = data_entry.struct.Size
                    r["offset"] = hex(data_entry.struct.OffsetToData)
                    r["entropy"] = calculate_entropy(
                        pe.get_data(data_entry.struct.OffsetToData, data_entry.struct.Size)
                    )
                    resources.append(r)
        _walk_resources(pe.DIRECTORY_ENTRY_RESOURCE.entries)
    result["resources"] = resources[:50]  # Cap at 50

    # --- TLS callbacks (anti-debug indicator) ---
    tls_callbacks = []
    if hasattr(pe, "DIRECTORY_ENTRY_TLS"):
        tls = pe.DIRECTORY_ENTRY_TLS
        if tls.struct.AddressOfCallBacks:
            callback_rva = tls.struct.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase
            try:
                idx = 0
                while True:
                    cb_addr = pe.get_dword_at_rva(callback_rva + idx * 4)
                    if cb_addr == 0:
                        break
                    tls_callbacks.append(hex(cb_addr))
                    idx += 1
                    if idx > 20:
                        break
            except Exception:
                pass
    result["tls_callbacks"] = tls_callbacks

    # --- IOC Summary / Flags ---
    flags = []
    if suspicious_found:
        for cat, items in suspicious_found.items():
            flags.append({"type": "suspicious_import", "category": cat, "severity": "high" if cat in ("process_injection", "process_hollowing", "credential_access") else "medium", "detail": f"{len(items)} suspicious API(s) in category '{cat}'"})
    for sec in sections:
        if sec.get("rwx_warning"):
            flags.append({"type": "rwx_section", "severity": "high", "detail": f"Section '{sec['name']}' is Read+Write+Execute"})
        if sec["entropy_status"] == "high":
            flags.append({"type": "high_entropy", "severity": "medium", "detail": f"Section '{sec['name']}' entropy {sec['entropy']:.2f} (encrypted/packed)"})
        if sec.get("packer_indicator"):
            flags.append({"type": "packer", "severity": "medium", "detail": f"Section '{sec['name']}' matches packer: {sec['packer_indicator']}"})
    if tls_callbacks:
        flags.append({"type": "tls_callback", "severity": "medium", "detail": f"{len(tls_callbacks)} TLS callback(s) detected (possible anti-debug)"})
    if not result["optional_header"]["aslr"]:
        flags.append({"type": "no_aslr", "severity": "low", "detail": "ASLR not enabled"})
    if not result["optional_header"]["dep_nx"]:
        flags.append({"type": "no_dep", "severity": "low", "detail": "DEP/NX not enabled"})
    if total_entropy >= ENTROPY_HIGH_THRESHOLD:
        flags.append({"type": "high_total_entropy", "severity": "medium", "detail": f"Overall file entropy {total_entropy:.2f} suggests packing/encryption"})

    result["flags"] = flags
    result["flag_count"] = {"high": len([f for f in flags if f["severity"] == "high"]), "medium": len([f for f in flags if f["severity"] == "medium"]), "low": len([f for f in flags if f["severity"] == "low"])}

    pe.close()
    return jsonify(result)


@app.route("/api/file/pe/section")
def api_file_pe_section():
    """Return detailed data for a specific PE section including hex dump and strings."""
    filepath = request.args.get("path", "")
    section_idx = request.args.get("index", type=int)
    max_bytes = request.args.get("max_bytes", 4096, type=int)

    if not filepath:
        return jsonify({"error": "No path specified"}), 400
    if section_idx is None:
        return jsonify({"error": "No section index specified"}), 400

    norm_path = os.path.normpath(filepath)
    if not os.path.isfile(norm_path):
        return jsonify({"error": "File not found"}), 404

    try:
        import pefile
    except ImportError:
        return jsonify({"error": "pefile module not installed"}), 500

    try:
        pe = pefile.PE(norm_path, fast_load=False)
    except pefile.PEFormatError as e:
        return jsonify({"error": f"Not a valid PE file: {e}"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    if section_idx < 0 or section_idx >= len(pe.sections):
        pe.close()
        return jsonify({"error": f"Section index {section_idx} out of range (0-{len(pe.sections)-1})"}), 400

    section = pe.sections[section_idx]
    sec_name = section.Name.decode("utf-8", errors="replace").rstrip("\x00")
    sec_data = section.get_data()
    entropy = calculate_entropy(sec_data)

    # Build characteristic flags detail
    char_flags = []
    char_val = section.Characteristics
    flag_defs = [
        (0x00000020, "CNT_CODE", "Contains executable code"),
        (0x00000040, "CNT_INITIALIZED_DATA", "Contains initialized data"),
        (0x00000080, "CNT_UNINITIALIZED_DATA", "Contains uninitialized data"),
        (0x00000200, "LNK_INFO", "Contains comments or other info"),
        (0x00000800, "LNK_REMOVE", "Will not become part of image"),
        (0x00001000, "LNK_COMDAT", "Contains COMDAT data"),
        (0x00004000, "NO_DEFER_SPEC_EXC", "Reset speculative exception handling"),
        (0x00008000, "GPREL", "Contains GP-relative data"),
        (0x01000000, "LNK_NRELOC_OVFL", "Extended relocations"),
        (0x02000000, "MEM_DISCARDABLE", "Can be discarded as needed"),
        (0x04000000, "MEM_NOT_CACHED", "Cannot be cached"),
        (0x08000000, "MEM_NOT_PAGED", "Not pageable"),
        (0x10000000, "MEM_SHARED", "Can be shared in memory"),
        (0x20000000, "MEM_EXECUTE", "Can be executed as code"),
        (0x40000000, "MEM_READ", "Readable"),
        (0x80000000, "MEM_WRITE", "Writable"),
    ]
    for mask, name, desc in flag_defs:
        if char_val & mask:
            char_flags.append({"flag": name, "description": desc})

    # Generate hex dump of section data (limited)
    display_size = min(len(sec_data), max_bytes)
    hex_lines = []
    for offset in range(0, display_size, 16):
        chunk = sec_data[offset:offset + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        hex_lines.append(f"{offset:08x}  {hex_part:<48s} |{ascii_part}|")

    # Extract printable strings (min length 4)
    strings_found = []
    current = []
    str_offset = 0
    for i, b in enumerate(sec_data):
        if 32 <= b < 127:
            if not current:
                str_offset = i
            current.append(chr(b))
        else:
            if len(current) >= 4:
                strings_found.append({"offset": str_offset, "value": "".join(current)})
            current = []
    if len(current) >= 4:
        strings_found.append({"offset": str_offset, "value": "".join(current)})

    # Also look for wide (UTF-16 LE) strings
    wide_strings = []
    current = []
    str_offset = 0
    i = 0
    while i < len(sec_data) - 1:
        lo, hi = sec_data[i], sec_data[i + 1]
        if hi == 0 and 32 <= lo < 127:
            if not current:
                str_offset = i
            current.append(chr(lo))
        else:
            if len(current) >= 4:
                wide_strings.append({"offset": str_offset, "value": "".join(current), "encoding": "UTF-16LE"})
            current = []
        i += 2
    if len(current) >= 4:
        wide_strings.append({"offset": str_offset, "value": "".join(current), "encoding": "UTF-16LE"})

    result = {
        "index": section_idx,
        "name": sec_name,
        "virtual_address": hex(section.VirtualAddress),
        "virtual_size": section.Misc_VirtualSize,
        "raw_offset": hex(section.PointerToRawData),
        "raw_offset_dec": section.PointerToRawData,
        "raw_size": section.SizeOfRawData,
        "characteristics": hex(section.Characteristics),
        "characteristic_flags": char_flags,
        "entropy": entropy,
        "total_data_size": len(sec_data),
        "display_size": display_size,
        "hex_dump": "\n".join(hex_lines),
        "strings": strings_found[:500],
        "wide_strings": wide_strings[:200],
        "string_count": len(strings_found),
        "wide_string_count": len(wide_strings),
    }

    pe.close()
    return jsonify(result)


# --- Main ---
if __name__ == "__main__":
    # Start background alert loader
    loader = threading.Thread(target=alert_loader_thread, daemon=True)
    loader.start()

    print(f"[*] Detonation Chamber UI starting on http://0.0.0.0:{WEBUI_PORT}")
    print(f"    Rustinel alerts: {RUSTINEL_ALERTS_DIR}")
    print(f"    Detonator API:   {DETONATOR_API}")
    print(f"    Agent API:       {DETONATOR_AGENT_API}")
    print(f"    LitterBox:       {LITTERBOX_API}")

    app.run(host="0.0.0.0", port=WEBUI_PORT, debug=False)
