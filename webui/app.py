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
    """Unified submission endpoint - sends to DetonatorAgent and optionally LitterBox."""
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
    if target in ("agent", "both"):
        try:
            r = requests.post(
                f"{DETONATOR_AGENT_API}/api/execute/exec",
                files={"file": (filename, file_bytes)},
                timeout=60,
            )
            results["agent"] = {"status": r.status_code, "data": r.json() if r.ok else r.text}
        except Exception as e:
            results["agent"] = {"status": 502, "error": str(e)}

    # Submit to LitterBox
    if target in ("litterbox", "both"):
        try:
            r = requests.post(
                f"{LITTERBOX_API}/upload",
                files={"file": (filename, file_bytes)},
                timeout=120,
            )
            results["litterbox"] = {"status": r.status_code, "data": r.json() if r.ok else r.text}
        except Exception as e:
            results["litterbox"] = {"status": 502, "error": str(e)}

    # Include file metadata in response
    results["file_info"] = {
        "name": filename,
        "size": len(file_bytes),
        "sha256": file_sha256,
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
