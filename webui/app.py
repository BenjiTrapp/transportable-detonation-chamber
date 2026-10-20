"""
Detonation Chamber - Unified Web UI
Aggregates data from Rustinel, Fibratus, Detonator, DetonatorAgent, and LitterBox
into a single dark-themed interface inspired by the Rustinel tracing UI.

Run: python app.py
Access: http://localhost:9000
"""

import datetime
import json
import os
import glob
import platform
import time
import hashlib
import math
import struct
import threading
import subprocess
from pathlib import Path
from flask import Flask, render_template, jsonify, request, send_from_directory
from werkzeug.utils import secure_filename
import requests

# Tool-agnostic scoring layer for live-memory findings. Scanners are plugged in
# as normalizers there, so the verdict logic does not depend on any one tool.
import memory_evidence
# Offline analysis of exit-time minidumps (no scanner binary involved).
import minidump_analysis

app = Flask(__name__)

# --- Browser-side request forgery --------------------------------------
# The UI has no login (lab tool on an isolated network), but a browser on
# the VM or host can still be made to talk to it by any web page it opens:
#
#   * CSRF: a page posts a form or fetch() to http://<vm>:9000/api/submit.
#     Browsers mark such requests with the page's Origin (or Referer), so a
#     state-changing request naming a foreign origin is refused. Clients
#     without these headers (curl, MCP, scripts) are not affected.
#   * DNS rebinding: a page on evil.example re-points its own name to the VM
#     and then counts as same-origin - it could read every response. The Host
#     header still says evil.example, so only IP literals, localhost and the
#     names in TDC_ALLOWED_HOSTS are served.
from urllib.parse import urlparse as _urlparse
import ipaddress as _ipaddress

_ALLOWED_HOSTNAMES = {"localhost"} | {
    h.strip().lower() for h in os.environ.get("TDC_ALLOWED_HOSTS", "").split(",") if h.strip()}
_UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _host_allowed(host):
    host = (host or "").strip().lower()
    if host.startswith("["):                       # [::1]:9000
        name = host[1:host.find("]")] if "]" in host else host[1:]
    else:
        name = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
    if not name:
        return False
    if name in _ALLOWED_HOSTNAMES:
        return True
    try:
        _ipaddress.ip_address(name)
        return True
    except ValueError:
        return False


@app.before_request
def _block_cross_site_requests():
    if not _host_allowed(request.host):
        return jsonify({"error": "Host not allowed",
                        "hint": "use the IP address, or add the name to TDC_ALLOWED_HOSTS"}), 403
    if request.method in _UNSAFE_METHODS:
        source = request.headers.get("Origin") or request.headers.get("Referer")
        # "null" is what sandboxed iframes and file:// pages send.
        if source and (source == "null" or _urlparse(source).netloc.lower() != request.host.lower()):
            return jsonify({"error": "Cross-site request rejected"}), 403
    return None


@app.after_request
def _security_headers(resp):
    # No framing (clickjacking), no MIME sniffing of served samples/JSON, and
    # no URLs with sample paths leaking to other sites via Referer.
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Content-Security-Policy", "frame-ancestors 'none'")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    return resp


@app.route("/api/health")
def api_health():
    """Liveness probe."""
    return jsonify({"ok": True})

# --- Configuration ---
RUSTINEL_ALERTS_DIR = os.environ.get("RUSTINEL_ALERTS_DIR", r"C:\tools\rustinel\logs")
RUSTINEL_INSTALL_DIR = os.environ.get("RUSTINEL_INSTALL_DIR", r"C:\tools\rustinel")
DETONATOR_API = os.environ.get("DETONATOR_API", "http://127.0.0.1:8000")
DETONATOR_AGENT_API = os.environ.get("DETONATOR_AGENT_API", "http://127.0.0.1:8080")
LITTERBOX_API = os.environ.get("LITTERBOX_API", "http://127.0.0.1:1337")
WEBUI_PORT = int(os.environ.get("WEBUI_PORT", "9000"))
VM_IP = os.environ.get("TDC_VM_IP", "")
VM_WEBUI_URL = os.environ.get("TDC_VM_WEBUI", "")
SUBMISSIONS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "submissions.json")
SCAN_HISTORY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan_history.json")
SCAN_HISTORY_MAX = 200

# Keys of memory findings this host produces on its own. Captured while the box
# is considered clean, then subtracted from later scans - the memory-side
# counterpart to Process Dump's clean-hash database.
MEMORY_BASELINE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "memory_baseline.json")


def _decode_console(raw):
    """Decode output of a Windows console program.

    PowerShell and most built-in tools write the OEM code page (cp850 on a
    German system) to pipes, while newer tools write UTF-8. Python's
    text=True decodes as cp1252, where bytes such as 0x81 ("ü" in cp850) are
    undefined: the reader thread raises and stdout silently becomes None.
    """
    if not raw:
        return ""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        pass
    try:
        return raw.decode("oem", errors="replace")   # Windows only
    except LookupError:
        return raw.decode("latin-1")


def _run_cmd(args, timeout=None, **kwargs):
    """subprocess.run with captured output decoded by _decode_console.

    Returns a CompletedProcess whose stdout/stderr are str, like text=True,
    but without the cp1252 decoding failure described above.
    """
    kwargs.pop("text", None)
    kwargs.pop("capture_output", None)
    proc = subprocess.run(args, capture_output=True, timeout=timeout, **kwargs)
    proc.stdout = _decode_console(proc.stdout)
    proc.stderr = _decode_console(proc.stderr)
    return proc


def _path_within(path, roots):
    r"""True if `path` lies inside one of `roots`.

    A plain startswith() also accepts siblings (C:\TempX for C:\Temp) and
    is fooled by junctions; this resolves the real path and compares whole
    path components, case-insensitively as Windows does.
    """
    try:
        real = os.path.normcase(os.path.realpath(path))
    except (OSError, ValueError):
        return False
    for root in roots:
        try:
            base = os.path.normcase(os.path.realpath(root))
            if os.path.commonpath([real, base]) == base:
                return True
        except (OSError, ValueError):
            continue  # different drive, or unresolvable root
    return False


def _wevtutil_query(log, query=None, count=None, newest_first=True, timeout=30):
    """Run `wevtutil qe ... /f:xml` and return the XML text.

    wevtutil writes the ANSI code page by default (cp1252: "AUTORIT\xc4T"),
    which is neither UTF-8 nor what _decode_console expects; /uni:true makes
    it emit UTF-16 so event text from any locale survives intact.
    Raises subprocess.TimeoutExpired / OSError like subprocess.run.
    """
    args = ["wevtutil", "qe", log, "/f:xml", "/uni:true"]
    if query:
        args.append(f"/q:{query}")
    if count:
        args.append(f"/c:{int(count)}")
    if newest_first:
        args.append("/rd:true")
    proc = subprocess.run(args, capture_output=True, timeout=timeout,
                          creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    raw = proc.stdout or b""
    if raw[:2] == b"\xff\xfe":
        raw = raw[2:]
    return raw.decode("utf-16-le", errors="replace"), proc


def _detect_vm_ip():
    """Auto-detect Hyper-V VM IP if not configured via environment variable."""
    global VM_IP, VM_WEBUI_URL
    if VM_IP:
        return  # Already set via env var
    try:
        result = _run_cmd(
            ["powershell", "-NoProfile", "-Command",
             "(Get-VM -Name 'DetonationChamber' -ErrorAction SilentlyContinue | "
             "Get-VMNetworkAdapter).IPAddresses | Where-Object { $_ -match '^\\d+\\.\\d+\\.\\d+\\.\\d+$' } | Select-Object -First 1"],
            timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            VM_IP = result.stdout.strip()
            VM_WEBUI_URL = f"http://{VM_IP}:9000"
            print(f"[config] Auto-detected VM IP: {VM_IP}")
    except Exception:
        pass
    if not VM_IP:
        VM_IP = "172.17.251.7"  # Fallback
        VM_WEBUI_URL = f"http://{VM_IP}:9000"


_detect_vm_ip()

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

# --- Scan History (shared timeline across all static scanners) ---
# Persists every scan (EMBER, capa, ThreatCheck, DefenderCheck) regardless of
# how it was triggered (web UI, curl/API, or MCP - the MCP server proxies to
# these same /api/scan/* endpoints). Read back by GET /api/scan/history.
scan_history_lock = threading.Lock()


def _load_scan_history():
    if os.path.isfile(SCAN_HISTORY_FILE):
        try:
            with open(SCAN_HISTORY_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return []
    return []


def _save_scan_history(history):
    try:
        with open(SCAN_HISTORY_FILE, "w") as f:
            json.dump(history, f, indent=2)
    except IOError:
        pass


def _normalize_scan(tool, result):
    """Derive a normalized (verdict, detected, clean, score) from a raw scan
    result so the shared timeline can render a consistent status column."""
    verdict, detected, clean, score = "unknown", None, None, None
    if not isinstance(result, dict):
        return verdict, detected, clean, score
    if result.get("score") is not None:
        try:
            score = float(result["score"])
        except (TypeError, ValueError):
            score = None
    if str(result.get("verdict", "")).lower() in ("malicious", "benign"):  # EMBER
        verdict = str(result["verdict"]).lower()
        detected = bool(result.get("malicious"))
        clean = not detected
    elif "detected" in result or "clean" in result:  # ThreatCheck / DefenderCheck
        detected = bool(result.get("detected"))
        clean = bool(result.get("clean"))
        verdict = "detected" if detected else ("clean" if clean else "unknown")
    elif tool and tool.lower() == "capa":  # capa reports capabilities, not a verdict
        cc = result.get("capability_count")
        verdict = "analyzed" if cc is not None else "unknown"
    elif tool and tool.lower() == "aether":  # live-memory findings, not a file verdict
        # The evidence layer is authoritative: it already accounts for the host
        # baseline, persistence and corroboration.
        ev = result.get("evidence") or {}
        label = (ev.get("label") or "").upper()
        if label == "MALICIOUS":
            verdict, detected, clean = "detected", True, False
        elif label == "SUSPICIOUS":
            verdict, detected, clean = "suspicious", True, False
        elif label == "CLEAN":
            verdict, detected, clean = "clean", False, True
        if ev.get("score") is not None:
            score = ev["score"]
    elif tool and tool.lower() == "exit capture":  # post-mortem dump analysis
        ev = result.get("evidence") or {}
        label = (ev.get("label") or "").upper()
        if label == "MALICIOUS":
            verdict, detected, clean = "detected", True, False
        elif label == "SUSPICIOUS":
            verdict, detected, clean = "suspicious", True, False
        elif label == "CLEAN":
            verdict, detected, clean = "clean", False, True
        if ev.get("score") is not None:
            score = ev["score"]
    elif tool and tool.lower() == "process dump":  # extraction, not a verdict
        # Hidden modules and header-less code chunks are the interesting cases;
        # a plain module dump just means something new was on the box.
        if result.get("hidden_modules") or result.get("code_chunks"):
            verdict, detected, clean = "detected", True, False
        elif result.get("dump_count"):
            verdict = "dumped"
        elif result.get("dump_count") == 0:
            verdict, clean = "clean", True
    return verdict, detected, clean, score


def _record_scan(tool, filename, result, status="ok"):
    """Append a scan to the shared history timeline (best-effort).

    ``result`` is the full JSON dict returned to the client (stored verbatim
    for the "> more" expander); ``status`` is "ok", "timeout", or "error".
    """
    import datetime
    try:
        result = result if isinstance(result, dict) else {}
        verdict, detected, clean, score = _normalize_scan(tool, result)
        sha256 = result.get("sha256", "") or ""
        entry = {
            "id": hashlib.md5(f"{sha256}{tool}{time.time()}".encode()).hexdigest()[:12],
            "timestamp": datetime.datetime.now().isoformat(),
            "tool": tool or result.get("tool") or "?",
            "filename": filename or "--",
            "sha256": sha256,
            "size": result.get("size"),
            "status": status,
            "verdict": verdict,
            "detected": detected,
            "clean": clean,
            "score": score,
            "result": result,   # full result for the detail expander
        }
        with scan_history_lock:
            history = _load_scan_history()
            history.insert(0, entry)
            if len(history) > SCAN_HISTORY_MAX:
                del history[SCAN_HISTORY_MAX:]
            _save_scan_history(history)
    except Exception:
        pass  # history must never break a scan


# --- Scan <-> process/sample correlation (graph enrichment) ---

def _extract_sha256(hashes):
    """Pull the SHA256 out of a Sysmon EID-1 Hashes string such as
    'SHA1=..,MD5=..,SHA256=ABC..,IMPHASH=..'. Returns lowercase hex or ''."""
    if not hashes:
        return ""
    for part in str(hashes).replace(";", ",").split(","):
        part = part.strip()
        if part[:7].upper() == "SHA256=":
            return part.split("=", 1)[1].strip().lower()
    return ""


_PROCESS_SCAN_TOOLS = {"aether", "process dump", "exit capture", "hunt-sleeping-beacons", "beaconeye"}


def _summarize_scan_entry(e):
    """Compact per-tool scan summary for the graph. Carries the full ``result``
    so the detail-panel expander can reuse renderHistoryDetail()."""
    return {
        "tool": e.get("tool"),
        "verdict": e.get("verdict"),
        "detected": e.get("detected"),
        "clean": e.get("clean"),
        "score": e.get("score"),
        "status": e.get("status"),
        "timestamp": e.get("timestamp"),
        "id": e.get("id"),
        "sha256": e.get("sha256"),
        "size": e.get("size"),
        "filename": e.get("filename"),
        "result": e.get("result"),
    }


def _scan_index():
    """Index the scan-history timeline by sha256 and by filename. Each key maps
    to {tool: latest-summary}. History is newest-first, so the first entry seen
    per (key, tool) is the most recent one."""
    by_sha, by_name = {}, {}
    for e in _load_scan_history():
        if not isinstance(e, dict):
            continue
        tool = (e.get("tool") or "?").lower()
        summ = _summarize_scan_entry(e)
        sha = (e.get("sha256") or "").lower()
        if sha:
            by_sha.setdefault(sha, {}).setdefault(tool, summ)
        nm = (e.get("filename") or "").lower()
        if nm and nm != "--":
            by_name.setdefault(nm, {}).setdefault(tool, summ)
    return by_sha, by_name


def _overall_verdict(summaries):
    """Roll up per-tool verdicts into one label for a badge."""
    if not summaries:
        return "unknown"
    if any(s.get("verdict") == "malicious" or s.get("detected") for s in summaries):
        return "malicious"
    if any(s.get("verdict") == "detected" for s in summaries):
        return "detected"
    if any((s.get("verdict") in ("clean", "benign")) or s.get("clean") for s in summaries):
        return "clean"
    if any(s.get("verdict") == "analyzed" for s in summaries):
        return "analyzed"
    return "unknown"


def _scans_for_node(node, by_sha):
    """Scans authoritatively matched to a process node by image SHA256 only —
    matching a running process to a scanned file by name would produce false
    positives (e.g. an OS notepad.exe vs. a scanned notepad.exe)."""
    sha = _extract_sha256(node.get("hashes"))
    if sha and sha in by_sha:
        return list(by_sha[sha].values())
    return []


def _build_samples(proc_map, by_sha, by_name):
    """Union of submitted + scanned files, grouped by sha256 (falling back to
    filename), each carrying its per-tool scans and — if it actually ran — its
    live PID. Files that were only statically scanned (never executed, e.g. a
    ransomware sample that must not be detonated) still appear here."""
    subs = _load_submissions()
    hist = _load_scan_history()

    # filename(lower) -> sha, so name-only scans merge into the sha'd group.
    name2sha = {}
    for it in subs + hist:
        if not isinstance(it, dict):
            continue
        sha = (it.get("sha256") or "").lower()
        nm = (it.get("filename") or "").lower()
        if sha and nm and nm != "--":
            name2sha.setdefault(nm, sha)

    samples = {}

    def bucket(sha, nm, disp):
        sha = (sha or "").lower()
        nml = (nm or "").lower()
        if not sha and nml in name2sha:
            sha = name2sha[nml]
        key = ("sha:" + sha) if sha else ("name:" + nml)
        s = samples.get(key)
        if s is None:
            s = {"sha256": sha, "filename": disp or nm or "--", "size": None,
                 "target": None, "submitted_at": None, "agent_pid": None,
                 "scan_map": {}, "sources": set()}
            samples[key] = s
        return s

    for sub in subs:  # newest-first: first submission per bucket wins
        if not isinstance(sub, dict):
            continue
        s = bucket(sub.get("sha256"), sub.get("filename"), sub.get("filename"))
        s["sources"].add("submission")
        if s["submitted_at"] is None:
            s["submitted_at"] = sub.get("timestamp")
            s["target"] = sub.get("target")
            s["agent_pid"] = sub.get("agent_pid")
        if s["size"] is None and sub.get("size") is not None:
            s["size"] = sub.get("size")

    for e in hist:  # newest-first: keep latest per tool
        if not isinstance(e, dict):
            continue
        # Live-memory scans target processes ("PID 1234", "all processes"),
        # not files; they belong to the process tree, not the Samples rail.
        if (e.get("tool") or "").lower() in _PROCESS_SCAN_TOOLS:
            continue
        s = bucket(e.get("sha256"), e.get("filename"), e.get("filename"))
        s["sources"].add("scan")
        tool = (e.get("tool") or "?").lower()
        if tool not in s["scan_map"]:
            s["scan_map"][tool] = _summarize_scan_entry(e)
        if s["size"] is None and e.get("size") is not None:
            s["size"] = e.get("size")

    # Resolve each sample to a live PID via SHA256 match on process hashes.
    sha2pid = {}
    newest_first = sorted(proc_map.items(),
                          key=lambda kv: _to_epoch(kv[1].get("started") or kv[1].get("first_seen")) or 0,
                          reverse=True)
    for pid, node in newest_first:      # the latest run of a sample wins
        nsha = _extract_sha256(node.get("hashes"))
        if nsha:
            sha2pid.setdefault(nsha, pid)

    out = []
    for s in samples.values():
        scans = list(s["scan_map"].values())
        pid = sha2pid.get(s["sha256"]) if s["sha256"] else None
        detonated = bool(proc_map.get(pid, {}).get("detonated")) if pid else False
        out.append({
            "sha256": s["sha256"],
            "filename": s["filename"],
            "size": s["size"],
            "target": s["target"],
            "submitted_at": s["submitted_at"],
            "agent_pid": s["agent_pid"],
            "pid": pid,                      # instance key, used to focus
            "os_pid": proc_map[pid].get("pid") if pid else None,
            "executed": pid is not None,
            "detonated": detonated,
            "verdict": _overall_verdict(scans),
            "scans": scans,
            "sources": sorted(s["sources"]),
        })

    def _sort_ts(x):
        ts = [x.get("submitted_at") or ""]
        for sc in x.get("scans", []):
            ts.append(sc.get("timestamp") or "")
        return max(ts)

    out.sort(key=_sort_ts, reverse=True)
    return out


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
        "agent_result": None,
        "litterbox_status": None,
        "litterbox_hash": None,
        "ioc_feed": None,
        "verdict": None,
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
            # The agent's /execute/exec response only carries status/pid/message;
            # stdout/stderr are fetched live from /api/logs/execution at poll time.
            entry["agent_result"] = {
                "http_status": results["agent"].get("status"),
                "pid": agent_data.get("pid"),
                "message": agent_data.get("message") or agent_data.get("Message"),
                "file_path": entry["file_path"],
            }
        else:
            # Non-dict payload (error string etc.) — still capture what we can
            entry["agent_result"] = {
                "http_status": results["agent"].get("status"),
                "error": results["agent"].get("error"),
                "raw": agent_data,
            }
    if "litterbox" in results:
        entry["litterbox_status"] = "success" if 200 <= results["litterbox"].get("status", 0) < 400 else "failed"
    if "ioc_feed" in results:
        entry["ioc_feed"] = results["ioc_feed"]
    # Carry over the litterbox hash if the submit handler computed one
    fi = results.get("file_info") if isinstance(results, dict) else None
    if isinstance(fi, dict):
        entry["litterbox_hash"] = fi.get("litterbox_hash")

    # The agent does not report where it wrote the sample. The running
    # process knows (it may still be alive right after the submit); else the
    # agent's drop folder. The former guess (a "vagrant" desktop folder) did
    # not exist on any VM, so hex/PE/FileMap links to samples were dead.
    if not entry["file_path"]:
        candidates = []
        if entry.get("agent_pid"):
            candidates.append(_image_path_for_pid(entry["agent_pid"]))
        candidates.append(os.path.join(r"C:\Users\Public\Downloads", os.path.basename(filename)))
        entry["file_path"] = next((c for c in candidates if c and os.path.isfile(c)), None)

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


_rustinel_file_cache = {}       # path -> (mtime_ns, size, [alerts])


def _parse_rustinel_file(filepath):
    """Parse one Rustinel alert file, reusing the last result if unchanged.

    The loader runs every 5 s; re-parsing every file each time cost ~2 s of
    CPU per cycle on the VM even when nothing had been written.
    """
    try:
        st = os.stat(filepath)
    except OSError:
        return []
    cached = _rustinel_file_cache.get(filepath)
    if cached and cached[0] == st.st_mtime_ns and cached[1] == st.st_size:
        return cached[2]
    parsed = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if line.strip():
                    alert = parse_rustinel_alert(line)
                    if alert:
                        parsed.append(alert)
    except (IOError, OSError):
        return cached[2] if cached else []
    _rustinel_file_cache[filepath] = (st.st_mtime_ns, st.st_size, parsed)
    return parsed


def load_rustinel_alerts():
    """Load all NDJSON alert files from Rustinel alerts directory."""
    alerts = []
    if not os.path.isdir(RUSTINEL_ALERTS_DIR):
        return alerts

    files = set(glob.glob(os.path.join(RUSTINEL_ALERTS_DIR, "*.ndjson")))
    # Also .json files (including date-suffixed like alerts.json.2026-06-08);
    # each may be a single JSON object or NDJSON, which the line parser covers.
    for pattern in ("*.json", "alerts.json.*"):
        files.update(glob.glob(os.path.join(RUSTINEL_ALERTS_DIR, pattern)))
    for filepath in sorted(files):
        alerts.extend(_parse_rustinel_file(filepath))
    # Forget files that were rotated away.
    for gone in set(_rustinel_file_cache) - files:
        _rustinel_file_cache.pop(gone, None)

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
        # Fibratus watches the whole system: an alert alone does not make a
        # process part of a detonation (it marked the web UI's own helpers,
        # Defender and OneDrive as "detonated"). Attribution to a sample
        # comes from the submission (PID + time window + image) instead.
        "detonated": False,
        "raw": data,
    }
    return alert


_fibratus_cache = {"record_id": None, "alerts": []}


def _fibratus_newest_record_id():
    """EventRecordID of the newest Fibratus event (cheap: one wevtutil call)."""
    try:
        raw, _ = _wevtutil_query("Application", "*[System[Provider[@Name='Fibratus']]]",
                                 count=1, timeout=10)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None
    start = raw.find("<EventRecordID>")
    if start < 0:
        return ""  # provider has no events
    end = raw.find("</EventRecordID>", start)
    return raw[start + len("<EventRecordID>"):end].strip()


def load_fibratus_alerts():
    """Load Fibratus alerts from Windows Event Log (Application log, Provider: Fibratus).

    Rendering 500 event messages through PowerShell takes ~3 s, so it only
    runs when the newest Fibratus record differs from the last load.
    """
    newest = _fibratus_newest_record_id()
    if newest is not None and newest == _fibratus_cache["record_id"]:
        return _fibratus_cache["alerts"]
    try:
        alerts = _load_fibratus_alerts_full()
    except Exception as e:
        # A failure here used to propagate into the loader loop and skip
        # storing *all* alerts, including Rustinel's, for that cycle.
        print(f"[fibratus_loader] {e}")
        return _fibratus_cache["alerts"]
    if alerts is None:
        # Query failed: keep serving the previous result rather than caching
        # an empty list until the next new Fibratus event.
        return _fibratus_cache["alerts"]
    if newest is not None:
        _fibratus_cache.update(record_id=newest, alerts=alerts)
    return alerts


def _load_fibratus_alerts_full():
    """Query and parse the most recent 500 Fibratus events."""
    global _fibratus_last_read_time
    alerts = []

    # Build PowerShell command to query Fibratus events
    # Use Get-WinEvent with FilterHashtable for efficiency
    ps_cmd = (
        "[Console]::OutputEncoding=[Text.Encoding]::UTF8; "
        "Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='Fibratus'} "
        "-MaxEvents 500 -ErrorAction SilentlyContinue | "
        "ForEach-Object { $_.Message } "
    )

    try:
        result = _run_cmd(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0,
        )
        if result.returncode != 0:
            return None
        if not result.stdout.strip():
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
        return None

    return alerts


_litterbox_backoff = {"until": 0.0, "results": []}
_LITTERBOX_RETRY_S = 60


def load_litterbox_results():
    """Poll LitterBox /files and /api/results/risk endpoints for analysis results.

    When LitterBox is not running each attempt costs a ~2 s connect timeout,
    so after a failure it is only retried once a minute.
    """
    if time.time() < _litterbox_backoff["until"]:
        return _litterbox_backoff["results"]
    alerts = []
    try:
        r = requests.get(f"{LITTERBOX_API}/files", timeout=5)
        if r.status_code != 200:
            return alerts
        data = r.json()
    except (requests.RequestException, ValueError):
        _litterbox_backoff["until"] = time.time() + _LITTERBOX_RETRY_S
        return _litterbox_backoff["results"]
    _litterbox_backoff["until"] = 0.0

    # Process payload-based results
    payloads = {}
    if isinstance(data, dict):
        payloads = data.get("payload_based", {}).get("payloads", {})

    for key, analysis in payloads.items():
        if not isinstance(analysis, dict):
            continue
        try:
            md5 = analysis.get("md5", "")
            filename = analysis.get("filename", "unknown")
            detection_risk = (analysis.get("detection_risk", "") or "").lower()
            entropy = analysis.get("entropy_value", 0)
            has_static = analysis.get("has_static_analysis", False)
            has_dynamic = analysis.get("has_dynamic_analysis", False)

            # Map detection_risk to severity and score
            risk_map = {"critical": ("critical", 9), "high": ("high", 7), "medium": ("medium", 5), "low": ("low", 2)}
            severity, score = risk_map.get(detection_risk, ("low", 1))

            # Skip if no meaningful risk
            if score <= 1 and not has_static and not has_dynamic:
                continue

            # Try to get detailed risk info
            description = f"Detection risk: {detection_risk}, Entropy: {entropy:.2f}"
            tags = []
            try:
                rr = requests.get(f"{LITTERBOX_API}/api/results/risk/{md5}", timeout=3)
                if rr.status_code == 200:
                    risk_data = rr.json()
                    risk_factors = risk_data.get("risk_factors", [])
                    if risk_factors:
                        description = "; ".join(risk_factors[:3])
                    risk_score = risk_data.get("risk_score", score)
                    if risk_score >= 7:
                        severity = "critical" if risk_score >= 9 else "high"
                    score = risk_score
            except Exception:
                pass

            alert = {
                "id": f"lb_{md5}",
                "timestamp": "",
                "severity": severity,
                "rule_name": f"LitterBox: {filename}",
                "rule_description": description,
                "engine": "litterbox",
                "tags": tags,
                "category": "process",
                "pid": None,
                "process_name": filename,
                "process_image": "",
                "command_line": "",
                "parent_pid": None,
                "parent_name": "",
                "parent_command_line": "",
                "user": "",
                "detonated": True,
                "detonation_source": "litterbox",
                "litterbox_score": score,
                "litterbox_id": md5,
                "sha256": "",
                "md5": md5,
                "raw": analysis,
            }
            alerts.append(alert)
        except (KeyError, TypeError, ValueError):
            continue

    # Served while LitterBox is unreachable, so results do not flicker away.
    _litterbox_backoff["results"] = alerts
    return alerts


_AGENT_PID_WINDOW = 6 * 3600   # seconds after submission a sample PID stays attributable


def _to_epoch(ts):
    """Epoch seconds for an ISO timestamp (naive = local time), or None."""
    if isinstance(ts, (int, float)) and not isinstance(ts, bool):
        return float(ts)
    if not ts:
        return None
    import re
    # Windows/Rustinel write 7 fractional digits; fromisoformat takes at most 6.
    text = re.sub(r"(\.\d{6})\d+", r"\1", str(ts).strip().replace("Z", "+00:00"))
    try:
        dt = datetime.datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.astimezone()
    return dt.timestamp()


def _agent_detonation_index():
    """pid -> [(window start, window end, sample basename or None)] from submissions."""
    index = {}
    try:
        subs = _load_submissions()
    except Exception:
        return index
    starts = []
    for sub in subs:
        apid = sub.get("agent_pid")
        start = _to_epoch(sub.get("timestamp"))
        if apid and start is not None:
            starts.append((start, str(apid), sub))
    starts.sort(key=lambda x: x[0])
    for i, (start, apid, sub) in enumerate(starts):
        end = start + _AGENT_PID_WINDOW
        # A later submission that reuses the PID ends this one's window.
        for later_start, later_pid, _ in starts[i + 1:]:
            if later_pid == apid:
                end = min(end, later_start)
                break
        name = os.path.basename(str(sub.get("file_path") or sub.get("filename") or "").replace("\\", "/"))
        # Only directly executed files must match the image; DLLs/scripts run
        # under a host process (rundll32, powershell, ...).
        must_match = name if name.lower().endswith((".exe", ".com", ".scr")) else None
        index.setdefault(apid, []).append((start - 60, end, must_match))
    return index


def _is_agent_detonation(index, pid, timestamp, image):
    windows = index.get(str(pid))
    if not windows:
        return False
    t = _to_epoch(timestamp)
    img = os.path.basename(str(image or "").replace("\\", "/")).lower()
    for start, end, name in windows:
        # An alert that cannot be placed in time cannot be attributed: the
        # PID may belong to any process that ever had it.
        if t is None or not (start <= t <= end):
            continue
        if name and img and img != name.lower():
            continue
        return True
    return False


class _PidInstances:
    """Maps (PID, time) to a process-instance key.

    Windows reuses PIDs, so a PID names different processes over time. The
    process maps key each instance separately: the newest instance of a PID
    keeps the plain "<pid>" key (so existing links and API calls by PID keep
    meaning "the current process"), older ones are "<pid>@<start epoch>".
    """

    SLACK = 60   # seconds: alert/event clocks and process start may differ a little

    def __init__(self, procs):
        self.by_pid = {}
        self.image = {}
        for key, node in procs.items():
            t = _to_epoch(node.get("started") or node.get("first_seen"))
            self.by_pid.setdefault(str(node.get("pid")), []).append(
                (t if t is not None else float("-inf"), key))
            self.image[key] = _basename(node.get("image") or "").lower() or (node.get("name") or "").lower()
            # Sysmon ProcessCreate gives the real start; alert-derived nodes
            # only know when they were first seen, which can be later.
            self.exact = getattr(self, "exact", {})
            self.exact[key] = bool(node.get("started"))
        for lst in self.by_pid.values():
            lst.sort(key=lambda x: x[0])

    def resolve_key(self, key, at=None):
        """Map an instance key from another process map onto this one.

        "<pid>@<epoch>" resolves by its start time. A plain "<pid>" means the
        newest process with that PID - unless `at` says when it was seen.
        Keys differ between maps (the alert tree may not know a newer process
        that Sysmon saw), so a key is matched by PID and time, not by name.
        """
        key = str(key)
        pid, _, epoch = key.partition("@")
        if epoch:
            try:
                return self.resolve(pid, float(epoch.rstrip("+")))
            except ValueError:
                return None
        return self.resolve(pid, at) if at else (self.by_pid.get(pid) or [(0, None)])[-1][1]

    def resolve(self, pid, ts, image=None):
        """Key of the instance of `pid` that was alive at `ts`, or None.

        `image` (e.g. Sysmon's ParentImage for a parent lookup) rules out
        instances running a different program: with only one known holder
        of a PID, time alone cannot tell whether it is the right one.
        """
        cands = self.by_pid.get(str(pid)) if pid not in (None, "") else None
        if cands and image:
            want = _basename(str(image)).lower()
            if want and want != "unknown":
                cands = [c for c in cands if self.image.get(c[1]) in ("", "unknown", want)]
        if not cands:
            return None
        t = ts if isinstance(ts, (int, float)) else _to_epoch(ts)
        if t is None:
            return cands[-1][1]
        started = [key for start, key in cands if start <= t + self.SLACK]
        if started:
            return started[-1]
        # Every holder started after `ts`. A process with a known start cannot
        # have been alive then; one only seen through later alerts may have.
        fuzzy = [key for _, key in cands if not self.exact.get(key)]
        return fuzzy[0] if fuzzy else None


def _instance_keys(groups):
    """{pid: [node, ...] oldest first} -> {key: node}, setting node["key"]."""
    out = {}
    for pid, nodes in groups.items():
        for i, node in enumerate(nodes):
            # When the next process took over this PID: events after that
            # belong to it, not to this one.
            if i + 1 < len(nodes):
                node["superseded_at"] = nodes[i + 1].get("started") or nodes[i + 1].get("first_seen")
            if i == len(nodes) - 1:
                key = str(pid)
            else:
                t = _to_epoch(node.get("started") or node.get("first_seen"))
                key = f"{pid}@{int(t) if t is not None else i}"
                while key in out:
                    key += "+"
            node["key"] = key
            out[key] = node
    return out


def build_process_tree(alerts):
    """Build process tree from alerts data.
    
    Handles PID reuse: if a PID's executable changes between alerts,
    use the most recent process info (latest alert wins).
    """
    # Known sample PIDs from the submission history. Windows reuses PIDs, so
    # a PID alone used to mark every later process with that number as
    # detonated; an alert now only counts when it falls in that submission's
    # time window and, for directly executed samples, names the same image.
    _detonated_pids = _agent_detonation_index()

    # One entry per process instance: alerts are walked in time order and a
    # PID starts a new instance when its image changes or after it exited.
    groups = {}          # pid -> [entry, ...] oldest first
    ordered = sorted((a for a in alerts if a.get("pid")),
                     key=lambda a: _to_epoch(a.get("timestamp")) or 0)
    for alert in ordered:
        pid = str(alert.get("pid"))
        insts = groups.setdefault(pid, [])
        cur = insts[-1] if insts else None
        alert_image = (alert.get("process_image") or "").lower()
        new_instance = cur is None
        if cur is not None:
            cur_image = (cur.get("image") or "").lower()
            if alert_image and cur_image and alert_image != cur_image:
                new_instance = True
            elif cur.get("exit_time"):
                ended, now = _to_epoch(cur["exit_time"]), _to_epoch(alert.get("timestamp"))
                if ended is not None and now is not None and now > ended + 1:
                    new_instance = True
        if new_instance:
            cur = {
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
            insts.append(cur)
        proc_entry = cur
        if not proc_entry.get("image") and alert.get("process_image"):
            proc_entry["image"] = alert["process_image"]
            proc_entry["name"] = alert.get("process_name") or proc_entry["name"]
        if not proc_entry.get("command_line") and alert.get("command_line"):
            proc_entry["command_line"] = alert["command_line"]
        if proc_entry.get("parent_pid") in (None, "") and alert.get("parent_pid"):
            proc_entry["parent_pid"] = alert["parent_pid"]
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

        # Track detonation enrichment (Fibratus / LitterBox / submission PIDs)
        agent_match = _is_agent_detonation(_detonated_pids, pid, alert.get("timestamp"),
                                           alert.get("process_image"))
        if alert.get("detonated") or agent_match:
            proc_entry["activity"]["detonated"] += 1
            proc_entry["detonated"] = True
            det_src = alert.get("detonation_source", "")
            if det_src and det_src not in proc_entry["detonation_sources"]:
                proc_entry["detonation_sources"].append(det_src)
            if agent_match and "agent" not in proc_entry["detonation_sources"]:
                proc_entry["detonation_sources"].append("agent")

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

    # Parents that never raised an alert themselves get a stub node, one per
    # PID and program, so the graph can still show the relationship. Stubs
    # join the instance groups before keys are assigned, so "<pid>" stays the
    # newest process with that PID.
    probe = _PidInstances(_instance_keys(groups))
    stubs = {}
    for entry in [e for lst in groups.values() for e in lst]:
        ppid = entry.get("parent_pid")
        if ppid in (None, "") or str(ppid) == str(entry.get("pid")):
            continue
        if probe.resolve(str(ppid), entry.get("first_seen"), image=entry.get("parent_name")):
            continue
        sid = (str(ppid), (entry.get("parent_name") or "").lower())
        t = _to_epoch(entry.get("first_seen"))
        stub = stubs.get(sid)
        if stub is None:
            stub = stubs[sid] = {
                "pid": str(ppid),
                "name": entry.get("parent_name") or "unknown",
                "image": "",
                "command_line": entry.get("parent_command_line", ""),
                "user": "",
                "parent_pid": None,
                "parent_name": "",
                "integrity": "",
                "working_dir": "",
                "first_seen": entry.get("first_seen", ""),
                "last_seen": entry.get("last_seen", ""),
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
                "is_stub": True,
                "_t": t,
            }
            groups.setdefault(str(ppid), []).append(stub)
        elif t is not None and (stub["_t"] is None or t < stub["_t"]):
            stub["_t"], stub["first_seen"] = t, entry.get("first_seen", "")
    for lst in groups.values():
        lst.sort(key=lambda e: _to_epoch(e.get("first_seen")) or 0)
    for stub in stubs.values():
        stub.pop("_t", None)
    processes = _instance_keys(groups)

    # Link children to the parent instance alive when the child appeared.
    resolver = _PidInstances(processes)
    for key, proc in processes.items():
        proc["parent_key"] = None
        ppid = proc.get("parent_pid")
        if ppid in (None, "") or str(ppid) == str(proc.get("pid")):
            continue
        parent_key = resolver.resolve(str(ppid), proc.get("first_seen"), image=proc.get("parent_name"))
        if parent_key and parent_key != key:
            proc["parent_key"] = parent_key
            if key not in processes[parent_key]["children"]:
                processes[parent_key]["children"].append(key)

    # Cross-reference with submission history: mark processes whose PID matches
    # a known detonated sample (agent_pid) as detonated, including child processes
    # (matched per alert above, so a reused PID does not qualify)
    for key, proc in list(processes.items()):
        if "agent" not in proc["detonation_sources"]:
            continue
        # Mark direct children as detonated too (spawned by detonated sample)
        for child_pid in proc.get("children", []):
            if child_pid in processes:
                processes[child_pid]["detonated"] = True
                if "child_of_detonated" not in processes[child_pid]["detonation_sources"]:
                    processes[child_pid]["detonation_sources"].append("child_of_detonated")

    # Flag the alerts of attributed processes, so /api/alerts?detonated=true
    # returns the sample's alerts (and only those).
    for proc in processes.values():
        if proc.get("detonated"):
            for a in proc.get("alerts", []):
                a["detonated"] = True

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


# --- VM alert fallback ---
_vm_fetch_failures = 0  # Track consecutive failures to avoid spamming logs


_PROXY_HOP_HEADER = "X-TDC-Proxied"


def _vm_get(path, **kwargs):
    """GET from the VM's web UI (used when this instance has no local data).

    Sends a hop marker: if VM_WEBUI_URL points back at this instance - the
    fallback address is a guess - the receiving side refuses to proxy again
    instead of recursing until every worker thread is stuck waiting on itself.
    """
    # The alert loader calls this from a background thread, outside any request.
    from flask import has_request_context
    if has_request_context() and request.headers.get(_PROXY_HOP_HEADER):
        raise RuntimeError("refusing to proxy a proxied request")
    headers = dict(kwargs.pop("headers", None) or {})
    headers[_PROXY_HOP_HEADER] = "1"
    return requests.get(f"{VM_WEBUI_URL}{path}", headers=headers, **kwargs)


def _fetch_vm_alerts():
    """Fetch alerts from the VM's webui API as fallback when local sources are empty."""
    global _vm_fetch_failures
    try:
        r = _vm_get("/api/alerts", timeout=5)
        if r.status_code == 200:
            alerts = r.json()
            if isinstance(alerts, list) and alerts:
                if _vm_fetch_failures > 0:
                    print(f"[alert_loader] VM connection restored, got {len(alerts)} alerts from {VM_WEBUI_URL}")
                _vm_fetch_failures = 0
                return alerts
    except Exception:
        _vm_fetch_failures += 1
        if _vm_fetch_failures <= 3:
            print(f"[alert_loader] VM unreachable at {VM_WEBUI_URL} (attempt {_vm_fetch_failures})")
    return []


def _alerts_version(alerts):
    """Content token for an alert list: changes whenever any alert is added,
    removed or replaced. Hashing the ids costs a few ms for ~10k alerts."""
    h = hashlib.md5()
    for a in alerts:
        h.update(str(a.get("id") or a.get("timestamp") or "").encode("utf-8", "replace"))
        h.update(b"\n")
    return f"{len(alerts)}-{h.hexdigest()[:16]}"


def _store_alerts(alerts, processes=None):
    """Publish an alert list; skips the rebuild when nothing changed.

    The process tree also depends on submissions.json (detonation flags), so
    its mtime is part of the version. Without this check every 5 s cycle
    rebuilt the tree from ~10k alerts even while idle.
    """
    try:
        sub_mtime = os.path.getmtime(SUBMISSIONS_FILE)
    except OSError:
        sub_mtime = 0
    version = f"{_alerts_version(alerts)}-{int(sub_mtime)}"
    with store_lock:
        if events_store.get("alerts_version") == version:
            return
    if processes is None:
        processes = build_process_tree(alerts)
    with store_lock:
        events_store["alerts"] = alerts
        events_store["processes"] = processes
        events_store["alerts_version"] = version


# --- Background alert loader ---
def alert_loader_thread():
    """Periodically reload alerts from Rustinel, Fibratus, and LitterBox."""
    while True:
        try:
            # Quick check: are local data sources actually available with data?
            # Just having the directory isn't enough - check for actual alert files
            has_local_data = (
                os.path.isdir(RUSTINEL_ALERTS_DIR) and
                any(True for f in os.listdir(RUSTINEL_ALERTS_DIR)
                    if f.endswith(('.ndjson', '.json')))
            )

            # If no local alert data, try VM first (much faster than waiting for
            # PowerShell timeouts from Fibratus/Sysmon queries that won't return data anyway)
            if not has_local_data and VM_WEBUI_URL:
                vm_alerts = _fetch_vm_alerts()
                if vm_alerts:
                    _store_alerts(vm_alerts)
                    time.sleep(5)
                    continue

            # Load from local sources
            rustinel_alerts = load_rustinel_alerts()
            fibratus_alerts = load_fibratus_alerts()
            litterbox_alerts = load_litterbox_results()

            # Merge and deduplicate
            all_alerts = rustinel_alerts + fibratus_alerts + litterbox_alerts

            # Fallback: if no local data, try fetching from VM's webui
            if not all_alerts and VM_WEBUI_URL:
                vm_alerts = _fetch_vm_alerts()
                if vm_alerts:
                    all_alerts = vm_alerts

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

            _store_alerts(unique_alerts)
        except Exception as e:
            print(f"[alert_loader] Error: {e}")
        time.sleep(5)


# --- Routes: Pages ---
@app.route("/")
def index():
    return render_template("index.html")


# --- Routes: API ---
_status_cache = {"at": 0.0, "data": None}
_STATUS_TTL = 5  # seconds; the dashboard polls every 10 s


def _probe_http(url, timeout=2):
    try:
        return requests.get(url, timeout=timeout)
    except Exception:
        return None


@app.route("/api/status")
def api_status():
    """Get status of all integrated services.

    The HTTP probes run concurrently: done one after another, each offline
    service added its full connect timeout to every dashboard refresh.
    """
    if _status_cache["data"] is not None and time.time() - _status_cache["at"] < _STATUS_TTL:
        return jsonify(_status_cache["data"])

    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=6) as pool:
        f_agent = pool.submit(_probe_http, f"{DETONATOR_AGENT_API}/api/lock/status")
        f_det = pool.submit(_probe_http, f"{DETONATOR_API}/api/submissions")
        f_lb = pool.submit(_probe_http, LITTERBOX_API)
        f_fib = pool.submit(_is_fibratus_running)
        f_rust = pool.submit(lambda: os.path.isdir(RUSTINEL_ALERTS_DIR) and _is_rustinel_running())
        f_sysmon = pool.submit(_is_sysmon_running)

        status = {}
        r = f_agent.result()
        if r is not None and r.status_code == 200:
            try:
                status["detonator_agent"] = {"online": True, "data": r.json()}
            except ValueError:
                status["detonator_agent"] = {"online": False, "status_code": r.status_code}
        elif r is not None:
            status["detonator_agent"] = {"online": False, "status_code": r.status_code}
        else:
            status["detonator_agent"] = {"online": False}

        r = f_det.result()
        status["detonator"] = {"online": r is not None and r.status_code == 200}
        r = f_lb.result()
        status["litterbox"] = {"online": r is not None and r.status_code == 200}
        status["fibratus"] = {"online": f_fib.result()}
        status["rustinel"] = {
            "online": bool(f_rust.result()),
            "alerts_count": len(events_store.get("alerts", [])),
        }
        status["sysmon"] = {"online": f_sysmon.result()}

    _status_cache.update(at=time.time(), data=status)
    return jsonify(status)


# --- Service launch configuration ---
# Paths are auto-detected: VM paths first, then dev/local paths
def _find_service_launch_config():
    """Detect available service launch commands based on installed paths."""
    configs = {}

    # Rustinel
    for exe in [r"C:\tools\rustinel\rustinel.exe", os.path.join(RUSTINEL_INSTALL_DIR, "rustinel.exe")]:
        if os.path.isfile(exe):
            configs["rustinel"] = {"exe": exe, "args": "run", "cwd": os.path.dirname(exe)}
            break

    # DetonatorAgent
    for exe in [r"C:\DetonatorAgent\publish\DetonatorAgent.exe"]:
        if os.path.isfile(exe):
            configs["detonator_agent"] = {"exe": exe, "args": "--port 8080 --edr fibratus", "cwd": os.path.dirname(exe)}
            break

    # Detonator API
    for venv_py in [r"C:\detonator\.venv\Scripts\python.exe"]:
        if os.path.isfile(venv_py):
            configs["detonator"] = {
                "exe": venv_py,
                "args": '-c "from detonatorapi.fastapi_app import app; import uvicorn; uvicorn.run(app, host=\'0.0.0.0\', port=8000)"',
                "cwd": r"C:\detonator",
            }
            break

    # LitterBox - check multiple possible locations
    litterbox_dirs = [
        r"C:\LitterBox",
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "LitterBox"),
    ]
    for lb_dir in litterbox_dirs:
        lb_script = os.path.join(lb_dir, "litterbox.py")
        if os.path.isfile(lb_script):
            # Prefer venv python, fallback to system
            venv_py = os.path.join(lb_dir, "venv", "Scripts", "python.exe")
            py_exe = venv_py if os.path.isfile(venv_py) else "python"
            configs["litterbox"] = {"exe": py_exe, "args": "litterbox.py", "cwd": lb_dir}
            break

    # Fibratus - Windows Service (with exe path for auto-registration if service is missing)
    fibratus_exe = None
    for exe_path in [r"C:\Program Files\Fibratus\Bin\fibratus.exe", r"C:\Program Files\Fibratus\fibratus.exe"]:
        if os.path.isfile(exe_path):
            fibratus_exe = exe_path
            break
    configs["fibratus"] = {"service": "fibratus", "exe": fibratus_exe}

    # Sysmon - Windows Service (ARM64 uses Sysmon64a, x86/x64 uses Sysmon64)
    sysmon_svc = "Sysmon64a" if platform.machine() == "ARM64" else "Sysmon64"
    configs["sysmon"] = {"service": sysmon_svc}

    return configs


def _try_vm_service_start(svc_name):
    """Try to start a service on the VM via WinRM/PSRemoting. Returns a Flask response or None.

    Credentials come from TDC_VM_USER / TDC_VM_PASS and reach PowerShell
    through its environment, not its command line: command lines are visible
    to every process on the box, including a running sample.
    """
    import ipaddress
    user = os.environ.get("TDC_VM_USER", "").strip()
    password = os.environ.get("TDC_VM_PASS", "")
    if not user or not password:
        return None
    try:
        ipaddress.ip_address(VM_IP)
    except ValueError:
        return None
    try:
        ps_cmd = (
            "$pass = ConvertTo-SecureString $env:TDC_VM_PASS -AsPlainText -Force; "
            "$cred = New-Object System.Management.Automation.PSCredential($env:TDC_VM_USER, $pass); "
            f"Invoke-Command -ComputerName '{VM_IP}' -Credential $cred -ScriptBlock {{ "
            f"  Start-Service -Name '{svc_name}' -ErrorAction Stop; "
            f"  (Get-Service -Name '{svc_name}').Status "
            f"}} -ErrorAction Stop"
        )
        child_env = dict(os.environ, TDC_VM_USER=user, TDC_VM_PASS=password)
        result = _run_cmd(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            timeout=15, env=child_env,
        )
        if result.returncode == 0 and "Running" in result.stdout:
            return jsonify({"success": True, "message": f"Service '{svc_name}' started on VM ({VM_IP})"})
        elif result.returncode == 0:
            return jsonify({"success": True, "message": f"Service '{svc_name}' command sent to VM ({VM_IP}): {result.stdout.strip()}"})
    except (subprocess.TimeoutExpired, Exception):
        pass
    return None


@app.route("/api/service/launch", methods=["POST"])
def api_service_launch():
    """Launch a service by name."""
    data = request.get_json(force=True) if request.is_json else request.form
    service_name = data.get("service", "").strip()

    if not service_name:
        return jsonify({"error": "No service specified"}), 400

    configs = _find_service_launch_config()
    if service_name not in configs:
        return jsonify({"error": f"Unknown service: {service_name}", "available": list(configs.keys())}), 404

    config = configs[service_name]

    try:
        # Windows Service start
        if "service" in config:
            svc_name = config["service"]
            result = _run_cmd(
                ["powershell", "-NoProfile", "-Command", f"Start-Service -Name '{svc_name}' -ErrorAction Stop"],
                timeout=10
            )
            if result.returncode != 0:
                # Service might not be registered yet — try to install it first
                exe_path = config.get("exe")
                if exe_path and os.path.isfile(exe_path) and "NoServiceFoundForGivenName" in result.stderr:
                    # Attempt to register the service via the executable
                    install_result = _run_cmd(
                        [exe_path, "install-service"],
                        timeout=15
                    )
                    if install_result.returncode == 0:
                        # Set to automatic and start
                        _run_cmd(
                            ["powershell", "-NoProfile", "-Command",
                             f"Set-Service -Name '{svc_name}' -StartupType Automatic -ErrorAction SilentlyContinue"],
                            timeout=5
                        )
                        start_result = _run_cmd(
                            ["powershell", "-NoProfile", "-Command",
                             f"Start-Service -Name '{svc_name}' -ErrorAction Stop"],
                            timeout=10
                        )
                        if start_result.returncode == 0:
                            return jsonify({"success": True, "message": f"Service '{svc_name}' registered and started"})
                        else:
                            return jsonify({"error": f"Service registered but failed to start: {start_result.stderr.strip()}"}), 500
                    else:
                        return jsonify({"error": f"Service not found and registration failed: {install_result.stderr.strip() or install_result.stdout.strip()}"}), 500
                elif exe_path and not os.path.isfile(exe_path):
                    # Try to start on VM as fallback
                    vm_result = _try_vm_service_start(svc_name)
                    if vm_result:
                        return vm_result
                    return jsonify({"error": f"Service '{svc_name}' not found locally (expected at: {exe_path}). VM also unreachable."}), 500
                elif not exe_path:
                    # Service not installed locally - try VM
                    vm_result = _try_vm_service_start(svc_name)
                    if vm_result:
                        return vm_result
                    return jsonify({"error": f"Service '{svc_name}' is not installed locally. Ensure the VM is running (VM IP: {VM_IP})."}), 500
                else:
                    return jsonify({"error": f"Failed to start service: {result.stderr.strip()}"}), 500
            return jsonify({"success": True, "message": f"Service '{svc_name}' started"})

        # Process launch
        exe = config["exe"]
        args = config.get("args", "")
        cwd = config.get("cwd", "")

        if not os.path.isfile(exe) and exe != "python":
            return jsonify({"error": f"Executable not found: {exe}"}), 404

        # Launch detached process
        cmd_parts = [exe] + (args.split() if args and not args.startswith('-c') else ([args] if args else []))
        if args.startswith('-c'):
            cmd_parts = [exe, "-c", args[3:].strip().strip('"')]

        subprocess.Popen(
            cmd_parts,
            cwd=cwd or None,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=0x00000008 | 0x00000200,  # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
        )

        # Invalidate status caches so next poll picks up new state
        _rustinel_proc_cache["checked_at"] = 0
        _sysmon_proc_cache["checked_at"] = 0
        _fibratus_proc_cache["checked_at"] = 0

        return jsonify({"success": True, "message": f"Launched {service_name}"})

    except subprocess.TimeoutExpired:
        return jsonify({"error": "Launch timed out"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/service/configs")
def api_service_configs():
    """Return detected service launch configurations."""
    configs = _find_service_launch_config()
    # Sanitize for frontend (just report which are launchable)
    result = {}
    for name, cfg in configs.items():
        if "service" in cfg:
            result[name] = {"type": "service", "service_name": cfg["service"], "launchable": True}
        else:
            launchable = os.path.isfile(cfg["exe"]) or cfg["exe"] == "python"
            result[name] = {"type": "process", "launchable": launchable, "cwd": cfg.get("cwd", "")}
    return jsonify(result)


# Cache for rustinel process check (avoid spawning powershell on every request)
_rustinel_proc_cache = {"online": False, "checked_at": 0}


def _is_rustinel_running():
    """Fast check if Rustinel is running (cached for 5s).
    Uses tasklist (native, instant) instead of PowerShell (4s+ cold start).
    """
    now = time.time()
    if now - _rustinel_proc_cache["checked_at"] < 5:
        return _rustinel_proc_cache["online"]
    try:
        result = _run_cmd(
            ["tasklist", "/FI", "IMAGENAME eq rustinel.exe", "/NH"],
            timeout=5
        )
        online = "rustinel.exe" in result.stdout.lower()
        _rustinel_proc_cache["online"] = online
        _rustinel_proc_cache["checked_at"] = now
        return online
    except Exception:
        _rustinel_proc_cache["online"] = False
        _rustinel_proc_cache["checked_at"] = now
        return False


def _get_rustinel_process():
    """Get detailed Rustinel process info (for detail panel only)."""
    try:
        result = _run_cmd(
            ["powershell", "-NoProfile", "-Command",
             "Get-Process -Name rustinel -ErrorAction SilentlyContinue | "
             "Select-Object Id, StartTime, WorkingSet64 | ConvertTo-Json"],
            timeout=5
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
    """Fast check if Sysmon service is running (cached for 10s).
    Uses 'sc query' (native, instant) instead of PowerShell (4s+ cold start).
    Checks Sysmon64a (ARM64) first, then Sysmon64 (x86/x64).
    """
    now = time.time()
    if now - _sysmon_proc_cache["checked_at"] < 10:
        return _sysmon_proc_cache["online"]
    try:
        for svc_name in ("Sysmon64a", "Sysmon64"):
            result = _run_cmd(
                ["sc", "query", svc_name],
                timeout=5
            )
            if "RUNNING" in result.stdout:
                _sysmon_proc_cache["online"] = True
                _sysmon_proc_cache["checked_at"] = now
                return True
        _sysmon_proc_cache["online"] = False
        _sysmon_proc_cache["checked_at"] = now
        return False
    except Exception:
        _sysmon_proc_cache["online"] = False
        _sysmon_proc_cache["checked_at"] = now
        return False


# Cache for Fibratus check
_fibratus_proc_cache = {"online": False, "checked_at": 0}


def _is_fibratus_running():
    """Check if Fibratus is running as a service or process (cached for 10s).
    Uses 'sc query' + tasklist (native, instant) instead of PowerShell (4s+ cold start).
    """
    now = time.time()
    if now - _fibratus_proc_cache["checked_at"] < 10:
        return _fibratus_proc_cache["online"]
    try:
        # First try service check (fast)
        result = _run_cmd(
            ["sc", "query", "fibratus"],
            timeout=5
        )
        if "RUNNING" in result.stdout:
            _fibratus_proc_cache["online"] = True
            _fibratus_proc_cache["checked_at"] = now
            return True
        # Fallback: check if running as a process
        result = _run_cmd(
            ["tasklist", "/FI", "IMAGENAME eq fibratus.exe", "/NH"],
            timeout=5
        )
        online = "fibratus.exe" in result.stdout.lower()
        _fibratus_proc_cache["online"] = online
        _fibratus_proc_cache["checked_at"] = now
        return online
    except Exception:
        _fibratus_proc_cache["online"] = False
        _fibratus_proc_cache["checked_at"] = now
        return False


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
        result = _run_cmd([exe, "--version"], timeout=5)
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


_rustinel_info_cache = {"at": 0.0, "static": None}
_RUSTINEL_STATIC_TTL = 120   # rule counts, version: change only on reinstall/update


def _read_log_tail(path, lines=20, chunk=64 * 1024):
    """Last `lines` non-empty lines of a text file without reading all of it."""
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - chunk))
            data = f.read()
    except OSError:
        return []
    text = data.decode("utf-8", errors="ignore")
    out = [l.strip() for l in text.splitlines() if l.strip()]
    return out[-lines:]


@app.route("/api/rustinel")
def api_rustinel():
    """Get detailed Rustinel engine status, loaded rules, and configuration.

    Polled by the dashboard every 10 s. The expensive parts - counting ~740
    rule files, running rustinel --version, and a PowerShell process query
    (2-5 s, and often timing out, which made Rustinel look offline) - are
    either cached or replaced by the tasklist-based check.
    """
    now = time.time()
    static = _rustinel_info_cache["static"]
    if static is None or now - _rustinel_info_cache["at"] > _RUSTINEL_STATIC_TTL:
        static = {
            "version": _get_rustinel_version(),
            "rules": _get_rustinel_rules(),
            "etw_providers": _get_rustinel_etw_providers(),
            # Start time and memory: detail only, refreshed with the cache.
            "process": _get_rustinel_process(),
        }
        _rustinel_info_cache.update(at=now, static=static)

    log_files = sorted(glob.glob(os.path.join(RUSTINEL_ALERTS_DIR, "rustinel.log.*")),
                       reverse=True)
    recent_log_lines = _read_log_tail(log_files[0]) if log_files else []

    info = {
        "online": _is_rustinel_running(),
        "version": static["version"],
        "process": static["process"],
        "install_dir": RUSTINEL_INSTALL_DIR,
        "alerts_dir": RUSTINEL_ALERTS_DIR,
        "rules": static["rules"],
        "etw_providers": static["etw_providers"],
        "alerts_count": len(events_store.get("alerts", [])),
        "recent_log": recent_log_lines,
    }
    return jsonify(info)


_alerts_body_cache = {"entry": None}   # (version, json body, gzip body)
_alerts_body_lock = threading.Lock()

# Raw-event keys that repeat a top-level field verbatim (Rustinel stores ECS
# fields flat). They made up ~30 MB of the ~79 MB list.
_RAW_DUPLICATES = {
    "process.command_line": "command_line",
    "process.parent.command_line": "parent_command_line",
    "rule.description": "rule_description",
}


def _slim_alert(alert):
    """List form of an alert: raw without fields the alert already carries.

    The full event stays available from /api/alerts/<id>; the detail view
    loads it on demand.
    """
    raw = alert.get("raw")
    if not isinstance(raw, dict) or not raw:
        return alert
    slim_raw = {}
    trimmed = False
    for key, value in raw.items():
        dup_of = _RAW_DUPLICATES.get(key)
        if dup_of and alert.get(dup_of) == value:
            trimmed = True
            continue
        if key == "edr.match" and isinstance(value, dict) and set(value) - {"summary"}:
            # The full Sigma match is only shown in the detail view.
            slim_raw[key] = {"summary": value.get("summary")}
            trimmed = True
            continue
        slim_raw[key] = value
    if not trimmed:
        return alert
    out = dict(alert)
    out["raw"] = slim_raw
    out["raw_trimmed"] = True
    return out


@app.route("/api/alerts/<path:alert_id>")
def api_alert_detail(alert_id):
    """One alert with its complete raw event."""
    with store_lock:
        alerts = events_store.get("alerts", [])
    for a in alerts:
        if str(a.get("id")) == alert_id:
            return jsonify(a)
    return jsonify({"error": "Alert not found"}), 404


@app.route("/api/alerts")
def api_alerts():
    """Get all Rustinel/Fibratus alerts.

    The unfiltered list is polled every 5 s per open tab and is tens of MB,
    so it carries an ETag (unchanged list -> 304, no body), drops raw fields
    that duplicate the alert's own fields, and is served gzip-compressed;
    both bodies are built once per list version and shared by all clients.
    """
    filtered = any(request.args.get(k) for k in ("severity", "engine", "pid", "since", "detonated", "limit"))
    if not filtered:
        with store_lock:
            alerts = events_store.get("alerts", [])
            version = events_store.get("alerts_version") or _alerts_version(alerts)
        etag = f'"{version}"'
        if request.headers.get("If-None-Match") == etag:
            resp = app.response_class(status=304)
        else:
            with _alerts_body_lock:
                # Version and bodies are swapped together, so a client can
                # never receive one list's body under another list's ETag.
                cached = _alerts_body_cache.get("entry")
                if not cached or cached[0] != version:
                    import gzip
                    body = json.dumps([_slim_alert(a) for a in alerts]).encode("utf-8")
                    cached = (version, body, gzip.compress(body, compresslevel=5))
                    _alerts_body_cache["entry"] = cached
            if "gzip" in request.headers.get("Accept-Encoding", "").lower():
                resp = app.response_class(cached[2], mimetype="application/json")
                resp.headers["Content-Encoding"] = "gzip"
            else:
                resp = app.response_class(cached[1], mimetype="application/json")
            resp.headers["Vary"] = "Accept-Encoding"
        resp.headers["ETag"] = etag
        resp.headers["Cache-Control"] = "no-cache"
        return resp

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
        # Compare as instants: alert timestamps mix "Z", "+02:00" and naive
        # local times; comparing those as datetimes raised and fell back to a
        # string comparison that was wrong across time zones.
        since_t = _to_epoch(since)
        if since_t is None:
            return jsonify({"error": "since must be an ISO-8601 timestamp"}), 400
        alerts = [a for a in alerts if (_to_epoch(a.get("timestamp")) or 0) >= since_t]

    limit = request.args.get("limit", type=int)
    if limit:
        # Newest first, so a limit keeps the recent end of the list.
        alerts = sorted(alerts, key=lambda a: _to_epoch(a.get("timestamp")) or 0, reverse=True)[:limit]
        return jsonify([_slim_alert(a) for a in alerts])

    return jsonify(alerts)


@app.route("/api/processes")
def api_processes():
    """Get process tree built from alerts.
    
    Query params:
        max: Maximum number of processes to return (default: 200, 0=unlimited)
        min_threats: Minimum threat count to include (default: 1)
        sort: Sort order - 'threats' (default), 'recent', 'severity'
        detonated: If 'true', only return detonated processes
        include_parents: If 'true' (default), include parent processes for context
    """
    max_procs = request.args.get("max", 200, type=int)
    min_threats = request.args.get("min_threats", 1, type=int)
    sort_by = request.args.get("sort", "threats")
    detonated_only = request.args.get("detonated", "").lower() == "true"
    include_parents = request.args.get("include_parents", "true").lower() != "false"

    with store_lock:
        all_processes = events_store.get("processes", {})

    if not all_processes:
        return jsonify({})

    # Filter by minimum threats
    filtered = {
        pid: proc for pid, proc in all_processes.items()
        if (proc.get("activity", {}).get("threats", 0) >= min_threats)
    }

    # Filter by detonated if requested
    if detonated_only:
        filtered = {pid: proc for pid, proc in filtered.items() if proc.get("detonated")}

    # Sort to prioritize interesting processes
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}

    def sort_key(item):
        pid, proc = item
        if sort_by == "recent":
            return proc.get("last_seen", "")
        elif sort_by == "severity":
            max_sev = 0
            for alert in proc.get("alerts", []):
                sev = severity_order.get(alert.get("severity", "unknown"), 0)
                if sev > max_sev:
                    max_sev = sev
            return (max_sev, proc.get("activity", {}).get("threats", 0))
        else:  # threats (default)
            return proc.get("activity", {}).get("threats", 0)

    sorted_procs = sorted(filtered.items(), key=sort_key, reverse=True)

    # Apply limit (0 = no limit)
    if max_procs > 0:
        selected_pids = set(pid for pid, _ in sorted_procs[:max_procs])

        # Include parent processes for graph context (not counted toward limit)
        if include_parents:
            parents_to_add = set()
            for pid in list(selected_pids):
                proc = all_processes.get(pid, {})
                pkey = proc.get("parent_key")
                if pkey and pkey in all_processes and pkey not in selected_pids:
                    parents_to_add.add(pkey)
            selected_pids.update(parents_to_add)

        result = {pid: proc for pid, proc in all_processes.items() if pid in selected_pids}
    else:
        result = filtered

    # Strip the full alert objects from response to reduce payload size
    # (keep only essential fields for graph rendering)
    compact_result = {}
    for pid, proc in result.items():
        compact_proc = dict(proc)
        # Reduce alerts to lightweight format (just timestamp + severity for time filtering)
        if compact_proc.get("alerts"):
            compact_proc["alerts"] = [
                {"timestamp": a.get("timestamp", ""), "severity": a.get("severity", "unknown"),
                 "rule_name": a.get("rule_name", ""), "category": a.get("category", "")}
                for a in compact_proc["alerts"]
            ]
        # Remove raw field from alerts to save bandwidth
        compact_result[pid] = compact_proc

    return jsonify(compact_result)


def _basename(path):
    """Return the last path component of a Windows/Unix path."""
    if not path:
        return ""
    return path.replace("/", "\\").rstrip("\\").split("\\")[-1] or path


def _proc_max_severity(proc):
    """Highest alert severity for a process (as string)."""
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
    best = "unknown"
    for a in proc.get("alerts", []):
        sev = (a.get("severity") or "unknown").lower()
        if order.get(sev, 0) > order.get(best, 0):
            best = sev
    return best


def _build_full_process_map():
    """Merge the authoritative Sysmon EID-1 process tree with alert-derived
    enrichment into a single {pid(str): proc} map with a `children` list.

    Returns (proc_map, sysmon_events) where sysmon_events is the raw event list
    (all relevant EIDs) so the caller can attach scoped activity. If Sysmon is
    unavailable locally, falls back to the alert-only process tree.
    """
    proc_map = {}
    sysmon_events = []

    if _is_sysmon_running():
        # One PowerShell call covering process-create + all activity EIDs we render.
        sysmon_events = _read_sysmon_events(
            max_events=4000,
            event_ids=[1, 3, 8, 11, 12, 13, 14, 22],
        )
        if not isinstance(sysmon_events, list):
            sysmon_events = []
        # Events with an "error" key mean the query failed — ignore them.
        sysmon_events = [e for e in sysmon_events if isinstance(e, dict) and "error" not in e]

        # One node per ProcessCreate (EID 1): each is a distinct process,
        # even when Windows handed out the same PID again later.
        groups = {}
        for ev in sysmon_events:
            if ev.get("event_id") != 1:
                continue
            pid = ev.get("pid")
            if pid is None or str(pid) == "":
                continue
            pid = str(pid)
            ts = ev.get("timestamp", "")
            ppid = ev.get("parent_pid")
            groups.setdefault(pid, []).append({
                "pid": pid,
                "name": _basename(ev.get("image", "")) or "unknown",
                "image": ev.get("image", ""),
                "command_line": ev.get("commandline", ""),
                "user": ev.get("user", ""),
                "parent_pid": str(ppid) if ppid not in (None, "") else None,
                # Sysmon writes "-" when it does not know the parent.
                "parent_name": "" if (ev.get("parent_image") or "-") == "-" else _basename(ev["parent_image"]),
                "integrity": ev.get("integrity", ""),
                "hashes": ev.get("hashes", ""),
                "started": ts,
                "first_seen": ts,
                "last_seen": ts,
                "exit_time": None,
                "children": [],
                "activity": {"file": 0, "network": 0, "dns": 0, "registry": 0,
                             "injection": 0, "threats": 0},
                "alerts_count": 0,
                "severity": "unknown",
                "detonated": False,
                "detonation_sources": [],
                "source": "sysmon",
            })
        for lst in groups.values():
            lst.sort(key=lambda n: _to_epoch(n["started"]) or 0)
        proc_map = _instance_keys(groups)
        # Process exits (EID 5) close the instance that was running.
        exits = _PidInstances(proc_map)
        for ev in sysmon_events:
            if ev.get("event_id") == 5 and ev.get("pid") not in (None, ""):
                k = exits.resolve(ev["pid"], ev.get("timestamp"))
                if k and not proc_map[k].get("exit_time"):
                    proc_map[k]["exit_time"] = ev.get("timestamp")

    # Merge alert-derived enrichment (threats, severity, detonation, activity).
    with store_lock:
        alert_procs = dict(events_store.get("processes", {}))

    sysmon_instances = _PidInstances(proc_map)
    for akey, aproc in alert_procs.items():
        pid = str(aproc.get("pid", akey))
        # The Sysmon instance alive when this alert instance was first seen,
        # if it runs the same image - otherwise it is a different process.
        node = None
        skey = sysmon_instances.resolve(pid, aproc.get("first_seen"))
        if skey and proc_map[skey].get("source") == "sysmon":
            a_img = (aproc.get("image") or "").lower()
            s_img = (proc_map[skey].get("image") or "").lower()
            if not a_img or not s_img or a_img == s_img:
                node = proc_map[skey]
        if node is None:
            # Alert-only process (no Sysmon ProcessCreate seen) — include it.
            node = {
                "pid": pid,
                "name": aproc.get("name", "unknown"),
                "image": aproc.get("image", ""),
                "command_line": aproc.get("command_line", ""),
                "user": aproc.get("user", ""),
                "parent_pid": str(aproc["parent_pid"]) if aproc.get("parent_pid") not in (None, "") else None,
                "parent_name": aproc.get("parent_name", ""),
                "integrity": aproc.get("integrity", ""),
                "hashes": "",
                "first_seen": aproc.get("first_seen", ""),
                "last_seen": aproc.get("last_seen", ""),
                "exit_time": aproc.get("exit_time"),
                "children": [],
                "activity": {"file": 0, "network": 0, "dns": 0, "registry": 0,
                             "injection": 0, "threats": 0},
                "alerts_count": 0,
                "severity": "unknown",
                "detonated": False,
                "detonation_sources": [],
                "source": "alert",
            }
            key = akey if akey not in proc_map else f"{pid}@{int(_to_epoch(aproc.get('first_seen')) or 0)}"
            while key in proc_map:
                key += "+"
            node["key"] = key
            proc_map[key] = node
        else:
            node["source"] = "sysmon+alert"
            # Prefer alert parent linkage if Sysmon lacked one.
            if not node.get("parent_pid") and aproc.get("parent_pid") not in (None, ""):
                node["parent_pid"] = str(aproc["parent_pid"])
            if not node.get("name") or node["name"] == "unknown":
                node["name"] = aproc.get("name", node["name"])
            if not node.get("image"):
                node["image"] = aproc.get("image", "")
            if not node.get("command_line"):
                node["command_line"] = aproc.get("command_line", "")

        # Enrichment from the alert tree.
        act = aproc.get("activity", {})
        node["activity"]["threats"] = act.get("threats", 0)
        node["activity"]["file"] = act.get("file", 0)
        node["activity"]["network"] = act.get("network", 0)
        node["activity"]["dns"] = act.get("dns", 0)
        node["activity"]["registry"] = act.get("registry", 0)
        node["activity"]["injection"] = act.get("injection", 0)
        node["alerts_count"] = len(aproc.get("alerts", []))
        node["severity"] = _proc_max_severity(aproc)
        node["detonated"] = bool(aproc.get("detonated"))
        node["detonation_sources"] = aproc.get("detonation_sources", [])
        if aproc.get("exit_time"):
            node["exit_time"] = aproc["exit_time"]
        if aproc.get("last_seen") and aproc["last_seen"] > (node.get("last_seen") or ""):
            node["last_seen"] = aproc["last_seen"]

    # Rebuild children links across the merged map, instance to instance.
    instances = _PidInstances(proc_map)
    for node in proc_map.values():
        node["children"] = []
        node["parent_key"] = None
    stubs = {}
    for key, node in list(proc_map.items()):
        ppid = node.get("parent_pid")
        if not ppid or str(ppid) == str(node.get("pid")):
            continue
        pkey = instances.resolve(ppid, node.get("started") or node.get("first_seen"),
                                 image=node.get("parent_name"))
        if pkey and pkey != key:
            node["parent_key"] = pkey
            proc_map[pkey]["children"].append(key)
        elif node.get("parent_name"):
            # Parent started before the event window (e.g. the agent that
            # launched the sample): a stub with the name Sysmon reported.
            sid = f"{ppid}~{node['parent_name'].lower()}"
            stub_key = stubs.get(sid)
            if stub_key is None:
                t = _to_epoch(node.get("started") or node.get("first_seen"))
                stub_key = str(ppid) if str(ppid) not in proc_map else f"{ppid}@{int(t) if t is not None else 0}"
                while stub_key in proc_map:
                    stub_key += "+"
                stubs[sid] = stub_key
                proc_map[stub_key] = {
                    "pid": str(ppid), "key": stub_key, "name": node["parent_name"], "image": "",
                    "command_line": "", "user": "", "parent_pid": None, "parent_key": None,
                    "parent_name": "", "integrity": "", "hashes": "", "first_seen": "",
                    "last_seen": "", "exit_time": None, "children": [],
                    "activity": {"file": 0, "network": 0, "dns": 0, "registry": 0,
                                 "injection": 0, "threats": 0},
                    "alerts_count": 0, "severity": "unknown", "detonated": False,
                    "detonation_sources": [], "source": "sysmon-parent", "is_stub": True,
                }
            node["parent_key"] = stub_key
            proc_map[stub_key]["children"].append(key)

    return proc_map, sysmon_events


@app.route("/api/process-graph")
def api_process_graph():
    """Focused process-graph drilldown rooted on a single PID.

    Query params:
        pid: root process id (required)
        down_depth: descendant depth to expand (default 0 = unlimited)
        up_depth: ancestor levels to include (default 0 = all the way to root)
        max_nodes: safety cap on total process nodes (default 400)

    Returns the root's ancestor chain + descendant subtree plus the network,
    DNS, file, registry and injection activity scoped to that process set.
    """
    root_pid = request.args.get("pid", type=str)
    if not root_pid:
        return jsonify({"error": "pid parameter is required"}), 400
    root_pid = str(root_pid)
    down_depth = request.args.get("down_depth", 0, type=int)
    up_depth = request.args.get("up_depth", 0, type=int)
    max_nodes = request.args.get("max_nodes", 400, type=int)

    # If Sysmon is offline locally, proxy to the VM (same codebase there).
    if not _is_sysmon_running() and VM_WEBUI_URL:
        try:
            r = _vm_get("/api/process-graph",
                             params=request.args, timeout=15)
            if r.status_code == 200:
                return jsonify(r.json())
        except Exception:
            pass

    proc_map, sysmon_events = _build_full_process_map()

    # "pid" may be an instance key ("1234@1789...") or a plain PID. With `at`
    # (e.g. an alert's timestamp) a plain PID resolves to the process that
    # had it at that moment rather than its newest holder.
    at = request.args.get("at")
    if at or root_pid not in proc_map:
        resolved = _PidInstances(proc_map).resolve_key(root_pid, at)
        if resolved:
            root_pid = resolved

    if root_pid not in proc_map:
        return jsonify({
            "error": f"Process {root_pid} not found",
            "root_pid": root_pid,
            "processes": {}, "network": [], "dns": [],
            "files": [], "registry": [], "injections": [],
        }), 404

    selected = {}  # pid -> role metadata

    # Ancestors: walk the parent instances up.
    ancestors = []
    cur = proc_map[root_pid].get("parent_key")
    seen_anc = {root_pid}
    level = 0
    while cur and cur in proc_map and cur not in seen_anc:
        if up_depth and level >= up_depth:
            break
        ancestors.append(cur)
        seen_anc.add(cur)
        level += 1
        cur = proc_map[cur].get("parent_key")
    for i, apid in enumerate(ancestors):
        selected[apid] = {"is_root": False, "is_ancestor": True, "depth": -(i + 1)}

    # Root + descendants: BFS down children.
    selected[root_pid] = {"is_root": True, "is_ancestor": False, "depth": 0}
    truncated = False
    queue = [(root_pid, 0)]
    while queue:
        pid, depth = queue.pop(0)
        if down_depth and depth >= down_depth:
            continue
        for child in proc_map[pid].get("children", []):
            if child in selected:
                continue
            if len(selected) >= max_nodes:
                truncated = True
                break
            selected[child] = {"is_root": False, "is_ancestor": False, "depth": depth + 1}
            queue.append((child, depth + 1))
        if len(selected) >= max_nodes:
            truncated = True
            break

    selected_pids = set(selected.keys())

    # Assemble process payload (children restricted to the selected set).
    processes = {}
    for pid in selected_pids:
        node = dict(proc_map[pid])
        node["children"] = [c for c in node.get("children", []) if c in selected_pids]
        node.update(selected[pid])
        processes[pid] = node

    # Attach static-scan verdicts (EMBER/capa/ThreatCheck/DefenderCheck) matched
    # to each process by image SHA256, for graph verdict badges + detail panel.
    scan_by_sha, _ = _scan_index()
    for node in processes.values():
        node["scans"] = _scans_for_node(node, scan_by_sha)

    # Scope activity events to the selected process instances. Events carry a
    # PID and a time; the instance alive at that time owns the event, so a
    # later process that reused the PID does not inherit them.
    instances = _PidInstances(proc_map)
    network, dns, files, registry, injections = [], [], [], [], []
    for ev in sysmon_events:
        eid = ev.get("event_id")
        if eid not in (3, 8, 11, 12, 13, 14, 22):
            continue
        ts = ev.get("timestamp", "")
        key = instances.resolve(ev.get("pid"), ts) if ev.get("pid") is not None else None
        pid = str(ev.get("pid")) if ev.get("pid") is not None else ""
        if eid == 3 and key in selected_pids:
            network.append({"pid": pid, "key": key, "dst_ip": ev.get("dst_ip", ""),
                            "dst_port": ev.get("dst_port", ""),
                            "dst_hostname": ev.get("dst_hostname", ""),
                            "protocol": ev.get("protocol", "tcp"),
                            "timestamp": ts})
        elif eid == 22 and key in selected_pids:
            dns.append({"pid": pid, "key": key, "query": ev.get("query", ""),
                        "result": ev.get("result", ""), "timestamp": ts})
        elif eid == 11 and key in selected_pids:
            files.append({"pid": pid, "key": key, "target": ev.get("target", ""), "timestamp": ts})
        elif eid in (12, 13, 14) and key in selected_pids:
            registry.append({"pid": pid, "key": key, "target": ev.get("target", ""),
                             "details": ev.get("details", ""), "timestamp": ts})
        elif eid == 8:
            spid = str(ev.get("source_pid")) if ev.get("source_pid") is not None else pid
            tpid = str(ev.get("target_pid")) if ev.get("target_pid") is not None else ""
            skey = instances.resolve(spid, ts)
            tkey = instances.resolve(tpid, ts)
            if skey in selected_pids and tkey in selected_pids:
                injections.append({"source_pid": spid, "target_pid": tpid,
                                   "source_key": skey, "target_key": tkey,
                                   "target_image": ev.get("target_image", ""),
                                   "timestamp": ts})

    return jsonify({
        "root_pid": root_pid,
        "truncated": truncated,
        "node_count": len(processes),
        "processes": processes,
        "network": network,
        "dns": dns,
        "files": files,
        "registry": registry,
        "injections": injections,
    })


@app.route("/api/process-graph/roots")
def api_process_graph_roots():
    """Candidate root processes for the drilldown landing picker:
    detonated samples and highest-threat processes."""
    with store_lock:
        procs = dict(events_store.get("processes", {}))

    candidates = []
    for pid, proc in procs.items():
        threats = proc.get("activity", {}).get("threats", 0)
        detonated = bool(proc.get("detonated"))
        if threats <= 0 and not detonated:
            continue
        candidates.append({
            "pid": str(pid),                  # instance key, used to focus
            "os_pid": str(proc.get("pid", pid)),
            "name": proc.get("name", "unknown"),
            "image": proc.get("image", ""),
            "threats": threats,
            "severity": _proc_max_severity(proc),
            "detonated": detonated,
            "detonation_sources": proc.get("detonation_sources", []),
            "children_count": len(proc.get("children", [])),
            "first_seen": proc.get("first_seen", ""),
        })

    # Detonated first, then by threat count.
    candidates.sort(key=lambda c: (c["detonated"], c["threats"]), reverse=True)
    return jsonify(candidates[:50])


@app.route("/api/graph/samples")
def api_graph_samples():
    """Submitted + scanned files for the graph landing 'Samples' rail. Includes
    files that were only statically scanned and never executed, so a
    static-only sample (e.g. a ransomware binary we must not detonate) is still
    visible with its EMBER/capa/ThreatCheck verdicts."""
    if not _is_sysmon_running() and VM_WEBUI_URL:
        try:
            r = _vm_get("/api/graph/samples", timeout=15)
            if r.status_code == 200:
                return jsonify(r.json())
        except Exception:
            pass
    proc_map, _ = _build_full_process_map()
    by_sha, by_name = _scan_index()
    return jsonify({"samples": _build_samples(proc_map, by_sha, by_name)})


@app.route("/api/sysmon")
def api_sysmon():
    """Get recent Sysmon events from Windows Event Log."""
    max_events = request.args.get("max", 100, type=int)
    since = request.args.get("since")
    pid = request.args.get("pid", type=int)
    parent_pid = request.args.get("parent_pid", type=int)
    until = request.args.get("until")
    event_id_raw = request.args.get("event_id", "")
    # Support comma-separated event IDs (e.g. "1,3,11")
    event_ids = [int(x) for x in event_id_raw.split(",") if x.strip().isdigit()] if event_id_raw else []
    event_id = event_ids[0] if len(event_ids) == 1 else None

    # If Sysmon not available locally, proxy from VM
    if not _is_sysmon_running():
        try:
            params = {k: v for k, v in {"max": max_events, "since": since, "pid": pid,
                                        "parent_pid": parent_pid, "until": until,
                                        "event_id": event_id_raw or None}.items() if v is not None}
            r = _vm_get("/api/sysmon", params=params, timeout=10)
            if r.status_code == 200:
                return jsonify(r.json())
        except Exception:
            pass
        return jsonify([{"error": f"Sysmon not available locally and VM ({VM_IP}) unreachable."}])

    events = _read_sysmon_events(max_events=max_events, since=since, pid=pid, event_id=event_id,
                                 event_ids=event_ids, parent_pid=parent_pid, until=until)
    return jsonify(events)


# --- ETW Browser ---

ETW_CHANNELS = {
    "sysmon": {
        "name": "Microsoft-Windows-Sysmon/Operational",
        "label": "Sysmon",
        "description": "Process creation, network, file, registry, DNS, image loads (all Sysmon event types)",
    },
    "security": {
        "name": "Security",
        "label": "Security (Audit)",
        "description": "Logon events (4624/4625), privilege use (4672), process audit (4688), account management",
    },
    "powershell": {
        "name": "Microsoft-Windows-PowerShell/Operational",
        "label": "PowerShell",
        "description": "Script block logging (4104), module loads, command invocations — detects obfuscated scripts",
    },
    "defender": {
        "name": "Microsoft-Windows-Windows Defender/Operational",
        "label": "Defender",
        "description": "Malware detections (1116/1117), scan results, real-time protection events, exclusions",
    },
    "wmi": {
        "name": "Microsoft-Windows-WMI-Activity/Operational",
        "label": "WMI Activity",
        "description": "WMI queries, event subscriptions (T1546.003), provider loads — persistence detection",
    },
    "task-scheduler": {
        "name": "Microsoft-Windows-TaskScheduler/Operational",
        "label": "Task Scheduler",
        "description": "Task creation/modification/execution (T1053.005) — persistence and lateral movement",
    },
    "bits": {
        "name": "Microsoft-Windows-Bits-Client/Operational",
        "label": "BITS Client",
        "description": "Background file transfers — often abused for stealthy C2 downloads (T1197)",
    },
    "dns-client": {
        "name": "Microsoft-Windows-DNS-Client/Operational",
        "label": "DNS Client",
        "description": "DNS resolution queries — detect C2 beaconing, DGA domains, DNS tunneling",
    },
    "firewall": {
        "name": "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
        "label": "Firewall",
        "description": "Firewall rule changes, blocked connections — detect evasion and lateral movement",
    },
    "applocker": {
        "name": "Microsoft-Windows-AppLocker/EXE and DLL",
        "label": "AppLocker",
        "description": "Application execution control — blocked/allowed executables and DLLs",
    },
    "winrm": {
        "name": "Microsoft-Windows-WinRM/Operational",
        "label": "WinRM",
        "description": "Remote management activity — detect lateral movement via PS remoting",
    },
    "application": {
        "name": "Application",
        "label": "Application (Fibratus)",
        "description": "Application log — includes Fibratus alerts and crash dumps",
    },
}


@app.route("/api/etw/channels")
def api_etw_channels():
    """List available ETW channels with availability status."""
    probe = request.args.get("probe", "false") == "true"
    if not probe:
        return jsonify(ETW_CHANNELS)

    # A channel counts as available when it exists and holds at least one
    # record - the same meaning as the former PowerShell probe, but answered
    # by one fast `wevtutil gli` per channel, run in parallel.
    from concurrent.futures import ThreadPoolExecutor

    def _probe(log_name):
        try:
            out = _run_cmd(["wevtutil", "gli", log_name], timeout=10)
        except Exception:
            return None
        if out.returncode != 0:
            return False
        for line in out.stdout.splitlines():
            if line.strip().lower().startswith("numberoflogrecords:"):
                try:
                    return int(line.split(":", 1)[1].strip()) > 0
                except ValueError:
                    return None
        # Disabled channels that never wrote a log file report no record count.
        return False

    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = {key: pool.submit(_probe, ch["name"]) for key, ch in ETW_CHANNELS.items()}
        status_map = {key: f.result() for key, f in futures.items()}

    enriched = {}
    for key, ch in ETW_CHANNELS.items():
        enriched[key] = {**ch, "available": status_map.get(key, None)}
    return jsonify(enriched)


@app.route("/api/etw/events")
def api_etw_events():
    """Query events from a specific ETW channel / Windows Event Log.

    Uses `wevtutil /f:RenderedXml`, which includes the localized message and
    level, instead of a PowerShell pipeline (several seconds per call on the
    VM, started every 5 s while the ETW tab was open).
    """
    import xml.etree.ElementTree as ET
    from datetime import datetime as _dt, timezone as _tz

    channel_key = request.args.get("channel", "security")
    max_events = request.args.get("max", 50, type=int)
    since = request.args.get("since")
    keyword_filter = request.args.get("filter", "")
    event_id_filter = request.args.get("event_id", type=int)

    channel_info = ETW_CHANNELS.get(channel_key)
    if not channel_info:
        return jsonify({"error": f"Unknown channel: {channel_key}"}), 400

    log_name = channel_info["name"]
    max_events = max(1, min(max_events or 50, 500))

    # Request values only enter the query as validated integers/timestamps.
    conditions = []
    if event_id_filter:
        conditions.append(f"EventID={int(event_id_filter)}")
    if since:
        try:
            since_dt = _dt.fromisoformat(since.strip().replace("Z", "+00:00"))
        except ValueError:
            return jsonify({"error": "since must be an ISO-8601 timestamp"}), 400
        if since_dt.tzinfo is None:
            since_dt = since_dt.astimezone()
        conditions.append("TimeCreated[@SystemTime>='"
                          + since_dt.astimezone(_tz.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z") + "']")
    query = "*[System[" + " and ".join(conditions) + "]]" if conditions else None

    args = ["wevtutil", "qe", log_name, "/f:RenderedXml", "/uni:true",
            f"/c:{max_events}", "/rd:true"]
    if query:
        args.append(f"/q:{query}")
    try:
        proc = subprocess.run(args, capture_output=True, timeout=20,
                              creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except subprocess.TimeoutExpired:
        return jsonify({"events": [], "channel": channel_info, "error": "Query timed out (20s)"})
    except (FileNotFoundError, OSError) as e:
        return jsonify({"events": [], "channel": channel_info, "error": str(e)})

    raw = (proc.stdout or b"")
    if raw[:2] == b"\xff\xfe":
        raw = raw[2:]
    xml_text = raw.decode("utf-16-le", errors="replace")
    if proc.returncode != 0 and "<Event" not in xml_text:
        err = _decode_console(proc.stderr).strip()
        return jsonify({"events": [], "channel": channel_info,
                        "error": err or f"wevtutil exited with {proc.returncode}"})

    ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
    events = []
    for chunk in xml_text.split("</Event>"):
        begin = chunk.find("<Event")
        if begin < 0:
            continue
        try:
            ev = ET.fromstring(chunk[begin:] + "</Event>")
        except ET.ParseError:
            continue
        data = {}
        for d in ev.iter(f"{ns}Data"):
            name = d.get("Name")
            if name:
                data[name] = d.text or ""
            elif d.text:
                data["_Message"] = d.text      # unnamed EventData, as before
        provider = ev.find(f"{ns}System/{ns}Provider")
        eid = ev.find(f"{ns}System/{ns}EventID")
        tc = ev.find(f"{ns}System/{ns}TimeCreated")
        message = ev.findtext(f"{ns}RenderingInfo/{ns}Message") or data.get("_Message", "")
        level = ev.findtext(f"{ns}RenderingInfo/{ns}Level") or ""
        ts = tc.get("SystemTime", "") if tc is not None else ""
        try:
            base, _, frac = ts.rstrip("Z").partition(".")
            ts = _dt.fromisoformat(base + "." + (frac + "000000")[:6] + "+00:00").astimezone().isoformat()
        except ValueError:
            pass
        try:
            event_id = int(eid.text) if eid is not None and eid.text else 0
        except ValueError:
            event_id = 0
        item = {
            "timestamp": ts,
            "event_id": event_id,
            "level": level,
            "provider": provider.get("Name", "") if provider is not None else "",
            "message": message.strip().split("\n")[0].strip(),
            "data": {k: v for k, v in data.items() if not k.startswith("_")},
        }
        if keyword_filter and keyword_filter.lower() not in (
                message + " " + json.dumps(item["data"], ensure_ascii=False)).lower():
            continue
        events.append(item)

    if not events:
        return jsonify({"events": [], "channel": channel_info,
                        "note": "No events found or channel not available"})
    return jsonify({"events": events, "channel": channel_info, "count": len(events)})


_sysmon_stats_cache = {"at": 0.0, "data": None}
_SYSMON_STATS_TTL = 30


def _sysmon_recent_ids(count):
    """Event IDs of the newest `count` Sysmon events, or None on timeout."""
    try:
        raw, _ = _wevtutil_query("Microsoft-Windows-Sysmon/Operational", count=count, timeout=20)
    except subprocess.TimeoutExpired:
        return None
    import re as _re
    return _re.findall(r"<EventID>(\d+)</EventID>", raw)


@app.route("/api/sysmon/stats")
def api_sysmon_stats():
    """Get Sysmon event counts by type, with diagnostic info."""
    try:
        # Quick pre-check: if Sysmon service is not running, don't even try querying the log
        if not _is_sysmon_running():
            # Try fetching from VM instead
            try:
                r = _vm_get("/api/sysmon/stats", timeout=5)
                if r.status_code == 200:
                    data = r.json()
                    if data.get("online"):
                        data["source"] = "vm"
                        return jsonify(data)
            except Exception:
                pass
            return jsonify({
                "online": False,
                "stats": [],
                "diagnostic": f"Sysmon service is not running locally. VM ({VM_IP}) also unreachable.",
            })

        # Log metadata via wevtutil (one native call instead of PowerShell).
        gli = _run_cmd(["wevtutil", "gli", "Microsoft-Windows-Sysmon/Operational"], timeout=10)
        if gli.returncode != 0:
            return jsonify({
                "online": False,
                "stats": [],
                "diagnostic": "Event log 'Microsoft-Windows-Sysmon/Operational' does not exist. Sysmon may not be properly installed.",
            })
        record_count = 0
        for line in gli.stdout.splitlines():
            if line.strip().lower().startswith("numberoflogrecords:"):
                try:
                    record_count = int(line.split(":", 1)[1].strip())
                except ValueError:
                    pass
        enabled_line = _run_cmd(["wevtutil", "gl", "Microsoft-Windows-Sysmon/Operational"], timeout=10).stdout
        if "enabled: false" in enabled_line.lower():
            return jsonify({
                "online": False,
                "stats": [],
                "diagnostic": "Sysmon event log exists but is disabled.",
            })

        if record_count == 0:
            return jsonify({
                "online": True,
                "stats": [],
                "diagnostic": "Sysmon event log is empty (0 records). Service is running but no events have been logged yet. Check Sysmon config.",
                "record_count": record_count,
            })

        cached = _sysmon_stats_cache.get("data")
        if cached and time.time() - _sysmon_stats_cache["at"] < _SYSMON_STATS_TTL:
            return jsonify(dict(cached, record_count=record_count))

        # Distribution of the latest 500 events by ID.
        events = _sysmon_recent_ids(500)
        if events is None:
            return jsonify({
                "online": True,
                "stats": [],
                "diagnostic": f"Event log query timed out. Log has {record_count} records.",
                "record_count": record_count,
            })
        if events:
            from collections import Counter
            data = [{"Name": k, "Count": v} for k, v in Counter(events).items()]
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
            payload = {"online": True, "stats": stats}
            _sysmon_stats_cache.update(at=time.time(), data=payload)
            return jsonify(dict(payload, record_count=record_count))

        # Command returned empty despite records existing
        return jsonify({
            "online": True,
            "stats": [],
            "diagnostic": f"Event log has {record_count} records but query returned no results. Possible permission issue.",
            "record_count": record_count,
        })
    except Exception as e:
        return jsonify({"online": False, "error": str(e), "stats": []})


def _sysmon_xpath(event_ids=None, since=None, pid=None, parent_pid=None, until=None):
    """XPath for wevtutil: lets the event log do the filtering.

    Filtering in the log matters for correctness, not only speed: with
    -MaxEvents applied first and the ID/PID filter afterwards, busy event types
    (image loads, process access) pushed the requested ones out of the window.
    """
    system = []
    ids = [int(i) for i in (event_ids or []) if str(i).isdigit()]
    if ids:
        system.append("(" + " or ".join(f"EventID={i}" for i in ids) + ")")
    if since:
        from datetime import datetime as _dt, timezone as _tz
        try:
            ts = _dt.fromisoformat(str(since).strip().replace("Z", "+00:00"))
            if ts.tzinfo is None:
                ts = ts.astimezone()          # naive input: local time
            system.append("TimeCreated[@SystemTime>='"
                          + ts.astimezone(_tz.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z") + "']")
        except ValueError:
            pass
    if until:
        t = _to_epoch(until)
        if t is not None:
            from datetime import datetime as _dt2, timezone as _tz2
            system.append("TimeCreated[@SystemTime<'"
                          + _dt2.fromtimestamp(t, _tz2.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z") + "']")
    query = "*[System[" + " and ".join(system) + "]]" if system else "*"
    for field, value in (("ProcessId", pid), ("ParentProcessId", parent_pid)):
        if value:
            clause = f"EventData[Data[@Name='{field}']='{int(value)}']"
            query = (query[:-1] + f" and {clause}]") if query != "*" else f"*[{clause}]"
    return query


def _read_sysmon_events(max_events=100, since=None, pid=None, event_id=None, event_ids=None,
                        parent_pid=None, until=None):
    """Read Sysmon events from the Windows Event Log with full field extraction.

    Uses wevtutil with an XPath filter and parses the XML here. The former
    PowerShell pipeline converted every event with [xml]$_.ToXml(), which took
    8-17 s on the ARM64 VM for a few thousand events.
    """
    import xml.etree.ElementTree as ET
    max_events = max(1, min(int(max_events or 100), 5000))
    ids = list(event_ids or ([event_id] if event_id else []))
    query = _sysmon_xpath(ids, since=since, pid=pid, parent_pid=parent_pid, until=until)
    try:
        raw, proc = _wevtutil_query("Microsoft-Windows-Sysmon/Operational", query,
                                    count=max_events, timeout=30)
    except subprocess.TimeoutExpired:
        return [{"error": "Sysmon event query timed out"}]
    except (FileNotFoundError, OSError) as e:
        return [{"error": str(e)}]
    if proc.returncode != 0 and not proc.stdout:
        msg = _decode_console(proc.stderr).strip()
        return [{"error": msg}] if msg else []

    ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
    data = []
    for chunk in raw.split("</Event>"):
        begin = chunk.find("<Event")
        if begin < 0:
            continue
        try:
            ev = ET.fromstring(chunk[begin:] + "</Event>")
        except ET.ParseError:
            continue
        item = {d.get("Name"): (d.text or "") for d in ev.iter(f"{ns}Data") if d.get("Name")}
        eid = ev.find(f"{ns}System/{ns}EventID")
        tc = ev.find(f"{ns}System/{ns}TimeCreated")
        try:
            item["_EventId"] = int(eid.text) if eid is not None else 0
        except (TypeError, ValueError):
            item["_EventId"] = 0
        # SystemTime is UTC with 7 fractional digits; callers (and the
        # previous PowerShell path) use local time with an offset.
        st = tc.get("SystemTime", "") if tc is not None else ""
        try:
            from datetime import datetime as _dt
            base, _, frac = st.rstrip("Z").partition(".")
            t = _dt.fromisoformat(base + "." + (frac + "000000")[:6] + "+00:00")
            item["_TimeCreated"] = t.astimezone().isoformat()
        except ValueError:
            item["_TimeCreated"] = st
        data.append(item)

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


@app.route("/api/processes/<key>")
def api_process_detail(key):
    """One process instance: "<pid>" is the newest process with that PID,
    "<pid>@<start epoch>" an earlier one (PIDs are reused)."""
    with store_lock:
        processes = events_store.get("processes", {})
    proc = processes.get(str(key))
    if proc is None or request.args.get("at"):
        # A key from the process graph (Sysmon-based) or a PID plus time.
        resolved = _PidInstances(processes).resolve_key(key, request.args.get("at"))
        proc = processes.get(resolved) if resolved else proc
    if not proc:
        return jsonify({"error": "Process not found"}), 404
    return jsonify(proc)


@app.route("/api/sessions")
def api_sessions():
    """Alert activity grouped into sessions: bursts separated by quiet gaps.

    Query: gap (seconds of silence that end a session, default 600),
    limit (newest sessions returned, default 50). Each session is a summary
    (time span, counts by severity, processes, top rules, alert ids); the
    alerts themselves are at /api/alerts/<id>. The former version returned
    every alert in one "session" - 78 MB per call.
    """
    gap = max(10, min(request.args.get("gap", 600, type=int) or 600, 7 * 86400))
    limit = max(1, min(request.args.get("limit", 50, type=int) or 50, 500))
    with store_lock:
        alerts = list(events_store.get("alerts", []))

    timed = []
    for a in alerts:
        t = _to_epoch(a.get("timestamp"))
        if t is not None:
            timed.append((t, a))
    timed.sort(key=lambda x: x[0])

    sessions, current, last_t = [], None, None
    for t, a in timed:
        if current is None or t - last_t > gap:
            current = {"start": a.get("timestamp"), "start_epoch": t, "alerts": []}
            sessions.append(current)
        current["alerts"].append(a)
        current["end"] = a.get("timestamp")
        last_t = t

    out = []
    for sess in sessions[-limit:][::-1]:
        group = sess.pop("alerts")
        severity, procs, rules = {}, {}, {}
        for a in group:
            sev = (a.get("severity") or "unknown").lower()
            severity[sev] = severity.get(sev, 0) + 1
            if a.get("pid") is not None:
                key = str(a["pid"])
                entry = procs.setdefault(key, {"pid": a["pid"], "name": a.get("process_name") or "", "alerts": 0})
                entry["alerts"] += 1
            rule = a.get("rule_name") or "unknown"
            rules[rule] = rules.get(rule, 0) + 1
        out.append({
            "start": sess["start"],
            "end": sess["end"],
            "duration_s": round(_to_epoch(sess["end"]) - sess["start_epoch"], 1),
            "count": len(group),
            "severity": severity,
            "process_count": len(procs),
            "processes": sorted(procs.values(), key=lambda p: -p["alerts"])[:20],
            "top_rules": [{"rule": r, "count": c} for r, c in
                          sorted(rules.items(), key=lambda x: -x[1])[:10]],
            "alert_ids": [a.get("id") for a in group[-200:]],
        })
    return jsonify({"gap_s": gap, "total_sessions": len(sessions), "sessions": out})


# --- Proxy routes to downstream services ---
def _proxied(r):
    """Relay a DetonatorAgent / LitterBox response without letting it run as a page.

    These services render reports that contain sample-derived text (strings,
    file names, YARA matches). Passed through as text/html on this origin, any
    markup in them would execute with full access to this UI's API. Only data
    types are relayed as-is; everything else is served as plain text in a
    sandbox.
    """
    ctype = r.headers.get("Content-Type", "application/json")
    base = ctype.split(";", 1)[0].strip().lower()
    if base not in ("application/json", "text/plain", "application/octet-stream",
                    "application/zip", "text/csv"):
        ctype = "text/plain; charset=utf-8"
    return (r.content, r.status_code, {
        "Content-Type": ctype,
        "Content-Security-Policy": "sandbox; default-src 'none'",
        "X-Content-Type-Options": "nosniff",
    })


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
        return _proxied(r)
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
        return _proxied(r)
    except requests.RequestException as e:
        return jsonify({"error": f"DetonatorAgent unavailable: {e}"}), 502


@app.route("/api/litterbox/<path:path>", methods=["GET", "POST"])
def proxy_litterbox(path):
    """Proxy requests to LitterBox API.
    Routes are passed through directly - LitterBox uses both /api/* and root-level routes."""
    # Try /api/ prefix first, fall back to root path if 404
    url = f"{LITTERBOX_API}/{path}"
    try:
        if request.method == "GET":
            r = requests.get(url, params=request.args, timeout=10)
            if r.status_code == 404:
                r = requests.get(f"{LITTERBOX_API}/api/{path}", params=request.args, timeout=10)
        else:
            r = requests.post(url, data=request.form, files=request.files, timeout=120)
            if r.status_code == 404:
                r = requests.post(f"{LITTERBOX_API}/api/{path}", data=request.form, files=request.files, timeout=120)
        return _proxied(r)
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
    exit_capture_armed_at = None
    if target in ("agent", "both"):
        # Arm dump-on-exit before the sample starts: a sample that exits within
        # a second is exactly the case the live scanners cannot reach.
        ok, err = _exit_capture_arm(filename)
        if ok:
            exit_capture_armed_at = time.time()
            results["exit_capture"] = {"armed": True, "image": os.path.basename(filename),
                                       "window": EXIT_CAPTURE_WINDOW}
        else:
            results["exit_capture"] = {"armed": False, "reason": err}
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

    # --- Memory scanning (async, after agent execution) ---
    # Exit capture first: it only waits for the dump, so it never delays the
    # live scanners, and it needs the PID to pick the right dump folder.
    if exit_capture_armed_at is not None:
        if agent_pid:
            _exit_capture_watch(filename, agent_pid, file_sha256, exit_capture_armed_at)
        else:
            # Nothing ran, so nothing will exit; do not leave the key behind.
            _exit_capture_disarm(filename)
            results["exit_capture"] = {"armed": False, "reason": "agent returned no PID"}

    # Named beacon_scan for backwards compatibility with existing clients,
    # but it now covers every live-memory tool, not just the beacon hunters.
    memory_tools_available = (os.path.isfile(HUNT_SLEEPING_BEACONS_EXE)
                              or os.path.isfile(BEACONEYE_EXE)
                              or os.path.isfile(AETHER_EXE)
                              or os.path.isfile(PROCESSDUMP_EXE))
    if agent_pid and memory_tools_available:
        _run_memory_scans_async(agent_pid, file_sha256)
        results["beacon_scan"] = {
            "triggered": True,
            "tools": [],
        }
        if os.path.isfile(HUNT_SLEEPING_BEACONS_EXE):
            results["beacon_scan"]["tools"].append("Hunt-Sleeping-Beacons")
        if os.path.isfile(BEACONEYE_EXE):
            results["beacon_scan"]["tools"].append("BeaconEye")
        if os.path.isfile(AETHER_EXE):
            results["beacon_scan"]["tools"].append("Aether")
        if os.path.isfile(PROCESSDUMP_EXE):
            results["beacon_scan"]["tools"].append("Process Dump")
    else:
        results["beacon_scan"] = {
            "triggered": False,
            "reason": "No PID available" if not agent_pid else "Memory tools not installed",
        }

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
    # Entries recorded before the path fix point at a folder that never
    # existed; show where the sample actually is when it is still there.
    out = []
    for sub in subs:
        path = sub.get("file_path")
        if isinstance(sub, dict) and (not path or not os.path.isfile(path)) and sub.get("filename"):
            alt = os.path.join(r"C:\Users\Public\Downloads", os.path.basename(sub["filename"]))
            if os.path.isfile(alt):
                sub = dict(sub, file_path=alt)
        out.append(sub)
    return jsonify(out)


_lb_online_cache = {"at": 0.0, "online": False}
_LB_ONLINE_TTL = 15


def _litterbox_online():
    """LitterBox reachability, cached briefly (polled every 5 s per open result)."""
    now = time.time()
    if now - _lb_online_cache["at"] < _LB_ONLINE_TTL:
        return _lb_online_cache["online"]
    try:
        online = requests.get(LITTERBOX_API, timeout=2).status_code == 200
    except Exception:
        online = False
    _lb_online_cache.update(at=now, online=online)
    return online


def _fetch_many(specs):
    """GET several URLs concurrently. specs: name -> (url, timeout).

    Returns name -> Response, or None where the request failed.
    """
    from concurrent.futures import ThreadPoolExecutor
    if not specs:
        return {}

    def _one(url, timeout):
        try:
            return requests.get(url, timeout=timeout)
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=min(8, len(specs))) as pool:
        futures = {name: pool.submit(_one, url, t) for name, (url, t) in specs.items()}
        return {name: f.result() for name, f in futures.items()}


@app.route("/api/detonation/results")
def api_detonation_results():
    """Poll for combined detonation results: LitterBox static/dynamic + Fibratus/Rustinel alerts.
    Query params: sha256 (file hash), pid (agent PID), litterbox_hash (LB hash if different), filename."""
    sha256 = request.args.get("sha256", "")
    pid = request.args.get("pid", "")
    filename = request.args.get("filename", "")
    lb_hash = request.args.get("litterbox_hash", "") or sha256

    results = {"sha256": sha256, "pid": pid, "ready": {}}

    # --- External services, queried concurrently ---
    # Done one after another, the LitterBox and agent calls added their
    # timeouts up on every 5 s poll whenever a service was down.
    litterbox_online = _litterbox_online()
    results["litterbox_online"] = litterbox_online
    requests_to_make = {
        "agent_lock": (f"{DETONATOR_AGENT_API}/api/lock/status", 2),
        "agent_exec": (f"{DETONATOR_AGENT_API}/api/logs/execution", 3),
        "agent_log": (f"{DETONATOR_AGENT_API}/api/logs/agent", 3),
    }
    if litterbox_online:
        if lb_hash:
            requests_to_make["lb_static"] = (f"{LITTERBOX_API}/api/results/static/{lb_hash}", 5)
            requests_to_make["lb_info"] = (f"{LITTERBOX_API}/api/results/info/{lb_hash}", 5)
        dyn_target = pid or lb_hash
        if dyn_target:
            requests_to_make["lb_dynamic"] = (f"{LITTERBOX_API}/api/results/dynamic/{dyn_target}", 5)
    fetched = _fetch_many(requests_to_make)

    def _json_of(key):
        r = fetched.get(key)
        if r is None or r.status_code != 200:
            return None
        try:
            return r.json()
        except ValueError:
            return None

    # --- LitterBox Static Results ---
    if lb_hash and litterbox_online:
        static = _json_of("lb_static")
        if static is not None:
            results["litterbox_static"] = static
        results["ready"]["static"] = static is not None
    else:
        # Offline or nothing to look up: do not block polling on it.
        results["ready"]["static"] = True

    # --- LitterBox Dynamic Results ---
    if litterbox_online and (pid or lb_hash):
        dynamic = _json_of("lb_dynamic")
        if dynamic is not None:
            results["litterbox_dynamic"] = dynamic
        results["ready"]["dynamic"] = dynamic is not None
    else:
        results["ready"]["dynamic"] = True

    # --- LitterBox File Info (includes basic PE info, hashes) ---
    info = _json_of("lb_info")
    if info is not None:
        results["litterbox_info"] = info

    # --- Memory scan results (from async cache) ---
    _rs = _beacon_results_cache
    hsb_result = _rs.lookup("hsb", pid, sha256)
    beaconeye_result = _rs.lookup("beaconeye", pid, sha256)
    aether_result = _rs.lookup("aether", pid, sha256)
    processdump_result = _rs.lookup("processdump", pid, sha256)
    exitcapture_result = _rs.lookup("exitcapture", pid, sha256)

    if hsb_result:
        results["hunt_sleeping_beacons"] = hsb_result
    if beaconeye_result:
        results["beaconeye"] = beaconeye_result
    if aether_result:
        results["aether"] = aether_result
    if processdump_result:
        results["process_dump"] = processdump_result
    if exitcapture_result:
        results["exit_capture_result"] = exitcapture_result

    # --- Network beaconing from Sysmon EID 3 (survives process exit) ---
    if pid:
        results["network_beaconing"] = _network_beaconing_for_pid(pid)

    # Memory tool status
    results["beacon_tools"] = {
        "hsb_installed": os.path.isfile(HUNT_SLEEPING_BEACONS_EXE),
        "beaconeye_installed": os.path.isfile(BEACONEYE_EXE),
        "aether_installed": os.path.isfile(AETHER_EXE),
        "process_dump_installed": os.path.isfile(PROCESSDUMP_EXE),
    }

    # --- Fibratus / Rustinel Alerts matching this detonation ---
    matching_alerts = []

    # PIDs are reused: an alert only matches by PID if it was raised after
    # this submission. Without this bound, months-old alerts of whatever
    # process once had the same PID were attributed to the sample and drove
    # its verdict.
    pid_window = None
    if pid:
        try:
            with submissions_lock:
                subs = _load_submissions()
        except Exception:
            subs = []
        starts = sorted(
            t for t in (_to_epoch(sub.get("timestamp")) for sub in subs
                        if str(sub.get("agent_pid")) == str(pid)
                        and (not sha256 or sub.get("sha256") == sha256))
            if t is not None)
        if starts:
            start = starts[-1] - 60
            later = [t for t in (_to_epoch(sub.get("timestamp")) for sub in subs
                                 if str(sub.get("agent_pid")) == str(pid))
                     if t is not None and t > starts[-1]]
            pid_window = (start, min([start + 60 + _AGENT_PID_WINDOW] + later))

    with store_lock:
        all_alerts = list(events_store.get("alerts", []))
    for alert in all_alerts:
        # Match by PID (flat field from parse_rustinel_alert / parse_fibratus_alert)
        alert_pid = str(alert.get("pid", ""))
        alert_ppid = str(alert.get("parent_pid", ""))
        # Also check the raw event for nested process.pid (ECS format)
        raw = alert.get("raw", {})
        raw_pid = str(_get_nested(raw, "process.pid", ""))
        raw_ppid = str(_get_nested(raw, "process.parent.pid", ""))
        # Check file hash from raw event
        alert_hash = _get_nested(raw, "file.hash.sha256", "") or ""
        # Also check process.hash.sha256 (some rules attach it there)
        proc_hash = _get_nested(raw, "process.hash.sha256", "") or ""
        # Check command_line and process_image for sample filename
        cmdline = (alert.get("command_line", "") or "").lower()
        proc_image = (alert.get("process_image", "") or "").lower()
        proc_name = (alert.get("process_name", "") or "").lower()

        matched = False
        if pid:
            pid_str = str(pid)
            if alert_pid == pid_str or raw_pid == pid_str or alert_ppid == pid_str or raw_ppid == pid_str:
                t = _to_epoch(alert.get("timestamp"))
                # Unknown submission time: keep the old behaviour. Unknown
                # alert time: cannot be placed, so not attributed by PID.
                matched = pid_window is None or (
                    t is not None and pid_window[0] <= t <= pid_window[1])
        if not matched and sha256 and len(sha256) >= 16:
            sha_lower = sha256.lower()
            if (sha_lower[:16] in alert_hash.lower() or
                sha_lower[:16] in proc_hash.lower()):
                matched = True
        if not matched and filename and len(filename) >= 3:
            # Match by sample filename in command line, process image, or process name
            fn_lower = filename.lower()
            # Strip extension for broader matching (e.g. "mimikatz" matches "mimikatz.exe")
            fn_stem = fn_lower.rsplit(".", 1)[0] if "." in fn_lower else fn_lower
            if len(fn_stem) >= 3 and (fn_lower in cmdline or fn_lower in proc_image or
                fn_stem in proc_name or fn_stem in cmdline):
                matched = True

        if matched:
            matching_alerts.append(alert)

    results["fibratus_alerts"] = matching_alerts[:50]
    results["fibratus_alert_count"] = len(matching_alerts)

    # Include EDR service status so frontend can detect offline state early
    fibratus_online = _is_fibratus_running()
    rustinel_online = os.path.isdir(RUSTINEL_ALERTS_DIR) and _is_rustinel_running()
    results["edr_status"] = {
        "fibratus_online": fibratus_online,
        "rustinel_online": rustinel_online,
    }

    # EDR is "ready" if we have alerts OR if both services are offline (no point waiting)
    if len(matching_alerts) > 0:
        results["ready"]["fibratus"] = True
    elif not fibratus_online and not rustinel_online:
        results["ready"]["fibratus"] = True  # Don't block polling if both are offline
    else:
        results["ready"]["fibratus"] = False

    # --- DetonatorAgent block (live lock status + persisted execution result) ---
    agent_block = {"in_use": None}
    lock = _json_of("agent_lock")
    agent_block["online"] = lock is not None
    if isinstance(lock, dict):
        agent_block["in_use"] = lock.get("in_use", lock.get("locked"))

    # Pull the persisted IOC-feed status from submission history
    try:
        with submissions_lock:
            subs = _load_submissions()
        for sub in subs:
            if (pid and str(sub.get("agent_pid")) == str(pid)) or (sha256 and sub.get("sha256") == sha256):
                agent_block["ioc_feed"] = sub.get("ioc_feed")
                break
    except Exception:
        pass

    # Live execution logs from the agent. GetExecutionLogs returns the LAST
    # execution's stdout/stderr/pid, so only surface it when its PID matches the
    # sample we're polling for (avoids showing an unrelated detonation's output).
    if agent_block["online"]:
        execution = {}
        log_data = _json_of("agent_exec")
        if isinstance(log_data, dict):
            log_pid = str(log_data.get("pid", ""))
            if not pid or log_pid == str(pid):
                execution["pid"] = log_data.get("pid")
                execution["stdout"] = log_data.get("stdout")
                execution["stderr"] = log_data.get("stderr")
        agent_log = fetched.get("agent_log")
        if agent_log is not None and agent_log.status_code == 200:
            execution["agent_logs"] = agent_log.text[:20000]
        if execution:
            agent_block["execution"] = execution
    results["agent"] = agent_block
    if agent_block.get("ioc_feed") and "ioc_feed" not in results:
        results["ioc_feed"] = agent_block["ioc_feed"]

    # --- Aggregated verdict (CLEAN / SUSPICIOUS / MALICIOUS) ---
    results["verdict"] = _compute_verdict(results, matching_alerts)

    return jsonify(results)


_net_beacon_cache = {}          # pid -> (fetched_at, result)
_NET_BEACON_TTL = 20            # seconds; polling runs every 5 s


def _sysmon_network_events(pid):
    """Sysmon NetworkConnect events of one PID as (timestamp, ip, port).

    Uses wevtutil with an XPath filter on ProcessId, so the event log does the
    filtering. The generic _read_sysmon_events path starts PowerShell and
    filters in Python, which costs ~8 s per call on the ARM64 VM.
    """
    import datetime as _dt
    import xml.etree.ElementTree as ET
    query = ("*[System[(EventID=3)] and "
             f"EventData[Data[@Name='ProcessId']='{int(pid)}']]")
    raw, _ = _wevtutil_query("Microsoft-Windows-Sysmon/Operational", query, count=500, timeout=15)
    ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
    conns, image = [], ""
    for chunk in raw.split("</Event>"):
        start = chunk.find("<Event")
        if start < 0:
            continue
        try:
            ev = ET.fromstring(chunk[start:] + "</Event>")
        except ET.ParseError:
            continue
        data = {d.get("Name"): (d.text or "") for d in ev.iter(f"{ns}Data")}
        image = image or os.path.basename(data.get("Image", ""))
        utc = data.get("UtcTime", "")
        try:
            t = _dt.datetime.strptime(utc[:23], "%Y-%m-%d %H:%M:%S.%f").replace(
                tzinfo=_dt.timezone.utc).timestamp()
        except ValueError:
            continue
        conns.append((t, data.get("DestinationIp"), data.get("DestinationPort")))
    return conns, image


def _network_beaconing_for_pid(pid):
    """Score a process's outbound connections for check-in periodicity.

    Reads Sysmon NetworkConnect events, which are logged as they happen and
    therefore remain available after the process has exited. Cached briefly
    because the result page polls this every few seconds.
    """
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return {"error": "invalid pid"}

    cached = _net_beacon_cache.get(pid)
    if cached and time.time() - cached[0] < _NET_BEACON_TTL:
        return cached[1]

    if not _is_sysmon_running():
        return {"available": False, "reason": "Sysmon not running"}
    try:
        conns, image = _sysmon_network_events(pid)
    except Exception as e:
        return {"available": False, "reason": str(e)}

    findings = memory_evidence.beaconing_from_connections(conns, process=image)
    endpoints = sorted({f"{ip}:{port}" for _, ip, port in conns})
    result = {
        "available": True,
        "connections": len(conns),
        "endpoints": endpoints[:50],
        "evidence_findings": findings,
    }
    _net_beacon_cache[pid] = (time.time(), result)
    if len(_net_beacon_cache) > 200:
        oldest = min(_net_beacon_cache, key=lambda k: _net_beacon_cache[k][0])
        _net_beacon_cache.pop(oldest, None)
    return result


def _compute_verdict(results, matching_alerts):
    """Aggregate a single verdict from EDR alerts, LitterBox findings, and beacon scans.
    Mirrors the Detonator reference UI's edr_verdict concept."""
    score = 0
    reasons = []

    # EDR alerts weighted by severity
    crit = high = 0
    for alert in matching_alerts:
        sev = (alert.get("severity") or "").lower()
        if sev in ("critical", "crit"):
            crit += 1
        elif sev in ("high", "medium"):
            high += 1
    if crit:
        score += 3
        reasons.append(f"{crit} critical EDR alert(s)")
    if high:
        score += 2
        reasons.append(f"{high} high/medium EDR alert(s)")
    other_alerts = len(matching_alerts) - crit - high
    if other_alerts > 0:
        score += 1
        reasons.append(f"{other_alerts} low/other EDR alert(s)")

    # LitterBox dynamic indicators
    # PE-Sieve and Moneta are not scored here: they feed the memory evidence
    # model below, so a finding both of them report counts as one corroborated
    # fact rather than twice.

    # LitterBox static score (0-10 scale from LitterBox info)
    info = results.get("litterbox_info") or {}
    if isinstance(info, dict) and isinstance(info.get("score"), (int, float)):
        if info["score"] >= 7:
            score += 3
            reasons.append(f"LitterBox score {info['score']}/10")
        elif info["score"] >= 4:
            score += 1
            reasons.append(f"LitterBox score {info['score']}/10")

    # --- Live-memory evidence (all scanners, one model) ---
    # Every memory scanner's output goes through memory_evidence, which weighs
    # findings by evidence class, persistence across samples, cross-tool
    # corroboration and novelty against this host's baseline. That replaces the
    # old per-tool point rules, which trusted each tool's own severity and so
    # graded a clean explorer.exe as malicious.
    process_name = ""
    agent = results.get("agent") or {}
    if isinstance(agent, dict):
        process_name = (agent.get("execution") or {}).get("process_name") or ""
    if not process_name:
        process_name = (results.get("file_info") or {}).get("name") or ""

    mem_findings = memory_evidence.collect(results, process=process_name)
    mem_sources = [k for k in ("aether", "process_dump", "hunt_sleeping_beacons",
                               "beaconeye", "exit_capture_result") if results.get(k)]
    if (results.get("network_beaconing") or {}).get("evidence_findings"):
        mem_sources.append("network_beaconing")
    if mem_sources:
        evidence = memory_evidence.score(mem_findings, baseline=_memory_baseline)

        # Distinguish "scanned and found nothing" from "could not observe".
        # A process that exited before the live scan produces no findings,
        # which must not be read as a clean result - unless the exit dump
        # captured it, in which case it was observed after all.
        aether_res = results.get("aether") or {}
        exit_res = results.get("exit_capture_result") or {}
        exit_observed = isinstance(exit_res, dict) and exit_res.get("observed")
        if (isinstance(aether_res, dict) and aether_res.get("observed") is False
                and not exit_observed):
            evidence["label"] = "NOT OBSERVED"
            evidence["note"] = aether_res.get("observation_note")
            reasons.append(
                "Live-memory scan observed nothing - the process exited before "
                "it ran (not evidence of being clean)"
            )
        elif exit_observed and aether_res.get("observed") is False:
            evidence["note"] = ("Process exited before the live scan; it was "
                                "analyzed from its exit-time memory dump instead.")
        evidence["sources_present"] = mem_sources

        # Emitted even when empty, so the UI can tell "tools ran, nothing
        # scored" apart from "tools never ran".
        results["memory_evidence"] = evidence

        # The evidence score is already calibrated (2.0 suspicious / 6.0
        # malicious); fold it in at the same scale as the other signals.
        if evidence["score"] >= memory_evidence.VERDICT_MALICIOUS:
            score += 4
        elif evidence["score"] >= memory_evidence.VERDICT_SUSPICIOUS:
            score += 2
        # Below VERDICT_SUSPICIOUS the evidence model itself calls the result
        # CLEAN. Adding a point anyway turned every sample with a little
        # uncorroborated noise into SUSPICIOUS overall.
        if evidence["score"] >= memory_evidence.VERDICT_SUSPICIOUS:
            reasons.extend(evidence["reasons"][:4])
        elif evidence["score"] > 0:
            reasons.append(
                f"Weak memory findings only (evidence score {evidence['score']}, "
                f"below the {memory_evidence.VERDICT_SUSPICIOUS} threshold) - not counted"
            )
        if evidence["suppressed_count"]:
            reasons.append(
                f"{evidence['suppressed_count']} finding(s) suppressed by the host baseline"
            )

    if score >= 3:
        label = "MALICIOUS"
    elif score >= 1:
        label = "SUSPICIOUS"
    else:
        label = "CLEAN"
    return {"label": label, "score": score, "reasons": reasons}


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
        # Memory dumps and the artifacts extracted from them
        PROCESSDUMP_DIR,
    ]
    norm_path = os.path.normpath(filepath)
    if not _path_within(norm_path, allowed_prefixes):
        return jsonify({"error": "Access denied: path outside allowed directories"}), 403

    if not os.path.isfile(norm_path):
        return jsonify({"error": "File not found"}), 404

    directory = os.path.dirname(norm_path)
    filename = os.path.basename(norm_path)
    # Samples can be HTML/SVG; never let the browser render one on this origin.
    resp = send_from_directory(directory, filename, as_attachment=True,
                               mimetype="application/octet-stream")
    resp.headers["Content-Security-Policy"] = "sandbox; default-src 'none'"
    return resp


@app.route("/api/file/hex")
def api_file_hex():
    """Return hex dump of a file's bytes starting from a given offset."""
    filepath = request.args.get("path", "")
    # Negative sizes would make f.read() return the whole file as a JSON int list.
    num_bytes = max(1, min(request.args.get("bytes", 8192, type=int) or 8192, 65536))
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
    num_bytes = max(1, min(request.form.get("bytes", 512, type=int) or 512, 65536))
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

    # Writes are limited to places that hold samples and analysis copies.
    # Previously all of C:\Users was writable - including every user's
    # Startup folder, i.e. code execution at next logon. Executable script
    # and shortcut types are refused even inside these folders.
    import tempfile
    allowed_write_dirs = [
        os.path.join(tempfile.gettempdir(), "hex_uploads"),
        r"C:\Temp",
        r"C:\Users\Public\Downloads",    # where the agent drops samples
        PROCESSDUMP_DIR,
    ]
    if not _path_within(norm_path, allowed_write_dirs):
        return jsonify({"error": "Access denied: write not allowed to this path",
                        "allowed": allowed_write_dirs}), 403
    if os.path.splitext(norm_path)[1].lower() in (
            ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".lnk", ".hta", ".py"):
        return jsonify({"error": "Access denied: refusing to modify script/shortcut files"}), 403

    if not os.path.isfile(norm_path):
        return jsonify({"error": "File not found"}), 404

    # Validate types before touching the file: a string offset or non-int byte
    # used to surface as an uncaught TypeError (500).
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        return jsonify({"error": "offset must be a non-negative integer"}), 400
    if not isinstance(byte_values, list) or not all(
            isinstance(b, int) and not isinstance(b, bool) and 0 <= b <= 255 for b in byte_values):
        return jsonify({"error": "bytes must be a list of integers 0-255"}), 400
    if len(byte_values) > 1024 * 1024:
        return jsonify({"error": "at most 1 MiB per write"}), 400
    if offset + len(byte_values) > os.path.getsize(norm_path):
        return jsonify({"error": "write would extend past the end of the file"}), 400

    try:
        raw_bytes = bytes(byte_values)
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

# --- EMBER2024 (thrember) ML classifier Integration ---
EMBER_ROOT = r"C:\tools\EMBER2024"
EMBER_PYTHON = r"C:\tools\EMBER2024\venv\Scripts\python.exe"
EMBER_SCRIPT = r"C:\tools\EMBER2024\ember_scan.py"
EMBER_MODELS_DIR = r"C:\tools\EMBER2024\models"
# Binary (malicious/benign) benchmark models exposed by the scanner UI.
EMBER_MODELS = [
    "EMBER2024_all", "EMBER2024_PE", "EMBER2024_Win32", "EMBER2024_Win64",
    "EMBER2024_Dot_Net", "EMBER2024_ELF", "EMBER2024_PDF", "EMBER2024_APK",
]

# --- Mandiant capa (static capability detection) Integration ---
CAPA_EXE = r"C:\tools\capa\capa.exe"


def _parse_capa_attack(entries):
    """Format capa ATT&CK/MBC spec entries into 'Tactic: Technique::Sub [ID]' strings."""
    out = []
    for e in entries or []:
        if not isinstance(e, dict):
            out.append(str(e))
            continue
        # ATT&CK uses tactic/technique/subtechnique; MBC uses objective/behavior.
        head = e.get("tactic") or e.get("objective") or ""
        mid = e.get("technique") or e.get("behavior") or ""
        sub = e.get("subtechnique") or e.get("method") or ""
        ident = e.get("id") or ""
        s = head
        if mid:
            s += f": {mid}"
        if sub:
            s += f"::{sub}"
        if ident:
            s += f" [{ident}]"
        out.append(s.strip(": ").strip() or str(e.get("parts", "")))
    return out

# --- Beacon Scanner Integration ---
HUNT_SLEEPING_BEACONS_EXE = r"C:\tools\Hunt-Sleeping-Beacons\Hunt-Sleeping-Beacons.exe"
BEACONEYE_EXE = r"C:\tools\BeaconEye\BeaconEye.exe"

# --- Live-memory forensics / dumping ---
AETHER_EXE = r"C:\tools\Aether\Aether.exe"
AETHER_RULES_DIR = r"C:\tools\Aether\rules"
PROCESSDUMP_EXE = r"C:\tools\ProcessDump\pd64.exe"
PROCESSDUMP_DIR = r"C:\dumps"

class _ResultStore:
    """Live-memory scanner results per detonation, kept on disk.

    Results used to live only in memory, so every restart of the web UI
    (deploys, crashes, reboots) dropped them: a detonation polled afterwards
    lost its Aether/Process Dump/exit-capture evidence and its verdict
    changed. Each entry is its own JSON file, written atomically, so storing
    one result never rewrites the others.

    Entries are addressed by tool plus PID and/or sample SHA256. PIDs are
    reused by Windows, so a PID match only counts when it belongs to the same
    sample - or, when no sample is given, when it is recent.
    """

    def __init__(self, directory, limit=600):
        self.dir = directory
        self.limit = limit
        self._lock = threading.Lock()
        self._mem = {}            # key -> (meta, value)
        self._index = {}          # key -> meta for entries only on disk
        try:
            os.makedirs(self.dir, exist_ok=True)
            for name in os.listdir(self.dir):
                if not name.endswith(".json"):
                    continue
                try:
                    with open(os.path.join(self.dir, name), "r", encoding="utf-8") as f:
                        doc = json.load(f)
                    self._index[doc["key"]] = doc["meta"]
                except (OSError, ValueError, KeyError, TypeError):
                    continue
        except OSError as e:
            print(f"[results] cannot use {self.dir}: {e} - results stay in memory only")

    def _path(self, key):
        return os.path.join(self.dir, hashlib.sha1(key.encode("utf-8")).hexdigest() + ".json")

    def _write(self, key, meta, value):
        path = self._path(key)
        tmp = path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"key": key, "meta": meta, "value": value}, f, default=str)
            os.replace(tmp, path)
        except (OSError, TypeError, ValueError) as e:
            print(f"[results] could not persist {key}: {e}")

    def _evict(self):
        keys = {**self._index, **{k: m for k, (m, _) in self._mem.items()}}
        if len(keys) <= self.limit:
            return
        for key, _ in sorted(keys.items(), key=lambda kv: kv[1].get("stored_at", 0))[:len(keys) - self.limit]:
            self._mem.pop(key, None)
            self._index.pop(key, None)
            try:
                os.remove(self._path(key))
            except OSError:
                pass

    def put(self, tool, value, pid=None, sha256=None):
        """Store a result under tool+PID and tool+SHA256 (whichever are known)."""
        meta = {"stored_at": time.time(), "pid": str(pid) if pid else None, "sha256": sha256 or None}
        keys = [f"{tool}_{pid}"] if pid else []
        if sha256:
            keys.append(f"{tool}_{sha256}")
        with self._lock:
            for key in keys:
                self._mem[key] = (meta, value)
                self._index.pop(key, None)
            self._evict()
        for key in keys:
            self._write(key, meta, value)

    def _entry(self, key):
        with self._lock:
            hit = self._mem.get(key)
            if hit:
                return hit
            meta = self._index.get(key)
        if meta is None:
            return None
        try:
            with open(self._path(key), "r", encoding="utf-8") as f:
                doc = json.load(f)
        except (OSError, ValueError):
            return None
        with self._lock:
            self._mem[key] = (doc["meta"], doc["value"])
            self._index.pop(key, None)
        return doc["meta"], doc["value"]

    def lookup(self, tool, pid=None, sha256=None, max_pid_age=6 * 3600):
        """Newest matching result, or None.

        With a SHA256, a PID entry from a different sample is ignored. With
        only a PID, entries older than max_pid_age are ignored (the PID has
        probably been reused since).
        """
        candidates = []
        if sha256:
            hit = self._entry(f"{tool}_{sha256}")
            if hit:
                candidates.append(hit)
        if pid:
            hit = self._entry(f"{tool}_{pid}")
            if hit:
                meta = hit[0]
                if sha256:
                    if meta.get("sha256") in (None, sha256):
                        candidates.append(hit)
                elif time.time() - meta.get("stored_at", 0) <= max_pid_age:
                    candidates.append(hit)
        if not candidates:
            return None
        return max(candidates, key=lambda h: h[0].get("stored_at", 0))[1]


_beacon_results_cache = _ResultStore(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "memory_results"))
_beacon_cache_lock = threading.Lock()

# Per-host baseline of benign memory findings, shared by every scanner.
_memory_baseline = memory_evidence.MemoryBaseline(MEMORY_BASELINE_FILE)


# --- Exit capture (dump-on-exit via Windows Silent Process Exit) -----------
#
# Short-lived samples exit before any live scanner reaches them. Windows can
# write a full-memory dump at the moment a process exits; it is switched on per
# image name through two registry keys. Unlike Process Dump's -closemon this
# injects nothing into other processes - which matters here, because -closemon
# writes x64 hook bytes into every process, including native ARM64 ones it
# cannot tell apart from x64 (its architecture check only looks at PE32+).

EXIT_CAPTURE_DIR = r"C:\dumps\exit"
EXIT_CAPTURE_WINDOW = 120      # seconds a submission stays armed
EXIT_CAPTURE_KEEP = 20         # capture folders retained before pruning
# FullMemory | FullMemoryInfo (region types/protection) | ThreadInfo (start addresses)
EXIT_CAPTURE_DUMP_TYPE = 0x2 | 0x800 | 0x1000
FLG_MONITOR_SILENT_PROCESS_EXIT = 0x200

_IFEO_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
_SPE_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit"

_exit_capture_lock = threading.Lock()
_exit_capture_armed = {}       # image name -> {"armed_at", "prior_globalflag", "spe_existed"}


def _exit_capture_supported():
    try:
        import winreg  # noqa: F401
        return True
    except ImportError:
        return False


def _exit_capture_arm(image_name):
    """Switch dump-on-exit on for one image name. Returns (ok, error)."""
    if not _exit_capture_supported():
        return False, "exit capture requires Windows"
    import winreg
    image_name = os.path.basename(image_name or "")
    if not image_name.lower().endswith((".exe", ".com", ".scr")):
        return False, "only executables can be monitored by image name"
    try:
        os.makedirs(EXIT_CAPTURE_DIR, exist_ok=True)
    except OSError as e:
        return False, f"cannot create {EXIT_CAPTURE_DIR}: {e}"

    with _exit_capture_lock:
        state = _exit_capture_armed.get(image_name.lower())
        try:
            ifeo = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE,
                                      f"{_IFEO_KEY}\\{image_name}", 0,
                                      winreg.KEY_READ | winreg.KEY_WRITE)
            # Keep whatever GlobalFlag someone else set, and restore it later.
            try:
                prior, _ = winreg.QueryValueEx(ifeo, "GlobalFlag")
            except OSError:
                prior = None
            if state is None:
                state = {"prior_globalflag": prior}
            winreg.SetValueEx(ifeo, "GlobalFlag", 0, winreg.REG_DWORD,
                              (prior or 0) | FLG_MONITOR_SILENT_PROCESS_EXIT)
            winreg.CloseKey(ifeo)

            spe = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE,
                                     f"{_SPE_KEY}\\{image_name}", 0, winreg.KEY_WRITE)
            winreg.SetValueEx(spe, "ReportingMode", 0, winreg.REG_DWORD, 2)  # local dump
            winreg.SetValueEx(spe, "LocalDumpFolder", 0, winreg.REG_EXPAND_SZ, EXIT_CAPTURE_DIR)
            winreg.SetValueEx(spe, "DumpType", 0, winreg.REG_DWORD, EXIT_CAPTURE_DUMP_TYPE)
            winreg.SetValueEx(spe, "IgnoreSelfExits", 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(spe)
        except OSError as e:
            return False, f"registry write failed: {e}"
        state["armed_at"] = time.time()
        # Overlapping submissions of the same file name share the registry
        # keys; only the last one to finish may remove them.
        state["refs"] = state.get("refs", 0) + 1
        _exit_capture_armed[image_name.lower()] = state
    return True, None


def _exit_capture_disarm(image_name):
    """Undo _exit_capture_arm, restoring any GlobalFlag that was there before."""
    if not _exit_capture_supported():
        return
    import winreg
    image_name = os.path.basename(image_name or "")
    with _exit_capture_lock:
        state = _exit_capture_armed.get(image_name.lower())
        if state and state.get("refs", 1) > 1:
            state["refs"] -= 1
            return
        state = _exit_capture_armed.pop(image_name.lower(), None) or {}
        prior = state.get("prior_globalflag")
        try:
            ifeo = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{_IFEO_KEY}\\{image_name}",
                                  0, winreg.KEY_READ | winreg.KEY_WRITE)
            if prior:
                winreg.SetValueEx(ifeo, "GlobalFlag", 0, winreg.REG_DWORD, prior)
                winreg.CloseKey(ifeo)
            else:
                try:
                    winreg.DeleteValue(ifeo, "GlobalFlag")
                except OSError:
                    pass
                # Remove the key only when we leave it empty.
                empty = winreg.QueryInfoKey(ifeo)[:2] == (0, 0)
                winreg.CloseKey(ifeo)
                if empty:
                    winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, f"{_IFEO_KEY}\\{image_name}")
        except OSError:
            pass
        try:
            winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, f"{_SPE_KEY}\\{image_name}")
        except OSError:
            pass


def _exit_capture_find_dump(image_name, pid=None, since=0.0):
    """Newest exit dump for an image (optionally one PID) written after `since`."""
    if not os.path.isdir(EXIT_CAPTURE_DIR):
        return None
    prefix = os.path.basename(image_name).lower() + "-(pid-"
    best = None
    for folder in os.listdir(EXIT_CAPTURE_DIR):
        if not folder.lower().startswith(prefix):
            continue
        if pid and f"-(pid-{int(pid)})" not in folder.lower():
            continue
        full = os.path.join(EXIT_CAPTURE_DIR, folder)
        for name in os.listdir(full) if os.path.isdir(full) else []:
            if not name.lower().endswith(".dmp"):
                continue
            path = os.path.join(full, name)
            mtime = os.path.getmtime(path)
            if mtime >= since and (best is None or mtime > best[0]):
                best = (mtime, path)
    return best[1] if best else None


def _exit_capture_prune():
    """Keep the newest EXIT_CAPTURE_KEEP capture folders; full dumps are large."""
    if not os.path.isdir(EXIT_CAPTURE_DIR):
        return
    import shutil
    folders = [os.path.join(EXIT_CAPTURE_DIR, f) for f in os.listdir(EXIT_CAPTURE_DIR)]
    folders = sorted((f for f in folders if os.path.isdir(f)),
                     key=os.path.getmtime, reverse=True)
    for old in folders[EXIT_CAPTURE_KEEP:]:
        shutil.rmtree(old, ignore_errors=True)


def _exit_capture_analyze(dump_path, process_name):
    """Analyze one exit dump and cache-friendly shape the result."""
    extract_dir = os.path.join(os.path.dirname(dump_path), "artifacts")
    rules_dir = AETHER_RULES_DIR if os.path.isdir(AETHER_RULES_DIR) else None
    result = minidump_analysis.analyze(
        dump_path, process=process_name, rules_dir=rules_dir, extract_dir=extract_dir)
    result["evidence"] = memory_evidence.score(
        result["evidence_findings"], baseline=_memory_baseline)
    return result


def _exit_capture_watch(image_name, pid, sha256, armed_at):
    """Wait for the sample to exit (or the window to close), then analyze."""
    def _wait_for_dump():
        deadline = armed_at + EXIT_CAPTURE_WINDOW
        while time.time() < deadline:
            dump = _exit_capture_find_dump(image_name, pid=pid, since=armed_at - 1)
            if dump:
                # The dump is written while the process is held at exit; give
                # the writer a moment to finish before reading it.
                size = -1
                for _ in range(20):
                    try:
                        cur = os.path.getsize(dump)
                    except OSError:
                        return None
                    if cur == size and cur > 0:
                        break
                    size = cur
                    time.sleep(0.5)
                return dump
            time.sleep(2)
        return None

    def _watch():
        try:
            dump = _wait_for_dump()
        finally:
            # Whatever happens above, the IFEO keys must not stay behind: a
            # left-over GlobalFlag would dump that image name forever.
            _exit_capture_disarm(image_name)

        if not dump:
            entry = {
                "tool": "Exit Capture", "process": image_name, "pid": pid,
                "observed": False, "captured": False,
                "note": f"Process did not exit within {EXIT_CAPTURE_WINDOW}s "
                        "(still running - the live scanners cover it).",
            }
        else:
            try:
                entry = _exit_capture_analyze(dump, image_name)
                entry["captured"] = True
                entry["pid"] = pid
                _record_scan("Exit Capture", f"PID {pid}", entry)
            except Exception as e:
                entry = {"tool": "Exit Capture", "pid": pid, "captured": True,
                         "observed": False, "dump_path": dump, "error": str(e)}
        _beacon_results_cache.put("exitcapture", entry, pid=pid, sha256=sha256)
        _exit_capture_prune()

    threading.Thread(target=_watch, daemon=True).start()


SCAN_UPLOADS_KEEP = 40


def _save_scan_upload(file):
    """Store an uploaded sample in its own temp directory.

    A shared fixed name broke as soon as two scans overlapped: the running
    scanner holds the file open, so the next open(..., "wb") fails with
    Errno 22, or one scan analyzes the other upload's bytes. Returns
    (filepath, cleanup_dir).
    """
    import tempfile
    base = os.path.join(tempfile.gettempdir(), "scan_uploads")
    os.makedirs(base, exist_ok=True)
    # Uploads stay around briefly (results link to them, e.g. "open in hex
    # editor"); older ones are pruned so the folder does not grow forever.
    try:
        import shutil
        dirs = sorted((os.path.join(base, d) for d in os.listdir(base)),
                      key=os.path.getmtime, reverse=True)
        for old in [d for d in dirs if os.path.isdir(d)][SCAN_UPLOADS_KEEP:]:
            shutil.rmtree(old, ignore_errors=True)
    except OSError:
        pass
    cleanup_dir = tempfile.mkdtemp(dir=base)
    filepath = os.path.join(cleanup_dir, secure_filename(file.filename or "") or "scan_target")
    file.save(filepath)
    return filepath, cleanup_dir


@app.route("/api/scan/threatcheck", methods=["POST"])
def api_scan_threatcheck():
    """Run ThreatCheck on an uploaded file or a VM path."""
    engine = request.form.get("engine", "Defender")  # Defender or AMSI
    file_type = request.form.get("type", "Bin")  # Bin or Script
    filepath = request.form.get("path", "")

    if not os.path.isfile(THREATCHECK_EXE):
        return jsonify({"error": "ThreatCheck not installed"}), 500

    # If file uploaded, save it to a private temp directory
    cleanup_dir = None
    if "file" in request.files:
        filepath, cleanup_dir = _save_scan_upload(request.files["file"])
    elif not filepath or not os.path.isfile(filepath):
        return jsonify({"error": "No file provided or path not found"}), 400

    try:
        args = [THREATCHECK_EXE, "-f", filepath, "-e", engine]
        if file_type == "Script":
            args.extend(["-t", "Script"])
        result = _run_cmd(
            args, timeout=120,
            cwd=os.path.dirname(THREATCHECK_EXE)
        )
        output = (result.stdout or "") + (result.stderr or "")
        detected = "Identified" in output or "DETECTED" in output.upper()
        clean = "No threat found" in output

        resp = {
            "tool": "ThreatCheck",
            "engine": engine,
            "file_type": file_type,
            "filepath": filepath,
            "output": output.strip(),
            "detected": detected,
            "clean": clean,
            "exit_code": result.returncode,
        }
        _record_scan("ThreatCheck", os.path.basename(filepath), resp)
        return jsonify(resp)
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

    # If file uploaded, save it to a private temp directory
    cleanup_dir = None
    if "file" in request.files:
        filepath, cleanup_dir = _save_scan_upload(request.files["file"])
    elif not filepath or not os.path.isfile(filepath):
        return jsonify({"error": "No file provided or path not found"}), 400

    try:
        result = _run_cmd(
            [DEFENDERCHECK_EXE, filepath],
            timeout=120,
            cwd=os.path.dirname(DEFENDERCHECK_EXE)
        )
        output = (result.stdout or "") + (result.stderr or "")
        detected = "Identified" in output or "detected" in output.lower()
        clean = "No threat found" in output

        resp = {
            "tool": "DefenderCheck",
            "filepath": filepath,
            "output": output.strip(),
            "detected": detected,
            "clean": clean,
            "exit_code": result.returncode,
        }
        _record_scan("DefenderCheck", os.path.basename(filepath), resp)
        return jsonify(resp)
    except subprocess.TimeoutExpired:
        return jsonify({"error": "DefenderCheck timed out (120s)"}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/scan/ember", methods=["POST"])
def api_scan_ember():
    """Score a file with an EMBER2024 (thrember) LightGBM classifier.

    Returns the malicious probability (0..1) and a verdict. Params:
      file / path  - uploaded file or a VM-local path
      model        - one of EMBER_MODELS (default EMBER2024_all)
      threshold    - malicious decision threshold (default 0.5)
    """
    model = request.form.get("model", "EMBER2024_all")
    if model not in EMBER_MODELS:
        return jsonify({"error": f"Unknown model '{model}'"}), 400
    try:
        threshold = float(request.form.get("threshold", "0.5"))
    except ValueError:
        return jsonify({"error": "Invalid threshold"}), 400

    if not os.path.isfile(EMBER_PYTHON) or not os.path.isfile(EMBER_SCRIPT):
        return jsonify({"error": "EMBER2024 not installed"}), 500

    filepath = request.form.get("path", "")
    cleanup_dir = None
    if "file" in request.files:
        filepath, cleanup_dir = _save_scan_upload(request.files["file"])
    elif not filepath or not os.path.isfile(filepath):
        return jsonify({"error": "No file provided or path not found"}), 400

    try:
        result = _run_cmd(
            [EMBER_PYTHON, EMBER_SCRIPT, filepath,
             "--model", model,
             "--threshold", str(threshold),
             "--models-dir", EMBER_MODELS_DIR],
            timeout=120,
            cwd=EMBER_ROOT,
        )
        stdout = (result.stdout or "").strip()
        try:
            data = json.loads(stdout.splitlines()[-1]) if stdout else {}
        except (ValueError, IndexError):
            data = {}

        if not data or "error" in data:
            err = data.get("error") if data else ((result.stderr or stdout or "no output").strip())
            return jsonify({"error": f"EMBER scan failed: {err}"}), 500

        # Normalize to the shared scanner-result shape used by the UI/history.
        score = data.get("score")
        malicious = bool(data.get("malicious"))
        data["detected"] = malicious
        data["clean"] = not malicious
        data["output"] = (
            f"Model: {data.get('model')}\n"
            f"Malicious probability: {score:.4f}\n"
            f"Threshold: {data.get('threshold')}\n"
            f"Verdict: {str(data.get('verdict', '')).upper()}\n"
            f"SHA256: {data.get('sha256')}"
        )
        _record_scan("EMBER2024", os.path.basename(filepath), data)
        return jsonify(data)
    except subprocess.TimeoutExpired:
        return jsonify({"error": "EMBER scan timed out (120s)"}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/scan/capa", methods=["POST"])
def api_scan_capa():
    """Detect capabilities in a file with Mandiant capa (static, ATT&CK-mapped).

    Params:
      file / path  - uploaded file or a VM-local path
    """
    if not os.path.isfile(CAPA_EXE):
        return jsonify({"error": "capa not installed"}), 500

    filepath = request.form.get("path", "")
    cleanup_dir = None
    if "file" in request.files:
        file = request.files["file"]
        file_bytes = file.read()
        import tempfile
        # Each upload gets its OWN directory. capa can run for a very long time
        # on large/packed samples (it is x86-emulated on this ARM64 VM), and a
        # still-running capa.exe keeps the sample file locked. With a shared
        # fixed filename, the next upload's open(...,"wb") then fails with
        # OSError [Errno 22] and every subsequent scan 500s. A unique dir per
        # request isolates that and lets us clean up afterwards.
        base = os.path.join(tempfile.gettempdir(), "scan_uploads")
        os.makedirs(base, exist_ok=True)
        cleanup_dir = tempfile.mkdtemp(dir=base)
        # secure_filename strips spaces / Windows-illegal chars from the name.
        filepath = os.path.join(cleanup_dir, secure_filename(file.filename or "") or "scan_target")
        with open(filepath, "wb") as f:
            f.write(file_bytes)
    elif not filepath or not os.path.isfile(filepath):
        return jsonify({"error": "No file provided or path not found"}), 400

    try:
        proc = subprocess.Popen(
            [CAPA_EXE, "-q", "-j", filepath],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            cwd=os.path.dirname(CAPA_EXE),
        )
        try:
            out, err = proc.communicate(timeout=300)
        except subprocess.TimeoutExpired:
            # Force-kill the whole tree: capa may spawn analysis children, and
            # proc.kill() alone can orphan one that keeps holding the sample.
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           capture_output=True)
            try:
                proc.communicate(timeout=10)
            except Exception:
                pass
            _record_scan("capa", os.path.basename(filepath),
                         {"tool": "capa", "error": "capa timed out (300s)"},
                         status="timeout")
            return jsonify({"error": "capa timed out (300s) - sample too large or packed for static capa analysis on this ARM64 VM"}), 504
        returncode = proc.returncode
        stdout = (out or "").strip()
        try:
            doc = json.loads(stdout)
        except ValueError:
            errtxt = (err or stdout or "no output").strip()
            low = errtxt.lower()
            # capa is x86 and only understands x86/x64/.NET PEs. On this ARM64
            # VM most local binaries are ARM64, which capa rejects outright.
            if "arm64" in low or "unsupported" in low and "architecture" in low:
                msg = ("capa cannot analyze this file: unsupported architecture "
                       "(capa supports x86/x64 and .NET PEs, not ARM64/other).")
            elif not stdout and not (err or "").strip():
                msg = "capa produced no output (it may not support this file type)."
            else:
                msg = f"capa produced no JSON: {errtxt[:500]}"
            _record_scan("capa", os.path.basename(filepath),
                         {"tool": "capa", "error": msg, "exit_code": returncode,
                          "stderr": errtxt[:1000]},
                         status="error")
            return jsonify({"error": msg}), 422

        meta = doc.get("meta", {}) or {}
        sample = meta.get("sample", {}) or {}
        analysis = meta.get("analysis", {}) or {}
        rules = doc.get("rules", {}) or {}

        capabilities = []
        for name, r in rules.items():
            rm = (r.get("meta", {}) or {})
            if rm.get("lib"):
                continue  # skip library/helper rules
            attack = rm.get("att&ck") or rm.get("attack") or []
            mbc = rm.get("mbc") or []
            capabilities.append({
                "name": rm.get("name", name),
                "namespace": rm.get("namespace", "") or "",
                "matches": len(r.get("matches", []) or []),
                "attack": _parse_capa_attack(attack),
                "mbc": _parse_capa_attack(mbc),
            })
        capabilities.sort(key=lambda c: (c["namespace"], c["name"]))

        # Collect the distinct ATT&CK tactics seen, for a quick summary line.
        tactics = []
        for c in capabilities:
            for a in c["attack"]:
                tac = a.split(":")[0].strip()
                if tac and tac not in tactics:
                    tactics.append(tac)

        data = {
            "tool": "capa",
            "filepath": filepath,
            "sha256": sample.get("sha256", ""),
            "md5": sample.get("md5", ""),
            "format": analysis.get("format", ""),
            "arch": analysis.get("arch", ""),
            "os": analysis.get("os", ""),
            "capability_count": len(capabilities),
            "tactics": tactics,
            "capabilities": capabilities,
            "exit_code": returncode,
        }
        data["output"] = (
            f"Format: {data['format']} / {data['arch']} / {data['os']}\n"
            f"Capabilities: {len(capabilities)}\n"
            f"ATT&CK tactics: {', '.join(tactics) if tactics else 'none'}\n"
            f"SHA256: {data['sha256']}"
        )
        _record_scan("capa", os.path.basename(filepath), data)
        return jsonify(data)
    except Exception as e:
        _record_scan("capa", os.path.basename(filepath),
                     {"tool": "capa", "error": str(e)}, status="error")
        return jsonify({"error": str(e)}), 500
    finally:
        if cleanup_dir:
            import shutil
            shutil.rmtree(cleanup_dir, ignore_errors=True)


@app.route("/api/process/lookup")
def api_process_lookup():
    """Find running PIDs by (partial) image name.

    The sidebar process list is built from Sysmon/ETW telemetry and keeps
    historical entries, so it is not a reliable source of currently running
    PIDs. This asks the OS directly.
    """
    name = (request.args.get("name") or "").strip().lower()
    if not name:
        return jsonify({"error": "No name specified"}), 400

    try:
        proc = _run_cmd(
            ["tasklist", "/fo", "csv", "/nh"],
            timeout=30,
        )
    except FileNotFoundError:
        return jsonify({"error": "tasklist unavailable (not running on Windows)"}), 501
    except subprocess.TimeoutExpired:
        return jsonify({"error": "tasklist timed out"}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    import csv as _csv
    matches = []
    for row in _csv.reader((proc.stdout or "").splitlines()):
        if len(row) < 2:
            continue
        image, pid_str = row[0], row[1]
        if name not in image.lower():
            continue
        try:
            matches.append({
                "pid": int(pid_str),
                "name": image,
                "memory": row[4] if len(row) > 4 else "",
            })
        except ValueError:
            continue

    matches.sort(key=lambda m: m["pid"])
    return jsonify({"name": name, "count": len(matches), "matches": matches[:50]})


@app.route("/api/scan/status")
def api_scan_status():
    """Return availability status of scanning tools."""
    ember_installed = os.path.isfile(EMBER_PYTHON) and os.path.isfile(EMBER_SCRIPT)
    ember_models = []
    if os.path.isdir(EMBER_MODELS_DIR):
        ember_models = [
            m for m in EMBER_MODELS
            if os.path.isfile(os.path.join(EMBER_MODELS_DIR, m + ".model"))
        ]
    return jsonify({
        "threatcheck": {
            "installed": os.path.isfile(THREATCHECK_EXE),
            "path": THREATCHECK_EXE,
        },
        "defendercheck": {
            "installed": os.path.isfile(DEFENDERCHECK_EXE),
            "path": DEFENDERCHECK_EXE,
        },
        "ember": {
            "installed": ember_installed,
            "path": EMBER_SCRIPT,
            "models": ember_models,
        },
        "capa": {
            "installed": os.path.isfile(CAPA_EXE),
            "path": CAPA_EXE,
        },
        "hunt_sleeping_beacons": {
            "installed": os.path.isfile(HUNT_SLEEPING_BEACONS_EXE),
            "path": HUNT_SLEEPING_BEACONS_EXE,
        },
        "beaconeye": {
            "installed": os.path.isfile(BEACONEYE_EXE),
            "path": BEACONEYE_EXE,
        },
        "aether": {
            "installed": os.path.isfile(AETHER_EXE),
            "path": AETHER_EXE,
            "rules": len(glob.glob(os.path.join(AETHER_RULES_DIR, "*.json")))
                     if os.path.isdir(AETHER_RULES_DIR) else 0,
        },
        "process_dump": {
            "installed": os.path.isfile(PROCESSDUMP_EXE),
            "path": PROCESSDUMP_EXE,
            # Without the baseline every known-good module gets dumped too.
            "clean_db": os.path.isfile(os.path.join(os.path.dirname(PROCESSDUMP_EXE), "clean.hashes")),
            "dump_dir": PROCESSDUMP_DIR,
        },
        "exit_capture": {
            # OS-native, so "installed" just means we run on Windows.
            "installed": _exit_capture_supported(),
            "dump_dir": EXIT_CAPTURE_DIR,
            "window_seconds": EXIT_CAPTURE_WINDOW,
            "armed": sorted(_exit_capture_armed.keys()),
        },
    })


@app.route("/api/scan/history")
def api_scan_history():
    """Return the shared scan-history timeline (most recent first).

    Optional ?limit=N caps the number of entries returned.
    """
    history = _load_scan_history()
    try:
        limit = int(request.args.get("limit", "0"))
        if limit > 0:
            history = history[:limit]
    except (TypeError, ValueError):
        pass
    return jsonify({"count": len(history), "history": history})


@app.route("/api/scan/history/clear", methods=["POST"])
def api_scan_history_clear():
    """Clear the shared scan-history timeline."""
    with scan_history_lock:
        _save_scan_history([])
    return jsonify({"ok": True})


# --- Beacon Scanner Endpoints ---

_ANSI_RE = None


def _strip_ansi(text):
    global _ANSI_RE
    import re
    if _ANSI_RE is None:
        _ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
    return _ANSI_RE.sub("", text or "")


def _cross_arch_note(pid):
    """Why a scan of `pid` may be unreliable on this host, or None.

    Hunt-Sleeping-Beacons and BeaconEye are x64 tools. On ARM64 Windows they
    run emulated and read thread contexts and heaps through x64 structures,
    which only describe x64 (emulated) processes - such as most implants.
    """
    machine = _process_machine(pid)
    if machine and machine != "x64" and platform.machine().upper() == "ARM64":
        return f"target is a native {machine} process; this x64 scanner only sees x64 processes reliably"
    return None


def _run_hsb(pid=None):
    """Run Hunt-Sleeping-Beacons. Returns (result, error)."""
    if not os.path.isfile(HUNT_SLEEPING_BEACONS_EXE):
        return None, "Hunt-Sleeping-Beacons not installed"
    args = [HUNT_SLEEPING_BEACONS_EXE, "--commandline"]
    if pid:
        args += ["-p", str(int(pid))]
    try:
        proc = _run_cmd(args, timeout=120, cwd=os.path.dirname(HUNT_SLEEPING_BEACONS_EXE))
    except subprocess.TimeoutExpired:
        return None, "Hunt-Sleeping-Beacons timed out (120s)"
    except Exception as e:
        return None, str(e)
    output = _strip_ansi((proc.stdout or "") + (proc.stderr or ""))
    findings = _parse_hsb_output(output)
    result = {
        "tool": "Hunt-Sleeping-Beacons",
        "pid": pid,
        "output": output.strip()[-20000:],
        "findings": findings,
        "suspicious_count": len(findings),
        "exit_code": proc.returncode,
    }
    if pid:
        note = _cross_arch_note(pid)
        if note:
            result["limitation"] = note
    return result, None


def _run_beaconeye(pid=None):
    """Run BeaconEye. Returns (result, error).

    BeaconEye has no PID option: it scans every process (well under a
    second) and the report is filtered to the requested PID afterwards.
    """
    if not os.path.isfile(BEACONEYE_EXE):
        return None, "BeaconEye not installed"
    try:
        proc = _run_cmd([BEACONEYE_EXE], timeout=180, cwd=os.path.dirname(BEACONEYE_EXE))
    except subprocess.TimeoutExpired:
        return None, "BeaconEye timed out (180s)"
    except Exception as e:
        return None, str(e)
    output = _strip_ansi((proc.stdout or "") + (proc.stderr or ""))
    findings = _parse_beaconeye_output(output)
    if pid:
        findings = [f for f in findings if str(f.get("pid")) == str(pid)]
    result = {
        "tool": "BeaconEye",
        "pid": pid,
        "output": output.strip()[-20000:],
        "findings": findings,
        "beacons_found": len(findings),
        "exit_code": proc.returncode,
    }
    if pid:
        note = _cross_arch_note(pid)
        if note:
            result["limitation"] = note
    return result, None


def _scan_endpoint(runner, tool_key):
    data = request.get_json(silent=True) if request.is_json else request.form
    data = data or {}
    pid = data.get("pid")
    if pid not in (None, ""):
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            return jsonify({"error": "pid must be an integer"}), 400
    else:
        pid = None
    result, error = runner(pid)
    if error:
        status = 500 if "not installed" in error else 504 if "timed out" in error else 500
        return jsonify({"error": error}), status
    if pid:
        _beacon_results_cache.put(tool_key, result, pid=pid)
    return jsonify(result)


@app.route("/api/scan/beacons", methods=["POST"])
def api_scan_beacons():
    """Run Hunt-Sleeping-Beacons on a specific PID or all processes."""
    return _scan_endpoint(_run_hsb, "hsb")


@app.route("/api/scan/beaconeye", methods=["POST"])
def api_scan_beaconeye():
    """Run BeaconEye to scan process memory for CobaltStrike beacon configs."""
    return _scan_endpoint(_run_beaconeye, "beaconeye")


# --- Live-memory forensics: Aether ---

def _summarize_aether(payload):
    """Condense Aether's JSON report into counts the UI can render directly.

    Aether's "findings" array is heterogeneous: structural memory IOCs carry a
    "type" (MISSING_PEB, HEAP_API_TABLE, TSAV_*), while signature matches carry
    a "category" plus a "hits" list. They are split apart here so each can be
    presented on its own terms.

    Severity comes from Aether itself rather than being inferred from the
    finding type: it grades the same type differently depending on how much
    corroboration its L3 layer found (a MISSING_PEB image, for instance, is
    reported as INFO on its own and escalated only when another signal agrees).
    """
    findings = payload.get("findings") or []

    structural = [f for f in findings if f.get("type")]
    sig_groups = [f for f in findings if f.get("category")]

    by_severity, by_type = {}, {}
    struct_severity = {}
    for f in findings:
        sev = (f.get("severity") or "unknown").lower()
        by_severity[sev] = by_severity.get(sev, 0) + 1
    for f in structural:
        by_type[f["type"]] = by_type.get(f["type"], 0) + 1
        sev = (f.get("severity") or "unknown").lower()
        struct_severity[sev] = struct_severity.get(sev, 0) + 1

    categories, mitre = {}, set()
    sig_hits = 0
    # Generic string patterns match plenty of benign software, so track the
    # high-risk hits separately from the raw count.
    high_risk_hits = 0
    for g in sig_groups:
        cat = g.get("category")
        hits = g.get("hits") or []
        count = g.get("hit_count") or len(hits)
        categories[cat] = categories.get(cat, 0) + count
        sig_hits += count
        if g.get("mitre"):
            mitre.add(g["mitre"])
        for h in hits:
            try:
                if int(h.get("risk_score") or 0) >= 8:
                    high_risk_hits += 1
            except (TypeError, ValueError):
                pass

    return {
        "findings_total": len(findings),
        "structural_total": len(structural),
        "by_severity": by_severity,
        "by_type": by_type,
        "critical": by_severity.get("critical", 0),
        "high": by_severity.get("high", 0),
        "medium": by_severity.get("medium", 0),
        "info": by_severity.get("info", 0),
        # Severity split over structural IOCs only. Signature groups are graded
        # critical even for low-risk string patterns, which makes the combined
        # counts above unsuitable for scoring.
        "structural_critical": struct_severity.get("critical", 0),
        "structural_high": struct_severity.get("high", 0),
        "structural_by_severity": struct_severity,
        # Thread start-address verdicts are the highest-signal subset.
        "tsav": {t: c for t, c in by_type.items() if t.startswith("TSAV_")},
        "signature_groups": len(sig_groups),
        "signature_hits": sig_hits,
        "signature_high_risk": high_risk_hits,
        "signature_categories": categories,
        "mitre": sorted(mitre),
        "pe_headers_in_private": payload.get("pe_headers_in_private", 0),
        "dotnet_assemblies_in_private": payload.get("dotnet_assemblies_in_private", 0),
        "regions_scanned": payload.get("regions_scanned", 0),
        "bytes_scanned": payload.get("bytes_scanned", 0),
        "scan_time_ms": payload.get("scan_time_ms", 0),
    }


def _run_aether_once(pid=None, scan_all=False, timeout=180):
    """Single Aether invocation in JSON mode. Returns (result_dict, error)."""
    if not os.path.isfile(AETHER_EXE):
        return None, "Aether not installed"

    args = [AETHER_EXE, "--scan", "--json"]
    if scan_all:
        args = [AETHER_EXE, "--scan-all", "--json"]
    elif pid:
        args += ["--pid", str(pid)]
    else:
        return None, "No PID specified"

    if os.path.isdir(AETHER_RULES_DIR):
        args += ["--rules", AETHER_RULES_DIR]

    try:
        proc = _run_cmd(
            args, timeout=timeout,
            cwd=os.path.dirname(AETHER_EXE),
        )
    except subprocess.TimeoutExpired:
        return None, f"Aether timed out ({timeout}s)"
    except Exception as e:
        return None, str(e)

    stdout = proc.stdout or ""
    stderr = proc.stderr or ""

    # Aether prints a banner before the JSON object, so locate the report by
    # its first brace rather than parsing the whole stream.
    payload, parse_error = None, None
    start = stdout.find("{")
    if start >= 0:
        try:
            payload = json.loads(stdout[start:])
        except json.JSONDecodeError as e:
            parse_error = f"Could not parse Aether JSON: {e}"
    else:
        parse_error = "Aether produced no JSON output"

    result = {
        "tool": "Aether",
        "pid": pid,
        "scan_all": scan_all,
        "exit_code": proc.returncode,
        "raw_output": stdout.strip()[:20000],
    }
    if stderr.strip():
        result["stderr"] = stderr.strip()[:2000]
    if payload is not None:
        result["report"] = payload
        result["summary"] = _summarize_aether(payload)
    if parse_error:
        result["parse_error"] = parse_error

    return result, None


def _run_aether(pid=None, scan_all=False, timeout=180, samples=1, interval=3.0,
                process_name=""):
    """Scan with Aether, optionally sampling repeatedly.

    Live memory changes between scans, so a single snapshot cannot distinguish
    "this process has an implant" from "this region looked odd for a moment".
    With samples > 1 the same target is scanned several times and each finding
    records how many samples contained it; the scoring layer then discounts
    transient ones.
    """
    samples = max(1, min(int(samples or 1), 10))
    runs, errors = [], []

    for i in range(samples):
        if i:
            time.sleep(max(0.0, min(float(interval or 0), 30.0)))
        result, error = _run_aether_once(pid=pid, scan_all=scan_all, timeout=timeout)
        if error:
            errors.append(error)
            # A tool that is missing or times out will not succeed on retry.
            break
        runs.append(result)

    if not runs:
        return None, (errors[0] if errors else "Aether produced no result")

    # The last run carries the report shown in the UI; earlier ones only
    # contribute persistence information.
    final = dict(runs[-1])
    final["samples"] = len(runs)
    final["sample_interval"] = interval if len(runs) > 1 else 0

    # A scan that read no regions observed nothing - usually because the
    # process exited first. That is a failed observation, not a clean result,
    # and must not be reported as evidence of absence.
    scanned_any = any((r.get("report") or {}).get("regions_scanned") for r in runs)
    final["observed"] = bool(scanned_any)
    if not scanned_any:
        final["observation_note"] = (
            "No memory regions could be read - the process most likely exited "
            "before the scan. This is not evidence that it was clean."
        )

    # Key by full image path where it can be resolved (see _image_path_for_pid).
    identity = (_image_path_for_pid(pid) if pid else "") or process_name
    per_sample = [
        memory_evidence.from_aether(r.get("report") or {}, process=identity)
        for r in runs
    ]
    merged = memory_evidence.merge_samples(per_sample)
    final["evidence_findings"] = merged
    final["evidence"] = memory_evidence.score(merged, baseline=_memory_baseline)
    if not scanned_any:
        final["evidence"]["label"] = "NOT OBSERVED"
        final["evidence"]["note"] = final["observation_note"]

    if errors:
        final["sample_errors"] = errors
    return final, None


@app.route("/api/scan/aether", methods=["POST"])
def api_scan_aether():
    """Scan a live process with Aether (injection / implant memory forensics).

    Accepts ``samples`` (and ``interval`` seconds) to scan repeatedly: findings
    then carry how many samples contained them, and the scoring layer discounts
    the transient ones.
    """
    data = request.get_json(force=True) if request.is_json else request.form
    pid = data.get("pid")
    scan_all = str(data.get("scan_all", "")).lower() in ("1", "true", "yes")
    samples = data.get("samples") or 1
    interval = data.get("interval") or 3
    process_name = (data.get("process") or "").strip()

    if not pid and not scan_all:
        return jsonify({"error": "Provide a pid, or set scan_all"}), 400

    # Resolve the image name so findings are attributed to a process rather
    # than a PID, which is what makes baselines reusable across reboots.
    if pid and not process_name:
        process_name = _image_name_for_pid(pid)

    # A whole-system sweep touches every accessible process, so it gets longer.
    result, error = _run_aether(
        pid=pid, scan_all=scan_all, timeout=600 if scan_all else 180,
        samples=samples, interval=interval, process_name=process_name,
    )
    if error:
        status = 500 if "not installed" in error else 504 if "timed out" in error else 400
        return jsonify({"error": error, "path": AETHER_EXE}), status

    result["process"] = process_name
    if pid:
        _beacon_results_cache.put("aether", result, pid=pid)

    _record_scan("Aether", f"PID {pid}" if pid else "all processes", result)

    return jsonify(result)


def _image_name_for_pid(pid):
    """Best-effort image name for a PID (used to key findings and baselines)."""
    try:
        proc = _run_cmd(
            ["tasklist", "/fi", f"PID eq {int(pid)}", "/fo", "csv", "/nh"],
            timeout=15,
        )
        import csv as _csv
        for row in _csv.reader((proc.stdout or "").splitlines()):
            if row and row[0] and not row[0].startswith("INFO"):
                return row[0]
    except Exception:
        pass
    return ""


# --- Memory baseline management ---------------------------------------


def _parse_json_stream(text):
    """Parse concatenated JSON objects (Aether's --scan-all emits one per PID)."""
    decoder = json.JSONDecoder()
    objs, i, n = [], 0, len(text)
    start = text.find("{")
    if start < 0:
        return objs
    i = start
    while i < n:
        while i < n and text[i] in " \r\n\t,[]":
            i += 1
        if i >= n:
            break
        try:
            obj, i = decoder.raw_decode(text, i)
        except json.JSONDecodeError:
            # Skip to the next object rather than losing the rest of the sweep.
            nxt = text.find("{", i + 1)
            if nxt < 0:
                break
            i = nxt
            continue
        if isinstance(obj, dict):
            objs.append(obj)
    return objs


def _image_path_for_pid(pid):
    """Full image path of a running process, or "" (non-Windows / no access).

    Findings are keyed by path, not name, so a sample calling itself
    svchost.exe does not inherit the real svchost's baseline entries.
    """
    if os.name != "nt":
        return ""
    import ctypes
    from ctypes import wintypes
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    k32.QueryFullProcessImageNameW.argtypes = (
        wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD))
    k32.CloseHandle.argtypes = (wintypes.HANDLE,)
    try:
        handle = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
    except (TypeError, ValueError, OverflowError):
        return ""
    if not handle:
        return ""
    try:
        buf = ctypes.create_unicode_buffer(1024)
        size = wintypes.DWORD(len(buf))
        if k32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
            return buf.value
        return ""
    finally:
        k32.CloseHandle(handle)


def _process_machine(pid):
    """'x64', 'ARM64', 'x86', ... for a running process, or None if unknown.

    Read from the image's PE header: on ARM64 Windows, IsWow64Process2
    reports x64 processes as native, so it cannot tell them apart.
    """
    path = _image_path_for_pid(pid)
    if not path:
        return None
    try:
        with open(path, "rb") as f:
            head = f.read(4096)
        off = struct.unpack_from("<I", head, 0x3C)[0]
        machine = struct.unpack_from("<H", head, off + 4)[0]
    except (OSError, struct.error):
        return None
    return {0x8664: "x64", 0xAA64: "ARM64", 0x14C: "x86", 0xA641: "ARM64EC", 0x1C4: "ARM"}.get(machine)


def _running_process_names():
    """PID -> image name for every running process (tasklist)."""
    names = {}
    try:
        proc = _run_cmd(["tasklist", "/fo", "csv", "/nh"],
                              timeout=30)
        import csv as _csv
        for row in _csv.reader((proc.stdout or "").splitlines()):
            if len(row) >= 2:
                try:
                    names[int(row[1])] = row[0]
                except ValueError:
                    continue
    except Exception:
        pass
    return names


# --- System-wide memory sweep (background job) ------------------------
#
# Scans every accessible process. On a clean box this is also the most
# complete way to capture the host baseline in one go.

_sweep_lock = threading.Lock()
_sweep_state = {"running": False}

# The chamber's own security tooling keeps detection rules in memory (rule
# strings such as "sekurlsa::logonpasswords" are exactly what the signature
# scanner looks for), so it matches its own signatures. Those processes are
# reported as excluded rather than scored.
HOST_TOOL_IMAGES = {
    "fibratus.exe", "rustinel.exe", "msmpeng.exe", "mssense.exe", "nissrv.exe",
    "aether.exe", "pd64.exe", "pd32.exe", "sysmon64.exe", "sysmon64a.exe",
    "sysmon.exe", "hunt-sleeping-beacons.exe", "beaconeye.exe",
}


def _is_host_tool(pid, image):
    if pid == os.getpid():
        return True  # this web UI: it loads the signature rules itself
    return (image or "").lower() in HOST_TOOL_IMAGES


def _sweep_entry(per_pid, pid, image):
    """Per-process accumulator; resolves the image path once per PID."""
    entry = per_pid.get(pid)
    if entry is None:
        entry = per_pid[pid] = {"process": image, "findings": [],
                                "identity": _image_path_for_pid(pid) or image}
    return entry


def _run_sweep(use_aether, use_processdump, capture_baseline):
    started = time.time()
    names = _running_process_names()
    per_pid, errors, stats = {}, [], {}

    if use_aether and os.path.isfile(AETHER_EXE):
        args = [AETHER_EXE, "--scan-all", "--json"]
        if os.path.isdir(AETHER_RULES_DIR):
            args += ["--rules", AETHER_RULES_DIR]
        try:
            proc = _run_cmd(args, timeout=1200,
                                  cwd=os.path.dirname(AETHER_EXE))
            reports = _parse_json_stream(proc.stdout or "")
            stats["aether_processes"] = len(reports)
            for rep in reports:
                pid = rep.get("pid")
                if pid is None:
                    continue
                image = names.get(int(pid), "")
                entry = _sweep_entry(per_pid, int(pid), image)
                entry["findings"] += memory_evidence.from_aether(rep, process=entry["identity"])
                per_pid[int(pid)]["regions_scanned"] = rep.get("regions_scanned", 0)
        except subprocess.TimeoutExpired:
            errors.append("Aether sweep timed out (1200s)")
        except Exception as e:
            errors.append(f"Aether sweep failed: {e}")

    if use_processdump and os.path.isfile(PROCESSDUMP_EXE):
        result, error = _run_process_dump(dump_system=True, timeout=1800)
        if error:
            errors.append(f"Process Dump sweep failed: {error}")
        else:
            stats["dumps"] = result["dump_count"]
            stats["dump_dir"] = result["output_dir"]
            by_pid = {}
            for d in result["dumps"]:
                if d.get("pid") is not None:
                    by_pid.setdefault(d["pid"], []).append(d)
            for pid, dumps in by_pid.items():
                image = names.get(pid, "")
                entry = _sweep_entry(per_pid, pid, image)
                entry["findings"] += memory_evidence.from_process_dump(
                    {"dumps": dumps}, process=entry["identity"])

    captured = 0
    processes, excluded = [], []
    for pid, entry in per_pid.items():
        if _is_host_tool(pid, entry["process"]):
            excluded.append({"pid": pid, "process": entry["process"] or "(this web UI)"})
            continue
        if capture_baseline:
            captured += _memory_baseline.add(entry["findings"])
            continue
        ev = memory_evidence.score(entry["findings"], baseline=_memory_baseline)
        if not ev["findings"] and not ev["suppressed_count"]:
            continue
        processes.append({
            "pid": pid,
            "process": entry["process"],
            "label": ev["label"],
            "score": ev["score"],
            "suppressed": ev["suppressed_count"],
            "regions_scanned": entry.get("regions_scanned"),
            "reasons": ev["reasons"][:4],
            "findings": [
                {k: f.get(k) for k in ("kind", "label", "source", "score",
                                       "confidence", "detail", "evidence")}
                for f in ev["findings"][:8]
            ],
        })
    processes.sort(key=lambda p: (-p["score"], p["process"].lower()))

    return {
        "started": started,
        "finished": time.time(),
        "duration_s": round(time.time() - started, 1),
        "mode": "baseline" if capture_baseline else "scan",
        "processes_seen": len(per_pid),
        "flagged": sum(1 for p in processes if p["label"] != "CLEAN"),
        "processes": processes[:200],
        # Security tools match their own detection rules; listed, not scored.
        "excluded_host_tools": sorted(excluded, key=lambda e: e["process"].lower()),
        "baseline_keys_added": captured if capture_baseline else None,
        "baseline": _memory_baseline.stats(),
        "stats": stats,
        "errors": errors,
    }


@app.route("/api/memory/sweep", methods=["POST"])
def api_memory_sweep_start():
    """Start a background sweep of every process.

    Body: {"aether": true, "processdump": false, "baseline": false}
    With "baseline": true the findings are recorded as the host baseline
    instead of being scored - run that on a clean box.
    """
    data = request.get_json(force=True) if request.is_json else request.form
    truthy = lambda v, d: d if v is None else str(v).lower() in ("1", "true", "yes")
    use_aether = truthy(data.get("aether"), True)
    use_pd = truthy(data.get("processdump"), False)
    capture_baseline = truthy(data.get("baseline"), False)

    if not (use_aether and os.path.isfile(AETHER_EXE)) and not (use_pd and os.path.isfile(PROCESSDUMP_EXE)):
        return jsonify({"error": "No selected sweep tool is installed"}), 400

    with _sweep_lock:
        if _sweep_state.get("running"):
            return jsonify({"error": "A sweep is already running",
                            "started": _sweep_state.get("started")}), 409
        _sweep_state.clear()
        _sweep_state.update({
            "running": True, "started": time.time(),
            "options": {"aether": use_aether, "processdump": use_pd,
                        "baseline": capture_baseline},
        })

    def _job():
        try:
            result = _run_sweep(use_aether, use_pd, capture_baseline)
            with _sweep_lock:
                _sweep_state.update({"running": False, "result": result})
        except Exception as e:
            with _sweep_lock:
                _sweep_state.update({"running": False, "error": str(e)})

    threading.Thread(target=_job, daemon=True).start()
    return jsonify({"started": True, "options": _sweep_state["options"]})


@app.route("/api/memory/sweep", methods=["GET"])
def api_memory_sweep_status():
    """Progress or result of the last sweep."""
    with _sweep_lock:
        state = dict(_sweep_state)
    if state.get("running"):
        state["elapsed_s"] = round(time.time() - state.get("started", time.time()), 1)
    return jsonify(state)


# --- Process Dump clean-hash database ---------------------------------
#
# Provisioning only runs "-db genquick" (running processes). The full "-db gen"
# also hashes every PE under WINDIR and Program Files, so modules that simply
# were not loaded during provisioning stop showing up in dumps. It takes tens of
# minutes, hence a background job. Only run it while the box is clean.

_pd_db_lock = threading.Lock()
_pd_db_state = {"running": False}


def _pd_db_counts():
    """Hash counts per database file, parsed from the files themselves."""
    root = os.path.dirname(PROCESSDUMP_EXE)
    out = {}
    for name in ("clean.hashes", "entrypoints.hashes", "shortentrypoints.hashes"):
        path = os.path.join(root, name)
        out[name] = os.path.getsize(path) if os.path.isfile(path) else None
    return out


@app.route("/api/processdump/baseline", methods=["GET"])
def api_pd_baseline_status():
    with _pd_db_lock:
        state = dict(_pd_db_state)
    if state.get("running"):
        state["elapsed_s"] = round(time.time() - state.get("started", time.time()), 1)
    state["files"] = _pd_db_counts()
    return jsonify(state)


@app.route("/api/processdump/baseline", methods=["POST"])
def api_pd_baseline_build():
    """Extend the clean-hash database. Body: {"mode": "gen" | "genquick"}."""
    data = request.get_json(force=True) if request.is_json else request.form
    mode = (data.get("mode") or "gen").lower()
    if mode not in ("gen", "genquick"):
        return jsonify({"error": "mode must be gen or genquick"}), 400
    if not os.path.isfile(PROCESSDUMP_EXE):
        return jsonify({"error": "Process Dump not installed"}), 500

    with _pd_db_lock:
        if _pd_db_state.get("running"):
            return jsonify({"error": "Database generation already running"}), 409
        _pd_db_state.clear()
        _pd_db_state.update({"running": True, "mode": mode, "started": time.time(),
                             "files_before": _pd_db_counts()})

    def _job():
        root = os.path.dirname(PROCESSDUMP_EXE)
        try:
            proc = _run_cmd([PROCESSDUMP_EXE, "-db", mode, "-nh"],
                                  timeout=7200, cwd=root)
            out = (proc.stdout or "") + (proc.stderr or "")
            # Process Dump reports the resulting total on its last summary line.
            total = None
            for line in out.splitlines():
                if "clean hash database now has" in line:
                    digits = "".join(c for c in line.split("has", 1)[1] if c.isdigit())
                    total = int(digits) if digits else None
            with _pd_db_lock:
                _pd_db_state.update({
                    "running": False, "finished": time.time(),
                    "exit_code": proc.returncode, "clean_hashes": total,
                    "output_tail": out.strip()[-3000:],
                })
        except subprocess.TimeoutExpired:
            with _pd_db_lock:
                _pd_db_state.update({"running": False, "error": "timed out after 2h"})
        except Exception as e:
            with _pd_db_lock:
                _pd_db_state.update({"running": False, "error": str(e)})

    threading.Thread(target=_job, daemon=True).start()
    return jsonify({"started": True, "mode": mode})


@app.route("/api/memory/baseline", methods=["GET"])
def api_memory_baseline():
    """Report what the host baseline currently suppresses."""
    stats = _memory_baseline.stats()
    stats["path"] = MEMORY_BASELINE_FILE
    return jsonify(stats)


@app.route("/api/memory/baseline/capture", methods=["POST"])
def api_memory_baseline_capture():
    """Scan processes and record their findings as benign for this host.

    Run this while the box is clean. Everything seen now stops counting as
    evidence later, which is what removes the standing noise (explorer.exe's
    heap API tables, framework string matches) from every later verdict.
    """
    data = request.get_json(force=True) if request.is_json else request.form
    pids = data.get("pids") or []
    names = data.get("names") or []
    samples = data.get("samples") or 2

    if isinstance(pids, str):
        pids = [p.strip() for p in pids.split(",") if p.strip()]
    if isinstance(names, str):
        names = [n.strip() for n in names.split(",") if n.strip()]

    # Default to the processes that generate the standing noise.
    if not pids and not names:
        names = ["explorer.exe", "svchost.exe", "RuntimeBroker.exe", "msedge.exe"]

    targets = []
    for pid in pids:
        try:
            targets.append((int(pid), _image_name_for_pid(pid)))
        except (TypeError, ValueError):
            continue
    for name in names:
        try:
            proc = _run_cmd(
                ["tasklist", "/fi", f"IMAGENAME eq {name}", "/fo", "csv", "/nh"],
                timeout=20,
            )
            import csv as _csv
            for row in _csv.reader((proc.stdout or "").splitlines()):
                if len(row) >= 2 and not row[0].startswith("INFO"):
                    try:
                        targets.append((int(row[1]), row[0]))
                    except ValueError:
                        continue
        except Exception:
            continue

    if not targets:
        return jsonify({"error": "No matching running processes"}), 404

    # Cap the work: a baseline sweep is interactive, not a batch job.
    targets = targets[:12]

    captured, scanned, failures = 0, [], []
    for pid, image in targets:
        result, error = _run_aether(
            pid=pid, samples=samples, interval=2, process_name=image, timeout=180
        )
        if error:
            failures.append({"pid": pid, "process": image, "error": error})
            continue
        findings = result.get("evidence_findings") or []
        added = _memory_baseline.add(findings)
        captured += added
        scanned.append({
            "pid": pid, "process": image,
            "findings": len(findings), "new_keys": added,
        })

    stats = _memory_baseline.stats()
    return jsonify({
        "captured": captured,
        "scanned": scanned,
        "failures": failures,
        "samples_per_process": samples,
        "baseline": stats,
    })


@app.route("/api/memory/baseline", methods=["DELETE"])
def api_memory_baseline_clear():
    """Forget the host baseline (every finding counts as evidence again)."""
    _memory_baseline.clear()
    return jsonify({"ok": True, "baseline": _memory_baseline.stats()})


@app.route("/api/memory/evidence", methods=["POST"])
def api_memory_evidence():
    """Re-score the cached memory findings for a PID across all scanners.

    Useful after a baseline change, and the place where cross-tool
    corroboration becomes visible without re-running any scanner.
    """
    data = request.get_json(force=True) if request.is_json else request.form
    pid = data.get("pid")
    if not pid:
        return jsonify({"error": "Provide a pid"}), 400

    with _beacon_cache_lock:
        cached = {
            "aether": _beacon_results_cache.lookup("aether", pid),
            "process_dump": _beacon_results_cache.lookup("processdump", pid),
            "hunt_sleeping_beacons": _beacon_results_cache.lookup("hsb", pid),
            "beaconeye": _beacon_results_cache.lookup("beaconeye", pid),
            "exit_capture_result": _beacon_results_cache.lookup("exitcapture", pid),
        }
    cached = {k: v for k, v in cached.items() if v}
    net = _network_beaconing_for_pid(pid)
    if net.get("evidence_findings"):
        cached["network_beaconing"] = net
    if not cached:
        return jsonify({"error": f"No cached memory results for PID {pid}"}), 404

    # The process may have exited, in which case tasklist knows no name. Use
    # the name recorded with the results so all sources agree on it -
    # corroboration matches findings by process name.
    process_name = ""
    for key in ("aether", "exit_capture_result", "process_dump"):
        entry = cached.get(key) or {}
        if entry.get("process"):
            process_name = entry["process"]
            break
    process_name = process_name or _image_name_for_pid(pid)
    findings = memory_evidence.collect(cached, process=process_name)
    return jsonify({
        "pid": pid,
        "process": process_name,
        "sources": sorted(cached.keys()),
        "evidence": memory_evidence.score(findings, baseline=_memory_baseline),
    })


# --- Memory dumping: Process Dump ---

def _parse_processdump_filename(name):
    """Pull the metadata Process Dump encodes into each dump's filename.

    Examples:
      notepad_exe_PID2990_hiddenmodule_16B8ABB0000_x86.dll
      notepad_exe_PID2c54_codechunk_17BD0000_x64.exe
    """
    info = {"filename": name, "kind": "module"}
    stem = os.path.splitext(name)[0]
    parts = stem.split("_")

    for part in parts:
        if part.startswith("PID"):
            info["pid_hex"] = part[3:]
            try:
                # Process Dump writes the PID in hex in the filename.
                info["pid"] = int(part[3:], 16)
            except ValueError:
                pass
    if "hiddenmodule" in stem:
        # Module was never registered in the PEB: stomping or manual mapping.
        info["kind"] = "hiddenmodule"
    elif "codechunk" in stem:
        # Executable memory with no PE header; headers were synthesized.
        info["kind"] = "codechunk"
    if parts and parts[-1] in ("x86", "x64"):
        info["arch"] = parts[-1]
        if len(parts) >= 2:
            info["base_address"] = parts[-2]
    return info


PROCESSDUMP_KEEP = 30  # per-run dump folders retained under C:\dumps


def _processdump_prune():
    """Keep the newest PROCESSDUMP_KEEP run folders (the exit\\ folder is separate)."""
    if not os.path.isdir(PROCESSDUMP_DIR):
        return
    import shutil
    runs = []
    for name in os.listdir(PROCESSDUMP_DIR):
        full = os.path.join(PROCESSDUMP_DIR, name)
        # Run folders are named <YYYYmmdd-HHMMSS>_<label>; leave anything else alone.
        if os.path.isdir(full) and len(name) > 16 and name[8] == "-" and name[:8].isdigit():
            runs.append(full)
    runs.sort(key=os.path.getmtime, reverse=True)
    for old in runs[PROCESSDUMP_KEEP:]:
        shutil.rmtree(old, ignore_errors=True)


def _classify_codechunk(entry, raw):
    """Mark Process Dump code chunks that are host artifacts, not sample code.

    Process Dump wraps a header-less executable region in a synthetic PE whose
    first section holds the region. On ARM64 hosts running x64 samples, that
    region is frequently the emulator's ARM64 translation cache; the same
    classifier the exit-capture analysis uses decides that from the bytes.
    """
    if platform.machine().upper() not in ("ARM64", "AARCH64"):
        return
    try:
        import pefile
        pe = pefile.PE(data=raw, fast_load=True)
        payload = pe.sections[0].get_data() if pe.sections else b""
        pe.close()
    except Exception:
        return
    cls, why = minidump_analysis.classify_private_exec({}, payload, emulated=True)
    if cls != "code":
        entry["host_class"] = cls
        entry["host_reason"] = why


def _run_process_dump(pid=None, dump_system=False, ignore_db=False,
                      process_name="", timeout=None):
    """Run Process Dump and describe what it produced.

    Returns (result_dict, error_or_None). Shared by the HTTP endpoint and the
    post-detonation scan chain so both produce identically shaped results.
    """
    if not os.path.isfile(PROCESSDUMP_EXE):
        return None, "Process Dump not installed"
    if not pid and not dump_system:
        return None, "No PID specified"

    # Each run gets its own folder so the result lists exactly what this dump
    # produced, instead of everything ever dumped.
    stamp = time.strftime("%Y%m%d-%H%M%S")
    label = f"pid{pid}" if pid else "system"
    out_dir = os.path.join(PROCESSDUMP_DIR, f"{stamp}_{label}")
    try:
        os.makedirs(out_dir, exist_ok=True)
    except OSError as e:
        return None, f"Cannot create dump folder: {e}"

    args = [PROCESSDUMP_EXE, "-o", out_dir]
    if dump_system:
        args.append("-system")
    else:
        args += ["-pid", str(pid)]
    if ignore_db:
        # Dump known-good modules too; useful when the baseline is suspect.
        args += ["-db", "ignore"]

    if timeout is None:
        timeout = 900 if dump_system else 300

    try:
        proc = _run_cmd(
            args, timeout=timeout,
            cwd=os.path.dirname(PROCESSDUMP_EXE),
        )
    except subprocess.TimeoutExpired:
        return None, f"Process Dump timed out ({timeout}s)"
    except Exception as e:
        return None, str(e)

    output = (proc.stdout or "") + (proc.stderr or "")

    dumps = []
    try:
        for name in sorted(os.listdir(out_dir)):
            full = os.path.join(out_dir, name)
            if not os.path.isfile(full):
                continue
            entry = _parse_processdump_filename(name)
            entry["path"] = full
            entry["size"] = os.path.getsize(full)
            try:
                if entry["kind"] == "codechunk":
                    # Chunks are small and their bytes are needed anyway.
                    with open(full, "rb") as f:
                        raw = f.read()
                    entry["sha256"] = hashlib.sha256(raw).hexdigest()
                    _classify_codechunk(entry, raw)
                else:
                    # A -system dump writes thousands of modules; hash them
                    # in chunks instead of loading each one into memory.
                    h = hashlib.sha256()
                    with open(full, "rb") as f:
                        for block in iter(lambda: f.read(1024 * 1024), b""):
                            h.update(block)
                    entry["sha256"] = h.hexdigest()
            except OSError:
                pass
            dumps.append(entry)
    except OSError:
        pass

    host_chunks = sum(1 for d in dumps if d.get("host_class"))
    _processdump_prune()
    return {
        "tool": "Process Dump",
        "pid": pid,
        "process": process_name,
        "system": dump_system,
        # Flagged so the evidence layer can discount the dumps: without the
        # baseline the dump is "everything", not "what is new".
        "clean_db_ignored": ignore_db,
        "output_dir": out_dir,
        "dumps": dumps,
        "dump_count": len(dumps),
        "hidden_modules": sum(1 for d in dumps if d["kind"] == "hiddenmodule"),
        # Header-less chunks the host explains (emulator cache) are listed but
        # not counted, so the headline matches what the evidence model scores.
        "code_chunks": sum(1 for d in dumps if d["kind"] == "codechunk" and not d.get("host_class")),
        "host_code_chunks": host_chunks,
        "output": output.strip()[:20000],
        "exit_code": proc.returncode,
    }, None


@app.route("/api/scan/processdump", methods=["POST"])
def api_scan_processdump():
    """Dump a live process's memory components to disk with Process Dump.

    The resulting PE files are regular samples on disk, so each one can be fed
    straight back into the file map, PE analyzer, capa or EMBER.
    """
    data = request.get_json(force=True) if request.is_json else request.form
    pid = data.get("pid")
    dump_system = str(data.get("system", "")).lower() in ("1", "true", "yes")
    ignore_db = str(data.get("ignore_clean_db", "")).lower() in ("1", "true", "yes")

    if not os.path.isfile(PROCESSDUMP_EXE):
        return jsonify({"error": "Process Dump not installed", "path": PROCESSDUMP_EXE}), 500
    if not pid and not dump_system:
        return jsonify({"error": "Provide a pid, or set system"}), 400

    result, error = _run_process_dump(
        pid=pid, dump_system=dump_system, ignore_db=ignore_db,
        process_name=_image_name_for_pid(pid) if pid else "",
    )
    if error:
        status = 504 if "timed out" in error else 500
        return jsonify({"error": error}), status

    if pid:
        _beacon_results_cache.put("processdump", result, pid=pid)

    _record_scan("Process Dump", f"PID {pid}" if pid else "all processes", result)

    return jsonify(result)


def _parse_hsb_output(output):
    """Parse Hunt-Sleeping-Beacons output.

    Format (logger.hpp):
        * Detections for: <image> (<pid>) <cmdline>
            ! Thread <tid> | <title> | <description> | Severity: <level>
    One finding per process, carrying its thread detections.
    """
    import re
    head = re.compile(r"^\* Detections for: (.+?) \((\d+)\)\s*(.*)$")
    det = re.compile(r"^!\s*Thread (\d+)\s*\|\s*(.*?)\s*\|\s*(.*?)\s*\|\s*Severity:\s*(\w+)", re.I)
    findings, current = [], None
    for raw in _strip_ansi(output).splitlines():
        line = raw.strip()
        m = head.match(line)
        if m:
            current = {"process": m.group(1), "pid": int(m.group(2)),
                       "cmdline": m.group(3).strip(), "detections": [], "indicators": []}
            findings.append(current)
            continue
        m = det.match(line)
        if m and current is not None:
            d = {"thread": int(m.group(1)), "title": m.group(2), "detail": m.group(3),
                 "severity": m.group(4).lower()}
            current["detections"].append(d)
            current["indicators"].append(f"{d['title']}: {d['detail']} ({d['severity']})")
    for f in findings:
        sev = [d["severity"] for d in f["detections"]]
        f["severity"] = "high" if "high" in sev else "medium" if "mid" in sev or "medium" in sev else "low"
    return findings


def _parse_beaconeye_output(output):
    """Parse BeaconEye output.

    Format (BeaconEye.cs):
          <image> (<pid>), Keys Found:<bool>, Configuration Address: 0x<addr> [...]
              <Name>: <Value>        (one line per config item)
    """
    import re
    head = re.compile(r"^(.+?) \((\d+)\), Keys Found:(\w+), Configuration Address: (0x[0-9A-Fa-f]+)")
    findings, current = [], None
    for raw in _strip_ansi(output).splitlines():
        line = raw.strip()
        m = head.match(line)
        if m:
            current = {"process": m.group(1), "pid": int(m.group(2)),
                       "keys_found": m.group(3).lower() == "true",
                       "config_address": m.group(4), "config": {},
                       "summary": f"Cobalt Strike beacon config in {m.group(1)} ({m.group(2)}) at {m.group(4)}"}
            findings.append(current)
            continue
        if current is not None and raw.startswith("\t") and ": " in line:
            k, v = line.split(": ", 1)
            current["config"][k.strip()] = v.strip()
        elif not raw.startswith("\t"):
            current = None
    for f in findings:
        c2 = f["config"].get("C2Server")
        if c2:
            f["config"]["c2"] = c2
            f["summary"] += f", C2 {c2}"
    return findings


def _run_memory_scans_async(pid, sha256):
    """Run every live-memory tool against a detonated process, in background.

    Order matters: the read-only scanners go first so their view of the process
    is undisturbed, and Process Dump runs last because it writes files.
    """
    def _scan():
        import time as _time
        # Wait a few seconds for the beacon to initialize and enter sleep
        _time.sleep(5)

        # Beacon scanners (read-only, fast). Errors are stored too, so the
        # result view shows why a tool produced nothing.
        for tool, runner in (("hsb", _run_hsb), ("beaconeye", _run_beaconeye)):
            result, error = runner(pid)
            if result is None and error and "not installed" in error:
                continue
            _beacon_results_cache.put(tool, result or {"error": error}, pid=pid, sha256=sha256)

        # Aether: injection / implant structure scan of the live process.
        # Sampled three times so the evidence layer can tell a persistent
        # implant from memory that briefly looked odd.
        process_name = _image_name_for_pid(pid)
        if os.path.isfile(AETHER_EXE):
            try:
                aether_result, aether_error = _run_aether(
                    pid=pid, timeout=180, samples=3, interval=3,
                    process_name=process_name,
                )
                entry = aether_result or {"tool": "Aether", "error": aether_error}
                _beacon_results_cache.put("aether", entry, pid=pid, sha256=sha256)
                if aether_result:
                    _record_scan("Aether", f"PID {pid}", aether_result)
            except Exception as e:
                _beacon_results_cache.put("aether", {"tool": "Aether", "error": str(e)}, pid=pid, sha256=sha256)

        # Process Dump last: it writes files, and running it after the scanners
        # keeps their view of the process undisturbed. The clean-hash database
        # stays active, so the dump holds what is new on this box rather than
        # every module the process loaded.
        if os.path.isfile(PROCESSDUMP_EXE):
            try:
                dump_result, dump_error = _run_process_dump(
                    pid=pid, process_name=process_name, timeout=300
                )
                entry = dump_result or {"tool": "Process Dump", "error": dump_error}
                _beacon_results_cache.put("processdump", entry, pid=pid, sha256=sha256)
                if dump_result:
                    _record_scan("Process Dump", f"PID {pid}", dump_result)
            except Exception as e:
                _beacon_results_cache.put("processdump", {"tool": "Process Dump", "error": str(e)},
                                          pid=pid, sha256=sha256)

    thread = threading.Thread(target=_scan, daemon=True)
    thread.start()


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

# Upper bound for the file map visualizer: samples beyond this are plotted
# from their first 64 MB so one huge file cannot stall the UI thread.
VISUALIZE_MAX_BYTES = 64 * 1024 * 1024

# Recently computed file maps, keyed by path + mtime + size + grid parameters.
from collections import OrderedDict as _OrderedDict
_visualize_cache = _OrderedDict()
VISUALIZE_CACHE_SIZE = 12

# --- DiE-style Detection Signatures ---
# Compiler/Linker detection based on linker version and import patterns
PE_LINKER_SIGNATURES = {
    (14, 0): "Microsoft Visual C++ 2015-2022",
    (14, 16): "Microsoft Visual C++ 2019-2022",
    (14, 29): "Microsoft Visual C++ 2019-2022 (v16.x)",
    (14, 30): "Microsoft Visual C++ 2022 (v17.0+)",
    (14, 36): "Microsoft Visual C++ 2022 (v17.6+)",
    (12, 0): "Microsoft Visual C++ 2013",
    (11, 0): "Microsoft Visual C++ 2012",
    (10, 0): "Microsoft Visual C++ 2010",
    (9, 0): "Microsoft Visual C++ 2008",
    (8, 0): "Microsoft Visual C++ 2005",
    (7, 10): "Microsoft Visual C++ 2003",
    (7, 0): "Microsoft Visual C++ 2002",
    (6, 0): "Microsoft Visual C++ 6.0",
    (2, 25): "Borland Delphi / C++ Builder",
    (2, 56): "Borland Delphi 7+",
    (1, 71): "MinGW / GCC (Cygwin)",
    (2, 22): "MinGW-w64 / GCC",
    (2, 36): "MinGW-w64 / GCC 10+",
}

# Import-based compiler detection patterns
PE_COMPILER_IMPORT_PATTERNS = {
    "mscoree.dll": ("Language", ".NET CLR Assembly"),
    "msvbvm60.dll": ("Compiler", "Visual Basic 6.0"),
    "python3": ("Language", "Python (CPython)"),
    "python2": ("Language", "Python 2.x (CPython)"),
    "libgcc_s_dw2-1.dll": ("Compiler", "GCC (MinGW 32-bit)"),
    "libgcc_s_seh-1.dll": ("Compiler", "GCC (MinGW-w64)"),
    "libstdc++-6.dll": ("Compiler", "GCC (C++ Runtime)"),
    "go.buildid": ("Language", "Go (Golang)"),
    "cygwin1.dll": ("Compiler", "GCC (Cygwin)"),
    "vcruntime140.dll": ("Runtime", "MSVC 2015-2022 Runtime"),
    "vcruntime140d.dll": ("Runtime", "MSVC Debug Runtime"),
    "ucrtbased.dll": ("Runtime", "Universal CRT (Debug)"),
}

# Packer/Protector entry point heuristics
PE_EP_SECTION_DETECTORS = {
    "UPX1": "UPX (Ultimate Packer for Executables)",
    "UPX0": "UPX (Ultimate Packer for Executables)",
    ".aspack": "ASPack",
    ".adata": "ASPack",
    ".nsp0": "NsPack",
    ".themida": "Themida / WinLicense",
    ".vmp0": "VMProtect",
    ".vmp1": "VMProtect",
    ".enigma1": "Enigma Protector",
    "pec": "PECompact",
    ".mpress1": "MPRESS",
    ".petite": "Petite",
    ".packed": "Unknown Packer",
    ".RLPack": "RLPack",
}

# Byte signatures for common packers (at entry point or file offsets)
PE_PACKER_BYTE_SIGS = [
    # (offset_type, offset, bytes, name, version)
    ("ep", 0, b"\x60\xBE", "UPX", "0.89-3.x"),
    ("ep", 0, b"\xE9\x00\x00\x00\x00\x60", "UPX", "modified"),
    ("ep", 0, b"\x83\xEC\x04\x53\x55\x56\x57", "ASPack", "2.x"),
    ("ep", 0, b"\x90\x90\x90\x90\x68", "PECompact", "1.x"),
    ("ep", 0, b"\xB8\x00\x00\x00\x00\x60\x0B\xC0", "Petite", "2.x"),
    ("ep", 0, b"\xEB\x06\x68", "Themida", "2.x+"),
    ("ep", 0, b"\x68\x00\x00\x00\x00\xE8\x01\x00\x00\x00\xC3\xC3", "VMProtect", "2.x+"),
    ("ep", 0, b"\x55\x8B\xEC\x83\xC4", "Borland Delphi", "EP signature"),
    ("ep", 0, b"\x55\x8B\xEC\x6A\xFF\x68", "MSVC", "Standard EP"),
    ("ep", 0, b"\x48\x83\xEC\x28\xE8", "MSVC x64", "Standard EP"),
    ("file", 0, b"MZ", "PE", "DOS Header"),
]

# ELF compiler detection based on .comment section or build-id
ELF_COMPILER_PATTERNS = [
    (b"GCC:", "Compiler", "GCC"),
    (b"clang version", "Compiler", "LLVM/Clang"),
    (b"rustc", "Compiler", "Rust (rustc)"),
    (b"Go build", "Compiler", "Go (gc)"),
    (b"Free Pascal", "Compiler", "Free Pascal"),
    (b"Zig", "Compiler", "Zig"),
]


def calculate_entropy(data):
    """Calculate Shannon entropy of a byte sequence."""
    if not data:
        return 0.0
    # Counter tallies the bytes in C; the former per-byte Python loop was the
    # single largest cost when analyzing multi-MB samples.
    from collections import Counter
    length = len(data)
    entropy = 0.0
    for count in Counter(data).values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def calculate_entropy_map(data, num_blocks=64):
    """Calculate entropy for equal-sized blocks across the file (for visual heatmap)."""
    if not data or len(data) < num_blocks:
        return []
    block_size = len(data) // num_blocks
    entropy_map = []
    for i in range(num_blocks):
        start = i * block_size
        end = start + block_size if i < num_blocks - 1 else len(data)
        block = data[start:end]
        entropy_map.append(round(calculate_entropy(block), 3))
    return entropy_map


def detect_pe_characteristics(pe, file_data, sections_info):
    """
    DiE-style detection: identify compiler, linker, packer, protector, overlay.
    Returns a dict with detection results.
    """
    detections = []  # list of {type, name, version, confidence}
    assessment = "clean"  # clean, packed, encrypted, protected, suspicious

    # --- 1. Linker Version Detection ---
    oh = pe.OPTIONAL_HEADER
    linker_key = (oh.MajorLinkerVersion, oh.MinorLinkerVersion)
    linker_name = PE_LINKER_SIGNATURES.get(linker_key)
    if linker_name:
        detections.append({
            "type": "linker",
            "name": linker_name,
            "version": f"{oh.MajorLinkerVersion}.{oh.MinorLinkerVersion:02d}",
            "confidence": "high",
        })
    else:
        # Try range-based matching for MSVC
        if oh.MajorLinkerVersion == 14:
            detections.append({
                "type": "linker",
                "name": "Microsoft Visual C++ (2015+)",
                "version": f"{oh.MajorLinkerVersion}.{oh.MinorLinkerVersion:02d}",
                "confidence": "medium",
            })
        elif oh.MajorLinkerVersion >= 2 and oh.MajorLinkerVersion <= 6:
            detections.append({
                "type": "linker",
                "name": f"Unknown Linker v{oh.MajorLinkerVersion}.{oh.MinorLinkerVersion}",
                "version": f"{oh.MajorLinkerVersion}.{oh.MinorLinkerVersion:02d}",
                "confidence": "low",
            })

    # --- 2. Compiler/Language Detection via Imports ---
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_lower = entry.dll.decode("utf-8", errors="replace").lower()
            for pattern, (det_type, det_name) in PE_COMPILER_IMPORT_PATTERNS.items():
                if pattern.lower() in dll_lower:
                    detections.append({
                        "type": det_type.lower(),
                        "name": det_name,
                        "version": "",
                        "confidence": "high",
                    })
                    break

    # --- 3. .NET Detection ---
    has_dotnet = hasattr(pe, "DIRECTORY_ENTRY_COM_DESCRIPTOR")
    if not has_dotnet and hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        has_dotnet = any(b"mscoree.dll" in (e.dll or b"") for e in pe.DIRECTORY_ENTRY_IMPORT)
    if not has_dotnet:
        # Check CLR data directory (index 14) even if pefile didn't parse it
        try:
            clr_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
            if clr_dir.VirtualAddress > 0 and clr_dir.Size > 0:
                has_dotnet = True
        except (IndexError, AttributeError):
            pass
    if has_dotnet:
        detections.append({
            "type": "language",
            "name": ".NET Assembly (CLR)",
            "version": "",
            "confidence": "high",
        })

    # --- 4. Packer/Protector Detection ---
    packer_detected = False

    # 4a. Section name matching
    for sec_info in sections_info:
        sec_name = sec_info["name"]
        for packer_sec, packer_label in PE_EP_SECTION_DETECTORS.items():
            if sec_name.lower().startswith(packer_sec.lower()):
                detections.append({
                    "type": "packer",
                    "name": packer_label,
                    "version": f"Section: {sec_name}",
                    "confidence": "high",
                })
                packer_detected = True
                break

    # 4b. Entry point section analysis
    ep_offset = oh.AddressOfEntryPoint
    ep_section_name = ""
    for section in pe.sections:
        sec_start = section.VirtualAddress
        sec_end = sec_start + section.Misc_VirtualSize
        if sec_start <= ep_offset < sec_end:
            ep_section_name = section.Name.decode("utf-8", errors="replace").rstrip("\x00")
            break

    if ep_section_name and ep_section_name not in (".text", ".code", "CODE", ".init"):
        # Entry point in unusual section
        for packer_sec, packer_name in PE_EP_SECTION_DETECTORS.items():
            if ep_section_name.lower().startswith(packer_sec.lower()):
                if not any(d["type"] == "packer" and packer_name in d["name"] for d in detections):
                    detections.append({
                        "type": "packer",
                        "name": packer_name,
                        "version": f"EP in section: {ep_section_name}",
                        "confidence": "high",
                    })
                    packer_detected = True
                break

    # 4c. Entry point byte signature matching
    if ep_section_name:
        try:
            ep_file_offset = pe.get_offset_from_rva(ep_offset)
            if ep_file_offset and ep_file_offset < len(file_data) - 16:
                ep_bytes = file_data[ep_file_offset:ep_file_offset + 16]
                for (sig_type, sig_off, sig_bytes, sig_name, sig_ver) in PE_PACKER_BYTE_SIGS:
                    if sig_type == "ep" and ep_bytes[sig_off:sig_off + len(sig_bytes)] == sig_bytes:
                        # Don't duplicate MSVC standard EP if linker already detected
                        if "MSVC" in sig_name and any(d["type"] == "linker" and "Visual C" in d["name"] for d in detections):
                            continue
                        if not any(d["name"] == sig_name for d in detections):
                            detections.append({
                                "type": "packer" if sig_name not in ("MSVC", "MSVC x64", "Borland Delphi") else "compiler",
                                "name": sig_name,
                                "version": sig_ver,
                                "confidence": "medium",
                            })
                            if sig_name not in ("MSVC", "MSVC x64", "Borland Delphi", "PE"):
                                packer_detected = True
        except Exception:
            pass

    # --- 5. Entropy-based Packing/Encryption Detection ---
    high_entropy_sections = [s for s in sections_info if s["entropy"] >= ENTROPY_HIGH_THRESHOLD]
    total_raw = sum(s["raw_size"] for s in sections_info)
    high_entropy_raw = sum(s["raw_size"] for s in high_entropy_sections)

    if total_raw > 0 and high_entropy_raw / total_raw > 0.6:
        if not packer_detected:
            detections.append({
                "type": "packer",
                "name": "Unknown Packer/Crypter",
                "version": f"{len(high_entropy_sections)} section(s) with entropy > 7.0",
                "confidence": "medium",
            })
        assessment = "encrypted" if high_entropy_raw / total_raw > 0.8 else "packed"
    elif packer_detected:
        assessment = "packed"

    # --- 6. Overlay Detection ---
    overlay_offset = 0
    overlay_size = 0
    if pe.sections:
        last_section = max(pe.sections, key=lambda s: s.PointerToRawData + s.SizeOfRawData)
        last_end = last_section.PointerToRawData + last_section.SizeOfRawData
        if last_end < len(file_data):
            overlay_offset = last_end
            overlay_size = len(file_data) - last_end
            if overlay_size > 512:  # Significant overlay
                overlay_entropy = calculate_entropy(file_data[overlay_offset:overlay_offset + min(overlay_size, 65536)])
                detections.append({
                    "type": "overlay",
                    "name": "Data Overlay",
                    "version": f"{overlay_size} bytes, entropy {overlay_entropy:.2f}",
                    "confidence": "high",
                })
                if overlay_entropy >= ENTROPY_HIGH_THRESHOLD:
                    if assessment == "clean":
                        assessment = "suspicious"

    # --- 7. Anti-Debug / Protector Indicators ---
    has_tls = hasattr(pe, "DIRECTORY_ENTRY_TLS") and pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks != 0
    has_rwx = any(s.get("rwx_warning") for s in sections_info)
    has_no_imports = not hasattr(pe, "DIRECTORY_ENTRY_IMPORT") or len(pe.DIRECTORY_ENTRY_IMPORT) < 3

    if has_tls and (has_rwx or packer_detected):
        if not any(d["type"] == "protector" for d in detections):
            detections.append({
                "type": "protector",
                "name": "Anti-Debug Protection",
                "version": "TLS callbacks + suspicious characteristics",
                "confidence": "medium",
            })
        if assessment == "clean":
            assessment = "protected"

    if has_no_imports and packer_detected:
        assessment = "packed"

    # --- 8. Rich Header analysis (MSVC build tool versions) ---
    rich_header_info = None
    try:
        rich = pe.parse_rich_header()
        if rich and rich.get("values"):
            rich_entries = []
            values = rich["values"]
            # Values come in pairs: (compID, count), where compID = (prodID << 16 | buildID)
            for i in range(0, len(values) - 1, 2):
                comp_id = values[i]
                count = values[i + 1]
                prod_id = (comp_id >> 16) & 0xFFFF
                build_id = comp_id & 0xFFFF
                # Map known product IDs
                tool_names = {
                    0x01: "Import", 0x02: "Linker (old)", 0x04: "Linker",
                    0x06: "MASM", 0x07: "MASM (x64)",
                    0x0A: "C Compiler", 0x0B: "C++ Compiler",
                    0x0D: "Resource", 0x0F: "ASM (x64)",
                    0x5D: "C Compiler (x64)", 0x5E: "C++ Compiler (x64)",
                    0x93: "LTCG", 0x95: "C/C++ Compiler (new)",
                    0xFF: "Export", 0x100: "CVTRES",
                    0x101: "Linker (x64)", 0x103: "MASM (ARM)",
                    0x104: "C Compiler (ARM)", 0x105: "C++ Compiler (ARM)",
                    0xFD: "CVTRES (new)",
                }
                tool_name = tool_names.get(prod_id, f"Tool_{prod_id:04X}")
                rich_entries.append({
                    "tool": tool_name,
                    "id": prod_id,
                    "build": build_id,
                    "count": count,
                })
            rich_header_info = rich_entries[:30]  # Cap entries
    except Exception:
        pass

    # --- Build section layout for visualization ---
    section_layout = []
    file_size = len(file_data)
    for sec_info in sections_info:
        raw_offset = sec_info.get("raw_offset_dec", 0)
        raw_size = sec_info["raw_size"]
        if file_size > 0:
            section_layout.append({
                "name": sec_info["name"],
                "offset": raw_offset,
                "size": raw_size,
                "pct_start": round(raw_offset / file_size * 100, 2),
                "pct_size": round(raw_size / file_size * 100, 2),
                "entropy": sec_info["entropy"],
                "entropy_status": sec_info["entropy_status"],
                "executable": sec_info.get("executable", False),
                "writable": sec_info.get("writable", False),
                "packer": sec_info.get("packer_indicator", ""),
            })

    # Entropy map (64 blocks for heatmap visualization)
    entropy_map = calculate_entropy_map(file_data, 64)

    return {
        "detections": detections,
        "assessment": assessment,
        "ep_section": ep_section_name,
        "overlay": {"offset": overlay_offset, "size": overlay_size} if overlay_size > 0 else None,
        "rich_header": rich_header_info,
        "section_layout": section_layout,
        "entropy_map": entropy_map,
        "file_size": file_size,
    }


def detect_elf_characteristics(data, sections_info, security_info, has_pie, interpreter, needed_libs):
    """
    DiE-style detection for ELF: identify compiler, packer, protector.
    """
    detections = []
    assessment = "clean"

    # --- 1. Compiler Detection via .comment section ---
    # Search for .comment section content in raw data
    comment_content = b""
    for sec in sections_info:
        if sec.get("name") == ".comment" and sec.get("offset_dec", 0) > 0 and sec.get("size", 0) > 0:
            start = sec["offset_dec"]
            end = start + min(sec["size"], 4096)
            if end <= len(data):
                comment_content = data[start:end]
            break

    if comment_content:
        for pattern, det_type, det_name in ELF_COMPILER_PATTERNS:
            if pattern in comment_content:
                # Extract version string
                version = ""
                try:
                    idx = comment_content.index(pattern)
                    ver_str = comment_content[idx:idx + 80].decode("utf-8", errors="replace")
                    ver_str = ver_str.split("\x00")[0].strip()
                    version = ver_str
                except Exception:
                    pass
                detections.append({
                    "type": det_type.lower(),
                    "name": det_name,
                    "version": version,
                    "confidence": "high",
                })
                break

    # --- 2. Compiler detection via section names and patterns ---
    section_names = [s["name"] for s in sections_info]

    if ".gopclntab" in section_names or ".go.buildinfo" in section_names:
        if not any(d["name"] == "Go (gc)" for d in detections):
            detections.append({
                "type": "compiler",
                "name": "Go (gc)",
                "version": "Detected via .gopclntab/.go.buildinfo",
                "confidence": "high",
            })
    elif ".rustc" in section_names or any(".rodata" in s and s.get("size", 0) > 100000 for s in sections_info):
        # Rust binaries often have large .rodata
        # Check for rust-specific symbols or panic messages in data
        if b"rustc" in data[:65536] or b"panicked at" in data[:262144]:
            if not any("Rust" in d["name"] for d in detections):
                detections.append({
                    "type": "compiler",
                    "name": "Rust (rustc)",
                    "version": "Detected via binary patterns",
                    "confidence": "medium",
                })

    # --- 3. Interpreter/Linker Detection ---
    if interpreter:
        if "ld-linux" in interpreter or "ld.so" in interpreter:
            detections.append({
                "type": "linker",
                "name": "GNU ld (glibc dynamic linker)",
                "version": interpreter,
                "confidence": "high",
            })
        elif "ld-musl" in interpreter:
            detections.append({
                "type": "linker",
                "name": "musl libc linker",
                "version": interpreter,
                "confidence": "high",
            })
    elif not interpreter and not needed_libs:
        detections.append({
            "type": "linker",
            "name": "Static binary (no dynamic linker)",
            "version": "",
            "confidence": "high",
        })

    # --- 4. Packer Detection ---
    packer_detected = False
    for sec in sections_info:
        sec_name = sec.get("name", "")
        for packer_sec, packer_label in ELF_PACKER_SECTIONS.items():
            if sec_name.lower() == packer_sec.lower() or sec_name.lower().startswith(packer_sec.lower()):
                detections.append({
                    "type": "packer",
                    "name": packer_label,
                    "version": f"Section: {sec_name}",
                    "confidence": "high",
                })
                packer_detected = True
                break

    # UPX detection via magic bytes
    if b"UPX!" in data[:4096]:
        if not any("UPX" in d["name"] for d in detections):
            detections.append({
                "type": "packer",
                "name": "UPX (Ultimate Packer for Executables)",
                "version": "Magic 'UPX!' found",
                "confidence": "high",
            })
            packer_detected = True

    # --- 5. Entropy-based detection ---
    high_entropy_sections = [s for s in sections_info if s.get("entropy", 0) >= ENTROPY_HIGH_THRESHOLD and s.get("size", 0) > 1024]
    total_raw = sum(s.get("size", 0) for s in sections_info if s.get("size", 0) > 0)
    high_entropy_raw = sum(s.get("size", 0) for s in high_entropy_sections)

    if total_raw > 0 and high_entropy_raw / total_raw > 0.6:
        if not packer_detected:
            detections.append({
                "type": "packer",
                "name": "Unknown Packer/Crypter",
                "version": f"{len(high_entropy_sections)} section(s) with entropy > 7.0",
                "confidence": "medium",
            })
        assessment = "encrypted" if high_entropy_raw / total_raw > 0.8 else "packed"
    elif packer_detected:
        assessment = "packed"

    # --- 6. Protector indicators ---
    has_wx = any(s.get("wx_warning") for s in sections_info)
    has_anti_debug = any("ptrace" in s.get("name", "") or "anti" in s.get("name", "").lower() for s in sections_info)

    if has_wx and packer_detected:
        if not any(d["type"] == "protector" for d in detections):
            detections.append({
                "type": "protector",
                "name": "Self-modifying code / Protector",
                "version": "W+X sections with packer indicators",
                "confidence": "medium",
            })
        assessment = "protected"

    # --- 7. Section layout for visualization ---
    section_layout = []
    file_size = len(data)
    for sec in sections_info:
        offset = sec.get("offset_dec", 0)
        size = sec.get("size", 0)
        if file_size > 0 and size > 0:
            section_layout.append({
                "name": sec.get("name", ""),
                "offset": offset,
                "size": size,
                "pct_start": round(offset / file_size * 100, 2),
                "pct_size": round(size / file_size * 100, 2),
                "entropy": sec.get("entropy", 0),
                "entropy_status": sec.get("entropy_status", "normal"),
                "executable": "X" in sec.get("flags_str", ""),
                "writable": "W" in sec.get("flags_str", ""),
                "packer": sec.get("packer_indicator", ""),
            })

    entropy_map = calculate_entropy_map(data, 64)

    return {
        "detections": detections,
        "assessment": assessment,
        "section_layout": section_layout,
        "entropy_map": entropy_map,
        "file_size": file_size,
    }


def _quarantine_hint(path, base_msg):
    """Append a Defender-quarantine hint when an upload vanished or can't be read.

    Uploaded malware (e.g. mimikatz) staged under %TEMP%\\hex_uploads is deleted
    by Defender real-time protection unless that folder is excluded, which
    surfaces as 'File not found' or '[Errno 22]'. Point the user at the cause."""
    lowered = (path or "").lower()
    if "hex_uploads" in lowered:
        return (f"{base_msg}. The uploaded file appears to have been removed or locked by "
                f"Windows Defender. Exclude the upload folder (C:\\WINDOWS\\TEMP\\hex_uploads) "
                f"from Defender, or disable real-time monitoring, then re-upload the sample.")
    return base_msg


@app.route("/api/file/pe")
def api_file_pe():
    """Parse PE header and return structured analysis with IOC indicators."""
    filepath = request.args.get("path", "")
    if not filepath:
        return jsonify({"error": "No path specified"}), 400

    norm_path = os.path.normpath(filepath)
    if not os.path.isfile(norm_path):
        return jsonify({"error": _quarantine_hint(norm_path, "File not found")}), 404

    try:
        import pefile
    except ImportError:
        return jsonify({"error": "pefile module not installed"}), 500

    try:
        # Read the bytes ourselves and hand them to pefile via data= rather than
        # letting pefile mmap the path. mmap fails with [Errno 22] on Windows when
        # the file is locked (e.g. AV scanning a sample in TEMP), and reading the
        # bytes also avoids holding a file handle open on the sample.
        with open(norm_path, "rb") as f:
            pe_bytes = f.read()
        pe = pefile.PE(data=pe_bytes, fast_load=False)
    except pefile.PEFormatError as e:
        return jsonify({"error": f"Not a valid PE file: {e}"}), 400
    except (IOError, OSError) as e:
        return jsonify({"error": _quarantine_hint(norm_path, f"Unable to read file: {e}")}), 500
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
    # Reuse the bytes already read for pefile: a second open() here doubled
    # the I/O and left the handle open (the AV-lock issue noted above).
    file_data = pe_bytes
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
            "raw_offset_dec": section.PointerToRawData,
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
            # The callback array holds pointers: 8 bytes in PE32+. Reading
            # DWORDs there interleaved the halves and stopped at the first
            # zero high half.
            is64 = pe.OPTIONAL_HEADER.Magic == 0x20B
            stride = 8 if is64 else 4
            read_ptr = pe.get_qword_at_rva if is64 else pe.get_dword_at_rva
            try:
                idx = 0
                while True:
                    cb_addr = read_ptr(callback_rva + idx * stride)
                    if not cb_addr:
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
            sev = "high" if cat in ("process_injection", "process_hollowing", "credential_access") else "medium"
            evidence = {
                "matched_apis": [f"{i['dll']}!{i['function']}" for i in items],
                "why": f"Imports from category '{cat}' are commonly used in malicious techniques ({cat.replace('_', ' ')})",
                "reference_apis": SUSPICIOUS_IMPORTS.get(cat, []),
            }
            flags.append({"type": "suspicious_import", "category": cat, "severity": sev, "detail": f"{len(items)} suspicious API(s) in category '{cat}'", "evidence": evidence})
    for sec in sections:
        if sec.get("rwx_warning"):
            flags.append({"type": "rwx_section", "severity": "high", "detail": f"Section '{sec['name']}' is Read+Write+Execute", "evidence": {"section": sec["name"], "permissions": sec.get("permissions", "RWX"), "why": "Sections with Read+Write+Execute permissions allow self-modifying code, a hallmark of shellcode and packers"}})
        if sec["entropy_status"] == "high":
            flags.append({"type": "high_entropy", "severity": "medium", "detail": f"Section '{sec['name']}' entropy {sec['entropy']:.2f} (encrypted/packed)", "evidence": {"section": sec["name"], "entropy": sec["entropy"], "threshold": ENTROPY_HIGH_THRESHOLD, "why": f"Entropy {sec['entropy']:.2f} exceeds threshold {ENTROPY_HIGH_THRESHOLD} indicating compressed, encrypted, or packed content"}})
        if sec.get("packer_indicator"):
            flags.append({"type": "packer", "severity": "medium", "detail": f"Section '{sec['name']}' matches packer: {sec['packer_indicator']}", "evidence": {"section": sec["name"], "packer": sec["packer_indicator"], "why": f"Section name matches known packer/protector signature: {sec['packer_indicator']}"}})
    if tls_callbacks:
        flags.append({"type": "tls_callback", "severity": "medium", "detail": f"{len(tls_callbacks)} TLS callback(s) detected (possible anti-debug)", "evidence": {"callbacks": tls_callbacks, "why": "TLS callbacks execute before the entry point and are commonly used for anti-debugging or to run code before analysis tools attach"}})
    if not result["optional_header"]["aslr"]:
        flags.append({"type": "no_aslr", "severity": "low", "detail": "ASLR not enabled", "evidence": {"why": "Address Space Layout Randomization is disabled, making ROP/exploit development easier"}})
    if not result["optional_header"]["dep_nx"]:
        flags.append({"type": "no_dep", "severity": "low", "detail": "DEP/NX not enabled", "evidence": {"why": "Data Execution Prevention is disabled, allowing shellcode execution from data segments"}})
    if total_entropy >= ENTROPY_HIGH_THRESHOLD:
        flags.append({"type": "high_total_entropy", "severity": "medium", "detail": f"Overall file entropy {total_entropy:.2f} suggests packing/encryption", "evidence": {"entropy": total_entropy, "threshold": ENTROPY_HIGH_THRESHOLD, "why": f"Whole-file entropy {total_entropy:.2f} exceeds {ENTROPY_HIGH_THRESHOLD}, typical of packed/encrypted executables (normal code is 5.0-6.5)"}})

    result["flags"] = flags
    result["flag_count"] = {"high": len([f for f in flags if f["severity"] == "high"]), "medium": len([f for f in flags if f["severity"] == "medium"]), "low": len([f for f in flags if f["severity"] == "low"])}

    # --- DiE-style Detection Analysis ---
    try:
        detection_result = detect_pe_characteristics(pe, file_data, sections)
        result["detection"] = detection_result
    except Exception as e:
        result["detection"] = {"detections": [], "assessment": "clean", "error": str(e),
                               "entropy_map": [], "section_layout": [], "file_size": len(file_data)}

    pe.close()
    return jsonify(result)


def _parse_cert_subject(dn):
    """Pull a human-friendly name out of an X.500 DN string.
    Returns the CN if present, else the O, else the raw DN."""
    if not dn:
        return ""
    fields = {}
    # DNs look like "CN=Microsoft Corporation, O=Microsoft Corporation, C=US".
    for part in dn.split(","):
        if "=" in part:
            k, _, v = part.partition("=")
            fields.setdefault(k.strip().upper(), v.strip())
    return fields.get("CN") or fields.get("O") or dn.strip()


def _pe_embedded_signature(pe):
    """Report whether the PE carries an embedded Authenticode signature
    (the IMAGE_DIRECTORY_ENTRY_SECURITY / certificate table)."""
    import pefile
    try:
        idx = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[idx]
        return {
            "has_embedded": bool(sec_dir.VirtualAddress and sec_dir.Size),
            "offset": hex(sec_dir.VirtualAddress) if sec_dir.VirtualAddress else None,
            "size": sec_dir.Size,
        }
    except Exception:
        return {"has_embedded": False, "offset": None, "size": 0}


def _authenticode_verify(norm_path):
    """Run Get-AuthenticodeSignature to determine the signer and trust status.
    Windows-only; returns None when PowerShell is unavailable (e.g. dev on macOS)."""
    escaped = norm_path.replace("'", "''")
    # Force UTF-8 output: Get-AuthenticodeSignature's StatusMessage is localized
    # (e.g. German "Signatur wurde überprüft.") and non-ASCII bytes crash the
    # subprocess reader thread under text=True, yielding empty stdout. We capture
    # bytes and decode with errors='replace' below. Also silence the progress stream.
    ps_cmd = (
        "$OutputEncoding=[Text.Encoding]::UTF8;"
        "[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
        "$ProgressPreference='SilentlyContinue';"
        f"$s = Get-AuthenticodeSignature -LiteralPath '{escaped}';"
        "$o = [ordered]@{ status = $s.Status.ToString(); status_message = $s.StatusMessage };"
        "if ($s.SignerCertificate) { $c = $s.SignerCertificate;"
        "  $o.signer_subject = $c.Subject; $o.signer_issuer = $c.Issuer;"
        "  $o.signer_thumbprint = $c.Thumbprint; $o.signer_serial = $c.SerialNumber;"
        "  $o.not_before = $c.NotBefore.ToString('o'); $o.not_after = $c.NotAfter.ToString('o') };"
        "if ($s.TimeStamperCertificate) { $t = $s.TimeStamperCertificate;"
        "  $o.timestamp_subject = $t.Subject; $o.timestamp_thumbprint = $t.Thumbprint };"
        "[PSCustomObject]$o | ConvertTo-Json -Compress"
    )
    try:
        # Capture bytes (not text=True) and decode ourselves with errors='replace'
        # so localized non-ASCII output can't crash the reader thread.
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, timeout=25,
        )
    except (FileNotFoundError, OSError):
        return None  # No PowerShell here (non-Windows host).
    except subprocess.TimeoutExpired:
        return {"status": "UnknownError", "status_message": "Signature verification timed out"}
    out = (result.stdout or b"").decode("utf-8", errors="replace").strip()
    if not out:
        err = (result.stderr or b"").decode("utf-8", errors="replace").strip()
        return {"status": "UnknownError",
                "status_message": err or "No output from Get-AuthenticodeSignature"}
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return {"status": "UnknownError", "status_message": "Unparseable signature output"}


@app.route("/api/file/signature")
def api_file_signature():
    """Report who signed a file (Authenticode) and whether the signature is trusted.

    Combines the embedded certificate-table check (cross-platform, via pefile)
    with Windows' Get-AuthenticodeSignature for signer identity + trust status
    (which also covers catalog-signed OS binaries with no embedded signature).
    """
    filepath = request.args.get("path", "")
    if not filepath:
        return jsonify({"error": "No path specified"}), 400

    norm_path = os.path.normpath(filepath)
    if not os.path.isfile(norm_path):
        return jsonify({"error": _quarantine_hint(norm_path, "File not found")}), 404

    try:
        import pefile  # noqa: F401  (module-level alias used by helpers)
    except ImportError:
        return jsonify({"error": "pefile module not installed"}), 500

    result = {"path": filepath}

    # 1. Embedded certificate table (works anywhere). Non-fatal for non-PE files —
    # Get-AuthenticodeSignature still works for scripts, MSI, catalog-signed files.
    try:
        with open(norm_path, "rb") as f:
            pe_bytes = f.read()
        pe = pefile.PE(data=pe_bytes, fast_load=True)
        result["embedded"] = _pe_embedded_signature(pe)
        pe.close()
    except pefile.PEFormatError:
        result["embedded"] = {"has_embedded": False, "offset": None, "size": 0, "not_pe": True}
    except (IOError, OSError) as e:
        return jsonify({"error": _quarantine_hint(norm_path, f"Unable to read file: {e}")}), 500
    except Exception as e:
        result["embedded"] = {"has_embedded": False, "offset": None, "size": 0, "error": str(e)}

    # 2. Authenticode signer + trust status (Windows only).
    auth = _authenticode_verify(norm_path)
    if auth is None:
        # No PowerShell: fall back to the embedded-table indicator alone.
        has = result["embedded"]["has_embedded"]
        result["signed"] = has
        result["status"] = "EmbeddedSignaturePresent" if has else "NotSigned"
        result["verification_available"] = False
        result["note"] = ("Signer identity and trust could not be verified here "
                           "(PowerShell/Get-AuthenticodeSignature unavailable on this host). "
                           "Run the analysis on the Windows VM for full signer details.")
        return jsonify(result)

    status = auth.get("status", "UnknownError")
    result["verification_available"] = True
    result["status"] = status
    result["status_message"] = auth.get("status_message", "")
    result["signed"] = status not in ("NotSigned", "NotSupportedFileFormat")
    result["trusted"] = status == "Valid"

    if auth.get("signer_subject"):
        result["signer"] = {
            "name": _parse_cert_subject(auth.get("signer_subject")),
            "subject": auth.get("signer_subject"),
            "issuer": auth.get("signer_issuer", ""),
            "issuer_name": _parse_cert_subject(auth.get("signer_issuer", "")),
            "thumbprint": auth.get("signer_thumbprint", ""),
            "serial": auth.get("signer_serial", ""),
            "valid_from": auth.get("not_before", ""),
            "valid_to": auth.get("not_after", ""),
        }
    if auth.get("timestamp_subject"):
        result["timestamp"] = {
            "name": _parse_cert_subject(auth.get("timestamp_subject")),
            "subject": auth.get("timestamp_subject"),
            "thumbprint": auth.get("timestamp_thumbprint", ""),
        }

    return jsonify(result)


@app.route("/api/file/pe/section")
def api_file_pe_section():
    """Return detailed data for a specific PE section including hex dump and strings."""
    filepath = request.args.get("path", "")
    section_idx = request.args.get("index", type=int)
    max_bytes = max(1, min(request.args.get("max_bytes", 4096, type=int) or 4096, 16 * 1024 * 1024))

    if not filepath:
        return jsonify({"error": "No path specified"}), 400
    if section_idx is None:
        return jsonify({"error": "No section index specified"}), 400

    norm_path = os.path.normpath(filepath)
    if not os.path.isfile(norm_path):
        return jsonify({"error": _quarantine_hint(norm_path, "File not found")}), 404

    try:
        import pefile
    except ImportError:
        return jsonify({"error": "pefile module not installed"}), 500

    try:
        # See api_file_pe: read bytes and pass via data= to avoid mmap [Errno 22]
        # on Windows when the sample file is locked by AV.
        with open(norm_path, "rb") as f:
            pe_bytes = f.read()
        pe = pefile.PE(data=pe_bytes, fast_load=False)
    except pefile.PEFormatError as e:
        return jsonify({"error": f"Not a valid PE file: {e}"}), 400
    except (IOError, OSError) as e:
        return jsonify({"error": _quarantine_hint(norm_path, f"Unable to read file: {e}")}), 500
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


# --- ELF Analysis ---

# Suspicious ELF symbols/function imports (similar to PE suspicious imports)
SUSPICIOUS_ELF_IMPORTS = {
    "process_injection": ["ptrace", "process_vm_writev", "process_vm_readv", "__libc_dlopen_mode"],
    "code_execution": ["mprotect", "mmap", "execve", "execvp", "execl", "system", "popen", "dlopen", "dlsym"],
    "anti_debug": ["ptrace", "prctl", "getppid", "kill"],
    "networking": ["socket", "connect", "bind", "listen", "accept", "send", "recv", "sendto", "recvfrom", "getaddrinfo"],
    "file_operations": ["unlink", "rename", "chmod", "chown", "fchmod", "link", "symlink", "mount"],
    "privilege_escalation": ["setuid", "setgid", "seteuid", "setreuid", "setregid", "capset"],
    "crypto": ["EVP_EncryptInit", "EVP_DecryptInit", "AES_encrypt", "AES_decrypt", "RSA_public_encrypt", "RC4"],
    "evasion": ["fork", "daemon", "setsid", "dup2", "memfd_create", "fexecve"],
}

# Known ELF section names indicating packers/protectors
ELF_PACKER_SECTIONS = {
    "upx": "UPX",
    ".upx": "UPX",
    "UPX!": "UPX",
    ".themida": "Themida",
    ".enigma": "Enigma Protector",
    ".vmprotect": "VMProtect",
    ".packed": "Generic Packer",
    ".crypted": "Encrypted/Packed",
}


@app.route("/api/file/elf")
def api_file_elf():
    """Parse ELF header and return structured analysis with IOC indicators."""
    filepath = request.args.get("path", "")
    if not filepath:
        return jsonify({"error": "No path specified"}), 400

    norm_path = os.path.normpath(filepath)
    if not os.path.isfile(norm_path):
        return jsonify({"error": "File not found"}), 404

    try:
        with open(norm_path, "rb") as f:
            data = f.read()
    except Exception as e:
        return jsonify({"error": f"Cannot read file: {e}"}), 500

    # Verify ELF magic
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return jsonify({"error": "Not a valid ELF file (missing \\x7fELF magic)"}), 400

    result = {"valid": True, "path": filepath, "file_size": len(data)}

    # --- ELF Identification (e_ident) ---
    ei_class = data[4]  # 1=32bit, 2=64bit
    ei_data = data[5]   # 1=little-endian, 2=big-endian
    ei_version = data[6]
    ei_osabi = data[7]

    is_64 = ei_class == 2
    is_le = ei_data == 1
    endian = "<" if is_le else ">"

    class_map = {1: "ELF32", 2: "ELF64"}
    data_map = {1: "Little-endian (LSB)", 2: "Big-endian (MSB)"}
    osabi_map = {
        0: "UNIX System V", 1: "HP-UX", 2: "NetBSD", 3: "Linux",
        6: "Solaris", 7: "AIX", 8: "IRIX", 9: "FreeBSD",
        10: "Tru64", 11: "Novell Modesto", 12: "OpenBSD",
        64: "ARM EABI", 97: "ARM", 255: "Standalone"
    }

    result["ident"] = {
        "class": class_map.get(ei_class, f"Unknown ({ei_class})"),
        "is_64bit": is_64,
        "data": data_map.get(ei_data, f"Unknown ({ei_data})"),
        "is_little_endian": is_le,
        "version": ei_version,
        "osabi": osabi_map.get(ei_osabi, f"Unknown ({ei_osabi})"),
        "osabi_raw": ei_osabi,
    }

    # --- ELF Header ---
    type_map = {0: "NONE", 1: "REL (Relocatable)", 2: "EXEC (Executable)", 3: "DYN (Shared Object/PIE)", 4: "CORE"}
    machine_map = {
        0: "None", 2: "SPARC", 3: "x86 (i386)", 6: "Intel 80486",
        8: "MIPS", 20: "PowerPC", 21: "PowerPC64", 22: "S390",
        40: "ARM", 43: "SPARC V9", 50: "IA-64", 62: "x86-64 (AMD64)",
        183: "AArch64 (ARM64)", 243: "RISC-V", 247: "eBPF",
    }

    if is_64:
        if len(data) < 64:
            return jsonify({"error": "File too small for ELF64 header"}), 400
        # ELF64 header: e_type(2) e_machine(2) e_version(4) e_entry(8) e_phoff(8) e_shoff(8) e_flags(4) e_ehsize(2) e_phentsize(2) e_phnum(2) e_shentsize(2) e_shnum(2) e_shstrndx(2)
        hdr = struct.unpack(f"{endian}HHI QQQ I HHHHHH", data[16:64])
        e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = hdr
    else:
        if len(data) < 52:
            return jsonify({"error": "File too small for ELF32 header"}), 400
        # ELF32 header
        hdr = struct.unpack(f"{endian}HHI III I HHHHHH", data[16:52])
        e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = hdr

    result["header"] = {
        "type": type_map.get(e_type, f"Unknown ({e_type})"),
        "type_raw": e_type,
        "machine": machine_map.get(e_machine, f"Unknown ({e_machine})"),
        "machine_raw": e_machine,
        "version": e_version,
        "entry_point": hex(e_entry),
        "program_header_offset": e_phoff,
        "section_header_offset": e_shoff,
        "flags": hex(e_flags),
        "header_size": e_ehsize,
        "ph_entry_size": e_phentsize,
        "ph_count": e_phnum,
        "sh_entry_size": e_shentsize,
        "sh_count": e_shnum,
        "sh_str_index": e_shstrndx,
        "is_executable": e_type == 2,
        "is_shared_object": e_type == 3,
        "is_pie": e_type == 3,  # DYN with entry point often means PIE
        "is_relocatable": e_type == 1,
    }

    # --- Security Features ---
    has_pie = e_type == 3
    has_nx = False  # Will check PT_GNU_STACK
    has_relro = False
    has_full_relro = False
    has_stack_canary = False  # Will check symbols
    has_fortify = False  # Will check symbols
    is_stripped = True  # Assume stripped unless we find .symtab

    # --- Section Headers ---
    sections = []
    shstrtab_data = b""

    # Read section header string table first
    if e_shstrndx < e_shnum and e_shoff > 0:
        if is_64:
            str_sec_offset = e_shoff + e_shstrndx * e_shentsize
            if str_sec_offset + e_shentsize <= len(data):
                sh_entry = struct.unpack(f"{endian}IIQQQQIIQQ", data[str_sec_offset:str_sec_offset + 64])
                shstrtab_offset = sh_entry[4]  # sh_offset
                shstrtab_size = sh_entry[5]    # sh_size
                if shstrtab_offset + shstrtab_size <= len(data):
                    shstrtab_data = data[shstrtab_offset:shstrtab_offset + shstrtab_size]
        else:
            str_sec_offset = e_shoff + e_shstrndx * e_shentsize
            if str_sec_offset + e_shentsize <= len(data):
                sh_entry = struct.unpack(f"{endian}IIIIIIIIII", data[str_sec_offset:str_sec_offset + 40])
                shstrtab_offset = sh_entry[4]
                shstrtab_size = sh_entry[5]
                if shstrtab_offset + shstrtab_size <= len(data):
                    shstrtab_data = data[shstrtab_offset:shstrtab_offset + shstrtab_size]

    def get_shstr(offset):
        """Get null-terminated string from section header string table."""
        if offset >= len(shstrtab_data):
            return ""
        end = shstrtab_data.find(b"\x00", offset)
        if end == -1:
            end = min(offset + 64, len(shstrtab_data))
        return shstrtab_data[offset:end].decode("utf-8", errors="replace")

    # Section type map
    sh_type_map = {
        0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA",
        5: "HASH", 6: "DYNAMIC", 7: "NOTE", 8: "NOBITS", 9: "REL",
        10: "SHLIB", 11: "DYNSYM", 14: "INIT_ARRAY", 15: "FINI_ARRAY",
        0x6ffffff6: "GNU_HASH", 0x6ffffffd: "VERDEF", 0x6ffffffe: "VERNEED",
        0x6fffffff: "VERSYM",
    }

    total_entropy = calculate_entropy(data)
    result["total_entropy"] = total_entropy

    for i in range(e_shnum):
        offset = e_shoff + i * e_shentsize
        if offset + e_shentsize > len(data):
            break

        if is_64:
            sh = struct.unpack(f"{endian}IIQQQQIIQQ", data[offset:offset + 64])
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = sh
        else:
            sh = struct.unpack(f"{endian}IIIIIIIIII", data[offset:offset + 40])
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = sh

        sec_name = get_shstr(sh_name)

        # Calculate entropy for this section
        sec_entropy = 0.0
        if sh_type != 8 and sh_size > 0 and sh_offset + sh_size <= len(data):  # Not NOBITS
            sec_data_bytes = data[sh_offset:sh_offset + sh_size]
            sec_entropy = calculate_entropy(sec_data_bytes)

        sec_info = {
            "index": i,
            "name": sec_name,
            "type": sh_type_map.get(sh_type, f"0x{sh_type:x}"),
            "type_raw": sh_type,
            "flags": sh_flags,
            "flags_str": _elf_section_flags_str(sh_flags),
            "address": hex(sh_addr),
            "offset": hex(sh_offset),
            "offset_dec": sh_offset,
            "size": sh_size,
            "link": sh_link,
            "info": sh_info,
            "alignment": sh_addralign,
            "entry_size": sh_entsize,
            "entropy": sec_entropy,
            "entropy_status": "high" if sec_entropy >= ENTROPY_HIGH_THRESHOLD else "warn" if sec_entropy >= ENTROPY_WARN_THRESHOLD else "normal",
            "executable": bool(sh_flags & 0x4),
            "writable": bool(sh_flags & 0x1),
            "allocatable": bool(sh_flags & 0x2),
        }

        # Check for packer indicators
        for packer_name, packer_label in ELF_PACKER_SECTIONS.items():
            if sec_name.lower().startswith(packer_name.lower()):
                sec_info["packer_indicator"] = packer_label
                break

        # Flag WX (writable + executable) sections
        if sec_info["executable"] and sec_info["writable"]:
            sec_info["wx_warning"] = True

        # Check if .symtab exists (means not fully stripped)
        if sec_name == ".symtab":
            is_stripped = False

        sections.append(sec_info)

    result["sections"] = sections
    result["is_stripped"] = is_stripped

    # --- Program Headers (Segments) ---
    segments = []
    pt_type_map = {
        0: "NULL", 1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 4: "NOTE",
        5: "SHLIB", 6: "PHDR", 7: "TLS",
        0x6474e550: "GNU_EH_FRAME", 0x6474e551: "GNU_STACK",
        0x6474e552: "GNU_RELRO", 0x6474e553: "GNU_PROPERTY",
    }

    for i in range(e_phnum):
        offset = e_phoff + i * e_phentsize
        if offset + e_phentsize > len(data):
            break

        if is_64:
            ph = struct.unpack(f"{endian}IIQQQQQQ", data[offset:offset + 56])
            p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = ph
        else:
            ph = struct.unpack(f"{endian}IIIIIIII", data[offset:offset + 32])
            p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = ph

        seg_info = {
            "index": i,
            "type": pt_type_map.get(p_type, f"0x{p_type:x}"),
            "type_raw": p_type,
            "flags": p_flags,
            "flags_str": _elf_segment_flags_str(p_flags),
            "offset": hex(p_offset),
            "vaddr": hex(p_vaddr),
            "paddr": hex(p_paddr),
            "filesz": p_filesz,
            "memsz": p_memsz,
            "align": p_align,
            "readable": bool(p_flags & 4),
            "writable": bool(p_flags & 2),
            "executable": bool(p_flags & 1),
        }

        # Check security features
        if p_type == 0x6474e551:  # GNU_STACK
            if not (p_flags & 1):  # Not executable
                has_nx = True
            seg_info["security_note"] = "NX stack" if not (p_flags & 1) else "Executable stack (no NX!)"

        if p_type == 0x6474e552:  # GNU_RELRO
            has_relro = True
            seg_info["security_note"] = "RELRO (read-only relocations)"

        # Extract interpreter path
        if p_type == 3 and p_filesz > 0 and p_offset + p_filesz <= len(data):  # PT_INTERP
            interp = data[p_offset:p_offset + p_filesz].rstrip(b"\x00").decode("utf-8", errors="replace")
            seg_info["interpreter"] = interp
            result["interpreter"] = interp

        segments.append(seg_info)

    result["segments"] = segments

    # --- Dynamic Section (imports, needed libraries) ---
    dynamic_entries = []
    needed_libs = []
    soname = None
    rpath = None
    runpath = None
    dynamic_strtab_offset = 0
    dynamic_strtab_size = 0

    # Find .dynstr section for resolving dynamic string table
    dynstr_data = b""
    for sec in sections:
        if sec["name"] == ".dynstr" and sec["offset_dec"] + sec["size"] <= len(data):
            dynstr_data = data[sec["offset_dec"]:sec["offset_dec"] + sec["size"]]
            break

    def get_dynstr(offset):
        if offset >= len(dynstr_data):
            return ""
        end = dynstr_data.find(b"\x00", offset)
        if end == -1:
            end = min(offset + 256, len(dynstr_data))
        return dynstr_data[offset:end].decode("utf-8", errors="replace")

    # Find and parse .dynamic section
    for sec in sections:
        if sec["name"] == ".dynamic" and sec["offset_dec"] + sec["size"] <= len(data):
            dyn_offset = sec["offset_dec"]
            dyn_size = sec["size"]
            entry_size = 16 if is_64 else 8

            dt_tag_map = {
                0: "NULL", 1: "NEEDED", 2: "PLTRELSZ", 3: "PLTGOT", 4: "HASH",
                5: "STRTAB", 6: "SYMTAB", 7: "RELA", 8: "RELASZ", 9: "RELAENT",
                10: "STRSZ", 11: "SYMENT", 12: "INIT", 13: "FINI", 14: "SONAME",
                15: "RPATH", 16: "SYMBOLIC", 17: "REL", 20: "PLTREL", 21: "DEBUG",
                23: "JMPREL", 24: "BIND_NOW", 25: "INIT_ARRAY", 26: "FINI_ARRAY",
                29: "RUNPATH", 30: "FLAGS", 0x6ffffffb: "FLAGS_1",
                0x6ffffff0: "VERSYM", 0x6ffffffe: "VERNEED", 0x6fffffff: "VERNEEDNUM",
            }

            i = 0
            while i < dyn_size:
                if is_64:
                    if dyn_offset + i + 16 > len(data):
                        break
                    d_tag, d_val = struct.unpack(f"{endian}qQ", data[dyn_offset + i:dyn_offset + i + 16])
                else:
                    if dyn_offset + i + 8 > len(data):
                        break
                    d_tag, d_val = struct.unpack(f"{endian}iI", data[dyn_offset + i:dyn_offset + i + 8])

                if d_tag == 0:  # DT_NULL
                    break

                tag_name = dt_tag_map.get(d_tag, f"0x{d_tag:x}")

                if d_tag == 1:  # DT_NEEDED
                    lib = get_dynstr(d_val)
                    needed_libs.append(lib)
                elif d_tag == 14:  # DT_SONAME
                    soname = get_dynstr(d_val)
                elif d_tag == 15:  # DT_RPATH
                    rpath = get_dynstr(d_val)
                elif d_tag == 29:  # DT_RUNPATH
                    runpath = get_dynstr(d_val)
                elif d_tag == 24:  # DT_BIND_NOW
                    has_full_relro = has_relro  # RELRO + BIND_NOW = Full RELRO
                elif d_tag == 0x6ffffffb:  # DT_FLAGS_1
                    if d_val & 0x1:  # DF_1_NOW
                        has_full_relro = has_relro

                i += entry_size
            break

    result["needed_libraries"] = needed_libs
    result["soname"] = soname
    result["rpath"] = rpath
    result["runpath"] = runpath

    # --- Symbol Analysis (from .dynsym) ---
    imported_symbols = []
    exported_symbols = []
    dynsym_data = b""
    dynsym_entsize = 24 if is_64 else 16

    for sec in sections:
        if sec["name"] == ".dynsym" and sec["offset_dec"] + sec["size"] <= len(data):
            dynsym_data = data[sec["offset_dec"]:sec["offset_dec"] + sec["size"]]
            break

    if dynsym_data:
        num_syms = len(dynsym_data) // dynsym_entsize
        for i in range(1, min(num_syms, 2000)):  # Skip index 0, cap at 2000
            sym_offset = i * dynsym_entsize
            if is_64:
                st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack(
                    f"{endian}IBBHQQ", dynsym_data[sym_offset:sym_offset + 24]
                )
            else:
                st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack(
                    f"{endian}IIIBBH", dynsym_data[sym_offset:sym_offset + 16]
                )

            sym_name = get_dynstr(st_name)
            if not sym_name:
                continue

            st_bind = st_info >> 4
            st_type = st_info & 0xf

            sym_entry = {
                "name": sym_name,
                "bind": ["LOCAL", "GLOBAL", "WEAK"][st_bind] if st_bind < 3 else f"OTHER({st_bind})",
                "type": ["NOTYPE", "OBJECT", "FUNC", "SECTION", "FILE"][st_type] if st_type < 5 else f"OTHER({st_type})",
                "value": hex(st_value),
                "size": st_size,
                "shndx": st_shndx,
            }

            if st_shndx == 0:  # UND - imported
                imported_symbols.append(sym_entry)
            else:
                exported_symbols.append(sym_entry)

            # Check for stack canary / fortify
            if sym_name == "__stack_chk_fail" or sym_name == "__stack_chk_guard":
                has_stack_canary = True
            if "__fortify" in sym_name.lower() or sym_name.endswith("_chk"):
                has_fortify = True

    result["imported_symbols"] = imported_symbols[:500]
    result["exported_symbols"] = exported_symbols[:500]
    result["import_count"] = len(imported_symbols)
    result["export_count"] = len(exported_symbols)

    # --- Suspicious Import Detection ---
    suspicious_found = {}
    for sym in imported_symbols:
        for category, api_list in SUSPICIOUS_ELF_IMPORTS.items():
            if sym["name"] in api_list:
                if category not in suspicious_found:
                    suspicious_found[category] = []
                suspicious_found[category].append(sym["name"])
    result["suspicious_imports"] = suspicious_found

    # --- Security Summary ---
    result["security"] = {
        "pie": has_pie,
        "nx": has_nx,
        "relro": "Full" if has_full_relro else ("Partial" if has_relro else "None"),
        "stack_canary": has_stack_canary,
        "fortify": has_fortify,
        "stripped": is_stripped,
    }

    # --- IOC Flags ---
    flags = []

    if not has_nx:
        flags.append({"type": "no_nx", "severity": "high", "detail": "NX (non-executable stack) not enabled — stack is executable", "evidence": {"why": "Without NX, the stack is executable — shellcode placed on the stack via buffer overflows can run directly"}})
    if not has_pie:
        flags.append({"type": "no_pie", "severity": "medium", "detail": "Not a position-independent executable (no ASLR for main binary)", "evidence": {"why": "Without PIE, the main binary loads at a fixed address, making ROP gadgets and return-to-libc attacks trivial"}})
    if not has_relro:
        flags.append({"type": "no_relro", "severity": "medium", "detail": "No RELRO — GOT is writable (GOT overwrite attacks possible)", "evidence": {"why": "The Global Offset Table remains writable at runtime, allowing attackers to redirect function calls by overwriting GOT entries"}})
    elif not has_full_relro:
        flags.append({"type": "partial_relro", "severity": "low", "detail": "Partial RELRO — GOT partially protected", "evidence": {"why": "GOT is partially protected (read-only after relocation for some entries), but lazy-bound entries remain writable"}})
    if not has_stack_canary:
        flags.append({"type": "no_canary", "severity": "medium", "detail": "No stack canary detected (__stack_chk_fail not imported)", "evidence": {"why": "No stack-smashing protector — buffer overflows won't be detected by canary checks before return"}})
    if is_stripped:
        flags.append({"type": "stripped", "severity": "low", "detail": "Binary is stripped (no .symtab — harder to analyze)", "evidence": {"why": "Symbol table removed — function names and debug info unavailable, complicating reverse engineering (common in malware)"}})
    if rpath:
        flags.append({"type": "rpath", "severity": "medium", "detail": f"RPATH set: {rpath} (potential DLL hijacking)", "evidence": {"path": rpath, "why": f"RPATH '{rpath}' overrides standard library search order — an attacker can place a malicious .so in this path to hijack execution"}})
    if runpath:
        flags.append({"type": "runpath", "severity": "low", "detail": f"RUNPATH set: {runpath}", "evidence": {"path": runpath, "why": f"RUNPATH '{runpath}' is set (lower priority than RPATH but still influences library loading)"}})

    if suspicious_found:
        for cat, syms in suspicious_found.items():
            sev = "high" if cat in ("process_injection", "privilege_escalation", "anti_debug") else "medium"
            evidence = {
                "matched_apis": syms,
                "why": f"Imports from category '{cat}' are commonly used in malicious techniques ({cat.replace('_', ' ')})",
                "reference_apis": SUSPICIOUS_ELF_IMPORTS.get(cat, []),
            }
            flags.append({"type": "suspicious_import", "category": cat, "severity": sev, "detail": f"{len(syms)} suspicious symbol(s): {', '.join(syms[:5])}", "evidence": evidence})

    for sec in sections:
        if sec.get("wx_warning"):
            flags.append({"type": "wx_section", "severity": "high", "detail": f"Section '{sec['name']}' is Writable+Executable (W^X violation)", "evidence": {"section": sec["name"], "why": "Writable+Executable sections violate W^X policy, allowing self-modifying code — a strong indicator of shellcode or runtime unpacking"}})
        if sec["entropy_status"] == "high":
            flags.append({"type": "high_entropy", "severity": "medium", "detail": f"Section '{sec['name']}' entropy {sec['entropy']:.2f} (packed/encrypted)", "evidence": {"section": sec["name"], "entropy": sec["entropy"], "threshold": ENTROPY_HIGH_THRESHOLD, "why": f"Entropy {sec['entropy']:.2f} exceeds threshold {ENTROPY_HIGH_THRESHOLD} indicating compressed, encrypted, or packed content"}})
        if sec.get("packer_indicator"):
            flags.append({"type": "packer", "severity": "medium", "detail": f"Section '{sec['name']}' matches packer: {sec['packer_indicator']}", "evidence": {"section": sec["name"], "packer": sec["packer_indicator"], "why": f"Section name matches known packer/protector signature: {sec['packer_indicator']}"}})

    if total_entropy >= ENTROPY_HIGH_THRESHOLD:
        flags.append({"type": "high_total_entropy", "severity": "medium", "detail": f"Overall file entropy {total_entropy:.2f} suggests packing/encryption", "evidence": {"entropy": total_entropy, "threshold": ENTROPY_HIGH_THRESHOLD, "why": f"Whole-file entropy {total_entropy:.2f} exceeds {ENTROPY_HIGH_THRESHOLD}, typical of packed/encrypted executables (normal code is 4.5-6.0)"}})

    result["flags"] = flags
    result["flag_count"] = {
        "high": len([f for f in flags if f["severity"] == "high"]),
        "medium": len([f for f in flags if f["severity"] == "medium"]),
        "low": len([f for f in flags if f["severity"] == "low"]),
    }

    # --- DiE-style Detection Analysis ---
    try:
        detection_result = detect_elf_characteristics(
            data, sections, result.get("security", {}),
            has_pie, result.get("interpreter", ""), needed_libs
        )
        result["detection"] = detection_result
    except Exception as e:
        result["detection"] = {"detections": [], "assessment": "clean", "error": str(e),
                               "entropy_map": [], "section_layout": [], "file_size": len(data)}

    return jsonify(result)


def _elf_section_flags_str(flags):
    """Convert ELF section flags to human-readable string."""
    parts = []
    if flags & 0x1: parts.append("W")
    if flags & 0x2: parts.append("A")
    if flags & 0x4: parts.append("X")
    if flags & 0x10: parts.append("M")
    if flags & 0x20: parts.append("S")
    if flags & 0x40: parts.append("I")
    if flags & 0x80: parts.append("L")
    if flags & 0x100: parts.append("O")
    if flags & 0x200: parts.append("G")
    if flags & 0x400: parts.append("T")
    return "".join(parts) if parts else "—"


def _elf_segment_flags_str(flags):
    """Convert ELF segment flags to human-readable string."""
    parts = []
    if flags & 4: parts.append("R")
    if flags & 2: parts.append("W")
    if flags & 1: parts.append("X")
    return "".join(parts) if parts else "—"


# =====================================================================
# FILE MAP VISUALIZER
# Builds the three planes shown side by side in the file map views:
#   BytePlot  - every cell colored by the byte class it contains
#   Entropy   - local Shannon entropy heatmap (0..1, normalized by 8 bits)
#   Structure - PE/ELF structural regions mapped onto raw file offsets
# The planes are returned as base64 byte arrays so the browser can paint
# them onto a canvas without shipping the whole sample to the client.
# =====================================================================

# Byte classes used by the BytePlot plane (index -> legend entry).
BYTEPLOT_CLASS_NULL = 0      # 0x00
BYTEPLOT_CLASS_FF = 1        # 0xFF
BYTEPLOT_CLASS_VISIBLE = 2   # printable ASCII
BYTEPLOT_CLASS_INVISIBLE = 3 # control characters
BYTEPLOT_CLASS_NONASCII = 4  # >= 0x80

BYTEPLOT_LEGEND = [
    {"id": BYTEPLOT_CLASS_FF, "label": "0xFF", "color": "#ffffff"},
    {"id": BYTEPLOT_CLASS_NULL, "label": "0x00", "color": "#000000"},
    {"id": BYTEPLOT_CLASS_VISIBLE, "label": "visible ASCII", "color": "#1a3bff"},
    {"id": BYTEPLOT_CLASS_INVISIBLE, "label": "invisible ASCII", "color": "#00c814"},
    {"id": BYTEPLOT_CLASS_NONASCII, "label": "non-ASCII", "color": "#e6e600"},
]

ENTROPY_LEGEND = [
    {"value": 0.2, "label": "0.2 (repetition)", "color": "#2f4f54"},
    {"value": 0.5, "label": "0.5 (code)", "color": "#1f9aa8"},
    {"value": 0.8, "label": "0.8 (packed)", "color": "#22d3e0"},
]

# Structure colors: one hue family per structural role.
STRUCT_COLORS = {
    "msdos": "#1a3bff",
    "dos_stub": "#2b4fd4",
    "coff": "#00c814",
    "optional": "#ee2222",
    "section_table": "#e6e600",
    "section": "#dcdcdc",
    "resources": "#19c85a",
    "imports": "#00e000",
    "exports": "#ff9d00",
    "relocations": "#8b22ee",
    "debug": "#3b6dff",
    "tls": "#ff5fc8",
    "certificate": "#00bcbc",
    "load_config": "#b8a600",
    "iat": "#00b894",
    "delay_imports": "#7fd400",
    "exception": "#c05fff",
    "entry_point": "#ff2b3c",
    "overlay": "#6b7280",
    "elf_header": "#1a3bff",
    "program_headers": "#00c814",
    "section_headers": "#e6e600",
    "dynamic": "#8b22ee",
    "symbols": "#ff9d00",
    "notes": "#00bcbc",
}

# Greys cycled through consecutive sections so neighbours stay distinguishable.
SECTION_GREYS = ["#e4e4e4", "#c6c6c6", "#a9a9a9", "#8d8d8d"]


def _byteplot_plane(data, cols, max_rows):
    """Build the byteplot grid.

    Returns (plane_bytes, rows, bytes_per_cell, mode).

    When one cell maps to exactly one byte the plane is a stream of class
    indices ("class" mode) and the browser paints the legend colors directly.
    For bigger files a cell covers several bytes, so the plane carries blended
    RGB triples ("rgb" mode): the cell color is the average of its bytes'
    class colors. Averaging is what preserves texture - picking the majority
    class instead flattens mixed data into solid blocks.
    """
    size = len(data)
    if size == 0:
        return b"", 0, 1, "class"

    bytes_per_cell = max(1, math.ceil(size / (cols * max_rows)))
    rows = math.ceil(size / (bytes_per_cell * cols))

    # Translation table: byte value -> class index, so counting is done in C.
    table = bytearray(256)
    for b in range(256):
        if b == 0x00:
            table[b] = BYTEPLOT_CLASS_NULL
        elif b == 0xFF:
            table[b] = BYTEPLOT_CLASS_FF
        elif 0x20 <= b <= 0x7E:
            table[b] = BYTEPLOT_CLASS_VISIBLE
        elif b < 0x80:
            table[b] = BYTEPLOT_CLASS_INVISIBLE
        else:
            table[b] = BYTEPLOT_CLASS_NONASCII
    classified = data.translate(bytes(table))

    if bytes_per_cell == 1:
        # One byte per cell: the classified buffer already is the plane.
        return classified, rows, 1, "class"

    # Class colors in plane order, used to average a cell's bytes.
    rgb = [(0, 0, 0)] * 5
    for entry in BYTEPLOT_LEGEND:
        h = entry["color"].lstrip("#")
        rgb[entry["id"]] = (int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16))

    plane = bytearray(rows * cols * 3)
    class_bytes = [bytes([c]) for c in range(5)]
    for idx in range(rows * cols):
        start = idx * bytes_per_cell
        if start >= size:
            break
        chunk = classified[start:start + bytes_per_cell]
        n = len(chunk)
        r = g = b = 0
        for cls in range(5):
            count = chunk.count(class_bytes[cls])
            if count:
                cr, cg, cb = rgb[cls]
                r += cr * count
                g += cg * count
                b += cb * count
        p = idx * 3
        plane[p] = r // n
        plane[p + 1] = g // n
        plane[p + 2] = b // n

    return bytes(plane), rows, bytes_per_cell, "rgb"


def _entropy_plane(data, rows, cols, min_window=64):
    """Local Shannon entropy per cell, scaled to 0..255 (1.0 == 8 bits/byte).

    Cells covering fewer than min_window bytes are widened with surrounding
    bytes, so a short block still yields a meaningful value instead of noise.
    """
    from collections import Counter

    size = len(data)
    total_cells = rows * cols
    if size == 0 or total_cells == 0:
        return b""

    cell_bytes = size / total_cells
    plane = bytearray(total_cells)
    log2 = math.log2

    for idx in range(total_cells):
        start = int(idx * cell_bytes)
        end = int((idx + 1) * cell_bytes)
        if end <= start:
            end = start + 1
        if end - start < min_window:
            # Widen symmetrically around the cell, clamped to the file.
            pad = (min_window - (end - start)) // 2
            start = max(0, start - pad)
            end = min(size, start + min_window)
            start = max(0, end - min_window)
        chunk = data[start:end]
        if not chunk:
            continue
        length = len(chunk)
        entropy = 0.0
        for count in Counter(chunk).values():
            p = count / length
            entropy -= p * log2(p)
        plane[idx] = min(255, int(entropy / 8.0 * 255))

    return bytes(plane)


def _clip_region(offset, size, file_size):
    """Clamp a region to the real file bounds; return None when it is outside."""
    if offset is None or size is None:
        return None
    try:
        offset, size = int(offset), int(size)
    except (TypeError, ValueError):
        return None
    if size <= 0 or offset < 0 or offset >= file_size:
        return None
    return offset, min(size, file_size - offset)


def _region(name, kind, offset, size, file_size, color=None, detail=None, priority=0):
    """Build a structure region entry, or None when it does not fit the file."""
    clipped = _clip_region(offset, size, file_size)
    if not clipped:
        return None
    offset, size = clipped
    return {
        "name": name,
        "kind": kind,
        "offset": offset,
        "size": size,
        "end": offset + size,
        "color": color or STRUCT_COLORS.get(kind, "#9ca3af"),
        "detail": detail or {},
        # Higher priority regions are painted last (on top of enclosing ones).
        "priority": priority,
    }


def _pe_structure_regions(pe, data):
    """Map PE headers, sections, data directories and overlay onto file offsets."""
    import pefile

    file_size = len(data)
    regions = []

    def add(*args, **kwargs):
        r = _region(*args, **kwargs)
        if r:
            regions.append(r)

    e_lfanew = pe.DOS_HEADER.e_lfanew
    add("MSDOS Header", "msdos", 0, min(64, e_lfanew or 64), file_size)
    if e_lfanew > 64:
        add("DOS Stub", "dos_stub", 64, e_lfanew - 64, file_size,
            detail={"note": "DOS stub / rich header area"})

    # PE signature + COFF file header.
    coff_size = 4 + 20
    add("COFF File Header", "coff", e_lfanew, coff_size, file_size, detail={
        "machine": hex(pe.FILE_HEADER.Machine),
        "sections": pe.FILE_HEADER.NumberOfSections,
    })

    opt_offset = e_lfanew + coff_size
    opt_size = pe.FILE_HEADER.SizeOfOptionalHeader
    add("Optional Header", "optional", opt_offset, opt_size, file_size, detail={
        "magic": hex(pe.OPTIONAL_HEADER.Magic),
        "entry_point_rva": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
    })

    table_offset = opt_offset + opt_size
    add("Section Table", "section_table", table_offset,
        pe.FILE_HEADER.NumberOfSections * 40, file_size,
        detail={"entries": pe.FILE_HEADER.NumberOfSections})

    # Sections (raw data on disk).
    end_of_sections = 0
    for i, section in enumerate(pe.sections):
        name = section.Name.decode("utf-8", errors="replace").rstrip("\x00") or f"section{i}"
        raw_off, raw_size = section.PointerToRawData, section.SizeOfRawData
        perms = "".join([
            "R" if section.Characteristics & 0x40000000 else "-",
            "W" if section.Characteristics & 0x80000000 else "-",
            "X" if section.Characteristics & 0x20000000 else "-",
        ])
        add(name, "section", raw_off, raw_size, file_size,
            color=SECTION_GREYS[i % len(SECTION_GREYS)],
            detail={
                "virtual_address": hex(section.VirtualAddress),
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": raw_size,
                "permissions": perms,
                "entropy": round(calculate_entropy(section.get_data()), 3),
            })
        if raw_size:
            end_of_sections = max(end_of_sections, raw_off + raw_size)

    # Data directories, translated from RVA to raw file offsets.
    dir_map = [
        ("IMAGE_DIRECTORY_ENTRY_EXPORT", "Exports", "exports"),
        ("IMAGE_DIRECTORY_ENTRY_IMPORT", "Imports", "imports"),
        ("IMAGE_DIRECTORY_ENTRY_RESOURCE", "Resources", "resources"),
        ("IMAGE_DIRECTORY_ENTRY_EXCEPTION", "Exception Table", "exception"),
        ("IMAGE_DIRECTORY_ENTRY_BASERELOC", "Relocations", "relocations"),
        ("IMAGE_DIRECTORY_ENTRY_DEBUG", "Debug Info", "debug"),
        ("IMAGE_DIRECTORY_ENTRY_TLS", "TLS Directory", "tls"),
        ("IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG", "Load Config", "load_config"),
        ("IMAGE_DIRECTORY_ENTRY_IAT", "Import Address Table", "iat"),
        ("IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT", "Delay Imports", "delay_imports"),
    ]
    for entry_name, label, kind in dir_map:
        try:
            idx = pefile.DIRECTORY_ENTRY[entry_name]
            d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[idx]
            if not d.VirtualAddress or not d.Size:
                continue
            offset = pe.get_offset_from_rva(d.VirtualAddress)
            add(label, kind, offset, d.Size, file_size, priority=2,
                detail={"rva": hex(d.VirtualAddress), "size": d.Size})
        except Exception:
            continue

    # The certificate table is stored as a raw file offset, not an RVA.
    try:
        idx = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[idx]
        if d.VirtualAddress and d.Size:
            add("Certificate Table", "certificate", d.VirtualAddress, d.Size, file_size,
                priority=2, detail={"file_offset": hex(d.VirtualAddress), "size": d.Size})
    except Exception:
        pass

    # Entry point marker (small but always visible).
    try:
        ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        if ep_rva:
            ep_offset = pe.get_offset_from_rva(ep_rva)
            ep_section = ""
            for section in pe.sections:
                if section.contains_rva(ep_rva):
                    ep_section = section.Name.decode("utf-8", errors="replace").rstrip("\x00")
                    break
            add("Entry Point", "entry_point", ep_offset, 16, file_size, priority=5,
                detail={"rva": hex(ep_rva), "file_offset": hex(ep_offset), "section": ep_section})
    except Exception:
        pass

    # Overlay: everything appended behind the last section.
    if end_of_sections and end_of_sections < file_size:
        overlay_size = file_size - end_of_sections
        add("Overlay", "overlay", end_of_sections, overlay_size, file_size, priority=1,
            detail={
                "size": overlay_size,
                "entropy": round(calculate_entropy(data[end_of_sections:]), 3),
            })

    return regions


def _elf_structure_regions(data):
    """Map ELF header, program/section headers and sections onto file offsets."""
    file_size = len(data)
    if file_size < 16 or data[:4] != b"\x7fELF":
        return []

    is_64 = data[4] == 2
    endian = "<" if data[5] == 1 else ">"
    regions = []

    def add(*args, **kwargs):
        r = _region(*args, **kwargs)
        if r:
            regions.append(r)

    try:
        if is_64:
            hdr = struct.unpack(f"{endian}HHI QQQ I HHHHHH", data[16:64])
        else:
            hdr = struct.unpack(f"{endian}HHI III I HHHHHH", data[16:52])
    except struct.error:
        return []

    (_e_type, _e_machine, _e_version, e_entry, e_phoff, e_shoff,
     _e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = hdr

    add("ELF Header", "elf_header", 0, e_ehsize or (64 if is_64 else 52), file_size)
    if e_phoff:
        add("Program Headers", "program_headers", e_phoff, e_phnum * e_phentsize, file_size,
            detail={"entries": e_phnum})
    if e_shoff:
        add("Section Headers", "section_headers", e_shoff, e_shnum * e_shentsize, file_size,
            detail={"entries": e_shnum})

    sh_fmt = f"{endian}IIQQQQIIQQ" if is_64 else f"{endian}IIIIIIIIII"
    sh_len = 64 if is_64 else 40

    # Section header string table, needed for section names.
    shstrtab = b""
    if e_shoff and e_shstrndx < e_shnum:
        try:
            off = e_shoff + e_shstrndx * e_shentsize
            entry = struct.unpack(sh_fmt, data[off:off + sh_len])
            if entry[4] + entry[5] <= file_size:
                shstrtab = data[entry[4]:entry[4] + entry[5]]
        except struct.error:
            pass

    def shname(name_off):
        if name_off >= len(shstrtab):
            return ""
        end = shstrtab.find(b"\x00", name_off)
        if end == -1:
            end = len(shstrtab)
        return shstrtab[name_off:end].decode("utf-8", errors="replace")

    # Sections that get their own color instead of the grey cycle.
    special = {
        ".dynamic": "dynamic", ".dynsym": "symbols", ".dynstr": "symbols",
        ".symtab": "symbols", ".strtab": "symbols",
        ".note.ABI-tag": "notes", ".note.gnu.build-id": "notes",
        ".rela.dyn": "relocations", ".rela.plt": "relocations",
        ".rel.dyn": "relocations", ".rel.plt": "relocations",
    }

    grey_idx = 0
    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        if off + sh_len > file_size:
            break
        try:
            sh = struct.unpack(sh_fmt, data[off:off + sh_len])
        except struct.error:
            break
        sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size = sh[0], sh[1], sh[2], sh[3], sh[4], sh[5]
        name = shname(sh_name)
        sections.append({"name": name, "addr": sh_addr, "offset": sh_offset, "size": sh_size})
        # SHT_NULL has no content, SHT_NOBITS (.bss) occupies no file space.
        if sh_type in (0, 8) or sh_size == 0:
            continue
        perms = "".join([
            "A" if sh_flags & 0x2 else "-",
            "W" if sh_flags & 0x1 else "-",
            "X" if sh_flags & 0x4 else "-",
        ])
        kind = special.get(name)
        if kind:
            color = None
        else:
            kind = "section"
            color = SECTION_GREYS[grey_idx % len(SECTION_GREYS)]
            grey_idx += 1
        if name.startswith(".debug"):
            kind, color = "debug", None
        add(name or f"section{i}", kind, sh_offset, sh_size, file_size, color=color, detail={
            "address": hex(sh_addr),
            "size": sh_size,
            "flags": perms,
            "entropy": round(calculate_entropy(data[sh_offset:sh_offset + sh_size]), 3),
        })

    # Entry point: translate the virtual address through its containing section.
    if e_entry:
        for sec in sections:
            if sec["addr"] and sec["addr"] <= e_entry < sec["addr"] + sec["size"]:
                ep_offset = sec["offset"] + (e_entry - sec["addr"])
                add("Entry Point", "entry_point", ep_offset, 16, file_size, priority=5, detail={
                    "virtual_address": hex(e_entry),
                    "file_offset": hex(ep_offset),
                    "section": sec["name"],
                })
                break

    return regions


def _pe_import_tree(pe):
    """DLL -> function tree for the import graph, with suspicious APIs tagged."""
    tree = []
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return tree

    # Flatten the suspicious API catalog once for quick lookups.
    api_category = {}
    for category, api_list in SUSPICIOUS_IMPORTS.items():
        for api in api_list:
            api_category[api] = category

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode("utf-8", errors="replace") if entry.dll else "?"
        funcs = []
        suspicious = 0
        for imp in entry.imports:
            name = imp.name.decode("utf-8", errors="replace") if imp.name else f"Ordinal_{imp.ordinal}"
            category = api_category.get(name)
            if category:
                suspicious += 1
            funcs.append({
                "name": name,
                "address": hex(imp.address) if imp.address else None,
                "category": category,
            })
        funcs.sort(key=lambda f: (f["category"] is None, f["name"].lower()))
        tree.append({
            "dll": dll,
            "count": len(funcs),
            "suspicious_count": suspicious,
            "functions": funcs[:400],
        })

    tree.sort(key=lambda d: (-d["suspicious_count"], d["dll"].lower()))
    return tree


def _pe_export_tree(pe):
    """Exported symbols, grouped under the reported DLL name."""
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        return None
    exp_dir = pe.DIRECTORY_ENTRY_EXPORT
    dll_name = ""
    try:
        if exp_dir.name:
            dll_name = exp_dir.name.decode("utf-8", errors="replace")
    except Exception:
        pass
    symbols = []
    for exp in exp_dir.symbols:
        name = exp.name.decode("utf-8", errors="replace") if exp.name else f"Ordinal_{exp.ordinal}"
        symbols.append({
            "name": name,
            "ordinal": exp.ordinal,
            "address": hex(exp.address) if exp.address else None,
        })
    symbols.sort(key=lambda s: s["name"].lower())
    return {
        "dll": dll_name or "(this image)",
        "count": len(symbols),
        "functions": symbols[:400],
    }


def _elf_symbol_trees(data):
    """Needed libraries and dynamic symbols for the ELF import/export graph.

    ELF does not record which library a symbol comes from, so imports are
    grouped as 'undefined dynamic symbols' with the DT_NEEDED list alongside.
    """
    file_size = len(data)
    if file_size < 64 or data[:4] != b"\x7fELF":
        return [], None

    is_64 = data[4] == 2
    endian = "<" if data[5] == 1 else ">"
    try:
        if is_64:
            hdr = struct.unpack(f"{endian}HHI QQQ I HHHHHH", data[16:64])
        else:
            hdr = struct.unpack(f"{endian}HHI III I HHHHHH", data[16:52])
    except struct.error:
        return [], None

    e_shoff, e_shentsize, e_shnum, e_shstrndx = hdr[5], hdr[10], hdr[11], hdr[12]
    sh_fmt = f"{endian}IIQQQQIIQQ" if is_64 else f"{endian}IIIIIIIIII"
    sh_len = 64 if is_64 else 40

    shstrtab = b""
    if e_shoff and e_shstrndx < e_shnum:
        try:
            off = e_shoff + e_shstrndx * e_shentsize
            entry = struct.unpack(sh_fmt, data[off:off + sh_len])
            if entry[4] + entry[5] <= file_size:
                shstrtab = data[entry[4]:entry[4] + entry[5]]
        except struct.error:
            pass

    def cstr(buf, offset):
        if offset >= len(buf):
            return ""
        end = buf.find(b"\x00", offset)
        if end == -1:
            end = len(buf)
        return buf[offset:end].decode("utf-8", errors="replace")

    named = {}
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        if off + sh_len > file_size:
            break
        try:
            sh = struct.unpack(sh_fmt, data[off:off + sh_len])
        except struct.error:
            break
        named[cstr(shstrtab, sh[0])] = {"offset": sh[4], "size": sh[5], "entsize": sh[9]}

    dynstr = b""
    if ".dynstr" in named:
        s = named[".dynstr"]
        if s["offset"] + s["size"] <= file_size:
            dynstr = data[s["offset"]:s["offset"] + s["size"]]

    # DT_NEEDED entries from .dynamic
    needed = []
    if ".dynamic" in named and dynstr:
        s = named[".dynamic"]
        ent = 16 if is_64 else 8
        fmt = f"{endian}qQ" if is_64 else f"{endian}iI"
        pos = s["offset"]
        end = min(s["offset"] + s["size"], file_size)
        while pos + ent <= end:
            try:
                d_tag, d_val = struct.unpack(fmt, data[pos:pos + ent])
            except struct.error:
                break
            if d_tag == 0:  # DT_NULL
                break
            if d_tag == 1:  # DT_NEEDED
                needed.append(cstr(dynstr, d_val))
            pos += ent

    # Dynamic symbols, split into undefined (imports) and defined (exports).
    imports, exports = [], []
    if ".dynsym" in named and dynstr:
        s = named[".dynsym"]
        ent = s["entsize"] or (24 if is_64 else 16)
        count = s["size"] // ent if ent else 0
        for i in range(min(count, 2000)):
            off = s["offset"] + i * ent
            if off + ent > file_size:
                break
            try:
                if is_64:
                    st_name, st_info, _st_other, st_shndx, st_value, _st_size = struct.unpack(
                        f"{endian}IBBHQQ", data[off:off + 24])
                else:
                    st_name, st_value, _st_size, st_info, _st_other, st_shndx = struct.unpack(
                        f"{endian}IIIBBH", data[off:off + 16])
            except struct.error:
                break
            name = cstr(dynstr, st_name)
            if not name:
                continue
            sym_type = {1: "OBJECT", 2: "FUNC", 6: "TLS"}.get(st_info & 0xF, "OTHER")
            if st_shndx == 0:  # SHN_UNDEF -> resolved at load time
                imports.append({"name": name, "category": None, "address": None, "type": sym_type})
            else:
                exports.append({"name": name, "ordinal": i, "address": hex(st_value), "type": sym_type})

    # Tag imported symbols that match the suspicious API catalog.
    api_category = {}
    for category, api_list in SUSPICIOUS_IMPORTS.items():
        for api in api_list:
            api_category[api] = category
    for sym in imports:
        sym["category"] = api_category.get(sym["name"])

    import_tree = []
    for lib in needed:
        import_tree.append({
            "dll": lib,
            "count": 0,
            "suspicious_count": 0,
            "functions": [],
            "note": "DT_NEEDED (symbol attribution not recorded in ELF)",
        })
    if imports:
        imports.sort(key=lambda f: (f["category"] is None, f["name"].lower()))
        import_tree.insert(0, {
            "dll": "undefined dynamic symbols",
            "count": len(imports),
            "suspicious_count": len([s for s in imports if s["category"]]),
            "functions": imports[:400],
        })

    export_tree = None
    if exports:
        exports.sort(key=lambda s: s["name"].lower())
        export_tree = {
            "dll": ".dynsym (defined symbols)",
            "count": len(exports),
            "functions": exports[:400],
        }

    return import_tree, export_tree


@app.route("/api/file/visualize")
def api_file_visualize():
    """File map planes (byteplot, entropy, structure) plus import/export trees."""
    import base64

    filepath = request.args.get("path", "")
    cols = min(max(request.args.get("cols", 256, type=int), 32), 512)
    max_rows = min(max(request.args.get("rows", 512, type=int), 64), 1024)
    entropy_cols = min(max(request.args.get("entropy_cols", 96, type=int), 4), 256)

    if not filepath:
        return jsonify({"error": "No path specified"}), 400

    norm_path = os.path.normpath(filepath)
    if not os.path.isfile(norm_path):
        return jsonify({"error": _quarantine_hint(norm_path, "File not found")}), 404

    # The same file is mapped by the hex minimap, the analysis panel and the
    # FileMap tab; computing the planes takes seconds for large samples.
    try:
        st = os.stat(norm_path)
        cache_key = (norm_path.lower(), st.st_mtime_ns, st.st_size, cols, max_rows, entropy_cols)
    except OSError:
        cache_key = None
    cached = _visualize_cache.get(cache_key) if cache_key else None
    if cached is not None:
        _visualize_cache.move_to_end(cache_key)
        return jsonify(dict(cached, path=filepath))

    try:
        with open(norm_path, "rb") as f:
            data = f.read(VISUALIZE_MAX_BYTES + 1)
    except (IOError, OSError) as e:
        return jsonify({"error": _quarantine_hint(norm_path, f"Unable to read file: {e}")}), 500

    truncated = len(data) > VISUALIZE_MAX_BYTES
    if truncated:
        data = data[:VISUALIZE_MAX_BYTES]

    if not data:
        return jsonify({"error": "File is empty"}), 400

    # --- Format detection + structure mapping ---
    fmt, regions, import_tree, export_tree = "raw", [], [], None
    parse_error = None

    if data[:2] == b"MZ":
        fmt = "PE"
        try:
            import pefile
            # Full parsing also walks resources, relocations and debug data,
            # which the map does not use and which dominate on large DLLs.
            pe = pefile.PE(data=data, fast_load=True)
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
            ])
            regions = _pe_structure_regions(pe, data)
            import_tree = _pe_import_tree(pe)
            export_tree = _pe_export_tree(pe)
            pe.close()
        except ImportError:
            parse_error = "pefile module not installed"
        except Exception as e:
            parse_error = f"PE parsing failed: {e}"
    elif data[:4] == b"\x7fELF":
        fmt = "ELF"
        try:
            regions = _elf_structure_regions(data)
            import_tree, export_tree = _elf_symbol_trees(data)
        except Exception as e:
            parse_error = f"ELF parsing failed: {e}"

    # --- Planes ---
    byteplot, rows, bytes_per_cell, byteplot_mode = _byteplot_plane(data, cols, max_rows)
    entropy = _entropy_plane(data, rows, entropy_cols)

    # Legend entries for the structure column, deduplicated in paint order.
    # The offset lets the UI jump straight to a region from the legend.
    struct_legend, seen = [], set()
    for r in sorted(regions, key=lambda x: (x["priority"], x["offset"])):
        key = (r["name"], r["color"])
        if key in seen:
            continue
        seen.add(key)
        struct_legend.append({
            "label": r["name"],
            "color": r["color"],
            "kind": r["kind"],
            "offset": r["offset"],
        })

    result = {
        "format": fmt,
        "path": filepath,
        "filename": os.path.basename(norm_path),
        "file_size": len(data),
        "truncated": truncated,
        "rows": rows,
        "cols": cols,
        "bytes_per_cell": bytes_per_cell,
        "entropy_cols": entropy_cols,
        "byteplot": base64.b64encode(byteplot).decode("ascii"),
        "byteplot_mode": byteplot_mode,
        "entropy": base64.b64encode(entropy).decode("ascii"),
        "total_entropy": round(calculate_entropy(data), 3),
        "regions": sorted(regions, key=lambda r: (r["priority"], r["offset"])),
        "import_tree": import_tree,
        "export_tree": export_tree,
        "legend": {
            "byteplot": BYTEPLOT_LEGEND,
            "entropy": ENTROPY_LEGEND,
            "structure": struct_legend,
        },
        "parse_error": parse_error,
    }
    if cache_key:
        _visualize_cache[cache_key] = result
        while len(_visualize_cache) > VISUALIZE_CACHE_SIZE:
            _visualize_cache.popitem(last=False)
    return jsonify(result)


# --- Main ---
# Start background alert loader (works with both direct run and import by dev_server)
# When Flask reloader is active, only start in the child process to avoid duplicate threads
_is_reloader_child = os.environ.get("WERKZEUG_RUN_MAIN") == "true"
_reloader_active = os.environ.get("FLASK_DEBUG") == "1" or os.environ.get("FLASK_ENV") == "development"
# Tests import the module without the loader polling services in the background.
_background_disabled = os.environ.get("TDC_NO_BACKGROUND") == "1"

if not _background_disabled and (_is_reloader_child or not _reloader_active):
    loader = threading.Thread(target=alert_loader_thread, daemon=True)
    loader.start()

if __name__ == "__main__":
    print(f"[*] Detonation Chamber UI starting on http://0.0.0.0:{WEBUI_PORT}")
    print(f"    Rustinel alerts: {RUSTINEL_ALERTS_DIR}")
    print(f"    Detonator API:   {DETONATOR_API}")
    print(f"    Agent API:       {DETONATOR_AGENT_API}")
    print(f"    LitterBox:       {LITTERBOX_API}")

    # 0.0.0.0 keeps the UI reachable from the host over the VM network; set
    # WEBUI_HOST=127.0.0.1 to restrict it to the VM itself.
    app.run(host=os.environ.get("WEBUI_HOST", "0.0.0.0"), port=WEBUI_PORT, debug=False)
