#!/usr/bin/env python3
"""
Transportable Detonation Chamber - MCP Server

Exposes TDC functionality as MCP tools for use with Claude Code and other MCP clients.
Connects to the TDC Web UI API running on the analysis VM.
"""

import json
import os
import sys
from typing import Optional

import httpx
from mcp.server.fastmcp import FastMCP

TDC_BASE_URL = os.environ.get("TDC_URL", "http://192.168.64.4:9000")

mcp = FastMCP(
    "Transportable Detonation Chamber",
    instructions="Malware analysis lab - submit samples, query Sysmon/ETW events, inspect processes, and manage detonations",
)


def _raise_with_body(r: httpx.Response) -> None:
    """raise_for_status, but carry the API's {"error": ...} text along.

    The endpoints explain failures in the body (tool not installed, timeout,
    bad parameter); a bare HTTPStatusError dropped that explanation.
    """
    if not r.is_error:
        return
    try:
        detail = r.json().get("error")
    except (ValueError, AttributeError):
        detail = None
    raise RuntimeError(f"HTTP {r.status_code}: {detail or r.text[:300]}")


def _get(path: str, params: dict | None = None, timeout: float = 15.0) -> dict | list:
    """GET request to TDC API."""
    r = httpx.get(f"{TDC_BASE_URL}{path}", params=params, timeout=timeout)
    _raise_with_body(r)
    return r.json()


def _post(path: str, data: dict | None = None, files: dict | None = None, timeout: float = 60.0) -> dict | list:
    """POST request to TDC API."""
    r = httpx.post(f"{TDC_BASE_URL}{path}", data=data, files=files, timeout=timeout)
    _raise_with_body(r)
    return r.json()


def _call(method: str, path: str, timeout: float = 60.0, **kwargs) -> dict:
    """Request that returns the API's JSON error body instead of raising.

    The live-memory endpoints answer 4xx with an explanatory {"error": ...}
    (e.g. no cached results for a PID); surfacing that text is more useful to
    an MCP client than an HTTP exception.
    """
    try:
        r = httpx.request(method, f"{TDC_BASE_URL}{path}", timeout=timeout, **kwargs)
    except httpx.TimeoutException:
        return {"error": f"No answer within {timeout:.0f}s - the server may still be working"}
    except httpx.HTTPError as e:
        return {"error": f"Request failed: {e}"}
    try:
        body = r.json()
    except ValueError:
        r.raise_for_status()
        return {"error": f"Unexpected non-JSON response ({r.status_code})"}
    if r.is_error and isinstance(body, dict) and "error" not in body:
        body["error"] = f"HTTP {r.status_code}"
    return body


# --- Status & Services ---


@mcp.tool()
def tdc_status() -> str:
    """Get the overall status of all TDC services (Sysmon, Rustinel, Detonator, Fibratus, LitterBox)."""
    status = _get("/api/status")
    lines = []
    for svc, info in status.items():
        online = info.get("online", False) if isinstance(info, dict) else False
        extra = ""
        if isinstance(info, dict):
            if "alerts_count" in info:
                extra = f" ({info['alerts_count']} alerts)"
            elif "data" in info and isinstance(info["data"], dict):
                extra = f" (in_use={info['data'].get('in_use', '?')})"
        lines.append(f"{'✓' if online else '✗'} {svc}{extra}")
    return "\n".join(lines)


@mcp.tool()
def tdc_service_launch(service: str) -> str:
    """Start/restart a TDC service on the VM.

    Args:
        service: Service name (sysmon, rustinel, fibratus, detonator, litterbox)
    """
    result = _post("/api/service/launch", data={"service": service})
    return json.dumps(result, indent=2)


# --- Sysmon Events ---


@mcp.tool()
def tdc_sysmon_events(
    event_id: Optional[str] = None,
    pid: Optional[int] = None,
    max_events: int = 50,
) -> str:
    """Query Sysmon events from the Windows Event Log on the analysis VM.

    Args:
        event_id: Filter by Sysmon Event ID(s), comma-separated (e.g. "1,3,11"). Common IDs: 1=ProcessCreate, 3=NetworkConnect, 5=ProcessTerminate, 7=ImageLoad, 8=CreateRemoteThread, 10=ProcessAccess, 11=FileCreate, 12/13=Registry, 22=DNSQuery
        pid: Filter by Process ID
        max_events: Maximum number of events to return (default 50)
    """
    params = {"max": max_events}
    if event_id:
        params["event_id"] = event_id
    if pid:
        params["pid"] = pid
    events = _get("/api/sysmon", params=params)
    if not events:
        return "No Sysmon events found."
    if isinstance(events, list) and events and events[0].get("error"):
        return f"Error: {events[0]['error']}"

    lines = []
    for ev in events:
        ts = ev.get("timestamp", "")[:19]
        eid = ev.get("event_id", "?")
        etype = ev.get("type", f"Event_{eid}")
        pid_val = ev.get("pid", "")
        image = (ev.get("image", "") or "").split("\\")[-1]
        detail = ""
        if eid == 1:
            detail = ev.get("commandline", "")[:120]
        elif eid == 3:
            detail = f"{ev.get('dst_ip', '')}:{ev.get('dst_port', '')}"
        elif eid == 11:
            detail = ev.get("target", "")[:100]
        elif eid == 22:
            detail = ev.get("query", "")
        elif eid == 7:
            detail = (ev.get("loaded_image", "") or "").split("\\")[-1]
        elif eid == 8:
            detail = f"src={ev.get('source_pid','')} -> tgt={ev.get('target_pid','')}"
        lines.append(f"[{ts}] EID:{eid} ({etype}) PID:{pid_val} {image} | {detail}")

    return f"{len(events)} events:\n" + "\n".join(lines)


@mcp.tool()
def tdc_sysmon_stats() -> str:
    """Get Sysmon event statistics - counts by event type from the last 500 events."""
    stats = _get("/api/sysmon/stats")
    if stats.get("error"):
        return f"Error: {stats['error']}"
    if stats.get("diagnostic"):
        return f"Diagnostic: {stats['diagnostic']}"

    entries = stats.get("stats", [])
    if not entries:
        return "No statistics available."

    total = sum(s["count"] for s in entries)
    lines = [f"Total: {total} events (last 500)"]
    for s in sorted(entries, key=lambda x: x["count"], reverse=True):
        lines.append(f"  EID {s['event_id']:>2}: {s['name']:<20} {s['count']:>4}")
    return "\n".join(lines)


# --- ETW Events ---


@mcp.tool()
def tdc_etw_events(
    channel: str = "security",
    max_events: int = 20,
    event_id: Optional[int] = None,
) -> str:
    """Query Windows ETW (Event Tracing for Windows) events from various log channels.

    Args:
        channel: One of sysmon, security, powershell, defender, wmi,
            task-scheduler, bits, dns-client, firewall, applocker, winrm,
            application (see tdc_etw_channels)
        max_events: Maximum events to return (default 20, max 500)
        event_id: Only events with this Windows Event ID
    """
    params = {"channel": channel, "max": max_events}
    if event_id:
        params["event_id"] = event_id
    data = _call("GET", "/api/etw/events", params=params, timeout=30.0)
    # The endpoint answers {"events": [...], "channel": ..., "note"/"error"}.
    if data.get("error"):
        return f"Error: {data['error']}"
    events = data.get("events") or []
    if not events:
        return data.get("note") or f"No ETW events from channel '{channel}'."
    lines = []
    for ev in events:
        ts = (ev.get("timestamp") or "")[:19]
        eid = ev.get("event_id", "?")
        msg = (ev.get("message") or "")[:150]
        lines.append(f"[{ts}] EID:{eid} {msg}")
    return f"{len(lines)} events from '{channel}':\n" + "\n".join(lines)


@mcp.tool()
def tdc_etw_channels() -> str:
    """List available ETW log channels and their availability status."""
    channels = _get("/api/etw/channels", params={"probe": "true"})
    lines = []
    for key, info in channels.items():
        avail = "✓" if info.get("available") else "✗"
        lines.append(f"{avail} {key:<16} {info.get('label', '')} - {info.get('description', '')[:80]}")
    return "\n".join(lines)


# --- Alerts ---


@mcp.tool()
def tdc_alerts(
    severity: Optional[str] = None,
    engine: Optional[str] = None,
    pid: Optional[int] = None,
    since: Optional[str] = None,
    detonated_only: bool = False,
    max_alerts: int = 30,
) -> str:
    """Query security alerts from the Rustinel/Fibratus/LitterBox detection engines, newest first.

    Args:
        severity: Filter by severity (critical, high, medium, low)
        engine: Filter by detection engine (e.g. sigma, yara, fibratus)
        pid: Filter by Process ID
        since: Only alerts at or after this ISO-8601 time (e.g. 2026-10-20T08:00:00Z)
        detonated_only: Only alerts attributed to a detonated sample
        max_alerts: Maximum alerts to return (default 30)
    """
    params = {"limit": max(1, min(max_alerts, 1000))}
    if severity:
        params["severity"] = severity
    if engine:
        params["engine"] = engine
    if pid:
        params["pid"] = pid
    if since:
        params["since"] = since
    if detonated_only:
        params["detonated"] = "true"
    alerts = _call("GET", "/api/alerts", params=params, timeout=120.0)
    if isinstance(alerts, dict) and alerts.get("error"):
        return f"Error: {alerts['error']}"
    if not alerts:
        return "No alerts found."
    lines = []
    for a in alerts:
        ts = (a.get("timestamp") or "")[:19]
        sev = (a.get("severity") or "?").upper()
        name = a.get("rule_name") or a.get("name") or "unknown"
        lines.append(f"[{ts}] [{sev}] {name} (engine={a.get('engine', '?')}, pid={a.get('pid', '')}, "
                     f"proc={a.get('process_name', '')}, id={a.get('id')})")
    return (f"{len(alerts)} alert(s), newest first - full event via tdc_alert_detail(id):\n"
            + "\n".join(lines))


@mcp.tool()
def tdc_alert_detail(alert_id: str) -> str:
    """Get one alert with its complete raw event (Sigma/YARA match, process, parent, rule).

    Args:
        alert_id: The alert id shown by tdc_alerts / tdc_sessions
    """
    d = _call("GET", f"/api/alerts/{alert_id}")
    if d.get("error"):
        return f"Error: {d['error']}"
    head = [f"{(d.get('severity') or '?').upper()} {d.get('rule_name')} [{d.get('engine')}] at {d.get('timestamp')}",
            f"Process: {d.get('process_name')} (PID {d.get('pid')}) {d.get('process_image') or ''}"]
    if d.get("command_line"):
        head.append(f"Command: {d['command_line'][:500]}")
    if d.get("parent_name") or d.get("parent_pid"):
        head.append(f"Parent: {d.get('parent_name')} (PID {d.get('parent_pid')}) {d.get('parent_command_line') or ''}"[:500])
    if d.get("rule_description"):
        head.append(f"Rule: {d['rule_description'][:400]}")
    if d.get("tags"):
        head.append("Tags: " + ", ".join(map(str, d["tags"])))
    return "\n".join(head) + "\n\nRaw event:\n" + json.dumps(d.get("raw") or {}, indent=1, default=str)[:6000]


@mcp.tool()
def tdc_sessions(gap_minutes: int = 10, limit: int = 10) -> str:
    """Group alerts into activity sessions (bursts separated by quiet periods), newest first.

    Good for "what happened during the last detonation": each session lists
    its time span, severity counts, the busiest processes and top rules.

    Args:
        gap_minutes: Minutes without alerts that end a session (default 10)
        limit: Number of sessions to return (default 10)
    """
    d = _call("GET", "/api/sessions", params={"gap": gap_minutes * 60, "limit": limit})
    if d.get("error"):
        return f"Error: {d['error']}"
    lines = [f"{d.get('total_sessions')} session(s) with a {gap_minutes} min gap; newest {len(d.get('sessions') or [])}:"]
    for sess in d.get("sessions") or []:
        sev = ", ".join(f"{k} {v}" for k, v in sorted(sess["severity"].items(), key=lambda x: -x[1]))
        lines.append(f"\n[{(sess['start'] or '')[:19]} .. {(sess['end'] or '')[:19]}] {sess['count']} alerts "
                     f"({sev}) in {sess['process_count']} process(es)")
        procs = ", ".join(f"{p['name']}({p['pid']}) x{p['alerts']}" for p in sess["processes"][:6])
        lines.append(f"  processes: {procs}")
        rules = "; ".join(f"{r['rule']} x{r['count']}" for r in sess["top_rules"][:5])
        lines.append(f"  rules: {rules}")
    return "\n".join(lines)


# --- Process Tree ---


@mcp.tool()
def tdc_processes(max_procs: int = 50) -> str:
    """Get the process tree showing active/monitored processes with threat counts.

    Args:
        max_procs: Maximum processes to return (default 50, sorted by threats)
    """
    procs = _get("/api/processes", params={"max": max_procs, "sort": "threats", "include_parents": "true"})
    if not procs:
        return "No processes found."

    lines = []
    for pid, proc in sorted(procs.items(), key=lambda x: x[1].get("activity", {}).get("threats", 0), reverse=True):
        name = proc.get("name", "?")
        threats = proc.get("activity", {}).get("threats", 0)
        image = proc.get("image", "")
        cmdline = proc.get("command_line", "")[:100]
        user = proc.get("user", "")
        status = "exited" if proc.get("exit_time") else "running"
        threat_marker = f" ⚠ {threats} threats" if threats > 0 else ""
        lines.append(f"PID {pid}: {name} [{status}]{threat_marker}")
        if image:
            lines.append(f"  Image: {image}")
        if cmdline:
            lines.append(f"  Cmd: {cmdline}")
        if user:
            lines.append(f"  User: {user}")
    return f"{len(procs)} processes:\n" + "\n".join(lines)


@mcp.tool()
def tdc_process_detail(pid: str) -> str:
    """Get detailed information about a specific process: identity, parent,
    activity counters, detonation attribution and its most recent alerts.

    Args:
        pid: Process ID (the newest process with that PID) or an instance key
            "<pid>@<start epoch>" for an earlier process that had the same PID
            (shown by tdc_process_graph / tdc_processes)
    """
    p = _call("GET", f"/api/processes/{pid}")
    if p.get("error"):
        return f"Process {pid}: {p['error']}"
    act = p.get("activity") or {}
    lines = [
        f"PID {p.get('pid')}" + (f" (instance {p['key']})" if p.get("key") and p["key"] != str(p.get("pid")) else "")
        + f": {p.get('name')} [{'exited ' + str(p.get('exit_time')) if p.get('exit_time') else 'running/unknown'}]",
        f"Image: {p.get('image')}",
        f"Command: {(p.get('command_line') or '')[:500]}",
        f"User: {p.get('user')}  Integrity: {p.get('integrity')}",
        f"Parent: {p.get('parent_name')} (PID {p.get('parent_pid')}"
        + (f", instance {p['parent_key']}" if p.get("parent_key") and p.get("parent_key") != str(p.get("parent_pid")) else "") + ")",
        f"Children: {', '.join(map(str, p.get('children') or [])) or '-'}",
        f"First/last seen: {p.get('first_seen')} / {p.get('last_seen')}",
        "Activity: " + ", ".join(f"{k} {v}" for k, v in act.items() if v),
    ]
    if p.get("detonated"):
        lines.append(f"Detonated: yes ({', '.join(p.get('detonation_sources') or [])})")
    alerts = sorted(p.get("alerts") or [], key=lambda a: a.get("timestamp") or "", reverse=True)
    if alerts:
        lines.append(f"\n{len(alerts)} alert(s), newest 15:")
        for a in alerts[:15]:
            lines.append(f"  [{(a.get('timestamp') or '')[:19]}] [{(a.get('severity') or '?').upper()}] "
                         f"{a.get('rule_name')} [{a.get('engine')}] id={a.get('id')}")
    return "\n".join(lines)


@mcp.tool()
def tdc_process_graph(pid: str, depth: int = 0, max_nodes: int = 150, at: Optional[str] = None) -> str:
    """Show the process tree around a PID: its ancestors, the PID itself and its
    descendants, with alerts, detonation marks, network connections, DNS queries
    and remote-thread (injection) edges per process.

    PIDs are reused by Windows: a plain PID means its newest process; pass `at`
    (e.g. an alert timestamp) for the process that had the PID at that time,
    or an instance key "<pid>@<start epoch>".

    Args:
        pid: Process ID or instance key to center the tree on
        depth: Descendant levels to include (0 = all)
        max_nodes: Cap on processes returned (default 150)
        at: Optional ISO-8601 time to pick the process that had this PID then
    """
    params = {"pid": pid, "down_depth": depth, "max_nodes": max_nodes}
    if at:
        params["at"] = at
    g = _call("GET", "/api/process-graph", params=params, timeout=60.0)
    if g.get("error"):
        return f"Error: {g['error']}"
    procs = g.get("processes") or {}
    if not procs:
        return f"No process data for PID {pid}."
    net, dns = {}, {}
    for ev in g.get("network") or []:
        net.setdefault(str(ev.get("key") or ev.get("pid")), set()).add(f"{ev.get('dst_ip')}:{ev.get('dst_port')}")
    for ev in g.get("dns") or []:
        dns.setdefault(str(ev.get("key") or ev.get("pid")), set()).add(ev.get("query") or "")
    inj = {}
    for ev in g.get("injections") or []:
        inj.setdefault(str(ev.get("source_key") or ev.get("source_pid")), set()).add(str(ev.get("target_pid")))

    def line(p, indent):
        marks = []
        if p.get("is_root"):
            marks.append("FOCUS")
        if p.get("detonated"):
            marks.append("DETONATED")
        if p.get("alerts_count"):
            marks.append(f"{p['alerts_count']} alert(s), max {p.get('severity')}")
        if p.get("exit_time"):
            marks.append("exited")
        inst = f", instance {p['key']}" if p.get("key") and p["key"] != str(p.get("pid")) else ""
        out = [f"{'  ' * indent}{'└ ' if indent else ''}{p.get('name') or '?'} (PID {p.get('pid')}{inst})"
               + (f"  [{'; '.join(marks)}]" if marks else "")]
        pad = "  " * indent + ("  " if indent else "") + "    "
        if p.get("command_line"):
            out.append(f"{pad}cmd: {p['command_line'][:160]}")
        key = str(p.get("key") or p.get("pid"))
        if net.get(key):
            out.append(f"{pad}net: {', '.join(sorted(net[key])[:8])}")
        if dns.get(key):
            out.append(f"{pad}dns: {', '.join(sorted(dns[key])[:8])}")
        if inj.get(key):
            out.append(f"{pad}remote thread into PID {', '.join(sorted(inj[key]))}")
        return out

    for k, p in procs.items():
        p.setdefault("key", k)
    roots = [p for p in procs.values() if str(p.get("parent_key") or p.get("parent_pid")) not in procs]
    lines, seen = [], set()

    def walk(p, indent):
        key = str(p.get("key"))
        if key in seen:
            return
        seen.add(key)
        lines.extend(line(p, indent))
        kids = [procs[str(c)] for c in p.get("children") or []
                if str(c) in procs and str(procs[str(c)].get("parent_key") or procs[str(c)].get("parent_pid")) == key]
        for k in sorted(kids, key=lambda k: k.get("first_seen") or ""):
            walk(k, indent + 1)

    for r in sorted(roots, key=lambda r: r.get("depth") or 0):
        walk(r, 0)
    header = f"{len(procs)} process(es) around {g.get('root_pid') or pid}" + (" (truncated)" if g.get("truncated") else "")
    return header + ":\n" + "\n".join(lines)


@mcp.tool()
def tdc_process_lookup(name: str) -> str:
    """Find running processes on the VM by (partial) image name, e.g. to get a PID
    for tdc_memory_scan.

    Args:
        name: Part of the image name, e.g. 'explorer' or 'rundll32'
    """
    d = _call("GET", "/api/process/lookup", params={"name": name})
    if d.get("error"):
        return f"Error: {d['error']}"
    if not d.get("matches"):
        return f"No running process matches '{name}'."
    return f"{d['count']} match(es):\n" + "\n".join(
        f"  PID {m['pid']}: {m['name']} ({m.get('memory', '?')})" for m in d["matches"])


# --- Submissions & Detonation ---


@mcp.tool()
def tdc_submit_file(file_path: str, target: str = "both") -> str:
    """Submit a malware sample for detonation and analysis.

    The file is sent to DetonatorAgent for execution and optionally to LitterBox for
    static+dynamic analysis. Sysmon, Rustinel, and Fibratus will monitor the execution.

    Args:
        file_path: Local path to the file to submit
        target: Where to submit - 'agent' (execute only), 'litterbox' (analyze only), 'both' (default)
    """
    if not os.path.isfile(file_path):
        return f"Error: File not found: {file_path}"

    filename = os.path.basename(file_path)
    with open(file_path, "rb") as f:
        files = {"file": (filename, f)}
        data = {"target": target}
        # target=both runs agent, upload, static and dynamic analysis in one
        # request (up to ~11 min); a shorter client timeout reported a failure
        # for a detonation that had in fact started.
        result = _post("/api/submit", data=data, files=files, timeout=720.0)
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
def tdc_submissions() -> str:
    """List all submitted samples and their status."""
    subs = _get("/api/submissions")
    if not subs:
        return "No submissions found."
    if isinstance(subs, dict) and subs.get("error"):
        return f"Error: {subs['error']}"

    lines = []
    entries = subs if isinstance(subs, list) else subs.get("submissions", [])
    for sub in entries[:30]:
        ts = sub.get("timestamp", "")[:19]
        fname = sub.get("filename", "?")
        sha = sub.get("sha256", "")[:16]
        pid = sub.get("agent_pid", "")
        verdict = (sub.get("verdict") or {}).get("label") if isinstance(sub.get("verdict"), dict) else sub.get("verdict")
        lines.append(f"[{ts}] {fname} (sha256={sha}...) agent={sub.get('agent_status') or '-'} "
                     f"litterbox={sub.get('litterbox_status') or '-'} pid={pid}"
                     + (f" verdict={verdict}" if verdict else ""))
    return f"{len(entries)} submissions:\n" + "\n".join(lines)


@mcp.tool()
def tdc_detonation_results(sha256: Optional[str] = None, pid: Optional[int] = None,
                           filename: Optional[str] = None) -> str:
    """Get the combined verdict and results of a detonation: overall verdict with
    reasons, EDR alerts, memory evidence (live scan + exit dump), network beaconing,
    LitterBox and the sample's stdout/stderr.

    Args:
        sha256: SHA256 hash of the sample
        pid: Process ID from detonation
        filename: Sample file name (improves alert matching)
    """
    params = {k: v for k, v in {"sha256": sha256, "pid": pid, "filename": filename}.items() if v}
    if not params:
        return "Give sha256 and/or pid (see tdc_submissions)."
    d = _call("GET", "/api/detonation/results", params=params, timeout=60.0)
    if d.get("error"):
        return f"Error: {d['error']}"
    v = d.get("verdict") or {}
    lines = [f"VERDICT: {v.get('label')} (score {v.get('score')})"]
    lines += [f"  - {r}" for r in (v.get("reasons") or [])[:10]]
    me = d.get("memory_evidence")
    if isinstance(me, dict):
        lines.append(f"\nMemory evidence: {me.get('label')} ({me.get('score')})"
                     + (f" - {me['note']}" if me.get("note") else ""))
    nb = d.get("network_beaconing")
    if isinstance(nb, dict) and nb.get("evidence_findings"):
        lines.append(f"Network beaconing: {len(nb['evidence_findings'])} periodic destination(s)")
    ec = d.get("exit_capture_result")
    if isinstance(ec, dict):
        lines.append(f"Exit capture: {'observed' if ec.get('observed') else ec.get('status') or 'no dump'}")
    alerts = d.get("fibratus_alerts") or []
    lines.append(f"\nEDR alerts: {d.get('fibratus_alert_count', 0)}")
    for a in alerts[:10]:
        lines.append(f"  [{(a.get('timestamp') or '')[:19]}] [{(a.get('severity') or '?').upper()}] "
                     f"{a.get('rule_name')} ({a.get('process_name')} PID {a.get('pid')}) id={a.get('id')}")
    edr = d.get("edr_status") or {}
    lines.append(f"EDR online: fibratus={edr.get('fibratus_online')} rustinel={edr.get('rustinel_online')}; "
                 f"LitterBox online={d.get('litterbox_online')}")
    for key, label in (("litterbox_static", "LitterBox static"), ("litterbox_dynamic", "LitterBox dynamic")):
        if d.get(key):
            lines.append(f"{label}: {json.dumps(d[key], default=str)[:600]}")
    ex = ((d.get("agent") or {}).get("execution") or {})
    if ex.get("stdout") or ex.get("stderr"):
        lines.append(f"\nSample stdout: {(ex.get('stdout') or '')[:800]}")
        if ex.get("stderr"):
            lines.append(f"Sample stderr: {ex['stderr'][:800]}")
    ready = d.get("ready") or {}
    pending = [k for k, ok in ready.items() if not ok]
    if pending:
        lines.append(f"\nStill pending: {', '.join(pending)} (poll again)")
    lines.append("Memory details: tdc_detonation_memory(pid, sha256)")
    return "\n".join(lines)


# --- Scanning ---


@mcp.tool()
def tdc_scan_threatcheck(file_path: str) -> str:
    """Run ThreatCheck against a file to find AV signature detection offsets.

    Splits the file binary to identify exactly which bytes trigger Windows Defender.

    Args:
        file_path: Local path to the file to scan
    """
    if not os.path.isfile(file_path):
        return f"Error: File not found: {file_path}"

    with open(file_path, "rb") as f:
        files = {"file": (os.path.basename(file_path), f)}
        result = _post("/api/scan/threatcheck", files=files, timeout=180.0)
    return json.dumps(result, indent=2, default=str)[:4000]


@mcp.tool()
def tdc_scan_defendercheck(file_path: str) -> str:
    """Run DefenderCheck against a file to identify detection signatures.

    Args:
        file_path: Local path to the file to scan
    """
    if not os.path.isfile(file_path):
        return f"Error: File not found: {file_path}"

    with open(file_path, "rb") as f:
        files = {"file": (os.path.basename(file_path), f)}
        result = _post("/api/scan/defendercheck", files=files, timeout=180.0)
    return json.dumps(result, indent=2, default=str)[:4000]


@mcp.tool()
def tdc_scan_ember(
    file_path: str,
    model: str = "EMBER2024_all",
    threshold: float = 0.5,
) -> str:
    """Score a file with an EMBER2024 (thrember) LightGBM ML classifier.

    Extracts EMBERv3 static features and returns a malicious probability (0..1)
    plus a benign/malicious verdict. Works on PE/ELF/PDF/APK samples.

    Args:
        file_path: Local path to the file to scan
        model: Benchmark model to use. One of EMBER2024_all, EMBER2024_PE,
            EMBER2024_Win32, EMBER2024_Win64, EMBER2024_Dot_Net, EMBER2024_ELF,
            EMBER2024_PDF, EMBER2024_APK (default EMBER2024_all)
        threshold: Malicious decision threshold (default 0.5)
    """
    if not os.path.isfile(file_path):
        return f"Error: File not found: {file_path}"

    with open(file_path, "rb") as f:
        files = {"file": (os.path.basename(file_path), f)}
        data = {"model": model, "threshold": str(threshold)}
        result = _post("/api/scan/ember", data=data, files=files, timeout=180.0)
    return json.dumps(result, indent=2, default=str)[:4000]


@mcp.tool()
def tdc_scan_capa(file_path: str) -> str:
    """Detect capabilities in a file with Mandiant capa (static, ATT&CK-mapped).

    Identifies what a PE/.NET/ELF/shellcode sample can do (e.g. process injection,
    persistence, C2) and maps findings to MITRE ATT&CK and the Malware Behavior
    Catalog. Complements tdc_scan_ember (which gives an ML malicious score).

    Args:
        file_path: Local path to the file to analyze
    """
    if not os.path.isfile(file_path):
        return f"Error: File not found: {file_path}"

    with open(file_path, "rb") as f:
        files = {"file": (os.path.basename(file_path), f)}
        result = _post("/api/scan/capa", files=files, timeout=360.0)
    return json.dumps(result, indent=2, default=str)[:6000]


# --- PE Analysis ---


@mcp.tool()
def tdc_pe_analyze(path: str) -> str:
    """Analyze a PE file in the VM - headers, security flags, sections, imports, IOC flags.

    Args:
        path: File path inside the analysis VM (e.g. a sample path from
            tdc_submissions or a dump path from tdc_memory_dump)
    """
    result = _call("GET", "/api/file/pe", params={"path": path}, timeout=120.0)
    if result.get("error"):
        return f"Error: {result['error']}"

    fh = result.get("file_header") or {}
    oh = result.get("optional_header") or {}
    output = [
        f"Machine: {fh.get('machine', '?')}  Type: {'DLL' if fh.get('is_dll') else 'EXE'}",
        f"Compiled: {fh.get('timestamp_utc', '?')}",
        f"Subsystem: {oh.get('subsystem_name', '?')}  Entry point: {oh.get('entry_point', '?')}",
        f"ASLR={oh.get('aslr')} DEP={oh.get('dep_nx')} CFG={oh.get('cfg')}  "
        f"Total entropy: {result.get('total_entropy')}",
    ]
    sections = result.get("sections") or []
    if sections:
        output.append(f"\nSections ({len(sections)}):")
        for sec in sections:
            output.append(f"  {sec.get('name','?'):<10} VSize={sec.get('virtual_size',0):>8}  "
                          f"RSize={sec.get('raw_size',0):>8}  Entropy={sec.get('entropy',0):.2f}"
                          + ("  RWX" if sec.get("rwx_warning") else ""))
    imports = result.get("imports") or []
    if imports:
        output.append(f"\nImports ({result.get('dll_count')} DLLs, {result.get('import_count')} functions):")
        for imp in imports[:10]:
            output.append(f"  {imp.get('dll','?')}: {imp.get('count', 0)} functions")
    flags = result.get("flags") or []
    if flags:
        output.append(f"\nIOC flags ({len(flags)}):")
        for f in flags[:15]:
            output.append(f"  [{f.get('severity','?').upper()}] {f.get('detail','')}")
    det = (result.get("detection") or {}).get("detections") or []
    if det:
        output.append("\nDetections: " + ", ".join(d.get("name", "?") for d in det[:8]))
    return "\n".join(output)


# --- Search (unified) ---


@mcp.tool()
def tdc_search(query: str) -> str:
    """Search across all TDC data - processes, alerts, sysmon events - for a keyword.

    Useful for finding all activity related to a specific malware, tool name, IP, domain, etc.

    Args:
        query: Search term (e.g. 'mimikatz', 'powershell', '192.168.1.100', 'cmd.exe')
    """
    q = query.lower()
    results = {"processes": [], "alerts": [], "sysmon_events": []}

    # Search processes
    results["submissions"] = []
    procs = _get("/api/processes", params={"max": 0, "min_threats": 0, "sort": "threats",
                                           "include_parents": "true"}, timeout=60.0)
    for pid, proc in procs.items():
        searchable = " ".join([
            proc.get("name", ""), proc.get("image", ""),
            proc.get("command_line", ""), proc.get("user", ""), str(pid)
        ]).lower()
        if q in searchable:
            results["processes"].append({
                "pid": pid, "name": proc.get("name"),
                "cmdline": proc.get("command_line", "")[:150],
                "threats": proc.get("activity", {}).get("threats", 0),
            })

    # Search alerts
    alerts = _get("/api/alerts", timeout=120.0)  # full list, tens of MB
    for a in alerts:
        searchable = " ".join(str(x or "") for x in [
            a.get("rule_name"), a.get("process_name"), a.get("process_image"),
            a.get("command_line"), a.get("parent_command_line"), a.get("pid"),
            json.dumps(a.get("raw", {}), default=str),
        ]).lower()
        if q in searchable:
            results["alerts"].append({
                "timestamp": (a.get("timestamp") or "")[:19],
                "severity": a.get("severity"),
                "name": a.get("rule_name"),
                "pid": a.get("pid"),
                "process": a.get("process_name"),
            })

    # Search sysmon events
    events = _get("/api/sysmon", params={"max": 1000}, timeout=60.0)
    for ev in events if isinstance(events, list) else []:
        searchable = " ".join([
            ev.get("image", ""), ev.get("commandline", ""),
            ev.get("type", ""), ev.get("target", ""),
            ev.get("query", ""), ev.get("dst_ip", ""),
            ev.get("loaded_image", ""), str(ev.get("pid", "")),
        ]).lower()
        if q in searchable:
            results["sysmon_events"].append({
                "timestamp": ev.get("timestamp", "")[:19],
                "event_id": ev.get("event_id"),
                "type": ev.get("type"),
                "pid": ev.get("pid"),
                "image": (ev.get("image", "") or "").split("\\")[-1],
                "detail": ev.get("commandline", ev.get("target", ev.get("query", "")))[:100],
            })

    subs = _get("/api/submissions")
    for sub in subs if isinstance(subs, list) else subs.get("submissions", []):
        if q in " ".join(str(sub.get(k) or "") for k in ("filename", "sha256", "agent_pid", "file_path")).lower():
            results["submissions"].append(sub)

    # Format output
    lines = [f"Search results for '{query}':"]
    if results["submissions"]:
        lines.append(f"\n--- Submissions ({len(results['submissions'])}) ---")
        for sub in results["submissions"][:10]:
            lines.append(f"  [{(sub.get('timestamp') or '')[:19]}] {sub.get('filename')} "
                         f"pid={sub.get('agent_pid')} sha256={(sub.get('sha256') or '')[:16]}...")

    if results["processes"]:
        lines.append(f"\n--- Processes ({len(results['processes'])}) ---")
        for p in results["processes"][:15]:
            threat_mark = f" ⚠{p['threats']}" if p["threats"] > 0 else ""
            lines.append(f"  PID {p['pid']}: {p['name']}{threat_mark} | {p['cmdline']}")

    if results["alerts"]:
        lines.append(f"\n--- Alerts ({len(results['alerts'])}) ---")
        for a in results["alerts"][:20]:
            lines.append(f"  [{a['timestamp']}] [{a['severity']}] {a['name']} (pid={a['pid']} {a['process']})")

    if results["sysmon_events"]:
        lines.append(f"\n--- Sysmon Events ({len(results['sysmon_events'])}) ---")
        for ev in results["sysmon_events"][:20]:
            lines.append(f"  [{ev['timestamp']}] EID:{ev['event_id']} ({ev['type']}) PID:{ev['pid']} {ev['image']} | {ev['detail']}")

    total = sum(len(v) for v in results.values())
    if total == 0:
        return f"No results found for '{query}'."

    lines.append(f"\nTotal: {total} matches")
    return "\n".join(lines)


# --- PowerShell Commands ---


@mcp.tool()
def tdc_powershell_activity(pid: Optional[int] = None, max_events: int = 30) -> str:
    """Get PowerShell execution activity from Sysmon (ProcessCreate events with powershell).

    Args:
        pid: Optional PID to filter (shows powershell launched by this process)
        max_events: Maximum events to return
    """
    events = []
    if pid:
        # The process itself (if it is PowerShell) and everything it started.
        events += _get("/api/sysmon", params={"event_id": "1", "pid": pid, "max": 50})
        events += _get("/api/sysmon", params={"event_id": "1", "parent_pid": pid, "max": 500}, timeout=60.0)
    else:
        events = _get("/api/sysmon", params={"event_id": "1", "max": 1000}, timeout=60.0)
    events = [e for e in events if isinstance(e, dict) and "error" not in e]
    if not events or not isinstance(events, list):
        return "No Sysmon ProcessCreate events available."

    ps_events = []
    for ev in events:
        image = (ev.get("image", "") or "").lower()
        cmdline = (ev.get("commandline", "") or "").lower()
        if "powershell" not in image and "powershell" not in cmdline and "pwsh" not in image:
            continue
        if pid and str(ev.get("pid")) != str(pid) and str(ev.get("parent_pid")) != str(pid):
            continue
        ps_events.append(ev)

    if not ps_events:
        return "No PowerShell activity found."

    lines = [f"{len(ps_events)} PowerShell executions:"]
    for ev in ps_events[:max_events]:
        ts = ev.get("timestamp", "")[:19]
        epid = ev.get("pid", "?")
        ppid = ev.get("parent_pid", "?")
        cmd = ev.get("commandline", "")[:200]
        user = ev.get("user", "")
        lines.append(f"\n[{ts}] PID:{epid} (parent:{ppid}) User:{user}")
        lines.append(f"  {cmd}")

    return "\n".join(lines)


# --- Live memory (Aether, Process Dump, exit capture, evidence model) ---


def _fmt_evidence(ev: dict, limit: int = 8) -> list[str]:
    """Render a memory-evidence verdict as readable lines."""
    lines = [f"Verdict: {ev.get('label')} (score {ev.get('score')}; "
             f"suspicious >= {ev.get('thresholds', {}).get('suspicious')}, "
             f"malicious >= {ev.get('thresholds', {}).get('malicious')})"]
    if ev.get("note"):
        lines.append(f"Note: {ev['note']}")
    if ev.get("suppressed_count"):
        lines.append(f"{ev['suppressed_count']} finding(s) suppressed by the host baseline")
    for f in (ev.get("findings") or [])[:limit]:
        if not f.get("score"):
            continue
        why = [f"confidence {f.get('confidence')}"]
        if (f.get("samples") or 1) > 1:
            why.append(f"seen {f.get('seen_in')}/{f.get('samples')} samples")
        if f.get("corroborated_by"):
            why.append("corroborated by " + ", ".join(f["corroborated_by"]))
        lines.append(f"  {f['score']:5.2f}  {f.get('label')} [{f.get('source')}] - "
                     f"{(f.get('detail') or '')[:120]} ({'; '.join(why)})")
    return lines


@mcp.tool()
def tdc_memory_scan(pid: int, samples: int = 3, interval: int = 3) -> str:
    """Scan a running process's memory with Aether and score the findings.

    Repeated sampling separates findings that persist from memory that only
    briefly looked suspicious. The verdict comes from TDC's evidence model
    (evidence class, persistence, corroboration, host baseline), not from
    Aether's own severity labels.

    Args:
        pid: Process ID inside the analysis VM
        samples: Number of scans (1-10, default 3)
        interval: Seconds between scans (default 3)
    """
    result = _call("POST", "/api/scan/aether",
                   data={"pid": pid, "samples": samples, "interval": interval},
                   # server worst case: 180 s per sample plus the pauses
                   timeout=60.0 + samples * 180 + max(0, samples - 1) * min(interval, 30))
    if result.get("error"):
        return f"Error: {result['error']}"
    head = [f"Aether scan of PID {pid} ({result.get('process') or '?'}), "
            f"{result.get('samples')} sample(s)"]
    if result.get("observed") is False:
        head.append(result.get("observation_note") or "Nothing observed.")
    return "\n".join(head + _fmt_evidence(result.get("evidence") or {}))


@mcp.tool()
def tdc_memory_dump(pid: int, ignore_clean_db: bool = False) -> str:
    """Dump a running process's memory components to disk with Process Dump.

    Modules matching the clean-hash database are skipped, so the dump holds
    what is new on the box: unpacked payloads, hidden modules and header-less
    code chunks. Returned paths can be passed to tdc_file_map.

    Args:
        pid: Process ID inside the analysis VM
        ignore_clean_db: Also dump known-good modules (default False)
    """
    result = _call("POST", "/api/scan/processdump",
                   data={"pid": pid, "ignore_clean_db": str(ignore_clean_db).lower()},
                   timeout=360.0)
    if result.get("error"):
        return f"Error: {result['error']}"
    lines = [f"{result.get('dump_count')} dump(s) in {result.get('output_dir')}: "
             f"{result.get('hidden_modules')} hidden module(s), "
             f"{result.get('code_chunks')} code chunk(s)"
             + (f", {result['host_code_chunks']} host-explained chunk(s) (emulator cache)"
                if result.get("host_code_chunks") else "")]
    for d in (result.get("dumps") or [])[:40]:
        tag = f" [host: {d['host_class']}]" if d.get("host_class") else ""
        lines.append(f"  {d.get('kind'):13} {d.get('arch') or '':4} {d.get('size'):>9}  {d.get('path')}{tag}")
    return "\n".join(lines)


@mcp.tool()
def tdc_memory_evidence(pid: int) -> str:
    """Re-score every cached memory result for a PID across all sources.

    Combines Aether, Process Dump, exit-capture and beacon scanners into one
    verdict. Use after a detonation or after changing the host baseline.

    Args:
        pid: Process ID the results were recorded under
    """
    result = _call("POST", "/api/memory/evidence", data={"pid": pid}, timeout=60.0)
    if result.get("error"):
        return f"Error: {result['error']}"
    head = [f"PID {pid} ({result.get('process') or '?'}) - sources: "
            + ", ".join(result.get("sources") or [])]
    return "\n".join(head + _fmt_evidence(result.get("evidence") or {}, limit=12))


@mcp.tool()
def tdc_detonation_memory(pid: int, sha256: str = "") -> str:
    """Memory results of a detonation: live scans, exit capture, beaconing.

    Includes the analysis of the exit-time memory dump, which covers samples
    that terminated before any live scanner could reach them.

    Args:
        pid: PID returned by tdc_submit
        sha256: Sample hash (optional, helps match cached results)
    """
    params = {"pid": pid}
    if sha256:
        params["sha256"] = sha256
    d = _call("GET", "/api/detonation/results", params=params, timeout=60.0)
    lines = []
    ev = d.get("memory_evidence")
    if ev:
        lines.append("Sources: " + ", ".join(ev.get("sources_present") or []))
        lines += _fmt_evidence(ev, limit=12)
    else:
        lines.append("No memory results yet (scans run for ~1-2 minutes after detonation).")
    ec = d.get("exit_capture_result") or {}
    if ec.get("captured"):
        lines.append(f"Exit capture: {len(ec.get('artifacts') or [])} artifact(s) extracted")
        for a in (ec.get("artifacts") or [])[:10]:
            lines.append(f"  {a.get('kind'):18} {a.get('size'):>9}  {a.get('path')}")
    net = d.get("network_beaconing") or {}
    if net.get("available"):
        lines.append(f"Network: {net.get('connections')} connection(s) to "
                     f"{len(net.get('endpoints') or [])} endpoint(s)")
    return "\n".join(lines)


@mcp.tool()
def tdc_memory_baseline(action: str = "status", names: str = "") -> str:
    """Inspect or manage the host memory baseline.

    The baseline holds findings this host produces on its own (framework
    strings, pointer tables in explorer.exe ...). They stop counting as
    evidence. Capture only while the box is clean.

    Args:
        action: "status", "capture" (named processes), "sweep" (every process,
            runs in background) or "clear"
        names: Comma-separated image names for "capture" (default: the usual
            noisy processes)
    """
    if action == "status":
        d = _call("GET", "/api/memory/baseline")
        if d.get("stale"):
            return f"Baseline OUTDATED: {d.get('note')} ({d.get('stale_keys')} old key(s) ignored)"
        return (f"Baseline: {d.get('total')} key(s), updated {d.get('updated')}\n"
                + json.dumps(d.get("by_kind"), indent=2))
    if action == "capture":
        d = _call("POST", "/api/memory/baseline/capture",
                  data={"names": names} if names else {}, timeout=4500.0)
        if d.get("error"):
            return f"Error: {d['error']}"
        return (f"Captured {d.get('captured')} new key(s); total {d['baseline']['total']}\n"
                + "\n".join(f"  {s['process']} (PID {s['pid']}): {s['new_keys']} new"
                            for s in d.get("scanned") or []))
    if action == "sweep":
        d = _call("POST", "/api/memory/sweep", data={"aether": "true", "baseline": "true"})
        return "Baseline sweep started; check with tdc_memory_sweep_status." if d.get("started") \
            else f"Error: {d.get('error')}"
    if action == "clear":
        d = _call("DELETE", "/api/memory/baseline", timeout=15.0)
        return f"Error: {d['error']}" if d.get("error") else "Baseline cleared."
    return "Unknown action (use status, capture, sweep or clear)."


@mcp.tool()
def tdc_memory_sweep(dump_unknown: bool = False) -> str:
    """Start a background memory sweep of every process in the VM.

    Each process is scored against the host baseline. Takes several minutes;
    poll with tdc_memory_sweep_status.

    Args:
        dump_unknown: Also run Process Dump -system (slow, writes many files)
    """
    d = _call("POST", "/api/memory/sweep",
              data={"aether": "true", "processdump": str(dump_unknown).lower()})
    return "Sweep started." if d.get("started") else f"Error: {d.get('error')}"


@mcp.tool()
def tdc_memory_sweep_status() -> str:
    """Progress or result of the last memory sweep."""
    d = _call("GET", "/api/memory/sweep")
    if d.get("running"):
        return f"Sweep running for {d.get('elapsed_s')}s."
    if d.get("error"):
        return f"Sweep failed: {d['error']}"
    r = d.get("result")
    if not r:
        return "No sweep has run yet."
    flagged = [p for p in r.get("processes") or [] if p.get("score")]
    lines = [f"{r['mode']} sweep: {r['processes_seen']} processes in {r['duration_s']}s; "
             f"{len(flagged)} with findings beyond the baseline"]
    if r.get("excluded_host_tools"):
        lines.append("Excluded host tools: " + ", ".join(e["process"] for e in r["excluded_host_tools"]))
    for p in flagged[:20]:
        lines.append(f"  {p['label']:10} {p['score']:5}  {p['process']} (PID {p['pid']})")
        for reason in p.get("reasons", [])[:2]:
            lines.append(f"      {reason}")
    return "\n".join(lines)


@mcp.tool()
def tdc_file_map(path: str) -> str:
    """Structure overview of a PE/ELF file in the VM (sections, directories, imports).

    Works on dumped artifacts too, e.g. paths returned by tdc_memory_dump.

    Args:
        path: File path inside the analysis VM
    """
    d = _call("GET", "/api/file/visualize", params={"path": path, "rows": 64}, timeout=60.0)
    if d.get("error"):
        return f"Error: {d['error']}"
    lines = [f"{d.get('filename')}: {d.get('format')}, {d.get('file_size')} bytes, "
             f"entropy {d.get('total_entropy')}"]
    if d.get("parse_error"):
        lines.append(f"Parse error: {d['parse_error']}")
    for r in d.get("regions") or []:
        lines.append(f"  {r['offset']:#010x} {r['size']:>9}  {r['name']}")
    for t in (d.get("import_tree") or [])[:15]:
        susp = f", {t['suspicious_count']} suspicious" if t.get("suspicious_count") else ""
        lines.append(f"  import {t['dll']} ({t['count']}{susp})")
    return "\n".join(lines)


# --- File inspection (paths inside the VM) ---


@mcp.tool()
def tdc_file_hex(path: str, offset: int = 0, length: int = 256) -> str:
    """Hex dump of a file in the VM (e.g. at an offset reported by ThreatCheck,
    tdc_pe_analyze or tdc_file_map).

    Args:
        path: File path inside the analysis VM
        offset: Start offset in bytes (decimal)
        length: Number of bytes, at most 4096
    """
    d = _call("GET", "/api/file/hex",
              params={"path": path, "offset": max(0, offset), "bytes": max(1, min(length, 4096))})
    if d.get("error"):
        return f"Error: {d['error']}"
    return (f"{path} @ {d.get('offset')} ({d.get('bytes_shown')} of {d.get('size', '?')} bytes)\n"
            + (d.get("hex") or ""))


@mcp.tool()
def tdc_pe_section(path: str, index: int, max_bytes: int = 1024) -> str:
    """Inspect one PE section: characteristics, entropy, hex dump and its
    ASCII/UTF-16 strings. Section indexes come from tdc_pe_analyze.

    Args:
        path: PE file path inside the analysis VM
        index: Section index (0-based)
        max_bytes: Bytes of the hex dump (default 1024)
    """
    d = _call("GET", "/api/file/pe/section",
              params={"path": path, "index": index, "max_bytes": max(16, min(max_bytes, 65536))}, timeout=60.0)
    if d.get("error"):
        return f"Error: {d['error']}"
    lines = [f"Section {index} {d.get('name', '')}: characteristics {d.get('characteristics')}, "
             f"entropy {d.get('entropy')}",
             "Flags: " + ", ".join(f.get("flag", "?") for f in d.get("characteristic_flags") or [])]
    if d.get("hex_dump"):
        lines += ["", d["hex_dump"]]
    for key, label in (("strings", "ASCII strings"), ("wide_strings", "UTF-16 strings")):
        items = d.get(key) or []
        if items:
            lines.append(f"\n{label} ({d.get(key[:-1] + '_count', len(items))}):")
            for it in items[:40]:
                text = it.get("value") if isinstance(it, dict) else it
                off = it.get("offset") if isinstance(it, dict) else None
                lines.append(f"  {hex(off) if isinstance(off, int) else ''} {str(text)[:120]}")
    return "\n".join(lines)


@mcp.tool()
def tdc_elf_analyze(path: str) -> str:
    """Analyze an ELF file in the VM - header, hardening (PIE/NX/RELRO/canary),
    needed libraries, suspicious symbols and IOC flags.

    Args:
        path: ELF file path inside the analysis VM
    """
    d = _call("GET", "/api/file/elf", params={"path": path}, timeout=120.0)
    if d.get("error"):
        return f"Error: {d['error']}"
    h, sec = d.get("header") or {}, d.get("security") or {}
    lines = [f"{h.get('machine')} {h.get('type')}  entry {h.get('entry_point')}",
             "Hardening: " + ", ".join(f"{k}={v}" for k, v in sec.items()),
             f"Total entropy: {d.get('total_entropy')}"]
    if d.get("needed_libraries"):
        lines.append("Needs: " + ", ".join(d["needed_libraries"][:20]))
    sections = d.get("sections") or []
    if sections:
        lines.append(f"\nSections ({len(sections)}):")
        for s_ in sections[:30]:
            lines.append(f"  {str(s_.get('name')):<20} {s_.get('flags_str', ''):<5} size={s_.get('size')} "
                         f"entropy={s_.get('entropy')}")
    flags = d.get("flags") or []
    if flags:
        lines.append(f"\nIOC flags ({len(flags)}):")
        lines += [f"  [{(f.get('severity') or '?').upper()}] {f.get('detail')}" for f in flags[:20]]
    return "\n".join(lines)


@mcp.tool()
def tdc_file_signature(path: str) -> str:
    """Check a file's Authenticode signature in the VM: signed or not, signer,
    issuer, trust status and whether a signature blob is embedded.

    Args:
        path: File path inside the analysis VM
    """
    d = _call("GET", "/api/file/signature", params={"path": path}, timeout=60.0)
    if d.get("error"):
        return f"Error: {d['error']}"
    signer = d.get("signer") or {}
    lines = [f"{path}: {'signed' if d.get('signed') else 'NOT signed'}, "
             f"{'trusted' if d.get('trusted') else 'not trusted'} - {d.get('status', '?')}"
             + (f" ({d['status_message']})" if d.get('status_message') else "")]
    if signer:
        lines += [f"Signer: {signer.get('subject')}", f"Issuer: {signer.get('issuer')}",
                  f"Serial: {signer.get('serial')}  Thumbprint: {signer.get('thumbprint')}",
                  f"Valid: {signer.get('valid_from')} .. {signer.get('valid_to')}"]
    emb = d.get("embedded") or {}
    if emb.get("has_embedded"):
        lines.append(f"Embedded signature at offset {emb.get('offset')} ({emb.get('size')} bytes)")
    return "\n".join(lines)


# --- Beacon scanners, scan history, tool status ---


@mcp.tool()
def tdc_scan_beacons(pid: Optional[int] = None) -> str:
    """Run Hunt-Sleeping-Beacons: finds threads that sleep in suspicious ways
    (beacon-style waits, abnormal call stacks). Without a PID it scans all processes.

    Args:
        pid: Process to scan (omit for all)
    """
    d = _call("POST", "/api/scan/beacons", data={"pid": pid} if pid else {}, timeout=120.0)
    if d.get("error"):
        return f"Error: {d['error']}"
    lines = [f"Hunt-Sleeping-Beacons: {d.get('suspicious_count', 0)} suspicious process(es)"]
    if d.get("limitation"):
        lines.append(f"Limited: {d['limitation']}")
    for f in (d.get("findings") or [])[:20]:
        lines.append(f"  {f.get('process')} (PID {f.get('pid')}) [{f.get('severity')}]")
        lines += [f"    thread {x.get('thread')}: {x.get('title')} - {x.get('detail')} ({x.get('severity')})"
                  for x in (f.get("detections") or [])[:10]]
    summary = [l for l in (d.get("output") or "").splitlines() if l.strip().startswith("* Scanned")]
    if summary:
        lines.append(summary[-1].strip())
    return "\n".join(lines)


@mcp.tool()
def tdc_scan_beaconeye(pid: Optional[int] = None) -> str:
    """Run BeaconEye: searches process memory for Cobalt Strike beacon
    configurations. Without a PID it scans all processes.

    Args:
        pid: Process to scan (omit for all)
    """
    d = _call("POST", "/api/scan/beaconeye", data={"pid": pid} if pid else {}, timeout=150.0)
    if d.get("error"):
        return f"Error: {d['error']}"
    lines = [f"BeaconEye: {d.get('beacons_found', 0)} beacon(s)"]
    if d.get("limitation"):
        lines.append(f"Limited: {d['limitation']}")
    for f in (d.get("findings") or [])[:10]:
        lines.append(f"  {f.get('summary')}")
        lines += [f"    {k}: {v}" for k, v in (f.get("config") or {}).items() if k != "c2"][:25]
    summary = [l for l in (d.get("output") or "").splitlines() if l.strip().startswith("[+] Scanned")]
    if summary:
        lines.append(summary[-1].strip())
    return "\n".join(lines)


@mcp.tool()
def tdc_scan_history(limit: int = 20) -> str:
    """List recent static scans (EMBER, capa, ThreatCheck, DefenderCheck) with
    their verdicts, newest first.

    Args:
        limit: Number of entries (default 20)
    """
    d = _call("GET", "/api/scan/history", params={"limit": limit})
    if d.get("error"):
        return f"Error: {d['error']}"
    items = d.get("history") or []
    if not items:
        return "No scans recorded."
    return f"{len(items)} scan(s):\n" + "\n".join(
        f"  [{(h.get('timestamp') or '')[:19]}] {h.get('tool'):<14} {h.get('filename')} -> "
        f"{h.get('verdict') or h.get('status')}"
        + (f" (score {h['score']})" if h.get("score") is not None else "")
        + (f" sha256={h['sha256'][:16]}..." if h.get("sha256") else "")
        for h in items)


@mcp.tool()
def tdc_tools_status() -> str:
    """Which analysis tools are installed on the VM (Aether, Process Dump,
    exit capture, EMBER, capa, ThreatCheck, DefenderCheck, BeaconEye, ...)."""
    d = _call("GET", "/api/scan/status")
    if d.get("error"):
        return f"Error: {d['error']}"
    lines = []
    for name, info in sorted(d.items()):
        if not isinstance(info, dict):
            continue
        state = "installed" if info.get("installed") else "NOT installed"
        extra = {k: v for k, v in info.items() if k not in ("installed", "path")}
        lines.append(f"  {'✓' if info.get('installed') else '✗'} {name:<20} {state}"
                     + (f"  {json.dumps(extra, default=str)[:160]}" if extra else ""))
    return "Analysis tools:\n" + "\n".join(lines)


@mcp.tool()
def tdc_processdump_baseline(action: str = "status", mode: str = "genquick") -> str:
    """Process Dump's clean-hash database (modules it skips when dumping).

    Args:
        action: 'status' or 'build' (run on a clean VM; 'gen' takes 20+ minutes)
        mode: For build: 'genquick' (fast) or 'gen' (full)
    """
    if action == "build":
        d = _call("POST", "/api/processdump/baseline", data={"mode": mode}, timeout=30.0)
        return f"Error: {d['error']}" if d.get("error") else f"Build started ({mode}): {json.dumps(d, default=str)}"
    d = _call("GET", "/api/processdump/baseline")
    if d.get("error"):
        return f"Error: {d['error']}"
    files = ", ".join(f"{k} {v}" for k, v in (d.get("files") or {}).items())
    return f"Clean-hash database: {files or 'empty'}{' (build running)' if d.get('running') else ''}"


@mcp.tool()
def tdc_rustinel_info() -> str:
    """Rustinel EDR engine details: loaded Sigma/YARA/IOC rules, ETW providers, alert count."""
    d = _call("GET", "/api/rustinel")
    if d.get("error"):
        return f"Error: {d['error']}"
    rules = d.get("rules") or {}
    lines = [f"Rustinel {d.get('version') or ''} - {d.get('alerts_count')} alerts in {d.get('alerts_dir')}",
             "Rules: " + ", ".join(f"{k} {v}" for k, v in rules.items() if not isinstance(v, dict)),
             "ETW providers: " + ", ".join(p.get("name", "?") for p in d.get("etw_providers") or [])]
    return "\n".join(lines)


if __name__ == "__main__":
    mcp.run()
