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


def _get(path: str, params: dict | None = None, timeout: float = 15.0) -> dict | list:
    """GET request to TDC API."""
    r = httpx.get(f"{TDC_BASE_URL}{path}", params=params, timeout=timeout)
    r.raise_for_status()
    return r.json()


def _post(path: str, data: dict | None = None, files: dict | None = None, timeout: float = 60.0) -> dict | list:
    """POST request to TDC API."""
    r = httpx.post(f"{TDC_BASE_URL}{path}", data=data, files=files, timeout=timeout)
    r.raise_for_status()
    return r.json()


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
        channel: ETW channel (sysmon, security, powershell, defender, wmi, applocker, firewall, dns, bits, taskscheduler, rdp, application, system)
        max_events: Maximum events to return (default 20)
        event_id: Filter by specific Windows Event ID
    """
    params = {"channel": channel, "max": max_events}
    if event_id:
        params["event_id"] = event_id
    events = _get("/api/etw/events", params=params)
    if not events:
        return f"No ETW events from channel '{channel}'."
    if isinstance(events, dict) and events.get("error"):
        return f"Error: {events['error']}"

    lines = []
    for ev in events if isinstance(events, list) else []:
        ts = ev.get("timestamp", "")[:19]
        eid = ev.get("event_id", "?")
        msg = ev.get("message", "")[:150]
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
    max_alerts: int = 30,
) -> str:
    """Query security alerts from Rustinel/Fibratus detection engines.

    Args:
        severity: Filter by severity (critical, high, medium, low)
        engine: Filter by detection engine (rustinel, fibratus)
        pid: Filter by Process ID
        max_alerts: Maximum alerts to return (default 30)
    """
    params = {}
    if severity:
        params["severity"] = severity
    if engine:
        params["engine"] = engine
    if pid:
        params["pid"] = pid
    alerts = _get("/api/alerts", params=params)
    if not alerts:
        return "No alerts found."

    alerts = alerts[:max_alerts]
    lines = []
    for a in alerts:
        ts = a.get("timestamp", "")[:19]
        sev = a.get("severity", "?").upper()
        name = a.get("name", a.get("rule", "unknown"))
        eng = a.get("engine", "?")
        apid = a.get("pid", "")
        proc = a.get("process_name", "")
        lines.append(f"[{ts}] [{sev}] {name} (engine={eng}, pid={apid}, proc={proc})")

    header = f"{len(alerts)} alerts"
    if len(alerts) < len(_get("/api/alerts", params=params)):
        header += f" (showing first {max_alerts})"
    return header + ":\n" + "\n".join(lines)


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
def tdc_process_detail(pid: int) -> str:
    """Get detailed information about a specific process by PID.

    Args:
        pid: Process ID to inspect
    """
    try:
        proc = _get(f"/api/processes/{pid}")
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            return f"Process {pid} not found."
        raise
    return json.dumps(proc, indent=2, default=str)


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
        result = _post("/api/submit", data=data, files=files, timeout=120.0)
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
        status = sub.get("status", "?")
        pid = sub.get("agent_pid", "")
        lines.append(f"[{ts}] {fname} (sha256={sha}...) status={status} pid={pid}")
    return f"{len(entries)} submissions:\n" + "\n".join(lines)


@mcp.tool()
def tdc_detonation_results(sha256: Optional[str] = None, pid: Optional[int] = None) -> str:
    """Get detonation/analysis results for a sample.

    Args:
        sha256: SHA256 hash of the sample
        pid: Process ID from detonation
    """
    params = {}
    if sha256:
        params["sha256"] = sha256
    if pid:
        params["pid"] = pid
    results = _get("/api/detonation/results", params=params, timeout=30.0)
    return json.dumps(results, indent=2, default=str)[:4000]


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
        result = _post("/api/scan/threatcheck", files=files, timeout=120.0)
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
        result = _post("/api/scan/defendercheck", files=files, timeout=120.0)
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
        result = _post("/api/scan/ember", data=data, files=files, timeout=120.0)
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
        result = _post("/api/scan/capa", files=files, timeout=300.0)
    return json.dumps(result, indent=2, default=str)[:6000]


# --- PE Analysis ---


@mcp.tool()
def tdc_pe_analyze(file_path: str) -> str:
    """Analyze a PE (Portable Executable) file - headers, sections, imports, exports, packing indicators.

    Args:
        file_path: Local path to the PE file
    """
    if not os.path.isfile(file_path):
        return f"Error: File not found: {file_path}"

    with open(file_path, "rb") as f:
        files = {"file": (os.path.basename(file_path), f)}
        result = _post("/api/file/pe", files=files, timeout=30.0)

    if isinstance(result, dict) and result.get("error"):
        return f"Error: {result['error']}"

    output = []
    if isinstance(result, dict):
        if "headers" in result:
            h = result["headers"]
            output.append(f"Machine: {h.get('machine', '?')}")
            output.append(f"Compiled: {h.get('timestamp', '?')}")
            output.append(f"Subsystem: {h.get('subsystem', '?')}")
            output.append(f"Entry Point: {h.get('entry_point', '?')}")
        if "sections" in result:
            output.append(f"\nSections ({len(result['sections'])}):")
            for s in result["sections"]:
                output.append(f"  {s.get('name','?'):<10} VSize={s.get('virtual_size',0):>8}  RSize={s.get('raw_size',0):>8}  Entropy={s.get('entropy',0):.2f}")
        if "imports" in result:
            output.append(f"\nImports ({len(result['imports'])} DLLs):")
            for imp in result["imports"][:10]:
                output.append(f"  {imp.get('dll','?')}: {len(imp.get('functions',[]))} functions")
        if "packing" in result:
            p = result["packing"]
            output.append(f"\nPacking indicators: {json.dumps(p, default=str)}")

    return "\n".join(output) if output else json.dumps(result, indent=2, default=str)[:3000]


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
    procs = _get("/api/processes", params={"max": 200, "sort": "threats", "include_parents": "true"})
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
    alerts = _get("/api/alerts")
    for a in alerts:
        searchable = " ".join([
            a.get("name", ""), a.get("rule", ""),
            a.get("process_name", ""), str(a.get("pid", "")),
            json.dumps(a.get("raw", {}), default=str),
        ]).lower()
        if q in searchable:
            results["alerts"].append({
                "timestamp": a.get("timestamp", "")[:19],
                "severity": a.get("severity"),
                "name": a.get("name", a.get("rule")),
                "pid": a.get("pid"),
                "process": a.get("process_name"),
            })

    # Search sysmon events
    events = _get("/api/sysmon", params={"max": 200})
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

    # Format output
    lines = [f"Search results for '{query}':"]

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
    events = _get("/api/sysmon", params={"event_id": "1", "max": max_events * 3})
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


if __name__ == "__main__":
    mcp.run()
