"""Tool catalog and update checks for the Tool Updates section.

Everything here only looks: installed version, available version, status.
Installing is done by the update runner with the install scripts. The checks
talk to the system through an injected ``Env`` (processes, HTTP, files), so
the tests run without a VM and without a network.

Every check ends in an entry dict::

    {id, name, kind, installed, available, status, pinned, detail, log,
     updated_at}

``status`` is one of up_to_date, update_available, pinned_update, unknown,
not_installed, offline, error (the runner adds queued, updating, updated,
failed and reboot_required). A failure in one tool becomes ``error`` with a
one-line detail and never stops the check of the others.
"""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Dict, List, NamedTuple, Optional

import requests

CHECK_TIMEOUT = 60
CHOCO_TIMEOUT = 180
HTTP_TIMEOUT = 20
PROBE_TIMEOUT = 5
OFFLINE_DETAIL = "No internet access from the VM"
GITHUB_API = "https://api.github.com"

SYSMON_BINARY_URL = "https://download.sysinternals.com/files/Sysmon.zip"
SYSMON_CONFIG_URL = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"

CHOCO_CONSUMERS = {
    "python312": ["task:LitterBox", "task:DetonatorAPI", "task:DetonatorUI"],
    "dotnet-8.0-sdk": ["task:DetonatorAgent"],
    "php": ["task:theZoo-WebUI"],
}


class RunResult(NamedTuple):
    returncode: int
    stdout: str
    stderr: str


class HttpResult(NamedTuple):
    status: int
    headers: dict
    json: Any
    text: str


def _as_text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value or ""


class Env:
    """The real environment: subprocesses, HTTP and the file system."""

    def run(self, args: List[str], timeout: float) -> RunResult:
        # Popen instead of subprocess.run: on timeout the whole process tree
        # is killed, because grandchildren (git-remote-https, choco, scripts)
        # keep the pipes open and run() would block in communicate().
        windows = os.name == "nt"
        kwargs: Dict[str, Any] = {}
        if windows:
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        else:
            kwargs["start_new_session"] = True
        child_env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
        try:
            proc = subprocess.Popen(
                args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                encoding="utf-8", errors="replace", env=child_env, **kwargs)
        except FileNotFoundError:
            return RunResult(127, "", "not found: %s" % args[0])
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            self._kill_tree(proc, windows)
            try:
                out, err = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired as late:
                out, err = _as_text(late.stdout), _as_text(late.stderr)
            note = "timed out after %ss" % timeout
            return RunResult(124, out or "", ((err or "").rstrip() + "\n" + note).strip())
        return RunResult(proc.returncode, out or "", err or "")

    @staticmethod
    def _kill_tree(proc, windows: bool) -> None:
        try:
            if windows:
                subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)], stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            else:
                os.killpg(proc.pid, signal.SIGKILL)
        except (OSError, subprocess.SubprocessError):
            pass
        try:
            proc.kill()
        except OSError:
            pass

    def http_get(self, url: str, timeout: float, method: str = "GET") -> HttpResult:
        headers = {"User-Agent": "tdc-tool-updates"}
        if url.startswith(GITHUB_API):
            headers["Accept"] = "application/vnd.github+json"
            token = os.environ.get("TDC_GITHUB_TOKEN")
            if token:
                headers["Authorization"] = "Bearer " + token
        try:
            resp = requests.request(method, url, headers=headers, timeout=timeout, allow_redirects=True)
        except requests.RequestException as exc:
            return HttpResult(0, {}, None, str(exc))
        payload = None
        if method == "GET":
            try:
                payload = resp.json()
            except ValueError:
                payload = None
        lowered = {str(k).lower(): v for k, v in resp.headers.items()}
        return HttpResult(resp.status_code, lowered, payload, resp.text if method == "GET" else "")

    def exists(self, path: str) -> bool:
        return os.path.exists(path)

    def read_text(self, path: str) -> Optional[str]:
        try:
            with open(path, encoding="utf-8-sig", errors="replace") as handle:
                return handle.read()
        except OSError:
            return None


@dataclass
class ToolSpec:
    id: str
    name: str
    kind: str  # choco | winget | git | release | sysinternals
    path: Optional[str]
    repo: Optional[str] = None
    version_cmd: Optional[List[str]] = None
    version_regex: Optional[str] = None
    marker: Optional[str] = None
    script: Optional[str] = None
    script_args: List[str] = field(default_factory=list)
    pinned: Optional[str] = None
    consumers: List[str] = field(default_factory=list)
    network: bool = True
    # sysinternals: the URL whose ETag is compared, and its key in tdc-source.json
    url: Optional[str] = None
    etag_key: Optional[str] = None
    # status when ``path`` is missing
    missing_status: str = "not_installed"


SEMVER = r"(\d+\.\d+\.\d+)"
SYSMON_MARKER = "C:\\tools\\sysmon\\tdc-source.json"

CATALOG: List[ToolSpec] = [
    ToolSpec("windbg", "WinDbg", "winget", None, script=None),
    ToolSpec("rustinel_rules", "Rustinel rules", "git", "C:\\tools\\detection-rules\\rustinel-rules",
             script="install-detection-rules.ps1"),
    ToolSpec("elastic_rules", "Elastic YARA rules", "git", "C:\\tools\\detection-rules\\elastic-protections",
             script="install-detection-rules.ps1"),
    ToolSpec("detonator_agent", "DetonatorAgent", "git", "C:\\DetonatorAgent",
             script="install-detonator.ps1", consumers=["task:DetonatorAgent"]),
    ToolSpec("detonator", "Detonator", "git", "C:\\detonator",
             script="install-detonator.ps1", consumers=["task:DetonatorAPI", "task:DetonatorUI"]),
    ToolSpec("litterbox", "LitterBox", "git", "C:\\LitterBox",
             script="install-litterbox.ps1", consumers=["task:LitterBox"]),
    ToolSpec("thezoo_webui", "theZoo WebUI", "git", "C:\\tools\\theZoo-WebUI",
             script="install-thezoo.ps1", consumers=["task:theZoo-WebUI"]),
    ToolSpec("thezoo", "theZoo", "git", "C:\\tools\\theZoo-WebUI\\theZoo",
             script="install-thezoo.ps1", consumers=["task:theZoo-WebUI"]),
    ToolSpec("hunt_sleeping_beacons", "Hunt-Sleeping-Beacons", "git", "C:\\tools\\Hunt-Sleeping-Beacons-src",
             script="install-hunt-sleeping-beacons.ps1"),
    ToolSpec("ember", "EMBER2024", "git", "C:\\tools\\EMBER2024\\EMBER2024",
             script="install-ember.ps1"),
    ToolSpec("aether", "Aether", "git", "C:\\tools\\Aether-src",
             script="install-aether.ps1", script_args=["-NoPrebuilt", "-Force"], missing_status="unknown"),
    ToolSpec("capa", "capa", "release", "C:\\tools\\capa\\capa.exe", repo="mandiant/capa",
             version_cmd=["C:\\tools\\capa\\capa.exe", "--version"], version_regex=SEMVER,
             marker="C:\\tools\\capa\\tdc-release.txt",
             script="install-capa.ps1", script_args=["-Force"]),
    ToolSpec("beaconeye", "BeaconEye", "release", "C:\\tools\\BeaconEye\\BeaconEye.exe", repo="CCob/BeaconEye",
             marker="C:\\tools\\BeaconEye\\tdc-release.txt",
             script="install-beaconeye.ps1", script_args=["-Force"]),
    ToolSpec("process_dump", "Process Dump", "release", "C:\\tools\\ProcessDump\\pd64.exe",
             repo="glmcdona/Process-Dump", marker="C:\\tools\\ProcessDump\\tdc-release.txt",
             script="install-process-dump.ps1", script_args=["-Force"]),
    ToolSpec("threatcheck", "ThreatCheck", "release", "C:\\tools\\ThreatCheck\\bin\\ThreatCheck.exe",
             repo="rasta-mouse/ThreatCheck", marker="C:\\tools\\ThreatCheck\\tdc-release.txt",
             script="install-scanner-tools.ps1", script_args=["-Force", "-Only", "ThreatCheck"]),
    ToolSpec("defendercheck", "DefenderCheck", "release", "C:\\tools\\DefenderCheck\\bin\\DefenderCheck.exe",
             repo="matterpreter/DefenderCheck", marker="C:\\tools\\DefenderCheck\\tdc-release.txt",
             script="install-scanner-tools.ps1", script_args=["-Force", "-Only", "DefenderCheck"]),
    ToolSpec("rustinel", "Rustinel", "release", "C:\\tools\\rustinel\\rustinel.exe", repo="Karib0u/rustinel",
             version_cmd=["C:\\tools\\rustinel\\rustinel.exe", "--version"], version_regex=SEMVER,
             marker="C:\\tools\\rustinel\\tdc-release.txt",
             script="install-rustinel.ps1", script_args=["-Force"], pinned="1.1.1",
             consumers=["task:Rustinel", "service:Rustinel"]),
    ToolSpec("fibratus", "Fibratus", "release", "C:\\Program Files\\Fibratus\\Bin\\fibratus.exe",
             repo="rabbitstack/fibratus",
             version_cmd=["C:\\Program Files\\Fibratus\\Bin\\fibratus.exe", "version"], version_regex=SEMVER,
             marker="C:\\Program Files\\Fibratus\\tdc-release.txt",
             script="install-fibratus.ps1", script_args=["-Force"], pinned="3.0.0",
             consumers=["service:fibratus"]),
    ToolSpec("rizin", "Rizin (Cutter)", "release", "C:\\tools\\cutter\\rizin.exe", repo="rizinorg/cutter",
             version_regex=r"Cutter-v(\S+?)-Windows", marker="C:\\tools\\cutter\\tdc-package.txt",
             script="install-rizin.ps1", script_args=[], pinned="2.5.0", consumers=["rizin_sessions"]),
    ToolSpec("sysmon", "Sysmon", "sysinternals", "C:\\tools\\sysmon", marker=SYSMON_MARKER,
             script="install-sysmon.ps1", script_args=["-Force"],
             url=SYSMON_BINARY_URL, etag_key="binary_etag"),
    ToolSpec("sysmon_config", "Sysmon config", "sysinternals", "C:\\tools\\sysmon", marker=SYSMON_MARKER,
             script="install-sysmon.ps1", script_args=[],
             url=SYSMON_CONFIG_URL, etag_key="config_etag"),
]

WINGET_IDS = {"windbg": "Microsoft.WinDbg"}


def normalize_version(s: str) -> str:
    s = (s or "").strip()
    if s[:1] in ("v", "V"):
        s = s[1:]
    return s.strip()


def compare_versions(a: str, b: str) -> int:
    pa = [p for p in re.split(r"[.\-_+]", normalize_version(a)) if p != ""]
    pb = [p for p in re.split(r"[.\-_+]", normalize_version(b)) if p != ""]
    for i in range(max(len(pa), len(pb))):
        x = pa[i] if i < len(pa) else "0"
        y = pb[i] if i < len(pb) else "0"
        if x.isdigit() and y.isdigit():
            x, y = int(x), int(y)
        else:
            x, y = str(x).lower(), str(y).lower()
        if x != y:
            return -1 if x < y else 1
    return 0


def parse_choco_outdated(text: str) -> List[Dict[str, Any]]:
    rows = []
    for line in (text or "").splitlines():
        parts = line.strip().split("|")
        if len(parts) != 4 or not parts[0] or " " in parts[0]:
            continue
        rows.append({"package": parts[0], "current": parts[1], "available": parts[2],
                     "pinned": parts[3].strip().lower() == "true"})
    return rows


def _one_line(value: Any, limit: int = 200) -> str:
    text = str(value).strip()
    line = text.splitlines()[0].strip() if text else ""
    if not line:
        line = type(value).__name__ if isinstance(value, BaseException) else "unknown error"
    elif isinstance(value, BaseException) and type(value) is not Exception:
        line = "%s: %s" % (type(value).__name__, line)
    return line[:limit]


def _entry(spec, installed=None, available=None, status="unknown", detail="") -> Dict[str, Any]:
    return {"id": spec.id, "name": spec.name, "kind": spec.kind, "installed": installed,
            "available": available, "status": status, "pinned": spec.pinned, "detail": detail,
            "log": [], "updated_at": None}


def check_choco(env) -> List[Dict[str, Any]]:
    res = env.run(["choco", "outdated", "-r", "--ignore-unfound", "--limit-output"], CHOCO_TIMEOUT)
    if res.returncode == 127:
        return [{"id": "choco", "name": "Chocolatey", "kind": "choco", "installed": None,
                 "available": None, "status": "not_installed", "pinned": None,
                 "detail": "Chocolatey is not installed", "log": [], "updated_at": None}]
    rows = parse_choco_outdated(res.stdout)
    # choco may exit with 2 when packages are outdated; any other failure
    # must not look like "all packages are current"
    if res.returncode == 124 or (res.returncode not in (0, 2) and not rows):
        if res.returncode == 124:
            detail = "choco outdated timed out"
        else:
            detail = _one_line(res.stderr or res.stdout or "choco outdated failed (exit %d)" % res.returncode)
        return [{"id": "choco", "name": "Chocolatey", "kind": "choco", "installed": None,
                 "available": None, "status": "error", "pinned": None,
                 "detail": detail, "log": [], "updated_at": None}]
    entries = []
    for row in rows:
        pinned = row["pinned"]
        entries.append({
            "id": "choco:" + row["package"], "name": row["package"], "kind": "choco",
            "installed": row["current"], "available": row["available"],
            "status": "pinned_update" if pinned else "update_available",
            "pinned": row["current"] if pinned else None,
            "detail": "Pinned in Chocolatey; unpin it to upgrade" if pinned else "",
            "log": [], "updated_at": None})
    return entries


def _git(env, path: str, *args: str) -> RunResult:
    return env.run(["git", "-c", "safe.directory=*", "-C", path] + list(args), CHECK_TIMEOUT)


def _check_git(spec, env) -> Dict[str, Any]:
    fetched = _git(env, spec.path, "fetch", "--quiet")
    if fetched.returncode != 0:
        return _entry(spec, status="error", detail=_one_line(fetched.stderr or fetched.stdout or "git fetch failed"))
    head = _git(env, spec.path, "rev-parse", "--short", "HEAD")
    if head.returncode != 0:
        return _entry(spec, status="error", detail=_one_line(head.stderr or "git rev-parse failed"))
    installed = head.stdout.strip()
    upstream = _git(env, spec.path, "rev-parse", "--short", "@{u}")
    if upstream.returncode != 0:
        return _entry(spec, installed=installed, status="unknown", detail="No upstream branch to compare with")
    available = upstream.stdout.strip()
    behind = _git(env, spec.path, "rev-list", "--count", "HEAD..@{u}")
    if behind.returncode != 0:
        return _entry(spec, installed, available, "error",
                      _one_line(behind.stderr or "git rev-list failed"))
    try:
        count = int(behind.stdout.strip())
    except ValueError:
        return _entry(spec, installed, available, "error", "git rev-list gave no number")
    if count > 0:
        return _entry(spec, installed, available, "update_available",
                      "%d new commit%s" % (count, "" if count == 1 else "s"))
    return _entry(spec, installed, available, "up_to_date")


def _first_line(text: Optional[str]) -> str:
    for line in (text or "").splitlines():
        if line.strip():
            return line.strip()
    return ""


def _regex_group(pattern: Optional[str], text: str) -> Optional[str]:
    if not pattern:
        return None
    m = re.search(pattern, text)
    if not m:
        return None
    return m.group(1) if m.groups() else m.group(0)


def _installed_release(spec, env) -> str:
    if spec.version_cmd:
        res = env.run(spec.version_cmd, CHECK_TIMEOUT)
        if res.returncode == 0:
            found = _regex_group(spec.version_regex, res.stdout + "\n" + res.stderr)
            if found:
                return normalize_version(found)
    if spec.marker:
        line = _first_line(env.read_text(spec.marker))
        if line:
            found = _regex_group(spec.version_regex, line) if spec.version_regex else None
            return normalize_version(found or line)
    return "unknown"


def _github_latest(spec, env):
    """The latest release tag, or (None, error-detail)."""
    res = env.http_get("%s/repos/%s/releases/latest" % (GITHUB_API, spec.repo), HTTP_TIMEOUT)
    if res.status == 0:
        return None, "GitHub is not reachable"
    if res.status in (403, 429) and str(res.headers.get("x-ratelimit-remaining", "")) == "0":
        return None, "GitHub API rate limit reached; set TDC_GITHUB_TOKEN to raise it"
    if res.status != 200 or not isinstance(res.json, dict) or not res.json.get("tag_name"):
        return None, "GitHub API answered HTTP %d for %s" % (res.status, spec.repo)
    return normalize_version(str(res.json["tag_name"])), ""


def _check_release(spec, env) -> Dict[str, Any]:
    installed = _installed_release(spec, env)
    available, problem = _github_latest(spec, env)
    if available is None:
        return _entry(spec, installed, None, "error", problem)
    newer = installed == "unknown" or compare_versions(installed, available) < 0
    if not newer:
        return _entry(spec, installed, available, "up_to_date")
    if spec.pinned:
        detail = "Pinned to %s for compatibility; %s is available" % (spec.pinned, available)
        return _entry(spec, installed, available, "pinned_update", detail)
    detail = "Installed version unknown; an update records it" if installed == "unknown" else ""
    return _entry(spec, installed, available, "update_available", detail)


def _etag(value: Any) -> str:
    text = str(value or "").strip()
    if text.startswith("W/"):
        text = text[2:]
    return text.strip('"')


def _check_sysinternals(spec, env) -> Dict[str, Any]:
    recorded = ""
    try:
        data = json.loads(env.read_text(spec.marker) or "")
        if isinstance(data, dict):
            recorded = _etag(data.get(spec.etag_key))
    except ValueError:
        recorded = ""
    res = env.http_get(spec.url, HTTP_TIMEOUT, method="HEAD")
    if res.status == 0:
        return _entry(spec, recorded or None, None, "error", "Download server is not reachable")
    if res.status != 200:
        return _entry(spec, recorded or None, None, "error", "HEAD %s answered HTTP %d" % (spec.url, res.status))
    current = _etag(res.headers.get("etag"))
    if not current:
        return _entry(spec, recorded or None, None, "unknown", "The server sent no ETag")
    if not recorded:
        return _entry(spec, None, current, "unknown", "Not checked yet; an update records the current version")
    if recorded != current:
        return _entry(spec, recorded, current, "update_available", "The download changed since the install")
    return _entry(spec, recorded, current, "up_to_date")


# winget's "no installed package found matching input criteria", signed and unsigned
WINGET_NO_MATCH = (-1978335212, 2316632084)


def _winget_error(spec, res) -> Dict[str, Any]:
    detail = _one_line(res.stderr.strip() or res.stdout.strip() or "winget failed (exit %d)" % res.returncode)
    return _entry(spec, status="error", detail=detail)


def _check_winget(spec, env) -> Dict[str, Any]:
    winget_id = WINGET_IDS.get(spec.id, spec.id)
    res = env.run(["winget", "list", "--id", winget_id, "--upgrade-available",
                   "--accept-source-agreements"], CHECK_TIMEOUT)
    if res.returncode == 127:
        return _entry(spec, status="unknown", detail="winget is not available for SYSTEM")
    if res.returncode not in (0,) + WINGET_NO_MATCH:
        return _winget_error(spec, res)
    for line in res.stdout.splitlines():
        tokens = line.split()
        if winget_id in tokens:
            i = tokens.index(winget_id)
            installed = tokens[i + 1] if len(tokens) > i + 1 else None
            available = tokens[i + 2] if len(tokens) > i + 2 and re.search(r"\d", tokens[i + 2]) else None
            return _entry(spec, installed, available, "update_available")
    listed = env.run(["winget", "list", "--id", winget_id, "--accept-source-agreements"], CHECK_TIMEOUT)
    if listed.returncode not in (0,) + WINGET_NO_MATCH:
        return _winget_error(spec, listed)
    if listed.returncode in WINGET_NO_MATCH or winget_id not in listed.stdout:
        return _entry(spec, status="not_installed")
    return _entry(spec, status="up_to_date")


def _present(spec, env) -> bool:
    if spec.path is None:
        return True
    return env.exists(spec.path + "\\.git" if spec.kind == "git" else spec.path)


def check_tool(spec: ToolSpec, env) -> Dict[str, Any]:
    try:
        if not _present(spec, env):
            return _entry(spec, status=spec.missing_status,
                          detail="Source folder not found" if spec.missing_status == "unknown" else "")
        if spec.kind == "git":
            return _check_git(spec, env)
        if spec.kind == "release":
            return _check_release(spec, env)
        if spec.kind == "sysinternals":
            return _check_sysinternals(spec, env)
        if spec.kind == "winget":
            return _check_winget(spec, env)
        return _entry(spec, status="error", detail="Unknown tool kind: %s" % spec.kind)
    except Exception as exc:  # one tool never breaks the check of the others
        return _entry(spec, status="error", detail=_one_line(exc))


def check_all(env, max_workers: int = 4) -> List[Dict[str, Any]]:
    probe = env.http_get(GITHUB_API, timeout=PROBE_TIMEOUT)
    if probe.status == 0:
        entries = []
        for spec in CATALOG:
            try:
                if not _present(spec, env):
                    entries.append(_entry(spec, status=spec.missing_status))
                elif spec.network:
                    entries.append(_entry(spec, status="offline", detail=OFFLINE_DETAIL))
                else:
                    entries.append(check_tool(spec, env))
            except Exception as exc:
                entries.append(_entry(spec, status="error", detail=_one_line(exc)))
        return entries
    with ThreadPoolExecutor(max_workers=max(1, max_workers)) as pool:
        choco_future = pool.submit(check_choco, env)
        futures = [pool.submit(check_tool, spec, env) for spec in CATALOG]
        try:
            entries = list(choco_future.result())
        except Exception as exc:
            entries = [{"id": "choco", "name": "Chocolatey", "kind": "choco", "installed": None,
                        "available": None, "status": "error", "pinned": None,
                        "detail": _one_line(exc), "log": [], "updated_at": None}]
        entries.extend(f.result() for f in futures)
    return entries
