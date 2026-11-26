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

import copy
import datetime
import json
import logging
import ntpath
import os
import platform
import re
import signal
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, NamedTuple, Optional, Tuple

import requests

logger = logging.getLogger(__name__)

CHECK_TIMEOUT = 60
SCRIPT_TIMEOUT = 45 * 60
GIT_PULL_TIMEOUT = 10 * 60
CONSUMER_TIMEOUT = 120
LOG_LINES = 200
REBOOT_CODES = (3010, 1641)
CHOCO_TIMEOUT = 180
HTTP_TIMEOUT = 20
PROBE_TIMEOUT = 5
OFFLINE_DETAIL = "No internet access from the VM"
GITHUB_API = "https://api.github.com"
NO_RELEASES_DETAIL = "Upstream publishes no GitHub releases."
VERSION_UNKNOWN_DETAIL = "Installed version unknown; an update records it"

SYSMON_BINARY_URL = "https://download.sysinternals.com/files/Sysmon.zip"
SYSMON_CONFIG_URL = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"

PYTHON_PACKAGE = "python312"
PYTHON_DETAIL = "The web UI runs on this Python; updating it restarts services and may need a reboot."
# Packages TDC itself holds back; unlike a Chocolatey pin, an explicit update may install them.
TDC_PINNED_CHOCO = (PYTHON_PACKAGE,)
DETONATOR_CONSUMERS = ["task:DetonatorAgent", "task:DetonatorAPI", "task:DetonatorUI"]

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
    """Decode child output. Sysmon prints UTF-16LE inside an otherwise UTF-8/ASCII stream;
    dropping the NULs after a UTF-8 decode keeps both parts readable."""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return (value or "").replace("\x00", "").replace("\r\n", "\n")


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
                env=child_env, **kwargs)
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
            out, err = _as_text(out), _as_text(err)
            return RunResult(124, out, (err.rstrip() + "\n" + note).strip())
        return RunResult(proc.returncode, _as_text(out), _as_text(err))

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

    def http_get(self, url: str, timeout: float, method: str = "GET",
                 headers: Optional[Dict[str, str]] = None) -> HttpResult:
        extra = headers or {}
        headers = {"User-Agent": "tdc-tool-updates"}
        if url.startswith(GITHUB_API):
            headers["Accept"] = "application/vnd.github+json"
            token = os.environ.get("TDC_GITHUB_TOKEN")
            if token:
                headers["Authorization"] = "Bearer " + token
        headers.update(extra)
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
NTSLEUTH_DIR = "C:\\tools\\ntsleuth"


def ntsleuth_exe_path(machine: str) -> str:
    """The NTSleuth binary of a host architecture. The release has no plain ntsleuth.exe; an ARM64 host
    installs the x64 one as well, so the updater only needs the one that matches the host to test for presence."""
    view = "arm64" if machine.upper() in ("ARM64", "AARCH64") else "x64"
    return "%s\\ntsleuth-%s.exe" % (NTSLEUTH_DIR, view)


SYSMON_MARKER = "C:\\tools\\sysmon\\tdc-source.json"

CATALOG: List[ToolSpec] = [
    ToolSpec("windbg", "WinDbg", "winget", None, script=None),
    ToolSpec("rustinel_rules", "Rustinel rules", "git", "C:\\tools\\detection-rules\\rustinel-rules",
             script="install-detection-rules.ps1"),
    ToolSpec("elastic_rules", "Elastic YARA rules", "git", "C:\\tools\\detection-rules\\elastic-protections",
             script="install-detection-rules.ps1"),
    # one script installs both, so a run of either stops the tasks of both
    ToolSpec("detonator_agent", "DetonatorAgent", "git", "C:\\DetonatorAgent",
             script="install-detonator.ps1", consumers=list(DETONATOR_CONSUMERS)),
    ToolSpec("detonator", "Detonator", "git", "C:\\detonator",
             script="install-detonator.ps1", consumers=list(DETONATOR_CONSUMERS)),
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
    ToolSpec("ntsleuth", "NTSleuth", "release", ntsleuth_exe_path(platform.machine()), repo="xaitax/NTSleuth",
             marker=NTSLEUTH_DIR + "\\tdc-release.txt", script="install-ntsleuth.ps1", script_args=["-Force"]),
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
    # Upgrading a metapackage (git) upgrades its <x>.install too; list it once.
    listed = {row["package"] for row in rows}
    rows = [row for row in rows
            if not (row["package"].endswith(".install") and row["package"][:-len(".install")] in listed)]
    entries = []
    for row in rows:
        choco_pinned = row["pinned"]
        held = choco_pinned or row["package"] in TDC_PINNED_CHOCO
        if choco_pinned:
            detail = "Pinned in Chocolatey; unpin it to upgrade"
        else:
            detail = PYTHON_DETAIL if held else ""
        entries.append({
            "id": "choco:" + row["package"], "name": row["package"], "kind": "choco",
            "installed": row["current"], "available": row["available"],
            "status": "pinned_update" if held else "update_available",
            "pinned": row["current"] if held else None,
            "choco_pinned": choco_pinned,
            "detail": detail,
            "log": [], "updated_at": None})
    return entries


def git_command(path: str, *args: str) -> List[str]:
    """A git call for a repository that belongs to another user, run as SYSTEM.

    safe.directory names this one repository (git compares forward slashes);
    fsmonitor, hooks, the ssh command and credential helpers of the repo or of
    the user config must not run code as SYSTEM."""
    return (["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=NUL", "-c", "core.sshCommand=",
             "-c", "credential.helper=", "-c", "safe.directory=" + path.replace("\\", "/"), "-C", path]
            + list(args))


def _git(env, path: str, *args: str) -> RunResult:
    return env.run(git_command(path, *args), CHECK_TIMEOUT)


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
    """The latest release tag, or (None, error-detail); (None, "") when the repo has no releases."""
    res = env.http_get("%s/repos/%s/releases/latest" % (GITHUB_API, spec.repo), HTTP_TIMEOUT)
    if res.status == 0:
        return None, "GitHub is not reachable"
    if res.status == 404:
        return None, ""
    if res.status in (403, 429) and str(res.headers.get("x-ratelimit-remaining", "")) == "0":
        return None, "GitHub API rate limit reached; set TDC_GITHUB_TOKEN to raise it"
    if res.status != 200 or not isinstance(res.json, dict) or not res.json.get("tag_name"):
        return None, "GitHub API answered HTTP %d for %s" % (res.status, spec.repo)
    return normalize_version(str(res.json["tag_name"])), ""


def _check_release(spec, env) -> Dict[str, Any]:
    installed = _installed_release(spec, env)
    available, problem = _github_latest(spec, env)
    if available is None and not problem:
        return _entry(spec, installed, None, "unknown", NO_RELEASES_DETAIL)
    if available is None:
        return _entry(spec, installed, None, "error", problem)
    newer = installed == "unknown" or compare_versions(installed, available) < 0
    if not newer:
        return _entry(spec, installed, available, "up_to_date")
    if spec.pinned:
        detail = "Pinned to %s for compatibility; %s is available" % (spec.pinned, available)
        return _entry(spec, installed, available, "pinned_update", detail)
    detail = VERSION_UNKNOWN_DETAIL if installed == "unknown" else ""
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
    # the installer records the ETag of the uncompressed download; requests would otherwise get the gzip variant's
    res = env.http_get(spec.url, HTTP_TIMEOUT, method="HEAD", headers={"Accept-Encoding": "identity"})
    if res.status == 0:
        return _entry(spec, recorded or None, None, "error", "Download server is not reachable")
    if res.status != 200:
        return _entry(spec, recorded or None, None, "error", "HEAD %s answered HTTP %d" % (spec.url, res.status))
    current = _etag(res.headers.get("etag"))
    if not current:
        return _entry(spec, recorded or None, None, "unknown", "The server sent no ETag")
    if not recorded:
        return _entry(spec, None, current, "update_available", VERSION_UNKNOWN_DETAIL)
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


# ---------------------------------------------------------------------------
# Update runner
# ---------------------------------------------------------------------------

BUSY_MESSAGE = "An update check or install is already running."
INTERRUPTED_DETAIL = "Interrupted: the web UI restarted during the update."
WINGET_UPGRADE = ["winget", "upgrade", "--id", "Microsoft.WinDbg", "--silent",
                  "--accept-source-agreements", "--accept-package-agreements"]
_STATE_REPLACE_ATTEMPTS = 10
_STATE_REPLACE_PAUSE = 0.05
_POWERSHELL = ["powershell", "-NoProfile", "-Command"]


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _split_consumer(cid: str) -> Tuple[str, str]:
    kind, _, name = cid.partition(":")
    if kind not in ("task", "service") or not name:
        raise ValueError("Unknown consumer: %s" % cid)
    return kind, name


def _powershell(env, script: str, timeout: float) -> RunResult:
    return env.run(_POWERSHELL + [script], timeout)


def consumer_running(cid: str, env) -> bool:
    kind, name = _split_consumer(cid)
    if kind == "task":
        script = "(Get-ScheduledTask -TaskName %s -ErrorAction SilentlyContinue).State -eq 'Running'" % _ps_quote(name)
    else:
        script = "(Get-Service -Name %s -ErrorAction SilentlyContinue).Status -eq 'Running'" % _ps_quote(name)
    res = _powershell(env, script, CONSUMER_TIMEOUT)
    return res.returncode == 0 and res.stdout.strip().lower() == "true"


def _safe_kill_dirs(dirs, windows_dir: Optional[str] = None, program_files: Optional[List[str]] = None) -> List[str]:
    """The folders from which running processes may be ended for a task.

    Refused: anything that is not an absolute drive path, drive roots and
    folders with fewer than two components counting the drive (C:\\ and C:
    are out, C:\\LitterBox is fine), and anything under the Windows folder,
    Program Files, Program Files (x86), C:\\Users, C:\\ProgramData or a base
    Python install (C:\\Python3*).
    Those hold shared binaries, and ending everything started from them would
    end unrelated programs."""
    windows_dir = windows_dir or os.environ.get("SystemRoot") or "C:\\Windows"
    if program_files is None:
        program_files = [os.environ.get("ProgramFiles") or "C:\\Program Files",
                         os.environ.get("ProgramFiles(x86)") or "C:\\Program Files (x86)"]
    refused = [windows_dir] + list(program_files)

    def norm(path: str) -> str:
        return ntpath.normpath(str(path).strip().strip('"').strip()).rstrip("\\").lower()

    protected = [norm(p) for p in refused if p]
    result: List[str] = []
    for raw in dirs or []:
        text = str(raw or "").strip().strip('"').strip()
        if not text:
            continue
        drive, rest = ntpath.splitdrive(ntpath.normpath(text))
        if len(drive) != 2 or drive[1] != ":" or not rest.startswith("\\"):
            continue  # relative, UNC or without a drive
        path = norm(text)
        parts = [p for p in path.split("\\") if p]
        if len(parts) < 2 or ".." in parts:
            continue
        if any(path == p or path.startswith(p + "\\") for p in protected):
            continue
        if re.fullmatch(r"[a-z]:\\python3[^\\]*(\\.*)?", path):
            continue
        if re.fullmatch(r"[a-z]:\\(users|programdata)(\\.*)?", path):
            continue  # profiles and shared program data hold per-user and shared binaries
        clean = ntpath.normpath(text).rstrip("\\")
        if clean not in result:
            result.append(clean)
    return result


def stop_consumer(cid: str, env) -> None:
    """Stop a task (and what runs from its install folder) or a service.

    Raises RuntimeError when a command fails."""
    kind, name = _split_consumer(cid)
    if kind == "task":
        # Stop-ScheduledTask leaves child processes behind at times, so
        # processes started from the task's own folder are ended as well. The
        # folders come from the task, pass _safe_kill_dirs, and never touch
        # the web UI or its parents.
        query = (
            "$t=Get-ScheduledTask -TaskName %s -ErrorAction Stop; foreach($a in $t.Actions){ "
            "if($a.WorkingDirectory){[Environment]::ExpandEnvironmentVariables($a.WorkingDirectory)} "
            "elseif($a.Execute){Split-Path -Parent ([Environment]::ExpandEnvironmentVariables($a.Execute))} }"
        ) % _ps_quote(name)
        res = _powershell(env, query, CONSUMER_TIMEOUT)
        if res.returncode != 0:
            raise RuntimeError(_one_line(res.stderr or res.stdout or "exit code %d" % res.returncode))
        dirs = _safe_kill_dirs(res.stdout.splitlines())
        script = "$n=%s; Stop-ScheduledTask -TaskName $n -ErrorAction Stop" % _ps_quote(name)
        if dirs:
            script += (
                "; $keep=@(); $p=%d; for($i=0; $p -and $i -lt 32; $i++){ $keep+=$p; "
                "$p=(Get-CimInstance Win32_Process -Filter ('ProcessId='+$p) -ErrorAction SilentlyContinue).ParentProcessId }; "
                "foreach($d in @(%s)){ "
                "Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $keep -notcontains $_.Id -and "
                "$_.Path.StartsWith($d+[char]92,[StringComparison]::OrdinalIgnoreCase) } | "
                "Stop-Process -Force -ErrorAction SilentlyContinue }"
            ) % (os.getpid(), ",".join(_ps_quote(d) for d in dirs))
    else:
        script = "Stop-Service -Name %s -Force -ErrorAction Stop" % _ps_quote(name)
    res = _powershell(env, script, CONSUMER_TIMEOUT)
    if res.returncode != 0:
        raise RuntimeError(_one_line(res.stderr or res.stdout or "exit code %d" % res.returncode))


def start_consumer(cid: str, env) -> None:
    """Start a task or service. Raises RuntimeError when the command fails."""
    kind, name = _split_consumer(cid)
    if kind == "task":
        script = "Start-ScheduledTask -TaskName %s -ErrorAction Stop" % _ps_quote(name)
    else:
        script = "Start-Service -Name %s -ErrorAction Stop" % _ps_quote(name)
    res = _powershell(env, script, CONSUMER_TIMEOUT)
    if res.returncode != 0:
        raise RuntimeError(_one_line(res.stderr or res.stdout or "exit code %d" % res.returncode))


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _spawn_thread(work: Callable[[], None]) -> None:
    threading.Thread(target=work, name="tool-updates", daemon=True).start()


def _rizin_sha256(spec, env, available: str) -> Optional[str]:
    """The SHA-256 GitHub publishes for the Cutter package, or None."""
    res = env.http_get("%s/repos/%s/releases/latest" % (GITHUB_API, spec.repo), HTTP_TIMEOUT)
    if res.status != 200 or not isinstance(res.json, dict):
        return None
    wanted = "Cutter-v%s-Windows-x86_64.zip" % available
    for asset in res.json.get("assets") or []:
        if isinstance(asset, dict) and asset.get("name") == wanted:
            digest = str(asset.get("digest") or "")
            if digest.lower().startswith("sha256:") and re.fullmatch(r"[0-9a-fA-F]{64}", digest[7:]):
                return digest[7:].lower()
    return None


class _Failure(Exception):
    """A tool failed in a way that has a ready-made detail."""


class UpdateManager:
    """State, run order and maintenance mode of the tool updates."""

    def __init__(self, env, state_path: str, log_path: str, scripts_dir: str,
                 preconditions: Callable[[], Optional[str]] = lambda: None,
                 close_rizin: Callable[[], None] = lambda: None,
                 spawn: Callable[[Callable[[], None]], None] = _spawn_thread):
        self.env = env
        self.state_path = state_path
        self.log_path = log_path
        self.scripts_dir = scripts_dir
        self.preconditions = preconditions
        self.close_rizin = close_rizin
        self.spawn = spawn
        self._lock = threading.RLock()
        self._queue: List[str] = []
        self._include_pinned = False
        self._state = self._load()
        if self._state.get("stopped"):
            try:
                self.spawn(self._restart_stopped)
            except Exception as exc:
                logger.warning("Could not start the restart of interrupted consumers: %s", exc)

    # -- state -------------------------------------------------------------

    @staticmethod
    def _fresh() -> Dict[str, Any]:
        return {"mode": "idle", "checked_at": None, "tools": [], "queued_prev": {},
                "progress": {"done": 0, "total": 0, "current": None}, "last_run": None,
                "stopped": None}

    def _load(self) -> Dict[str, Any]:
        state = self._fresh()
        try:
            with open(self.state_path, encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            return state
        if not isinstance(data, dict):
            return state
        tools = [t for t in data.get("tools") or [] if isinstance(t, dict) and t.get("id")]
        prev = data.get("queued_prev") if isinstance(data.get("queued_prev"), dict) else {}
        changed = False
        for tool in tools:
            if tool.get("status") == "updating":
                tool["status"] = "failed"
                tool["detail"] = INTERRUPTED_DETAIL
                changed = True
            elif tool.get("status") == "queued":
                tool["status"] = prev.get(tool["id"]) or "unknown"
                changed = True
        state["tools"] = tools
        state["checked_at"] = data.get("checked_at")
        if isinstance(data.get("last_run"), dict):
            state["last_run"] = data["last_run"]
        stopped = data.get("stopped")
        if isinstance(stopped, dict) and stopped.get("consumers"):
            state["stopped"] = {"tool": str(stopped.get("tool") or ""),
                                "consumers": [str(c) for c in stopped["consumers"] if isinstance(c, str)]}
            changed = True
        if changed or data.get("mode") in ("updating", "checking"):
            self._state = state
            self._persist()
        return state

    def _persist(self) -> None:
        """Write the state beside the file, flush it to disk, then put it in
        place, so a crash halfway leaves the old state."""
        with self._lock:
            payload = {k: v for k, v in self._state.items() if k != "progress"}
            tmp = self.state_path + ".tmp"
            try:
                parent = os.path.dirname(self.state_path)
                if parent:
                    os.makedirs(parent, exist_ok=True)
                with open(tmp, "w", encoding="utf-8") as handle:
                    json.dump(payload, handle, indent=2)
                    handle.flush()
                    os.fsync(handle.fileno())
                for attempt in range(1, _STATE_REPLACE_ATTEMPTS + 1):
                    try:
                        os.replace(tmp, self.state_path)
                        break
                    except PermissionError:
                        if attempt == _STATE_REPLACE_ATTEMPTS:
                            raise
                        time.sleep(_STATE_REPLACE_PAUSE)
            except (OSError, TypeError, ValueError) as exc:
                logger.warning("Could not save the tool update state: %s", exc)
                try:
                    os.remove(tmp)
                except OSError:
                    pass

    def _restart_stopped(self) -> None:
        """Start again what an interrupted run had stopped (the web UI restarted
        in the middle of an update), and say so in the failed tool's detail."""
        with self._lock:
            pending = self._state.get("stopped")
        if not pending:
            return
        restarted: List[str] = []
        lines: List[str] = []
        for cid in pending["consumers"]:
            try:
                start_consumer(cid, self.env)
                restarted.append(cid.split(":", 1)[-1])
                lines.append("Started %s after the interrupted update" % cid)
                logger.info("Restarted %s after an interrupted update", cid)
            except Exception as exc:
                lines.append("Could not start %s: %s" % (cid, _one_line(exc)))
                logger.warning("Could not restart %s after an interrupted update: %s", cid, exc)
        stamp = _now()
        with self._lock:
            entry = self._entry(pending["tool"])
            if entry is not None and restarted and entry.get("status") == "failed" \
                    and str(entry.get("detail", "")).startswith(INTERRUPTED_DETAIL):
                entry["detail"] = "%s Restarted: %s." % (INTERRUPTED_DETAIL, ", ".join(restarted))
            if self._state.get("stopped") is pending:
                self._state["stopped"] = None
            self._persist()
        self._append_log_file(["%s [%s] %s" % (stamp, pending["tool"], l) for l in lines])

    def _set_stopped(self, tool_id: str, consumers: List[str]) -> None:
        with self._lock:
            if not consumers and not self._state.get("stopped"):
                return
            self._state["stopped"] = {"tool": tool_id, "consumers": list(consumers)} if consumers else None
            self._persist()

    @property
    def maintenance(self) -> bool:
        with self._lock:
            return self._state["mode"] == "updating"

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            s = self._state
            return copy.deepcopy({"mode": s["mode"], "checked_at": s["checked_at"], "tools": s["tools"],
                                  "progress": s["progress"], "last_run": s["last_run"]})

    def _entry(self, tool_id: str) -> Optional[Dict[str, Any]]:
        for tool in self._state["tools"]:
            if tool["id"] == tool_id:
                return tool
        return None

    # -- check -------------------------------------------------------------

    def start_check(self) -> Tuple[int, Dict[str, Any]]:
        with self._lock:
            if self._state["mode"] != "idle":
                return 409, {"error": BUSY_MESSAGE}
            self._state["mode"] = "checking"
            self._state["progress"] = {"done": 0, "total": 0, "current": None}
            self._persist()
        try:
            self.spawn(self.run_check_sync)
        except Exception:
            self._finish_mode()
            raise
        return 202, {"started": True}

    def _finish_mode(self) -> None:
        with self._lock:
            self._state["mode"] = "idle"
            self._state["progress"]["current"] = None
            self._persist()

    def run_check_sync(self) -> None:
        with self._lock:
            if self._state["mode"] == "idle":
                self._state["mode"] = "checking"
        try:
            entries = check_all(self.env)
            with self._lock:
                old = {t["id"]: t for t in self._state["tools"]}
                for entry in entries:
                    previous = old.get(entry["id"])
                    if previous:
                        entry["log"] = previous.get("log", [])
                        entry["updated_at"] = previous.get("updated_at")
                self._state["tools"] = entries
                self._state["checked_at"] = _now()
        except Exception as exc:
            logger.warning("Tool update check failed: %s", exc)
        finally:
            self._finish_mode()

    # -- apply -------------------------------------------------------------

    @staticmethod
    def _spec(tool_id: str) -> Optional[ToolSpec]:
        return next((t for t in CATALOG if t.id == tool_id), None)

    @staticmethod
    def _order_key(tool_id: str) -> Tuple[int, int]:
        if tool_id == "choco:python312":
            return (2, 0)
        if tool_id.startswith("choco:"):
            return (1, 0)
        for i, spec in enumerate(CATALOG):
            if spec.id == tool_id:
                return (0, i)
        return (1, 0)

    @staticmethod
    def _needs_include_pinned(entry: Dict[str, Any]) -> bool:
        if entry["status"] == "pinned_update":
            return True
        if entry["status"] != "failed":
            return False
        spec = next((t for t in CATALOG if t.id == entry["id"]), None)
        pin = entry.get("pinned") or (spec.pinned if spec else None)
        available = entry.get("available")
        return bool(pin and available and compare_versions(str(available), str(pin)) != 0)

    def start_apply(self, tools, include_pinned: bool = False) -> Tuple[int, Dict[str, Any]]:
        busy = (409, {"error": BUSY_MESSAGE})
        with self._lock:
            if self._state["mode"] != "idle":
                return busy
        # The callback may probe other services; do not hold the lock for it
        reason = self.preconditions()
        if reason:
            return 409, {"error": reason}
        with self._lock:
            if self._state["mode"] != "idle":
                return busy
            entries = self._state["tools"]
            known = {t["id"]: t for t in entries}
            if isinstance(tools, list) and "all" in tools:
                return 400, {"error": 'Use "all" alone or a list of tool ids'}
            requested = [tools] if isinstance(tools, str) else list(tools or [])
            if "all" in requested:
                chosen = [t["id"] for t in entries if t["status"] == "update_available"
                          or (include_pinned and t["status"] == "pinned_update"
                              and not t.get("choco_pinned"))]
            else:
                unknown = [t for t in requested if t not in known]
                if unknown:
                    return 400, {"error": "Unknown tools: %s" % ", ".join(unknown)}
                chosen = []
                for tool_id in requested:
                    entry = known[tool_id]
                    if entry.get("choco_pinned") and entry["status"] in ("update_available", "pinned_update", "failed"):
                        return 409, {"error": "%s is pinned in Chocolatey. Unpin it with choco pin remove -n %s first." % (
                            entry["name"], tool_id.split(":", 1)[-1])}
                    if self._needs_include_pinned(entry) and not include_pinned:
                        return 409, {"error": "%s is pinned to %s. Pass include_pinned to install %s." % (
                            entry["name"], entry.get("pinned"), entry.get("available"))}
                    if entry["status"] in ("update_available", "pinned_update", "failed") and tool_id not in chosen:
                        chosen.append(tool_id)
            if not chosen:
                return 409, {"error": "No updates to install."}
            chosen.sort(key=self._order_key)
            self._queue = chosen
            self._include_pinned = include_pinned
            self._state["queued_prev"] = {i: known[i]["status"] for i in chosen}
            for tool_id in chosen:
                known[tool_id]["status"] = "queued"
            self._state["mode"] = "updating"
            self._state["progress"] = {"done": 0, "total": len(chosen), "current": None}
            self._persist()
        try:
            self.spawn(self.run_apply_sync)
        except Exception:
            self._abort_queue()
            raise
        return 202, {"started": True, "tools": list(chosen)}

    def _abort_queue(self) -> None:
        with self._lock:
            for tool_id in self._queue:
                entry = self._entry(tool_id)
                if entry and entry["status"] == "queued":
                    entry["status"] = self._state["queued_prev"].get(tool_id) or "unknown"
            self._queue = []
            self._state["mode"] = "idle"
            self._persist()

    def run_apply_sync(self) -> None:
        with self._lock:
            queue = list(self._queue)
            if not queue or self._state["mode"] != "updating":
                return
        started = _now()
        results: Dict[str, str] = {}
        try:
            for i, tool_id in enumerate(queue):
                try:
                    results[tool_id] = self._run_tool(tool_id)
                except Exception as exc:  # one tool never stops the run
                    logger.exception("Update of %s crashed", tool_id)
                    self._set(tool_id, status="failed", detail=_one_line(exc))
                    results[tool_id] = "failed"
                with self._lock:
                    self._state["progress"]["done"] = i + 1
                    self._persist()
        finally:
            with self._lock:
                self._queue = []
                self._state["queued_prev"] = {}
                self._state["last_run"] = {"started_at": started, "finished_at": _now(), "results": results}
                self._state["mode"] = "idle"
                self._state["progress"]["current"] = None
                self._persist()

    def _set(self, tool_id: str, **fields) -> None:
        with self._lock:
            entry = self._entry(tool_id)
            if entry is not None:
                entry.update(fields)

    # -- one tool ----------------------------------------------------------

    def _script_call(self, script: str, args: List[str]) -> List[str]:
        return ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                os.path.join(self.scripts_dir, script)] + list(args)

    def _run_tool(self, tool_id: str) -> str:
        with self._lock:
            entry = copy.deepcopy(self._entry(tool_id))
            self._state["progress"]["current"] = entry["name"]
            self._set(tool_id, status="updating", detail="")
            self._persist()
        spec = self._spec(tool_id)
        if spec is not None:
            consumers = list(spec.consumers)
        else:
            consumers = list(CHOCO_CONSUMERS.get(tool_id.split(":", 1)[1], []))
        lines: List[str] = []

        def note(text: str) -> None:
            lines.extend(l for l in str(text).splitlines() if l.strip())

        def run(args: List[str], timeout: float) -> RunResult:
            note("> " + " ".join(args))
            res = self.env.run(args, timeout)
            note(res.stdout.rstrip())
            note(res.stderr.rstrip())
            return res

        status, detail = "failed", ""
        stopped: List[str] = []
        try:
            if "rizin_sessions" in consumers:
                try:
                    self.close_rizin()
                except Exception as exc:
                    note("Closing the Rizin sessions failed: %s" % _one_line(exc))
            commands = self._plan(spec, entry, note)
            for cid in consumers:
                if cid == "rizin_sessions":
                    continue
                try:
                    if consumer_running(cid, self.env):
                        stopped.append(cid)
                except Exception as exc:
                    note("Could not check %s: %s" % (cid, _one_line(exc)))
            # Written before anything is stopped: if the web UI dies from here
            # on, the next start knows what to start again.
            self._set_stopped(tool_id, stopped)
            for cid in stopped:
                try:
                    stop_consumer(cid, self.env)
                    note("Stopped %s" % cid)
                except Exception as exc:
                    note("Could not stop %s: %s" % (cid, _one_line(exc)))
            try:
                code = 0
                for args, timeout in commands:
                    res = run(args, timeout)
                    code = res.returncode
                    if code != 0:
                        break
                status, detail = self._outcome(code, commands)
            finally:
                for cid in stopped:
                    try:
                        start_consumer(cid, self.env)
                        note("Started %s" % cid)
                    except Exception as exc:
                        note("Could not start %s: %s" % (cid, _one_line(exc)))
                self._set_stopped(tool_id, [])
            if status in ("updated", "reboot_required"):
                status, detail = self._recheck(tool_id, spec, status, detail)
        except _Failure as exc:
            status, detail = "failed", str(exc)
        except Exception as exc:
            status, detail = "failed", _one_line(exc)
        self._finish_tool(tool_id, status, detail, lines)
        return status

    def _plan(self, spec, entry, note) -> List[Tuple[List[str], float]]:
        """The commands that update one tool, or a _Failure."""
        if spec is None:  # a choco package
            package = entry["id"].split(":", 1)[1]
            return [(["choco", "upgrade", package, "-y", "--no-progress"], SCRIPT_TIMEOUT)]
        if spec.kind == "winget":
            return [(list(WINGET_UPGRADE), SCRIPT_TIMEOUT)]
        script_path = os.path.join(self.scripts_dir, spec.script or "")
        if not spec.script or not self.env.exists(script_path):
            raise _Failure("Install script missing: %s (run make deploy)" % script_path)
        args = list(spec.script_args)
        if spec.pinned:
            available = str(entry.get("available") or "").strip()
            if not available or available.lower() == "unknown":
                raise _Failure("No target version known for %s; run Check for updates first." % spec.name)
            args += ["-Version", available]
            if spec.id == "rizin":
                digest = _rizin_sha256(spec, self.env, available)
                if not digest:
                    raise _Failure("GitHub publishes no SHA-256 for this package; not installed.")
                args += ["-PackageSha256", digest]
        commands: List[Tuple[List[str], float]] = []
        if spec.kind == "git":
            commands.append((git_command(spec.path, "pull", "--ff-only", "--autostash"), GIT_PULL_TIMEOUT))
        commands.append((self._script_call(spec.script, args), SCRIPT_TIMEOUT))
        return commands

    @staticmethod
    def _outcome(code: int, commands) -> Tuple[str, str]:
        if code == 0:
            return "updated", ""
        if code in REBOOT_CODES:
            return "reboot_required", "Restart the VM to finish the update."
        if code == 124:
            return "failed", "Timed out; see the log."
        if code == 127:
            return "failed", "Command not found; see the log."
        return "failed", "Exit code %d; see the log." % code

    def _recheck(self, tool_id: str, spec, status: str, detail: str) -> Tuple[str, str]:
        """The new check is the truth: a script may exit 0 and install nothing."""
        if spec is None:
            fresh = {e["id"]: e for e in check_choco(self.env)}
            current = fresh.get(tool_id) or fresh.get("choco")  # "choco" = the list itself failed
            if current is None:
                with self._lock:
                    old = self._entry(tool_id)
                    old["installed"] = old.get("available")
                return status, detail
        else:
            current = check_tool(spec, self.env)
        with self._lock:
            old = self._entry(tool_id)
            if current["status"] in ("update_available", "pinned_update"):
                if status == "reboot_required":
                    return status, detail
                return "failed", "Install finished but the tool still reports %s; see the log." % (
                    current.get("installed") or "an old version")
            if current["status"] == "not_installed":
                return "failed", "Install finished but the tool is not found; see the log."
            if current["status"] == "up_to_date":
                old["installed"] = current["installed"]
                old["available"] = current["available"]
                return status, detail
        # unknown, error, offline: no proof either way, and the install itself succeeded
        if status == "updated":
            detail = "Installed; could not re-check (%s)" % (current.get("detail") or current["status"])
        return status, detail

    def _finish_tool(self, tool_id: str, status: str, detail: str, lines: List[str]) -> None:
        stamp = _now()
        tail = lines[-LOG_LINES:]
        formatted = ["%s [%s] %s" % (stamp, tool_id, l) for l in tail]
        self._set(tool_id, status=status, detail=detail, log=formatted, updated_at=stamp)
        self._append_log_file(formatted)
        with self._lock:
            self._persist()

    def _append_log_file(self, lines: List[str]) -> None:
        try:
            parent = os.path.dirname(self.log_path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(self.log_path, "a", encoding="utf-8") as handle:
                handle.write("\n".join(lines) + "\n")
        except OSError as exc:
            logger.warning("Could not write the tool update log: %s", exc)
