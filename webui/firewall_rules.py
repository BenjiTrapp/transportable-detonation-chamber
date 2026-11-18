"""Enforcement for the FIREWALL tab: cut a connection, isolate the VM, and never claim more than stands.

Everything with a side effect on the Windows firewall lives here. ``firewall`` judges, ``firewall_store``
remembers, this module acts. The runner is injected: ``run(args: list[str]) -> (returncode, stdout, stderr)``
(``run_powershell`` is the real one), so the whole module is testable without Windows.

Nothing is ever put into a command line as text. A call is ``powershell -NoProfile -NonInteractive
-ExecutionPolicy Bypass -File firewall_rules.ps1 -Op <verb> -Name ... -Program ...``: the values an image path,
an address or a port come from malware-adjacent data are their own list items and reach the script as
parameters. ``-Command`` is never used, because it joins its arguments into one line of PowerShell and parses
it. The one exception is ``kill``: ``taskkill /PID <int> /F``, the pid a checked integer.

Rules: every rule is named ``TDC-FW-<id>`` and nothing else is touched. ``<id>`` is 12 hex digits of ``blake2s``
over scope, image, address, port and protocol, so the same block is the same rule. The *automatic* block is
program-scoped (``block(image=..., ip=...)``): in Windows Firewall an explicit Block beats any Allow, so a block
on an address alone would cut TDC's own fetcher off from the address it is about to fetch from. A block for
everyone is ``block(ip=...)`` without an image, a separate decision of the caller. The key of a rule in
``firewall.Context.rules`` is ``firewall.rule_key`` of what the rule really has: ``rules()`` gives it as ``key``.

A rule that cannot bite is never reported as blocking. With a profile switched off, ``New-NetFirewallRule`` and
``DefaultOutboundAction`` both succeed and do nothing, so: a write refuses while any profile is off
(``RuleError``), every rule is read back with its real parameters after it is written, and ``verified`` is true
only when it stands, is enabled, is what was asked for and every profile it covers is on. A profile that cannot be
read counts as off. ``_firewall_is_off`` of app.py is not used: it is in the module that imports this one, it only
says "off in *all* profiles", it answers False when it cannot read the registry, and it caches for a minute.

ISOLATED sets ``DefaultOutboundAction Block`` on all profiles. Loopback, over which TDC's whole inner traffic
runs, needs no rule: Windows Firewall does not filter loopback traffic at all, and Windows refuses ``::1`` as a
rule's RemoteAddress anyway (earlier versions wrote a loopback allow rule; it was a no-op, its IPv6 half could not
be written, and leaving still removes it if one is found). Inbound is untouched. The default action
governs only the traffic that **no rule matches**, and Windows ships enabled outbound Allow rules (Core
Networking's DNS among them), so ISOLATED also switches off every enabled local outbound Allow rule that is not
TDC's and remembers exactly which (``Settings.allow_disabled``); leaving switches exactly those on again. A rule
from another store, a group policy above all, cannot be switched off locally: what is still enabled is read back
after the switch (``allowed_out``) and said. ``verified`` depends on the stage. Where the cut rule (below) stands
(``cut``, ``cut_policy``) it means that rule was read back: it shuts the egress whether or not the list could be read.
An unreadable or non-empty list only keeps the cut rule standing (``cut_policy``); it is dropped, and the state is the
plain ISOLATED (``isolated``), only when the list was read and is empty, and there, with the rule gone, ``verified``
means Block read back and the Allow list read back empty. The order is:
profiles read and checked, the previous ``DefaultOutboundAction`` and the marker saved in ``Settings`` *before*
anything changes, then the cut (``isolate``, below); after it ``converge``: Windows' rules read, their names saved,
they are switched off, then Block, then read back, then the cut rule removed. Leaving goes backwards and is never refused for
a profile that is off. Every step is one PowerShell call however many rules it touches, because a call costs seconds
on a small VM.

TDC's own fetch gets its way out **per fetch**, not as a standing rule: ``allow_fetch`` writes an allow rule
for the fetcher program to the one address it is about to fetch from and ``deny_fetch`` removes it when the
fetch ends (``forget_fetch_rules`` clears what an interrupted run left). The reason is that the fetcher is a
Python interpreter: a standing allow rule for it would let anything in the guest that can run that python out
to anywhere, for as long as ISOLATED is on. The residual, stated plainly: while a fetch runs, something able to
run that python could reach that one address. Part B's proxy, which executes nothing it is sent, is the
structural fix.

The marker (``Settings.isolated``) alone says that TDC is isolating; the profiles are never used to infer it. A crash in
between leaves the marker, and ``startup_state`` reports an isolation it finds and does **not** lift it.
``scripts/tdc-unisolate.ps1`` is the way out when the Web UI is not reachable; it reads ``allow_disabled`` too.

The cut is the fast way to shut the egress: **one** outbound Block rule, ``TDC-FW-ISO-cut``, for every program and
every address, written and read back by one call (``cut``). In Windows Firewall a Block rule beats every Allow rule, so
the ~135 Allow rules that Windows ships need not be switched off one by one (that measured 38.5 s; ``Cut`` alone
2.44 s, the whole press 8.8 s on a quiet VM).
Loopback is in the rule's address set and that is harmless: Windows does not filter loopback, so the Web UI stays
reachable. No Allow exception gets through the cut, **so there is no ``allow_fetch`` while it stands**. Its name
starts ``TDC-FW-ISO-``, so ``RemoveIsolate`` and ``scripts/tdc-unisolate.ps1`` remove it with no cleanup path of its own.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import ntpath
import os
import re
import subprocess
import sys
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

import firewall
from firewall_store import STAGES

RULE_PREFIX = "TDC-FW-"
ISOLATE_PREFIX = RULE_PREFIX + "ISO-"
LOOPBACK_RULE = ISOLATE_PREFIX + "loopback"  # written by older versions: only removed now (see the module docstring)
FETCHER_RULE = ISOLATE_PREFIX + "fetcher"     # the standing fetcher rule of older versions: only removed now
FETCH_PREFIX = ISOLATE_PREFIX + "fetch-"      # one allow rule per fetch, for as long as that fetch lasts
CUT_RULE = ISOLATE_PREFIX + "cut"             # the one catch-all outbound Block rule of the cut (see the module docstring)

PROFILE_NAMES = ("Domain", "Private", "Public")
OUTBOUND_ACTIONS = ("Allow", "Block", "NotConfigured")
UNISOLATE_SCRIPT = "scripts/tdc-unisolate.ps1"

_SYSTEM32 = ntpath.join(os.environ.get("SystemRoot") or r"C:\Windows", "System32")
POWERSHELL = ntpath.join(_SYSTEM32, "WindowsPowerShell", "v1.0", "powershell.exe")
TASKKILL = ntpath.join(_SYSTEM32, "taskkill.exe")
SWAP_SUFFIX = "-new"       # a stand-in rule while a rule is replaced, so that there is never a gap

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "firewall_rules.ps1")
RUN_TIMEOUT_S = 90
MAX_PATH_CHARS = 4096
MIN_KILL_PID = 5           # 0 is the idle process, 4 the system; both cannot be killed and must not be tried

EXIT_PROFILE_OFF = 3       # the exit codes of firewall_rules.ps1
EXIT_EXISTS = 4

_NAME = re.compile(r"TDC-FW-[A-Za-z0-9-]{1,40}")
_BLOCK_NAME = re.compile(r"TDC-FW-[0-9a-f]{12}(?:-new)?")
_FETCH_NAME = re.compile(re.escape(FETCH_PREFIX) + r"[0-9a-f]{12}")

_LOCK = threading.RLock()

# Every PowerShell call is reported to CALL_OBSERVER (set by the caller, None for none) as ``{op, lock, wait_ms,
# run_ms, rc, thread}``: the op, which run holds the lock (None for a call made without it), how long that run
# waited for the lock (given to its first call, 0.0 to the rest; None without the lock), how long the call ran,
# its exit code and the thread's name. No parameter and no output is in it, with one exception: an answer that names
# the way it was read (``Via``, "fast" or "cmdlet") adds ``via``, and on a fallback ``fallback``, its reason (at most
# MAX_FALLBACK_CHARS), so that a fallback that keeps happening can be found and does not only show as slowness. An
# answer with no marker on stdout may carry it on stderr (``Get`` for a rule that is not there prints nothing). The
# wait is measured where the lock is taken, because a press that waits for someone else's run is the variance a
# single call cannot show.
CALL_OBSERVER: Optional[Callable[[Dict[str, Any]], None]] = None
WAYS = ("fast", "cmdlet")
MAX_FALLBACK_CHARS = 200
_clock = time.perf_counter                # tests pin it
_held = threading.local()                 # per thread: depth, what holds the lock, the wait not yet reported


class _Locked:
    """``_LOCK`` as a context manager that measures how long its outermost acquisition waited."""

    def __init__(self, what: str):
        self.what = what

    def __enter__(self) -> None:
        started = _clock()
        _LOCK.acquire()
        depth = getattr(_held, "depth", 0)
        if depth == 0:
            _held.what, _held.wait_ms = self.what, (_clock() - started) * 1000.0
        _held.depth = depth + 1

    def __exit__(self, *exc: Any) -> None:
        _held.depth -= 1
        _LOCK.release()


_locked = _Locked


class RuleError(Exception):
    """A firewall change that could not be made, or a state that cannot be trusted. The message is for the analyst."""


class ProfileOffError(RuleError):
    """Nothing was changed because a firewall profile is off: a rule or a default action would do nothing."""


# ---- running ---------------------------------------------------------------------------------


def run_powershell(args: List[str]) -> Tuple[int, str, str]:
    """The real runner: ``args`` as a list, no shell, no stdin; returns ``(returncode, stdout, stderr)``.

    A program that is not there or does not answer in ``RUN_TIMEOUT_S`` is a nonzero code with the reason in stderr.
    """
    extra: Dict[str, Any] = {}
    if sys.platform == "win32":
        extra["creationflags"] = subprocess.CREATE_NO_WINDOW
    try:
        done = subprocess.run(list(args), capture_output=True, text=True, encoding="utf-8", errors="replace",
                              stdin=subprocess.DEVNULL, timeout=RUN_TIMEOUT_S, shell=False, **extra)
    except subprocess.TimeoutExpired:
        return 124, "", f"{args[0]} did not answer within {RUN_TIMEOUT_S} s"
    except (OSError, ValueError) as e:
        return 127, "", f"{type(e).__name__}: {e}"
    return done.returncode, done.stdout or "", done.stderr or ""


def _first_line(text: Any) -> str:
    for line in str(text or "").splitlines():
        if line.strip():
            return line.strip()[:300]
    return ""


def _call(run, args: List[str]) -> Tuple[int, str, str]:
    started = _clock()
    rc: Any = None
    out: Any = None
    err: Any = None
    try:
        rc, out, err = run(args)
    except Exception as e:
        raise RuleError(f"could not run {args[0]}: {type(e).__name__}: {_first_line(e)}") from e
    finally:
        _report(args, started, rc, out, err)
    return int(rc), out or "", err or ""


def _way(out: Any) -> Dict[str, str]:
    """``{"via"[, "fallback"]}`` of an answer that names the way it was read: its first row with a ``Via``, at the top
    or under ``profiles``; ``{}`` for any other answer."""
    if not isinstance(out, str) or '"Via"' not in out:
        return {}
    answer = json.loads(out)
    rows = answer if isinstance(answer, list) else [answer]
    if isinstance(answer, dict) and isinstance(answer.get("profiles"), list):
        rows += answer["profiles"]
    for row in rows:
        if isinstance(row, dict) and "Via" in row:
            if row["Via"] not in WAYS:
                return {}
            way = {"via": row["Via"]}
            if row.get("Fallback"):
                way["fallback"] = str(row["Fallback"])[:MAX_FALLBACK_CHARS]
            return way
    return {}


def _way_on_stderr(err: Any) -> Dict[str, str]:
    """The way of an answer that has nothing to say on stdout (``Get`` for a rule that is not there): the first line
    of stderr that is a JSON object with a ``Via``; ``{}`` when there is none."""
    if not isinstance(err, str):
        return {}
    for line in err.splitlines():
        line = line.strip()
        if line.startswith("{") and '"Via"' in line:
            try:
                return _way(line)
            except ValueError:
                continue
    return {}


def _report(args: List[str], started: float, rc: Any, out: Any = None, err: Any = None) -> None:
    """Tell CALL_OBSERVER about one call; never raises, and changes nothing."""
    observer = CALL_OBSERVER
    if observer is None:
        return
    try:
        ran = (_clock() - started) * 1000.0
        op = args[args.index("-Op") + 1] if "-Op" in args[:-1] else ntpath.basename(str(args[0]))
        locked = getattr(_held, "depth", 0) > 0
        wait = None
        if locked:
            wait, _held.wait_ms = _held.wait_ms, 0.0
        record = {"op": str(op), "lock": _held.what if locked else None, "wait_ms": wait, "run_ms": ran,
                  "rc": rc if isinstance(rc, int) else None, "thread": threading.current_thread().name}
        try:
            record.update(_way(out) or _way_on_stderr(err))
        except Exception:
            pass
        observer(record)
    except Exception:
        pass


def _ps(run, op: str, **params: Optional[str]) -> Tuple[int, str, str]:
    args = [POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", SCRIPT, "-Op", op]
    for name, value in params.items():
        if value is not None:
            args += ["-" + name, str(value)]
    return _call(run, args)


def _ok(run, op: str, **params: Optional[str]) -> str:
    rc, out, err = _ps(run, op, **params)
    if rc != 0:
        raise RuleError(f"{op} failed ({rc}): {_first_line(err) or _first_line(out) or 'no message'}")
    return out


def _json(text: str, what: str) -> Any:
    try:
        return json.loads(text)
    except ValueError as e:
        raise RuleError(f"cannot read the answer for {what}: {_first_line(text)[:80]!r}") from e


# ---- what the analyst or the data may give us ------------------------------------------------


def _clean_path(value: Any, what: str) -> str:
    """A program path as text. Anything is allowed that a file name can be on Windows plus what Sysmon
    makes of one; it is only ever one list item, so it is checked for what would confuse the parameter
    binder (a leading dash, control characters) and for size."""
    if not isinstance(value, str):
        raise RuleError(f"{what} must be a path")
    text = value.strip()
    if not text or len(text) > MAX_PATH_CHARS or text.startswith("-") or any(ord(c) < 32 or ord(c) == 127 for c in text):
        raise RuleError(f"{what} is not a usable path")
    return text


def _clean_ip(value: Any) -> str:
    try:
        addr = ipaddress.ip_address(value.strip()) if isinstance(value, str) else None
    except ValueError:
        addr = None
    if addr is None or getattr(addr, "scope_id", None):
        raise RuleError(f"not an address: {str(value)[:60]!r}")
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return str(addr)


def _clean_port(value: Any) -> int:
    if isinstance(value, str) and value.strip().isascii() and value.strip().isdigit():
        value = int(value.strip())
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise RuleError(f"not a port: {str(value)[:20]!r}")
    return value


def _clean_protocol(value: Any) -> str:
    text = value.strip().lower() if isinstance(value, str) else ""
    if text not in ("tcp", "udp"):
        raise RuleError(f"a port needs a protocol, tcp or udp, not {str(value)[:20]!r}")
    return text


def _norm_address(text: Any) -> str:
    """An address or range of a rule in one spelling: a single host without a prefix, a range as ``a/n``."""
    raw = str(text).strip()
    try:
        net = ipaddress.ip_network(raw, strict=False)
    except ValueError:
        return raw.lower()
    return str(net.network_address) if net.num_addresses == 1 else str(net)


def _spec(name: str, action: str, image: Optional[str] = None, addresses: Tuple[str, ...] = (),
          port: Optional[int] = None, protocol: Optional[str] = None) -> Dict[str, Any]:
    """What a rule is meant to be: the parameters ``Create`` gets and ``_matches`` holds a rule up against."""
    return {"name": name, "action": action, "image": image, "addresses": tuple(addresses), "port": port,
            "protocol": protocol}


def rule_id_for(scope: str, image: Optional[str], ip: Optional[str], port: Optional[int], protocol: Optional[str]) -> str:
    """``TDC-FW-`` and 12 hex digits: the same block is the same rule, whoever asks and in whatever case the image is."""
    text = "\0".join([scope, (image or "").lower(), ip or "", str(port or ""), protocol or ""])
    return RULE_PREFIX + hashlib.blake2s(text.encode("utf-8", "replace"), digest_size=6).hexdigest()


def _same_path(a: str, b: str) -> bool:
    return a.lower().replace("/", "\\") == b.lower().replace("/", "\\")


LOOPBACK_TEXT = ("{address} is a loopback address: Windows Firewall does not filter loopback traffic, so a rule for it "
                 "would stand, read back as written, and block nothing. TDC does not write it, for one program or "
                 "for all; to stop the process, block it everywhere or KILL it.")


def _is_loopback(address: str) -> bool:
    """127.0.0.0/8 and ::1 (``_clean_ip`` has already unwrapped an IPv4-mapped form): traffic Windows never filters."""
    return ipaddress.ip_address(address).is_loopback


def _is_local_only(address: str) -> bool:
    addr = ipaddress.ip_address(address)
    return addr.is_loopback or addr.is_unspecified or addr.is_multicast


def _block_spec(image: Any, ip: Any, port: Any, protocol: Any) -> Dict[str, Any]:
    program = _clean_path(image, "image") if image is not None else None
    address = _clean_ip(ip) if ip is not None else None
    if program is None and address is None:
        raise RuleError("a block needs a program, an address, or both")
    if address is not None and _is_loopback(address):
        raise RuleError(LOOPBACK_TEXT.format(address=address))
    if program is None and _is_local_only(address):
        raise RuleError(f"{address} is loopback, unspecified or multicast: a block for every program there would cut TDC's own traffic")
    number = None
    kind = None
    if port is not None:
        if address is None:
            raise RuleError("a port needs an address")
        number = _clean_port(port)
        kind = _clean_protocol(protocol)
    scope = "program" if program and address else "process" if program else "everyone"
    spec = _spec(rule_id_for(scope, program, address, number, kind), "Block", program,
                 (address,) if address else (), number, kind)
    spec["ip"] = address
    return spec


# ---- reading the firewall --------------------------------------------------------------------


def _is_on(value: Any) -> bool:
    return value is True or (isinstance(value, str) and value.strip().lower() == "true")


def _states(rows: Any) -> List[Dict[str, Any]]:
    if isinstance(rows, dict):
        rows = [rows]
    found: List[Dict[str, Any]] = []
    for row in rows if isinstance(rows, list) else ():
        if isinstance(row, dict) and row.get("Name") in PROFILE_NAMES:
            outbound = str(row.get("DefaultOutboundAction") or "").strip()
            configured = str(row.get("Configured") or "").strip()
            found.append({"name": row["Name"], "enabled": _is_on(row.get("Enabled")), "outbound": outbound,
                          "configured": configured if configured in OUTBOUND_ACTIONS else None})
    if {s["name"] for s in found} != set(PROFILE_NAMES):
        raise RuleError("cannot read the Windows Firewall profiles; nothing can be enforced")
    return found


def _profiles(run) -> List[Dict[str, Any]]:
    """``[{"name", "enabled", "outbound"}]`` of Domain, Private and Public as they are in force; a profile that cannot be
    read, or an answer that does not name all three, is an error (fail closed)."""
    return _states(_json(_ok(run, "Profiles"), "the profiles"))


def _off_names(states: List[Dict[str, Any]]) -> List[str]:
    return [s["name"] for s in states if not s["enabled"]]


def _off_text(names: Any) -> str:
    listed = names if isinstance(names, str) else ", ".join(names)
    return (f"Windows Firewall is switched off for: {listed or 'a profile'}. A rule or a default action "
            "would be accepted and do nothing, so nothing is enforced.")


def profiles_off(run) -> List[str]:
    """The firewall profiles (Domain, Private, Public) that are not on; empty when all three are. Raises ``RuleError``
    when they cannot be read, because "cannot tell" must not read as "on"."""
    return _off_names(_profiles(run))


def profile_states(run) -> List[Dict[str, Any]]:
    """``[{"name", "enabled", "outbound", "configured"}]`` of the three profiles, ``outbound`` as in force: one read,
    for a caller that needs the default action as well as which profiles are off. Raises ``RuleError`` like
    ``profiles_off``."""
    return _profiles(run)


def enable_firewall(run) -> None:
    """Switch Domain, Private and Public on (``Set-NetFirewallProfile -Enabled True``) and check that they are.

    This changes what the malware sees, so TDC never does it by itself: the caller asks the analyst first.
    """
    with _locked("enable"):
        _ok(run, "Enable")
        off = profiles_off(run)
    if off:
        raise RuleError(f"the firewall stays off for: {', '.join(off)}")


def _view(raw: Dict[str, Any]) -> Dict[str, Any]:
    """A rule as ``firewall_rules.ps1`` describes it, in the form ``_matches`` and ``rules`` compare."""
    def listed(value: Any) -> List[str]:
        items = value if isinstance(value, list) else [] if value is None else [value]
        return [str(i).strip() for i in items if str(i).strip()]

    program = str(raw.get("Program") or "").strip()
    addresses = [a for a in listed(raw.get("RemoteAddress")) if a.lower() != "any"]
    ports = [p for p in listed(raw.get("RemotePort")) if p.lower() != "any"]
    protocol = {"6": "tcp", "17": "udp"}.get(str(raw.get("Protocol") or "").strip().lower(),
                                            str(raw.get("Protocol") or "").strip().lower())
    profile_text = str(raw.get("Profile") or "").strip().lower()
    covered = [n for n in PROFILE_NAMES if n.lower() in re.split(r"[\s,]+", profile_text)]
    return {"name": str(raw.get("Name") or ""), "enabled": _is_on(raw.get("Enabled")),
            "action": str(raw.get("Action") or "").strip().lower(),
            "direction": str(raw.get("Direction") or "").strip().lower(),
            "profiles": covered if covered and "any" not in profile_text else list(PROFILE_NAMES),
            "image": None if program.lower() in ("", "any") else program,
            "addresses": frozenset(_norm_address(a) for a in addresses), "ports": ports,
            "protocol": None if protocol in ("", "any") else protocol}


def _describe(run, name: str) -> Optional[Dict[str, Any]]:
    """The rule ``name`` as it really is, or None when there is none."""
    out = _ok(run, "Get", Name=name)
    if not out.strip():
        return None
    data = _json(out, name)
    if isinstance(data, list):
        data = data[0] if data else None
    return _view(data) if isinstance(data, dict) else None


def _matches(view: Dict[str, Any], spec: Dict[str, Any]) -> bool:
    return (view["action"] == spec["action"].lower() and view["direction"] == "outbound"
            and (view["image"] or "").lower() == (spec["image"] or "").lower()
            and view["addresses"] == frozenset(_norm_address(a) for a in spec["addresses"])
            and view["ports"] == ([str(spec["port"])] if spec["port"] else [])
            and view["protocol"] == spec["protocol"])


def _standing_problem(view: Dict[str, Any], states: List[Dict[str, Any]]) -> Optional[str]:
    """Why a rule that is there would not bite, or None. Enabled, outbound, and every profile it covers on."""
    if not view["enabled"]:
        return "the rule is disabled"
    if view["direction"] != "outbound":
        return "the rule is not an outbound rule"
    off = [n for n in _off_names(states) if n in view["profiles"]]
    if off:
        return _off_text(off)
    return None


# ---- blocks ----------------------------------------------------------------------------------


def _create_params(spec: Dict[str, Any]) -> Dict[str, Optional[str]]:
    return {"Name": spec["name"], "Program": spec["image"],
            "RemoteAddress": ",".join(spec["addresses"]) or None,
            "RemotePort": str(spec["port"]) if spec["port"] else None,
            "Protocol": spec["protocol"].upper() if spec["protocol"] else None,
            "Action": spec["action"]}


def _create(run, spec: Dict[str, Any]) -> int:
    rc, out, err = _ps(run, "Create", **_create_params(spec))
    if rc == EXIT_PROFILE_OFF:
        raise RuleError(_off_text(_first_line(err)))
    if rc not in (0, EXIT_EXISTS):
        raise RuleError(f"could not write {spec['name']} ({rc}): {_first_line(err) or _first_line(out) or 'no message'}")
    return rc


def _replace(run, spec: Dict[str, Any]) -> None:
    """Replace the rule of ``spec["name"]`` without a moment in which no such rule stands: a stand-in with the
    same parameters is written first, the old rule goes, the new one is written, then the stand-in goes. (A rule
    that vanishes for a moment is a block that does not hold, or, for ISOLATED, a fetcher that is cut off.) If it
    fails halfway the stand-in (``<name>-new``) stays and keeps the effect; ``rules()`` lists it and the hatch removes it."""
    stand_in = dict(spec, name=spec["name"] + SWAP_SUFFIX)
    _ok(run, "Remove", Name=stand_in["name"])
    if _create(run, stand_in) != 0:
        raise RuleError(f"{stand_in['name']} is already there")
    try:
        _ok(run, "Remove", Name=spec["name"])
        _create(run, spec)
        _ok(run, "Remove", Name=stand_in["name"])
    except RuleError as e:
        raise RuleError(f"{stand_in['name']} is standing in for {spec['name']} and keeps its effect, so the rule may be "
                        f"missing under its own name; replacing it failed: {_first_line(e)}") from e


def _write(run, spec: Dict[str, Any]) -> Optional[str]:
    """Write one rule and read it back. Returns why it does not stand, or None when it does.

    A rule of that name that is already there and is what was asked for, and enabled, is left alone: replacing it
    would open a gap in a block that holds. One that differs or is disabled is replaced (``_replace``).
    """
    view = None
    if _create(run, spec) == EXIT_EXISTS:
        view = _describe(run, spec["name"])
        if view is None or not _matches(view, spec) or not view["enabled"]:
            _replace(run, spec)
            view = None
    if view is None:
        view = _describe(run, spec["name"])
    if view is None:
        return "the rule is not there after it was written"
    if not _matches(view, spec):
        return "the rule is there, but not with the parameters that were asked for"
    try:
        return _standing_problem(view, _profiles(run))
    except RuleError as e:
        return str(e)


def _fetcher_paths(value: Any) -> Tuple[str, ...]:
    """``fetcher`` as a tuple of paths: one path, several of them, or none (``None``, the explicit opt-out).

    Several, because a venv's ``python.exe`` on Windows is a launcher that hands the work to the base
    interpreter: the socket may belong to either binary, and a guard that names one of them has a blind spot.
    """
    if value is None:
        return ()
    if not isinstance(value, str) and not isinstance(value, (list, tuple)):
        raise RuleError(f"fetcher must be a path or a list of paths, not {type(value).__name__}")
    values = [value] if isinstance(value, str) else list(value)
    return tuple(_clean_path(v, "fetcher") for v in values)


def block(run, *, image: Optional[str] = None, ip: Optional[str] = None, port: Optional[int] = None,
          protocol: Optional[str] = None, fetcher: Optional[Any]) -> Dict[str, Any]:
    """Block outbound traffic and check that the block stands.

    ``image`` and ``ip``: this program to this address (the automatic block, always program-scoped). ``image`` alone:
    the process, everywhere. ``ip`` alone: every program to that address, which includes TDC's own fetcher, so
    that is a separate decision of the caller. ``port`` needs ``ip`` and ``protocol`` (tcp or udp); ``protocol``
    without a port is ignored, because the rule then blocks every protocol, as the key of ``firewall.rule_key``
    says.

    Returns ``{rule_id, name, image, ip, port, protocol, verified, problem}``. ``verified`` is True only when
    the rule was read back from the firewall, is what was asked for, is enabled, and every profile it covers is
    on; otherwise ``problem`` says why and the caller must not call the endpoint blocked. Raises ``RuleError`` when
    a profile is off (nothing is written then), when the arguments are unsound, or when the write fails.

    A block on a loopback address (``127.0.0.0/8``, ``::1``, either IPv4-mapped) is refused for one program and for
    all: Windows Firewall does not filter loopback, so the rule would stand, read back as written, and block nothing,
    and nothing that cannot work is written or called verified.

    Two more blocks would cut TDC off from itself and are refused. A block for every program (no ``image``) on an
    address that is unspecified or multicast: that is where the lockout lives, while a block that names a program
    touches only that program, so a sample's own mDNS or SSDP traffic (multicast, which Windows does filter) can be
    cut. And a block on any program
    of ``fetcher``, because an explicit Block beats the per-fetch Allow rule of ISOLATED. This module cannot know the
    fetcher's path, so ``fetcher`` is a **required** keyword: the caller passes the ``python.exe`` of the web UI venv
    (and the base interpreter behind it, as a list), the same paths it gives ``allow_fetch``. ``fetcher=None`` is the
    explicit opt-out; leaving it out is a ``TypeError``.
    """
    spec = _block_spec(image, ip, port, protocol)
    for program in _fetcher_paths(fetcher):
        if spec["image"] is not None and _same_path(spec["image"], program):
            raise RuleError("that program is TDC's own fetcher: blocking it would cut TDC off from its fetch targets")
    with _locked("block"):
        problem = _write(run, spec)
    return {"rule_id": spec["name"], "name": spec["name"], "image": spec["image"], "ip": spec["ip"],
            "port": spec["port"], "protocol": spec["protocol"], "verified": problem is None, "problem": problem}


def unblock(run, rule_id: str) -> None:
    """Remove one of our block rules and check that it is gone. A rule that is not there is not an error.

    Only ``TDC-FW-`` and 12 hex digits are accepted: no wildcard, no foreign rule, and not the allow rules of
    ISOLATED, which only ``isolate`` writes and removes.
    """
    if not isinstance(rule_id, str) or not _BLOCK_NAME.fullmatch(rule_id):
        raise RuleError(f"not a TDC block rule: {str(rule_id)[:60]!r}")
    with _locked("unblock"):
        _ok(run, "Remove", Name=rule_id)
        if _describe(run, rule_id) is not None:
            raise RuleError(f"{rule_id} is still there after it was removed")


def verify(run, rule_id: str) -> bool:
    """Whether ``rule_id`` is a Block rule that stands now: there, outbound, enabled, every profile it covers on, and
    not on a loopback address (which Windows does not filter).

    False for anything else, and for anything that cannot be read: it never raises.
    """
    try:
        if not isinstance(rule_id, str) or not _NAME.fullmatch(rule_id):
            return False
        view = _describe(run, rule_id)
        if view is None or view["action"] != "block":
            return False
        ip = _identity(view)[1]
        if ip is not None and "/" not in ip and "," not in ip and _is_loopback(ip):
            return False                         # it stands, and Windows does not filter loopback
        return _standing_problem(view, _profiles(run)) is None
    except RuleError:
        return False


# ---- the cut: one rule that shuts the egress -------------------------------------------------


def _cut_problem(view: Optional[Dict[str, Any]]) -> Optional[str]:
    """Why a rule read back as ``CUT_RULE`` does not shut the egress, or None when it does: there, a Block, outbound for
    every program and address, enabled, and covering all three profiles (the profiles were on when it was written)."""
    if view is None:
        return "the rule is not there after it was written"
    if not _matches(view, _spec(CUT_RULE, "Block")):
        return "the rule is there, but it is not a block for every program and address"
    if not view["enabled"]:
        return "the rule is there, but it is disabled"
    uncovered = [n for n in PROFILE_NAMES if n not in view["profiles"]]
    if uncovered:
        return f"the rule is there, but it does not cover: {', '.join(uncovered)}"
    return None


def cut(run) -> Dict[str, Any]:
    """Shut the egress with one outbound Block rule for everything, and read it back, in **one** PowerShell call.

    ``Cut`` checks the profiles, writes ``CUT_RULE`` when it is not there and gives the rule as ``Get`` does; one call
    instead of three because loading the NetSecurity module is 1-2 s of every call. A rule that already stands is left
    alone; one that is there disabled or narrower is brought to the catch-all shape in place (never removed, so there is no
    moment without it) by the same call. Either way it is read back. Returns ``{rule_id, verified, problem, profiles_off}``: ``verified`` is True
    only when the rule was read back and ``problem`` is None; ``profiles_off`` is always empty (a profile that is off
    is a ``ProfileOffError`` and nothing is written). Raises ``RuleError`` when the call fails or its answer cannot be read.
    """
    with _locked("cut"):
        rc, out, err = _ps(run, "Cut")
        if rc == EXIT_PROFILE_OFF:
            raise ProfileOffError(_off_text(_first_line(err)))
        if rc != 0:
            raise RuleError(f"could not write {CUT_RULE} ({rc}): {_first_line(err) or _first_line(out) or 'no message'}")
        view = None
        if out.strip():
            data = _json(out, CUT_RULE)
            if isinstance(data, list):
                data = data[0] if data else None
            view = _view(data) if isinstance(data, dict) else None
        problem = _cut_problem(view)
        if problem and _first_line(err):
            problem += f" (repair: {_first_line(err)})"
    return {"rule_id": CUT_RULE, "verified": problem is None, "problem": problem, "profiles_off": []}


def uncut(run) -> Dict[str, Any]:
    """Remove ``CUT_RULE`` and read it back: ``{removed, problem}``. ``removed`` is True only when the rule is read as
    gone (a rule that was never there is gone too); a failure is told in ``problem`` and never raised, because the way
    out must be able to say what it could not do. Never refused for a profile that is off."""
    with _locked("uncut"):
        try:
            _ok(run, "Remove", Name=CUT_RULE)
            if _describe(run, CUT_RULE) is not None:      # Remove is quiet about a rule it did not remove
                return {"removed": False, "problem": f"{CUT_RULE} is still there after it was removed"}
        except RuleError as e:
            return {"removed": False, "problem": _first_line(e)}
    return {"removed": True, "problem": None}


def cut_stands(run) -> Optional[bool]:
    """Whether the cut shuts the egress now: ``CUT_RULE`` read from the firewall and holding up (``_cut_problem``).
    True or False; ``None`` when it cannot be read, so that "cannot tell" is never taken for either answer."""
    try:
        return _cut_problem(_describe(run, CUT_RULE)) is None
    except RuleError:
        return None


# ---- the way out of ISOLATED, one fetch at a time --------------------------------------------


def fetch_rule_name(ip: Any, port: Optional[int] = None, fetcher: Optional[str] = None) -> str:
    """The name of the per-fetch allow rule for one program and one endpoint: ``TDC-FW-ISO-fetch-<12 hex>``.

    It follows from the program, the address and the port, so the same fetch always asks for the same rule,
    while two fetches to different endpoints - or to one endpoint as two different programs, which a venv
    launcher makes possible - can never replace each other's way out.
    """
    address = _clean_ip(ip)
    number = _clean_port(port) if port is not None else None
    program = _clean_path(fetcher, "fetcher").lower().replace("/", "\\") if fetcher is not None else ""
    text = "\0".join(["fetch", program, address, str(number or "")])
    return FETCH_PREFIX + hashlib.blake2s(text.encode("utf-8", "replace"), digest_size=6).hexdigest()


def allow_fetch(run, *, fetcher: str, ip: Any, port: Optional[int] = None) -> Dict[str, Any]:
    """Allow one fetcher program out to one address, for one fetch: ``{name, rule_id, verified, problem}``.

    ISOLATED shuts every way out that TDC can shut, so TDC's own fetch needs a hole. This is that hole, as small as
    a program-path rule can be made: one program, one address, one port when it is known, and ``deny_fetch``
    takes it away the moment the fetch ends. See the module docstring for why there is no standing rule for the
    fetcher any more, and for the residual that is left. A caller whose fetch may run as more than one binary
    (``sys.executable`` and the base interpreter a venv launcher starts) calls this once per path.

    Raises ``RuleError`` when the arguments are unsound or a profile is off (nothing is enforced then anyway,
    so the caller may go ahead with the fetch and say so); ``problem`` is why a rule that was written cannot be
    relied on.
    """
    program = _clean_path(fetcher, "fetcher")
    address = _clean_ip(ip)
    number = _clean_port(port) if port is not None else None
    spec = _spec(fetch_rule_name(address, number, program), "Allow", program, (address,), number,
                 "tcp" if number is not None else None)      # http(s) is tcp
    with _locked("allow_fetch"):
        problem = _write(run, spec)
    return {"name": spec["name"], "rule_id": spec["name"], "verified": problem is None, "problem": problem}


def deny_fetch(run, name: str) -> None:
    """Remove a per-fetch allow rule, and a stand-in of it, and check that both are gone.

    Only ``TDC-FW-ISO-fetch-<12 hex>`` is accepted, so this can be pointed at no other rule. Both removals are tried even when the first fails: the rule under its
    own name is the way out that has to go, and a stand-in that will not budge must not keep it open. What is
    still standing afterwards is raised, with the failures that were seen.
    """
    if not isinstance(name, str) or not _FETCH_NAME.fullmatch(name):
        raise RuleError(f"not a TDC per-fetch rule: {str(name)[:60]!r}")
    both = (name + SWAP_SUFFIX, name)
    with _locked("deny_fetch"):
        failed = []
        for each in both:
            try:
                _ok(run, "Remove", Name=each)
            except RuleError as e:
                failed.append(f"{each}: {_first_line(e)}")
        still = [n for n in both if _describe(run, n) is not None]
    if still:
        raise RuleError(f"{', '.join(still)} is still there after it was removed"
                        + (f" ({'; '.join(failed)})" if failed else ""))


def forget_fetch_rules(run) -> Tuple[List[str], List[Dict[str, str]]]:
    """Remove every per-fetch allow rule that stands, and the standing fetcher rule older versions wrote.

    ``(removed, stuck)``: the names that went, and ``{rule_id, problem}`` for each one that would not. A failed
    removal does **not** stop the others: every one of them is a way out of ISOLATED standing open, and after a
    crash this is the only thing that can find them, because the names died with the process that held them.
    The caller is told which are left so that it can say so instead of leaving a hole nobody sees.

    A fetch that is in flight owns its rules; the caller only runs this when none is.

    The list is read **without** the lock, and the lock is taken only when there is something to remove: the sweep
    runs every minute while ISOLATED is on, nearly always finds nothing, and a press must not wait seconds behind a
    read that changes nothing. Every removal still happens under the lock and is read back, so the list being a
    snapshot costs nothing: a rule gone before its removal is read back as gone, and one that appeared after the
    read is found by the next sweep.
    """
    removed: List[str] = []
    stuck: List[Dict[str, str]] = []
    names = [r["rule_id"] for r in rules(run)
             if r["rule_id"].startswith(FETCH_PREFIX) or r["rule_id"] in (FETCHER_RULE, FETCHER_RULE + SWAP_SUFFIX)]
    if not names:
        return removed, stuck
    with _locked("forget_fetch_rules"):
        for name in names:
            try:
                _ok(run, "Remove", Name=name)
                if _describe(run, name) is not None:    # Remove is quiet about a rule it did not remove
                    raise RuleError(f"{name} is still there after it was removed")
                removed.append(name)
            except RuleError as e:
                stuck.append({"rule_id": name, "problem": _first_line(e)})
    return removed, stuck


def _identity(view: Dict[str, Any]) -> Tuple[Optional[str], Optional[str], Optional[int], Optional[str], bool]:
    """``(image, ip, port, protocol, canonical)`` of a rule. Canonical: a program and/or one address, and a port
    only with an address and a protocol, i.e. a shape ``block`` writes and ``firewall.rule_key`` can name."""
    addresses = sorted(view["addresses"])
    ip = addresses[0] if len(addresses) == 1 and "/" not in addresses[0] else None
    port = int(view["ports"][0]) if len(view["ports"]) == 1 and view["ports"][0].isdigit() else None
    canonical = (view["image"] is not None or ip is not None) and len(addresses) == (1 if ip else 0)
    canonical = canonical and len(view["ports"]) == (1 if port is not None else 0)
    canonical = canonical and (port is None or (ip is not None and view["protocol"] in ("tcp", "udp")))
    canonical = canonical and (view["protocol"] is None or port is not None)
    return view["image"], ip or (",".join(addresses) or None), port, view["protocol"], bool(canonical)


def rules(run) -> List[Dict[str, Any]]:
    """Our rules, and only ours (names starting ``TDC-FW-``), as they really are.

    ``{rule_id, name, kind, action, enabled, image, ip, port, protocol, key, blocking, cuts}``. ``cuts`` is True only
    for ``CUT_RULE`` in the catch-all shape ``cut`` writes and reads back (``cut_stands``). ``kind`` is ``"block"``
    (written by ``block``) or ``"isolate"`` (the allow rules of ISOLATED). ``blocking`` is True for a Block rule
    that stands, in the shape ``block`` writes, with every profile it covers on; ``key`` is then
    ``firewall.rule_key`` of the rule's real image, address and port. A rule that is listed but not
    ``blocking`` (disabled, a profile off, or changed by someone) must not be shown as a block; nor is a rule on a
    loopback address, which Windows does not filter.

    **Several rules can share a key**: ``firewall.rule_key`` has no protocol and a rule id has (tcp/443 and udp/443 at
    one endpoint are two rules, a stand-in left by a failed replacement is a third). Each is its own entry here,
    with its own ``rule_id`` and ``protocol``. The caller groups by ``key``: ``Context.rules`` takes any one id per key,
    and *unblocking a key must remove every ``rule_id`` of that key*, or the endpoint still reads as blocked. Known
    limitation: a tcp rule makes a udp flow to the same endpoint read as blocked in the classifier, which does not
    look at the protocol; the UI shows the rule's ``protocol`` beside the claim.
    """
    data = _json(_ok(run, "List"), "the rule list")
    if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
        raise RuleError("cannot read the rule list")
    try:
        states: Optional[List[Dict[str, Any]]] = _states(data.get("profiles"))
    except RuleError:
        states = None
    listed = []
    for raw in data["rules"]:
        name = str(raw.get("Name") or "") if isinstance(raw, dict) else ""
        if not name.startswith(RULE_PREFIX):
            continue
        view = _view(raw)
        kind = "isolate" if name.startswith(ISOLATE_PREFIX) else "block"
        image, ip, port, protocol, canonical = _identity(view)
        standing = states is not None and _standing_problem(view, states) is None
        # a loopback rule (an earlier version could write one) stands and bites nothing: it is no block
        inert = ip is not None and canonical and _is_loopback(ip)
        blocking = kind == "block" and view["action"] == "block" and canonical and standing and not inert
        listed.append({"rule_id": name, "name": name, "kind": kind, "action": view["action"].capitalize(),
                       "enabled": view["enabled"], "image": image, "ip": ip, "port": port, "protocol": protocol,
                       "key": firewall.rule_key(image or "", ip or "", port) if canonical else None,
                       "blocking": blocking, "cuts": name == CUT_RULE and _cut_problem(view) is None})
    return listed


# ---- the process -----------------------------------------------------------------------------


def kill(run, pid: int) -> None:
    """``taskkill /PID <pid> /F``: the hammer, a button of its own. Refuses pids that are not a process to kill:
    below 5 (idle, system) and this process."""
    if isinstance(pid, bool) or not isinstance(pid, int) or pid < MIN_KILL_PID or pid == os.getpid():
        raise RuleError(f"not a process that may be killed: {str(pid)[:20]!r}")
    rc, out, err = _call(run, [TASKKILL, "/PID", str(pid), "/F"])
    if rc != 0:
        raise RuleError(f"could not kill {pid} ({rc}): {_first_line(err) or _first_line(out) or 'no message'}")


# ---- isolated --------------------------------------------------------------------------------


def _encode_outbound(current: Dict[str, str]) -> str:
    """What to remember of ``DefaultOutboundAction``: ``Allow`` when all profiles agree, else ``Domain=Allow,Private=Block,...``."""
    for name in PROFILE_NAMES:
        if current.get(name) not in OUTBOUND_ACTIONS:
            raise RuleError(f"cannot remember DefaultOutboundAction {str(current.get(name))[:20]!r} of {name}")
    values = {current[n] for n in PROFILE_NAMES}
    if len(values) == 1:
        return values.pop()
    return ",".join(f"{n}={current[n]}" for n in PROFILE_NAMES)


def _decode_outbound(text: Any) -> Optional[Dict[str, str]]:
    """Inverse of ``_encode_outbound``; None for anything that is not one of its answers."""
    if not isinstance(text, str):
        return None
    text = text.strip()
    if text in OUTBOUND_ACTIONS:
        return {n: text for n in PROFILE_NAMES}
    pairs = [part.partition("=") for part in text.split(",")]
    found = {k.strip(): v.strip() for k, _, v in pairs}
    if set(found) == set(PROFILE_NAMES) and len(pairs) == len(PROFILE_NAMES) and all(v in OUTBOUND_ACTIONS for v in found.values()):
        return found
    return None


def _apply_outbound(run, target: Dict[str, str]) -> List[Dict[str, Any]]:
    """Set ``DefaultOutboundAction`` per profile and read it back; returns the profiles as read, raises when it did not take.

    One call per distinct value (one when all profiles agree). ``SetDefaultOutbound`` answers with the profiles
    as it reads them after the change, which is the read back; an answer that is not that is read again.

    The write goes to the PersistentStore, so it is checked there (``configured``): NotConfigured reads back as
    NotConfigured there, while the ActiveStore shows what it resolves to. A target of Block must in addition be in
    force (``outbound`` Block), because that is what ISOLATED claims; a group policy that overrides it fails here."""
    groups: Dict[str, List[str]] = {}
    for name in PROFILE_NAMES:
        groups.setdefault(target[name], []).append(name)
    out = ""
    for value, names in groups.items():
        if len(groups) == 1:
            out = _ok(run, "SetDefaultOutbound", DefaultOutboundAction=value)
        else:
            out = _ok(run, "SetDefaultOutbound", Profiles=",".join(names), DefaultOutboundAction=value)
    try:
        states = _states(json.loads(out))
    except (ValueError, RuleError):
        states = _profiles(run)
    by_name = {s["name"]: s for s in states}

    def took(name: str) -> bool:
        s = by_name.get(name)
        if s is None:
            return False
        configured = s["configured"] if s["configured"] is not None else s["outbound"]
        return configured == target[name] and (target[name] != "Block" or s["outbound"] == "Block")
    wrong = [n for n in PROFILE_NAMES if not took(n)]
    if wrong:
        raise RuleError(f"DefaultOutboundAction did not change for: {', '.join(wrong)}")
    return states


def _remove_isolate_rules(run) -> List[str]:
    """Remove the rules of ISOLATED in whatever shape they are found, in one call (``RemoveIsolate``: every
    ``TDC-FW-ISO-*``): the cut rule, the per-fetch rules of a fetch that was still running, their stand-ins, and the
    loopback and standing fetcher rules of older versions. Returns the names that were removed (so the caller can tell
    that the cut rule was among them); what is still there afterwards is raised."""
    data = _json(_ok(run, "RemoveIsolate"), "the removal of the ISOLATED rules")
    still = data.get("still") if isinstance(data, dict) else None
    if isinstance(still, str):
        still = [still]
    if not isinstance(still, list):
        raise RuleError("cannot read what is left of the ISOLATED rules")
    if still:
        raise RuleError(f"{', '.join(str(s) for s in still)} is still there after it was removed")
    removed = data.get("removed")
    return [str(n) for n in removed] if isinstance(removed, list) else []


def _forget(settings, stuck=(), **also: Any) -> None:
    """Forget the marker and the memory in one write; ``stuck`` stays recorded, ``also`` is written with them."""
    settings.set(isolated=False, outbound_before=None, isolated_since=None, allow_disabled=list(stuck), **also)


# ---- Windows' own outbound Allow rules -------------------------------------------------------
# DefaultOutboundAction Block governs only the traffic that no rule matches, and a stock Windows ships enabled
# outbound Allow rules (Core Networking's DNS, DHCP, Teredo, IP-HTTPS, Group Policy, the Store apps' rules...).
# An explicit Block beats an Allow, but a default does not, so ISOLATED switches those rules off itself and puts
# back exactly the ones it switched off.

ALLOW_OUT_CHUNK = 6000     # base64 characters per call: far under the 32767 of a Windows command line


def _allow_view(raw: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(raw, dict):
        return None
    name = str(raw.get("Name") or "")
    if not name or name.startswith(RULE_PREFIX):
        return None
    source = str(raw.get("Source") or "").strip()
    return {"name": name, "display": str(raw.get("DisplayName") or "").strip() or name,
            "group": str(raw.get("Group") or "").strip(), "source": source or "unknown",
            "local": source.lower() == "local"}


def allowed_out(run) -> List[Dict[str, Any]]:
    """Every enabled outbound Allow rule in force that is not TDC's: ``[{name, display, group, source, local}]``.

    Each of them still lets traffic out under ``DefaultOutboundAction Block``. ``local`` (``source`` ``Local``)
    is a rule of this machine, which ISOLATED can switch off; any other source, a group policy above all, cannot be
    switched off from here. Raises ``RuleError`` when the list cannot be read: "cannot tell" is never "none".
    """
    return _allow_out_state(run)[1]


def _allow_out_state(run) -> Tuple[Optional[List[Dict[str, Any]]], List[Dict[str, Any]]]:
    """``(profiles, rules)`` from one ``AllowOut`` call: the profiles as ``_profiles`` gives them (None when the answer
    has no readable profiles) and the rules as ``allowed_out`` gives them."""
    data = _json(_ok(run, "AllowOut"), "the outbound allow rules")
    try:
        states: Optional[List[Dict[str, Any]]] = _states(data.get("profiles")) if isinstance(data, dict) else None
    except RuleError:
        states = None
    rows = data.get("rules") if isinstance(data, dict) else None
    if isinstance(rows, dict):
        rows = [rows]
    if not isinstance(rows, list):
        raise RuleError("cannot read the outbound allow rules")
    found = [v for v in (_allow_view(r) for r in rows) if v is not None]
    return states, sorted(found, key=lambda r: r["name"].lower())


def _clean_rule_names(names: Any) -> List[str]:
    out = []
    for name in names or ():
        if isinstance(name, str) and name and len(name) <= 1024 and not name.startswith(RULE_PREFIX) and name not in out:
            out.append(name)
    return out


def _name_chunks(names: List[str]) -> List[str]:
    """``names`` as base64 of JSON lists, each short enough for one command line."""
    chunks: List[str] = []
    batch: List[str] = []
    for name in names:
        trial = batch + [name]
        encoded = base64.b64encode(json.dumps(trial).encode("utf-8")).decode("ascii")
        if batch and len(encoded) > ALLOW_OUT_CHUNK:
            chunks.append(base64.b64encode(json.dumps(batch).encode("utf-8")).decode("ascii"))
            batch = [name]
        else:
            batch = trial
    if batch:
        chunks.append(base64.b64encode(json.dumps(batch).encode("utf-8")).decode("ascii"))
    return chunks


def _set_allow_out(run, names: Any, on: bool, cancelled: Optional[Callable[[], bool]] = None
                   ) -> Tuple[List[str], List[Dict[str, str]], List[str], List[str]]:
    """Switch the named local outbound Allow rules on or off: ``(done, failed, missing, unreached)``.

    ``failed`` is ``[{name, problem}]``; ``missing`` the names that are no longer there as a local outbound Allow
    rule. ``cancelled`` is asked between two chunks (not before the first: the caller asks before the step), and when
    it says True the rest is not sent: ``unreached`` names what no call was made for. A call that fails as a whole
    raises ``RuleError``; what is done before it stays done."""
    op = "EnableAllowOut" if on else "DisableAllowOut"
    done: List[str] = []
    failed: List[Dict[str, str]] = []
    missing: List[str] = []
    chunks = _name_chunks(_clean_rule_names(names))
    for index, chunk in enumerate(chunks):
        if index and cancelled is not None and cancelled():
            unreached = [n for rest in chunks[index:] for n in json.loads(base64.b64decode(rest).decode("utf-8"))]
            return done, failed, missing, unreached
        data = _json(_ok(run, op, Names=chunk), op)
        if not isinstance(data, dict):
            raise RuleError(f"cannot read the answer of {op}")

        def listed(value):
            return value if isinstance(value, list) else [] if value is None else [value]
        done += [str(n) for n in listed(data.get("done")) if isinstance(n, str)]
        missing += [str(n) for n in listed(data.get("missing")) if isinstance(n, str)]
        failed += [{"name": str(f.get("Name") or ""), "problem": _first_line(f.get("Error")) or "no message"}
                   for f in listed(data.get("failed")) if isinstance(f, dict)]
    return done, failed, missing, []


def _reopen(run, names: Any) -> Tuple[List[str], Optional[str]]:
    """Switch the rules ISOLATED switched off on again: ``(stuck, problem)``, the names that are still off and
    why. A rule that is gone is not stuck: there is nothing left to put back."""
    names = _clean_rule_names(names)
    if not names:
        return [], None
    try:
        _, failed, _, _ = _set_allow_out(run, names, True)
    except RuleError as e:
        return names, _first_line(e)
    stuck = [f["name"] for f in failed if f["name"] in names]
    return stuck, (failed[0]["problem"] if failed else None)


def _stuck_text(stuck: List[str], problem: Optional[str]) -> str:
    shown = ", ".join(stuck[:5]) + (f" and {len(stuck) - 5} more" if len(stuck) > 5 else "")
    return (f"{len(stuck)} of Windows' outbound Allow rules that ISOLATED switched off could not be switched on again "
            f"({shown}{': ' + problem if problem else ''}). They stay recorded; leaving ISOLATED again, a restart of "
            f"the web UI, or {UNISOLATE_SCRIPT} tries again.")


def _still_open(run) -> Tuple[Optional[List[Dict[str, Any]]], Optional[str]]:
    """What still lets traffic out after ISOLATED went on, read back: ``(rules, None)`` or ``(None, why not)``."""
    try:
        return allowed_out(run), None
    except RuleError as e:
        return None, _first_line(e)


def open_text(still: Optional[List[Dict[str, Any]]], error: Optional[str]) -> Optional[str]:
    """One sentence on what ISOLATED does not close, or None when the read back found nothing."""
    if error is not None or still is None:
        return (f"Which of Windows' own outbound Allow rules are still enabled could not be read ({error or 'no answer'}), "
                "so whether ISOLATED is closed is not known.")
    if not still:
        return None
    shown = ", ".join(f"{r['display']} ({r['source']})" for r in still[:5]) + (f" and {len(still) - 5} more" if len(still) > 5 else "")
    return (f"{len(still)} outbound Allow {'rule is' if len(still) == 1 else 'rules are'} still enabled and let traffic "
            f"out despite ISOLATED: {shown}. A rule set by a group policy cannot be switched off from here.")


def isolate(run, on: bool, *, settings) -> Dict[str, Any]:
    """Turn ISOLATED on or off. On has two stages: ``isolate`` cuts, ``converge`` tidies up afterwards.

    On, in this order: the profiles are read (one call) and must all be on (``ProfileOffError`` otherwise, with nothing
    changed; unreadable, nothing changed either). The previous ``DefaultOutboundAction`` and the marker are saved before
    anything else changes (when that cannot be saved nothing is touched). Then ``cut`` writes the one catch-all outbound
    Block rule and reads it back, ``settings.stage`` becomes ``cut`` and the call returns. That is all that happens here:
    the egress is shut from that moment (a Block rule beats every Allow rule), and the ~135 Allow rules of Windows are
    neither read nor touched, the default action still what it was. They need not be: before the cut nothing has been
    switched off, so there is nothing to record, and what would stay open is no question for a rule that closes by Block
    beating Allow. ``converging`` is True: the slow, thorough part is ``converge``, which the caller runs afterwards and
    in the background; it reads those rules and records the local ones in ``settings.allow_disabled`` before it switches
    any off. In stage ``cut`` ``verified`` means that the cut rule was read back as the catch-all, enabled, on all three
    profiles, and nothing more; ``allowed_out`` is not part of this answer, and **no fetch is let out while the cut
    stands** (``allow_fetch`` has nothing to get through).
    When the cut fails, a fresh isolation is undone (the marker and the memory forgotten, what it may have written
    removed; if even that fails the marker stays and the message names ``scripts/tdc-unisolate.ps1``). Isolating while
    isolated cuts again and keeps the first memory of the default action and the record of the rules switched off (a
    local rule that came back on is added to the record by the next ``converge``), and a marker without a recorded baseline (damaged) gets
    ``Allow`` as its baseline and ``note`` says so; a failure there is not undone either, because the isolation was
    already on. Returns ``{"isolated": True, "stage": "cut", "rule_id", "verified", "converging": True,
    "outbound_before", "profiles_off", "note"}``.

    TDC's own fetch is **not** allowed out by this: ``allow_fetch`` opens one address for the time of one fetch
    (see the module docstring).

    ``settings.isolated`` is the only authority for "TDC is isolating"; nothing is inferred from the profiles. An
    isolation may start from an egress that is already Block: that is recorded as the baseline like any other.

    Off: the way back, in reverse, to **the recorded baseline**: ``DefaultOutboundAction`` back to what was saved (per
    profile, when they differed), exactly the rules ISOLATED switched off switched on again, the ISOLATED rules removed
    (whatever shape they are in, the cut rule among them), the marker, the stage and the memory forgotten last, in one
    write. It works from **any** stage, a convergence that was stopped half way included: ``allow_disabled`` is recorded
    before anything is switched off, so what is put back is always complete. That is what makes the press safe to
    ask no confirmation for. The caller stops a running ``converge`` first (``cancelled``); this call then waits for
    that step to end, because both hold the same lock. A rule that will not switch on again stays
    in ``allow_disabled`` and ``note`` names it; a rule that is gone is not missed. It works whatever the profiles are.
    When the baseline is itself Block the egress stays shut: that is the VM's own baseline and not a TDC lockout, and
    ``note`` says so. With the marker but no baseline it assumes ``Allow``, the Windows default, and says so
    (``assumed_allow``). Without the marker it changes nothing but the rules a failed leaving left off and a cut rule
    that a crash left standing (it says so in ``note``), and if the egress is nonetheless shut ``note`` says that TDC
    is not the one isolating and names the hatch.
    Returns ``{"isolated": False, "changed", "assumed_allow", "cut_removed", "outbound_after", "allow_disabled",
    "note"}``, and ``profiles_off`` as read back when it changed something. ``cut_removed`` is True when the cut rule
    was among what was removed (in stage ``isolated`` it is not there any more). Both directions give ``profiles_off``
    so that the caller need not read the profiles once more.
    """
    with _locked("isolate"):
        return _isolate_on(run, settings) if on else _isolate_off(run, settings)


def _join(*parts: Optional[str]) -> Optional[str]:
    text = " ".join(p for p in parts if p)
    return text or None


def _isolate_on(run, settings) -> Dict[str, Any]:
    # Only the profiles are read before the cut: nothing is switched off yet, so there is nothing to record about
    # Windows' Allow rules, and the cut closes by Block beating Allow whether or not they could be read (``converge``
    # reads them when it needs them).
    try:
        states = _profiles(run)
    except RuleError as e:
        raise RuleError(f"the firewall profiles could not be read, so the way back cannot be recorded; nothing was "
                        f"changed ({_first_line(e)})") from e
    off = _off_names(states)
    if off:
        raise ProfileOffError(_off_text(off))
    # What is put back is what is *configured* (the PersistentStore, the store SetDefaultOutbound writes), not what
    # is in force: a NotConfigured profile is in force as Allow, and restoring that as Allow would leave the host
    # configured differently from how it was found. ``outbound`` (in force) stays the authority for the claims.
    current = {s["name"]: s["configured"] or s["outbound"] for s in states}
    marker = bool(settings.isolated)
    already = marker and settings.outbound_before is not None
    damaged = marker and settings.outbound_before is None
    note = None
    if already:
        remembered = settings.outbound_before
    elif damaged:
        remembered = "Allow"
        note = ("The ISOLATED marker had no recorded baseline, so Allow, the Windows default, is recorded as the way "
                "back; the egress is Block now because TDC shut it, not because it was the VM's baseline.")
    else:
        remembered = _encode_outbound(current)
    recorded = _clean_rule_names(getattr(settings, "allow_disabled", None))
    if not already:
        try:
            settings.set(outbound_before=remembered, isolated=True,
                         isolated_since=(settings.isolated_since or time.time()) if damaged else time.time())
        except Exception as e:
            raise RuleError(f"the way back could not be saved ({type(e).__name__}: {_first_line(e)}); "
                            "nothing was changed") from e
    try:
        made = cut(run)
    except Exception as e:
        if not marker:
            _roll_back(run, settings, recorded, e)
            if isinstance(e, RuleError):
                raise
            raise RuleError(f"the cut failed: {type(e).__name__}: {_first_line(e)}") from e
        if isinstance(e, ProfileOffError):
            raise
        raise RuleError(f"{_first_line(e)}. ISOLATED was on and stays on. Whether the cut rule was written again is "
                        "not known (the call can fail after the rule was written); the state reads it again. If the "
                        "cut shows as not confirmed, press again, or CUT AGAIN in the band.") from e
    try:
        settings.set(stage="cut")
        staged = None
    except Exception as e:
        staged = (f"The cut stands, but the stage could not be saved ({type(e).__name__}: {_first_line(e)}); "
                  "the file may still name an earlier stage.")
    problem = None if made["verified"] else f"The cut rule is not confirmed: {made['problem']}."
    return {"isolated": True, "stage": "cut", "rule_id": made["rule_id"], "verified": bool(made["verified"]),
            "converging": True, "outbound_before": remembered, "profiles_off": [],
            "note": _join(note, problem, staged)}


def converge(run, *, settings, cancelled: Callable[[], bool]) -> Dict[str, Any]:
    """The thorough half of ISOLATED, after ``isolate`` cut. It reads Windows' own enabled outbound Allow rules
    (``allowed_out``; unreadable means nothing is switched off), records the *local* ones in ``settings.allow_disabled``
    **before** it switches them off (not saved means none is touched), sets ``DefaultOutboundAction Block`` and reads it
    back, reads back what still lets traffic out, and then, when nothing does, removes the cut rule. It takes tens of
    seconds (one call per step, each of them seconds), which is why it is not part of the press: the caller runs it in
    the background.

    No marker, no work: when ``settings.isolated`` is False (a leave came first) it changes nothing and says so
    (``refused``), because a worker that outlived a leave would switch off again the very rules the leave switched on.

    ``cancelled`` is asked before **every** PowerShell step (the read of the rules, their switching off, Block, the read
    back, the read of the cut rule, its removal) and between the chunks of the switching off, and the work stops at the
    next one when it says True: ``{"cancelled": True, "stage": "cut"}``. A switching off stopped between its chunks
    leaves the rest of the rules on; every one of them, switched off or not reached, was recorded before the first chunk,
    so leaving still puts back all that was switched off (switching on one that is on changes nothing). An exception
    from ``cancelled`` itself is not caught, wherever it is asked: it is the caller's bug, not a failed step. The cut
    rule is still standing then, so the egress is shut; what was switched off stays
    recorded in ``settings.allow_disabled``, and leaving puts it back. The cut rule falls last, after the default is Block
    and the rules are off, so that at no moment is anything open. When something is still enabled that cannot be switched
    off from here (a group policy), the cut rule **stays**: it is the only thing that closes the egress there
    (``stage`` ``cut_policy``). A step that fails leaves the cut rule standing too and ends in ``stage`` ``cut``, with
    the failure in ``note``; nothing is rolled back, because the state is closed and the way back is in ``allow_disabled``.

    Returns ``{"stage", "verified", "allowed_out", "allowed_out_error", "cancelled", "refused", "note"}``. ``verified``
    means, where the cut rule stands (``cut_policy``), that the **cut rule was read back**, and nothing more; in
    ``isolated``, where it is gone, Block read back, the Allow list read back empty and the rule read as gone. The cut
    rule closes the egress whether or not the
    list of Allow rules could be read, because a Block rule beats every Allow rule. An unreadable list decides only
    whether the rule may be dropped, and then it may not. So ``verified`` is True in ``cut_policy`` (the rule read back as
    standing) and in ``isolated`` (Block read back, the list read and empty, the rule read as gone); do not "fix" the
    first by tying it to the list."""
    with _locked("converge"):
        return _converge(run, settings, cancelled)


def _converge(run, settings, cancelled: Callable[[], bool]) -> Dict[str, Any]:
    raised: List[BaseException] = []

    def asked() -> bool:
        # an exception from the callback is the caller's bug: noted here so the catch-all below lets it through
        try:
            return cancelled()
        except BaseException as e:
            raised.append(e)
            raise

    def result(stage: str, note: Optional[str] = None, *, verified: bool = False, still=None, error=None,
               stopped: bool = False, refused: bool = False) -> Dict[str, Any]:
        return {"stage": stage, "verified": verified, "allowed_out": still, "allowed_out_error": error,
                "cancelled": stopped, "refused": refused, "note": note}

    if not settings.isolated:
        return result("open", "ISOLATED is not on (there is no marker), so nothing was changed.", refused=True)
    if asked():
        return result("cut", "Cancelled before anything was read; the cut stands.", stopped=True)
    try:
        _, foreign = _allow_out_state(run)
    except Exception as e:
        return result("cut", f"Windows' own outbound Allow rules could not be read, so none was switched off ({_first_line(e)}); "
                             "the cut stands and the egress is shut.")
    recorded = _clean_rule_names(getattr(settings, "allow_disabled", None))
    closing = _clean_rule_names(recorded + [r["name"] for r in foreign if r["local"]])
    try:
        if closing != recorded:
            try:
                settings.set(allow_disabled=closing)
            except Exception as e:
                raise RuleError(f"the way back could not be saved ({type(e).__name__}: {_first_line(e)}); "
                                "no rule was switched off") from e
        if asked():
            return result("cut", "Cancelled before anything was switched off; the cut stands.", stopped=True)
        # the flag is asked between the chunks too: a press or a leave must not wait out a step of 135 rules
        _, _, _, unreached = _set_allow_out(run, closing, False, asked)     # one that stays on is read back below
        if unreached:
            return result("cut", f"Cancelled while Windows' Allow rules were being switched off: "
                                 f"{len(closing) - len(unreached)} of {len(closing)} were sent, {len(unreached)} were "
                                 "not reached. The cut stands, and all of them stay recorded, so leaving puts back "
                                 "every one that was switched off.", stopped=True)
        if asked():
            return result("cut", "Cancelled after Windows' Allow rules were switched off; the cut stands.", stopped=True)
        off = _off_names(_apply_outbound(run, {n: "Block" for n in PROFILE_NAMES}))
        if off:
            raise RuleError(_off_text(off))
        if asked():
            return result("cut", "Cancelled after the default action was set to Block; the cut stands.", stopped=True)
        still, error = _still_open(run)
    except Exception as e:
        if raised:
            raise
        return result("cut", f"The thorough part of ISOLATED did not finish ({_first_line(e)}); the cut stands and the "
                             "egress is shut. Leaving ISOLATED puts back what was switched off.")
    if still == []:
        if asked():
            return result("cut", "Cancelled before the cut rule was removed; the cut stands.", still=still, stopped=True)
        gone = uncut(run)
        if not gone["removed"]:
            return result("cut", f"The cut rule could not be removed ({gone['problem']}); it stands and the egress is shut.",
                          still=still)
        stage, verified, note = "isolated", True, None
    else:
        if asked():
            return result("cut", "Cancelled before the cut rule was read back; the cut stands.", still=still, error=error,
                          stopped=True)
        stands = cut_stands(run)
        stage, verified = "cut_policy", stands is True
        if stands:
            holds = "The cut rule stays and is read back as standing: it is what closes the egress here."
        else:
            holds = "The cut rule could not be read back as standing, so whether the egress is shut is not known."
        if still is None:
            note = _join(f"Which of Windows' own outbound Allow rules are still enabled could not be read "
                         f"({error or 'no answer'}), so the thorough state is not reached.", holds)
        else:
            note = _join(open_text(still, error), holds)
    try:
        settings.set(stage=stage)
    except Exception as e:
        note = _join(note, f"The stage could not be saved ({type(e).__name__}: {_first_line(e)}).")
    return result(stage, note, verified=verified, still=still, error=error)


def _roll_back(run, settings, recorded: List[str], cause: BaseException) -> None:
    """A fresh isolation whose cut failed: forget the marker and the memory (``recorded``, the rules an earlier failed
    leaving left off, stays) and remove what the cut may have written. If that fails too the marker stays, because
    the state is not known and a marker is what makes the next start announce it."""
    try:
        _remove_isolate_rules(run)
        _forget(settings, recorded, stage="open")
    except Exception as e:
        raise RuleError(f"isolating failed ({_first_line(cause)}) and could not be undone ({_first_line(e)}); the egress "
                        f"may be shut. Run {UNISOLATE_SCRIPT} on the VM to open it.") from e


def _isolate_off(run, settings) -> Dict[str, Any]:
    if not settings.isolated:
        return _not_isolating(run, settings)
    target = _decode_outbound(settings.outbound_before)
    assumed = target is None
    if assumed:
        target = {n: "Allow" for n in PROFILE_NAMES}
    states = _apply_outbound(run, target)
    stuck, problem = _reopen(run, getattr(settings, "allow_disabled", None))
    removed = _remove_isolate_rules(run)
    _forget(settings, stuck, stage="open")
    shut = [n for n in PROFILE_NAMES if target[n] == "Block"]
    note = None
    if assumed:
        note = "No baseline was recorded; Allow, the Windows default, was assumed."
    elif shut:
        note = (f"The baseline recorded before ISOLATED is Block on {', '.join(shut)}: outbound stays shut there, "
                "and TDC's own fetch is no longer let out either. That is the VM's own baseline, not a TDC lockout.")
    return {"isolated": False, "changed": True, "assumed_allow": assumed, "cut_removed": CUT_RULE in removed,
            "outbound_after": target, "allow_disabled": stuck, "profiles_off": _off_names(states),
            "note": _join(note, _stuck_text(stuck, problem) if stuck else None)}


def _not_isolating(run, settings) -> Dict[str, Any]:
    """Leaving ISOLATED when TDC is not isolating: nothing is changed but the rules a failed leaving left switched
    off and a cut rule that a crash left standing (a catch-all Block with no marker is the state in which someone needs
    help, so it goes and the note says so; it is looked for first, so that with none there nothing is written), and an
    egress that is shut anyway is said."""
    cut_removed = False
    cut_problem = None
    try:
        try:
            standing = _describe(run, CUT_RULE) is not None
        except RuleError:
            standing = True             # cannot tell: sweeping is harmless, a catch-all left standing is not
        if standing:
            cut_removed = CUT_RULE in _remove_isolate_rules(run)
    except Exception as e:
        cut_problem = _first_line(e)
    leftover = _clean_rule_names(getattr(settings, "allow_disabled", None))
    stuck: List[str] = []
    problem = None
    if leftover:
        stuck, problem = _reopen(run, leftover)
        try:
            settings.set(allow_disabled=stuck)
        except Exception:
            pass                    # the record stays as it was; switching on again is harmless to repeat
    try:
        current: Optional[Dict[str, str]] = {s["name"]: s["outbound"] for s in _profiles(run)}
    except RuleError:
        current = None
    changed = cut_removed or len(stuck) < len(leftover)
    shut = ", ".join(n for n in PROFILE_NAMES if current and current[n] == "Block")
    parts: List[Optional[str]] = []
    if cut_removed:
        parts.append(f"{CUT_RULE} was standing without a marker (a crash left it); it was removed.")
    elif cut_problem:
        parts.append(f"{CUT_RULE} may be standing without a marker and could not be removed ({cut_problem}).")
    if shut:
        parts.append(f"Outbound is still blocked on {shut}, and TDC is not isolating (there is no marker)." if changed else
                     f"TDC is not isolating (there is no marker), so nothing was changed, but outbound is blocked on {shut}.")
    if shut or (cut_problem and not cut_removed):
        parts.append(f"{'If that is not wanted, run' if shut else 'Run'} {UNISOLATE_SCRIPT} on the VM.")
    if stuck:
        parts.append(_stuck_text(stuck, problem))
    return {"isolated": False, "changed": changed, "assumed_allow": False,
            "cut_removed": cut_removed, "outbound_after": current, "allow_disabled": stuck, "note": _join(*parts)}


def _recorded_stage(settings, marker: bool) -> str:
    """The stage the settings name, for a state that cannot be judged from the firewall. A stage without a marker is not
    a stage; a marker with no stage saved means the press died after the marker and before the stage, and the press
    writes the marker before it cuts, so the cut is the stage that is at least in question."""
    if not marker:
        return "open"
    stage = getattr(settings, "stage", "open")
    return stage if stage in STAGES and stage != "open" else "cut"


def _startup_kind(marker: bool, off: List[str], blocking: List[str], cut: str) -> str:
    """What the start-up found, from four facts only: the marker, the profiles that are off, the profiles whose default
    is Block (``blocking``) and the cut rule (``cut``: ``full`` | ``wrong`` (there, not a full cut) | ``absent`` |
    ``unreadable``). Every start-up decision follows from this one answer and nothing else, so each combination has one
    place and cannot be caught by whichever arm happens to come first:

    - ``unmarked``: no marker (whatever else is found is announced and left alone).
    - ``in_force``: marker, no profile off, and the egress is shut: Block on all three or a full cut rule.
    - ``off``: marker, not in force, a profile is off, and something was meant to shut it: some Block or a cut rule that
      stands or cannot be read. A profile that is off is never shut, so this is never isolated.
    - ``unknown``: marker, nothing is off, the egress is not known to be shut and the cut rule cannot be read. The marker
      is believed (the precedent of an unreadable firewall): isolated, announced, nothing changed.
    - ``partial``: marker, nothing off, Block on some profiles only, and no full cut: not a working isolation.
    - ``stale``: marker, and no Block and no full cut and nothing unreadable: the egress is open (the hatch was used or the
      switch never happened). The one kind that clears the marker.
    """
    if not marker:
        return "unmarked"
    if not off and (len(blocking) == len(PROFILE_NAMES) or cut == "full"):
        return "in_force"
    if off and (blocking or cut in ("full", "unreadable")):
        return "off"
    if cut == "unreadable":
        return "unknown"
    return "partial" if blocking else "stale"


def startup_state(run, settings) -> Dict[str, Any]:
    """What the firewall is like when the service starts: ``{"isolated", "profiles_off", "announce", "note",
    "allowed_out", "stage"}``.

    ``settings.isolated`` (the marker) is the only authority for "TDC is isolating"; the firewall is only checked
    against it. ``isolated`` is True when there is a marker **and** the enforcement is in force: all three profiles on
    and either the default action Block on all three **or** ``CUT_RULE`` standing (a Block rule beats every Allow
    rule). Whatever is found here was not set in this session, so it is announced and **never lifted**: a crash in the
    middle of a detonation must not open the egress. The only thing that is ever switched is an Allow rule back on, and
    only where that opens nothing: ``_startup_kind`` is the single place that says which state this is, and the
    one call that touches enforcement (``_reopen``) sits behind one guard.

    ``stage`` is what is found, not what was saved: ``cut`` when a cut rule stands and the thorough part has not been
    reached (the default is not Block on every profile, or the rule was not dropped after it), ``cut_policy`` when the
    default is Block and something still lets traffic out (a cut rule is what closes it when it stands), ``isolated``
    when the default is Block, nothing lets traffic out and the cut rule is gone, ``open`` when no enforcement is in
    force (with a marker that is a coarse label: it does not say the marker may be pressed again). When the cut rule
    cannot be read, the stage cannot be judged and the recorded one is given where the marker is believed; where it is
    not, ``open``. A marker's saved stage is **written** when it differs from what was found (bookkeeping, no rule
    changes; a failed write is said in ``note``), but never when the cut rule could not be read: whoever reads
    ``settings.stage`` must read the stage that holds, and an unreadable rule may be a true ``cut``. A ``CUT_RULE`` that
    is there but not a full cut (disabled, narrowed) is no cut: it is named in ``note`` and announced in every case, left
    alone because removing a rule that blocks part of the egress could open it, and it keeps the stage from being
    ``isolated`` (the rule is not dropped).

    By ``_startup_kind``:

    - ``in_force``: ``isolated``, announced, nothing changed. With Block on all three, Windows' own outbound Allow rules
      that are still enabled are read back into ``allowed_out`` and named in ``note``. A cut rule over a default that is
      not (all) Block is the state a crash in stage ``cut`` leaves: clearing the marker as stale (what this function once
      did) would switch Windows' Allow rules on again and leave a catch-all Block rule that nobody owns.
    - ``off``: not isolated (neither the default nor the cut rule applies where the firewall is off), announced, kept.
    - ``unknown``: the marker is believed, ``isolated``, announced, nothing changed, the note says it is not known.
    - ``partial``: Block on some profiles only: not isolated, announced, marker kept.
    - ``stale``: the rules ISOLATED switched off are switched on again and the marker and the stage are cleared (with the
      egress open, neither opens anything), announced.
    - ``unmarked``: outbound shut anyway (a Block default or a standing cut rule): not isolated, announced, nothing
      changed - except that the Allow rules a failed leaving left off are switched on again when a full cut rule stands
      (a Block rule beats them, so that opens nothing; with only the default on Block it would, so they stay off). With
      outbound open they are switched on again too; announced if any stays off. A stage saved without a marker is set back
      to ``open``.
    - cannot read the firewall: the marker is believed, announced.

    It holds the module's lock for its whole run: it writes the stage, can forget the marker and can switch rules on,
    and a press or a convergence must not interleave with that.
    """
    with _locked("startup_state"):
        return _startup_state(run, settings)


def _startup_state(run, settings) -> Dict[str, Any]:
    marker = bool(settings.isolated)
    saved = getattr(settings, "stage", "open")
    if not marker and saved != "open":
        try:
            settings.set(stage="open")
        except Exception:
            pass                    # bookkeeping only: the answer below never reads the saved stage without a marker
    try:
        states = _profiles(run)
    except RuleError as e:
        return {"isolated": marker, "profiles_off": [], "announce": True, "allowed_out": None,
                "stage": _recorded_stage(settings, marker), "note": f"the firewall could not be read: {_first_line(e)}"}
    off = _off_names(states)
    blocking = [s["name"] for s in states if s["outbound"] == "Block"]
    all_block = len(blocking) == len(PROFILE_NAMES)
    # one read of the cut rule says all of it; ``cut_stands`` would call a rule that is there but not a full cut False,
    # like an absent one
    try:
        view = _describe(run, CUT_RULE)
        cut = "absent" if view is None else "full" if _cut_problem(view) is None else "wrong"
    except RuleError:
        view, cut = None, "unreadable"
    kind = _startup_kind(marker, off, blocking, cut)
    leftover = _clean_rule_names(getattr(settings, "allow_disabled", None))
    malformed = (f"{CUT_RULE} was found, but it is not a full cut ({_cut_problem(view)}). It was left alone on purpose, "
                 f"because removing a rule that blocks only part of the egress could open it; {UNISOLATE_SCRIPT} removes it."
                 if cut == "wrong" else None)
    cut_text = (f"{CUT_RULE} could not be read, so whether the egress is shut by it is not known; nothing was changed."
                if cut == "unreadable" else None)

    # the one guard in front of the one call that touches enforcement: the egress is open already, or a full cut rule
    # stands (a Block rule beats the Allow rules, so switching them on opens nothing)
    reopen = kind == "stale" or (kind == "unmarked" and (not blocking or cut == "full"))
    stuck: List[str] = []
    problem = None
    if reopen and leftover:
        stuck, problem = _reopen(run, leftover)
    reopened = len(leftover) - len(stuck) if reopen else 0

    note = None
    still = None
    stage = "open"
    isolated = kind in ("in_force", "unknown")
    announce = marker or bool(blocking) or cut == "full" or malformed is not None
    derived = cut != "unreadable"       # the stage comes from what was found, and so may be saved
    if kind == "in_force" and all_block:
        still, error = _still_open(run)
        note = _join("ISOLATED is on: the default outbound action is Block on every profile, and the outbound Allow "
                     "rules of Windows' own that ISOLATED switched off stay off; loopback, and TDC's own fetch to one "
                     "address for the seconds that fetch takes, are let out.",
                     f"{CUT_RULE} stands as well and shuts the egress by itself." if cut == "full" else None,
                     open_text(still, error) or "The read back found no other outbound Allow rule enabled.", cut_text)
        if cut == "unreadable":
            stage = _recorded_stage(settings, marker)
        elif cut != "absent":           # a rule that is there, a full cut or not, is not a cut that was dropped
            stage = "cut" if still == [] else "cut_policy"
        else:
            stage = "isolated" if still == [] else "cut_policy"
    elif kind == "in_force":
        stage = "cut"
        note = (f"ISOLATED is on, from the cut: {CUT_RULE} stands and shuts the egress (a Block rule beats every Allow "
                "rule), but the default outbound action is not Block on every profile yet, so the thorough part did "
                "not finish and Windows' own outbound Allow rules may still be enabled. Nothing was changed; leaving "
                "ISOLATED puts back what was switched off.")
    elif kind == "off":
        if blocking:
            note = _join(f"ISOLATED is marked, but outbound is blocked on {', '.join(blocking)} only and the firewall is "
                         f"off for {', '.join(off)}: this is not a working isolation.",
                         f"{CUT_RULE} stands, but it does not apply where the firewall is off." if cut == "full" else None,
                         cut_text)
        elif cut == "full":
            note = (f"ISOLATED is marked and {CUT_RULE} stands, but the firewall is off for {', '.join(off)}, where the "
                    "rule does not apply: this is not a working isolation.")
        else:
            note = _join(f"ISOLATED is marked and the firewall is off for {', '.join(off)}, where nothing applies: this is "
                         "not a working isolation.", cut_text)
    elif kind == "unknown":
        stage = _recorded_stage(settings, marker)
        default = f"outbound is blocked on {', '.join(blocking)} only" if blocking else "the default outbound action is not Block"
        note = _join(f"ISOLATED is marked and {default}, so the egress is shut only if the cut rule stands.", cut_text)
    elif kind == "partial":
        note = (f"ISOLATED is marked, but outbound is blocked on {', '.join(blocking)} only: this is not a working "
                "isolation.")
    elif kind == "stale":
        derived = False             # _forget writes the stage with the marker
        try:
            _forget(settings, stuck, stage="open")
            note = _join("A stale ISOLATED marker was cleared: outbound is open (was scripts/tdc-unisolate.ps1 run?).",
                         _stuck_text(stuck, problem) if stuck else None)
        except Exception as e:
            note = f"The ISOLATED marker is stale but could not be cleared: {_first_line(e)}"
    else:                           # unmarked
        derived = False
        if leftover and reopen:
            try:
                settings.set(allow_disabled=stuck)
            except Exception:
                pass                # the record stays as it was; switching on again is harmless to repeat
        if blocking or cut == "full":
            parts = [f"Outbound is blocked on {', '.join(blocking)}, but TDC did not set it (there is no ISOLATED marker)."
                     if blocking else None,
                     f"{CUT_RULE} stands as well and shuts the egress." if blocking and cut == "full" else
                     f"{CUT_RULE} stands and shuts the egress, but TDC did not set it (there is no ISOLATED marker)."
                     if cut == "full" else None]
            if reopened:
                announce = True
                parts.append(f"{reopened} of Windows' outbound Allow rules that a failed leaving switched off "
                             f"{'was' if reopened == 1 else 'were'} switched on again, which opens nothing while "
                             f"{CUT_RULE} stands; {UNISOLATE_SCRIPT} opens the egress.")
            else:
                parts.append(f"Nothing was changed; {UNISOLATE_SCRIPT} opens it.")
            note = _join(*parts)
        if stuck:
            note, announce = _join(note, _stuck_text(stuck, problem)), True
    note = _join(note, malformed)
    if marker and derived and stage != saved:
        try:
            settings.set(stage=stage)
        except Exception as e:
            note = _join(note, f"The stage found ({stage}) could not be saved ({type(e).__name__}: {_first_line(e)}); "
                               f"the file still names {saved}.")
    return {"isolated": isolated, "profiles_off": off, "announce": announce, "note": note, "allowed_out": still,
            "stage": stage}
