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
after the switch (``allowed_out``) and said, and ISOLATED is ``verified`` only when that list is empty. The order is:
profiles checked, Windows' rules read, the previous ``DefaultOutboundAction``, the rule names and the marker saved
in ``Settings`` *before* anything changes, Windows' rules switched off, then Block, then read back. Leaving goes
backwards and is never refused for a profile that is off. Every step is one PowerShell call however many rules
it touches, because a call costs seconds on a small VM: ISOLATED on is four calls, off is three.

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
from typing import Any, Dict, List, Optional, Tuple

import firewall

RULE_PREFIX = "TDC-FW-"
ISOLATE_PREFIX = RULE_PREFIX + "ISO-"
LOOPBACK_RULE = ISOLATE_PREFIX + "loopback"  # written by older versions: only removed now (see the module docstring)
FETCHER_RULE = ISOLATE_PREFIX + "fetcher"     # the standing fetcher rule of older versions: only removed now
FETCH_PREFIX = ISOLATE_PREFIX + "fetch-"      # one allow rule per fetch, for as long as that fetch lasts

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
    try:
        rc, out, err = run(args)
    except Exception as e:
        raise RuleError(f"could not run {args[0]}: {type(e).__name__}: {_first_line(e)}") from e
    return int(rc), out or "", err or ""


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


def _is_local_only(address: str) -> bool:
    addr = ipaddress.ip_address(address)
    return addr.is_loopback or addr.is_unspecified or addr.is_multicast


def _block_spec(image: Any, ip: Any, port: Any, protocol: Any) -> Dict[str, Any]:
    program = _clean_path(image, "image") if image is not None else None
    address = _clean_ip(ip) if ip is not None else None
    if program is None and address is None:
        raise RuleError("a block needs a program, an address, or both")
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


def enable_firewall(run) -> None:
    """Switch Domain, Private and Public on (``Set-NetFirewallProfile -Enabled True``) and check that they are.

    This changes what the malware sees, so TDC never does it by itself: the caller asks the analyst first.
    """
    with _LOCK:
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

    Two blocks would cut TDC off from itself and are refused. A block for every program (no ``image``) on an address
    that is loopback, unspecified or multicast: that is where the lockout lives, while a block that names a program
    touches only that program, so a sample's own loopback, mDNS or SSDP traffic can be cut. And a block on any program
    of ``fetcher``, because an explicit Block beats the per-fetch Allow rule of ISOLATED. This module cannot know the
    fetcher's path, so ``fetcher`` is a **required** keyword: the caller passes the ``python.exe`` of the web UI venv
    (and the base interpreter behind it, as a list), the same paths it gives ``allow_fetch``. ``fetcher=None`` is the
    explicit opt-out; leaving it out is a ``TypeError``.
    """
    spec = _block_spec(image, ip, port, protocol)
    for program in _fetcher_paths(fetcher):
        if spec["image"] is not None and _same_path(spec["image"], program):
            raise RuleError("that program is TDC's own fetcher: blocking it would cut TDC off from its fetch targets")
    with _LOCK:
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
    with _LOCK:
        _ok(run, "Remove", Name=rule_id)
        if _describe(run, rule_id) is not None:
            raise RuleError(f"{rule_id} is still there after it was removed")


def verify(run, rule_id: str) -> bool:
    """Whether ``rule_id`` is a Block rule that stands now: there, outbound, enabled, and every profile it covers on.

    False for anything else, and for anything that cannot be read: it never raises.
    """
    try:
        if not isinstance(rule_id, str) or not _NAME.fullmatch(rule_id):
            return False
        view = _describe(run, rule_id)
        return view is not None and view["action"] == "block" and _standing_problem(view, _profiles(run)) is None
    except RuleError:
        return False


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
    with _LOCK:
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
    with _LOCK:
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
    """
    removed: List[str] = []
    stuck: List[Dict[str, str]] = []
    with _LOCK:
        for rule in rules(run):
            name = rule["rule_id"]
            if not (name.startswith(FETCH_PREFIX) or name in (FETCHER_RULE, FETCHER_RULE + SWAP_SUFFIX)):
                continue
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

    ``{rule_id, name, kind, action, enabled, image, ip, port, protocol, key, blocking}``. ``kind`` is ``"block"``
    (written by ``block``) or ``"isolate"`` (the allow rules of ISOLATED). ``blocking`` is True for a Block rule
    that stands, in the shape ``block`` writes, with every profile it covers on; ``key`` is then
    ``firewall.rule_key`` of the rule's real image, address and port. A rule that is listed but not
    ``blocking`` (disabled, a profile off, or changed by someone) must not be shown as a block.

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
        blocking = kind == "block" and view["action"] == "block" and canonical and standing
        listed.append({"rule_id": name, "name": name, "kind": kind, "action": view["action"].capitalize(),
                       "enabled": view["enabled"], "image": image, "ip": ip, "port": port, "protocol": protocol,
                       "key": firewall.rule_key(image or "", ip or "", port) if canonical else None,
                       "blocking": blocking})
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


def _remove_isolate_rules(run) -> None:
    """Remove the allow rules of ISOLATED in whatever shape they are found, in one call (``RemoveIsolate``: every
    ``TDC-FW-ISO-*``): the per-fetch rules of a fetch that was still running, their stand-ins, and the loopback
    and standing fetcher rules of older versions. What is still there afterwards is raised."""
    data = _json(_ok(run, "RemoveIsolate"), "the removal of the ISOLATED rules")
    still = data.get("still") if isinstance(data, dict) else None
    if isinstance(still, str):
        still = [still]
    if not isinstance(still, list):
        raise RuleError("cannot read what is left of the ISOLATED rules")
    if still:
        raise RuleError(f"{', '.join(str(s) for s in still)} is still there after it was removed")


def _forget(settings, stuck=()) -> None:
    settings.set(isolated=False, outbound_before=None, isolated_since=None, allow_disabled=list(stuck))


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


def _set_allow_out(run, names: Any, on: bool) -> Tuple[List[str], List[Dict[str, str]], List[str]]:
    """Switch the named local outbound Allow rules on or off: ``(done, failed, missing)``.

    ``failed`` is ``[{name, problem}]``; ``missing`` the names that are no longer there as a local outbound Allow
    rule. A call that fails as a whole raises ``RuleError``; what is done before it stays done."""
    op = "EnableAllowOut" if on else "DisableAllowOut"
    done: List[str] = []
    failed: List[Dict[str, str]] = []
    missing: List[str] = []
    for chunk in _name_chunks(_clean_rule_names(names)):
        data = _json(_ok(run, op, Names=chunk), op)
        if not isinstance(data, dict):
            raise RuleError(f"cannot read the answer of {op}")

        def listed(value):
            return value if isinstance(value, list) else [] if value is None else [value]
        done += [str(n) for n in listed(data.get("done")) if isinstance(n, str)]
        missing += [str(n) for n in listed(data.get("missing")) if isinstance(n, str)]
        failed += [{"name": str(f.get("Name") or ""), "problem": _first_line(f.get("Error")) or "no message"}
                   for f in listed(data.get("failed")) if isinstance(f, dict)]
    return done, failed, missing


def _reopen(run, names: Any) -> Tuple[List[str], Optional[str]]:
    """Switch the rules ISOLATED switched off on again: ``(stuck, problem)``, the names that are still off and
    why. A rule that is gone is not stuck: there is nothing left to put back."""
    names = _clean_rule_names(names)
    if not names:
        return [], None
    try:
        _, failed, _ = _set_allow_out(run, names, True)
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
    """Turn ISOLATED on or off.

    On, in this order: all profiles must be on (``ProfileOffError`` otherwise, with nothing changed). Windows' own enabled
    outbound Allow rules are read (``allowed_out``); when they cannot be, nothing is changed, because what would stay
    open is not known. The previous ``DefaultOutboundAction``, the marker and the names of the *local* rules about to
    be switched off (``settings.allow_disabled``) are saved before anything else changes (when that cannot be saved
    nothing is touched). Then those rules are switched off, ``DefaultOutboundAction Block`` is set and read back, and what still lets traffic out is read back. When a step
    fails, a fresh isolation is rolled back in reverse; if even that fails the marker stays and the message names
    ``scripts/tdc-unisolate.ps1``. Isolating while isolated keeps the first memory of the default action, adds any
    local rule that is enabled again to the record and switches it off; a marker without a recorded baseline (damaged)
    gets ``Allow`` as its baseline and ``note`` says so, and a failure there is not rolled back either, because the
    isolation was already on. Returns ``{"isolated": True, "outbound_before", "verified", "allowed_out",
    "allowed_out_error", "profiles_off", "note"}``: ``allowed_out`` is what the read back found still enabled (a rule set by a group
    policy cannot be switched off from here), and ``verified`` is True only when Block was read back **and** that list
    was read and is empty. ``note`` says what stays open.

    TDC's own fetch is **not** allowed out by this: ``allow_fetch`` opens one address for the time of one fetch
    (see the module docstring).

    ``settings.isolated`` is the only authority for "TDC is isolating"; nothing is inferred from the profiles. An
    isolation may start from an egress that is already Block: that is recorded as the baseline like any other.

    Off: the way back, in reverse, to **the recorded baseline**: ``DefaultOutboundAction`` back to what was saved (per
    profile, when they differed), exactly the rules ISOLATED switched off switched on again, the allow rules removed
    (whatever shape they are in), the marker and the memory forgotten last. A rule that will not switch on again stays
    in ``allow_disabled`` and ``note`` names it; a rule that is gone is not missed. It works whatever the profiles are.
    When the baseline is itself Block the egress stays shut: that is the VM's own baseline and not a TDC lockout, and
    ``note`` says so. With the marker but no baseline it assumes ``Allow``, the Windows default, and says so
    (``assumed_allow``). Without the marker it changes nothing but the rules a failed leaving left off, and if the
    egress is nonetheless shut ``note`` says that TDC is not the one isolating and names the hatch.
    Returns ``{"isolated": False, "changed", "assumed_allow", "outbound_after", "allow_disabled", "note"}``, and
    ``profiles_off`` as read back when it changed something. Both directions give ``profiles_off`` so that the
    caller need not read the profiles once more.
    """
    with _LOCK:
        return _isolate_on(run, settings) if on else _isolate_off(run, settings)


def _join(*parts: Optional[str]) -> Optional[str]:
    text = " ".join(p for p in parts if p)
    return text or None


def _isolate_on(run, settings) -> Dict[str, Any]:
    try:
        states, foreign = _allow_out_state(run)      # the profiles and Windows' rules, in one call
    except RuleError as e:
        off = _off_names(_profiles(run))
        if off:
            raise ProfileOffError(_off_text(off)) from e
        raise RuleError(f"Windows' own outbound Allow rules could not be read, so what ISOLATED would leave open is not "
                        f"known; nothing was changed ({_first_line(e)})") from e
    if states is None:
        states = _profiles(run)
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
    closing = _clean_rule_names(recorded + [r["name"] for r in foreign if r["local"]])
    changes: Dict[str, Any] = {}
    if not already:
        changes = {"outbound_before": remembered, "isolated": True,
                   "isolated_since": (settings.isolated_since or time.time()) if damaged else time.time()}
    if closing != recorded:
        changes["allow_disabled"] = closing
    if changes:
        try:
            settings.set(**changes)
        except Exception as e:
            raise RuleError(f"the way back could not be saved ({type(e).__name__}: {_first_line(e)}); "
                            "nothing was changed") from e
    step = 0            # 2 Windows' rules off, 3 the default action: how far it got
    try:
        step = 2
        _set_allow_out(run, closing, False)       # a rule that stays on is in the read back below
        step = 3
        off = _off_names(_apply_outbound(run, {n: "Block" for n in PROFILE_NAMES}))
        if off:
            raise RuleError(_off_text(off))
    except Exception as e:
        if not marker:
            _roll_back(run, settings, current, step, closing, e)
            if isinstance(e, RuleError):
                raise
            raise RuleError(f"isolating failed: {type(e).__name__}: {_first_line(e)}") from e
        raise RuleError(f"{_first_line(e)}. ISOLATED was on and stays as it is, which may cut TDC's fetcher off; "
                        f"run {UNISOLATE_SCRIPT} on the VM to open the egress.") from e
    still, error = _still_open(run)
    return {"isolated": True, "outbound_before": remembered, "verified": still == [], "allowed_out": still,
            "allowed_out_error": error, "profiles_off": [], "note": _join(note, open_text(still, error))}


def _roll_back(run, settings, before: Dict[str, str], step: int, closing: List[str], cause: BaseException) -> None:
    """A fresh isolation that failed: put back what was there, in reverse. If that fails too the marker stays,
    because the state is not known and a marker is what makes the next start announce it."""
    try:
        if step >= 3:
            _apply_outbound(run, before)
        if step >= 2:
            stuck, problem = _reopen(run, closing)
            if stuck:
                raise RuleError(_stuck_text(stuck, problem))
        _remove_isolate_rules(run)
        _forget(settings, [] if step >= 2 else _clean_rule_names(getattr(settings, "allow_disabled", None)))
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
    _remove_isolate_rules(run)
    _forget(settings, stuck)
    shut = [n for n in PROFILE_NAMES if target[n] == "Block"]
    note = None
    if assumed:
        note = "No baseline was recorded; Allow, the Windows default, was assumed."
    elif shut:
        note = (f"The baseline recorded before ISOLATED is Block on {', '.join(shut)}: outbound stays shut there, "
                "and TDC's own fetch is no longer let out either. That is the VM's own baseline, not a TDC lockout.")
    return {"isolated": False, "changed": True, "assumed_allow": assumed, "outbound_after": target,
            "allow_disabled": stuck, "profiles_off": _off_names(states), "note": _join(note, _stuck_text(stuck, problem) if stuck else None)}


def _not_isolating(run, settings) -> Dict[str, Any]:
    """Leaving ISOLATED when TDC is not isolating: nothing is changed but the rules a failed leaving left switched
    off, and an egress that is shut anyway is said."""
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
    note = None
    if current and "Block" in current.values():
        note = (f"TDC is not isolating (there is no marker), so nothing was changed, but outbound is blocked on "
                f"{', '.join(n for n in PROFILE_NAMES if current[n] == 'Block')}. If that is not wanted, "
                f"run {UNISOLATE_SCRIPT} on the VM.")
    return {"isolated": False, "changed": len(stuck) < len(leftover), "assumed_allow": False,
            "outbound_after": current, "allow_disabled": stuck,
            "note": _join(note, _stuck_text(stuck, problem) if stuck else None)}


def startup_state(run, settings) -> Dict[str, Any]:
    """What the firewall is like when the service starts: ``{"isolated", "profiles_off", "announce", "note",
    "allowed_out"}``.

    ``settings.isolated`` (the marker) is the only authority for "TDC is isolating"; the profiles are only checked
    against it. ``isolated`` is True when there is a marker **and** the default action is in force: Block on all
    three profiles, all three on. Whatever is found here was not set in this session, so it is announced and **never
    lifted**: a crash in the middle of a detonation must not open the egress.

    - marker, in force: ``isolated``, announced; Windows' own outbound Allow rules that are still enabled are read
      back into ``allowed_out`` and named in ``note``, because the default action does not stop what they allow.
    - marker, Block on some profiles only or a profile off: not isolated, announced, marker kept.
    - marker, outbound plainly open (no profile on Block): stale, because ``scripts/tdc-unisolate.ps1`` was used or
      the switch never happened. The rules ISOLATED switched off are switched on again and the marker is cleared
      (bookkeeping: with the default on Allow neither opens anything) and it is announced.
    - no marker, outbound shut anyway: not isolated, but announced: whoever shut it, the analyst must know.
    - no marker, outbound open, rules a failed leaving left off: switched on again; announced if any stays off.
    - cannot read the firewall: the marker is believed, announced.
    """
    marker = bool(settings.isolated)
    try:
        states = _profiles(run)
    except RuleError as e:
        return {"isolated": marker, "profiles_off": [], "announce": True, "allowed_out": None,
                "note": f"the firewall could not be read: {_first_line(e)}"}
    off = _off_names(states)
    blocking = [s["name"] for s in states if s["outbound"] == "Block"]
    in_force = marker and len(blocking) == len(PROFILE_NAMES) and not off
    leftover = _clean_rule_names(getattr(settings, "allow_disabled", None))
    note = None
    still = None
    announce = marker or bool(blocking)
    if in_force:
        still, error = _still_open(run)
        note = _join("ISOLATED is on: the default outbound action is Block on every profile, and the outbound Allow rules "
                     "of Windows' own that ISOLATED switched off stay off; loopback, and TDC's own fetch to one address "
                     "for the seconds that fetch takes, are let out.",
                     open_text(still, error) or "The read back found no other outbound Allow rule enabled.")
    elif marker and blocking:
        note = (f"ISOLATED is marked, but outbound is blocked on {', '.join(blocking)} only"
                + (f" and the firewall is off for {', '.join(off)}" if off else "") + ": this is not a working isolation.")
    elif marker:
        stuck, problem = _reopen(run, leftover)
        try:
            _forget(settings, stuck)
            note = _join("A stale ISOLATED marker was cleared: outbound is open (was scripts/tdc-unisolate.ps1 run?).",
                         _stuck_text(stuck, problem) if stuck else None)
        except Exception as e:
            note = f"The ISOLATED marker is stale but could not be cleared: {_first_line(e)}"
    elif blocking:
        note = (f"Outbound is blocked on {', '.join(blocking)}, but TDC did not set it (there is no ISOLATED marker). "
                f"Nothing was changed; {UNISOLATE_SCRIPT} opens it.")
    elif leftover:
        stuck, problem = _reopen(run, leftover)
        try:
            settings.set(allow_disabled=stuck)
        except Exception:
            pass
        if stuck:
            note, announce = _stuck_text(stuck, problem), True
    return {"isolated": in_force, "profiles_off": off, "announce": announce, "note": note, "allowed_out": still}
