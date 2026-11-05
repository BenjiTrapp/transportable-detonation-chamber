"""Named pipe helpers: name canonicalization, grouping keys and the
signature catalog of known malicious / remote-exec pipe names.

Pure Python; used by the Sysmon EID 17/18 pipe observation code.
"""

from __future__ import annotations

import json
import math
import os
import re
from collections import Counter

from memory_evidence import KINDS, VERDICT_MALICIOUS, MemoryFinding

# A single catalogued pipe is strong evidence, but never a verdict by itself.
MAX_SIGNATURE_WEIGHT = VERDICT_MALICIOUS - 1.0

DEFAULT_SIGNATURES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                       "pipe_signatures.json")

_MATCH_TYPES = ("prefix", "exact", "contains", "regex")
_PIPE_PREFIX_RE = re.compile(r"^\\\\[^\\]+\\pipe(?=\\|$)", re.IGNORECASE)
_GUID_RE = re.compile(r"\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?",
                      re.IGNORECASE)
_HEX_RUN_RE = re.compile(r"(?=[0-9a-f]*\d)[0-9a-f]{4,}")
_DIGITS_RE = re.compile(r"[0-9]+")
_REGEX_CACHE: dict = {}


def canonical_name(name: str) -> str:
    """`\\\\.\\pipe\\x`, `x` and `\\x` all become `\\x`; case is preserved."""
    n = (name or "").strip()
    n = _PIPE_PREFIX_RE.sub("", n)
    return "\\" + n.lstrip("\\")


def sysmon_pipe_name(raw: str) -> str:
    """Canonical name of a Sysmon `PipeName`, except Sysmon's own placeholder
    `<Anonymous Pipe>`, which is kept as is so it stays distinguishable from a
    real pipe of that name (always logged with a leading backslash)."""
    n = (raw or "").strip()
    return n if n.lower() == _ANONYMOUS else canonical_name(n)


def normalize_for_key(name: str) -> str:
    """Lowercased canonical name with GUIDs, hex runs and digit runs as `*`."""
    n = canonical_name(name).lower()
    n = _GUID_RE.sub("*", n)
    n = _HEX_RUN_RE.sub("*", n)
    n = _DIGITS_RE.sub("*", n)
    return re.sub(r"\*+", "*", n)


def load_signatures(path: str | None = None) -> list[dict]:
    """Load the catalog; malformed entries and invalid regexes are skipped."""
    path = path or DEFAULT_SIGNATURES_PATH
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except (OSError, ValueError) as exc:
        print(f"[pipe_analysis] cannot load signatures from {path}: {exc}")
        return []
    if not isinstance(raw, list):
        print(f"[pipe_analysis] signature file {path} is not a list")
        return []
    sigs = []
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict):
            print(f"[pipe_analysis] skipping non-object signature #{i}: {entry!r}")
            continue
        pattern = entry.get("pattern")
        kind = entry.get("match")
        if not isinstance(pattern, str) or not pattern or kind not in _MATCH_TYPES:
            print(f"[pipe_analysis] skipping malformed signature #{i}: {entry!r}")
            continue
        raw_weight = entry.get("weight")
        try:
            weight = None if raw_weight is None else float(raw_weight)
        except (TypeError, ValueError):
            weight = float("nan")
        if weight is not None and math.isnan(weight):
            print(f"[pipe_analysis] skipping signature #{i} with invalid weight {raw_weight!r}")
            continue
        if weight is not None and not 0.0 <= weight <= MAX_SIGNATURE_WEIGHT:
            clamped = min(max(weight, 0.0), MAX_SIGNATURE_WEIGHT)
            print(f"[pipe_analysis] signature #{i} weight {weight} clamped to {clamped} "
                  f"(one pipe must not reach MALICIOUS on its own)")
            weight = clamped
        sig = {
            "family": str(entry.get("family") or "unknown"),
            "pattern": pattern,
            "match": kind,
            "weight": weight,
            "note": str(entry.get("note") or ""),
        }
        if kind == "regex":
            try:
                _compiled(pattern)
            except re.error as exc:
                print(f"[pipe_analysis] skipping signature #{i} with invalid regex {pattern!r}: {exc}")
                continue
        sigs.append(sig)
    return sigs


def _compiled(pattern: str):
    rx = _REGEX_CACHE.get(pattern)
    if rx is None:
        rx = _REGEX_CACHE[pattern] = re.compile(pattern, re.IGNORECASE)
    return rx


def _matches(name: str, sig: dict) -> bool:
    kind = sig["match"]
    if kind == "regex":
        return _compiled(sig["pattern"]).search(name) is not None
    lname, pat = name.lower(), sig["pattern"].lower()
    if kind == "exact":
        return lname == canonical_name(pat).lower()
    if kind == "prefix":
        return lname.startswith(canonical_name(pat).lower())
    if kind == "contains":
        return pat in lname
    return False


def match_signature(name: str, signatures: list[dict]) -> dict | None:
    """First catalog entry matching the canonical pipe name (case-insensitive)."""
    cname = canonical_name(name)
    for sig in signatures or []:
        try:
            if _matches(cname, sig):
                return sig
        except (KeyError, re.error):
            continue
    return None


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in Counter(s).values())


def looks_random(name: str) -> bool:
    """A name token looks generated: a GUID, a hex run (>= 6, digits and
    letters), or a long (>= 12) high-entropy token that mixes digits and
    letters or is a vowel-less letter soup.

    Tokens are split at `\\`, `-`, `_`, `.` and spaces, so counters and PIDs
    (`CatalogChangeListener-3e0-0`, `dotnet-diagnostic-1234-...`) and
    CamelCase words are not random. Names in `BENIGN_PIPE_PREFIXES` never are.
    """
    cname = canonical_name(name)
    if is_benign_name(cname):
        return False
    if _GUID_RE.search(cname):
        return True
    return any(_random_token(t) for t in _TOKEN_SPLIT_RE.split(cname) if t)


def _random_token(tok: str) -> bool:
    digits = sum(c.isdigit() for c in tok)
    letters = sum(c.isalpha() for c in tok)
    if _HEX_TOKEN_RE.fullmatch(tok) and digits and letters:
        return True
    if len(tok) < 12 or _entropy(tok) < 3.5:
        return False
    if digits >= 2 and letters >= 2:
        return True
    if letters == len(tok):
        vowels = sum(c in "aeiouy" for c in tok.lower())
        return vowels / len(tok) < 0.2
    return False


# Well-known Windows/runtime/browser pipes whose names carry PIDs, counters or
# random ids. Only the random_name flag is affected: they still get every
# other flag, and they are no catalog entries (never c2_default or a family).
BENIGN_PIPE_PREFIXES = (
    r"\winsock2\catalogchangelistener-",
    r"\dotnet-diagnostic-",
    r"\pipe_eventroot\cimv2scm event provider",
    r"\chrome.",
    r"\local\chrome.",
    r"\mojo.",
    r"\local\mojo.",
    r"\crashpad_",
    r"\local\crashpad_",
    r"\tsvcpipe-",
    r"\gecko-crash-server-pipe.",
)
_TOKEN_SPLIT_RE = re.compile(r"[\\\-_. ]+")
_HEX_TOKEN_RE = re.compile(r"[0-9a-f]{6,}", re.IGNORECASE)


def is_benign_name(name: str) -> bool:
    """The name starts with one of `BENIGN_PIPE_PREFIXES` (case-insensitive)."""
    return canonical_name(name).lower().startswith(BENIGN_PIPE_PREFIXES)


SENSITIVE_SYSTEM_PIPES = frozenset({r"\svcctl", r"\lsarpc", r"\samr", r"\netlogon", r"\atsvc"})
_IGNORED_PREFIXES = (r"\pshost.",)
# Sysmon's placeholder for unnamed (anonymous) pipes, e.g. stdout redirection.
# Compared raw: a real named pipe always arrives with a leading backslash, so
# `\<Anonymous Pipe>` (a legal pipe name) is not hidden.
_ANONYMOUS = "<anonymous pipe>"
_DEFAULT_SIGNATURES: list | None = None
_FRACTION_RE = re.compile(r"(\.\d{6})\d+")


def default_signatures() -> list[dict]:
    """The bundled catalog, loaded once."""
    global _DEFAULT_SIGNATURES
    if _DEFAULT_SIGNATURES is None:
        _DEFAULT_SIGNATURES = load_signatures(None)
    return _DEFAULT_SIGNATURES


def _epoch(ts) -> float | None:
    import datetime
    if not ts:
        return None
    text = _FRACTION_RE.sub(r"\1", str(ts).strip().replace("Z", "+00:00"))
    try:
        dt = datetime.datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.astimezone()
    return dt.timestamp()


def is_ignored(ev, self_pid) -> bool:
    """Pipe events that are noise: no PID, the web UI's own pipe proxy
    (`self_pid`), empty names, anonymous pipes and PowerShell host pipes."""
    pid = ev.get("pid")
    if pid in (None, "") or (self_pid is not None and str(pid) == str(self_pid)):
        return True
    raw = (ev.get("pipe") or "").strip()
    if raw.lower() == _ANONYMOUS:
        return True
    name = canonical_name(raw).lower()
    return name == "\\" or name.startswith(_IGNORED_PREFIXES)


def analyze(events, sample_keys, resolve, self_pid, signatures=None) -> dict:
    """Pipes the sample subtree created or connected to, with flags.

    `events` are Sysmon EID 17/18 dicts (type, pipe, pid, timestamp, ...);
    `resolve(pid, ts)` maps them to process-instance keys. Only pipes that a
    sample instance touched are reported, but every process on such a pipe
    is listed so cross-process use is visible. Events of the web UI itself
    (`self_pid`) and PowerShell host pipes are ignored.
    """
    sigs = default_signatures() if signatures is None else signatures
    sample_keys = set(sample_keys or ())
    groups: dict = {}
    for ev in events or []:
        if not isinstance(ev, dict) or ev.get("type") not in ("PipeCreated", "PipeConnected"):
            continue
        if is_ignored(ev, self_pid):
            continue
        pid = ev.get("pid")
        name = canonical_name(ev.get("pipe") or "")
        ts = ev.get("timestamp") or ""
        key = resolve(str(pid), ts)
        g = groups.setdefault(name.lower(), {"pipe": name, "created": [], "connected": [],
                                             "times": [], "sample_created": False,
                                             "other_created": False, "sample_connected": False,
                                             "other_connected": False, "images": [],
                                             "sample_created_images": [],
                                             "sample_connected_images": []})
        in_sample = key is not None and key in sample_keys
        shown = key if key is not None else str(pid)
        role = "created" if ev["type"] == "PipeCreated" else "connected"
        if shown not in g[role]:
            g[role].append(shown)
        image = ev.get("image") or ""
        if in_sample:
            if image not in g["images"]:
                g["images"].append(image)
            g["sample_" + role + "_images"].append((_epoch(ts), image))
        g[("sample_" if in_sample else "other_") + role] = True
        g["times"].append((_epoch(ts), ts))

    pipes, findings = [], []
    for g in groups.values():
        if not (g["sample_created"] or g["sample_connected"]):
            continue
        name = g["pipe"]
        hit = match_signature(name, sigs)
        flags = []
        if hit:
            flags.append("c2_default")
        if (g["sample_created"] and g["other_connected"]) or (g["other_created"] and g["sample_connected"]):
            flags.append("cross_process")
        if g["sample_connected"] and name.lower() in SENSITIVE_SYSTEM_PIPES:
            flags.append("sensitive_system")
        if looks_random(name):
            flags.append("random_name")
        timed = sorted((t for t in g["times"] if t[0] is not None), key=lambda t: t[0])
        pipes.append({
            "pipe": name,
            "family": hit["family"] if hit else None,
            "note": hit["note"] if hit else "",
            "created_by": g["created"],
            "connected_by": g["connected"],
            "first_seen": timed[0][1] if timed else (g["times"][0][1] if g["times"] else ""),
            "last_seen": timed[-1][1] if timed else (g["times"][-1][1] if g["times"] else ""),
            "flags": flags,
        })
        findings += _flag_findings(name, flags, hit, g["images"], _primary_image(g))
    pipes.sort(key=lambda p: (_epoch(p["first_seen"]) or 0.0, p["pipe"].lower()))
    return {"pipes": pipes, "evidence_findings": findings}


def _primary_image(g) -> str:
    """Earliest sample image that created the pipe, else the earliest that connected."""
    for seen in (g["sample_created_images"], g["sample_connected_images"]):
        if seen:
            return min(seen, key=lambda t: (t[0] is None, t[0] or 0.0))[1]
    return g["images"][0] if g["images"] else ""


SOURCE = "sysmon-pipes"
_FLAG_KINDS = {
    "c2_default": "pipe_c2_default",
    "cross_process": "pipe_cross_process",
    "sensitive_system": "pipe_sensitive_system",
    "random_name": "pipe_random_name",
}


def _finding(kind, name, image, detail, weight=None, family=None):
    return MemoryFinding(
        source=SOURCE, kind=kind, process=image, detail=detail,
        identity=(normalize_for_key(name),), weight=weight,
        extra={"pipe": name, "family": family},
    )


def _flag_findings(name, flags, hit, images, primary) -> list:
    """Findings for a pipe's flags.

    The C2 kind is one fact about the pipe and counts once (for `primary`):
    per-image copies would escape saturation and add up. The other kinds are
    emitted per sample image, because their baseline keys are per process.
    """
    out = []
    for flag in flags:
        kind = _FLAG_KINDS.get(flag)
        if not kind:
            continue
        weight, family, detail = None, None, name
        targets = images or [""]
        if kind == "pipe_c2_default":
            targets = [primary]
            if hit:
                weight = hit.get("weight")
                if weight is None:
                    weight = KINDS[kind]["weight"]
                family = hit.get("family")
                detail = f"{name} ({family})" + (f" - {hit['note']}" if hit.get("note") else "")
        for image in targets:
            out.append(_finding(kind, name, image, detail, weight=weight, family=family))
    return out


def _never_baselined(name: str) -> bool:
    """Names whose key is all wildcards or random: baselining them would
    suppress every other random-named pipe."""
    return normalize_for_key(name).strip("\\*") == "" or looks_random(name)


def baseline_findings(events, self_pid, signatures=None) -> list:
    """Baseline-able (non-C2) findings for every pipe event on a clean host.

    Each event yields the kinds a later detonation could report for the same
    process and normalized pipe name, so they share its finding key.
    Catalogued (C2/tool) pipes are never baselined, not even their
    non-C2 kinds: a known implant pipe on the "clean" host is not benign.
    """
    sigs = default_signatures() if signatures is None else signatures
    out, seen = [], set()
    for ev in events or []:
        if not isinstance(ev, dict) or ev.get("type") not in ("PipeCreated", "PipeConnected"):
            continue
        if is_ignored(ev, self_pid):
            continue
        name = canonical_name(ev.get("pipe") or "")
        if _never_baselined(name):
            continue
        if match_signature(name, sigs):
            continue
        image = ev.get("image") or ""
        kinds = ["pipe_cross_process"]
        if ev["type"] == "PipeConnected" and name.lower() in SENSITIVE_SYSTEM_PIPES:
            kinds.append("pipe_sensitive_system")
        for kind in kinds:
            f = _finding(kind, name, image, name)
            if f["key"] not in seen:
                seen.add(f["key"])
                out.append(f)
    return out
