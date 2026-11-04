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
        try:
            weight = float(entry.get("weight") or 0.0)
        except (TypeError, ValueError):
            print(f"[pipe_analysis] skipping signature #{i} with invalid weight {entry.get('weight')!r}")
            continue
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
    """Last name component is GUID-shaped, or long (>=12) with entropy >= 3.5."""
    last = canonical_name(name).rstrip("\\").split("\\")[-1]
    if _GUID_RE.fullmatch(last):
        return True
    return len(last) >= 12 and _entropy(last) >= 3.5
