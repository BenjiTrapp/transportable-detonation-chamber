"""Detection rules drafted from what the Syscalls tab observes: a signature catalog, and YARA rules.

Two things leave this module. `syscall_signatures.json` holds the hook and patch patterns, loaded the way
`pipe_signatures.json` is. A YARA rule is drafted from a stub found outside ntdll; drafting only returns text,
`apply_draft` is the one function that writes, and only on request.

What the catalog is, and is not. Recognising a form stays in the code: `syscall_baseline.classify_stub` decodes the
displacement, it does not compare bytes. The catalog gives the analyst the family name and the note of a form that
has been recognised, and it lets a deviation be checked for being covered. Its `weight` is **advisory and not the
score**: scoring lives in `memory_evidence.KINDS`, and nothing here feeds it. The file is a bare JSON array, as
`pipe_signatures.json` is, and cannot carry a comment: this is where it says so about itself.

What a test pins, and what it does not. For the **hook shapes** ("Inline hook") the code recognises and labels each
one, so a test requires every such entry to match an example that `syscall_baseline._find_hook` decodes under the
same name, and the file cannot grow a hook the code does not know. For the **patch shapes** ("Stub patch") the code
recognises nothing: `classify_stub` calls any stub that differs and has no jump `diverged`, whether it holds `RET`,
`XOR EAX, EAX; RET` or noise. Those entries are checked only against hand-written examples in the test, and this
catalog is the one place that names them. Adding a patch pattern is therefore not validated by the code.

Malware chooses much of what a rule would say: a file name, a process name, a module. That text goes into a rule
the detection engine hot-reloads, and a rule that does not parse takes every other rule of its directory down with
it. So nothing a sample can influence is copied into a rule as it is: it is reduced to a short run of safe
characters first, the rule name is built from the syscall and a digest, and `check_draft` accepts nothing but the
exact form `draft_yara` writes, which is what `apply_draft` and the download route hold their input to.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import math
import os
import re
import tempfile

from memory_evidence import VERDICT_MALICIOUS

MAX_SIGNATURE_WEIGHT = VERDICT_MALICIOUS - 1.0

DEFAULT_SIGNATURES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "syscall_signatures.json")

_MATCH_TYPES = ("prefix", "exact", "contains", "regex")
VIEWS = ("arm64", "x64", "x86")

_DEFAULT_SIGNATURES: list[dict] | None = None
_HEX_ONLY = re.compile(r"(?:[0-9a-fA-F]{2})+")


def load_signatures(path: str | None = None) -> list[dict]:
    """Load the catalog; malformed entries and invalid regexes are skipped.

    The `weight` of an entry is advisory, a hint to a reader of how serious the form is: it is not the score, which
    comes from `memory_evidence.KINDS`, and it is clamped below MALICIOUS so that it could never be mistaken for one.

    An entry is `{family, pattern, match, weight, note}` and optionally a `view`. The pattern is matched against
    the live bytes of a stub as lower-case hex, so a pattern of a kind other than `regex` must be hex. A view
    is given where the pattern means something only there: an x64 opcode is a different instruction on ARM64."""
    path = path or DEFAULT_SIGNATURES_PATH
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except (OSError, ValueError) as exc:
        print(f"[syscall_rules] cannot load signatures from {path}: {exc}")
        return []
    if not isinstance(raw, list):
        print(f"[syscall_rules] signature file {path} is not a list")
        return []
    sigs = []
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict):
            print(f"[syscall_rules] skipping non-object signature #{i}: {entry!r}")
            continue
        pattern, kind, view = entry.get("pattern"), entry.get("match"), entry.get("view")
        if not isinstance(pattern, str) or not pattern or kind not in _MATCH_TYPES:
            print(f"[syscall_rules] skipping malformed signature #{i}: {entry!r}")
            continue
        if view is not None and view not in VIEWS:
            print(f"[syscall_rules] skipping signature #{i} with unknown view {view!r}")
            continue
        raw_weight = entry.get("weight")
        try:
            weight = float(raw_weight) if not isinstance(raw_weight, bool) else float("nan")
        except (TypeError, ValueError):
            weight = float("nan")
        if math.isnan(weight):
            print(f"[syscall_rules] skipping signature #{i} with invalid weight {raw_weight!r}")
            continue
        if not 0.0 <= weight <= MAX_SIGNATURE_WEIGHT:
            clamped = min(max(weight, 0.0), MAX_SIGNATURE_WEIGHT)
            print(f"[syscall_rules] signature #{i} weight {weight} clamped to {clamped} "
                  f"(one pattern must not reach MALICIOUS on its own)")
            weight = clamped
        if kind == "regex":
            try:
                re.compile(pattern, re.IGNORECASE)
            except re.error as exc:
                print(f"[syscall_rules] skipping signature #{i} with invalid regex {pattern!r}: {exc}")
                continue
        elif not _HEX_ONLY.fullmatch(pattern):
            print(f"[syscall_rules] skipping signature #{i}: a {kind} pattern is whole bytes in hex, "
                  f"not {pattern!r}")
            continue
        sig = {"family": str(entry.get("family") or "unknown"), "pattern": pattern, "match": kind,
               "weight": weight, "note": str(entry.get("note") or "")}
        if view is not None:
            sig["view"] = view
        sigs.append(sig)
    return sigs


def default_signatures() -> list[dict]:
    """The bundled catalog, loaded once."""
    global _DEFAULT_SIGNATURES
    if _DEFAULT_SIGNATURES is None:
        _DEFAULT_SIGNATURES = load_signatures(None)
    return _DEFAULT_SIGNATURES


def _matches(live_hex: str, sig: dict) -> bool:
    kind, pattern = sig["match"], sig["pattern"]
    if kind == "regex":
        return re.search(pattern, live_hex, re.IGNORECASE) is not None
    pattern = pattern.lower()
    if kind == "exact":
        return live_hex == pattern
    if kind == "prefix":
        return live_hex.startswith(pattern)
    return pattern in live_hex


def matching(live_hex: str, view: str | None = None, signatures: list[dict] | None = None) -> list[dict]:
    """The catalog entries that the bytes of a stub (hex) match. An entry with a view applies to that view only."""
    sigs = default_signatures() if signatures is None else signatures
    live_hex = live_hex.lower()
    return [s for s in sigs if s.get("view") in (None, view) and _matches(live_hex, s)]


# --------------------------------------------------------------------------
# Text that comes from a sample
# --------------------------------------------------------------------------

TEXT_MAX = 120
_UNSAFE = re.compile(r"[^A-Za-z0-9 ._:@()\[\]+,=#~-]")


def clean(value, limit: int = TEXT_MAX) -> str:
    """`value` as a short run of safe characters, for use inside a quoted string of a rule.

    Anything outside a small set of printable ASCII becomes `_`: quotes, backslashes, braces, slashes (so no
    `*/`), `$`, control characters, line breaks and everything that is not ASCII. The length is capped before
    anything else is done with it."""
    text = "" if value is None else str(value)[:limit]
    return _UNSAFE.sub("_", text).strip()


# --------------------------------------------------------------------------
# YARA
# --------------------------------------------------------------------------

RULE_PREFIX = "TDC_DirectSyscall_"
RULE_MAX = 4096
_STUB_MIN, _STUB_MAX = 8, 64
_BUILD = re.compile(r"[A-Za-z0-9._-]{1,32}")
_SYSCALL_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
# libyara refuses an identifier longer than 128 characters; the longest name draft_yara makes is 97
RULE_NAME_MAX = 128
_NAME_TAIL = r"[A-Za-z0-9_]{1,%d}" % (RULE_NAME_MAX - len(RULE_PREFIX))
_RULE_NAME = re.compile(RULE_PREFIX + _NAME_TAIL)

_SEVERITIES = ("high", "medium")
_TAGS = "attack.defense_evasion,attack.t1106"
_AUTHOR = "DetonationChamber"

# One meta string: printable ASCII without the quote and the backslash
_S = r'[ -!#-\[\]-~]{0,400}'
_RULE_FORM = re.compile(
    r"rule (?P<name>" + RULE_PREFIX + _NAME_TAIL + r") \{\n"
    r"    meta:\n"
    r'        description = "' + _S + r'"\n'
    r'        author      = "' + _AUTHOR + r'"\n'
    r'        severity    = "(?:' + "|".join(_SEVERITIES) + r')"\n'
    r'        tags        = "' + re.escape(_TAGS) + r'"\n'
    r'        generated   = "' + _S + r'"\n'
    r'        os_build    = "' + _BUILD.pattern + r'"\n'
    r'        os_view     = "(?:' + "|".join(VIEWS) + r')"\n'
    r'        note        = "' + _S + r'"\n'
    r"\n"
    r"    strings:\n"
    r"        \$stub = \{ [0-9A-F]{2}(?: [0-9A-F]{2}){" + str(_STUB_MIN - 1) + "," + str(_STUB_MAX - 1) + r"} \}\n"
    r"\n"
    r"    condition:\n"
    r"        \$stub\n"
    r"\}\n")

RULE_RELOAD_SECONDS = 2


def _stub_bytes(hit: dict) -> bytes:
    raw = hit.get("stub_hex")
    if not isinstance(raw, str) or len(raw) > 2 * _STUB_MAX or not _HEX_ONLY.fullmatch(raw):
        raise ValueError("the hit carries no stub bytes to write a rule about")
    data = bytes.fromhex(raw)
    if len(data) < _STUB_MIN:
        raise ValueError(f"a stub of {len(data)} bytes is too short to make a rule from")
    return data


def _int_field(hit: dict, key: str, high: int, required: bool) -> int | None:
    value = hit.get(key)
    if value is None and not required:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= high:
        raise ValueError(f"{key} must be a non-negative integer")
    return value


def draft_yara(hit: dict, build: str, view: str, source: str, *, now: datetime.datetime | None = None) -> dict:
    """The draft of a rule for a stub found outside ntdll: `{kind, name, text, target}`. Nothing is written.

    `hit` is one hit of `syscall_scan.find_stubs_*` (`syscall`, `number`, `offset`, `stub_hex`, `import_present`)
    and may carry `sample`, the file or process it was found in. The rule says which build and which view it was
    made for: the stub is a different shape on another view, so a rule without it would be silent there, and
    nobody would know why. A rule is exactly what is in its bytes; it does not know about the name of a sample.

    Raises ValueError for a hit that cannot make a rule, and for a build, view or syscall name that is not what
    it looks like."""
    if not isinstance(hit, dict):
        raise ValueError("the hit must be an object")
    if not isinstance(build, str) or not _BUILD.fullmatch(build):
        raise ValueError("the build must be like 26220.5770")
    if view not in VIEWS:
        raise ValueError("the view must be one of " + ", ".join(VIEWS))
    data = _stub_bytes(hit)
    number = _int_field(hit, "number", 0xFFFFFFFF, required=True)
    offset = _int_field(hit, "offset", 2 ** 64 - 1, required=False)
    syscall = hit.get("syscall")
    if syscall is not None and (not isinstance(syscall, str) or not _SYSCALL_NAME.fullmatch(syscall)):
        raise ValueError("the syscall must be a name like NtWriteVirtualMemory, or none")

    stub = " ".join(f"{b:02X}" for b in data)
    digest = hashlib.sha1(f"{build}|{view}|{stub}".encode("ascii")).hexdigest()[:8]
    label = syscall or f"Number0x{number:X}"
    name = f"{RULE_PREFIX}{label}_{view}_{digest}"
    if syscall:
        description = f"Direct syscall stub for {syscall} (0x{number:X}) as numbered on Windows {build}, {view} view"
    else:
        description = (f"Direct syscall stub with number 0x{number:X}, which Windows {build} does not number, "
                       f"{view} view")
    where = (f" at offset 0x{offset:X}" if offset is not None else "")
    sample = clean(hit.get("sample"))
    where += f" in {sample}" if sample else ""
    note = (f"Found{where}. Matches these stub bytes anywhere, the ntdll of this build included "
            "(Rustinel does not scan the Windows directory). Review before keeping.")
    stamp = (now or datetime.datetime.now(datetime.timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")
    generated = f"{stamp} by the Syscalls tab, source {clean(source, 40) or 'unknown'}"
    severity = "high" if hit.get("import_present") is False else "medium"
    text = (f"rule {name} {{\n"
            f"    meta:\n"
            f'        description = "{description}"\n'
            f'        author      = "{_AUTHOR}"\n'
            f'        severity    = "{severity}"\n'
            f'        tags        = "{_TAGS}"\n'
            f'        generated   = "{generated}"\n'
            f'        os_build    = "{build}"\n'
            f'        os_view     = "{view}"\n'
            f'        note        = "{note}"\n'
            f"\n"
            f"    strings:\n"
            f"        $stub = {{ {stub} }}\n"
            f"\n"
            f"    condition:\n"
            f"        $stub\n"
            f"}}\n")
    draft = {"kind": "yara", "name": name, "text": text, "target": name + ".yar"}
    check_draft(draft)
    return draft


def check_draft(draft) -> tuple[str, str]:
    """`(name, text)` of a draft that is exactly what `draft_yara` writes, else ValueError.

    The text comes back from the browser, so it is checked rather than trusted: a draft with a second rule, an
    `include`, a stray quote or a condition of someone's own is not one of ours and is never written."""
    if not isinstance(draft, dict):
        raise ValueError("the draft must be an object")
    name, text = draft.get("name"), draft.get("text")
    if not isinstance(name, str) or not _RULE_NAME.fullmatch(name):
        raise ValueError("the draft has no valid rule name")
    if not isinstance(text, str) or len(text) > RULE_MAX:
        raise ValueError("the draft has no rule text")
    form = _RULE_FORM.fullmatch(text)
    if form is None or form.group("name") != name:
        raise ValueError("the text is not a rule this tab generates")
    return name, text


def apply_draft(draft: dict, rules_dir: str) -> dict:
    """Write a drafted rule into `rules_dir`, the directory the detection engine reads, as `<name>.yar`.

    A rule of that name already there is left alone (`status` "exists"): the name holds the stub, build and view,
    so it is the same rule. The file appears whole or not at all, because the engine reloads on any change and a
    half-written rule would stop every rule beside it. Raises ValueError for a draft that is not ours and OSError
    when the directory cannot be written."""
    name, text = check_draft(draft)
    target = os.path.join(rules_dir, name + ".yar")
    if not os.path.isdir(rules_dir):
        parent = os.path.dirname(os.path.abspath(rules_dir))
        if not os.path.isdir(parent):
            raise FileNotFoundError(f"{parent} does not exist: the detection rules are not installed here")
        os.mkdir(rules_dir)
    if os.path.lexists(target):
        return {"status": "exists", "name": name, "path": target}
    # a name that is made on the spot and refused if it exists: a link planted at a name that could be foreseen
    # (the digest is of bytes the sample carries) would send this write wherever the link points
    handle, tmp = tempfile.mkstemp(dir=rules_dir, prefix=".", suffix=".tmp")
    try:
        with os.fdopen(handle, "w", encoding="ascii", newline="\n") as out:
            out.write(text)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, target)
    except OSError:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise
    return {"status": "written", "name": name, "path": target, "reload_seconds": RULE_RELOAD_SECONDS}


# --------------------------------------------------------------------------
# A signature drafted from a deviation
# --------------------------------------------------------------------------

_DEVIATIONS = ("hooked", "patched", "diverged")
_SIGNATURE_PREFIX_BYTES = 4


def draft_signature(dev: dict, view: str | None = None) -> dict:
    """The catalog entry for a deviation of `syscall_scan.measure`, to be reviewed and added to the file by hand.

    The pattern is the literal start of the live stub: a displacement or an address in it is the one thing it
    would be wrong to keep, which the note says. Raises ValueError for a stub that deviates in nothing, for a hook
    this host knows (a rule for it would flag the EDR), and for one without bytes."""
    if not isinstance(dev, dict):
        raise ValueError("the deviation must be an object")
    state = dev.get("state")
    if state not in _DEVIATIONS:
        raise ValueError("only a hooked, patched or diverged stub is drafted into a signature")
    if dev.get("allowlisted"):
        raise ValueError("this hook is known on this host: a signature for it would flag the hook that belongs here")
    actual = dev.get("actual")
    if not isinstance(actual, str) or len(actual) > 256 or not _HEX_ONLY.fullmatch(actual):
        raise ValueError("the deviation carries no bytes to make a signature from")
    if view is not None and view not in VIEWS:
        raise ValueError("the view must be one of " + ", ".join(VIEWS))
    differs = " The syscall number differs from the baseline." if dev.get("number_matches") is False else ""
    note = (f"Drafted from {clean(dev.get('name'), 64) or 'a stub'} in {clean(dev.get('module'), 32) or 'a module'}"
            f" ({state}, jump into {clean(dev.get('target_owner'), 64) or 'an unresolved target'}).{differs} "
            f"Literal first {_SIGNATURE_PREFIX_BYTES} bytes of the live stub: replace an address or a "
            "displacement by a pattern before keeping it.")
    entry = {"family": "Inline hook" if state == "hooked" else "Stub patch",
             "pattern": actual[:2 * _SIGNATURE_PREFIX_BYTES].lower(), "match": "prefix",
             "weight": min(3.0 if state == "patched" else 1.0, MAX_SIGNATURE_WEIGHT), "note": note}
    if view is not None:
        entry["view"] = view
    return entry
