"""Tool-agnostic memory evidence model.

Live-process memory scanners are awkward to build a verdict on:

  * They grade differently. Aether reports a generic string match such as
    "watermark" in explorer.exe as CRITICAL, while its structural checks use the
    same word for a thread whose RIP disagrees with its start address. Trusting
    the tool's own severity therefore marks a clean Windows box as malicious.
  * A single snapshot is not reproducible. Scanning the same process twice
    minutes apart yields different findings, because the memory genuinely
    changed. Scoring a one-shot scan scores noise.
  * Any one scanner alone is weak evidence. PE-Sieve, Moneta, Aether and
    Hunt-Sleeping-Beacons each see part of the picture.

This module keeps the scoring independent of any particular scanner. Findings
from any source are normalized into one schema and weighted by five factors:

  evidence class   structural facts outrank behavioural hints outrank strings
  persistence      how many samples of a repeated scan contained the finding
  corroboration    whether an independent source agrees on the same process
  novelty          whether the finding also occurs in this host's clean baseline
  observation      how much of the act was seen: an upload that our own
                   isolated server accepted shows the attempt, not that a real
                   C2 received anything. A finding without the field was seen
                   in full, so the scanners above are weighed as before.

Two sources can see one phenomenon. Sysmon's connection log and a capture of
the same traffic both see a beacon loop, and the two findings together would
cross the malicious threshold on their own. A kind may therefore name kinds it
``supersedes``. The findings of both kinds on one process that share an
endpoint, directly or through each other, are one phenomenon, and only one side
of it is scored: whichever gives the higher total, chosen over the whole set at
once so that the order findings arrive in cannot change the verdict. The other
side stays listed with ``superseded_by`` and still counts as the independent
second opinion that it is. Adding a finding never lowers the score, except a
finding that shows two such phenomena to be one (what was counted twice is then
counted once), and except past ``SUPERSEDE_MAX_ENUMERATED`` such phenomena on
one process, where the choice is no longer searched exhaustively.

Adding a scanner means adding a normalizer function; nothing else changes.
"""

import hashlib
import ipaddress
import json
import math
import os
import threading
import time

import net_behavior

# --- Evidence classes -------------------------------------------------
# Ordered by how hard the signal is to fake or to trip accidentally.
EVIDENCE_STRUCTURAL = "structural"   # verifiable fact about memory layout
EVIDENCE_BEHAVIORAL = "behavioral"   # pattern of use, e.g. a pointer table
EVIDENCE_STRING = "string"           # a byte pattern was present somewhere
EVIDENCE_ARTIFACT = "artifact"       # something was extracted to disk

EVIDENCE_RANK = {
    EVIDENCE_STRUCTURAL: 0,
    EVIDENCE_BEHAVIORAL: 1,
    EVIDENCE_ARTIFACT: 2,
    EVIDENCE_STRING: 3,
}

# --- Canonical finding kinds -----------------------------------------
# weight:     contribution when fully confident
# corroborate: needs an independent agreeing signal for full weight, because
#              the kind alone also occurs in legitimate software
KINDS = {
    # Thread start-address verdicts: the strongest single signals, because a
    # thread executing private memory has no benign explanation. Weighted to
    # reach the malicious threshold on their own, without corroboration.
    "thread_start_private": {
        "weight": 6.0, "evidence": EVIDENCE_STRUCTURAL, "corroborate": False,
        "label": "Thread starts in private executable memory",
    },
    "thread_rip_mismatch": {
        "weight": 6.0, "evidence": EVIDENCE_STRUCTURAL, "corroborate": False,
        "label": "Suspended thread RIP disagrees with its start address",
    },
    "thread_staged_rw": {
        "weight": 3.0, "evidence": EVIDENCE_STRUCTURAL, "corroborate": True,
        "label": "Thread start in private RW memory (pre-VirtualProtect staging)",
    },
    "thread_spoof_trampoline": {
        "weight": 2.5, "evidence": EVIDENCE_STRUCTURAL, "corroborate": True,
        "label": "Thread start address points at a spoof trampoline",
    },
    # Image-backed anomalies
    "hollowed_host": {
        "weight": 4.0, "evidence": EVIDENCE_STRUCTURAL, "corroborate": False,
        "label": "Thread runs inside an image missing from the PEB",
    },
    "disk_mem_diff": {
        "weight": 4.0, "evidence": EVIDENCE_STRUCTURAL, "corroborate": False,
        "label": "Executable page differs from the same RVA on disk",
    },
    "modified_code": {
        "weight": 3.0, "evidence": EVIDENCE_STRUCTURAL, "corroborate": True,
        "label": "Modified code pages in a mapped image",
    },
    "injected_code": {
        "weight": 4.0, "evidence": EVIDENCE_STRUCTURAL, "corroborate": False,
        "label": "Injected or replaced code",
    },
    # Hidden modules fire on ngen/R2R images and packaged apps too, so they
    # need a second opinion before counting fully.
    "hidden_module": {
        "weight": 3.5, "evidence": EVIDENCE_STRUCTURAL, "corroborate": True,
        "label": "Mapped image not registered in the PEB module list",
    },
    "private_rwx": {
        "weight": 2.0, "evidence": EVIDENCE_STRUCTURAL, "corroborate": True,
        "label": "Private RWX allocation",
    },
    "hook_prologue": {
        "weight": 2.5, "evidence": EVIDENCE_STRUCTURAL, "corroborate": True,
        "label": "Trampoline prologue in private code",
    },
    "reflective_pe": {
        "weight": 3.0, "evidence": EVIDENCE_STRUCTURAL, "corroborate": False,
        "label": "PE header in private memory (reflective load)",
    },
    "reflective_dotnet": {
        "weight": 3.5, "evidence": EVIDENCE_STRUCTURAL, "corroborate": False,
        "label": "Reflectively loaded .NET assembly",
    },
    # Behavioural: real technique, but the detector also matches C++ vtables
    # and framework dispatch tables. explorer.exe trips this on a clean box.
    "heap_api_table": {
        "weight": 1.5, "evidence": EVIDENCE_BEHAVIORAL, "corroborate": True,
        "label": "Heap-resident API pointer table (runtime API resolution)",
    },
    "sleeping_beacon": {
        "weight": 3.5, "evidence": EVIDENCE_BEHAVIORAL, "corroborate": False,
        "label": "Callstack indicates a sleeping beacon",
    },
    # Periodic outbound connections. Regular intervals are what separates a
    # check-in loop from ordinary traffic; a single connection says nothing.
    "c2_beaconing": {
        "weight": 3.0, "evidence": EVIDENCE_BEHAVIORAL, "corroborate": True,
        "label": "Periodic outbound connections (beaconing)",
    },
    "beacon_config": {
        "weight": 4.5, "evidence": EVIDENCE_STRUCTURAL, "corroborate": False,
        "label": "Decoded C2 beacon configuration",
    },
    # Named pipes from Sysmon EID 17/18. A catalogued implant/tool default
    # name is graded by its catalog weight and is never baselined away: a
    # Cobalt Strike pipe on the clean host is a finding, not noise.
    "pipe_c2_default": {
        "weight": 4.0, "evidence": EVIDENCE_STRUCTURAL, "corroborate": False,
        "baseline_exempt": True,
        "label": "Named pipe matches a known C2 / tool default",
    },
    "pipe_cross_process": {
        "weight": 1.5, "evidence": EVIDENCE_BEHAVIORAL, "corroborate": True,
        "label": "Named pipe shared with another process",
    },
    "pipe_sensitive_system": {
        "weight": 1.0, "evidence": EVIDENCE_BEHAVIORAL, "corroborate": True,
        "label": "Connected to a sensitive system pipe (SCM/LSA/SAM)",
    },
    # Random names are exempt because their normalized keys collapse to
    # wildcards: one GUID pipe in the baseline would hide every other.
    "pipe_random_name": {
        "weight": 0.8, "evidence": EVIDENCE_STRING, "corroborate": True,
        "baseline_exempt": True,
        "label": "Randomly named pipe",
    },
    # Extracted artifacts
    "dumped_hidden_module": {
        "weight": 3.0, "evidence": EVIDENCE_ARTIFACT, "corroborate": False,
        "label": "Hidden module recovered from memory",
    },
    "dumped_code_chunk": {
        "weight": 2.5, "evidence": EVIDENCE_ARTIFACT, "corroborate": False,
        "label": "Header-less executable region recovered from memory",
    },
    # Strings. Weight is derived from the rule's own risk score, because
    # "beacon.dll" and "kernel32.dll" are not the same kind of evidence.
    "memory_signature": {
        "weight": 1.0, "evidence": EVIDENCE_STRING, "corroborate": True,
        "label": "In-memory signature match",
    },
    # Network, from a capture (net_evidence). Weights from the design spec.
    # A capture knows no process, so every source here is "network" and a
    # second opinion has to come from a host-side tool on the same process.
    # A check-in is a beacon whose server answered: the same loop c2_beaconing
    # sees in Sysmon, measured on the wire, so it absorbs that finding rather
    # than adding to it. Like c2_beaconing it stands alone only when tight
    # (net_evidence clears needs_corroboration then); a loose rhythm also fits
    # a poller.
    "c2_checkin": {
        "weight": 4.0, "evidence": EVIDENCE_STRUCTURAL, "corroborate": True,
        "supersedes": ("c2_beaconing",),
        "label": "Periodic check-in answered by its server",
    },
    "exfil_upload": {
        "weight": 4.0, "evidence": EVIDENCE_STRUCTURAL, "corroborate": False,
        "label": "Data sent out (size and destination on the wire)",
    },
    "credential_in_transit": {
        "weight": 4.5, "evidence": EVIDENCE_STRUCTURAL, "corroborate": False,
        "label": "Credentials sent in clear text",
    },
    "payload_staging": {
        "weight": 4.0, "evidence": EVIDENCE_STRUCTURAL, "corroborate": False,
        "label": "Executable downloaded (a file, not only a URL)",
    },
    # A JA3/JA4 hash is shared by every program built on the same TLS stack.
    "tls_ja3_known": {
        "weight": 2.5, "evidence": EVIDENCE_STRUCTURAL, "corroborate": True,
        "label": "TLS client fingerprint of a catalogued tool",
    },
    # Updaters walk mirror lists too.
    "fallback_rotation": {
        "weight": 3.0, "evidence": EVIDENCE_BEHAVIORAL, "corroborate": True,
        "label": "One request rotated through fallback hosts",
    },
    # Software retries an offline service as well.
    "dead_c2_retry": {
        "weight": 2.0, "evidence": EVIDENCE_BEHAVIORAL, "corroborate": True,
        "label": "Repeated attempts to an unreachable host",
    },
    # Ten different invented names failing within a minute is not something
    # ordinary software does; the resolver's own names are not counted.
    "dga_pattern": {
        "weight": 2.0, "evidence": EVIDENCE_BEHAVIORAL, "corroborate": False,
        "label": "Generated-looking names, burst of NXDOMAIN answers",
    },
    # Installers ask for their public address too.
    "recon_service": {
        "weight": 1.0, "evidence": EVIDENCE_BEHAVIORAL, "corroborate": True,
        "label": "Public address or location lookup",
    },
}

# The kinds a network capture produces (net_evidence), and the only ones a
# network rule may name (net_rules checks this when a rule loads).
NETWORK_KINDS = ("c2_checkin", "exfil_upload", "credential_in_transit", "payload_staging",
                 "tls_ja3_known", "fallback_rotation", "dead_c2_retry", "dga_pattern",
                 "recon_service")


def _check_kinds(kinds=None):
    """Every ``supersedes`` target is a kind, the relation has no cycle (two
    kinds that supersede each other would take each other out), no kind is on
    both sides of it (a phenomenon has two sides, the superseding kinds and
    the superseded ones, and a chain would give it three), and every network
    kind is a kind."""
    kinds = KINDS if kinds is None else kinds
    for kind, spec in kinds.items():
        for other in spec.get("supersedes", ()):
            if other not in kinds:
                raise ValueError("kind %r supersedes %r, which is not a kind" % (kind, other))
    superseded = {k for spec in kinds.values() for k in spec.get("supersedes", ())}
    done = set()
    for start in kinds:
        if start in done:
            continue
        path, stack = [], [(start, iter(kinds[start].get("supersedes", ())))]
        on_path = {start}
        path.append(start)
        while stack:
            kind, targets = stack[-1]
            nxt = next(targets, None)
            if nxt is None:
                stack.pop()
                on_path.discard(path.pop())
                done.add(kind)
                continue
            if nxt in on_path:
                raise ValueError("kinds supersede each other in a cycle: %s"
                                 % " -> ".join(path[path.index(nxt):] + [nxt]))
            if nxt not in done:
                on_path.add(nxt)
                path.append(nxt)
                stack.append((nxt, iter(kinds[nxt].get("supersedes", ()))))
    for kind, spec in kinds.items():
        if spec.get("supersedes") and kind in superseded:
            raise ValueError("kind %r supersedes others and is superseded itself: a chain "
                             "of supersedes has no two sides to choose between" % kind)
    for kind in NETWORK_KINDS:
        if kind not in kinds:
            raise ValueError("network kind %r is not a kind" % kind)


_check_kinds()

# Aether finding type -> canonical kind
AETHER_TYPE_MAP = {
    "TSAV_SHELLCODE_PRIVATE": "thread_start_private",
    "TSAV_SUSPENDED_RIP": "thread_rip_mismatch",
    "TSAV_STAGED_PRIVATE_RW": "thread_staged_rw",
    "TSAV_SPOOF_TRAMPOLINE": "thread_spoof_trampoline",
    "TSAV_HOLLOWED_HOST": "hollowed_host",
    "TSAV_MODIFIED_HOST": "modified_code",
    "TSAV_MAPPED_NONPE": "reflective_pe",
    "MISSING_PEB": "hidden_module",
    "PRIVATE_RWX": "private_rwx",
    "DISK_MEM_DIFF": "disk_mem_diff",
    "HOOK_PROLOGUE": "hook_prologue",
    "HEAP_API_TABLE": "heap_api_table",
}

# Signature risk score (0-10 in Aether's rules) -> weight multiplier.
# A risk 3 pattern such as "kernel32.dll" is almost pure noise; risk 8+ names
# an actual implant artifact.
SIGNATURE_RISK_WEIGHTS = {
    10: 3.0, 9: 2.5, 8: 2.0, 7: 1.0, 6: 0.6, 5: 0.4,
}

# Confidence multipliers
PERSISTENCE_FULL = 1.0      # present in every sample
PERSISTENCE_PARTIAL = 0.55  # present in at least half
PERSISTENCE_SINGLE = 0.25   # seen once in a multi-sample run
UNCORROBORATED = 0.4        # kind needs a second opinion and did not get one
BASELINE_KNOWN = 0.0        # also present on the clean host baseline

# Repetition of one kind within one process is one phenomenon, not N
# independent facts: ten hidden modules in a packaged app is a property of how
# that app loads, not ten separate intrusions. The group's contribution is
# therefore capped at this multiple of its strongest single finding.
SATURATION_CAP = 2.0

# Minimum base weight for a finding to count as an independent second opinion.
CORROBORATION_MIN_WEIGHT = 1.0
# corroboration_scope of a finding that is about one destination only.
CORROBORATION_SCOPE_ENDPOINT = "endpoint"
# attribution of a capture finding whose process is the sample's by
# assumption (a capture knows no process): it counts with that process for
# grouping and supersede, but gets and gives a second opinion only through a
# shared endpoint (Ruling 69)
ATTRIBUTION_ASSUMED = "assumed"

VERDICT_MALICIOUS = 6.0
VERDICT_SUSPICIOUS = 2.0


# Version of the finding-key scheme. Baselines record it; a baseline built
# with another version is ignored until it is captured again, because its
# keys can no longer match (or could match the wrong thing).
#   1: process identified by image *name*
#   2: process identified by full image path where known - a sample that
#      names itself svchost.exe no longer inherits svchost's baseline
KEY_VERSION = 2


def _process_identity(process):
    """(display name, key part) for a process given as a name or full path."""
    text = (process or "").strip()
    if "\\" in text or "/" in text:
        norm = text.replace("/", "\\").lower()
        if norm.startswith("\\??\\"):
            norm = norm[4:]
        return text.replace("/", "\\").rsplit("\\", 1)[-1], norm
    return text, text.lower()


def _short_hash(*parts):
    """Stable short digest over the identity-defining parts of a finding."""
    raw = "|".join(str(p) for p in parts)
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:16]


class MemoryFinding(dict):
    """One normalized finding.

    Behaves as a plain dict so it serializes straight to JSON, but is built
    through a constructor that enforces the schema.
    """

    def __init__(self, source, kind, process, detail="", address=None,
                 identity=(), raw_severity="", weight=None, extra=None):
        spec = KINDS.get(kind, {})
        super().__init__()
        self["source"] = source
        self["kind"] = kind
        self["label"] = spec.get("label", kind)
        self["evidence"] = spec.get("evidence", EVIDENCE_STRING)
        self["base_weight"] = spec.get("weight", 1.0) if weight is None else weight
        self["needs_corroboration"] = spec.get("corroborate", True)
        display, process_key = _process_identity(process)
        self["process"] = display
        if process_key != display.lower():
            self["image_path"] = process
        self["detail"] = detail
        self["address"] = address
        self["raw_severity"] = raw_severity
        # Identity deliberately excludes the address: ASLR and heap churn move
        # the same logical finding around between scans, which is exactly what
        # made one-shot results look unstable.
        self["key"] = _short_hash(kind, process_key, *identity)
        if extra:
            self.update(extra)


# --- Normalizers: one per scanner -------------------------------------

def from_aether(report, process=""):
    """Normalize an Aether JSON report.

    Aether mixes two shapes in its "findings" array: structural IOCs carry a
    "type", signature matches carry a "category" plus a "hits" list.
    """
    out = []
    if not isinstance(report, dict):
        return out

    for f in report.get("findings") or []:
        ftype = f.get("type")
        if ftype:
            kind = AETHER_TYPE_MAP.get(ftype)
            if not kind:
                continue
            # Identity: what the finding is about, not where it currently sits.
            # For a pointer table that is the set of modules it references; for
            # an image it is the region size.
            evidence_text = f.get("evidence") or ""
            modules = ""
            if kind == "heap_api_table":
                # The module list is the stable part of a heap table finding.
                modules = ",".join(sorted(
                    m.strip().lower()
                    for m in evidence_text.split("\n")[-1].split(",")
                    if m.strip()
                ))
            out.append(MemoryFinding(
                source="aether", kind=kind, process=process,
                detail=f.get("description") or "",
                address=f.get("address"),
                identity=(f.get("size") or 0, modules),
                raw_severity=(f.get("severity") or "").lower(),
                extra={
                    "evidence_text": evidence_text[:600] or None,
                    "size": f.get("size"),
                    "pointer_count": f.get("pointer_count"),
                    "module_count": f.get("module_count"),
                    "private_pages": f.get("private_pages"),
                },
            ))
            continue

        category = f.get("category")
        if not category:
            continue
        # One finding per distinct pattern, so a rule firing 10 times on the
        # same string does not outweigh a single structural fact.
        seen_patterns = {}
        for hit in f.get("hits") or []:
            pattern = hit.get("pattern") or ""
            risk = int(hit.get("risk_score") or 0)
            prev = seen_patterns.get(pattern)
            if prev is None or risk > prev[0]:
                seen_patterns[pattern] = (risk, hit)
        for pattern, (risk, hit) in seen_patterns.items():
            weight = SIGNATURE_RISK_WEIGHTS.get(risk, 0.2)
            out.append(MemoryFinding(
                source="aether", kind="memory_signature", process=process,
                detail=f"{category}: {pattern}"
                       + (f" - {hit.get('description')}" if hit.get("description") else ""),
                address=hit.get("offset"),
                identity=(category, pattern),
                raw_severity=(f.get("severity") or "").lower(),
                weight=weight,
                extra={
                    "category": category,
                    "pattern": pattern,
                    "risk_score": risk,
                    "encoding": hit.get("encoding"),
                    "mitre": f.get("mitre"),
                    # High-risk named artifacts stand on their own.
                    "needs_corroboration": risk < 8,
                },
            ))

    if report.get("dotnet_assemblies_in_private"):
        out.append(MemoryFinding(
            source="aether", kind="reflective_dotnet", process=process,
            detail=f"{report['dotnet_assemblies_in_private']} .NET assembly(ies) in private memory",
            identity=("dotnet", report["dotnet_assemblies_in_private"]),
        ))
    if report.get("pe_headers_in_private"):
        out.append(MemoryFinding(
            source="aether", kind="reflective_pe", process=process,
            detail=f"{report['pe_headers_in_private']} PE header(s) in private memory",
            identity=("pe", report["pe_headers_in_private"]),
        ))
    return out


def from_process_dump(result, process=""):
    """Normalize a Process Dump result: extracted artifacts are evidence too.

    When the operator bypassed the clean-hash database, the dump contains every
    module rather than only the unknown ones, so "it was dumped" no longer
    carries novelty. The classification (hidden module / header-less chunk)
    still does, at reduced weight.

    Code chunks the caller has classified as host artifacts (``host_class`` on
    the dump entry - e.g. the x64 emulator's ARM64 translation cache) are not
    evidence about the sample and are skipped.
    """
    out = []
    if not isinstance(result, dict):
        return out
    db_ignored = bool(result.get("clean_db_ignored"))
    for dump in result.get("dumps") or []:
        kind = {
            "hiddenmodule": "dumped_hidden_module",
            "codechunk": "dumped_code_chunk",
        }.get(dump.get("kind"))
        if not kind:
            continue
        if dump.get("host_class"):
            continue
        weight = KINDS[kind]["weight"]
        detail = dump.get("filename") or ""
        if db_ignored:
            weight *= 0.4
            detail += " (clean-hash database bypassed)"
        out.append(MemoryFinding(
            source="process-dump", kind=kind, process=process,
            detail=detail,
            address=dump.get("base_address"),
            # The content hash is the stable identity of a dumped artifact.
            identity=(dump.get("sha256") or dump.get("size") or 0,),
            weight=weight,
            extra={
                "path": dump.get("path"),
                "sha256": dump.get("sha256"),
                "size": dump.get("size"),
                "arch": dump.get("arch"),
                "clean_db_ignored": db_ignored or None,
            },
        ))
    return out


def from_pe_sieve(result, process=""):
    """Normalize PE-Sieve output as reported through LitterBox."""
    out = []
    if not isinstance(result, dict):
        return out
    count = (result.get("suspicious") or result.get("total_suspicious")
             or result.get("replaced") or 0)
    if isinstance(count, (int, float)) and count:
        out.append(MemoryFinding(
            source="pe-sieve", kind="injected_code", process=process,
            detail=f"PE-Sieve flagged {int(count)} suspicious module(s)",
            identity=("pe-sieve", int(count)),
        ))
    return out


def from_moneta(result, process=""):
    """Normalize Moneta output as reported through LitterBox."""
    out = []
    if not isinstance(result, dict):
        return out
    iocs = result.get("ioc_count") or result.get("iocs") or 0
    if isinstance(iocs, list):
        iocs = len(iocs)
    if isinstance(iocs, (int, float)) and iocs:
        out.append(MemoryFinding(
            source="moneta", kind="modified_code", process=process,
            detail=f"Moneta reported {int(iocs)} IOC(s)",
            identity=("moneta", int(iocs)),
        ))
    return out


def from_hsb(result, process=""):
    """Normalize Hunt-Sleeping-Beacons findings (one per process).

    Identity is the set of detection titles, not thread IDs, so the same
    sleeping implant matches across scans and against the baseline.
    """
    out = []
    if not isinstance(result, dict):
        return out
    limited = bool(result.get("limitation"))
    for f in result.get("findings") or []:
        dets = f.get("detections") or []
        titles = sorted({d.get("title", "") for d in dets}) or sorted(set(f.get("indicators") or []))
        indicators = "; ".join(f.get("indicators") or [])
        high = f.get("severity") == "high"
        out.append(MemoryFinding(
            source="hunt-sleeping-beacons", kind="sleeping_beacon",
            process=process or f.get("process") or "",
            detail=indicators[:400],
            identity=tuple(titles)[:6],
            raw_severity=f.get("severity") or "",
            weight=(KINDS["sleeping_beacon"]["weight"] * (1.0 if high else 0.6)
                    * (0.5 if limited else 1.0)),
            extra={
                "threads": [d.get("thread") for d in dets][:20],
                # A cross-architecture view or a low-severity hit is a lead,
                # not proof: it needs a second source.
                "needs_corroboration": True if (limited or not high) else KINDS["sleeping_beacon"].get("corroborate", True),
                "limitation": result.get("limitation"),
            },
        ))
    return out


# --- Network behaviour ------------------------------------------------

# What counts as regular is defined once, in net_behavior.periodicity; these
# are its thresholds, named here for the callers that read them from this module.
BEACON_MIN_CONNECTIONS = net_behavior.BEACON_MIN_CONNECTIONS
BEACON_MAX_COV = net_behavior.BEACON_MAX_COV
BEACON_MIN_INTERVAL_S = net_behavior.BEACON_MIN_INTERVAL_S

# A rhythm that is tight and sustained is machine-driven on its own; a looser
# or shorter one also fits update checks and telemetry. Four or five random
# contacts pass the regularity gate about one time in ten; they can never be
# tight, which takes six.
BEACON_TIGHT_MAX_COV = 0.2
BEACON_TIGHT_MIN_ON_RHYTHM = 0.7
BEACON_TIGHT_MIN_CONNECTIONS = 6
# Weight of a beacon that is periodic but not tight, as a share of its kind's.
BEACON_LOOSE_FACTOR = 0.7


def beacon_is_tight(cov, on_rhythm, connections):
    """Is a periodic rhythm tight enough to stand without a second opinion?"""
    return (cov <= BEACON_TIGHT_MAX_COV and on_rhythm >= BEACON_TIGHT_MIN_ON_RHYTHM
            and connections >= BEACON_TIGHT_MIN_CONNECTIONS)


def beaconing_from_connections(connections, process=""):
    """Detect periodic outbound connections from (timestamp, ip, port) tuples.

    Works from any connection log - Sysmon EID 3, ETW, a pcap summary - so it
    is independent of whichever tool happens to watch the network.

    Each endpoint's timestamps are measured by ``net_behavior.periodicity``,
    the one definition of a rhythm in this project: robust (median and median
    absolute deviation, so a slow first connect or a retry does not hide an
    exact rhythm), connections less than ``BEACON_MIN_INTERVAL_S`` apart are
    one check-in, and a series with more than one time scale has no interval.
    """
    by_endpoint = {}
    for ts, ip, port in connections:
        if not ip or ts is None:
            continue
        by_endpoint.setdefault((ip, port), []).append(ts)

    out = []
    for (ip, port), times in by_endpoint.items():
        p = net_behavior.periodicity(times, rounded=False)
        if not p["periodic"]:
            continue
        median, robust_cov, on_rhythm = p["interval"], p["cov"], p["on_rhythm"]
        tight = beacon_is_tight(robust_cov, on_rhythm, p["connections"])
        weight = KINDS["c2_beaconing"]["weight"] * (1.0 if tight else BEACON_LOOSE_FACTOR)
        out.append(MemoryFinding(
            source="sysmon-network", kind="c2_beaconing", process=process,
            detail=f"{len(times)} connections to {ip}:{port}, every {median:.1f}s "
                   f"({on_rhythm:.0%} of intervals on rhythm, robust CoV {robust_cov:.2f})",
            identity=(ip, port),
            weight=round(weight, 2),
            extra={
                "endpoint": f"{ip}:{port}",
                "dest": ip,
                "connections": len(times),
                "mean_interval_s": round(median, 2),
                "cov": round(robust_cov, 3),
                "on_rhythm": round(on_rhythm, 2),
                "needs_corroboration": not tight,
            },
        ))
    return out


def from_beaconeye(result, process=""):
    """Normalize BeaconEye findings: a parsed beacon configuration is strong evidence."""
    out = []
    if not isinstance(result, dict):
        return out
    limited = bool(result.get("limitation"))
    for f in result.get("findings") or []:
        cfg = f.get("config") or {}
        out.append(MemoryFinding(
            source="beaconeye", kind="beacon_config", process=process or f.get("process") or "",
            detail=f.get("summary") or "CobaltStrike beacon configuration",
            identity=(cfg.get("C2Server") or cfg.get("c2") or "", cfg.get("Watermark") or ""),
            weight=KINDS["beacon_config"]["weight"] * (0.5 if limited else 1.0),
            extra={"config": cfg or None, "keys_found": f.get("keys_found"),
                   "limitation": result.get("limitation")},
        ))
    return out


# --- Persistence across repeated samples ------------------------------

def merge_samples(samples):
    """Collapse per-sample finding lists into one list carrying persistence.

    ``samples`` is a list of finding lists, one per scan of the same target.
    A finding present in every sample is a property of the process; one that
    appears once is memory that happened to look that way for a moment.
    """
    total = len(samples)
    if total == 0:
        return []

    merged = {}
    for findings in samples:
        # Persistence counts samples, not hits: two heap tables in one scan is
        # one sample's worth of evidence for that key.
        keys_this_sample = set()
        for f in findings:
            entry = merged.get(f["key"])
            if entry is None:
                entry = dict(f, seen_in=0, occurrences=0)
                merged[f["key"]] = entry
            entry["occurrences"] += 1
            keys_this_sample.add(f["key"])
        for key in keys_this_sample:
            merged[key]["seen_in"] += 1

    for entry in merged.values():
        entry["samples"] = total
        entry["persistence"] = round(entry["seen_in"] / total, 3)
    return list(merged.values())


def _persistence_factor(finding):
    samples = finding.get("samples") or 1
    if samples <= 1:
        # Single scan: no persistence information, so neither reward nor punish.
        return 1.0
    ratio = (finding.get("seen_in") or 1) / samples
    if ratio >= 0.999:
        return PERSISTENCE_FULL
    if ratio >= 0.5:
        return PERSISTENCE_PARTIAL
    return PERSISTENCE_SINGLE


# --- Host baseline ----------------------------------------------------

class MemoryBaseline:
    """Keys of findings observed on this host while it was considered clean.

    This is the memory-side equivalent of Process Dump's clean-hash database:
    anything the box produces on its own stops being evidence.
    """

    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self._data = self._empty()
        self.load()

    @staticmethod
    def _empty():
        return {"created": None, "updated": None, "key_version": KEY_VERSION, "keys": {}}

    def _stale(self):
        """True if the stored keys were built with another key scheme."""
        return self._data.get("key_version", 1) != KEY_VERSION

    def load(self):
        if not os.path.isfile(self.path):
            return
        try:
            with open(self.path, "r") as f:
                data = json.load(f)
            if isinstance(data, dict) and isinstance(data.get("keys"), dict):
                self._data = data
                if self._stale():
                    print(f"[memory_baseline] {self.path} uses key scheme "
                          f"v{data.get('key_version', 1)}, current is v{KEY_VERSION}: "
                          f"ignored until the baseline is captured again")
        except (ValueError, IOError) as e:
            # Keep the unreadable file for inspection instead of silently
            # starting empty and overwriting it on the next add().
            print(f"[memory_baseline] unreadable baseline {self.path}: {e}")
            try:
                os.replace(self.path, self.path + ".corrupt")
            except OSError:
                pass

    def save(self):
        # Write to a temp file and swap it in: an interrupted in-place write
        # used to leave invalid JSON, which load() then treated as empty.
        tmp = self.path + ".tmp"
        try:
            with open(tmp, "w") as f:
                json.dump(self._data, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
        except (IOError, OSError) as e:
            print(f"[memory_baseline] could not save {self.path}: {e}")

    def add(self, findings):
        """Record findings as benign-for-this-host. Returns the number added."""
        added = 0
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self._lock:
            if self._stale():
                # Old keys cannot match new findings; start the new scheme fresh.
                self._data = self._empty()
            keys = self._data.setdefault("keys", {})
            for f in findings:
                entry = keys.get(f["key"])
                if entry is None:
                    keys[f["key"]] = {
                        "kind": f["kind"],
                        "process": f.get("process") or "",
                        "detail": (f.get("detail") or "")[:160],
                        "first_seen": now,
                        "count": 1,
                    }
                    added += 1
                else:
                    entry["count"] = entry.get("count", 1) + 1
            self._data["created"] = self._data.get("created") or now
            self._data["updated"] = now
            self.save()
        return added

    def knows(self, key):
        if self._stale():
            return False
        return key in (self._data.get("keys") or {})

    def clear(self):
        with self._lock:
            self._data = self._empty()
            self.save()

    def stats(self):
        # Under the lock: a sweep thread adds keys while requests read stats.
        with self._lock:
            keys = dict(self._data.get("keys") or {})
            created, updated = self._data.get("created"), self._data.get("updated")
            stale = self._stale()
            stored_version = self._data.get("key_version", 1)
        by_kind = {}
        for entry in keys.values():
            by_kind[entry.get("kind", "?")] = by_kind.get(entry.get("kind", "?"), 0) + 1
        out = {
            "total": 0 if stale else len(keys),
            "by_kind": {} if stale else by_kind,
            "created": created,
            "updated": updated,
            "key_version": KEY_VERSION,
        }
        if stale:
            out["stale"] = True
            out["stale_keys"] = len(keys)
            out["note"] = (f"Baseline was captured with key scheme v{stored_version} "
                           f"and is ignored; capture it again on a clean system.")
        return out


# --- Scoring ----------------------------------------------------------

def _observation_factor(finding):
    """The share of the act that was seen, 0..1; 1.0 when the finding does not say."""
    value = finding.get("observation", 1.0)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or math.isnan(value):
        return 1.0
    return min(1.0, max(0.0, float(value)))


def _endpoints(finding):
    """The destinations a finding names: its dest and, for a name, its addresses."""
    out = set()
    for value in [finding.get("dest")] + list(finding.get("addresses") or ()):
        if not isinstance(value, str) or not value:
            continue
        try:
            out.add(str(ipaddress.ip_address(value)))
        except ValueError:
            out.add(value.lower().rstrip("."))
    return out


def _group_total(contributions):
    """What one (process, kind) group adds once saturation has capped it."""
    values = sorted(contributions, reverse=True)
    if not values:
        return 0.0
    allowance = values[0] * SATURATION_CAP
    running = 0.0
    for value in values:
        running += min(value, max(0.0, allowance - running))
    return running


def _total(entries, excluded):
    groups = {}
    for index, (group, contribution) in entries.items():
        if index not in excluded:
            groups.setdefault(group, []).append(contribution)
    return round(sum(_group_total(values) for values in groups.values()), 6)


# Components of one process whose sides are chosen together, by trying every
# combination. Real captures have one or two per C2; past this the sides are
# chosen per component, which is still independent of the order of findings.
SUPERSEDE_MAX_ENUMERATED = 10


def _components(findings, entries, proc_key):
    """One phenomenon per component: ``[(process, superseding side, other side)]``.

    Findings take part when they are scored, name an endpoint and are of a kind
    that supersedes or is superseded. Two of them on the same process that
    share an endpoint are in one component, whichever side they are on, so a
    check-in to a name and one to its address and the Sysmon beacons on two
    ports of that address are one component. Only components with both sides
    are returned, ordered by their content, not by where the findings sat.
    """
    superseding = {k for k, spec in KINDS.items() if spec.get("supersedes")}
    superseded = {k for spec in KINDS.values() for k in spec.get("supersedes", ())}
    parent = {}

    def root(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    first = {}
    for i, f in enumerate(findings):
        if i not in entries or f.get("kind") not in superseding | superseded:
            continue
        ends = _endpoints(f)
        if not ends:
            continue
        parent[i] = i
        side = "a" if f.get("kind") in superseding else "b"
        for end in ends:
            first.setdefault((proc_key(f), end, side), []).append(i)
    # An edge joins a superseding finding and a superseded one that share an
    # endpoint. Two check-ins on one address are not one phenomenon by that
    # alone (a CDN address carries many names); a beacon to it makes them one.
    for (process, end, side), here in first.items():
        if side != "a":
            continue
        for j in first.get((process, end, "b"), ()):
            for i in here:
                a, b = root(i), root(j)
                if a != b:
                    parent[max(a, b)] = min(a, b)
    members = {}
    for i in parent:
        members.setdefault(root(i), []).append(i)
    out = []
    for group in members.values():
        side_a = sorted(i for i in group if findings[i]["kind"] in superseding)
        side_b = sorted(i for i in group if findings[i]["kind"] not in superseding)
        if side_a and side_b:
            out.append((proc_key(findings[group[0]]), side_a, side_b))

    def content(i):
        f = findings[i]
        return (f.get("kind") or "", f.get("source") or "", f.get("key") or "", entries[i][1])

    out.sort(key=lambda c: (c[0], sorted(content(i) for i in c[1] + c[2])))
    return out


def _supersessions(findings, entries, proc_key):
    """``{index: index of the winner}`` for the findings supersede takes out.

    ``entries`` maps the index of every scored finding (not known to the
    baseline) to its saturation group and contribution. Each component of
    ``_components`` is one phenomenon seen two ways (the check-ins of a C2 and
    Sysmon's beacons to it), so only one side of it counts: of all the ways to
    choose a side in every component of a process, the one with the highest
    total wins; a tie goes to the superseding side. The choice is made over
    the whole set at once, so it does not depend on the order of the findings,
    and adding a finding can only lower the score when that finding shows two
    components to be one phenomenon (it joins them): what was counted twice is
    then counted once. A finding the baseline knows takes part in neither side:
    it counts nothing, so it must not take away what another would have counted.

    Both guarantees are bounded. The best total is searched over all choices
    only up to ``SUPERSEDE_MAX_ENUMERATED`` components on one process; past
    that the result starts from the best of three whole-set choices and is
    improved one component at a time (see the code). It is still independent
    of order and never below counting either view of every component whole,
    but it is a local optimum, so there adding a finding can lower the score
    without joining anything.

    Considered and not taken: forbid only *pairs* of findings that share an
    endpoint and take the best total over the pair-free subsets. That is
    monotone by construction (0 drops in 1,500 random sets against 12 here),
    but it counts two views of one C2 twice whenever they name different
    endpoints of it: a check-in to a name and Sysmon's beacon to an address
    the name also resolves to, through a third finding. With no process
    attribution in a capture that is the more likely error, so components
    were chosen. A later phase that attributes connections to processes may
    want the pair rule instead.
    """
    out = {}
    by_process = {}
    for component in _components(findings, entries, proc_key):
        by_process.setdefault(component[0], []).append(component)

    def winner_of(side):
        return max(side, key=lambda i: (entries[i][1], findings[i].get("key") or ""))

    for process, components in sorted(by_process.items()):
        local = {i: e for i, e in entries.items() if e[0][0] == process}
        if len(components) <= SUPERSEDE_MAX_ENUMERATED:
            best = None
            for mask in range(1 << len(components)):
                excluded = set()
                for bit, (_p, side_a, side_b) in enumerate(components):
                    excluded.update(side_b if not mask >> bit & 1 else side_a)
                rank = (_total(local, excluded), -bin(mask).count("1"), -mask)
                if best is None or rank > best[0]:
                    best = (rank, mask)
            choices = [not best[1] >> bit & 1 for bit in range(len(components))]
        else:
            # Past the cap: the best of three choices, each independent of the
            # order of the findings: every component on its superseding side,
            # every one on the other side, and each on its own larger side.
            candidates = [
                [True] * len(components),
                [False] * len(components),
                [_total({i: entries[i] for i in side_a}, set())
                 >= _total({i: entries[i] for i in side_b}, set())
                 for _p, side_a, side_b in components]]

            def total_of(choice):
                excluded = set()
                for keep_a, (_p, side_a, side_b) in zip(choice, components):
                    excluded.update(side_b if keep_a else side_a)
                return _total(local, excluded)
            choices = max(candidates, key=lambda c: (total_of(c), c.count(True)))
            # Then flip one component at a time, in the canonical order, while
            # that raises the total: saturation often makes a mix of sides
            # best (two beacons fill their kind's cap, the rest count as
            # check-ins), and none of the three candidates is a mix.
            best_total = total_of(choices)
            improved = True
            while improved:
                improved = False
                for bit in range(len(choices)):
                    trial = list(choices)
                    trial[bit] = not trial[bit]
                    value = total_of(trial)
                    if value > best_total:
                        choices, best_total, improved = trial, value, True
        for keep_a, (_p, side_a, side_b) in zip(choices, components):
            keep, drop = (side_a, side_b) if keep_a else (side_b, side_a)
            winner = winner_of(keep)
            for i in drop:
                out[i] = winner
    return out


def score(findings, baseline=None):
    """Weigh normalized findings into a verdict.

    Returns a dict with the verdict, the scored findings (each carrying the
    factors that produced its confidence), and the suppressed ones, so the
    result can be audited rather than trusted. ``suppressed`` holds what the
    baseline knows (``suppressed_count``) and what another finding absorbed
    (``superseded_by``, ``superseded_count``).
    """
    scored, suppressed = [], []

    # Corroboration is per process: a kind that needs a second opinion gets it
    # from any finding of a different source on the same process.
    # Process names come from different tools (tasklist, the submitted file
    # name, a dump's module list), so they are compared case-insensitively.
    def proc_key(f):
        return (f.get("process") or "").lower()

    def known(f):
        if baseline is None or KINDS.get(f.get("kind"), {}).get("baseline_exempt"):
            return False
        return baseline.knows(f["key"])

    # Only substantial findings may corroborate another source. Otherwise a
    # trivial string hit ("kernel32.dll", weight 0.2) would vouch for anything
    # that happens to share the process.
    # A finding with corroboration_scope "endpoint" is about one destination
    # only (an upload to a known-good host): it neither gets nor gives a second
    # opinion except with a finding that names the same endpoint. An OCSP
    # request is not made suspicious by a reflective PE elsewhere in the
    # process, nor does it vouch for one.
    # A finding whose process is only assumed (attribution "assumed": a
    # capture's finding given to the sample) neither gets nor gives a second
    # opinion through the process: only through a shared endpoint, with a
    # finding of any process and any other source.
    def assumed(f):
        return f.get("attribution") == ATTRIBUTION_ASSUMED

    sources_by_process = {}
    scoped = []
    for f in findings:
        if f.get("base_weight", 0) < CORROBORATION_MIN_WEIGHT:
            continue
        if known(f):
            continue
        if f.get("corroboration_scope") == CORROBORATION_SCOPE_ENDPOINT or assumed(f):
            scoped.append(f)
            continue
        sources_by_process.setdefault(proc_key(f), set()).add(f["source"])
    eligible = [f for f in findings
                if f.get("base_weight", 0) >= CORROBORATION_MIN_WEIGHT and not known(f)]

    def corroborators(f):
        if assumed(f):
            mine = _endpoints(f)
            return {g["source"] for g in eligible if g is not f and mine & _endpoints(g)} - {f["source"]}
        if f.get("corroboration_scope") == CORROBORATION_SCOPE_ENDPOINT:
            pool = [g for g in eligible if g is not f]
        elif scoped:
            pool = scoped
        else:
            return sources_by_process.get(proc_key(f), set()) - {f["source"]}
        mine = _endpoints(f)
        near = {g["source"] for g in pool
                if proc_key(g) == proc_key(f) and mine & _endpoints(g)}
        if f.get("corroboration_scope") != CORROBORATION_SCOPE_ENDPOINT:
            near |= sources_by_process.get(proc_key(f), set())
        return near - {f["source"]}

    # Every finding is weighed first, then supersede decides which side of
    # each phenomenon counts, from the totals of all choices at once. The
    # findings it takes out stay in sources_by_process above, so they still
    # corroborate, the one that won as well as any other.
    weighed = {}
    for index, f in enumerate(findings):
        if known(f):
            continue
        factors = {"persistence": _persistence_factor(f)}
        corroborated_by = None
        cf = 1.0
        if f.get("needs_corroboration"):
            others = corroborators(f)
            if others:
                corroborated_by = sorted(others)
            else:
                cf = UNCORROBORATED
        factors["corroboration"] = cf
        factors["observation"] = _observation_factor(f)
        confidence = round(min(1.0, factors["persistence"] * cf * factors["observation"]), 3)
        contribution = round(f.get("base_weight", 1.0) * confidence, 3)
        weighed[index] = (factors, corroborated_by, confidence, contribution)

    out_by = _supersessions(
        findings, {i: ((proc_key(findings[i]), findings[i]["kind"]), w[3])
                   for i, w in weighed.items()}, proc_key)
    absorbed = {}
    for index, winner in out_by.items():
        absorbed.setdefault(winner, []).append(
            {"kind": findings[index].get("kind"), "source": findings[index].get("source")})
    baseline_count = superseded_count = 0

    for index, f in enumerate(findings):
        item = dict(f)

        if index not in weighed:
            item["baseline"] = "known"
            item["confidence"] = 0.0
            item["score"] = 0.0
            item["factors"] = {"baseline": BASELINE_KNOWN}
            suppressed.append(item)
            baseline_count += 1
            continue
        if index in out_by:
            winner = findings[out_by[index]]
            item["superseded_by"] = winner["kind"]
            item["superseded_by_key"] = winner.get("key")
            item["confidence"] = 0.0
            item["score"] = 0.0
            item["factors"] = {"superseded": 0.0}
            suppressed.append(item)
            superseded_count += 1
            continue
        item["baseline"] = "new"

        factors, corroborated_by, confidence, contribution = weighed[index]
        if corroborated_by:
            item["corroborated_by"] = corroborated_by
        item["confidence"] = confidence
        item["raw_score"] = contribution
        item["score"] = contribution
        item["factors"] = factors
        if index in absorbed:
            item["absorbed"] = absorbed[index]
        scored.append(item)

    # Saturation: cap what one kind can contribute per process. Without this a
    # scanner reporting the same phenomenon ten times outweighs ten different
    # corroborated facts.
    groups = {}
    for item in scored:
        groups.setdefault((proc_key(item), item["kind"]), []).append(item)

    for (proc, kind), items in groups.items():
        if len(items) < 2:
            continue
        items.sort(key=lambda x: -x["raw_score"])
        strongest = items[0]["raw_score"]
        allowance = strongest * SATURATION_CAP
        running = 0.0
        for rank, item in enumerate(items):
            remaining = max(0.0, allowance - running)
            capped = min(item["raw_score"], remaining)
            running += capped
            item["score"] = round(capped, 3)
            item["saturation"] = {
                "rank": rank + 1,
                "group_size": len(items),
                "group_cap": round(allowance, 2),
            }

    total = round(sum(item["score"] for item in scored), 2)

    scored.sort(key=lambda x: (-x["score"], EVIDENCE_RANK.get(x["evidence"], 9)))

    if total >= VERDICT_MALICIOUS:
        label = "MALICIOUS"
    elif total >= VERDICT_SUSPICIOUS:
        label = "SUSPICIOUS"
    else:
        label = "CLEAN"

    reasons = []
    for item in scored:
        if item["score"] <= 0:
            continue
        reason = item["label"]
        if item.get("process"):
            reason += f" in {item['process']}"
        bits = [f"{item['source']}", f"confidence {item['confidence']:.2f}"]
        if (item.get("samples") or 1) > 1:
            bits.append(f"seen in {item['seen_in']}/{item['samples']} samples")
        if item.get("corroborated_by"):
            bits.append("corroborated by " + ", ".join(item["corroborated_by"]))
        elif item.get("needs_corroboration"):
            bits.append("uncorroborated")
        sat = item.get("saturation")
        if sat and sat["group_size"] > 1:
            bits.append(f"{sat['rank']} of {sat['group_size']} of this kind")
        for other in item.get("absorbed") or ():
            bits.append(f"absorbs {other['kind']} from {other['source']}")
        reasons.append(f"{reason} ({'; '.join(bits)})")

    by_evidence = {}
    for item in scored:
        by_evidence[item["evidence"]] = round(
            by_evidence.get(item["evidence"], 0.0) + item["score"], 2)

    return {
        "label": label,
        "score": total,
        "thresholds": {"suspicious": VERDICT_SUSPICIOUS, "malicious": VERDICT_MALICIOUS},
        "findings": scored,
        "suppressed": suppressed,
        # Read as "suppressed by the host baseline" by app.py and the UI.
        "suppressed_count": baseline_count,
        "superseded_count": superseded_count,
        "by_evidence": by_evidence,
        "reasons": reasons[:12],
        "sources": sorted({f["source"] for f in findings}),
    }


def collect(results, process="", network_process=None):
    """Pull every supported scanner result out of a detonation result dict.

    A capture knows no process, so the findings of the network report come
    without one; they are the sample's traffic (the report was imported for
    it), so they are attributed to ``network_process`` (default ``process``)
    and marked ``attribution: "assumed"``. Supersede matches by process:
    without this a capture's check-in and Sysmon's beaconing of the same loop
    never met and counted twice. Corroboration of such a finding goes only
    through a shared endpoint (see score). A finding that already names a
    process, or one with a pid, keeps what it has.
    """
    findings = []
    aether = results.get("aether") or {}
    if isinstance(aether, dict):
        # A multi-sample scan already carries merged findings.
        # An empty merged list is still the authoritative result; falling back
        # to the raw report would re-score only the last sample.
        if "evidence_findings" in aether:
            findings += aether["evidence_findings"] or []
        elif aether.get("report"):
            findings += from_aether(aether["report"], process)
    findings += from_process_dump(results.get("process_dump") or {}, process)
    findings += from_hsb(results.get("hunt_sleeping_beacons") or {}, process)
    findings += from_beaconeye(results.get("beaconeye") or {}, process)

    # Exit-time dump analysis already produces normalized findings.
    exit_res = results.get("exit_capture_result") or {}
    if isinstance(exit_res, dict) and exit_res.get("evidence_findings"):
        findings += exit_res["evidence_findings"]

    # Network beaconing derived from the connection log.
    net = results.get("network_beaconing") or {}
    if isinstance(net, dict) and net.get("evidence_findings"):
        findings += net["evidence_findings"]

    # Named pipes from Sysmon EID 17/18.
    pipes = results.get("named_pipes") or {}
    if isinstance(pipes, dict) and pipes.get("evidence_findings"):
        findings += pipes["evidence_findings"]

    # The network report imported for the sample (net_evidence, source
    # "network"). It only holds findings of events the network baseline does
    # not know; one marked baseline anyway stays out. Copies: the report is the
    # stored one, and scoring must not write into it.
    report = results.get("network") or {}
    if isinstance(report, dict) and isinstance(report.get("evidence_findings"), list):
        owner = _process_identity(process if network_process is None else network_process)[0]
        for f in report["evidence_findings"]:
            if not isinstance(f, dict) or f.get("baseline"):
                continue
            if owner and not f.get("process") and f.get("pid") in (None, ""):
                f = dict(f, process=owner, attribution=ATTRIBUTION_ASSUMED)
            findings.append(dict(f))

    dyn = results.get("litterbox_dynamic") or {}
    if isinstance(dyn, dict):
        findings += from_pe_sieve(dyn.get("pe_sieve") or dyn.get("pe_sieve_results") or {}, process)
        findings += from_moneta(dyn.get("moneta") or dyn.get("moneta_results") or {}, process)
    return findings
