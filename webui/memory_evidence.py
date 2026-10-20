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
from any source are normalized into one schema and weighted by four factors:

  evidence class   structural facts outrank behavioural hints outrank strings
  persistence      how many samples of a repeated scan contained the finding
  corroboration    whether an independent source agrees on the same process
  novelty          whether the finding also occurs in this host's clean baseline

Adding a scanner means adding a normalizer function; nothing else changes.
"""

import hashlib
import json
import os
import threading
import time

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
}

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

# A beacon needs enough check-ins to show a rhythm.
BEACON_MIN_CONNECTIONS = 4
# Coefficient of variation of the intervals: below this the timing is regular
# enough to be machine-driven. Jittered C2 (20-30% jitter) stays under 0.5.
BEACON_MAX_COV = 0.5
# Connections closer than this are a burst (one request), not separate beacons.
BEACON_MIN_INTERVAL_S = 0.5


def beaconing_from_connections(connections, process=""):
    """Detect periodic outbound connections from (timestamp, ip, port) tuples.

    Works from any connection log - Sysmon EID 3, ETW, a pcap summary - so it
    is independent of whichever tool happens to watch the network.

    Periodicity is measured robustly (median and median absolute deviation):
    real check-in loops have outliers - a slow first connect, a retry - and a
    mean/stdev estimate lets a single outlier hide an otherwise exact rhythm.
    """
    import statistics

    by_endpoint = {}
    for ts, ip, port in connections:
        if not ip or ts is None:
            continue
        by_endpoint.setdefault((ip, port), []).append(ts)

    out = []
    for (ip, port), times in by_endpoint.items():
        times.sort()
        intervals = [b - a for a, b in zip(times, times[1:]) if b - a >= BEACON_MIN_INTERVAL_S]
        if len(intervals) + 1 < BEACON_MIN_CONNECTIONS:
            continue
        median = statistics.median(intervals)
        if median <= 0:
            continue
        mad = statistics.median(abs(x - median) for x in intervals)
        # 1.4826 * MAD estimates the standard deviation for normal data.
        robust_cov = 1.4826 * mad / median
        on_rhythm = sum(1 for x in intervals if abs(x - median) <= 0.25 * median) / len(intervals)
        if robust_cov > BEACON_MAX_COV or on_rhythm < 0.5:
            continue
        # A tight, sustained rhythm is machine-driven on its own; looser timing
        # also fits update checks and telemetry, so it needs a second opinion.
        tight = robust_cov <= 0.2 and on_rhythm >= 0.7 and len(intervals) + 1 >= 6
        weight = KINDS["c2_beaconing"]["weight"] * (1.0 if tight else 0.7)
        out.append(MemoryFinding(
            source="sysmon-network", kind="c2_beaconing", process=process,
            detail=f"{len(times)} connections to {ip}:{port}, every {median:.1f}s "
                   f"({on_rhythm:.0%} of intervals on rhythm, robust CoV {robust_cov:.2f})",
            identity=(ip, port),
            weight=round(weight, 2),
            extra={
                "endpoint": f"{ip}:{port}",
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

def score(findings, baseline=None):
    """Weigh normalized findings into a verdict.

    Returns a dict with the verdict, the scored findings (each carrying the
    factors that produced its confidence), and the suppressed ones, so the
    result can be audited rather than trusted.
    """
    scored, suppressed = [], []

    # Corroboration is per process: a kind that needs a second opinion gets it
    # from any finding of a different source on the same process.
    # Process names come from different tools (tasklist, the submitted file
    # name, a dump's module list), so they are compared case-insensitively.
    def proc_key(f):
        return (f.get("process") or "").lower()

    # Only substantial findings may corroborate another source. Otherwise a
    # trivial string hit ("kernel32.dll", weight 0.2) would vouch for anything
    # that happens to share the process.
    sources_by_process = {}
    for f in findings:
        if f.get("base_weight", 0) < CORROBORATION_MIN_WEIGHT:
            continue
        if baseline is not None and baseline.knows(f["key"]):
            continue
        sources_by_process.setdefault(proc_key(f), set()).add(f["source"])


    for f in findings:
        item = dict(f)
        factors = {}

        if baseline is not None and baseline.knows(f["key"]):
            item["baseline"] = "known"
            item["confidence"] = 0.0
            item["score"] = 0.0
            item["factors"] = {"baseline": BASELINE_KNOWN}
            suppressed.append(item)
            continue
        item["baseline"] = "new"

        pf = _persistence_factor(f)
        factors["persistence"] = pf

        cf = 1.0
        if f.get("needs_corroboration"):
            others = sources_by_process.get(proc_key(f), set()) - {f["source"]}
            if others:
                item["corroborated_by"] = sorted(others)
            else:
                cf = UNCORROBORATED
        factors["corroboration"] = cf

        confidence = round(min(1.0, pf * cf), 3)
        contribution = round(f.get("base_weight", 1.0) * confidence, 3)

        item["confidence"] = confidence
        item["raw_score"] = contribution
        item["score"] = contribution
        item["factors"] = factors
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
        "suppressed_count": len(suppressed),
        "by_evidence": by_evidence,
        "reasons": reasons[:12],
        "sources": sorted({f["source"] for f in findings}),
    }


def collect(results, process=""):
    """Pull every supported scanner result out of a detonation result dict."""
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

    dyn = results.get("litterbox_dynamic") or {}
    if isinstance(dyn, dict):
        findings += from_pe_sieve(dyn.get("pe_sieve") or dyn.get("pe_sieve_results") or {}, process)
        findings += from_moneta(dyn.get("moneta") or dyn.get("moneta_results") or {}, process)
    return findings
