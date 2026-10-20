"""Post-mortem analysis of Windows minidumps captured at process exit.

Short-lived samples are gone before any live scanner starts. Windows can write
a full-memory dump at the moment a process exits (Silent Process Exit
monitoring, configured per image name in the registry). This module reads such
a dump and produces the same normalized findings as the live scanners, so the
evidence model can score a process that no longer exists.

It needs nothing but the dump: no scanner binary, no access to the original
process. Checks performed:

  thread starts       thread start address inside private executable memory
  reflective images   PE headers in non-image memory (and .NET metadata in them)
  hidden images       MEM_IMAGE allocations missing from the loader's module list
  private code        private executable allocations
  signatures          string rules (ASCII and UTF-16LE) over non-image memory

Executable artifacts found in memory are written back to disk as files, with
section offsets realigned so ordinary PE tooling can open them.

Host awareness: on ARM64 Windows an emulated x64 process carries the emulator's
translation cache as private executable memory. That is expected there and is
discounted rather than reported as injected code.
"""

import json
import os
import struct

import memory_evidence as me

# Minidump stream types
STREAM_THREAD_LIST = 3
STREAM_MODULE_LIST = 4
STREAM_SYSTEM_INFO = 7
STREAM_MEMORY64_LIST = 9
STREAM_MEMORY_INFO_LIST = 16
STREAM_THREAD_INFO_LIST = 17

ARCH_NAMES = {0: "x86", 5: "ARM", 9: "AMD64", 12: "ARM64"}

MEM_COMMIT = 0x1000
MEM_IMAGE = 0x1000000
MEM_MAPPED = 0x40000
MEM_PRIVATE = 0x20000
PAGE_EXECUTE_ANY = 0x10 | 0x20 | 0x40 | 0x80
PAGE_EXECUTE_READWRITE = 0x40

TYPE_NAMES = {MEM_IMAGE: "image", MEM_MAPPED: "mapped", MEM_PRIVATE: "private"}

# Modules that mark a process as running under x64/x86 emulation on ARM64.
EMULATOR_MODULES = ("xtajit64.dll", "xtajit64se.dll", "xtajit.dll")

# Upper bounds keep a single huge dump from stalling the web worker.
MAX_SIGNATURE_SCAN_BYTES = 96 * 1024 * 1024
MAX_ARTIFACT_BYTES = 32 * 1024 * 1024
MAX_ARTIFACTS = 40


class MinidumpError(ValueError):
    pass


class Minidump:
    """Read-only view over a minidump file (the subset needed here)."""

    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.data = f.read()
        if self.data[:4] != b"MDMP":
            raise MinidumpError("not a minidump (missing MDMP signature)")

        # A truncated or corrupt dump surfaces as struct.error from any of the
        # readers below; report it as a dump problem, not a code bug.
        try:
            _, _, count, rva = struct.unpack_from("<4sIII", self.data, 0)
            count = min(count, max(0, (len(self.data) - rva) // 12))
            self.streams = {}
            for i in range(count):
                stype, size, srva = struct.unpack_from("<III", self.data, rva + i * 12)
                self.streams[stype] = (size, srva)

            self.arch = self._read_arch()
            self.modules = self._read_modules()
            self.regions = self._read_memory_info()
            self.threads = self._read_thread_info()
            self._ranges = self._read_memory64()
        except struct.error as e:
            raise MinidumpError(f"truncated or corrupt minidump: {e}") from e
        self._range_starts = [r[0] for r in self._ranges]
        self._regions_sorted = sorted(self.regions, key=lambda r: r["base"])
        self._region_starts = [r["base"] for r in self._regions_sorted]

    # --- streams ------------------------------------------------------

    def _stream(self, stype):
        return self.streams.get(stype)

    def _read_arch(self):
        s = self._stream(STREAM_SYSTEM_INFO)
        if not s:
            return "unknown"
        return ARCH_NAMES.get(struct.unpack_from("<H", self.data, s[1])[0], "unknown")

    def _utf16_at(self, rva):
        length = struct.unpack_from("<I", self.data, rva)[0]
        return self.data[rva + 4:rva + 4 + length].decode("utf-16le", errors="replace")

    def _read_modules(self):
        s = self._stream(STREAM_MODULE_LIST)
        if not s:
            return []
        count = struct.unpack_from("<I", self.data, s[1])[0]
        count = min(count, max(0, (s[0] - 4) // 108))
        mods = []
        for i in range(count):
            off = s[1] + 4 + i * 108
            base, size, _, _, name_rva = struct.unpack_from("<QIIII", self.data, off)
            path = self._utf16_at(name_rva)
            mods.append({
                "name": path.replace("/", "\\").split("\\")[-1],
                "path": path,
                "base": base,
                "size": size,
            })
        return mods

    def _read_memory_info(self):
        s = self._stream(STREAM_MEMORY_INFO_LIST)
        if not s:
            return []
        header, entry, count = struct.unpack_from("<IIQ", self.data, s[1])
        # Entry size and count come from the file. An entry size of 0 would
        # re-read the same offset forever; cap both by the stream size.
        if entry < 48:
            raise MinidumpError(f"memory info entry size {entry} is too small")
        count = min(count, max(0, (s[0] - header) // entry))
        regions = []
        for i in range(count):
            (base, alloc_base, alloc_protect, _, size, state, protect,
             rtype, _) = struct.unpack_from("<QQIIQIIII", self.data, s[1] + header + i * entry)
            regions.append({
                "base": base, "allocation_base": alloc_base,
                "allocation_protect": alloc_protect, "size": size,
                "state": state, "protect": protect, "type": rtype,
            })
        return regions

    def _read_thread_info(self):
        s = self._stream(STREAM_THREAD_INFO_LIST)
        if not s:
            return []
        header, entry, count = struct.unpack_from("<III", self.data, s[1])
        if entry < 64:
            raise MinidumpError(f"thread info entry size {entry} is too small")
        count = min(count, max(0, (s[0] - header) // entry))
        threads = []
        for i in range(count):
            vals = struct.unpack_from("<IIIIQQQQQQ", self.data, s[1] + header + i * entry)
            threads.append({"tid": vals[0], "start": vals[8]})
        return threads

    def _read_memory64(self):
        s = self._stream(STREAM_MEMORY64_LIST)
        if not s:
            return []
        count, base_rva = struct.unpack_from("<QQ", self.data, s[1])
        count = min(count, max(0, (s[0] - 16) // 16))
        ranges, offset = [], base_rva
        for i in range(count):
            start, size = struct.unpack_from("<QQ", self.data, s[1] + 16 + i * 16)
            ranges.append((start, size, offset))
            offset += size
        # read() walks ranges in address order; the file order is usually
        # ascending already, but nothing guarantees it.
        ranges.sort(key=lambda r: r[0])
        return ranges

    # --- memory access ------------------------------------------------

    def read(self, address, size):
        """Bytes at a virtual address, assembled across captured ranges.

        An image spans several regions (one per section), which a dump stores
        as separate ranges. Gaps the dump did not capture are zero-filled so
        offsets inside the returned buffer still match virtual addresses; the
        result stops at the first gap after the last captured byte, and at the
        end of the file if the dump was truncated.
        """
        import bisect
        end = address + size
        out = bytearray()
        cursor = address
        # Start at the last range beginning at or before the address instead
        # of walking every range for every read.
        i = max(0, bisect.bisect_right(self._range_starts, address) - 1)
        for start, length, offset in self._ranges[i:]:
            r_end = start + length
            if r_end <= cursor:
                continue
            if start >= end:
                break
            if start > cursor:
                if not out:
                    # Leading gap: the requested start itself was not captured.
                    return b""
                out.extend(b"\0" * (start - cursor))
                cursor = start
            take_from = cursor - start
            take = min(r_end, end) - cursor
            chunk = self.data[offset + take_from:offset + take_from + take]
            out.extend(chunk)
            cursor += len(chunk)
            if len(chunk) < take or cursor >= end:
                # Short chunk: the file ends inside this range.
                break
        return bytes(out)

    def read_region(self, region, limit=None):
        size = region["size"] if limit is None else min(region["size"], limit)
        return self.read(region["base"], size)

    def region_at(self, address):
        import bisect
        i = bisect.bisect_right(self._region_starts, address) - 1
        if i >= 0:
            r = self._regions_sorted[i]
            if r["base"] <= address < r["base"] + r["size"]:
                return r
        return None

    def module_at(self, address):
        for m in self.modules:
            if m["base"] <= address < m["base"] + m["size"]:
                return m
        return None

    @property
    def captured_bytes(self):
        return sum(r[1] for r in self._ranges)


# --- helpers -------------------------------------------------------------

def _is_exec(region):
    return bool(region["protect"] & PAGE_EXECUTE_ANY)


def _arm64_code_density(buf):
    """Count instruction patterns that only occur in ARM64 code.

    RET, BR/BLR and the frame-record STP/LDP of x29/x30 are distinctive 32-bit
    encodings; x64 code essentially never produces them on aligned words.
    """
    hits = 0
    for i in range(0, len(buf) - 3, 4):
        w = int.from_bytes(buf[i:i + 4], "little")
        if (w == 0xD65F03C0
                or (w & 0xFFFFFC1F) in (0xD61F0000, 0xD63F0000)
                or (w & 0xFFC07FFF) in (0xA9007BFD, 0xA9407BFD, 0xA9807BFD, 0xA8C07BFD)):
            hits += 1
    return hits


def classify_private_exec(region, buf, emulated):
    """Explain a private executable region before treating it as evidence.

    Returns (classification, reason). Only "code" counts as evidence; the
    other classes are artifacts of how the host runs the process.
    Observed on ARM64 Windows running x64 samples:
      * the emulator's translation cache - ~1 MB of dense ARM64 code
      * an emulator stub page whose only content is a single RET (0xC3)
    An injected x64 payload looks like neither.
    """
    nonzero = len(buf) - buf.count(0)
    if nonzero == 0:
        return "empty", "committed but zero-filled"
    if emulated:
        arm = _arm64_code_density(buf)
        if arm >= 16 and arm * 4 >= nonzero * 0.02:
            return "emulator_cache", f"ARM64 translation cache ({arm} ARM64 instruction patterns)"
        if nonzero == 1 and buf.lstrip(b"\0")[:1] == b"\xC3":
            return "emulator_stub", "emulator stub page (single RET)"
    return "code", ""


def _pe_info(buf):
    """Minimal PE header check. Returns a dict or None."""
    if len(buf) < 0x40 or buf[:2] != b"MZ":
        return None
    e_lfanew = struct.unpack_from("<I", buf, 0x3C)[0]
    if e_lfanew <= 0 or e_lfanew + 24 > len(buf) or buf[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        return None
    machine, nsec = struct.unpack_from("<HH", buf, e_lfanew + 4)
    opt_size = struct.unpack_from("<H", buf, e_lfanew + 20)[0]
    magic = struct.unpack_from("<H", buf, e_lfanew + 24)[0] if e_lfanew + 26 <= len(buf) else 0
    return {
        "e_lfanew": e_lfanew,
        "machine": machine,
        "sections": nsec,
        "optional_size": opt_size,
        "pe32plus": magic == 0x20B,
    }


def realign_image(buf):
    """Turn a memory-layout PE image into a file other tools can parse.

    In memory each section sits at its VirtualAddress; on disk it sits at
    PointerToRawData. Pointing the raw fields at the virtual layout makes the
    image readable without moving any bytes - the standard fix for dumps.
    """
    info = _pe_info(buf)
    if not info:
        return buf
    out = bytearray(buf)
    table = info["e_lfanew"] + 24 + info["optional_size"]
    for i in range(min(info["sections"], 96)):
        off = table + i * 40
        if off + 40 > len(out):
            break
        vsize, vaddr = struct.unpack_from("<II", out, off + 8)
        raw_size = struct.unpack_from("<I", out, off + 16)[0]
        size = max(vsize, raw_size)
        if vaddr + size > len(out):
            size = max(0, len(out) - vaddr)
        struct.pack_into("<II", out, off + 16, size, vaddr)
    return bytes(out)


def load_rules(rules_dir):
    """Load string rules (Aether's JSON rule format: pattern/risk_score/category)."""
    rules = []
    if not rules_dir or not os.path.isdir(rules_dir):
        return rules
    for name in sorted(os.listdir(rules_dir)):
        if not name.endswith(".json"):
            continue
        try:
            with open(os.path.join(rules_dir, name), "r", encoding="utf-8") as f:
                entries = json.load(f)
        except (OSError, ValueError):   # ValueError covers JSON and UTF-8 errors
            continue
        for e in entries if isinstance(entries, list) else []:
            if not isinstance(e, dict):
                continue
            pattern = e.get("pattern")
            if not isinstance(pattern, str):
                continue
            ascii_needle = pattern.encode("latin-1", errors="ignore")
            if len(ascii_needle) < 4:
                # Very short patterns match almost anything in raw memory.
                # Checked on the encoded bytes: dropped non-Latin characters
                # could otherwise leave a 0-3 byte needle.
                continue
            try:
                risk = int(e.get("risk_score") or 0)
            except (TypeError, ValueError):
                risk = 0
            rules.append({
                "pattern": pattern,
                "ascii": ascii_needle,
                "utf16": pattern.encode("utf-16le"),
                "risk": risk,
                "category": (e.get("category") or "").upper(),
                "description": e.get("description") or "",
            })
    return rules


# --- analysis ------------------------------------------------------------

def analyze(path, process="", rules_dir=None, extract_dir=None):
    """Analyze an exit dump. Returns a JSON-serializable result dict."""
    dump = Minidump(path)
    findings, artifacts, notes = [], [], []

    module_bases = {m["base"] for m in dump.modules}
    emulated = any(m["name"].lower() in EMULATOR_MODULES for m in dump.modules)
    if emulated:
        notes.append(
            f"Process ran under x64 emulation on an {dump.arch} host; the "
            "emulator's own executable memory is classified and not scored."
        )

    committed = [r for r in dump.regions if r["state"] == MEM_COMMIT]
    private_exec = [r for r in committed if r["type"] == MEM_PRIVATE and _is_exec(r)]

    # 1. Thread start addresses
    for t in dump.threads:
        region = dump.region_at(t["start"])
        if region and region["type"] == MEM_PRIVATE and _is_exec(region):
            findings.append(me.MemoryFinding(
                source="exit-capture", kind="thread_start_private", process=process,
                detail=f"Thread {t['tid']} started at {t['start']:#x} in private "
                       f"executable memory (allocation {region['allocation_base']:#x})",
                address=hex(t["start"]),
                identity=(region["size"],),
            ))
        elif region is None and t["start"]:
            notes.append(f"Thread {t['tid']} start {t['start']:#x} is outside captured memory")

    # 2. Reflective images in non-image memory
    seen_alloc = set()
    for r in committed:
        if r["type"] == MEM_IMAGE or r["allocation_base"] in seen_alloc:
            continue
        head = dump.read(r["allocation_base"], 0x1000)
        info = _pe_info(head)
        if not info:
            continue
        seen_alloc.add(r["allocation_base"])
        alloc_regions = [x for x in committed if x["allocation_base"] == r["allocation_base"]]
        alloc_size = sum(x["size"] for x in alloc_regions)
        image = dump.read(r["allocation_base"], min(alloc_size, MAX_ARTIFACT_BYTES))
        is_dotnet = b"BSJB" in image[:min(len(image), 4 * 1024 * 1024)]
        kind = "reflective_dotnet" if is_dotnet else "reflective_pe"
        findings.append(me.MemoryFinding(
            source="exit-capture", kind=kind, process=process,
            detail=f"PE image in {TYPE_NAMES.get(r['type'], 'non-image')} memory at "
                   f"{r['allocation_base']:#x} ({alloc_size // 1024} KB"
                   + (", .NET metadata" if is_dotnet else "") + ")",
            address=hex(r["allocation_base"]),
            identity=(alloc_size, info["machine"]),
        ))
        artifacts.append({
            "kind": "reflective_dotnet" if is_dotnet else "reflective_pe",
            "base": r["allocation_base"], "data": realign_image(image),
            "ext": "dll",
        })

    # 3. Image allocations the loader does not know about
    image_allocs = {}
    for r in committed:
        if r["type"] == MEM_IMAGE:
            image_allocs.setdefault(r["allocation_base"], 0)
            image_allocs[r["allocation_base"]] += r["size"]
    for base, size in image_allocs.items():
        if base in module_bases:
            continue
        head = dump.read(base, 0x1000)
        if not _pe_info(head):
            continue
        findings.append(me.MemoryFinding(
            source="exit-capture", kind="hidden_module", process=process,
            detail=f"Mapped image at {base:#x} ({size // 1024} KB) is not in the module list",
            address=hex(base),
            identity=(size,),
        ))
        artifacts.append({
            "kind": "hidden_module", "base": base,
            "data": realign_image(dump.read(base, min(size, MAX_ARTIFACT_BYTES))),
            "ext": "dll",
        })

    # 4. Private executable memory without a PE header. Each region is
    # classified first, so host artifacts (emulator cache and stubs) are
    # recorded as such instead of being scored as injected code.
    host_regions = []
    for r in private_exec:
        if r["allocation_base"] in seen_alloc:
            continue
        buf = dump.read_region(r, MAX_ARTIFACT_BYTES)
        cls, why = classify_private_exec(r, buf, emulated)
        if cls != "code":
            host_regions.append({
                "base": hex(r["base"]), "size": r["size"],
                "protect": hex(r["protect"]), "class": cls, "reason": why,
            })
            continue
        rwx = bool(r["protect"] & PAGE_EXECUTE_READWRITE)
        findings.append(me.MemoryFinding(
            source="exit-capture", kind="private_rwx", process=process,
            detail=f"Private {'RWX' if rwx else 'executable'} region at {r['base']:#x} "
                   f"({r['size'] // 1024} KB, protect {r['protect']:#x})",
            address=hex(r["base"]),
            identity=(r["size"], r["protect"]),
        ))
        artifacts.append({
            "kind": "codechunk", "base": r["base"], "data": buf, "ext": "bin",
        })

    # 5. String rules over non-image memory
    rules = load_rules(rules_dir)
    sig_hits = {}
    scanned = 0
    prefilter = None
    if rules:
        import re
        needles = {n for rule in rules for n in (rule["ascii"], rule["utf16"]) if n}
        prefilter = re.compile(b"|".join(re.escape(n) for n in needles))
    if rules:
        for r in committed:
            if r["type"] == MEM_IMAGE:
                # Legitimate DLLs are full of API names; scanning them only
                # reproduces the noise the rules are meant to avoid.
                continue
            if scanned >= MAX_SIGNATURE_SCAN_BYTES:
                notes.append("Signature scan stopped at the size limit")
                break
            buf = dump.read_region(r, MAX_SIGNATURE_SCAN_BYTES - scanned)
            scanned += len(buf)
            if not buf:
                continue
            # One regex pass tells whether any needle occurs at all; most
            # regions have none and skip the per-rule search entirely. The
            # exact search below still runs where it matters, because the
            # alternation would hide a short needle inside a longer match.
            if prefilter is not None and prefilter.search(buf) is None:
                continue
            for rule in rules:
                for enc, needle in (("ascii", rule["ascii"]), ("utf16le", rule["utf16"])):
                    if not needle:
                        continue
                    pos = buf.find(needle)
                    if pos < 0:
                        continue
                    key = (rule["category"], rule["pattern"])
                    if key not in sig_hits or rule["risk"] > sig_hits[key]["rule"]["risk"]:
                        sig_hits[key] = {
                            "rule": rule, "encoding": enc,
                            "address": r["base"] + pos, "region_type": r["type"],
                        }
    for (category, pattern), hit in sig_hits.items():
        risk = hit["rule"]["risk"]
        findings.append(me.MemoryFinding(
            source="exit-capture", kind="memory_signature", process=process,
            detail=f"{category}: {pattern}"
                   + (f" - {hit['rule']['description']}" if hit["rule"]["description"] else ""),
            address=hex(hit["address"]),
            identity=(category, pattern),
            weight=me.SIGNATURE_RISK_WEIGHTS.get(risk, 0.2),
            extra={
                "category": category, "pattern": pattern, "risk_score": risk,
                "encoding": hit["encoding"],
                "needs_corroboration": risk < 8,
            },
        ))

    # 6. The main image as it looked in memory at exit. For packed samples this
    # is the unpacked payload, which is what static analysis actually wants.
    main = dump.modules[0] if dump.modules else None
    if main:
        artifacts.insert(0, {
            "kind": "main_image", "base": main["base"],
            "data": realign_image(dump.read(main["base"], min(main["size"], MAX_ARTIFACT_BYTES))),
            "ext": "exe" if main["name"].lower().endswith(".exe") else "dll",
            "name": main["name"],
        })

    written = _write_artifacts(artifacts, extract_dir, process)

    return {
        "tool": "Exit Capture",
        "dump_path": path,
        "dump_size": len(dump.data),
        "process": process,
        "host_arch": dump.arch,
        "emulated": emulated,
        "modules": len(dump.modules),
        "regions": len(dump.regions),
        "threads": len(dump.threads),
        "captured_bytes": dump.captured_bytes,
        "private_exec_regions": len(private_exec),
        # Private executable regions explained by the host, not by the sample.
        "host_regions": host_regions,
        "signature_rules": len(rules),
        "signature_bytes_scanned": scanned,
        "artifacts": written,
        "notes": notes,
        "evidence_findings": findings,
        # A readable dump is a successful observation even with zero findings.
        "observed": bool(dump.regions and dump.captured_bytes),
    }


def _write_artifacts(artifacts, extract_dir, process):
    if not extract_dir:
        return []
    try:
        os.makedirs(extract_dir, exist_ok=True)
    except OSError:
        return []
    import hashlib
    stem = (process or "process").replace("\\", "_").replace("/", "_")
    out = []
    for a in artifacts[:MAX_ARTIFACTS]:
        data = a.get("data") or b""
        if len(data) < 64:
            continue
        name = f"{stem}_{a['kind']}_{a['base']:x}.{a['ext']}"
        full = os.path.join(extract_dir, name)
        try:
            with open(full, "wb") as f:
                f.write(data)
        except OSError:
            continue
        out.append({
            "kind": a["kind"],
            "filename": name,
            "path": full,
            "base_address": hex(a["base"]),
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "is_pe": data[:2] == b"MZ",
        })
    return out
