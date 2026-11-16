"""Offline IP to country and autonomous system lookup for the FIREWALL tab.

The chamber must never ask an online service about an address a sample just
contacted, so the answer comes from files that ship with the program in
``webui/data``. They are produced by ``make geoip`` (``scripts/fetch-geoip.py``,
which downloads the public IPtoASN tables and calls ``build_index``) and
committed::

    ip2asn-v4.idx    fixed-length records, sorted by start address, big-endian: ">IIIH"
                     start (u32), end (u32), AS number (u32), country (u16)
    ip2asn-v6.idx    the same for IPv6, on the upper 64 bits of an address: ">QQIH"
                     start (u64), end (u64), AS number (u32), country (u16)
    asn-names.tsv.gz "AS number<TAB>description" lines, gzipped
    countries.tsv    cc, name, lat, lon, region: one centroid per country, written by hand

The country is its two ASCII letters as one 16-bit number (``"RU"`` is
``0x5255``); ``0`` means that the registry data names none. Start and end are
both inclusive and ranges do not overlap. A routed range only: the "Not routed"
rows (AS 0) are left out, and neighbouring ranges of the same AS and country are
merged, which changes no answer.

The IPv6 records use the upper 64 bits because a routed prefix is shorter than
a /64 and only its first and last /64 matter. The few ranges that are smaller
than a /64, and the partial /64 at the edge of a range, share their /64 with
another AS and cannot be told apart at this resolution, so they are left out:
an address in one of them gets no answer (0.2 % of the ranges of 2026-11).

``load`` maps the two index files with ``mmap`` and ``lookup`` bisects over them,
so a lookup reads a few pages and the tables are not held in memory. There is no
build step at start-up and nothing is written at run time. The AS names are read
from their file on the first hit.

``lookup(ip)`` returns a ``GeoInfo`` for a public address in a routed range and
``None`` when nothing is known about the address: a local address, a string that
is not an address, an address in no range, or no data at all (a missing file is
not an error). A known AS is never hidden: ``cc`` is None when the data names no
country, and ``country``, ``lat`` and ``lon`` are None when there is no centroid
for it. This module knows nothing about the UI; whoever draws the "unknown" case
builds it from ``scope_of`` and the ``None`` it got here.

Standard library only.
"""

from __future__ import annotations

import bisect
import gzip
import hashlib
import ipaddress
import logging
import math
import mmap
import os
import struct
import tempfile
import threading
import zlib
from collections import namedtuple

logger = logging.getLogger(__name__)

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

SOURCE_V4 = "ip2asn-v4.tsv.gz"      # the upstream tables, read by build_index only
SOURCE_V6 = "ip2asn-v6.tsv.gz"
COUNTRIES_FILE = "countries.tsv"
INDEX_V4 = "ip2asn-v4.idx"
INDEX_V6 = "ip2asn-v6.idx"
NAMES_FILE = "asn-names.tsv.gz"

RECORD_V4 = struct.Struct(">IIIH")
RECORD_V6 = struct.Struct(">QQIH")
KEY_V4 = struct.Struct(">I")
KEY_V6 = struct.Struct(">Q")

JITTER_MAX_DEGREES = 2.0

GeoInfo = namedtuple("GeoInfo", "cc country lat lon asn as_org scope")

_LOCAL_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16",   # this host, RFC 1918, CGNAT
    "fc00::/7",                                                                       # unique local
))
_LOW_64_BITS = (1 << 64) - 1


# ---- address scope -----------------------------------------------------------------------


def _parse(ip):
    """The address as ``ipaddress`` object (an IPv4-mapped IPv6 address as its IPv4), or None."""
    if not isinstance(ip, str):
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.version == 6 and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def scope_of(ip):
    """``"public"``, ``"local"`` (private, loopback, link-local, CGNAT, multicast, reserved) or ``"invalid"``."""
    addr = _parse(ip)
    if addr is None:
        return "invalid"
    if (addr.is_loopback or addr.is_link_local or addr.is_multicast
            or addr.is_unspecified or addr.is_reserved):
        return "local"
    # is_private is not used: it also covers the documentation ranges (2001:db8::/32,
    # 192.0.2.0/24 ...), which are not local and are what the tests resolve
    if any(addr in net for net in _LOCAL_NETWORKS):
        return "local"
    return "public"


# ---- index build (make geoip, tests; not used at run time) --------------------------------


def _country_word(cc):
    """The two ASCII letters of a country code as one 16-bit number; 0 when there are none."""
    if len(cc) != 2 or not cc.isascii() or not cc.isalpha():
        return 0
    cc = cc.upper()
    return (ord(cc[0]) << 8) | ord(cc[1])


def _read_ranges(path, address_class):
    """([(start, end, asn, country_word)] sorted and merged, {asn: description}) of an upstream table.

    Unusable lines and unrouted ranges (AS 0) are skipped. IPv6 bounds are cut to their upper
    64 bits and the /64 at an edge that the range does not fill is dropped (see the module
    docstring). Raises OSError or EOFError for an unreadable or truncated file.
    """
    version6 = address_class is ipaddress.IPv6Address
    rows = []
    names = {}
    with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
        for line in f:
            parts = line.rstrip("\r\n").split("\t", 4)
            if len(parts) < 5:
                continue
            try:
                start = int(address_class(parts[0].strip()))
                end = int(address_class(parts[1].strip()))
                asn = int(parts[2])
            except ValueError:
                continue
            if asn <= 0 or end < start:
                continue
            if version6:
                first = (start >> 64) + (1 if start & _LOW_64_BITS else 0)
                last = (end >> 64) - (0 if end & _LOW_64_BITS == _LOW_64_BITS else 1)
                if first > last:
                    continue
                start, end = first, last
            rows.append((start, end, asn, _country_word(parts[3].strip())))
            names.setdefault(asn, parts[4].strip())
    rows.sort()
    merged = []
    for start, end, asn, word in rows:
        if merged and merged[-1][1] + 1 == start and merged[-1][2:] == (asn, word):
            merged[-1] = (merged[-1][0], end, asn, word)
        else:
            merged.append((start, end, asn, word))
    return merged, names


def _atomic_write(path, data):
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=os.path.basename(path) + ".")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def build_index(tables_dir, out_dir):
    """Write the index files of the upstream tables in ``tables_dir`` into ``out_dir``; returns the IPv4 index path.

    Both tables are read to the end before anything is written, so a missing or truncated
    table (OSError, EOFError) leaves ``out_dir`` as it was. The output is reproducible.
    """
    v4_rows, v4_names = _read_ranges(os.path.join(tables_dir, SOURCE_V4), ipaddress.IPv4Address)
    v6_rows, v6_names = _read_ranges(os.path.join(tables_dir, SOURCE_V6), ipaddress.IPv6Address)
    names = {**v6_names, **v4_names}
    text = "".join(f"{asn}\t{names[asn]}\n" for asn in sorted(names))
    names_blob = gzip.compress(text.encode("utf-8"), 9, mtime=0)
    os.makedirs(out_dir, exist_ok=True)
    v4_path = os.path.join(out_dir, INDEX_V4)
    _atomic_write(v4_path, b"".join(RECORD_V4.pack(*row) for row in v4_rows))
    _atomic_write(os.path.join(out_dir, INDEX_V6), b"".join(RECORD_V6.pack(*row) for row in v6_rows))
    _atomic_write(os.path.join(out_dir, NAMES_FILE), names_blob)
    return v4_path


# ---- lookup ------------------------------------------------------------------------------


class _Index:
    """One family's records, read through ``mmap``; a sequence of start keys for ``bisect``."""

    def __init__(self, path, record, key):
        self._record = record
        self._key = key
        self._file = None
        self._map = None
        self._count = 0
        try:
            self._file = open(path, "rb")
        except FileNotFoundError:
            return
        size = os.fstat(self._file.fileno()).st_size
        if size % record.size:
            self._file.close()
            raise ValueError(f"{os.path.basename(path)}: {size} bytes is not a whole number of records")
        self._count = size // record.size
        if self._count:
            try:
                self._map = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ)
            except BaseException:
                self._file.close()
                raise

    def __len__(self):
        return self._count

    def __getitem__(self, i):
        return self._key.unpack_from(self._map, i * self._record.size)[0]

    def find(self, key):
        """(asn, country_word) of the range that holds ``key``, or None."""
        if not self._count:
            return None
        i = bisect.bisect_right(self, key) - 1
        if i < 0:
            return None
        _start, end, asn, word = self._record.unpack_from(self._map, i * self._record.size)
        return (asn, word) if key <= end else None

    def close(self):
        if self._map is not None:
            self._map.close()
            self._map = None
        if self._file is not None:
            self._file.close()
            self._file = None


class _State:
    def __init__(self, v4=None, v6=None, countries=None, names_path=None):
        self.v4 = v4
        self.v6 = v6
        self.countries = countries or {}
        self._names_path = names_path
        self._names = None
        self._names_lock = threading.Lock()

    @property
    def available(self):
        return any(index is not None and len(index) for index in (self.v4, self.v6))

    def as_org(self, asn):
        with self._names_lock:
            if self._names is None:
                self._names = {}
                try:
                    with gzip.open(self._names_path, "rt", encoding="utf-8", errors="replace") as f:
                        for line in f:
                            number, _, description = line.rstrip("\n").partition("\t")
                            if number.isdigit():
                                self._names[int(number)] = description
                except (OSError, EOFError, TypeError, zlib.error):
                    pass
        return self._names.get(asn, "")

    def close(self):
        for index in (self.v4, self.v6):
            if index is not None:
                index.close()


_state = _State()


def _read_countries(path):
    """{cc: (name, lat, lon)} of countries.tsv; comment lines and unusable rows are skipped."""
    countries = {}
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.startswith("#"):
                    continue
                parts = line.rstrip("\r\n").split("\t")
                if len(parts) < 4:
                    continue
                try:
                    countries[parts[0].strip().upper()] = (parts[1].strip(), float(parts[2]), float(parts[3]))
                except ValueError:
                    continue
    except (OSError, ValueError):
        pass
    return countries


def load(data_dir=DATA_DIR):
    """(Re)load the index files of ``data_dir``.

    Never raises: without index files, or with one that is not a whole number of
    records, ``available()`` is False. Meant for start-up and for tests, not to be
    called while another thread looks up.
    """
    global _state
    old, _state = _state, _State()
    old.close()
    if not any(os.path.exists(os.path.join(data_dir, n)) for n in (INDEX_V4, INDEX_V6)):
        logger.info("geoip: no index in %s, lookups are unavailable", data_dir)
        return
    v4 = v6 = None
    try:
        v4 = _Index(os.path.join(data_dir, INDEX_V4), RECORD_V4, KEY_V4)
        v6 = _Index(os.path.join(data_dir, INDEX_V6), RECORD_V6, KEY_V6)
        countries = _read_countries(os.path.join(data_dir, COUNTRIES_FILE))
    except (OSError, ValueError) as exc:
        logger.warning("geoip: cannot load the index of %s: %s", data_dir, exc)
        for index in (v4, v6):
            if index is not None:
                index.close()
        return
    _state = _State(v4, v6, countries, os.path.join(data_dir, NAMES_FILE))


def available():
    return _state.available


def lookup(ip):
    """The ``GeoInfo`` of a public address, or None when nothing is known about it (see the module docstring)."""
    if scope_of(ip) != "public":
        return None
    addr = _parse(ip)
    state = _state
    if addr.version == 4:
        found = state.v4.find(int(addr)) if state.v4 is not None else None
    else:
        found = state.v6.find(int(addr) >> 64) if state.v6 is not None else None
    if found is None:
        return None
    asn, word = found
    cc = chr(word >> 8) + chr(word & 0xFF) if word else None
    name, lat, lon = state.countries.get(cc, (None, None, None))
    return GeoInfo(cc, name, lat, lon, asn, state.as_org(asn), "public")


def jitter(ip, lat, lon):
    """A stable point within 2 degrees of (lat, lon) that depends only on ``ip``.

    Every address of a country has the same centroid; the spread keeps the dots of
    several connections apart on the map, and the same address always lands on the same spot.
    """
    digest = hashlib.blake2s(ip.encode("utf-8"), digest_size=8).digest()
    angle = int.from_bytes(digest[:4], "big") / 2 ** 32 * 2 * math.pi
    radius = math.sqrt(int.from_bytes(digest[4:], "big") / 2 ** 32) * JITTER_MAX_DEGREES
    new_lat = max(-90.0, min(90.0, lat + radius * math.sin(angle)))
    new_lon = (lon + radius * math.cos(angle) + 180.0) % 360.0 - 180.0
    return (new_lat, new_lon)
