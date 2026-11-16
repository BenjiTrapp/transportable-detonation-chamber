#!/usr/bin/env python3
"""Refresh the offline IP-to-country/ASN index in webui/data (needs internet, run by `make geoip`).

Downloads the IPv4 and IPv6 tables of iptoasn.com (public domain, CC0) into a
temporary directory, turns them into the compact index that webui/geoip.py reads
(ip2asn-v4.idx, ip2asn-v6.idx, asn-names.tsv.gz; the layout is in the docstring of
webui/geoip.py) and writes them to webui/data together with SOURCES.md. The
downloaded tables are deleted again: only the index is committed.

Every refresh changes the index files completely, so each one adds a new few-MB
blob to git history. Refresh rarely.

An index file is replaced only when both tables downloaded completely and read
as gzip files with at least one usable row; an interrupted download changes nothing.

countries.tsv (country centroids) is written by hand and is not touched here.

Usage:
  python3 scripts/fetch-geoip.py
"""
import gzip
import os
import sys
import tempfile
import urllib.request
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "webui"))

import geoip  # noqa: E402

DATA_DIR = geoip.DATA_DIR
BASE_URL = "https://iptoasn.com/data/"
TABLES = (geoip.SOURCE_V4, geoip.SOURCE_V6)
TIMEOUT = 120


def download(name, directory):
    """Save one table into ``directory``; raises when the transfer is cut short or the table is unusable."""
    # the server answers 403 to urllib's default User-Agent
    request = urllib.request.Request(BASE_URL + name, headers={"User-Agent": "tdc-fetch-geoip/1.0"})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        blob = response.read()
        expected = response.headers.get("Content-Length")
    if expected is not None and int(expected) != len(blob):
        raise ValueError(f"{name}: got {len(blob)} of {expected} bytes")
    path = os.path.join(directory, name)
    with open(path, "wb") as f:
        f.write(blob)
    rows = 0
    with gzip.open(path, "rt", encoding="utf-8") as f:
        for line in f:
            if line.count("\t") >= 4:
                rows += 1
    if rows == 0:
        raise ValueError(f"{name} has no usable row")
    return rows, len(blob)


def main():
    counts = {}
    with tempfile.TemporaryDirectory(prefix="tdc-geoip-") as tmp:
        for name in TABLES:
            print(f"fetching {BASE_URL}{name}")
            counts[name], size = download(name, tmp)
            print(f"  {counts[name]} ranges, {size} bytes")
        geoip.build_index(tmp, DATA_DIR)
    sizes = {name: os.path.getsize(os.path.join(DATA_DIR, name))
             for name in (geoip.INDEX_V4, geoip.INDEX_V6, geoip.NAMES_FILE)}
    for name, size in sizes.items():
        print(f"  wrote {name}: {size} bytes")
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    with open(os.path.join(DATA_DIR, "SOURCES.md"), "w", encoding="utf-8") as f:
        f.write(
            "# Offline geo data\n\n"
            "Used by `webui/geoip.py`; the chamber never asks an online service about an address.\n\n"
            f"- `ip2asn-v4.idx`, `ip2asn-v6.idx`, `asn-names.tsv.gz`: built on {today} by `make geoip` "
            f"(`scripts/fetch-geoip.py`) from the IPtoASN tables {BASE_URL}ip2asn-v4.tsv.gz "
            f"({counts[TABLES[0]]} ranges) and ip2asn-v6.tsv.gz ({counts[TABLES[1]]} ranges), which "
            "combine RIR and routing data. Licence of the source: CC0 (public domain). The upstream "
            "tables are not kept; the record layout is described in the docstring of `webui/geoip.py`. "
            "Each refresh adds a new blob of a few MB to git history, so refresh rarely.\n"
            "- `countries.tsv`: written by hand, one centroid per ISO 3166-1 alpha-2 code "
            "(plus XK, which the registries use for Kosovo). Not fetched.\n"
        )
    print("done")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, EOFError) as exc:
        print(f"fetch-geoip failed: {exc}", file=sys.stderr)
        sys.exit(1)
