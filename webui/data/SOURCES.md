# Offline geo data

Used by `webui/geoip.py`; the chamber never asks an online service about an address.

- `ip2asn-v4.idx`, `ip2asn-v6.idx`, `asn-names.tsv.gz`: built on 2026-11-16 by `make geoip` (`scripts/fetch-geoip.py`) from the IPtoASN tables https://iptoasn.com/data/ip2asn-v4.tsv.gz (540291 ranges) and ip2asn-v6.tsv.gz (178858 ranges), which combine RIR and routing data. Licence of the source: CC0 (public domain). The upstream tables are not kept; the record layout is described in the docstring of `webui/geoip.py`. Each refresh adds a new blob of a few MB to git history, so refresh rarely.
- `countries.tsv`: written by hand, one centroid per ISO 3166-1 alpha-2 code (plus XK, which the registries use for Kosovo). Not fetched.
