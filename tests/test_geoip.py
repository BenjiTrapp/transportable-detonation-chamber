"""Offline IP to country and ASN lookup (webui/geoip.py).

Runs against the few ranges under tests/samples/geoip/ (in the upstream table
format, built into an index in tmp_path), never against the committed index in
webui/data and never against the network.
"""

import gzip
import os
import runpy
import struct
import sys
import zlib

import pytest

import geoip

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "samples", "geoip")


@pytest.fixture(autouse=True)
def reset_geoip_state(tmp_path):
    """No test leaves the module pointing at its own tmp_path index."""
    yield
    geoip.load(str(tmp_path / "nothing"))


@pytest.fixture
def geo(tmp_path):
    geoip.build_index(str(FIXTURE_DIR), str(tmp_path))
    copy_countries(str(tmp_path))
    geoip.load(str(tmp_path))
    return geoip


def open_files():
    """The number of open file descriptors of this process (None where there is no /dev/fd)."""
    try:
        return len(os.listdir("/dev/fd"))
    except OSError:
        return None


def copy_countries(directory):
    with open(os.path.join(FIXTURE_DIR, "countries.tsv"), encoding="utf-8") as src, \
            open(os.path.join(directory, "countries.tsv"), "w", encoding="utf-8") as dst:
        dst.write(src.read())


def write_tables(directory, v4_rows, v6_rows=()):
    """Upstream tables with the given rows in ``directory``."""
    os.makedirs(directory, exist_ok=True)
    for name, rows in (("ip2asn-v4.tsv.gz", v4_rows), ("ip2asn-v6.tsv.gz", v6_rows)):
        with gzip.open(os.path.join(directory, name), "wt", encoding="utf-8") as f:
            f.write("".join("\t".join(row) + "\n" for row in rows))


def load_rows(tmp_path, v4_rows, v6_rows=()):
    """Build an index of the rows and load it, with the fixture's countries."""
    write_tables(str(tmp_path / "src"), v4_rows, v6_rows)
    geoip.build_index(str(tmp_path / "src"), str(tmp_path / "data"))
    copy_countries(str(tmp_path / "data"))
    geoip.load(str(tmp_path / "data"))
    return geoip


def test_scope_separates_local_from_public():
    for ip in ("10.0.0.5", "192.168.64.4", "172.17.251.7", "127.0.0.1", "::1",
               "169.254.1.1", "100.64.0.1", "224.0.0.1", "fe80::1"):
        assert geoip.scope_of(ip) == "local"
    assert geoip.scope_of("185.244.25.17") == "public"
    for bad in ("", "x", "1.2.3", "999.1.1.1", "185.244.25.17:443"):
        assert geoip.scope_of(bad) == "invalid"


def test_scope_edges_of_the_private_ranges():
    assert geoip.scope_of("172.15.255.255") == "public"
    assert geoip.scope_of("172.16.0.0") == "local"
    assert geoip.scope_of("172.31.255.255") == "local"
    assert geoip.scope_of("172.32.0.0") == "public"
    assert geoip.scope_of("100.63.255.255") == "public"
    assert geoip.scope_of("100.127.255.255") == "local"
    assert geoip.scope_of("100.128.0.0") == "public"
    assert geoip.scope_of("0.0.0.0") == "local"
    assert geoip.scope_of("255.255.255.255") == "local"
    assert geoip.scope_of("fd00::1") == "local"
    assert geoip.scope_of("::ffff:10.0.0.5") == "local"
    assert geoip.scope_of("::ffff:8.8.8.8") == "public"
    assert geoip.scope_of(None) == "invalid"


def test_lookup_resolves_country_and_asn(geo):
    g = geo.lookup("185.244.25.17")
    assert (g.cc, g.asn) == ("RU", 200557)
    assert g.as_org and g.scope == "public"
    assert g.country == "Russia"
    assert -90 <= g.lat <= 90 and -180 <= g.lon <= 180


def test_lookup_returns_none_outside_every_range(geo):
    assert geo.lookup("203.0.113.9") is None        # in no range of the fixture
    assert geo.lookup("10.0.0.5") is None           # local, never looked up
    assert geo.lookup("nonsense") is None


def test_lookup_handles_ipv6(geo):
    assert geo.lookup("2001:db8::1").cc == "DE"


def test_lookup_finds_the_first_and_last_address_of_a_range(geo):
    assert geo.lookup("185.244.24.0").asn == 200557
    assert geo.lookup("185.244.27.255").asn == 200557
    assert geo.lookup("185.244.23.255") is None
    assert geo.lookup("185.244.28.0") is None
    assert geo.lookup("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff").asn == 64496
    assert geo.lookup("2001:db9::") is None
    assert geo.lookup("2001:db7:ffff:ffff:ffff:ffff:ffff:ffff") is None


def test_lookup_picks_the_right_range_among_neighbours(geo):
    assert geo.lookup("1.0.0.1").asn == 13335
    assert geo.lookup("8.8.8.8").asn == 15169
    assert geo.lookup("81.2.69.160").cc == "GB"
    assert geo.lookup("2a00:1450:4001::1").cc == "IE"


def test_lookup_does_not_resolve_unrouted_ranges(geo):
    assert geo.lookup("1.0.2.1") is None            # AS 0 "Not routed"
    assert geo.lookup("198.51.100.7") is None


def test_lookup_maps_an_ipv4_mapped_address_to_its_ipv4(geo):
    assert geo.lookup("::ffff:185.244.25.17").cc == "RU"


def test_missing_data_is_not_an_error(tmp_path):
    geoip.load(str(tmp_path))
    assert geoip.available() is False
    assert geoip.lookup("185.244.25.17") is None


def test_an_empty_table_is_not_available(tmp_path):
    load_rows(tmp_path, [])
    assert geoip.available() is False
    assert geoip.lookup("8.8.8.8") is None


def test_available_after_loading_the_fixture(geo):
    assert geo.available() is True


def test_a_truncated_table_is_an_error_at_build_time_and_writes_nothing(tmp_path):
    src = tmp_path / "src"
    write_tables(str(src), [(f"20.{i // 256}.{i % 256}.0", f"20.{i // 256}.{i % 256}.255",
                             str(1000 + i), "US", f"AS-{i}") for i in range(2000)])
    path = src / "ip2asn-v4.tsv.gz"
    path.write_bytes(path.read_bytes()[:-40])
    with pytest.raises(EOFError):
        geoip.build_index(str(src), str(tmp_path / "out"))
    assert not (tmp_path / "out").exists()


def test_a_missing_table_is_an_error_at_build_time(tmp_path):
    with pytest.raises(OSError):
        geoip.build_index(str(tmp_path / "nothing"), str(tmp_path / "out"))


def test_an_index_that_is_not_a_whole_number_of_records_is_unavailable(tmp_path):
    geoip.build_index(str(FIXTURE_DIR), str(tmp_path))
    path = tmp_path / "ip2asn-v4.idx"
    path.write_bytes(path.read_bytes()[:-3])
    geoip.load(str(tmp_path))
    assert geoip.available() is False
    assert geoip.lookup("8.8.8.8") is None


def test_only_one_family_present_still_resolves_that_family(tmp_path):
    geoip.build_index(str(FIXTURE_DIR), str(tmp_path))
    os.unlink(tmp_path / "ip2asn-v6.idx")
    copy_countries(str(tmp_path))
    geoip.load(str(tmp_path))
    assert geoip.available() is True
    assert geoip.lookup("8.8.8.8").asn == 15169
    assert geoip.lookup("2001:db8::1") is None


def test_a_countries_file_that_is_not_utf8_does_not_raise_or_leak(tmp_path):
    geoip.build_index(str(FIXTURE_DIR), str(tmp_path))
    with open(os.path.join(FIXTURE_DIR, "countries.tsv"), "rb") as f:
        text = f.read()
    (tmp_path / "countries.tsv").write_bytes(text + b"\xff\xfe\tbroken\t1\t2\tX\n")
    before = open_files()
    geoip.load(str(tmp_path))
    assert geoip.available() is True
    assert geoip.lookup("185.244.25.17").country == "Russia"      # the rows before the bad bytes survive
    geoip.load(str(tmp_path / "nothing"))
    assert open_files() == before


def test_a_failed_load_closes_the_files_it_opened(tmp_path):
    geoip.build_index(str(FIXTURE_DIR), str(tmp_path))
    (tmp_path / "ip2asn-v6.idx").write_bytes(b"\0" * 5)           # not a whole number of records
    before = open_files()
    geoip.load(str(tmp_path))
    assert geoip.available() is False
    assert open_files() == before


def test_a_failing_mmap_closes_the_index_file(tmp_path, monkeypatch):
    geoip.build_index(str(FIXTURE_DIR), str(tmp_path))

    def refuse(*args, **kwargs):
        raise OSError("cannot map")

    monkeypatch.setattr(geoip.mmap, "mmap", refuse)
    before = open_files()
    with pytest.raises(OSError):
        geoip._Index(str(tmp_path / "ip2asn-v4.idx"), geoip.RECORD_V4, geoip.KEY_V4)
    assert open_files() == before
    geoip.load(str(tmp_path))                                      # load degrades instead of raising
    assert geoip.available() is False
    assert open_files() == before


@pytest.mark.parametrize("damage", ("garbage", "truncated"))
def test_a_damaged_names_file_leaves_the_asn_without_a_name(tmp_path, damage):
    geoip.build_index(str(FIXTURE_DIR), str(tmp_path))
    copy_countries(str(tmp_path))
    path = tmp_path / "asn-names.tsv.gz"
    if damage == "garbage":
        # a valid gzip header, then a deflate stream that zlib rejects
        path.write_bytes(b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff" + b"\xff" * 50)
        with pytest.raises(zlib.error):
            gzip.decompress(path.read_bytes())
    else:
        path.write_bytes(path.read_bytes()[:-20])
    geoip.load(str(tmp_path))
    g = geoip.lookup("185.244.25.17")
    assert (g.cc, g.asn, g.as_org) == ("RU", 200557, "")


def test_the_fetch_script_reports_a_damaged_download_instead_of_a_traceback(monkeypatch, capsys):
    class Response:
        headers = {}

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff" + b"\xff" * 50

    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: Response())
    script = os.path.join(os.path.dirname(__file__), "..", "scripts", "fetch-geoip.py")
    monkeypatch.setattr(sys, "path", list(sys.path))
    with pytest.raises(SystemExit) as stop:
        runpy.run_path(script, run_name="__main__")
    assert stop.value.code == 1
    assert "fetch-geoip failed" in capsys.readouterr().err


def test_malformed_lines_are_skipped(tmp_path):
    g = load_rows(tmp_path, [("8.8.8.0", "8.8.8.255", "15169", "US", "GOOGLE"),
                             ("not-an-ip", "8.8.9.255", "1", "US", "X"),
                             ("8.8.9.0", "8.8.9.255", "abc", "US", "X"),
                             ("8.8.10.0", "8.8.10.255"),
                             ("1.0.0.0", "1.0.0.255", "13335", "US", "CLOUDFLARENET")])
    assert g.lookup("8.8.8.8").asn == 15169
    assert g.lookup("1.0.0.1").asn == 13335
    assert g.lookup("8.8.9.1") is None
    assert g.lookup("8.8.10.1") is None


def test_a_country_without_a_centroid_still_resolves_its_asn(geo):
    g = geo.lookup("193.0.0.9")                      # NL is not in the fixture's countries.tsv
    assert g is not None
    assert (g.cc, g.asn, g.scope) == ("NL", 3333, "public")
    assert "RIPE" in g.as_org
    assert g.lat is None and g.lon is None and g.country is None


def test_a_range_without_a_country_still_resolves_its_asn(geo):
    g = geo.lookup("194.0.0.9")                      # the registry data says "Unknown"
    assert (g.cc, g.asn) == (None, 64500)
    assert g.lat is None and g.lon is None and g.country is None
    assert "NOCOUNTRY" in g.as_org


def test_rows_may_come_in_any_order(tmp_path):
    g = load_rows(tmp_path, [("8.8.8.0", "8.8.8.255", "15169", "US", "GOOGLE"),
                             ("1.0.0.0", "1.0.0.255", "13335", "US", "CLOUDFLARENET")])
    assert g.lookup("1.0.0.1").asn == 13335
    assert g.lookup("8.8.8.8").asn == 15169


def test_the_index_layout_is_pinned(tmp_path):
    """The committed index files are read by whatever version of geoip.py ships with them."""
    geoip.build_index(str(FIXTURE_DIR), str(tmp_path))
    v4 = (tmp_path / "ip2asn-v4.idx").read_bytes()
    v6 = (tmp_path / "ip2asn-v6.idx").read_bytes()
    # 1.0.0.0-1.0.0.255 AS13335 US, then 8.8.8.0-8.8.8.255 AS15169 US ...
    assert v4[:14] == struct.pack(">IIIH", 0x01000000, 0x010000FF, 13335, 0x5553)
    assert v4[14:28] == struct.pack(">IIIH", 0x08080800, 0x080808FF, 15169, 0x5553)
    assert len(v4) == 6 * 14                         # 6 routed ranges; the 2 "Not routed" ones are left out
    # IPv6 on the upper 64 bits: 2001:db8::/32 is 2001:0db8:0000:0000 - 2001:0db8:ffff:ffff
    assert v6[:22] == struct.pack(">QQIH", 0x20010DB800000000, 0x20010DB8FFFFFFFF, 64496, 0x4445)
    assert len(v6) == 2 * 22
    names = gzip.decompress((tmp_path / "asn-names.tsv.gz").read_bytes()).decode("utf-8").splitlines()
    assert "13335\tCLOUDFLARENET - Cloudflare, Inc." in names
    assert names == sorted(names, key=lambda line: int(line.split("\t")[0]))


def test_the_build_is_reproducible(tmp_path):
    geoip.build_index(str(FIXTURE_DIR), str(tmp_path / "a"))
    geoip.build_index(str(FIXTURE_DIR), str(tmp_path / "b"))
    for name in ("ip2asn-v4.idx", "ip2asn-v6.idx", "asn-names.tsv.gz"):
        assert (tmp_path / "a" / name).read_bytes() == (tmp_path / "b" / name).read_bytes()


def test_neighbouring_ranges_of_one_as_are_merged(tmp_path):
    g = load_rows(tmp_path, [("8.8.8.0", "8.8.8.255", "15169", "US", "GOOGLE"),
                             ("8.8.9.0", "8.8.9.255", "15169", "US", "GOOGLE"),
                             ("8.8.10.0", "8.8.10.255", "15169", "DE", "GOOGLE"),
                             ("8.8.12.0", "8.8.12.255", "15169", "DE", "GOOGLE")])
    assert os.path.getsize(tmp_path / "data" / "ip2asn-v4.idx") == 3 * 14
    assert g.lookup("8.8.8.0").cc == g.lookup("8.8.9.255").cc == "US"
    assert g.lookup("8.8.10.0").cc == "DE"
    assert g.lookup("8.8.11.0") is None              # the gap stays a gap


def test_ipv6_is_cut_to_the_upper_64_bits_and_partial_edges_are_dropped(tmp_path):
    g = load_rows(tmp_path, [], [
        ("2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", "64496", "DE", "WHOLE"),
        ("2a00:1::", "2a00:1::ffff", "1", "DE", "TINY"),                            # inside one /64
        ("2a00:2::5", "2a00:2:0:2:ffff:ffff:ffff:ffff", "2", "DE", "RAGGED"),       # first /64 is partial
    ])
    assert g.lookup("2001:db8:0:0:1::1").asn == 64496
    assert g.lookup("2a00:1::1") is None
    assert g.lookup("2a00:2::5") is None                                            # the partial /64
    assert g.lookup("2a00:2:0:1::5").asn == 2
    assert g.lookup("2a00:2:0:2:ffff:ffff:ffff:ffff").asn == 2


def test_jitter_is_stable_and_small(geo):
    a = geo.jitter("185.244.25.17", 55.0, 37.0)
    assert a == geo.jitter("185.244.25.17", 55.0, 37.0)
    assert a != geo.jitter("185.244.25.18", 55.0, 37.0)
    assert abs(a[0] - 55.0) <= 2 and abs(a[1] - 37.0) <= 2


def test_jitter_stays_on_the_map_near_the_edges():
    for i in range(200):
        lat, lon = geoip.jitter(f"185.244.25.{i}", 89.5, 179.5)
        assert -90 <= lat <= 90 and -180 <= lon <= 180
        lat, lon = geoip.jitter(f"185.244.26.{i}", -89.5, -179.5)
        assert -90 <= lat <= 90 and -180 <= lon <= 180


def test_load_maps_a_copy_and_never_holds_the_committed_index_open(tmp_path, geoip_cache):
    """Windows refuses to overwrite a mapped file. With the committed index mapped, a deploy could not replace it
    while the web UI ran; so load maps a copy in CACHE_DIR and leaves the source closed."""
    geoip.build_index(str(FIXTURE_DIR), str(tmp_path / "data"))
    copy_countries(str(tmp_path / "data"))
    geoip.load(str(tmp_path / "data"))
    assert geoip.lookup("8.8.8.8").asn == 15169
    copies = sorted(os.listdir(geoip_cache))
    assert [c.split("-")[1] for c in copies] == ["v4", "v6"] and all(c.endswith(".idx") for c in copies)
    mapped = [geoip._state.v4._file.name, geoip._state.v6._file.name]
    assert all(os.path.dirname(m) == str(geoip_cache) for m in mapped), mapped
    # the source can be replaced (as a deploy does) and the next load answers from the new one
    write_tables(str(tmp_path / "src"), [("8.8.8.0", "8.8.8.255", "64500", "NL", "EXAMPLE-AS")])
    geoip.build_index(str(tmp_path / "src"), str(tmp_path / "data"))
    geoip.load(str(tmp_path / "data"))
    assert geoip.lookup("8.8.8.8").asn == 64500
    assert len([c for c in os.listdir(geoip_cache) if c.startswith("ip2asn-v4-")]) == 1   # the old copy is gone


def test_a_changed_source_of_the_same_size_is_not_answered_from_a_stale_copy(tmp_path, geoip_cache):
    geoip.build_index(str(FIXTURE_DIR), str(tmp_path))
    geoip.load(str(tmp_path))
    assert geoip.lookup("8.8.8.8").asn == 15169
    path = tmp_path / "ip2asn-v4.idx"
    data = bytearray(path.read_bytes())
    for i in range(0, len(data), geoip.RECORD_V4.size):            # same size, other AS numbers
        start, end, _asn, word = geoip.RECORD_V4.unpack_from(data, i)
        geoip.RECORD_V4.pack_into(data, i, start, end, 64511, word)
    path.write_bytes(bytes(data))
    stat = os.stat(path)
    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000_000))
    geoip.load(str(tmp_path))
    assert geoip.lookup("8.8.8.8").asn == 64511


def test_a_copy_that_cannot_be_made_leaves_no_geo_data_instead_of_raising(tmp_path, monkeypatch):
    geoip.build_index(str(FIXTURE_DIR), str(tmp_path))
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("x")
    monkeypatch.setattr(geoip, "CACHE_DIR", str(blocker / "cache"))
    before = open_files()
    geoip.load(str(tmp_path))
    assert geoip.available() is False and geoip.lookup("8.8.8.8") is None
    assert open_files() == before
