"""Assessment of network connections for the FIREWALL tab (webui/firewall.py).

The module is pure: every test hands it Sysmon-shaped events and a Context and
looks at what comes out. The geo lookup is a small fake, so these tests never
touch geoip's module state or its data files.
"""

import json
import os
from datetime import datetime, timezone

import pytest

import firewall
import geoip

SAMPLE_PATH = os.path.join(os.path.dirname(__file__), "samples", "firewall", "sysmon_events.json")
with open(SAMPLE_PATH, encoding="utf-8") as f:
    SAMPLE_EVENTS = json.load(f)

T0 = datetime(2026, 11, 14, 10, 0, 0, tzinfo=timezone.utc).timestamp()   # the sample detonation starts here
IMAGE = r"C:\x\a.exe"
TDC_PYTHON = r"C:\DetonationChamberUI\venv\Scripts\python.exe"
GITHUB_IP = "140.82.121.3"

FAKE_GEO = {
    "1.2.3.4": geoip.GeoInfo("DE", "Germany", 51.0, 10.0, 24940, "Hetzner Online GmbH", "public"),
    "5.6.7.8": geoip.GeoInfo("NL", "Netherlands", 52.0, 5.0, 14061, "DigitalOcean", "public"),
    "9.9.9.9": geoip.GeoInfo(None, None, None, None, 19281, "Quad9", "public"),
}


def R(image, ip, port):
    return firewall.rule_key(image, ip, port)


@pytest.fixture(autouse=True)
def reset_geoip_state(tmp_path):
    """No test leaves geoip pointing at data of its own (the default-lookup test loads an empty table)."""
    yield
    geoip.load(str(tmp_path / "nothing"))


def fake_geo(ip):
    return FAKE_GEO.get(ip)


def iso(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat()


def conn(pid=4812, image=IMAGE, dst="1.2.3.4", dport=443, sport=51000, t=0, hostname="-",
         proto="tcp", src="10.0.2.15"):
    return {"timestamp": iso(t), "event_id": 3, "pid": str(pid), "image": image, "user": "WIN11\\analyst",
            "type": "NetworkConnect", "dst_ip": dst, "dst_port": str(dport), "dst_hostname": hostname,
            "protocol": proto, "src_ip": src, "src_port": str(sport)}


def fw(action="ALLOW", dst="1.2.3.4", dport=443, proto="TCP", src="10.0.2.15"):
    """A firewall event the way log_store.parse_firewall_log yields it."""
    return {"time": "2026-11-14T10:00:01Z", "source": "firewall", "message": "",
            "fields": {"action": action, "protocol": proto, "src_ip": src, "dst_ip": dst,
                       "src_port": 51000, "dst_port": dport, "path": "SEND"}}


def ctx_with(**kw):
    kw.setdefault("dns", {GITHUB_IP: "api.github.com"})
    kw.setdefault("geo_lookup", fake_geo)
    return firewall.Context(**kw)


def classify_one(event, ctx=None, fw_events=()):
    return firewall.classify([event], list(fw_events), ctx or ctx_with())[0]


# ---- the tags and their severities -----------------------------------------------------------


def test_the_fourteen_tags_and_their_severities():
    assert firewall.SEVERITIES == ("info", "low", "medium", "high", "critical")
    assert firewall.TAGS == {
        "ioc": "critical", "beacon": "critical",
        "sigma": "high", "detonated": "high", "direct-ip": "high", "download": "high", "tdc-anomaly": "high",
        "lolbin": "medium", "dga": "medium", "risky-tld": "medium", "dead-drop": "medium", "rare-port": "medium",
        "newborn": "low", "dropped": "info",
    }


def test_severity_is_the_highest_of_the_tags():
    assert firewall.severity_of(["newborn", "lolbin", "sigma"]) == "high"
    assert firewall.severity_of(["dropped"]) == "info"
    assert firewall.severity_of([]) == "info"
    assert firewall.severity_of(["no-such-tag", "newborn"]) == "low"


# ---- bundling --------------------------------------------------------------------------------


def test_bundle_merges_by_key_without_source_port():
    flows = firewall.bundle([conn(pid=4812, dst="1.2.3.4", dport=443, sport=51000, t=1),
                             conn(pid=4812, dst="1.2.3.4", dport=443, sport=51001, t=61)])
    assert len(flows) == 1
    assert flows[0]["count"] == 2
    assert flows[0]["first_seen"] < flows[0]["last_seen"]


def test_bundle_separates_process_endpoint_and_source_address():
    flows = firewall.bundle([conn(pid=1), conn(pid=2), conn(pid=1, dport=80), conn(pid=1, src="10.0.2.99"),
                             conn(pid=1, image=r"C:\x\b.exe")])
    assert len(flows) == 5


def test_bundle_normalises_what_sysmon_writes():
    flow = firewall.bundle([conn(pid="4812", dport="443", proto="TCP", hostname="Evil.Example.", t=5)])[0]
    assert flow["pid"] == 4812 and flow["dst_port"] == 443 and flow["protocol"] == "tcp"
    assert flow["dst_hostname"] == "evil.example"
    assert flow["first_seen"] == 5.0 and flow["last_seen"] == 5.0


def test_bundle_treats_dash_placeholders_as_absent():
    flow = firewall.bundle([conn(image="-", dst="-", hostname="-", src="-", dport="53", t=1)])[0]
    assert flow["image"] == "" and flow["dst_ip"] == "" and flow["src_ip"] == ""
    assert flow["dst_hostname"] is None


def test_bundle_keeps_a_hostname_seen_on_a_later_connection():
    flows = firewall.bundle([conn(t=1, hostname="-"), conn(t=2, hostname="late.example")])
    assert flows[0]["dst_hostname"] == "late.example"


def test_bundle_ignores_other_events_and_damaged_ones():
    other = dict(conn(t=1), event_id=22)
    broken = dict(conn(t=1), error="read failed")
    no_time = dict(conn(t=1), timestamp="")
    bad_time = dict(conn(t=1), timestamp="yesterday")
    assert firewall.bundle([other, broken, no_time, bad_time, "not an event", None]) == []
    assert firewall.bundle([]) == []


def test_bundle_tolerates_a_port_that_is_not_a_number():
    flow = firewall.bundle([conn(dport="-")])[0]
    assert flow["dst_port"] is None


def test_bundle_orders_connections_in_time_and_caps_them():
    events = [conn(t=t) for t in (300, 100, 200)]
    assert firewall.bundle(events)[0]["times"] == [100.0, 200.0, 300.0]
    many = firewall.bundle([conn(t=t) for t in range(firewall.MAX_TIMES + 50)])[0]
    assert many["count"] == firewall.MAX_TIMES + 50
    assert len(many["times"]) == firewall.MAX_TIMES
    assert many["times"][-1] == float(firewall.MAX_TIMES + 49)


def test_flow_key_is_the_documented_tuple():
    key = firewall.flow_key(conn(pid="4812", dport="443", proto="TCP", sport=1))
    assert key == (IMAGE, 4812, "tcp", "10.0.2.15", "1.2.3.4", 443)
    assert key == firewall.flow_key(conn(pid=4812, dport=443, proto="tcp", sport=2))


# ---- names -----------------------------------------------------------------------------------


def test_hostname_falls_back_to_the_dns_map():
    ctx = ctx_with(dns={"1.2.3.4": "evil.example"})
    flows = firewall.classify([conn(dst="1.2.3.4", hostname="-")], [], ctx)
    assert flows[0]["dst_hostname"] == "evil.example"


def test_the_hostname_sysmon_reports_wins_over_the_map():
    ctx = ctx_with(dns={"1.2.3.4": "evil.example"})
    flows = firewall.classify([conn(dst="1.2.3.4", hostname="reported.example")], [], ctx)
    assert flows[0]["dst_hostname"] == "reported.example"


def test_direct_ip_when_no_dns_resolved_there():
    flows = firewall.classify([conn(dst="1.2.3.4")], [], ctx_with(dns={}))
    assert "direct-ip" in flows[0]["tags"]


def test_direct_ip_needs_neither_the_map_nor_sysmons_hostname_to_explain_the_address():
    # Sysmon fills DestinationHostname from the local DNS cache: a populated field means a name was
    # involved, even when the answer predates the ring or fell outside the map
    named_by_sysmon = classify_one(conn(dst="1.2.3.4", hostname="cached.example"), ctx_with(dns={}))
    named_by_the_map = classify_one(conn(dst="1.2.3.4", hostname="-"), ctx_with(dns={"1.2.3.4": "x.example"}))
    unexplained = classify_one(conn(dst="1.2.3.4", hostname="-"), ctx_with(dns={}))
    assert "direct-ip" not in named_by_sysmon["tags"] and "direct-ip" not in named_by_the_map["tags"]
    assert "direct-ip" in unexplained["tags"]


def test_no_direct_ip_when_a_name_resolved_there_or_the_address_is_local():
    named = classify_one(conn(dst="1.2.3.4"), ctx_with(dns={"1.2.3.4": "evil.example"}))
    local = classify_one(conn(dst="192.168.64.1"), ctx_with(dns={}))
    assert "direct-ip" not in named["tags"] and "direct-ip" not in local["tags"]


def test_dns_map_reads_sysmon_eid_22():
    events = [
        {"timestamp": iso(10), "event_id": 22, "query": "Evil.Example.", "result": "::ffff:1.2.3.4;"},
        {"timestamp": iso(20), "event_id": 22, "query": "time.example",
         "result": "type:  5 time.cdn.example;::ffff:5.6.7.8;2001:db8::1;"},
        {"timestamp": iso(30), "event_id": 22, "query": "nx.example", "result": "-"},
        {"timestamp": iso(40), "event_id": 22, "query": "-", "result": "9.9.9.9;"},
        {"timestamp": iso(50), "event_id": 3, "query": "ignored.example", "result": "7.7.7.7;"},
    ]
    assert firewall.dns_map(events) == {"1.2.3.4": "evil.example", "5.6.7.8": "time.example",
                                        "2001:db8::1": "time.example"}


def test_dns_map_last_answer_wins_whatever_the_order_of_the_events():
    events = [
        {"timestamp": iso(30), "event_id": 22, "query": "new.example", "result": "1.2.3.4;"},
        {"timestamp": iso(10), "event_id": 22, "query": "old.example", "result": "1.2.3.4;"},
    ]
    assert firewall.dns_map(events) == {"1.2.3.4": "new.example"}


def test_dns_map_keeps_every_answer_unless_the_caller_asks_for_a_ttl():
    day = 24 * 3600
    events = [{"timestamp": iso(0), "event_id": 22, "query": "old.example", "result": "1.1.1.1;"},
              {"timestamp": iso(day + 5), "event_id": 22, "query": "new.example", "result": "2.2.2.2;"}]
    assert firewall.dns_map(events) == {"1.1.1.1": "old.example", "2.2.2.2": "new.example"}
    assert firewall.dns_map(events, ttl_s=day) == {"2.2.2.2": "new.example"}
    assert list(firewall.dns_map(events, limit=1)) == ["2.2.2.2"]


def test_a_flow_long_after_its_dns_answer_is_not_a_hardcoded_target():
    two_days = 2 * 24 * 3600
    dns_events = [{"timestamp": iso(0), "event_id": 22, "query": "old.example", "result": "1.2.3.4;"},
                  {"timestamp": iso(two_days), "event_id": 22, "query": "other.example", "result": "5.6.7.8;"}]
    ctx = ctx_with(dns=firewall.dns_map(dns_events))
    f = classify_one(conn(dst="1.2.3.4", t=two_days), ctx)
    assert "direct-ip" not in f["tags"] and f["dst_hostname"] == "old.example"


# ---- the tags --------------------------------------------------------------------------------


def test_ioc_hit_is_critical():
    flows = firewall.classify([conn(dst="1.2.3.4")], [], ctx_with(ioc_ips={"1.2.3.4"}))
    assert "ioc" in flows[0]["tags"]
    assert firewall.severity_of(flows[0]["tags"]) == "critical"
    assert flows[0]["severity"] == "critical"


def test_ioc_domain_matches_the_name_and_its_parent_domains():
    ctx = ctx_with(ioc_domains={"evil.example"})
    assert "ioc" in classify_one(conn(hostname="evil.example"), ctx)["tags"]
    assert "ioc" in classify_one(conn(hostname="c2.evil.example"), ctx)["tags"]
    assert "ioc" not in classify_one(conn(hostname="notevil.example"), ctx)["tags"]
    assert "ioc" not in classify_one(conn(hostname="example"), ctx)["tags"]


def test_beaconing_is_found_in_a_regular_rhythm():
    events = [conn(dst="1.2.3.4", dport=443, t=t) for t in range(0, 900, 60)]
    flows = firewall.classify(events, [], ctx_with())
    assert "beacon" in flows[0]["tags"]


def test_no_beacon_for_an_irregular_or_short_series():
    irregular = [conn(t=t) for t in (0, 3, 50, 52, 400, 401, 900)]
    short = [conn(t=t) for t in (0, 60, 120)]
    assert "beacon" not in firewall.classify(irregular, [], ctx_with())[0]["tags"]
    assert "beacon" not in firewall.classify(short, [], ctx_with())[0]["tags"]


def test_sigma_when_an_alert_names_the_endpoint():
    alert_nested = {"raw": {"destination": {"ip": "1.2.3.4", "port": 443}}}
    alert_flat = {"raw": {"network.destination.ip": "5.6.7.8", "network.destination.port": "8080"}}
    ctx = ctx_with(alerts=[alert_nested, alert_flat, {"raw": None}, "garbage"])
    assert "sigma" in classify_one(conn(dst="1.2.3.4", dport=443), ctx)["tags"]
    assert "sigma" in classify_one(conn(dst="5.6.7.8", dport=8080), ctx)["tags"]
    assert "sigma" not in classify_one(conn(dst="1.2.3.4", dport=80), ctx)["tags"]
    assert "sigma" not in classify_one(conn(dst="9.9.9.9", dport=443), ctx)["tags"]


def test_detonated_for_a_submission_and_for_its_descendants():
    ctx = ctx_with(submission_pids={100},
                   processes={100: {"start": 0.0, "image": "a.exe"},
                              200: {"start": 1.0, "image": "b.exe", "parent_pid": 100},
                              300: {"start": 2.0, "image": "c.exe", "parent_pid": 200},
                              400: {"start": 3.0, "image": "d.exe", "parent_pid": 999}})
    for pid, expected in ((100, True), (200, True), (300, True), (400, False), (500, False)):
        assert ("detonated" in classify_one(conn(pid=pid, t=1000), ctx)["tags"]) is expected


def test_detonated_survives_a_parent_loop():
    ctx = ctx_with(submission_pids={9},
                   processes={1: {"parent_pid": 2}, 2: {"parent_pid": 1}})
    assert "detonated" not in classify_one(conn(pid=1), ctx)["tags"]


def test_download_comes_from_the_flag_the_caller_passes():
    ctx = ctx_with(downloads={(4812, "1.2.3.4", 443)})
    assert "download" in classify_one(conn(pid=4812, dst="1.2.3.4", dport=443), ctx)["tags"]
    assert "download" not in classify_one(conn(pid=4813, dst="1.2.3.4", dport=443), ctx)["tags"]
    assert firewall.TAGS["download"] == "high"


def test_lolbin_by_file_name_not_by_folder():
    assert "lolbin" in classify_one(conn(image=r"C:\Windows\System32\CertUtil.exe"))["tags"]
    assert "lolbin" in classify_one(conn(image=r"C:\Users\x\Temp\rundll32.exe"))["tags"]
    assert "lolbin" not in classify_one(conn(image=r"C:\Program Files\Chrome\chrome.exe"))["tags"]
    assert "lolbin" not in classify_one(conn(image="-"))["tags"]


def test_risky_tld_and_dead_drop_from_the_name():
    risky = classify_one(conn(hostname="payload.example.top"))
    onion = classify_one(conn(hostname="abcdefgh.onion"))
    drop = classify_one(conn(hostname="api.telegram.org"))
    raw = classify_one(conn(hostname="raw.githubusercontent.com"))
    plain = classify_one(conn(hostname="www.example.com"))
    assert "risky-tld" in risky["tags"] and "risky-tld" in onion["tags"]
    assert "dead-drop" in drop["tags"] and "dead-drop" in raw["tags"]
    assert not {"risky-tld", "dead-drop"} & set(plain["tags"])
    assert "dead-drop" not in classify_one(conn(hostname="notpastebin.com"))["tags"]


def test_rare_port_outside_the_usual_list_and_for_the_classics():
    assert "rare-port" in classify_one(conn(dport=9001))["tags"]
    assert "rare-port" in classify_one(conn(dport=4444))["tags"]
    assert "rare-port" not in classify_one(conn(dport=443))["tags"]
    assert "rare-port" not in classify_one(conn(dport=53, proto="udp"))["tags"]
    # a service on the LAN or loopback is not rare, unless it is one of the classics
    assert "rare-port" not in classify_one(conn(dst="192.168.64.1", dport=8766))["tags"]
    # nor is it for an address that is none
    assert "rare-port" not in classify_one(conn(dst="-", dport=9001))["tags"]
    assert "rare-port" in classify_one(conn(dst="192.168.64.1", dport=31337))["tags"]


def test_newborn_only_within_sixty_seconds():
    ctx = ctx_with(processes={4812: {"start": 100.0, "image": r"C:\x\a.exe"}})
    near = firewall.classify([conn(pid=4812, t=140)], [], ctx)
    far = firewall.classify([conn(pid=4812, t=400)], [], ctx)
    assert "newborn" in near[0]["tags"] and "newborn" not in far[0]["tags"]


def test_newborn_needs_a_start_time_and_not_a_start_in_the_future():
    ctx = ctx_with(processes={4812: {"start": 100.0}, 7: {"image": "x.exe"}})
    assert "newborn" not in classify_one(conn(pid=4812, t=50), ctx)["tags"]
    assert "newborn" not in classify_one(conn(pid=7, t=50), ctx)["tags"]
    assert "newborn" not in classify_one(conn(pid=8, t=50), ctx)["tags"]


def test_dga_detection():
    assert firewall.is_dga("kqj3x9zmfvbt7w2p.top") is True
    assert firewall.is_dga("cdn.statically.io") is False
    assert firewall.is_dga("") is False


def test_dga_ignores_ordinary_long_names_and_ip_literals():
    for name in ("raw.githubusercontent.com", "login.microsoftonline.com", "download.windowsupdate.com",
                 "d111111abcdef8.cloudfront.net", "ec2-54-12-33-1.compute-1.amazonaws.com", "bbc.co.uk",
                 "1.2.3.4", "localhost", "a" * 40 + ".com"):
        assert firewall.is_dga(name) is False, name
    assert firewall.is_dga("4829175036481.com") is True       # nearly all digits
    assert firewall.is_dga(None) is False


def test_dga_looks_at_the_registered_name_not_at_the_subdomains():
    assert firewall.is_dga("x7f3q9kz2m1w8vb4.cloudfront.net") is False
    assert firewall.is_dga("www.kqj3x9zmfvbt7w2p.co.uk") is True


def test_entropy_is_shannon_bits_per_character():
    assert firewall.entropy("") == 0.0
    assert firewall.entropy("aaaa") == 0.0
    assert firewall.entropy("abcd") == pytest.approx(2.0)


def test_dga_tag_on_a_flow_with_a_resolved_name():
    assert "dga" in classify_one(conn(hostname="kqj3x9zmfvbt7w2p.top"))["tags"]


# ---- the firewall log ------------------------------------------------------------------------


def test_firewall_records_land_on_the_endpoint_not_the_process():
    flows = firewall.classify([conn(pid=1, dst="1.2.3.4", dport=443),
                               conn(pid=2, dst="1.2.3.4", dport=443)],
                              [fw(action="DROP", dst="1.2.3.4", dport=443)], ctx_with())
    assert all(f["fw_dropped"] == 1 for f in flows)
    assert all("dropped" in f["endpoint_tags"] for f in flows)
    assert all("dropped" not in f["tags"] for f in flows)


def test_firewall_join_counts_allowed_and_dropped_and_normalises_the_protocol():
    flows = firewall.bundle([conn(dst="1.2.3.4", dport=443, proto="tcp"),
                             conn(dst="1.2.3.4", dport=53, proto="udp")])
    firewall.attach_firewall(flows, [fw("ALLOW", dport=443, proto="TCP"), fw("ALLOW", dport=443, proto="6"),
                                     fw("DROP", dport=443, proto="tcp"), fw("OPEN", dport=443, proto="TCP"),
                                     fw("DROP", dport=53, proto="17"),
                                     fw("DROP", dport=80, proto="TCP"),
                                     fw("DROP", dst="5.6.7.8", dport=443, proto="TCP"),
                                     fw("DROP", dport=443, proto="TCP", src="10.0.2.99")])
    tcp = next(f for f in flows if f["dst_port"] == 443)
    udp = next(f for f in flows if f["dst_port"] == 53)
    assert (tcp["fw_records"], tcp["fw_allowed"], tcp["fw_dropped"]) == (4, 2, 1)
    assert tcp["endpoint_tags"] == ["dropped"]
    assert (udp["fw_records"], udp["fw_allowed"], udp["fw_dropped"]) == (1, 0, 1)


def test_firewall_join_without_records_is_zero_and_repeatable():
    flows = firewall.bundle([conn()])
    firewall.attach_firewall(flows, [])
    assert (flows[0]["fw_records"], flows[0]["fw_allowed"], flows[0]["fw_dropped"]) == (0, 0, 0)
    assert flows[0]["endpoint_tags"] == []
    events = [fw("DROP")]
    firewall.attach_firewall(flows, events)
    firewall.attach_firewall(flows, events)
    assert flows[0]["fw_dropped"] == 1


def test_firewall_join_takes_flat_events_and_skips_junk():
    flows = firewall.bundle([conn()])
    flat = {"action": "DROP", "protocol": "TCP", "src_ip": "10.0.2.15", "dst_ip": "1.2.3.4", "dst_port": "443"}
    firewall.attach_firewall(flows, [flat, {"fields": None}, "junk", None, {"fields": {"action": "DROP"}}])
    assert flows[0]["fw_dropped"] == 1 and flows[0]["fw_records"] == 1


# ---- self-exclusion --------------------------------------------------------------------------


def test_tdc_python_is_self_and_only_an_unexpected_endpoint_is_an_anomaly():
    to_github = firewall.classify([conn(image=TDC_PYTHON, dst=GITHUB_IP)], [], ctx_with())[0]
    to_unknown_host = firewall.classify([conn(image=TDC_PYTHON, dst="1.2.3.4")], [], ctx_with())[0]
    assert to_github["self"] is True and "tdc-anomaly" not in to_github["tags"]
    assert to_unknown_host["self"] is True and "tdc-anomaly" in to_unknown_host["tags"]


def test_tdc_may_talk_to_loopback_and_to_what_the_caller_expects():
    loop = classify_one(conn(image=TDC_PYTHON, dst="127.0.0.1", dport=8000, src="127.0.0.1"))
    fetched = classify_one(conn(image=TDC_PYTHON, dst="1.2.3.4"), ctx_with(fetch_targets={"1.2.3.4"}))
    by_name = classify_one(conn(image=TDC_PYTHON, dst="1.2.3.4", hostname="download.sysinternals.com"))
    assert "tdc-anomaly" not in loop["tags"] and "tdc-anomaly" not in fetched["tags"]
    assert "tdc-anomaly" not in by_name["tags"]
    other_lan = classify_one(conn(image=TDC_PYTHON, dst="192.168.64.9", dport=22))
    assert "tdc-anomaly" in other_lan["tags"]


def test_other_processes_are_not_self_and_never_anomalous():
    f = classify_one(conn(image=IMAGE, dst="1.2.3.4"))
    assert f["self"] is False and "tdc-anomaly" not in f["tags"]
    lookalike = classify_one(conn(image=r"C:\Users\x\Temp\python.exe", dst="1.2.3.4"))
    assert lookalike["self"] is False


def test_self_matches_the_paths_in_tdc_images_ignoring_case():
    assert classify_one(conn(image=TDC_PYTHON.upper()))["self"] is True
    assert classify_one(conn(image=r"C:\Program Files\Git\mingw64\libexec\git-core\git-remote-https.exe"))["self"]
    assert classify_one(conn(image=r"c:\litterbox\venv\scripts\python.exe"))["self"] is True
    assert classify_one(conn(image=r"C:\detonator\.venv\Scripts\python.exe"))["self"] is True
    assert classify_one(conn(image=r"C:\DetonatorAgent\publish\DetonatorAgent.exe"))["self"] is True
    assert classify_one(conn(image=r"C:\Program Files\Fibratus\Bin\fibratus.exe"))["self"] is True
    assert classify_one(conn(image=r"C:\tools\rustinel\rustinel.exe"))["self"] is True
    assert classify_one(conn(image=r"C:\Program Files\Git\cmd\GIT.EXE"))["self"] is True


def test_git_counts_by_name_and_tdc_anomaly_is_the_net_under_that():
    # matching is by path and by name, and both can be abused: a dropped git.exe is "self"
    # but is flagged the moment it reaches anything TDC has no business with
    dropped = classify_one(conn(image=r"C:\Users\x\Temp\git.exe", dst="1.2.3.4"))
    assert dropped["self"] is True and "tdc-anomaly" in dropped["tags"]
    assert classify_one(conn(image=r"C:\Users\x\Temp\gitt.exe"))["self"] is False
    assert classify_one(conn(image=r"C:\DetonationChamberUI2\x.exe"))["self"] is False


# ---- state, rules ----------------------------------------------------------------------------


def test_state_is_allowed_unless_a_rule_or_a_pending_decision_says_otherwise():
    ctx = ctx_with(rules={R(IMAGE, "1.2.3.4", 443): "TDC-FW-a1"}, pending={R("", "5.6.7.8", None)})
    blocked = classify_one(conn(dst="1.2.3.4", dport=443), ctx)
    other_port = classify_one(conn(dst="1.2.3.4", dport=80), ctx)
    pending = classify_one(conn(dst="5.6.7.8"), ctx)
    assert (blocked["state"], blocked["rule_id"]) == ("blocked", "TDC-FW-a1")
    assert (other_port["state"], other_port["rule_id"]) == ("allowed", None)
    assert (pending["state"], pending["rule_id"]) == ("pending", None)


def test_rule_keys_are_what_rule_key_says_and_endpoint_key_is_unchanged():
    assert firewall.rule_key(IMAGE, "1.2.3.4", 443) == r"c:\x\a.exe|1.2.3.4:443"
    assert firewall.rule_key(IMAGE, "1.2.3.4", None) == r"c:\x\a.exe|1.2.3.4"
    assert firewall.rule_key(IMAGE, "", None) == r"c:\x\a.exe|"
    assert firewall.rule_key("", "1.2.3.4", 443) == "|1.2.3.4:443"
    assert firewall.rule_key("", "2001:db8::1", 443) == "|[2001:db8::1]:443"
    assert firewall.endpoint_key("2001:db8::1", 443) == "[2001:db8::1]:443"
    assert firewall.endpoint_key("1.2.3.4", 443) == "1.2.3.4:443"
    assert firewall.endpoint_key("1.2.3.4", None) == "1.2.3.4"


def test_a_block_for_one_program_leaves_another_programs_flow_to_the_same_endpoint_allowed():
    ctx = ctx_with(rules={R(IMAGE, "1.2.3.4", 443): "r1"})
    mine = classify_one(conn(image=IMAGE, dst="1.2.3.4", dport=443), ctx)
    other = classify_one(conn(image=r"C:\x\b.exe", dst="1.2.3.4", dport=443), ctx)
    elsewhere = classify_one(conn(image=IMAGE, dst="1.2.3.4", dport=80), ctx)
    assert (mine["state"], mine["rule_id"]) == ("blocked", "r1")
    assert (other["state"], other["rule_id"]) == ("allowed", None)
    assert elsewhere["state"] == "allowed"
    for rules in ({R(IMAGE, "1.2.3.4", None): "r"}, {R(IMAGE, "", None): "r"}):
        ctx = ctx_with(rules=rules)
        assert classify_one(conn(image=r"C:\x\b.exe", dst="1.2.3.4"), ctx)["state"] == "allowed"
        assert classify_one(conn(image=IMAGE, dst="1.2.3.4", dport=80), ctx)["state"] == "blocked"


def test_a_block_for_every_process_hits_all_of_them():
    ip_port = ctx_with(rules={R("", "1.2.3.4", 443): "r"})
    whole_ip = ctx_with(rules={R("", "1.2.3.4", None): "r"})
    for ctx in (ip_port, whole_ip):
        for image in (IMAGE, r"C:\x\b.exe", TDC_PYTHON):
            assert classify_one(conn(image=image, dst="1.2.3.4", dport=443), ctx)["state"] == "blocked"
        assert classify_one(conn(dst="5.6.7.8", dport=443), ctx)["state"] == "allowed"
    assert classify_one(conn(dst="1.2.3.4", dport=80), ip_port)["state"] == "allowed"
    assert classify_one(conn(dst="1.2.3.4", dport=80), whole_ip)["state"] == "blocked"


def test_the_most_specific_rule_wins_in_the_documented_order():
    ladder = [(R(IMAGE, "1.2.3.4", 443), "1"), (R(IMAGE, "1.2.3.4", None), "2"), (R(IMAGE, "", None), "3"),
              (R("", "1.2.3.4", 443), "4"), (R("", "1.2.3.4", None), "5")]
    for n in range(5):
        ctx = ctx_with(rules=dict(ladder[n:]))
        assert classify_one(conn(dst="1.2.3.4", dport=443), ctx)["rule_id"] == str(n + 1)


def test_rule_keys_ignore_case_and_cover_ipv6():
    ctx = ctx_with(rules={R(IMAGE.upper(), "2001:db8::1", 443): "v6"})
    assert classify_one(conn(dst="2001:db8::1", dport=443), ctx)["rule_id"] == "v6"


def test_a_flow_without_an_image_or_address_matches_no_rule_by_accident():
    ctx = ctx_with(rules={"|": "everything", R("", "", None): "nothing"})
    assert classify_one(conn(image="-", dst="1.2.3.4"), ctx)["state"] == "allowed"
    assert classify_one(conn(image=IMAGE, dst="-"), ctx)["state"] == "allowed"


def test_a_blocked_decision_beats_a_pending_one():
    ctx = ctx_with(rules={R("", "5.6.7.8", None): "r"}, pending={R("", "5.6.7.8", None)})
    assert classify_one(conn(dst="5.6.7.8"), ctx)["state"] == "blocked"


def test_a_pending_decision_is_program_scoped_too():
    ctx = ctx_with(pending={R(IMAGE, "5.6.7.8", 443)})
    assert classify_one(conn(image=IMAGE, dst="5.6.7.8", dport=443), ctx)["state"] == "pending"
    assert classify_one(conn(image=r"C:\x\b.exe", dst="5.6.7.8", dport=443), ctx)["state"] == "allowed"


def test_a_rule_that_bites_a_tdc_process_is_shown_as_it_is():
    ctx = ctx_with(rules={R("", "1.2.3.4", None): "r2"})
    f = classify_one(conn(image=TDC_PYTHON, dst="1.2.3.4"), ctx)
    assert f["self"] is True and f["state"] == "blocked" and f["rule_id"] == "r2"


# ---- geo -------------------------------------------------------------------------------------


def test_local_addresses_get_scope_local_and_no_geo():
    f = firewall.classify([conn(dst="192.168.64.1")], [], ctx_with())[0]
    assert f["geo"]["scope"] == "local" and f["geo"]["lat"] is None


def test_geo_of_a_public_address_is_the_jittered_centroid():
    geo = classify_one(conn(dst="1.2.3.4"))["geo"]
    lat, lon = geoip.jitter("1.2.3.4", 51.0, 10.0)
    assert geo == {"scope": "public", "cc": "DE", "country": "Germany", "lat": lat, "lon": lon,
                   "asn": 24940, "as_org": "Hetzner Online GmbH"}


def test_geo_without_a_centroid_keeps_the_asn_and_skips_the_jitter():
    geo = classify_one(conn(dst="9.9.9.9"))["geo"]
    assert geo["scope"] == "public" and geo["lat"] is None and geo["lon"] is None
    assert geo["cc"] is None and geo["asn"] == 19281 and geo["as_org"] == "Quad9"


def test_geo_of_an_unknown_public_address_is_scope_public_and_empty():
    geo = classify_one(conn(dst="203.0.113.77"))["geo"]
    assert geo == {"scope": "public", "cc": None, "country": None, "lat": None, "lon": None,
                   "asn": None, "as_org": None}


def test_geo_of_a_garbage_address_is_invalid():
    assert classify_one(conn(dst="-"))["geo"]["scope"] == "invalid"
    assert classify_one(conn(dst="not-an-ip"))["geo"]["scope"] == "invalid"


def test_the_default_geo_lookup_is_geoips_and_is_empty_without_data(tmp_path):
    geoip.load(str(tmp_path / "nothing"))
    f = firewall.classify([conn(dst="1.2.3.4")], [], firewall.Context())[0]
    assert f["geo"]["scope"] == "public" and f["geo"]["cc"] is None and f["geo"]["lat"] is None


# ---- classify as a whole ---------------------------------------------------------------------


def test_classify_of_nothing_is_nothing():
    assert firewall.classify([], [], ctx_with()) == []
    assert firewall.classify([], [fw()], ctx_with()) == []


def test_classified_flows_are_plain_json():
    flows = firewall.classify(SAMPLE_EVENTS, [fw("DROP", dst="203.0.113.50", dport=8080)], ctx_with())
    again = json.loads(json.dumps(flows, allow_nan=False))
    assert again == flows
    for f in flows:
        assert set(f) >= {"image", "pid", "protocol", "src_ip", "dst_ip", "dst_port", "count", "first_seen",
                          "last_seen", "dst_hostname", "fw_records", "fw_allowed", "fw_dropped", "geo",
                          "tags", "endpoint_tags", "severity", "state", "rule_id", "capture_ids", "self"}
        assert all(t in firewall.TAGS for t in f["tags"] + f["endpoint_tags"])
        assert f["capture_ids"] == []


def test_a_detonation_is_read_the_way_an_analyst_would():
    events = SAMPLE_EVENTS
    ctx = ctx_with(dns=firewall.dns_map(events), submission_pids={4812},
                   processes={4812: {"start": T0, "image": "invoice.exe", "parent_pid": 3100},
                              5120: {"start": T0 + 30, "image": "powershell.exe", "parent_pid": 4812}},
                   downloads={(5120, "203.0.113.50", 8080)})
    flows = {(f["image"].rsplit("\\", 1)[-1], f["dst_ip"], f["dst_port"]): f
             for f in firewall.classify(events, [], ctx)}
    beacon = flows[("invoice.exe", "198.51.100.7", 443)]
    stage2 = flows[("powershell.exe", "203.0.113.50", 8080)]
    classic = flows[("invoice.exe", "203.0.113.50", 4444)]
    edge = flows[("msedge.exe", "93.184.216.34", 443)]
    assert beacon["count"] == 12 and {"beacon", "dga", "risky-tld", "detonated"} <= set(beacon["tags"])
    assert beacon["dst_hostname"] == "kqj3x9zmfvbt7w2p.top" and "direct-ip" not in beacon["tags"]
    assert beacon["severity"] == "critical"
    assert {"direct-ip", "download", "lolbin", "detonated", "rare-port", "newborn"} <= set(stage2["tags"])
    assert {"direct-ip", "rare-port", "detonated"} <= set(classic["tags"])
    assert edge["tags"] == [] and edge["severity"] == "info"


# ---- summary ---------------------------------------------------------------------------------


def test_summarize_of_nothing():
    s = firewall.summarize([])
    assert (s["connections"], s["events"], s["blocked"], s["pending"], s["captures"]) == (0, 0, 0, 0, 0)
    assert s["top_processes"] == [] and s["top_endpoints"] == [] and s["top_countries"] == []


def test_summarize_numbers():
    ctx = ctx_with(rules={R("", "5.6.7.8", None): "r"}, pending={R("", "9.9.9.9", None)})
    events = ([conn(pid=1, dst="1.2.3.4", t=t) for t in range(3)] + [conn(pid=2, dst="1.2.3.4", t=9)]
              + [conn(pid=1, dst="5.6.7.8", dport=80, t=5)] + [conn(pid=3, dst="9.9.9.9", t=6)]
              + [conn(pid=1, dst="192.168.64.1", dport=53, t=7)])
    flows = firewall.classify(events, [], ctx)
    flows[0]["capture_ids"] = ["c1", "c2"]
    flows[1]["capture_ids"] = ["c2"]
    s = firewall.summarize(flows)
    assert (s["connections"], s["events"], s["blocked"], s["pending"], s["captures"]) == (5, 7, 1, 1, 2)
    assert s["top_processes"][0] == {"image": IMAGE, "flows": 5, "count": 7}
    assert s["top_endpoints"][0] == {"dst_ip": "1.2.3.4", "dst_port": 443, "dst_hostname": None,
                                     "flows": 2, "count": 4}
    assert s["top_countries"][0] == {"cc": "DE", "country": "Germany", "flows": 2, "count": 4}
    assert [c["cc"] for c in s["top_countries"]] == ["DE", "NL"]


def test_summarize_keeps_the_tops_short():
    events = [conn(dst=f"1.2.3.{i}", t=i) for i in range(1, 30)]
    s = firewall.summarize(firewall.classify(events, [], ctx_with()))
    assert len(s["top_endpoints"]) == firewall.TOP_N
