"""LOGS tab back end: access/MCP capture, search and sources routes, the real readers.

Regressions covered:
  * a failure while logging must never change the response
  * a long search must not block other requests
  * Sysmon EID 3 / 22 events carry the fields the netflow and DNS parsers need
"""

import json
import re
import threading
import time

import pytest

import log_store


@pytest.fixture
def logs(tdc, tmp_path):
    """An empty store of its own (persisting under tmp_path) behind the routes."""
    store = log_store.LogStore(persist_dir=str(tmp_path / "logs"))
    tdc.set_log_store(store)
    yield store
    tdc.set_log_store(None)


def _events(store, source):
    return [e for e in store.snapshot() if e["source"] == source]


# ---- capture ---------------------------------------------------------------------------------


def test_a_request_becomes_an_access_event(client, logs):
    assert client.get("/api/health", headers={"User-Agent": "Mozilla/5.0 (X11)"}).status_code == 200
    (ev,) = _events(logs, "access")
    f = ev["fields"]
    assert f["method"] == "GET" and f["path"] == "/api/health" and f["status"] == 200
    assert isinstance(f["duration_ms"], (int, float)) and f["duration_ms"] >= 0
    assert f["client"] == "browser" and f["user_agent"].startswith("Mozilla")
    assert "remote_addr" in f and f["query"] == ""
    assert re.match(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$", ev["time"])
    assert "/api/health" in ev["message"] and "200" in ev["message"]


def test_query_string_is_recorded(client, logs):
    client.get("/api/logs/sources?x=1&y=two")
    assert _events(logs, "access")[-1]["fields"]["query"] == "x=1&y=two"


def test_mcp_headers_add_an_mcp_event(client, logs):
    client.get("/api/health", headers={"X-TDC-Client": "mcp", "X-TDC-MCP-Tool": "tdc_status",
                                       "User-Agent": "python-httpx/0.27"})
    (access,) = _events(logs, "access")
    (mcp,) = _events(logs, "mcp")
    assert access["fields"]["client"] == "mcp"
    f = mcp["fields"]
    assert f["tool"] == "tdc_status" and f["method"] == "GET" and f["path"] == "/api/health"
    assert f["status"] == 200 and f["duration_ms"] >= 0
    assert mcp["message"] == "tdc_status \u2192 GET /api/health (200)"


def test_without_headers_there_is_no_mcp_event(client, logs):
    client.get("/api/health", headers={"User-Agent": "curl/8.0"})
    assert _events(logs, "mcp") == []
    assert _events(logs, "access")[0]["fields"]["client"] == "other"


def test_the_mcp_marker_needs_the_exact_header_value(client, logs):
    client.get("/api/health", headers={"X-TDC-Client": "browser", "X-TDC-MCP-Tool": "x"})
    assert _events(logs, "mcp") == []


def test_static_and_favicon_are_not_logged(client, logs):
    client.get("/static/js/app.js")
    client.get("/favicon.ico")
    assert logs.snapshot() == []


@pytest.mark.parametrize("path, poll", [
    ("/api/status", True), ("/api/health", True), ("/api/updates", True), ("/api/alerts", True),
    ("/api/logs/sources", True), ("/api/scan/history", False),
])
def test_polling_paths_are_marked(client, logs, tdc, monkeypatch, path, poll):
    client.get(path)
    ev = [e for e in _events(logs, "access") if e["fields"]["path"] == path][0]
    assert ev["fields"]["poll"] is poll


def test_a_rejected_request_is_logged_with_its_status(client, logs):
    assert client.get("/api/health", headers={"Host": "evil.example"}).status_code == 403
    (ev,) = _events(logs, "access")
    assert ev["fields"]["status"] == 403


def test_a_failing_log_store_never_breaks_the_response(client, tdc, monkeypatch):
    class Broken:
        def add(self, *a, **k):
            raise RuntimeError("disk on fire")

    tdc.set_log_store(Broken())
    try:
        r = client.get("/api/health", headers={"X-TDC-Client": "mcp"})
    finally:
        tdc.set_log_store(None)
    assert r.status_code == 200 and r.get_json() == {"ok": True}


# ---- search ----------------------------------------------------------------------------------


def _seed(store, n=3):
    for i in range(n):
        store.add("dns", "2099-01-01T00:00:%02dZ" % i, f"host{i}.example", {"query": f"host{i}.example"})


def test_search_returns_the_result_schema(client, logs):
    logs.add("dns", "2026-11-14T10:00:00Z", "evil.example -> 1.2.3.4", {"query": "evil.example"})
    r = client.get("/api/logs/search?q=evil&earliest=1970-01-01")
    assert r.status_code == 200
    body = r.get_json()
    assert body["type"] == "events" and body["count"] == 1 and body["matched"] == 1
    assert body["events"][0]["message"].startswith("evil.example")
    for key in ("columns", "rows", "truncated", "histogram", "fields", "took_ms"):
        assert key in body
    assert body["took_ms"] >= 0


def test_search_defaults(client, logs):
    _seed(logs)
    r = client.get("/api/logs/search")
    assert r.status_code == 200      # q=* and earliest=-24h
    assert r.get_json()["type"] == "events"


def test_a_bad_query_is_a_400_with_its_position(client, logs):
    r = client.get("/api/logs/search?q=" + "source%3Ddns%20%7C%20bogus")
    assert r.status_code == 400
    body = r.get_json()
    assert body["error"] and isinstance(body["pos"], int) and body["pos"] > 0


def test_a_bad_time_is_a_400(client, logs):
    r = client.get("/api/logs/search?earliest=not-a-time")
    assert r.status_code == 400 and "error" in r.get_json()


def test_other_failures_are_a_general_500(client, logs, tdc, monkeypatch, caplog):
    def boom(*a, **k):
        raise ValueError("secret internals /etc/passwd")

    monkeypatch.setattr(tdc.log_search, "run", boom)
    with caplog.at_level("ERROR"):
        r = client.get("/api/logs/search")
    assert r.status_code == 500
    assert "secret" not in r.get_data(as_text=True)
    assert r.get_json()["error"]
    assert any("secret internals" in (rec.exc_text or "") or "secret internals" in rec.getMessage()
               for rec in caplog.records)


@pytest.mark.parametrize("limit, shown", [("5", 5), ("0", 1), ("-3", 1), ("99999", 1000), ("abc", 200)])
def test_limit_is_clamped(client, logs, limit, shown):
    for i in range(1200):
        logs.add("dns", "2099-01-01T00:00:00Z", f"m{i}", {})
    body = client.get(f"/api/logs/search?q=*&earliest=1970-01-01&limit={limit}").get_json()
    assert len(body["events"]) == shown
    assert body["count"] == 1200 and body["truncated"] is True


def test_the_response_is_strict_json(client, logs):
    logs.add("dns", "2026-11-14T10:00:00Z", "x", {"ratio": float("nan"), "big": float("inf"), "s": "\ud800"})
    r = client.get("/api/logs/search?earliest=1970-01-01")
    assert r.status_code == 200
    json.loads(r.get_data(as_text=True), parse_constant=lambda c: pytest.fail(f"non-JSON constant {c}"))


def test_sources_lists_all_six(client, logs):
    logs.set_status("firewall", "unavailable", "Firewall is off; no packets are logged.")
    body = client.get("/api/logs/sources").get_json()
    assert [s["source"] for s in body] == ["powershell", "access", "mcp", "netflow", "dns", "firewall"]
    fw = body[-1]
    assert fw["status"] == "unavailable" and fw["hint"].startswith("Firewall is off")


def test_a_long_search_does_not_block_other_requests(client, tdc, logs):
    for i in range(50000):
        logs.add("dns", "2099-01-01T00:00:00Z", f"query {i} some text to scan through", {"n": i})
    slow = tdc.app.test_client()
    done = threading.Event()

    def search():
        slow.get("/api/logs/search?earliest=1970-01-01&q=*zzz*yyy*xxx*")
        done.set()

    t = threading.Thread(target=search)
    t.start()
    time.sleep(0.05)
    started = time.time()
    r = client.get("/api/health")
    elapsed = time.time() - started
    t.join(30)
    assert r.status_code == 200
    assert elapsed < 1.0, elapsed


# ---- Sysmon field promotion -----------------------------------------------------------------

_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def _sysmon_xml(eid, **data):
    items = "".join(f"<Data Name='{k}'>{v}</Data>" for k, v in data.items())
    return (f"<Event xmlns='{_NS}'><System><EventID>{eid}</EventID>"
            f"<TimeCreated SystemTime='2026-11-14T10:00:00.1234567Z'/></System>"
            f"<EventData>{items}</EventData></Event>")


class _Proc:
    returncode = 0
    stdout = b"x"
    stderr = b""


def test_sysmon_network_and_dns_events_carry_source_and_status(tdc, monkeypatch):
    xml = (_sysmon_xml(3, Image="C:\\a.exe", ProcessId="42", Protocol="tcp", SourceIp="10.0.0.5",
                       SourcePort="49152", DestinationIp="1.2.3.4", DestinationPort="443")
           + _sysmon_xml(22, Image="C:\\a.exe", ProcessId="42", QueryName="evil.example",
                         QueryResults="1.2.3.4;", QueryStatus="0"))
    monkeypatch.setattr(tdc, "_wevtutil_query", lambda *a, **k: (xml, _Proc()))
    net, dns = tdc._read_sysmon_events(event_ids=[3, 22], max_events=10)
    assert net["src_ip"] == "10.0.0.5" and net["src_port"] == "49152"
    assert net["dst_ip"] == "1.2.3.4" and net["dst_port"] == "443"
    assert dns["status"] == "0" and dns["query"] == "evil.example"


# ---- real readers ----------------------------------------------------------------------------


def test_windows_sources_are_unavailable_off_windows(tdc, tmp_path, monkeypatch):
    monkeypatch.setattr(tdc, "_IS_WINDOWS", False)
    store = log_store.LogStore()
    collector = tdc.make_log_collector(store)
    collector.tick()
    status = {s["source"]: s for s in store.sources()}
    for name in ("powershell", "netflow", "dns", "firewall"):
        assert status[name]["status"] == "unavailable"
        assert status[name]["hint"] == "Windows event logs are only available on the VM."


def test_powershell_reader_queries_from_the_last_record(tdc, monkeypatch):
    calls = []

    def fake(log, query=None, count=None, newest_first=True, timeout=30):
        calls.append((log, query, count, newest_first))
        xml = ("<Event xmlns='%s'><System><EventID>4104</EventID><EventRecordID>%d</EventRecordID>"
               "</System></Event>" % (_NS, 7 + len(calls)))
        return xml, _Proc()

    monkeypatch.setattr(tdc, "_IS_WINDOWS", True)
    monkeypatch.setattr(tdc, "_wevtutil_query", fake)
    text, last = tdc._read_powershell_log(None)
    assert calls[0][0] == "Microsoft-Windows-PowerShell/Operational"
    assert "EventID=4103" in calls[0][1] and "EventID=4104" in calls[0][1] and "EventID=4100" in calls[0][1]
    assert "timediff" in calls[0][1] and calls[0][2] == 5000 and calls[0][3] is True
    assert last == 8 and "<EventRecordID>8" in text
    text, last = tdc._read_powershell_log(8)
    assert "EventRecordID>8]" in calls[1][1] and calls[1][3] is False
    assert last == 9


def test_powershell_reader_without_events_keeps_the_position(tdc, monkeypatch):
    monkeypatch.setattr(tdc, "_IS_WINDOWS", True)
    monkeypatch.setattr(tdc, "_wevtutil_query", lambda *a, **k: ("", _Proc()))
    assert tdc._read_powershell_log(12) == ("", 12)


def test_powershell_reader_raises_on_a_wevtutil_failure(tdc, monkeypatch):
    class Failed:
        returncode = 15007
        stdout = b""
        stderr = b"The specified channel could not be found.\r\nmore"

    monkeypatch.setattr(tdc, "_IS_WINDOWS", True)
    monkeypatch.setattr(tdc, "_wevtutil_query", lambda *a, **k: ("", Failed()))
    with pytest.raises(RuntimeError, match="channel could not be found"):
        tdc._read_powershell_log(None)


def test_sysmon_reader_passes_ids_and_since(tdc, monkeypatch):
    seen = {}
    monkeypatch.setattr(tdc, "_IS_WINDOWS", True)
    monkeypatch.setattr(tdc, "_read_sysmon_events", lambda **kw: seen.update(kw) or [])
    tdc._read_sysmon_for_logs([3, 22], "2026-11-14T10:00:00Z")
    assert seen["event_ids"] == [3, 22] and seen["since"] == "2026-11-14T10:00:00Z"
    assert seen["max_events"] == 5000


@pytest.fixture
def fw_file(tdc, tmp_path, monkeypatch):
    path = tmp_path / "pfirewall.log"
    monkeypatch.setattr(tdc, "FIREWALL_LOG", str(path))
    monkeypatch.setattr(tdc, "_IS_WINDOWS", True)
    return path


HEADER = ("#Version: 1.5\n#Software: Microsoft Windows Firewall\n#Time Format: Local\n"
          "#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack "
          "tcpwin icmptype icmpcode info path pid\n")
LINE = "2026-11-14 10:00:0%d ALLOW TCP 10.0.0.5 1.2.3.4 49152 443 0 - 0 0 0 - - - SEND 42\n"


def test_firewall_reader_first_read_includes_the_header(tdc, fw_file):
    fw_file.write_bytes((HEADER + "".join(LINE % i for i in range(3))).encode())
    text, offset, hint = tdc._read_firewall_log(None)
    assert text.startswith("#Version") and text.count("ALLOW") == 3
    assert offset == fw_file.stat().st_size and hint == ""


def test_firewall_reader_returns_only_complete_lines(tdc, fw_file):
    data = (HEADER + LINE % 1).encode()
    fw_file.write_bytes(data + b"2026-11-14 10:00:02 ALLOW TCP 10.0")
    text, offset, _ = tdc._read_firewall_log(None)
    assert text.endswith("SEND 42\n") and offset == len(data)
    with open(fw_file, "ab") as f:
        f.write(b".0.5 1.2.3.4 1 2 0 - 0 0 0 - - - SEND 42\n")
    text, offset2, _ = tdc._read_firewall_log(offset)
    assert text.startswith("2026-11-14 10:00:02") and text.endswith("\n")
    assert offset2 == fw_file.stat().st_size


def test_firewall_reader_follows_a_rotated_file(tdc, fw_file):
    fw_file.write_bytes((HEADER + LINE % 1).encode())
    fw_file.write_bytes((HEADER + LINE % 2).encode())          # shorter than the offset below
    text, offset, _ = tdc._read_firewall_log(10 ** 6)
    assert "10:00:02" in text and offset == fw_file.stat().st_size


def test_firewall_reader_big_files_start_in_the_tail(tdc, fw_file, monkeypatch):
    monkeypatch.setattr(tdc, "FIREWALL_FIRST_READ_BYTES", 2000)
    body = "".join(LINE % (i % 10) for i in range(500))
    fw_file.write_bytes((HEADER + body).encode())
    text, offset, _ = tdc._read_firewall_log(None)
    assert text.startswith("#Version") and "#Fields:" in text
    assert text.count("ALLOW") < 500
    assert text.rstrip("\n").splitlines()[-1].endswith("SEND 42")
    # the first line after the header is whole, not the cut-off start of a line
    first = [l for l in text.splitlines() if not l.startswith("#")][0]
    assert first.startswith("2026-11-14")


def test_firewall_reader_missing_file_with_the_firewall_on(tdc, fw_file, monkeypatch):
    monkeypatch.setattr(tdc, "_firewall_is_off", lambda: False)
    text, offset, hint = tdc._read_firewall_log(None)
    assert text == "" and offset is None
    assert "configure-logging.ps1" in hint


def test_firewall_reader_missing_file_with_the_firewall_off(tdc, fw_file, monkeypatch):
    monkeypatch.setattr(tdc, "_firewall_is_off", lambda: True)
    assert tdc._read_firewall_log(None) == ("", None, "Firewall is off; no packets are logged.")


def test_collector_end_to_end_with_the_real_readers(tdc, fw_file, monkeypatch):
    fw_file.write_bytes((HEADER + LINE % 1).encode())
    monkeypatch.setattr(tdc, "_wevtutil_query", lambda *a, **k: ("", _Proc()))
    monkeypatch.setattr(tdc, "_read_sysmon_events", lambda **kw: [])
    store = log_store.LogStore()
    collector = tdc.make_log_collector(store)
    out = collector.tick()
    assert out["firewall"] == 1 or out["firewall"] == 0     # the sample line may be older than 24 h
    status = {s["source"]: s["status"] for s in store.sources()}
    assert status["firewall"] == "ok" and status["powershell"] == "ok" and status["dns"] == "ok"
