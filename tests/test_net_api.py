"""The HTTP API of the network analysis: pcap import, stored reports, baseline.

Regressions covered:
  * there was no way to hand a capture to ``net_analyze`` from the web UI
  * a report is stored with the capture's analysis (restart-proof, like the
    memory results) and listed newest first with a summary, not the whole report
  * a report id is looked up as a key and never as a path, a client file name
    never becomes a file name on the server, and an upload has a size limit
  * a file that is not a capture is a 400 that says so, not an empty report
  * a password sent over FTP, SMTP (AUTH LOGIN and PLAIN), HTTP Basic, in a
    form, in a query string, or as a base64 value must be in no response
    body of the import, the stored report, the list or the baseline
  * the baseline is captured from an analysis without the baseline, so the
    capture of the clean VM is learned whole, and a later import suppresses it
"""

import base64
import io
import os

import pytest

import test_net_analyze as na
from test_net_analyze import C2, _pcap_with_http_c2, _pcap_with_ncsi, _write
from test_net_default_rules import Capture

MULTIPART = "multipart/form-data"


def _upload(client, path, name="c.pcap", url="/api/network/import", **fields):
    with open(path, "rb") as fh:
        data = dict(fields, file=(io.BytesIO(fh.read()), name))
    return client.post(url, data=data, content_type=MULTIPART)


def test_importing_a_pcap_returns_a_report(client, tmp_path):
    r = _upload(client, _pcap_with_http_c2(tmp_path))
    assert r.status_code == 200
    report = r.get_json()
    assert report["event_summary"]["http"] >= 1
    assert report["mode"] == "online" and report["filename"] == "c.pcap"
    assert report["id"] and report["timestamp"]


def test_a_report_can_be_fetched_again_by_id(client, tmp_path):
    first = _upload(client, _pcap_with_http_c2(tmp_path)).get_json()
    again = client.get("/api/network/report?id=%s" % first["id"])
    assert again.status_code == 200 and again.get_json() == first


def test_a_report_survives_a_restart(client, tdc, tmp_path):
    rid = _upload(client, _pcap_with_http_c2(tmp_path)).get_json()["id"]
    tdc._net_reports = tdc._ResultStore(str(tmp_path / "net_results"))
    assert client.get("/api/network/report?id=%s" % rid).get_json()["id"] == rid
    assert [r["id"] for r in client.get("/api/network/reports").get_json()["reports"]] == [rid]


def test_importing_without_a_file_is_a_bad_request(client):
    assert client.post("/api/network/import").status_code == 400
    r = client.post("/api/network/import", data={"mode": "online"}, content_type=MULTIPART)
    assert r.status_code == 400


def test_a_file_that_is_not_a_pcap_is_refused_with_a_reason(client, tmp_path):
    p = tmp_path / "x.pcap"
    p.write_bytes(b"nope")
    r = _upload(client, str(p), "x.pcap")
    assert r.status_code == 400 and "pcap" in r.get_json()["error"].lower()
    assert client.get("/api/network/reports").get_json()["reports"] == []


def test_an_empty_file_is_refused_too(client, tmp_path):
    p = tmp_path / "e.pcap"
    p.write_bytes(b"")
    assert _upload(client, str(p), "e.pcap").status_code == 400


def test_an_empty_capture_is_a_report_that_observed_nothing(client, tmp_path):
    r = _upload(client, na._empty_pcap(tmp_path))
    assert r.status_code == 200 and r.get_json()["observed"] is False


def test_an_unknown_mode_is_refused_and_isolated_is_kept(client, tmp_path):
    path = _pcap_with_http_c2(tmp_path)
    assert _upload(client, path, mode="offline").status_code == 400
    assert _upload(client, path, mode="isolated").get_json()["mode"] == "isolated"
    assert client.get("/api/network/reports").get_json()["reports"][0]["mode"] == "isolated"


@pytest.mark.parametrize("rid", ["../../etc/passwd", "..%2f..%2fx", "a" * 32 + "/../x", "",
                                 "A" * 32, "0" * 31, "0" * 33, "g" * 32])
def test_a_report_id_that_is_not_one_of_ours_is_refused(client, rid):
    assert client.get("/api/network/report", query_string={"id": rid}).status_code == 400


def test_an_unknown_report_id_is_not_found(client):
    assert client.get("/api/network/report?id=" + "0" * 32).status_code == 404
    assert client.get("/api/network/report").status_code == 400


def test_the_reports_list_is_newest_first(client, tmp_path):
    for name in ("a.pcap", "b.pcap"):
        _upload(client, _pcap_with_http_c2(tmp_path), name)
    names = [r["filename"] for r in client.get("/api/network/reports").get_json()["reports"]]
    assert names == ["b.pcap", "a.pcap"]


def test_a_list_entry_is_a_summary_and_not_the_report(client, tmp_path):
    report = _upload(client, _pcap_with_http_c2(tmp_path), "c.pcap", process="a.exe").get_json()
    row = client.get("/api/network/reports").get_json()["reports"][0]
    assert {"id", "filename", "timestamp", "mode", "summary"} <= set(row)
    assert "events" not in row and "iocs" not in row
    assert row["id"] == report["id"] and row["mode"] == "online"
    s = row["summary"]
    assert s["events"] == len(report["events"]) and s["event_summary"] == report["event_summary"]
    assert s["findings"] == len(report["evidence_findings"]) and s["verdict"]


def test_a_stored_report_that_lost_its_summary_or_report_is_not_listed(client, tdc, tmp_path):
    rid = _upload(client, _pcap_with_http_c2(tmp_path)).get_json()["id"]
    tdc._net_reports = tdc._ResultStore(str(tmp_path / "other"))
    assert client.get("/api/network/reports").get_json()["reports"] == []
    assert client.get("/api/network/report?id=" + rid).status_code == 404


def test_the_client_file_name_never_becomes_a_path_on_the_server(client, tdc, tmp_path):
    r = _upload(client, _pcap_with_http_c2(tmp_path), "../../../evil\\..\\x.pcap")
    assert r.status_code == 200
    assert "/" not in r.get_json()["filename"] and "\\" not in r.get_json()["filename"]
    stored = os.listdir(tdc._net_upload_dir())
    assert len(stored) == 1 and stored[0] == r.get_json()["id"] + ".pcap"
    assert not os.path.exists(os.path.join(str(tmp_path), "evil"))


def test_uploads_are_pruned(client, tdc, tmp_path, monkeypatch):
    monkeypatch.setattr(tdc, "NET_UPLOADS_KEEP", 2)
    path = _pcap_with_http_c2(tmp_path)
    for i in range(5):
        _upload(client, path, "c%d.pcap" % i)
        for n in os.listdir(tdc._net_upload_dir()):
            os.utime(os.path.join(tdc._net_upload_dir(), n), (1000 + i, 1000 + i))
    assert len(os.listdir(tdc._net_upload_dir())) <= 3


def test_an_upload_over_the_limit_is_refused_and_leaves_nothing(client, tdc, tmp_path, monkeypatch):
    monkeypatch.setattr(tdc, "NET_UPLOAD_MAX", 1000)
    r = _upload(client, _pcap_with_http_c2(tmp_path))
    assert r.status_code == 413
    assert os.listdir(tdc._net_upload_dir()) == []
    assert client.get("/api/network/reports").get_json()["reports"] == []


def test_the_bytes_of_a_capture_are_never_opened_or_run(client, tdc, tmp_path, monkeypatch):
    import subprocess
    calls = []
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: calls.append(a))
    cap = Capture()
    cap.get(5.0, "stage.top", "/a.bin", na._pe(), "application/octet-stream")
    assert _upload(client, _write(tmp_path, cap)).status_code == 200
    assert calls == []
    assert os.listdir(tdc._net_upload_dir()) == [
        n for n in os.listdir(tdc._net_upload_dir()) if n.endswith(".pcap")]


def test_the_report_is_what_the_analysis_made(client, tdc, tmp_path):
    from net_analyze import analyze_pcap
    path = _pcap_with_http_c2(tmp_path)
    got = _upload(client, path).get_json()
    want = analyze_pcap(path, rules=tdc._net_rules_file(), baseline=tdc._net_baseline)
    for key in ("events", "event_summary", "rule_hits", "evidence_findings", "iocs", "files"):
        assert got[key] == want[key], key


def test_capturing_a_baseline_reports_what_it_learned(client, tmp_path):
    r = _upload(client, _pcap_with_ncsi(tmp_path), "b.pcap", url="/api/network/baseline/capture")
    assert r.status_code == 200
    body = r.get_json()
    assert body["count"] >= 1 and body["added"] == body["count"]
    assert any(item["dest"] == "www.msftconnecttest.com" for item in body["learned"])
    assert client.get("/api/network/baseline").get_json()["count"] == body["count"]


def test_a_captured_baseline_suppresses_the_same_traffic_in_the_next_import(client, tmp_path):
    path = _pcap_with_ncsi(tmp_path)
    before = _upload(client, path).get_json()
    _upload(client, path, url="/api/network/baseline/capture")
    after = _upload(client, path).get_json()
    assert before["suppressed_count"] == 0 and after["suppressed_count"] > 0


def test_capturing_the_baseline_does_not_use_the_baseline(client, tmp_path):
    path = _pcap_with_ncsi(tmp_path)
    first = _upload(client, path, url="/api/network/baseline/capture").get_json()
    again = _upload(client, path, url="/api/network/baseline/capture").get_json()
    assert again["added"] == 0 and again["count"] == first["count"]
    assert again["events_seen"] == first["events_seen"] > 0


def test_a_baseline_capture_stores_no_report(client, tmp_path):
    _upload(client, _pcap_with_ncsi(tmp_path), url="/api/network/baseline/capture")
    assert client.get("/api/network/reports").get_json()["reports"] == []


def test_the_baseline_capture_refuses_what_the_import_refuses(client, tmp_path):
    url = "/api/network/baseline/capture"
    assert client.post(url).status_code == 400
    p = tmp_path / "x.pcap"
    p.write_bytes(b"nope")
    r = _upload(client, str(p), url=url)
    assert r.status_code == 400 and "pcap" in r.get_json()["error"].lower()


def test_an_empty_baseline_has_a_count_of_zero(client):
    body = client.get("/api/network/baseline").get_json()
    assert body["count"] == 0 and body["total"] == 0


# --- no response carries a password -------------------------------------------------------

def _credential_capture(tmp_path):
    cap = Capture()
    cap.tcp(5.0, C2, 21, [("c", b"USER stealer\r\nPASS Ftp-Pw-1&x\r\nSTOR h.zip\r\n"),
                          ("s", b"220 ftp\r\n331 ok\r\n230 ok\r\n150 ok\r\n")])
    login = base64.b64encode(b"Smtp-Login-Pw-2").decode()
    plain = base64.b64encode(b"\0bot@e.top\0Smtp-Plain-Pw-3").decode()
    cap.tcp(7.0, C2, 25, [("c", b"EHLO x\r\nAUTH LOGIN\r\n" + base64.b64encode(b"bot@e.top")
                                + b"\r\n" + login.encode() + b"\r\nQUIT\r\n"),
                          ("s", b"220 smtp\r\n250 ok\r\n334 VXNlcm5hbWU6\r\n334 UGFzc3dvcmQ6\r\n"
                                b"235 ok\r\n221 bye\r\n")])
    cap.tcp(8.0, C2, 587, [("c", b"EHLO x\r\nAUTH PLAIN " + plain.encode() + b"\r\nQUIT\r\n"),
                           ("s", b"220 smtp\r\n250 ok\r\n235 ok\r\n221 bye\r\n")])
    basic = base64.b64encode(b"alice:Basic-Pw-4").decode()
    cap.get(9.0, "panel.top", "/admin", b"hi",
            headers=b"Authorization: Basic " + basic.encode() + b"\r\n")
    cap.post(11.0, "shop.top", "/login", b"user=alice&password=Form-Pw-5&go=1")
    cap.get(13.0, "shop.top", "/api?user=alice&password=Query-Pw-6", b"ok")
    blob = base64.b64encode(b"user=bob&password=Blob-Pw-7").decode()
    cap.post(15.0, "drop.top", "/up", ("data=" + blob).encode())
    plains = ["Ftp-Pw-1", "Smtp-Login-Pw-2", "Smtp-Plain-Pw-3", "Basic-Pw-4", "Form-Pw-5",
              "Query-Pw-6", "Blob-Pw-7"]
    encoded = [login, plain, basic, blob]
    return _write(tmp_path, cap), plains + encoded


def test_no_response_of_the_api_carries_a_password(client, tmp_path):
    path, secrets = _credential_capture(tmp_path)
    responses = {}
    imported = _upload(client, path, "pw.pcap")
    assert imported.status_code == 200
    responses["import"] = imported.data
    rid = imported.get_json()["id"]
    responses["report"] = client.get("/api/network/report?id=%s" % rid).data
    responses["reports"] = client.get("/api/network/reports").data
    captured = _upload(client, path, "pw.pcap", url="/api/network/baseline/capture")
    assert captured.status_code == 200
    responses["capture"] = captured.data
    responses["baseline"] = client.get("/api/network/baseline").data
    again = _upload(client, path, "pw.pcap")
    responses["import with baseline"] = again.data
    for where, raw in responses.items():
        assert len(raw) > 20, where
        for secret in secrets:
            assert secret.encode() not in raw, (where, secret)
    # and what the store keeps on disk is the same masked report
    store = os.listdir(str(tmp_path / "net_results"))
    for name in store:
        with open(os.path.join(str(tmp_path / "net_results"), name), "rb") as fh:
            stored = fh.read()
        for secret in secrets:
            assert secret.encode() not in stored, (name, secret)


def test_the_credentials_were_in_the_capture_and_were_found(client, tmp_path):
    path, _ = _credential_capture(tmp_path)
    report = _upload(client, path).get_json()
    kinds = {e["type"] for e in report["events"]}
    assert {"ftp", "smtp", "http"} <= kinds
    ftp = [e for e in report["events"] if e["type"] == "ftp"][0]
    assert ftp["password"] == "***"


def test_a_password_in_the_process_field_is_masked_too(client, tmp_path):
    r = _upload(client, _pcap_with_http_c2(tmp_path), process="a.exe password=Proc-Pw-9")
    rid = r.get_json()["id"]
    raw = r.data + client.get("/api/network/reports").data + client.get(
        "/api/network/report?id=" + rid).data
    assert b"Proc-Pw-9" not in raw
