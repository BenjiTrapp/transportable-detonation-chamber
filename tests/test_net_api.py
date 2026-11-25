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
import json
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
    assert r.status_code == 400
    assert r.get_json()["error"] == "not a pcap or pcapng file: unrecognised header"
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
                                 "A" * 32, "0" * 31, "0" * 33, "g" * 32,
                                 "0" * 32 + "\n", "\n" + "0" * 32, "0" * 32 + "\r\n"])
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


# --- the size is settled before the body is parsed ------------------------------------------

@pytest.fixture
def parsed(monkeypatch):
    """The multipart parser, spied on: how many bodies Werkzeug parsed."""
    from werkzeug.formparser import FormDataParser
    calls = []
    real = FormDataParser.parse

    def spy(self, *args, **kwargs):
        calls.append(1)
        return real(self, *args, **kwargs)
    monkeypatch.setattr(FormDataParser, "parse", spy)
    return calls


@pytest.mark.parametrize("url", ["/api/network/import", "/api/network/baseline/capture"])
def test_a_large_content_length_is_refused_before_the_body_is_parsed(client, tdc, tmp_path,
                                                                     monkeypatch, parsed, url):
    monkeypatch.setattr(tdc, "NET_UPLOAD_MAX", 1000)
    monkeypatch.setattr(tdc, "_NET_FORM_ALLOWANCE", 100)
    saved = []
    monkeypatch.setattr(tdc, "_save_net_upload", lambda *a: saved.append(a))
    r = client.post(url, data={"file": (io.BytesIO(b"x" * 50000), "big.pcap")},
                    content_type=MULTIPART)
    assert r.status_code == 413 and "larger" in r.get_json()["error"]
    assert parsed == [] and saved == []


class _Counting(io.BytesIO):
    def __init__(self, data):
        super().__init__(data)
        self.read_bytes = 0

    def read(self, size=-1):
        chunk = super().read(size)
        self.read_bytes += len(chunk)
        return chunk

    readinto = None


def _chunked(client, url, size):
    boundary = "xBOUNDARYx"
    body = (("--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"big.pcap\"\r\n"
             "Content-Type: application/octet-stream\r\n\r\n" % boundary).encode()
            + b"x" * size + ("\r\n--%s--\r\n" % boundary).encode())
    stream = _Counting(body)
    r = client.post(url, input_stream=stream, content_type=MULTIPART + "; boundary=" + boundary,
                    environ_overrides={"wsgi.input_terminated": True})
    return r, stream, len(body)


@pytest.mark.parametrize("url", ["/api/network/import", "/api/network/baseline/capture"])
def test_a_body_without_a_content_length_is_bounded_too(client, tdc, tmp_path, monkeypatch, url):
    monkeypatch.setattr(tdc, "NET_UPLOAD_MAX", 1000)
    monkeypatch.setattr(tdc, "_NET_FORM_ALLOWANCE", 100)
    r, stream, total = _chunked(client, url, 200000)
    assert r.status_code == 413 and "larger" in r.get_json()["error"]
    assert stream.read_bytes < total / 4, (stream.read_bytes, total)
    assert not os.path.isdir(tdc._net_upload_dir()) or os.listdir(tdc._net_upload_dir()) == []


def test_a_body_without_a_content_length_within_the_limit_is_analyzed(client, tmp_path):
    with open(_pcap_with_http_c2(tmp_path), "rb") as fh:
        pcap = fh.read()
    boundary = "xBOUNDARYx"
    body = (("--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"c.pcap\"\r\n"
             "Content-Type: application/octet-stream\r\n\r\n" % boundary).encode()
            + pcap + ("\r\n--%s--\r\n" % boundary).encode())
    r = client.post("/api/network/import", input_stream=io.BytesIO(body),
                    content_type=MULTIPART + "; boundary=" + boundary,
                    environ_overrides={"wsgi.input_terminated": True})
    assert r.status_code == 200 and r.get_json()["event_summary"]["http"] >= 1


# --- follow-up details ----------------------------------------------------------------------

def test_a_password_in_the_client_file_name_is_masked_before_the_name_is_cleaned(client, tmp_path):
    r = _upload(client, _pcap_with_http_c2(tmp_path), "password=Hunter2.pcap")
    rid = r.get_json()["id"]
    raw = r.data + client.get("/api/network/reports").data + client.get(
        "/api/network/report?id=" + rid).data
    assert b"Hunter2" not in raw
    assert r.get_json()["filename"].startswith("password")


def test_a_baseline_capture_says_when_its_capture_was_cut_short(client, tmp_path):
    whole = _upload(client, _pcap_with_http_c2(tmp_path), url="/api/network/baseline/capture")
    assert whole.get_json()["truncated"] is False
    cut = _upload(client, na._truncated_pcap(tmp_path), url="/api/network/baseline/capture")
    body = cut.get_json()
    assert cut.status_code == 200 and body["truncated"] is True
    assert body["added"] <= body["events_seen"] and "errors" in body and body["note"]


def test_the_rules_next_to_the_app_win_over_the_parent_directory(tdc):
    app_dir = os.path.dirname(os.path.abspath(tdc.__file__))
    candidates = tdc._net_rules_candidates()
    assert candidates[0] == os.path.join(app_dir, "rules", "network", "default.yaml")
    assert candidates[1] == os.path.join(os.path.dirname(app_dir), "rules", "network",
                                         "default.yaml")
    assert candidates[2].startswith("C:\\vagrant")


def test_the_first_rules_file_that_exists_is_used(tdc, tmp_path, monkeypatch):
    first, second = tmp_path / "a.yaml", tmp_path / "b.yaml"
    second.write_text("x")
    monkeypatch.setattr(tdc, "_net_rules_candidates", lambda: [str(first), str(second)])
    assert tdc._net_rules_file() == str(second)
    first.write_text("y")
    assert tdc._net_rules_file() == str(first)


def test_missing_rules_are_named_in_the_report_errors(client, tdc, tmp_path, monkeypatch):
    monkeypatch.setattr(tdc, "_net_rules_candidates", lambda: [str(tmp_path / "none.yaml")])
    report = _upload(client, _pcap_with_http_c2(tmp_path)).get_json()
    assert any(e.startswith("rules:") and "none.yaml" in e for e in report["errors"])
    assert report["rule_hits"] == [] and report["events"]


# --- the report of a detonation (Task 16, Ruling 64) ----------------------------------------

SAMPLE = "a1" * 32
OTHER = "b2" * 32


def _poll(client, tdc, monkeypatch, query):
    """/api/detonation/results with LitterBox, the agent, the EDRs and Sysmon away."""
    from test_api_payloads import _results_without_the_vm
    _results_without_the_vm(tdc, monkeypatch)
    r = client.get("/api/detonation/results?" + query)
    assert r.status_code == 200
    return r


def test_an_import_keeps_the_sample_it_belongs_to(client, tmp_path):
    """Regressions covered: nothing tied a report to a detonated sample, so the
    results of a detonation could never carry one. The optional field `sha256`
    is kept, lower case, on the report and its list entry; without it, None."""
    tied = _upload(client, _pcap_with_http_c2(tmp_path), "a.pcap", sha256=SAMPLE.upper()).get_json()
    loose = _upload(client, _pcap_with_http_c2(tmp_path), "b.pcap").get_json()
    assert tied["sample_sha256"] == SAMPLE and loose["sample_sha256"] is None
    rows = {r["filename"]: r for r in client.get("/api/network/reports").get_json()["reports"]}
    assert rows["a.pcap"]["sample_sha256"] == SAMPLE and rows["b.pcap"]["sample_sha256"] is None
    assert client.get("/api/network/report?id=" + tied["id"]).get_json()["sample_sha256"] == SAMPLE


@pytest.mark.parametrize("bad", ["abc", "g" * 64, SAMPLE + "0", "../" + SAMPLE[3:], SAMPLE[:63] + " x"])
def test_a_sample_hash_that_is_not_one_is_refused_and_stores_nothing(client, tdc, tmp_path, bad):
    """Regressions covered: a malformed hash would become a key of the store; it
    is a 400 that says what is wanted, before the capture is saved or analyzed."""
    r = _upload(client, _pcap_with_http_c2(tmp_path), sha256=bad)
    assert r.status_code == 400 and "sha256" in r.get_json()["error"]
    assert client.get("/api/network/reports").get_json()["reports"] == []
    upload_dir = tdc._net_upload_dir()
    assert not os.path.isdir(upload_dir) or os.listdir(upload_dir) == []


def test_the_baseline_capture_takes_no_sample(client, tdc, tmp_path):
    """Regressions covered: the baseline capture shares the upload code; a sample
    field there must neither refuse the capture nor tie anything to a sample."""
    r = _upload(client, _pcap_with_http_c2(tmp_path), url="/api/network/baseline/capture", sha256="x")
    assert r.status_code == 200
    assert tdc._net_reports.keys("netsample_") == []


def test_the_detonation_results_carry_the_newest_report_of_the_sample(client, tdc, tmp_path, monkeypatch):
    """Regressions covered: nothing set results.network, so the NETWORK panel of
    the Submit tab could never appear. The newest report imported for the sample
    is returned as stored (masked; never rebuilt), the hash in any case; another
    sample, or no sample, gets no `network` key."""
    _upload(client, _pcap_with_http_c2(tmp_path), "old.pcap", sha256=SAMPLE)
    newest = _upload(client, _pcap_with_http_c2(tmp_path), "new.pcap", sha256=SAMPLE).get_json()
    _upload(client, _pcap_with_http_c2(tmp_path), "other.pcap", sha256=OTHER)
    _upload(client, _pcap_with_http_c2(tmp_path), "loose.pcap")
    stored = client.get("/api/network/report?id=" + newest["id"]).get_json()
    got = _poll(client, tdc, monkeypatch, "sha256=%s&pid=4242" % SAMPLE).get_json()
    eventless = {k: v for k, v in stored.items() if k not in ("events", "behavior")}
    assert got["network"] == dict(eventless, event_count=len(stored["events"]))
    assert got["network"]["filename"] == "new.pcap" and stored["events"]
    assert _poll(client, tdc, monkeypatch, "sha256=" + SAMPLE.upper()).get_json()["network"]["id"] == newest["id"]
    assert _poll(client, tdc, monkeypatch, "sha256=" + OTHER).get_json()["network"]["filename"] == "other.pcap"
    assert "network" not in _poll(client, tdc, monkeypatch, "sha256=" + "c3" * 32).get_json()
    assert "network" not in _poll(client, tdc, monkeypatch, "pid=4242").get_json()
    assert "network" not in _poll(client, tdc, monkeypatch, "sha256=../etc").get_json()


def test_the_poll_finds_the_report_by_key_and_survives_a_restart(client, tdc, tmp_path, monkeypatch):
    """Regressions covered: the endpoint is polled every 5 s; finding the report
    must not list or read every stored report. It is an index from the sample
    to its newest report id, kept on disk like the reports."""
    rid = _upload(client, _pcap_with_http_c2(tmp_path), sha256=SAMPLE).get_json()["id"]
    tdc._net_reports = tdc._ResultStore(str(tmp_path / "net_results"))

    def no_scan(*a, **k):
        raise AssertionError("the poll listed the stored reports")

    looked = []
    real_lookup = tdc._net_reports.lookup
    monkeypatch.setattr(tdc._net_reports, "keys", no_scan)
    monkeypatch.setattr(tdc._net_reports, "lookup", lambda tool, **k: looked.append(tool) or real_lookup(tool, **k))
    assert _poll(client, tdc, monkeypatch, "sha256=" + SAMPLE).get_json()["network"]["id"] == rid
    assert looked == ["netsample", "netreport"]


def test_a_report_the_store_dropped_is_not_returned(client, tdc, tmp_path, monkeypatch):
    """Regressions covered: an index left behind after its report was evicted
    must not break the poll; the results simply carry no report."""
    rid = _upload(client, _pcap_with_http_c2(tmp_path), sha256=SAMPLE).get_json()["id"]
    with tdc._net_reports._lock:
        tdc._net_reports._mem.pop("netreport_" + rid)
    assert "network" not in _poll(client, tdc, monkeypatch, "sha256=" + SAMPLE).get_json()


def test_the_detonation_results_carry_no_password_of_the_report(client, tdc, tmp_path, monkeypatch):
    """Regressions covered: the report in the detonation results must be the
    masked one, like every other response of the network analysis."""
    path, secrets = _credential_capture(tmp_path)
    assert _upload(client, path, sha256=SAMPLE).status_code == 200
    raw = _poll(client, tdc, monkeypatch, "sha256=" + SAMPLE).data
    assert b'"network"' in raw
    for secret in secrets:
        assert secret.encode() not in raw, secret


def test_the_poll_carries_no_events_of_the_report(client, tdc, tmp_path, monkeypatch):
    """Regressions covered (Ruling 66): the whole report, events and all, rode
    along on every 5 s poll. The results carry it without `events` and
    `behavior`, with their number; ids, counts, findings, indicators, files
    and the status keys stay, and the stored report keeps its events."""
    rid = _upload(client, _pcap_with_http_c2(tmp_path), sha256=SAMPLE).get_json()["id"]
    net = _poll(client, tdc, monkeypatch, "sha256=" + SAMPLE).get_json()["network"]
    assert "events" not in net and "behavior" not in net
    for key in ("id", "event_summary", "evidence_findings", "iocs", "files", "observed", "note",
                "truncated", "errors", "rule_hits", "rule_unevaluated", "rule_budget_spent"):
        assert key in net, key
    stored = client.get("/api/network/report?id=" + rid).get_json()
    assert net["event_count"] == len(stored["events"]) > 0


def test_an_evicted_newest_report_falls_back_to_the_newest_still_kept(client, tdc, tmp_path, monkeypatch):
    """Regressions covered (Ruling 68): the index named only the newest report of
    a sample, so once the store dropped it the results carried none although an
    older report of the sample was still kept."""
    old = _upload(client, _pcap_with_http_c2(tmp_path), "old.pcap", sha256=SAMPLE).get_json()["id"]
    mid = _upload(client, _pcap_with_http_c2(tmp_path), "mid.pcap", sha256=SAMPLE).get_json()["id"]
    new = _upload(client, _pcap_with_http_c2(tmp_path), "new.pcap", sha256=SAMPLE).get_json()["id"]
    assert _poll(client, tdc, monkeypatch, "sha256=" + SAMPLE).get_json()["network"]["id"] == new
    with tdc._net_reports._lock:
        tdc._net_reports._mem.pop("netreport_" + new)
    assert _poll(client, tdc, monkeypatch, "sha256=" + SAMPLE).get_json()["network"]["id"] == mid
    with tdc._net_reports._lock:
        tdc._net_reports._mem.pop("netreport_" + mid)
    assert _poll(client, tdc, monkeypatch, "sha256=" + SAMPLE).get_json()["network"]["id"] == old
    # an index entry of the first version (one id) still works
    tdc._net_reports.put("netsample", {"id": old}, sha256=OTHER)
    assert _poll(client, tdc, monkeypatch, "sha256=" + OTHER).get_json()["network"]["id"] == old


def test_the_index_of_a_sample_is_bounded(client, tdc, tmp_path, monkeypatch):
    monkeypatch.setattr(tdc, "NET_REPORTS_KEEP", 2)
    ids = [_upload(client, _pcap_with_http_c2(tmp_path), sha256=SAMPLE).get_json()["id"] for _ in range(3)]
    assert tdc._net_reports.lookup("netsample", sha256=SAMPLE) == {"ids": ids[::-1][:2]}


# --- network findings in the combined verdict (Ruling 65) ----------------------------------

def _verdict_with(client, tdc, tmp_path, monkeypatch, path=None):
    if path is not None:
        assert _upload(client, path, sha256=SAMPLE).status_code == 200
    return _poll(client, tdc, monkeypatch, "sha256=%s&filename=evil.exe" % SAMPLE).get_json()


def test_without_a_report_the_verdict_is_what_it_was(client, tdc, tmp_path, monkeypatch):
    """Regressions covered: the network source changes nothing when there is no report."""
    d = _verdict_with(client, tdc, tmp_path, monkeypatch)
    assert d["verdict"]["label"] == "CLEAN" and d["verdict"]["score"] == 0
    assert "memory_evidence" not in d and "network" not in d


def test_an_hour_of_ordinary_traffic_keeps_the_verdict_clean(client, tdc, tmp_path, monkeypatch):
    """Regressions covered: a benign capture must not raise the verdict; it is a
    source that was looked at (sources_present), and nothing scores."""
    from test_net_default_rules import _benign_capture
    monkeypatch.setattr(Capture, "read", lambda self: self)
    d = _verdict_with(client, tdc, tmp_path, monkeypatch, _write(tmp_path, _benign_capture(), "hour.pcap"))
    assert d["verdict"]["label"] == "CLEAN" and d["verdict"]["score"] == 0
    assert d["memory_evidence"]["sources_present"] == ["network"]
    assert d["memory_evidence"]["label"] == "CLEAN"


def test_a_c2_capture_raises_the_combined_verdict(client, tdc, tmp_path, monkeypatch):
    """Regressions covered: "network findings in the common verdict" was promised
    for Phase 1 and nothing fed them in. The report's findings score with source
    "network" in the same memory evidence the verdict folds in."""
    cap = Capture()
    na._http_c2(cap)
    cap.get(50.0, "stage.top", "/a.bin", na._pe(), "application/octet-stream")
    d = _verdict_with(client, tdc, tmp_path, monkeypatch, _write(tmp_path, cap, "c2.pcap"))
    ev = d["memory_evidence"]
    assert ev["sources_present"] == ["network"]
    assert sorted(f["kind"] for f in ev["findings"]) == ["c2_checkin", "payload_staging"]
    assert all(f["source"] == "network" for f in ev["findings"])
    assert ev["label"] == "SUSPICIOUS" and ev["score"] == 5.6
    assert d["verdict"]["label"] == "SUSPICIOUS" and d["verdict"]["score"] == 2


def test_a_lone_check_in_without_a_second_signal_does_not_raise_the_verdict(client, tdc, tmp_path, monkeypatch):
    """Regressions covered (Ruling 51): a capture knows no process, so a check-in
    on its own needs a host-side second opinion; uncorroborated it is listed
    (scored down) but leaves the verdict clean."""
    d = _verdict_with(client, tdc, tmp_path, monkeypatch, _pcap_with_http_c2(tmp_path))
    ev = d["memory_evidence"]
    assert [f["kind"] for f in ev["findings"]] == ["c2_checkin"] and ev["score"] == 1.6
    assert ev["label"] == "CLEAN" and d["verdict"]["label"] == "CLEAN"


def test_scoring_does_not_write_into_the_stored_report(client, tdc, tmp_path, monkeypatch):
    """Regressions covered: the store hands out its own dicts; the verdict's
    scoring must work on copies of the findings."""
    rid = _upload(client, _pcap_with_http_c2(tmp_path), sha256=SAMPLE).get_json()["id"]
    before = json.dumps(tdc._net_reports.lookup("netreport", sha256=rid), sort_keys=True)
    _poll(client, tdc, monkeypatch, "sha256=" + SAMPLE)
    _poll(client, tdc, monkeypatch, "sha256=" + SAMPLE)
    assert json.dumps(tdc._net_reports.lookup("netreport", sha256=rid), sort_keys=True) == before


def test_findings_marked_baseline_stay_out_of_the_verdict(tdc):
    results = {"network": {"evidence_findings": [
        {"source": "network", "kind": "exfil_upload", "baseline": "known", "key": "k1"},
        {"source": "network", "kind": "dga_pattern", "key": "k2"}]}}
    assert [f["kind"] for f in tdc.memory_evidence.collect(results)] == ["dga_pattern"]


def _verdict_with_sysmon_beacon(client, tdc, monkeypatch, beacon_process="evil.exe", ip="198.51.100.100"):
    """/api/detonation/results for PID 4242 whose Sysmon connection log beacons
    8 x 60 s to ip:80 from beacon_process (None: no Sysmon beacon at all)."""
    from test_api_payloads import _results_without_the_vm
    _results_without_the_vm(tdc, monkeypatch)
    if beacon_process is not None:
        conns = [(1000.0 + 60 * i, ip, 80) for i in range(8)]
        findings = tdc.memory_evidence.beaconing_from_connections(conns, process=beacon_process)
        monkeypatch.setattr(tdc, "_network_beaconing_for_pid",
                            lambda pid: {"available": True, "evidence_findings": findings})
    r = client.get("/api/detonation/results?sha256=%s&pid=4242&filename=evil.exe" % SAMPLE)
    assert r.status_code == 200
    return r.get_json()


def test_a_sysmon_beacon_and_the_captures_check_in_count_once_and_corroborate(client, tdc, tmp_path, monkeypatch):
    """Regressions covered: the capture's findings came without a process, while
    supersede and corroboration match by process, so the Sysmon beacon of the
    sample and the check-in of its capture - one loop - were both counted
    (3.0 + 1.6, nothing superseded). They are attributed to the sample's
    process (the one Sysmon saw for its PID): the check-in absorbs the beacon
    and is corroborated by it."""
    assert _upload(client, _pcap_with_http_c2(tmp_path), sha256=SAMPLE).status_code == 200
    d = _verdict_with_sysmon_beacon(client, tdc, monkeypatch)
    ev = d["memory_evidence"]
    assert [(f["kind"], f["process"]) for f in ev["findings"]] == [("c2_checkin", "evil.exe")]
    checkin = ev["findings"][0]
    assert checkin["corroborated_by"] == ["sysmon-network"]
    assert [(f["kind"], f.get("superseded_by") is not None) for f in ev["suppressed"]] == [("c2_beaconing", True)]
    assert ev["score"] == 4.0
    # the stored report keeps its findings as they were imported
    stored = client.get("/api/network/reports").get_json()["reports"][0]["id"]
    assert all(f["process"] == "" for f in
               client.get("/api/network/report?id=" + stored).get_json()["evidence_findings"])


def test_without_a_host_side_signal_the_check_in_still_needs_one(client, tdc, tmp_path, monkeypatch):
    """Ruling 51 is not loosened: with nothing of the sample's own on the host,
    the attributed check-in stays uncorroborated (1.6) and the verdict clean."""
    assert _upload(client, _pcap_with_http_c2(tmp_path), sha256=SAMPLE).status_code == 200
    d = _verdict_with_sysmon_beacon(client, tdc, monkeypatch, beacon_process=None)
    ev = d["memory_evidence"]
    assert [f["kind"] for f in ev["findings"]] == ["c2_checkin"] and ev["score"] == 1.6
    assert d["verdict"]["label"] == "CLEAN"


def test_a_finding_that_names_its_process_keeps_it(tdc):
    results = {"network": {"evidence_findings": [
        {"source": "network", "kind": "dga_pattern", "key": "k", "process": "other.exe"},
        {"source": "network", "kind": "dga_pattern", "key": "k2", "process": ""}]}}
    got = tdc.memory_evidence.collect(results, process="", network_process="evil.exe")
    assert [f["process"] for f in got] == ["other.exe", "evil.exe"]
    assert [f["process"] for f in tdc.memory_evidence.collect(results, process="Evil.exe")] == ["other.exe", "Evil.exe"]


# --- Ruling 69: an assumed process corroborates only through a shared endpoint --------------

def _reflective_pe(tdc, process):
    return dict(tdc.memory_evidence.MemoryFinding(source="aether", kind="reflective_pe", process=process,
                                                  identity=("r",)))


def _checkin(tdc):
    """A capture's check-in as net_evidence makes it: no process, no pid."""
    return dict(tdc.memory_evidence.MemoryFinding(
        source="network", kind="c2_checkin", process="", identity=("evil.top",),
        extra={"dest": "evil.top", "addresses": ["198.51.100.100"], "pid": None}))


def test_a_beacon_to_another_address_does_not_vouch_for_the_check_in(client, tdc, tmp_path, monkeypatch):
    """Regressions covered (Ruling 69): once the capture's findings were given the
    sample's process, any substantial host finding of the sample corroborated
    them, about any endpoint: a check-in to evil.top and a Sysmon beacon of
    evil.exe to 203.0.113.9 went from 4.6 SUSPICIOUS to 7.0 MALICIOUS. The
    attributed check-in is marked "assumed" and is corroborated only through a
    shared endpoint; the two are two findings, neither superseded."""
    assert _upload(client, _pcap_with_http_c2(tmp_path), sha256=SAMPLE).status_code == 200
    d = _verdict_with_sysmon_beacon(client, tdc, monkeypatch, ip="203.0.113.9")
    ev = d["memory_evidence"]
    by_kind = {f["kind"]: f for f in ev["findings"]}
    assert set(by_kind) == {"c2_beaconing", "c2_checkin"} and ev["suppressed"] == []
    assert by_kind["c2_checkin"]["attribution"] == "assumed" and by_kind["c2_checkin"]["process"] == "evil.exe"
    assert not by_kind["c2_checkin"].get("corroborated_by")
    assert ev["score"] == 4.6 and d["verdict"]["label"] == "SUSPICIOUS"


def test_a_reflective_pe_of_the_sample_does_not_vouch_for_the_check_in(tdc):
    """Regressions covered (Ruling 69): a check-in attributed to evil.exe (the
    agent names the process) and a reflective PE in evil.exe: 4.6 -> 7.0 after
    the attribution, back to 4.6 - a reflective PE says nothing about evil.top."""
    results = {"agent": {"execution": {"process_name": "evil.exe"}},
               "aether": {"evidence_findings": [_reflective_pe(tdc, "evil.exe")]},
               "network": {"evidence_findings": [_checkin(tdc)]}}
    verdict = tdc._compute_verdict(results, [])
    ev = results["memory_evidence"]
    checkin = [f for f in ev["findings"] if f["kind"] == "c2_checkin"][0]
    assert checkin["attribution"] == "assumed" and not checkin.get("corroborated_by")
    assert ev["score"] == 4.6 and verdict["label"] == "SUSPICIOUS"
    # a finding of the same endpoint, of any process, still vouches for it
    results.pop("memory_evidence")
    results["network_beaconing"] = {"evidence_findings": tdc.memory_evidence.beaconing_from_connections(
        [(1000.0 + 60 * i, "198.51.100.100", 80) for i in range(8)], process="other.exe")}
    tdc._compute_verdict(results, [])
    checkin = [f for f in results["memory_evidence"]["findings"] if f["kind"] == "c2_checkin"][0]
    assert checkin["corroborated_by"] == ["sysmon-network"]


def test_a_finding_with_a_process_or_a_pid_is_not_assumed(tdc):
    results = {"network": {"evidence_findings": [
        {"source": "network", "kind": "dga_pattern", "key": "a", "process": "x.exe"},
        {"source": "network", "kind": "dga_pattern", "key": "b", "process": "", "pid": 77},
        {"source": "network", "kind": "dga_pattern", "key": "c", "process": ""}]}}
    got = tdc.memory_evidence.collect(results, network_process="evil.exe")
    assert [(f["process"], f.get("attribution")) for f in got] == [
        ("x.exe", None), ("", None), ("evil.exe", "assumed")]
    assert [f.get("attribution") for f in tdc.memory_evidence.collect(results)] == [None, None, None]


def test_the_owner_is_never_a_child_seen_on_the_named_pipes(tdc):
    """Regressions covered: the named pipes cover the sample's whole process
    subtree, so the owner taken from them could be a child. Only the root
    PID's own image (its Sysmon connections) or the named process counts."""
    pipe = dict(tdc.memory_evidence.MemoryFinding(source="sysmon-pipes", kind="pipe_c2_default",
                                                  process="child.exe", identity=("p",)))
    results = {"named_pipes": {"evidence_findings": [pipe]}, "network": {"evidence_findings": [_checkin(tdc)]}}
    tdc._compute_verdict(results, [])
    got = [f for f in results["memory_evidence"]["findings"] + results["memory_evidence"]["suppressed"]
           if f["kind"] == "c2_checkin"][0]
    assert got["process"] == "" and "attribution" not in got
