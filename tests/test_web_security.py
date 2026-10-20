"""Browser-borne attacks and file access.

Regressions covered:
  * cross-site POSTs (CSRF) to /api/submit and friends
  * DNS rebinding: a foreign host name pointed at the VM could read responses
  * /api/file/hex/write accepted all of C:\\Users (Startup folders) and untyped input
  * proxied LitterBox/agent HTML was served on this origin
  * a proxied request could proxy itself again (fallback VM address = this instance)
"""

import os
import tempfile

import pytest


UNSAFE = "/api/scan/history/clear"


@pytest.mark.parametrize("headers, status", [
    ({}, 200),                                            # curl, MCP, scripts
    ({"Origin": "http://localhost"}, 200),                # the UI itself
    ({"Origin": "http://evil.example"}, 403),
    ({"Referer": "http://evil.example/page"}, 403),
    ({"Origin": "null"}, 403),                            # sandboxed iframe, file://
])
def test_cross_site_post_is_refused(client, tdc, monkeypatch, headers, status):
    monkeypatch.setattr(tdc, "_save_scan_history", lambda h: None)
    assert client.post(UNSAFE, headers=headers).status_code == status


def test_submit_from_foreign_origin_is_refused(client):
    assert client.post("/api/submit", headers={"Origin": "http://evil.example"}).status_code == 403


@pytest.mark.parametrize("host, status", [
    ("192.168.64.4:9000", 200),
    ("localhost:9000", 200),
    ("[::1]:9000", 200),
    ("evil.example:9000", 403),
    ("evil.example", 403),
])
def test_host_header_allowlist(client, host, status):
    assert client.get("/api/health", headers={"Host": host}).status_code == status


def test_allowed_host_names_can_be_added(tdc, client, monkeypatch):
    monkeypatch.setattr(tdc, "_ALLOWED_HOSTNAMES", tdc._ALLOWED_HOSTNAMES | {"tdc.lab"})
    assert client.get("/api/health", headers={"Host": "tdc.lab:9000"}).status_code == 200


def test_security_headers(client):
    h = client.get("/api/health").headers
    assert h["X-Frame-Options"] == "DENY"
    assert h["X-Content-Type-Options"] == "nosniff"
    assert "frame-ancestors 'none'" in h["Content-Security-Policy"]


@pytest.fixture
def hex_file():
    folder = os.path.join(tempfile.gettempdir(), "hex_uploads")
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, "pytest_sample.bin")
    with open(path, "wb") as f:
        f.write(b"\0" * 64)
    yield path
    os.unlink(path)


@pytest.mark.parametrize("body, status", [
    ({"offset": 2, "bytes": [0x4D, 0x5A]}, 200),
    ({"offset": "2", "bytes": [1]}, 400),
    ({"offset": -1, "bytes": [1]}, 400),
    ({"offset": 0, "bytes": [256]}, 400),
    ({"offset": 0, "bytes": [True]}, 400),
    ({"offset": 63, "bytes": [1, 2]}, 400),             # past the end of the file
])
def test_hex_write_validates_input(client, hex_file, body, status):
    assert client.post("/api/file/hex/write", json=dict(body, path=hex_file)).status_code == status


def test_hex_write_only_in_analysis_folders(client, tmp_path, hex_file):
    outside = tmp_path / "startup.bin"
    outside.write_bytes(b"\0" * 8)
    assert client.post("/api/file/hex/write",
                       json={"path": str(outside), "offset": 0, "bytes": [1]}).status_code == 403
    script = os.path.join(os.path.dirname(hex_file), "x.ps1")
    assert client.post("/api/file/hex/write",
                       json={"path": script, "offset": 0, "bytes": [1]}).status_code == 403


class _Resp:
    def __init__(self, ctype):
        self.headers, self.content, self.status_code = {"Content-Type": ctype}, b"<script>", 200


@pytest.mark.parametrize("ctype, served", [
    ("text/html; charset=utf-8", "text/plain; charset=utf-8"),
    ("image/svg+xml", "text/plain; charset=utf-8"),
    ("application/xhtml+xml", "text/plain; charset=utf-8"),
    ("TEXT/HTML", "text/plain; charset=utf-8"),
    ("application/json", "application/json"),
])
def test_proxied_responses_never_render_as_pages(tdc, ctype, served):
    _, _, headers = tdc._proxied(_Resp(ctype))
    assert headers["Content-Type"] == served
    assert headers["Content-Security-Policy"].startswith("sandbox")


def test_downloads_are_attachments_in_a_sandbox(tdc, client, monkeypatch, tmp_path):
    f = tmp_path / "evil.html"
    f.write_text("<script>alert(1)</script>")
    monkeypatch.setattr(tdc, "_path_within", lambda p, roots: True)
    r = client.get(f"/api/file/download?path={f}")
    assert r.status_code == 200
    assert r.mimetype == "application/octet-stream"
    assert r.headers["Content-Disposition"].startswith("attachment")
    assert "sandbox" in r.headers["Content-Security-Policy"]


def test_proxied_request_is_not_proxied_again(tdc):
    with tdc.app.test_request_context("/api/sysmon", headers={"X-TDC-Proxied": "1"}):
        with pytest.raises(RuntimeError):
            tdc._vm_get("/api/sysmon", timeout=1)


def test_path_within_rejects_siblings_traversal_and_links(tdc, tmp_path):
    root = tmp_path / "Temp"
    (root / "sub").mkdir(parents=True)
    sibling = tmp_path / "TempX"
    sibling.mkdir()
    (root / "link").symlink_to(sibling, target_is_directory=True)
    roots = [str(root)]
    assert tdc._path_within(str(root / "sub" / "a.bin"), roots)
    assert not tdc._path_within(str(sibling / "a.bin"), roots)
    assert not tdc._path_within(str(root / ".." / "TempX" / "a.bin"), roots)
    assert not tdc._path_within(str(root / "link" / "a.bin"), roots)    # junction/symlink out
