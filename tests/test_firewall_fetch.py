"""The guarded fetch (webui/firewall_fetch.py), against real sockets.

The API tests (``tests/test_firewall_api.py``) put a fake connection in front of this module, so they test the
policy around a fetch and never its own socket code. That is where the property that matters most lives -
"TDC connects to the address it observed and resolves no name" - plus the deadline for the whole fetch, which a
fake can neither keep nor break. So everything here runs against a server on ``127.0.0.1``: one that answers,
one that drips bytes, one that speaks TLS with a throwaway certificate.

``tests/samples/firewall/test-only-tls-key-and-cert.pem`` is a self-signed key and certificate for
``stage.example.net``, made for these tests alone and good for nothing else: the fetch does not check
certificates (the peer is a suspected C2), and the test only wants to see which name the handshake carries.
"""

import os
import socket
import ssl
import threading
import time

import pytest

import firewall_fetch as fetcher

CERT = os.path.join(os.path.dirname(__file__), "samples", "firewall", "test-only-tls-key-and-cert.pem")
HOST = "stage.example.net"
ALLOW_ALL = (lambda ip: None)       # the address policy is tested on its own below; loopback is refused there


class Server(threading.Thread):
    """A TCP server on 127.0.0.1 that answers every request with what ``handler`` writes."""

    def __init__(self, handler, tls=False):
        super().__init__(daemon=True)
        self.handler, self.requests, self.sni = handler, [], []
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(4)
        self.port = self.listener.getsockname()[1]
        self.context = None
        if tls:
            self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.context.load_cert_chain(CERT)
            self.context.sni_callback = lambda sock, name, ctx: self.sni.append(name)
        self.start()

    def run(self):
        while True:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        try:
            if self.context is not None:
                conn = self.context.wrap_socket(conn, server_side=True)
            conn.settimeout(10)
            data = b""
            while b"\r\n\r\n" not in data:
                part = conn.recv(4096)
                if not part:
                    break
                data += part
            self.requests.append(data.decode("latin-1"))
            self.handler(conn)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def close(self):
        try:
            self.listener.close()
        except OSError:
            pass


@pytest.fixture
def serve():
    """Start servers and shut them down with the test."""
    started = []

    def start(handler, tls=False):
        server = Server(handler, tls)
        started.append(server)
        return server
    yield start
    for server in started:
        server.close()


@pytest.fixture
def lookups(monkeypatch):
    """Every name ``socket.getaddrinfo`` is asked for (a fetch may only ever ask for the literal)."""
    seen = []
    real = socket.getaddrinfo

    def watching(host, *args, **kwargs):
        seen.append(host)
        return real(host, *args, **kwargs)
    monkeypatch.setattr(socket, "getaddrinfo", watching)
    return seen


def answer(body=b"MZ\x90\x00stage two", status="200 OK", headers=(), length=None):
    def handler(conn):
        head = [f"HTTP/1.1 {status}"] + [f"{k}: {v}" for k, v in headers]
        head.append(f"Content-Length: {len(body) if length is None else length}")
        conn.sendall(("\r\n".join(head) + "\r\n\r\n").encode("ascii") + body)
    return handler


def drip(head=b"HTTP/1.1 200 OK\r\n", pause=0.05, count=2000):
    """A server that sends ``head`` and then one byte at a time, for ever.

    This is the shape that a per-``recv`` timeout cannot stop: every single read arrives in time while the
    fetch never ends.
    """
    def handler(conn):
        conn.sendall(head)
        for _ in range(count):
            try:
                conn.sendall(b"X")
            except OSError:
                return
            time.sleep(pause)
    return handler


def staging(tmp_path):
    folder = tmp_path / fetcher.STAGING
    return sorted(os.listdir(folder)) if folder.is_dir() else []


# ---- the address is the one that was observed, and no name is resolved -----------------------


def test_the_fetch_goes_to_the_address_and_only_names_the_host_in_the_request(serve, lookups, tmp_path):
    server = serve(answer())
    out = fetcher.fetch(f"http://{HOST}:{server.port}/a.dll", "127.0.0.1", server.port,
                        capture_dir=str(tmp_path), refuse=ALLOW_ALL, timeout=10)
    assert out["sha256"] and out["size"] == len(b"MZ\x90\x00stage two") and out["magic"] == "MZ"
    assert open(out["path"], "rb").read() == b"MZ\x90\x00stage two"
    request = server.requests[0]
    assert request.startswith("GET /a.dll HTTP/1.1\r\n")
    assert f"Host: {HOST}:{server.port}\r\n" in request
    assert HOST not in lookups and set(lookups) <= {"127.0.0.1"}


def test_a_name_as_the_destination_is_refused_before_a_socket_is_opened(lookups):
    with pytest.raises(fetcher.FetchError):
        fetcher.pinned_connection("http", HOST, 80, HOST, 1)
    assert lookups == []


def test_the_tls_handshake_carries_the_url_host_as_sni(serve, lookups, tmp_path):
    server = serve(answer(), tls=True)
    out = fetcher.fetch(f"https://{HOST}:{server.port}/a.dll", "127.0.0.1", server.port,
                        capture_dir=str(tmp_path), refuse=ALLOW_ALL, timeout=10)
    assert out["sha256"] and server.sni == [HOST]              # the certificate itself is deliberately not checked
    assert f"Host: {HOST}:{server.port}" in server.requests[0]
    assert HOST not in lookups


def test_an_address_in_the_url_sends_no_sni(serve, tmp_path):
    server = serve(answer(), tls=True)
    out = fetcher.fetch(f"https://127.0.0.1:{server.port}/a.dll", "127.0.0.1", server.port,
                        capture_dir=str(tmp_path), refuse=ALLOW_ALL, timeout=10)
    assert out["sha256"] and server.sni == [None]


def test_a_redirect_is_followed_on_the_same_address(serve, lookups, tmp_path):
    hops = []

    def handler(conn):
        hops.append(len(hops))
        if len(hops) == 1:
            conn.sendall(b"HTTP/1.1 302 Found\r\nLocation: /real/a.dll\r\nContent-Length: 0\r\n\r\n")
        else:
            answer()(conn)
    server = serve(handler)
    out = fetcher.fetch(f"http://{HOST}:{server.port}/a.dll", "127.0.0.1", server.port,
                        capture_dir=str(tmp_path), refuse=ALLOW_ALL, timeout=10)
    assert out["redirects"] == 1 and out["sha256"]
    assert [r.split(" ")[1] for r in server.requests] == ["/a.dll", "/real/a.dll"]
    assert HOST not in lookups


# ---- one deadline for the whole fetch -------------------------------------------------------


def test_a_server_that_drips_its_headers_cannot_hold_the_fetch(serve, tmp_path):
    server = serve(drip())
    started = time.monotonic()
    with pytest.raises(fetcher.FetchError) as e:
        fetcher.fetch(f"http://{HOST}:{server.port}/a.dll", "127.0.0.1", server.port,
                      capture_dir=str(tmp_path), refuse=ALLOW_ALL, timeout=0.5)
    took = time.monotonic() - started
    assert str(e.value) == "timed out" and took < 5           # not 2000 x 0.05 s
    assert staging(tmp_path) == []


def test_a_server_that_drips_its_body_cannot_hold_the_fetch(serve, tmp_path):
    server = serve(drip(head=b"HTTP/1.1 200 OK\r\nContent-Length: 2000\r\n\r\n"))
    started = time.monotonic()
    with pytest.raises(fetcher.FetchError) as e:
        fetcher.fetch(f"http://{HOST}:{server.port}/a.dll", "127.0.0.1", server.port,
                      capture_dir=str(tmp_path), refuse=ALLOW_ALL, timeout=0.5)
    took = time.monotonic() - started
    assert str(e.value) == "timed out" and took < 5
    assert staging(tmp_path) == []                            # the part that arrived is gone


def test_a_slow_server_that_stays_inside_the_deadline_is_fetched(serve, tmp_path):
    def handler(conn):
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n")
        for byte in (b"M", b"Z", b"\x00", b"\x00"):
            conn.sendall(byte)
            time.sleep(0.05)
    server = serve(handler)
    out = fetcher.fetch(f"http://{HOST}:{server.port}/a.dll", "127.0.0.1", server.port,
                        capture_dir=str(tmp_path), refuse=ALLOW_ALL, timeout=10)
    assert out["size"] == 4 and out["magic"] == "MZ"


def test_a_body_that_stops_short_of_its_length_is_not_a_capture(serve, tmp_path):
    server = serve(answer(body=b"MZ", length=99))
    with pytest.raises(fetcher.FetchError) as e:
        fetcher.fetch(f"http://{HOST}:{server.port}/a.dll", "127.0.0.1", server.port,
                      capture_dir=str(tmp_path), refuse=ALLOW_ALL, timeout=10)
    assert "stopped short" in str(e.value) and staging(tmp_path) == []


def test_the_size_limit_stops_a_body_that_declares_nothing(serve, tmp_path):
    def handler(conn):
        conn.sendall(b"HTTP/1.1 200 OK\r\n\r\n" + b"A" * 5000)
    server = serve(handler)
    with pytest.raises(fetcher.FetchError) as e:
        fetcher.fetch(f"http://{HOST}:{server.port}/a.dll", "127.0.0.1", server.port,
                      capture_dir=str(tmp_path), refuse=ALLOW_ALL, timeout=10, max_bytes=1000, chunk=256)
    assert str(e.value) == "too large" and staging(tmp_path) == []


def test_a_declared_size_over_the_limit_is_refused_before_the_body_is_read(serve, tmp_path):
    server = serve(answer(body=b"A" * 10, length=10 ** 9))
    with pytest.raises(fetcher.FetchError) as e:
        fetcher.fetch(f"http://{HOST}:{server.port}/a.dll", "127.0.0.1", server.port,
                      capture_dir=str(tmp_path), refuse=ALLOW_ALL, timeout=10, max_bytes=1000)
    assert str(e.value) == "too large" and staging(tmp_path) == []


def test_a_server_that_says_nothing_is_a_protocol_error_not_a_capture(serve, tmp_path):
    server = serve(lambda conn: conn.close())
    with pytest.raises(fetcher.FetchError) as e:
        fetcher.fetch(f"http://{HOST}:{server.port}/a.dll", "127.0.0.1", server.port,
                      capture_dir=str(tmp_path), refuse=ALLOW_ALL, timeout=10)
    assert "protocol error" in str(e.value)


def test_a_refused_connection_is_a_network_error(tmp_path):
    free = socket.socket()
    free.bind(("127.0.0.1", 0))
    port = free.getsockname()[1]
    free.close()
    with pytest.raises(fetcher.FetchError) as e:
        fetcher.fetch(f"http://{HOST}:{port}/a.dll", "127.0.0.1", port,
                      capture_dir=str(tmp_path), refuse=ALLOW_ALL, timeout=5)
    assert "network" in str(e.value) or str(e.value) == "timed out"


class _Late:
    """A connection whose read ends the way a TLS socket does when the watchdog shut it down mid-read."""

    io_sock = None

    def __init__(self, pause, error):
        self.pause, self.error = pause, error

    def connect(self):
        pass

    def request(self, method, target, headers=None):
        pass

    def getresponse(self):
        time.sleep(self.pause)
        raise self.error

    def close(self):
        pass


def test_a_tls_socket_the_watchdog_shut_down_is_a_timeout_not_a_valueerror(tmp_path):
    late = _Late(0.2, ValueError("Read on closed or unwrapped SSL socket"))
    with pytest.raises(fetcher.FetchError) as e:
        fetcher.fetch(f"https://{HOST}/a.dll", "203.0.113.5", 443, capture_dir=str(tmp_path),
                      refuse=ALLOW_ALL, timeout=0.1, connect=lambda *a: late)
    assert str(e.value) == "timed out"


def test_a_valueerror_that_is_not_the_clock_is_not_dressed_up_as_a_timeout(tmp_path):
    early = _Late(0, ValueError("something else entirely"))
    with pytest.raises(ValueError) as e:
        fetcher.fetch(f"https://{HOST}/a.dll", "203.0.113.5", 443, capture_dir=str(tmp_path),
                      refuse=ALLOW_ALL, timeout=10, connect=lambda *a: early)
    assert "something else" in str(e.value)


def test_a_budget_that_is_already_spent_asks_nothing(tmp_path):
    asked = []
    with pytest.raises(fetcher.FetchError) as e:
        fetcher.fetch(f"http://{HOST}/a.dll", "203.0.113.5", 80, capture_dir=str(tmp_path), refuse=ALLOW_ALL,
                      timeout=-5, connect=lambda *a: asked.append(a))
    assert str(e.value) == "timed out" and asked == []


# ---- the URL is held to the endpoint --------------------------------------------------------


@pytest.mark.parametrize("url, why", [
    ("http://198.51.100.1:8080/a.dll", "another address"),
    ("http://host:9999/a.dll", "another port"),
    ("https://host:8080/a.dll", "scheme"),
    ("ftp://host:8080/a.dll", "http(s)"),
    ("http://host:8080/a dll", "cannot be sent"),
    ("x" * 9000, "no usable URL"),
    (None, "no usable URL"),
])
def test_a_url_that_leaves_the_observed_endpoint_is_refused(url, why):
    with pytest.raises(fetcher.FetchError) as e:
        fetcher.target_of(url, "203.0.113.50", 8080, "http")
    assert why in str(e.value)


def test_the_first_hop_sets_the_port_and_the_scheme_when_they_are_unknown():
    assert fetcher.target_of("https://host/a.dll", "203.0.113.50") == ("https", "host", 443, "/a.dll")
    assert fetcher.target_of("http://host/a?b=1", "203.0.113.50") == ("http", "host", 80, "/a?b=1")
    assert fetcher.target_of("http://user:pw@host:8080/a", "203.0.113.50", 8080)[1] == "host"


@pytest.mark.parametrize("scheme, host, port, want", [
    ("http", "h", 80, "h"), ("http", "h", 8080, "h:8080"), ("https", "h", 443, "h"),
    ("https", "h", 80, "h:80"), ("http", "h", 443, "h:443"),
    ("http", "2001:db8::1", 80, "[2001:db8::1]"), ("https", "2001:db8::1", 8443, "[2001:db8::1]:8443"),
])
def test_the_host_header_brackets_ipv6_and_keeps_a_port_that_is_not_the_default(scheme, host, port, want):
    assert fetcher.host_header(scheme, host, port) == want


# ---- which addresses TDC will fetch from ----------------------------------------------------


OWN = frozenset({"192.168.64.129", "192.168.64.1"})


@pytest.mark.parametrize("ip", ["127.0.0.1", "::1", "::ffff:127.0.0.1", "0.0.0.0", "224.0.0.1",
                                "169.254.169.254", "240.0.0.1", "not-an-ip", "", None])
def test_the_vms_own_side_is_refused(ip):
    assert fetcher.refuse_address(ip, own=OWN)


@pytest.mark.parametrize("ip", ["192.168.64.129", "192.168.64.1", "::ffff:192.168.64.1"])
def test_this_machines_own_addresses_and_gateways_are_refused_even_on_the_lan(ip):
    assert "own address or its gateway" in fetcher.refuse_address(ip, allow_lan=True, own=OWN)


@pytest.mark.parametrize("ip", ["10.1.2.3", "172.16.5.5", "192.168.1.9", "100.64.0.1", "fd00::1"])
def test_a_private_address_is_refused_unless_the_lab_says_otherwise(ip):
    assert "TDC_FIREWALL_FETCH_LAN" in fetcher.refuse_address(ip, own=OWN)
    assert fetcher.refuse_address(ip, allow_lan=True, own=OWN) is None


@pytest.mark.parametrize("ip", ["203.0.113.50", "8.8.8.8", "2001:db8::1", "::ffff:203.0.113.50"])
def test_a_public_address_is_allowed(ip):
    assert fetcher.refuse_address(ip, own=OWN) is None


def test_the_fetch_itself_asks_the_policy_first(tmp_path, lookups):
    with pytest.raises(fetcher.FetchError) as e:
        fetcher.fetch("http://127.0.0.1:9000/a.dll", "127.0.0.1", 9000, capture_dir=str(tmp_path))
    assert "refused" in str(e.value) and lookups == []


WINDOWS_ROUTES = """\
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0     192.168.64.1    192.168.64.129     25
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
"""

MAC_ROUTES = """\
Routing tables

Internet:
Destination        Gateway            Flags        Netif Expire
default            192.168.1.254      UGScg          en0
127                127.0.0.1          UCS            lo0
"""

LINUX_ROUTES = """\
Kernel IP routing table
Destination     Gateway         Genmask         Flags   MSS Window  irtt Iface
0.0.0.0         10.0.2.2        0.0.0.0         UG        0 0          0 eth0
10.0.2.0        0.0.0.0         255.255.255.0   U         0 0          0 eth0
"""


@pytest.mark.parametrize("text, want", [(WINDOWS_ROUTES, {"192.168.64.1"}), (MAC_ROUTES, {"192.168.1.254"}),
                                        (LINUX_ROUTES, {"10.0.2.2"}), ("", set()), ("junk\n0.0.0.0 nope", set())])
def test_the_default_gateway_is_read_from_the_route_table(text, want):
    assert fetcher.gateways_from(text) == want


def test_the_own_addresses_are_remembered_and_a_box_that_answers_neither_is_empty(monkeypatch):
    calls = []
    monkeypatch.setattr(fetcher, "_own_cache", (0.0, frozenset()))
    monkeypatch.setattr(fetcher, "_interface_addresses", lambda: calls.append("if") or {"203.0.113.9"})
    monkeypatch.setattr(fetcher, "_gateways", lambda: calls.append("gw") or {"203.0.113.1"})
    assert fetcher.own_addresses() == frozenset({"203.0.113.9", "203.0.113.1"})
    assert fetcher.own_addresses() == frozenset({"203.0.113.9", "203.0.113.1"}) and calls == ["if", "gw"]
    monkeypatch.setattr(fetcher, "_own_cache", (0.0, frozenset()))
    monkeypatch.setattr(fetcher, "_interface_addresses", lambda: 1 / 0)
    monkeypatch.setattr(fetcher, "_gateways", lambda: (_ for _ in ()).throw(OSError("no route")))
    assert fetcher.own_addresses() == frozenset()


def test_this_machines_real_addresses_are_found_and_are_addresses(monkeypatch):
    monkeypatch.setattr(fetcher, "_own_cache", (0.0, frozenset()))
    found = fetcher.own_addresses(refresh=True)
    assert all(fetcher.is_ip_literal(a) for a in found)
    assert not any(a.startswith("127.") for a in found)       # loopback is refused by its own rule


# ---- what is left over ----------------------------------------------------------------------


def test_the_staging_folder_is_emptied_but_the_captures_are_kept(tmp_path):
    incoming = tmp_path / fetcher.STAGING
    incoming.mkdir()
    (incoming / "tmp1").write_bytes(b"half a payload")
    (incoming / "tmp2").write_bytes(b"another half")
    (incoming / "folder").mkdir()
    (tmp_path / "ab").mkdir()
    (tmp_path / "ab" / "abcd").write_bytes(b"a capture")
    assert fetcher.clear_staging(str(tmp_path)) == 2
    assert os.listdir(incoming) == ["folder"] and (tmp_path / "ab" / "abcd").exists()
    assert fetcher.clear_staging(str(tmp_path)) == 0
    assert fetcher.clear_staging(str(tmp_path / "nothing-here")) == 0


@pytest.mark.parametrize("head, magic", [(b"MZ\x90", "MZ"), (b"\x7fELFx", "ELF"), (b"PK\x03\x04", "PK"),
                                         (b"#!/bin/sh", "#!"), (b"%PDF-1.7", "PDF"), (b"hello ok", "text"),
                                         (b"\x00\x01\x02", "unknown"), (b"", "unknown")])
def test_the_magic_comes_from_the_first_bytes(head, magic):
    assert fetcher.magic_of(head) == magic


@pytest.mark.parametrize("value, want", [("Mozilla/5.0", "Mozilla/5.0"), ("a\r\nX: y", None), ("Ü", None),
                                         ("", None), ("a" * 400, None), (None, None), (5, None)])
def test_a_header_value_that_could_split_a_header_is_not_used(value, want):
    assert fetcher.clean_header_text(value) == want
