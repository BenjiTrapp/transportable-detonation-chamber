r"""The guarded fetch of the FIREWALL tab: get the file a loader wanted, and nothing else.

When a detonated loader fetches its second stage, TDC blocks the loader and fetches the file itself, so the
sample is preserved and never runs. That makes this the one place in the web UI that deliberately contacts a
suspected C2, so everything here is about bounding what that contact can do:

* **One address, no name resolution.** The connection goes to the address the sample was seen talking to; the
  URL's host name is only the ``Host`` header and the TLS SNI. ``requests`` is not used: it resolves names,
  reads ``HTTP(S)_PROXY`` from the environment and follows redirects by itself. ``http.client`` handed a
  literal address does none of those, and ``pinned_connection`` refuses anything but a literal.
* **One deadline for the whole fetch.** A socket timeout is per ``recv``, so a server that sends one byte
  every 29 s keeps every single read inside a 30 s timeout while the fetch never ends - and two such servers
  would hold every fetch worker for good. Therefore: each read is given the time that is left, each read does
  at most one ``recv`` (``read1``), and a watchdog shuts the socket down at the deadline, which turns the
  next read into EOF. A fetch that ends because the watchdog fired is a timeout, never a short file.
* **One size.** ``Content-Length`` is checked before anything is read and the real length while it streams,
  and a body that stops short of a declared length is an error. ``Accept-Encoding: identity`` means nothing
  is decoded, so a compression bomb is only a big file.
* **Redirects stay on the endpoint.** At most ``MAX_REDIRECTS``, each held to the observed address, port and
  scheme, and no name is resolved to follow one.
* **Addresses TDC will not fetch from** (``refuse_address``): its own loopback services, its own interface
  addresses and gateways, and - unless the lab says otherwise - every private address.

The body is written into ``<capture_dir>\.incoming`` and moved to ``<capture_dir>\<sha[:2]>\<sha256>``, with
no extension. It is never executed and never reported anywhere online.

The certificate of an HTTPS peer is **not** checked. The peer is a suspected C2, nothing it says is trusted,
and the answer is only stored; refusing a self-signed C2 certificate would lose the sample.

``app.py`` keeps ``_fetch_capture`` as the thin wrapper that gives this module the lab's settings (which
addresses are allowed, the limits, the loader's User-Agent) and records what came back.
"""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import logging
import os
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from typing import Any, Callable, Dict, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import geoip

logger = logging.getLogger(__name__)

MAX_BYTES = 64 * 1024 * 1024
TIMEOUT = 30
MAX_REDIRECTS = 3
CHUNK = 64 * 1024
MAX_URL_LEN = 8192             # as firewall_store.MAX_URL_LEN: a stage-2 URL may carry a base64 query
STAGING = ".incoming"          # where a body is written before it is named by its hash
REDIRECTS = (301, 302, 303, 307, 308)
DEFAULT_USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/124.0.0.0 Safari/537.36")

OWN_TTL_S = 300                # how long the VM's own addresses are remembered (they rarely change, and
                               # finding them costs a name lookup and a `route print`; start-up primes it)
ROUTE_TIMEOUT_S = 10
ROUTE_COMMAND = ["route", "print", "-4"] if os.name == "nt" else ["netstat", "-rn"]

_MAGICS = ((b"MZ", "MZ"), (b"\x7fELF", "ELF"), (b"PK\x03\x04", "PK"), (b"#!", "#!"), (b"%PDF", "PDF"),
           (b"\xd0\xcf\x11\xe0", "OLE"), (b"7z\xbc\xaf", "7z"), (b"Rar!", "RAR"), (b"\x1f\x8b", "GZ"),
           (b"\xca\xfe\xba\xbe", "CAFEBABE"), (b"MSCF", "CAB"))

_own_lock = threading.Lock()
_own_cache: Tuple[float, frozenset] = (0.0, frozenset())


class FetchError(Exception):
    """Why nothing was stored. Every message is safe to show: it names no secret and no local path."""


# ---- small helpers --------------------------------------------------------------------------


def magic_of(head: bytes) -> str:
    """What the first bytes say the file is: ``MZ``, ``ELF``, ``PK`` ..., else ``text`` or ``unknown``."""
    for prefix, name in _MAGICS:
        if head.startswith(prefix):
            return name
    return "text" if head and all(32 <= b < 127 or b in (9, 10, 13) for b in head) else "unknown"


def clean_header_text(value: Any, limit: int = 300) -> Optional[str]:
    """``value`` when it is printable ASCII and short (so it cannot split a header), else None."""
    if isinstance(value, str) and 0 < len(value) <= limit and all(32 <= ord(c) < 127 for c in value):
        return value
    return None


def is_ip_literal(host: Any) -> bool:
    try:
        ipaddress.ip_address(str(host))
        return True
    except ValueError:
        return False


def _plain(text: Any) -> str:
    """``text`` as a plain address (no zone id, IPv4-mapped unwrapped), or ``""`` when it is not one."""
    raw = str(text or "").split("%")[0]
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return ""
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return str(addr)


def same_ip(a: Any, b: Any) -> bool:
    """Whether two addresses are the same host, ``::ffff:1.2.3.4`` and ``1.2.3.4`` included."""
    left, right = _plain(a), _plain(b)
    return bool(left) and left == right


def host_header(scheme: str, host: str, port: Optional[int]) -> str:
    """The ``Host`` header for a hop: IPv6 in brackets, the port only when it is not the scheme's own."""
    name = f"[{host}]" if ":" in host else host
    return name if port is None or port == (443 if scheme == "https" else 80) else f"{name}:{port}"


# ---- which addresses TDC may fetch from -----------------------------------------------------


def gateways_from(text: str) -> Set[str]:
    """The gateways of the default routes in a ``route print`` / ``netstat -rn`` table.

    Every shape of that table (Windows, macOS, Linux) starts a default route with ``default``, ``0.0.0.0`` or
    ``::/0``, and the gateway is the first address on the line that is not the destination or the mask.
    Deliberately loose: a line that is not understood simply adds nothing, and the private-address rule of
    ``refuse_address`` is the net under this.
    """
    found: Set[str] = set()
    for line in (text or "").splitlines():
        parts = line.split()
        if not parts or parts[0].lower() not in ("default", "0.0.0.0", "::/0", "::"):
            continue
        for token in parts[1:]:
            address = _plain(token)
            if not address:
                continue
            addr = ipaddress.ip_address(address)
            if addr.is_unspecified or addr.is_multicast:        # the mask column, a multicast route
                continue
            found.add(address)
            break
    return found


def _gateways() -> Set[str]:
    proc = subprocess.run(ROUTE_COMMAND, capture_output=True, timeout=ROUTE_TIMEOUT_S,
                          creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return gateways_from((proc.stdout or b"").decode("utf-8", "replace"))


def _interface_addresses() -> Set[str]:
    """This machine's own addresses: what its name resolves to, plus the source address of its default route."""
    found = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            found.add(_plain(info[4][0]))
    except (OSError, UnicodeError, IndexError):
        pass
    # The address an outbound packet would leave from. connect() on a datagram socket sends nothing and
    # resolves nothing: the documentation addresses below are never contacted.
    for family, probe in ((socket.AF_INET, ("192.0.2.1", 9)), (socket.AF_INET6, ("2001:db8::1", 9))):
        try:
            sock = socket.socket(family, socket.SOCK_DGRAM)
        except OSError:
            continue
        try:
            sock.connect(probe)
            found.add(_plain(sock.getsockname()[0]))
        except OSError:
            pass
        finally:
            sock.close()
    return {a for a in found if a}


def own_addresses(now: Optional[float] = None, refresh: bool = False) -> frozenset:
    """The addresses of this machine and of its default gateways, remembered for ``OWN_TTL_S``.

    The web UI and the detonation services listen on ``0.0.0.0``, so the VM's own LAN address is the same door
    as the loopback address that ``refuse_address`` turns away, and the gateway is the analyst's side of that
    network. What cannot be read is simply not in the set; the private-address rule is the net under it.
    """
    global _own_cache
    now = time.time() if now is None else now
    with _own_lock:
        stamp, cached = _own_cache
        if not refresh and 0 <= now - stamp < OWN_TTL_S:
            return cached
    found: Set[str] = set()
    for step in (_interface_addresses, _gateways):
        try:
            found |= step()
        except Exception as exc:                 # a box that answers neither is covered by the LAN rule
            logger.debug("firewall fetch: %s failed: %s", step.__name__, exc)
    with _own_lock:
        _own_cache = (now, frozenset(found))
        return _own_cache[1]


def refuse_address(ip: Any, *, allow_lan: bool = False, own: Optional[Set[str]] = None) -> Optional[str]:
    """Why TDC will not fetch from ``ip``, or None.

    Loopback and its relatives: a script in the guest could otherwise have TDC fetch
    ``http://127.0.0.1:8080/...`` (the Detonator, the agent, LitterBox) and keep the answer. The VM's own
    addresses and gateways: those services listen on ``0.0.0.0``, so the VM's LAN address opens the same door,
    and the gateway is the analyst's machine. Private addresses in general: the host sits one private address
    away from the guest, and in ISOLATED the fetcher is the only program allowed out, which would make this
    the one remaining path onto that machine - the opposite of why the guest fetches instead of the host. A lab
    that serves its stage 2 from an INetSim box on the LAN turns it on deliberately with
    ``TDC_FIREWALL_FETCH_LAN=1`` (``allow_lan``), and even then this VM's own addresses stay refused.
    """
    address = _plain(ip)
    if not address:
        return "not an IP address"
    addr = ipaddress.ip_address(address)
    if addr.is_loopback or addr.is_unspecified or addr.is_multicast or addr.is_link_local or addr.is_reserved:
        return "that address is TDC's own side of the VM (loopback, link-local, multicast or reserved)"
    if address in (own_addresses() if own is None else own):
        return "that is this VM's own address or its gateway, not an endpoint of the sample"
    if geoip.scope_of(address) == "local" and not allow_lan:
        return ("that is a private address, where the analyst's own host and the lab network live; "
                "set TDC_FIREWALL_FETCH_LAN=1 if TDC may fetch from the LAN")
    return None


# ---- the connection -------------------------------------------------------------------------


class _KeepSocket:
    """Keeps the socket that the reads go through.

    ``http.client`` drops ``self.sock`` inside ``getresponse()`` when the answer says ``Connection: close``,
    while the response keeps reading from it - and the deadline has to reach that socket before every read.
    """

    io_sock = None

    def connect(self):
        super().connect()
        self.io_sock = self.sock


class _PinnedHTTPConnection(_KeepSocket, http.client.HTTPConnection):
    """Plain HTTP to one address; the host name never reaches a resolver."""


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """The same over TLS, with the loader's host name as SNI and no certificate check (see the module docstring)."""

    io_sock = None

    def __init__(self, ip, port, timeout, sni):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        super().__init__(ip, port, timeout=timeout, context=context)
        self._sni, self._tls = sni, context

    def connect(self):
        http.client.HTTPConnection.connect(self)
        self.sock = self._tls.wrap_socket(self.sock, server_hostname=self._sni)
        self.io_sock = self.sock          # reads go through the TLS socket, and so must the timeouts


def pinned_connection(scheme: str, host: str, port: int, ip: str, timeout: float):
    """A connection to ``ip:port`` and nowhere else; ``host`` is only the ``Host`` header and the SNI.

    ``ip`` must be a literal address. That is what makes a name impossible to resolve here, which is the
    point: a fresh lookup could answer with an address the sample never talked to.
    """
    if not is_ip_literal(ip):
        raise FetchError("the destination must be an address, not a name")
    if scheme == "https":
        return _PinnedHTTPSConnection(ip, int(port), timeout, None if is_ip_literal(host) else host)
    return _PinnedHTTPConnection(ip, int(port), timeout=timeout)


class _Watchdog:
    """Shuts a socket down at ``deadline`` so that a server which drips bytes cannot hold a fetch open.

    A socket timeout is per ``recv`` and cannot bound a whole exchange. ``shutdown`` turns the next read into
    EOF, which the reader reports as a protocol error or a short body; ``fired`` tells the caller it was the
    clock, so the fetch fails as a timeout instead of storing a truncated file.
    """

    def __init__(self, sock, deadline: float):
        self.sock, self.fired, self._timer = sock, False, None
        if sock is None:
            return
        self._timer = threading.Timer(max(0.05, deadline - time.monotonic()), self._fire)
        self._timer.daemon = True
        self._timer.start()

    def _fire(self):
        self.fired = True
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def cancel(self):
        if self._timer is not None:
            self._timer.cancel()


# ---- the fetch ------------------------------------------------------------------------------


def target_of(url: Any, observed_ip: Any, observed_port: Optional[int] = None,
              observed_scheme: Optional[str] = None) -> Tuple[str, str, int, str]:
    """``(scheme, host, port, target)`` of ``url``, held to the endpoint that was observed.

    An address literal in the URL must be the observed address, the port must be the observed port, and the
    scheme must be the one the first request used: a redirect that changes either leaves the endpoint TDC saw.
    ``None`` for the port or the scheme means "not known yet", so the first hop sets them.
    """
    if not isinstance(url, str) or not url or len(url) > MAX_URL_LEN:
        raise FetchError("no usable URL")
    if not all(32 < ord(c) < 127 for c in url):
        raise FetchError("the URL has characters that cannot be sent as they are")
    parts = urlparse(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise FetchError("not an http(s) URL")
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        raise FetchError("bad port in the URL")
    host = parts.hostname
    if is_ip_literal(host) and not same_ip(host, observed_ip):
        raise FetchError("the URL names another address than the one observed")
    if observed_port is not None and port != observed_port:
        raise FetchError("the URL names another port than the one observed")
    if observed_scheme is not None and parts.scheme != observed_scheme:
        raise FetchError("the URL changes the scheme of the connection that was observed")
    path = parts.path or "/"
    return parts.scheme, host, port, path + ("?" + parts.query if parts.query else "")


def _read_body(resp, conn, deadline: float, watchdog: Optional[_Watchdog], capture_dir: str,
               max_bytes: int, chunk: int) -> Tuple[str, str, int, bytes]:
    """The body into a temp file under ``<capture_dir>/.incoming``: ``(path, sha256, size, first bytes)``."""
    declared = resp.getheader("Content-Length")
    declared = int(declared) if declared and str(declared).strip().isdigit() else None
    if declared is not None and declared > max_bytes:
        raise FetchError("too large")
    staging = os.path.join(capture_dir, STAGING)
    os.makedirs(staging, exist_ok=True)
    digest, size, head = hashlib.sha256(), 0, b""
    tmp = tempfile.NamedTemporaryFile(dir=staging, delete=False)
    try:
        with tmp:
            while True:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise FetchError("timed out")
                sock = getattr(conn, "io_sock", None)
                if sock is not None:
                    try:
                        sock.settimeout(max(0.1, left))
                    except OSError:                  # the socket is already gone; the read below says so
                        pass
                part = resp.read1(chunk) if hasattr(resp, "read1") else resp.read(chunk)
                if not part:
                    break
                size += len(part)
                if size > max_bytes:
                    raise FetchError("too large")
                if len(head) < 8:
                    head = (head + part)[:8]
                digest.update(part)
                tmp.write(part)
            if watchdog is not None and watchdog.fired:
                raise FetchError("timed out")        # the end of the body was the watchdog, not the server
            if declared is not None and size != declared:
                raise FetchError("the answer stopped short of the length it declared")
            tmp.flush()
            os.fsync(tmp.fileno())
    except BaseException:
        try:
            os.remove(tmp.name)
        except OSError:
            pass
        raise
    return tmp.name, digest.hexdigest(), size, head


def fetch(url: Any, ip: Any, port: Optional[int] = None, *, capture_dir: str, user_agent: Optional[str] = None,
          timeout: float = TIMEOUT, max_bytes: int = MAX_BYTES, max_redirects: int = MAX_REDIRECTS,
          chunk: int = CHUNK, refuse: Optional[Callable[[Any], Optional[str]]] = None,
          connect: Optional[Callable[..., Any]] = None) -> Dict[str, Any]:
    """Fetch ``url`` from the observed address ``ip:port`` and store the body; what was stored.

    ``{path, sha256, size, magic, status, redirects, content_type, user_agent}``. Raises ``FetchError`` for
    anything that is not a stored file: a refused address, a URL that does not match the observation, an
    answer that is not 200, an empty or short body, and each of the limits.

    ``refuse`` decides which addresses may be fetched from (``refuse_address``; ``app.py`` passes it with the
    lab's settings) and ``connect`` builds the connection (``pinned_connection``). Both are injected so a test
    can drive a real socket server on loopback, which the address policy would otherwise turn away.
    """
    refusal = (refuse or refuse_address)(ip) if isinstance(ip, str) else "no address"
    if refusal:
        raise FetchError("refused: " + refusal)
    connect = connect or pinned_connection
    sent_agent = clean_header_text(user_agent) or DEFAULT_USER_AGENT
    deadline = time.monotonic() + max(0.0, float(timeout))
    scheme, host, hop_port, target = target_of(url, ip, port)
    origin_host, redirects, status, content_type = host, 0, None, ""
    while True:
        left = deadline - time.monotonic()
        if left <= 0:
            raise FetchError("timed out")
        conn, watchdog = connect(scheme, host, hop_port, ip, max(0.1, left)), None
        try:
            conn.connect()
            watchdog = _Watchdog(getattr(conn, "io_sock", None), deadline)
            conn.request("GET", target, headers={
                "Host": host_header(scheme, host, hop_port), "User-Agent": sent_agent, "Accept": "*/*",
                "Accept-Encoding": "identity", "Connection": "close"})
            resp = conn.getresponse()
            status = resp.status
            if status in REDIRECTS:
                location = resp.getheader("Location")
                if not location:
                    raise FetchError(f"HTTP {status} without a Location")
                if redirects >= max_redirects:
                    raise FetchError("too many redirects")
                redirects += 1
                url = urljoin(url, location)
                scheme, host, hop_port, target = target_of(
                    url, ip, port if port is not None else hop_port, scheme)
                if host.lower() != origin_host.lower() and not same_ip(host, ip):
                    raise FetchError("a redirect leaves the observed address")
                continue
            if status != 200:
                raise FetchError(f"HTTP {status}")
            content_type = clean_header_text(resp.getheader("Content-Type") or "", 200) or ""
            tmp_path, sha256, size, head = _read_body(resp, conn, deadline, watchdog, capture_dir,
                                                      max_bytes, chunk)
            break
        except FetchError:
            raise
        except (OSError, http.client.HTTPException, ValueError) as e:
            # The watchdog's shutdown can also surface as ValueError("Read on closed or unwrapped SSL socket"),
            # because SSLSocket.shutdown clears _sslobj while a read is in it; that is the clock, not a bug.
            if (watchdog is not None and watchdog.fired) or time.monotonic() >= deadline \
                    or isinstance(e, (TimeoutError, socket.timeout)):
                raise FetchError("timed out") from e
            if isinstance(e, ValueError):
                raise                      # a ValueError that is not the clock is a fault, not a fetch result
            if isinstance(e, http.client.HTTPException):
                raise FetchError(f"protocol error: {type(e).__name__}") from e
            raise FetchError(f"network or disk error: {type(e).__name__}") from e
        finally:
            if watchdog is not None:
                watchdog.cancel()
            try:
                conn.close()
            except Exception:
                pass
    try:
        if size == 0:
            raise FetchError("empty response")
        final_dir = os.path.join(capture_dir, sha256[:2])
        os.makedirs(final_dir, exist_ok=True)
        final = os.path.join(final_dir, sha256)
        os.replace(tmp_path, final)        # named by its hash only: no URL text ever reaches a path
    except BaseException:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise
    return {"path": final, "sha256": sha256, "size": size, "magic": magic_of(head), "status": status,
            "redirects": redirects, "content_type": content_type, "user_agent": sent_agent}


def clear_staging(capture_dir: str) -> int:
    """Delete what a fetch left in ``<capture_dir>/.incoming``; the number of files removed.

    A fetch that was killed (the service stopped, the VM reverted) leaves a partial body there. It is never
    recorded as a capture, but it would sit in a folder that is excluded from Defender and readable through
    ``/api/file/download``, so start-up empties it.
    """
    staging = os.path.join(capture_dir, STAGING)
    removed = 0
    try:
        names = os.listdir(staging)
    except OSError:
        return 0
    for name in names:
        path = os.path.join(staging, name)
        try:
            if os.path.isfile(path):
                os.remove(path)
                removed += 1
        except OSError as exc:
            logger.warning("firewall fetch: cannot remove %s: %s", path, exc)
    return removed
