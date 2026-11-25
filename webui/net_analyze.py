"""A pcap to one network report: flows, parsers, decoding, behaviour, rules, evidence.

The parsers, the decoder, the behaviour analysis, the rules and the evidence
model each answer one question about a capture. Nothing so far asked them in
order, and the order is where a report goes wrong: a parser chosen by port
alone, a connection no parser claimed that vanishes, a rule hit whose index
points into a different list than the report shows, findings built without
``known_good``, a password serialized because one step forgot to mask. This
module is that order, in ``analyze_pcap``. The false assumptions it avoids:

  * The port names the protocol. Malware speaks HTTP on 443 and TLS on 8080.
    Each parser is only tried when the bytes look like its protocol (a TLS
    record, an HTTP request or status line, a line protocol that
    ``net_mail_ftp`` recognises by its commands); the port only says which of
    those is tried first. A UDP flow on port 53 that does not parse as DNS is
    not lost. DNS over TCP is not parsed (it is profiled as ``raw``), and
    whatever no parser claims is profiled by ``net_raw``.
  * A connection is only what a parser says about it. Every TCP flow is also
    a ``conn`` event (it was established: the server answered) or a
    ``conn_failed`` event (a SYN that nobody answered, ``refused`` when it was
    reset), and every UDP flow that no parser claims is a ``udp`` event, so
    a dead C2 shows as repeated failures (``net_behavior``'s ``retry``) and a
    connection that carried something unknown is still in the report. A flow
    captured from its middle with nothing from the server is a ``conn``: the
    capture cannot say the attempt failed.
  * A name from a capture is text. A TLS server name, a Host header, a URL, a
    user name or a mail address may hold NUL, newline or any byte, in no
    particular character set. The parsers keep a name's bytes (ASCII, every
    other byte a ``surrogateescape`` code point) instead of guessing, and
    every name field (``dest``, ``sni``, ``url``, ``user``, ``mail_from``,
    ``rcpt_to``) of every parser's event is rendered once, here, with
    ``net_events.render_bytes``, exactly as ``net_dns`` renders the labels of
    a DNS name (which are therefore left as they are): a printable ASCII byte
    stands for itself, a backslash is ``\\\\``, any other byte ``\\DDD``. One
    spelling for one name, whichever protocol carried it (one IOC, not two),
    and no raw control byte reaches a rule, a log or the report. Error lines
    are free text and keep their spaces, but their unprintable characters are
    written the same way (``safe_text``).
  * One download is the unit of cost. A capture of many small decompression
    bombs would be inflated into the hash a thousand times over, so one
    ``net_http.HashBudget`` of ``CAPTURE_HASH_BUDGET`` bytes is shared by every
    flow of a capture.
  * "No finding" is an answer. A rule the regex time budget could not decide
    is listed (``rule_unevaluated``, ``rule_budget_spent``), an empty capture
    is ``observed`` False with a ``note`` and differs from a capture in which
    nothing was found, and the isolated mode (``mode="isolated"``: our own
    server took the data) marks uploads and logins as partly observed.
  * The findings know what the rules know. They are built with the rule set's
    ``known_good``; without it an idle Windows hour scores MALICIOUS.
  * The clean machine is quiet. It is not, and ``known_good`` covers only what
    every Windows machine does. Events the ``net_baseline.NetBaseline`` knows
    are suppressed: kept in the report and counted (``suppressed_count``,
    ``baseline`` "known" on the event) but invisible to the rules and the
    findings. The rhythm of a check-in is measured over every event first, so
    a beacon whose requests the baseline knows is still measured, and is
    suppressed only when the baseline knows that rhythm too.
  * An event may be serialized as it is. ``ftp`` and ``smtp`` events hold a
    ``net_mail_ftp.Secret`` that refuses JSON on purpose, a decoded credential
    carries the plain text and its encoded form (``text``, ``encoded``), and a
    password also travels in plain text: a login form, a query string, URL
    userinfo, a cookie, an API-key header, a WebSocket message, a reply that
    echoes it, and from there into a finding's URL. Masking per key misses the
    next key, so the whole report goes through one pass at the end
    (``mask_report``): ``net_mail_ftp.masked`` for every ``Secret``, and
    ``net_decode.mask_credentials``, the detection behind the ``credential``
    flag, for every string (bodies, replies and messages line by line);
    credential, cookie and secret-named header values are ``***``. A decoded
    credential is also masked in its own event and where its encoded value
    sat. Rules and findings ran on the plain events before, so masking changes
    no verdict. Nothing secret is written to the baseline either.
  * Every address is an indicator. The servers of ``known_good`` names are
    the idle machine's: an address that only known-good lookups answered, and
    the address of a connection that carried nothing but events to known-good
    names, are not listed. A transfer's address is, unless a known-good lookup
    returned it, so a claimed name on a foreign address keeps the address.
  * A step that fails ends the analysis. A capture is hostile input: a parser
    that raises on one flow is an entry in ``errors`` and the next parser (at
    the end ``net_raw``) is tried; the decoder, the behaviour analysis, the
    rules and the evidence step are each contained the same way.

Files that crossed the wire are listed under a ``.bin`` name made of their
hash and their kind. They are never written, opened or executed here.
"""

import ipaddress
import math
import os

import net_behavior
import net_decode
import net_dns
import net_events
import net_evidence
import net_flows
import net_http
import net_mail_ftp
import net_raw
import net_rules
import net_tls

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_RULES = os.path.join(ROOT, "rules", "network", "default.yaml")

MODES = {"online": True, "isolated": False}     # mode -> observed_fully
CAPTURE_HASH_BUDGET = 256 * 1024 * 1024         # bytes streamed into file hashes per capture
MAX_IOCS = 5000

BEHAVIOR_TYPES = ("beacon", "retry", "fanout")
NAME_FIELDS = ("dest", "sni", "mail_from", "user", "url")
NAME_LIST_FIELDS = ("rcpt_to",)
EXECUTABLES = net_evidence.EXECUTABLES

# The fake internet answers from these addresses: a connection to one says
# nothing about where the sample wanted to go (its name does).
_FAKE_INTERNET = ipaddress.ip_network("198.18.0.0/15")
_BROADCAST = ipaddress.ip_address("255.255.255.255")
_ANONYMOUS = frozenset(("anonymous", "ftp"))

# Which parser a port suggests first. Only parsers whose content check passed are tried.
_PORT_HINTS = {}
for _port in (443, 465, 563, 636, 853, 989, 990, 992, 993, 994, 995, 5061, 8443):
    _PORT_HINTS[_port] = "tls"
for _port in (80, 591, 3128, 8000, 8008, 8080, 8888):
    _PORT_HINTS[_port] = "http"
for _port in (21, 25, 587, 2121, 2525):
    _PORT_HINTS[_port] = "mail"
_ORDER = ("tls", "http", "mail")


# --- choosing a parser ---------------------------------------------------------------

def _looks_like_tls(stream):
    return len(stream) >= 3 and stream[0] == 0x16 and stream[1] == 0x03


def _looks_like_lines(stream):
    head = bytes(stream[:64])
    return bool(head) and (head[:1].isalpha() or head[:3].isdigit())


def _candidates(flow):
    """Parsers whose content check passes for a TCP flow, the port's own first."""
    client, server = flow.client_stream(), flow.server_stream()
    fits = set()
    if _looks_like_tls(client) or (flow.client_guessed and _looks_like_tls(server)):
        fits.add("tls")
    if net_http.looks_like_http(client) or net_http.looks_like_http(server):
        fits.add("http")
    if _looks_like_lines(client) or _looks_like_lines(server):
        fits.add("mail")
    hint = _PORT_HINTS.get(flow.dport)
    ordered = [hint] if hint in fits else []
    return ordered + [name for name in _ORDER if name in fits and name != hint]


def _parse(name, flow, budget):
    # Looked up on the module at call time, so one parser can be replaced (a test).
    if name == "tls":
        return net_tls.events_from_flow(flow)
    if name == "http":
        return net_http.events_from_flow(flow, hash_budget=budget)
    if name == "mail":
        return net_mail_ftp.events_from_flow(flow)
    if name == "dns":
        return net_dns.events_from_flow(flow)
    return net_raw.events_from_flow(flow)


_MODULES = {"tls": "net_tls", "http": "net_http", "mail": "net_mail_ftp", "dns": "net_dns",
            "raw": "net_raw"}


def _describe(flow):
    return "%s %s:%s -> %s:%s" % (flow.proto, flow.src, flow.sport, flow.dst, flow.dport)


def safe_text(text):
    """Free text (an error, a reason) with every byte that is not printable
    written as ``render_bytes`` writes it (``\\DDD``), and a backslash as
    ``\\\\``; spaces and other printable characters stay as they are."""
    out = []
    for c in str(text):
        if c == "\\":
            out.append("\\\\")
        elif c.isprintable():
            out.append(c)
        else:
            try:
                raw = c.encode("utf-8", "surrogateescape")
            except UnicodeEncodeError:
                raw = c.encode("utf-8", "surrogatepass")
            out.append(net_events.render_bytes(raw))
    return "".join(out)


def _failure(where, exc):
    return safe_text("%s: %s: %s" % (where, type(exc).__name__, exc))


def _run_parser(name, flow, budget, errors):
    try:
        found = _parse(name, flow, budget)
    except Exception as exc:        # a capture is hostile input; the next parser is tried
        errors.append(_failure("%s on %s" % (_MODULES[name], _describe(flow)), exc))
        return []
    return list(found or [])


def _has_payload(flow):
    return bool(flow.client_stream() or flow.server_stream())


# --- connection events -------------------------------------------------------------------

def connection_event(flow, app=""):
    """The ``conn``, ``conn_failed`` or ``udp`` event of a flow.

    ``app`` names the parser that claimed a TCP flow (``tls``, ``http``,
    ``ftp``, ``smtp``, ``raw``, or "" for a flow without payload).
    """
    duration = round(max(0.0, flow.last_ts - flow.first_ts), 6)
    common = dict(dest=flow.dst, port=flow.dport, src=flow.src, sport=flow.sport,
                  first_ts=flow.first_ts, last_ts=flow.last_ts)
    if flow.proto == "udp":
        return net_events.NetEvent(
            "udp", flow.first_ts, duration=duration, client_bytes=flow.client_bytes,
            server_bytes=flow.server_bytes, client_packets=flow.client_packets,
            server_packets=flow.server_packets, answered=bool(flow.answered),
            stream_capped=bool(flow.capped), **common)
    if not flow.answered and not flow.client_guessed:
        return net_events.NetEvent(
            "conn_failed", flow.first_ts, proto="tcp", attempts=flow.client_packets,
            refused=bool(flow.server_reset), **common)
    return net_events.NetEvent(
        "conn", flow.first_ts, proto="tcp", app=app, duration=duration,
        client_bytes=flow.client_bytes, server_bytes=flow.server_bytes,
        client_packets=flow.client_packets, server_packets=flow.server_packets,
        client_guessed=bool(flow.client_guessed), stream_capped=bool(flow.capped),
        stream_gaps=list(flow.gaps), **common)


def _flow_events(flow, budget, errors, claimed=None):
    if flow.proto == "udp":
        if net_dns.is_dns(flow):
            found = _run_parser("dns", flow, budget, errors)
            if found:
                return found
        out = [connection_event(flow)]
        if _has_payload(flow):
            out += _run_parser("raw", flow, budget, errors)
        return out
    found, app = [], ""
    for name in _candidates(flow):
        found = _run_parser(name, flow, budget, errors)
        if found:
            app = found[0]["type"] if name == "mail" else name
            break
    if not found and _has_payload(flow):
        found = _run_parser("raw", flow, budget, errors)
        app = "raw" if found else ""
    conn = connection_event(flow, app)
    if claimed is not None:
        claimed[id(conn)] = found
    return [conn] + found


# --- names -----------------------------------------------------------------------------------

def render_name(text):
    """A name as ``net_dns`` writes one (see the module docstring)."""
    try:
        raw = text.encode("utf-8", "surrogateescape")
    except UnicodeEncodeError:
        raw = text.encode("utf-8", "surrogatepass")
    return net_events.render_bytes(raw)


def _render_names(event):
    """Render every name field of a parser's event, once. DNS events come rendered."""
    if event.get("type") == "dns":
        return event
    for field in NAME_FIELDS:
        value = event.get(field)
        if isinstance(value, str):
            event[field] = render_name(value)
    for field in NAME_LIST_FIELDS:
        values = event.get(field)
        if isinstance(values, list):
            event[field] = [render_name(v) if isinstance(v, str) else v for v in values]
    dest = event.get("dest")
    event["dest_is_ip"] = isinstance(dest, str) and _ip(dest) is not None
    return event


def collect_events(path, hash_budget=None):
    """``(events, errors, pcap_result)``: the parsers' and connection events of a
    capture, names rendered, in time order. No decoding or behaviour yet."""
    return _collect(path, hash_budget)[:3]


def _collect(path, hash_budget=None):
    """``collect_events`` plus ``claimed``: id of a ``conn`` event -> the
    parser events of its flow."""
    if hash_budget is None:
        hash_budget = net_http.HashBudget(CAPTURE_HASH_BUDGET)
    result = net_flows.read_pcap(path)
    errors, events, claimed = [], [], {}
    for flow in result.flows:
        try:
            events += _flow_events(flow, hash_budget, errors, claimed)
        except Exception as exc:    # e.g. a flow attribute a parser left odd
            errors.append(_failure("net_analyze on %s" % _describe(flow), exc))
    events = net_events.sort_events(_render_names(e) for e in events)
    return events, errors, result, claimed


# --- the report: masking ------------------------------------------------------------------------

_SCRUBBED_TEXT = ("query", "url", "body_text", "resp_text")
# Header values masked whole: the credential headers, the cookies, and any
# header whose name says secret (X-Api-Key, X-Auth-Token...), as the decoder's
# credential flag reads names.
_SECRET_HEADERS = frozenset(("authorization", "proxy-authorization", "cookie", "set-cookie"))
_HEADER_FIELDS = frozenset(("headers", "resp_headers"))
# Fields of free text read line by line ("name: value" lines, dump records).
_LINE_FIELDS = frozenset(("body_text", "resp_text", "text"))


def _scrub_text(text, prefix, length):
    if not isinstance(text, str) or not prefix:
        return text
    pos = text.find(prefix)
    while pos >= 0:
        text = text[:pos] + "***" + text[pos + max(length, len(prefix)):]
        pos = text.find(prefix, pos + 3)
    return text


def _scrub_source(source, prefix, length):
    """Replace an encoded credential where it sat in the event it was decoded from."""
    for field in _SCRUBBED_TEXT:
        if field in source:
            source[field] = _scrub_text(source[field], prefix, length)
    for field in ("headers", "resp_headers"):
        headers = source.get(field)
        if isinstance(headers, dict):
            for name, value in list(headers.items()):
                headers[name] = _scrub_text(value, prefix, length)
    messages = source.get("messages")
    if isinstance(messages, list):
        for message in messages:
            if isinstance(message, dict):
                message["text"] = _scrub_text(message.get("text"), prefix, length)


def _mask_header(name, value):
    if not isinstance(value, str):
        return mask_report(value)
    lname = name.lower() if isinstance(name, str) else ""
    if lname in _SECRET_HEADERS or net_decode.is_secret_name(lname):
        value = value.strip()
        if lname in ("authorization", "proxy-authorization") and " " in value:
            return value.split(None, 1)[0] + " ***"
        return "***" if value else value
    return net_decode.mask_credentials(value)


def mask_report(value, key=None):
    """A copy of any report structure with every credential masked.

    One pass over everything, so that no key (an event field, a finding, a rule
    hit, an IOC, a key added later) can carry a password past it: every string
    goes through ``net_decode.mask_credentials`` (bodies, replies and messages
    line by line), and header values whose name says secret, cookies and
    credentials are ``***``. ``net_mail_ftp.masked`` is applied too, so a
    ``Secret`` anywhere is masked as well. Applying it twice changes nothing.
    """
    value = net_mail_ftp.masked(value) if key is None else value
    if isinstance(value, dict):
        if key in _HEADER_FIELDS:
            return {k: _mask_header(k, v) for k, v in value.items()}
        return {k: mask_report(v, k if isinstance(k, str) else "") for k, v in value.items()}
    if isinstance(value, list):
        return [mask_report(v, key or "") for v in value]
    if isinstance(value, str):
        return net_decode.mask_credentials(value, lines=key in _LINE_FIELDS)
    return value


def _mask_decoded(events, copies, source_of):
    """A decoded credential and the encoded value it came from, masked in the copies."""
    position = {id(e): i for i, e in enumerate(events)}
    for event, copy in zip(events, copies):
        if event.get("type") != "decoded" or not event.get("credential"):
            continue
        if copy.get("text") is not None:
            copy["text"] = "***"
        copy["encoded"] = "***"
        copy["preview"] = ""
        copy["sha256"] = None       # the hash of a short "user:password" is the password
        source = source_of.get(id(event))
        if source is not None and id(source) in position:
            length = event.get("encoded_len")
            _scrub_source(copies[position[id(source)]], event.get("encoded") or "",
                          length if isinstance(length, int) else 0)


def _jsonable(value):
    """A value ``json.dumps`` writes as standard JSON, whatever a parser left in it."""
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, (set, frozenset)):
        return sorted((_jsonable(v) for v in value), key=repr)
    if isinstance(value, (bytes, bytearray)):
        return net_events.render_bytes(bytes(value))
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


# --- the report: indicators and files ---------------------------------------------------------

def _ip(text):
    try:
        return ipaddress.ip_address(text)
    except (ValueError, TypeError):
        return None


def _address(text):
    """An address worth naming as an indicator, or None."""
    ip = _ip(text)
    if ip is None or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return None
    if ip.version == 4 and (ip in _FAKE_INTERNET or ip == _BROADCAST):
        return None
    return ip


class _Indicators:
    def __init__(self):
        self.found = {}
        self.capped = False

    def add(self, kind, value, event, **extra):
        if not isinstance(value, str) or not value:
            return
        key = (kind, value)
        entry = self.found.get(key)
        if entry is None:
            if len(self.found) >= MAX_IOCS:
                self.capped = True
                return
            entry = self.found[key] = dict(type=kind, value=value, count=0,
                                           first_ts=event.get("ts"), sources=[], **extra)
        entry["count"] += 1
        if event["type"] not in entry["sources"]:
            entry["sources"].append(event["type"])

    def ip(self, text, event):
        ip = _address(text)
        if ip is not None:
            self.add("ip", str(ip), event, public=ip.is_global)

    def name(self, text, event, known_good):
        if not isinstance(text, str) or not text:
            return
        if _ip(text) is not None:
            self.ip(text, event)
        elif not known_good.hides({"dest": text}) and not net_behavior.is_housekeeping(text):
            self.add("domain", text.lower().rstrip("."), event)


_IOC_ORDER = ("domain", "ip", "url", "sha256", "email", "account")


def _quiet_addresses(events, claimed, known_good):
    """``(addresses, positions)`` that are a known-good server, not an indicator.

    ``addresses`` were answered by the capture's lookups for known-good names
    only; ``positions`` are the ``conn`` events whose flow carried nothing but
    events to known-good names (whose name is as trusted as the rest of
    ``known_good``: the sample's own header or server name). An upload or
    download keeps its address unless a known-good lookup returned it, so a
    claimed name on a foreign address still leaves the address in the list.
    """
    names = {}
    for e in events:
        if e.get("type") != "dns" or e.get("query_type") not in ("A", "AAAA"):
            continue
        hidden = known_good.hides({"dest": e.get("dest")})
        for answer in e.get("answers") or ():
            ip = _ip(answer)
            if ip is not None:
                names.setdefault(str(ip), []).append(hidden)
    addresses = {ip for ip, hidden in names.items() if all(hidden)}
    positions = set()
    for i, e in enumerate(events):
        found = claimed.get(id(e)) if e.get("type") == "conn" else None
        if found and all(isinstance(f.get("dest"), str) and known_good.hides({"dest": f["dest"]})
                         for f in found):
            positions.add(i)
    return addresses, positions


def _iocs(copies, known_good, quiet=(set(), set())):
    out = _Indicators()
    addresses, positions = quiet

    def foreign(text):
        ip = _ip(text)
        return ip is None or str(ip) not in addresses

    for i, e in enumerate(copies):
        etype = e.get("type")
        if e.get("baseline") == "known" or etype in BEHAVIOR_TYPES:
            continue
        dest = e.get("dest")
        name_known = isinstance(dest, str) and known_good.hides({"dest": dest})
        if etype != "decoded" and i not in positions and foreign(dest):
            out.name(dest, e, known_good)
        for address in e.get("addresses") or ():
            if foreign(address):
                out.ip(address, e)
        if (etype == "dns" and e.get("query_type") in ("A", "AAAA") and not name_known
                and isinstance(dest, str) and dest and not net_behavior.is_housekeeping(dest)):
            for answer in e.get("answers") or ():
                out.ip(answer, e)
        if etype == "http" and not name_known and e.get("url"):
            out.add("url", e["url"], e)
        if etype == "download":
            out.add("sha256", e.get("sha256") or e.get("wire_sha256"), e)
        if etype == "upload" and e.get("kind") in EXECUTABLES:
            out.add("sha256", e.get("sha256"), e)
        if (etype == "decoded" and not e.get("credential") and e.get("text") is None
                and e.get("kind")):
            out.add("sha256", e.get("sha256"), e)
        if etype == "smtp":
            for address in [e.get("mail_from")] + list(e.get("rcpt_to") or ()):
                out.add("email", address, e)
        user = e.get("user")
        if etype in ("ftp", "smtp") and isinstance(user, str) and user and not (
                etype == "ftp" and user.lower() in _ANONYMOUS):
            out.add("account", "%s://%s@%s" % (etype, user, dest), e,
                    password_captured=bool(e.get("password_captured")))
    items = sorted(out.found.values(),
                   key=lambda i: (_IOC_ORDER.index(i["type"]), i["first_ts"] or 0, i["value"]))
    return items, out.capped


def _files(copies):
    files, seen = [], {}
    for e in copies:
        etype = e.get("type")
        if etype not in ("download", "upload", "decoded"):
            continue
        if etype == "decoded" and (e.get("credential") or e.get("text") is not None
                                   or not e.get("kind")):
            continue
        sha = e.get("sha256") or e.get("wire_sha256")
        if not isinstance(sha, str) or not sha:
            continue
        key = (etype, sha)
        if key in seen:
            seen[key]["count"] += 1
            continue
        kind = e.get("kind") or "data"
        entry = {"name": "%s.%s.bin" % (sha, net_events.render_bytes(kind.encode("utf-8"))),
                 "sha256": sha, "hashed": "file" if e.get("sha256") else "wire",
                 "kind": kind, "size": e.get("size"), "direction": etype,
                 "dest": e.get("dest"), "url": e.get("url"), "path": e.get("path"),
                 "content_type": e.get("content_type"), "truncated": e.get("truncated"),
                 "ts": e.get("ts"), "addresses": list(e.get("addresses") or []), "count": 1}
        if e.get("baseline") == "known":
            entry["baseline"] = "known"
        seen[key] = entry
        files.append(entry)
    return files


# --- the whole chain ------------------------------------------------------------------------------

def _ruleset(rules):
    if isinstance(rules, net_rules.RuleSet):
        return rules
    if rules is None:
        rules = [DEFAULT_RULES]
    elif isinstance(rules, str):
        rules = [rules]
    return net_rules.load_rules(rules)


def _remap(hits, positions):
    """Rule hits whose event references index the report's event list."""
    out = []
    for hit in hits:
        copy = dict(hit)
        refs = []
        for ref in hit.get("events") or ():
            ref = dict(ref)
            index = ref.get("index")
            if isinstance(index, int) and 0 <= index < len(positions):
                ref["index"] = positions[index]
            refs.append(ref)
        copy["events"] = refs
        out.append(copy)
    return out


def analyze_pcap(path, rules=None, baseline=None, process="", mode="online"):
    """The network report of a capture (see the module docstring).

    ``rules`` is None (``rules/network/default.yaml``), a list of rule files or
    directories, or a loaded ``net_rules.RuleSet``. ``baseline`` is a
    ``net_baseline.NetBaseline`` or None. ``process`` names the sample's
    process for events that carry none. ``mode`` is ``"online"`` (the real
    internet answered: what was sent was received) or ``"isolated"`` (our
    server answered: an upload or a login is an attempt). Nothing in the
    capture raises out of here; every failure is a line in ``errors``.
    """
    if mode not in MODES:
        raise ValueError("mode must be one of %s, not %r" % (", ".join(MODES), mode))
    errors = []
    ruleset = _ruleset(rules)
    errors += ["rules: %s" % safe_text(e) for e in ruleset.errors]
    known_good = net_rules.KnownGood(ruleset.lists.get(net_rules.KNOWN_GOOD, ()))
    budget = net_http.HashBudget(CAPTURE_HASH_BUDGET)
    base, parse_errors, result, claimed = _collect(path, budget)
    errors += parse_errors

    decoded, source_of = [], {}
    for e in base:
        if e["type"] not in ("http", "websocket"):
            continue
        try:
            found = net_decode.decode_event_fields(e)
        except Exception as exc:
            errors.append(_failure("net_decode on a %s event to %s" % (e["type"], e["dest"]),
                                   exc))
            continue
        for d in found:
            source_of[id(d)] = e
        decoded += found

    try:
        behavior = list(net_behavior.analyze(base + decoded))
    except Exception as exc:
        errors.append(_failure("net_behavior", exc))
        behavior = []
    events = net_events.sort_events(base + decoded + behavior)

    known = [False] * len(events)
    if baseline is not None:
        for i, e in enumerate(events):
            try:
                known[i] = bool(baseline.knows_event(e))
            except Exception as exc:
                errors.append(_failure("net_baseline", exc))
                break
    positions = [i for i, k in enumerate(known) if not k]
    active = [events[i] for i in positions]
    # Known lookups still tie a name to its addresses for the findings; appended
    # after the active events, so the rule hits' positions stay valid.
    answers = [e for e, k in zip(events, known) if k and e["type"] == "dns"]

    try:
        hits = ruleset.evaluate(active)
    except Exception as exc:
        errors.append(_failure("net_rules", exc))
        hits = net_rules.Hits()
    try:
        findings = net_evidence.findings_from(active + answers, hits, process=process,
                                              observed_fully=MODES[mode], known_good=ruleset)
    except Exception as exc:
        errors.append(_failure("net_evidence", exc))
        findings = []

    copies = net_mail_ftp.masked(events)
    _mask_decoded(events, copies, source_of)
    copies = mask_report(copies)
    for event, copy, is_known in zip(events, copies, known):
        copy["known_good"] = (event["type"] not in net_rules.ALWAYS_VISIBLE
                              and known_good.hides(event))
        if is_known:
            copy["baseline"] = "known"
    iocs, iocs_capped = _iocs(copies, known_good,
                              _quiet_addresses(events, claimed, known_good))

    note = result.note
    if not events:
        empty = "the capture holds no TCP or UDP traffic: nothing was observed"
        note = "%s; %s" % (note, empty) if note else empty
    report = {
        "events": copies,
        "event_summary": net_events.event_summary(events),
        "behavior": [c for c in copies if c["type"] in BEHAVIOR_TYPES],
        "rule_hits": _remap(hits, positions),
        "rule_unevaluated": list(getattr(hits, "unevaluated", [])),
        "rule_budget_spent": bool(getattr(hits, "budget_spent", False)),
        "rule_engine": getattr(hits, "regex_engine", ruleset.regex_engine),
        "rule_notes": list(ruleset.notes),
        "evidence_findings": findings,
        "iocs": iocs,
        "iocs_capped": iocs_capped,
        "files": _files(copies),
        "observed": bool(events),
        "note": note,
        "truncated": bool(result.truncated),
        "format": result.format,
        "packet_count": result.packet_count,
        "flow_count": len(result.flows),
        "mode": mode,
        "process": process,
        "errors": errors,
        "suppressed_count": sum(known),
        "hash_budget_spent": any(e.get("hash_budget_spent") for e in events),
    }
    # The one masking pass over everything serialized (see mask_report).
    return mask_report(_jsonable(net_mail_ftp.masked(report)))
