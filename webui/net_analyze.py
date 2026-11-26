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
    flow of a capture. One message is not the unit either: two hundred
    pipelined 290-byte gzip bombs (77 KB of capture) are 51 MiB of body text
    and took a minute to mask, so the text the analysis reads shares one
    ``net_http.TextBudget`` of ``ANALYSIS_TEXT_BUDGET`` characters, of which a
    flow may take ``FLOW_TEXT_BUDGET`` (``text_budget_spent``), and the report
    keeps ``CAPTURE_TEXT_BUDGET`` characters of it (``report_text_cut``: the
    report shows part of a body that the decoder and the rules read whole).
    Four megabytes of pipelined one-line GETs are 150,000 events and 1.7 GB
    of memory, so a capture keeps at most ``MAX_EVENTS`` parser events: what
    comes after is not parsed, and ``events_capped`` says the report is cut
    (the UI says so). A DNS answer that points back into itself many times is
    bounded the same way.
    Decoded values are not parser events and query strings are no body text:
    two hundred GETs with four base64-gzip query values each were 800 decoded
    events and 60 MB of report, so the decoded events of a capture share one
    ``net_decode.DecodeBudget`` (``MAX_DECODED`` of them, their kept text, their
    inflating) of which each flow has a share (``decoded_capped``), and a
    capture keeps at most ``MAX_DNS_ANSWERS`` DNS answers (``dns_answers_capped``;
    ``net_dns`` keeps a few dozen per message).
  * A cap is no verdict. Caps that are first come let a sample pad its C2
    out of them: one flow of 20,001 GETs before a check-in left no finding
    and a CLEAN verdict, forty gzip bombs before a base64 PE its decoding. So
    a flow keeps at most ``MAX_EVENTS_PER_FLOW`` parser events
    (``flows_capped``) and a share of each budget, every flow keeps its
    connection event however far past the cap it comes (``flows_unparsed``),
    and whatever cut the analysis is listed in ``incomplete``
    (``memory_evidence.network_incomplete``), which the combined verdict
    carries: a CLEAN of a cut capture is a lower bound, not "nothing found".
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
    findings. An upload is suppressed only when it went to an address an
    answer of this capture's resolvers gave for its name: a sample's ``Host:
    ocsp.digicert.com`` sent to its own address is no OCSP request, and its own
    DNS server's answer for that name is no resolution (``net_dns.trusted_lookups``). The rhythm of a check-in is measured over every event first, so
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
    credential is also masked in its own event (whole when it was found under
    a secret name, else only its secrets: a decoded config keeps its C2 URL)
    and where its encoded value sat. Rules and findings ran on the plain events before, so masking changes
    no verdict. Nothing secret is written to the baseline either.
  * Every address is an indicator. The servers of ``known_good`` names are
    the idle machine's and are not listed, but only where a DNS answer in the
    capture says so: an address that known-good lookups (and no other) returned,
    and to which no connection claimed a name that answer does not cover. A
    claimed name is not corroboration: a known-good Host header sent to an
    address no known-good lookup returned keeps the address in the list.
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

import memory_evidence
import net_baseline
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
CAPTURE_TEXT_BUDGET = 8 * 1024 * 1024           # characters of body text the report keeps
ANALYSIS_TEXT_BUDGET = 32 * 1024 * 1024         # characters of body text analysed per capture
FLOW_TEXT_BUDGET = 4 * 1024 * 1024              # ... and per flow
MAX_EVENTS = 20000                              # parser events kept per capture
MAX_EVENTS_PER_FLOW = 2000                      # ... and per flow
# decoded events (net_decode) of a capture and of one flow: how many, the text
# they keep, the bytes their inflate steps produce
MAX_DECODED = 5000
MAX_DECODED_PER_FLOW = 1000
DECODED_TEXT_BUDGET = 8 * 1024 * 1024
DECODED_TEXT_PER_FLOW = 2 * 1024 * 1024
DECODE_INFLATE_BUDGET = 64 * 1024 * 1024
DECODE_INFLATE_PER_FLOW = 16 * 1024 * 1024
MAX_DNS_ANSWERS = 10000                         # DNS answer records kept per capture
MAX_IOCS = 5000

BEHAVIOR_TYPES = ("beacon", "retry", "fanout")
NAME_FIELDS = ("dest", "sni", "mail_from", "user", "url")
NAME_LIST_FIELDS = ("rcpt_to", "hosts")
# free text from a capture that keeps its spaces: unprintable bytes as \DDD (safe_text)
TEXT_FIELDS = ("subject",)
TEXT_LIST_FIELDS = ("commands", "files", "uploaded", "attachments")
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


class _Limits:
    """What one capture may still cost: the shared hash and analysis text
    budgets (``text``, of which each flow gets a share, ``flow_text``) and the
    parser events left under ``MAX_EVENTS`` (see the module docstring)."""

    def __init__(self, hash_budget=None, text_budget=None, max_events=None):
        self.hash = hash_budget if hash_budget is not None else net_http.HashBudget(
            CAPTURE_HASH_BUDGET)
        self.text = text_budget if text_budget is not None else net_http.TextBudget(
            ANALYSIS_TEXT_BUDGET)
        self.flow_text = self.text
        self.events_left = MAX_EVENTS if max_events is None else max_events
        # what the flow being parsed may still add; its parser reads one more, so a cut shows
        self.flow_events = self.events_left
        self.events_capped = False
        self.flows_capped = 0       # flows cut by MAX_EVENTS_PER_FLOW
        self.flows_unparsed = 0     # flows past the capture's cap: their connection event only
        self.answers_left = MAX_DNS_ANSWERS
        self.answers_capped = False
        self.flow_of = {}           # id of a parser event -> the index of its flow


def _parse(name, flow, budget):
    # Looked up on the module at call time, so one parser can be replaced (a test).
    if name == "tls":
        return net_tls.events_from_flow(flow)
    if name == "http":
        return net_http.events_from_flow(flow, hash_budget=budget.hash,
                                         text_budget=budget.flow_text,
                                         max_messages=budget.flow_events + 1)
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
    for field in TEXT_FIELDS:
        if isinstance(event.get(field), str):
            event[field] = safe_text(event[field])
    for field in TEXT_LIST_FIELDS:
        values = event.get(field)
        if isinstance(values, list):
            event[field] = [safe_text(v) if isinstance(v, str) else v for v in values]
    headers = event.get("headers")
    if isinstance(headers, dict) and isinstance(dict.get(headers, "host"), str):
        headers["host"] = render_name(dict.get(headers, "host"))
    dest = event.get("dest")
    event["dest_is_ip"] = isinstance(dest, str) and _ip(dest) is not None
    return event


def collect_events(path, hash_budget=None):
    """``(events, errors, pcap_result)``: the parsers' and connection events of a
    capture, names rendered, in time order. No decoding or behaviour yet."""
    return _collect(path, _Limits(hash_budget))[:3]


_CONNECTION_TYPES = frozenset(("conn", "conn_failed", "udp"))


def _collect(path, limits=None):
    """``collect_events`` plus ``claimed``: id of a ``conn`` event -> the
    parser events of its flow. ``limits`` (a ``_Limits``) says when to stop:
    a flow keeps at most ``MAX_EVENTS_PER_FLOW`` parser events
    (``flows_capped`` counts the flows cut so), the capture at most
    ``MAX_EVENTS`` (``events_capped``); a flow past that is not parsed, but
    its connection event is kept, as every flow's is (``flows_unparsed``)."""
    if limits is None:
        limits = _Limits()
    result = net_flows.read_pcap(path)
    errors, events, claimed = [], [], {}
    for index, flow in enumerate(result.flows):
        if limits.events_left <= 0:
            limits.events_capped = True
            limits.flows_unparsed += 1
            try:
                events.append(connection_event(flow))
            except Exception as exc:
                errors.append(_failure("net_analyze on %s" % _describe(flow), exc))
            continue
        allowed = min(limits.events_left, MAX_EVENTS_PER_FLOW)
        limits.flow_events = allowed
        limits.flow_text = net_http.TextBudget(FLOW_TEXT_BUDGET, limits.text)
        try:
            found = _flow_events(flow, limits, errors, claimed)
        except Exception as exc:    # e.g. a flow attribute a parser left odd
            errors.append(_failure("net_analyze on %s" % _describe(flow), exc))
            continue
        connections = [e for e in found if e.get("type") in _CONNECTION_TYPES]
        parsed = [e for e in found if e.get("type") not in _CONNECTION_TYPES]
        if len(parsed) > allowed:
            parsed = parsed[:allowed]
            if allowed < limits.events_left:
                limits.flows_capped += 1
            else:
                limits.events_capped = True
        for conn in connections:
            if id(conn) in claimed:
                claimed[id(conn)] = parsed
        limits.events_left -= len(parsed)
        for e in parsed:
            limits.flow_of[id(e)] = index
            if e.get("type") == "dns":
                _charge_answers(e, limits)
        events += connections + parsed
    events = net_events.sort_events(_render_names(e) for e in events)
    return events, errors, result, claimed


def _charge_answers(event, limits):
    """Keep a DNS event's answers within what the capture may still keep."""
    answers = event.get("answers")
    if not isinstance(answers, list):
        return
    if len(answers) > limits.answers_left:
        event["answers"] = answers[:limits.answers_left]
        event["answers_capped"] = True
    if event.get("answers_capped"):
        limits.answers_capped = True
    limits.answers_left -= len(event["answers"])


def _decode_all(base, limits, errors):
    """``(decoded, source_of, budget)``: the decoded events of the http and
    websocket events, within a ``net_decode.DecodeBudget`` for the capture and
    a share of it for each flow, so that one flow cannot spend what the
    others' values need."""
    budget = net_decode.DecodeBudget(MAX_DECODED, DECODED_TEXT_BUDGET, DECODE_INFLATE_BUDGET)
    shares = {}
    decoded, source_of = [], {}
    for e in base:
        if e["type"] not in ("http", "websocket"):
            continue
        flow = limits.flow_of.get(id(e))
        share = shares.get(flow)
        if share is None:
            share = shares[flow] = net_decode.DecodeBudget(
                MAX_DECODED_PER_FLOW, DECODED_TEXT_PER_FLOW, DECODE_INFLATE_PER_FLOW, budget)
        try:
            found = net_decode.decode_event_fields(e, share)
        except Exception as exc:
            errors.append(_failure("net_decode on a %s event to %s" % (e["type"], e["dest"]),
                                   exc))
            continue
        for d in found:
            source_of[id(d)] = e
        decoded += found
    return decoded, source_of, budget


# --- the report: masking ------------------------------------------------------------------------

_SCRUBBED_TEXT = ("query", "url", "body_text", "resp_text")
# Header values masked whole: the credential headers, the cookies, any header
# whose name says secret (X-Api-Key, X-Auth-Token...), as the decoder's
# credential flag reads names, and any that carries a session (X-Session,
# Session-Id, X-SID).
_SECRET_HEADERS = frozenset(("authorization", "proxy-authorization", "cookie", "set-cookie"))
_HEADER_FIELDS = frozenset(("headers", "resp_headers"))
# Fields of free text read line by line ("name: value" lines, dump records).
_LINE_FIELDS = frozenset(("body_text", "resp_text", "text"))
# Fields that hold a URL path or a URL: a value in a path segment ends at "/".
_PATH_FIELDS = frozenset(("path", "url"))


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
    if lname == "host":
        return value            # a name, rendered like dest; nothing in it is a secret
    if (lname in _SECRET_HEADERS or net_decode.is_secret_name(lname)
            or net_decode.is_session_header(lname)):
        value = value.strip()
        if lname in ("authorization", "proxy-authorization") and " " in value:
            return value.split(None, 1)[0] + " ***"
        return "***" if value else value
    # A header value is a value, not prose: "password:x" in it is a pair. The
    # User-Agent is the exception (a fingerprint, like the event's ua field).
    return net_decode.mask_credentials(value, colons=lname != "user-agent")


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
        return net_decode.mask_credentials(value, lines=key in _LINE_FIELDS,
                                           path=key in _PATH_FIELDS)
    return value


def _mask_decoded(events, copies, source_of):
    """A decoded credential and the encoded value it came from, masked in the copies.

    A value that is a credential by where it was found (an Authorization
    header, a form key or cookie that says secret) is masked whole. One that
    is a credential by its text (a decoded config with a ``<key>`` or
    ``"password":`` in it) keeps its text with the secrets masked
    (``net_decode.mask_credentials``, which removes whatever the flag found):
    replaced whole, a decoded C2 config lost its C2 URL. Its encoded form,
    its hash and the encoded value in the source are masked either way: they
    give the secret back."""
    position = {id(e): i for i, e in enumerate(events)}
    for event, copy in zip(events, copies):
        if event.get("type") != "decoded" or not event.get("credential"):
            continue
        if copy.get("text") is not None:
            whole = net_decode.credential_by_name(event.get("field") or "",
                                                  event.get("name") or "")
            copy["text"] = "***" if whole else net_decode.mask_credentials(copy["text"],
                                                                         lines=True)
        copy["encoded"] = "***"
        copy["preview"] = ""
        copy["sha256"] = None       # the hash of a short "user:password" is the password
        source = source_of.get(id(event))
        if source is not None and id(source) in position:
            length = event.get("encoded_len")
            _scrub_source(copies[position[id(source)]], event.get("encoded") or "",
                          length if isinstance(length, int) else 0)


def _cut_report_text(copies):
    """Cut the body and message text of the report's event copies to
    ``CAPTURE_TEXT_BUDGET`` characters together, in time order, marking each
    copy cut with ``report_text_cut`` (and ``body_capped`` / ``resp_capped``).
    Only the report is cut: the analysis read the events whole. True when
    anything was cut."""
    budget = net_http.TextBudget(CAPTURE_TEXT_BUDGET)
    cut_any = False
    for copy in copies:
        cut = False
        if copy.get("type") == "http":
            for field, flag in (("body_text", "body_capped"), ("resp_text", "resp_capped")):
                text, spent = net_http._charge_text(copy.get(field), budget)
                if spent:
                    copy[field], copy[flag], cut = text, True, True
        elif copy.get("type") == "websocket" and isinstance(copy.get("messages"), list):
            for message in copy["messages"]:
                if isinstance(message, dict) and isinstance(message.get("text"), str):
                    text, spent = net_http._charge_text(message["text"], budget)
                    if spent:
                        message["text"], cut = text, True
        if cut:
            copy["report_text_cut"] = cut_any = True
    return cut_any


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


def _norm(name):
    return name.lower().rstrip(".") if isinstance(name, str) else ""


def _quiet_addresses(events, claimed, known_good, resolvers=None):
    """Addresses that are a known-good server, not an indicator.

    A claimed name (a Host header, a server name) is not corroboration: the
    sample writes it, and so is an answer of its own DNS server. An address
    is quiet only when an answer of the capture's resolvers
    (``net_dns.trusted_lookups``) mapped a known-good name to it, no answer mapped another name to
    it, and no connection to it claimed a name that such an answer does not
    cover (a name that is not known-good, or a known-good name that was
    resolved elsewhere or not at all). A known-good Host header sent to an
    address no known-good lookup returned keeps that address as an IOC.
    """
    names = {}
    for e in net_dns.trusted_lookups(events, resolvers):
        if e.get("query_type") not in ("A", "AAAA"):
            continue
        for answer in e.get("answers") or ():
            ip = _ip(answer)
            if ip is not None:
                names.setdefault(str(ip), set()).add(_norm(e.get("dest")))
    quiet = {ip for ip, found in names.items()
             if found and all(known_good.hides({"dest": n}) for n in found)}
    for e in events:
        ip = _ip(e.get("dest")) if e.get("type") == "conn" else None
        if ip is None or str(ip) not in quiet:
            continue
        claims = [n for f in claimed.get(id(e)) or ()
                  for n in (f.get("hosts") or [f.get("dest")])]
        for name in claims:
            if not isinstance(name, str) or not name or _ip(name) is not None:
                continue            # a profile of bytes claims no name
            if _norm(name) not in names[str(ip)]:
                quiet.discard(str(ip))
                break
    return quiet


def _iocs(copies, known_good, quiet=frozenset()):
    out = _Indicators()
    addresses = quiet

    def foreign(text):
        ip = _ip(text)
        return ip is None or str(ip) not in addresses

    for e in copies:
        etype = e.get("type")
        if e.get("baseline") == "known" or etype in BEHAVIOR_TYPES:
            continue
        dest = e.get("dest")
        hosts = [h for h in e.get("hosts") or () if isinstance(h, str)]
        name_known = isinstance(dest, str) and known_good.hides({"dest": dest, "hosts": hosts})
        if etype != "decoded" and foreign(dest):
            out.name(dest, e, known_good)
        if len(set(hosts)) > 1:
            # every name of a request that gives several, known good or not
            for host in hosts:
                if _ip(host) is None:
                    out.add("domain", _norm(host), e)
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
    limits = _Limits()
    base, parse_errors, result, claimed = _collect(path, limits)
    errors += parse_errors

    decoded, source_of, decode_budget = _decode_all(base, limits, errors)
    # With a baseline, only the answers of the resolvers it learned on the clean machine count
    # (net_dns.trusted_lookups); without one, the capture's own share rule decides.
    learned = None
    if baseline is not None:
        try:
            learned = baseline.learned_resolvers()
        except Exception as exc:
            errors.append(_failure("net_baseline", exc))

    try:
        behavior = list(net_behavior.analyze(base + decoded, resolvers=learned))
    except Exception as exc:
        errors.append(_failure("net_behavior", exc))
        behavior = []
    events = net_events.sort_events(base + decoded + behavior)

    known = [False] * len(events)
    if baseline is not None:
        resolved = net_baseline.resolved_addresses(events, learned)
        for i, e in enumerate(events):
            try:
                known[i] = bool(baseline.knows_event(e)) and (
                    e.get("type") != "upload" or net_baseline.upload_resolved(e, resolved))
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
                                              observed_fully=MODES[mode], known_good=ruleset,
                                              resolvers=learned)
    except Exception as exc:
        errors.append(_failure("net_evidence", exc))
        findings = []

    copies = net_mail_ftp.masked(events)
    _mask_decoded(events, copies, source_of)
    report_text_cut = _cut_report_text(copies)
    copies = mask_report(_jsonable(copies))
    for event, copy, is_known in zip(events, copies, known):
        copy["known_good"] = (event["type"] not in net_rules.ALWAYS_VISIBLE
                              and known_good.hides(event))
        if is_known:
            copy["baseline"] = "known"
    iocs, iocs_capped = _iocs(copies, known_good,
                              _quiet_addresses(events, claimed, known_good, learned))

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
        "text_budget_spent": any(e.get("text_budget_spent") for e in events),
        "report_text_cut": report_text_cut,
        "max_report_text": CAPTURE_TEXT_BUDGET,
        "events_capped": limits.events_capped,
        "max_events": MAX_EVENTS,
        "flows_capped": limits.flows_capped,
        "flows_unparsed": limits.flows_unparsed,
        "max_events_per_flow": MAX_EVENTS_PER_FLOW,
        "decoded_capped": decode_budget.capped,
        "max_decoded": MAX_DECODED,
        "dns_answers_capped": limits.answers_capped,
        "max_dns_answers": MAX_DNS_ANSWERS,
    }
    # The one masking pass over everything serialized (see mask_report). The
    # event copies went through it above; a second pass over them changes
    # nothing and doubled the time of a capture full of text.
    report["incomplete"] = memory_evidence.network_incomplete(report)
    done = {key: report[key] for key in ("events", "behavior")}
    rest = mask_report(_jsonable(net_mail_ftp.masked(
        {k: v for k, v in report.items() if k not in done})))
    return {k: done[k] if k in done else rest[k] for k in report}
