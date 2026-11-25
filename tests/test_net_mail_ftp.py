"""FTP and SMTP sessions to ``ftp`` and ``smtp`` events.

Regressions covered:
  * a stolen-credential upload over FTP or SMTP carries its account in clear
    text; a parser that kept only commands lost the one fact a later phase
    scores. The credentials are captured, and a password never appears in the
    event's repr, in ``str()``, in the recorded command list or in the
    ``masked`` copy (``password_captured`` tells a captured password from an
    absent one without printing it)
  * the password was a ``str`` subclass, so ``json.dumps(event)`` (what
    ``NetEvent`` is documented to allow), pickle, concatenation and ``join``
    wrote the real value with no error; ``Secret`` is not a ``str`` and each of
    those raises, so a report or API response that forgets ``masked`` fails in
    its first test instead of leaking; ``masked`` takes an event, a list of
    events or any nesting and finds credentials by type, not by key name
  * a body of nothing but MIME boundary lines made every line parse the
    previous (empty or header-only) part, which let a capture buy seconds of
    CPU per message; empty parts are not parsed and parsed parts are bounded
  * ``AUTH LOGIN`` / ``AUTH PLAIN`` send base64: both forms (value inline or on
    the next line) are decoded; a line that is not base64, or a server that
    refused the mechanism so the client went on with commands, neither drops
    the session nor turns a command into a credential
  * after STARTTLS (SMTP) or AUTH TLS (FTP) the stream is ciphertext: parsing
    it as commands invented sessions, and saying nothing made "no more data"
    look the same as "went encrypted here"; ``starttls`` and ``encrypted``
    record it, and a refused upgrade whose plain text goes on is still read
  * DATA ends only at a lone dot, which a crafted capture never sends: the
    body is counted, never kept, every kept list is capped and ``capped``
    names what was cut
  * a message body that looks like commands (MAIL FROM, a dot stuffed line) was
    read as protocol; a DATA the server refused swallowed the commands after it
  * one SMTP connection carries several messages; each is its own event with
    the time of its MAIL FROM
  * a stream cut by a gap or ending inside a line gave a half password that
    would be reported as the account's; an unfinished line is never used
  * a capture that starts mid-session made the server the client
  * a flow that is not FTP or SMTP (HTTP on port 25, TLS on 465, UDP) produced
    an event
  * a user name or mail address was decoded as UTF-8 or else Latin-1, so one
    name got two spellings in the report; names keep their bytes
    (``surrogateescape``) for ``net_analyze`` to render as DNS names are
"""

import base64
import copy
import json
import os
import pickle
import socket
import tempfile

import dpkt
import pytest

import net_flows
import net_mail_ftp

CLIENT = "192.0.2.10"
SERVER = "198.51.100.7"
CPORT = 49152

_SYN, _ACK, _PSH = dpkt.tcp.TH_SYN, dpkt.tcp.TH_ACK, dpkt.tcp.TH_PUSH
_SEGMENT = 60000
_TLS = b"\x16\x03\x01\x00\x30"


def _frame(src, sport, dst, dport, seq, ack, flags, payload=b""):
    seg = dpkt.tcp.TCP(sport=sport, dport=dport, seq=seq & 0xFFFFFFFF,
                       ack=ack & 0xFFFFFFFF, flags=flags, win=8192, data=payload)
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst),
                    p=dpkt.ip.IP_PROTO_TCP, ttl=64, data=seg)
    return bytes(dpkt.ethernet.Ethernet(
        dst=b"\x02\x00\x00\x00\x00\x01", src=b"\x02\x00\x00\x00\x00\x02",
        type=dpkt.ethernet.ETH_TYPE_IP, data=ip))


def _udp_frame(payload):
    dgram = dpkt.udp.UDP(sport=CPORT, dport=25, data=payload)
    dgram.ulen = len(dgram)
    ip = dpkt.ip.IP(src=socket.inet_aton(CLIENT), dst=socket.inet_aton(SERVER),
                    p=dpkt.ip.IP_PROTO_UDP, ttl=64, data=dgram)
    return bytes(dpkt.ethernet.Ethernet(
        dst=b"\x02\x00\x00\x00\x00\x01", src=b"\x02\x00\x00\x00\x00\x02",
        type=dpkt.ethernet.ETH_TYPE_IP, data=ip))


def _read(packets):
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "mail.pcap")
        with open(path, "wb") as fh:
            w = dpkt.pcap.Writer(fh, linktype=dpkt.pcap.DLT_EN10MB)
            for ts, buf in packets:
                w.writepkt(buf, ts)
        result = net_flows.read_pcap(path)
    assert len(result.flows) == 1, result.note
    return result.flows[0]


def _session(port, segments, syn=True, drop=()):
    """Write the segments to a pcap, read it back, return the single flow.

    ``segments`` is a list of ``(ts, "c" | "s", payload)`` in the order they are
    written; ``drop`` lists indices that are never captured (their sequence
    space is still used, which leaves a hole), ``syn=False`` a capture that
    begins mid-connection. Going through ``read_pcap`` means the parser is fed
    what the real reader produces.
    """
    ends = {"c": (CLIENT, CPORT, SERVER, port), "s": (SERVER, port, CLIENT, CPORT)}
    isn = {"c": 1000, "s": 5000}
    nxt = {"c": isn["c"] + 1, "s": isn["s"] + 1}
    built = []
    for ts, direction, payload in segments:
        frames = []
        other = "s" if direction == "c" else "c"
        for i in range(0, len(payload), _SEGMENT):
            part = payload[i:i + _SEGMENT]
            frames.append((ts, _frame(*ends[direction], nxt[direction], nxt[other],
                                      _ACK | _PSH, part)))
            nxt[direction] += len(part)
        built.append(frames)
    packets = []
    if syn:
        t0 = min(ts for ts, _d, _p in segments) - 1.0
        packets += [
            (t0, _frame(*ends["c"], isn["c"], 0, _SYN)),
            (t0 + 0.1, _frame(*ends["s"], isn["s"], isn["c"] + 1, _SYN | _ACK)),
            (t0 + 0.2, _frame(*ends["c"], isn["c"] + 1, isn["s"] + 1, _ACK)),
        ]
    for index, frames in enumerate(built):
        if index not in drop:
            packets += frames
    return _read(packets)


def _line_flow(port, client, server=b"", **kw):
    segments = []
    if client:
        segments.append((2.0, "c", client))
    if server:
        segments.append((3.0, "s", server))
    return _session(port, segments, **kw)


def _one(port, client, server=b"", **kw):
    events = net_mail_ftp.events_from_flow(_line_flow(port, client, server, **kw))
    assert len(events) == 1
    return events[0]


def _b64(text):
    return base64.b64encode(text.encode()).decode()


def _mail(*lines, **kw):
    """One message's commands: envelope, DATA, the given lines, the terminator."""
    body = b"".join(line.encode() + b"\r\n" for line in lines)
    return (b"MAIL FROM:<a@evil.top>\r\nRCPT TO:<b@drop.top>\r\nDATA\r\n" + body
            + kw.get("end", b".\r\n"))


_OK_SERVER = b"220 ok\r\n250 ok\r\n250 ok\r\n250 ok\r\n354 go\r\n250 queued\r\n"


# --- the contract from the brief --------------------------------------------

def test_ftp_credentials_and_commands_are_captured():
    e = net_mail_ftp.events_from_flow(_line_flow(21,
        b"USER bot\r\nPASS s3cret\r\nSTOR log.txt\r\n",
        b"220 ok\r\n331 ok\r\n230 ok\r\n150 ok\r\n"))[0]
    assert e["type"] == "ftp" and e["user"] == "bot" and e["password"] == "s3cret"
    assert "log.txt" in e["files"]


def test_smtp_envelope_and_subject_are_captured():
    e = net_mail_ftp.events_from_flow(_line_flow(25,
        b"EHLO x\r\nMAIL FROM:<a@evil.top>\r\nRCPT TO:<b@drop.top>\r\nDATA\r\n"
        b"Subject: logs\r\n\r\nbody\r\n.\r\n",
        b"220 ok\r\n250 ok\r\n250 ok\r\n250 ok\r\n354 go\r\n"))[0]
    assert e["type"] == "smtp" and e["mail_from"] == "a@evil.top"
    assert e["rcpt_to"] == ["b@drop.top"] and e["subject"] == "logs"


def test_smtp_auth_login_credentials_are_decoded():
    e = net_mail_ftp.events_from_flow(_line_flow(587,
        b"AUTH LOGIN\r\nYm90\r\nczNjcmV0\r\n", b"334 x\r\n334 y\r\n235 ok\r\n"))[0]
    assert e["user"] == "bot" and e["password"] == "s3cret"


def test_an_incomplete_session_yields_what_was_seen():
    e = net_mail_ftp.events_from_flow(_line_flow(21, b"USER bot\r\n", b"220 ok\r\n"))[0]
    assert e["user"] == "bot" and e["password"] == ""


# --- credentials are never printed -------------------------------------------

def test_a_password_is_not_in_the_repr_str_or_command_list():
    e = _one(21, b"USER bot\r\nPASS s3cret\r\nACCT hunter2\r\nSTOR a.txt\r\n")
    assert e["password"] == "s3cret"
    for rendered in (repr(e), str(e), repr(e["password"]), str(e["password"]),
                     "%s" % e["password"], "{}".format(e["password"])):
        assert "s3cret" not in rendered
    assert "hunter2" not in repr(e)
    assert e["commands"] == ["USER bot", "PASS ***", "ACCT ***", "STOR a.txt"]


def test_masked_copy_hides_the_password_but_says_whether_there_was_one():
    seen = _one(21, b"USER bot\r\nPASS s3cret\r\n")
    absent = _one(21, b"USER bot\r\n")
    assert seen["password_captured"] is True and absent["password_captured"] is False
    assert net_mail_ftp.masked(seen)["password"] == "***"
    assert net_mail_ftp.masked(absent)["password"] == ""
    assert "s3cret" not in json.dumps(net_mail_ftp.masked(seen))
    assert seen["password"] == "s3cret"          # the event itself is untouched


def test_smtp_password_is_masked_like_ftp():
    e = _one(587, b"AUTH LOGIN\r\nYm90\r\nczNjcmV0\r\n")
    assert e["password_captured"] is True and e["user"] == "bot"
    assert "s3cret" not in repr(e) and "s3cret" not in str(e)
    assert "s3cret" not in json.dumps(net_mail_ftp.masked(e))


# --- the credential type fails closed ---------------------------------------

def test_json_refuses_an_event_that_holds_a_credential():
    e = _one(21, b"USER bot\r\nPASS s3cret\r\n")
    for doc in (e, [e], {"events": [e]}):
        with pytest.raises(TypeError):
            json.dumps(doc)
    absent = _one(21, b"USER bot\r\n")
    with pytest.raises(TypeError):              # not a function of what the capture held
        json.dumps(absent)


def test_a_secret_cannot_be_turned_into_text_by_accident():
    secret = _one(21, b"USER bot\r\nPASS s3cret\r\n")["password"]
    assert not isinstance(secret, str)
    with pytest.raises(TypeError):
        "pw=" + secret
    with pytest.raises(TypeError):
        secret + "x"
    with pytest.raises(TypeError):
        ",".join([secret])
    with pytest.raises(TypeError):
        pickle.dumps(secret)
    with pytest.raises(TypeError):
        pickle.dumps(_one(21, b"USER bot\r\nPASS s3cret\r\n"))
    with pytest.raises(TypeError):
        "s" in secret
    with pytest.raises(TypeError):
        list(secret)
    rendered = "%s %r " % (secret, secret) + "{} {:>10}".format(secret, secret)
    assert "s3cret" not in rendered


def test_a_secret_still_compares_and_counts_like_its_text():
    secret = net_mail_ftp.Secret("s3cret")
    assert secret == "s3cret" and "s3cret" == secret and secret != "other"
    assert secret == net_mail_ftp.Secret("s3cret") and secret != 5
    assert hash(secret) == hash("s3cret") and {"s3cret": 1}[secret] == 1
    assert bool(secret) and len(secret) == 6
    assert not net_mail_ftp.Secret("") and len(net_mail_ftp.Secret("")) == 0
    assert secret.reveal() == "s3cret" and type(secret.reveal()) is str
    assert copy.deepcopy(secret) == "s3cret" and copy.copy(secret) == "s3cret"


def test_masked_takes_one_event_or_many_and_finds_credentials_by_type():
    one = _one(21, b"USER bot\r\nPASS s3cret\r\n")
    two = _one(587, b"AUTH LOGIN\r\nYm90\r\nczNjcmV0\r\n")
    for shaped in (one, [one, two], (one, two), iter([one, two]),
                   {"events": [one], "other": {"deep": [two]}}):
        text = json.dumps(net_mail_ftp.masked(shaped))
        assert "s3cret" not in text and "***" in text
    nested = net_mail_ftp.masked({"a": {"cred": net_mail_ftp.Secret("x1")},
                                  "b": [net_mail_ftp.Secret("")], "c": 3, "d": "text"})
    assert nested == {"a": {"cred": "***"}, "b": [""], "c": 3, "d": "text"}
    assert type(net_mail_ftp.masked(one)) is dict
    assert one["password"] == "s3cret"                    # the original is untouched


# --- SMTP authentication -----------------------------------------------------

def test_auth_plain_inline_and_on_the_next_line():
    blob = base64.b64encode(b"\x00bot\x00s3cret").decode()
    inline = _one(587, ("AUTH PLAIN %s\r\n" % blob).encode())
    nextline = _one(587, ("AUTH PLAIN\r\n%s\r\n" % blob).encode(), b"334 \r\n235 ok\r\n")
    for e in (inline, nextline):
        assert e["user"] == "bot" and e["password"] == "s3cret"
        assert e["auth"] == "PLAIN"


def test_auth_login_with_the_user_on_the_command_line():
    e = _one(587, ("AUTH LOGIN %s\r\n%s\r\n" % (_b64("bot"), _b64("s3cret"))).encode())
    assert e["user"] == "bot" and e["password"] == "s3cret"


def test_a_line_that_is_not_base64_does_not_drop_the_session():
    e = _one(587, b"AUTH LOGIN\r\n!!not base64!!\r\nczNjcmV0\r\n"
                  b"MAIL FROM:<a@evil.top>\r\nRCPT TO:<b@drop.top>\r\n")
    assert e["user"] == "" and e["password"] == "s3cret"
    assert e["mail_from"] == "a@evil.top" and e["rcpt_to"] == ["b@drop.top"]


def test_a_refused_auth_does_not_turn_commands_into_credentials():
    e = _one(25, b"AUTH LOGIN\r\nMAIL FROM:<a@evil.top>\r\nRCPT TO:<b@drop.top>\r\n",
             b"220 hi\r\n504 no such mechanism\r\n")
    assert e["user"] == "" and e["password"] == "" and e["password_captured"] is False
    assert e["mail_from"] == "a@evil.top"


def test_login_result_and_attempts_come_from_the_reply_codes():
    ok = _one(587, b"AUTH LOGIN\r\nYm90\r\nczNjcmV0\r\n", b"334 x\r\n334 y\r\n235 ok\r\n")
    bad = _one(587, b"AUTH LOGIN\r\nYm90\r\nczNjcmV0\r\n", b"334 x\r\n334 y\r\n535 no\r\n")
    unknown = _one(587, b"AUTH LOGIN\r\nYm90\r\nczNjcmV0\r\n", b"334 x\r\n")
    assert ok["auth_ok"] is True and bad["auth_ok"] is False and unknown["auth_ok"] is None
    assert ok["auth_attempts"] == 1


def test_ftp_login_result_and_the_last_attempt_is_reported():
    e = _one(21, b"USER a\r\nPASS one\r\nUSER b\r\nPASS two\r\n",
             b"220 ok\r\n331 x\r\n530 no\r\n331 x\r\n230 in\r\n")
    assert e["user"] == "b" and e["password"] == "two"
    assert e["auth_attempts"] == 2 and e["auth_ok"] is True
    failed = _one(21, b"USER a\r\nPASS one\r\n", b"220 ok\r\n331 x\r\n530 no\r\n")
    assert failed["auth_ok"] is False


# --- STARTTLS ----------------------------------------------------------------

def test_smtp_starttls_is_recorded_and_the_ciphertext_is_not_parsed():
    e = _one(587, b"EHLO x\r\nSTARTTLS\r\n" + _TLS + b"\r\nMAIL FROM:<hidden@x.top>\r\n",
             b"220 hi\r\n250 ok\r\n220 go ahead\r\n")
    assert e["starttls"] is True and e["encrypted"] is True
    assert e["mail_from"] == "" and e["rcpt_to"] == []


def test_a_refused_starttls_keeps_reading_the_plain_text_that_follows():
    e = _one(25, b"STARTTLS\r\nMAIL FROM:<a@evil.top>\r\n",
             b"220 hi\r\n454 tls not available\r\n")
    assert e["starttls"] is True and e["encrypted"] is False
    assert e["mail_from"] == "a@evil.top"


def test_starttls_with_nothing_after_it_is_unknown_not_plain():
    e = _one(587, b"EHLO x\r\nSTARTTLS\r\n")
    assert e["starttls"] is True and e["encrypted"] is None
    assert _one(587, b"EHLO x\r\n")["starttls"] is False


def test_ftp_auth_tls_is_recorded_and_the_login_after_it_is_not_readable():
    e = _one(21, b"AUTH TLS\r\n" + _TLS + b"\r\nUSER hidden\r\n",
             b"220 ok\r\n234 go\r\n")
    assert e["starttls"] is True and e["encrypted"] is True and e["user"] == ""
    refused = _one(21, b"AUTH TLS\r\nUSER bot\r\n", b"220 ok\r\n502 no\r\n")
    assert refused["encrypted"] is False and refused["user"] == "bot"


# --- the message -------------------------------------------------------------

def test_body_bytes_counts_the_body_after_the_headers():
    e = _one(25, _mail("Subject: logs", "", "body"), _OK_SERVER)
    assert e["body_bytes"] == len(b"body\r\n") and e["data_complete"] is True


def test_encoded_and_folded_subjects_are_decoded():
    encoded = "=?UTF-8?B?%s?=" % _b64("Zugangsdaten für ü")
    e = _one(25, _mail("Subject: " + encoded, "", "x"), _OK_SERVER)
    assert e["subject"] == "Zugangsdaten für ü"
    folded = _one(25, _mail("Subject: part one", " and two", "", "x"), _OK_SERVER)
    assert folded["subject"] == "part one and two"


def test_attachment_names_come_from_the_mime_parts():
    e = _one(25, _mail(
        "Subject: s", 'Content-Type: multipart/mixed; boundary="B"', "",
        "--B", "Content-Type: text/plain", "", "hello",
        "--B", 'Content-Type: application/zip; name="loot.zip"',
        'Content-Disposition: attachment; filename="passwords.zip"', "", "UEsDBA==",
        "--B", "Content-Disposition: attachment;", ' filename="shot.png"', "", "iVBO",
        "--B--"), _OK_SERVER)
    assert e["attachments"] == ["passwords.zip", "shot.png"]


def test_a_body_that_looks_like_commands_is_still_a_body():
    e = _one(25, _mail("Subject: s", "", "MAIL FROM:<fake@x.top>", "RCPT TO:<fake@x.top>",
                       "..", "QUIT") + b"RSET\r\n", _OK_SERVER)
    assert e["mail_from"] == "a@evil.top" and e["rcpt_to"] == ["b@drop.top"]
    assert e["data_complete"] is True


def test_a_refused_data_does_not_swallow_the_commands_after_it():
    client = (b"MAIL FROM:<a@evil.top>\r\nRCPT TO:<b@drop.top>\r\nDATA\r\n"
              b"MAIL FROM:<c@evil.top>\r\nRCPT TO:<d@drop.top>\r\n")
    server = b"220 hi\r\n250 ok\r\n250 ok\r\n554 no valid recipients\r\n250 ok\r\n250 ok\r\n"
    events = net_mail_ftp.events_from_flow(_line_flow(25, client, server))
    assert [e["mail_from"] for e in events] == ["a@evil.top", "c@evil.top"]
    assert events[0]["data_complete"] is False and events[0]["body_bytes"] == 0


def test_several_messages_are_several_events_with_their_own_time():
    first = _mail("Subject: one", "", "x")
    second = _mail("Subject: two", "", "yy").replace(b"a@evil.top", b"c@evil.top")
    flow = _session(25, [(2.0, "c", b"EHLO x\r\n" + first), (7.0, "c", second),
                         (8.0, "s", _OK_SERVER + _OK_SERVER)])
    events = net_mail_ftp.events_from_flow(flow)
    assert [e["subject"] for e in events] == ["one", "two"]
    assert [e["mail_from"] for e in events] == ["a@evil.top", "c@evil.top"]
    assert events[0]["ts"] == 2.0 and events[1]["ts"] == 7.0


def test_the_envelope_forms_of_mail_from_and_rcpt_to():
    e = _one(25, b"mail from: <A@Evil.top> SIZE=100\r\nrcpt to:<b@drop.top>\r\n"
                 b"RCPT TO: c@drop.top\r\n")
    assert e["mail_from"] == "A@Evil.top"
    assert e["rcpt_to"] == ["b@drop.top", "c@drop.top"]
    assert _one(25, b"MAIL FROM:<>\r\n")["mail_from"] == ""


def test_a_session_without_a_message_still_gives_one_event():
    e = _one(25, b"EHLO x\r\nAUTH LOGIN\r\nYm90\r\nczNjcmV0\r\nQUIT\r\n")
    assert e["type"] == "smtp" and e["mail_from"] == "" and e["rcpt_to"] == []
    assert e["user"] == "bot"


# --- bounds ------------------------------------------------------------------

def test_a_data_that_never_ends_is_counted_and_not_kept():
    size = 2 * 1024 * 1024
    body = (b"x" * 70 + b"\r\n") * (size // 72)
    e = _one(25, _mail("Subject: big", "", end=b"") + body, _OK_SERVER)
    assert e["data_complete"] is False and e["subject"] == "big"
    assert e["body_bytes"] == len(body)
    assert len(repr(e)) < 5000


def test_kept_lists_are_capped_and_the_cap_is_visible():
    cap = net_mail_ftp.MAX_ITEMS
    many = b"".join(b"RCPT TO:<u%d@drop.top>\r\n" % i for i in range(cap + 50))
    smtp = _one(25, b"MAIL FROM:<a@evil.top>\r\n" + many)
    assert len(smtp["rcpt_to"]) == cap and "rcpt_to" in smtp["capped"]
    ftp = _one(21, b"".join(b"STOR f%d\r\n" % i for i in range(cap + 50)))
    assert len(ftp["files"]) == cap and len(ftp["commands"]) == cap
    assert set(ftp["capped"]) == {"commands", "files", "uploaded"}
    assert _one(21, b"USER bot\r\n")["capped"] == []


def test_one_long_command_is_cut_to_a_bounded_length():
    e = _one(21, b"USER bot\r\nSTOR " + b"a" * 5000 + b"\r\n")
    assert len(e["files"][0]) <= net_mail_ftp.MAX_ITEM_CHARS
    assert len(e["commands"][1]) <= net_mail_ftp.MAX_ITEM_CHARS


# --- ftp ---------------------------------------------------------------------

def test_ftp_uploads_are_told_from_downloads():
    e = _one(21, b"USER bot\r\nRETR tool.exe\r\nSTOR loot.zip\r\nAPPE log.txt\r\nSTOR loot.zip\r\n")
    assert e["files"] == ["tool.exe", "loot.zip", "log.txt"]
    assert e["uploaded"] == ["loot.zip", "log.txt"]


def test_ftp_ignores_lines_that_are_not_commands():
    e = _one(21, b"USER bot\r\n\x00\x01\x02garbage\xff\r\nsomething not ftp at all\r\nNOOP\r\n")
    assert e["commands"] == ["USER bot", "NOOP"]


# --- the flow ----------------------------------------------------------------

def test_the_event_has_the_schema_fields_and_the_time_of_the_first_command():
    e = _one(21, b"USER bot\r\n", b"220 ok\r\n")
    assert e["dest"] == SERVER and e["dest_is_ip"] is True and e["port"] == 21
    assert e["in_tree"] is False and e["ts"] == 2.0     # not the SYN's 1.0


def test_the_protocol_follows_the_content_not_only_the_port():
    assert _one(2121, b"USER bot\r\nPASS x\r\n")["type"] == "ftp"
    assert _one(2222, b"EHLO x\r\nMAIL FROM:<a@b.top>\r\n")["type"] == "smtp"
    assert _one(25, b"QUIT\r\n")["type"] == "smtp"
    assert _one(21, b"QUIT\r\n")["type"] == "ftp"
    assert _one(7000, b"NOOP\r\n", b"220 ProFTPD ready\r\n")["type"] == "ftp"
    assert _one(7000, b"NOOP\r\n", b"220 mx ESMTP ready\r\n")["type"] == "smtp"


def test_a_session_of_which_only_the_server_banner_was_captured_is_still_an_event():
    assert _one(25, b"", b"220 mx ESMTP ready\r\n")["type"] == "smtp"
    assert _one(21, b"", b"220 FTP server ready\r\n")["type"] == "ftp"


def test_flows_that_are_not_ftp_or_smtp_give_no_events():
    http = _line_flow(25, b"GET / HTTP/1.1\r\nHost: x.top\r\n\r\n", b"HTTP/1.1 200 OK\r\n\r\n")
    assert net_mail_ftp.events_from_flow(http) == []
    implicit_tls = _line_flow(465, _TLS + b"\x01" * 48, b"\x16\x03\x03" + b"\x02" * 20)
    assert net_mail_ftp.events_from_flow(implicit_tls) == []
    assert net_mail_ftp.events_from_flow(_line_flow(21, b"\x00\x01\x02\x03\r\n")) == []
    udp = _read([(1.0, _udp_frame(b"USER bot\r\nPASS x\r\n"))])
    assert udp.proto == "udp" and net_mail_ftp.events_from_flow(udp) == []


def test_a_capture_that_starts_with_the_server_banner_is_not_read_backwards():
    flow = _session(21, [(1.0, "s", b"220 ok\r\n"), (2.0, "c", b"USER bot\r\nPASS s3cret\r\n"),
                         (3.0, "s", b"331 x\r\n230 y\r\n")], syn=False)
    assert flow.client_guessed and flow.src == SERVER       # the reader guessed wrongly
    e = net_mail_ftp.events_from_flow(flow)[0]
    assert e["user"] == "bot" and e["password"] == "s3cret"
    assert e["dest"] == SERVER and e["port"] == 21


def test_a_hole_in_the_client_stream_ends_the_session_there_and_says_so():
    flow = _session(21, [(2.0, "c", b"USER bot\r\n"), (3.0, "c", b"PASS s3cret\r\n"),
                         (4.0, "c", b"STOR late.txt\r\n"), (5.0, "s", b"220 ok\r\n")],
                    drop=(1,))
    e = net_mail_ftp.events_from_flow(flow)[0]
    assert e["user"] == "bot" and e["password"] == "" and e["files"] == []
    assert e["truncated"] is True and e["stream_gaps"] == [len(b"PASS s3cret\r\n")]


def test_an_unfinished_last_line_is_never_used():
    e = _one(21, b"USER bot\r\nPASS s3cr")
    assert e["user"] == "bot" and e["password"] == "" and e["password_captured"] is False
    assert e["truncated"] is True
    assert _one(21, b"USER bot\r\n")["truncated"] is False


def test_an_unfinished_data_line_still_counts_toward_the_body():
    e = _one(25, _mail("Subject: s", "", "abc", end=b"") + b"partial", _OK_SERVER)
    assert e["body_bytes"] == len(b"abc\r\n") + len(b"partial")


def test_non_ascii_bytes_do_not_raise():
    e = _one(21, b"USER b\xe4\xf6t\r\nSTOR \xff\xfe.txt\r\n")
    assert e["user"].encode("ascii", "surrogateescape") == b"b\xe4\xf6t"
    assert len(e["files"]) == 1


def test_boundary_lines_do_not_buy_a_parse_each(monkeypatch):
    calls = []
    real = net_mail_ftp._headers
    monkeypatch.setattr(net_mail_ftp, "_headers", lambda block: calls.append(1) or real(block))
    empty = [b"--x"] * 20000
    e = _one(25, _mail("Subject: s", "", *[line.decode() for line in empty]), _OK_SERVER)
    assert e["data_complete"] is True and len(calls) == 1      # the message headers only
    del calls[:]
    parts = []
    for _ in range(5000):
        parts += ["--x", "X-Filler: 1", ""]
    e = _one(25, _mail("Subject: s", "", *parts), _OK_SERVER)
    assert len(calls) <= net_mail_ftp.MAX_MIME_PARTS + 1
    assert "attachments" in e["capped"]
    assert e["subject"] == "s" and e["body_bytes"] > 0


def test_attachments_before_the_part_limit_are_still_found():
    e = _one(25, _mail(
        "Subject: s", "", "--B", 'Content-Disposition: attachment; filename="a.zip"', "",
        "data", "--B--"), _OK_SERVER)
    assert e["attachments"] == ["a.zip"] and e["capped"] == []


# --- names keep their bytes -----------------------------------------------------------------

def _wire(text):
    return text.encode("ascii", "surrogateescape")


def test_mail_addresses_keep_their_bytes():
    e = _one(25, b"EHLO x\r\nMAIL FROM:<a@T\xe9p\x1b.top>\r\nRCPT TO:<b@d\xc3\xa9.top>\r\n"
                 b"QUIT\r\n", b"220 smtp\r\n250 ok\r\n250 ok\r\n250 ok\r\n")
    assert _wire(e["mail_from"]) == b"a@T\xe9p\x1b.top"
    assert [_wire(r) for r in e["rcpt_to"]] == [b"b@d\xc3\xa9.top"]


def test_user_names_keep_their_bytes():
    ftp = _one(21, b"USER b\x1bot\xe9\r\nPASS x\r\n", b"220 ftp\r\n331 ok\r\n230 ok\r\n")
    assert _wire(ftp["user"]) == b"b\x1bot\xe9"
    user = base64.b64encode(b"m\xc3\xa4il\x1b@e.top")
    smtp = _one(25, b"EHLO x\r\nAUTH LOGIN\r\n" + user + b"\r\n" + base64.b64encode(b"pw")
                + b"\r\nQUIT\r\n", b"220 smtp\r\n250 ok\r\n334 x\r\n334 y\r\n235 ok\r\n")
    assert _wire(smtp["user"]) == b"m\xc3\xa4il\x1b@e.top"
