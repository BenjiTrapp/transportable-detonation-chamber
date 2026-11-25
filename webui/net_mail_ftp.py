"""FTP and SMTP control streams to ``ftp`` and ``smtp`` events.

Infostealers ship their harvest out over FTP or SMTP, and the account they use
travels in clear text, which is the strongest thing a pcap can show about them.
Later phases score the credentials, the envelope (sender, recipients, subject,
attachment names) and the names of uploaded files. The assumptions this module
refuses to make:

  * A credential is harmless to carry around. The password is kept in the event
    because the evidence needs it, but as a ``Secret``, which is deliberately
    not a ``str``. Its repr, ``str()`` and format give ``***``, so a log line or
    traceback does not show it, and anything that would silently copy the text
    out (``json.dumps`` and so ``flask.jsonify``, pickling, ``+``, ``join``)
    raises ``TypeError`` instead. This holds for every ftp and smtp event, with
    or without a password, so a consumer that forgets to mask fails in its
    first test and not on the one capture that held a credential. To put an
    event into a report, an API response, a file or any other serialized form,
    serialize ``masked(event)`` (it also takes a list of events or any nesting,
    and finds a ``Secret`` by type, not by key). The copy has ``***`` (or
    ``""`` when none was captured) for the password; ``password_captured`` is
    the bool that says whether there is one without showing it. The
    ``commands`` list of an FTP session holds ``PASS ***``, never the argument.
    ``Secret.reveal()`` returns the plain text for the one consumer that must
    have it, and nothing else should call it. A ``Secret`` still compares and
    hashes equal to its text, has a truth value and a length.
  * A stream is a whole session. It is routinely cut: a hole ends it
    (``Flow.client_stream`` stops at the first gap), the capture can stop, the
    retention cap shortens it. A line that has no line end is never used (half
    a password would be reported as the account's); the session gives the event
    of what was read before the damage, and ``truncated`` / ``stream_gaps`` /
    ``stream_capped`` say it was cut, like ``net_http``.
  * Everything after STARTTLS (SMTP) or AUTH TLS (FTP) is text. It is
    ciphertext once the server accepts, and parsing it as commands invents
    sessions, while saying nothing makes "no more data" look the same as "the
    session went encrypted here". ``starttls`` is True when the client asked
    for the upgrade and ``encrypted`` says what followed: True when the next
    client bytes are a TLS record (parsing stops there), False when plain text
    went on (the server refused; it is still read), None when nothing followed
    in the capture. Without an upgrade ``starttls`` is False and ``encrypted``
    None. A session that is encrypted from the first byte (SMTPS on 465, FTPS
    implicit) has no readable command and gives no event here; ``net_tls`` has
    its handshake.
  * A message body is small and ends politely. DATA ends only at a lone dot,
    which a crafted capture never sends, and a body can be any size. The body
    is never kept: ``body_bytes`` is the exact count of what followed the
    header section (up to the last byte captured), and only the header block (at
    most ``MAX_HEADER_BLOCK`` bytes per message or MIME part, read for the
    subject and attachment names) is held while a line is read. Every kept list
    holds at most ``MAX_ITEMS`` entries of at most ``MAX_ITEM_CHARS``
    characters; ``capped`` names the fields that lost entries. ``data_complete``
    is False when the dot never came. A body that looks like commands is a body
    (the DATA state decides, not the line), and a DATA the server refused (no
    354 for it) does not swallow the commands after it; when the server's side
    was not captured completely, DATA is assumed accepted.
  * The first sender is the client. A capture that starts with the server's
    banner makes the reader guess wrongly (``Flow.client_guessed``); a stream
    that starts with a reply code is then taken for the server's.
  * The port names the protocol. Both start with ``220``, and malware does not
    keep to 21 and 25, so the client's commands decide (``USER``/``RETR`` are
    FTP's, ``EHLO``/``MAIL`` SMTP's) and the port, then the banner text, only
    settle a session whose commands fit both (``QUIT``, ``NOOP``) or that has
    none. A stream of anything else is not an event.
  * One connection is one message. Each ``MAIL FROM`` opens a message and
    becomes its own ``smtp`` event with the time of that command, carrying the
    session's credentials; a session without a message gives one event with an
    empty envelope. An FTP control connection is one ``ftp`` event.
  * Login worked because it was sent. ``auth_ok`` is True when the server said
    so (230, 235), False when it refused (530, 535) after a credential was
    sent, and None when the capture does not tell. ``auth_attempts`` counts the
    credentials sent; ``user`` and ``password`` are the last of them.
  * Base64 is base64. ``AUTH LOGIN`` and ``AUTH PLAIN`` (value on the command
    line or on the next line) are decoded; a line that does not decode leaves
    that value empty and the session goes on, and a client that goes on with
    commands (the server refused the mechanism) does not have them read as
    credentials. Other mechanisms (CRAM-MD5, XOAUTH2) carry no password that
    could be read here and are only named in ``auth``.

Not read: the FTP data connections (the file contents are on another flow),
SMTP ``BDAT`` chunks (read as lines) and anything past STARTTLS. Bytes from a
capture are never executed or opened as a file.

``dest`` is the server address and ``port`` its TCP port; ``ts`` is that of the
client's first byte (the ``MAIL FROM`` line for an ``smtp`` event).
"""

import base64
import re
from collections.abc import Iterable, Mapping
from email.header import decode_header, make_header
from email.parser import HeaderParser

import net_flows
from net_events import NetEvent

MAX_ITEMS = 500             # entries of any kept list
MAX_ITEM_CHARS = 512        # characters of one kept entry
MAX_HEADER_BLOCK = 64 * 1024
MAX_MIME_PARTS = 1000       # header blocks of MIME parts parsed per message

_FTP_VERBS = frozenset(
    "USER PASS ACCT CWD CDUP XCUP PWD XPWD LIST NLST MLSD MLST RETR STOR STOU APPE "
    "DELE MKD XMKD RMD XRMD RNFR RNTO TYPE MODE STRU PASV EPSV PORT EPRT LPRT SYST "
    "FEAT OPTS SITE SIZE MDTM REST ABOR STAT PBSZ PROT CCC SMNT REIN ALLO".split())
_SMTP_VERBS = frozenset(
    "HELO EHLO LHLO MAIL RCPT DATA RSET VRFY EXPN STARTTLS BDAT SEND SOML SAML TURN "
    "ETRN".split())
_SHARED_VERBS = frozenset("NOOP QUIT AUTH HELP".split())
_SMTP_ALL = _SMTP_VERBS | _SHARED_VERBS

_FTP_PORTS = frozenset((21, 2121))
_SMTP_PORTS = frozenset((25, 465, 587, 2525))
_FTP_TLS = frozenset(("TLS", "SSL", "TLS-C", "TLS-P"))
_FTP_STORE = frozenset(("STOR", "STOU", "APPE"))

_VERB = re.compile(r"[A-Za-z]{3,4}$")
_BANNER = re.compile(rb"\d{3}[ -]")
_REPLY = re.compile(rb"\d{3}(?:[ -]|\r?$)")
_MAIL_FROM = re.compile(r"MAIL\s+FROM:\s*<?([^>\s]*)", re.I)
_RCPT_TO = re.compile(r"RCPT\s+TO:\s*<?([^>\s]*)", re.I)
_UNFOLD = re.compile(r"\r?\n(?=[ \t])")


class Secret:
    """A password: equal to its text, printed as ``***``, and nothing else.

    Not a ``str``, so the ways a ``str`` leaks without a sound all fail with a
    ``TypeError`` instead: ``json.dumps`` (and so ``flask.jsonify``), pickling,
    concatenation, ``join``, ``in`` and iteration. It still compares and hashes
    like its text, has a truth value and a length, and prints as ``***`` under
    ``repr``, ``str`` and ``format``. ``reveal()`` is the one way to the text.
    """

    __slots__ = ("_text",)

    def __init__(self, text):
        object.__setattr__(self, "_text", text)

    def __setattr__(self, name, value):
        raise AttributeError("a Secret does not change")

    def __eq__(self, other):
        if isinstance(other, Secret):
            return self._text == other._text
        if isinstance(other, str):
            return self._text == other
        return NotImplemented

    def __hash__(self):
        return hash(self._text)

    def __bool__(self):
        return bool(self._text)

    def __len__(self):
        return len(self._text)

    def __repr__(self):
        return "'***'"

    def __str__(self):
        return "***"

    def __format__(self, spec):
        return format("***", spec)

    def __reduce__(self):
        raise TypeError("a Secret cannot be pickled")

    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        return self

    def reveal(self):
        return self._text


def masked(value):
    """A copy of an event, a list of events or any nesting of them that is safe
    to render, log or serialize.

    Every ``Secret`` found, wherever it sits and whatever its key is called, is
    replaced by ``"***"`` (``""`` when it was empty). Mappings come back as
    plain dicts and other iterables (not strings) as lists; everything else is
    returned as it is.
    """
    if isinstance(value, Secret):
        return "***" if value else ""
    if isinstance(value, Mapping):
        return {key: masked(item) for key, item in value.items()}
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        return value
    return [masked(item) for item in value]


# --- reading lines --------------------------------------------------------------

def _lines(stream):
    """``(start, end, text)`` of each line that has a line end, ``text`` without it."""
    pos = 0
    while True:
        eol = stream.find(b"\n", pos)
        if eol < 0:
            return
        yield pos, eol + 1, stream[pos:eol].rstrip(b"\r")
        pos = eol + 1


def _text(raw):
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _clip(text):
    return text[:MAX_ITEM_CHARS]


def _keep(capped, name, items, value, unique=False):
    if unique and value in items:
        return
    if len(items) >= MAX_ITEMS:
        capped.add(name)
        return
    items.append(value)


def _after_starttls(stream, end):
    """What follows the upgrade command: True (a TLS record), False (text) or None."""
    rest = stream[end:end + 1]
    if not rest:
        return None
    return rest[0] in (0x16, 0x80)


def _reply_codes(stream):
    return [int(line[:3]) for line in stream.split(b"\n") if _REPLY.match(line)]


def _auth_ok(codes, attempts, ok, bad):
    if any(c in ok for c in codes):
        return True
    if attempts and any(c in bad for c in codes):
        return False
    return None


# --- one flow, seen from the client -------------------------------------------

class _Side:
    """The flow in client/server terms, whichever way the reader guessed."""

    def __init__(self, flow):
        client, server = flow.client_stream(), flow.server_stream()
        swapped = (bool(flow.client_guessed) and bool(_BANNER.match(client))
                   and not _BANNER.match(server))
        if swapped:
            self.client, self.server = server, client
            self.client_dir = "s"
            self.addr, self.port = flow.src, flow.sport
            client_gaps, server_gaps = flow.server_gaps, flow.client_gaps
        else:
            self.client, self.server = client, server
            self.client_dir = "c"
            self.addr, self.port = flow.dst, flow.dport
            client_gaps, server_gaps = flow.client_gaps, flow.server_gaps
        self.gaps = list(client_gaps) + list(server_gaps)
        self.capped = bool(flow.capped)
        self.cut = bool(self.gaps) or self.capped
        self.server_cut = bool(server_gaps) or self.capped
        self._index = net_flows.stream_time_index(flow.packets, self.client_dir, self.client)
        self._first_ts = flow.first_ts

    def at(self, offset):
        return net_flows.time_at_offset(self._index, offset, self._first_ts)


def _textual(stream, first):
    return not stream or first(stream[:1])


def _protocol(side):
    """"ftp", "smtp" or "" for the stream of a flow."""
    ftp = smtp = unknown = seen = skip = 0
    for _start, _end, raw in _lines(side.client):
        seen += 1
        if seen > 30:
            break
        if skip:                # the base64 of an AUTH exchange, or what follows AUTH TLS
            skip -= 1
            continue
        words = raw.split(None, 1)
        verb = words[0].decode("latin-1").upper() if words else ""
        if verb == "AUTH":
            skip = 2
        if verb in _FTP_VERBS:
            ftp += 1
        elif verb in _SMTP_VERBS:
            smtp += 1
        elif verb not in _SHARED_VERBS:
            unknown += 1
    if ftp != smtp:
        return "ftp" if ftp > smtp else "smtp"
    if not ftp and unknown:
        return ""
    if not (side.client or side.server):
        return ""
    if not (_textual(side.client, bytes.isalpha) and _textual(side.server, bytes.isdigit)):
        return ""
    if side.port in _FTP_PORTS:
        return "ftp"
    if side.port in _SMTP_PORTS:
        return "smtp"
    banner = side.server[:200].upper()
    if b"SMTP" in banner:
        return "smtp"
    if b"FTP" in banner:
        return "ftp"
    return ""


class _Session:
    """What the client side of one connection said, apart from the messages."""

    def __init__(self):
        self.user = ""
        self.password = ""
        self.attempts = 0
        self.starttls = False
        self.encrypted = None
        self.auth = ""
        self.commands = []
        self.files = []
        self.uploaded = []
        self.mails = []
        self.capped = set()
        self.stopped = False

    def upgrade(self, stream, end):
        """Note a TLS upgrade command; True when the rest of the stream is not text."""
        self.starttls = True
        self.encrypted = _after_starttls(stream, end)
        self.stopped = self.encrypted is not False
        return self.stopped


def _partial(side, session):
    """Does the client stream end inside a line that is still to be read?"""
    return bool(side.client) and not session.stopped and not side.client.endswith(b"\n")


def _fields(side, session, codes, ok, bad):
    return dict(
        user=_clip(session.user), password=Secret(_clip(session.password)),
        password_captured=bool(session.password), auth_attempts=session.attempts,
        auth_ok=_auth_ok(codes, session.attempts, ok, bad),
        starttls=session.starttls, encrypted=session.encrypted,
        truncated=side.cut or _partial(side, session),
        stream_gaps=list(side.gaps), stream_capped=side.capped)


# --- ftp ------------------------------------------------------------------------

def _read_ftp(side):
    s = _Session()
    for start, end, raw in _lines(side.client):
        line = _text(raw).lstrip()
        verb, _sep, arg = line.partition(" ")
        verb = verb.upper()
        if not _VERB.match(verb):
            continue
        arg = arg.strip()
        shown = line
        if verb in ("PASS", "ACCT"):
            shown = verb + " ***"
        if verb == "PASS":
            s.password = arg
            s.attempts += 1
        _keep(s.capped, "commands", s.commands, _clip(shown))
        if verb == "USER":
            s.user = arg
        elif verb == "RETR" or verb in _FTP_STORE:
            if arg:
                _keep(s.capped, "files", s.files, _clip(arg), unique=True)
                if verb != "RETR":
                    _keep(s.capped, "uploaded", s.uploaded, _clip(arg), unique=True)
        elif verb == "AUTH" and arg.upper() in _FTP_TLS:
            if s.upgrade(side.client, end):
                break
    return s


def _ftp_event(side):
    s = _read_ftp(side)
    codes = _reply_codes(side.server)
    return NetEvent(
        "ftp", side.at(0), dest=side.addr, port=side.port,
        commands=s.commands, files=s.files, uploaded=s.uploaded,
        capped=sorted(s.capped), **_fields(side, s, codes, (230,), (530,)))


# --- smtp -----------------------------------------------------------------------

def _b64(line):
    text = line.strip()
    text += "=" * (-len(text) % 4)
    try:
        return base64.b64decode(text, validate=True)
    except ValueError:
        return None


def _header_text(value):
    value = _UNFOLD.sub("", value or "")
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def _headers(block):
    try:
        return HeaderParser().parsestr(_text(block), headersonly=True)
    except Exception:
        return None


def _filename(message):
    try:
        return _clip(_header_text(message.get_filename()))
    except Exception:
        return ""


class _Mail:
    """One message of a session: envelope so far, and what DATA showed of it."""

    def __init__(self, ts, sender):
        self.ts = ts
        self.mail_from = sender
        self.rcpt_to = []
        self.subject = ""
        self.attachments = []
        self.body_bytes = 0
        self.data_complete = False
        self.capped = set()
        self._head = bytearray()    # the message's header section
        self._part = None           # the header block of the MIME part being read
        self._parsed = 0            # part blocks parsed so far
        self._in_head = True

    def _grow(self, block, text):
        if len(block) + len(text) + 2 > MAX_HEADER_BLOCK:
            self.capped.add("headers")
        else:
            block += text + b"\r\n"

    def _name(self, name):
        if name:
            _keep(self.capped, "attachments", self.attachments, name)

    def _head_done(self):
        self._in_head = False
        message = _headers(bytes(self._head))
        if message is not None:
            self.subject = _clip(_header_text(message.get("Subject")))
            self._name(_filename(message))

    def _part_done(self):
        block, self._part = self._part, None
        if not block:               # no header lines: nothing to read
            return
        if self._parsed >= MAX_MIME_PARTS:
            self.capped.add("attachments")
            return
        self._parsed += 1
        message = _headers(bytes(block))
        if message is not None:
            self._name(_filename(message))

    def line(self, text, size, complete):
        """Take one line of DATA; True when it is the terminating dot."""
        if complete and text == b".":
            self.data_complete = True
            return True
        if self._in_head:
            if text:
                self._grow(self._head, text)
            else:
                self._head_done()
            return False
        self.body_bytes += size
        if text.startswith(b"--") and len(text) > 2 and b" " not in text:
            self._part_done()
            self._part = bytearray()
        elif self._part is not None:
            if text:
                self._grow(self._part, text)
            else:
                self._part_done()
        return False

    def finish(self):
        if self._in_head:
            self._head_done()
        self._part_done()


def _is_command(line):
    words = line.split(None, 1)
    return bool(words) and words[0].upper() in _SMTP_ALL


def _credentials(s, expect, line):
    """Take one base64 line of an AUTH exchange; returns what is expected next."""
    raw = _b64(line)
    text = _text(raw) if raw is not None else ""
    if expect == "login_user":
        s.user = text
        return "login_pass"
    if expect == "login_pass":
        s.password = text
        s.attempts += raw is not None
        return None
    parts = (raw or b"").split(b"\x00")
    if len(parts) >= 2:
        s.user, s.password = _text(parts[-2]), _text(parts[-1])
        s.attempts += 1
    return None


def _auth(s, line):
    """Handle an AUTH command; returns what is expected on the next line."""
    words = line.split(None, 2)
    mechanism = words[1].upper() if len(words) > 1 else ""
    initial = words[2] if len(words) > 2 else ""
    s.auth = mechanism
    if mechanism == "LOGIN":
        return _credentials(s, "login_user", initial) if initial else "login_user"
    if mechanism == "PLAIN":
        return _credentials(s, "plain", initial) if initial else "plain"
    return None


def _read_smtp(side):
    s = _Session()
    # a refused DATA is told by the server having no 354 for it; with no
    # server side to ask, DATA is taken as accepted
    accepted = _reply_codes(side.server).count(354)
    unchecked = not side.server or side.server_cut
    datas = 0
    mail = None
    in_data = False
    expect = None
    for start, end, raw in _lines(side.client):
        if in_data:
            if mail.line(raw, end - start, True):
                s.mails.append(mail)
                mail = None
                in_data = False
            continue
        line = _text(raw).lstrip()
        if expect:
            if line == "*":
                expect = None
                continue
            if not _is_command(line):
                expect = _credentials(s, expect, line)
                continue
            expect = None
        verb = line.partition(" ")[0].upper()
        if verb == "MAIL":
            found = _MAIL_FROM.match(line)
            if found:
                if mail is not None:
                    s.mails.append(mail)
                mail = _Mail(side.at(start), _clip(found.group(1)))
        elif verb == "RCPT":
            found = _RCPT_TO.match(line)
            if found and mail is not None:
                _keep(mail.capped, "rcpt_to", mail.rcpt_to, _clip(found.group(1)))
        elif verb == "DATA" and mail is not None:
            datas += 1
            in_data = unchecked or datas <= accepted
        elif verb == "RSET" and mail is not None:
            s.mails.append(mail)
            mail = None
        elif verb == "AUTH":
            expect = _auth(s, line)
        elif verb == "STARTTLS":
            if s.upgrade(side.client, end):
                break
    if in_data and not s.stopped:
        tail = side.client[side.client.rfind(b"\n") + 1:]
        if tail:
            mail.line(tail, len(tail), False)
    if mail is not None:
        s.mails.append(mail)
    return s


def _smtp_events(side):
    s = _read_smtp(side)
    shared = _fields(side, s, _reply_codes(side.server), (235,), (535,))
    events = []
    for mail in s.mails or [None]:
        if mail is not None:
            mail.finish()
        capped = s.capped | (mail.capped if mail is not None else set())
        events.append(NetEvent(
            "smtp", mail.ts if mail is not None else side.at(0),
            dest=side.addr, port=side.port,
            mail_from=mail.mail_from if mail else "",
            rcpt_to=mail.rcpt_to if mail else [],
            subject=mail.subject if mail else "",
            body_bytes=mail.body_bytes if mail else 0,
            attachments=mail.attachments if mail else [],
            data_complete=mail.data_complete if mail else False,
            auth=s.auth, capped=sorted(capped), **shared))
    return events


def events_from_flow(flow):
    """``ftp`` or ``smtp`` events of a TCP flow (an ``smtp`` event per message).
    A flow that carries neither gives an empty list."""
    if flow.proto != "tcp":
        return []
    side = _Side(flow)
    kind = _protocol(side)
    if kind == "ftp":
        return [_ftp_event(side)]
    if kind == "smtp":
        return _smtp_events(side)
    return []
