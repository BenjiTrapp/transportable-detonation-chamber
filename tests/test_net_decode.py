"""Decoding of encoded values found in network events.

Regressions covered:
  * every long alphanumeric string looks like base64 and every even-length run
    of hex digits looks like hex; decoding eagerly reported hashes, session
    ids, UUIDs, JWT signatures, long identifiers and random tokens as
    "decoded", and buried the one field that mattered. A result is reported
    only when it is text or a known file type, and a seeded batch of random
    tokens must produce no report at all
  * a value that decodes to nothing but zero bytes or spaces counted as
    printable and was reported
  * a base64 blob that decodes to a PE (or ELF, zip, PDF, image, SQLite) is not
    readable text and was dropped, although it is the most interesting finding
  * UTF-16LE text (PowerShell -EncodedCommand, most Windows stealers) was
    judged by its NUL bytes and dropped as binary; a C string's trailing NUL
    made short text look binary
  * base64 of a gzip or zlib blob, base64 of base64, and a percent-escaped
    base64 value stayed unreadable behind their outer layer; the depth is
    capped and an inflating layer is bounded, so a nest of layers or a
    decompression bomb cannot run away
  * ordinary URL encoding (``%20`` in a sentence) was reported as a decoded
    payload for every request with a space in its query
  * a field may hold bytes that are not UTF-8, a lone surrogate or a non-string;
    none of them raise
  * a base64 value in a form field, a JSON string or a multipart part was
    missed because only the whole body was examined; a value that is
    form-encoded base64 (``+`` and ``=`` intact) was mangled by treating ``+``
    as a space
  * an event holding a ``Secret`` (ftp, smtp) must stay as unserializable as it
    was: only the named text fields are read, nothing is copied across
  * a decoded event carried raw bytes and could not be serialized; binary
    results are described by kind, size, hash and a ``render_bytes`` preview
  * HTTP headers were not read, so ``Authorization: Basic`` (user:password in
    base64) and tokens in ``Cookie`` or a header the malware invented stayed
    opaque; every header value is read, not an allow-list of names. A ``Basic``
    credential is only a few characters long ("user:pass" is 12) and fell
    under the general length floor, so the scheme itself is evidence enough.
    A decoded credential is marked ``credential`` for the later tasks that
    mask at the serialization boundary: they can only mask what is marked
  * ``credential`` was False for plainly credential-bearing text, the direction
    that leaks: a password with a space, ``name=value`` and JSON pairs with a
    ``password`` key, URL userinfo, a second line that was not credential-
    shaped, a long password, and the line format of a browser-credential dump
    (``Chrome|https://bank.com|bob|Passw0rd!``) all went unmarked. The marker
    errs towards True: a false mark costs a reader one ``***``, a missed one
    puts a password in a report for good
  * ``pw`` and a bare ``p`` (``u=bob&p=hunter2``, ``?pw=...``, ``{"pw": ...}``)
    were not secret words, two of the commonest field names in real logins and
    in minimal exfil forms; they count as whole words only, so ``map=3`` and
    ``page`` stay unmarked
  * a password that is itself a URL (``bob:https://x.com/zzz``) was cut out
    before the colon check and went unmarked
  * a 12-character base64 value (``password``, ``root:toor``, ``hostname``) was
    under the floor although it is 25 times less likely to fool the decoder
    than the 10-character hex floor that is accepted
  * a text that begins with ``MZ`` or ``GIF89a`` was reported as a PE or GIF
    with its text dropped; those magics (and ``%PDF-``, ``Rar!``) count only
    when the bytes are not readable text
  * an event with thousands of encoded values (a WebSocket stream, a huge form)
    made the walk unbounded; the number of values, the scanned size and the
    reported events are capped
"""

import base64
import gzip
import hashlib
import json
import random
import time
import zlib

import pytest

import net_decode
import net_events
import net_mail_ftp
import test_net_http as pcap_http     # builds events through the real read_pcap -> net_http path


def b64(raw):
    return base64.b64encode(raw).decode()


# --- the brief ---------------------------------------------------------------

def test_base64_that_yields_text_is_decoded():
    d = net_decode.decode("aGVsbG8gd29ybGQ=")
    assert d.scheme == "base64" and d.text == "hello world"


def test_base64_that_yields_noise_is_not_decoded():
    assert net_decode.decode("3q2+7w3q2+7w3q2+7w==") is None


def test_base64_that_yields_a_pe_is_decoded_as_a_file():
    d = net_decode.decode(base64.b64encode(b"MZ\x90\x00" + b"\x00" * 60).decode())
    assert d.scheme == "base64" and d.kind == "pe"


def test_hex_that_yields_text_is_decoded():
    assert net_decode.decode("68656c6c6f").text == "hello"


def test_url_encoding_is_decoded():
    assert net_decode.decode("a%20b%26c").text == "a b&c"


def test_a_short_value_is_left_alone():
    assert net_decode.decode("abcd") is None


def test_binary_input_does_not_raise():
    assert net_decode.decode(b"\xff\xfe\x00\x01" * 8) is None


def test_decoding_walks_the_fields_of_an_http_event():
    e = net_events.NetEvent("http", 1.0, dest="evil.top", method="POST",
                            body_text="data=aGVsbG8gd29ybGQ=")
    out = net_decode.decode_event_fields(e)
    assert [d["type"] for d in out] == ["decoded"]
    assert out[0]["text"] == "hello world" and out[0]["field"] == "body_text"


# --- when not to decode ------------------------------------------------------

NOT_ENCODED = [
    "d41d8cd98f00b204e9800998ecf8427e",                      # md5
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "550e8400-e29b-41d4-a716-446655440000",                  # uuid
    "7f3a9c1e4b2d8f06a5e1c3b9d7f20486",                      # session id
    "ThisIsAVeryLongCamelCaseIdentifierName",
    "usr/local/lib/python3/site-packages/requests",
    "SGVsbG8",                                               # decodes, but 7 chars: too short
    "0123456789012345",                                      # digits only
    "AAAAAAAAAAAAAAAAAAAAAAAA",                              # zero bytes
    "2020202020202020",                                      # hex of spaces
    "deadbeefdeadbeefdeadbeef",
    "Mozilla/5.0",
    "",
    "   ",
]


@pytest.mark.parametrize("value", NOT_ENCODED)
def test_ordinary_strings_are_not_decoded(value):
    assert net_decode.decode(value) is None


def test_a_jwt_signature_is_noise_but_its_header_is_json():
    header = b64(b'{"alg":"HS256","typ":"JWT"}').rstrip("=")
    signature = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    assert net_decode.decode(signature) is None
    assert net_decode.decode(header).text == '{"alg":"HS256","typ":"JWT"}'


def test_random_tokens_are_never_reported():
    rng = random.Random(8)
    reported = []
    for _ in range(4000):
        raw = bytes(rng.randrange(256) for _ in range(rng.randrange(8, 48)))
        for token in (b64(raw), raw.hex(), base64.urlsafe_b64encode(raw).decode().rstrip("=")):
            d = net_decode.decode(token)
            if d is not None:
                reported.append((token, d.scheme, d.kind))
    assert reported == []


def _reported_share(alphabet, low, high, count, seed):
    rng = random.Random(seed)
    hits = 0
    for _ in range(count):
        length = rng.randrange(low, high + 1) // 2 * 2
        if net_decode.decode("".join(rng.choice(alphabet) for _ in range(length))):
            hits += 1
    return hits / count


def test_decimal_numbers_are_almost_never_read_as_hex():
    """A 16 to 24 digit number is valid hex; the plain-character rule for short
    results keeps the rate at about 0.2 % (measured 182 in 100000)."""
    assert _reported_share("0123456789", 16, 24, 20000, 21) < 0.004


def test_short_random_hex_ids_are_rarely_read_as_text():
    """Measured 152 in 100000 for 10 to 14 hex digits; longer ids almost never."""
    assert _reported_share("0123456789abcdef", 10, 14, 20000, 22) < 0.004
    assert _reported_share("0123456789abcdef", 16, 32, 20000, 23) < 0.0008


def test_plain_url_encoding_of_a_sentence_is_not_a_finding():
    assert net_decode.decode("hello%20world%20and%20more") is None
    assert net_decode.decode("a%20b") is None
    assert net_decode.decode("redirect%3Dhttp%3A%2F%2Fexample.com%2Fpath%2Fto") is None


def test_text_without_letters_or_digits_is_not_a_finding():
    assert net_decode.decode("2d2d2d2d2d2d2d2d2d2d") is None      # twenty hyphens


# --- the base64 floor -------------------------------------------------------

@pytest.mark.parametrize("word", [b"password", b"root:toor", b"hostname", b"Administrator1", b"cmd /c dir"])
def test_a_twelve_character_base64_value_is_decoded(word):
    token = b64(word)
    assert len(token) >= net_decode.MIN_BASE64 == 12
    assert net_decode.decode(token).text == word.decode()


def test_below_the_floor_base64_is_left_alone():
    assert net_decode.decode(b64(b"whoami")) is None      # 8 characters
    assert net_decode.decode("aGVsbG8=") is None


def test_twelve_character_random_base64_is_almost_never_read_as_text():
    """Measured about 0.006 % by review (12 in 200000), 25 times below the hex floor."""
    rng = random.Random(31)
    hits = sum(1 for _ in range(30000)
               if net_decode.decode(b64(bytes(rng.randrange(256) for _ in range(9)))))
    assert hits / 30000 < 0.0005


# --- readable text that starts like a file -------------------------------------

@pytest.mark.parametrize("text", [
    b"MZ-Berlin weekly report: all quiet this week, nothing to add for the board, see you Monday",
    b"GIF89a is the image format we use in the report",
    b"GIF87a and friends: a list of formats",
    b"%PDF-1.4 is what the printer driver writes, see the manual",
    b"Rar!\x1a\x07 is how the archive starts, as plain text",
])
def test_readable_text_that_starts_like_a_file_is_text(text):
    for token in (b64(text), text.hex()):
        d = net_decode.decode(token)
        assert d.kind == "text" and d.text == text.decode()


def test_a_real_file_is_still_a_file_not_text():
    for kind in ("pe", "pdf", "png", "elf", "zip"):
        assert net_decode.decode(b64(FILES[kind])).kind == kind
    pe = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00" + bytes(range(256)) * 2
    assert net_decode.decode(b64(pe)).kind == "pe"


# --- what is decoded ---------------------------------------------------------

def test_hex_is_case_insensitive():
    assert net_decode.decode("48656C6C6F20576F726C64").text == "Hello World"


def test_base64_without_padding_and_urlsafe_alphabet():
    raw = b"user=admin&pass=????>>>>"
    token = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    assert "-" in token or "_" in token
    d = net_decode.decode(token)
    assert d.text == raw.decode() and d.scheme == "base64"


def test_both_base64_alphabets_in_one_value_is_not_base64():
    assert net_decode.decode("abcd+efgh_ijkl-mnop/qrst") is None


def test_misplaced_padding_is_not_base64():
    assert net_decode.decode("aGVsbG8=gd29ybGQ=") is None


def test_a_line_wrapped_base64_blob_is_one_value():
    raw = b"The quick brown fox jumps over the lazy dog. " * 4
    wrapped = base64.encodebytes(raw).decode()
    assert "\n" in wrapped.strip()
    assert net_decode.decode(wrapped).text == raw.decode()


def test_utf8_text_is_decoded_as_utf8():
    d = net_decode.decode(b64("Grüße aus Köln".encode()))
    assert d.text == "Grüße aus Köln" and d.charset == "utf-8"


def test_utf16le_text_is_decoded():
    command = "Get-Process | Out-File c:\\x.txt"
    d = net_decode.decode(b64(command.encode("utf-16-le")))
    assert d.text == command and d.charset == "utf-16-le"


def test_a_c_string_with_its_terminator_is_text():
    assert net_decode.decode(b64(b"admin:secret1\x00")).text == "admin:secret1"


def test_ansi_text_with_one_accented_byte_is_text():
    d = net_decode.decode(b64("user=Müller&host=PC01".encode("cp1252")))
    assert d.text == "user=Müller&host=PC01" and d.charset == "cp1252"


def test_mostly_binary_bytes_are_not_text():
    assert net_decode.decode(b64(bytes(range(0, 40)))) is None


def test_url_encoding_of_non_ascii_text():
    d = net_decode.decode("%E4%BD%A0%E5%A5%BD%E4%B8%96%E7%95%8C%EF%BC%8C%E6%AC%A2%E8%BF%8E")
    assert d.text == "你好世界，欢迎" and d.scheme == "url"


def test_escaping_a_letter_is_deliberate_and_decoded():
    d = net_decode.decode("%75ser%3Dadmin%26pass%3Dhunter2")
    assert d.text == "user=admin&pass=hunter2"


def test_escaping_every_character_is_decoded():
    d = net_decode.decode("".join("%%%02x" % b for b in b"cmd=whoami"))
    assert d.text == "cmd=whoami"


def test_a_percent_that_is_not_an_escape_is_left_alone():
    assert net_decode.decode("100%25%zz") is None


def test_bytes_input_is_read_like_text():
    d = net_decode.decode(b"aGVsbG8gd29ybGQ=")
    assert d.text == "hello world"


def test_surrounding_whitespace_is_ignored():
    assert net_decode.decode("  aGVsbG8gd29ybGQ=\r\n").text == "hello world"


def test_decoded_keeps_the_raw_bytes():
    d = net_decode.decode("68656c6c6f")
    assert d.bytes == b"hello"


# --- files -------------------------------------------------------------------

FILES = {
    "pe": b"MZ\x90\x00" + b"\x00" * 60,
    "elf": b"\x7fELF\x02\x01\x01" + b"\x00" * 40,
    "zip": b"PK\x03\x04" + b"\x14\x00" * 20,
    "pdf": b"%PDF-1.4\n" + b"\x00\xff" * 10,
    "png": b"\x89PNG\r\n\x1a\n" + b"\x00" * 30,
    "sqlite": b"SQLite format 3\x00" + b"\x10\x00" * 20,
    "gzip": gzip.compress(bytes(range(256)) * 4),
}


@pytest.mark.parametrize("kind", sorted(FILES))
def test_known_file_types_are_decoded_as_files(kind):
    for token in (b64(FILES[kind]), FILES[kind].hex()):
        d = net_decode.decode(token)
        assert d is not None and d.kind == kind and d.text is None
        assert d.bytes == FILES[kind]


def test_a_file_signature_alone_is_not_a_file():
    assert net_decode.decode(b64(b"MZ" + b"\x00\x01\x02\x03\x80\x81\x82\x83")) is None


def test_plain_text_has_kind_text():
    assert net_decode.decode("68656c6c6f").kind == "text"


# --- nesting -----------------------------------------------------------------

def test_base64_of_gzip_is_read_through():
    d = net_decode.decode(b64(gzip.compress(b"stolen credentials: admin / hunter2")))
    assert d.text == "stolen credentials: admin / hunter2"
    assert d.layers == ("base64", "gzip") and d.scheme == "base64+gzip"


def test_base64_of_zlib_is_read_through():
    d = net_decode.decode(b64(zlib.compress(b"stolen credentials: admin / hunter2")))
    assert d.layers == ("base64", "zlib") and d.text.startswith("stolen")


def test_base64_of_a_compressed_pe_is_a_pe():
    d = net_decode.decode(b64(zlib.compress(FILES["pe"] + b"\x01" * 100)))
    assert d.kind == "pe" and d.layers == ("base64", "zlib")


def test_base64_twice():
    d = net_decode.decode(b64(b64(b"stolen credentials: admin / hunter2").encode()))
    assert d.layers == ("base64", "base64") and d.text == "stolen credentials: admin / hunter2"


def test_a_percent_escaped_base64_value():
    d = net_decode.decode("aGVsbG8gd29ybGQ%3D")
    assert d.text == "hello world" and d.layers == ("url", "base64")


def test_compressed_noise_is_not_reported_unless_it_is_a_gzip_file():
    rng = random.Random(1)
    noise = bytes(rng.randrange(256) for _ in range(200))
    assert net_decode.decode(b64(zlib.compress(noise))) is None
    d = net_decode.decode(b64(gzip.compress(noise)))
    assert d.kind == "gzip" and d.layers == ("base64",)


def test_layers_stop_at_the_cap():
    raw = b"stolen credentials: admin / hunter2"
    token = raw
    for _ in range(net_decode.MAX_LAYERS + 3):
        token = b64(token).encode()
    d = net_decode.decode(token)
    assert d is not None and len(d.layers) == net_decode.MAX_LAYERS
    assert d.text != raw.decode()


def test_a_decompression_bomb_is_cut_at_the_ceiling():
    bomb = b64(gzip.compress(b"A" * (20 * 1024 * 1024), 9))
    started = time.time()
    d = net_decode.decode(bomb)
    assert time.time() - started < 5
    assert d.truncated is True and len(d.bytes) <= net_decode.MAX_INFLATED


def test_a_value_over_the_input_cap_is_decoded_from_its_start():
    raw = (b"credential dump line\n" * 40000)[:700000]
    d = net_decode.decode(b64(raw))
    assert d.truncated is True
    assert d.text.startswith("credential dump line")
    assert len(d.bytes) <= net_decode.MAX_INPUT


def test_a_value_within_the_cap_is_not_flagged():
    assert net_decode.decode("aGVsbG8gd29ybGQ=").truncated is False


# --- input that is not text --------------------------------------------------

@pytest.mark.parametrize("value", [
    None, 5, 1.5, ["aGVsbG8gd29ybGQ="], {"a": 1}, b"", b"\x00" * 64,
    bytes(range(256)) * 4, "\udcff" * 40, "\ud800aGVsbG8gd29ybGQ=",
    "%" * 40, "=" * 40, "%ff%fe%00%01%ff%fe%00%01", "é" * 40,
])
def test_nothing_raises(value):
    assert net_decode.decode(value) is None


def test_invalid_base64_and_hex_do_not_raise():
    for value in ("a" * 17, "a" * 18 + "=", "zz" * 20, "0x" + "4" * 20, "abc" * 7):
        net_decode.decode(value)


def test_bytearray_input_is_accepted():
    assert net_decode.decode(bytearray(b"aGVsbG8gd29ybGQ=")).text == "hello world"


# --- walking events ----------------------------------------------------------

def http(**fields):
    return net_events.NetEvent("http", 12.5, dest="evil.top", port=80,
                               process="x.exe", pid=7, method="POST", **fields)


def test_the_decoded_event_points_at_its_source():
    out = net_decode.decode_event_fields(http(body_text="data=aGVsbG8gd29ybGQ="))
    d = out[0]
    assert d["type"] == "decoded" and d["ts"] == 12.5 and d["dest"] == "evil.top"
    assert d["port"] == 80 and d["pid"] == 7 and d["process"] == "x.exe"
    assert d["field"] == "body_text" and d["name"] == "data"
    assert d["scheme"] == "base64" and d["kind"] == "text" and d["source"] == "http"
    assert d["encoded"] == "aGVsbG8gd29ybGQ=" and d["in_tree"] is False
    assert isinstance(d, net_events.NetEvent)


def test_every_field_of_a_form_is_looked_at():
    body = "id=17&user=YWRtaW5pc3RyYXRvcg==&pw=aHVudGVyMmh1bnRlcjI%3D&note=hi"
    out = net_decode.decode_event_fields(http(body_text=body))
    assert [(d["name"], d["text"]) for d in out] == [
        ("user", "administrator"), ("pw", "hunter2hunter2")]


def test_a_plus_in_a_form_value_is_not_a_space():
    text = b"query?select * from t where a>>b?"
    token = b64(text)
    assert "+" in token
    out = net_decode.decode_event_fields(http(body_text="d=" + token))
    assert out and out[0]["text"] == text.decode()


def test_a_query_string_is_walked():
    out = net_decode.decode_event_fields(http(query="a=1&b=68656c6c6f", body_text=""))
    assert [(d["field"], d["name"], d["text"]) for d in out] == [("query", "b", "hello")]


def test_the_response_is_walked_too():
    out = net_decode.decode_event_fields(
        http(body_text="", resp_text=b64(b"cmd:download http://x.test/a.exe")))
    assert out[0]["field"] == "resp_text" and out[0]["text"].startswith("cmd:download")


def test_a_whole_body_that_is_one_encoded_value():
    out = net_decode.decode_event_fields(http(body_text=b64(b"hostname=PC01;user=bob")))
    assert out[0]["name"] == "" and out[0]["text"] == "hostname=PC01;user=bob"


def test_a_padded_base64_body_is_not_mistaken_for_a_form():
    out = net_decode.decode_event_fields(http(body_text="aGVsbG8gd29ybGQ="))
    assert [d["text"] for d in out] == ["hello world"]


def test_a_body_of_encoded_lines_is_walked_line_by_line():
    body = "\r\n".join([b64(b"first stolen record: admin"), "not encoded", b64(b"second record: bob / pw1")])
    out = net_decode.decode_event_fields(http(body_text=body))
    assert [(d["name"], d["text"]) for d in out] == [
        ("line 1", "first stolen record: admin"), ("line 3", "second record: bob / pw1")]


def test_a_wrapped_blob_is_one_value_not_many_lines():
    raw = b"The quick brown fox jumps over the lazy dog. " * 4
    out = net_decode.decode_event_fields(http(body_text=base64.encodebytes(raw).decode()))
    assert [(d["name"], d["text"]) for d in out] == [("", raw.decode())]


def test_json_string_values_are_walked():
    body = json.dumps({"id": 4, "d": b64(b"stolen cookie: session=abc123"), "ok": True})
    out = net_decode.decode_event_fields(http(body_text=body))
    assert [(d["name"], d["text"]) for d in out] == [("d", "stolen cookie: session=abc123")]


def test_json_escaped_slashes_do_not_break_base64():
    text = b"a user name ??? / and so on >>> ???"
    token = b64(text)
    assert "/" in token
    body = '{"d":"%s"}' % token.replace("/", "\\/")
    assert "\\/" in body
    out = net_decode.decode_event_fields(http(body_text=body))
    assert out and out[0]["text"] == text.decode()


def test_multipart_parts_are_walked():
    body = ("--XYZ\r\nContent-Disposition: form-data; name=\"info\"\r\n\r\n"
            + b64(b"os=Windows 10;user=bob;av=none") + "\r\n--XYZ\r\n"
            "Content-Disposition: form-data; name=\"n\"\r\n\r\n42\r\n--XYZ--\r\n")
    out = net_decode.decode_event_fields(http(body_text=body))
    assert [(d["name"], d["text"]) for d in out] == [("info", "os=Windows 10;user=bob;av=none")]


def test_websocket_messages_are_walked():
    e = net_events.NetEvent("websocket", 3.0, dest="c2.top", messages=[
        {"direction": "c", "text": "ping"},
        {"direction": "s", "text": b64(b"run: whoami /all")},
        {"direction": "s", "text": None}])
    out = net_decode.decode_event_fields(e)
    assert [(d["field"], d["text"]) for d in out] == [("messages[1].text", "run: whoami /all")]


def test_an_event_without_encoded_content_gives_nothing():
    assert net_decode.decode_event_fields(
        http(body_text="id=17&name=bob&session=7f3a9c1e4b2d8f06a5e1c3b9d7f20486",
             query="q=hello%20world", resp_text="<html>ok</html>")) == []


def test_other_event_types_are_not_walked():
    dns = net_events.NetEvent("dns", 1.0, dest="aGVsbG8gd29ybGQ.evil.top",
                              query="aGVsbG8gd29ybGQ=")
    assert net_decode.decode_event_fields(dns) == []
    done = net_events.NetEvent("decoded", 1.0, dest="x", body_text="aGVsbG8gd29ybGQ=")
    assert net_decode.decode_event_fields(done) == []


def test_missing_and_odd_fields_do_not_raise():
    e = http(body_text=None, resp_text=b"aGVsbG8gd29ybGQ=", query=5)
    out = net_decode.decode_event_fields(e)
    assert [d["field"] for d in out] == ["resp_text"]
    assert net_decode.decode_event_fields(net_events.NetEvent("http", 1.0)) == []
    assert net_decode.decode_event_fields(
        net_events.NetEvent("websocket", 1.0, messages="nope")) == []
    assert net_decode.decode_event_fields(
        net_events.NetEvent("websocket", 1.0, messages=[None, 3, {"text": 4}])) == []


def test_a_binary_result_is_described_not_carried():
    pe = FILES["pe"] + bytes(range(256))
    out = net_decode.decode_event_fields(http(body_text="f=" + b64(pe)))
    d = out[0]
    assert d["kind"] == "pe" and d["text"] is None and d["size"] == len(pe)
    assert d["sha256"] == hashlib.sha256(pe).hexdigest()
    assert d["preview"].startswith("MZ\\144\\000")
    assert not any(isinstance(v, (bytes, bytearray)) for v in d.values())
    json.dumps(out)


def test_decoded_events_are_json_serializable():
    out = net_decode.decode_event_fields(http(
        body_text="a=" + b64("naïve ☃".encode("utf-8") * 3) + "&b=" + b64(b"x\x00y\x01 text " * 4)))
    json.dumps(out)


def test_long_decoded_text_is_capped_with_its_real_size():
    raw = b"credential dump line\n" * 5000
    out = net_decode.decode_event_fields(http(body_text="d=" + b64(raw)))
    d = out[0]
    assert d["text_capped"] is True and len(d["text"]) == net_decode.MAX_EVENT_TEXT
    assert d["size"] == len(raw)


def test_a_short_decoded_text_is_not_flagged_capped():
    out = net_decode.decode_event_fields(http(body_text="d=aGVsbG8gd29ybGQ="))
    assert out[0]["text_capped"] is False


def test_the_source_event_is_not_changed():
    e = http(body_text="data=aGVsbG8gd29ybGQ=")
    before = json.dumps(e, sort_keys=True)
    net_decode.decode_event_fields(e)
    assert json.dumps(e, sort_keys=True) == before


def test_an_event_with_a_secret_stays_unserializable_and_is_not_walked():
    e = net_events.NetEvent("ftp", 1.0, dest="ftp.evil", user="bob",
                            password=net_mail_ftp.Secret("aGVsbG8gd29ybGQ="),
                            body_text=b64(b"anything readable here"))
    assert net_decode.decode_event_fields(e) == []
    with pytest.raises(TypeError):
        json.dumps(e)


def test_decoded_events_hold_no_secret():
    secret = net_mail_ftp.Secret("hunter2")
    e = http(body_text="d=aGVsbG8gd29ybGQ=", password=secret)
    out = net_decode.decode_event_fields(e)
    assert "password" not in out[0]
    json.dumps(out)


# --- headers and credentials ---------------------------------------------------

def test_a_basic_authorization_header_is_decoded_and_marked_as_a_credential():
    out = net_decode.decode_event_fields(http(headers={
        "host": "c2.evil.top", "authorization": "Basic dXNlcjpwYXNz"}))
    assert len(out) == 1
    d = out[0]
    assert d["field"] == "headers.authorization" and d["name"] == "Basic"
    assert d["text"] == "user:pass" and d["scheme"] == "base64" and d["credential"] is True


def test_a_basic_credential_with_a_colon_in_the_password_and_non_ascii():
    out = net_decode.decode_event_fields(http(headers={
        "proxy-authorization": "basic " + b64("bob:pä:ss".encode())}))
    assert out[0]["text"] == "bob:pä:ss" and out[0]["credential"] is True


def test_basic_that_is_not_a_credential_pair_is_left_to_the_general_rule():
    plain = net_decode.decode_event_fields(http(headers={"authorization": "Basic aGVsbG8gd29ybGQ="}))
    assert [(d["text"], d["credential"]) for d in plain] == [("hello world", True)]
    assert net_decode.decode_event_fields(http(headers={"authorization": "Basic dXNl"})) == []
    assert net_decode.decode_event_fields(http(headers={"authorization": "Basic !!!!"})) == []


def test_a_bearer_token_is_read_segment_by_segment():
    token = ".".join([b64(b'{"alg":"HS256","typ":"JWT"}').rstrip("="),
                      b64(b'{"sub":"bob","admin":true}').rstrip("="),
                      "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"])
    out = net_decode.decode_event_fields(http(headers={"authorization": "Bearer " + token}))
    assert [(d["name"], d["text"]) for d in out] == [
        ("Bearer[0]", '{"alg":"HS256","typ":"JWT"}'), ("Bearer[1]", '{"sub":"bob","admin":true}')]
    assert all(d["credential"] for d in out)


def test_a_custom_header_name_is_read_too():
    out = net_decode.decode_event_fields(http(headers={
        "X-Session": b64(b"host=PC01;user=bob;role=admin")}))
    assert [(d["field"], d["text"], d["credential"]) for d in out] == [
        ("headers.x-session", "host=PC01;user=bob;role=admin", False)]


def test_cookie_values_are_read_one_by_one():
    cookie = "sid=" + b64(b"host=PC01;user=bob;role=admin") + "; theme=dark; id=17; t=aGVsbG8gd29ybGQ%3D"
    out = net_decode.decode_event_fields(http(headers={"cookie": cookie}))
    assert [(d["field"], d["name"], d["text"]) for d in out] == [
        ("headers.cookie", "sid", "host=PC01;user=bob;role=admin"),
        ("headers.cookie", "t", "hello world")]
    assert not any(d["credential"] for d in out)


def test_a_set_cookie_value_with_attributes_and_a_quoted_value():
    out = net_decode.decode_event_fields(http(resp_headers={
        "set-cookie": 'session="%s"; Path=/; HttpOnly' % b64(b"user=bob;role=admin;exp=999")}))
    assert [(d["field"], d["name"], d["text"]) for d in out] == [
        ("resp_headers.set-cookie", "session", "user=bob;role=admin;exp=999")]


def test_several_set_cookie_headers_joined_by_the_parser_are_each_read():
    joined = ("a=%s; Path=/, b=%s; Expires=Wed, 21 Oct 2037 07:28:00 GMT; HttpOnly"
              % (b64(b"user=bob;role=admin;exp=999"), b64(b"host=PC01;os=Windows 10;x=1")))
    out = net_decode.decode_event_fields(http(resp_headers={"set-cookie": joined}))
    assert [(d["name"], d["text"]) for d in out] == [
        ("a", "user=bob;role=admin;exp=999"), ("b", "host=PC01;os=Windows 10;x=1")]


def _real_events(request, response):
    return pcap_http._events(request, response)


def test_a_set_cookie_of_a_real_http_exchange_is_decoded():
    session = b64(b"role=operator;host=PC01;expires=999999")
    response = pcap_http._ok(b"ok", b"Set-Cookie: session=%s; Path=/; HttpOnly\r\n" % session.encode())
    [event] = _real_events(pcap_http._get(), response)
    assert "set-cookie" in event["resp_headers"]
    out = net_decode.decode_event_fields(event)
    assert [(d["field"], d["name"], d["text"], d["credential"]) for d in out] == [
        ("resp_headers.set-cookie", "session", "role=operator;host=PC01;expires=999999", False)]
    json.dumps(out)


def test_two_set_cookies_of_a_real_exchange_are_both_decoded():
    one, two = b64(b"role=operator;host=PC01;n=1"), b64(b"role=guest;host=PC02;n=2")
    response = pcap_http._ok(b"", b"Set-Cookie: a=%s; Path=/\r\nSet-Cookie: b=%s; Secure\r\n"
                             % (one.encode(), two.encode()))
    [event] = _real_events(pcap_http._get(), response)
    out = net_decode.decode_event_fields(event)
    assert [(d["name"], d["text"]) for d in out] == [
        ("a", "role=operator;host=PC01;n=1"), ("b", "role=guest;host=PC02;n=2")]


def test_request_and_response_headers_of_a_real_exchange_are_both_read():
    request = pcap_http._get(extra=b"Authorization: Basic dXNlcjpwYXNz\r\n"
                             b"Cookie: t=%s\r\n" % b64(b"user=bob;role=admin;exp=999").encode())
    response = pcap_http._ok(b"", b"X-Token: %s\r\n" % b64(b"issued-to=bob;scope=all;n=7").encode())
    [event] = _real_events(request, response)
    out = net_decode.decode_event_fields(event)
    assert [(d["field"], d["text"], d["credential"]) for d in out] == [
        ("headers.authorization", "user:pass", True),
        ("headers.cookie", "user=bob;role=admin;exp=999", False),
        ("resp_headers.x-token", "issued-to=bob;scope=all;n=7", True)]


def test_an_ordinary_real_exchange_decodes_nothing():
    request = pcap_http._get(extra=b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
                             b"Accept: */*\r\n")
    response = pcap_http._ok(b"<html>hi</html>", b"Content-Type: text/html\r\nServer: nginx/1.18.0\r\n"
                             b"ETag: \"5e1c3b9d7f2048\"\r\nSet-Cookie: sid=7f3a9c1e4b2d8f06a5e1c3b9d7f20486; Path=/\r\n")
    [event] = _real_events(request, response)
    assert net_decode.decode_event_fields(event) == []


def test_a_bare_base64_header_value_with_padding_is_not_taken_for_a_cookie():
    out = net_decode.decode_event_fields(http(headers={"x-data": "aGVsbG8gd29ybGQ="}))
    assert [(d["name"], d["text"]) for d in out] == [("", "hello world")]


def test_ordinary_request_headers_give_nothing():
    headers = {
        "host": "www.example.com", "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
        "accept-encoding": "gzip, deflate", "accept-language": "en-US,en;q=0.9",
        "connection": "keep-alive", "content-type": "application/x-www-form-urlencoded",
        "content-length": "1234", "cache-control": "no-cache no-store",
        "if-none-match": '"33a64df551425fcc55e4d42a148795d9f25f89d4"',
        "sec-websocket-key": "x3JJHMbDL1EzLkh9GBhXDw==", "referer": "http://example.com/a%20b/c",
        "cookie": "_ga=GA1.2.123456789.1700000000; sessionid=7f3a9c1e4b2d8f06a5e1c3b9d7f20486",
        "etag": "W/\"5e1c3b9d7f2048\"", "x-forwarded-for": "203.0.113.9, 198.51.100.4",
    }
    assert net_decode.decode_event_fields(http(headers=headers)) == []


def marked(text, **event):
    """``credential`` of the first thing found in a body field holding ``text``."""
    out = net_decode.decode_event_fields(http(body_text="d=" + b64(text), **event))
    assert out and out[0]["text"] == text.decode()
    return out[0]["credential"]


def test_a_decoded_user_password_pair_is_marked_wherever_it_was_found():
    assert marked(b"admin:hunter2-secret") is True
    assert marked(b"a@b.example:pw1\nbob:letmein99") is True
    cookie = net_decode.decode_event_fields(http(headers={"cookie": "auth=" + b64(b"admin:hunter2-secret")}))
    assert cookie[0]["credential"] is True


@pytest.mark.parametrize("text", [
    b"login=bob&password=hunter2&x=1",
    b"Chrome|https://bank.com|bob|Passw0rd!",
    b"https://bob:hunter2@evil.top/",
    b"admin:correct horse battery",
    b"John Smith:pw12345",
    b"admin:hunter2\nnote: x",
    b"bob:" + b"p" * 130,
    b"pass: hunter2 user: bob",
    b"stolen credentials: admin / hunter2",
    b"user=bob&pass=hunter2&host=PC01",
    b"first line\nsecond:line",
    b"hostname: PC01",
    b"ftp://bob:s3cret!@files.evil.top/in",
    b'{"user":"bob","password":"hunter2 and more"}',
    b"{'username': 'bob', 'Passwd': 'x'}",
    b"api_key=0123456789abcdef&v=1",
    b"client_secret: abcdefghij",
    b"X-Auth-Token: abcdefghij",
    b"u=bob&p=hunter2&host=PC01",
    b"http://evil.top/l?pw=hunter2xx",
    b'{"u":"bob","pw":"hunter2xx"}',
    b"user_pw = hunter2xx and more",
    b"P: hunter2xx",
    b"bob:https://x.com/zzz",
    b"bob: https://x.com/zzz?a=b:c",
])
def test_credential_bearing_text_is_marked(text):
    assert marked(text) is True


@pytest.mark.parametrize("text", [
    b"Chrome|https://bank.com|bob|Passw0rd!\nEdge|https://mail.example|alice|pw",
    b"https://bank.com\tbob\tPassw0rd!",
    b"https://bank.com;bob;Passw0rd!",
    b"name,url,username,password\nbank,https://bank.com,bob,Passw0rd!",
    b"URL: https://bank.com\nUSER: bob\nPASS: hunter2",
    b"Firefox,www.bank.com,bob,Passw0rd!",
    b"android://abc@com.bank.app|bob|Passw0rd!",
])
def test_the_lines_of_a_browser_credential_dump_are_marked(text):
    assert marked(text) is True


def test_a_name_that_says_secret_marks_what_it_holds():
    plain = b"correct horse battery staple"
    assert marked(plain) is False
    for name in ("password", "pwd", "client_secret", "access_token", "apikey", "auth", "cred", "PassPhrase"):
        out = net_decode.decode_event_fields(http(body_text="%s=%s" % (name, b64(plain))))
        assert out[0]["credential"] is True, name
    out = net_decode.decode_event_fields(http(headers={"x-api-key": b64(plain)}))
    assert out[0]["credential"] is True
    out = net_decode.decode_event_fields(http(headers={"cookie": "sessiontoken=" + b64(plain)}))
    assert out[0]["credential"] is True
    out = net_decode.decode_event_fields(http(body_text="note=" + b64(plain)))
    assert out[0]["credential"] is False


def test_pw_and_p_are_names_when_whole_not_when_part_of_a_word():
    plain = b"correct horse battery staple"
    for name in ("p", "P", "pw", "PW", "user_pw", "x-p"):
        out = net_decode.decode_event_fields(http(body_text="%s=%s" % (name, b64(plain))))
        assert out[0]["credential"] is True, name
    out = net_decode.decode_event_fields(http(headers={"x-pw": b64(plain)}))
    assert out[0]["credential"] is True
    for name in ("page", "up", "pwn", "map", "ppp", "help"):
        out = net_decode.decode_event_fields(http(body_text="%s=%s" % (name, b64(plain))))
        assert out[0]["credential"] is False, name


@pytest.mark.parametrize("text", [
    b"192.168.1.5:4444", b"C:\\Users\\bob\\AppData\\x.exe", b"http://evil.top/gate.php?id=7",
    b"http://evil.top:8080/gate.php?id=7 and more text",
    b"12:30:45 the nightly backup finished",
    b"id,name\n1,bob\n2,alice", b'{"id":4,"ok":true,"name":"abcdefgh","count":12}',
    b"the quick brown fox jumps over the lazy dog",
    b"https://bank.com|bob", b"os=Windows 10;host=PC01;av=none",
    b"the map=3 and the grape=red, up=down, tap=on, stop=now, ppp=7",
    b"https://evil.top:8080/a/b and then http://10.0.0.5:8080/x",
])
def test_text_that_is_not_credential_shaped_is_not_marked(text):
    assert marked(text) is False


def test_marking_stays_linear_on_hostile_text():
    started = time.time()
    for text in (b":" * 60000, b"a:" * 30000, b"pass" * 15000, b"pass" + b" " * 60000 + b"x",
                 b"x://" * 15000, b"\n".join([b"a|b|c|https://x.y"] * 3000),
                 b"https://" + b"a:" * 20000 + b"@"):
        net_decode.decode_event_fields(http(body_text="d=" + b64(text)))
    assert time.time() - started < 5


def test_credential_is_always_present_and_a_plain_bool():
    for out in (net_decode.decode_event_fields(http(body_text="d=aGVsbG8gd29ybGQ=")),
                net_decode.decode_event_fields(http(headers={"x": "68656c6c6f"}))):
        assert out[0]["credential"] is False


def test_odd_headers_do_not_raise():
    for headers in (None, 5, "x", [("a", "b")], {1: "aGVsbG8gd29ybGQ="}, {"a": None},
                    {"a": 5}, {"a": b"aGVsbG8gd29ybGQ="}, {"a": ["aGVsbG8gd29ybGQ=", None, 3]}):
        net_decode.decode_event_fields(http(headers=headers, resp_headers=headers))
    out = net_decode.decode_event_fields(http(headers={"a": ["aGVsbG8gd29ybGQ=", None]}))
    assert [d["text"] for d in out] == ["hello world"]


def test_a_header_event_with_a_secret_elsewhere_keeps_it_out_of_the_result():
    e = http(headers={"authorization": "Basic dXNlcjpwYXNz"},
             password=net_mail_ftp.Secret("hunter2"))
    out = net_decode.decode_event_fields(e)
    json.dumps(out)
    assert "password" not in out[0]


def test_headers_are_walked_in_bounded_time_and_count():
    headers = {"x-%d" % i: b64(b"header number %06d ok" % i) for i in range(3000)}
    out = net_decode.decode_event_fields(http(headers=headers))
    assert len(out) == net_decode.MAX_DECODED_PER_EVENT
    hostile = {"h%d" % i: "a=" * 50 + ";" * 5000 + "." * 5000 for i in range(50)}
    started = time.time()
    net_decode.decode_event_fields(http(headers=hostile))
    assert time.time() - started < 5


# --- bounds ------------------------------------------------------------------

def test_the_number_of_values_examined_per_field_is_capped():
    body = "&".join("k%d=%s" % (i, b64(b"value number %06d here" % i))
                    for i in range(net_decode.MAX_VALUES_PER_FIELD + 30))
    out = net_decode.decode_event_fields(http(body_text=body))
    assert len(out) == net_decode.MAX_VALUES_PER_FIELD
    assert out[-1]["name"] == "k%d" % (net_decode.MAX_VALUES_PER_FIELD - 1)


def test_the_number_of_decoded_events_per_event_is_capped():
    messages = [{"direction": "s", "text": b64(b"message number %06d ok" % i)}
                for i in range(2000)]
    e = net_events.NetEvent("websocket", 1.0, dest="c2.top", messages=messages)
    out = net_decode.decode_event_fields(e)
    assert len(out) == net_decode.MAX_DECODED_PER_EVENT


def test_the_scanned_size_per_event_is_capped():
    filler = "x" * 1000
    messages = [{"direction": "s", "text": filler} for _ in range(5000)]
    messages.append({"direction": "s", "text": b64(b"too far down to be seen")})
    e = net_events.NetEvent("websocket", 1.0, dest="c2.top", messages=messages)
    assert net_decode.decode_event_fields(e) == []


def test_many_bombs_in_one_event_are_bounded_together():
    bomb = b64(gzip.compress(b"A" * (8 * 1024 * 1024), 9))
    body = "&".join("k%d=%s" % (i, bomb) for i in range(20))
    started = time.time()
    out = net_decode.decode_event_fields(http(body_text=body))
    assert time.time() - started < 10
    assert len(out) == 20
    inflated = [d for d in out if d["layers"] == ["base64", "gzip"]]
    assert len(inflated) == net_decode.MAX_EVENT_INFLATE // net_decode.MAX_INFLATED
    assert all(d["kind"] == "gzip" for d in out if d not in inflated)


def test_hostile_json_and_forms_are_scanned_in_linear_time():
    started = time.time()
    for body in ('"a":"' * 40000, '"' * 200000, "{" + '"k":"v",' * 30000,
                 "&=" * 100000, "a=" * 100000, "--" + "x" * 100000):
        net_decode.decode_event_fields(http(body_text=body))
    assert time.time() - started < 10
