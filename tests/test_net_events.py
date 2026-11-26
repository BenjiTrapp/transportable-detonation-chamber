"""Network event schema.

Regressions covered:
  * a typo in an event type ("conn_fail") would pass silently and make every
    rule that filters on the real name see nothing
  * a destination that is an IP address was indistinguishable from a hostname,
    so "connected without a DNS lookup" could not be told from a normal lookup
  * events from several parsers were merged in parser order, not time order;
    events sharing a timestamp swapped places between runs
  * a caller could pass in_tree=True and claim a process link a pcap cannot
    have
  * events did not serialise to JSON
  * bytes from a capture (a DNS label, a delimiter, a server name) reached
    reports raw, with NULs, newlines and bytes above 0x7F in them, or
    as ``bytes``, which JSON refuses; ``render_bytes`` writes them as plain
    ASCII text in one escaping style, and two different byte strings never
    give the same text (a dot inside a DNS label stays apart from the dot
    between labels, ``a\\.b`` from ``a.b``), which is proved over every
    byte string up to two bytes and every string up to four bytes of the
    awkward ones, and by reading the text back
  * the rendering is shared by the DNS parser and the raw profiler, so a
    change here must not move DNS output: it is compared with the original
    DNS label rule on every one- and two-byte label
"""

import itertools
import json

import pytest

import net_events


def test_event_carries_the_mandatory_fields():
    e = net_events.NetEvent("dns", 1700000000.5, process="a.exe", pid=42,
                            dest="evil.top", query_type="A")
    assert e["type"] == "dns" and e["pid"] == 42
    assert e["ts"] == 1700000000.5
    assert e["process"] == "a.exe"
    assert e["dest"] == "evil.top"
    assert e["dest_is_ip"] is False
    assert e["in_tree"] is False
    assert e["query_type"] == "A"


def test_every_mandatory_field_exists_with_defaults():
    e = net_events.NetEvent("conn", 1.0)
    for key in ("type", "ts", "process", "pid", "dest", "dest_is_ip", "port", "in_tree"):
        assert key in e
    assert e["process"] == "" and e["pid"] is None
    assert e["dest"] == "" and e["dest_is_ip"] is False
    assert e["port"] is None


def test_port_is_kept():
    assert net_events.NetEvent("conn", 1.0, dest="203.0.113.9", port=443)["port"] == 443


def test_an_ip_destination_is_marked_as_one():
    assert net_events.NetEvent("conn", 1.0, dest="203.0.113.9")["dest_is_ip"] is True
    assert net_events.NetEvent("conn", 1.0, dest="2001:db8::1")["dest_is_ip"] is True
    assert net_events.NetEvent("conn", 1.0, dest="evil.top")["dest_is_ip"] is False
    assert net_events.NetEvent("conn", 1.0, dest="999.1.1.1")["dest_is_ip"] is False


def test_an_unknown_type_is_rejected():
    with pytest.raises(ValueError):
        net_events.NetEvent("teleport", 1.0)


def test_every_documented_type_is_accepted():
    expected = ("dns conn conn_failed tls http udp raw ftp smtp websocket "
                "download upload decoded beacon retry fanout").split()
    assert tuple(net_events.EVENT_TYPES) == tuple(expected)
    for t in expected:
        assert net_events.NetEvent(t, 1.0)["type"] == t


def test_in_tree_cannot_be_claimed_by_the_caller():
    assert net_events.NetEvent("conn", 1.0, in_tree=True)["in_tree"] is False


def test_dest_is_ip_cannot_be_overridden_by_the_caller():
    e = net_events.NetEvent("conn", 1.0, dest="evil.top", dest_is_ip=True)
    assert e["dest_is_ip"] is False


def test_timestamp_is_stored_as_float():
    assert isinstance(net_events.NetEvent("dns", 5)["ts"], float)


def test_event_is_a_dict_and_serialises_to_json():
    e = net_events.NetEvent("http", 2.0, dest="203.0.113.9", port=80, method="GET")
    assert isinstance(e, dict)
    back = json.loads(json.dumps(e))
    assert back["method"] == "GET" and back["dest_is_ip"] is True


def test_events_sort_by_time_and_keep_insertion_order_on_ties():
    a = net_events.NetEvent("dns", 2.0, dest="b")
    b = net_events.NetEvent("dns", 1.0, dest="a")
    c = net_events.NetEvent("conn", 1.0, dest="c")
    assert [e["dest"] for e in net_events.sort_events([a, b, c])] == ["a", "c", "b"]
    assert [e["dest"] for e in net_events.sort_events([c, b, a])] == ["c", "a", "b"]


def test_sorting_does_not_modify_its_input():
    a = net_events.NetEvent("dns", 2.0)
    b = net_events.NetEvent("dns", 1.0)
    events = [a, b]
    net_events.sort_events(events)
    assert events == [a, b] and events[0] is a


def test_summary_counts_each_type():
    evs = [net_events.NetEvent("dns", 1.0), net_events.NetEvent("dns", 2.0),
           net_events.NetEvent("http", 3.0)]
    assert net_events.event_summary(evs) == {"dns": 2, "http": 1}


def test_summary_of_nothing_is_empty():
    assert net_events.event_summary([]) == {}


# --- render_bytes -------------------------------------------------------------

def _read_back(text):
    """The bytes a ``render_bytes`` text stands for; raises on a malformed one."""
    out = bytearray()
    i = 0
    while i < len(text):
        if text[i] != "\\":
            out.append(ord(text[i]))
            i += 1
        elif text[i + 1].isdigit():
            out.append(int(text[i + 1:i + 4]))
            i += 4
        else:
            out.append(ord(text[i + 1]))
            i += 2
    return bytes(out)


def test_printable_ascii_is_unchanged():
    printable = bytes(b for b in range(0x21, 0x7F) if b != 0x5C)
    assert net_events.render_bytes(printable) == printable.decode("ascii")
    assert net_events.render_bytes(b"example.com") == "example.com"
    assert net_events.render_bytes(b"") == ""


def test_a_backslash_is_escaped():
    assert net_events.render_bytes(b"a\\b") == "a\\\\b"


def test_control_bytes_and_space_are_written_as_three_digit_decimal():
    assert net_events.render_bytes(b"\x00") == "\\000"
    assert net_events.render_bytes(b"\n") == "\\010"
    assert net_events.render_bytes(b"\r\n") == "\\013\\010"
    assert net_events.render_bytes(b" ") == "\\032"
    assert net_events.render_bytes(b"\x7f") == "\\127"
    for b in list(range(0x21)) + [0x7F]:
        assert net_events.render_bytes(bytes([b])) == "\\%03d" % b


def test_bytes_above_ascii_are_written_as_three_digit_decimal():
    assert net_events.render_bytes(b"\x80\xff") == "\\128\\255"
    assert net_events.render_bytes("é".encode()) == "\\195\\169"


def test_the_rendering_is_plain_ascii_without_control_characters():
    text = net_events.render_bytes(bytes(range(256)))
    assert text.isascii() and text.isprintable() and " " not in text
    assert json.loads(json.dumps(text)) == text


def test_listed_bytes_are_escaped_and_the_rest_is_not():
    assert net_events.render_bytes(b"a.b") == "a.b"
    assert net_events.render_bytes(b"a.b", escape=b".") == "a\\.b"
    assert net_events.render_bytes(b"a\\.b", escape=b".") == "a\\\\\\.b"
    assert net_events.render_bytes(b"a;b", escape=b".;") == "a\\;b"


@pytest.mark.parametrize("bad", [b"1", b" ", b"\x00", b"\xff"])
def test_only_printable_non_digit_ascii_can_be_listed_for_escaping(bad):
    with pytest.raises(ValueError):
        net_events.render_bytes(b"x", escape=bad)


@pytest.mark.parametrize("escape", [b"", b"."])
def test_two_different_byte_strings_never_render_to_the_same_text(escape):
    seen = {}
    everything = [bytes(p) for n in (0, 1, 2) for p in itertools.product(range(256), repeat=n)]
    awkward = b"\\.01 9\x00\n\xffa"
    everything += [bytes(p) for p in itertools.product(awkward, repeat=3)]
    everything += [bytes(p) for p in itertools.product(awkward, repeat=4)]
    for raw in everything:
        text = net_events.render_bytes(raw, escape=escape)
        assert seen.setdefault(text, raw) == raw, (raw, seen[text])
        assert _read_back(text) == raw


def test_a_dot_in_a_label_is_told_from_the_dot_between_labels():
    inside = net_events.render_bytes(b"a.b", escape=b".")
    assert ".".join([inside, "top"]) != ".".join(
        [net_events.render_bytes(b"a", escape=b"."), net_events.render_bytes(b"b", escape=b"."),
         "top"])
    # the raw bytes backslash + dot are not the escaped dot either
    assert net_events.render_bytes(b"a\\.b", escape=b".") != inside


def _original_dns_label(raw):
    out = []
    for byte in raw:
        if byte in (0x2E, 0x5C):
            out.append("\\" + chr(byte))
        elif 0x21 <= byte <= 0x7E:
            out.append(chr(byte))
        else:
            out.append("\\%03d" % byte)
    return "".join(out)


def test_dns_labels_are_written_exactly_as_before_the_rule_moved_here():
    labels = [bytes(p) for n in (0, 1, 2) for p in itertools.product(range(256), repeat=n)]
    for raw in labels:
        assert net_events.render_bytes(raw, escape=b".") == _original_dns_label(raw)


def test_readable_text_is_told_from_bytes():
    assert net_events.is_readable_text(b"MZ-Berlin weekly report: the numbers are in the sheet")
    assert net_events.is_readable_text("Grüße aus Köln, das Wetter ist schön".encode("utf-8"))
    assert not net_events.is_readable_text(b"MZ\x90\x00\x03\x00\x00\x00" + bytes(range(256)))
    assert not net_events.is_readable_text(b"")
