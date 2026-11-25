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
"""

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
