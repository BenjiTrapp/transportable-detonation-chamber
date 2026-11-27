"""The diverter's allocation (webui/net_divert.py): one address per faked name, handed out on first lookup.

Everything runs against ``FakeSystemOps``. What that proves is the bookkeeping: which calls were made, in which
number, and that the map is answered from memory. That adding an address really takes ~100 ms on the VM and that a
pool really refuses past some count is measured (scripts/measure-secondary-addresses.ps1), not shown by these tests.
"""

import ipaddress
import threading

import pytest

import net_divert
import net_system


class _Adapter(net_system.FakeSystemOps):
    """An adapter that remembers what is on it (``present``), takes ``refuse_walk_after`` addresses of the walk and
    refuses every one after that, and refuses the addresses in ``refuse`` always. A refused call is recorded, as the
    base class does it, and then raises. Removing an address that is not there fails, as netsh does."""

    def __init__(self, present=(), refuse=(), refuse_walk_after=None, addressing=None):
        super().__init__(addressing=addressing)
        self.present = set(present)
        self.refuse = set(refuse)
        self.refuse_walk_after = refuse_walk_after

    @staticmethod
    def _on_walk(address):
        return not address.startswith("198.18.0.")          # the shared default is 198.18.0.1, before the walk

    def add_address(self, index, address, mask):
        refused = address in self.refuse
        if self.refuse_walk_after is not None and self._on_walk(address):
            tried = len([c for c in self.calls if c[0] == "add_address" and self._on_walk(c[2])])
            refused = refused or tried >= self.refuse_walk_after
        if refused:
            self.calls.append(("add_address", index, address, mask))
            raise net_system.SystemOpsError("netsh add address failed (1): The pool is full")
        super().add_address(index, address, mask)
        self.present.add(address)

    def remove_address(self, index, address):
        super().remove_address(index, address)
        if address not in self.present:
            raise net_system.SystemOpsError("netsh delete address failed (1): The element was not found")
        self.present.discard(address)

    def read_addressing(self, index):
        """What the adapter has: the addressing it was given, and the fake internet's addresses that are on it."""
        state = super().read_addressing(index)
        state["addresses"] = state["addresses"] + [
            {"address": a, "mask": "255.255.0.0", "skip_as_source": True}
            for a in sorted(self.present) if a.startswith("198.1")]
        return state


GUEST = "192.168.64.4"          # an address the machine has already, which is what a caller passes as ``shared``


# What read_addressing returns for an adapter on DHCP (net_system.WindowsSystemOps.read_addressing): restore_addressing
# takes exactly this shape and nothing else.
DHCP = {"index": 7, "dhcp": True,
        "addresses": [{"address": GUEST, "mask": "255.255.255.0", "skip_as_source": False}],
        "gateway": "192.168.64.1", "dns": ["192.168.64.1"], "dns_static": []}


def _diverter(fail_adds_after=None, fail_removes=False, index=7, shared=GUEST, refuse=(), addressing=None, **kw):
    """``shared=None`` is the default shared address, which the diverter has to put on the adapter itself; the
    default of this helper is one that is there already. ``addressing`` is what the adapter reads as (the fake's
    own static default when left out)."""
    ops = _Adapter(present=[shared] if shared else [], refuse=refuse, refuse_walk_after=fail_adds_after,
                   addressing=addressing)
    if fail_removes:
        ops.fail["remove_address"] = net_system.SystemOpsError("netsh delete address failed (1): not found")
    if shared is not None:
        kw["shared"] = shared
    return net_divert.GuestDiverter(ops, index, **kw)


def _adds(d):
    return [c for c in d.ops.calls if c[0] == "add_address"]


def test_a_name_gets_one_address_and_keeps_it():
    d = _diverter()
    first = d.address_for("c2.evil")
    assert d.address_for("c2.evil") == first
    assert d.name_for(first) == "c2.evil"


def test_two_names_never_share_an_address():          # Review Focus 4
    d = _diverter()
    seen = {d.address_for("h%d.top" % i) for i in range(50)}
    assert len(seen) == 50


def test_nothing_is_assigned_before_a_name_asks():
    d = _diverter()
    d.start()
    assert [c for c in d.ops.calls if c[0] == "add_address"] == []


def test_the_map_is_answered_from_memory_not_from_the_adapter():
    d = _diverter()
    d.address_for("c2.evil")
    before = len(d.ops.calls)
    for _ in range(100):
        d.address_for("c2.evil")
        d.name_for(d.address_for("c2.evil"))
    assert len(d.ops.calls) == before


def test_a_refused_address_falls_back_to_the_shared_one_and_says_so():   # Review Focus 2
    d = _diverter(fail_adds_after=2)
    d.address_for("a.top"), d.address_for("b.top")
    assert d.address_for("c.top") == d.shared
    assert "c.top" in d.state()["shared_names"]
    assert d.state()["shared_reason"] == net_divert.SHARED_FALLBACK_REASON
    assert d.shared in d.ops.present            # the address that was handed out leads to this machine


def test_stop_removes_exactly_what_was_added():
    d = _diverter()
    names = ["a.top", "b.top", "c.top"]
    added = {d.address_for(n) for n in names}
    d.stop()
    removed = {c[2] for c in d.ops.calls if c[0] == "remove_address"}
    assert removed == added


# --- what the brief's six do not pin ---


def test_addresses_walk_up_from_198_18_1_1_and_skip_the_network_and_broadcast_octets():
    d = _diverter()
    got = [d.address_for("h%d.top" % i) for i in range(256)]
    assert got[0] == "198.18.1.1"
    assert got[253] == "198.18.1.254"
    assert got[254] == "198.18.2.1"            # .255 and .0 are skipped
    assert not [a for a in got if a.endswith(".0") or a.endswith(".255")]
    assert got == sorted(got, key=lambda a: tuple(int(p) for p in a.split(".")))


def test_an_address_is_added_with_the_adapter_index_and_the_mask_that_was_measured():
    d = _diverter(index=9)
    address = d.address_for("c2.evil")
    assert d.ops.calls == [("add_address", 9, address, "255.255.0.0")]


def test_a_name_is_one_name_whatever_its_case_and_trailing_dot():
    d = _diverter()
    first = d.address_for("C2.Evil")
    assert d.address_for("c2.evil.") == first
    assert d.name_for(first) == "c2.evil"
    assert len(_adds(d)) == 1


def test_a_name_that_is_not_one_is_refused_before_anything_is_added():
    d = _diverter()
    for bad in ("", ".", None, 7, b"a.top"):
        with pytest.raises(ValueError):
            d.address_for(bad)
    assert d.ops.calls == []


def test_name_for_does_not_know_an_address_that_was_never_handed_out_nor_the_shared_one():
    d = _diverter(fail_adds_after=0)
    assert d.name_for("198.18.1.1") is None
    d.address_for("a.top")
    # several names live on the shared address: it names none of them, only SNI or Host can
    assert d.name_for(d.shared) is None
    assert d.name_for("not an address") is None


def test_a_name_that_fell_back_keeps_the_shared_address_and_is_not_tried_again():
    d = _diverter(fail_adds_after=0)
    assert d.address_for("a.top") == d.shared
    asked = len(d.ops.calls)
    assert d.address_for("a.top") == d.shared
    assert len(d.ops.calls) == asked
    assert d.state()["shared_names"] == ["a.top"]


def test_a_call_the_machine_rejects_as_invalid_is_a_bug_and_not_a_refusal():
    d = _diverter(prefix="10.0")                 # not the fake internet: add_address raises ValueError
    with pytest.raises(ValueError):
        d.address_for("a.top")
    assert d.state()["shared_names"] == []


def test_the_shared_address_is_given_or_is_the_one_before_the_walk_begins():
    assert _diverter(shared=None).shared == "198.18.0.1"
    assert _diverter(shared="192.168.64.9").shared == "192.168.64.9"


def test_state_holds_a_copy_of_the_map():
    d = _diverter()
    a = d.address_for("a.top")
    s = d.state()
    assert s["names"] == {"a.top": a}
    s["names"]["x.top"] = "1.2.3.4"
    s["shared_names"].append("x.top")
    assert d.state()["names"] == {"a.top": a}
    assert d.state()["shared_names"] == []
    assert d.state()["shared_reason"] is None


def test_stop_tries_every_removal_and_then_says_which_failed():
    d = _diverter(fail_removes=True)
    for n in ("a.top", "b.top", "c.top"):
        d.address_for(n)
    with pytest.raises(net_system.SystemOpsError) as e:
        d.stop()
    assert len([c for c in d.ops.calls if c[0] == "remove_address"]) == 3
    assert len(d.state()["remove_failed"]) == 3
    assert "198.18.1.1" in str(e.value)
    # a second stop retries what is still there, and only that
    d.ops.fail.clear()
    d.ops.calls.clear()
    d.stop()
    assert len([c for c in d.ops.calls if c[0] == "remove_address"]) == 3
    assert d.state()["remove_failed"] == []
    d.ops.calls.clear()
    d.stop()
    assert d.ops.calls == []


def test_a_name_that_is_new_after_stop_gets_no_address():
    d = _diverter()
    d.address_for("a.top")
    d.stop()
    d.ops.calls.clear()
    with pytest.raises(RuntimeError):
        d.address_for("b.top")
    assert d.ops.calls == []
    assert d.address_for("a.top").startswith("198.18.")      # a known name is still answered from memory


def test_threads_asking_for_the_same_names_get_one_address_each_and_one_add_each():
    d = _diverter()
    names = ["h%d.top" % i for i in range(20)]
    answers = []

    def ask():
        answers.append({n: d.address_for(n) for n in names})

    threads = [threading.Thread(target=ask) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(a == answers[0] for a in answers)
    assert len(set(answers[0].values())) == 20
    assert len(_adds(d)) == 20


def test_the_protocol_asks_to_be_implemented():
    base = net_divert.Diverter()
    for call in (lambda: base.address_for("a.top"), lambda: base.name_for("198.18.1.1"), base.start, base.stop,
                 base.state):
        with pytest.raises(NotImplementedError):
            call()


# --- the shared address has to exist (review of Task 2, Important 1) ---


def _removes(d):
    return [c[2] for c in d.ops.calls if c[0] == "remove_address"]


def test_a_given_shared_address_is_neither_added_nor_removed():
    d = _diverter(fail_adds_after=0)
    d.address_for("a.top")
    d.stop()
    assert GUEST not in [c[2] for c in d.ops.calls if c[0] in ("add_address", "remove_address")]
    assert GUEST in d.ops.present


def test_the_default_shared_address_goes_on_the_adapter_together_with_the_first_name():
    d = _diverter(shared=None)
    d.start()
    assert _adds(d) == []                                   # not at start: nothing is added before a name asks
    own = d.address_for("a.top")
    assert {own, d.shared} <= d.ops.present
    assert d.state()["shared_on_adapter"] is True
    adds = _adds(d)
    d.address_for("b.top")
    d.address_for("a.top")
    assert len(_adds(d)) == len(adds) + 1                   # b only: the shared one is added once


def test_a_refused_name_falls_back_to_a_shared_address_that_is_there_even_when_the_first_name_is_refused():
    d = _diverter(shared=None, fail_adds_after=0)
    assert d.address_for("a.top") == d.shared
    assert d.shared in d.ops.present                        # established at that moment, not before
    assert d.state()["shared_names"] == ["a.top"]
    assert d.state()["unaddressed_names"] == []


def test_the_default_shared_address_is_taken_off_again_with_the_rest():
    d = _diverter(shared=None)
    added = {d.address_for(n) for n in ("a.top", "b.top")}
    d.stop()
    assert set(_removes(d)) == added | {d.shared}
    assert d.ops.present == set()


def test_a_name_with_no_address_and_no_shared_address_is_listed_as_unaddressed():
    d = _diverter(shared=None, refuse=["198.18.0.1"], fail_adds_after=0)
    assert d.address_for("a.top") == d.shared               # still a value the DNS server can answer with
    s = d.state()
    assert s["unaddressed_names"] == ["a.top"]
    assert s["unaddressed_reason"] == net_divert.UNADDRESSED_REASON
    assert s["shared_names"] == [] and s["shared_reason"] is None
    assert s["shared_on_adapter"] is False
    assert d.shared not in d.ops.present


def test_an_adapter_that_refuses_everything_is_not_asked_for_the_shared_address_forever():
    d = _diverter(shared=None, refuse=["198.18.0.1"], fail_adds_after=0)
    for i in range(30):
        d.address_for("h%d.top" % i)
    asked = [c for c in d.ops.calls if c[0] == "add_address" and c[2] == d.shared]
    assert len(asked) == net_divert.SHARED_ATTEMPTS
    assert len(d.state()["unaddressed_names"]) == 30


def test_a_shared_address_that_could_not_be_added_with_the_first_name_is_tried_again_at_a_fallback():
    d = _diverter(shared=None, refuse=["198.18.0.1"])
    own = d.address_for("a.top")
    assert own in d.ops.present and d.state()["shared_on_adapter"] is False
    d.ops.refuse.clear()
    d.ops.refuse_walk_after = 0                             # now the pool refuses the names
    assert d.address_for("b.top") == d.shared
    assert d.shared in d.ops.present
    assert d.state()["shared_names"] == ["b.top"]


# --- the walk moves past an address that failed (Important 2 and 3) ---


def test_an_address_that_fails_is_skipped_for_the_rest_of_the_session():
    d = _diverter(refuse=["198.18.1.1"])                    # a leftover of a crashed session, say
    assert d.address_for("a.top") == d.shared               # that name paid the one failing call
    others = [d.address_for(n) for n in ("b.top", "c.top", "d.top")]
    assert others == ["198.18.1.2", "198.18.1.3", "198.18.1.4"]
    assert len([c for c in d.ops.calls if c[0] == "add_address" and c[2] == "198.18.1.1"]) == 1


def test_an_address_whose_add_failed_is_maybe_there_and_stop_asks_for_it_to_go():
    d = _diverter(refuse=["198.18.1.1"])
    d.address_for("a.top")
    d.address_for("b.top")
    assert d.state()["maybe_added"] == ["198.18.1.1"]
    d.stop()                                                # the adapter says "not found": that is not an error
    assert "198.18.1.1" in _removes(d)
    assert d.state()["maybe_added"] == [] and d.state()["remove_failed"] == []


def test_a_leftover_that_the_stop_does_remove_is_gone_afterwards():
    d = _diverter(refuse=["198.18.1.1"])
    d.ops.present.add("198.18.1.1")                         # the add failed because it is already there
    d.address_for("a.top")
    d.stop()
    assert "198.18.1.1" not in d.ops.present


def test_a_failing_removal_of_a_maybe_added_address_does_not_stop_the_rest():
    d = _diverter(refuse=["198.18.1.1"])
    d.address_for("a.top")
    own = d.address_for("b.top")
    d.stop()
    assert own in _removes(d) and own not in d.ops.present


# --- what ops may raise (Minor) ---


@pytest.mark.parametrize("failure", [OSError("pipe closed"), RuntimeError("boom"), net_system.SystemOpsError("no"),
                                     TimeoutError("netsh did not answer")])
def test_whatever_the_machine_raises_other_than_a_rejected_call_is_a_refusal(failure):
    d = _diverter()
    d.ops.fail["add_address"] = failure
    assert d.address_for("a.top") == d.shared               # and nothing escapes into the caller's thread
    assert d.state()["shared_names"] == ["a.top"]


# --- the shared address that is passed in, and name_for on what is not an address (Minor) ---


@pytest.mark.parametrize("shared", ["198.18.1.1", "198.18.77.3", "198.18.255.254"])
def test_a_shared_address_on_the_walk_is_refused(shared):
    with pytest.raises(ValueError):
        net_divert.GuestDiverter(net_system.FakeSystemOps(), 7, shared=shared)


@pytest.mark.parametrize("shared", ["198.18.0.5", "198.19.1.1", "192.168.64.4"])
def test_a_shared_address_off_the_walk_is_accepted(shared):
    assert net_divert.GuestDiverter(net_system.FakeSystemOps(), 7, shared=shared).shared == shared


@pytest.mark.parametrize("shared", ["not an address", 7, "::1", ""])
def test_a_shared_address_that_is_not_ipv4_is_refused(shared):
    with pytest.raises(ValueError):
        net_divert.GuestDiverter(net_system.FakeSystemOps(), 7, shared=shared)


@pytest.mark.parametrize("junk", [["x"], {"a": 1}, {"198.18.1.1"}, None, 7, b"198.18.1.1"])
def test_name_for_answers_none_to_what_is_not_an_address(junk):
    d = _diverter()
    d.address_for("a.top")
    assert d.name_for(junk) is None


# --- the session: the adapter, the isolation rule, and taking all of it back (Task 3) ---


def _kinds(d):
    return [c[0] for c in d.ops.calls]


def _calls(d, method):
    return [c for c in d.ops.calls if c[0] == method]


def test_start_makes_the_adapter_static_before_the_first_address():
    d = _diverter(addressing=DHCP)
    d.start()
    kinds = _kinds(d)
    assert "set_static" in kinds
    assert "add_address" not in kinds
    d.address_for("a.top")
    kinds = _kinds(d)
    assert kinds.index("set_static") < kinds.index("add_address")
    # with the adapter's real address, not with a made-up one: DHCP is off from here on and the lease goes with it
    first = _calls(d, "set_static")[0]
    assert first[1:] == (7, GUEST, "255.255.255.0", "192.168.64.1", None)


def test_start_goes_through_its_steps_in_the_order_that_keeps_the_machine_on_the_network():
    d = _diverter(addressing=DHCP)
    d.start()
    assert _kinds(d) == ["remove_firewall_rules", "read_addressing", "set_static", "add_firewall_rule", "set_static"]


def test_the_guests_dns_is_pointed_at_us_after_the_isolation_rule_stands():
    d = _diverter(addressing=DHCP)
    d.start()
    assert _calls(d, "set_static")[-1][1:] == (7, GUEST, "255.255.255.0", "192.168.64.1", ["127.0.0.1"])
    d = _diverter(addressing=DHCP, dns_address="192.168.64.4")
    d.start()
    assert _calls(d, "set_static")[-1][5] == ["192.168.64.4"]


def test_stop_puts_dhcp_back_even_when_removing_an_address_fails():
    d = _diverter(addressing=DHCP, fail_removes=True)
    d.start(); d.address_for("a.top")
    with pytest.raises(net_system.SystemOpsError):
        d.stop()
    assert ("restore_addressing", 7) in [(c[0], c[1]) for c in d.ops.calls]


def test_stop_hands_back_exactly_what_it_read():
    d = _diverter(addressing=DHCP)
    d.start()
    d.stop()
    assert _calls(d, "restore_addressing")[0][1:] == (7, DHCP)


def test_the_isolation_rule_is_named_and_is_removed_at_start_and_stop():
    d = _diverter()
    d.start()
    assert ("add_firewall_rule", net_divert.ISOLATION_RULE) in [(c[0], c[1]) for c in d.ops.calls]
    assert [c for c in d.ops.calls if c[0] == "remove_firewall_rules"]
    d.ops.calls.clear(); d.stop()
    assert [c for c in d.ops.calls if c[0] == "remove_firewall_rules"]
    assert net_divert.ISOLATION_RULE not in d.ops.rules


def test_the_rule_is_in_the_namespace_that_the_firewall_tab_does_not_touch():
    assert net_divert.ISOLATION_RULE == "TDC-NET-ISOLATE"
    assert not net_divert.ISOLATION_RULE.startswith(net_system.FIREWALL_TAB_PREFIX)


def _covered(spec_values, text):
    """Whether an address (or a port) lies in one of the ``a-b`` ranges a rule spec lists."""
    try:
        value = ipaddress.ip_address(text)
    except ValueError:
        value = int(text)
    for item in spec_values:
        low, _, high = item.partition("-")
        high = high or low
        if isinstance(value, int):
            if int(low) <= value <= int(high):
                return True
        elif ":" in low + high or ":" in str(value):
            if ((":" in low) == (value.version == 6)) and ipaddress.ip_address(low) <= value <= ipaddress.ip_address(high):
                return True
        elif value.version == 4 and ipaddress.ip_address(low) <= value <= ipaddress.ip_address(high):
            return True
    return False


def _isolation_spec(**kw):
    d = _diverter(**kw)
    d.start()
    return d.ops.rules[net_divert.ISOLATION_RULE]


def test_the_rule_blocks_what_goes_out_and_leaves_the_fake_internet_and_loopback_alone():
    spec = _isolation_spec()
    assert spec["action"] == "block" and spec["direction"] == "out"
    blocked = spec["remote_address"]
    for out in ("8.8.8.8", "192.168.64.1", "10.0.0.1", "198.20.0.1", "198.17.255.255", "169.254.1.1", "224.0.0.251",
                "255.255.255.255", "0.0.0.0", "128.0.0.1", "2001:db8::1", "fe80::1", "ff02::fb"):
        assert _covered(blocked, out), out
    for kept in ("198.18.0.0", "198.18.1.1", "198.19.255.255", "127.0.0.1", "127.255.255.255", "::1"):
        assert not _covered(blocked, kept), kept


def test_the_rule_does_not_catch_what_the_service_ports_and_winrm_answer_from():
    spec = _isolation_spec()
    for port in ("9000", "5985", "5986"):
        assert not _covered(spec["local_port"], port), port
    for port in ("1", "80", "8999", "9001", "49152", "65535"):
        assert _covered(spec["local_port"], port), port


def test_the_service_ports_can_be_given():
    spec = _isolation_spec(service_ports=(9000, 9443))
    assert not _covered(spec["local_port"], "9443") and _covered(spec["local_port"], "9442")


def test_a_profile_that_is_off_is_reported_and_is_not_an_error():
    d = _diverter()
    d.ops.profiles_off = ["Public"]
    d.start()
    assert d.state()["isolation"] == {"rule": net_divert.ISOLATION_RULE, "written": True, "profiles_off": ["Public"]}


def test_start_removes_what_an_earlier_session_left_before_it_changes_anything():
    d = _diverter(addressing=DHCP)
    d.ops.present.update({"198.18.1.1", "198.18.1.2", "198.18.0.1"})
    d.start()
    kinds = _kinds(d)
    assert kinds[0] == "remove_firewall_rules"
    assert sorted(c[2] for c in _calls(d, "remove_address")) == ["198.18.0.1", "198.18.1.1", "198.18.1.2"]
    assert max(i for i, k in enumerate(kinds) if k == "remove_address") < kinds.index("set_static")
    d.stop()
    # the leftovers were never the adapter's own configuration
    assert _calls(d, "restore_addressing")[0][2] == DHCP


def test_start_leaves_an_address_of_the_adapter_alone_even_when_it_looks_like_a_leftover():
    own = dict(DHCP, addresses=[{"address": "10.198.18.4", "mask": "255.0.0.0", "skip_as_source": False}])
    d = _diverter(addressing=own)
    d.start()
    assert _calls(d, "remove_address") == []


def test_start_with_no_address_to_keep_changes_nothing_and_says_so():
    d = _diverter(addressing=dict(DHCP, addresses=[]))
    with pytest.raises(net_system.SystemOpsError):
        d.start()
    assert _calls(d, "set_static") == [] and _calls(d, "add_firewall_rule") == []


@pytest.mark.parametrize("failing,after", [("set_static", ["restore_addressing"]),
                                           ("add_firewall_rule", ["restore_addressing"])])
def test_a_start_that_fails_takes_back_what_it_had_done_and_raises_the_original(failing, after):
    d = _diverter(addressing=DHCP)
    boom = net_system.SystemOpsError("%s: access denied" % failing)
    d.ops.fail[failing] = boom
    with pytest.raises(net_system.SystemOpsError) as e:
        d.start()
    assert e.value is boom
    assert after[0] in _kinds(d)
    assert len(_calls(d, "remove_firewall_rules")) == 2          # at the start, and again in the teardown
    assert d.state()["stopped"] is True


def test_a_start_that_cannot_even_read_the_adapter_restores_nothing():
    d = _diverter(addressing=DHCP)
    d.ops.fail["read_addressing"] = net_system.SystemOpsError("no adapter")
    with pytest.raises(net_system.SystemOpsError):
        d.start()
    assert _calls(d, "set_static") == [] and _calls(d, "restore_addressing") == []


def test_start_twice_is_one_start_and_a_stopped_diverter_does_not_start_again():
    d = _diverter(addressing=DHCP)
    d.start()
    before = len(d.ops.calls)
    d.start()
    assert len(d.ops.calls) == before                       # reading the adapter again would take our own change for its state
    d.stop()
    with pytest.raises(RuntimeError):
        d.start()


# --- stop is a chain that does not break ---


@pytest.mark.parametrize("failing", ["remove_address", "remove_firewall_rules", "restore_addressing"])
def test_a_step_of_stop_that_fails_does_not_skip_the_others_and_its_error_surfaces(failing):
    d = _diverter(addressing=DHCP)
    d.start()
    d.address_for("a.top")
    d.ops.calls.clear()
    boom = net_system.SystemOpsError("%s failed" % failing)
    d.ops.fail[failing] = boom
    with pytest.raises(net_system.SystemOpsError) as e:
        d.stop()
    for method in ("remove_address", "remove_firewall_rules", "restore_addressing"):
        assert _calls(d, method), method
    if failing != "remove_address":
        assert e.value is boom
    else:
        assert "198.18.1.1" in str(e.value)


def test_when_several_steps_fail_the_first_error_surfaces_and_the_others_are_in_the_state():
    d = _diverter(addressing=DHCP)
    d.start()
    d.address_for("a.top")
    d.ops.fail["remove_firewall_rules"] = net_system.SystemOpsError("rule gone wrong")
    d.ops.fail["restore_addressing"] = net_system.SystemOpsError("netsh said no")
    d.ops.fail["remove_address"] = net_system.SystemOpsError("not found")
    with pytest.raises(net_system.SystemOpsError) as e:
        d.stop()
    assert "198.18.1.1" in str(e.value)                      # addresses are the first step
    errors = d.state()["stop_errors"]
    assert len(errors) == 3 and "rule gone wrong" in errors[1] and "netsh said no" in errors[2]


def test_a_second_stop_retries_only_the_step_that_failed():
    d = _diverter(addressing=DHCP)
    d.start()
    d.ops.fail["restore_addressing"] = net_system.SystemOpsError("netsh said no")
    with pytest.raises(net_system.SystemOpsError):
        d.stop()
    d.ops.fail.clear()
    d.ops.calls.clear()
    d.stop()
    assert _kinds(d) == ["restore_addressing"]
    d.ops.calls.clear()
    d.stop()
    assert d.ops.calls == []
    assert d.state()["stop_errors"] == []


def test_a_diverter_that_never_started_has_nothing_of_the_firewall_or_the_adapter_to_take_back():
    d = _diverter()
    d.address_for("a.top")
    d.stop()
    assert _calls(d, "remove_firewall_rules") == [] and _calls(d, "restore_addressing") == []


def test_stop_removes_an_address_that_it_never_added_when_it_lies_on_the_adapter():    # a timed-out add that worked
    d = _diverter(addressing=DHCP)
    d.start()
    d.address_for("a.top")
    d.ops.present.add("198.18.7.7")
    d.stop()
    assert "198.18.7.7" in _removes(d) and "198.18.7.7" not in d.ops.present
    assert d.ops.present == {GUEST}


def test_the_sweep_reads_the_adapter_once_and_never_during_the_session():
    d = _diverter(addressing=DHCP)
    d.start()
    for i in range(30):
        d.address_for("h%d.top" % i)
    assert len(_calls(d, "read_addressing")) == 1            # the one of start
    d.ops.calls.clear()
    d.stop()
    assert len(_calls(d, "read_addressing")) == 1


def test_the_sweep_tries_an_address_once_even_when_it_is_also_one_that_was_recorded():
    d = _diverter(addressing=DHCP, fail_removes=True)
    d.start()
    d.address_for("a.top")
    with pytest.raises(net_system.SystemOpsError):
        d.stop()
    assert _removes(d) == ["198.18.1.1"]


def test_the_sweep_leaves_alone_what_is_not_ours_and_what_the_adapter_has_of_its_own():
    d = _diverter(addressing=DHCP, shared=GUEST)
    d.start()
    d.ops.present.update({"198.19.0.9", "192.168.64.77"})        # another prefix; and an address that is not the fake internet's
    d.stop()
    assert _removes(d) == []


def test_a_sweep_that_cannot_read_the_adapter_does_not_skip_the_rest_and_is_tried_again():
    d = _diverter(addressing=DHCP)
    d.start()
    d.address_for("a.top")
    d.ops.fail["read_addressing"] = net_system.SystemOpsError("powershell timed out")
    with pytest.raises(net_system.SystemOpsError) as e:
        d.stop()
    assert "powershell timed out" in str(e.value)
    assert _calls(d, "remove_address") and _calls(d, "restore_addressing") and _calls(d, "remove_firewall_rules")
    d.ops.fail.clear()
    d.ops.calls.clear()
    d.stop()
    assert _kinds(d) == ["read_addressing"]


def test_the_default_shared_address_is_swept_with_the_rest():
    d = _diverter(addressing=DHCP, shared=None)
    d.start()
    d.address_for("a.top")
    d.stop()
    assert d.ops.present == set()


# --- what was seen and not answered (Review Focus 1) ---


def test_a_hard_coded_address_is_recorded_as_blocked_not_dropped():    # Review Focus 1
    d = _diverter()
    d.start()
    d.note_blocked("203.0.113.9", 4444, pid=4242, process="x.exe")
    b = d.blocked_attempts()[0]
    assert (b["dest"], b["port"], b["pid"], b["process"]) == ("203.0.113.9", 4444, 4242, "x.exe")
    assert b["answered"] is False


def test_the_same_attempt_repeated_is_one_entry_with_a_count_and_a_different_one_is_another():
    d = _diverter()
    for _ in range(5):
        d.note_blocked("203.0.113.9", 4444, pid=4242, process="x.exe", at=10.0)
    d.note_blocked("203.0.113.9", 4445, pid=4242, process="x.exe", at=11.0)
    got = d.blocked_attempts()
    assert [b["count"] for b in got] == [5, 1]
    assert got[0]["first"] == 10.0 and got[1]["first"] == 11.0


def test_the_blocked_attempts_are_copies_and_the_state_counts_them():
    d = _diverter()
    d.note_blocked("203.0.113.9", 4444)
    d.blocked_attempts()[0]["dest"] = "x"
    d.blocked_attempts().clear()
    assert d.blocked_attempts()[0]["dest"] == "203.0.113.9"
    assert d.state()["blocked"] == 1
    assert d.blocked_attempts()[0]["pid"] is None and d.blocked_attempts()[0]["process"] is None


def test_a_sample_that_tries_every_address_does_not_grow_the_list_without_end():
    d = _diverter()
    for i in range(net_divert.MAX_BLOCKED + 50):
        d.note_blocked("203.0.%d.%d" % divmod(i, 256), 80)
    assert len(d.blocked_attempts()) == net_divert.MAX_BLOCKED
    assert d.state()["blocked_overflow"] == 50
    d.note_blocked("203.0.0.0", 80)                          # one that is in the list is still counted
    assert d.blocked_attempts()[0]["count"] == 2


@pytest.mark.parametrize("dest,port", [("", 80), (None, 80), ("203.0.113.9", -1), ("203.0.113.9", 70000),
                                       ("203.0.113.9", "80"), ("203.0.113.9", True)])
def test_a_blocked_attempt_that_is_not_one_is_refused(dest, port):
    d = _diverter()
    with pytest.raises(ValueError):
        d.note_blocked(dest, port)
    assert d.blocked_attempts() == []
