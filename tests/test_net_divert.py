"""The diverter's allocation (webui/net_divert.py): one address per faked name, handed out on first lookup.

Everything runs against ``FakeSystemOps``. What that proves is the bookkeeping: which calls were made, in which
number, and that the map is answered from memory. That adding an address really takes ~100 ms on the VM and that a
pool really refuses past some count is measured (scripts/measure-secondary-addresses.ps1), not shown by these tests.
"""

import threading

import pytest

import net_divert
import net_system


class _RefusingAfter(net_system.FakeSystemOps):
    """A machine whose adapter takes ``n`` addresses and refuses every one after that. The refused call is
    recorded, as the base class does it, and then raises."""

    def __init__(self, n, **kw):
        super().__init__(**kw)
        self.n = n

    def add_address(self, index, address, mask):
        if len([c for c in self.calls if c[0] == "add_address"]) >= self.n:
            self.fail["add_address"] = net_system.SystemOpsError("netsh add address failed (1): The pool is full")
        super().add_address(index, address, mask)


def _diverter(fail_adds_after=None, fail_removes=False, index=7, **kw):
    if fail_adds_after is None:
        ops = net_system.FakeSystemOps()
    else:
        ops = _RefusingAfter(fail_adds_after)
    if fail_removes:
        ops.fail["remove_address"] = net_system.SystemOpsError("netsh delete address failed (1): not found")
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


def test_a_name_after_a_refusal_is_still_tried_for_its_own_address_and_leaves_no_gap():
    ops = net_system.FakeSystemOps(fail={"add_address": net_system.SystemOpsError("busy")})
    d = net_divert.GuestDiverter(ops, 7)
    assert d.address_for("a.top") == d.shared
    refused = _adds(d)[0][2]
    del ops.fail["add_address"]
    own = d.address_for("b.top")
    assert own != d.shared and d.name_for(own) == "b.top"
    assert own == refused                         # nothing was put on the adapter at that address, so it is free


def test_a_call_the_machine_rejects_as_invalid_is_a_bug_and_not_a_refusal():
    d = _diverter(prefix="10.0")                 # not the fake internet: add_address raises ValueError
    with pytest.raises(ValueError):
        d.address_for("a.top")
    assert d.state()["shared_names"] == []


def test_the_shared_address_is_given_or_is_the_one_before_the_walk_begins():
    assert _diverter().shared == "198.18.0.1"
    assert _diverter(shared="192.168.64.4").shared == "192.168.64.4"


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
