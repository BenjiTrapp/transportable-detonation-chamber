"""The seam between the fake internet and the operating system (webui/net_system.py).

``FakeSystemOps`` is what every later task's tests stand on; ``WindowsSystemOps`` is the real thing. Nothing here
changes an adapter, a firewall or a certificate store: the Windows class is driven through an injected runner that
records the command lines it was given and answers like netsh, certutil and the PowerShell script would.

**The honesty boundary.** That proves the Python side: the order of the commands, what is refused before anything
runs, what is read back and what a non-zero exit becomes. It does not prove that netsh does what the arguments say,
that PowerShell accepts the script, or that the table of ``GetExtendedTcpTable`` is read right on a machine - the
one test that calls the real API is skipped off Windows. What netsh does to a DHCP adapter was measured on the VM
(scripts/measure-secondary-addresses.ps1); a green run here is never evidence for it.
"""

import base64
import json
import re
import socket
import sys

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import net_system

ON_WINDOWS = sys.platform == "win32"


@pytest.fixture
def win(monkeypatch):
    """WindowsSystemOps on any platform: the check for Windows is the one thing replaced."""
    monkeypatch.setattr(net_system, "_is_windows", lambda: True)


# --------------------------------------------------------------------------------------------------
# the two tests of the plan
# --------------------------------------------------------------------------------------------------


def test_the_fake_records_what_was_asked_of_it_and_answers_from_its_table():
    # the owner's end comes first: pid 4242 is the process at 10.0.0.5:51000 talking to 198.18.1.1:80
    ops = net_system.FakeSystemOps(tcp_owners={("10.0.0.5", 51000, "198.18.1.1", 80): 4242})
    ops.add_address(7, "198.18.1.1", "255.255.0.0")
    assert ops.calls == [("add_address", 7, "198.18.1.1", "255.255.0.0")]
    assert ops.tcp_owner("10.0.0.5", 51000, "198.18.1.1", 80) == 4242
    assert ops.tcp_owner("10.0.0.6", 51000, "198.18.1.1", 80) is None
    assert ops.tcp_owner("198.18.1.1", 80, "10.0.0.5", 51000) is None      # the server's end first is not the owner


def test_the_windows_ops_are_not_importable_off_windows_but_the_module_is():
    # every later task's tests run on the host, so importing the module must not
    # need Windows: only calling WindowsSystemOps may.
    assert hasattr(net_system, "WindowsSystemOps")


# --------------------------------------------------------------------------------------------------
# the protocol and the fake
# --------------------------------------------------------------------------------------------------

CALLS = [
    ("add_address", (7, "198.18.1.1", "255.255.0.0")),
    ("remove_address", (7, "198.18.1.1")),
    ("set_static", (7, "10.0.0.5", "255.255.255.0", "10.0.0.1", ["10.0.0.2"])),
    ("restore_addressing", (7, {})),
    ("set_dns", (7, ["127.0.0.1"])),
    ("network_profile", (7,)),
    ("read_addressing", (7,)),
    ("add_firewall_rule", ("TDC-NET-ISOLATE", {"action": "block"})),
    ("remove_firewall_rules", ("TDC-NET-",)),
    ("install_ca", ("pem",)),
    ("remove_ca", ("A" * 40,)),
    ("tcp_owner", ("10.0.0.5", 51000, "198.18.1.1", 80)),
]
# what the fake and the Windows class both refuse: (method, arguments) that must raise ValueError
REFUSED = [
    ("add_address", ("7", "198.18.1.1", "255.255.0.0")),
    ("add_address", (7, "198.18.1", "255.255.0.0")),
    ("add_address", (7, "198.18.1.1", "255.0.255.0")),
    ("add_address", (7, "203.0.113.9", "255.255.255.0")),
    ("add_address", (7, "198.20.0.1", "255.255.0.0")),
    ("remove_address", (0, "198.18.1.1")),
    ("remove_address", (7, "::1")),
    ("set_static", (True, "10.0.0.5", "255.255.255.0", None, None)),
    ("set_static", (7, "10.0.0.5", "255.255.255.0", "gateway", None)),
    ("set_static", (7, "10.0.0.5", "255.255.255.0", None, "127.0.0.1")),
    ("set_dns", (7, None)),
    ("set_dns", (7, "127.0.0.1")),
    ("set_dns", (7, ["localhost"])),
    ("set_dns", (0, ["127.0.0.1"])),
    ("network_profile", (None,)),
    ("read_addressing", (None,)),
    ("restore_addressing", (7, None)),
    ("restore_addressing", (7, {"dhcp": True, "address": "192.168.64.4"})),
    ("restore_addressing", (7, {"index": 8, "dhcp": True, "addresses": [], "dns_static": []})),
    ("add_firewall_rule", ("TDC-FW-abc", {"action": "block"})),
    ("add_firewall_rule", ("isolate", {"action": "block"})),
    ("add_firewall_rule", ("TDC-NET-X", {})),
    ("add_firewall_rule", ("TDC-NET-X", {"action": "block", "colour": "red"})),
    ("add_firewall_rule", ("TDC-NET-X", {"action": "block", "remote_address": "LocalSubnet"})),
    ("add_firewall_rule", ("TDC-NET-X", {"action": "block", "remote_port": []})),
    ("remove_firewall_rules", ("TDC-FW-",)),
    ("remove_firewall_rules", ("TDC-F",)),
    ("remove_firewall_rules", ("*",)),
    ("install_ca", ("pem",)),
    ("install_ca", ("",)),
    ("remove_ca", ("AB",)),
    ("remove_ca", ("G" * 40,)),
    ("tcp_owner", ("not-an-ip", 51000, "198.18.1.1", 80)),
    ("tcp_owner", ("10.0.0.5", "51000", "198.18.1.1", 80)),
    ("tcp_owner", ("10.0.0.5", 70000, "198.18.1.1", 80)),
]


@pytest.mark.parametrize("method,args", CALLS, ids=[c[0] for c in CALLS])
def test_the_base_class_is_a_protocol_with_nothing_behind_it(method, args):
    with pytest.raises(NotImplementedError):
        getattr(net_system.SystemOps(), method)(*args)


@pytest.mark.parametrize("method,args", REFUSED, ids=lambda v: v if isinstance(v, str) else "")
def test_the_fake_refuses_what_the_windows_ops_refuse(method, args):
    # a call that raises ValueError on Windows must not pass against the fake, or the tests of every caller
    # would be green for a mistake that fails in the guest
    ops = net_system.FakeSystemOps()
    with pytest.raises(ValueError):
        getattr(ops, method)(*args)
    assert ops.rules == {} and ops.cas == {}


@pytest.mark.parametrize("method,args", [r for r in REFUSED if r[0] != "tcp_owner"],
                         ids=lambda v: v if isinstance(v, str) else "")
def test_a_call_the_fake_refuses_is_recorded_first_so_a_test_can_see_what_was_attempted(method, args):
    ops = net_system.FakeSystemOps()
    with pytest.raises(ValueError):
        getattr(ops, method)(*args)
    assert ops.calls == [(method,) + args]


@pytest.mark.parametrize("method,args", REFUSED, ids=lambda v: v if isinstance(v, str) else "")
def test_the_windows_ops_refuse_the_same_calls_and_run_nothing(win, method, args):
    ops, run = _ops()
    with pytest.raises(ValueError):
        getattr(ops, method)(*args)
    assert run.calls == []


def test_the_fake_accepts_what_read_addressing_returned_and_nothing_else_for_a_restore():
    ops = net_system.FakeSystemOps()
    ops.restore_addressing(7, ops.read_addressing(7))
    assert [c[0] for c in ops.calls] == ["read_addressing", "restore_addressing"]


def test_the_fake_compares_a_thumbprint_without_regard_to_case():
    ops = net_system.FakeSystemOps()
    thumb = ops.install_ca(_pem_only())
    assert ops.remove_ca(thumb.lower()) is True


def test_a_failure_asked_for_at_tcp_owner_is_raised_though_the_call_is_not_recorded():
    # the path on which a caller whose table cannot be read falls back to correlating by Sysmon
    ops = net_system.FakeSystemOps(fail={"tcp_owner": net_system.SystemOpsError("the table cannot be read")})
    with pytest.raises(net_system.SystemOpsError, match="cannot be read"):
        ops.tcp_owner("10.0.0.5", 51000, "198.18.1.1", 80)
    assert ops.calls == []


def test_the_fake_is_a_system_ops_and_has_every_method_of_the_protocol():
    ops = net_system.FakeSystemOps()
    assert isinstance(ops, net_system.SystemOps)
    for method, _ in CALLS:
        assert getattr(net_system.FakeSystemOps, method) is not getattr(net_system.SystemOps, method)


def test_the_fake_records_a_call_the_same_way_whether_it_was_made_by_position_or_by_name():
    ops = net_system.FakeSystemOps()
    ops.add_address(7, "198.18.1.1", "255.255.0.0")
    ops.add_address(index=7, address="198.18.1.2", mask="255.255.0.0")
    ops.set_static(7, address="10.0.0.5", mask="255.255.255.0", gateway="10.0.0.1", dns=["127.0.0.1"])
    assert ops.calls == [
        ("add_address", 7, "198.18.1.1", "255.255.0.0"),
        ("add_address", 7, "198.18.1.2", "255.255.0.0"),
        ("set_static", 7, "10.0.0.5", "255.255.255.0", "10.0.0.1", ["127.0.0.1"]),
    ]


def test_asking_who_owns_a_connection_is_not_recorded_because_it_is_asked_per_accept():
    ops = net_system.FakeSystemOps()
    ops.tcp_owner("198.18.1.1", 80, "10.0.0.5", 51000)
    assert ops.calls == []


def test_the_fake_answers_read_addressing_from_what_it_was_given_and_hands_out_copies():
    given = {"dhcp": True, "addresses": [{"address": "192.168.64.4"}]}
    ops = net_system.FakeSystemOps(addressing=given)
    first = ops.read_addressing(7)
    first["dhcp"] = False
    assert ops.read_addressing(7) == given
    assert ops.calls == [("read_addressing", 7), ("read_addressing", 7)]


def test_a_failure_is_recorded_first_and_then_raised_so_a_test_can_see_what_was_attempted():
    boom = net_system.SystemOpsError("netsh said no")
    ops = net_system.FakeSystemOps(fail={"remove_address": boom})
    with pytest.raises(net_system.SystemOpsError):
        ops.remove_address(7, "198.18.1.1")
    assert ops.calls == [("remove_address", 7, "198.18.1.1")]
    ops.add_address(7, "198.18.1.2", "255.255.0.0")        # only the named method fails


def test_the_fake_keeps_the_rules_and_the_certificates_it_was_given_so_a_stop_can_be_checked():
    ops = net_system.FakeSystemOps()
    ops.add_firewall_rule("TDC-NET-ISOLATE", {"action": "block"})
    ops.add_firewall_rule("TDC-NET-OTHER", {"action": "allow"})
    ops.add_firewall_rule("TDC-OTHER-abc", {"action": "block"})
    assert ops.remove_firewall_rules("TDC-NET-") == 2
    assert sorted(ops.rules) == ["TDC-OTHER-abc"]

    thumb = ops.install_ca(_pem_only())
    assert thumb in ops.cas
    assert ops.remove_ca(thumb) is True
    assert ops.remove_ca(thumb) is False
    assert ops.cas == {}


def test_the_fake_reports_the_profiles_it_was_told_are_off():
    assert net_system.FakeSystemOps().add_firewall_rule("TDC-NET-X", {"action": "block"}) == []
    off = net_system.FakeSystemOps(profiles_off=["Public"])
    assert off.add_firewall_rule("TDC-NET-X", {"action": "block"}) == ["Public"]


# --------------------------------------------------------------------------------------------------
# the TCP table
# --------------------------------------------------------------------------------------------------


def _row(state, laddr, lport, raddr, rport, pid):
    """One MIB_TCPROW_OWNER_PID as Windows lays it out: addresses and ports in network byte order."""
    def addr(text):
        return socket.inet_aton(text)

    def port(number):
        return bytes([number >> 8, number & 0xFF, 0, 0])

    import struct
    return (struct.pack("<I", state) + addr(laddr) + port(lport) + addr(raddr) + port(rport)
            + struct.pack("<I", pid))


def _table(*rows):
    import struct
    return struct.pack("<I", len(rows)) + b"".join(rows)


ESTABLISHED = 5
LISTEN = 2
TIME_WAIT = 11


def test_the_table_is_read_with_ports_and_addresses_the_right_way_round():
    raw = _table(_row(ESTABLISHED, "10.0.0.5", 51000, "198.18.1.1", 80, 4242),
                 _row(LISTEN, "0.0.0.0", 445, "0.0.0.0", 0, 4))
    assert net_system.parse_tcp_table(raw) == [
        (ESTABLISHED, "10.0.0.5", 51000, "198.18.1.1", 80, 4242),
        (LISTEN, "0.0.0.0", 445, "0.0.0.0", 0, 4),
    ]


def test_a_table_that_ends_inside_a_row_is_an_error_and_not_a_shorter_table():
    raw = _table(_row(ESTABLISHED, "10.0.0.5", 51000, "198.18.1.1", 80, 4242))
    with pytest.raises(net_system.SystemOpsError):
        net_system.parse_tcp_table(raw[:-3])
    with pytest.raises(net_system.SystemOpsError):
        net_system.parse_tcp_table(b"")


def _windows_ops(**kw):
    return net_system.WindowsSystemOps(**kw)


def test_the_owner_is_the_pid_of_the_row_with_exactly_that_local_and_remote_end(win):
    raw = _table(_row(ESTABLISHED, "10.0.0.5", 51000, "198.18.1.1", 80, 4242),
                 _row(ESTABLISHED, "198.18.1.1", 80, "10.0.0.5", 51000, 1100))
    ops = _windows_ops(read_tcp_table=lambda: raw)
    assert ops.tcp_owner("10.0.0.5", 51000, "198.18.1.1", 80) == 4242
    assert ops.tcp_owner("198.18.1.1", 80, "10.0.0.5", 51000) == 1100
    assert ops.tcp_owner("10.0.0.5", 51001, "198.18.1.1", 80) is None
    assert ops.tcp_owner("10.0.0.6", 51000, "198.18.1.1", 80) is None


def test_a_row_that_belongs_to_nobody_is_not_an_owner(win):
    # a TIME_WAIT row has pid 0; answering 0 would read as a process
    raw = _table(_row(TIME_WAIT, "10.0.0.5", 51000, "198.18.1.1", 80, 0))
    assert _windows_ops(read_tcp_table=lambda: raw).tcp_owner("10.0.0.5", 51000, "198.18.1.1", 80) is None


def test_a_live_row_wins_over_a_dead_one_for_the_same_four_numbers(win):
    raw = _table(_row(TIME_WAIT, "10.0.0.5", 51000, "198.18.1.1", 80, 0),
                 _row(ESTABLISHED, "10.0.0.5", 51000, "198.18.1.1", 80, 4242))
    assert _windows_ops(read_tcp_table=lambda: raw).tcp_owner("10.0.0.5", 51000, "198.18.1.1", 80) == 4242


def test_an_address_that_is_not_ipv4_is_no_owner_and_not_an_error(win):
    ops = _windows_ops(read_tcp_table=lambda: _table())
    assert ops.tcp_owner("fe80::1", 51000, "198.18.1.1", 80) is None


def test_a_table_that_cannot_be_read_is_an_error_so_the_caller_can_fall_back(win):
    def broken():
        raise net_system.SystemOpsError("GetExtendedTcpTable failed")
    with pytest.raises(net_system.SystemOpsError):
        _windows_ops(read_tcp_table=broken).tcp_owner("10.0.0.5", 51000, "198.18.1.1", 80)


@pytest.mark.skipif(not ON_WINDOWS, reason="GetExtendedTcpTable exists only on Windows")
def test_the_real_table_names_this_process_as_the_owner_of_its_own_listener():
    import os
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    client = socket.create_connection(listener.getsockname())
    try:
        local = client.getsockname()
        remote = client.getpeername()
        ops = net_system.WindowsSystemOps()
        assert ops.tcp_owner(local[0], local[1], remote[0], remote[1]) == os.getpid()
    finally:
        client.close()
        listener.close()


# --------------------------------------------------------------------------------------------------
# off Windows
# --------------------------------------------------------------------------------------------------


@pytest.mark.skipif(ON_WINDOWS, reason="this is the behaviour off Windows")
def test_constructing_the_windows_ops_off_windows_says_so():
    with pytest.raises(RuntimeError, match="Windows"):
        net_system.WindowsSystemOps()


# --------------------------------------------------------------------------------------------------
# what WindowsSystemOps runs
# --------------------------------------------------------------------------------------------------


class Runner:
    """Stands in for ``run_powershell``: records every command line and answers like the program would.

    ``answers`` maps a program's file name (netsh.exe, certutil.exe, powershell.exe, ipconfig.exe) to a list of
    ``(rc, stdout, stderr)`` that are used in order; the last one repeats. Without one the answer is success.
    """

    def __init__(self, answers=None):
        self.calls = []
        self.answers = {k: list(v) for k, v in (answers or {}).items()}

    def __call__(self, args):
        self.calls.append(list(args))
        program = re.split(r"[\\/]", args[0])[-1].lower()
        queue = self.answers.get(program)
        if not queue:
            return 0, "", ""
        return queue.pop(0) if len(queue) > 1 else queue[0]

    def netsh(self):
        return [c[1:] for c in self.calls if c[0].lower().endswith("netsh.exe")]

    def programs(self):
        return [re.split(r"[\\/]", c[0])[-1].lower() for c in self.calls]


def _ops(answers=None):
    runner = Runner(answers)
    return net_system.WindowsSystemOps(run=runner), runner


def test_an_address_is_added_with_skipassource_in_the_form_the_measurement_proved(win):
    ops, run = _ops()
    ops.add_address(7, "198.18.1.1", "255.255.0.0")
    assert run.netsh() == [["interface", "ipv4", "add", "address", "7", "198.18.1.1", "255.255.0.0",
                            "skipassource=true"]]


def test_an_address_is_removed_by_its_index_and_value(win):
    ops, run = _ops()
    ops.remove_address(7, "198.18.1.1")
    assert run.netsh() == [["interface", "ipv4", "delete", "address", "7", "198.18.1.1"]]


def test_a_non_zero_exit_of_netsh_is_an_error_with_its_first_line_even_though_netsh_writes_it_to_stdout(win):
    ops, run = _ops({"netsh.exe": [(1, "\r\nThe object already exists.\r\nmore\r\n", "")]})
    with pytest.raises(net_system.SystemOpsError, match="The object already exists"):
        ops.add_address(7, "198.18.1.1", "255.255.0.0")


@pytest.mark.parametrize("index", [0, -1, True, "7", None, 1.5])
def test_an_adapter_index_that_is_not_a_positive_integer_runs_nothing(win, index):
    ops, run = _ops()
    with pytest.raises(ValueError):
        ops.add_address(index, "198.18.1.1", "255.255.0.0")
    assert run.calls == []


@pytest.mark.parametrize("address,mask", [("198.18.1", "255.255.0.0"), ("198.18.1.1; calc", "255.255.0.0"),
                                          ("198.18.1.1", "255.0.255.0"), ("198.18.1.1", "garbage"),
                                          ("::1", "255.255.0.0"), ("-1.2.3.4", "255.255.0.0")])
def test_an_address_or_mask_that_is_not_ipv4_runs_nothing(win, address, mask):
    ops, run = _ops()
    with pytest.raises(ValueError):
        ops.add_address(7, address, mask)
    assert run.calls == []


def test_add_address_adds_only_the_fake_internets_own_addresses_but_a_restore_may_re_add_any(win):
    ops, run = _ops()
    for address in ("198.18.0.1", "198.19.255.254"):
        ops.add_address(7, address, "255.254.0.0")
    for address in ("198.17.255.255", "198.20.0.0", "10.0.0.6", "203.0.113.9"):
        with pytest.raises(ValueError):
            ops.add_address(7, address, "255.254.0.0")
    assert len(run.netsh()) == 2           # the restore test below re-adds 10.0.0.6 through the private path


def test_set_static_gives_the_real_address_and_the_gateway_then_the_dns_servers_in_order(win):
    ops, run = _ops()
    ops.set_static(7, "192.168.64.4", "255.255.255.0", "192.168.64.1", ["127.0.0.1", "9.9.9.9"])
    assert run.netsh() == [
        ["interface", "ipv4", "set", "address", "name=7", "source=static", "address=192.168.64.4",
         "mask=255.255.255.0", "gateway=192.168.64.1"],
        ["interface", "ipv4", "set", "dnsservers", "name=7", "source=static", "address=127.0.0.1",
         "validate=no"],
        ["interface", "ipv4", "add", "dnsservers", "name=7", "address=9.9.9.9", "index=2", "validate=no"],
    ]


def test_set_static_without_a_gateway_or_dns_touches_neither(win):
    ops, run = _ops()
    ops.set_static(7, "192.168.64.4", "255.255.255.0", None, None)
    assert run.netsh() == [["interface", "ipv4", "set", "address", "name=7", "source=static",
                            "address=192.168.64.4", "mask=255.255.255.0"]]


def test_set_static_with_an_empty_dns_list_clears_the_servers(win):
    ops, run = _ops()
    ops.set_static(7, "192.168.64.4", "255.255.255.0", None, [])
    assert run.netsh()[-1] == ["interface", "ipv4", "set", "dnsservers", "name=7", "source=static",
                               "address=none"]


def test_set_dns_sets_the_servers_and_touches_no_address(win):
    ops, run = _ops()
    ops.set_dns(7, ["127.0.0.1", "9.9.9.9"])
    assert run.netsh() == [
        ["interface", "ipv4", "set", "dnsservers", "name=7", "source=static", "address=127.0.0.1", "validate=no"],
        ["interface", "ipv4", "add", "dnsservers", "name=7", "address=9.9.9.9", "index=2", "validate=no"],
    ]


def test_set_dns_with_an_empty_list_clears_the_servers_and_a_failure_is_an_error(win):
    ops, run = _ops()
    ops.set_dns(7, [])
    assert run.netsh() == [["interface", "ipv4", "set", "dnsservers", "name=7", "source=static", "address=none"]]
    ops, _ = _ops({"netsh.exe": [(1, "Access is denied.", "")]})
    with pytest.raises(net_system.SystemOpsError, match="Access is denied"):
        ops.set_dns(7, ["127.0.0.1"])


def test_the_fake_records_set_dns_and_answers_the_profile_it_was_given():
    ops = net_system.FakeSystemOps(profile="Public")
    ops.set_dns(7, ["127.0.0.1"])
    assert ops.network_profile(7) == "Public"
    assert ops.calls == [("set_dns", 7, ["127.0.0.1"]), ("network_profile", 7)]


@pytest.mark.parametrize("category,profile", [("Public", "Public"), ("Private", "Private"),
                                              ("DomainAuthenticated", "Domain"), (None, None), ("Other", None)])
def test_the_network_profile_is_named_the_way_the_firewall_profiles_are(win, category, profile):
    ops, run = _ops({"powershell.exe": [(0, json.dumps({"category": category}), "")]})
    assert ops.network_profile(7) == profile
    assert _payload_of(run.calls[0]) == {"op": "profile", "index": 7}
    assert "Get-NetConnectionProfile" in _script_of(run.calls[0])


def test_set_static_stops_at_the_first_command_that_fails(win):
    ops, run = _ops({"netsh.exe": [(1, "Access is denied.", "")]})
    with pytest.raises(net_system.SystemOpsError, match="Access is denied"):
        ops.set_static(7, "192.168.64.4", "255.255.255.0", "192.168.64.1", ["127.0.0.1"])
    assert len(run.netsh()) == 1


# ---- reading and restoring the addressing ---------------------------------------------------------


def _script_of(call):
    """The PowerShell text of a run: the -EncodedCommand argument decoded."""
    encoded = call[call.index("-EncodedCommand") + 1]
    return base64.b64decode(encoded).decode("utf-16-le")


def _payload_of(call):
    script = _script_of(call)
    match = re.search(r"FromBase64String\('([A-Za-z0-9+/=]*)'\)", script)
    return json.loads(base64.b64decode(match.group(1)).decode("utf-8"))


DHCP_ADAPTER = {
    "dhcp": True,
    "addresses": [{"address": "192.168.64.4", "prefix": 24, "skip_as_source": False}],
    "gateway": "192.168.64.1",
    "dns": ["192.168.64.1"],
    "dns_static": [],
}
STATIC_ADAPTER = {
    "dhcp": False,
    "addresses": [{"address": "10.0.0.5", "prefix": 24, "skip_as_source": False},
                  {"address": "10.0.0.6", "prefix": 24, "skip_as_source": True}],
    "gateway": "10.0.0.1",
    "dns": ["10.0.0.2", "10.0.0.3"],
    "dns_static": ["10.0.0.2", "10.0.0.3"],
}


def _answer(adapter):
    return (0, json.dumps(adapter), "")


def test_the_addressing_is_read_as_a_dict_with_masks_not_prefix_lengths(win):
    ops, run = _ops({"powershell.exe": [_answer(STATIC_ADAPTER)]})
    state = ops.read_addressing(7)
    assert state == {
        "index": 7,
        "dhcp": False,
        "addresses": [{"address": "10.0.0.5", "mask": "255.255.255.0", "skip_as_source": False},
                      {"address": "10.0.0.6", "mask": "255.255.255.0", "skip_as_source": True}],
        "gateway": "10.0.0.1",
        "dns": ["10.0.0.2", "10.0.0.3"],
        "dns_static": ["10.0.0.2", "10.0.0.3"],
    }
    assert _payload_of(run.calls[0]) == {"op": "read", "index": 7}


def test_the_real_address_comes_first_so_that_it_is_the_one_a_restore_sets_first(win):
    adapter = dict(STATIC_ADAPTER, addresses=[{"address": "198.18.1.1", "prefix": 16, "skip_as_source": True},
                                              {"address": "10.0.0.5", "prefix": 24, "skip_as_source": False}])
    ops, _ = _ops({"powershell.exe": [_answer(adapter)]})
    assert [a["address"] for a in ops.read_addressing(7)["addresses"]] == ["10.0.0.5", "198.18.1.1"]


def test_a_single_value_where_a_list_was_meant_is_still_a_list(win):
    # PowerShell's ConvertTo-Json writes a one-element array as its element when it is piped
    adapter = dict(DHCP_ADAPTER, dns="192.168.64.1", dns_static="", addresses={"address": "192.168.64.4",
                                                                               "prefix": 24,
                                                                               "skip_as_source": False})
    ops, _ = _ops({"powershell.exe": [_answer(adapter)]})
    state = ops.read_addressing(7)
    assert state["dns"] == ["192.168.64.1"]
    assert state["dns_static"] == []
    assert len(state["addresses"]) == 1


def test_an_answer_that_is_not_the_addressing_is_an_error_and_not_an_empty_state(win):
    # restoring from an empty state would take the adapter's address away
    for bad in ["", "not json", "[]", json.dumps({"dhcp": True})]:
        ops, _ = _ops({"powershell.exe": [(0, bad, "")]})
        with pytest.raises(net_system.SystemOpsError):
            ops.read_addressing(7)


def test_a_failed_read_is_an_error_with_the_first_line_of_stderr(win):
    ops, _ = _ops({"powershell.exe": [(1, "", "No MSFT_NetIPInterface objects found\nat line 3")]})
    with pytest.raises(net_system.SystemOpsError, match="No MSFT_NetIPInterface"):
        ops.read_addressing(7)


def test_a_round_trip_on_an_adapter_that_was_not_changed_runs_nothing_that_changes_it(win):
    for adapter in (DHCP_ADAPTER, STATIC_ADAPTER):
        ops, run = _ops({"powershell.exe": [_answer(adapter)]})
        state = ops.read_addressing(7)
        run.calls.clear()
        ops.restore_addressing(7, state)
        assert run.netsh() == []
        assert "ipconfig.exe" not in run.programs()
        assert run.programs() == ["powershell.exe"]            # only the look at the adapter


def test_a_dhcp_adapter_that_was_taken_off_dhcp_goes_back_to_dhcp_before_anything_else(win):
    # the measured case: add address switched DHCP off and the leased address went with it
    changed = dict(STATIC_ADAPTER,
                   addresses=[{"address": "198.18.1.1", "prefix": 16, "skip_as_source": True}],
                   dns_static=[])
    ops, run = _ops({"powershell.exe": [_answer(DHCP_ADAPTER), _answer(changed)]})
    state = ops.read_addressing(7)
    run.calls.clear()
    ops.restore_addressing(7, state)
    assert run.netsh() == [
        ["interface", "ipv4", "set", "address", "name=7", "source=dhcp"],
        ["interface", "ipv4", "set", "dnsservers", "name=7", "source=dhcp"],
    ]
    assert "ipconfig.exe" in run.programs()


def test_an_adapter_that_is_already_on_dhcp_is_not_told_to_switch_it_on_again(win):
    # netsh refuses ("DHCP is already enabled"), and a restore that worked must not report that as a failure
    adapter = dict(DHCP_ADAPTER, dns=["1.1.1.1"], dns_static=["1.1.1.1"])
    ops, run = _ops({"powershell.exe": [_answer(adapter), _answer(DHCP_ADAPTER)],
                     "netsh.exe": [(0, "", "")]})
    state = ops.read_addressing(7)
    run.calls.clear()
    ops.restore_addressing(7, state)
    assert run.netsh() == [["interface", "ipv4", "set", "dnsservers", "name=7", "source=static",
                            "address=1.1.1.1", "validate=no"]]
    assert "ipconfig.exe" not in run.programs()


def test_a_dhcp_adapter_with_static_dns_gets_its_static_dns_back(win):
    adapter = dict(DHCP_ADAPTER, dns=["1.1.1.1"], dns_static=["1.1.1.1", "9.9.9.9"])
    changed = dict(STATIC_ADAPTER, dns_static=[])
    ops, run = _ops({"powershell.exe": [_answer(adapter), _answer(changed)]})
    state = ops.read_addressing(7)
    run.calls.clear()
    ops.restore_addressing(7, state)
    assert run.netsh() == [
        ["interface", "ipv4", "set", "address", "name=7", "source=dhcp"],
        ["interface", "ipv4", "set", "dnsservers", "name=7", "source=static", "address=1.1.1.1",
         "validate=no"],
        ["interface", "ipv4", "add", "dnsservers", "name=7", "address=9.9.9.9", "index=2", "validate=no"],
    ]


def test_a_static_adapter_gets_its_primary_back_then_loses_what_we_added_and_regains_what_it_had(win):
    ours = {"address": "198.18.1.1", "prefix": 16, "skip_as_source": True}
    during = dict(STATIC_ADAPTER, addresses=STATIC_ADAPTER["addresses"][:1] + [ours])
    after_set = dict(STATIC_ADAPTER, addresses=[STATIC_ADAPTER["addresses"][0], ours])
    ops, run = _ops({"powershell.exe": [_answer(STATIC_ADAPTER), _answer(during), _answer(after_set)]})
    state = ops.read_addressing(7)
    run.calls.clear()
    ops.restore_addressing(7, state)
    assert run.netsh() == [
        ["interface", "ipv4", "set", "address", "name=7", "source=static", "address=10.0.0.5",
         "mask=255.255.255.0", "gateway=10.0.0.1"],
        ["interface", "ipv4", "delete", "address", "7", "198.18.1.1"],
        ["interface", "ipv4", "add", "address", "7", "10.0.0.6", "255.255.255.0", "skipassource=true"],
        ["interface", "ipv4", "set", "dnsservers", "name=7", "source=static", "address=10.0.0.2",
         "validate=no"],
        ["interface", "ipv4", "add", "dnsservers", "name=7", "address=10.0.0.3", "index=2", "validate=no"],
    ]


def test_a_restore_that_cannot_look_at_the_adapter_still_restores(win):
    # the way out must not depend on the thing that may be broken
    ops, run = _ops({"powershell.exe": [_answer(DHCP_ADAPTER), (1, "", "WMI is not answering")]})
    state = ops.read_addressing(7)
    run.calls.clear()
    ops.restore_addressing(7, state)
    assert run.netsh()[0] == ["interface", "ipv4", "set", "address", "name=7", "source=dhcp"]


def test_a_restore_tries_every_step_and_then_says_which_failed(win):
    changed = dict(STATIC_ADAPTER, dns_static=[])
    ops, run = _ops({"powershell.exe": [_answer(DHCP_ADAPTER), _answer(changed)],
                     "netsh.exe": [(1, "The system cannot find the file specified.", ""), (0, "", "")]})
    state = ops.read_addressing(7)
    run.calls.clear()
    with pytest.raises(net_system.SystemOpsError, match="source=dhcp|set address"):
        ops.restore_addressing(7, state)
    assert len(run.netsh()) == 2          # the dns step was tried although the address step failed


def test_a_state_that_this_class_did_not_produce_is_refused_before_anything_runs(win):
    ops, run = _ops()
    for bad in [None, {}, {"dhcp": True}, {"dhcp": "yes", "addresses": [], "dns_static": []}, [], "dhcp"]:
        with pytest.raises((ValueError, TypeError)):
            ops.restore_addressing(7, bad)
    assert run.calls == []


# ---- the firewall -----------------------------------------------------------------------------------

RULE = {
    "direction": "out",
    "action": "block",
    "remote_address": ["0.0.0.0-198.17.255.255", "198.20.0.0-255.255.255.255"],
    "protocol": "tcp",
    "remote_port": [80, "8000-8100"],
    "program": r"C:\Program Files\x.exe",
}


def test_a_rule_is_written_through_new_netfirewallrule_with_every_value_as_data(win):
    ops, run = _ops({"powershell.exe": [(0, json.dumps({"profiles_off": []}), "")]})
    assert ops.add_firewall_rule("TDC-NET-ISOLATE", RULE) == []
    call = run.calls[0]
    assert call[:6] == [net_system.POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                        "-EncodedCommand"]
    assert "-Command" not in call
    script = _script_of(call)
    assert "New-NetFirewallRule" in script
    assert _payload_of(call) == {
        "op": "add_rule", "name": "TDC-NET-ISOLATE",
        "spec": {"direction": "Outbound", "action": "Block",
                 "remote_address": ["0.0.0.0-198.17.255.255", "198.20.0.0-255.255.255.255"],
                 "protocol": "TCP", "remote_port": ["80", "8000-8100"],
                 "program": r"C:\Program Files\x.exe"},
    }


def test_nothing_the_caller_gave_is_part_of_the_script_but_the_one_base64_payload(win):
    hostile = "x'; Remove-Item C:\\ -Recurse; '"
    ops, run = _ops({"powershell.exe": [(0, json.dumps({"profiles_off": []}), "")]})
    ops.add_firewall_rule("TDC-NET-ISOLATE", dict(RULE, program=hostile))
    script = _script_of(run.calls[0])
    assert "Remove-Item" not in script
    assert hostile not in script
    assert _payload_of(run.calls[0])["spec"]["program"] == hostile


def test_the_script_is_the_same_text_whatever_the_call_so_only_the_payload_differs(win):
    ops, run = _ops({"powershell.exe": [(0, json.dumps({"profiles_off": []}), ""), (0, json.dumps({"removed": 0}), "")]})
    ops.add_firewall_rule("TDC-NET-A", RULE)
    ops.remove_firewall_rules("TDC-NET-")
    strip = lambda c: re.sub(r"FromBase64String\('[^']*'\)", "", _script_of(c))
    assert strip(run.calls[0]) == strip(run.calls[1])


def test_the_profiles_that_are_off_are_handed_back_because_a_rule_there_would_bite_nothing(win):
    ops, run = _ops({"powershell.exe": [(0, json.dumps({"profiles_off": ["Public"]}), "")]})
    assert ops.add_firewall_rule("TDC-NET-ISOLATE", RULE) == ["Public"]


def test_a_single_profile_that_powershell_wrote_as_a_bare_string_is_still_a_list(win):
    ops, run = _ops({"powershell.exe": [(0, json.dumps({"profiles_off": "Public"}), "")]})
    assert ops.add_firewall_rule("TDC-NET-ISOLATE", RULE) == ["Public"]


@pytest.mark.parametrize("name", ["", "isolate", "TDC-", "TDC-NET-*", "TDC-NET-A B", "TDC-NET-A\n", "TDC-NET-" + "x" * 80,
                                  "tdc-net-x", "FW-TDC-NET", "TDC-NET-[a]", "TDC-NET-?"])
def test_a_rule_name_outside_the_tdc_namespace_or_with_a_wildcard_runs_nothing(win, name):
    ops, run = _ops()
    with pytest.raises(ValueError):
        ops.add_firewall_rule(name, RULE)
    assert run.calls == []


@pytest.mark.parametrize("spec", [
    {},
    {"action": "deny"},
    {"action": "block", "direction": "sideways"},
    {"action": "block", "colour": "red"},
    {"action": "block", "protocol": "gopher"},
    {"action": "block", "remote_port": [0]},
    {"action": "block", "remote_port": ["80;81"]},
    {"action": "block", "remote_port": [70000]},
    {"action": "block", "remote_address": ["not-an-address"]},
    {"action": "block", "remote_address": ["1.2.3.4/33"]},
    {"action": "block", "program": "-Program"},
    {"action": "block", "program": "a\x00b"},
    "block",
])
def test_a_rule_spec_that_is_not_understood_runs_nothing(win, spec):
    ops, run = _ops()
    with pytest.raises(ValueError):
        ops.add_firewall_rule("TDC-NET-ISOLATE", spec)
    assert run.calls == []


def test_a_spec_with_only_an_action_is_an_outbound_rule_for_everything(win):
    ops, run = _ops({"powershell.exe": [(0, json.dumps({"profiles_off": []}), "")]})
    ops.add_firewall_rule("TDC-NET-ISOLATE", {"action": "allow"})
    assert _payload_of(run.calls[0])["spec"] == {"direction": "Outbound", "action": "Allow"}


def test_a_single_address_or_port_is_accepted_without_a_list(win):
    ops, run = _ops({"powershell.exe": [(0, json.dumps({"profiles_off": []}), "")]})
    ops.add_firewall_rule("TDC-NET-A", {"action": "allow", "protocol": "udp", "remote_address": "198.18.0.0/15",
                                        "local_port": 53})
    spec = _payload_of(run.calls[0])["spec"]
    assert spec["remote_address"] == ["198.18.0.0/15"]
    assert spec["local_port"] == ["53"]
    assert spec["protocol"] == "UDP"


def test_a_failed_write_of_a_rule_is_an_error(win):
    ops, run = _ops({"powershell.exe": [(1, "", "Cannot create a file when that file already exists.")]})
    with pytest.raises(net_system.SystemOpsError, match="already exists"):
        ops.add_firewall_rule("TDC-NET-ISOLATE", RULE)


def test_rules_are_removed_by_prefix_and_the_number_removed_is_returned(win):
    ops, run = _ops({"powershell.exe": [(0, json.dumps({"removed": 2}), "")]})
    assert ops.remove_firewall_rules("TDC-NET-") == 2
    assert _payload_of(run.calls[0]) == {"op": "remove_rules", "prefix": "TDC-NET-"}


@pytest.mark.parametrize("prefix", ["", "T", "TDC", "*", "TDC-*", "Core", "TDC-NET-\n", "TDC-NET-?", "[x]"])
def test_a_prefix_that_could_reach_a_rule_that_is_not_ours_runs_nothing(win, prefix):
    ops, run = _ops()
    with pytest.raises(ValueError):
        ops.remove_firewall_rules(prefix)
    assert run.calls == []


# ---- the certificate ----------------------------------------------------------------------------------


def _pem():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TDC test CA")])
    import datetime
    now = datetime.datetime(2026, 11, 27)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii"), cert


def _pem_only():
    return _pem()[0]


def test_the_thumbprint_is_the_sha1_of_the_der_as_windows_shows_it():
    pem, cert = _pem()
    assert net_system.thumbprint_of(pem) == cert.fingerprint(hashes.SHA1()).hex().upper()
    assert net_system.thumbprint_of(pem.encode("ascii")) == net_system.thumbprint_of(pem)


@pytest.mark.parametrize("bad", ["", "nonsense", "-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n"])
def test_something_that_is_not_a_certificate_has_no_thumbprint(bad):
    with pytest.raises(ValueError):
        net_system.thumbprint_of(bad)


def test_a_ca_is_added_to_the_machine_root_store_and_its_thumbprint_is_checked_after(win, tmp_path):
    pem, cert = _pem()
    thumb = cert.fingerprint(hashes.SHA1()).hex().upper()
    seen = {}

    def run(args):
        seen.setdefault("calls", []).append(list(args))
        if "-addstore" in args:
            with open(args[-1]) as f:
                seen["file_pem"] = f.read()
        return 0, "", ""

    ops = net_system.WindowsSystemOps(run=run)
    assert ops.install_ca(pem) == thumb
    add, verify = seen["calls"]
    assert add[1:4] == ["-f", "-addstore", "Root"]
    assert seen["file_pem"] == pem
    assert verify[1:] == ["-store", "Root", thumb]
    import os
    assert not os.path.exists(add[-1])             # the file is not left behind


def test_a_ca_that_is_not_in_the_store_afterwards_is_an_error(win):
    runs = []

    def run(args):
        runs.append(args)
        return (0, "", "") if "-addstore" in args else (1, "Not found", "")

    ops = net_system.WindowsSystemOps(run=run)
    with pytest.raises(net_system.SystemOpsError):
        ops.install_ca(_pem_only())


def test_a_failed_certutil_is_an_error_with_its_first_line_and_the_file_is_still_removed(win):
    files = []

    def run(args):
        files.append(args[-1])
        return 5, "\nAccess is denied.\n", ""

    ops = net_system.WindowsSystemOps(run=run)
    with pytest.raises(net_system.SystemOpsError, match="Access is denied"):
        ops.install_ca(_pem_only())
    import os
    assert not os.path.exists(files[0])


def test_a_ca_is_removed_by_thumbprint(win):
    ops, run = _ops()
    assert ops.remove_ca("ab" * 20) is True
    assert run.calls[0][1:] == ["-delstore", "Root", "AB" * 20]


def test_removing_a_ca_that_is_not_there_is_not_an_error_so_the_next_start_can_sweep(win):
    # the exit code and text of certutil are localised: absence is judged by looking, not by the message
    ops, run = _ops({"certutil.exe": [(1, "CertUtil: -delstore command FAILED: 0x80092004", ""),
                                      (1, "not found", "")]})
    assert ops.remove_ca("AB" * 20) is False


def test_a_ca_that_will_not_go_is_an_error(win):
    ops, run = _ops({"certutil.exe": [(5, "Access is denied.", ""), (0, "Serial Number: 01", "")]})
    with pytest.raises(net_system.SystemOpsError, match="Access is denied"):
        ops.remove_ca("AB" * 20)


@pytest.mark.parametrize("thumb", ["", "AB", "G" * 40, "AB" * 20 + "\n", "-all", "AB CD " * 6, "AB" * 21])
def test_a_thumbprint_that_is_not_forty_hex_digits_runs_nothing(win, thumb):
    ops, run = _ops()
    with pytest.raises(ValueError):
        ops.remove_ca(thumb)
    assert run.calls == []


# ---- the runner -------------------------------------------------------------------------------------


def test_a_runner_that_raises_is_an_error_of_this_module_not_a_stray_exception(win):
    def run(args):
        raise OSError("cannot start")

    with pytest.raises(net_system.SystemOpsError, match="cannot start"):
        net_system.WindowsSystemOps(run=run).remove_address(7, "198.18.1.1")
