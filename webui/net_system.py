"""The seam between the fake internet and the operating system.

Everything the fake internet does to the machine it runs on - addresses on the adapter, the adapter's own
configuration, a firewall rule, a certificate in the machine store, and the question "which process owns this
connection" - goes through ``SystemOps``. ``FakeSystemOps`` records what it was asked and answers from what it was
given, so every other module of the fake internet is tested on a developer's machine; ``WindowsSystemOps`` is the
real thing and the only class that can only run on Windows. Importing this module needs no Windows: only
constructing ``WindowsSystemOps`` does.

How it shells out. No value is ever part of a command line as text. ``netsh`` and ``certutil`` get their values as
list items (no shell: ``run_powershell`` of ``firewall_rules`` is the runner, it runs any program). What needs
PowerShell (reading the adapter, the firewall rules) is **one fixed script**, ``_SCRIPT``, run with
``-EncodedCommand``; the only thing that varies between calls is a base64 JSON payload that the script decodes into
data and hands to one cmdlet as parameters. Base64 cannot close the quotes around it, so nothing the caller gave can
become code, and unlike ``firewall_rules.ps1`` there is no second file to deploy. ``-Command`` is never used with the
values in it, for the reason ``firewall_rules`` gives: it joins its arguments into one line and parses it.

What a failure looks like. A program that exits non-zero is a ``SystemOpsError`` with the first line of what it
printed - netsh writes its errors to stdout, not stderr, so both are read. A value that cannot be what it must be
(an adapter index that is not a positive integer, an address that is not IPv4, a rule name outside ``TDC-``) is a
``ValueError`` and nothing is run.

The adapter. ``netsh interface ipv4 add address`` puts a static address on the adapter, and on an adapter that is
configured by DHCP that switches DHCP off: the leased address goes at once, the client stops renewing and the
machine disappears from the network. That is not a theory: it cost the test VM its network
(scripts/measure-secondary-addresses.ps1, ``dhcp_before`` Enabled, ``dhcp_after_adding`` Disabled). So the caller
reads the addressing first (``read_addressing``), makes the adapter static with the real address
(``set_static``), only then adds addresses, and at the end hands exactly what it read back to
``restore_addressing``. ``add_address`` itself does not look at DHCP: that is the caller's order, kept in one place.
"""

from __future__ import annotations

import base64
import copy
import ctypes
import hashlib
import ipaddress
import json
import ntpath
import os
import re
import ssl
import struct
import sys
import tempfile
from typing import Any, Callable, Dict, List, Optional, Tuple

from firewall_rules import run_powershell

_SYSTEM32 = ntpath.join(os.environ.get("SystemRoot") or r"C:\Windows", "System32")
POWERSHELL = ntpath.join(_SYSTEM32, "WindowsPowerShell", "v1.0", "powershell.exe")
NETSH = ntpath.join(_SYSTEM32, "netsh.exe")
CERTUTIL = ntpath.join(_SYSTEM32, "certutil.exe")
IPCONFIG = ntpath.join(_SYSTEM32, "ipconfig.exe")

CA_STORE = "Root"          # the machine's Trusted Root Certification Authorities

# Rules of the fake internet live in the TDC- namespace and never in TDC-FW-: those are the FIREWALL tab's, which
# lists, switches off around and removes them by that prefix (firewall_rules). A prefix that could reach them, or a
# rule that could be mistaken for one of them, is refused.
RULE_NAMESPACE = "TDC-"
FIREWALL_TAB_PREFIX = "TDC-FW-"
_RULE_NAME = re.compile(r"TDC-[A-Za-z0-9][A-Za-z0-9._-]{0,60}")
_THUMBPRINT = re.compile(r"[0-9A-Fa-f]{40}")

ERROR_INSUFFICIENT_BUFFER = 122
AF_INET = 2
TCP_TABLE_OWNER_PID_ALL = 5
TCP_TABLE_RETRIES = 8
TCP_TABLE_SLACK = 24 * 64      # rows that may appear between asking for the size and reading the table

IDLE_PID = 0


class SystemOpsError(Exception):
    """An operating system call that failed. The message is for the analyst: the program and its first line."""


# --------------------------------------------------------------------------------------------------
# What may be asked
# --------------------------------------------------------------------------------------------------


class SystemOps:
    """Protocol of the operations the fake internet performs on the machine."""

    def add_address(self, index, address, mask):
        """Add a secondary IPv4 address to adapter ``index``, with ``skipassource`` so that no connection of the
        machine leaves from it."""
        raise NotImplementedError

    def remove_address(self, index, address):
        raise NotImplementedError

    def set_static(self, index, address, mask, gateway, dns):
        """Configure adapter ``index`` statically with ``address``/``mask``, ``gateway`` (None: leave it) and the
        ``dns`` servers (None: leave them, an empty list: none). The caller does this before it adds an address."""
        raise NotImplementedError

    def read_addressing(self, index):
        """The adapter's addressing as a dict that ``restore_addressing`` takes as it is, DHCP state included."""
        raise NotImplementedError

    def restore_addressing(self, index, state):
        """Put adapter ``index`` back to ``state``, which is what ``read_addressing`` returned for it. On an adapter
        that was not changed this changes nothing."""
        raise NotImplementedError

    def add_firewall_rule(self, name, spec):
        """Write one firewall rule ``name`` (``TDC-...``) as ``spec`` describes it (see ``WindowsSystemOps``).
        Returns the firewall profiles that are switched off: a rule written while one is off does nothing there."""
        raise NotImplementedError

    def remove_firewall_rules(self, prefix):
        """Remove every rule whose name starts with ``prefix``; returns how many there were."""
        raise NotImplementedError

    def install_ca(self, pem):
        """Add the certificate to the machine's trusted roots; returns its thumbprint."""
        raise NotImplementedError

    def remove_ca(self, thumbprint):
        """Remove the certificate with that thumbprint; True if one was there, False if not (not an error)."""
        raise NotImplementedError

    def tcp_owner(self, local_ip, local_port, remote_ip, remote_port):
        """The pid that owns the entry of the TCP table whose local end is ``local_ip:local_port`` and whose remote
        end is ``remote_ip:remote_port``, or None. The ends are the entry's own: the server side of a connection and
        the client side are two entries, each with the ends the other way round."""
        raise NotImplementedError


# --------------------------------------------------------------------------------------------------
# In-memory fake
# --------------------------------------------------------------------------------------------------

_DEFAULT_ADDRESSING = {
    "dhcp": False,
    "addresses": [{"address": "10.0.0.5", "mask": "255.255.255.0", "skip_as_source": False}],
    "gateway": "10.0.0.1",
    "dns": ["10.0.0.1"],
    "dns_static": ["10.0.0.1"],
}


class FakeSystemOps(SystemOps):
    """A machine that is only a list of what was asked of it.

    ``calls`` holds one tuple per call, ``(method, *arguments)`` with the arguments in the order of the signature
    however the call was spelled, in the order the calls came. Asking who owns a connection (``tcp_owner``) is not
    recorded: it is asked once per accepted connection and says nothing about what was done to the machine.

    ``tcp_owners`` maps ``(local_ip, local_port, remote_ip, remote_port)`` to a pid. ``addressing`` is what
    ``read_addressing`` answers (a copy; its shape is the caller's, the Windows class's is described at
    ``WindowsSystemOps.read_addressing``). ``fail`` maps a method name to an exception that is raised by that method,
    after the call is recorded and before it has any effect. ``profiles_off`` is what ``add_firewall_rule`` reports.
    ``rules`` (name to spec) and ``cas`` (thumbprint to pem) hold what was written and not yet removed.
    """

    def __init__(self, tcp_owners: Optional[Dict[Tuple[str, int, str, int], int]] = None,
                 addressing: Optional[Dict[str, Any]] = None, fail: Optional[Dict[str, BaseException]] = None,
                 profiles_off: Optional[List[str]] = None):
        self.calls: List[tuple] = []
        self.tcp_owners = dict(tcp_owners or {})
        self.addressing = addressing
        self.fail = dict(fail or {})
        self.profiles_off = list(profiles_off or [])
        self.rules: Dict[str, Any] = {}
        self.cas: Dict[str, str] = {}

    def _did(self, method: str, *args: Any) -> None:
        self.calls.append((method,) + args)
        failure = self.fail.get(method)
        if failure is not None:
            raise failure

    def add_address(self, index, address, mask):
        self._did("add_address", index, address, mask)

    def remove_address(self, index, address):
        self._did("remove_address", index, address)

    def set_static(self, index, address, mask, gateway, dns):
        self._did("set_static", index, address, mask, gateway, dns)

    def read_addressing(self, index):
        self._did("read_addressing", index)
        if self.addressing is not None:
            return copy.deepcopy(self.addressing)
        return dict(copy.deepcopy(_DEFAULT_ADDRESSING), index=index)

    def restore_addressing(self, index, state):
        self._did("restore_addressing", index, state)

    def add_firewall_rule(self, name, spec):
        self._did("add_firewall_rule", name, spec)
        self.rules[name] = spec
        return list(self.profiles_off)

    def remove_firewall_rules(self, prefix):
        self._did("remove_firewall_rules", prefix)
        gone = [n for n in self.rules if n.startswith(prefix)]
        for name in gone:
            del self.rules[name]
        return len(gone)

    def install_ca(self, pem):
        self._did("install_ca", pem)
        try:
            thumbprint = thumbprint_of(pem)
        except ValueError:
            # a fake accepts what a test made up; only the real store has to be given a certificate
            text = pem if isinstance(pem, str) else bytes(pem).decode("utf-8", "replace")
            thumbprint = hashlib.sha1(text.encode("utf-8")).hexdigest().upper()
        self.cas[thumbprint] = pem
        return thumbprint

    def remove_ca(self, thumbprint):
        self._did("remove_ca", thumbprint)
        return self.cas.pop(thumbprint, None) is not None

    def tcp_owner(self, local_ip, local_port, remote_ip, remote_port):
        return self.tcp_owners.get((local_ip, local_port, remote_ip, remote_port))


# --------------------------------------------------------------------------------------------------
# What may be handed to the system
# --------------------------------------------------------------------------------------------------


def _index(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"not an adapter index: {str(value)[:20]!r}")
    return value


def _ipv4(value: Any, what: str = "address") -> str:
    try:
        if not isinstance(value, str):
            raise ValueError
        return str(ipaddress.IPv4Address(value))
    except ValueError:
        raise ValueError(f"not an IPv4 {what}: {str(value)[:40]!r}") from None


def _mask(value: Any) -> str:
    try:
        if not isinstance(value, str):
            raise ValueError
        return str(ipaddress.IPv4Network("0.0.0.0/" + value).netmask)
    except ValueError:
        raise ValueError(f"not an IPv4 netmask: {str(value)[:40]!r}") from None


def _servers(value: Any) -> Optional[List[str]]:
    if value is None:
        return None
    if isinstance(value, str) or not hasattr(value, "__iter__"):
        raise ValueError("dns must be a list of addresses")
    return [_ipv4(v, "dns server") for v in value]


def _rule_name(value: Any) -> str:
    if not isinstance(value, str) or not _RULE_NAME.fullmatch(value) or value.startswith(FIREWALL_TAB_PREFIX):
        raise ValueError(f"not a rule name of the fake internet (TDC-..., not TDC-FW-): {str(value)[:60]!r}")
    return value


def _rule_prefix(value: Any) -> str:
    if not isinstance(value, str) or not _RULE_NAME.fullmatch(value):
        raise ValueError(f"not a rule prefix of the fake internet (TDC-...): {str(value)[:60]!r}")
    if value.startswith(FIREWALL_TAB_PREFIX) or FIREWALL_TAB_PREFIX.startswith(value):
        raise ValueError(f"{value!r} would reach the rules of the FIREWALL tab (TDC-FW-)")
    return value


def _thumbprint(value: Any) -> str:
    if not isinstance(value, str) or not _THUMBPRINT.fullmatch(value):
        raise ValueError(f"not a SHA-1 thumbprint: {str(value)[:60]!r}")
    return value.upper()


def thumbprint_of(pem: Any) -> str:
    """The thumbprint Windows shows for a certificate: SHA-1 of its DER form, upper-case hex, no spaces.

    One certificate only. Raises ``ValueError`` for anything that is not one."""
    text = pem.decode("ascii", "strict") if isinstance(pem, (bytes, bytearray)) else pem
    try:
        der = ssl.PEM_cert_to_DER_cert(text.strip())
    except Exception:
        raise ValueError("not a PEM certificate") from None
    if not der:
        raise ValueError("not a PEM certificate")
    return hashlib.sha1(der).hexdigest().upper()


_DIRECTIONS = {"in": "Inbound", "inbound": "Inbound", "out": "Outbound", "outbound": "Outbound"}
_ACTIONS = {"allow": "Allow", "block": "Block"}
_PROTOCOLS = {"tcp": "TCP", "udp": "UDP", "any": None}
_SPEC_KEYS = ("direction", "action", "program", "protocol", "remote_address", "local_address", "remote_port",
              "local_port")
MAX_PATH_CHARS = 4096


def _many(value: Any, what: str) -> list:
    items = list(value) if isinstance(value, (list, tuple)) else [value]
    if not items:
        raise ValueError(f"{what} is an empty list: leave it out for 'any'")
    return items


def _rule_address(value: Any) -> str:
    """An address, a ``a/n`` network or an ``a-b`` range, IPv4 or IPv6: the forms ``-RemoteAddress`` takes that
    say exactly which addresses, and none of its keywords."""
    if not isinstance(value, str) or not value.isascii():
        raise ValueError(f"not an address: {str(value)[:40]!r}")
    try:
        if "-" in value:
            low, _, high = value.partition("-")
            a, b = ipaddress.ip_address(low), ipaddress.ip_address(high)
            if a.version != b.version or a > b:
                raise ValueError
        elif "/" in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
    except ValueError:
        raise ValueError(f"not an address, network or range: {str(value)[:40]!r}") from None
    return value


def _rule_port(value: Any) -> str:
    """A port or an ``a-b`` range of ports as the text ``-LocalPort`` takes, never one of its keywords."""
    text = str(value) if isinstance(value, int) and not isinstance(value, bool) else value
    if not isinstance(text, str) or not re.fullmatch(r"[0-9]{1,5}(-[0-9]{1,5})?", text):
        raise ValueError(f"not a port or port range: {str(value)[:20]!r}")
    numbers = [int(n) for n in text.split("-")]
    if any(not 1 <= n <= 65535 for n in numbers) or numbers != sorted(numbers):
        raise ValueError(f"not a port or port range: {text!r}")
    return text


def _rule_program(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("program must be a path")
    text = value.strip()
    if not text or len(text) > MAX_PATH_CHARS or text.startswith("-") \
            or any(ord(c) < 32 or ord(c) == 127 for c in text):
        raise ValueError("program is not a usable path")
    return text


def _rule_spec(spec: Any) -> Dict[str, Any]:
    """``spec`` as the payload of the script: what is there, spelled the way ``New-NetFirewallRule`` wants it.

    ``action`` is required (``"allow"`` or ``"block"``). ``direction`` is ``"out"`` unless it says ``"in"``.
    ``protocol`` is ``"tcp"``, ``"udp"`` or ``"any"``. ``program`` is a path. ``remote_address`` and
    ``local_address`` are an address, a network ``a/n`` or a range ``a-b``, or a list of them; ``remote_port`` and
    ``local_port`` a port or a range ``a-b``, or a list of them. Anything left out means "any". Anything else is
    refused, so that a key that is not understood does not silently widen a rule.
    """
    if not isinstance(spec, dict):
        raise ValueError("a rule spec is a dict")
    unknown = sorted(set(spec) - set(_SPEC_KEYS))
    if unknown:
        raise ValueError(f"unknown rule spec key: {unknown[0]!r}")
    action = _ACTIONS.get(str(spec.get("action")).lower()) if isinstance(spec.get("action"), str) else None
    if action is None:
        raise ValueError("a rule needs an action, allow or block")
    direction = _DIRECTIONS.get(str(spec.get("direction", "out")).lower()) \
        if isinstance(spec.get("direction", "out"), str) else None
    if direction is None:
        raise ValueError(f"direction is in or out, not {str(spec.get('direction'))[:20]!r}")
    out: Dict[str, Any] = {"direction": direction, "action": action}
    if "protocol" in spec:
        key = str(spec["protocol"]).lower() if isinstance(spec["protocol"], str) else None
        if key not in _PROTOCOLS:
            raise ValueError(f"protocol is tcp, udp or any, not {str(spec['protocol'])[:20]!r}")
        if _PROTOCOLS[key]:
            out["protocol"] = _PROTOCOLS[key]
    if "program" in spec:
        out["program"] = _rule_program(spec["program"])
    for key in ("remote_address", "local_address"):
        if key in spec:
            out[key] = [_rule_address(v) for v in _many(spec[key], key)]
    for key in ("remote_port", "local_port"):
        if key in spec:
            out[key] = [_rule_port(v) for v in _many(spec[key], key)]
    return out


# --------------------------------------------------------------------------------------------------
# The TCP table (ctypes, iphlpapi)
# --------------------------------------------------------------------------------------------------


class _TcpRowOwnerPid(ctypes.Structure):
    """MIB_TCPROW_OWNER_PID. Addresses are in network byte order in memory; a port is in the low 16 bits, network
    byte order. Fixed-width fields, not ``wintypes.DWORD``: that is ``c_ulong`` and 8 bytes wide on the macOS and
    Linux hosts these tests run on."""
    _fields_ = [("state", ctypes.c_uint32), ("local_addr", ctypes.c_uint32), ("local_port", ctypes.c_uint32),
                ("remote_addr", ctypes.c_uint32), ("remote_port", ctypes.c_uint32),
                ("owning_pid", ctypes.c_uint32)]


_ROW_SIZE = ctypes.sizeof(_TcpRowOwnerPid)

_iphlpapi = None
if os.name == "nt":
    _iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
    _iphlpapi.GetExtendedTcpTable.restype = ctypes.c_uint32
    _iphlpapi.GetExtendedTcpTable.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32), ctypes.c_int,
                                              ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]


def _win_error(code: int, what: str) -> SystemOpsError:
    fmt = getattr(ctypes, "FormatError", None)
    text = fmt(code).strip() if fmt else f"error {code}"
    return SystemOpsError(f"{what} failed ({code}): {text}")


def _port(raw: int) -> int:
    return ((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF)


def _address(raw: int) -> str:
    return str(ipaddress.IPv4Address(struct.pack("=I", raw)))


def read_tcp_table() -> bytes:
    """The IPv4 TCP table as ``GetExtendedTcpTable`` writes it: a count and that many ``_TcpRowOwnerPid``.

    The call answers 122 (insufficient buffer) with the size it needs, and the table can grow between that answer
    and the next call, so it is asked again with some room until it fits. That return value is the error code
    itself; it is not in ``GetLastError``."""
    if _iphlpapi is None:
        raise SystemOpsError("the TCP table needs Windows (iphlpapi)")
    size = ctypes.c_uint32(0)
    buf = None
    for _ in range(TCP_TABLE_RETRIES):
        code = _iphlpapi.GetExtendedTcpTable(buf, ctypes.byref(size), 0, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
        if code == 0:
            return buf.raw[:size.value]
        if code != ERROR_INSUFFICIENT_BUFFER:
            raise _win_error(code, "GetExtendedTcpTable")
        size = ctypes.c_uint32(size.value + TCP_TABLE_SLACK)
        buf = ctypes.create_string_buffer(size.value)
    raise SystemOpsError("GetExtendedTcpTable failed: the table kept growing")


def parse_tcp_table(raw: bytes) -> List[Tuple[int, str, int, str, int, int]]:
    """``[(state, local_ip, local_port, remote_ip, remote_port, pid)]`` of the table ``read_tcp_table`` returns.

    A table that ends inside a row is an error and not a shorter table: a row that is missing is an owner that
    cannot be found, and "nobody owns it" must not be the answer to "could not read it"."""
    if len(raw) < 4:
        raise SystemOpsError("the TCP table is shorter than its header")
    (count,) = struct.unpack_from("<I", raw, 0)
    if len(raw) < 4 + count * _ROW_SIZE:
        raise SystemOpsError(f"the TCP table says {count} rows but holds only {(len(raw) - 4) // _ROW_SIZE}")
    rows = []
    for n in range(count):
        row = _TcpRowOwnerPid.from_buffer_copy(raw, 4 + n * _ROW_SIZE)
        rows.append((row.state, _address(row.local_addr), _port(row.local_port), _address(row.remote_addr),
                     _port(row.remote_port), row.owning_pid))
    return rows


# --------------------------------------------------------------------------------------------------
# PowerShell: the one script
# --------------------------------------------------------------------------------------------------

# The only text that reaches PowerShell as code. ``@@PAYLOAD@@`` is replaced by base64 (A-Z a-z 0-9 + / =), which
# cannot leave the single quotes around it. Written for PowerShell 5.1, what Windows ships.
#
# Errors: with $ErrorActionPreference Stop every failure ends in the catch, which writes its first line to stderr
# and exits 1. (Anything else on stderr under -EncodedCommand would be CLIXML.) Output is one JSON object.
#
# 'read' is what ``read_addressing`` needs and the cmdlets give: the DHCP flag, the addresses with the prefix
# length and SkipAsSource, the default gateway, the DNS servers in force, and - separately - the DNS servers that are
# *configured*. The registry value NameServer of the interface is non-empty exactly when DNS is static; whether it is
# is the one thing Get-DnsClientServerAddress does not say, and restoring DNS to DHCP or to a static list depends on
# it. Link-local addresses (the 169.254 a DHCP client falls back on) are not the adapter's configuration.
#
# 'add_rule' writes the rule for all profiles, then reads it back and fails when it is not enabled, and says which
# profiles are off: New-NetFirewallRule succeeds on a profile that is switched off and the rule then bites nothing.
_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
try {
    $p = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('@@PAYLOAD@@')) | ConvertFrom-Json
    switch ($p.op) {
        'read' {
            $i = [int]$p.index
            $ipif = Get-NetIPInterface -InterfaceIndex $i -AddressFamily IPv4
            $addresses = @(Get-NetIPAddress -InterfaceIndex $i -AddressFamily IPv4 |
                Where-Object { $_.SuffixOrigin -ne 'Link' } |
                ForEach-Object { [ordered]@{ address = [string]$_.IPAddress; prefix = [int]$_.PrefixLength;
                                             skip_as_source = [bool]$_.SkipAsSource } })
            $route = Get-NetRoute -InterfaceIndex $i -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' `
                -ErrorAction SilentlyContinue | Sort-Object -Property RouteMetric | Select-Object -First 1
            $gateway = $null
            if ($route -and $route.NextHop -and ([string]$route.NextHop -ne '0.0.0.0')) { $gateway = [string]$route.NextHop }
            $dns = @(Get-DnsClientServerAddress -InterfaceIndex $i -AddressFamily IPv4 |
                ForEach-Object { $_.ServerAddresses } | ForEach-Object { [string]$_ })
            $guid = [string](Get-NetAdapter -InterfaceIndex $i).InterfaceGuid
            $key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\' + $guid
            $ns = [string](Get-ItemProperty -LiteralPath $key -Name NameServer -ErrorAction SilentlyContinue).NameServer
            $static = @($ns -split '[,\s]+' | Where-Object { $_ })
            ConvertTo-Json -Compress -Depth 5 -InputObject ([ordered]@{
                dhcp = ([string]$ipif.Dhcp -eq 'Enabled'); addresses = $addresses; gateway = $gateway
                dns = $dns; dns_static = $static })
        }
        'add_rule' {
            $s = $p.spec
            $a = @{ Name = [string]$p.name; DisplayName = [string]$p.name; Direction = [string]$s.direction
                    Action = [string]$s.action; Enabled = 'True'; Profile = 'Any' }
            if ($s.program) { $a['Program'] = [string]$s.program }
            if ($s.protocol) { $a['Protocol'] = [string]$s.protocol }
            if ($s.remote_address) { $a['RemoteAddress'] = @($s.remote_address | ForEach-Object { [string]$_ }) }
            if ($s.local_address) { $a['LocalAddress'] = @($s.local_address | ForEach-Object { [string]$_ }) }
            if ($s.remote_port) { $a['RemotePort'] = @($s.remote_port | ForEach-Object { [string]$_ }) }
            if ($s.local_port) { $a['LocalPort'] = @($s.local_port | ForEach-Object { [string]$_ }) }
            New-NetFirewallRule @a | Out-Null
            $rule = Get-NetFirewallRule -Name ([string]$p.name)
            if ([string]$rule.Enabled -ne 'True') { throw "$($p.name) was written but is not enabled" }
            $off = @(Get-NetFirewallProfile -All | Where-Object { [string]$_.Enabled -ne 'True' } |
                ForEach-Object { [string]$_.Name })
            ConvertTo-Json -Compress -InputObject ([ordered]@{ profiles_off = $off })
        }
        'remove_rules' {
            $found = @(Get-NetFirewallRule -Name (([string]$p.prefix) + '*') -ErrorAction SilentlyContinue)
            if ($found.Count -gt 0) { $found | Remove-NetFirewallRule }
            ConvertTo-Json -Compress -InputObject ([ordered]@{ removed = $found.Count })
        }
        default { throw "unknown operation: $($p.op)" }
    }
} catch {
    [Console]::Error.WriteLine((([string]$_.Exception.Message) -split "`r?`n")[0])
    exit 1
}
"""


def _first_line(*texts: Any) -> str:
    for text in texts:
        for line in str(text or "").splitlines():
            if line.strip():
                return line.strip()[:300]
    return ""


def _is_windows() -> bool:
    return sys.platform == "win32"


def _mask_of(prefix: int) -> str:
    return str(ipaddress.IPv4Network("0.0.0.0/%d" % prefix).netmask)


def _text_list(value: Any) -> List[str]:
    """A list of strings from what ConvertTo-Json made of one: a list, a bare string, or nothing."""
    if value is None or value == "":
        return []
    if isinstance(value, str):
        return [value]
    return [str(v) for v in value]


def _same_addresses(a: List[Dict[str, Any]], b: List[Dict[str, Any]]) -> bool:
    def key(entries):
        return sorted((e["address"], e["mask"], bool(e.get("skip_as_source"))) for e in entries)
    return key(a) == key(b)


def _checked_state(index: int, state: Any) -> Dict[str, Any]:
    """``state`` if it is what ``read_addressing`` returns, else ``ValueError``. Restoring from anything else could
    take the adapter's address away, so nothing is run on a state that is not understood."""
    if not isinstance(state, dict) or not isinstance(state.get("dhcp"), bool) \
            or not isinstance(state.get("addresses"), list) or not isinstance(state.get("dns_static"), list):
        raise ValueError("not a state of read_addressing")
    if "index" in state and state["index"] != index:
        raise ValueError(f"the state is of adapter {state['index']}, not of {index}")
    for entry in state["addresses"]:
        if not isinstance(entry, dict):
            raise ValueError("not a state of read_addressing")
        _ipv4(entry.get("address"))
        _mask(entry.get("mask"))
    if not state["dhcp"] and not state["addresses"]:
        raise ValueError("a static state without an address cannot be restored")
    _servers(state["dns_static"])
    if state.get("gateway") is not None:
        _ipv4(state["gateway"], "gateway")
    return state


class WindowsSystemOps(SystemOps):
    """The real operations: ``netsh``, ``certutil``, one PowerShell script, and ``iphlpapi`` through ctypes.

    ``run`` is the runner, ``run(args: list[str]) -> (returncode, stdout, stderr)`` (``firewall_rules.run_powershell``
    by default); ``read_tcp_table`` returns the raw table (``read_tcp_table`` by default). Both are for the tests.
    Raises ``RuntimeError`` when constructed off Windows.

    The addressing as ``read_addressing`` returns it::

        {"index": 7, "dhcp": False,
         "addresses": [{"address": "10.0.0.5", "mask": "255.255.255.0", "skip_as_source": False}, ...],
         "gateway": "10.0.0.1" or None,
         "dns": [...servers in force...], "dns_static": [...servers that are configured, [] if from DHCP...]}

    The address that is not ``skip_as_source`` comes first: it is the adapter's own and the one a static restore
    sets first. ``restore_addressing`` accepts exactly this dict and nothing else.

    The firewall spec of ``add_firewall_rule`` is described at ``_rule_spec``.
    """

    def __init__(self, run: Optional[Callable[[List[str]], Tuple[int, str, str]]] = None,
                 read_tcp_table: Optional[Callable[[], bytes]] = None):
        if not _is_windows():
            raise RuntimeError("WindowsSystemOps needs Windows; use FakeSystemOps")
        self._run = run or run_powershell
        self._read_table = read_tcp_table or globals()["read_tcp_table"]

    # -- running --

    def _call(self, args: List[str]) -> Tuple[int, str, str]:
        try:
            rc, out, err = self._run(args)
        except Exception as e:
            raise SystemOpsError(f"could not run {ntpath.basename(args[0])}: {type(e).__name__}: {e}") from e
        return int(rc), out or "", err or ""

    def _checked(self, args: List[str], what: str) -> str:
        rc, out, err = self._call(args)
        if rc != 0:
            raise SystemOpsError(f"{what} failed ({rc}): {_first_line(err, out) or 'no message'}")
        return out

    def _netsh(self, *args: str) -> str:
        # netsh writes its errors to stdout
        return self._checked([NETSH] + list(args), "netsh " + " ".join(args[:4]))

    def _powershell(self, payload: Dict[str, Any], what: str) -> Dict[str, Any]:
        data = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
        script = _SCRIPT.replace("@@PAYLOAD@@", data)
        encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        out = self._checked([POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                             "-EncodedCommand", encoded], what)
        try:
            answer = json.loads(out)
        except ValueError:
            raise SystemOpsError(f"cannot read the answer for {what}: {_first_line(out)[:80]!r}") from None
        if not isinstance(answer, dict):
            raise SystemOpsError(f"cannot read the answer for {what}: not an object")
        return answer

    # -- addresses --

    def add_address(self, index, address, mask):
        self._netsh("interface", "ipv4", "add", "address", str(_index(index)), _ipv4(address), _mask(mask),
                    "skipassource=true")

    def remove_address(self, index, address):
        self._netsh("interface", "ipv4", "delete", "address", str(_index(index)), _ipv4(address))

    def _set_dns(self, index: int, servers: List[str]) -> None:
        name = f"name={index}"
        if not servers:
            self._netsh("interface", "ipv4", "set", "dnsservers", name, "source=static", "address=none")
            return
        self._netsh("interface", "ipv4", "set", "dnsservers", name, "source=static", "address=" + servers[0],
                    "validate=no")
        for position, server in enumerate(servers[1:], start=2):
            self._netsh("interface", "ipv4", "add", "dnsservers", name, "address=" + server,
                        f"index={position}", "validate=no")

    def set_static(self, index, address, mask, gateway, dns):
        index = _index(index)
        args = ["interface", "ipv4", "set", "address", f"name={index}", "source=static",
                "address=" + _ipv4(address), "mask=" + _mask(mask)]
        if gateway is not None:
            args.append("gateway=" + _ipv4(gateway, "gateway"))
        servers = _servers(dns)
        self._netsh(*args)
        if servers is not None:
            self._set_dns(index, servers)

    # -- reading and restoring the addressing --

    def read_addressing(self, index):
        index = _index(index)
        answer = self._powershell({"op": "read", "index": index}, "reading the addressing")
        if not isinstance(answer.get("dhcp"), bool) or "addresses" not in answer:
            raise SystemOpsError("cannot read the answer for reading the addressing: no dhcp state or addresses")
        raw = answer["addresses"]
        entries = [raw] if isinstance(raw, dict) else list(raw or [])
        addresses = []
        try:
            for entry in entries:
                addresses.append({"address": _ipv4(entry["address"]), "mask": _mask_of(int(entry["prefix"])),
                                  "skip_as_source": bool(entry.get("skip_as_source"))})
            gateway = answer.get("gateway")
            gateway = _ipv4(gateway, "gateway") if gateway else None
            dns = [_ipv4(s, "dns server") for s in _text_list(answer.get("dns"))]
            dns_static = [_ipv4(s, "dns server") for s in _text_list(answer.get("dns_static"))]
        except (KeyError, TypeError, ValueError) as e:
            raise SystemOpsError(f"cannot read the answer for reading the addressing: {e}") from e
        # The adapter's own address first, whatever order the cmdlet listed them in: sort() is stable.
        addresses.sort(key=lambda a: a["skip_as_source"])
        return {"index": index, "dhcp": answer["dhcp"], "addresses": addresses, "gateway": gateway, "dns": dns,
                "dns_static": dns_static}

    def restore_addressing(self, index, state):
        index = _index(index)
        state = _checked_state(index, state)
        try:
            current = self.read_addressing(index)
        except SystemOpsError:
            current = None             # the way back must not depend on the thing that may be broken
        if current is not None and self._unchanged(state, current):
            return
        failures: List[str] = []

        def step(function: Callable[..., Any], *args: Any) -> Any:
            try:
                return function(*args)
            except SystemOpsError as e:
                failures.append(str(e))
                return None

        # The address first: without one the machine is off the network and nothing else matters until it is back.
        if state["dhcp"]:
            step(self._netsh, "interface", "ipv4", "set", "address", f"name={index}", "source=dhcp")
        else:
            self._restore_static(index, state, failures, step)
        if state["dns_static"]:
            step(self._set_dns, index, list(state["dns_static"]))
        else:
            step(self._netsh, "interface", "ipv4", "set", "dnsservers", f"name={index}", "source=dhcp")
        if state["dhcp"]:
            # What the measurement script does after it has put DHCP back: ask for the lease now instead of
            # waiting for the client to notice. Best effort; the lease comes anyway.
            try:
                self._run([IPCONFIG, "/renew"])
            except Exception:
                pass
        if failures:
            raise SystemOpsError("restoring the addressing of adapter %d did not complete: %s"
                                 % (index, "; ".join(failures)))

    def _restore_static(self, index: int, state: Dict[str, Any], failures: List[str], step: Callable) -> None:
        primary = state["addresses"][0]
        args = ["interface", "ipv4", "set", "address", f"name={index}", "source=static",
                "address=" + primary["address"], "mask=" + primary["mask"]]
        if state.get("gateway"):
            args.append("gateway=" + state["gateway"])
        failed_before = len(failures)
        step(self._netsh, *args)
        if len(failures) > failed_before:
            return                      # the primary address did not go back: nothing below can be judged
        try:
            now = self.read_addressing(index)["addresses"]
        except SystemOpsError as e:
            failures.append(str(e))
            return
        wanted = {(a["address"], a["mask"], a["skip_as_source"]) for a in state["addresses"]}
        for entry in now:
            if (entry["address"], entry["mask"], entry["skip_as_source"]) not in wanted:
                step(self.remove_address, index, entry["address"])
        have = {(a["address"], a["mask"], a["skip_as_source"]) for a in now}
        for entry in state["addresses"][1:]:
            if (entry["address"], entry["mask"], entry["skip_as_source"]) in have:
                continue
            if entry["skip_as_source"]:
                step(self.add_address, index, entry["address"], entry["mask"])
            else:
                step(self._netsh, "interface", "ipv4", "add", "address", str(index), entry["address"],
                     entry["mask"])

    @staticmethod
    def _unchanged(state: Dict[str, Any], current: Dict[str, Any]) -> bool:
        """Whether the adapter is as ``state`` says. A DHCP adapter is only compared by that: its lease may be a
        different one, and putting DHCP back on an adapter that is on DHCP would release what it has."""
        if state["dhcp"] != current["dhcp"] or list(state["dns_static"]) != list(current["dns_static"]):
            return False
        if state["dhcp"]:
            return True
        return _same_addresses(state["addresses"], current["addresses"]) \
            and (state.get("gateway") or None) == (current.get("gateway") or None)

    # -- the firewall --

    def add_firewall_rule(self, name, spec):
        name = _rule_name(name)
        answer = self._powershell({"op": "add_rule", "name": name, "spec": _rule_spec(spec)},
                                  f"writing the rule {name}")
        return _text_list(answer.get("profiles_off"))

    def remove_firewall_rules(self, prefix):
        prefix = _rule_prefix(prefix)
        answer = self._powershell({"op": "remove_rules", "prefix": prefix}, f"removing the rules {prefix}*")
        try:
            return int(answer["removed"])
        except (KeyError, TypeError, ValueError):
            raise SystemOpsError("cannot read the answer for removing the rules: no count") from None

    # -- the certificate --

    def install_ca(self, pem):
        thumbprint = thumbprint_of(pem)
        text = pem.decode("ascii") if isinstance(pem, (bytes, bytearray)) else pem
        handle, path = tempfile.mkstemp(suffix=".cer", prefix="tdc-ca-")
        try:
            with os.fdopen(handle, "w", newline="\n") as f:
                f.write(text)
            self._checked([CERTUTIL, "-f", "-addstore", CA_STORE, path], "certutil -addstore")
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass
        # What was installed is what was asked for, or this is not a thumbprint that can be removed again.
        rc, out, err = self._call([CERTUTIL, "-store", CA_STORE, thumbprint])
        if rc != 0:
            raise SystemOpsError(f"certutil -addstore reported success but {thumbprint} is not in the {CA_STORE} "
                                 f"store: {_first_line(err, out)}")
        return thumbprint

    def remove_ca(self, thumbprint):
        thumbprint = _thumbprint(thumbprint)
        rc, out, err = self._call([CERTUTIL, "-delstore", CA_STORE, thumbprint])
        if rc == 0:
            return True
        # certutil's exit code and message are localised and an absent certificate is one of its failures, so
        # absence is judged by looking: a certificate that is still there is the error, one that is not is done.
        again, _, _ = self._call([CERTUTIL, "-store", CA_STORE, thumbprint])
        if again == 0:
            raise SystemOpsError(f"certutil -delstore failed ({rc}): {_first_line(err, out) or 'no message'}")
        return False

    # -- the TCP table --

    def tcp_owner(self, local_ip, local_port, remote_ip, remote_port):
        local, remote = ipaddress.ip_address(local_ip), ipaddress.ip_address(remote_ip)
        if local.version != 4 or remote.version != 4:
            return None                 # only the IPv4 table is read: the fake internet is IPv4
        wanted = (str(local), local_port, str(remote), remote_port)
        owner = None
        for _, laddr, lport, raddr, rport, pid in parse_tcp_table(self._read_table()):
            if (laddr, lport, raddr, rport) == wanted and pid != IDLE_PID:
                owner = pid     # a TIME_WAIT leftover of the same four numbers has pid 0 and never wins
        return owner
