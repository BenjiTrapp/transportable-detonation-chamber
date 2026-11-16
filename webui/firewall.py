"""Assessment of network connections for the FIREWALL tab.

Pure functions, no I/O and no Windows: everything the assessment needs arrives
as an argument, so the whole module runs under pytest on any platform. The one
thing it reaches for by itself is the geo lookup, and that is a field of the
``Context`` (``geoip.lookup`` by default) so a test can swap it.

Input is what the collectors read: Sysmon events as ``_read_sysmon_events`` yields
them (EID 3 network connect, EID 22 DNS query; ``timestamp`` is ISO text) and
Windows firewall log events as ``log_store.parse_firewall_log`` yields them
(``{"fields": {"action", "protocol", "src_ip", "dst_ip", "dst_port", ...}}``).
Sysmon writes ``"-"`` for a value it does not have; that and a blank both mean
"absent" and come out as ``""`` (``None`` for a hostname).

``bundle`` merges the single connections of one process to one endpoint into a
flow, keyed by ``flow_key``: ``(image, pid, protocol, src_ip, dst_ip, dst_port)``,
no source port. Times are epoch seconds. A flow keeps the times of its newest
``MAX_TIMES`` connections in ``times`` (oldest first) because the beaconing
detector needs single connections and the activity bars need a rhythm.

``classify`` is the whole pipeline: it bundles, joins the firewall log, resolves
names through ``ctx.dns`` and tags every flow. A classified flow is plain JSON::

    image pid protocol src_ip dst_ip dst_port        the key
    count first_seen last_seen times                 bundling
    dst_hostname                                     Sysmon's, else ctx.dns's, else None
    fw_records fw_allowed fw_dropped endpoint_tags   the endpoint's, see attach_firewall
    geo         {scope, cc, country, lat, lon, asn, as_org}
    tags        what is suspicious about this process talking to this endpoint
    severity    the highest severity among tags ("info" when there are none)
    state       "allowed" | "blocked" | "pending"
    rule_id     the rule that blocks it, if state is "blocked"
    capture_ids [] here; the caller fills in the samples it has secured
    self        True for TDC's own processes (TDC_IMAGES)

Two things belong to the endpoint and not to the process: the numbers of the
firewall log (it has no image, and in practice no PID) and the ``dropped`` tag
that follows from them. They are in ``fw_*`` and ``endpoint_tags``, never in
``tags``.

``geo`` is always a dict. A public address that the offline table knows has its
country and AS, and a position moved by ``geoip.jitter`` when the country has a
centroid. Anything else has ``scope`` from ``geoip.scope_of`` and no data.

``state`` follows ``ctx.rules``, ``{key: rule_id}``, where a key is made by ``rule_key``:
a program, an endpoint, or both. The automatic block is program-scoped (this loader, this
address), so a rule for one image must not mark another process's flow to the same address.
``classify`` tries five levels, the most specific first, and the first hit is ``rule_id``:

    1. this image, this ip:port      2. this image, this ip      3. this image, any address
    4. any image, this ip:port       5. any image, this ip

A flow that no rule hits and that a key of ``ctx.pending`` (same keys, same levels) names is
"pending". The state is what the rules say, also for a TDC process: ``self`` only tells the UI
that it must not offer to block it.

The tags are the thirteen of the design plus ``tdc-anomaly`` (TDC's own python
talking to an endpoint it has no business with). ``TAGS`` maps each to its
severity and is ordered from the highest severity down.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

import geoip
import memory_evidence

SEVERITIES = ("info", "low", "medium", "high", "critical")

TAGS = {
    "ioc": "critical",
    "beacon": "critical",
    "sigma": "high",
    "detonated": "high",
    "direct-ip": "high",
    "download": "high",
    "tdc-anomaly": "high",
    "lolbin": "medium",
    "dga": "medium",
    "risky-tld": "medium",
    "dead-drop": "medium",
    "rare-port": "medium",
    "newborn": "low",
    "dropped": "info",
}

# Living-off-the-land binaries that have no business talking to the network on a
# user's behalf; matched on the file name, lower case.
LOLBINS = frozenset({
    "certutil.exe", "bitsadmin.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe", "curl.exe",
    "wscript.exe", "cscript.exe", "powershell.exe", "pwsh.exe", "wmic.exe", "msiexec.exe",
    "installutil.exe", "msbuild.exe", "regasm.exe", "regsvcs.exe", "cmstp.exe", "odbcconf.exe",
    "hh.exe", "ftp.exe",
})

# Paste, chat and file-drop services that C2 and droppers use as a mailbox.
# A name matches itself and every subdomain of it.
DEAD_DROPS = frozenset({
    "telegram.org", "t.me", "pastebin.com", "paste.ee", "hastebin.com", "discord.com", "discordapp.com",
    "discordapp.net", "raw.githubusercontent.com", "gist.githubusercontent.com", "transfer.sh",
    "anonfiles.com", "file.io", "mega.nz", "dl.dropboxusercontent.com",
})

RISKY_TLDS = frozenset({"onion", "bit", "top", "xyz", "tk", "ml", "ga", "cf"})

# Anything else is "rare". 8080 and 8443 are left out on purpose: that is where
# stage-2 servers like to sit.
COMMON_PORTS = frozenset({21, 22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 853, 993, 995})
SUSPICIOUS_PORTS = frozenset({4444, 5555, 6666, 8888, 9999, 31337})

# TDC's own programs, matched case-insensitively: these exact paths (the python of the web UI,
# of the Detonator and of LitterBox, see scripts/configure-services.ps1), anything below one of
# the install roots (a trailing backslash: the root itself is not a program), and git.exe by name.
# Git's own folder is a root too, because ``git fetch`` does its network work in git-remote-https.exe.
# Matching by path and by name can be abused: a file named git.exe in %TEMP% counts as TDC's, and so
# does anything a sample drops into one of these folders. ``tdc-anomaly`` is the net under this: a TDC
# image that reaches an endpoint outside TDC_ENDPOINTS (and the caller's fetch targets) is flagged
# high whatever the image really is.
TDC_IMAGES = (
    "c:\\detonationchamberui\\venv\\scripts\\python.exe",
    "c:\\detonator\\.venv\\scripts\\python.exe",
    "c:\\litterbox\\venv\\scripts\\python.exe",
)
TDC_ROOTS = (
    "c:\\detonationchamberui\\",
    "c:\\detonator\\",
    "c:\\detonatoragent\\",
    "c:\\litterbox\\",
    "c:\\tools\\rustinel\\",
    "c:\\program files\\fibratus\\",
    "c:\\program files\\git\\",
)
TDC_BASENAMES = frozenset({"git.exe"})

# What TDC's python may reach besides loopback and the endpoints a Context lists as
# fetch targets: tool updates, package managers and ``git fetch``. A name matches
# itself and every subdomain of it.
TDC_ENDPOINTS = frozenset({
    "api.github.com", "github.com", "raw.githubusercontent.com", "objects.githubusercontent.com",
    "release-assets.githubusercontent.com", "download.sysinternals.com",
    "chocolatey.org", "community.chocolatey.org", "packages.chocolatey.org",
    "cdn.winget.microsoft.com", "winget.azureedge.net",
})

DGA_ENTROPY = 3.5          # Shannon bits per character of the registered name
DGA_MIN_LEN = 12           # shorter names carry too little to judge
DGA_DIGIT_RATIO = 0.3      # or this share of digits
NEWBORN_S = 60             # a process younger than this when it connects

MAX_TIMES = 200            # single connection times kept per flow
DNS_MAX_ENTRIES = 20000
TOP_N = 5

_PROTOCOLS = {"6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6"}
_SECOND_LEVEL = frozenset({"co", "com", "org", "net", "gov", "edu", "ac"})
_ALERT_IP_KEYS = ("destination.ip", "destination.address", "network.destination.ip", "network.destination.address")
_ALERT_PORT_KEYS = ("destination.port", "network.destination.port")
_FRACTION = re.compile(r"\.(\d+)")
_MAX_ANCESTORS = 32


@dataclass
class Context:
    """What the assessment knows besides the connections themselves.

    dns              IP -> name, as ``dns_map`` builds it
    alerts           Rustinel/Fibratus alerts; the network ones carry ``raw.destination.*``
    submission_pids  PIDs that are submissions in a detonation window
    ioc_ips          IPs of the IOC list, normalised (``1.2.3.4``)
    ioc_domains      names of the IOC list, lower case, without a trailing dot
    processes        PID -> {"start": epoch, "image", "parent_pid"} from Sysmon EID 1
    rules            {rule_key(...): rule_id} of the TDC firewall rules that stand (see the module docstring)
    pending          rule_key(...) keys that have an open decision
    downloads        {(pid, dst_ip, dst_port)} of connections for which a URL to an executable was seen
    fetch_targets    IPs and names TDC's own fetcher was sent to; not an anomaly for ``tdc-anomaly``
    geo_lookup       ``ip -> GeoInfo | None``
    """

    dns: Dict[str, str] = field(default_factory=dict)
    alerts: List[Dict[str, Any]] = field(default_factory=list)
    submission_pids: Set[int] = field(default_factory=set)
    ioc_ips: Set[str] = field(default_factory=set)
    ioc_domains: Set[str] = field(default_factory=set)
    processes: Dict[int, Dict[str, Any]] = field(default_factory=dict)
    rules: Dict[str, str] = field(default_factory=dict)
    pending: Set[str] = field(default_factory=set)
    downloads: Set[Tuple[Optional[int], str, Optional[int]]] = field(default_factory=set)
    fetch_targets: Set[str] = field(default_factory=set)
    geo_lookup: Callable[[str], Any] = field(default_factory=lambda: geoip.lookup)


# ---- normalising what Sysmon and the firewall log write ---------------------------------------


def _sysmon_str(value: Any) -> str:
    """A Sysmon string value; Sysmon's "-" placeholder and blanks mean absent (empty string)."""
    text = "" if value is None else str(value).strip()
    return "" if text == "-" else text


def _int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if value.is_integer() else None
    try:
        return int(_sysmon_str(value))
    except ValueError:
        return None


def _norm_ip(text: str) -> Optional[str]:
    """The canonical form of an address (an IPv4-mapped IPv6 address as its IPv4), or None."""
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return str(addr)


def _ip(value: Any) -> str:
    text = _sysmon_str(value)
    return _norm_ip(text) or text


def _proto(value: Any) -> str:
    text = _sysmon_str(value).lower()
    return _PROTOCOLS.get(text, text)


def _host(value: Any) -> str:
    """A name in lower case without its trailing dot; "" when there is none."""
    return _sysmon_str(value).lower().rstrip(".")


def _fold(value: Any) -> str:
    return str(value).strip().lower()


def _epoch(value: Any) -> Optional[float]:
    """Epoch seconds of an ISO timestamp (with offset or ``Z``; no offset means local time), or None."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = _FRACTION.sub(lambda m: "." + (m.group(1) + "000000")[:6], value.strip().replace("Z", "+00:00"), count=1)
    try:
        return datetime.fromisoformat(text).timestamp()
    except (ValueError, OverflowError, OSError):
        return None


def _is_event(ev: Any, eid: int) -> bool:
    return isinstance(ev, dict) and _int(ev.get("event_id")) == eid and not ev.get("error")


def endpoint_key(ip: str, port: Optional[int]) -> str:
    """An endpoint as text: ``1.2.3.4:443``, ``[2001:db8::1]:443``, or the IP alone when there is no port."""
    if port is None:
        return ip
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def rule_key(image: str, ip: str, port: Optional[int]) -> str:
    """The key of a rule in ``Context.rules`` and ``Context.pending``: ``<image>|<endpoint>``, image in lower case.

    An empty ``image`` means every process, an empty ``ip`` every address (the port then does not count).
    ``rule_key(loader, "1.2.3.4", 443)`` is the automatic block, ``rule_key("", "1.2.3.4", None)`` the
    endpoint blocked for everyone.
    """
    return f"{image.lower()}|{endpoint_key(ip, port) if ip else ''}"


def _rule_keys(image: str, ip: str, port: Optional[int]) -> List[str]:
    """The keys a flow can be hit by, most specific first; levels that would name nothing are left out."""
    keys = []
    if image and ip:
        keys += [rule_key(image, ip, port), rule_key(image, ip, None)]
    if image:
        keys.append(rule_key(image, "", None))
    if ip:
        keys += [rule_key("", ip, port), rule_key("", ip, None)]
    return [_fold(k) for k in keys]


# ---- bundling --------------------------------------------------------------------------------


def flow_key(ev: Dict[str, Any]) -> Tuple[str, Optional[int], str, str, str, Optional[int]]:
    """``(image, pid, protocol, src_ip, dst_ip, dst_port)`` of a Sysmon connection event, normalised."""
    return (_sysmon_str(ev.get("image")), _int(ev.get("pid")), _proto(ev.get("protocol")),
            _ip(ev.get("src_ip")), _ip(ev.get("dst_ip")), _int(ev.get("dst_port")))


def bundle(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Merge Sysmon EID 3 events into flows, oldest first; events of other kinds or without a time are skipped."""
    timed = []
    for ev in events:
        if not _is_event(ev, 3):
            continue
        epoch = _epoch(ev.get("timestamp"))
        if epoch is not None:
            timed.append((epoch, ev))
    timed.sort(key=lambda pair: pair[0])
    flows: Dict[Tuple, Dict[str, Any]] = {}
    for epoch, ev in timed:
        key = flow_key(ev)
        flow = flows.get(key)
        if flow is None:
            image, pid, protocol, src_ip, dst_ip, dst_port = key
            flow = flows[key] = {"image": image, "pid": pid, "protocol": protocol, "src_ip": src_ip,
                                 "dst_ip": dst_ip, "dst_port": dst_port, "count": 0, "first_seen": epoch,
                                 "last_seen": epoch, "times": [], "dst_hostname": None}
        flow["count"] += 1
        flow["last_seen"] = epoch
        flow["times"].append(epoch)
        if flow["dst_hostname"] is None:
            flow["dst_hostname"] = _host(ev.get("dst_hostname")) or None
    for flow in flows.values():
        del flow["times"][:-MAX_TIMES]
    return list(flows.values())


def dns_map(events: List[Dict[str, Any]], ttl_s: Optional[float] = None,
            limit: int = DNS_MAX_ENTRIES) -> Dict[str, str]:
    """IP -> queried name from Sysmon EID 22 events; the newest answer for an address wins.

    A name, once seen, explains its address for as long as the caller holds the flow: forgetting it
    would turn every older flow into a hardcoded target (``direct-ip``). Memory is bounded by ``limit``
    (the most recently answered addresses are kept) and by the store's ring. A caller that wants an
    expiry passes ``ttl_s``: answers older than that, measured against the newest answer, are dropped.
    """
    answers = []
    for ev in events:
        if not _is_event(ev, 22):
            continue
        epoch, name = _epoch(ev.get("timestamp")), _host(ev.get("query"))
        if epoch is None or not name:
            continue
        for part in _sysmon_str(ev.get("result")).split(";"):
            ip = _norm_ip(part.strip())          # a CNAME answer reads "type:  5 name" and is no address
            if ip:
                answers.append((epoch, ip, name))
    answers.sort(key=lambda a: a[0])
    if ttl_s is not None and answers:
        oldest = answers[-1][0] - ttl_s
        answers = [a for a in answers if a[0] >= oldest]
    out: Dict[str, str] = {}
    for _, ip, name in answers:
        out.pop(ip, None)
        out[ip] = name
    if len(out) > limit:
        out = dict(list(out.items())[-limit:])
    return out


def attach_firewall(flows: List[Dict[str, Any]], fw_events: List[Dict[str, Any]]) -> None:
    """Write ``fw_records``, ``fw_allowed``, ``fw_dropped`` and ``endpoint_tags`` onto the flows.

    The firewall log has no image and no usable PID, so the join is the four-tuple
    ``(protocol, src_ip, dst_ip, dst_port)`` and the numbers belong to the endpoint:
    two processes talking to the same endpoint carry the same figures. ``fw_records``
    counts every record, ``fw_allowed`` the ALLOW ones, ``fw_dropped`` the DROP ones.
    """
    counts: Dict[Tuple, List[int]] = {}
    for ev in fw_events:
        fields = ev.get("fields") if isinstance(ev, dict) and isinstance(ev.get("fields"), dict) else ev
        if not isinstance(fields, dict):
            continue
        key = (_proto(fields.get("protocol")), _ip(fields.get("src_ip")), _ip(fields.get("dst_ip")),
               _int(fields.get("dst_port")))
        action = _sysmon_str(fields.get("action")).upper()
        seen = counts.setdefault(key, [0, 0, 0])
        seen[0] += 1
        seen[1] += action == "ALLOW"
        seen[2] += action == "DROP"
    for flow in flows:
        records, allowed, dropped = counts.get(
            (flow["protocol"], flow["src_ip"], flow["dst_ip"], flow["dst_port"]), (0, 0, 0))
        flow["fw_records"], flow["fw_allowed"], flow["fw_dropped"] = records, allowed, dropped
        flow["endpoint_tags"] = ["dropped"] if dropped else []


# ---- names -----------------------------------------------------------------------------------


def entropy(text: str) -> float:
    """Shannon entropy of ``text`` in bits per character; 0.0 for the empty string."""
    if not text:
        return 0.0
    total = len(text)
    return -sum(n / total * math.log2(n / total) for n in Counter(text).values())


def _host_chain(host: str) -> List[str]:
    """The name and its parent domains down to two labels: a.b.evil.example -> itself, b.evil.example, evil.example."""
    labels = host.split(".")
    return [".".join(labels[i:]) for i in range(max(1, len(labels) - 1))] if host else []


def _registered_label(host: str) -> str:
    """The label that was bought: ``kqj3x`` in ``www.kqj3x.top`` and in ``kqj3x.co.uk``."""
    labels = host.split(".")
    if len(labels) == 1:
        return labels[0]
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL:
        return labels[-3]
    return labels[-2]


def is_dga(name: str) -> bool:
    """Whether the registered label of ``name`` looks machine-made: long, and random or full of digits.

    Only the label that was bought counts; subdomains of big hosters are random by design.
    """
    host = _host(name) if isinstance(name, str) else ""
    if not host or _norm_ip(host):
        return False
    label = _registered_label(host)
    if len(label) < DGA_MIN_LEN:
        return False
    digits = sum(c.isdigit() for c in label)
    return entropy(label) >= DGA_ENTROPY or digits / len(label) >= DGA_DIGIT_RATIO


# ---- tags ------------------------------------------------------------------------------------


def severity_of(tags: Iterable[str]) -> str:
    """The highest severity among ``tags`` (unknown tags count for nothing); "info" for none."""
    return SEVERITIES[max((SEVERITIES.index(TAGS[t]) for t in tags if t in TAGS), default=0)]


def _nested(data: Any, dotted: str) -> Any:
    """``data[dotted]`` if the key is flat, else walked through nested dicts; None when absent."""
    if not isinstance(data, dict):
        return None
    if dotted in data:
        return data[dotted]
    current: Any = data
    for part in dotted.split("."):
        current = current.get(part) if isinstance(current, dict) else None
    return current


def _alert_endpoints(alerts: List[Dict[str, Any]]) -> Set[Tuple[str, Optional[int]]]:
    """The ``(ip, port)`` endpoints that alerts name in ``raw.destination.*``; the port is None when it is not named."""
    out: Set[Tuple[str, Optional[int]]] = set()
    for alert in alerts:
        raw = alert.get("raw") if isinstance(alert, dict) else None
        ip = next((_ip(v) for v in (_nested(raw, k) for k in _ALERT_IP_KEYS) if _sysmon_str(v)), "")
        if ip:
            port = next((_int(v) for v in (_nested(raw, k) for k in _ALERT_PORT_KEYS) if _int(v) is not None), None)
            out.add((ip, port))
    return out


def _is_tdc_image(image: str) -> bool:
    path = image.replace("/", "\\").lower()
    return (path in TDC_IMAGES or path.startswith(TDC_ROOTS)
            or path.rsplit("\\", 1)[-1] in TDC_BASENAMES)


def _is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def _is_detonated(pid: Optional[int], ctx: Context) -> bool:
    """Whether ``pid`` or one of its ancestors is a submission."""
    seen = set()
    while pid is not None and pid not in seen and len(seen) < _MAX_ANCESTORS:
        if pid in ctx.submission_pids:
            return True
        seen.add(pid)
        pid = _int((ctx.processes.get(pid) or {}).get("parent_pid"))
    return False


def _is_newborn(flow: Dict[str, Any], ctx: Context) -> bool:
    start = (ctx.processes.get(flow["pid"]) or {}).get("start")
    if isinstance(start, bool) or not isinstance(start, (int, float)):
        return False
    return 0 <= flow["first_seen"] - start < NEWBORN_S


def _is_beaconing(flow: Dict[str, Any]) -> bool:
    connections = [(t, flow["dst_ip"], flow["dst_port"]) for t in flow["times"]]
    return bool(memory_evidence.beaconing_from_connections(connections, process=flow["image"]))


def _tdc_expects(flow: Dict[str, Any], host: str, ctx: Context) -> bool:
    return (_is_loopback(flow["dst_ip"]) or flow["dst_ip"] in ctx.fetch_targets
            or any(h in TDC_ENDPOINTS or h in ctx.fetch_targets for h in _host_chain(host)))


def _tag_flow(flow: Dict[str, Any], ctx: Context, alert_endpoints: Set[Tuple[str, Optional[int]]],
              is_tdc: bool) -> List[str]:
    """What is suspicious about this process talking to this endpoint, most severe first.

    Only tags of the flow itself: ``dropped`` belongs to the endpoint (``attach_firewall``).
    """
    ip, port, image = flow["dst_ip"], flow["dst_port"], flow["image"]
    host = flow.get("dst_hostname") or ctx.dns.get(ip) or ""
    chain = _host_chain(host)
    scope = geoip.scope_of(ip)
    found = set()
    if ip in ctx.ioc_ips or any(h in ctx.ioc_domains for h in chain):
        found.add("ioc")
    if _is_beaconing(flow):
        found.add("beacon")
    if (ip, port) in alert_endpoints or (ip, None) in alert_endpoints:
        found.add("sigma")
    if _is_detonated(flow["pid"], ctx):
        found.add("detonated")
    # A hardcoded target is an address that no name explains. Sysmon fills DestinationHostname from the
    # local DNS cache, so a populated field is evidence that a name was involved, even when the answer
    # predates the ring or fell outside the map. A C2 with a usable cache entry escapes this tag, but it is
    # high severity and the false positive is the common case; ioc, beacon, rare-port, risky-tld and
    # dead-drop still catch such a C2.
    if scope == "public" and ip not in ctx.dns and not flow.get("dst_hostname"):
        found.add("direct-ip")
    if (flow["pid"], ip, port) in ctx.downloads:
        found.add("download")
    if is_tdc and not _tdc_expects(flow, host, ctx):
        found.add("tdc-anomaly")
    if image.replace("/", "\\").rsplit("\\", 1)[-1].lower() in LOLBINS:
        found.add("lolbin")
    if is_dga(host):
        found.add("dga")
    if "." in host and host.rsplit(".", 1)[-1] in RISKY_TLDS:
        found.add("risky-tld")
    if any(h in DEAD_DROPS for h in chain):
        found.add("dead-drop")
    if port is not None and (port in SUSPICIOUS_PORTS or (scope == "public" and port not in COMMON_PORTS)):
        found.add("rare-port")
    if _is_newborn(flow, ctx):
        found.add("newborn")
    return [tag for tag in TAGS if tag in found]


# ---- the whole pipeline ----------------------------------------------------------------------


def _geo(ip: str, ctx: Context) -> Dict[str, Any]:
    found = ctx.geo_lookup(ip) if ip else None
    if found is None:
        return {"scope": geoip.scope_of(ip), "cc": None, "country": None, "lat": None, "lon": None,
                "asn": None, "as_org": None}
    lat = lon = None
    if found.lat is not None and found.lon is not None:
        lat, lon = geoip.jitter(ip, found.lat, found.lon)
    return {"scope": "public", "cc": found.cc, "country": found.country, "lat": lat, "lon": lon,
            "asn": found.asn, "as_org": found.as_org}


def classify(events: List[Dict[str, Any]], fw_events: List[Dict[str, Any]], ctx: Context) -> List[Dict[str, Any]]:
    """Bundle the connections, join the firewall log, and tag and place every flow (see the module docstring)."""
    flows = bundle(events)
    attach_firewall(flows, fw_events)
    alert_endpoints = _alert_endpoints(ctx.alerts)
    rules = {_fold(k): v for k, v in ctx.rules.items()}
    pending = {_fold(k) for k in ctx.pending}
    for flow in flows:
        ip = flow["dst_ip"]
        if not flow["dst_hostname"]:
            flow["dst_hostname"] = ctx.dns.get(ip) or None
        flow["geo"] = _geo(ip, ctx)
        is_tdc = _is_tdc_image(flow["image"])
        flow["tags"] = _tag_flow(flow, ctx, alert_endpoints, is_tdc)
        flow["severity"] = severity_of(flow["tags"])
        keys = _rule_keys(flow["image"], ip, flow["dst_port"])
        rule_id = next((rules[k] for k in keys if k in rules), None)
        flow["rule_id"] = rule_id
        flow["state"] = "blocked" if rule_id is not None else "pending" if pending & set(keys) else "allowed"
        flow["capture_ids"] = []
        flow["self"] = is_tdc
    return flows


# ---- summary ---------------------------------------------------------------------------------


def _top(flows: List[Dict[str, Any]], group: Callable[[Dict[str, Any]], Optional[Tuple]],
         label: Callable[[Tuple, Dict[str, Any]], Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The ``TOP_N`` groups with the most connections; ``group`` returns None for a flow that belongs to none."""
    totals: Dict[Tuple, List[Any]] = {}
    for flow in flows:
        key = group(flow)
        if key is None:
            continue
        entry = totals.setdefault(key, [0, 0, flow])
        entry[0] += 1
        entry[1] += flow["count"]
    ranked = sorted(totals.items(), key=lambda item: (-item[1][1], -item[1][0], str(item[0])))
    return [dict(label(key, first), flows=n_flows, count=count) for key, (n_flows, count, first) in ranked[:TOP_N]]


def summarize(flows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Totals and tops of classified flows.

    ``connections`` is the number of flows, ``events`` the single connections in them (the sum of
    ``count``). ``captures`` is the number of different secured samples. No byte counts: Sysmon has none.
    """
    return {
        "connections": len(flows),
        "events": sum(f["count"] for f in flows),
        "blocked": sum(f["state"] == "blocked" for f in flows),
        "pending": sum(f["state"] == "pending" for f in flows),
        "captures": len({c for f in flows for c in f["capture_ids"]}),
        "top_processes": _top(flows, lambda f: (f["image"],), lambda k, f: {"image": k[0]}),
        "top_endpoints": _top(flows, lambda f: (f["dst_ip"], f["dst_port"]),
                              lambda k, f: {"dst_ip": k[0], "dst_port": k[1], "dst_hostname": f["dst_hostname"]}),
        "top_countries": _top(flows, lambda f: (f["geo"]["cc"],) if f["geo"]["cc"] else None,
                              lambda k, f: {"cc": k[0], "country": f["geo"]["country"]}),
    }
