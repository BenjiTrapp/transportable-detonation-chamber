"""Network findings in the shared evidence model.

A capture says what a sample did on the wire; ``memory_evidence`` already turns
what scanners see in memory, in Sysmon's connection log and in named pipes into
one verdict. A second scoring for the network would give a second verdict about
the same sample, so this module turns network events and rule hits into
``memory_evidence.MemoryFinding`` objects and nothing else: the weights, the
baseline, corroboration and supersede live there. Several assumptions would make
the findings wrong:

  * An event and a rule hit are two findings. ``net.periodic_checkin`` fires on
    the very beacon event that is a check-in by itself, and the two would score
    one loop twice. A finding is one ``(kind, process, destination)``; a hit on
    a destination that already has its finding adds its rule id to it.
  * Every beacon is a full check-in. Four to five random contacts with one host
    are measured as periodic about one time in ten, and a poller is periodic
    too. Raising the minimum of four would barely help (five to seven random
    contacts pass about as often) and would lose every short beacon, so the
    weight decides instead: a rhythm can stand alone only when it is tight
    (``memory_evidence.beacon_is_tight``, the rule Sysmon beaconing uses) and
    has a process (see below); otherwise it weighs what a loose Sysmon beacon
    weighs and needs a second opinion, so many short rhythms in one capture
    cannot add up to a verdict. A rhythm of failed connections had no answer
    and is no check-in; repeated failures are ``dead_c2_retry`` from the
    ``retry`` event.
  * Data out is data received. In the isolated mode our own server took the
    upload and the login: that shows the attempt, not that a real C2 got
    anything, so those findings carry ``observation`` ``OBSERVATION_ISOLATED``.
    A check-in and a download are what the sample did either way.
  * A finding may copy what its event holds. An ``ftp`` or ``smtp`` event keeps
    its password as a ``net_mail_ftp.Secret``, which refuses JSON so that it
    cannot leak; a finding that copied it would break the verdict, and one that
    copied its text would leak it. A finding takes named plain fields of an
    event, and of a hit only the rule's name, id, techniques, family and
    severity and the destination and port of the events it names.
  * Everything a machine does is evidence. Connectivity checks, OCSP and the
    update service beacon and upload on every clean Windows box. Events whose
    destination is in the rule set's ``known_good`` give no finding, as they
    give no rule hit; a download or an upload is never hidden, because the
    name it claims is not evidence (``net_rules.ALWAYS_VISIBLE``, used here as
    it is: a sample that sends its harvest with ``Host: ocsp.digicert.com``
    must not vanish). Ordinary POSTs over 512 bytes to known hosts therefore
    stay findings, but they are marked ``known_good`` with the corroboration
    scope ``endpoint``: such a finding is corroborated only by a finding about
    the same endpoint, and vouches only for one. Every event of a capture is
    the sample's process, so without the scope any host-side finding (a
    reflective PE, 3.0) would turn the machine's OCSP POSTs into 4.0 of
    exfiltration, two unrelated facts counted as one. Without a process and
    without such a second signal an upload is 1.6; one host is CLEAN, two or
    more reach 3.2 and SUSPICIOUS by saturation, the price of not letting a
    claimed name hide data. The list is a required argument: without it an
    idle machine is MALICIOUS. A retry of a name the resolver asks for on its
    own (``wpad``, reverse lookups) is no dead C2.
  * A capture knows the process. It does not: an event without one is the
    sample's, ``process`` names it. That makes every periodic service and
    every telemetry POST on the machine look like the sample's own, so a
    ``c2_checkin`` or ``exfil_upload`` from an event without a ``pid`` needs a
    second, independent signal (a host-side tool on the same process) before
    it carries its full weight, however tight the rhythm. This is the honest
    position for a pcap; the next phase, which attributes connections to
    processes, can let an attributed finding stand alone again (an event with
    a ``pid`` already does). ``credential_in_transit``, ``payload_staging`` and
    ``dga_pattern`` still stand alone: a named-account login in clear text, an
    executable over plain HTTP and ten invented names failing in a minute are
    not what an idle machine does.
  * A rule can say more than the event. A hit on a beacon event is held to
    the same test as the event (measured, answered: "ein Check-in mit Antwort,
    nicht bloss ein Connect"), and a finding from a hit carries the addresses
    of the events it names, so it matches the Sysmon beacon it duplicates.
    Every finding on a name also carries what the capture's DNS answers gave
    for that name: an HTTP check-in is named by its Host header, Sysmon's by
    the address, and only the answers tie the two together.
"""

import ipaddress
import math
from collections.abc import Iterable, Mapping

import memory_evidence
import net_behavior
import net_rules

SOURCE = "network"
NETWORK_KINDS = memory_evidence.NETWORK_KINDS

# Share of an attempt that the isolated mode lets us see: an attempt counts
# less than a delivery. With a process (the next phase) one attempted upload
# (4.0 * 0.6) is still suspicious on its own; without one it needs a second
# signal first, like every check-in and upload of this phase.
OBSERVATION_ISOLATED = 0.6
PARTLY_OBSERVED = frozenset(("exfil_upload", "credential_in_transit"))

# Kinds that ordinary software produces too (a poller, a telemetry POST): with
# no process to tie them to the sample, they need a second, independent signal.
NEEDS_PROCESS = frozenset(("c2_checkin", "exfil_upload"))

EXECUTABLES = frozenset(("pe", "elf", "macho"))
FAILED_ONLY = frozenset(("conn_failed",))


def _number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return value if math.isfinite(value) else None


def _plain(value):
    """A JSON scalar, or None for anything else."""
    if value is None or isinstance(value, (str, bool)):
        return value
    return _number(value)


def _names(values):
    return [v for v in values if isinstance(v, str)] if isinstance(values, (list, tuple)) else []


def _dest_key(dest):
    if not isinstance(dest, str) or not dest:
        return ""
    try:
        return str(ipaddress.ip_address(dest))
    except ValueError:
        return dest.lower().rstrip(".")


def _housekeeping(dest):
    try:
        ipaddress.ip_address(dest)
        return False
    except ValueError:
        return net_behavior.is_housekeeping(dest)


class _Collector:
    """Findings by (kind, process, destination), in the order they were first seen."""

    def __init__(self, process, observed_fully, known_good):
        self.process = process if isinstance(process, str) else ""
        self.observed_fully = observed_fully
        self.known_good = known_good
        self.by_key = {}

    def scope(self, e):
        """Extra fields of a transfer to a known-good name (see the module docstring)."""
        if self.known_good and self.known_good.hides(e):
            return {"known_good": True,
                    "corroboration_scope": memory_evidence.CORROBORATION_SCOPE_ENDPOINT}
        return {}

    def owner(self, item):
        process = item.get("process")
        return process if isinstance(process, str) and process else self.process

    def get(self, kind, process, dest):
        return self.by_key.get((kind, process.lower(), _dest_key(dest)))

    def add(self, kind, process, dest, detail, weight=None, pid=None, **extra):
        observation = 1.0
        if kind in PARTLY_OBSERVED and not self.observed_fully:
            observation = OBSERVATION_ISOLATED
        extra.update(dest=dest, observation=observation, rules=extra.get("rules", []),
                     pid=pid)
        if kind in NEEDS_PROCESS and pid is None:
            extra["needs_corroboration"] = True
        finding = memory_evidence.MemoryFinding(
            SOURCE, kind, process, detail=detail, identity=(_dest_key(dest),),
            weight=weight, extra=extra)
        self.by_key[(kind, process.lower(), _dest_key(dest))] = finding
        return finding


def _pid(e):
    pid = e.get("pid")
    return pid if isinstance(pid, int) and not isinstance(pid, bool) else None


def _merge_pid(finding, e):
    """A finding stands alone only while every event behind it has a process."""
    if _pid(e) is None and finding["kind"] in NEEDS_PROCESS:
        finding["needs_corroboration"] = True
        finding["pid"] = None


# --- events ----------------------------------------------------------------------

def _checkin(e):
    """The measurement of a beacon event that is a check-in, or None.

    A check-in is measured (``interval`` above 0, as ``net.periodic_checkin``
    asks) and answered: a rhythm of failed connections is no check-in.
    """
    interval = _number(e.get("interval"))
    via = set(_names(e.get("via")))
    if interval is None or interval <= 0 or (via and via <= FAILED_ONLY):
        return None
    cov, on_rhythm = _number(e.get("cov")), _number(e.get("on_rhythm"))
    connections = _number(e.get("connections"))
    tight = (cov is not None and on_rhythm is not None and connections is not None
             and memory_evidence.beacon_is_tight(cov, on_rhythm, connections))
    return {"interval": interval, "via": via, "cov": cov, "on_rhythm": on_rhythm,
            "connections": connections, "tight": tight}


def _answered(e):
    """Did the event a check-in rule fired on get an answer?"""
    etype = e.get("type")
    if etype == "beacon":
        return _checkin(e) is not None
    if etype == "conn_failed":
        return False
    if etype == "http":
        return e.get("status") is not None
    return True


def _beacon(c, e, process):
    m = _checkin(e)
    if m is None:
        return
    dest = e.get("dest") or ""
    tight = m["tight"]
    weight = (memory_evidence.KINDS["c2_checkin"]["weight"] if tight else
              memory_evidence.KINDS["c2_beaconing"]["weight"] * memory_evidence.BEACON_LOOSE_FACTOR)
    weight = round(weight, 2)
    known = c.get("c2_checkin", process, dest)
    if known is not None:
        known["count"] += 1
        if weight <= known["base_weight"]:
            _merge_pid(known, e)
            return
    connections, cov, on_rhythm = m["connections"], m["cov"], m["on_rhythm"]
    detail = "%s check-ins to %s, every %.1fs" % (
        connections if connections is not None else "repeated", dest, m["interval"])
    if cov is not None and on_rhythm is not None:
        detail += " (%.0f%% of intervals on rhythm, robust CoV %.2f)" % (100 * on_rhythm, cov)
    finding = c.add("c2_checkin", process, dest, detail, weight=weight, pid=_pid(e),
                    addresses=_names(e.get("addresses")), interval_s=m["interval"],
                    jitter=_number(e.get("jitter")), cov=cov, on_rhythm=on_rhythm,
                    connections=connections, via=sorted(m["via"]),
                    needs_corroboration=not tight,
                    count=known["count"] if known is not None else 1)
    if known is not None:
        finding["rules"] = known["rules"]
        if known["pid"] is None:
            finding["needs_corroboration"] = True
            finding["pid"] = None


def _upload(c, e, process):
    dest = e.get("dest") or ""
    size = _number(e.get("size"))
    if size is None:
        size = _number(e.get("body_bytes")) or 0
    known = c.get("exfil_upload", process, dest)
    if known is not None:
        known["count"] += 1
        known["size"] += size
        known["detail"] = "%d uploads to %s, %d bytes" % (known["count"], dest, known["size"])
        _merge_pid(known, e)
        return
    c.add("exfil_upload", process, dest, "Upload to %s, %d bytes" % (dest, size), pid=_pid(e),
          size=size, sha256=_plain(e.get("sha256")), file_kind=_plain(e.get("kind")),
          method=_plain(e.get("method")), path=_plain(e.get("path")), count=1, **c.scope(e))


def _download(c, e, process):
    if e.get("kind") not in EXECUTABLES:
        return
    dest = e.get("dest") or ""
    known = c.get("payload_staging", process, dest)
    if known is not None:
        known["count"] += 1
        return
    c.add("payload_staging", process, dest,
          "%s file downloaded from %s" % (str(e["kind"]).upper(), dest), pid=_pid(e),
          sha256=_plain(e.get("sha256")), size=_plain(e.get("size")),
          file_kind=e["kind"], url=_plain(e.get("url")), count=1, **c.scope(e))


def _retry(c, e, process):
    dest = e.get("dest") or ""
    if not isinstance(dest, str) or not dest or _housekeeping(dest):
        return
    known = c.get("dead_c2_retry", process, dest)
    if known is not None:
        known["count"] += 1
        return
    attempts = _number(e.get("attempts"))
    c.add("dead_c2_retry", process, dest,
          "%s failed attempts to reach %s" % (attempts if attempts is not None else "Repeated",
                                              dest), pid=_pid(e),
          attempts=attempts, first_ts=_number(e.get("first_ts")),
          last_ts=_number(e.get("last_ts")), addresses=_names(e.get("addresses")), count=1)


def _fanout(c, e, process):
    kind = "dga_pattern" if e.get("nxdomain") else "fallback_rotation"
    dest = e.get("dest") or ""
    known = c.get(kind, process, dest)
    if known is not None:
        known["count"] += 1
        return
    hosts = _number(e.get("hosts"))
    if kind == "dga_pattern":
        detail = "%s names answered NXDOMAIN within %ss" % (hosts, _number(e.get("window_s")))
    else:
        detail = "%s requested from %s hosts" % (e.get("path"), hosts)
    c.add(kind, process, dest, detail, pid=_pid(e), hosts=hosts, path=_plain(e.get("path")),
          names=_names(e.get("dests")), count=1)


_EVENTS = {"beacon": _beacon, "upload": _upload, "download": _download,
           "retry": _retry, "fanout": _fanout}


def _hidden(e, known_good):
    # The rules' own exemption, so that the two cannot disagree: a transfer is
    # never hidden by the name it claims (see net_rules.ALWAYS_VISIBLE).
    if not known_good or e.get("type") in net_rules.ALWAYS_VISIBLE:
        return False
    if e.get("type") == "fanout":
        names = _names(e.get("dests"))
        return bool(names) and all(known_good.hides({"dest": n}) for n in names)
    return known_good.hides(e)


# --- rule hits ---------------------------------------------------------------------

def _resolve(events, ref):
    """The event a hit reference names, if ``events`` is the list it was evaluated on."""
    index = ref.get("index")
    if (not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < len(events)
            or not isinstance(events[index], dict)):
        return None
    e = events[index]
    if e.get("type") != ref.get("type") or (e.get("dest") or "") != (ref.get("dest") or ""):
        return None
    return e


def _from_hit(c, hit, events):
    kind = hit.get("kind")
    if not kind:
        return
    if kind not in NETWORK_KINDS:
        raise ValueError("rule %r names the evidence kind %r, which is not one of: %s"
                         % (hit.get("rule_id"), kind, ", ".join(NETWORK_KINDS)))
    process = c.owner(hit)
    rule_id = hit.get("rule_id") if isinstance(hit.get("rule_id"), str) else ""

    def credit(finding):
        if rule_id and rule_id not in finding["rules"]:
            finding["rules"].append(rule_id)

    per_dest = {}
    for ref in hit.get("events") or ():
        if not isinstance(ref, dict):
            continue
        e = _resolve(events, ref)
        if kind == "c2_checkin":
            # "Ein Check-in mit Antwort, nicht bloss ein Connect": a rule cannot
            # make a check-in of what the event path refused, and a reference
            # that cannot be looked up cannot show an answer.
            if ref.get("type") == "beacon":
                if e is None or _checkin(e) is None:
                    continue
                dest = e.get("dest") or ""
                if c.get(kind, process, dest) is None:
                    _beacon(c, e, process)
                credit(c.get(kind, process, dest))
                continue
            if ref.get("type") == "conn_failed" or (e is not None and not _answered(e)):
                continue
        dest = ref.get("dest") if isinstance(ref.get("dest"), str) else ""
        entry = per_dest.setdefault(_dest_key(dest), {
            "dest": dest, "port": _plain(ref.get("port")), "count": 0, "addresses": [],
            "pids": []})
        entry["count"] += 1
        entry["pids"].append(_pid(e) if e is not None else None)
        for address in (_names(e.get("addresses")) if e is not None else ()):
            if address not in entry["addresses"]:
                entry["addresses"].append(address)
    if not hit.get("events"):
        count = _number(hit.get("count"))
        per_dest[""] = {"dest": "", "port": None, "count": count if count is not None else 1,
                        "addresses": [], "pids": [None]}
    for entry in per_dest.values():
        known = c.get(kind, process, entry["dest"])
        if known is not None:
            credit(known)
            continue
        pids = entry["pids"]
        name = hit.get("name") if isinstance(hit.get("name"), str) else rule_id
        dest = entry["dest"]
        c.add(kind, process, dest, name + (" (%s)" % dest if dest else ""),
              pid=pids[0] if pids and None not in pids else None,
              port=entry["port"], count=entry["count"], addresses=entry["addresses"],
              rules=[rule_id] if rule_id else [], attack=_names(hit.get("attack")),
              family=_plain(hit.get("family")) or "", severity=_plain(hit.get("severity")) or "")


def findings_from(events, hits, process="", observed_fully=True, *, known_good):
    """``MemoryFinding`` objects for a capture's events and rule hits.

    ``events`` are network events (with the ``beacon``, ``retry`` and
    ``fanout`` events of ``net_behavior``), ``hits`` what
    ``net_rules.RuleSet.evaluate`` returned for exactly this list: a hit names
    its events by position, and a check-in hit whose beacon cannot be looked
    up in it is dropped. ``process`` is the sample's process, used where an
    event or hit names none. ``observed_fully`` is False in the isolated mode
    (see the module docstring).

    ``known_good`` has no default, because forgetting it is the worst mistake
    a caller can make here: an hour of an idle Windows machine scores
    MALICIOUS without it and CLEAN with it, and nothing else would say so.
    Pass the ``net_rules.RuleSet`` the hits came from (its ``known_good`` list
    is used, so the findings hide what the rules hide), a ``net_rules.KnownGood``
    or a list of names; ``()`` hides nothing, and is then a choice in plain
    sight. None is refused.

    A hit whose kind is not a network kind raises ``ValueError``: ``net_rules``
    refuses such a rule when it loads, so one here is a bug.
    """
    known_good = _known_good(known_good)
    events = list(events or ())
    c = _Collector(process, observed_fully, known_good)
    for e in events:
        if not isinstance(e, dict):
            continue
        handler = _EVENTS.get(e.get("type"))
        if handler is None or _hidden(e, known_good):
            continue
        handler(c, e, c.owner(e))
    for hit in hits or ():
        if isinstance(hit, dict):
            _from_hit(c, hit, events)
    answers = _answers(events)
    for finding in c.by_key.values():
        resolved = answers.get(_dest_key(finding.get("dest")))
        if resolved:
            addresses = list(finding.get("addresses") or [])
            finding["addresses"] = addresses + [a for a in resolved if a not in addresses]
    return list(c.by_key.values())


def _answers(events):
    """Name -> the addresses the capture's DNS answers gave for it.

    A check-in over HTTP names its host by the Host header and Sysmon by the
    address it connected to; without these the two findings of one loop share
    no endpoint and supersede cannot see that they are one.
    """
    table = {}
    for e in events:
        if not isinstance(e, dict) or e.get("type") != "dns":
            continue
        if e.get("query_type") not in (None, "A", "AAAA"):
            continue
        name = _dest_key(e.get("dest"))
        for answer in _names(e.get("answers")):
            try:
                address = str(ipaddress.ip_address(answer))
            except ValueError:
                continue
            known = table.setdefault(name, [])
            if address not in known:
                known.append(address)
    return table


def _known_good(value):
    if isinstance(value, net_rules.KnownGood):
        return value
    if isinstance(value, net_rules.RuleSet):
        return net_rules.KnownGood(value.lists.get(net_rules.KNOWN_GOOD, ()))
    if isinstance(value, Mapping):
        # RuleSet.lists is the easy mistake; iterating it would give list names.
        if net_rules.KNOWN_GOOD not in value:
            raise TypeError("known_good is a mapping without a %r list; pass the RuleSet "
                            "or its list" % net_rules.KNOWN_GOOD)
        value = value[net_rules.KNOWN_GOOD]
    if value is None or isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        raise TypeError("known_good must be the RuleSet, a KnownGood or a list of names "
                        "(pass () to hide nothing), not %r" % (value,))
    return net_rules.KnownGood(value)
