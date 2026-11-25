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
    weight decides instead: a rhythm stands alone only when it is tight
    (``memory_evidence.beacon_is_tight``, the rule Sysmon beaconing uses);
    otherwise it weighs what a loose Sysmon beacon weighs and needs a second
    opinion, so many short rhythms in one capture cannot add up to a verdict.
    A rhythm of failed connections had no answer and is no check-in; repeated
    failures are ``dead_c2_retry`` from the ``retry`` event.
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
    give no rule hit; an executable download is never hidden, because the name
    it came from is not evidence (``net_rules.ALWAYS_VISIBLE``). A retry of a
    name the resolver asks for on its own (``wpad``, reverse lookups) is no
    dead C2.
  * A capture knows the process. It does not: an event without one is the
    sample's, ``process`` names it.
"""

import ipaddress
import math

import memory_evidence
import net_behavior
import net_rules

SOURCE = "network"
NETWORK_KINDS = memory_evidence.NETWORK_KINDS

# Share of an attempt that the isolated mode lets us see. Low enough that an
# attempt counts less than a delivery, high enough that one attempted upload
# (4.0 * 0.6) is still suspicious on its own, as it should be.
OBSERVATION_ISOLATED = 0.6
PARTLY_OBSERVED = frozenset(("exfil_upload", "credential_in_transit"))

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

    def __init__(self, process, observed_fully):
        self.process = process if isinstance(process, str) else ""
        self.observed_fully = observed_fully
        self.by_key = {}

    def owner(self, item):
        process = item.get("process")
        return process if isinstance(process, str) and process else self.process

    def get(self, kind, process, dest):
        return self.by_key.get((kind, process.lower(), _dest_key(dest)))

    def add(self, kind, process, dest, detail, weight=None, **extra):
        observation = 1.0
        if kind in PARTLY_OBSERVED and not self.observed_fully:
            observation = OBSERVATION_ISOLATED
        extra.update(dest=dest, observation=observation, rules=extra.get("rules", []))
        finding = memory_evidence.MemoryFinding(
            SOURCE, kind, process, detail=detail, identity=(_dest_key(dest),),
            weight=weight, extra=extra)
        self.by_key[(kind, process.lower(), _dest_key(dest))] = finding
        return finding


# --- events ----------------------------------------------------------------------

def _beacon(c, e, process):
    interval = _number(e.get("interval"))
    via = set(_names(e.get("via")))
    if interval is None or interval <= 0 or (via and via <= FAILED_ONLY):
        return
    dest = e.get("dest") or ""
    cov, on_rhythm = _number(e.get("cov")), _number(e.get("on_rhythm"))
    connections = _number(e.get("connections"))
    tight = (cov is not None and on_rhythm is not None and connections is not None
             and memory_evidence.beacon_is_tight(cov, on_rhythm, connections))
    weight = (memory_evidence.KINDS["c2_checkin"]["weight"] if tight else
              memory_evidence.KINDS["c2_beaconing"]["weight"] * memory_evidence.BEACON_LOOSE_FACTOR)
    weight = round(weight, 2)
    known = c.get("c2_checkin", process, dest)
    if known is not None:
        known["count"] += 1
        if weight <= known["base_weight"]:
            return
    detail = "%s check-ins to %s, every %.1fs" % (
        connections if connections is not None else "repeated", dest, interval)
    if cov is not None and on_rhythm is not None:
        detail += " (%.0f%% of intervals on rhythm, robust CoV %.2f)" % (100 * on_rhythm, cov)
    finding = c.add("c2_checkin", process, dest, detail, weight=weight,
                    addresses=_names(e.get("addresses")), interval_s=interval,
                    jitter=_number(e.get("jitter")), cov=cov, on_rhythm=on_rhythm,
                    connections=connections, via=sorted(via), needs_corroboration=not tight,
                    count=known["count"] if known is not None else 1)
    if known is not None:
        finding["rules"] = known["rules"]


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
        return
    c.add("exfil_upload", process, dest, "Upload to %s, %d bytes" % (dest, size),
          size=size, sha256=_plain(e.get("sha256")), file_kind=_plain(e.get("kind")),
          method=_plain(e.get("method")), path=_plain(e.get("path")), count=1)


def _download(c, e, process):
    if e.get("kind") not in EXECUTABLES:
        return
    dest = e.get("dest") or ""
    known = c.get("payload_staging", process, dest)
    if known is not None:
        known["count"] += 1
        return
    c.add("payload_staging", process, dest,
          "%s file downloaded from %s" % (str(e["kind"]).upper(), dest),
          sha256=_plain(e.get("sha256")), size=_plain(e.get("size")),
          file_kind=e["kind"], url=_plain(e.get("url")), count=1)


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
                                              dest),
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
    c.add(kind, process, dest, detail, hosts=hosts, path=_plain(e.get("path")),
          names=_names(e.get("dests")), count=1)


_EVENTS = {"beacon": _beacon, "upload": _upload, "download": _download,
           "retry": _retry, "fanout": _fanout}


def _hidden(e, known_good):
    if not known_good or e.get("type") == "download":
        return False
    if e.get("type") == "fanout":
        names = _names(e.get("dests"))
        return bool(names) and all(known_good.hides({"dest": n}) for n in names)
    return known_good.hides(e)


# --- rule hits ---------------------------------------------------------------------

def _from_hit(c, hit):
    kind = hit.get("kind")
    if not kind:
        return
    if kind not in NETWORK_KINDS:
        raise ValueError("rule %r names the evidence kind %r, which is not one of: %s"
                         % (hit.get("rule_id"), kind, ", ".join(NETWORK_KINDS)))
    process = c.owner(hit)
    rule_id = hit.get("rule_id") if isinstance(hit.get("rule_id"), str) else ""
    per_dest = {}
    for ref in hit.get("events") or ():
        if isinstance(ref, dict):
            dest = ref.get("dest") if isinstance(ref.get("dest"), str) else ""
            entry = per_dest.setdefault(_dest_key(dest), [dest, _plain(ref.get("port")), 0])
            entry[2] += 1
    if not per_dest:
        count = _number(hit.get("count"))
        per_dest[""] = ["", None, count if count is not None else 1]
    for dest, port, count in per_dest.values():
        known = c.get(kind, process, dest)
        if known is not None:
            if rule_id and rule_id not in known["rules"]:
                known["rules"].append(rule_id)
            continue
        name = hit.get("name") if isinstance(hit.get("name"), str) else rule_id
        c.add(kind, process, dest, name + (" (%s)" % dest if dest else ""),
              port=port, count=count, rules=[rule_id] if rule_id else [],
              attack=_names(hit.get("attack")), family=_plain(hit.get("family")) or "",
              severity=_plain(hit.get("severity")) or "")


def findings_from(events, hits, process="", observed_fully=True, known_good=()):
    """``MemoryFinding`` objects for a capture's events and rule hits.

    ``events`` are network events (with the ``beacon``, ``retry`` and
    ``fanout`` events of ``net_behavior``), ``hits`` what
    ``net_rules.RuleSet.evaluate`` returned for them. ``process`` is the
    sample's process, used where an event or hit names none.
    ``observed_fully`` is False in the isolated mode (see the module
    docstring). ``known_good`` is the rule set's ``known_good`` list (or a
    ``net_rules.KnownGood``); an event whose destination it names gives no
    finding. A hit whose kind is not a network kind raises ``ValueError``:
    ``net_rules`` refuses such a rule when it loads, so one here is a bug.
    """
    if not isinstance(known_good, net_rules.KnownGood):
        known_good = net_rules.KnownGood(known_good or ())
    c = _Collector(process, observed_fully)
    for e in events or ():
        if not isinstance(e, dict):
            continue
        handler = _EVENTS.get(e.get("type"))
        if handler is None or _hidden(e, known_good):
            continue
        handler(c, e, c.owner(e))
    for hit in hits or ():
        if isinstance(hit, dict):
            _from_hit(c, hit)
    return list(c.by_key.values())
