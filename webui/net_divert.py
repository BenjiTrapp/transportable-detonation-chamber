"""Which fake address stands for which name (the fake internet's addressing).

A sample that resolves ``c2.evil`` and connects to what it was told gets a server that has to know which name was
meant. TLS says it in the SNI and HTTP in the ``Host`` header, but a raw protocol says nothing, and a sample that
connects by IP says nothing either. The only thing every connection carries is the *destination address*, so every
faked name gets an address of its own and the server answers by looking the address up (``name_for``).

The addresses are the fake internet's own, ``198.18.0.0/15`` (RFC 2544, routable nowhere), on the real adapter. They
walk upward from ``<prefix>.1.1`` and skip ``.0`` and ``.255`` in the last octet.

**On demand, never in advance.** An address is added to the adapter when a name is looked up for the first time and
not before: adding one was measured at 108-151 ms and removing one at 135 ms (scripts/measure-secondary-addresses.ps1),
so a pool of five hundred made in advance would cost over a minute of the session at each end, for names that are
never asked for. **And the map is ours.** Reading the adapter's address list was measured at 20 ms with two addresses
and 713 ms with 701, so ``address_for`` and ``name_for`` answer from two dicts in memory and never ask ``ops`` once a
name is known.

**When the adapter refuses.** A name whose address could not be added is not an error of the session: it gets the
*shared* address, and the name is recorded in ``state()["shared_names"]`` with ``SHARED_FALLBACK_REASON``, so that the
report can say which names lost their own address. On the shared address several names live at once, so
``name_for(shared)`` names none of them and the server has to take the name from the SNI or the ``Host`` header, which
is all it has there.

**The shared address has to exist, or the fallback leads nowhere.** Two cases:

- ``shared`` was passed: it is an address the machine already has (the adapter's own), it is checked not to lie on the
  walk, and it is neither added nor removed here.
- ``shared`` was left out: it is ``<prefix>.0.1``, the address just before the walk, and *this class* puts it on the
  adapter, together with the first name's address. It cannot be added at ``start`` (nothing is added before a name
  asks) and it cannot wait for the first fallback, because a fallback happens *because* adding failed. So it is
  added once the first name has been dealt with, whether that name got its own address or not. If that fails it is
  tried again at the next fallback, at most ``SHARED_ATTEMPTS`` times in all, so that an adapter that refuses
  everything is not asked again for every name.

A name that has neither its own address nor a shared one on the adapter is **unaddressed**: ``address_for`` still
answers (``shared``, a value the DNS server can put in a reply), but the name is listed in
``state()["unaddressed_names"]``, because traffic to that address reaches no server and the session must not read as
if the redirection had worked.

**A failed add is not a free address.** The walk moves on past an address whose ``add_address`` raised: a leftover of a
crashed session can make one address fail again and again, and a walk that stayed on it would make every later name
pay a failing call of 100 ms or more and lose its own address. Such an address is also *maybe added* (a timeout says
nothing about what the adapter did), so ``stop`` tries to remove it and ignores that failing, as it usually does.

``ValueError`` from ``ops`` is not a refusal. It means the call itself was wrong (``FakeSystemOps`` and
``WindowsSystemOps`` refuse the same things), and a wrong call must not be turned into a session that quietly serves
everything from one address. Anything else ``ops`` raises is the operating system saying no, whatever it is called,
and must not escape into the caller's DNS thread.

**The session around the addresses** (``start`` and ``stop``). Adding an address to a DHCP adapter takes it off DHCP and
the leased address goes with it (measured, and it cost the test VM its network for over an hour), so ``start`` reads
the adapter's addressing and makes it static *with its real address* before anything is added, on purpose instead of by
accident, and ``stop`` hands the very dict it read back to ``restore_addressing``. In between the isolation rule
``TDC-NET-ISOLATE`` stands: one outbound Block rule, because in Windows Firewall a Block beats every Allow and "block
everything, allow a few" cannot be written as rules of both kinds. The few are therefore taken *out of the block*: it
blocks every remote address except ``198.18.0.0/15`` and loopback. It has **no port in it**: an outbound rule is
checked when the guest opens a connection, and the replies on connections the host opened to the web UI and WinRM
are not checked again, so nothing has to be let out for them, while an exemption by local port would let through
whatever a sample sends *from* 9000, 5985 or 5986 (nobody holds UDP 9000, and TCP 5986 usually has no listener).
What the rule cannot stop, and says so (``blocked_attempts``): a sample that connects to an address of its own
choosing is seen and refused, never answered.

Nothing is added before the adapter is static. A name asked for before ``start`` has made it so (the DNS server a
tick early, or racing ``start``) gets the shared address and is not remembered; ``add_address`` would take a DHCP
adapter off the network. A firewall profile that is switched off makes the rule bite nothing there, so ``start``
refuses when the adapter's own profile is off, or every profile is, and ``state()["isolation"]["effective"]`` says
which it was.

``stop`` is a chain in which every step is tried whatever an earlier one did: the addresses, the rule, the addressing.
The first error surfaces once all have been tried, and all of them are in ``state()["stop_errors"]``. That includes
``KeyboardInterrupt`` and ``SystemExit``: removing 700 addresses takes about a minute, and being killed in that
minute is the case this chain is for. A step that
succeeded is not done again by a second ``stop``; one that failed is. The addresses step ends with a **sweep**: the
adapter's address list is read once and every address of this prefix that is on it is removed, whether this session
added it or not (every ``skip_as_source`` address of ``198.18.0.0/15``: a session with another prefix is covered, the
adapter's own address is never). An ``add_address`` that timed out and worked anyway, or a session that crashed,
leaves addresses that nothing else would ever take away. The read costs 713 ms at 701 addresses, which is affordable once at the
end and not in a loop, which is why the map stays in memory during the session.
"""

from __future__ import annotations

import ipaddress
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from net_system import FAKE_INTERNET, SystemOpsError

SHARED_FALLBACK_REASON = "address pool refused"
UNADDRESSED_REASON = "no address could be added and the shared address is not on the adapter"
SHARED_ATTEMPTS = 3

DEFAULT_PREFIX = "198.18"
MASK = "255.255.0.0"        # what the measurement added the addresses with: the /16 of the prefix

ISOLATION_RULE = "TDC-NET-ISOLATE"
FIREWALL_PROFILES = frozenset(("Domain", "Private", "Public"))
DEFAULT_DNS = "127.0.0.1"           # where the DNS server is; the loopback is not filtered, so no rule has to let it out
MAX_BLOCKED = 500                   # distinct attempts kept; a sample that tries every address must not grow the list


def _count(value: Any) -> Optional[int]:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _complement(allowed: List[Any], version: int) -> List[str]:
    """The ``a-b`` ranges of every address of ``version`` that lies in none of the ``allowed`` networks."""
    top = (1 << (32 if version == 4 else 128)) - 1
    make = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
    spans = sorted((int(n.network_address), int(n.broadcast_address)) for n in allowed if n.version == version)
    out, cursor = [], 0
    for low, high in spans:
        if low > cursor:
            out.append((cursor, low - 1))
        cursor = max(cursor, high + 1)
    if cursor <= top:
        out.append((cursor, top))
    return ["%s-%s" % (make(low), make(high)) for low, high in out]


def isolation_spec() -> Dict[str, Any]:
    """The firewall spec of the isolation rule (see the module): outbound Block of every remote address outside the
    fake internet and loopback, and nothing else. IPv6 is in it too: a sample that finds an AAAA or an ``[::]``
    literal must not walk around an IPv4-only rule. ``::`` is an allowed span of its own only so that no range of the
    rule starts at it; ``::1`` is left out of the block as 127.0.0.0/8 is."""
    allowed = [FAKE_INTERNET, ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::/128"),
               ipaddress.ip_network("::1/128")]
    return {"direction": "out", "action": "block",
            "remote_address": _complement(allowed, 4) + _complement(allowed, 6)}


class Diverter:
    """Protocol of whatever points a sample's traffic at the fake servers.

    ``address_for(name)`` is the address the name's DNS answer carries, and the same one every time. ``name_for(address)``
    is the name a connection to that address was meant for, or None. ``start`` and ``stop`` bracket a session;
    ``state()`` is what the report shows."""

    def address_for(self, name):
        raise NotImplementedError

    def name_for(self, address):
        raise NotImplementedError

    def start(self):
        raise NotImplementedError

    def stop(self):
        raise NotImplementedError

    def state(self):
        raise NotImplementedError


def _key(name: Any) -> str:
    """A DNS name is the same name in any case and with or without its root dot: two spellings must not take two
    addresses, and a lookup that does not find the first spelling would answer wrongly."""
    if not isinstance(name, str):
        raise ValueError(f"not a name: {str(name)[:40]!r}")
    key = name.strip().rstrip(".").lower()
    if not key:
        raise ValueError(f"not a name: {name[:40]!r}")
    return key


class GuestDiverter(Diverter):
    """The diverter that runs inside the guest and puts the addresses on the guest's own adapter ``index``.

    ``ops`` is a ``net_system.SystemOps``. ``prefix`` is the first two octets of the /16 the addresses come from.
    ``shared`` is the address that a name gets when its own could not be added; left out, it is ``<prefix>.0.1`` and
    this class adds it (see the module). One passed in must be an IPv4 address that is not on the walk.
    ``dns_address`` is where the guest's DNS is pointed (the DNS server of Task 6 listens there).

    Thread safety: the DNS server and the others ask from their own threads. Adding is serialised, so that two
    threads asking for one name get one address and one ``add_address``. Asking for a name that is already known
    takes no lock and no call."""

    def __init__(self, ops, index, prefix=DEFAULT_PREFIX, shared=None, dns_address=DEFAULT_DNS):
        ipaddress.IPv4Address(prefix + ".1.1")          # a prefix that is not two octets is the caller's bug
        ipaddress.IPv4Address(dns_address)
        self.dns_address = dns_address
        self.ops = ops
        self.index = index
        self.prefix = prefix
        self._own_shared = shared is None               # we put it on the adapter, and take it off again
        if shared is None:
            shared = prefix + ".0.1"
        else:
            self._check_shared(shared, prefix)
        self.shared = shared
        self._shared_ready = not self._own_shared       # on the adapter: given, or added by us
        self._shared_attempts = 0
        self._by_name: Dict[str, str] = {}
        self._by_address: Dict[str, str] = {}
        self._shared_names: List[str] = []
        self._shared_set = set()
        self._shared_reason: Optional[str] = None
        self._unaddressed: List[str] = []
        self._unaddressed_set = set()
        self._added: List[str] = []             # on the adapter by us, in the order they went there
        self._maybe: List[str] = []             # add_address raised: perhaps there, perhaps not
        self._remove_failed: Dict[str, str] = {}
        self._next = 0                          # position in the walk; moves on every attempt, failed or not
        self._started = False
        self._stopped = False
        self._addressable = False                       # the adapter is static: only then is an address added
        self._lock = threading.Lock()
        self._saved: Optional[Dict[str, Any]] = None    # the addressing as read, set just before it is first changed
        self._rule_touched = False                      # the isolation rule may exist
        self._rule_written = False
        self._profiles_off: List[str] = []
        self._effective: Optional[bool] = None
        self._rules_at_start: Optional[int] = None
        self._rules_at_stop: Optional[int] = None
        self._addresses_done = False                    # the steps of stop that went through, so a second stop
        self._rule_done = False                         # does what failed and nothing else
        self._restore_done = False
        self._stop_errors: List[str] = []
        self._blocked: List[Dict[str, Any]] = []
        self._blocked_index: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
        self._blocked_overflow = 0
        self._blocked_lock = threading.Lock()

    @staticmethod
    def _check_shared(shared: Any, prefix: str) -> None:
        try:
            if not isinstance(shared, str):
                raise ValueError
            address = ipaddress.IPv4Address(shared)
        except ValueError:
            raise ValueError(f"the shared address is not an IPv4 address: {str(shared)[:40]!r}") from None
        if address in ipaddress.IPv4Network(prefix + ".0.0/16") and address.packed[2] >= 1:
            raise ValueError(f"the shared address {shared} lies on the walk of {prefix}.x.x: a name would be given "
                             f"the address that the shared one is")

    # -- the map --

    def address_for(self, name):
        key = _key(name)
        known = self._by_name.get(key)
        if known is not None:
            return known
        if key in self._shared_set or key in self._unaddressed_set:
            return self.shared
        with self._lock:
            known = self._by_name.get(key)          # another thread may have been first
            if known is not None:
                return known
            if key in self._shared_set or key in self._unaddressed_set:
                return self.shared
            if self._stopped:
                raise RuntimeError("the diverter is stopped: no address is handed out any more")
            if not self._addressable:
                # Not remembered, and no add_address: on a DHCP adapter that call takes the adapter off the network.
                return self.shared
            address = self._walk_address()
            if address is not None:
                self._next += 1
                if self._add(address):
                    self._by_address[address] = key
                    self._by_name[key] = address        # last: a reader that finds the name finds the address too
                    if not self._shared_ready:
                        self._establish_shared()
                    return address
            if not self._shared_ready:
                self._establish_shared()
            if self._shared_ready:
                self._shared_names.append(key)
                self._shared_set.add(key)
                self._shared_reason = SHARED_FALLBACK_REASON
            else:
                self._unaddressed.append(key)
                self._unaddressed_set.add(key)
            return self.shared

    def name_for(self, address):
        try:
            return self._by_address.get(address)
        except TypeError:                           # not hashable, so not an address
            return None

    def _walk_address(self) -> Optional[str]:
        """The address at the current position of the walk: 254 per third octet (.1 to .254), third octets 1 to 255.
        None when the /16 is used up, which is a refusal like any other."""
        third, fourth = divmod(self._next, 254)
        if third >= 255:
            return None
        return "%s.%d.%d" % (self.prefix, third + 1, fourth + 1)

    def _add(self, address: str) -> bool:
        """Put ``address`` on the adapter. False when the machine said no: it is then *maybe* there."""
        try:
            self.ops.add_address(self.index, address, MASK)
        except ValueError:
            raise
        except Exception:
            self._maybe.append(address)
            return False
        self._added.append(address)
        return True

    def _establish_shared(self) -> None:
        if self._shared_attempts >= SHARED_ATTEMPTS:
            return
        self._shared_attempts += 1
        if self._add(self.shared):
            self._shared_ready = True
            self._maybe = [a for a in self._maybe if a != self.shared]

    # -- the session --

    def _ours(self, entry: Any) -> bool:
        """An entry of the adapter's address list that this module may remove as a leftover: ``skip_as_source`` and
        inside the fake internet. The first condition is what keeps the adapter's own address out of it, which can
        itself lie in that range (a fake-IP VPN uses it); a ``shared`` that was passed in is never touched."""
        try:
            if not entry.get("skip_as_source"):
                return False
            address = ipaddress.IPv4Address(entry.get("address"))
        except (AttributeError, ValueError):
            return False
        return address in FAKE_INTERNET and (self._own_shared or str(address) != self.shared)

    def start(self):
        """Take the machine's addressing for the session, in this order: what an earlier session left (the rule and
        the addresses), the adapter read, the adapter made static with its real address, the isolation rule, DNS.
        The adapter is read once for both the leftovers and what ``stop`` gives back. A start that fails takes back
        what it did and raises what went wrong. Starting twice is starting once; a stopped diverter does not start."""
        if self._stopped:
            raise RuntimeError("the diverter is stopped and cannot be started again")
        if self._started:
            return
        self._started = True
        try:
            self._begin()
        except BaseException:
            try:
                self.stop()
            except BaseException:
                pass                    # it is in state()["stop_errors"]; what surfaces is what made start fail
            raise

    def _begin(self) -> None:
        self._rule_touched = True
        self._rules_at_start = _count(self.ops.remove_firewall_rules(ISOLATION_RULE))
        current = self.ops.read_addressing(self.index)
        # Before anything of the adapter is changed: its own address may lie in the fake internet's range, and then
        # no address of that range can be told apart from it by what we add or remove.
        inside = [e["address"] for e in current["addresses"]
                  if not e.get("skip_as_source") and ipaddress.IPv4Address(e["address"]) in FAKE_INTERNET]
        if inside:
            raise SystemOpsError("adapter %s has its own address %s inside %s, the range of the fake internet: "
                                 "it cannot be told apart from what is added" % (self.index, inside[0], FAKE_INTERNET))
        for entry in current["addresses"]:
            if self._ours(entry):
                try:
                    self.ops.remove_address(self.index, entry["address"])
                except Exception as e:      # stop tries it again and says so if it still stays
                    self._remove_failed[entry["address"]] = str(e)[:300]
        state = dict(current, addresses=[e for e in current["addresses"] if not self._ours(e)])
        primary = next((e for e in state["addresses"] if not e.get("skip_as_source")), None)
        if primary is None:
            raise SystemOpsError("adapter %s has no address of its own to keep: it cannot be made static" % self.index)
        self._saved = state             # from here on the adapter may be changed, and stop gives this back
        self.ops.set_static(self.index, primary["address"], primary["mask"], state.get("gateway"), None)
        with self._lock:
            self._addressable = True    # the adapter is static with its real address: adding is safe from here on
        off = list(self.ops.add_firewall_rule(ISOLATION_RULE, isolation_spec()) or [])
        self._profiles_off = off
        self._rule_written = True
        self._effective = self._bites(off)
        if not self._effective:
            raise SystemOpsError("the firewall is switched off for %s: the isolation rule would bite nothing, and the "
                                 "sample would run on the real network"
                                 % ("every profile" if FIREWALL_PROFILES <= set(off) else "the adapter's profile"))
        self.ops.set_dns(self.index, [self.dns_address])

    def _bites(self, off: List[str]) -> bool:
        """Whether the rule that was written does anything on this adapter: not when the profile the adapter is on is
        switched off, nor when all are. If the adapter's profile cannot be told, any profile off counts."""
        if not off:
            return True
        if FIREWALL_PROFILES <= set(off):
            return False
        profile = self.ops.network_profile(self.index)
        return not off if profile is None else profile not in off

    def stop(self):
        """Take everything back: the addresses (what was added, then whatever of this prefix is still on the
        adapter), the isolation rule, the addressing. Every step is tried whatever an earlier one did; the first
        error is raised when all have been tried, and all of them are in ``state()["stop_errors"]``. A second
        ``stop`` repeats only the steps that failed."""
        errors: List[BaseException] = []

        def attempt(step):
            try:
                step()
            except BaseException as e:      # an interrupt must not skip the steps after it; it is raised at the end
                errors.append(e)

        with self._lock:
            self._stopped = True
            attempt(self._remove_addresses)
        attempt(self._remove_rule)
        attempt(self._restore)
        self._stop_errors = [str(e)[:500] for e in errors]
        if errors:
            raise errors[0]

    def _remove_one(self, address: str) -> Optional[BaseException]:
        """None when ``address`` is gone, else what went wrong. An interrupt is returned like any other error: the
        addresses that are left have to be tried whatever arrives while removing one."""
        try:
            self.ops.remove_address(self.index, address)
        except BaseException as e:
            return e
        return None

    def _remove_addresses(self) -> None:
        """Newest first, all of them whatever one does. An address that was only *maybe* added is asked to go too,
        and that failing (it usually was never there) is not an error. Then the sweep: see the module."""
        if self._addresses_done:
            return
        tried = set()
        interrupt: Optional[BaseException] = None
        for address in reversed(list(self._added)):
            tried.add(address)
            failure = self._remove_one(address)
            if failure is None:
                self._added.remove(address)
                self._remove_failed.pop(address, None)
                continue
            self._remove_failed[address] = str(failure)[:300]
            if not isinstance(failure, Exception):
                interrupt = interrupt or failure
        for address in list(self._maybe):
            failure = self._remove_one(address)
            if failure is not None and not isinstance(failure, Exception):
                interrupt = interrupt or failure
            self._maybe.remove(address)
        unread = None
        try:
            on_adapter = list(self.ops.read_addressing(self.index).get("addresses") or [])
        except BaseException as e:
            if not isinstance(e, Exception):
                interrupt = interrupt or e
            unread = str(e)[:300]
            on_adapter = []
        for entry in on_adapter:
            if entry.get("address") in tried or not self._ours(entry):
                continue
            failure = self._remove_one(entry["address"])
            if failure is None:
                self._remove_failed.pop(entry["address"], None)
                continue
            self._remove_failed[entry["address"]] = str(failure)[:300]
            if not isinstance(failure, Exception):
                interrupt = interrupt or failure
        if interrupt is not None:
            raise interrupt
        problems = []
        if self._remove_failed:
            first = sorted(self._remove_failed.items())[:5]
            problems.append("could not remove %d of the fake internet's addresses from adapter %s: %s"
                            % (len(self._remove_failed), self.index, "; ".join("%s (%s)" % kv for kv in first)))
        if unread is not None:
            problems.append("could not read adapter %s to look for addresses that were left: %s" % (self.index, unread))
        if problems:
            raise SystemOpsError("; ".join(problems))
        self._addresses_done = True

    def _remove_rule(self) -> None:
        if not self._rule_touched or self._rule_done:
            return
        self._rules_at_stop = _count(self.ops.remove_firewall_rules(ISOLATION_RULE))
        self._rule_done = True

    def _restore(self) -> None:
        if self._saved is None or self._restore_done:
            return
        self.ops.restore_addressing(self.index, self._saved)
        self._restore_done = True

    # -- what was seen and not answered --

    def note_blocked(self, dest, port, pid=None, process=None, at=None):
        """Record a connection that the isolation refused and nothing answered: a sample that went to an address of
        its own choosing, with no DNS and no proxy. It is not silent: it is an indicator, and the report shows it.
        The same (address, port, process) again is one entry whose ``count`` grows; ``MAX_BLOCKED`` distinct ones are
        kept and the rest are counted in ``state()["blocked_overflow"]``."""
        try:
            if not isinstance(dest, str):
                raise ValueError
            dest = str(ipaddress.ip_address(dest.strip()))
        except ValueError:
            raise ValueError("not an IP address: %r" % (str(dest)[:40],)) from None
        if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
            raise ValueError("not a port: %r" % (str(port)[:20],))
        at = time.time() if at is None else at
        key = (dest, port, pid, process)
        with self._blocked_lock:
            entry = self._blocked_index.get(key)
            if entry is not None:
                entry["count"] += 1
                entry["last"] = at
            elif len(self._blocked) >= MAX_BLOCKED:
                self._blocked_overflow += 1
            else:
                entry = {"dest": key[0], "port": port, "pid": pid, "process": process, "answered": False,
                         "count": 1, "first": at, "last": at}
                self._blocked.append(entry)
                self._blocked_index[key] = entry

    def blocked_attempts(self):
        """What was seen and not answered, in the order it was first seen, as copies."""
        with self._blocked_lock:
            return [dict(b) for b in self._blocked]

    def state(self):
        """What the report shows, as copies: ``names`` (name to its own address), ``shared`` (that address) and
        ``shared_on_adapter`` (whether it is there), ``shared_names`` (the names that had to live on it, in the order
        they asked) and ``shared_reason`` (why, or None), ``unaddressed_names`` (the names that have no address
        that leads anywhere) and ``unaddressed_reason``, ``maybe_added`` (addresses whose add failed and that
        ``stop`` has not yet tried to remove), ``remove_failed`` (``[{"address", "error"}]``, empty unless ``stop``
        could not take all away), ``isolation`` (``rule``, whether it was ``written``, the firewall
        ``profiles_off`` and whether the rule is ``effective`` on the adapter, ``found_at_start`` rules of an
        earlier session that did not clean up, ``found_at_stop`` rules that were still there and ``lost``: True when
        none was, the sign that something removed it during the detonation, None while it is not known), ``stop_errors``
        (the errors of the last ``stop``), ``blocked`` (distinct attempts) and ``blocked_overflow``."""
        with self._blocked_lock:
            blocked, overflow = len(self._blocked), self._blocked_overflow
        with self._lock:
            lost = None
            if self._rule_written and self._rules_at_stop is not None:
                lost = self._rules_at_stop == 0
            return {"isolation": {"rule": ISOLATION_RULE, "written": self._rule_written,
                                  "profiles_off": list(self._profiles_off), "effective": self._effective,
                                  "found_at_start": self._rules_at_start, "found_at_stop": self._rules_at_stop,
                                  "lost": lost},
                    "stop_errors": list(self._stop_errors), "blocked": blocked, "blocked_overflow": overflow,
                    "dns_address": self.dns_address,
                    "names": dict(self._by_name), "shared": self.shared, "shared_on_adapter": self._shared_ready,
                    "shared_names": list(self._shared_names), "shared_reason": self._shared_reason,
                    "unaddressed_names": list(self._unaddressed),
                    "unaddressed_reason": UNADDRESSED_REASON if self._unaddressed else None,
                    "maybe_added": list(self._maybe), "started": self._started, "stopped": self._stopped,
                    "remove_failed": [{"address": a, "error": e} for a, e in sorted(self._remove_failed.items())]}
