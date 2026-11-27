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
"""

from __future__ import annotations

import ipaddress
import threading
from typing import Any, Dict, List, Optional

from net_system import SystemOpsError

SHARED_FALLBACK_REASON = "address pool refused"
UNADDRESSED_REASON = "no address could be added and the shared address is not on the adapter"
SHARED_ATTEMPTS = 3

DEFAULT_PREFIX = "198.18"
MASK = "255.255.0.0"        # what the measurement added the addresses with: the /16 of the prefix


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

    Thread safety: the DNS server and the others ask from their own threads. Adding is serialised, so that two
    threads asking for one name get one address and one ``add_address``. Asking for a name that is already known
    takes no lock and no call."""

    def __init__(self, ops, index, prefix=DEFAULT_PREFIX, shared=None):
        ipaddress.IPv4Address(prefix + ".1.1")          # a prefix that is not two octets is the caller's bug
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
        self._lock = threading.Lock()

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

    def start(self):
        # Nothing is added here: an address is added when a name asks for it (see the module).
        self._started = True

    def stop(self):
        """Remove every address that was added, newest first, and try all of them whatever one of them does. What
        could not be removed is in ``state()["remove_failed"]`` and in the ``SystemOpsError`` this raises; a second
        ``stop`` tries those again and only those. An address that was only *maybe* added is asked to go too, and
        that failing (it usually was never there) is not an error."""
        with self._lock:
            self._stopped = True
            for address in reversed(list(self._added)):
                try:
                    self.ops.remove_address(self.index, address)
                except Exception as e:
                    self._remove_failed[address] = str(e)[:300]
                else:
                    self._added.remove(address)
                    self._remove_failed.pop(address, None)
            for address in list(self._maybe):
                try:
                    self.ops.remove_address(self.index, address)
                except Exception:
                    pass
                self._maybe.remove(address)
            failed = dict(self._remove_failed)
        if failed:
            first = sorted(failed.items())[:5]
            raise SystemOpsError("could not remove %d of the fake internet's addresses from adapter %s: %s"
                                 % (len(failed), self.index, "; ".join("%s (%s)" % kv for kv in first)))

    def state(self):
        """What the report shows, as copies: ``names`` (name to its own address), ``shared`` (that address) and
        ``shared_on_adapter`` (whether it is there), ``shared_names`` (the names that had to live on it, in the order
        they asked) and ``shared_reason`` (why, or None), ``unaddressed_names`` (the names that have no address
        that leads anywhere) and ``unaddressed_reason``, ``maybe_added`` (addresses whose add failed and that
        ``stop`` has not yet tried to remove), ``remove_failed`` (``[{"address", "error"}]``, empty unless ``stop``
        could not take all away)."""
        with self._lock:
            return {"names": dict(self._by_name), "shared": self.shared, "shared_on_adapter": self._shared_ready,
                    "shared_names": list(self._shared_names), "shared_reason": self._shared_reason,
                    "unaddressed_names": list(self._unaddressed),
                    "unaddressed_reason": UNADDRESSED_REASON if self._unaddressed else None,
                    "maybe_added": list(self._maybe), "started": self._started, "stopped": self._stopped,
                    "remove_failed": [{"address": a, "error": e} for a, e in sorted(self._remove_failed.items())]}
