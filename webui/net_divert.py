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
is all it has there. The shared address has to be reachable by whoever passes it: this class does not add it to the
adapter (``start`` adds nothing, a test pins that). The default is the address just before the walk begins.

``ValueError`` from ``ops`` is not a refusal. It means the call itself was wrong (``FakeSystemOps`` and
``WindowsSystemOps`` refuse the same things), and a wrong call must not be turned into a session that quietly serves
everything from one address. Only ``SystemOpsError`` is: that is what the operating system saying no looks like.
"""

from __future__ import annotations

import ipaddress
import threading
from typing import Any, Dict, List, Optional

from net_system import SystemOpsError

SHARED_FALLBACK_REASON = "address pool refused"

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
    ``shared`` is the address that a name gets when its own could not be added (see the module).

    Thread safety: the DNS server and the others ask from their own threads. Adding is serialised, so that two
    threads asking for one name get one address and one ``add_address``. Asking for a name that is already known
    takes no lock and no call."""

    def __init__(self, ops, index, prefix=DEFAULT_PREFIX, shared=None):
        ipaddress.IPv4Address(prefix + ".1.1")          # a prefix that is not two octets is the caller's bug
        self.ops = ops
        self.index = index
        self.prefix = prefix
        self.shared = shared if shared is not None else prefix + ".0.1"
        self._by_name: Dict[str, str] = {}
        self._by_address: Dict[str, str] = {}
        self._shared_names: List[str] = []
        self._shared_set = set()
        self._shared_reason: Optional[str] = None
        self._added: List[str] = []             # on the adapter by us, in the order they went there
        self._remove_failed: Dict[str, str] = {}
        self._next = 0                          # position in the walk; moves only when an address was taken
        self._started = False
        self._stopped = False
        self._lock = threading.Lock()

    # -- the map --

    def address_for(self, name):
        key = _key(name)
        known = self._by_name.get(key)
        if known is not None:
            return known
        if key in self._shared_set:
            return self.shared
        with self._lock:
            known = self._by_name.get(key)          # another thread may have been first
            if known is not None:
                return known
            if key in self._shared_set:
                return self.shared
            if self._stopped:
                raise RuntimeError("the diverter is stopped: no address is handed out any more")
            address = self._walk_address()
            if address is not None:
                try:
                    self.ops.add_address(self.index, address, MASK)
                except SystemOpsError:
                    address = None
            if address is None:
                self._shared_names.append(key)
                self._shared_set.add(key)
                self._shared_reason = SHARED_FALLBACK_REASON
                return self.shared
            self._added.append(address)
            self._next += 1
            self._by_address[address] = key
            self._by_name[key] = address            # last: a reader that finds the name finds the address too
            return address

    def name_for(self, address):
        return self._by_address.get(address)

    def _walk_address(self) -> Optional[str]:
        """The address at the current position of the walk: 254 per third octet (.1 to .254), third octets 1 to 255.
        None when the /16 is used up, which is a refusal like any other."""
        third, fourth = divmod(self._next, 254)
        if third >= 255:
            return None
        return "%s.%d.%d" % (self.prefix, third + 1, fourth + 1)

    # -- the session --

    def start(self):
        # Nothing is added here: an address is added when a name asks for it (see the module).
        self._started = True

    def stop(self):
        """Remove every address that was added, newest first, and try all of them whatever one of them does. What
        could not be removed is in ``state()["remove_failed"]`` and in the ``SystemOpsError`` this raises; a second
        ``stop`` tries those again and only those."""
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
            failed = dict(self._remove_failed)
        if failed:
            first = sorted(failed.items())[:5]
            raise SystemOpsError("could not remove %d of the fake internet's addresses from adapter %s: %s"
                                 % (len(failed), self.index, "; ".join("%s (%s)" % kv for kv in first)))

    def state(self):
        """What the report shows, as copies: ``names`` (name to its own address), ``shared`` (that address),
        ``shared_names`` (the names that had to live on it, in the order they asked) and ``shared_reason`` (why, or
        None), ``remove_failed`` (``[{"address", "error"}]``, empty unless ``stop`` could not take all away)."""
        with self._lock:
            return {"names": dict(self._by_name), "shared": self.shared, "shared_names": list(self._shared_names),
                    "shared_reason": self._shared_reason, "started": self._started, "stopped": self._stopped,
                    "remove_failed": [{"address": a, "error": e} for a, e in sorted(self._remove_failed.items())]}
