"""The certificate authority of one detonation, and a certificate per faked name.

The fake HTTPS server has to terminate TLS to read what the sample sends, and a sample's TLS stack only goes on to send
it when it accepts what the server presents. So a CA is made for the session, put into the machine's trusted roots for
as long as the session runs, and every faked name gets a certificate it signed. The CA's key exists in this process's
memory and nowhere else; it is never written to disk, so what a crash leaves behind is a certificate whose key is gone.

What the machine-wide store means. The store is the machine's, not the sample's: Windows' own clients (the connectivity
check, Windows Update, Defender, the time sync, the browser, TDC's update check) accept these certificates too while the
session lasts. That is handled where the session decides what may leave the machine; here it is the reason ``remove()``
has to happen and why a leftover is cleared at the next start.

Leftovers. ``SystemOps`` can install and remove a certificate by thumbprint but cannot list the store, so the CA of a
session that died could not be found again by anything but a note of its thumbprint. The note is a small JSON file
(``state_path``) written *before* the certificate goes into the store, so that no crash leaves a CA that nothing knows
about, and dropped when the certificate has been removed. ``install()`` clears what the note lists first. A removal
that fails is an error, not something to step over: installing a second CA on top of a first that could not be taken
out would leave two keys' worth of trust behind, and the note keeps the entry for the attempt after.

Cost. Generating a 2048-bit RSA key takes a noticeable moment (a few hundred milliseconds, more on a loaded VM) and
signing a certificate takes almost nothing. So both keys, the CA's and the one every leaf shares, are made when the
object is made, which is at the start of the session and not inside the first HTTPS handshake of the sample, whose
connect or handshake timeout is short and not ours. A leaf is therefore a signature over a name and a public key that
already exist. One leaf key for every name is safe here: the certificates are short-lived, the key never leaves the
process, and what it protects is traffic the analyst's own fake server decrypts anyway.

Names. A name arrives in the form the sample used: any case, a trailing dot, an IP literal, an IPv6 literal in
brackets. ``normalize_name`` brings those to one form, and the form is the cache key, so ``Example.COM.`` and
``example.com`` are one certificate, and an IP literal is an ``IPAddress`` SAN and never a ``DNSName`` (a client
matching an IP against a DNS SAN refuses the certificate).
"""

from __future__ import annotations

import datetime
import ipaddress
import json
import os
import re
import secrets
import threading
from collections import OrderedDict
from typing import Any, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from net_system import SystemOpsError, thumbprint_of

KEY_BITS = 2048
CA_VALIDITY = datetime.timedelta(days=1)
LEAF_VALIDITY = datetime.timedelta(hours=12)

# A clock that is a little behind ours (the guest's, after the time sync has moved it) would see a certificate that
# starts in the future. Both certificates start this long before they were made; a leaf never outlives the CA.
BACKDATE = datetime.timedelta(hours=1)

# A sample that resolves thousands of generated names must not grow this without end. A name evicted is signed again
# when it comes back, which costs a signature.
MAX_CERTS = 2048

_THUMBPRINT = re.compile(r"[0-9A-Fa-f]{40}")
_LABEL = re.compile(r"[a-z0-9_-]{1,63}")
_MAX_NAME = 253
_MAX_CN = 64              # an X.509 common name is at most 64 characters; the SAN is what clients read anyway
_FALLBACK_CN = "tdc-fake-host"


def normalize_name(name: Any) -> Tuple[str, bool]:
    """``(name, is_ip)`` in the one form a certificate is cached and issued under.

    An IP literal comes out as ``str(ipaddress.ip_address(...))`` (so two spellings of an IPv6 address are one name);
    a DNS name comes out lower-case, without a trailing dot and in its ASCII (punycode) form. Anything that cannot be
    one of those is a ``ValueError``: an empty name, a wildcard, spaces, a label over 63 characters."""
    if isinstance(name, (bytes, bytearray)):
        try:
            name = bytes(name).decode("ascii")
        except UnicodeDecodeError:
            raise ValueError("not a name") from None
    if not isinstance(name, str):
        raise ValueError(f"not a name: {str(name)[:40]!r}")
    text = name.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        return str(ipaddress.ip_address(text)), True
    except ValueError:
        pass
    if text.endswith("."):
        text = text[:-1]
    if not text.isascii():
        try:
            text = text.encode("idna").decode("ascii")
        except UnicodeError:
            raise ValueError(f"not a host name: {name[:40]!r}") from None
    text = text.lower()
    labels = text.split(".")
    if not text or len(text) > _MAX_NAME or not all(_LABEL.fullmatch(label) for label in labels):
        raise ValueError(f"not a host name: {name[:40]!r}")
    # "198.18.3.7." is not an IP literal and would pass as a DNS name made of digits; a certificate with that as a
    # DNSName is cached under the key of the IP and then served to a client that dials the IP, which refuses it. No
    # real name is all digits (a top-level domain never is), so a DNS SAN that reads like an address is never right.
    if all(label.isdigit() for label in labels):
        raise ValueError(f"not a host name or an IP address: {name[:40]!r}")
    return text, False


def _utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _pem_key(key: rsa.RSAPrivateKey) -> str:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                             serialization.NoEncryption()).decode("ascii")


def _default_state_path() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "session_ca.json")


class SessionCA:
    """A CA for one session, in the machine store between ``install()`` and ``remove()``.

    ``ops`` is a ``net_system.SystemOps``. ``state_path`` is where the thumbprint is noted while the CA is (or may be)
    in the store: by default ``session_ca.json`` beside this module (git-ignored). A test passes its own.

    ``pem`` is the CA certificate and ``thumbprint`` its SHA-1 as Windows shows it, both available at once.
    ``cert_for(name)`` is the certificate for one name as ``(cert_pem, key_pem)``, both text, issued by the first call
    and the same from every later one. All methods may be called from any thread.
    """

    def __init__(self, ops, state_path: Optional[str] = None):
        self._ops = ops
        self._state_path = state_path or _default_state_path()
        self._lock = threading.RLock()
        self._certs: "OrderedDict[str, Tuple[str, str]]" = OrderedDict()
        self._installed: Optional[str] = None       # the thumbprint ``install_ca`` answered, while it may be in the store
        self._noted = False

        self._ca_key = rsa.generate_private_key(public_exponent=65537, key_size=KEY_BITS)
        self._leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=KEY_BITS)
        self._leaf_key_pem = _pem_key(self._leaf_key)
        self._leaf_public = self._leaf_key.public_key()

        now = _utc_now()
        self._not_before = now - BACKDATE
        self._not_after = now + CA_VALIDITY
        name = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Detonation Chamber"),
            x509.NameAttribute(NameOID.COMMON_NAME, "TDC fake internet, session CA " + secrets.token_hex(4)),
        ])
        self._ca_name = name
        ca_public = self._ca_key.public_key()
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(ca_public)
            .serial_number(x509.random_serial_number())
            .not_valid_before(self._not_before).not_valid_after(self._not_after)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                         crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_public), critical=False)
            .sign(self._ca_key, hashes.SHA256())
        )
        self._ca_cert = certificate
        self.pem: str = certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
        self.thumbprint: str = thumbprint_of(self.pem)

    # -- certificates --

    def cert_for(self, name) -> Tuple[str, str]:
        """``(cert_pem, key_pem)`` for ``name``, signed by the session CA. The same name, in whatever spelling
        ``normalize_name`` folds into the same form, is signed once. ``ValueError`` for what is not a name."""
        key, is_ip = normalize_name(name)
        with self._lock:
            found = self._certs.get(key)
            if found is not None:
                self._certs.move_to_end(key)
                return found
            made = (self._sign(key, is_ip), self._leaf_key_pem)
            self._certs[key] = made
            while len(self._certs) > MAX_CERTS:
                self._certs.popitem(last=False)
            return made

    def _sign(self, name: str, is_ip: bool) -> str:
        san = x509.IPAddress(ipaddress.ip_address(name)) if is_ip else x509.DNSName(name)
        common = name if len(name) <= _MAX_CN else _FALLBACK_CN
        now = _utc_now()
        certificate = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common)]))
            .issuer_name(self._ca_name).public_key(self._leaf_public)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - BACKDATE).not_valid_after(min(now + LEAF_VALIDITY, self._not_after))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=True,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                         crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectAlternativeName([san]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(self._leaf_public), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self._ca_key.public_key()),
                           critical=False)
            .sign(self._ca_key, hashes.SHA256())
        )
        return certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")

    # -- the machine store --

    def install(self) -> str:
        """Clear what an earlier session left, then put this CA into the machine's trusted roots. Returns the
        thumbprint. Installing twice is one install. Raises ``SystemOpsError`` when the note of earlier sessions cannot
        be read or written, when a leftover cannot be removed (nothing is installed in any of these cases) or when the
        certificate cannot be added."""
        with self._lock:
            if self._installed is not None:
                return self._installed
            self._clear_leftovers()
            # Noted before it is in the store, not after: a crash between the two must not leave a CA nobody knows.
            self._note(add=self.thumbprint)
            try:
                installed = self._ops.install_ca(self.pem)
            except BaseException:
                self._take_back()
                raise
            if installed != self.thumbprint:
                self._take_back(installed)
                raise SystemOpsError(f"the store reports thumbprint {installed!r} for a certificate whose "
                                     f"thumbprint is {self.thumbprint}")
            self._installed = installed
            return installed

    def remove(self) -> bool:
        """Take the CA out of the machine store: ``remove_ca`` with the thumbprint that was installed. True when
        one was removed, False when there was nothing of ours to remove (never installed, already removed, or not
        in the store any more). A failure is raised and the note is kept, so that the next ``remove()`` and the next
        start try again."""
        with self._lock:
            if self._installed is None:
                if not self._noted:
                    return False
                # install() did not return - an exception or an interrupt inside it - and the store may or may not
                # hold the certificate: ask for it to go.
                thumbprint = self.thumbprint
            else:
                thumbprint = self._installed
            removed = self._ops.remove_ca(thumbprint)
            self._installed = None
            self._note(drop=self.thumbprint)
            return bool(removed)

    def _take_back(self, thumbprint: Optional[str] = None) -> None:
        # Best effort after a failed install: a timeout does not say whether certutil added the certificate.
        try:
            self._ops.remove_ca(thumbprint or self.thumbprint)
        except BaseException:
            return                          # the note stays, so the next start retries
        self._note(drop=self.thumbprint)

    def _clear_leftovers(self) -> None:
        for thumbprint in self._read_note():
            if thumbprint == self.thumbprint:
                continue
            self._ops.remove_ca(thumbprint)         # an absent one answers False; a failure propagates, note kept
            self._note(drop=thumbprint)

    # -- the note of what may be in the store --

    def _read_note(self) -> List[str]:
        """The thumbprints that may be in the store. No file is "none". A file that is there and cannot be read as
        a note is an error: it may be the note of a session that died, and reading it as empty would have the next
        write replace it, leaving a CA in the machine store that nothing names any more. A zero-length file is what
        a hard kill of the VM can leave behind, so that case is not rare."""
        try:
            with open(self._state_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (FileNotFoundError, NotADirectoryError):      # no file, or no directory it could be in
            return []
        except (OSError, ValueError) as e:
            raise self._unreadable(f"{type(e).__name__}: {e}") from e
        items = data.get("thumbprints") if isinstance(data, dict) else None
        if not isinstance(items, list) or not all(isinstance(t, str) and _THUMBPRINT.fullmatch(t) for t in items):
            raise self._unreadable("it is not a list of thumbprints")
        return [t.upper() for t in items]

    def _unreadable(self, why: str) -> SystemOpsError:
        return SystemOpsError(
            f"the note of the session CA ({self._state_path}) cannot be read: {why}. A CA of an earlier session may "
            f"still be in the machine's trusted roots: look for 'TDC fake internet, session CA' with "
            f"'certutil -store Root', delete it with 'certutil -delstore Root <thumbprint>', then delete the note. "
            f"Nothing was installed.")

    def _note(self, add: Optional[str] = None, drop: Optional[str] = None) -> None:
        current = self._read_note()
        wanted = [t for t in current if t != drop]
        if add and add not in wanted:
            wanted.append(add)
        if wanted != current or (add and not os.path.exists(self._state_path)):
            if wanted:
                try:
                    self._write_note(wanted)
                except OSError as e:
                    raise SystemOpsError(f"cannot write the note of the session CA ({self._state_path}): "
                                         f"{type(e).__name__}: {e}") from e
            else:
                try:
                    os.unlink(self._state_path)
                except OSError:
                    pass
        if add:
            self._noted = True
        if drop == self.thumbprint:
            self._noted = False

    def _write_note(self, thumbprints: List[str]) -> None:
        """Replace the note whole, and on disk before this returns: the note is written because a crash may follow
        at once, and after a hard kill NTFS can keep a rename without the data behind it."""
        directory = os.path.dirname(self._state_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        temporary = self._state_path + ".tmp"
        with open(temporary, "w", encoding="utf-8") as f:
            json.dump({"thumbprints": thumbprints}, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, self._state_path)
        if os.name != "nt":                 # a directory cannot be opened on Windows; there the rename is the journal's
            fd = os.open(directory or ".", os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
