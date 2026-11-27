"""The session CA (webui/net_ca.py): one CA per detonation, a certificate per faked name.

Everything runs against ``FakeSystemOps``, which refuses what Windows refuses (``install_ca`` a PEM that is not one,
``remove_ca`` a thumbprint that is malformed). What these tests do not show is certutil itself and the Windows
store; what they do show is that the certificates are ones a TLS client accepts (a real handshake in memory), that the
right thumbprint is asked to go, and that a CA left by an earlier session is not left.
"""

import datetime
import ipaddress
import json
import os
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

import net_ca
import net_system


@pytest.fixture
def state(tmp_path):
    return str(tmp_path / "session_ca.json")


@pytest.fixture(scope="module")
def shared_ca(tmp_path_factory):
    """One CA for the tests that only read certificates: generating two 2048-bit keys is the slow part."""
    return net_ca.SessionCA(net_system.FakeSystemOps(), state_path=str(tmp_path_factory.mktemp("ca") / "s.json"))


def _noted(path):
    with open(path) as f:
        return json.load(f)["thumbprints"]


def _parse(pem):
    return x509.load_pem_x509_certificate(pem.encode("ascii"))


def _san(cert):
    return cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value


def test_a_certificate_carries_the_name_asked_for_as_its_san(shared_ca):
    cert_pem, key_pem = shared_ca.cert_for("update.example.org")
    san = _san(_parse(cert_pem))
    assert san.get_values_for_type(x509.DNSName) == ["update.example.org"]
    assert san.get_values_for_type(x509.IPAddress) == []
    assert "PRIVATE KEY" in key_pem


def test_the_same_name_is_not_signed_twice(shared_ca):
    first = shared_ca.cert_for("signed-once.example.org")
    assert shared_ca.cert_for("signed-once.example.org") == first
    # a re-signed certificate has a new random serial, so equal text means it was not signed again
    assert _parse(first[0]).serial_number == _parse(shared_ca.cert_for("signed-once.example.org")[0]).serial_number


@pytest.mark.parametrize("spelling", ["Signed-Once.Example.ORG", "signed-once.example.org.", "SIGNED-ONCE.example.org."])
def test_a_name_in_another_spelling_is_the_same_name(shared_ca, spelling):
    assert shared_ca.cert_for(spelling) == shared_ca.cert_for("signed-once.example.org")
    assert _san(_parse(shared_ca.cert_for(spelling)[0])).get_values_for_type(x509.DNSName) == ["signed-once.example.org"]


def test_an_ip_literal_becomes_an_ip_san_not_a_dns_one(shared_ca):
    san = _san(_parse(shared_ca.cert_for("198.18.3.7")[0]))
    assert san.get_values_for_type(x509.IPAddress) == [ipaddress.ip_address("198.18.3.7")]
    assert san.get_values_for_type(x509.DNSName) == []


def test_an_ipv6_literal_is_one_certificate_however_it_is_spelled(shared_ca):
    first = shared_ca.cert_for("2001:DB8:0:0:0:0:0:1")
    assert shared_ca.cert_for("[2001:db8::1]") == first
    assert _san(_parse(first[0])).get_values_for_type(x509.IPAddress) == [ipaddress.ip_address("2001:db8::1")]


def test_remove_is_called_with_the_thumbprint_that_was_installed(state):
    ops = net_system.FakeSystemOps()
    ca = net_ca.SessionCA(ops, state_path=state)
    installed = ca.install()
    assert installed == ca.thumbprint == net_system.thumbprint_of(ca.pem)
    assert ca.remove() is True
    assert ops.calls == [("install_ca", ca.pem), ("remove_ca", installed)]
    assert ops.cas == {}


def test_install_removes_a_leftover_ca_of_an_earlier_session_first(state):
    ops = net_system.FakeSystemOps()
    earlier = net_ca.SessionCA(ops, state_path=state)
    earlier.install()                                   # and then the process dies: remove() never runs
    assert list(ops.cas) == [earlier.thumbprint]
    ops.calls.clear()

    now = net_ca.SessionCA(ops, state_path=state)
    now.install()

    assert ops.calls == [("remove_ca", earlier.thumbprint), ("install_ca", now.pem)]
    assert list(ops.cas) == [now.thumbprint]


def test_a_leftover_that_cannot_be_removed_stops_the_install(state):
    ops = net_system.FakeSystemOps()
    earlier = net_ca.SessionCA(ops, state_path=state)
    earlier.install()
    ops.fail["remove_ca"] = net_system.SystemOpsError("certutil -delstore failed (5): access denied")
    now = net_ca.SessionCA(ops, state_path=state)

    with pytest.raises(net_system.SystemOpsError, match="access denied"):
        now.install()

    assert [c[0] for c in ops.calls if c[0] == "install_ca"] == ["install_ca"]      # only the earlier one's
    assert list(ops.cas) == [earlier.thumbprint]
    assert _noted(state) == [earlier.thumbprint]            # still known, for the next try


def test_the_thumbprint_is_noted_before_the_certificate_is_in_the_store(state):
    seen = []

    class Watching(net_system.FakeSystemOps):
        def install_ca(self, pem):
            seen.append(_noted(state))
            return super().install_ca(pem)

    ca = net_ca.SessionCA(Watching(), state_path=state)
    ca.install()
    assert seen == [[ca.thumbprint]]


def test_a_removed_ca_is_no_longer_noted_and_the_next_start_has_nothing_to_clear(state):
    ops = net_system.FakeSystemOps()
    ca = net_ca.SessionCA(ops, state_path=state)
    ca.install()
    ca.remove()
    ops.calls.clear()

    net_ca.SessionCA(ops, state_path=state).install()

    assert [c[0] for c in ops.calls] == ["install_ca"]


def test_a_failed_remove_is_raised_and_kept_for_the_next_attempt(state):
    ops = net_system.FakeSystemOps()
    ca = net_ca.SessionCA(ops, state_path=state)
    ca.install()
    ops.fail["remove_ca"] = net_system.SystemOpsError("busy")
    with pytest.raises(net_system.SystemOpsError):
        ca.remove()
    del ops.fail["remove_ca"]

    assert ca.remove() is True
    assert ops.cas == {}


def test_remove_without_an_install_asks_for_nothing(state):
    ops = net_system.FakeSystemOps()
    assert net_ca.SessionCA(ops, state_path=state).remove() is False
    assert ops.calls == []


def test_a_failed_install_takes_the_certificate_back_and_forgets_it(state):
    ops = net_system.FakeSystemOps(fail={"install_ca": net_system.SystemOpsError("timed out")})
    ca = net_ca.SessionCA(ops, state_path=state)
    with pytest.raises(net_system.SystemOpsError, match="timed out"):
        ca.install()
    assert ("remove_ca", ca.thumbprint) in ops.calls
    assert not os.path.exists(state)
    ops.calls.clear()
    assert ca.remove() is False
    assert ops.calls == []


def test_remove_after_an_install_that_failed_and_could_not_be_taken_back_asks_again(state):
    """certutil timing out says nothing about whether it added the certificate, and when the attempt to take it back
    fails as well the note is all that is left of it."""
    ops = net_system.FakeSystemOps()
    ops.fail["install_ca"] = net_system.SystemOpsError("timed out")
    ops.fail["remove_ca"] = net_system.SystemOpsError("busy")
    ca = net_ca.SessionCA(ops, state_path=state)
    with pytest.raises(net_system.SystemOpsError, match="timed out"):
        ca.install()
    assert _noted(state) == [ca.thumbprint]

    ops.calls.clear()
    with pytest.raises(net_system.SystemOpsError, match="busy"):
        ca.remove()
    assert ops.calls == [("remove_ca", ca.thumbprint)]
    assert _noted(state) == [ca.thumbprint]

    del ops.fail["remove_ca"]
    ops.calls.clear()
    assert ca.remove() is False                      # nothing was in the store, which is not an error
    assert ops.calls == [("remove_ca", ca.thumbprint)]
    assert not os.path.exists(state)


def test_installing_twice_is_one_install(state):
    ops = net_system.FakeSystemOps()
    ca = net_ca.SessionCA(ops, state_path=state)
    assert ca.install() == ca.install()
    assert [c[0] for c in ops.calls] == ["install_ca"]


def test_the_ca_is_valid_for_a_day_and_a_leaf_for_twelve_hours(shared_ca):
    ca = _parse(shared_ca.pem)
    leaf = _parse(shared_ca.cert_for("lifetime.example.org")[0])
    now = datetime.datetime.now(datetime.timezone.utc)
    assert abs((ca.not_valid_after_utc - now) - datetime.timedelta(days=1)) < datetime.timedelta(minutes=2)
    assert abs((leaf.not_valid_after_utc - now) - datetime.timedelta(hours=12)) < datetime.timedelta(minutes=2)
    assert ca.not_valid_before_utc <= now and leaf.not_valid_before_utc <= now
    assert leaf.not_valid_after_utc <= ca.not_valid_after_utc
    assert ca.public_key().key_size == 2048


def test_a_leaf_is_signed_by_the_ca_and_is_not_a_ca(shared_ca):
    leaf = _parse(shared_ca.cert_for("signed.example.org")[0])
    leaf.verify_directly_issued_by(_parse(shared_ca.pem))
    assert leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    assert isinstance(leaf.signature_hash_algorithm, hashes.SHA256)


def _handshake(ca, server_name, cert_name=None):
    """A TLS client that trusts only ``ca.pem`` and checks ``server_name``, against a server that presents
    ``cert_for(cert_name or server_name)``; in memory. Returns the client's SSLObject once the handshake is done."""
    import os
    import tempfile
    cert_pem, key_pem = ca.cert_for(cert_name or server_name)
    with tempfile.TemporaryDirectory() as d:
        chain = os.path.join(d, "chain.pem")
        with open(chain, "w") as f:
            f.write(cert_pem + key_pem)
        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.load_cert_chain(chain)
    client_ctx = ssl.create_default_context(cadata=ca.pem)
    c_in, c_out, s_in, s_out = ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO()
    client = client_ctx.wrap_bio(c_in, c_out, server_hostname=server_name)
    server = server_ctx.wrap_bio(s_in, s_out, server_side=True)
    done = [False, False]
    for _ in range(20):
        for i, (side, rd, wr) in enumerate(((client, c_in, c_out), (server, s_in, s_out))):
            if done[i]:
                continue
            try:
                side.do_handshake()
                done[i] = True
            except ssl.SSLWantReadError:
                pass
            pending = wr.read()
            if pending:
                (s_in if i == 0 else c_in).write(pending)
        if all(done):
            return client
    raise AssertionError("handshake did not finish")


def test_a_client_that_trusts_the_ca_accepts_the_certificate_for_a_dns_name(shared_ca):
    assert _handshake(shared_ca, "tls.example.org").getpeercert()["subjectAltName"] == (("DNS", "tls.example.org"),)


def test_a_client_that_trusts_the_ca_accepts_the_certificate_for_an_ip_address(shared_ca):
    assert _handshake(shared_ca, "198.18.9.9").getpeercert()["subjectAltName"] == (("IP Address", "198.18.9.9"),)


def test_a_certificate_for_another_name_is_refused(shared_ca):
    with pytest.raises(ssl.SSLCertVerificationError):
        _handshake(shared_ca, "wanted.example.org", cert_name="other.example.org")


def test_another_sessions_ca_does_not_vouch_for_this_ones_certificates(shared_ca, state):
    """The signature is what is checked, not the issuer's name (a different CA has a different name, which would
    fail first and say nothing about the key)."""
    stranger = net_ca.SessionCA(net_system.FakeSystemOps(), state_path=state)
    cert = _parse(shared_ca.cert_for("x.example.org")[0])

    def verify_with(ca):
        ca_cert = _parse(ca.pem)
        ca_cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(),
                                    cert.signature_hash_algorithm)

    verify_with(shared_ca)
    with pytest.raises(InvalidSignature):
        verify_with(stranger)
    assert stranger.thumbprint != shared_ca.thumbprint


@pytest.mark.parametrize("bad", ["", " ", ".", "*.example.org", "a b.example.org", "a..b", "x" * 64 + ".org",
                                 "a/b", 5, None, b"\xff", "198.18.3.7.", "300.1.1.1", "1234", "1.2.3"])
def test_what_is_not_a_name_is_refused(shared_ca, bad):
    with pytest.raises(ValueError):
        shared_ca.cert_for(bad)


def test_an_internationalised_name_is_issued_under_its_ascii_form(shared_ca):
    san = _san(_parse(shared_ca.cert_for("bücher.example")[0]))
    assert san.get_values_for_type(x509.DNSName) == ["xn--bcher-kva.example"]


def test_a_name_longer_than_a_common_name_still_gets_a_certificate(shared_ca):
    name = ".".join(["a" * 60] * 3) + ".example"
    cert = _parse(shared_ca.cert_for(name)[0])
    assert _san(cert).get_values_for_type(x509.DNSName) == [name]


def test_a_flood_of_names_does_not_grow_the_cache_without_end(shared_ca, monkeypatch):
    monkeypatch.setattr(net_ca, "MAX_CERTS", 3)
    first = shared_ca.cert_for("flood0.example.org")
    for n in range(1, 5):
        shared_ca.cert_for(f"flood{n}.example.org")
    assert len(shared_ca._certs) <= 3
    assert shared_ca.cert_for("flood0.example.org") != first            # evicted, so signed anew


def test_concurrent_first_requests_for_one_name_get_one_certificate(shared_ca):
    results = []
    barrier = threading.Barrier(8)

    def ask():
        barrier.wait()
        results.append(shared_ca.cert_for("race.example.org"))

    threads = [threading.Thread(target=ask) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(results) == 8 and len(set(results)) == 1


def test_a_certificate_needs_no_new_key(shared_ca, monkeypatch):
    """The first HTTPS connection of a session must not wait for a 2048-bit key: both keys exist by then."""
    def no_key(*args, **kwargs):
        raise AssertionError("a key was generated")
    monkeypatch.setattr(net_ca.rsa, "generate_private_key", no_key)
    shared_ca.cert_for("first-connection.example.org")


def test_a_dotted_number_that_is_not_an_ip_does_not_get_a_certificate_a_client_dialling_the_ip_would_refuse(shared_ca):
    with pytest.raises(ValueError):
        shared_ca.cert_for("198.18.3.7.")
    san = _san(_parse(shared_ca.cert_for("198.18.3.7")[0]))
    assert san.get_values_for_type(x509.IPAddress) == [ipaddress.ip_address("198.18.3.7")]
    assert san.get_values_for_type(x509.DNSName) == []


EARLIER = "E5F9" + "0" * 36


@pytest.mark.parametrize("content", [
    "",                                                  # what a hard kill can leave of a rename
    '{"thumbprints": ["E5F9' + "0" * 20,                 # truncated
    "not json",
    '["E5F9' + "0" * 36 + '"]',                          # not the shape of a note
    '{"thumbprints": "E5F9' + "0" * 36 + '"}',
    '{"thumbprints": ["E5F9' + "0" * 36 + '", "not a thumbprint"]}',    # one entry that is not one
    '{"thumbprints": [5]}',
])
def test_a_note_that_cannot_be_read_stops_the_install_and_is_left_as_it_is(state, content):
    """Reading it as empty would have the next write replace it, and the CA of the session that wrote it would be
    in the machine store with nothing left that names it."""
    ops = net_system.FakeSystemOps()
    ops.cas[EARLIER] = "leftover"
    with open(state, "w") as f:
        f.write(content)

    with pytest.raises(net_system.SystemOpsError, match="cannot be read"):
        net_ca.SessionCA(ops, state_path=state).install()

    assert ops.calls == []
    assert list(ops.cas) == [EARLIER]
    with open(state) as f:
        assert f.read() == content


def test_a_note_that_is_a_directory_stops_the_install_too(state):
    os.mkdir(state)
    ops = net_system.FakeSystemOps()
    with pytest.raises(net_system.SystemOpsError, match="cannot be read"):
        net_ca.SessionCA(ops, state_path=state).install()
    assert ops.calls == []


def test_a_note_that_cannot_be_written_is_a_system_ops_error_and_nothing_is_installed(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    ops = net_system.FakeSystemOps()
    with pytest.raises(net_system.SystemOpsError, match="cannot write the note"):
        net_ca.SessionCA(ops, state_path=str(blocker / "session_ca.json")).install()
    assert ops.calls == []


def test_the_note_is_on_disk_before_it_replaces_the_old_one(state, monkeypatch):
    events = []
    real_fsync, real_replace = os.fsync, os.replace
    monkeypatch.setattr(net_ca.os, "fsync", lambda fd: (events.append("fsync"), real_fsync(fd))[1])
    monkeypatch.setattr(net_ca.os, "replace", lambda a, b: (events.append("replace"), real_replace(a, b))[1])

    net_ca.SessionCA(net_system.FakeSystemOps(), state_path=state).install()

    assert events[0] == "fsync" and "replace" in events                # the data is synced before the rename
    assert events.index("fsync") < events.index("replace")
    assert "fsync" in events[events.index("replace"):] or os.name == "nt"      # and the directory after it


def test_the_temporary_of_the_note_is_ignored_by_git():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, ".gitignore")) as f:
        lines = [line.strip() for line in f]
    assert "webui/session_ca.json" in lines and "webui/session_ca.json.tmp" in lines
