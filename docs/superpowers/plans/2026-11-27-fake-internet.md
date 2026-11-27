# Fake Internet (Phase 2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A detonation in `isolated` mode talks to a fake internet that TDC serves inside the guest, and the traffic comes back as a capture Phase 1 already knows how to read.

**Architecture:** A session owns everything with a lifetime: it configures the adapter, hands out one address per faked name on demand, binds fake servers, terminates TLS with a per-session CA, records every exchange, and takes all of it back when it ends. What it records it writes as a pcap, and then calls `net_analyze.analyze_pcap` — the seam between the two phases is a file, not an API. The redirection point sits behind a `Diverter` protocol so approach B (an external gateway) can replace it without touching servers, analysis, rules or UI.

**Tech Stack:** Python 3.9, `dpkt` (pcap writing), `cryptography` (session CA), `ctypes` (the Windows TCP table), `netsh` and `New-NetFirewallRule` through a seam, Flask routes in `webui/app.py`, vanilla JS in `webui/static/js/app.js`.

**Spec:** `docs/superpowers/specs/2026-11-25-fake-internet-design.md`

## Global Constraints

Exact values from the spec. Every task's requirements implicitly include this section.

- **Python 3.9-compatible.** The test venv is 3.9.6; the guest runs 3.12. No `match`, no `X | Y` type syntax, no `dict | dict`.
- **Nothing from NetLens.** No file, no code fragment, no rule, no fixture, no translation. The rule language and the servers are TDC's own.
- **`online` stays the default mode.** `isolated` and `isolated+passthrough` are chosen explicitly; nothing changes for `online` except the passive analysis Phase 1 already does.
- **Exactly one network session at a time.** A second submission is refused while one runs, after the pattern of the agent's `/api/lock/status`.
- **Addresses come from `198.18.0.0/15`** (RFC 2544) on the real adapter, with `skipassource=true`.
- **One address per name, assigned on demand** at that name's first lookup — never a pool in advance (measured: 108–151 ms per address, 135 ms per removal; 500 names would cost over a minute of the session's budget at each end).
- **The diverter keeps its own name→address map in memory** and never asks the adapter during a session (measured: reading the address list grows from 20 ms at two addresses to 713 ms at 701).
- **The adapter must be configured statically** before any address is added, with the real address set by the chamber, and put back as it was at the end. `netsh ... add address` takes a DHCP adapter off DHCP and the real address disappears with it (measured: `dhcp_before` Enabled → `dhcp_after_adding` Disabled).
- **Session length:** start budget 300 s; quiet end after 60 s with no network event but not before 90 s; on a detected periodic interval extend to at least four intervals plus a buffer; hard cap 30 min with a reaper; the operator can stop and extend at any time and sees the remaining time. Every extension is logged and appears in the report.
- **Isolation** is a Windows Firewall outbound block of everything with exceptions for `198.18.0.0/15`, loopback, the service ports and WinRM. The rule carries its own name and is removed at stop and at the next start. A sample with admin rights can remove it; that is an accepted weakness and has to be visible, not assumed away.
- **UDP is answered only on pre-bound ports** (53, 123, 137, 161, 500, 1900, 5353 and the C2-usual). Everything else is logged as a `udp` event and not answered, and the report says so.
- **The session CA** lives in the machine truststore only for the session, removed in the `finally` of the stop and again at the next start in case one was left behind.
- **Everything is recorded**, including traffic that is not the sample's. Separation happens afterwards, through the process-tree marking, the network baseline and the own-service allowlist.
- **Evidence kinds are created in Python.** YAML rules in `rules/network/` annotate and classify; they never set a weight.
- **Artifacts per run** go to `C:\dumps\network\<time>_<sha256-prefix>\`: `capture.pcap`, `events.json`, `report.json`, `files\*.bin`, `session.log`, pruned like the other collections (`NETWORK_KEEP`, the pattern of `_exit_capture_prune`, `webui/app.py:6896`).
- **Out of scope:** stage retrieval and chained detonations (Phase 3), the fingerprint and its encrypted ZIP (Phase 4). `payload_staging` already exists and is fed by Phase 1.
- The dead `#submit-edr` control (`webui/templates/index.html:1574`) is removed with the mode field.

## Review Focus

Five things the spec implies that no task's tests exercise on their own. Each line's test is added to the task that owns the code.

1. **A hard-coded IP with no DNS and no proxy.** The spec calls this approach A's gap. It must be *seen and blocked*, never silently dropped: address, port and process belong in the report as an IOC. Test in Task 3.
2. **The address pool refusing.** The adapter took 1001 without a failure, but a refusal must degrade to the shared address with the name taken from SNI or `Host` — not crash, not hang, and the report must say which names lost their own address. Test in Task 2.
3. **The session ending mid-exchange.** Stop while a server holds an open connection: the CA, the firewall rule and every address must still go, and a pcap cut in the middle must still be readable by `analyze_pcap`. Test in Task 11.
4. **The same address handed to two names.** Within a session a name keeps its address, and a released address is not reused while the session runs. Two names must never share one. Test in Task 2.
5. **The sample removing the firewall rule.** The session must notice that isolation stopped holding and mark the report `incomplete` with a reason, rather than claim isolation held for the whole run. Test in Task 10.

---

### Task 1: The seams — TCP table and system calls

**Files:**
- Create: `webui/net_system.py`
- Test: `tests/test_net_system.py`

**Interfaces:**
- Produces: `class SystemOps` with `add_address(index, address, mask)`, `remove_address(index, address)`, `set_static(index, address, mask, gateway, dns)`, `restore_addressing(index, state)`, `read_addressing(index) -> dict`, `add_firewall_rule(name, spec)`, `remove_firewall_rules(prefix)`, `install_ca(pem)`, `remove_ca(thumbprint)`, `tcp_owner(owner_ip, owner_port, peer_ip, peer_port) -> int | None` — the owner's end comes first: asked the other way round Windows finds TDC's own listening row and returns TDC's own pid, pinning the connection on the wrong process with no error. `class FakeSystemOps(SystemOps)` records calls and answers from a dict, for every later task's tests. `WindowsSystemOps` runs the real thing.

- [ ] **Step 1: Write the failing test**

```python
def test_the_fake_records_what_was_asked_of_it_and_answers_from_its_table():
    ops = net_system.FakeSystemOps(tcp_owners={("10.0.0.5", 51000, "198.18.1.1", 80): 4242})
    ops.add_address(7, "198.18.1.1", "255.255.0.0")
    assert ops.calls == [("add_address", 7, "198.18.1.1", "255.255.0.0")]
    assert ops.tcp_owner("10.0.0.5", 51000, "198.18.1.1", 80) == 4242
    assert ops.tcp_owner("10.0.0.6", 51000, "198.18.1.1", 80) is None


def test_the_windows_ops_are_not_importable_off_windows_but_the_module_is():
    # every later task's tests run on the host, so importing the module must not
    # need Windows: only calling WindowsSystemOps may.
    assert hasattr(net_system, "WindowsSystemOps")
```

- [ ] **Step 2: Run it and watch it fail** — `pytest tests/test_net_system.py -v`, expected `AttributeError`.
- [ ] **Step 3: Implement `webui/net_system.py`.** `SystemOps` is the protocol (plain base class with `NotImplementedError` bodies, no `typing.Protocol`: 3.9). `WindowsSystemOps` shells out to `netsh` / `New-NetFirewallRule` / `certutil` and reads the TCP table with `ctypes` following the pattern in `webui/pipe_backends.py`; its `__init__` raises on a non-Windows platform, the module imports anywhere.
- [ ] **Step 4: Tests pass.**
- [ ] **Step 5: Commit.**

---

### Task 2: Address allocation — one per name, on demand, from our own map

**Files:**
- Create: `webui/net_divert.py`
- Test: `tests/test_net_divert.py`

**Interfaces:**
- Consumes: `net_system.FakeSystemOps` (Task 1).
- Produces: `class Diverter` (the protocol: `address_for(name) -> str`, `name_for(address) -> str | None`, `start()`, `stop()`, `state() -> dict`) and `class GuestDiverter(Diverter)` with `__init__(ops, index, prefix="198.18", shared=None)`. `SHARED_FALLBACK_REASON = "address pool refused"`.

- [ ] **Step 1: Write the failing tests**

```python
def test_a_name_gets_one_address_and_keeps_it():
    d = _diverter()
    first = d.address_for("c2.evil")
    assert d.address_for("c2.evil") == first
    assert d.name_for(first) == "c2.evil"


def test_two_names_never_share_an_address():          # Review Focus 4
    d = _diverter()
    seen = {d.address_for("h%d.top" % i) for i in range(50)}
    assert len(seen) == 50


def test_nothing_is_assigned_before_a_name_asks():
    d = _diverter()
    d.start()
    assert [c for c in d.ops.calls if c[0] == "add_address"] == []


def test_the_map_is_answered_from_memory_not_from_the_adapter():
    d = _diverter()
    d.address_for("c2.evil")
    before = len(d.ops.calls)
    for _ in range(100):
        d.address_for("c2.evil")
        d.name_for(d.address_for("c2.evil"))
    assert len(d.ops.calls) == before


def test_a_refused_address_falls_back_to_the_shared_one_and_says_so():   # Review Focus 2
    d = _diverter(fail_adds_after=2)
    d.address_for("a.top"), d.address_for("b.top")
    assert d.address_for("c.top") == d.shared
    assert "c.top" in d.state()["shared_names"]
    assert d.state()["shared_reason"] == net_divert.SHARED_FALLBACK_REASON


def test_stop_removes_exactly_what_was_added():
    d = _diverter()
    names = ["a.top", "b.top", "c.top"]
    added = {d.address_for(n) for n in names}
    d.stop()
    removed = {c[2] for c in d.ops.calls if c[0] == "remove_address"}
    assert removed == added
```

- [ ] **Step 2: Run them and watch them fail.**
- [ ] **Step 3: Implement the allocation.** Addresses walk `198.18.1.1` upward, skipping `.0` and `.255` in the last octet. The map is two dicts; `address_for` adds through `ops` only on a miss. A failing `add_address` records the name under `shared_names` and returns `shared`.
- [ ] **Step 4: Tests pass.**
- [ ] **Step 5: Commit.**

---

### Task 3: The guest diverter — static adapter, isolation, and what it cannot reach

**Files:**
- Modify: `webui/net_divert.py`
- Test: `tests/test_net_divert.py`

**Interfaces:**
- Produces: `GuestDiverter.start()` records the adapter's addressing, switches it to static with the real address, writes the isolation rule and points the guest's DNS at us; `stop()` puts all of it back. `ISOLATION_RULE = "TDC-NET-ISOLATE"`. `blocked_attempts() -> list` holds what was seen and not answered.

- [ ] **Step 1: Write the failing tests**

```python
def test_start_makes_the_adapter_static_before_the_first_address():
    d = _diverter(addressing={"dhcp": True, "address": "192.168.64.4", "mask": "255.255.255.0"})
    d.start()
    kinds = [c[0] for c in d.ops.calls]
    assert kinds.index("set_static") < len(kinds)
    assert "add_address" not in kinds


def test_stop_puts_dhcp_back_even_when_removing_an_address_fails():
    d = _diverter(addressing={"dhcp": True}, fail_removes=True)
    d.start(); d.address_for("a.top")
    d.stop()
    assert ("restore_addressing", 7) in [(c[0], c[1]) for c in d.ops.calls]


def test_the_isolation_rule_is_named_and_is_removed_at_start_and_stop():
    d = _diverter()
    d.start()
    assert ("add_firewall_rule", net_divert.ISOLATION_RULE) in [(c[0], c[1]) for c in d.ops.calls]
    assert [c for c in d.ops.calls if c[0] == "remove_firewall_rules"]
    d.ops.calls.clear(); d.stop()
    assert [c for c in d.ops.calls if c[0] == "remove_firewall_rules"]


def test_a_hard_coded_address_is_recorded_as_blocked_not_dropped():    # Review Focus 1
    d = _diverter()
    d.start()
    d.note_blocked("203.0.113.9", 4444, pid=4242, process="x.exe")
    b = d.blocked_attempts()[0]
    assert (b["dest"], b["port"], b["pid"], b["process"]) == ("203.0.113.9", 4444, 4242, "x.exe")
    assert b["answered"] is False
```

- [ ] **Step 2: Run them and watch them fail.**
- [ ] **Step 3: Implement it.** `start()` in this order: remove leftovers from an earlier session, read addressing, `set_static`, isolation rule, DNS. `stop()` in a `finally` chain so a failure in one step does not skip the rest.
- [ ] **Step 4: Tests pass.**
- [ ] **Step 5: Commit.**

---

### Task 4: The session CA and a certificate per name

**Files:**
- Create: `webui/net_ca.py`
- Test: `tests/test_net_ca.py`

**Interfaces:**
- Produces: `class SessionCA` with `__init__(ops)`, `pem` (the CA certificate), `thumbprint`, `cert_for(name) -> (cert_pem, key_pem)`, `install()`, `remove()`. Certificates are cached per name.

- [ ] **Step 1: Write the failing tests** — `test_a_certificate_carries_the_name_asked_for_as_its_san`, `test_the_same_name_is_not_signed_twice`, `test_an_ip_literal_becomes_an_ip_san_not_a_dns_one`, `test_remove_is_called_with_the_thumbprint_that_was_installed`, `test_install_removes_a_leftover_ca_of_an_earlier_session_first`.
- [ ] **Step 2: Run them and watch them fail.**
- [ ] **Step 3: Implement with `cryptography`** — a 2048-bit RSA CA valid for one day, leaf certificates for 12 hours, `SubjectAlternativeName` with `DNSName` or `IPAddress` as the name requires.
- [ ] **Step 4: Tests pass.**
- [ ] **Step 5: Commit.**

---

### Task 5: Writing the capture, so Phase 1 can read it

**Files:**
- Create: `webui/net_pcap.py`
- Test: `tests/test_net_pcap.py`

**Interfaces:**
- Produces: `class CaptureWriter` with `__init__(path, guest_ip)`, `exchange(ts, dest, dport, sport, request, response, proto="tcp")`, `datagram(ts, dest, dport, sport, payload)`, `close()`. One TCP exchange becomes a whole conversation (handshake, data, close) so the parsers of Phase 1 see a flow.
- Produces: `class SessionContext`, the one object every server is given. Plain attributes, no behaviour: `diverter`, `ca`, `writer`, `ops`, `recorder` (collects events), `passthrough` (the allowlisted hosts), `mode`, `guest_ip`. Task 11's runner builds it; Tasks 6 to 9 and 15 only read it.

- [ ] **Step 1: Write the failing test**

```python
def test_what_was_written_is_what_analyze_pcap_reads_back(tmp_path):
    path = str(tmp_path / "capture.pcap")
    w = net_pcap.CaptureWriter(path, "10.0.2.15")
    w.exchange(1795000000.0, "203.0.113.5", 80, 49200,
               b"GET /gate.php HTTP/1.1\r\nHost: c2.evil\r\n\r\n",
               b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    w.close()
    report = net_analyze.analyze_pcap(path)
    assert report["event_summary"].get("http") == 1
    http = [e for e in report["events"] if e["type"] == "http"][0]
    assert (http["dest"], http["path"]) == ("c2.evil", "/gate.php")
```

- [ ] **Step 2: Run it and watch it fail.**
- [ ] **Step 3: Implement with `dpkt`**, Ethernet over IPv4, sequence numbers that advance with the payload so reassembly works.
- [ ] **Step 4: Tests pass.** Add `test_a_datagram_round_trip_is_read_back_as_a_dns_event` and `test_a_writer_closed_twice_does_not_raise`.
- [ ] **Step 5: Commit.**

---

### Task 6: The DNS server — where a faked name gets its address

**Files:**
- Create: `webui/net_resolve.py`
- Test: `tests/test_net_resolve.py`

**Interfaces:**
- Consumes: `net_divert.Diverter.address_for` (Task 2), `net_pcap.CaptureWriter.datagram` (Task 5).
- Produces: `class DnsServer` with `__init__(ctx)`, `answer(query_bytes) -> bytes | None`, `TTL = 60`, `HOUSEKEEPING` (the names a clean Windows asks for, answered but marked). `None` means "do not answer" and the caller logs a `udp` event instead.

This is the hinge of the whole approach: the address a name is given here is what the
fake servers later read back out of the destination address, which is the only way a raw
protocol carrying no name can be attributed at all.

- [ ] **Step 1: Write the failing tests**

```python
def test_an_a_query_is_answered_with_the_address_the_diverter_assigned():
    s, d = _server()
    reply = s.answer(_query("c2.evil", "A"))
    assert _answers(reply) == [d.address_for("c2.evil")]


def test_the_same_name_asked_twice_gets_the_same_address():
    s, _ = _server()
    assert _answers(s.answer(_query("c2.evil", "A"))) == _answers(s.answer(_query("c2.evil", "A")))


def test_an_address_is_assigned_only_when_the_name_is_asked_for():
    s, d = _server()
    assert d.state()["assigned"] == 0
    s.answer(_query("c2.evil", "A"))
    assert d.state()["assigned"] == 1


def test_a_name_on_the_passthrough_allowlist_is_not_faked():
    s, _ = _server(passthrough=["teamserver.mine"])
    assert s.answer(_query("teamserver.mine", "A")) is None


def test_an_aaaa_query_is_answered_with_no_records_not_with_nxdomain():
    # NXDOMAIN on AAAA makes some clients give up on the name entirely
    reply = _server()[0].answer(_query("c2.evil", "AAAA"))
    assert _rcode(reply) == 0 and _answers(reply) == []


def test_a_txt_query_gets_an_empty_answer_so_a_dns_tunnel_keeps_talking():
    reply = _server()[0].answer(_query("x.tunnel.evil", "TXT"))
    assert _rcode(reply) == 0


def test_a_malformed_query_is_not_answered_and_does_not_raise():
    assert _server()[0].answer(b"\xff\xff\xff") is None


def test_the_query_and_its_answer_are_both_written_to_the_capture():
    s, _ = _server()
    s.answer(_query("c2.evil", "A"))
    assert s.ctx.writer.datagrams >= 2
```

- [ ] **Step 2: Run them and watch them fail** — `pytest tests/test_net_resolve.py -v`.
- [ ] **Step 3: Implement `webui/net_resolve.py`** with `dpkt.dns` for both directions. Names from `HOUSEKEEPING` are answered and flagged so the report can set them aside; names on the passthrough allowlist return `None`.
- [ ] **Step 4: Tests pass.**
- [ ] **Step 5: Commit.**

---

### Task 7: The HTTP and HTTPS servers, and the answers that keep a sample going

**Files:**
- Create: `webui/net_servers.py`
- Test: `tests/test_net_servers.py`

**Interfaces:**
- Consumes: `net_ca.SessionCA` (Task 4), `net_divert.Diverter` (Task 2), `net_pcap.CaptureWriter` (Task 5), `net_system.SystemOps.tcp_owner` (Task 1).
- Produces: `class HttpServer` with `__init__(ctx)` where `ctx` carries diverter, ca, writer, ops and the recorder; `handle(request_bytes, local_addr, peer_addr) -> bytes`; `CREDIBLE` mapping host patterns to canned answers. `NO_TASK = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"`.

- [ ] **Step 1: Write the failing tests** — `test_an_unknown_host_gets_an_empty_200_so_the_beacon_lives`, `test_an_ip_lookup_service_gets_a_plausible_address`, `test_a_geolocation_lookup_gets_a_consistent_country_for_that_address`, `test_a_telegram_bot_api_call_gets_a_well_formed_ok_envelope`, `test_a_discord_webhook_post_gets_204`, `test_the_name_comes_from_the_destination_address_not_from_the_host_header`, `test_a_request_with_no_host_header_still_resolves_a_name_by_address`.
- [ ] **Step 2: Run them and watch them fail.**
- [ ] **Step 3: Implement.** Parse the request far enough for method, path, headers and body; resolve the name through `diverter.name_for(local_ip)` first and the `Host` header only as a fallback; record the exchange through the writer; answer from `CREDIBLE` or with `NO_TASK`.
- [ ] **Step 4: Tests pass.**
- [ ] **Step 5: Commit.**

---

### Task 8: SMTP, FTP, IMAP, POP3, DNS-over-HTTPS and WebSocket

**Files:**
- Modify: `webui/net_servers.py`
- Test: `tests/test_net_servers.py`

**Interfaces:**
- Produces: `SmtpServer`, `FtpServer`, `ImapServer`, `Pop3Server`, `DohServer`, `WebSocketServer`, each with `handle(...)` of the same shape, and `PREBOUND_TCP` / `PREBOUND_UDP` listing the ports bound in advance.

- [ ] **Step 1: Write the failing tests** — one exchange per protocol that ends in a credential or a payload being recorded: `test_a_login_to_the_smtp_server_is_accepted_and_the_credentials_are_recorded`, `test_an_ftp_stor_is_accepted_and_the_file_is_kept`, `test_an_imap_login_gets_ok_and_an_empty_inbox`, `test_a_pop3_session_ends_without_mail`, `test_a_doh_query_is_answered_with_the_address_the_diverter_gave_the_name`, `test_a_websocket_upgrade_is_accepted_and_frames_are_recorded`.
- [ ] **Step 2: Run them and watch them fail.**
- [ ] **Step 3: Implement.** Each server answers protocol-correctly and does nothing else; an accepted upload is written to `files\` and never opened.
- [ ] **Step 4: Tests pass.**
- [ ] **Step 5: Commit.**

---

### Task 9: The catch-all, the profile of an unknown protocol, and the UDP gap

**Files:**
- Modify: `webui/net_servers.py`
- Test: `tests/test_net_servers.py`

**Interfaces:**
- Produces: `CatchAll` with `handle(...)` and `profile() -> dict` holding `framing`, `delimiters`, `entropy`, `heartbeat_s`, `bytes_in`, `bytes_out`; `bind_on_demand(port)` for a `SYN_SENT` seen on an unbound port.

- [ ] **Step 1: Write the failing tests** — `test_a_length_prefixed_protocol_is_profiled_as_framed`, `test_a_newline_protocol_is_profiled_by_its_delimiter`, `test_high_entropy_payloads_are_reported_as_encrypted_looking`, `test_a_regular_heartbeat_is_measured`, `test_a_port_seen_in_syn_sent_is_bound_and_the_bind_is_logged`, `test_an_unbound_udp_port_is_logged_as_an_event_and_not_answered`.
- [ ] **Step 2: Run them and watch them fail.**
- [ ] **Step 3: Implement.** The profile is measured, never guessed; `bind_on_demand` is driven by the TCP table through `ops`.
- [ ] **Step 4: Tests pass.**
- [ ] **Step 5: Commit.**

---

### Task 10: The session's lifetime

**Files:**
- Create: `webui/net_session.py`
- Test: `tests/test_net_session.py`

**Interfaces:**
- Produces: `class Session` with `__init__(ctx, clock=time.time)`, `START_BUDGET_S = 300`, `QUIET_S = 60`, `QUIET_EARLIEST_S = 90`, `HARD_CAP_S = 1800`, `MIN_INTERVALS = 4`, properties `deadline`, `remaining`, methods `note_event(ts)`, `note_interval(seconds)`, `extend(seconds, reason)`, `should_end() -> (bool, reason)`, `log` (every extension with its reason).

- [ ] **Step 1: Write the failing tests**

```python
def test_a_quiet_session_ends_after_the_quiet_window_but_not_before_the_floor():
    s = _session(now=0.0)
    assert s.should_end(now=89.0)[0] is False
    assert s.should_end(now=91.0)[0] is True
    assert s.should_end(now=91.0)[1] == net_session.END_QUIET


def test_an_event_resets_the_quiet_window():
    s = _session(now=0.0)
    s.note_event(80.0)
    assert s.should_end(now=130.0)[0] is False
    assert s.should_end(now=145.0)[0] is True


def test_a_detected_interval_extends_to_four_intervals_plus_a_buffer():
    s = _session(now=0.0)
    s.note_interval(300.0)
    assert s.deadline >= 4 * 300.0
    assert s.log[-1]["reason"].startswith("interval")


def test_the_hard_cap_wins_over_every_extension():
    s = _session(now=0.0)
    s.note_interval(3600.0)
    assert s.deadline <= net_session.HARD_CAP_S


def test_the_operator_can_extend_and_stop_at_any_time():
    s = _session(now=0.0)
    s.extend(120.0, "operator")
    assert s.log[-1]["reason"] == "operator"
    s.stop("operator")
    assert s.should_end(now=0.0)[0] is True


def test_isolation_that_stopped_holding_marks_the_report_incomplete():   # Review Focus 5
    s = _session(now=0.0)
    s.note_isolation_lost(42.0, "rule TDC-NET-ISOLATE is gone")
    assert any("isolation" in r for r in s.incomplete())
```

- [ ] **Step 2: Run them and watch them fail.**
- [ ] **Step 3: Implement.** Pure logic over an injected clock — no threads, no sockets, no sleeps in this task.
- [ ] **Step 4: Tests pass.**
- [ ] **Step 5: Commit.**

---

### Task 11: Wiring a session end to end

**Files:**
- Modify: `webui/net_session.py`
- Test: `tests/test_net_session.py`

**Interfaces:**
- Produces: `class SessionRunner` with `start(mode, process, sha256, passthrough) -> dict`, `status() -> dict`, `stop() -> dict`, `ARTIFACT_ROOT`. On stop it writes `capture.pcap`, `events.json`, `report.json` and `session.log`, calls `net_analyze.analyze_pcap` and stores the report the way `/api/network/import` does.

- [ ] **Step 1: Write the failing tests**

```python
def test_a_session_produces_a_report_that_carries_the_mode_and_the_artifacts(tmp_path):
    r = _runner(tmp_path)
    r.start(mode="isolated", process="x.exe", sha256="ab" * 32, passthrough=[])
    r.servers["http"].handle(b"GET /gate.php HTTP/1.1\r\nHost: c2.evil\r\n\r\n",
                             ("198.18.1.1", 80), ("10.0.2.15", 49200))
    out = r.stop()
    assert out["report"]["mode"] == "isolated"
    for name in ("capture.pcap", "events.json", "report.json", "session.log"):
        assert (tmp_path / out["dir"] / name).exists()
    assert out["report"]["event_summary"].get("http") == 1


def test_stopping_mid_exchange_still_takes_everything_back(tmp_path):   # Review Focus 3
    r = _runner(tmp_path)
    r.start(mode="isolated", process="x.exe", sha256="", passthrough=[])
    r.address_for("c2.evil")
    r.servers["http"].begin_exchange()         # left open on purpose
    out = r.stop()
    assert out["cleanup"]["addresses_left"] == 0
    assert out["cleanup"]["ca_removed"] is True
    assert out["cleanup"]["firewall_removed"] is True
    assert net_analyze.analyze_pcap(str(tmp_path / out["dir"] / "capture.pcap"))["errors"] == []


def test_a_second_start_is_refused_while_one_runs(tmp_path):
    r = _runner(tmp_path)
    r.start(mode="isolated", process="", sha256="", passthrough=[])
    with pytest.raises(net_session.SessionBusy):
        r.start(mode="isolated", process="", sha256="", passthrough=[])
```

- [ ] **Step 2: Run them and watch them fail.**
- [ ] **Step 3: Implement.** The reaper is a daemon thread that calls `should_end` and stops the session; it is off under `TDC_NO_BACKGROUND`.
- [ ] **Step 4: Tests pass.**
- [ ] **Step 5: Commit.**

---

### Task 12: The routes

**Files:**
- Modify: `webui/app.py`
- Test: `tests/test_net_api.py`

**Interfaces:**
- Produces: `POST /api/network/session` (start: `mode`, `process`, `sha256`, `passthrough`), `GET /api/network/session` (status with `remaining`, `mode`, `events`, `log`), `POST /api/network/session/extend` (`seconds`), `DELETE /api/network/session` (stop, answers with the report id).

- [ ] **Step 1: Write the failing tests** — `test_starting_a_session_answers_with_its_deadline_and_mode`, `test_a_second_start_answers_409_and_names_the_running_session`, `test_the_status_carries_the_remaining_seconds_and_every_extension`, `test_extend_refuses_more_than_the_hard_cap`, `test_stopping_answers_with_the_report_id_and_the_report_is_readable`, `test_the_routes_answer_503_naming_the_fix_when_a_dependency_is_missing`.
- [ ] **Step 2: Run them and watch them fail.**
- [ ] **Step 3: Implement** beside the five existing `/api/network/*` routes, with the same guarded-import 503 as Phase 1.
- [ ] **Step 4: Tests pass.**
- [ ] **Step 5: Commit.**

---

### Task 13: The mode field in the Submit tab

**Files:**
- Modify: `webui/templates/index.html`, `webui/static/js/app.js`, `webui/app.py`
- Test: `tests/test_net_ui.py`, `tests/test_docs.py`

**Interfaces:**
- Produces: `#submit-netmode` with `online` selected, `isolated`, `isolated+passthrough`; `#submit-passthrough` (a free text field, shown only for `isolated+passthrough`); `/api/submit` takes `netmode` and `passthrough` and starts a session before the sample runs.

- [ ] **Step 1: Write the failing tests** — `test_the_mode_field_offers_three_modes_with_online_selected`, `test_the_passthrough_field_is_only_shown_for_the_passthrough_mode`, `test_submitting_with_online_starts_no_session`, `test_submitting_with_isolated_starts_a_session_before_the_agent_is_called`, `test_the_dead_submit_edr_control_is_gone`, `test_asset_versions_are_bumped`.
- [ ] **Step 2: Run them and watch them fail.**
- [ ] **Step 3: Implement.** Remove `#submit-edr` in the same change. Bump `style.css`, `app.js` and both themes by one.
- [ ] **Step 4: Tests pass.**
- [ ] **Step 5: Commit.**

---

### Task 14: The session panel in the NETWORK tab

**Files:**
- Modify: `webui/static/js/app.js`, `webui/templates/index.html`, `webui/static/css/style.css`, `webui/static/css/theme-cyberpunk.css`
- Test: `tests/test_net_ui.py`, `tests/test_theme.py`

**Interfaces:**
- Produces: `renderNetworkSession(state)` drawing mode, remaining time, the event count, every extension with its reason, and STOP / EXTEND buttons; polling at 2 s while a session runs and not at all otherwise.

- [ ] **Step 1: Write the failing tests** — `test_the_panel_names_the_mode_and_counts_down_the_remaining_time`, `test_every_extension_is_listed_with_its_reason`, `test_stop_and_extend_call_their_routes`, `test_without_a_session_the_panel_says_so_and_does_not_poll`, `test_both_themes_define_every_session_variable`.
- [ ] **Step 2: Run them and watch them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Tests pass.**
- [ ] **Step 5: Commit.**

---

### Task 15: Process attribution

**Files:**
- Modify: `webui/net_servers.py`, `webui/net_session.py`
- Test: `tests/test_net_servers.py`

**Interfaces:**
- Produces: every recorded exchange carries `pid` and `process` where the TCP table answered at accept time, and otherwise `attribution: "correlated"` from `_sysmon_network_events` by time, port and destination, or no process at all.

- [ ] **Step 1: Write the failing tests** — `test_the_owner_from_the_tcp_table_is_on_the_event`, `test_a_table_that_does_not_answer_falls_back_to_sysmon_correlation`, `test_a_correlated_owner_is_marked_as_correlated_not_observed`, `test_no_owner_at_all_leaves_the_process_empty_and_says_why`.
- [ ] **Step 2: Run them and watch them fail.**
- [ ] **Step 3: Implement.** The table is asked once at accept; the correlation runs at stop, over the events that have no pid.
- [ ] **Step 4: Tests pass.**
- [ ] **Step 5: Commit.**

---

### Task 16: Our own services are not the sample's traffic

**Files:**
- Modify: `webui/net_session.py`
- Test: `tests/test_net_session.py`

**Interfaces:**
- Produces: `OWN_SERVICES` (the process names and ports of TDC's own: the UI itself, the tool-update check, LitterBox, the agent, theZoo) and `Session.classify(event) -> "sample" | "own" | "housekeeping" | "unattributed"`. Events that are not `sample` keep their place in `events.json` and in the report's notes, and are not scored.

The spec's third way of separating noise, beside the process-tree marking and the
network baseline of Phase 1. Without it a run in `isolated` mode reports dozens of IOCs
that belong to Windows and to TDC: in that mode NCSI, Windows Update, Defender, the time
sync, Brave and TDC's own update check all land at the fake servers, and because the
session CA is in the machine store they even accept our certificates.

- [ ] **Step 1: Write the failing tests**

```python
def test_the_web_ui_talking_to_itself_is_classified_as_own():
    s = _session()
    assert s.classify({"process": "python.exe", "pid": _own_pid(), "dest": "127.0.0.1"}) == "own"


def test_the_connectivity_check_of_windows_is_housekeeping():
    s = _session()
    assert s.classify({"dest": "www.msftconnecttest.com", "process": "svchost.exe"}) == "housekeeping"


def test_the_sample_and_a_process_it_injected_are_both_the_sample():
    s = _session(sample="x.exe", tree={"x.exe", "explorer.exe"})
    assert s.classify({"process": "explorer.exe"}) == "sample"


def test_an_event_without_a_process_is_unattributed_not_the_sample():
    assert _session().classify({"dest": "c2.evil"}) == "unattributed"


def test_only_sample_events_are_scored_and_the_rest_stay_in_the_report():
    s = _session(sample="x.exe", tree={"x.exe"})
    report = s.summarise([{"process": "x.exe", "dest": "c2.evil", "type": "http"},
                          {"process": "svchost.exe", "dest": "www.msftconnecttest.com", "type": "http"}])
    assert report["scored"] == 1
    assert report["set_aside"]["housekeeping"] == 1
    assert len(report["events"]) == 2
```

- [ ] **Step 2: Run them and watch them fail.**
- [ ] **Step 3: Implement.** The process tree comes from what TDC already has (Sysmon, the graph), the way `_compute_verdict` builds it for alerts; no new tracer.
- [ ] **Step 4: Tests pass.**
- [ ] **Step 5: Commit.**

---

### Task 17: Deploy, documentation and the operator's notes

**Files:**
- Modify: `Makefile`, `make.ps1`, `scripts/deploy-utm.py`, `docs/web-ui.md`, `docs/api.md`, `docs/troubleshooting.md`, `README.md`
- Test: `tests/test_docs.py`

**Interfaces:**
- Produces: every new `webui/net_*.py` in all three deploy paths; the four new routes in the API page; the modes, the session control and the UDP gap in the web UI page; and in troubleshooting the two things that bite — the adapter is configured statically for the duration of a session, and a sample with admin rights can remove the isolation rule.

- [ ] **Step 1: Write the failing tests** — `test_every_deploy_path_uploads_the_new_network_modules`, `test_the_api_page_documents_each_session_route_exactly_once`, `test_the_web_ui_page_names_the_three_modes_and_the_udp_gap`, `test_troubleshooting_says_what_a_session_changes_on_the_adapter`.
- [ ] **Step 2: Run them and watch them fail.**
- [ ] **Step 3: Write the documentation and extend the three deploy lists.**
- [ ] **Step 4: Tests pass, then the full suite.**
- [ ] **Step 5: Commit.**
