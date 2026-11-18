# Firewall

Whom the chamber talks to while a sample runs, and the switches that cut it
off: per process, per endpoint or the whole VM at once.

The **FIREWALL** tab shows whom the chamber talks to and lets you act on it
while the sample runs: a process tree with each process's endpoints, a world
map of the destinations, and the switches that write rules into the Windows
Firewall. It is built from what Windows already records (Sysmon 1, 3 and 22,
`pfirewall.log`, PowerShell 4104/4103 and the BITS client log). It sees a
connection **after** it was made and does not hold one back. How late depends on
the source: everything is read every 10 seconds; while a detonation runs, Sysmon
(processes, connections, DNS) and the BITS log are read every second, but
PowerShell and the firewall log stay at 10 seconds. A download found in a
PowerShell script needs both the URL (from the script block) and the connection
(from Sysmon), so a PowerShell download cradle can be found, and its loader
blocked, up to about ten seconds after the connection.
Everything in it is text from the sample and is shown as text: URLs and host
names are defanged (`hxxp://`, `example[.]com`), never a link.

![The FIREWALL tab in the MAP view with nothing isolated: 12 connections over the last hour, a process tree of three svchost.exe instances with ALLOW switches and direct-ip tags, the world map with two arcs from the CHAMBER device to two destinations, and the summary with the CUT THE NETWORK card](../static/firewall_tab.png)

> **The tab as it opens, in the MAP view.** The head reads 12 connections with
> LIVE on, ASK at DETONATION, the ISOLATED button and the range buttons
> 15M, 1H, 4H, 24H, 7D and ALL, 1H the active one. On the left, PROCESSES: three
> `svchost.exe` instances (PIDs 4052, 3964 and 3008), each with a green ALLOW
> switch and a `direct-ip` tag, and under them the endpoints they talk to
> (`48.209.133.15` US :443/TCP with FW 1, `146.75.118.172` US
> :80/TCP, `72.145.35.97` US :443/TCP), plus a collapsed LOCAL group of 3. In
> the middle, DESTINATIONS under the MAP, LIST, ASN and DECISIONS switch: two
> orange arcs rise from the framed CHAMBER device in the strip under the map
> to `72.145.35.97` and `48.209.133.15`; the strip's left reads
> LOCATION NOT DETERMINED. Under the map the tab says that the six connections to
> local addresses are in the tree, not on the map. On the
> right, the SUMMARY: 12 connections (22 single ones), BLOCKED 0, OPEN DECISIONS
> 0, SAMPLES 0 secured, the top processes, endpoints and countries, and the note
> that Sysmon has no byte counts. Below it the NETWORK CUT card with the skull
> button, and at the bottom HUNT FURTHER with three ready LOGS searches and
> SECURED SAMPLES, 0 so far.

A connection here is a flow: one process (image and PID) to one endpoint
(protocol, address, port), with its count and its first and last packet. The
firewall log has no process, so its numbers (`FW (endpoint)`, the `dropped`
tag) belong to the endpoint, not to the process beside them. There are **no
byte counts**: Sysmon records none, and the `size` field of `pfirewall.log` is
per record and mostly empty. The tree's bars and the map's lines scale with the
number of connections instead, and the summary says why. Countries and AS
names come from an offline table in `webui/data` (iptoasn.com, public domain);
TDC never asks anyone online about an address it has seen from malware.
Private, loopback and link-local addresses are a group of their own and are not
on the map; TDC's own processes (the web UI, Detonator, LitterBox, Fibratus,
Rustinel, git) are a group of their own and are never blocked automatically.

| Tag | Severity | When |
|-----|----------|------|
| `ioc` | critical | the address or host name is on Rustinel's IOC lists |
| `beacon` | critical | the connection times have a regular rhythm (the beaconing detector of Live Memory) |
| `sigma` | high | a Rustinel or Fibratus alert names this address and port |
| `detonated` | high | the process, or one of its ancestors, is a submission |
| `direct-ip` | high | no DNS answer and no Sysmon host name explains the address: a hard-coded destination |
| `download` | high | a URL to an executable file (`.exe`, `.dll`, `.ps1`, `.hta`, `.msi`, ...) was seen for this connection |
| `tdc-anomaly` | high | one of TDC's own processes talks to an endpoint it has no business with |
| `lolbin` | medium | the image is a living-off-the-land binary (certutil, bitsadmin, mshta, rundll32, powershell, ...) |
| `dga` | medium | the name it resolved has high entropy or many digits |
| `risky-tld` | medium | `.onion`, `.bit`, `.top`, `.xyz`, `.tk`, `.ml`, `.ga`, `.cf` |
| `dead-drop` | medium | a paste, chat or file-drop service (telegram, pastebin, discord, raw.githubusercontent, transfer.sh, ...) |
| `rare-port` | medium | a port outside the usual list, or 4444, 5555, 6666, 8888, 9999, 31337 |
| `newborn` | low | the process was less than 60 s old when the connection began |
| `dropped` | info | the firewall dropped packets to this endpoint |

The colour of a row and of an arc is its most severe tag.

The **LIST** view of DESTINATIONS is the same flows as a table, one row per
process and endpoint. Its columns are PROCESS, PID, DESTINATION, ADDRESS, PORT,
PROTO, CC, AS, TAGS, CONN., FW (ENDPOINT) and STATE.

![The FIREWALL tab in the LIST view with nothing isolated: 14 connections as a table of svchost.exe TCP rows to Microsoft and Fastly addresses on ports 443 and 80 tagged direct-ip and allowed, and UDP rows to multicast addresses and to hackepeter-2 on ports 53 and 67](../static/firewall_list.png)

> **The same tab in the LIST view,** 14 connections, nothing isolated. The TCP
> rows are `svchost.exe` to `MICROSOFT-CORP-MSN-AS-BLOCK` and to
> `FASTLY - Fastly, Inc.` on ports 443 and 80, each tagged `direct-ip`, in
> state ALLOW, with firewall counts such as `1 / 0` under FW (ENDPOINT). Below
> them the UDP rows: `239.255.255.250:1900`, `224.0.0.252:5355`,
> `ff02::1:3:5355` and `hackepeter-2` (192.168.64.1) on ports 53 and 67.
> SECURED SAMPLES at the bottom reads "None yet."

**Blocking.** ALLOW / DENY writes a rule named `TDC-FW-...`: for one process to
one endpoint, for one process everywhere, or (a separate switch) for an
endpoint and every program, TDC's own fetch included. A rule only counts as a
block once it reads back from Windows as written and every profile it covers is
on. A loopback address (`127.0.0.0/8`, `::1`) is never blocked, for one process
or for all: Windows Firewall does not filter loopback, so such a rule would
stand, read back, and block nothing; the switch, the API and a download
decision say so instead. A blocked connection is not reset: a running one is expected to starve, which
looks like a network failure to the sample (Windows re-checks an established
flow against a new Block filter; the handover has the check that confirms it). The UI shows each rule's protocol, because the
assessment does not compare it: a tcp rule makes a udp flow to the same
endpoint read as blocked too. KILL ends a selected process with `taskkill /F`
after a confirmation (never one of TDC's own). While a Windows Firewall profile
is off no rule would bite, so every switch is disabled and a red band says so,
with TURN THE FIREWALL ON. TDC never turns it on by itself: that changes what
the sample sees.

**ASK** decides what happens when a process fetches a file. The setting lives
on the server, because the blocks it causes hold without a browser.

| Position | What happens |
|----------|--------------|
| `Detonation` (default) | A download of a process in a detonation (a submission or its descendants; a BITS job while a submission runs) is blocked at once and then asked about. Everything else is only tagged. |
| `All` | Every download is blocked and asked about, except those of TDC's own processes and of the tool-update hosts. |
| `Off` | Nothing is blocked, nothing is asked or fetched; downloads are still tagged and logged. The head says so the whole time. |

A download is seen when its URL appears in a PowerShell script block, in a
Sysmon command line (`certutil -urlcache`, `bitsadmin /transfer`, `curl`,
`mshta http://...`) or in the BITS log. A compiled loader that calls WinHTTP
itself shows no URL and is only a connection here: that is the known gap of
this part. A download also needs its connection, and Sysmon logs a connection
(EID 3) only for the programs its config includes: SwiftOnSecurity's list
(images under `C:\Users`, `C:\ProgramData`, `C:\Windows\Temp`, a list of
LOLBins, a few ports) plus what `scripts/install-sysmon.ps1` adds for this tab, outbound only:
`curl.exe`, `python.exe` and `pythonw.exe` (TDC's own, for `tdc-anomaly`) and
`svchost.exe` (BITS). A program outside it, under `Program Files` for one, or
code injected into another system process, makes no connection the tab sees.
A loader that runs as the very Python interpreter TDC's fetch runs as is never
blocked (a block on it would cut TDC's fetch off); its toast says the block is
NOT confirmed. The connection has already happened when TDC sees the URL, so the
question is honest about it: the toast, on every tab, says the loader **is
blocked** and offers CUT + FETCH (keep the block, TDC fetches the file itself),
CUT ONLY and ALLOW (lift the block). When nobody answers within
`TDC_FIREWALL_DECIDE_SECONDS` (30 s), TDC keeps the block and fetches the file
anyway, because a stage-2 URL is often good for one download only; that means
the chamber contacts the C2 unattended. While the cut stands (the panic
button, stages `cut` and `cut_policy`) none of that can happen: a Block rule for
every program beats every Allow rule, TDC's own fetch included, so CUT + FETCH
is not offered, the route refuses `block_fetch` with 409 and says to leave the
cut first, and a deadline only blocks. It writes no capture and records in the
decision why it could not secure the file (`result.note`; DECISIONS shows
"could not fetch"). Writing that block waits behind a running convergence of
ISOLATED (tens of seconds), which can hold up a collector tick (a deadline
shortly after a press nearly always meets that convergence, so this is the
common case in the cut); it is not skipped, and until the write replaces it the
decision keeps showing the block written when it was opened (the same rule). The deadline runs
on the server, so closing the page changes nothing, and what was decided while
nobody watched stays as a toast until it is closed. DECISIONS lists the open decisions and
those of the last 24 h: who took which, and when. `POST /api/firewall/decide`
takes only the id of a decision TDC opened, never a URL, so a sample cannot
use TDC as its proxy.

**The fetch** runs in the guest, never on the host, with the loader's
User-Agent when the script named one. It goes only to the address and port the
loader used (on every one of at most 3 redirects, no new DNS lookup), within
64 MB and 30 s in all. It refuses the VM's own addresses, its gateways and,
unless `TDC_FIREWALL_FETCH_LAN=1`, every private address: the analyst's host is
one of those.

**Secured samples** are stored in `C:\tdc\samples\<sha256[:2]>\<sha256>`
(excluded from Defender, both at provisioning and at every start of the web
UI), with their metadata in `webui/captures.json` (at most 500: URL, endpoint,
process, SHA-256, size, the first bytes' type, the User-Agent sent). They are
**never executed**: SECURED SAMPLES opens one in Rizin, Hex or ThreatScan.
To detonate one, submit it again on purpose in SUBMIT.

**ISOLATED** is the panic button: CUT THE NETWORK, the red skull under the
summary, and the ISOLATED switch in the head are one state and one press. A
press cuts **without a confirmation**. It writes one outbound Block rule for
every program and every address, `TDC-FW-ISO-cut`, reads it back in the same
PowerShell call and answers with `stage: "cut"`: measured 8.8 s on a quiet VM,
9.9-16.9 s while the tab's own polls load it (the cut call alone is 2.44 s; the
old ISOLATED took 38.5 s). That is enough because in Windows Firewall a Block
rule beats every Allow rule: on the VM, with the rule standing, `https://1.1.1.1`
and DNS were dead while all 135 of Windows' outbound Allow rules were still
enabled. Then a background worker does the thorough part (measured 59.3 s). A
default action stops only the traffic that no rule allows, and Windows ships
enabled outbound Allow rules (Core Networking's DNS, DHCP, Teredo, IP-HTTPS,
Group Policy, the Store apps' rules), so the worker switches off every enabled
outbound Allow rule of this machine that is not TDC's, records exactly which in
`webui/firewall_state.json` (`allow_disabled`) *before* it switches them, sets
the outbound default of every profile to Block and reads back which outbound
Allow rules are still enabled. When none is, the cut rule goes and the stage is
`isolated`, where TDC's own fetch can be let out again one address at a time.
A rule a group policy sets cannot be switched off locally: then the cut rule
stays, the stage is `cut_policy`, and the band and `allowed_out` of
`GET /api/firewall/isolate` name what it holds against. In `cut` and
`cut_policy` no fetch gets through, so TDC cannot secure a sample there.
`verified` says what was read back: in the cut stages, the cut rule as written,
read again from the rule list or one `Get` within 10 s; in `isolated`, Block in
force on every profile and the list empty. A firewall profile that is off makes
it false in every stage. A press on a state that is not confirmed closed cuts
again (and repairs a rule that was disabled or narrowed); on one that is, it
leaves, after a confirmation. Leaving works from any stage, also in the middle
of the background work, and switches exactly the recorded rules on again: from
`cut` that is two or three PowerShell calls, not measured (an estimate of about
2-10 s on a quiet VM from the per-call figures), measured 57.5 s from `isolated`
(135 rules back). What it
cuts, as far as those rules go: DNS, NTP, updates
(the tool updates refuse to run), and the cloud lookups and telemetry of the
EDR under test, whose verdicts may therefore differ from a connected run.
Loopback stays open without a rule (Windows Firewall does not filter it), and
the host still reaches port 9000, because that is inbound. While a press or a
leave of its own is on its way the button says CUTTING… or LEAVING… and waits;
it is never held because the background work runs. TDC's own fetch gets an allow rule for one address while it runs and
loses it when it ends; for those seconds anything that can run the web UI's
Python interpreter could reach that one address too. The band says so, and so
does `residual` in `GET /api/firewall/isolate`. The previous outbound default
is kept in `webui/firewall_state.json` too and put back when ISOLATED is
switched off: the value as configured, `NotConfigured` included, not the
`Allow` it resolves to in force, so the firewall is left configured as it was
found. A web UI that restarts in ISOLATED stays isolated and says so, in
the band and as a toast on whatever tab is open: a crash in the middle of a
detonation must not lift the block. The way out without the web UI is
`C:\tdc\scripts\tdc-unisolate.ps1` (`scripts/tdc-unisolate.ps1` here; `make
deploy` uploads it), run as Administrator in the VM: it opens the outbound
default on all three profiles (back to the recorded value when that is `Allow`
or `NotConfigured`, otherwise `Allow`; a recorded `Block` it names and leaves to
the analyst), switches on again the rules recorded in
`allow_disabled` (it only reads the file) and removes every `TDC-FW-*` rule,
nothing else.

![The FIREWALL tab with the network cut: a red band across the top with the time of the cut and the warning that TDC cannot secure a sample, CUT SECURING in red on the header switch and on the skull card, and 17 connections in the list, one tagged dga and one tagged dropped, while the summary reads BLOCKED 0](../static/firewall_cut.png)

> **The panic cut in force** (LIST view, 17 connections). The red band says
> when it started (2026-11-18 11:20:13), that one outbound Block rule for every
> program stands and was read back, that a Block rule beats every Allow rule and
> that loopback stays open, that **TDC cannot secure a sample in this state**
> because no fetch gets through a catch-all Block rule, and that Windows' own
> outbound Allow rules are being switched off in the background, the default
> set to Block, and then the rule goes. The header switch and the skull card
> both read `CUT · SECURING…` in red: one state, shown in two places. The
> table shows the tags `direct-ip`, one `dga` row (a defanged
> `a2-16-168-38`, `deploy`, `static`, `akamai` name, AKAMAI-ASN1, CC NL) and one `dropped`
> row (`hackepeter-2` 192.168.64.1:53 over UDP, 31 connections).
>
> **BLOCKED reads 0 here, and that is not a sign that nothing is blocked.**
> BLOCKED counts TDC's per-endpoint and per-process rules; the cut is neither,
> it is one catch-all rule, so the egress is shut while the counter stays at 0.

**Hunting further.** HUNT FURTHER lists ready LOGS searches for the selection,
each one click away; `in LOGS ▸` on a row, a point of the map or a toast opens
LOGS with the query and the time of those connections (5 minutes either side),
and `← FIREWALL` there leads back to the same selection.

- `dst_ip="203.0.113.7" | top image`: who else talks to this endpoint
- `source=netflow image="C:\Users\...\loader.exe" | timechart span=1m count by dst_ip`: the rhythm of a process
- `source=firewall action=DROP | stats count by dst_ip, dst_port`: what the firewall dropped
- `source=dns result="-" | top query`: names that never resolved, DGA suspects
- `source=powershell "http" | head 50`: download cradles in clear text

A network node in GRAPH has a FIREWALL button that opens this tab on that
endpoint, and so does the TRACING console for its process. Every action, the analyst's and TDC's own, is an
`access` event in LOGS (TDC's under `/internal/firewall/...`, with `by`:
`detector`, `analyst` or `deadline`).

On an **existing VM**, run `C:\tdc\scripts\configure-logging.ps1` once as
Administrator after `make deploy`: it also turns on the BITS client log the
download detection reads. The offline geo table travels with `make deploy`;
`make geoip` on the host only refreshes it.

The routes behind all of this are in the [API reference](api.md#firewall).

**Next:** [Tool updates](updates.md)
