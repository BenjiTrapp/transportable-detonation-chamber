# FIREWALL tab: handover for the first run on a real VM

Everything in the FIREWALL tab was written and tested on macOS, against mocked
Windows answers. **None of it has run on Windows yet.** This note is for
whoever first deploys it to a VM: what to do once, which screenshots to take,
and the list of assumptions about Windows that only a real VM can confirm.

## 1. Once, on an existing VM

A new VM gets all of this from provisioning. A VM that was provisioned before
the FIREWALL tab needs:

1. **`make deploy`, then `make restart`** (`.\make.ps1 deploy` on Hyper-V). The
   deploy now ships the five new modules (`firewall.py`, `firewall_fetch.py`,
   `firewall_rules.py`, `firewall_store.py`, `geoip.py`), `firewall_rules.ps1`,
   the data directories `webui/data/` (the offline geo index, about 9 MB) and
   `webui/static/data/` (the world map), and `scripts/tdc-unisolate.ps1` to
   `C:\tdc\scripts`. Without the restart the old `app.py` keeps running.
   `deploy-app` ships the same modules, data and `tdc-unisolate.ps1`, without
   the page assets.
   - The deploy overwrites the geo index while the web UI runs. That works
     because `geoip.load` maps a **copy** in `%TEMP%\tdc-geoip` (named after
     the source's size and mtime), never the file in `webui\data`; Windows
     refuses to overwrite a mapped file. A new index takes effect at the next
     start of the web UI.
2. **`C:\tdc\scripts\configure-logging.ps1`, once, as Administrator.** It turns
   on what the tab reads besides Sysmon: PowerShell script block and module
   logging, Windows Firewall logging of allowed and dropped packets
   (`pfirewall.log`), and now also the BITS client operational log (32 MB).
   Without it the tab still shows Sysmon's connections, but finds no download
   in a script or a BITS job, and `FW (endpoint)` and `dropped` stay empty.
3. **`make geoip` is not needed on the VM.** The geo index is committed in
   `webui/data/` and travels with the deploy. `make geoip` runs on the **host**
   (it needs internet) and only refreshes that index; each refresh adds a
   few-MB blob to git history, so do it rarely, then deploy. If the map says
   "No geo data ... run make geoip on the host and deploy again" after a
   deploy, the data directory did not arrive: check
   `C:\DetonationChamberUI\data\ip2asn-v4.idx`, rather than running `make geoip`.

The web UI tries to make `C:\tdc\samples` and its Defender exclusion at its own
start (provisioning does too). Whether the exclusion really holds is one of the
open Windows questions in Section 3: a failure is only logged.

## 2. Three screenshots

They can only be made on a running VM. The README references **none** of them
yet: `tests/test_docs.py::test_readme_images_exist_and_none_are_orphaned`
fails on a PNG in `static/` that the README does not use, and on a README
image that does not exist. So add each PNG and its reference **in the same
commit**, in the shape the LOGS section uses:

```html
<p align="center">
  <img src="static/firewall_tab.png" alt="..." width="100%">
</p>

> One or two sentences on what the picture shows.
```

| File | What it shows | Where in `README.md` |
|------|---------------|----------------------|
| `static/firewall_tab.png` | The tab during a detonation: the process tree with a detonated loader unfolded (its endpoints, tags and activity bars), MAP with arcs to a few countries, the summary below. A selected endpoint, so HUNT FURTHER shows its queries. | `## Firewall`, after the first paragraph (as `logs_tab.png` sits in `## Logs`) |
| `static/firewall_decision.png` | A decision toast with an open decision: the defanged URL, the countdown, CUT + FETCH, CUT ONLY, ALLOW and `in LOGS ▸`. Best over another tab, to show that it comes on every tab. | `## Firewall`, after the paragraph that ends "...so a sample cannot use TDC as its proxy." |
| `static/firewall_isolated.png` | ISOLATED on: the red ISOLATED switch and the band with what stays open (the per-fetch residual). | `## Firewall`, after the **ISOLATED** paragraph |

A detonation that makes such a picture without real malware: a submitted
PowerShell script that runs `Invoke-WebRequest http://<a public test host>/x.exe`
(a URL to an `.exe` in a script block, from a submission) opens a decision in
ASK `Detonation`.

## 3. What has never run on Windows

Gathered from the reports of Tasks 1-9 and the final review. For each: what to
check on the VM, and what breaks if the assumption is wrong. Most checks are
one command in an elevated PowerShell on the VM. Run them in this order: the
ISOLATED check, the curl and BITS decisions, blocking a running transfer, then
the rest.

### ISOLATED really closes (first)

`DefaultOutboundAction Block` stops only what **no** rule allows, and Windows
ships enabled outbound Allow rules (Core Networking's DNS above all). ISOLATED
therefore switches off every enabled local outbound Allow rule that is not
TDC's, records the names in `allow_disabled` of
`C:\DetonationChamberUI\firewall_state.json`, and switches exactly those on
again when it is left.

- **Nothing but TDC's own rules is let out.** *Check:* turn ISOLATED on; then
  `Resolve-DnsName example.com -DnsOnly` fails, and
  `Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound -Action Allow -Enabled True | Select Name, DisplayName, PolicyStoreSourceType`
  lists only `TDC-FW-ISO-*`. The band says "Read back: no outbound Allow rule
  but TDC's own is enabled", and `GET /api/firewall/isolate` has
  `allowed_out: []`. *If wrong:* DNS-tunnel C2 and DNS exfiltration still work
  in the one mode meant to stop them. If a rule is still listed, the band and
  `allowed_out` must name it (that half holds even when a rule resists); if
  the band says nothing while the command lists one, the read back is broken.
- **The way back is exact.** *Check:* note
  `(Get-NetFirewallRule -PolicyStore PersistentStore -Direction Outbound -Action Allow -Enabled True).Count`
  before ISOLATED, leave ISOLATED, count again: the same number, and
  `allow_disabled` in `firewall_state.json` is `[]`. Do it once more leaving
  through `C:\tdc\scripts\tdc-unisolate.ps1` instead of the UI (it prints one
  "Switched on again" line per rule). *If wrong:* Core Networking stays off
  after ISOLATED, and the VM has no DNS until someone notices.
- **`PolicyStoreSourceType` says `Local` for the built-in rules.** Only `Local`
  rules are switched off; any other source is only reported. *Check:* the
  command above shows `Local` for `CoreNet-DNS-Out-UDP`. *If wrong:* ISOLATED
  switches nothing off and the band lists every Windows rule as still open
  (honest, but not closed).
- **How long switching takes.** The Store apps bring dozens of outbound Allow
  rules; ISOLATED switches them in one PowerShell per ~6000 characters of names.
  *Check:* time `POST /api/firewall/isolate {on: true}`; it must stay well
  under `RUN_TIMEOUT_S` (90 s), and should be a few seconds.

### Processes and Sysmon

- **The ctypes process-time check** (`_process_started_at` in `webui/app.py`:
  `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)`, `GetProcessTimes`,
  `GetExitCodeProcess == STILL_ACTIVE`, run as SYSTEM).
  *Check:* during a detonation, `/api/firewall/connections` tags the
  submission's connections `detonated`, and KILL on a sample process asks for
  confirmation instead of answering "its start time cannot be read".
  *If wrong:* detonation windows close 60 s after the submission's timestamp
  instead of when the process ends (`FIREWALL_WINDOW_GRACE_S`), so a loader
  that downloads later is not "in a detonation" and ASK `Detonation` asks
  nothing; the fast 1 s collector tick stops early; and KILL refuses every PID
  (409).
- **A venv's `python.exe` is a launcher.** On Windows the venv's
  `Scripts\python.exe` starts the base interpreter (`sys._base_executable`, e.g.
  `C:\Python312\python.exe`), and the child owns the sockets.
  *Check:* the `Image` Sysmon EID 3 reports for the web UI's own connections and
  for a fetch (LOGS: `source=netflow image="*python*" | stats count by image`).
  *If wrong:* the fetch and the "never block TDC's fetcher" guard already name
  both binaries (`_fw_fetcher_paths`), so the fetch is covered. But
  `firewall.TDC_IMAGES` lists only the venv path: if Sysmon reports the base
  interpreter, the web UI's own traffic is not in the `TDC` group, carries no
  `tdc-anomaly`, and looks like any other process (it could be blocked by hand).
  Adding the base path to `TDC_IMAGES` would exempt every Python on the box, so
  it was deliberately not done blind.
- **Sysmon logs the connections a download needs.** SwiftOnSecurity's config
  logs EID 3 only for an include list; `install-sysmon.ps1` adds `curl.exe`,
  `python.exe`, `pythonw.exe` and `C:\Windows\System32\svchost.exe` (BITS) to
  it (`Set-NetworkConnectIncludes`). *Check:* `C:\tools\sysmon\sysmonconfig.xml`
  contains four `<Image name="TDC firewall tab" ...>` lines; then, with ASK on
  All, `curl.exe -o %TEMP%\x.exe http://<test host>/x.exe` and
  `bitsadmin /transfer t http://<test host>/y.exe %TEMP%\y.exe` must each open a
  decision. *If wrong:* a curl or BITS download never becomes a finding, and
  `tdc-anomaly` never fires because TDC's own python is not logged. If BITS
  still opens none, its connection is not reported as `svchost.exe`, and the
  BITS window logic of Task 3 serves nothing.
- **Sysmon field names for alerts** (`sigma` tag): `raw.destination.ip|address|port`
  and `raw.network.destination.*` are a reading of `app.py`; only the port keys
  were seen in code. *If wrong:* no connection ever gets `sigma`.

### BITS, PowerShell and the firewall log

- **The BITS `Url` field name** (EID 59/60 of
  `Microsoft-Windows-Bits-Client/Operational`, matched case-insensitively as
  `url`). *Check:* `bitsadmin /transfer t http://<host>/x.exe %TEMP%\x.exe`, then
  `wevtutil qe Microsoft-Windows-Bits-Client/Operational /c:2 /rd:true /f:xml`
  and look for `<Data Name='url'>`. *If wrong:* no BITS download is ever found;
  BITS (T1197) is then invisible as a download.
- **The BITS log is on** after `configure-logging.ps1` (`wevtutil gl
  Microsoft-Windows-Bits-Client/Operational` shows `enabled: true`). *If not:*
  same as above.
- **`pfirewall.log` and the `dropped` tag**: after `configure-logging.ps1`, a
  blocked connection shows `DROP` lines (LOGS: `source=firewall action=DROP`).

### Running `firewall_rules.ps1`

Every rule change goes through
`powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File firewall_rules.ps1 -Op <verb> ...`.

- **`exit 3` and `exit 4` under `-File`.** The script refuses `Create` with
  `exit 3` when a profile is off and `exit 4` when the rule exists.
  *Check:* with one profile off, `powershell -File firewall_rules.ps1 -Op Create
  -Name TDC-FW-test -Action Block -RemoteAddress 192.0.2.1; $LASTEXITCODE`
  prints `3`; a second identical call with all profiles on prints `4`.
  *If wrong:* a refusal reads as a plain failure (1) or as success (0): a block
  while a profile is off could be reported with the wrong reason, and the
  repair of an existing rule takes the wrong branch.
- **`-File` takes `$`, `;`, `"` and `,` in a value as text.** *Check:* a block
  of a program whose path holds a `;` or `$` creates exactly one rule with that
  path. *If wrong:* a hostile image path could become PowerShell code. This is
  the one security assumption on this list.
- **`-ExecutionPolicy Bypass` is allowed.** A policy set by GPO (MachinePolicy)
  overrides it. *If wrong:* every call fails: no rule, no ISOLATED, the tab says
  the rules cannot be read.
- **`Get-NetFirewallProfile -PolicyStore ActiveStore`** reports
  `DefaultOutboundAction` **per profile** as `Allow` / `Block` (and `Enabled` as
  `True` / `False`). *Check:* `Get-NetFirewallProfile -PolicyStore ActiveStore |
  Select Name, Enabled, DefaultOutboundAction`. *If it says `NotConfigured`* (the
  persistent store's word for "default"): ISOLATED's previous value is
  remembered as `NotConfigured` and put back as such (harmless), but the
  start-up check that decides whether an ISOLATED marker is still in force
  compares against `Block`; a misread makes it call a real isolation stale and
  clear the marker, or the reverse.
- **`AllowOut`, `DisableAllowOut` and `EnableAllowOut` under 5.1.** They were
  run only under PowerShell 7 on a Mac, against stub cmdlets. `-Names` is base64
  of a JSON list, decoded with `ConvertFrom-Json`. *Check:* `-Op AllowOut` gives
  `{"rules": [...]}` with zero, one and many rules; ISOLATED on and off with the
  checks above. *If wrong:* ISOLATED is refused ("could not be read; nothing was
  changed"), or the band says whether it is closed is unknown.
- **The `ConvertTo-Json` shapes** (Windows PowerShell 5.1). The script uses
  `-InputObject` and `@(...)` so that one profile or one rule is still a list,
  and `RemoteAddress` / `RemotePort` are arrays. *Check:* `-Op List` with zero,
  one and two `TDC-FW-*` rules, and `-Op Profiles`; each must be valid JSON with
  `rules` a list and `profiles` three objects. PowerShell 5.1 can wrap an array
  as `{"value": [...], "Count": n}`. *If wrong:* the rule list cannot be read:
  `rules_error` is set, nothing is claimed as blocked, and the switches show `?`.
- **Windows' spellings of a rule.** `Profile` (`Any`, or `Domain, Private,
  Public`), `Protocol` (`TCP` or `6`), `Program` (`Any` when none, the path's
  case), `RemoteAddress` (`1.2.3.4`, or with `/32` or `/255.255.255.255`). The
  read-back normalises these; that a rule written by `Create` reads back with
  `Profile: Any` and enabled is assumed. *Check:* block one endpoint, then
  `GET /api/firewall/rules` shows it with `blocking: true`.
  *If wrong:* `verified` is false, the flow never turns `blocked`, and every
  repeat block removes and rewrites the rule (the repair path).
- **An Allow rule with `-RemotePort` and `-Protocol`.** ISOLATED's per-fetch
  rule is `Create -Action Allow -Program <python> -RemoteAddress <ip>
  -RemotePort <port> -Protocol tcp`. *Check:* with ISOLATED on, answer a
  decision with CUT + FETCH; the capture appears, its `allow_closed` is `true`,
  and `Get-NetFirewallRule -Name 'TDC-FW-ISO-fetch-*'` is empty afterwards.
  *If wrong:* the fetch in ISOLATED fails (`allow_problem` says why) or the rule
  does not read back as written.
- **Loopback needs no allow rule** under `DefaultOutboundAction Block`. The rule
  `TDC-FW-ISO-loopback` is written anyway. *Check:* with ISOLATED on, every tab
  still works (Detonator 8000, Agent 8080, LitterBox 1337, Fibratus 8180).
- **The host still reaches port 9000 in ISOLATED** (an outbound default does not
  touch the answers to inbound sessions). *Check:* the web UI stays usable from
  the host with ISOLATED on. *If wrong:* ISOLATED locks the analyst out, and
  `C:\tdc\scripts\tdc-unisolate.ps1` from the VM console is the way back; run it
  once on purpose to see that it works.

### Blocking

- **A running connection starves when it is blocked.** The toast says so ("a
  running connection should starve; it gets no reset"), assuming Windows
  re-checks an established flow against a new Block filter. *Check:* start a
  long download from a test host (`curl.exe -o NUL --limit-rate 50k
  http://<test host>/big.bin`), block that endpoint from the tab, and the
  transfer must stall within a few seconds. *If wrong:* a block only stops new
  connections, the toast over-claims on every block, and the text must say so.
- **Detection to confirmed block.** A verified block is three to four PowerShell
  launches (Create with its own profile check, Get, Profiles, the List after it)
  behind `_fw_decision_lock`, after the 1 s tick (10 s for PowerShell script
  blocks) that saw the URL. *Check:* with ASK on All, note the time of a
  cradle's connection in LOGS and the `created_at` of its decision and of the
  block's read back in DECISIONS; put the number next to the README's "up to
  about ten seconds". *If longer:* the README states the real figure.

### The guarded fetch

- **`route print -4`'s columns.** The default gateway is taken from the line
  that starts with `0.0.0.0` (destination, mask, gateway, interface, metric).
  *Check:* `firewall_fetch.own_addresses(refresh=True)` in the web UI's Python
  contains the gateway (`ipconfig` shows it). *If wrong:* the gateway is not
  refused as a fetch target. The private-address refusal still covers it unless
  `TDC_FIREWALL_FETCH_LAN=1` is set.
- **`socket.getaddrinfo(socket.gethostname())` answers locally.** In ISOLATED
  DNS is blocked; if this call goes to DNS it can take a while. It runs at
  start-up and at most every 5 minutes, off the fetch's own deadline. *If slow:*
  a fetch that refreshes the list can be late.

### The secured samples and Defender

- **The Defender exclusion for `C:\tdc\samples`.** The web UI runs
  `Add-MpPreference -ExclusionPath C:\tdc\samples` at every start
  (`_ensure_capture_dir`), and only logs a failure. Tamper Protection, a
  policy-managed Defender or a Defender service that is not running can refuse
  it quietly. *Check:* after a web UI start, `Get-MpPreference | Select
  -ExpandProperty ExclusionPath` lists `C:\tdc\samples`; then let TDC fetch an
  EICAR test file and check that the file is still in
  `C:\tdc\samples\<sha256[:2]>\` a minute later, and that
  `GET /api/firewall/capture/<id>` says `exists: true`. To get one: on the host,
  `printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > eicar.exe`
  and `python3 -m http.server 8081` in that directory; start the web UI with
  `TDC_FIREWALL_FETCH_LAN=1` (the host is a private address, refused
  otherwise), set ASK to All, and in the VM run
  `powershell -c "iwr http://<host ip>:8081/eicar.exe -OutFile $env:TEMP\e.exe"`;
  answer CUT + FETCH. Unset `TDC_FIREWALL_FETCH_LAN` afterwards. *If wrong:*
  Defender quarantines every fetched stage-2, which is the one output of the
  download path; the capture's metadata stays, its file is gone, and nothing
  says why. Add the exclusion by hand or by policy.
- **Other EDRs.** The exclusion is Defender's only. An EDR under test (the
  reason TDC exists) may quarantine or delete files in `C:\tdc\samples`
  regardless. *Check:* the same EICAR run with each EDR the lab uses installed.
  *If wrong:* that EDR's runs lose their captures; give it an exclusion of its
  own, or say in the run's notes that captures are not kept under it.

### Load and policy

- **The collector's process load.** Every process TDC starts for the tab, and
  how often:
  - `wevtutil` for Sysmon (EID 1, 3, 22) and the BITS log every second during a
    detonation window, every 10 s outside one; the PowerShell log every 10 s
    (the firewall log is a file read, no process).
  - `powershell -Op List` (the TDC rules): at most once a minute
    (`FIREWALL_RULES_TTL_S`, shared by LIVE ticks, `/summary`, every tab's
    `/pending` poll and the sweep), and once after each block, unblock,
    decision, fetch rule, ISOLATED switch or TURN THE FIREWALL ON. While
    ISOLATED is on, the sweep's own `List` once a minute too.
  - `powershell -Op Profiles`: at most once a minute for `GET /isolate` (every
    10 s after an error), and fresh in every enforcement route.
  - `powershell -Op AllowOut`: at most once a minute while ISOLATED is on.
  - Per decision: Create, Get, Profiles and the List after it.
  None was measured. *Check:* during a detonation with the tab open on LIVE and
  a second browser tab open, watch the web UI's Python and its children for a
  minute (Task Manager, or `Get-Process wevtutil, powershell`). **Too high**
  is more than 10 % of one core for the web UI's Python with its children,
  averaged over that minute, or more than one `powershell.exe` started per
  10 s on average with no decision open. *If too high:* the sample runs on a
  busier box than it would, and timing-sensitive samples may notice; the fast
  tick's sources can be split further (`firewall_store.py`).
- **Classifying a full window.** `/connections` and `/summary` each classify
  the whole range (the beaconing test per flow) and read `captures.json`
  twice. *Check:* with range All and the ring near its 50 000 connections, time
  `GET /api/firewall/connections?max=5000`. **Too slow** is more than 1 s:
  LIVE then overlaps itself.
- **TURN THE FIREWALL ON under a managed profile.** `Set-NetFirewallProfile
  -Enabled True` may be overridden by a GPO. What the route then does has not
  been seen: the expectation is a 500 with the profiles still off, which the
  band shows. *Check, on a VM without a GPO:* switch one profile off in Windows
  Defender Firewall, press TURN THE FIREWALL ON once, and see the red band go.
  *Open question, only on a VM with a firewall GPO:* does the route answer 500
  and does the band stay? If it answers 200 with a profile still off, the
  route's read back is wrong.

### Deploy

- **`make deploy` while the web UI runs** overwrites `webui\data\*.idx`
  (Section 1). *Check once:* deploy twice in a row with the web UI running; no
  upload of an `.idx` fails, and `%TEMP%\tdc-geoip` (as SYSTEM:
  `C:\Windows\Temp\tdc-geoip`) holds one copy of each index. *If wrong:* the
  deploy of the index fails while the web UI runs, and a new index needs the
  web UI stopped first.

## 4. Limits that are by design, not bugs

So that nobody files them:

- **No byte counts.** Sysmon has none; the tab counts connections and firewall
  records (Part B's proxy would add them).
- **Seen after the fact.** During a detonation Sysmon and BITS are read every
  second, PowerShell and the firewall log every 10 s; outside one, everything
  every 10 s. A download in a PowerShell script needs the URL and the
  connection, so a cradle can be found, and its loader blocked, up to about
  10 s after the connection. A download decision blocks first and asks then. A
  compiled loader that calls WinHTTP shows no URL.
- **A Windows Update BITS job during a detonation counts as the detonation's.**
  The BITS log does not name who asked, so a BITS job for an executable while a
  submission runs is `in_detonation`; under ASK `Detonation` its `svchost.exe`
  gets a block to that address and a decision is opened. Deliberate: without it
  BITS (T1197) would be invisible as a download path. Update hosts that TDC
  knows are never asked about.
- **"blocked" ignores the protocol.** A tcp rule makes a udp flow to the same
  endpoint read as blocked; the UI shows the rule's protocol beside the claim.
- **ISOLATED's residual.** While a fetch runs, anything that can run the web
  UI's Python could reach that one address for those seconds. An outbound
  Allow rule a group policy sets cannot be switched off locally; it is named in
  the band and in `allowed_out`, and ISOLATED is then not `verified`.
- **ISOLATED changes what the EDR under test can do.** No cloud lookups, no
  telemetry upload: compare its verdicts only with other isolated runs.
- **A loader that runs as TDC's base Python is never blocked**, because a block
  on that program would cut TDC's own fetch off; its toast says NOT confirmed.
- **The MCP server only reads** (`tdc_firewall_connections`,
  `tdc_firewall_captures`): no tool blocks, isolates, decides, kills or turns
  the firewall on.
