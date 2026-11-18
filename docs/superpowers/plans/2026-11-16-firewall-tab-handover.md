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
panic cut, the ISOLATED check, the curl and BITS decisions, blocking a running
transfer, then the rest.

### The panic cut (mandatory, first)

The switch-on path of ISOLATED is now two stages, specified in
`docs/superpowers/specs/2026-11-17-panic-cut-design.md`. A press writes **one**
catch-all outbound Block rule, `TDC-FW-ISO-cut`, and returns with `stage: "cut"`
after 8.8 s on a quiet machine, 9.9-16.9 s while the tab's own polls load it (the
old path, 135 rules switched off one by one, took 38.5 s; see the open point on
the call budget at the end). A
background worker, `converge`, then does what ISOLATED always did, so that a
per-fetch Allow exception is possible again: when `allowed_out` comes back empty
the cut rule is dropped and the stage is `isolated`; when it does not (a group
policy Allow rule), the cut rule stays and the stage is `cut_policy`.

**These checks are mandatory, not optional.** The reason is one, and it holds for
every item below: the fake PowerShell runner in the tests does not model WFP
semantics. It cannot know that a Block rule beats an Allow rule, so **no test on
macOS can prove that the cut works**. That same blindness let the original
"default deny" ship while 135 Allow rules stayed enabled. What was measured on the
VM before the design (below) is evidence for the design; it is not a check of
what was built. Do all eight on the finished build.

Measured on the Windows 11 ARM VM (135 local outbound Allow rules, 2026-11-17),
for what to expect:

| Measured | Result |
|---|---|
| One catch-all Block rule written and read back, one PowerShell call | 2.13 s (hand-written script); the finished `Cut` verb alone 2.44-2.49 s (two quiet-moment runs) |
| `Profiles` alone | 1.13-1.65 s (two quiet-moment runs); 2.10 s under load in the first run |
| The press end to end (profiles read first, then the cut), quiet | 8.8 s |
| The same press while the tab's polls load the machine | 9.9-16.9 s (inside it: `Profiles` 5.66 s, `Cut` 7.29 s; lock wait 0 ms) |
| Convergence until `stage: "isolated"` | 59.3 s |
| Leaving from `isolated` (135 rules back) | 57.5 s |
| Repairing a rule of that name that was **disabled** | 5.92 s |
| Repairing one **narrowed** to one program and address | 3.38 s |
| With the cut standing: `curl https://1.1.1.1` | `http=000`, instantly |
| With the cut standing: DNS | dead |
| With the cut standing: `curl http://127.0.0.1:9000` | `http=200` (Windows does not filter loopback) |
| After removing the cut | `http=301`, DNS back |
| The old full ISOLATED cycle | 38.5 s on, 41.4 s off |

The rows about the cut standing held **while all 135 Allow rules were still
enabled**; that is the point of the design.

1. **Time to `stage: "cut"`.** *Check:* time
   `POST /api/firewall/isolate {"on": true}` from the request to the answer; the
   answer carries `stage: "cut"`, `verified: true`, `converging: true`. It must be
   **≤ 12 s**, the spec's ceiling; measured 8.8 s. Do it with the three profiles
   on, no `TDC-FW-ISO-cut` present, and **no browser polling the FIREWALL tab**
   (closed, or LIVE off): the threshold is for a quiet machine. With the tab open
   on LIVE the same press measured 9.9-16.9 s, because the tab's polls cost more
   than their interval; that is the open point on the call budget at the end of
   this document, not a regression of the cut, and until that point is fixed the
   figure under load is written down, not asserted. *If wrong (quiet, above
   12 s):* the button is not a panic button again. Look in
   `webui/logs/firewall-calls.log` at which of the two PowerShell calls it is
   (`Profiles`, then `Cut`): alone 1.13-1.65 s and 2.44-2.49 s. A repair of a
   falsified rule (item 7) is slower by design and does not count here.
2. **The egress is shut while the cut stands.** *Check:* right after the answer of
   item 1, while `converging` is still `true` (the Allow rules are still mostly
   enabled; that is what is being tested):
   `Resolve-DnsName example.com -DnsOnly` fails;
   `curl.exe -s -o NUL -m 5 -w "%{http_code}" https://1.1.1.1` prints `000` at
   once, not after the timeout; `curl.exe -s -o NUL -w "%{http_code}"
   http://127.0.0.1:9000` prints `200`. *If wrong:* the cut does not close, or
   closes the UI as well. In the first case the band must not say closed:
   `verified` is only "the cut rule was read back" (and read again, from the rule
   list or one `Get`, within 10 s), so a rule that reads back and does nothing is
   exactly what this check exists to catch. Repeat it once more in
   `cut_policy` if the VM has a group-policy Allow rule: the cut stays and must
   still close.
3. **Time to `stage: "isolated"`, and the cut is gone by then.** *Check:* poll
   `GET /api/firewall/isolate` after item 1 until `stage` is `isolated`; note the
   time. At that moment `Get-NetFirewallRule -Name TDC-FW-ISO-cut` finds nothing,
   `allowed_out` is `[]`, `converging` is `false`, DNS is still dead, and the
   `Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound -Action Allow
   -Enabled True` check of the section below lists nothing. Run
   `curl.exe -s -o NUL -m 2 -w "%{http_code}\n" https://1.1.1.1` in a loop from
   before the press until after this stage: it must never print anything but
   `000`, in particular not at the moment the cut rule falls (the Allow rules are
   switched off and the default is Block *before* the cut is dropped). The old
   path took 38.5 s; the whole convergence was **measured at 59.3 s** on the
   finished code. Write down what you see. *If it stays `cut`:* the worker failed and the band must say why (the cut
   stands and the egress is shut, which is the safe side). *If it stays
   `cut_policy`:* `allowed_out` names the rule and its store.
4. **Leaving in the middle of the convergence.** *Check:* press ISOLATED on; 5-10 s
   later, while `converging` is `true`, read `allow_disabled` in
   `C:\DetonationChamberUI\firewall_state.json` (it is written before the first
   switch is flipped, and may still be empty), then `POST /api/firewall/isolate
   {"on": false}`. It must **not** wait for the whole convergence: the worker
   stops between its PowerShell calls and the leave takes its normal path, so the
   time is the running call plus a normal leave, not the convergence's remaining
   time on top. Then **every rule named in `allow_disabled` is enabled again**
   (compare with the list read before leaving, and with the section below's
   count), `allow_disabled` is `[]`, no `TDC-FW-ISO-*` rule is left, `converging`
   is `false` and does **not** turn `true` again afterwards (a worker that kept
   running would switch the Allow rules off again behind the leave), and DNS
   works. Do it at least twice, at different moments (also right after the press,
   before the first rule is switched). *If wrong:* a leave that waits is a cut
   that cannot be undone for a minute; a rule left off is the VM without DNS,
   which is the failure the section below is about. No figure was measured for a
   leave in the middle of the convergence (a leave from `isolated` took 57.5 s):
   write down the time of the leave.
5. **The round trip.** *Check:* before the press, record
   `(Get-NetFirewallProfile -PolicyStore PersistentStore | Select Name,
   DefaultOutboundAction)` and the names
   `Get-NetFirewallRule -PolicyStore PersistentStore -Direction Outbound -Action Allow
   -Enabled True | Sort Name | Select -Expand Name` (135 on this VM). On a VM where
   the profiles are `NotConfigured`, ISOLATED records `outbound_before:
   "NotConfigured"`. Press on, wait for `isolated`, press off, and record both
   again: `DefaultOutboundAction` is back to the **configured** value, so
   `NotConfigured` is `NotConfigured` and **not** `Allow`; the 135 names are
   identical (`Compare-Object` prints nothing); `Get-NetFirewallRule -Name 'TDC-FW-*'`
   finds nothing (on a VM with no rule blocked by hand). Do it again leaving
   through `C:\tdc\scripts\tdc-unisolate.ps1`. *If wrong:* the host is left
   configured differently from how it was found, which is the one property of this
   feature that was proven on the VM and must not be lost.
6. **A restart in stage `cut` changes nothing.** *Check:* press on and restart the
   web UI (`make restart`, or stop the process) while `stage` is still `cut`, within
   a few seconds. After the start: `GET /api/firewall/isolate` says `stage: "cut"`,
   `TDC-FW-ISO-cut` is still standing, the marker in `firewall_state.json` is
   **not** cleared, `allow_disabled` is as it was, the egress is still shut (item 2's
   commands), and the convergence is **not** resumed by itself (`converging` stays
   `false`; the analyst decides to leave or to press again). Then leaving restores
   everything as in item 5. *If wrong:* the start treats "marker set, no profile on
   Block" as stale, switches the Allow rules back on and clears the marker, with the
   cut rule still standing: the state this design exists to avoid, and the one a
   crash in this stage leaves.
7. **The repair path.** *Check:* with ISOLATED off, make the rule wrong by hand,
   then press, once for each shape:
   - **Disabled:** `New-NetFirewallRule -Name TDC-FW-ISO-cut -DisplayName x
     -Direction Outbound -Action Block -Enabled False`.
   - **Narrowed:** `New-NetFirewallRule -Name TDC-FW-ISO-cut -DisplayName x
     -Direction Outbound -Action Block -Program C:\Windows\System32\notepad.exe
     -RemoteAddress 192.0.2.1` (a program and an address that do not include
     `1.1.1.1`, so the egress is open before the press).

   With the `curl` loop of item 3 running from before the press: the press ends
   with `stage: "cut"`, `verified: true`, the rule is the catch-all
   (`Get-NetFirewallRule -Name TDC-FW-ISO-cut | Get-NetFirewallApplicationFilter,
   Get-NetFirewallAddressFilter`: `Program Any`, `RemoteAddress Any`, enabled,
   `Profile Any`, `Block`, `Outbound`), and once the loop prints `000` it **never
   prints anything else** again: the repair must not remove the rule and write a new
   one (a gap with an open egress). Measured: **5.92 s** for the disabled rule,
   **3.38 s** for the narrowed one, both ending with the egress shut. That is slower
   than item 1 and is why the UI must not promise two seconds here. Leave
   afterwards, and check that `TDC-FW-ISO-cut` is gone. *If wrong:* a falsified
   cut rule is read as "cut", or repaired through a moment of open egress.
8. **A profile switched off after a cut.** *Check:* press on; once `stage: "cut"`
   (and again once `isolated`), switch one profile off with
   `Set-NetFirewallProfile -Profile Public -Enabled False`. Nothing may read as
   confirmed closed: `verified` is `false`; the skull button reads
   `CUT · FIREWALL OFF` and is **disabled**, with the reason in its title; the
   header switch shows the same state, not another one; and the red band offers
   `LEAVE ISOLATED` next to `TURN THE FIREWALL ON`, and that button works
   (it asks first, and gives the firewall back as found). Then switch the profile
   on again and see the state read confirmed again. *If wrong:* a rule that stands
   and reads back but does nothing is called closed (the same finding as the
   loopback block), or the panic button turns into a "reopen the network?" dialog
   in exactly the state where a reflexive yes throws the marker and the baseline
   away.

**To watch, not to assert: a deadline during a convergence.** Found in review, not
yet seen on a VM. A decision deadline that falls due while `converge` is running
stalls the sweep, and with it the collector, for tens of seconds. The deadline's
per-program block waits on the rules module's lock, which the convergence holds
across its PowerShell calls, and it waits inside `_fw_decision_lock`. A deadline
shortly after a press nearly always coincides with the convergence that follows
it, so in the cut this is the common case, not a corner case. A newly detected
download (`_fw_open_decision`, which blocks the loader first and asks then) waits
on the same lock in the same way. *What to look for:* press ISOLATED on during a
detonation with ASK on `Detonation` (or All) and a short decision deadline, and let
a decision open or fall due in the first minute. Watch for the LIVE list not
advancing (the newest connection ages while the sample is active), `/connections`
and `/pending` answering late, and the gap between a decision's `created_at` or
deadline and its block's `BLOCK` line in LOGS. By reading the code,
an analyst's answer to a decision takes `_fw_decision_lock` too, so a CUT ONLY or
ALLOW pressed in that window may hang as well: that is an inference, look for it.
Write down how long the stall lasts. It does not open anything (the cut stands and
the egress stays shut); the cost is that the tab is blind for that time.

### ISOLATED really closes

The text below is the old description of the whole of ISOLATED, written before the
panic cut. It still holds for the **end state** (stage `isolated`) and for the way
back. Where it speaks of how ISOLATED is switched **on** (the number of PowerShell
calls, how long switching takes), the panic cut above replaces it.

`DefaultOutboundAction Block` stops only what **no** rule allows, and Windows
ships enabled outbound Allow rules (Core Networking's DNS above all). ISOLATED
therefore switches off every enabled local outbound Allow rule that is not
TDC's, records the names in `allow_disabled` of
`C:\DetonationChamberUI\firewall_state.json`, and switches exactly those on
again when it is left.

- **Nothing but TDC's own rules is let out.** *Check:* turn ISOLATED on and wait for
  `stage: "isolated"`; then
  `Resolve-DnsName example.com -DnsOnly` fails, and
  `Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound -Action Allow -Enabled True | Select Name, DisplayName, PolicyStoreSourceType`
  lists nothing, or only a `TDC-FW-ISO-fetch-*` rule while a fetch runs
  (ISOLATED writes no rule of its own any more). The band says "Read back: no outbound Allow rule
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
- **How long switching takes.** *Superseded for switching on:* a press now cuts in
  8.8 s on a quiet machine (9.9-16.9 s under the tab's polling) and the thorough
  work below runs in the background (see "The panic cut");
  the figures here are those of the whole convergence and of leaving.
  ISOLATED on was four PowerShell calls (AllowOut,
  DisableAllowOut, SetDefaultOutbound, AllowOut), off is three
  (SetDefaultOutbound, EnableAllowOut, RemoveIsolate); the rules go through one
  pipeline per call (one call per ~6000 characters of names). *Check:* time
  `POST /api/firewall/isolate` both ways; it must stay well under
  `RUN_TIMEOUT_S` (90 s). While it runs the button reads CUTTING… / LEAVING…
  and an info toast says why it takes a while. **Measured** on the Windows 11
  ARM VM (135 local outbound Allow rules, 2026-11-17): **41.9 s on, 30.1 s
  off**. That is the expected figure, not a hang: switching that many rules is
  slow on Windows even in one pipeline per call.
- **What is put back is what was configured.** The baseline is read from the
  PersistentStore (`Configured` in `-Op Profiles`), the store
  `SetDefaultOutbound` writes; the ActiveStore (what is in force) answers
  whether ISOLATED holds. *Check:* with all three profiles `NotConfigured`
  (`Get-NetFirewallProfile -PolicyStore PersistentStore | Select Name,
  DefaultOutboundAction`), ISOLATED on records `outbound_before:
  "NotConfigured"`, the ActiveStore shows `Block`, and after leaving the
  PersistentStore shows `NotConfigured` again, not `Allow`. *If wrong:* the
  host is left configured differently from how it was found.

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
  it (`Set-NetworkConnectIncludes`), each as a `Rule` with
  `<Initiated condition="is">true</Initiated>`, so only their outbound
  connections are logged. *Check:* `C:\tools\sysmon\sysmonconfig.xml` contains
  four `<Rule name="TDC firewall tab: ...">` entries and `sysmon -c` accepted
  the config; browse the web UI from the host for a minute and no `tdc-anomaly`
  appears on a python flow (an accepted connection must not read as TDC's own
  outbound traffic); then, with ASK on
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
- **Loopback needs no allow rule** under `DefaultOutboundAction Block`: Windows
  Firewall does not filter loopback, and Windows refuses `::1` as a
  RemoteAddress, so ISOLATED writes none. *Check:* with ISOLATED on, every tab
  still works (Detonator 8000, Agent 8080, LitterBox 1337, Fibratus 8180), and
  `Test-NetConnection 127.0.0.1 -Port 8000` succeeds. *If wrong:* TDC's own
  services cannot reach each other in ISOLATED; the egress stays shut, so
  leave ISOLATED (the web UI is reached inbound) or run the hatch.
- **The host still reaches port 9000 in ISOLATED** (an outbound default does not
  touch the answers to inbound sessions). *Check:* the web UI stays usable from
  the host with ISOLATED on. *If wrong:* ISOLATED locks the analyst out, and
  `C:\tdc\scripts\tdc-unisolate.ps1` from the VM console is the way back; run it
  once on purpose to see that it works.

### Reads without the NetSecurity module (`-Op Compare`)

The read verbs of `firewall_rules.ps1` (`Profiles`, `List`, `Get`, and the
rule read behind them) no longer load the NetSecurity module. **COM**
(`HNetCfg.FwPolicy2`) answers what is **in force**; **CIM** (`MSFT_NetFirewall*`)
answers what is **configured**. That split is forced, not chosen: COM has no
representation for `NotConfigured`, and raw CIM cannot reach the ActiveStore
(`root/standardcimv2/ActiveStore` answers "Ungültiger Namespace"; raw CIM
reports `PolicyStoreSource=PersistentStore` for all 538 rules). Every number
and name is mapped from an exhaustive written-out list; anything not on it
throws into a fallback onto the old cmdlet path. The fallback is never silent:
`Via` and a one-line `Fallback` reason reach the call log.

- **`Compare` is a mandatory VM check, and no test on macOS replaces it.** It
  is a verb in the script, not a test harness, so it runs on any VM, including
  one with group policies. It reads both paths **independently** and compares
  them field by field; it prints `ok` and exits 0, or exits 1 on any
  difference. The fake runner of the tests cannot know what COM and CIM say, so
  only this run can show that they say what the cmdlets say. *Check:*
  `powershell -File firewall_rules.ps1 -Op Compare; $LASTEXITCODE` in each of
  the five states below. *If a field differs:* the fast path is wrong, and the
  tab stays correct only because the read falls back to the cmdlets: slow, and
  visible as `Fallback` in the call log.

  Final run, all five green:

  | State | Compare | Fields checked | What it confirms |
  |---|---|---|---|
  | A: nothing isolated; an IPv4 **and** an IPv6 rule, each with port and program | exit 0 | 51 | both address spellings, port, program path |
  | B: the cut standing | exit 0 | 30 | the catch-all: protocol Any, program Any, address Any |
  | C: converged (Block on all three profiles) | exit 0 | 9 | COM action `0` = Block, CIM `Block` |
  | D: Domain explicitly `Allow` | exit 0 | 9 | CIM `Allow` |
  | E: Domain `Allow`, Private `NotConfigured`, Public `Block` | exit 0 | 9 | **COM profile numbers 1 / 2 / 4 = Domain / Private / Public** |

  **Why D and E exist.** A to C left two holes: all three profiles normally
  stand identical on that VM, and none of the three configures a profile
  explicitly as `Allow`. CIM's `Allow` form and the profile numbering would
  have gone unchecked; a swapped number would have shown only as swapped rows,
  and only with three different states at once. Put everything back to
  `NotConfigured` afterwards, as the VM was found.

- **Two assumptions the gate disproved.** Both were found only by running it,
  and neither could have been found on macOS; they are what the gate is worth.
  1. *CIM hands back the action as a **name*** (`NotConfigured` / `Allow` /
     `Block`), not only as a number. An earlier probe of the same class on the
     same VM printed numbers, through a different access path; the cause is
     unknown. So **both forms are accepted**, each written out, with exact-case
     matching (a PowerShell hashtable ignores case, so `block` would otherwise
     have slipped through unlisted).
  2. *COM writes a single address of either family as a range to itself*:
     `1.1.1.1-1.1.1.1` and `2606:4700:4700::1111-2606:4700:4700::1111`, where
     the cmdlets say `1.1.1.1` and `2606:4700:4700::1111`. A range with
     **different** endpoints still throws, because collapsing it would
     misstate what the rule covers.

  Through every failing run the tab stayed correct: the reads still answered on
  the cmdlet path. That is the fallback working as designed.

- **`AllowOut` was deliberately NOT converted. This is the most important
  line of this section.** Raw CIM answers from the PersistentStore. On a host
  with group-policy rules the ActiveStore holds rules the PersistentStore does
  not, and those would be **missing from `allowed_out` entirely**: ISOLATED
  would report *closed* while they still let traffic out. On the project's VM
  this is invisible, because it has no group-policy rules at all. The counts
  there agree exactly (cmdlet ActiveStore 135, cmdlet PersistentStore 135, raw
  CIM 135), which is precisely why the trap is dangerous. The pin test
  `test_allowout_stays_on_the_cmdlets_because_cim_cannot_read_the_activestore`
  holds it. `AllowOut` did not appear in the measured steady-state load.
  *Do not convert it without a way to read the ActiveStore.*

- **Measured before and after** (VM, unloaded):

  | | before | after |
  |---|---|---|
  | one read, fresh process (`Profiles`) | 1.65 s | **0.59 s** |
  | `List` | 1.65 s | **0.56 s** |
  | `Get` | 1.65 s | **0.58 s** |
  | bare `powershell.exe -Command exit` (the floor) | 0.36 s | not applicable |
  | calls per 100 s of a watching tab | 5 | **2** |
  | `powershell.exe` busy | 18 % | **3.3 %** |
  | fallbacks in that window | not applicable | **none** (`{'fast': 2}`) |

  **The timings are also the proof that the module is not loaded.** A module
  load costs about 1.3 s on its own (0.36 s bare against 1.65 s with it), so a
  verb answering in 0.6 s cannot have loaded it. A separate module check is not
  needed, and an attempt to make one by inspecting a child process is
  meaningless: the child's module state is gone when it exits.

- **What this VM cannot prove.**
  - **The Local / GroupPolicy distinction**, because it has no group-policy
    rules. The run shows only that nothing is mis-reported as policy and no
    rule is lost. *One local GPO outbound Allow rule would prove it.*
  - **Never exercised, because TDC does not write them:** an inbound rule (COM
    direction `1`), rules limited to one or two profiles (masks `1` to `6`),
    and UDP (`17`). If any appears, that read falls back to the cmdlets, so
    nothing is misreported.
  - **CIM's numeric form on this script's path** never appeared. Both forms
    are accepted anyway.

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
  - `powershell -Op List` (the TDC rules): at most once a minute through the
    cache (`FIREWALL_RULES_TTL_S`, shared by LIVE ticks, `/summary`, every tab's
    `/pending` poll and the sweep), plus one forced read by `/rules` on every
    slow tick of LIVE (every 30 s), and once after each block, unblock,
    decision, fetch rule, ISOLATED switch or TURN THE FIREWALL ON. While
    ISOLATED is on, the sweep's own `List` once a minute too.
  - `powershell -Op Profiles`: at most once a minute for `GET /isolate`, every
    10 s while ISOLATED is on or after an error, and fresh in every enforcement
    route.
  - `powershell -Op AllowOut`: every 10 s while ISOLATED is on, in stages
    `isolated` and `cut_policy`.
  - `powershell -Op Get` of the cut rule: in stages `cut` and `cut_policy`, once
    per 10 s for `GET /isolate` when neither the press's read-back nor the rule
    list is younger than that.
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
- **Loopback cannot be blocked.** Windows Firewall does not filter loopback
  (seen on the VM: a "verified" rule for curl.exe to 127.0.0.1 let curl through
  with HTTP 200), so TDC refuses a block on `127.0.0.0/8` or `::1`, for one
  program and for all, and a download from a loopback address opens a decision
  whose block says why it was not written. To stop such a process: block it
  everywhere, or KILL it.
- **"blocked" ignores the protocol.** A tcp rule makes a udp flow to the same
  endpoint read as blocked; the UI shows the rule's protocol beside the claim.
- **ISOLATED's residual.** While a fetch runs, anything that can run the web
  UI's Python could reach that one address for those seconds. An outbound
  Allow rule a group policy sets cannot be switched off locally; it is named in
  the band and in `allowed_out`, and the cut rule then stays (stage
  `cut_policy`): closed and `verified`, but no fetch gets through.
- **ISOLATED changes what the EDR under test can do.** No cloud lookups, no
  telemetry upload: compare its verdicts only with other isolated runs.
- **A loader that runs as TDC's base Python is never blocked**, because a block
  on that program would cut TDC's own fetch off; its toast says NOT confirmed.
- **The MCP server only reads** (`tdc_firewall_connections`,
  `tdc_firewall_captures`): no tool blocks, isolates, decides, kills or turns
  the firewall on.
- **A disabled or narrowed `TDC-FW-ISO-cut` can outlive a cleared marker.** At
  start-up, a marker with no profile on Block and a cut rule of the wrong shape
  is read as stale: the marker is cleared and that rule stays. It opens nothing
  (a disabled rule blocks nothing, a narrowed one only part of the egress), the
  old code did the same, and the next press repairs it in place.

## Offener Punkt: die Aufruf-Bilanz des Tabs (gefunden beim Panikschnitt)

Das Aufruf-Log (`webui/logs/firewall-calls.log`, eine Zeile je
PowerShell-Aufruf mit Verursacher, Wartezeit auf die Sperre, Laufzeit und
Exit-Code) hat beim ersten VM-Lauf des Panikschnitts etwas aufgedeckt, das
**nicht** zu diesem Feature gehört, sondern zum ganzen FIREWALL-Tab:

- `GET /api/firewall/isolate` löst `Profiles` **und** `AllowOut` aus — gemessen
  3,5–7,2 s bzw. 6,1 s.
- `GET /api/firewall/connections` und `/rules` lösen je ein `List` aus — 3,5–9,4 s.
- Die Oberfläche fragt im LIVE-Betrieb **alle 5 Sekunden**.

Die Abfragen sind damit teurer als ihr Intervall. Mehrere `powershell.exe`
laufen dauernd gleichzeitig und bremsen sich gegenseitig: dieselbe Operation
kostet allein 2,44 s und unter dieser Last 7,29 s. Gewartet wird dabei auf
**keine** Sperre (`wait_ms=0.0`) — es ist reine Gleichzeitigkeit.

Folgen, die man sieht: der Panikdruck braucht auf einer ruhigen Maschine
einstellige Sekunden und unter Last bis 17 s, obwohl der Schnitt selbst 2,44 s
ist. Und jede Zahl, die die Oberfläche über Zeiten verspricht, hängt an dieser
Bilanz.

Was dagegen zu tun wäre (eigene Arbeit, nicht Teil des Panikschnitts):

1. Eine Abfrage darf nicht synchron auf einem PowerShell-Aufruf warten. Der
   Zustand liefert, was bekannt ist, mit seinem Alter („vor 8 s gelesen"), und
   ein Hintergrund-Auffrischer hält ihn aktuell.
2. `Profiles`, `AllowOut` und `List` teilen sich einen Cache mit einem
   gemeinsamen Auffrischer, statt dass drei Routen sie unabhängig anfordern.
3. Nie zwei gleiche Aufrufe gleichzeitig: wer schon unterwegs ist, wird
   abgewartet, nicht verdoppelt. Das gilt auch für das `Get` der Schnitt-Regel,
   das dieser Branch hinzugefügt hat (siehe unten): es ist **je Anfrage**, nicht
   je Server — zwei gleichzeitige `GET /isolate` starten je eines, mit N offenen
   Tabs also bis zu N in einem 10-s-Fenster.
4. Erst danach ist eine Zielzahl für den Druck wieder sinnvoll — und sie lässt
   sich dann aus dem Log belegen.
5. **Die Konvergenz hält `_LOCK` für ihren ganzen Lauf** (gefunden im
   Abschluss-Review, breiter als der Abschnitt „To watch, not to assert" oben
   ihn beschreibt). Hinter ihr warten nicht nur die Frist einer Entscheidung und
   ein neu erkannter Download, sondern auch die Antwort eines Analysten (CUT
   ONLY / ALLOW) und ein manuelles `/block` — und der Tab ist in der Minute nach
   einem Druck blind, denn die Konvergenz dauert gemessen 59,3 s. Es öffnet
   nichts (der Schnitt steht), kostet aber Sicht und Handlung genau dann, wenn
   ein Ausbruch läuft. *Vorgeschlagene Richtung:* eine eigene Sperre „ein
   Isolations-Lauf" für die Exklusivität gegen Druck und Verlassen, und `_LOCK`
   nur noch **je Schritt** nehmen, damit ein `block()` zwischen zwei Schritten
   der Konvergenz durchkommt. Nicht umgesetzt.
6. **Der Regel-Cache kennt keine Generation, und `_fw_rules()` hält seine Sperre
   über das ganze `List`** (zwei geparkte Befunde, ein Mechanismus, ein Fix).
   Eine Abfrage, die ihr `List` vor einem Schreiben begann und nach dem Leeren
   des Caches ablegt, legt einen veralteten Stand ab; zusammen mit einem
   `cut()`, der nach dem Schreiben scheitert, oder einem gescheiterten
   Speichern von `stage` ist das ein (doppelt bedingtes) Überbehaupten. Und
   jeder Leser des Caches — auch `GET /isolate` über `_fw_cut_rule_listed` —
   wartet hinter einem laufenden `List` (3,5–9,4 s). *Richtung:* ein
   Generationszähler, den jedes Vergessen erhöht und den ein `List` beim Ablegen
   prüft; dann kann die Sperre vor dem Aufruf losgelassen werden.
   *Größe des Fensters seit der Änderung der Aufruf-Bilanz — falls es überhaupt
   auftritt:* für die Schreiber in den Routen (`block`, `unblock`, Druck,
   Verlassen) ließ es sich nicht herstellen: ihr Vergessen kommt nach dem
   Schreiben und nimmt die Sperre, die das `List` hält, es räumt also auch einen
   gerade abgelegten Stand. Möglich scheint es nur im Fenster der Konvergenz
   (die Schritte schreiben, ein `List` liest zwischendurch, vergessen wird erst am
   Ende des Workers; gemessen ~59 s). Dann hielt ein so abgelegter veralteter
   Stand vorher höchstens ~30 s (der erzwungene Abruf von `/rules` heilte ihn);
   jetzt bis zu einer TTL, 60 s, oder bis zum Ende des Workers, was früher
   kommt, und `can_fetch` kann in dieser Zeit `true` zeigen. Nur Anzeige
   (Entscheidung und Frist lesen mit `force=True`); `verified` ist nicht
   betroffen.

**Von diesem Branch hinzugefügt — nach dem Fix messen.** Der Panikschnitt hat
selbst zur Bilanz beigetragen; jeder dieser Punkte ist einzeln begründet, aber
keiner ist unter Last gemessen:

- Die Isolate-TTL von 10 s: solange isoliert wird, `Profiles` alle 10 s, und in
  `isolated` und `cut_policy` zusätzlich `AllowOut` (~6 s) alle 10 s.
- `GET /isolate` wartet jetzt über `_fw_cut_rule_listed` auf `_fw_rules_lock`,
  also hinter jedem laufenden `List`.
- Ein zweites `Profiles`-Lesen, wenn der Profil-Cache aus `_fw_keep_profiles`
  kam (dort fehlt die Default-Aktion, die `verified` in `isolated` braucht).
- `_fw_fetch_refusal` erzwingt bei jeder `block_fetch`-Entscheidung ein `List`.
- *(Nach dem Abschluss-Review hinzugekommen.)* In `cut` und `cut_policy` ein
  `Get` der Schnitt-Regel alle 10 s für `GET /isolate`, wenn weder die
  Rücklesung des Drucks noch die Regelliste jünger ist — damit `verified` dort
  nicht auf einer einmaligen Rücklesung ruht. Billiger ginge es, wenn `Profiles`
  den Zustand der Schnitt-Regel im selben Prozess mitliefert (kein zweiter
  Modul-Start); das ist eine Änderung an `firewall_rules.ps1` und gehört zu
  diesem Punkt.

**Vorher gemessen, nachher wieder messen:** `Cut` allein 2,44 s; `Cut` im Druck
unter Last 7,29 s; Druck insgesamt 9,9–16,9 s; Wartezeit auf Sperren 0 ms.

### Aufruf-Bilanz, gemessen je Route (VM)

Jede Route des Tabs einzeln, auf der echten VM, kalt und gleich danach. Ein
PowerShell-Aufruf gegen das NetSecurity-Modul kostet dort 2,4–3,5 s. Die Zahlen
der Tabelle stammen von **vor** der Änderung; die Zeile `/summary` ist nach einer
späteren Messung richtiggestellt.

| Route | Dauer je Aufruf | PowerShell |
|---|---|---|
| `/api/firewall/isolate` | 0,01–0,17 s | **0 Aufrufe** (Cache-Treffer) |
| `/api/firewall/connections` | 0,85 s warm | **0 Aufrufe** warm (kalt: `Profiles` + `List`) |
| `/api/firewall/captures` | 0,02 s | **0 Aufrufe**, reiner Speicher |
| `/api/firewall/pending` | 0,02 s | kostenlos |
| `/api/firewall/summary` | 0,45–0,49 s (allein, zweimal im Abstand von 70 s) | **0 Aufrufe**, beide Male |
| `/api/firewall/rules` | 3,37 s, dann 4,26 s | **1 `List` bei jedem Aufruf** (`_fw_rules(force=True)`) |

**Korrektur: `/summary` hat nie gelesen.** Eine frühere Fassung dieser Tabelle
schrieb `/summary` „1 `List` bei jedem Aufruf“ zu (2,75 s, dann 3,24 s). Das war
falsch: `/summary` erzwingt nichts und liest die Regelliste nicht selbst. Das
`List` in seinem Zeitfenster war das erzwungene Lesen von `/rules`; die
Oberfläche schickt beide im selben `Promise.all` los, und die erste Messung rief
sie unmittelbar nacheinander auf. Dass `/summary` 2,75–3,24 s brauchte, lag daran,
dass es auf der Sperre des Regel-Caches hinter diesem `List` wartete. Allein
gemessen: 0 Aufrufe. Auch die 14 `List` der „16 Aufrufe“ kamen alle aus `/rules`
— aber aus einem Messaufbau, der `/rules` öfter abfragte als der Tab es tut: er
rief es in der Taktschleife **und** in einer eigenen Einzelsonde im selben
Fenster auf, und frühere Läufe hatten Browser-Tabs gegen denselben Server
offen. Der Tab allein (ein Aufruf je 30 s) ergäbe deutlich weniger; die
Zahl 16 ist keine Tab-Zahl, und eine Rechnung „vier Abfragen = vierzehn `List`“
gibt es nicht.

- **Die beiden 5-Sekunden-Abfragen (`/isolate`, `/pending`) sind kostenlos**,
  jedenfalls je Aufruf: Cache-Treffer. (Was `/isolate` über 100 s doch kostet,
  steht unten.)
- **`/captures` und `/pending` sind kostenlos.** Sie träge zu laden spart nichts.

**Die Änderung:** `/rules` nimmt den Regel-Cache (`FIREWALL_RULES_TTL_S = 60`)
statt zu erzwingen. Das ist sicher, weil jeder Weg, der eine Regel ändert
(`block`, `unblock`, der Druck, das Verlassen, die Regeln des Abrufs), den Cache
selbst vergisst: er kann nichts zeigen, was TDC getan hat, nur eine Änderung
von außen bis zu einer TTL verspätet. Was durchsetzt (Entscheidung, Frist,
`_fw_fetch_refusal`), liest weiter mit `force=True`. `/summary` brauchte keine
Änderung.

**Vorher/nachher, gemessen:** 100 s im Dauerbetrieb des Tabs, niemand drückt
etwas (das „vorher“ stammt aus dem oben beschriebenen Messaufbau, der `/rules`
häufiger abfragte als der Tab; der Vergleich überzeichnet die Ersparnis des
Tabs allein).

| | vorher | nachher |
|---|---|---|
| Aufrufe | 16 | **5** |
| `List` | 14 (alle `/rules`) | **2** (beide `/connections`, mit eigener TTL) |
| `Profiles` | 2 | 3 (alle `/isolate`) |
| `powershell.exe` ausgelastet | 42 % | **18 %** |

Vorhergesagt waren 1–2 `List` je 100 s (eingetroffen) und 3–6 % Auslastung
(zu niedrig: die drei `Profiles` von `/isolate` sind schwerer als angesetzt).

**Der verbleibende Verbrauch** (nicht Teil dieser Änderung, nicht umgesetzt):

- 2 `List` aus `/connections`: rechtmäßig, es liest mit seiner eigenen TTL.
- 3 `Profiles` aus `/isolate` in 100 s bei einer TTL von 60 s. Eines davon ist das
  doppelte Lesen: `_fw_keep_profiles` legt die Default-Aktion (`blocking`) als
  unbekannt ab, `verified` verlangt sie, also liest der Zustand die Profile
  beim nächsten `GET` noch einmal. *Richtung, eine Zeile:* `_fw_keep_profiles`
  hält `blocking` mit, statt `None` abzulegen.

**Der Regel-Cache ist jetzt bis zu einer TTL (60 s) alt, wo er vorher durch den
erzwungenen 30-s-Abruf nie älter als ~30 s war.** Das betrifft alles, was ihn
liest, ohne zu erzwingen, und das sind vier Oberflächen, die größten zuerst:

- **`/connections`** (alle 5 s): `flow["state"] = "blocked"` kommt aus
  `ctx.rules` (`_firewall_context` → `firewall.classify`). Das ist die
  Hauptliste des Tabs.
- **`/summary`**: dieselbe Liste wird zur Zahl der **BLOCKED-Kachel**
  (`firewall.summarize`).
- `/pending` (`can_fetch`) und `GET /isolate` (`can_fetch` über
  `_fw_cut_rule_listed`, das nicht einmal das Alter prüft).

**Eine Regel, die außerhalb von TDC entfernt wurde, steht damit bis zu 60 s
weiter als „blocked“ in der Liste und in der BLOCKED-Kachel.** Das ist gewollt
(60 s ist die Anzeige-TTL, es verspätet nur, was TDC nicht selbst getan hat, und
alles, was durchsetzt, liest mit `force=True`), aber es muss hier stehen. Die
Obergrenze ist 60 s: bei offenem Tab lesen `/connections` und `/pending` alle
3–5 s den Cache, ein abgelaufener wird also sofort erneuert. Zu Punkt 6 oben: in dieser Zeit kann außerdem
`can_fetch` `true` zeigen, wo die Entscheidung selbst (mit `force=True`)
ablehnen würde. Nur Anzeige: nichts wird daraufhin getan.
`verified` ist davon nicht betroffen: ein Cache-Treffer erneuert die Rücklesung
der Schnitt-Regel nicht (Test:
`test_a_cached_rule_list_never_renews_the_read_back_of_the_cut`).

**Ein Fehler wird ebenfalls eine ganze TTL lang gemerkt.** `_fw_rules` kennt
keine kürzere Fehler-TTL wie `FIREWALL_PROFILES_ERROR_TTL_S = 10`: ein einmaliges
Scheitern des `List` zeigt sich bis zu 60 s statt ~30 s. Eine kürzere Fehler-TTL
wäre eine Zeile, ändert aber die Aufrufzahl bei dauerhaftem Fehler (bis zu
6 statt 1 Aufruf je Minute, jeder hinter der Sperre) — eine Entscheidung, keine
Nebensache.

**Entscheidung: keine kurze Fehler-TTL für den Regel-Cache.** Bei einem
*dauerhaften* Fehler wären das bis zu 6 scheiternde `List` je Minute zu je
~3 s, jedes unter `_fw_rules_lock`, hinter der `GET /isolate` wartet: der Pfad,
der schnell sein muss, würde genau dann ausgehungert, wenn der Analyst ihn am
dringendsten braucht. Ein einmaliger Fehler, der bis zu 60 s steht, ist der
billigere Fall: der Tab sagt ehrlich, dass die Regeln nicht gelesen werden
konnten, und nichts behauptet daraufhin eine Schließung. Beim Profil-Cache ist
es umgekehrt, deshalb hat er `FIREWALL_PROFILES_ERROR_TTL_S = 10`: dort speist
ein veralteter Wert eine Aussage darüber, ob überhaupt etwas durchgesetzt wird.
Die Lücke ist also gewollt, nicht übersehen; bitte nicht „nachziehen".

**Gemessen und verworfen: träges Laden der 30-Sekunden-Routen.** Vorgeschlagen
war, `/captures`, `/pending`, `/rules` und `/summary` erst bei Bedarf zu laden.
Das bringt nichts: `/captures` und `/pending` kosten **keinen** PowerShell-Aufruf
(0,02 s, reiner Speicher), `/summary` ebenfalls keinen (0 Aufrufe, 0,45–0,49 s),
es gibt dort nichts zu sparen. `/rules` und `/summary` speisen immer sichtbare
Teile der Seite — die Schalter im Prozessbaum und die ganze rechte Spalte —, sie
ließen sich nicht aufschieben, ohne etwas, das auf dem Bildschirm steht, leer zu
lassen. Der teure Teil war nicht der Zeitpunkt des Ladens, sondern das
erzwungene Lesen in `/rules`; das ist behoben (16 → 5 Aufrufe, 42 % → 18 %, im Messaufbau oben).
**Nicht erneut vorschlagen.**

### Stand nach den modulfreien Lesevorgängen (gemessen, VM)

Die Lesevorgänge von `firewall_rules.ps1` laden das NetSecurity-Modul nicht mehr
(Abschnitt „Reads without the NetSecurity module“ oben). **Die Zahlen der
Tabellen und der Vorher/nachher-Tabelle oben sind damit überholt.** Ein
Lesevorgang kostet 0,56–0,59 s statt 1,65 s. Der Tab im Dauerbetrieb, 100 s,
niemand drückt etwas:

| | davor (18-%-Messung oben) | jetzt |
|---|---|---|
| PowerShell-Aufrufe je 100 s | 5 | **2** |
| `powershell.exe` ausgelastet | 18 % | **3,3 %** |
| Rückfälle auf die Cmdlets in diesem Fenster | nicht zutreffend | **keine** (`{'fast': 2}`) |

Zur Einordnung: derselbe Tab stand einmal bei 42 % und 16 Aufrufen je 100 s,
bevor `/rules` aufhörte, ein Lesen zu erzwingen. Welche Routen die beiden
verbleibenden Aufrufe auslösten, wurde nicht aufgeschrieben; die Aufteilung nach
`List` und `Profiles` ist hier deshalb nicht angegeben. `AllowOut` kam in der
Messung nicht vor. Die Punkte 1 bis 6 oben bleiben eigene Arbeit; die
Zielzahl für den Druck (Punkt 4) lässt sich jetzt aus dem Log neu belegen.

**Verworfen: der residente PowerShell-Prozess.** Er wäre der größere Hebel
gewesen (~0,2 s je Aufruf), aber:

- Er stellt eine stundenlang lebende, **erhöhte** PowerShell-Sitzung in eine
  Malware-Kammer, ein privilegiertes Ziel, das es heute nicht gibt: jeder
  Aufruf ist ein kurzlebiges `powershell.exe -File` mit Argumenten.
- Eine lange Sitzung sammelt Zustand (`$ErrorActionPreference`, Variablen,
  Fehlerzustände), und dieser Zustand würde **zwischen Befehlen durchsickern**.
  Heute beginnt jeder Aufruf frisch, und der nächste Befehl könnte der
  Panikschnitt sein.
- **Die Messung hat ihn unnötig gemacht:** der Preis war das Modul-Laden
  (~1,3 s), nicht der Prozessstart (0,36 s). Ohne Modul ist ein Lesen bei
  0,56–0,59 s, und die Ruhelast liegt bei 3,3 %.

**Nicht erneut vorschlagen.**
