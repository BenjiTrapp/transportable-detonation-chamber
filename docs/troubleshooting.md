# Troubleshooting

Where to look when a service is down, the UI stays blank or a detection never
arrives — and which file lives where.

## Check service status

```bash
# macOS / Linux
make services
```

```powershell
.\make.ps1 services
```

Expected output:

```text
  SERVICE               STATE
  -------               -----
  DetonationChamberUI   Running
  Rustinel              Running
  DetonatorAgent        Running
  LitterBox             Running
  Fibratus              Running
  theZoo-WebUI          Running
  Sysmon                Running
```

## Services not starting

```powershell
# SSH/RDP into the VM
vagrant ssh  # or: vagrant rdp

# Check and restart services
Get-ScheduledTask -TaskName DetonationChamberUI | Start-ScheduledTask
Get-ScheduledTask -TaskName Rustinel | Start-ScheduledTask
Get-ScheduledTask -TaskName DetonatorAgent | Start-ScheduledTask
Get-ScheduledTask -TaskName LitterBox | Start-ScheduledTask

# View logs
Get-Content C:\tools\logs\DetonatorAgent.log -Tail 50
Get-Content C:\tools\logs\DetonationChamberUI.log -Tail 50
```

## Port forwarding not working (Hyper-V)

Hyper-V uses a virtual switch. Connect directly via the VM's IP:

```powershell
# Find VM IP
.\make.ps1 status
# Or: vagrant ssh -c "ipconfig"

# Override in make.ps1
.\make.ps1 status -VMIp 172.17.x.x
```

## Web UI not loading

```bash
# Check if Flask is running
make status  # or: .\make.ps1 status

# Restart it
make restart  # or: .\make.ps1 restart

# View logs
make logs  # or: .\make.ps1 logs
```

## Web UI answers 403 "Host not allowed" or "Cross-site request rejected"

The UI only accepts IP addresses and `localhost` in the `Host` header (DNS
rebinding protection). Open it by IP, or add the name you use to
`TDC_ALLOWED_HOSTS`. "Cross-site request rejected" means a POST came from a
page on another origin, e.g. a bookmarklet or a tool running in the browser;
send it without an `Origin` header (curl, scripts) or from the UI itself.

## Rustinel not detecting events

```powershell
# Inside the VM:
Get-Process rustinel
Get-Content C:\tools\rustinel\logs\rustinel.log.* | Select-Object -Last 20
logman query -ets | findstr rustinel

# Restart if stale
logman stop rustinel-etw-trace -ets 2>$null
Start-ScheduledTask -TaskName "Rustinel"
```

## macOS: QEMU won't start

```bash
qemu-system-aarch64 --accel help  # Should show: hvf
ls /opt/homebrew/share/qemu/edk2-aarch64-code.fd
vagrant plugin list | grep qemu
```

## SYSCALLS tab shows no baseline

The notice over the map names the view. *No baseline for build …* means none has
been extracted for this Windows build yet (the web UI starts one in the
background, a few seconds; `C:\tools\ntsleuth\baseline\` holds the files) or
NTSleuth is not installed (`python3 scripts/deploy-utm.py --install
install-ntsleuth.ps1`, or the update button of [Tool updates](updates.md)).
*Not distinguishable on this host* is not a fault: the x64 baseline was
discarded on purpose, see [Live memory](memory.md#when-the-tab-says-it-cannot-measure).

## SYSCALLS GRAPH says there is no binary graph

GRAPH draws from `C:\tools\ntsleuth\baseline\binary-graph-<build>-<arch>.json`
(how it is made: [Configuration](configuration.md#the-binary-graph-cache)). The GRAPH button is always
on; where the graph is missing, the query and the figures answer with a
sentence in place of a picture, and the sentence says which of these it is:

| The tab says | What it means | What to do |
|---|---|---|
| *There is no binary graph for build … yet. It is being built in the background; that takes a few minutes.* | There is no file of this build and architecture, which includes the one a Windows update leaves behind under the old build number. The web UI started the build when you asked. | Wait a few minutes (it reads about 4,000 files) and press QUERY or RELOAD again. |
| *The binary graph … cannot be used (other build / other architecture / unknown format / malformed: …).* | A file of the right name that holds another build or architecture, a format this web UI does not know, or something that is not a graph (a power loss can leave a zero-filled file). It is built again in the background. | Wait, and ask again. |
| *The last build failed at …: <reason>. It is tried again from … on.* | The background build failed (for instance a timeout of 30 minutes, or a disk fault). A failed build is tried again after ten minutes. | Read the reason; ask again after the time it names. |
| *Building it failed 3 attempts in a row … It is not built again by itself: rebuild it by hand with scripts\build-binary-graph.ps1 -Force* | The web UI gave up: a failure that three builds in a row did not cure is not cured by a fourth, and each one reads all of System32 at the cost of CPU. | Rebuild it by hand, as Administrator: `C:\tdc\scripts\build-binary-graph.ps1 -Force`. The tab takes the new graph without a restart. |
| *Tool updates are running: no graph is built while they are.* | An update that swaps files in System32 or the web UI's Python under a build is the opposite of help. | Ask again when the update has ended. |
| *The binary graph … cannot be opened right now; it is read again on the next request.* | Another program, usually a scanner, holds the file without sharing it. Nothing is rebuilt. | Ask again. |

The script exits 0 even when it built nothing, so a provisioning that looks
clean can still have no graph: its yellow `[!]` lines name the reason, such as
*the web UI's Python is not there* (`install-webui.ps1` has not run) or *the
build of this system cannot be read from the registry*. The cache is built by the
web UI's own Python (`binary_graph.py`) and its command line is `--out <directory>
--build <build> --arch <arch>`; `--check` says whether a cache loads.

Two things that are not faults: an answer with **a table cut short**
(`partial`) is a binary whose import, delay-load or export table the reader had
to stop in, and the exploration view and the figures say the counts it affects are lower bounds, where the other answers say they are not certain; and
**files skipped** are PE files that could not be read, listed under the figure
*skipped*.

## Local install fails

```bash
# Verify Python version (needs 3.10+)
python3 --version

# If venv creation fails, try:
make uninstall  # or: .\make.ps1 uninstall
make install    # or: .\make.ps1 install
```

## File Structure

```text
transportable-detonation-chamber/
├── Makefile                        # Build system (macOS/Linux)
├── make.ps1                        # Build system (Windows PowerShell)
├── Vagrantfile                     # VM definition (Hyper-V)
├── Vagrantfile.utm                 # VM definition (QEMU/UTM, Apple Silicon)
├── README.md
├── tdc-logo.png
│
├── static/                         # Screenshots for the README and this guide
│
├── docs/                           # This guide, one page per topic
│
├── mcp/
│   ├── server.py                  # MCP server, talks to the web UI API
│   └── requirements.txt           # mcp, httpx  (make mcp-setup)
├── .mcp.json                      # Registers the MCP server for Claude Code
│
├── tests/                          # Unit tests (make unit-test), run by GitHub Actions
│   ├── samples/pipesim.c          # Harmless named-pipe test sample (build with zig cc)
│   └── fake_rizin.py              # Stands in for rizin's pipe mode in the RIZIN tests
│
├── webui/                          # Unified Web UI
│   ├── app.py                     # Flask backend (APIs, proxying, PE/ELF analysis)
│   ├── memory_evidence.py         # Tool-independent scoring of memory findings
│   ├── minidump_analysis.py       # Offline analysis of exit-time minidumps
│   ├── memory_results/            # Persisted live-memory results (git-ignored)
│   ├── pipe_analysis.py           # Pipe attribution, flags, evidence and baseline keys
│   ├── pipe_signatures.json       # Named-pipe catalog (C2 defaults, tools, APT pipes)
│   ├── pipe_proxy.py              # Interception engine (sessions, hold queue, recording)
│   ├── pipe_backends.py           # Win32 (ctypes) and in-memory fake pipe backends
│   ├── pipe_sessions/             # Ended interception recordings (git-ignored)
│   ├── syscall_baseline.py        # SYSCALLS tab: NTSleuth baseline (syscall numbers, RVAs, stubs) and its catalog
│   ├── syscall_scan.py            # SYSCALLS tab: a process's live stubs read (read-only) and measured against the baseline
│   ├── syscall_rules.py           # SYSCALLS tab: YARA rules and signature entries drafted from a stub or a deviation, applied on request
│   ├── syscall_signatures.json    # Syscall hook and patch patterns (inline hooks, neutralised stubs), per view
│   ├── win32_to_nt.py             # SYSCALLS tab: the curated Win32 to Nt table that turns a carried stub into a proven bypass
│   ├── binary_graph.py            # SYSCALLS tab: the import, export and forwarder tables of the System32 binaries
│   ├── binary_graph_query.py      # SYSCALLS tab: the questions asked of that graph, as nodes and edges cut at 400
│   ├── log_search.py              # LOGS tab: SPL-like search language (parser, evaluator, pipes)
│   ├── log_store.py               # LOGS tab: event ring buffer, source parsers, incremental collector
│   ├── logs/                      # Persisted access and MCP logs, JSONL (git-ignored)
│   ├── dashboards.py              # LOGS tab: the dashboards of your own and their tiles
│   ├── dashboards.json            # Saved dashboards and tiles (git-ignored)
│   ├── rizin_sessions.py          # RIZIN tab: rizin processes, console allowlist, analysis steps, projects
│   ├── rizin_projects/            # Renames and comments per file, <sha256>.rzdb (git-ignored)
│   ├── tool_updates.py            # Tool Updates: tool catalog and update checks
│   ├── firewall.py                # FIREWALL tab: bundling and tagging of connections (pure, no I/O)
│   ├── firewall_store.py          # FIREWALL tab: connection ring, collector, download findings, decisions, settings
│   ├── firewall_rules.py          # FIREWALL tab: TDC-FW-* rules, ISOLATED, kill (through firewall_rules.ps1)
│   ├── firewall_rules.ps1         # One firewall verb per call, values as -File parameters
│   ├── firewall_fetch.py          # FIREWALL tab: the guarded fetch of a stage-2 file
│   ├── geoip.py                   # Offline IP -> country / AS lookup
│   ├── data/                      # Offline geo index (iptoasn.com, CC0) and country centroids; `make geoip` refreshes it
│   ├── memory_baseline.json       # Host memory baseline (git-ignored)
│   ├── dev_server.py              # Dev server with live-reload
│   ├── requirements.txt           # Python deps (flask, requests, watchdog, pefile)
│   ├── templates/
│   │   └── index.html             # SPA with all tabs + Help modal
│   └── static/
│       ├── css/style.css          # Base styles and the Telemetry palette (every colour a variable in :root)
│       ├── css/theme-layout.css   # Window layout and controls, shared by both themes ([data-theme])
│       ├── css/theme-cyberpunk.css # Cyberpunk palette, scoped to [data-theme="cyberpunk"]
│       ├── js/app.js              # Frontend logic (single file, no build step)
│       ├── data/world.json        # Land mask of the FIREWALL map (Natural Earth 110m, public domain)
│       └── icon.png               # Logo
│
├── config/
│   ├── rustinel-config.toml       # Rustinel config (sigma/yara/ioc paths)
│   ├── fibratus.yml               # Fibratus config (JSON eventlog output)
│   └── profiles_init.yaml         # Detonator target profiles
│
├── rules/                          # Detection rules (copied to VM)
│
├── scripts/                        # Provisioning scripts
│   ├── install-prerequisites.ps1  # .NET 8, Python 3.12, Git, 7-Zip
│   ├── install-sysmon.ps1         # Sysmon (ARM64-aware; PipeEvent in exclude mode, 512 MB log)
│   ├── install-fibratus.ps1       # Fibratus v3.0.0
│   ├── install-rustinel.ps1       # Rustinel v1.1.1
│   ├── install-detection-rules.ps1 # Sigma + YARA rules
│   ├── install-detonator.ps1      # Detonator + DetonatorAgent
│   ├── install-litterbox.ps1      # LitterBox sandbox
│   ├── install-thezoo.ps1        # theZoo malware repository + WebUI
│   ├── install-hunt-sleeping-beacons.ps1 # Hunt-Sleeping-Beacons (VS Build Tools, x64 build)
│   ├── install-beaconeye.ps1     # BeaconEye (x64 release)
│   ├── install-aether.ps1        # Aether (prebuilt/ or Zig 0.16 build in the VM)
│   ├── install-process-dump.ps1  # Process Dump + clean-hash baseline (genquick)
│   ├── build-aether.sh           # Cross-compile Aether on the host into prebuilt/
│   ├── install-re-tools.ps1      # Detect It Easy, WinDbg, Ghidra
│   ├── install-rizin.ps1         # rizin 0.9.1 + rz-ghidra from Cutter's Windows package (pinned SHA-256)
│   ├── install-ntsleuth.ps1      # NTSleuth (SHA-256 checked) and the syscall baselines of this build, one per view
│   ├── install-webui.ps1         # Web UI deployment
│   ├── configure-logging.ps1     # PowerShell script block/module logging, Windows Firewall log, BITS log (LOGS, FIREWALL)
│   ├── tdc-unisolate.ps1         # The way out of ISOLATED without the web UI (run as Administrator)
│   ├── fetch-geoip.py            # `make geoip`: refresh webui/data from iptoasn.com (host, needs internet)
│   ├── build-worldmap.py         # Build webui/static/data/world.json from Natural Earth
│   ├── deploy-utm.py             # Push code to a UTM VM over WinRM, restart, run installers
│   ├── pipe-roundtrip-test.py    # Interception round trip on the VM (observe, edit, squat)
│   ├── build-wiki.py             # Builds the offline wiki from docs/ (make docs)
│   ├── wiki/                     # The pinned Mermaid 10 bundle and its licence
│   └── configure-services.ps1    # Service registration (runs on every boot)
│
└── prebuilt/                       # Host-built binaries uploaded by provisioning (git-ignored)
```

## VM File Layout

```text
C:\DetonationChamberUI\                 Web UI (Flask)
C:\tools\rustinel\                      Rustinel ETW engine + rules
C:\Program Files\Fibratus\              Fibratus kernel tracer (Bin\fibratus.exe)
C:\DetonatorAgent\                      .NET 8 execution agent
C:\LitterBox\                           Analysis sandbox
C:\tools\ThreatCheck\                   AV signature scanner
C:\tools\DefenderCheck\                 Defender evasion tester
C:\tools\EMBER2024\                     EMBER2024 ML classifier (thrember venv + models)
C:\tools\capa\                          Mandiant capa (static capability detection)
C:\tools\Hunt-Sleeping-Beacons\         Sleeping beacon scanner (x64)
C:\tools\BeaconEye\                     Cobalt Strike config scanner (x64)
C:\tools\Aether\                        Memory forensics scanner + rules\
C:\tools\ProcessDump\                   pd64.exe + clean-hash database
C:\tools\zig\                           Zig 0.16 (only when Aether was built in the VM)
C:\dumps\                               Process Dump output; exit\ holds exit-time dumps
C:\tools\theZoo-WebUI\                  theZoo malware sample browser (:8888)
C:\tools\detection-rules\               Sigma + YARA + IOC rules
C:\ProgramData\chocolatey\lib\die\      Detect It Easy (DiE 3.21)
C:\ProgramData\chocolatey\lib\ghidra\   Ghidra 12.1.2
C:\tools\cutter\                        rizin 0.9.1 + rz-ghidra (Cutter's Windows package; only rizin runs)
C:\tools\ntsleuth\                      NTSleuth (ntsleuth-arm64.exe on ARM64, ntsleuth-x64.exe) + baseline\ntsleuth-<build>-<view>.json
                                        baseline\binary-graph-<build>-<arch>.json: the import graph of System32 (GRAPH view)
C:\Windows\Temp\rizin_uploads\          Files uploaded in the RIZIN tab (newest 40)
C:\DetonationChamberUI\rizin_projects\  RIZIN projects (renames and comments)
C:\tdc\samples\                         Samples the FIREWALL tab fetched (<sha256[:2]>\<sha256>; never executed, Defender-excluded)
C:\tdc\scripts\                         Provisioning scripts; configure-logging.ps1, tdc-unisolate.ps1
WinDbgX.exe                             WinDbg Preview (via winget)
C:\Users\Public\Downloads\              Samples written by DetonatorAgent
```

**Next:** [Documentation index](README.md)
