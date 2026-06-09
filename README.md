# Transportable Detonation Chamber

<p align="center">
  <img src="tdc-logo.png" alt="Transportable Detonation Chamber">
</p>

<p align="center">
  <strong>A pre-configured Windows 11 VM for malware detonation testing against multiple EDR solutions.</strong><br>
  Unified dark-themed Web UI &bull; Real-time Sigma/YARA/IOC detection &bull; Kernel ETW telemetry<br>
  Supports <b>Windows</b> (Hyper-V) and <b>macOS Apple Silicon</b> (QEMU/UTM)
</p>

---

## Table of Contents

- [Quick Start](#quick-start)
- [Features](#features)
- [Architecture](#architecture)
- [Web UI](#web-ui)
- [Platform Support](#platform-support)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [API Reference](#api-reference)
- [Configuration](#configuration)
- [Detection Rules](#detection-rules)
- [File Structure](#file-structure)
- [Troubleshooting](#troubleshooting)
- [Security Notes](#security-notes)
- [Credits](#credits)

---

## Quick Start

### Option A: Local UI Only (no VM)

Run the Web UI locally for development or UI testing. Backend services won't be available, but all tabs and features render normally.

```bash
# macOS / Linux
make install    # Creates venv, installs Flask + deps
make run        # Starts on http://localhost:9000

# Windows (PowerShell)
.\make.ps1 install
.\make.ps1 run
```

### Option B: Full VM (recommended for analysis)

```bash
# macOS / Linux
make up         # Provisions the full Windows 11 VM
make open       # Opens http://<vm-ip>:9000 in browser

# Windows (PowerShell, run as Administrator)
.\make.ps1 up
.\make.ps1 open
```

First boot takes ~20-30 minutes (Windows) or ~30-45 minutes (macOS ARM).

---

## Features

### Unified Web UI (port 9000)

A single-page dark-themed interface that aggregates telemetry from all engines:

| Tab | Description |
|-----|-------------|
| **Dashboard** | Stats strip (alerts/processes/services/rules/tools), 6 service health cards, recent activity feed |
| **Tracing** | Real-time ETW event console, process filtering, timeline visualization |
| **Graph** | Process relationship graph with 5 layouts (Force/Hierarchical/Radial/Circular/Grid), zoom, search |
| **Sysmon** | Windows Sysmon event log viewer (process, network, file, registry, DNS events) |
| **Scanner** | ThreatCheck + DefenderCheck integration (Defender/AMSI engines), scan history |
| **Hex Editor** | Binary viewer with data inspector, drag-and-drop upload, PE Analysis button |
| **Submit** | Multi-target detonation (DetonatorAgent + LitterBox), stage-by-stage progress |

### Detection Engines

| Engine | Technology | Capabilities |
|--------|-----------|--------------|
| **Rustinel** | Rust + ETW | 20 Sigma rules, 717 YARA rules, IOC hash matching, real-time NDJSON alerts |
| **Fibratus** | Go + Kernel ETW | Process/file/registry/network telemetry, behavior rules |
| **Sysmon** | Sysinternals | Event logging (process creation, network, file, registry, image loads) |
| **LitterBox** | Python | Static (YARA, strings) + Dynamic (PE-Sieve, Moneta, HollowsHunter, RedEdr) |

### Analysis Capabilities

- **PE Header Analysis**: DOS/File/Optional headers, section table with entropy bars, ASLR/DEP/SEH/CFG detection
- **Suspicious Import Detection**: Categorized (injection, evasion, credential access, networking, crypto, shellcode)
- **Packer Identification**: UPX, Themida, VMProtect, ASPack, MPRESS, etc. via section name matching
- **RWX Section Flagging**: Read+Write+Execute permissions highlighted
- **TLS Callback Detection**: Anti-debug indicator
- **Entropy Visualization**: Per-section Shannon entropy with color coding (red >= 7.0 = packed/encrypted)

### Developer Experience

- **`make deploy-restart`**: Edit locally, push to VM, restart Flask in one command
- **`make run-debug`**: Flask auto-reload on file changes (local dev)
- **Loading Spinner**: Global overlay with 300ms delay threshold
- **Help Modal**: Built-in documentation (press "? Help" in sidebar)
- **Submissions History**: Persisted to JSON, with Hex button for quick inspection

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Windows 11 VM (Hyper-V / QEMU)                                 │
│                                                                  │
│  ┌────────────┐   ┌────────────────┐   ┌────────────┐          │
│  │  Web UI    │   │ DetonatorAgent │   │ LitterBox  │          │
│  │  :9000     │──▶│  :8080         │   │  :1337     │          │
│  └────────────┘   └────────────────┘   └────────────┘          │
│       │                  │                   │                   │
│       └──────────────────▼───────────────────┘                  │
│                  ┌────────────────┐                              │
│                  │    Fibratus    │                              │
│                  │  Kernel ETW    │                              │
│                  └────────────────┘                              │
│                  ┌────────────────┐                              │
│                  │   Rustinel     │                              │
│                  │ Sigma+YARA+IOC │                              │
│                  └────────────────┘                              │
│                  ┌────────────────┐                              │
│                  │    Sysmon      │                              │
│                  │  Event Log     │                              │
│                  └────────────────┘                              │
└─────────────────────────────────────────────────────────────────┘
```

### Data Flow

1. Sample submitted via Web UI → forwarded to DetonatorAgent + LitterBox
2. DetonatorAgent executes the sample, returns PID
3. LitterBox runs static (YARA, CheckPlz, Stringnalyzer) + dynamic (PE-Sieve, Moneta, HollowsHunter, RedEdr) analysis
4. Fibratus captures kernel-level ETW events for the process
5. Rustinel matches events against Sigma + YARA rules + IOC hashes
6. Web UI aggregates alerts from all engines into unified timeline

### Services

| Service | Port | Purpose | Technology |
|---------|------|---------|------------|
| **Web UI** | 9000 | Unified dashboard & API gateway | Python / Flask |
| **DetonatorAgent** | 8080 | Executes malware samples, returns PID | .NET 8.0 |
| **LitterBox** | 1337 | Static + dynamic analysis sandbox | Python / Flask |
| **Fibratus** | 8180 | Kernel ETW telemetry & behavior rules | Go |
| **Rustinel** | — | Sigma/YARA/IOC real-time detection | Rust |
| **Sysmon** | — | Windows event logging | Sysinternals |
| **Detonator** | 5000/8000 | Orchestration UI + REST API | Python |

---

## Web UI

### Dashboard

The main landing page shows:
- **Stats strip**: Alerts count (by severity), active processes, service health, loaded rules, available tools
- **Service cards**: Health status for Rustinel, DetonatorAgent, LitterBox, Fibratus, Sysmon, Scanner Tools
- **Activity feed**: Recent detection alerts with severity coloring and rule names

### Tracing

Real-time console showing ETW events and detection alerts:
- Filter by process (select from sidebar)
- Timeline visualization shows alert distribution over time
- Click any alert for full detail panel (raw JSON, ATT&CK tags, related processes)

### Graph

Interactive process relationship visualization:
- **5 layout modes**: Force-directed, Hierarchical, Radial, Circular, Grid
- **Zoom controls** with mouse wheel support
- **Search**: Find processes by name or PID
- **Time-range filtering**: 5m, 15m, 1h, All
- **Detail panel**: Click any node for full process info, connections, children tree

### Scanner

Run signature detection tools against files:
- **ThreatCheck**: Identifies the exact bytes triggering Defender/AMSI detection
- **DefenderCheck**: Tests if Defender would flag a file
- **Results**: Detection status, byte offset of trigger, link to hex editor for inspection
- **History**: All previous scan results persisted in-session

### Hex Editor

Full binary file viewer:
- **Drag-and-drop** file upload or specify VM path
- **Data inspector**: Int8/16/32/64, Float32/64, ASCII, UTF-16 at cursor position
- **PE Analysis**: Button parses full PE structure (headers, sections, imports, entropy, IOC flags)
- **Cross-tab integration**: Scanner "View in Hex" jumps directly to the flagged offset

### Submit

Multi-target sample detonation with progress tracking:
- **Targets**: DetonatorAgent only, LitterBox only, or Both
- **Pipeline visualization**: Stage-by-stage progress (Upload → Execute → Static → Dynamic → EDR)
- **Results aggregation**: YARA matches, PE-Sieve findings, Moneta results, HollowsHunter output, Fibratus alerts
- **Polling**: Auto-refreshes every 5 seconds for up to 2.5 minutes

### Help Modal

Built-in documentation accessible via "? Help" button in the sidebar:
- **Overview**: Capabilities and workflow
- **Usage Guide**: Per-tab documentation
- **API Reference**: All endpoints with methods and parameters
- **Architecture**: Diagram and data flow
- **Services**: Component details and detection rules

---

## Platform Support

| Host OS | Hypervisor | Guest Arch | Vagrantfile | Performance |
|---------|-----------|------------|-------------|-------------|
| Windows 10/11 (x86_64) | Hyper-V | x86_64 | `Vagrantfile` | Native |
| macOS Apple Silicon (M1-M4) | QEMU via vagrant-qemu | ARM64 | `Vagrantfile.utm` | Near-native via hvf |

### ARM64 Compatibility

| Component | ARM64 Support | Notes |
|-----------|--------------|-------|
| Sysmon | Native | `Sysmon64a.exe` (ARM64 binary) |
| Fibratus | Emulated (x86_64) | No ARM64 build; ~10-20% overhead |
| Rustinel | Emulated (x86_64) | No ARM64 build; ETW works under emulation |
| .NET 8 / Python 3.12 | Native | Full ARM64 SDK and runtime |
| DetonatorAgent | Native | Compiled from source via .NET 8 |
| Detonator / LitterBox | Native | Python-based |

---

## Prerequisites

### Windows Host

- Windows 10/11 with **Hyper-V** enabled
- **Vagrant** >= 2.4 ([download](https://www.vagrantup.com/downloads))
- **Administrator** PowerShell (required for Hyper-V)
- ~30 GB disk, ~8 GB RAM

```powershell
# Enable Hyper-V (reboot required)
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All
```

### macOS Host (Apple Silicon)

- macOS on Apple Silicon (M1/M2/M3/M4)
- **QEMU**: `brew install qemu`
- **Vagrant**: `brew install --cask vagrant`
- **vagrant-qemu plugin**: `vagrant plugin install vagrant-qemu`
- **Windows 11 ARM64 Vagrant box** (see [Vagrantfile.utm](Vagrantfile.utm) header for setup instructions)
- ~80 GB disk, ~8 GB RAM

### Local Development Only

- **Python 3.10+** (any platform)
- **Make** (macOS: Xcode CLI tools; Windows: not needed, use `make.ps1`)

---

## Installation

### Using make / make.ps1

The project includes a cross-platform build system:

| Command | Description |
|---------|-------------|
| `install` | Create Python venv + install Flask, requests, watchdog, pefile |
| `run` | Start Web UI locally on port 9000 |
| `run-debug` | Start with Flask auto-reload (watches file changes) |
| `up` | Provision and start the full VM |
| `halt` | Stop the VM gracefully |
| `destroy` | Delete the VM |
| `deploy` | Sync webui files (HTML/CSS/JS) to running VM |
| `deploy-app` | Sync Flask backend (app.py) to VM |
| `restart` | Restart the Web UI service on VM |
| `deploy-restart` | Deploy + restart in one step |
| `open` | Open Web UI in default browser |
| `status` | Show VM + service health |
| `services` | List all service states |
| `alerts` | Show recent detection alerts |
| `test` | Submit test sample to verify pipeline |
| `submit FILE=x` | Submit a file for detonation |
| `logs` | Tail Web UI logs from VM |
| `ssh` / `rdp` | Connect to VM |
| `clean` | Destroy VM + remove .vagrant |
| `clean-all` | Also remove cached Vagrant boxes |
| `uninstall` | Remove local Python venv |

**macOS / Linux:**
```bash
make install        # Local venv setup
make run            # Local server
make up             # Full VM
make deploy-restart # Push changes to VM
```

**Windows (PowerShell):**
```powershell
.\make.ps1 install
.\make.ps1 run
.\make.ps1 up              # Run as Administrator
.\make.ps1 deploy-restart
```

### Manual Installation

```bash
cd webui
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py               # http://localhost:9000
```

---

## Usage

### Detonation Workflow

1. Open the Web UI at `http://localhost:9000`
2. Go to the **Submit** tab
3. Drag and drop (or browse) a malware sample
4. Select target: **Agent** (execution), **LitterBox** (analysis), or **Both**
5. Click Submit — watch the pipeline stages progress
6. Switch to **Tracing** tab to see real-time ETW alerts
7. Switch to **Graph** tab to see process relationships
8. Check **Dashboard** for severity breakdown

### CLI Submission

```bash
# macOS / Linux
make submit FILE=./samples/mimikatz.exe TARGET=both

# Windows
.\make.ps1 submit -File .\samples\mimikatz.exe -Target2 both
```

### Scanner Workflow

1. Go to **Scanner** tab
2. Upload a file (drag and drop) or enter a VM path
3. Select tool (ThreatCheck / DefenderCheck) and engine (Defender / AMSI)
4. Click Scan — results show detection status and trigger offset
5. Click "View in Hex" to jump to the flagged bytes

### PE Analysis

1. Go to **Hex Editor** tab
2. Upload a PE file
3. Click **PE Analysis** button
4. Review: headers, security features (ASLR/DEP/SEH/CFG), section entropy, suspicious imports, packer indicators

---

## API Reference

All endpoints served on port `9000`. Responses are JSON.

### Core

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/alerts` | All detection alerts (Rustinel + Fibratus + LitterBox) |
| GET | `/api/processes` | Tracked processes with activity counts |
| GET | `/api/status` | Service health status (all components) |
| GET | `/api/rustinel` | Rustinel engine info (rules, version) |
| GET | `/api/submissions` | Submission history (last 200) |

### Submission & Detonation

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/submit` | Submit sample (multipart). Params: `file`, `target` (agent/litterbox/both) |
| GET | `/api/detonation/results` | Poll results. Params: `sha256`, `pid`, `litterbox_hash` |

### Hex Editor & PE

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/file/hex` | Hex dump. Params: `path`, `offset`, `bytes` |
| POST | `/api/file/hex/upload` | Upload file for hex viewing |
| GET | `/api/file/pe` | PE header analysis. Param: `path` |

### Scanner

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scan/threatcheck` | ThreatCheck scan. Params: `file`/`path`, `engine`, `type` |
| POST | `/api/scan/defendercheck` | DefenderCheck scan. Params: `file`/`path` |
| GET | `/api/scan/status` | Scanner tool availability |

### Proxy Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET/POST | `/api/litterbox/<path>` | Proxy to LitterBox API (:1337) |
| GET | `/api/fibratus/<path>` | Proxy to Fibratus API (:8180) |

---

## Configuration

### Environment Variables (Web UI)

| Variable | Default | Description |
|----------|---------|-------------|
| `RUSTINEL_ALERTS_DIR` | `C:\tools\rustinel\logs` | Rustinel NDJSON alert directory |
| `RUSTINEL_INSTALL_DIR` | `C:\tools\rustinel` | Rustinel installation root |
| `DETONATOR_API` | `http://127.0.0.1:8000` | Detonator REST API |
| `DETONATOR_AGENT_API` | `http://127.0.0.1:8080` | DetonatorAgent API |
| `LITTERBOX_API` | `http://127.0.0.1:1337` | LitterBox API |
| `WEBUI_PORT` | `9000` | Web UI listen port |

### Custom Detection Rules

**Sigma** (hot-reload):
```
C:\tools\detection-rules\rustinel-rules\dist\windows-advanced\rules\sigma\
```

**YARA** (hot-reload):
```
C:\tools\detection-rules\yara-combined\
```

**IOC Hashes** (hot-reload, add SHA-256 one per line):
```
C:\tools\detection-rules\rustinel-rules\dist\windows-advanced\rules\ioc\
```

### Defender Exclusions

Provisioning adds exclusions for detonation paths. To fully disable for testing:

```powershell
# Inside VM, run as Administrator
Set-MpPreference -DisableRealtimeMonitoring $true
```

---

## Detection Rules

| Type | Count | Source |
|------|-------|--------|
| **Sigma** | 20 rules | `Karib0u/rustinel-rules` windows-advanced pack |
| **YARA** | 717 compiled | Rustinel-rules + Elastic protections-artifacts |
| **IOC** | Dynamic | SHA-256 hash matching, auto-fed on sample submission |

**Sigma coverage:**
- 14 process_creation (encoded PowerShell, schtasks, LOLBins, credential dumping)
- 3 registry_event (Run key persistence, Defender tampering, WDigest)
- 1 task_creation (suspicious scheduled task actions)
- 1 ps_script (PowerShell script block logging)
- 1 service_creation

---

## File Structure

```
transportable-detonation-chamber/
├── Makefile                        # Build system (macOS/Linux)
├── make.ps1                        # Build system (Windows PowerShell)
├── Vagrantfile                     # VM definition (Hyper-V)
├── Vagrantfile.utm                 # VM definition (QEMU/UTM, Apple Silicon)
├── README.md
├── tdc-logo.png
│
├── webui/                          # Unified Web UI
│   ├── app.py                     # Flask backend (APIs, proxying, PE analysis)
│   ├── requirements.txt           # Python deps (flask, requests, watchdog, pefile)
│   ├── templates/
│   │   └── index.html             # SPA with all tabs + Help modal
│   └── static/
│       ├── css/style.css          # Dark theme (~3800 lines)
│       ├── js/app.js              # Frontend logic (~4000 lines)
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
│   ├── install-sysmon.ps1         # Sysmon (ARM64-aware)
│   ├── install-fibratus.ps1       # Fibratus v3.0.0
│   ├── install-rustinel.ps1       # Rustinel v1.1.1
│   ├── install-detection-rules.ps1 # Sigma + YARA rules
│   ├── install-detonator.ps1      # Detonator + DetonatorAgent
│   ├── install-litterbox.ps1      # LitterBox sandbox
│   ├── install-webui.ps1          # Web UI deployment
│   └── configure-services.ps1    # Service registration (runs on every boot)
│
└── test_alerts/                    # Test data for pipeline verification
```

### VM File Layout

```
C:\DetonationChamberUI\             Web UI (Flask)
C:\tools\rustinel\                  Rustinel ETW engine + rules
C:\tools\fibratus\                  Fibratus kernel tracer
C:\DetonatorAgent\                  .NET 8 execution agent
C:\LitterBox\                       Analysis sandbox
C:\tools\ThreatCheck\               AV signature scanner
C:\tools\DefenderCheck\             Defender evasion tester
C:\tools\detection-rules\           Sigma + YARA + IOC rules
C:\Users\vagrant\Desktop\infected\  Malware samples (Defender-excluded)
```

---

## Troubleshooting

### Check service status

```bash
# macOS / Linux
make services

# Windows
.\make.ps1 services
```

Expected output:
```
  SERVICE               STATE
  -------               -----
  DetonationChamberUI   Running
  Rustinel              Running
  DetonatorAgent        Running
  LitterBox             Running
  Fibratus              Running
  Sysmon                Running
```

### Services not starting

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

### Port forwarding not working (Hyper-V)

Hyper-V uses a virtual switch. Connect directly via the VM's IP:

```powershell
# Find VM IP
.\make.ps1 status
# Or: vagrant ssh -c "ipconfig"

# Override in make.ps1
.\make.ps1 status -VMIp 172.17.x.x
```

### Web UI not loading

```bash
# Check if Flask is running
make status  # or: .\make.ps1 status

# Restart it
make restart  # or: .\make.ps1 restart

# View logs
make logs  # or: .\make.ps1 logs
```

### Rustinel not detecting events

```powershell
# Inside the VM:
Get-Process rustinel
Get-Content C:\tools\rustinel\logs\rustinel.log.* | Select-Object -Last 20
logman query -ets | findstr rustinel

# Restart if stale
logman stop rustinel-etw-trace -ets 2>$null
Start-ScheduledTask -TaskName "Rustinel"
```

### macOS: QEMU won't start

```bash
qemu-system-aarch64 --accel help  # Should show: hvf
ls /opt/homebrew/share/qemu/edk2-aarch64-code.fd
vagrant plugin list | grep qemu
```

### Local install fails

```bash
# Verify Python version (needs 3.10+)
python3 --version

# If venv creation fails, try:
make uninstall  # or: .\make.ps1 uninstall
make install    # or: .\make.ps1 install
```

---

## Security Notes

- This VM is designed for **malware analysis** — treat it as compromised
- Use **snapshots** before each detonation (`vagrant snapshot save clean_state`)
- **Network isolation** recommended (Hyper-V internal/private switch)
- Defender exclusions configured for detonation paths only
- Rustinel active response is **disabled by default**
- The Web UI has no authentication — bind to localhost or use on isolated networks only

---

## Credits

- [dobin/detonator](https://github.com/dobin/detonator) — Orchestration framework
- [dobin/DetonatorAgent](https://github.com/dobin/DetonatorAgent) — Execution agent
- [rabbitstack/fibratus](https://github.com/rabbitstack/fibratus) — ETW detection engine
- [Karib0u/rustinel](https://github.com/Karib0u/rustinel) — Sigma/YARA EDR agent
- [BlackSnufkin/LitterBox](https://github.com/BlackSnufkin/LitterBox) — Payload analysis sandbox
