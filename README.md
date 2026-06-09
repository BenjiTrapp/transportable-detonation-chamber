# Transportable Detonation Chamber

<p align="center">
  <img src="tdc-logo.png" alt="Transportable Detonation Chamber" width="180">
</p>

A pre-configured Windows 11 VM for malware detonation testing against multiple EDR solutions.
Supports **Windows hosts** (Hyper-V) and **macOS Apple Silicon hosts** (QEMU/UTM) with
architecture-aware provisioning.

## What's Inside

| Component | Purpose | Port |
|-----------|---------|------|
| [Detonator](https://github.com/dobin/detonator) | Web UI + REST API for orchestrating detonations | 5000 (UI), 8000 (API) |
| [DetonatorAgent](https://github.com/dobin/DetonatorAgent) | Executes malware samples and collects EDR alerts | 8080 |
| [Fibratus](https://github.com/rabbitstack/fibratus) | Kernel ETW telemetry, behavior rules, YARA scanning | - |
| [Rustinel](https://github.com/Karib0u/rustinel) | Sigma/YARA/IOC detection engine via ETW | - |
| [LitterBox](https://github.com/BlackSnufkin/LitterBox) | Payload analysis sandbox (static + dynamic + EDR scoring) | 1337 |

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│  Windows 11 VM (Hyper-V or QEMU/UTM)                                     │
│                                                                           │
│  ┌──────────────┐    ┌──────────────────┐    ┌──────────────────┐        │
│  │  Detonator   │───▶│ DetonatorAgent   │    │   LitterBox      │        │
│  │  (Python)    │    │ (.NET 8.0)       │    │   (Python)       │        │
│  │  :5000/:8000 │    │ :8080            │    │   :1337          │        │
│  └──────────────┘    └────────┬─────────┘    └────────┬─────────┘        │
│                               │                       │                   │
│                    ┌──────────┴──────────┐   ┌────────┴─────────┐        │
│                    │  Executes sample    │   │ Static analysis   │        │
│                    │  Collects EDR logs  │   │ PE-Sieve, Moneta  │        │
│                    └──────────┬──────────┘   │ YARA, RedEdr ...  │        │
│                               │              └────────┬─────────┘        │
│              ┌────────────────┼────────────────┐      │                  │
│              ▼                                 ▼      ▼                  │
│  ┌──────────────────┐              ┌──────────────────┐                  │
│  │    Fibratus      │              │    Rustinel       │                  │
│  │  (ETW + Rules)   │              │ (ETW + Sigma +   │                  │
│  │                  │              │  YARA + IOC)      │                  │
│  └──────────────────┘              └──────────────────┘                  │
│              │                                 │                          │
│              ▼                                 ▼                          │
│     Windows Event Log                  NDJSON alerts                      │
│     (JSON format)                  (C:\tools\rustinel\logs)              │
└──────────────────────────────────────────────────────────────────────────┘
```

## Platform Support

| Host OS | Hypervisor | Guest Arch | Vagrantfile | Performance |
|---------|-----------|------------|-------------|-------------|
| Windows 10/11 (x86_64) | Hyper-V | x86_64 | `Vagrantfile` | Native (fastest) |
| macOS Apple Silicon (M1-M4) | QEMU via vagrant-qemu | ARM64 | `Vagrantfile.utm` | Near-native via hvf |

### How It Works on Each Platform

**Windows Host (Hyper-V)**
- Uses the standard `Vagrantfile` with the `hyperv` provider
- Guest runs Windows 11 x86_64 natively on Hyper-V
- All tools (Fibratus, Rustinel, Sysmon, .NET, Python) run as native x86_64 binaries
- Port forwarding handled by Hyper-V virtual switch
- Box: `gusztavvargadr/windows-11` from Vagrant Cloud (auto-downloaded)

**macOS Host (UTM/QEMU)**
- Uses `Vagrantfile.utm` with the `vagrant-qemu` provider
- Guest runs Windows 11 ARM64 under Apple's Hypervisor.framework (hvf)
- Architecture-aware provisioning detects `$env:PROCESSOR_ARCHITECTURE -eq "ARM64"`:
  - **Sysmon**: Native ARM64 binary (`Sysmon64a.exe` from the same Sysmon.zip)
  - **Fibratus**: x86_64 binary under Windows ARM emulation (no ARM64 build available)
  - **Rustinel**: x86_64 binary under Windows ARM emulation (no ARM64 build available)
  - **.NET 8 / Python 3.12**: Native ARM64 (full support)
  - **DetonatorAgent**: Builds natively for ARM64 via .NET 8
- Windows ARM's emulation layer runs x86_64 tools transparently with ~10-20% overhead
- ETW kernel tracing works under emulation (kernel itself is native ARM64)

## Prerequisites

### Windows Host (Hyper-V)

- **Windows 10/11** with Hyper-V enabled
- **Vagrant** >= 2.4 ([download](https://www.vagrantup.com/downloads))
- **Administrator** PowerShell (required for Hyper-V)
- ~30 GB free disk space
- ~8 GB RAM available for the VM

```powershell
# Enable Hyper-V (run as Administrator, reboot required)
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All
```

### macOS Host (Apple Silicon - UTM/QEMU)

- **macOS** on Apple Silicon (M1, M2, M3, M4)
- **Homebrew**: install from https://brew.sh
- **QEMU**: `brew install qemu`
- **Vagrant**: `brew install --cask vagrant`
- **vagrant-qemu plugin**: `vagrant plugin install vagrant-qemu`
- **Windows 11 ARM64 Vagrant box** (see below)
- ~80 GB free disk space
- ~8 GB RAM available for the VM

**Obtaining the Windows 11 ARM64 box:**

There is no official Windows 11 ARM64 box on Vagrant Cloud. You need to create one:

*Option A - Build with Packer (recommended):*
```bash
# Download Windows 11 ARM64 ISO from Microsoft:
# https://www.microsoft.com/software-download/windows11arm64

# Use a Packer template for ARM64
git clone https://github.com/StefanScherer/packer-windows
cd packer-windows
# Follow ARM64 build instructions in the repo, output: windows11-arm.box

# Import the box
vagrant box add win11-arm output/windows11-arm.box --provider qemu
```

*Option B - Convert from existing UTM/QCOW2 VM:*
```bash
# 1. Create a Windows 11 ARM VM manually in UTM
# 2. Inside the VM, configure WinRM for Vagrant (elevated PowerShell):
winrm quickconfig -force
winrm set winrm/config/service '@{AllowUnencrypted="true"}'
winrm set winrm/config/service/auth '@{Basic="true"}'
net user vagrant vagrant /add
net localgroup Administrators vagrant /add

# 3. Shut down the VM, locate the .qcow2 disk image
# 4. Package into a Vagrant box:
mkdir box-build && cd box-build
cat > metadata.json << 'EOF'
{"provider": "qemu"}
EOF
cp /path/to/disk.qcow2 box-disk.qcow2
tar czf win11-arm.box metadata.json box-disk.qcow2 Vagrantfile

# 5. Import:
vagrant box add win11-arm win11-arm.box --provider qemu
```

*Option C - Community box (check availability):*
```bash
vagrant cloud search windows-11-arm --provider qemu
```

## Quick Start

### Windows (Hyper-V)

```powershell
# Clone this repo
git clone https://github.com/your-user/transportable-detonation-chamber.git
cd transportable-detonation-chamber

# Start the VM (run as Administrator for Hyper-V)
vagrant up --provider=hyperv

# The first boot takes ~20-30 minutes (downloads + installs)
```

### macOS Apple Silicon (QEMU)

```bash
# Clone this repo
git clone https://github.com/your-user/transportable-detonation-chamber.git
cd transportable-detonation-chamber

# Use the UTM Vagrantfile
cp Vagrantfile.utm Vagrantfile.local
export VAGRANT_VAGRANTFILE=Vagrantfile.utm

# Start the VM
vagrant up --provider=qemu

# The first boot takes ~30-45 minutes (ARM emulation + downloads)
```

> **Note**: On macOS, you can also symlink the Vagrantfile:
> `ln -sf Vagrantfile.utm Vagrantfile` (then just use `vagrant up`).

Once provisioning completes, the services start automatically:

- **Unified Web UI**: http://localhost:9000 (recommended - integrates everything)
- **Detonator Web UI**: http://localhost:5000
- **Detonator REST API**: http://localhost:8000
- **DetonatorAgent API**: http://localhost:8080
- **LitterBox Web UI**: http://localhost:1337

## Usage

### Unified Interface (Recommended)

Open http://localhost:9000 for the integrated Detonation Chamber UI which combines:
- **Tracing tab**: Real-time Rustinel/Fibratus alerts with process tree, activity counters, 
  DNS/registry/file events, and full Sigma/YARA rule match details
- **Analysis tab**: LitterBox static analysis results and detection scores
- **Submit tab**: Upload samples to both DetonatorAgent (dynamic) and LitterBox (static) at once

### Submit a sample via Detonator Web UI

1. Open http://localhost:5000 in your browser
2. Upload your malware sample
3. Select the `localdetonator` profile
4. Submit and observe detection results

### Analyze a sample via LitterBox

1. Open http://localhost:1337 in your browser
2. Upload your payload
3. LitterBox runs static analysis (PE-Sieve, Hollows-Hunter, YARA, etc.)
4. Optionally dispatches to Fibratus EDR for dynamic detection
5. Get a Detection Score with indicator breakdown

### Submit via command line

```powershell
# From inside the VM (vagrant rdp or vagrant ssh):
cd C:\detonator
.venv\Scripts\activate
python -m detonatorcmd --profile localdetonator your_sample.exe
```

### Submit via REST API (from host)

```powershell
# Upload and detonate a file
$file = Get-Item ".\malware_sample.exe"
Invoke-RestMethod -Uri "http://localhost:8000/api/files" -Method Post -InFile $file.FullName

# Check submissions
Invoke-RestMethod -Uri "http://localhost:8000/api/submissions" -Method Get
```

### Check DetonatorAgent status

```powershell
# From host
Invoke-RestMethod -Uri "http://localhost:8080/api/lock/status"
# Returns: {"in_use":false}
```

## VM Management

### Common Commands (both platforms)

```powershell
# Stop the VM
vagrant halt

# Start the VM (services auto-start)
vagrant up

# SSH into the VM
vagrant ssh

# RDP into the VM
vagrant rdp

# Re-run provisioning (if you changed configs)
vagrant provision

# Destroy and rebuild from scratch
vagrant destroy -f
vagrant up --provider=hyperv   # Windows
vagrant up --provider=qemu     # macOS (with VAGRANT_VAGRANTFILE=Vagrantfile.utm)

# Take a snapshot (recommended before detonation)
vagrant snapshot save clean_state

# Restore snapshot
vagrant snapshot restore clean_state
```

### macOS-specific Notes

```bash
# Set the UTM Vagrantfile persistently
export VAGRANT_VAGRANTFILE=Vagrantfile.utm

# Or symlink for convenience
ln -sf Vagrantfile.utm Vagrantfile

# If vagrant-qemu hangs on boot, increase the timeout:
# Edit Vagrantfile.utm and set config.vm.boot_timeout = 1800

# Connect via RDP (install Microsoft Remote Desktop from App Store)
vagrant rdp
# Or manually: open rdp://localhost:3389
```

## Configuration

### Custom Fibratus rules

Place YARA/detection rules in `config/` and re-provision, or directly in the VM at:
- `C:\Program Files\Fibratus\Rules\`

### Custom Rustinel rules

Add Sigma/YARA/IOC rules to:
- `C:\tools\rustinel\rules\sigma\` - Sigma rules (.yml)
- `C:\tools\rustinel\rules\yara\` - YARA rules (.yar)
- `C:\tools\rustinel\rules\ioc\` - IOC feeds (hashes.txt, ips.txt, domains.txt)

Rules hot-reload automatically (no restart needed).

### Custom Detonator profiles

Edit `config/profiles_init.yaml` and run `vagrant provision --provision-with configure`.

### Custom LitterBox scanners and YARA rules

LitterBox comes with bundled scanners (PE-Sieve, Hollows-Hunter, Moneta, Patriot, etc.)
and YARA rulesets (Elastic, YARA-Forge). Add custom rules inside the VM:
- `C:\LitterBox\Scanners\Yara\rules\` - Custom YARA rules
- `C:\LitterBox\Config\edr_profiles\` - EDR dispatch profiles

### Defender exclusions

The provisioning adds Defender exclusions for detonation paths. To fully disable Defender
for testing (not recommended for production):

```powershell
# Inside the VM, run as Administrator
Set-MpPreference -DisableRealtimeMonitoring $true
```

## File Structure

```
transportable-detonation-chamber/
├── Vagrantfile                    # VM definition (Windows host, Hyper-V)
├── Vagrantfile.utm                # VM definition (macOS Apple Silicon, QEMU)
├── config/
│   ├── fibratus.yml              # Fibratus EDR config (JSON eventlog output)
│   ├── rustinel-config.toml      # Rustinel EDR config (Sigma/YARA/IOC paths)
│   └── profiles_init.yaml        # Detonator target profiles
├── webui/                         # Unified web interface
│   ├── app.py                    # Flask backend (API aggregation, alert loading)
│   ├── requirements.txt
│   ├── templates/index.html      # SPA shell
│   └── static/
│       ├── css/style.css         # Dark theme (Rustinel-inspired)
│       └── js/app.js             # Frontend logic (process tree, detail panels)
├── scripts/
│   ├── install-prerequisites.ps1 # .NET 8, Python 3.12, Git, Chocolatey, 7-Zip
│   ├── install-sysmon.ps1        # Sysmon (ARM64-aware: Sysmon64a.exe)
│   ├── install-fibratus.ps1      # Fibratus v3.0.0 (ARM64 emulation warning)
│   ├── install-rustinel.ps1      # Rustinel v1.1.1 (ARM64 emulation warning)
│   ├── install-detection-rules.ps1 # Sigma + YARA rules (rustinel-rules + Elastic)
│   ├── install-detonator.ps1     # Detonator + DetonatorAgent from source
│   ├── install-litterbox.ps1     # LitterBox payload analysis sandbox
│   ├── install-webui.ps1         # Unified web UI
│   └── configure-services.ps1    # Start all services (runs on every boot)
└── README.md
```

## Troubleshooting

### Services not starting

```powershell
# SSH/RDP into the VM and check manually
vagrant ssh

# Check service status
Get-Process fibratus, rustinel, DetonatorAgent -ErrorAction SilentlyContinue

# Manually start services
& "C:\Program Files\Fibratus\fibratus.exe" run
& "C:\tools\rustinel\rustinel.exe" run
cd C:\DetonatorAgent && dotnet run -- --port 8080 --edr fibratus
cd C:\detonator && .venv\Scripts\python.exe -m detonator
cd C:\LitterBox && venv\Scripts\python.exe litterbox.py
```

### Port forwarding not working

Hyper-V uses a virtual switch. If port forwarding fails, connect directly via the VM's IP:

```powershell
# Find the VM's IP
vagrant ssh -c "ipconfig"
```

### Vagrant SMB sync errors

If synced folders fail, set environment variables before `vagrant up`:

```powershell
$env:VAGRANT_SMB_USER = "your_windows_username"
$env:VAGRANT_SMB_PASS = "your_windows_password"
vagrant up --provider=hyperv
```

### DetonatorAgent API returns errors

```powershell
# Check if the agent is running and on which EDR mode
curl http://localhost:8080/api/lock/status

# View agent logs
Get-Content C:\tools\logs\DetonatorAgent.log -Tail 50
```

### macOS/UTM: QEMU won't start

```bash
# Verify QEMU is installed and supports hvf
qemu-system-aarch64 --accel help
# Should show: hvf

# Check that the EFI firmware exists
ls /opt/homebrew/share/qemu/edk2-aarch64-code.fd
# If missing: brew reinstall qemu

# Check vagrant-qemu plugin is installed
vagrant plugin list | grep qemu
```

### macOS/UTM: VM boots but WinRM times out

The Windows 11 ARM64 box must have WinRM configured:
```powershell
# Inside the VM (via UTM console or manual RDP):
winrm quickconfig -force
Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value true
Set-Item WSMan:\localhost\Service\Auth\Basic -Value true
New-NetFirewallRule -Name "WinRM" -DisplayName "WinRM" -Protocol TCP -LocalPort 5985 -Action Allow
```

### Rustinel not detecting events

```powershell
# Check Rustinel is running
Get-Process rustinel

# Check Rustinel log for ETW errors
Get-Content C:\tools\rustinel\logs\rustinel.log.* | Select-Object -Last 20

# Verify ETW trace session
logman query -ets | findstr rustinel

# If the ETW session is stale, stop and let Rustinel recreate it:
logman stop rustinel-etw-trace -ets
Start-ScheduledTask -TaskName "Rustinel"
```

## Security Notes

- This VM is designed for **malware analysis** - treat it as compromised
- Use snapshots before each detonation
- Network isolation is recommended (use Hyper-V internal/private switch)
- Defender exclusions are configured for detonation paths only
- Rustinel active response is **disabled by default** - enable after testing

## ARM64 Limitations (macOS/UTM)

When running on Apple Silicon via QEMU:

| Component | ARM64 Support | Notes |
|-----------|--------------|-------|
| Sysmon | Native | `Sysmon64a.exe` included in Sysmon.zip |
| Fibratus | Emulated (x86_64) | No ARM64 build; MSI installs under emulation |
| Rustinel | Emulated (x86_64) | No ARM64 build; ETW works under emulation |
| .NET 8 | Native | Full ARM64 SDK and runtime |
| Python 3.12 | Native | ARM64 installer from python.org |
| DetonatorAgent | Native | Compiled from source via .NET 8 |
| Detonator/LitterBox | Native | Python-based, runs on ARM64 Python |

**Known ARM64 caveats:**
- First launch of emulated x86_64 binaries is slower (JIT compilation of emulation)
- Fibratus kernel driver may have reduced functionality under emulation
- Some YARA rules that scan PE sections may behave differently for ARM64 PEs
- Total provisioning time is ~30-45 min vs ~20-30 min on native x86_64

## Detection Rules

The VM ships with a curated detection ruleset installed by `install-detection-rules.ps1`:

**Sigma Rules (20 rules from `Karib0u/rustinel-rules` windows-advanced pack):**
- 14 process_creation rules (encoded PowerShell, schtasks, LOLBins, credential dumping)
- 3 registry_event rules (Run key persistence, Defender tampering, WDigest)
- 1 task_creation rule (suspicious scheduled task actions)
- 1 ps_script rule (PowerShell script block logging)
- 1 service_creation rule

**YARA Rules (717 compiled rules):**
- Rustinel-rules pack: malware family signatures
- Elastic protections-artifacts: threat detection rules from Elastic Security

**IOC Engine:**
- Hash matching (MD5/SHA1/SHA256)
- Hot-reload: add IOCs at runtime, rules refresh within 2 seconds

Rules are loaded from:
- Sigma: `C:\tools\detection-rules\rustinel-rules\dist\windows-advanced\rules\sigma\`
- YARA: `C:\tools\detection-rules\yara-combined\` (junction combining both sources)
- IOC: `C:\tools\detection-rules\rustinel-rules\dist\windows-advanced\rules\ioc\`

## Credits

- [dobin/detonator](https://github.com/dobin/detonator) - Orchestration framework
- [dobin/DetonatorAgent](https://github.com/dobin/DetonatorAgent) - Execution agent
- [rabbitstack/fibratus](https://github.com/rabbitstack/fibratus) - ETW detection engine
- [Karib0u/rustinel](https://github.com/Karib0u/rustinel) - Sigma/YARA EDR agent
- [BlackSnufkin/LitterBox](https://github.com/BlackSnufkin/LitterBox) - Payload analysis sandbox
