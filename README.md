# Transportable Detonation Chamber

A pre-configured Windows 11 VM for malware detonation testing against multiple EDR solutions.
Uses Vagrant + Hyper-V to provision a fully automated analysis environment.

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
│  Windows 11 VM (Hyper-V)                                                 │
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
│     (JSON format)                  (C:\tools\rustinel\alerts)            │
└──────────────────────────────────────────────────────────────────────────┘
```

## Prerequisites

- **Windows 10/11 host** with Hyper-V enabled
- **Vagrant** >= 2.4 ([download](https://www.vagrantup.com/downloads))
- **Administrator** PowerShell (required for Hyper-V)
- ~30 GB free disk space
- ~8 GB RAM available for the VM

### Enable Hyper-V

```powershell
# Run as Administrator
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All
# Reboot required
```

## Quick Start

```powershell
# Clone this repo
git clone https://github.com/your-user/transportable-detonation-chamber.git
cd transportable-detonation-chamber

# Start the VM (run as Administrator for Hyper-V)
vagrant up --provider=hyperv

# The first boot takes ~20-30 minutes (downloads + installs)
```

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
vagrant up --provider=hyperv

# Take a snapshot (recommended before detonation)
vagrant snapshot save clean_state

# Restore snapshot
vagrant snapshot restore clean_state
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
├── Vagrantfile                    # VM definition
├── config/
│   ├── fibratus.yml              # Fibratus EDR config (JSON eventlog output)
│   ├── rustinel-config.toml      # Rustinel EDR config
│   └── profiles_init.yaml        # Detonator target profiles
├── webui/                         # Unified web interface
│   ├── app.py                    # Flask backend (API aggregation)
│   ├── requirements.txt
│   ├── templates/index.html      # SPA shell
│   └── static/
│       ├── css/style.css         # Dark theme (Rustinel-inspired)
│       └── js/app.js             # Frontend logic
├── scripts/
│   ├── install-prerequisites.ps1 # .NET 8, Python, Git, Chocolatey
│   ├── install-fibratus.ps1      # Fibratus v3.0.0
│   ├── install-rustinel.ps1      # Rustinel v1.1.1
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

## Security Notes

- This VM is designed for **malware analysis** - treat it as compromised
- Use snapshots before each detonation
- Network isolation is recommended (use Hyper-V internal/private switch)
- Defender exclusions are configured for detonation paths only
- Rustinel active response is **disabled by default** - enable after testing

## Credits

- [dobin/detonator](https://github.com/dobin/detonator) - Orchestration framework
- [dobin/DetonatorAgent](https://github.com/dobin/DetonatorAgent) - Execution agent
- [rabbitstack/fibratus](https://github.com/rabbitstack/fibratus) - ETW detection engine
- [Karib0u/rustinel](https://github.com/Karib0u/rustinel) - Sigma/YARA EDR agent
- [BlackSnufkin/LitterBox](https://github.com/BlackSnufkin/LitterBox) - Payload analysis sandbox
