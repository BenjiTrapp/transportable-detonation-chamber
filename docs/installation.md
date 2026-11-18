# Installation

How the Web UI and the full VM come up, with `make`, with `make.ps1` or by hand.

Before any of this, check [setup.md](setup.md): the VM needs a hypervisor, a Windows
11 image and about 30 GB (x86_64) or 80 GB (ARM64) of disk.

## Option A: local UI only (no VM)

Run the Web UI locally for development or UI testing. Backend services won't be
available, but all tabs and features render normally.

```bash
# macOS / Linux
make install    # Creates venv, installs Flask + deps
make run        # Starts on http://localhost:9000
```

```powershell
.\make.ps1 install
.\make.ps1 run
```

## Option B: full VM (recommended for analysis)

```bash
# macOS Apple Silicon (M1-M4) — UTM-based setup (recommended)
./scripts/setup-macos-utm.sh    # Guided: installs tools, creates VM, provisions

# macOS / Linux — Vagrant-based (requires pre-built box)
make up         # Provisions the full Windows 11 VM
make open       # Opens http://<vm-ip>:9000 in browser
```

```powershell
# Windows, run as Administrator
.\make.ps1 up
.\make.ps1 open
```

> First boot takes ~20-30 minutes (Windows) or ~30-45 minutes (macOS ARM).

The provisioning installs the detection engines, the analysis tools and the Web UI;
`scripts/configure-services.ps1` registers the services and runs on every boot. The
guided UTM path and its `--provision-only` re-run are described in
[setup.md](setup.md).

## Using make / make.ps1

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
| `docs` | Build the offline wiki from `docs/` into `webui/static/wiki.html` |
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

## Manual Installation

```bash
cd webui
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py               # http://localhost:9000
```

## Pushing changes to a running VM

`make deploy-restart` copies the Web UI files to the VM and restarts Flask in one
step; `scripts/deploy-utm.py` does the same over WinRM with `--restart` (without it
it only deploys) and can also run a single installer script:

```bash
python3 scripts/deploy-utm.py --vm-ip <vm> --vm-user tdc --vm-pass tdc --install install-sysmon.ps1
```

**Next:** [Configuration](configuration.md)
