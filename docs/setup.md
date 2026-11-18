# Setup

What your host needs before the VM exists, and what is different on an ARM64 Mac.

## Platform Support

| Host OS | Hypervisor | Guest Arch | Vagrantfile | Performance |
|---------|-----------|------------|-------------|-------------|
| Windows 10/11 (x86_64) | Hyper-V | x86_64 | `Vagrantfile` | Native |
| macOS Apple Silicon (M1-M4) | QEMU via vagrant-qemu | ARM64 | `Vagrantfile.utm` | Near-native via hvf |

## Prerequisites

What has to be in place before the VM can be provisioned, per host.

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
- **UTM** (recommended): `brew install --cask utm` or [mac.getutm.app](https://mac.getutm.app)
- **QEMU tools**: `brew install qemu` (for `qemu-img`)
- **Python 3** with `pywinrm`: `pip3 install pywinrm requests-ntlm`
- **Windows 11 ARM64 ISO** from [Microsoft](https://www.microsoft.com/software-download/windows11arm64)
- ~80 GB disk, ~8 GB RAM

#### Recommended Setup (UTM + automated provisioning)

The fastest path on Apple Silicon uses UTM as the hypervisor with automated
provisioning via WinRM. A single script handles everything after the initial
Windows installation:

```bash
# Full guided setup (installs prerequisites, guides VM creation, provisions)
./scripts/setup-macos-utm.sh

# Or step by step:
./scripts/setup-macos-utm.sh --skip-prerequisites   # if tools already installed
./scripts/setup-macos-utm.sh --provision-only --vm-ip 192.168.64.4  # re-provision existing VM
```

**Manual steps** (the script guides you through these):

1. Install UTM and create a Windows 11 ARM64 VM (8 GB RAM, 4 cores, 80 GB disk)
2. Install Windows normally with a local admin account (`vagrant`/`vagrant` recommended)
3. Run `scripts/prepare-vagrant-winrm.ps1` inside the VM (enables WinRM remote management)
4. Run `./scripts/setup-macos-utm.sh --provision-only --vm-ip <vm-ip>`

The provisioning installs all detection engines, analysis tools, and the unified
Web UI (~20-40 minutes on first run).

#### Alternative: Vagrant/QEMU (headless, experimental)

For a fully headless Vagrant-managed workflow, see
[Vagrantfile.utm](../Vagrantfile.utm). This path requires building a custom
`win11-arm` Vagrant box from the ISO:

```bash
make prerequisites-fix          # Install QEMU, Vagrant, vagrant-qemu plugin
./scripts/build-box-macos.sh --iso ~/Downloads/Win11_ARM64.iso
make build                      # Provision the VM
```

> **Note:** Headless QEMU boot of Windows 11 ARM64 ISOs can be unreliable on
> some QEMU/firmware combinations. The UTM path above is recommended.

### Local Development Only

No VM, just the Web UI: the tabs and features render, the backend services are
absent.

- **Python 3.10+** (any platform)
- **Make** (macOS: Xcode CLI tools; Windows: not needed, use `make.ps1`)

## ARM64 Compatibility

On an ARM64 VM the OS, the agent and the runtimes are native; the detection
engines and the memory scanners that have no ARM64 build run under Windows'
x86_64 emulation, which is what the x64 samples do too.

| Component | ARM64 Support | Notes |
|-----------|--------------|-------|
| Sysmon | Native | `Sysmon64a.exe` (ARM64 binary) |
| Fibratus | Emulated (x86_64) | No ARM64 build; ~10-20% overhead |
| Rustinel | Emulated (x86_64) | No ARM64 build; ETW works under emulation |
| .NET 8 / Python 3.12 | Native | Full ARM64 SDK and runtime |
| DetonatorAgent | Native | Compiled from source via .NET 8 |
| Detonator / LitterBox | Native | Python-based |
| Aether | Emulated (x86_64) | Deliberately x64: its thread-context probe uses the AMD64 `CONTEXT` layout, so a native ARM64 build would misread it |
| Process Dump | Emulated (x86_64) | `-closemon` is **not used**: it writes x64 hook bytes into every process and cannot tell ARM64 processes apart (Exit Capture replaces it) |
| Exit Capture | Native | OS feature (Silent Process Exit); emulator translation cache is recognized and not scored |
| Hunt-Sleeping-Beacons / BeaconEye | Emulated (x86_64) | x64 builds; reliable for x64 (emulated) targets, results for native ARM64 processes are marked as limited |
| rizin + rz-ghidra | Emulated (x86_64) | Cutter's Windows package is x64 only; `aaa` of a 150 KB sample takes about 2 s, `aa` of a 31 MB exit dump about 3 s (see [rizin.md](rizin.md)) |

What this costs in a memory verdict is in [memory.md](memory.md#arm64-hosts) under the
ARM64 hosts section.

**Next:** [Installation](installation.md)
