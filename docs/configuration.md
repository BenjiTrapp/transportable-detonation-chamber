# Configuration

Which settings the Web UI reads, which rules the engines load, and where you put
your own.

## Environment Variables (Web UI)

| Variable | Default | Description |
|----------|---------|-------------|
| `RUSTINEL_ALERTS_DIR` | `C:\tools\rustinel\logs` | Rustinel NDJSON alert directory |
| `RUSTINEL_INSTALL_DIR` | `C:\tools\rustinel` | Rustinel installation root |
| `DETONATOR_API` | `http://127.0.0.1:8000` | Detonator REST API |
| `DETONATOR_AGENT_API` | `http://127.0.0.1:8080` | DetonatorAgent API |
| `LITTERBOX_API` | `http://127.0.0.1:1337` | LitterBox API |
| `WEBUI_PORT` | `9000` | Web UI listen port |
| `WEBUI_HOST` | `0.0.0.0` | Listen address (`127.0.0.1` = VM only) |
| `TDC_ALLOWED_HOSTS` | — | Extra host names accepted in the `Host` header (comma-separated; IPs and `localhost` always work) |
| `TDC_VM_IP` | — | Address of the VM a host-side instance reaches over WinRM to start a service there, and the address its error messages name. Unset, the Web UI asks Hyper-V for the `DetonationChamber` VM's address and, failing that, falls back to `172.17.251.7` — and in both cases it **overwrites** `TDC_VM_WEBUI`, so set this one whenever you set that one |
| `TDC_VM_WEBUI` | — | Web UI of the VM, used by a host-side instance when it has no local Sysmon/alerts (only kept when `TDC_VM_IP` is set, see above) |
| `TDC_VM_USER` / `TDC_VM_PASS` | — | WinRM credentials for starting VM services from a host-side instance |
| `TDC_RIZIN` | `C:\tools\cutter\rizin.exe` | The rizin of the RIZIN tab (`scripts/install-rizin.ps1` installs it there) |
| `TDC_SCRIPTS_DIR` | `C:\tdc\scripts` | Where the web UI finds the install scripts it runs for [tool updates](updates.md) |
| `TDC_UPDATE_LOG` | `C:\tools\logs\tool-updates.log` | Log of the tool updates (off Windows: `tool-updates.log` next to `app.py`) |
| `TDC_UPDATE_CHECK_HOURS` | `24` | Hours between the automatic update checks; `0` turns them off |
| `TDC_NO_SYSCALL_STAGE` | — | `1` switches the syscall stage of a detonation off for the whole Web UI (the manual scan and the sweep stay available). Unset, the stage runs whenever a baseline of this build exists |
| `TDC_GITHUB_TOKEN` | — | Optional GitHub token for the update checks, to avoid the API rate limit |
| `TDC_LOG_DIR` | `webui/logs` (next to `app.py`) | Where the access and MCP logs of the LOGS tab are kept (`access.jsonl`, `mcp.jsonl`; 10 MB each, one older file) |
| `TDC_FIREWALL_DECIDE_SECONDS` | `30` | Seconds an open download decision waits before TDC blocks and fetches by itself; `0` fetches at once, without asking (held to one hour) |
| `TDC_FIREWALL_FETCH_LAN` | — | `1` lets the guarded fetch take a file from a **private** address (a lab whose stage 2 is served by an INetSim box). Refused by default: the analyst's own host is a private address away. This VM's own addresses and its gateways stay refused either way |

## The binary graph cache

The GRAPH view of the SYSCALLS tab ([The binary graph](memory.md#the-binary-graph)) is
drawn from one file, built locally from the PE files of the VM and kept beside
the syscall baselines:

```text
C:\tools\ntsleuth\baseline\binary-graph-<build>-<arch>.json
```

`<build>` is `CurrentBuildNumber.UBR` of the registry (for example
`26220.5770`) and `<arch>` is `arm64` or `x64`, the system's and read from the
registry, not the view of the process asking. There is exactly one cache per
build and architecture; a file named for another build or architecture is not
looked at, and the cache of an older build is left where it is. The path is not
configurable.

**At provisioning**, `scripts/build-binary-graph.ps1` builds it (`make deploy`,
`make.ps1 deploy` and `deploy-utm.py` copy it to `C:\tdc\scripts`, and setup runs it after
`install-webui.ps1`). It reads the import, delay-load and export tables of every
PE directly in `C:\Windows\System32`, about 4,000 files, with the VM's own Python
and `pefile`, follows every forwarded export through the api-set map to the
module that defines it, and writes the result in one piece. Nothing is
downloaded and nothing is asked of a service. A build takes a few minutes; the
script waits for it up to 30 minutes, and setup up to 40. A cache that is
already there is kept only when it loads: one that is cut short or zero-filled
(a power loss leaves such a file) is built again.

The script **always exits 0**. A graph that could not be built (the web UI's
Python is not installed yet, the registry cannot be read, the build timed out)
is a yellow warning with its reason, never a failed provisioning: a missing
cache is a state the tab handles, and the web UI builds one on demand.

**By hand**, as Administrator on the VM:

```powershell
C:\tdc\scripts\build-binary-graph.ps1 -Force
```

`-Force` builds it again even where a cache that loads exists (the tool updates
use it the same way). The tab takes the new file without a restart. From the repository, `python3
scripts/deploy-utm.py --vm-ip <vm> --vm-user tdc --vm-pass tdc --install
build-binary-graph.ps1` runs it on a VM.

**On demand**, the web UI builds a missing cache or one that does not load by
itself, in the background, the first time the GRAPH view or a figure asks for it. That build runs
at below-normal priority, so that it does not take the CPU from a sample under
observation, and reads the same 4,000 files, so expect a few minutes of disk
and a Python process of a few hundred MB while it runs. It is not started while
tool updates run. A failed build is not tried again for ten minutes, and after
**three failures in a row** not at all, until a usable cache appears: rebuild it by hand
as above. What the tab says in each state, and what to do, is in
[Troubleshooting](troubleshooting.md#syscalls-graph-says-there-is-no-binary-graph).
A syscall scan or a STUBS search never starts a build; it takes the graph that
is there.

## Detection Rules

| Type | Source |
|------|--------|
| **Sigma** | `Karib0u/rustinel-rules` windows-advanced pack |
| **YARA** | rustinel-rules + Elastic protections-artifacts (`C:\tools\detection-rules\yara-combined`) |
| **IOC** | SHA-256 hashes, IPs, domains, path regexes; sample hashes are added on submission |
| **Aether** | 380 in-memory signatures in `C:\tools\Aether\rules\` |

The number of rules Rustinel actually loaded is shown on the Dashboard and by
`GET /api/rustinel` / MCP `tdc_rustinel_info`.

## Custom Detection Rules

Drop your own rules into these directories inside the VM. Rustinel hot-reloads all
three, so no restart is needed.

**Sigma** (hot-reload):

```text
C:\tools\detection-rules\rustinel-rules\dist\windows-advanced\rules\sigma\
```

**YARA** (hot-reload):

```text
C:\tools\detection-rules\yara-combined\
```

**IOC hashes** (hot-reload, add SHA-256 one per line):

```text
C:\tools\detection-rules\rustinel-rules\dist\windows-advanced\rules\ioc\
```

## Sysmon Pipe Events

`scripts/install-sysmon.ps1` rewrites the downloaded SwiftOnSecurity config:
all `PipeEvent` include rules are replaced by one exclude group (image + pipe
name pairs only) and the Sysmon log is set to 512 MB
(`wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:536870912`). Re-run it
after updating the config:

```bash
python3 scripts/deploy-utm.py --vm-ip <vm> --vm-user tdc --vm-pass tdc --install install-sysmon.ps1
```

The pipe catalog `webui/pipe_signatures.json` is loaded once per web UI process;
restart the web UI after editing it.

## Defender Exclusions

Provisioning adds exclusions for detonation paths. To fully disable for testing:

```powershell
# Inside VM, run as Administrator
Set-MpPreference -DisableRealtimeMonitoring $true
```

## Security Notes

> **This VM is designed for malware analysis — treat it as compromised.**

- Use **snapshots** before each detonation (`vagrant snapshot save clean_state`)
- **Network isolation** recommended (Hyper-V internal/private switch)
- Defender exclusions configured for detonation paths only
- Rustinel active response is **disabled by default**
- The Web UI has no login — keep it on an isolated network: `/api/submit`
  executes files by design.

### Web UI hardening

- **Cross-site requests:** state-changing requests (POST/PUT/DELETE) whose
  `Origin`/`Referer` names another site are refused, so a web page opened in
  the VM's browser cannot submit samples or change settings. curl, the MCP
  server and scripts send no such header and are unaffected.
- **DNS rebinding:** only IP addresses, `localhost` and names listed in
  `TDC_ALLOWED_HOSTS` (comma-separated) are accepted in the `Host` header.
- **Writes:** `/api/file/hex/write` only writes inside the hex-upload folder,
  `C:\Temp`, `C:\Users\Public\Downloads` and `C:\dumps`, and never to script
  or shortcut files.
- **RIZIN console:** every command passes an allowlist on the server before
  rizin gets it: no programs, no other files, no writing, no debugging, and
  settings only for the disassembly and the analysis (see
  [Console without a shell](rizin.md#console-without-a-shell)). rizin opens files
  read-only, and names, strings and comments from a file are shown as text.
- **Headers:** no framing (clickjacking), `nosniff`, same-origin referrers.
- `WEBUI_HOST=127.0.0.1` restricts the listener to the VM itself.

**Next:** [Workflow](workflow.md)
