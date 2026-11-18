# Named Pipes

How the chamber sees the pipes a sample uses, and how it steps into one.

Beacons talk to their child processes and to each other over named pipes
(Cobalt Strike's `\msagent_##`, `\postex_*`, `\status_*`; PsExec-style
`\PSEXESVC`, Covenant's `\gruntsvc`, ...). The chamber watches pipes in two
ways.

## A: Observation (passive, from Sysmon)

Sysmon logs every pipe creation (EID 17) and connection (EID 18). The
provisioning switches the SwiftOnSecurity `PipeEvent` filter from its short
include list to **exclude** mode, so every pipe is logged except a few noisy
pairs of image *and* pipe name (Chrome/Edge Mojo and Crashpad pipes; `\lsass`
from `lsass.exe`, `\ntsvcs` from `services.exe`, `\srvsvc`/`\wkssvc` from
`svchost.exe`, all in `System32`; Defender from its platform folder) - never by
name alone. Anonymous pipes are logged too (Sysmon writes `<Anonymous Pipe>`)
and dropped when the events are read. The
Sysmon log is enlarged to 512 MB.

After a detonation, the pipe events of the sample's process subtree are
attributed to process instances and listed in the **NAMED PIPES** section of
the results. The query is pipe-first: the subtree's own PIDs are queried
first (window: submission to the subtree's last exit + 60 s, at most 6 h),
then every party on the pipes the sample touched by exact pipe name (up to 20
names; names with quotes are not queried), so unrelated host activity cannot
push the sample's events out of the 2000-event cap. `truncated` reports a cap
hit or names that were not looked up.

| Flag | Meaning | Evidence (weight) |
|------|---------|-------------------|
| `c2_default` | name matches the catalog `webui/pipe_signatures.json` (C2 defaults, credential dumpers, remote-exec tools, APT pipes) | structural, weight from the catalog (C2 4.0, remote exec 3.0); never baseline-suppressed, counted once per pipe |
| `cross_process` | created by the sample tree and connected by a process outside it (or the other way round) | behavioural 1.5, needs corroboration |
| `sensitive_system` | the sample connects to `\svcctl`, `\lsarpc`, `\samr`, `\netlogon` or `\atsvc` | behavioural 1.0, needs corroboration |
| `random_name` | a name token looks generated: GUID, hex run (≥ 6, digits and letters), or ≥ 12 characters with high entropy that mix digits and letters or have almost no vowels; tokens are split at `\ - _ . ` and spaces, so PIDs and counters do not count. Common Windows/runtime/browser pipes (`\Winsock2\CatalogChangeListener-*`, `\dotnet-diagnostic-*`, `\PIPE_EVENTROOT\*`, Chrome/Mojo/Crashpad, ...; `BENIGN_PIPE_PREFIXES` in `pipe_analysis.py`) are never flagged - only this flag is affected | string 0.8, needs corroboration |

Pipe findings enter the same evidence model as live memory (source
`sysmon-pipes`), so a default C2 pipe alone makes a sample SUSPICIOUS, and
together with a memory finding on the same process it corroborates it. The
catalog is plain JSON: add an entry (`pattern`, `match` exact/prefix/contains/regex,
`family`, `weight`, `note`) without touching code. It includes Metasploit's
`\msf-pipe` (the default `PIPENAME` of `reverse_named_pipe`); Sliver has no
default pipe name (the operator always chooses it), so it has no entry.

"Sweep as baseline" (Live Process Memory) also records the pipes of the last
30 minutes as known for this host, keyed by image path and a normalised name
(`\status_4a3f` → `\status_*`). Catalog pipes, random names and all-wildcard
names are never baselined.

In the **Graph** tab the **Pipes** toggle (on for detonated roots, off
otherwise) adds pipe nodes for the processes shown; in the isometric view two
processes on the same pipe are joined by a bridge. The **Pipes** tab lists raw
pipe events with name, PID and time filters.

## B: Interception (active, pipe-intercept style)

The **Pipes** tab starts interception sessions in the web UI process:

| Option | Values |
|--------|--------|
| How | **attach** to an existing pipe (exact name), or **arm** before a detonation: a watcher takes the first *new* pipe matching an exact name, prefix (e.g. `postex_`) or regex. Arm with an exact name that already exists is refused ("use attach") |
| Mode | **observe** (relay and record) or **hold** (each message waits until you forward, edit or drop it; auto-forwarded after the hold timeout) |
| Squat | opt-in, arm + exact only: the proxy creates the pipe before the real server does |
| Limits | 10 min default session (≤ 1 h), at most 16 live sessions, 1 MiB logged per message, 50 MiB per session. In hold mode a direction stops reading while its first message is held and the session already queues 16 MiB or 1000 messages (the pipe buffer fills and the sender blocks); a message-mode message over 16 MiB closes the connection. `\lsass`, `\ntsvcs`, `\protected_storage` and their NPFS aliases `\lsarpc`, `\samr`, `\netlogon`, `\svcctl`, `\epmapper`, `\InitShutdown` are refused (observation still sees them, e.g. `sensitive_system`) |

The proxy adds its own server instances of the pipe. Each client that lands
on one gets its own upstream connection to the real server, opened with
identification-only impersonation so a malicious server cannot borrow the web
UI's SYSTEM token. Recordings are written to `webui/pipe_sessions/` when a
session ends and can be exported as JSON; sessions do not resume after a
restart. The MCP tools can read sessions and recordings but cannot start or
steer them.

```text
Pipes tab → pattern "msagent_", match prefix, how arm, mode observe → Start
Submit tab → detonate the sample → the session attaches to \msagent_<hex>
```

## Limitations

- Interception needs the pipe name (or a prefix/regex) in advance. A client
  that was already connected before the session, or connects while the
  session is `starting`, is not intercepted.
- Servers that check their peer (client PID, token) or that create their pipe
  with `FILE_FLAG_FIRST_PIPE_INSTANCE` and refuse extra instances can notice
  or defeat the proxy.
- Squat creates the pipe first; a server that insists on owning the first
  instance fails to start. Use it only on purpose.
- Without an explicit `pipe_mode` the proxy reads the server's byte/message
  mode from a throw-away instance of its own; it never connects to the server
  for that. A client that connects in the instant this instance exists (only
  possible while the server has no free instance) loses its connection when
  it is closed; passing `pipe_mode` avoids even that.
- The 30-minute pipe window of "Sweep as baseline" includes a recent
  detonation's pipes - run it on a clean box only.
- Observation depends on Sysmon; with `available: false` the results say so
  instead of showing an empty list.
- The proxy's own pipe events are hidden by the web UI's current PID. After a
  restart, events of the previous web UI process show up in the Pipes tab's
  event list as `python.exe`; they are never attributed to a sample (the web
  UI is not in a sample's process tree).

**Next:** [Rizin](rizin.md)
