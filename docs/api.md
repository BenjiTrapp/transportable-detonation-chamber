# API Reference

Which routes the Web UI serves on port 9000, and which tools the MCP server
offers to an MCP client.

Responses are JSON.

## Core

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/alerts` | All detection alerts (Rustinel + Fibratus + LitterBox). gzip + ETag; `raw` omits fields duplicated at top level (`raw_trimmed: true`). Filters: `severity`, `engine`, `pid`, `since` (ISO-8601), `detonated=true`, `limit` (newest first) |
| GET | `/api/alerts/<id>` | One alert with its complete raw event |
| GET | `/api/processes` | Tracked processes with activity counts. Params: `max` (0 = all), `min_threats` (default 1), `sort` (`threats`/`recent`/`severity`), `detonated`, `include_parents` |
| GET | `/api/processes/<key>` | One process instance with its alerts. `<pid>` = newest process with that PID, `<pid>@<start epoch>` = an earlier one |
| GET | `/api/sessions` | Alerts grouped into activity bursts (summaries + alert ids). Params: `gap` (s, default 600), `limit` |
| GET | `/api/status` | Service health status (all components) |
| GET | `/api/health` | Liveness probe |
| GET | `/api/wiki` | Whether the offline wiki `static/wiki.html` is on this machine, and the file's last modification in UTC: `present`, `built` (ISO-8601, `null` without the file). The stamp is that copy's mtime, which a deploy can renew — the date the file was built from and the commit it was built at are in the wiki's own footer. The help asks this; `make docs` builds the file |
| POST | `/api/service/launch` | Start a service/tool. Param: `service` |
| GET | `/api/service/configs` | Detected service launch configurations |
| GET | `/api/rustinel` | Rustinel engine info (rules, version) |
| GET | `/api/submissions` | Submission history (last 200) |

## Submission & Detonation

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/submit` | Submit sample (multipart). Params: `file`, `target` (agent/litterbox/both) |
| GET | `/api/detonation/results` | Poll results. Params: `sha256`, `pid`, `litterbox_hash`, `filename` |

## Process Graph

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/process-graph` | Ancestors + descendants of a process with network, DNS, file, registry, injection and named pipe (`pipes`, `pipes_truncated`, `pipes_error`) events. Params: `pid` (PID or instance key), `at` (ISO time: the process that had the PID then), `down_depth` (0 = all), `up_depth`, `max_nodes` |
| GET | `/api/process-graph/roots` | Candidate focus processes (detonated / most alerts) |
| GET | `/api/graph/samples` | Submitted and scanned files with their scan verdicts |
| GET | `/api/pipes` | Sysmon named pipe events (EID 17/18) with catalog family. Params: `pid`, `key` (process instance key; window defaults to its lifetime), `since` (default: one hour ago), `until`, `name` (case-insensitive substring; a leading `\` anchors it at the start of the pipe name), `max` |

## Named Pipe Interception

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/pipes/intercept` | Interception sessions (live and ended), newest first |
| POST | `/api/pipes/intercept` | Start a session → 201 session (state `starting` until the first upstream is open, then `active`; `armed` while an arm session waits) / 400 error. JSON: `pattern` (required), `mode` (`observe`/`hold`), `how` (`attach`/`arm`), `match` (`exact`/`prefix`/`regex`), `squat` (arm + exact only), `max_duration` (default 600 s, at most 3600), `hold_timeout` (default 30 s, at most `max_duration`; both finite), `pipe_mode` (`byte`/`message`; skips probing the real server). Refused (400): `\lsass`, `\ntsvcs`, `\protected_storage`, `\lsarpc`, `\samr`, `\netlogon`, `\svcctl`, `\epmapper`, `\InitShutdown`; arm + exact for a pipe that already exists. 429 with 16 live sessions; 413 for a body over 2 MiB |
| GET | `/api/pipes/intercept/<sid>` | One session (state, target, connection and message counts, `self_connect_retries`: upstream connects that landed on the proxy's own instance and were retried) |
| DELETE | `/api/pipes/intercept/<sid>` | End a session; held messages are forwarded, both ends are closed |
| GET | `/api/pipes/intercept/<sid>/messages` | Recorded messages (`seq`, `conn`, `dir` `c2s`/`s2c`, `data_b64`, `state`: `held`, `passed`, `auto_passed`, `edited`, `dropped`, or `write_failed` when relaying a decided message failed). Params: `after` (seq), `limit` (default 200, max 1000) |
| POST | `/api/pipes/intercept/<sid>/messages/<seq>` | Decide a held message. JSON: `action` (`forward`/`drop`/`edit`), `data_b64` (for `edit`) |
| POST | `/api/pipes/intercept/<sid>/release` | Forward every held message → `{"released": n}` |
| GET | `/api/pipes/intercept/<sid>/export` | Session and all messages as a JSON attachment |

Windows hands a connecting client the oldest free instance of a pipe, whoever owns it. Once a session is `active` the proxy keeps that a proxy instance: when a client arrives it first creates its next listening instance and only then connects upstream for this client, so the connect takes the real server's current spare and the server's next spare is younger than the proxy's. Only before the first client is an upstream opened in advance (that is what the `starting` state waits for); it consumes the server instance that predates the session, and right after the first client one more upstream is opened and closed at once to consume the spare the server created for it. After that the server never holds an idle proxy connection. If an upstream connect lands on the proxy's own instance instead (the instance's client process id is the web UI's), the proxy closes it, gives the server a moment to create its next instance (backing off up to 1 s) and retries with a fresh instance; each such episode counts once in `self_connect_retries`. Without `pipe_mode`, the proxy reads the real server's pipe mode from a throw-away instance of its own (Windows gives every instance the type of the first one), so the probe never takes one of the server's instances; passing `pipe_mode` skips it. Only one live session may own a pipe: a second session for the same exact name is refused (400), and armed prefix/regex watchers skip pipes another session owns, because one session's upstream connect could otherwise land on the other's listening instance. Not intercepted are connections that existed before the session started or were made while it was `starting`, and a client that connects in the instant in which no proxy instance is listening (during a self-connect retry, or while the real server had no free instance).

## Hex Editor & Binary Analysis

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/file/hex` | Hex dump. Params: `path`, `offset`, `bytes` |
| POST | `/api/file/hex/upload` | Upload file for hex viewing |
| POST | `/api/file/hex/write` | Patch bytes (JSON: `path`, `offset`, `bytes`); analysis folders only |
| GET | `/api/file/download` | Download a file as attachment. Param: `path` |
| GET | `/api/file/signature` | Authenticode signer and trust. Param: `path` |
| GET | `/api/file/pe/section` | One PE section: hex dump and strings. Params: `path`, `index`, `max_bytes` |
| GET | `/api/file/pe` | PE header analysis. Param: `path` |
| GET | `/api/file/elf` | ELF binary analysis. Param: `path` |

## Rizin

One rizin session per opened file and browser tab (RIZIN tab). Addresses are integers in answers; in requests `addr` is decimal or `0x…`. Errors: 400 `{"refused": reason}` for invalid input, a refused console command or a file that cannot be opened (missing, empty, a folder); 403 for a UNC path or a path outside the folders that `/api/file/download` serves too (which include the uploads in `%TEMP%\rizin_uploads`); 404 `{"error": "session ended"}` (with `reason` when rizin stopped during that request); 409 `{"busy": true, "step"}` while an analysis step or another request has rizin (views wait about 2 s first), `{"moved": true}` once the file was opened in another tab, or `{"superseded": true}` for an open that a newer open of the same tab overtook; 500 `{"error"}` when rizin could not open the file ("rizin could not open the file: …"), answered something unexpected ("rizin answered something unexpected: …") or answered one of the three lists that are filtered on the server (strings, imports, flag names) with more than 32 MB ("too many strings to list here …: filter them in the console") or answered more than the limit of the command it ran ("rizin's answer to pdfj is larger than 67108864 bytes": 64 MB for the disassembly or the decompiler of one function, 256 MB for every other view), or a file on the VM could not be read or written (a full disk: "a file could not be read or written on the VM: …", "the upload could not be stored: …"); 503 `{"error": "rizin not installed", "path"}`.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/rizin/status` | `installed`, `path` (`TDC_RIZIN`), `version`, `ghidra` (rz-ghidra loads) |
| GET | `/api/rizin/files` | What the tab can open, existing non-empty files only: `submissions` (`filename`, `path`, `sha256`, `time`), `dumps` under `C:\dumps` (newest 500) and `uploads` (`name`, `path`, `size`) |
| POST | `/api/rizin/upload` | Upload a file (multipart `file`) to `%TEMP%\rizin_uploads` → `{"path"}` |
| POST | `/api/rizin/open` | Open a file. JSON: `path`, `tab` (browser tab ID) → `session`, `file` (`path`, the real one that was checked, `sha256`, `size`, `format`, `arch`, `bits`), `analysis`. A new file replaces the tab's session; the same file in another tab moves its session there, and while its session still closes it waits for that session's last save |
| GET | `/api/rizin/<sid>/status` | `analysis` (`state`, `step`, `done_steps`, `level`, `elapsed`, `note`), `seek`, `function`, without asking rizin |
| POST | `/api/rizin/<sid>/analyze` | Start the full analysis (aaa's steps one by one) → `analysis`. Between two steps the session pauses about 2 s, longer while requests use rizin (at most about 10 s), and answers requests; `step` is `null` then |
| POST | `/api/rizin/<sid>/close` | End the session (also the page's `sendBeacon` on pagehide) → `{"closed": true}` |
| GET | `/api/rizin/<sid>/functions` | `[{name, offset, size, nbbs}]` by address, read from rizin's `afl` (its row is about 63 B, while `aflj` carries about 2.7 KB per function); at most 200 000 of them, a line that is no row left out |
| GET | `/api/rizin/<sid>/disasm` | The function around `addr` from its start (the first page reaches `addr`), linear outside functions → `function`, `ops` (`offset`, `size`, `text`, `type`, `jump`, `comment`), `more` (outside functions not after a page of only invalid instructions; the RIZIN tab stops the linear disassembly after 2000 lines). Params: `addr`, `count` (default 400, at most 2000), `after` (the next page) |
| GET | `/api/rizin/<sid>/graph` | Basic blocks of the function around `addr` → `function`, `offset` (its entry), `nodes` (`offset`, `size`, `lines`, `jump`, `fail`, `cases`; edges only between its blocks) |
| GET | `/api/rizin/<sid>/decompile` | rz-ghidra's C for the function around `addr` → `available`, `reason`, `function`, `lines` (`text`, `offset` as `pdgo` shows it, `offsets`: every address of the line). `pdgj` may take up to 120 s (`DECOMPILE_TIMEOUT`); over it rizin is stopped and the session ends: 404 with `reason` "Decompiling took too long, the session ended." |
| GET | `/api/rizin/<sid>/hex` | Bytes at `addr` → `offset`, `bytes`, `paddr` (where they are in the opened file, from rizin's map there; `null` where no byte of the file is: a zero-filled part, no map, past the end). Param: `len` (default 512, at most 4096) |
| GET | `/api/rizin/<sid>/xrefs` | References to `addr` and from it; at a function's entry from the whole function → `scope`, `function`, `to`, `from` (`from`, `to`, `type`, `text`, `function`), `truncated` (over 500) |
| GET | `/api/rizin/<sid>/strings` | Strings, filtered and paged on the server → `total`, `items` (`offset`, `string`, `length`, `section`, `type`), `truncated` (rizin listed more than 200 000: the rest is left out). Params: `q`, `offset`, `limit` (default 200, at most 1000) |
| GET | `/api/rizin/<sid>/imports` | Imports, filtered (name or library) and paged → `total`, `items` (`offset`, `name`, `library`, `type`, `ordinal`), `truncated`. Params: `q`, `offset`, `limit` |
| GET | `/api/rizin/<sid>/flags` | Flag names for the console's Tab: those that start with `q` (any case), sorted → `total`, `names` (at most `limit`, default and most 200), `common` (the start all of them share, also those past `limit`), `truncated` (of more than 200 000 flags the rest is left out; of a `flj` over 32 MB none at all: `names` is empty and `common` is `""`, so Tab then lists the names of the tab's function list without completing one). rizin is asked again after a console command, a rename, a comment or an analysis step; requests that come while it is asked wait for that answer |
| POST | `/api/rizin/<sid>/seek` | JSON: `addr` (a number, `0x…`, or a function or flag name) → `seek`, `function` |
| POST | `/api/rizin/<sid>/console` | Run a rizin command. JSON: `cmd` → `output` (ANSI colours), `seek`, `function`, `truncated` (about 1 MB), `changed` (it renamed or commented). Allowlist on the server: no shell, no files, no other files opened, no debugging |
| POST | `/api/rizin/<sid>/rename` | Rename the function at `addr`. JSON: `addr`, `name` → `offset`, `name`; kept in the project |
| POST | `/api/rizin/<sid>/comment` | Comment at `addr` (an empty `text` removes it). JSON: `addr`, `text` → `offset`, `comment`; kept in the project |
| GET | `/api/rizin/<sid>/comment` | The comment at `addr` as the disassembly shows it → `offset`, `comment` (`""` without one); the right-click menu's Comment… field reads it where the disassembly has not loaded the address |

## Sysmon

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/sysmon` | Sysmon events. Params: `max`, `event_id`, `pid`, `parent_pid`, `since`, `until` |
| GET | `/api/sysmon/stats` | Sysmon statistics and diagnostics |

## ETW Browser

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/etw/channels` | List available channels. Param: `probe=true` adds availability status |
| GET | `/api/etw/events` | Query events. Params: `channel`, `max`, `since`, `filter` |

## Scanner

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scan/threatcheck` | ThreatCheck scan. Params: `file`/`path`, `engine`, `type` |
| POST | `/api/scan/defendercheck` | DefenderCheck scan. Params: `file`/`path` |
| POST | `/api/scan/ember` | EMBER2024 ML score. Params: `file`/`path`, `model`, `threshold` |
| POST | `/api/scan/capa` | capa capability detection (ATT&CK/MBC). Params: `file`/`path` |
| GET | `/api/scan/status` | Tool availability (ThreatCheck, DefenderCheck, EMBER2024, capa, Hunt-Sleeping-Beacons, BeaconEye, Aether, Process Dump, Exit Capture) |
| GET | `/api/scan/history` | Static scan timeline, newest first; each entry's `exists` says whether its file (`result.filepath`) is still there for the RIZIN tab (inside the folders the download serves, not empty). Param: `limit` |
| POST | `/api/scan/history/clear` | Clear the scan timeline |
| POST | `/api/scan/beacons` | Hunt-Sleeping-Beacons. Param: `pid` (omit for all) |
| POST | `/api/scan/beaconeye` | BeaconEye (Cobalt Strike configs). Param: `pid` (omit for all) |

## Live Memory

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scan/aether` | Aether scan of a PID, scored. Params: `pid`, `samples` (1-10), `interval` (s) |
| POST | `/api/scan/processdump` | Dump a PID's memory components. Params: `pid` or `system`, `ignore_clean_db` |
| POST | `/api/memory/evidence` | Re-score all cached memory results for a PID across sources. Params: `pid` |
| GET / DELETE | `/api/memory/baseline` | Host memory baseline statistics / clear it. `stale: true` means it was built with an older key scheme and is ignored until captured again |
| POST | `/api/memory/baseline/capture` | Record findings of named processes as baseline. Params: `names`, `samples` |
| POST / GET | `/api/memory/sweep` | Background sweep of every process (`aether`, `processdump`, `syscalls` (opt-in, off unless `true`), `baseline`) / status + result |
| GET / POST | `/api/processdump/baseline` | Process Dump clean-hash database status / build it (`mode`: `gen`, `genquick`) |
| GET | `/api/process/lookup` | Running PIDs by image name. Params: `name` |
| GET | `/api/file/visualize` | File map planes + structure + import/export trees. Params: `path`, `cols`, `rows` |

## Syscalls

Read-only measurement of the syscall stubs of a process against a baseline NTSleuth extracted from this system's ntdll and win32u. `view` is `arm64`, `x64` or `x86` (default: this host's own); a baseline exists for the first two. A request without a baseline for this build answers `503` (`400` for a scan) and starts the extraction in the background: `--no-symbols` when the symbol server cannot be reached, which leaves the parameter table incomplete and the measurement as it was. An x64 extraction whose RVAs and stub bytes equal the arm64 baseline's is not stored.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/syscalls/status` | `installed` and `path` of NTSleuth, `executables` per view, the system `build`, `baselines` (`build`, `view`, `current`, `symbols`, a `note` when the parameters are incomplete) and the background `extraction` (`running`, `failed` with `reason` and `indistinguishable`: true when the x64 extraction was the arm64 view, so no x64 baseline is stored and the host cannot measure emulated x64 samples) |
| GET | `/api/syscalls/baseline` | The syscall catalog, paged. Params: `view`, `query` (name substring or number), `module`, `offset`, `limit` (max 500), `lean` (`1`: each item is only its `name`, `module` and `number`, which is what the map reads; the default is the full item with `parameters` and `stub_hex`) |
| GET | `/api/syscalls/<name>` | One syscall with parameters, stub bytes and the compared `prefix_len`. Param: `view`. `404` for an unknown name |
| POST | `/api/syscalls/scan` | Measure a PID against the baseline of its view (read from the image, not from the request); scored in the evidence model and added to the scan history. Params: `pid`, `modules` (`ntdll.dll`, `win32u.dll`). `504` after 120 s |
| POST | `/api/syscalls/stubs` | Search for syscall stubs outside ntdll: in a process's private executable memory (`pid`) or in a file (`path` inside the readable folders, with `view`). Each hit names its syscall. `import_present` is `false` when the sample's import table, widened through the curated Win32-to-Nt table (`webui/win32_to_nt.json`), holds no path to it: a proven bypass. It is `true` when the sample imports the function as well, and `null` where no curated row leads to the syscall or the import table cannot be read (for a `pid`, the table of the process image); `imports_read` says whether it was read. `partial` says the search did not cover all it set out to |
| GET / POST / DELETE | `/api/syscalls/hook-baseline` | The hooks known on this host, as (syscall, owner) pairs per build and view / record the hooks of a PID (`pid`; only on a host known to be clean, and only a jump into a module, never a patch) / forget one set (`build` and `view` together) or all. Known hooks stay in the scan but no longer score |
| POST | `/api/syscalls/rule` | Draft a detection rule and write nothing. Params: a `hit` of `/api/syscalls/stubs` (optionally with `sample`), with `view` and `build` (default: this system's), gives a YARA rule `{kind, name, text, target}` that names its build and view; a `deviation` of `/api/syscalls/scan` with `view` gives an entry for `webui/syscall_signatures.json` and the catalog entries that already cover it. A known hook is refused, and so is a hit whose `stub_hex` is not exactly one stub of its view loading its `number` |
| POST | `/api/syscalls/rule/apply` | Write a YARA draft (the body of the draft, nothing else is accepted) as `<name>.yar` into the directory Rustinel reads (`C:\tools\detection-rules\yara-combined\tdc`); it should be loaded within about two seconds (hot reload, not yet verified on a VM). `409` when the rule is already there, `403` outside that directory, `507` when it holds 200 rule files, `500` when `tdc` is a link or junction. Only a rule `check_draft` could have made, of a stub of its view, is written |
| GET | `/api/syscalls/rule/download` | A YARA draft as a file, to be committed under `rules/yara/` so it is version-controlled and reviewable (the applied copy is lost with the VM; whether a committed rule is loaded again after a rebuild is not yet verified). Params: `name` and `text` of the draft |

## Proxy Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET/POST | `/api/litterbox/<path>` | Proxy to LitterBox API (:1337) |
| GET/POST | `/api/agent/<path>` | Proxy to DetonatorAgent (:8080) |
| GET/POST/PUT/DELETE | `/api/detonator/<path>` | Proxy to Detonator |

Proxied responses are only relayed as data (JSON, text, binary); HTML is served as plain text.

## Tool Updates

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/updates` | Update state: `mode` (`idle`/`checking`/`updating`), `checked_at`, one entry per tool (`installed`, `available`, `status`, `pinned`, `detail`, `log`), `progress`, `last_run` |
| POST | `/api/updates/check` | Start an update check in the background (202; 409 while a check or install runs) |
| POST | `/api/updates/apply` | Install updates. Body: `tools` (list of tool ids or `"all"` alone), `include_pinned` (default `false`). 202; 400 for a bad body, unknown ids or `"all"` mixed into a list; 409 with the reason while a detonation, memory sweep or process dump runs. While an install runs, POST/PUT/PATCH/DELETE requests elsewhere answer 503 (`maintenance: true`) |

## Logs

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/logs/search` | Search the log store with an SPL-like query. Params: `q` (default `*`), `earliest` (default `-24h`; `-15m`, `-2h`, `now` or ISO-8601), `latest`, `limit` (1-1000, default 200). 200 with `type` (`events`, `table` or `timechart`), `events`, `columns`, `rows`, `count`, `matched`, `truncated`, `histogram`, `fields` and `took_ms`; 400 with `error` and `pos` (index in the query) for a query or time that cannot be read; 500 with a general `error` for anything else. Every request is itself logged (`access`; `mcp` too when the MCP server made it), polling paths with `poll=true` |
| GET | `/api/logs/event/<id>` | One event of the log store in full (`id`, `time`, `source`, `message`, `fields`). A search response cuts every string at 64 KB and marks the event with `truncated_fields: true`; this route has the whole text. 404 with `error` when the event has left the store |
| GET | `/api/logs/sources` | The six sources (`powershell`, `access`, `mcp`, `netflow`, `dns`, `firewall`): `count`, `last_time`, `status` (`ok` or `unavailable`) and `hint` (why a source is unavailable) |

## Dashboards

Own dashboards of the Dashboard tab: a tile is a saved log search. Nothing is computed
on the server — the browser fetches every tile's numbers from `/api/logs/search`. Kept in
`webui/dashboards.json`; at most 10 dashboards, 12 tiles each, name 1-60 characters without
control characters, query at most 4000 characters, `earliest`/`latest` at most 40. A body that is
not a JSON object, carries an unknown field (it is named) or breaks a limit answers 400 with
`error`; an id that is gone 404 `Dashboard not found.` / `Panel not found.`; a write that fails 500
`The dashboards could not be saved; see the web UI log.`

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/dashboards` | Every dashboard in order: `id` (`d-` and 12 hex characters), `name`, `created` (ISO-8601 Z) and `panels`, each tile with `id` (`p-`), `name`, `query`, `form`, `earliest`, `latest` and `created`. A damaged file reads as what is still readable, never as an error |
| POST | `/api/dashboards` | Add a dashboard → 201 `{"dashboard": {...}}`. JSON: `name` (required). Names may repeat, the `id` is the key |
| PATCH | `/api/dashboards/<id>` | Rename a dashboard → `{"dashboard": {...}}`. JSON: `name` (required) |
| DELETE | `/api/dashboards/<id>` | Delete a dashboard and all its tiles → `{"deleted": true}` |
| POST | `/api/dashboards/<id>/panels` | Save a search as a tile → 201 `{"panel": {...}}`. JSON: `name`, `query`, `form` (`table`, `pie`, `bars`, `line` or `sankey`), `earliest`, `latest` (both optional, default empty = the whole store) |
| PATCH | `/api/dashboards/<id>/panels/<pid>` | Change a tile → `{"panel": {...}}`. JSON: `name`, `form`, `move` (`up`/`down`; at the end of the list it does nothing); at least one of them. Query and time range do not change — that is a new tile |
| DELETE | `/api/dashboards/<id>/panels/<pid>` | Delete one tile → `{"deleted": true}` |

## Firewall

Times are ISO-8601 UTC text; a flow's `times` is a list of epoch seconds. Errors are `{"error": ...}` with 400 (malformed), 404, 409 (refused: the Windows Firewall is off, a lockout, a block that could not be verified) or 500. Every action is an `access` event in the LOGS tab — the ones TDC takes by itself under `/internal/firewall/block`, `/internal/firewall/decide` and `/internal/firewall/fetch`, each with `by` (`detector`, `analyst` or `deadline`), the endpoint, the URL, the User-Agent that was sent and the outcome.

ISOLATED blocks the default way out and switches off Windows' own outbound Allow rules; what still gets out is in `allowed_out`. TDC's own fetch is let out one address at a time, only while it runs (`TDC-FW-ISO-fetch-*`, one rule per binary the fetch can run as, removed when the fetch ends, retried at every collector round, and swept at start-up and once a minute for a rule a crash left behind); what that leaves open is in `residual` of `GET /api/firewall/isolate`. A rule that could not be removed again is named in `fetch_paths_open` there, on the capture (`allow_closed`: `true` gone, `false` still standing with `close_problem` saying why, `null` nothing to close because ISOLATED is off, or because ISOLATED is on but the fetch gave up waiting for a sweep (or for the removal of that endpoint's rules) and opened none, with `allow_problem` saying so) and as an `/internal/firewall/allow` event in LOGS.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/firewall/connections` | Bundled flows with `tags`, `severity`, `geo` (`scope`, `cc`, `country`, `lat`, `lon`, `asn`, `as_org`), `state` (`allowed`, `blocked`, `pending`), `rule_id`, `capture_ids`. Params: `since`, `until` (ISO-8601 or epoch), `process` (substring of the image), `tag`, `state`, `max` (1-5000, default 500). Also `count`, `truncated`, `rules_error` (why the rules could not be read; nothing is then claimed as blocked), `isolated`, `ask_mode`, `sources` |
| GET | `/api/firewall/summary` | Totals, blocked and pending flows, top processes, endpoints and countries of the same window, plus `open_decisions`, `captures_total`, `geo_available` |
| GET | `/api/firewall/geo` | One offline lookup: `ip` gives `{ip, geo, available}` |
| GET | `/api/firewall/rules` | The `TDC-FW-*` rules that stand, one entry per rule: `rule_id`, `kind`, `image`, `ip`, `port`, `protocol`, `key`, `blocking`, `cuts` (true only for `TDC-FW-ISO-cut` standing as the catch-all Block) |
| POST | `/api/firewall/block` | `{scope, image, ip, port, protocol}`. `endpoint`: this program to `ip`; `endpoint_all`: every program, TDC's fetcher included; `process`: `image` anywhere. 409 while a firewall profile is off |
| POST | `/api/firewall/unblock` | `{rule_id}`; every rule that shares its key is removed |
| GET / POST | `/api/firewall/isolate` | GET: `isolated`, `stage` (`open`, `cut`, `isolated`, `cut_policy`), `converging` (the background worker runs), `converge_note` (what its last round said, or why it failed), `verified` (`null` while not isolated; in `cut` and `cut_policy` the cut rule read back and, read again within 10 s, still standing as written; in `isolated` Block in force on every profile and `allowed_out` empty; false in every stage while a profile is off or unreadable), `can_fetch` (always `false` in `cut` and `cut_policy`; `null` when not known), `outbound_before`, `isolated_since`, `profiles_off`, `startup`, `residual`, `allowed_out` (in `isolated` and `cut_policy`: Windows' own outbound Allow rules still enabled, read back, each `{name, display, group, source, local}`; `null` while ISOLATED is off, in stage `cut` on purpose, or when `allowed_out_error` says it could not be read), `allow_disabled` (how many rules ISOLATED holds switched off), `fetch_paths_open`, `fetches_in_flight`. The PowerShell reads behind it are cached: `profiles_off` for 60 s, but for 10 s while ISOLATED is on or after an error; `allowed_out` for 10 s; in the cut stages the read of the cut rule for 10 s (the rule list the tab polls counts as one). `profiles_off` and `allowed_out` are read again after every enforcement route. POST `{on: true}`: cut (409 while a profile is off); answers after the cut with `stage: "cut"`, `rule_id`, `verified` (the cut rule read back by this press), `converging`, `outbound_before`, `note` and `state` (the GET above). POST `{on: false}`: leave from any stage, stopping the worker at its next step (the answer can wait for the call it is in); the answer has `cut_removed`, `outbound_after`, `allow_disabled` (rules that would not switch on again), `note` and `state` |
| GET | `/api/firewall/pending` | `pending` (open decisions with `remaining` seconds and `can_fetch`: `false` while the cut stands or a block for every program stands on the endpoint, so CUT + FETCH is refused and the deadline only blocks; `null` when the rules cannot be read) and `history` (the last 24 h), `ask_mode`, `decide_seconds`, `isolated`, `startup` (`{id, announce, note}` of this server start, `null` until it was read: the toast on every tab) |
| POST | `/api/firewall/decide` | Exactly `{id, action}` (`allow`, `block`, `block_fetch`); no URL is ever taken. An id works once, a second answer gets the decision that was taken. `block_fetch` is refused with 409 while the cut stands (no Allow exception gets through the catch-all Block rule) or a block for every program stands on the endpoint |
| POST | `/api/firewall/ask` | `{mode}`: `detonation`, `all` or `off` (kept on the server) |
| POST | `/api/firewall/enable` | `{}`: switch the Windows Firewall on for every profile (TDC never does it by itself: it changes what the sample sees). `{enabled, profiles_off, state}`; 500 when a profile stays off |
| POST | `/api/firewall/kill` | `{pid}`: `taskkill /PID <pid> /F` for a process with connections in the tab, never one of TDC's own (409). `{pid, killed, image}`; 500 when taskkill fails |
| GET | `/api/firewall/captures` | The secured samples, newest first |
| GET | `/api/firewall/capture/<id>` | One capture with its metadata and whether its file still exists |

## MCP Server

`mcp/server.py` exposes the lab to MCP clients (Claude Code, Claude Desktop, ...)
over stdio (49 tools). It talks to the web UI API, so the VM must be reachable.

```bash
make mcp-setup        # creates mcp/.venv (Python >= 3.10) from mcp/requirements.txt
```

`.mcp.json` in the repository root registers it for Claude Code; set `TDC_URL`
there if the VM is not at `http://192.168.64.4:9000`.

| Area | Tools |
|------|-------|
| Status | `tdc_status`, `tdc_service_launch`, `tdc_tools_status`, `tdc_rustinel_info` |
| Tool updates | `tdc_updates_status`, `tdc_updates_check`, `tdc_updates_apply` |
| Detonation | `tdc_submit_file`, `tdc_submissions`, `tdc_detonation_results`, `tdc_detonation_memory` |
| Alerts | `tdc_alerts`, `tdc_alert_detail`, `tdc_sessions`, `tdc_search` |
| Processes | `tdc_processes`, `tdc_process_detail`, `tdc_process_graph`, `tdc_process_lookup`, `tdc_powershell_activity` |
| Events | `tdc_sysmon_events`, `tdc_sysmon_stats`, `tdc_etw_events`, `tdc_etw_channels` |
| Static analysis | `tdc_scan_ember`, `tdc_scan_capa`, `tdc_scan_threatcheck`, `tdc_scan_defendercheck`, `tdc_scan_history` |
| Files (paths in the VM) | `tdc_pe_analyze`, `tdc_pe_section`, `tdc_elf_analyze`, `tdc_file_signature`, `tdc_file_hex`, `tdc_file_map` |
| Named pipes (read-only) | `tdc_pipes`, `tdc_pipe_sessions` |
| Logs | `tdc_logs_search` |
| Firewall (read-only) | `tdc_firewall_connections`, `tdc_firewall_captures` |
| Live memory | `tdc_memory_scan`, `tdc_memory_dump`, `tdc_memory_evidence`, `tdc_memory_baseline`, `tdc_memory_sweep`, `tdc_memory_sweep_status`, `tdc_processdump_baseline`, `tdc_scan_beacons`, `tdc_scan_beaconeye` |

Every request of the MCP server carries `X-TDC-Client: mcp` and
`X-TDC-MCP-Tool: <tool name>`; the web UI logs them as `mcp` events, so a search
such as `source=mcp | stats count by tool` shows what an MCP client did.

Not exposed on purpose: byte patching (`/api/file/hex/write`), clearing the
scan history, starting, stopping or steering pipe interception (forward, drop,
edit), the raw service proxies, and everything of the FIREWALL tab that acts
(block, unblock, ISOLATED, the ASK switch, answering a decision, KILL, turning
the firewall on): a model must not take the chamber off the network or lift a
block on its own.

**Next:** [Development](development.md)
