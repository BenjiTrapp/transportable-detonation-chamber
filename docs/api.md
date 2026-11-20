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
| POST | `/api/rizin/<sid>/emulation/start` | Start the emulation (ESIL) at `addr` (optional, default the current address). JSON: `addr` → the state as `GET …/emulation` answers it. Sets `io.cache=true` (without it the run's writes are lost; the file on disk is never written), `esil.timeout` (5 s: a run then stops by itself), the traps `esil.breakoninvalid`, `esil.exectrap`, `esil.iotrap`, `esil.nonull`, `esil.verbose=1`, `esil.romem=false` and a 960 KB stack, then runs `aei`, `aeim`, `aepc`. Registers other than the stack pointer, base pointer and PC keep the values they had (rizin's `aei` does not reset them). 400 `refused` when `io.cache` did not take or the stack could not be mapped |
| GET | `/api/rizin/<sid>/emulation` | The emulation's state → `running`, `pc`, `registers` (`name`, `value`, as `ar` lists them), `changed` (the names that the last change of the registers changed), `stack` (up to 16 words from the stack pointer upwards, only those inside the stack the start mapped, and `[]` when the stack pointer is not in it: `addr`, `value`, `hint`: in a mapped region, the function the value is in (`name` or `name + offset`) or a flag exactly at it, never one of the emulator's register flags; otherwise `null`), `stopped` (why the run stopped, or `null`), `arch`, `bits`. 400 `refused` "the emulation is not started" before a start |
| POST | `/api/rizin/<sid>/emulation/stop` | Leave the emulation (`aeim-`; the cached writes stay) → `{"running": false}` |
| POST | `/api/rizin/<sid>/emulation/run` | Run the emulation. JSON: `kind` (`step`, `over`, `skip`, `to_call`, `cont` or `until`; there is no step back: rizin 0.9.1's `aesb` restores no memory and the step after it runs without moving the PC), `addr` (for `until`) → the state, with `stopped`: why it stopped, one of `breakpoint` (rizin's `[ESIL] hit breakpoint`; also a disabled one: rizin 0.9.1 ignores `enabled`), `timeout` (`esil.timeout`, 5 s; read from the end of stderr, where a run that floods it with `int3` warnings says so), `invalid` (bytes rizin cannot decode), `trap` (the PC is where nothing can execute, or an invalid read or write) or `step` (it did what was asked). Before it runs, the start's `esil.*` settings are set again and `io.cache` and the stack are checked; 400 `refused` for an unknown `kind`, `until` without `addr`, a run before the start, `io.cache` that does not hold, an unmapped stack. `step` is `aes`; `over` is `aeso`, or `aesu` to the address after an indirect call, which `aeso` would step into; `skip` is `aess`, or the PC set after an indirect call (`call qword [import]`), which `aess` would run; `to_call` runs one step, then hops with `aesu` through the straight code to the next call of any kind (rizin's `aecc` runs past a call through the import table, and ignores `esil.timeout`) and stops before it; `cont` is `aec`; `until` is `aesu`. A run drops the cached strings, imports, flags and functions |
| POST | `/api/rizin/<sid>/emulation/register` | Set a register. JSON: `name` (one of those `ar` lists, otherwise 400 `refused`), `value` (decimal or `0x…`) → the state |
| GET | `/api/rizin/<sid>/breakpoints` | The breakpoints rizin holds (`dblj`), lowest address first → `[{addr, enabled}]`. They are rizin's own, not the emulation's: they can be set before it starts, they survive it, and none of these three needs a running one. `enabled` is reported as rizin reports it, because a console `dbd` can set it — but rizin 0.9.1 stops a run at a disabled breakpoint all the same, so nothing here switches one off. The breakpoints are kept in the project: the same file opened again has them back (rizin's own project holds them, measured). A command or a condition that a project's breakpoint carries (`dbc`, `dbC`, which rizin runs when it hits) is taken off when the project loads, and a project whose breakpoints cannot be shown to be free of them is not used at all |
| POST | `/api/rizin/<sid>/breakpoints` | Set a breakpoint (`db @ addr`). JSON: `addr` → `breakpoints` (the list as GET answers it). Setting one that is there already leaves it as it is and is no error; 400 `refused` for an `addr` that is no address, for an `on` (there is none: remove the breakpoint instead) and when rizin left the address out of its list afterwards (another breakpoint covers it, on an arch whose breakpoints are wider than a byte). An address outside every map is set: rizin marks it `valid: false` and stops its runs there all the same. A breakpoint makes the session's project be written (a project now comes of a breakpoint alone) |
| DELETE | `/api/rizin/<sid>/breakpoints` | Remove the breakpoint at `addr` (`db- @ addr`), or all of them (`db-*`) for a request without one. JSON: `addr`, optional; an empty object or no body at all removes them all → `breakpoints`. Removing one that is not there is no error. The removal is saved too: the project is written again |
| GET | `/api/rizin/<sid>/patches` | What rizin's write cache holds (`wcj`), lowest address first → `[{addr, size, before, after, mine}]`, **one row per write operation, not per byte** (a two-byte `wx` is one row of `size` 2; a second write over the same address is another row whose `before` is what the first one wrote). `mine` is `true` for a write this session made through POST `/patch`, `false` for every other write in the cache — what an emulation run wrote, or a console `wx`, **also where that write lies inside a range this session patched**: rizin has one cache for both, so the session keeps a mirror of its own writes in the order it made them and matches it row by row against `wcj` (the cache is append-only and a removal keeps the order of the rest, both measured). A write of this session that no row holds any more (a console `wc-`, a restarted rizin) stops counting as its own. Two writes of the same bytes to the same address cannot be told apart; either of them is the same byte. rizin's `idx` and `written` are left out (the index changes with every removal, and nothing here ever commits the cache). The file on disk is never written. A console `e io.cache=false` leaves the rows listed but without effect: rizin then reads the file's bytes again. **What stays:** the rows with `mine: true` go into the project (its `/tdc` namespace, as `addr:hex`) and are written back with `wx` when the file is opened again, before the first view loads; the rows with `mine: false` end with the session — they are bytes that never stood in the file. A saved patch whose address is in none of the new file's maps is left out, and the session's note says which |
| POST | `/api/rizin/<sid>/patch` | Write bytes at `addr` into the write cache (`wx … @ addr`) → `patches` (the list as GET answers it). JSON: `addr` plus **either** `bytes` (an even number of hex digits, at most 4096 bytes, nothing else: no spaces, no `0x`) **or** `kind`: `nop` (fill the instruction with `0x90`), `flip` (a conditional jump to its opposite), `always` (a conditional jump to an unconditional one to the same place: `eb` for `7x rel8`, `e9` for `0f 8x rel32`, whose displacement goes up by one because `e9` is a byte shorter, with a `nop` filling the length) or `nocall` (a call to `nop`s of its length). A `kind` reads the instruction with `pdj 1 @ addr` and needs no assembler (`wa` stays out: rizin can hand assembling to nasm or as); it is x86 only. Needs no running emulation: `io.cache=true` is set and read back first, because without it rizin loses the write and says so on stderr only. 400 `refused` for a bad `addr`, for `bytes` and `kind` together or neither, for bytes that are no even-length hex or longer than 4096, for a `kind` that does not apply to the instruction there (`'call' is no x86 conditional jump …`), for an address where rizin decoded no instruction, on another arch, when `io.cache` did not take, and when rizin's cache holds no write at the address afterwards. Drops the cached strings, imports, flags and functions, and makes the project be written (a patch alone is reason enough for one). At most 32 KB of `addr:hex` fit into the project; what does not fit is left out of the save and the session's note says how many, so the analysis progress in the same namespace is never at risk |
| DELETE | `/api/rizin/<sid>/patch` | Take back **every write that overlaps `addr`** (`wc- addr addr+1`: an explicit range, because `wc- addr` alone drops every write in a whole block of 0x100 bytes from there). rizin removes a write operation whole, so taking back one byte of a 4096-byte `wx` takes all 4096, and both writes at an address a second `wx` covered go together; the `patches` answered afterwards shows what is left. Without an `addr`, the whole cache (`wc-*`) — **an emulation run's bytes included**, since rizin has one. JSON: `addr`, optional; an empty object or no body at all takes them all back → `patches`. Taking back where there is nothing is no error; 400 `refused` for a bad `addr` and when rizin kept the write. Saved as well: a patch taken back does not come back at the next open. Starting the emulation again does *not* clear them (it would take the hand-made patches with it, which are meant to stick), so a run's writes outlive a restart: the cache sits above the stack `aeim` maps, and a restarted run's stack still shows the words the last one wrote there — this is the way to clear them. Drops the cached views like POST |

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
| POST / GET | `/api/memory/sweep` | Background sweep of every process (`aether`, `processdump`, `baseline`) / status + result |
| GET / POST | `/api/processdump/baseline` | Process Dump clean-hash database status / build it (`mode`: `gen`, `genquick`) |
| GET | `/api/process/lookup` | Running PIDs by image name. Params: `name` |
| GET | `/api/file/visualize` | File map planes + structure + import/export trees. Params: `path`, `cols`, `rows` |

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
