# Rizin Emulation and Patching Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the RIZIN tab an ESIL-based emulator with breakpoints, an API-call assistant and byte patching, so a decryption routine can be run to its result and an anti-VM check can be patched, exported and detonated — without ever starting a process or writing the original file.

**Architecture:** Ansatz 1 from the design: every route is a short command sequence against the existing session pipe, exactly like `pdfj` or `afl` today. rizin holds the state; the server reads it back with `ar`, `dblj` and `wcj`. Runaway runs are bounded by rizin's own `esil.timeout`, so no server-side stepping loop and no second state machine exist. Patches live in `io.cache` (memory); only the hand-made ones persist, in the project's `/tdc` namespace, and the export builds a patched copy in Python.

**Tech Stack:** Python 3 / Flask (`webui/app.py`, `webui/rizin_sessions.py`), vanilla JS (`webui/static/js/app.js`), CSS custom properties (`webui/static/css/style.css`, `theme-layout.css`), pytest, Node 20 for the frontend tests.

**Spec:** `docs/superpowers/specs/2026-11-20-rizin-emulation-design.md`

## Global Constraints

- rizin is **0.9.1** (Cutter 2.5.0 package). Every command used must be one the spec's Befunde table verified against it.
- rizin is never started with `-w`; the original sample is never written. `wci` and `wc+` stay refused everywhere.
- No process is ever started: no `d` command that executes or attaches (`ood`, `dp`, `dc`, `ds`, `dm`, `dk`, `dd`, `dbt`).
- `esil.timeout` must stay well below `rizin_sessions.CONSOLE_TIMEOUT` (60 s).
- Addresses in JSON answers are integers; in requests `addr` is decimal or `0x…`. In the browser an address is always a `"0x…"` string, never a JS number.
- Everything that comes out of rizin (import names, function names, strings) is escaped or set as `textContent`. Register and memory values are numbers but import names are not.
- Colours only as `var(--…)`; values only in `:root` of `style.css`; every new `.rizin-*`/`.rz-*` selector needs its `[data-theme]` counterpart in `theme-layout.css`.
- Bump `style.css?v=`, `theme-layout.css?v=` and `app.js?v=` in `webui/templates/index.html` (lines 22-24 and 1620) in every task that touches those files.
- Every new top-level `rizin*` function goes in `RIZIN_FUNCTIONS` and every new `RIZIN_*` const in `RIZIN_CONSTS`, both in `tests/test_rizin_ui.py` — `test_rizin_lists_cover_the_block` fails otherwise. No new top-level `let` (`RIZIN_LETS` must stay empty).
- Every new per-file state field must be cleared in `rizinReset()`.
- A new route name that does **not** touch the pipe must be added to `rizinUsesPipe()`'s exclusion list in `app.js`.
- Tests run without rizin: `tests/fake_rizin.py` stands in for it.

## Review Focus

Five things the spec requires but no task's own happy-path tests would exercise. Each gets a test in the task that owns the code.

1. **A 32-bit stdcall SKIP leaves the stack wrong** if the argument count is missing or wrong — every later step then computes on a corrupt stack, which is the spec's "die Oberfläche lügt" anti-goal. Test in Task 8.
2. **A patch inside an emulation-created buffer has no file offset**; the export must name it and still write the others, not abort or silently drop it. Test in Task 9.
3. **`aec` while standing on a breakpoint** re-hits the same breakpoint; without the step-off the UI appears frozen at one address. Test in Task 3.
4. **A project whose `/tdc` patch list names an address outside the reopened file** (the file changed, or the list is stale) must be skipped with a note, not applied blindly or crash the boot. Test in Task 6.
5. **An emulation run with `io.cache` off** writes nothing, so a decryption appears to do nothing at all. The start sequence must fail loudly if `io.cache` did not take. Test in Task 2.

---

## File Structure

| File | Responsibility | Change |
|------|----------------|--------|
| `webui/rizin_sessions.py` | Emulation lifecycle, stepping, breakpoints, patches, persistence, allowlist | Modify |
| `webui/rizin_emulation.py` | **New.** Pure logic: the API assistant table, calling conventions, patch-byte computation, stop-reason parsing. No pipe, no Flask — so it is unit-testable on its own. | Create |
| `webui/app.py` | The `/api/rizin/<sid>/emulation*`, `/patch*`, `/reanalyze` and `/export` routes; the export builder | Modify |
| `webui/static/js/app.js` | Run strip, `EMULATION` dock pane, gutter breakpoints, patch menu entries, export and hand-off | Modify |
| `webui/templates/index.html` | Run-strip markup, the `EMULATION` tab and pane, menu entries, asset versions | Modify |
| `webui/static/css/style.css` | `.rizin-run*`, `.rizin-emu*`, `.rizin-gutter*`, PC and breakpoint marks | Modify |
| `webui/static/css/theme-layout.css` | The Cyberpunk counterpart of every new selector | Modify |
| `tests/fake_rizin.py` | An ESIL VM model: registers, a step machine, breakpoints, a write cache, 32-bit mode | Modify |
| `tests/test_rizin.py` | Server tests: allowlist, sessions, routes, export | Modify |
| `tests/test_rizin_emulation.py` | **New.** Unit tests for `rizin_emulation.py` | Create |
| `tests/test_rizin_ui.py` | Frontend tests (Node) and the static lists | Modify |
| `README.md` | Tab table, the Emulation section, API rows, allowlist table, security section, limitations | Modify |

`rizin_emulation.py` exists so the assistant table, the convention arithmetic and the patch-byte rules can be tested without a pipe. `rizin_sessions.py` is already 1782 lines; putting the table there would make it unwieldy.

---

### Task 1: Allowlist — cache writes, the breakpoint list, esil settings

**Files:**
- Modify: `webui/rizin_sessions.py:161-232` (the filter constants), `:329-338` (`_check_name`), `:394-411` (`_check_eval`)
- Test: `tests/test_rizin.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `check_console_command(text) -> str | None` keeps its signature. After this task it allows `wx`/`wo`/`wz`/`w`/`wc`/`wc-`, `db`/`db-`/`dbl`/`dbd`/`dbe`/`dbs`/`dbn`, `aepc`, and `e esil.*=…`/`e io.cache=…`; it still refuses everything in the step-1 test.

`check_console_command` is a pure function, so this task is a test and a table change.

- [ ] **Step 1: Write the failing tests**

```python
def test_console_allows_emulation_and_cache_writes():
    for cmd in ("wx 9090", "wx 90 @ 0x401000", "wo x 41", "wz hi", "w text", "wc", "wcj", "wc- 0x401000",
                "wc-*", "db", "db @ 0x401000", "db- @ 0x401000", "db-*", "dbl", "dblj", "dbd", "dbe",
                "dbs", "dbn name", "aepc 0x401000", "e esil.timeout=5", "e io.cache=true",
                "e esil.breakoninvalid=true"):
        assert rizin_sessions.check_console_command(cmd) is None, cmd


def test_console_still_refuses_what_writes_executes_or_hangs():
    cases = {
        "wci": "the file", "wc+ 0x0 0x10": "the file", "wa nop": "assembl",
        "wu /tmp/p": "file", "wff /tmp/x": "file", "wfs host 1": "file",
        "dbc pdf": "run", "dbC pdf": "run", "dbx rax": "run", "dbw w 1": "hang",
        "aep 0x10": "not allowed", "aepn": "not allowed",
        "ood": "not allowed", "dc": "not allowed", "ds": "not allowed", "dm": "not allowed",
        "dp": "not allowed", "dbt": "not allowed", "dk 9": "not allowed",
        "aa": "Full analysis", "aaa": "Full analysis", "aav": "Full analysis",
        "e esil.mdev.range=0x0": "cannot be set",
    }
    for cmd, fragment in cases.items():
        reason = rizin_sessions.check_console_command(cmd)
        assert reason and fragment in reason, (cmd, reason)
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_rizin.py -k "console_allows_emulation or console_still_refuses" -v`
Expected: FAIL — the first because `w`, `d` and the settings are refused by family, the second because `wci`, `dbw` etc. are refused with the generic family reason, not the specific one.

- [ ] **Step 3: Open the two families and the settings in `webui/rizin_sessions.py`**

Add `w` and `d` to `_FAMILIES`, then make them fail-closed from the inside, the way `e` already is (`_check_name` returns a refusal for any `e` name not in `_EVAL_NAMES`):

- `_WRITE_NAMES`: the write commands that reach only the cache — `w`, `wx`, `wo…`, `wz`, `wc`, `wcj`, `wc-`, `wc-*`. Any other `w` name is refused by name. `wci`, `wc+`, `wcp…`, `wcpi` refuse with "it writes the file", `wa…` with the existing `_ASSEMBLE` text, `wu`/`wf…` with "it reads a file".
- `_BP_NAMES`: `db`, `db-`, `db-*`, `db.`, `dbl`, `dblj`, `dblq`, `dbd`, `dbe`, `dbs`, `dbn`, `dbi…`, `dbh`. Any other `d` name is refused with the existing wording for the family. `dbc`, `dbC`, `dbx` refuse with "it runs rizin commands when the breakpoint hits", `dbw`/`dbW` with "watchpoints hang rizin", `dbm`/`dbf`/`dbt…` and every executing `d` command with "debugging is not available: emulation runs from the EMULATION tab".
- In `_check_eval`: add `"esil."` to `_EVAL_SET_PREFIXES` and `"io.cache"` to `_EVAL_SET_KEYS`, and add `esil.mdev.range` to `_EVAL_SET_REFUSED` with "it is handled by a command hook".

Keep `_REFUSED`'s `aep` entry but make it not match `aepc`: match `aep(?!c)`.

- [ ] **Step 4: Run the whole filter suite**

Run: `python3 -m pytest tests/test_rizin.py -k "console or refus or allowlist" -v`
Expected: PASS, including the pre-existing filter tests.

- [ ] **Step 5: Commit**

```bash
git add webui/rizin_sessions.py tests/test_rizin.py
git commit -m "feat(rizin): allow cache writes, the breakpoint list and esil settings in the console"
```

---

### Task 2: Emulation lifecycle in the session

**Files:**
- Create: `webui/rizin_emulation.py`
- Modify: `webui/rizin_sessions.py` (constants near `:65-118`, `RizinSession`)
- Modify: `tests/fake_rizin.py`
- Test: `tests/test_rizin.py`

**Interfaces:**
- Consumes: Task 1's filter (unused here — the session builds its own commands).
- Produces:
  - `rizin_sessions.ESIL_TIMEOUT: float` (seconds for `esil.timeout`), `ESIL_SETTINGS: tuple[str, ...]` (the guard settings as `key=value`).
  - `RizinSession.emulation_start(addr: int | None) -> dict` — sets `io.cache` and the guards, runs `aei`, `aeim`, `aepc`, returns the state dict.
  - `RizinSession.emulation_stop() -> dict` — `aeim-`, `wc-*` for run bytes only is *not* done here (see Task 5); leaves emulation mode and returns `{"running": False}`.
  - `RizinSession.emulation_register(name: str, value: int) -> dict` — `ar <name>=<value>`, then the state. `name` must match one of the registers `ar` listed, otherwise `RizinRefused`; never interpolate the name unchecked.
  - `RizinSession.emulation_state() -> dict` with keys `running: bool`, `pc: int | None`, `registers: list[{name, value}]`, `changed: list[str]`, `stack: list[{addr, value, hint}]`, `stopped: str | None`, `arch: str`, `bits: int | None`. `stack` holds `RIZIN_STACK_ROWS` words from the stack pointer upwards, read with `pxj`; `hint` is the flag name at `value` (from `fd @ value`) or `null`.
  - `rizin_emulation.parse_registers(text: str) -> list[{"name": str, "value": int}]` — reads `ar`'s `name = 0x…` lines.
  - `RizinRefused` is raised when emulation is asked for while it is not started, and when `io.cache` did not take.

- [ ] **Step 1: Write the failing tests**

```python
def test_emulation_start_sets_the_guards_and_reports_the_pc(rz):
    sid = rz.open_file()
    state = rz.post(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    assert state["running"] is True and state["pc"] == 0x140001440
    assert {r["name"] for r in state["registers"]} >= {"rax", "rip", "rsp"}
    settings = dict(line.split("=", 1) for line in rz.commands_matching("e ")[-1].split()[1:])
    assert settings["io.cache"] == "true" and float(settings["esil.timeout"]) > 0
    for key in ("esil.breakoninvalid", "esil.exectrap", "esil.iotrap", "esil.nonull"):
        assert settings[key] == "true"
    assert settings["esil.romem"] == "false"


def test_emulation_state_reads_the_stack_with_hints(rz):
    sid = rz.open_file()
    rz.post(f"/api/rizin/{sid}/emulation/start", {})
    rz.push_fake_stack([0x140001490])          # the address of sym.watchdog
    stack = rz.get(f"/api/rizin/{sid}/emulation")["stack"]
    assert len(stack) == tdc.RIZIN_STACK_ROWS
    assert stack[0]["value"] == 0x140001490 and stack[0]["hint"] == "sym.watchdog"
    assert stack[1]["hint"] is None


def test_emulation_refuses_when_io_cache_did_not_take(rz):
    # Review Focus 5: without io.cache nothing the run writes is kept, and a decryption
    # would silently do nothing. The start must fail loudly instead.
    sid = rz.open_file(env={"FAKE_RIZIN_NO_IO_CACHE": "1"})
    answer, status = rz.post_raw(f"/api/rizin/{sid}/emulation/start", {})
    assert status == 400 and "io.cache" in answer["refused"]


def test_emulation_state_is_refused_before_start(rz):
    sid = rz.open_file()
    answer, status = rz.get_raw(f"/api/rizin/{sid}/emulation")
    assert status == 400 and "not started" in answer["refused"]


def test_a_register_can_be_set_and_only_a_known_one(rz):
    sid = rz.open_file()
    rz.post(f"/api/rizin/{sid}/emulation/start", {})
    state = rz.post(f"/api/rizin/{sid}/emulation/register", {"name": "rax", "value": "0x41"})
    assert next(r["value"] for r in state["registers"] if r["name"] == "rax") == 0x41
    assert any(c.startswith("ar rax=0x41") for c in rz.commands())
    for name in ("rax; wci", "nope", "rax rbx", ""):
        answer, status = rz.post_raw(f"/api/rizin/{sid}/emulation/register",
                                     {"name": name, "value": "0x1"})
        assert status == 400 and "register" in answer["refused"], name


def test_parse_registers_reads_ar_output():
    text = "rax = 0x0000000000000041\nrip = 0x0000000000401000\n"
    assert rizin_emulation.parse_registers(text) == [
        {"name": "rax", "value": 0x41}, {"name": "rip", "value": 0x401000}]
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_rizin.py -k emulation tests/test_rizin_emulation.py -v`
Expected: FAIL — 404 on the unknown routes, and `rizin_emulation` does not exist.

- [ ] **Step 3: Teach `tests/fake_rizin.py` an ESIL VM**

Extend the `answer(cmd)` dispatch (`tests/fake_rizin.py:339`) with a model that the later tasks build on:

- A `REGS` dict for x86-64 (`rax`…`r15`, `rip`, `rsp`, `rbp`, `rflags`) and, under `FAKE_RIZIN_BITS=32`, the x86-32 set (`eax`…`edi`, `eip`, `esp`, `ebp`, `eflags`); `ij` reports `bits` accordingly.
- `aei`/`aeim` arm the VM (`aeim` sets the stack pointer); before `aei` the step and register commands answer rizin's "ESIL is not initialized" on stderr.
- `aepc <addr>` sets the PC. `ar` prints every register as `name = 0x%016x`; `ar <name>` one; `ar <name>=<value>` sets it.
- A stack area the test can seed, so `pxj` at the stack pointer answers known words, and `fd @ <addr>` answers the flag name at an address (or nothing).
- `e io.cache=true` is honoured unless `FAKE_RIZIN_NO_IO_CACHE` is set, in which case `e io.cache` keeps answering `false`.
- `e <key>` answers whatever was last set, so the test can read the guards back.

Keep the existing behaviour for every command already modelled.

- [ ] **Step 4: Write `webui/rizin_emulation.py` with `parse_registers`**

Module docstring: pure logic for the emulation, no pipe and no Flask, so it is testable on its own. Start with `parse_registers(text)`.

- [ ] **Step 5: Implement the lifecycle in `webui/rizin_sessions.py`**

Add `ESIL_TIMEOUT`, `ESIL_SETTINGS` and `RIZIN_STACK_ROWS` near the other constants, with a comment naming the measurement from the spec (`esil.timeout=3` ended `jmp $` after 3.02 s) and the rule that it stays well below `CONSOLE_TIMEOUT`.

In `RizinSession`: an `_emulation` flag, and `emulation_start`, `emulation_stop`, `emulation_state` going through `self._call("emulation", wait, …)` like the other session methods, so the gate and the error mapping are the existing ones. `emulation_start` sets the settings in one `e` command, reads `io.cache` back and raises `RizinRefused` if it is not `true`, then `aei`, `aeim`, `aepc <addr>`. `emulation_state` reads `ar`, `s`, and the stack with `pxj` at the stack pointer plus `fd` per non-zero word; `changed` compares against the registers kept from the previous state.

- [ ] **Step 6: Add the two routes in `webui/app.py`**

`POST /api/rizin/<sid>/emulation/start` (body `addr`, optional — defaults to the current seek), `GET /api/rizin/<sid>/emulation`, `POST /api/rizin/<sid>/emulation/stop` and `POST /api/rizin/<sid>/emulation/register` (`name`, `value`), all through `_rizin_call`. Add the matching README rows in the `### Rizin` table.

- [ ] **Step 7: Run the tests**

Run: `python3 -m pytest tests/test_rizin.py -k emulation tests/test_rizin_emulation.py tests/test_docs.py -v`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add webui/rizin_emulation.py webui/rizin_sessions.py webui/app.py tests/fake_rizin.py tests/test_rizin.py tests/test_rizin_emulation.py README.md
git commit -m "feat(rizin): start and read an ESIL emulation per session"
```

---

### Task 3: Stepping, running and why it stopped

**Files:**
- Modify: `webui/rizin_emulation.py`, `webui/rizin_sessions.py`, `webui/app.py`, `tests/fake_rizin.py`
- Test: `tests/test_rizin.py`, `tests/test_rizin_emulation.py`

**Interfaces:**
- Consumes: `emulation_state()`, `ESIL_TIMEOUT`, the fake VM from Task 2.
- Produces:
  - `RizinSession.emulation_run(kind: str, addr: int | None = None) -> dict` — the state dict of Task 2, with `stopped` filled in. `kind` is one of `"step"`, `"over"`, `"skip"`, `"back"`, `"to_call"`, `"cont"`, `"until"`; `"until"` requires `addr`. An unknown `kind` raises `RizinRefused`.
  - `rizin_emulation.STEP_COMMANDS: dict[str, str]` — `kind` to rizin command (`step`→`aes`, `over`→`aeso`, `skip`→`aess`, `back`→`aesb`, `to_call`→`aecc`, `cont`→`aec`, `until`→`aesu`).
  - `rizin_emulation.stop_reason(output: str, stderr: str) -> str` — one of `"breakpoint"`, `"timeout"`, `"invalid"`, `"trap"`, `"step"`.

- [ ] **Step 1: Write the failing tests**

```python
def test_stop_reason_reads_rizins_own_words():
    assert rizin_emulation.stop_reason("[ESIL] hit breakpoint at 0x14", "") == "breakpoint"
    assert rizin_emulation.stop_reason("", "WARNING: core: esil: timeout exceeded.") == "timeout"
    assert rizin_emulation.stop_reason("", "ERROR: invalid instruction") == "invalid"
    assert rizin_emulation.stop_reason("", "") == "step"


def test_each_run_kind_sends_its_command(rz):
    sid = rz.open_file()
    rz.post(f"/api/rizin/{sid}/emulation/start", {})
    for kind, command in (("step", "aes"), ("over", "aeso"), ("skip", "aess"),
                          ("back", "aesb"), ("to_call", "aecc")):
        rz.post(f"/api/rizin/{sid}/emulation/run", {"kind": kind})
        assert rz.commands()[-3:], kind
        assert any(c.split(" ")[0] == command for c in rz.commands()[-4:]), kind
    rz.post(f"/api/rizin/{sid}/emulation/run", {"kind": "until", "addr": "0x140001450"})
    assert any(c.startswith("aesu 0x140001450") for c in rz.commands()[-4:])


def test_cont_steps_off_the_breakpoint_it_stands_on(rz):
    # Review Focus 3: aec on a breakpoint hits the same one again, so the tab would
    # look frozen. The server steps once before it continues.
    sid = rz.open_file()
    rz.post(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    rz.post(f"/api/rizin/{sid}/breakpoints", {"addr": "0x140001440"})
    rz.post(f"/api/rizin/{sid}/breakpoints", {"addr": "0x140001450"})
    state = rz.post(f"/api/rizin/{sid}/emulation/run", {"kind": "cont"})
    sent = [c.split(" ")[0] for c in rz.commands()]
    assert sent.index("aes") < sent.index("aec")
    assert state["pc"] == 0x140001450 and state["stopped"] == "breakpoint"


def test_cont_that_runs_away_stops_with_timeout_and_keeps_the_session(rz):
    sid = rz.open_file(env={"FAKE_RIZIN_ESIL_RUNAWAY": "1"})
    rz.post(f"/api/rizin/{sid}/emulation/start", {})
    state = rz.post(f"/api/rizin/{sid}/emulation/run", {"kind": "cont"})
    assert state["stopped"] == "timeout"
    assert rz.get(f"/api/rizin/{sid}/status")["analysis"]["state"] in ("done", "stopped")


def test_run_refuses_an_unknown_kind(rz):
    sid = rz.open_file()
    rz.post(f"/api/rizin/{sid}/emulation/start", {})
    answer, status = rz.post_raw(f"/api/rizin/{sid}/emulation/run", {"kind": "ood"})
    assert status == 400 and "kind" in answer["refused"]
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_rizin.py -k "run_kind or cont_steps or runaway or unknown_kind" tests/test_rizin_emulation.py -v`
Expected: FAIL

- [ ] **Step 3: Extend the fake VM with a step machine**

`aes [N]`, `aeso`, `aess`, `aesb`, `aesu <addr>`, `aecc`, `aec` move the PC through the fake's existing op model (`linear`, `function_ops`): `aes` one op, `aeso`/`aess` past a `call`, `aesb` back one (keep a PC history), `aecc`/`aesuo call` to the next `call`, `aesu` to the address, `aec` to the nearest enabled breakpoint ahead — printing `[ESIL] hit breakpoint at 0x…` when it hits one. Under `FAKE_RIZIN_ESIL_RUNAWAY` `aec` prints rizin's timeout warning on stderr and leaves the PC where it was.

- [ ] **Step 4: Implement `STEP_COMMANDS` and `stop_reason` in `webui/rizin_emulation.py`**

`stop_reason` matches rizin's own wording from the spec's Befunde: `[ESIL] hit breakpoint`, `esil: timeout exceeded`, invalid-instruction and trap messages; anything else is `"step"`.

- [ ] **Step 5: Implement `emulation_run` in `webui/rizin_sessions.py`**

Runs under `self._call("emulation", wait, …)` with `timeout=ESIL_TIMEOUT + a grace` so a bounded run cannot trip the pipe's limit. For `"cont"`: if the PC is on an enabled breakpoint, send `aes` first, then `aec`. Use `pipe.console()` rather than `pipe.cmd()` so stderr comes back for `stop_reason`.

- [ ] **Step 6: Add `POST /api/rizin/<sid>/emulation/run` in `webui/app.py`**

Body `kind` and optional `addr`; `_rizin_forget(session)` afterwards, because a run changes bytes and therefore strings, flags and functions. README row.

- [ ] **Step 7: Run the tests**

Run: `python3 -m pytest tests/test_rizin.py tests/test_rizin_emulation.py tests/test_docs.py -v`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add webui/rizin_emulation.py webui/rizin_sessions.py webui/app.py tests/fake_rizin.py tests/test_rizin.py tests/test_rizin_emulation.py README.md
git commit -m "feat(rizin): step, run and report why the emulation stopped"
```

---

### Task 4: Breakpoints

**Files:**
- Modify: `webui/rizin_sessions.py`, `webui/app.py`, `tests/fake_rizin.py`
- Test: `tests/test_rizin.py`

**Interfaces:**
- Consumes: the fake VM's breakpoint set (Task 3).
- Produces:
  - `RizinSession.breakpoint_set(addr: int, on: bool = True) -> dict`, `breakpoint_clear(addr: int | None) -> dict` (`None` clears all), `breakpoints() -> list[{"addr": int, "enabled": bool}]`.
  - Breakpoints work without emulation running, so they can be placed before the first start.

- [ ] **Step 1: Write the failing tests**

```python
def test_breakpoints_are_set_listed_and_cleared(rz):
    sid = rz.open_file()
    rz.post(f"/api/rizin/{sid}/breakpoints", {"addr": "0x140001440"})
    rz.post(f"/api/rizin/{sid}/breakpoints", {"addr": 0x140001450})
    assert rz.get(f"/api/rizin/{sid}/breakpoints") == [
        {"addr": 0x140001440, "enabled": True}, {"addr": 0x140001450, "enabled": True}]
    assert any(c.startswith("db @ 0x140001440") for c in rz.commands())
    rz.delete(f"/api/rizin/{sid}/breakpoints", {"addr": "0x140001440"})
    assert [b["addr"] for b in rz.get(f"/api/rizin/{sid}/breakpoints")] == [0x140001450]
    rz.delete(f"/api/rizin/{sid}/breakpoints", {})
    assert rz.get(f"/api/rizin/{sid}/breakpoints") == []


def test_a_breakpoint_can_be_turned_off_without_losing_it(rz):
    sid = rz.open_file()
    rz.post(f"/api/rizin/{sid}/breakpoints", {"addr": "0x140001440"})
    rz.post(f"/api/rizin/{sid}/breakpoints", {"addr": "0x140001440", "on": False})
    assert rz.get(f"/api/rizin/{sid}/breakpoints") == [{"addr": 0x140001440, "enabled": False}]


def test_breakpoints_work_before_emulation_starts(rz):
    sid = rz.open_file()
    assert rz.post(f"/api/rizin/{sid}/breakpoints", {"addr": "0x140001440"})
    assert rz.get(f"/api/rizin/{sid}/breakpoints")
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_rizin.py -k breakpoint -v`
Expected: FAIL

- [ ] **Step 3: Model `db`, `db-`, `dbd`, `dbe` and `dblj` in the fake**

`db @ <addr>` adds (the spec measured that `db` takes no address argument — only the `@` form works), `db- @ <addr>` removes, `db-*` clears, `dbd`/`dbe` at the seek toggle `enabled`, `dblj` answers the JSON array with `addr`, `enabled`, `cond`, `hw`.

- [ ] **Step 4: Implement the three session methods**

Build `db @ {addr:#x}` style commands; read the list with `dblj` and keep only `addr` and `enabled` (the `cond` and `hw` fields are rizin's, unused here).

- [ ] **Step 5: Add the routes in `webui/app.py`**

`POST /api/rizin/<sid>/breakpoints` (`addr`, optional `on`), `DELETE` (`addr`, or none for all), `GET` (the list). README rows.

- [ ] **Step 6: Run the tests**

Run: `python3 -m pytest tests/test_rizin.py -k breakpoint tests/test_docs.py -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add webui/rizin_sessions.py webui/app.py tests/fake_rizin.py tests/test_rizin.py README.md
git commit -m "feat(rizin): set, list and clear emulation breakpoints"
```

---

### Task 5: Patching — bytes, the list, and taking it back

**Files:**
- Modify: `webui/rizin_emulation.py`, `webui/rizin_sessions.py`, `webui/app.py`, `tests/fake_rizin.py`
- Test: `tests/test_rizin.py`, `tests/test_rizin_emulation.py`

**Interfaces:**
- Consumes: `io.cache` from Task 2's start sequence; patching also works without emulation running, in which case the session sets `io.cache=true` on its own.
- Produces:
  - `rizin_emulation.patch_bytes(kind: str, op: dict) -> bytes` — `kind` is `"nop"`, `"flip"`, `"always"` or `"nocall"`; `op` is one instruction as `pdj` gives it (`size`, `bytes`, `type`, `mnemonic`). Raises `ValueError` when the kind does not apply to the instruction.
  - `rizin_emulation.JUMP_PAIRS: dict[str, str]` — the conditional-jump opcode pairs for `"flip"`.
  - `RizinSession.patch(addr: int, data: bytes) -> dict`, `patch_op(addr: int, kind: str) -> dict`, `patches() -> list[{"addr", "size", "before", "after", "mine"}]`, `unpatch(addr: int | None) -> dict`.
  - `mine` is `True` for a byte this session wrote through `patch`/`patch_op`, `False` for one an emulation run wrote. The session keeps the set of its own patched addresses; everything else in `wcj` came from the run.

- [ ] **Step 1: Write the failing tests**

```python
def test_patch_bytes_computes_the_four_kinds():
    jz = {"size": 2, "bytes": "7410", "type": "cjmp", "mnemonic": "jz"}
    assert rizin_emulation.patch_bytes("nop", jz) == b"\x90\x90"
    assert rizin_emulation.patch_bytes("flip", jz) == b"\x75\x10"
    assert rizin_emulation.patch_bytes("always", jz) == b"\xeb\x10"
    call = {"size": 5, "bytes": "e8e18f0000", "type": "call", "mnemonic": "call"}
    assert rizin_emulation.patch_bytes("nocall", call) == b"\x90" * 5
    with pytest.raises(ValueError):
        rizin_emulation.patch_bytes("flip", call)


def test_patch_writes_through_the_cache_and_lists_before_and_after(rz):
    sid = rz.open_file()
    rz.post(f"/api/rizin/{sid}/patch", {"addr": "0x140001440", "bytes": "9090"})
    assert any(c.startswith("wx 9090 @ 0x140001440") for c in rz.commands())
    rows = rz.get(f"/api/rizin/{sid}/patches")
    assert rows and rows[0]["addr"] == 0x140001440 and rows[0]["after"] == "90"
    assert all(r["mine"] is True for r in rows)


def test_a_run_s_bytes_are_in_the_list_but_not_mine(rz):
    sid = rz.open_file()
    rz.post(f"/api/rizin/{sid}/emulation/start", {})
    rz.post(f"/api/rizin/{sid}/patch", {"addr": "0x140001440", "bytes": "90"})
    rz.post(f"/api/rizin/{sid}/emulation/run", {"kind": "step"})  # the fake writes a byte
    rows = {r["addr"]: r["mine"] for r in rz.get(f"/api/rizin/{sid}/patches")}
    assert rows[0x140001440] is True
    assert any(mine is False for mine in rows.values())


def test_unpatch_takes_one_back_and_all_back(rz):
    sid = rz.open_file()
    rz.post(f"/api/rizin/{sid}/patch", {"addr": "0x140001440", "bytes": "90"})
    rz.post(f"/api/rizin/{sid}/patch", {"addr": "0x140001450", "bytes": "90"})
    rz.delete(f"/api/rizin/{sid}/patch", {"addr": "0x140001440"})
    assert [r["addr"] for r in rz.get(f"/api/rizin/{sid}/patches")] == [0x140001450]
    rz.delete(f"/api/rizin/{sid}/patch", {})
    assert rz.get(f"/api/rizin/{sid}/patches") == []


def test_patch_refuses_what_is_not_bytes(rz):
    sid = rz.open_file()
    for body in ({"addr": "0x140001440", "bytes": "9"}, {"addr": "0x140001440", "bytes": "zz"},
                 {"addr": "0x140001440", "bytes": "90" * 4097}, {"addr": "0x140001440"}):
        answer, status = rz.post_raw(f"/api/rizin/{sid}/patch", body)
        assert status == 400 and "refused" in answer, body
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_rizin.py -k "patch or unpatch" tests/test_rizin_emulation.py -v`
Expected: FAIL

- [ ] **Step 3: Model the write cache in the fake**

`wx <hex> [@ addr]` records before/after per byte over the fake's byte model; `wcj` answers the recorded entries in rizin's shape (`idx`, `addr`, `size`, `before`, `after`, `written: false`); `wc- [addr]` and `wc-*` drop entries; `px` reads through the cache so a patched byte shows. A `step` while emulation runs writes one byte, so a test can tell run bytes from patched ones.

- [ ] **Step 4: Implement `patch_bytes` and `JUMP_PAIRS` in `webui/rizin_emulation.py`**

`"nop"` and `"nocall"` are `b"\x90" * op["size"]`. `"flip"` and `"always"` work on the first opcode byte: `JUMP_PAIRS` covers the short forms (`70`↔`71` … `7e`↔`7f`) and the `0f 8x` near forms; `"always"` maps a short conditional to `eb` and a near one to `e9`, keeping the displacement and the length. A kind that does not apply raises `ValueError` with a reason the route turns into a refusal.

- [ ] **Step 5: Implement the session methods**

`patch` validates an even-length hex string of at most 4096 bytes, sets `io.cache=true` if emulation is not running, sends `wx <hex> @ <addr>` and records the addresses in `self._mine`. `patch_op` reads the instruction with `pdj 1 @ <addr>`, calls `patch_bytes`, then `patch`. `patches()` reads `wcj`, marks `mine`, sorts by address. `unpatch` sends `wc- @ <addr>` or `wc-*` and updates `self._mine`.

- [ ] **Step 6: Add the routes in `webui/app.py`**

`POST /api/rizin/<sid>/patch` (`addr` plus either `bytes` or `kind`), `DELETE /api/rizin/<sid>/patch` (`addr`, or none for all), `GET /api/rizin/<sid>/patches`. Each mutating one calls `_rizin_forget(session)`. README rows.

- [ ] **Step 7: Run the tests**

Run: `python3 -m pytest tests/test_rizin.py tests/test_rizin_emulation.py tests/test_docs.py -v`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add webui/rizin_emulation.py webui/rizin_sessions.py webui/app.py tests/fake_rizin.py tests/test_rizin.py tests/test_rizin_emulation.py README.md
git commit -m "feat(rizin): patch bytes in the cache, list them and take them back"
```

---

### Task 6: Patches and breakpoints survive the session

**Files:**
- Modify: `webui/rizin_sessions.py:769-828` (`_sanitize_project`, `_read_project_meta`), `:1047-1067` (boot), `:1537-1569` (snapshot and save)
- Test: `tests/test_rizin.py`

**Interfaces:**
- Consumes: `patches()`, `breakpoints()`, `patch`, `breakpoint_set` from Tasks 4 and 5.
- Produces:
  - `_sanitize_project(src, dst, level, mode, done, patches, breakpoints)` — two new parameters. `patches` is a list of `(addr, after_hex)` for `mine` entries only; `breakpoints` a list of `(addr, enabled)`.
  - `_read_project_meta(path)` gains `"patches"` and `"breakpoints"` keys, both lists, both `[]` when the project has none or the lines do not parse.
  - `_project_snapshot` returns `(seq, tmp, level, mode, done, patches, breakpoints)`.
  - A patch or a breakpoint makes the session dirty, so a project is written for them too.

- [ ] **Step 1: Write the failing tests**

```python
def test_a_patch_and_a_breakpoint_come_back_when_the_file_is_opened_again(rz):
    sid = rz.open_file()
    rz.post(f"/api/rizin/{sid}/patch", {"addr": "0x140001440", "bytes": "9090"})
    rz.post(f"/api/rizin/{sid}/breakpoints", {"addr": "0x140001450"})
    rz.flush_and_close(sid)
    sid = rz.open_file()
    assert [r["addr"] for r in rz.get(f"/api/rizin/{sid}/patches")] == [0x140001440, 0x140001441]
    assert rz.get(f"/api/rizin/{sid}/breakpoints") == [{"addr": 0x140001450, "enabled": True}]
    assert any(c.startswith("wx 9090 @ 0x140001440") for c in rz.commands_after_open())


def test_what_a_run_wrote_does_not_come_back(rz):
    sid = rz.open_file()
    rz.post(f"/api/rizin/{sid}/emulation/start", {})
    rz.post(f"/api/rizin/{sid}/emulation/run", {"kind": "step"})
    assert rz.get(f"/api/rizin/{sid}/patches")
    rz.flush_and_close(sid)
    sid = rz.open_file()
    assert rz.get(f"/api/rizin/{sid}/patches") == []


def test_a_stale_patch_outside_the_file_is_skipped_with_a_note(rz):
    # Review Focus 4: the saved list must not be applied blindly nor break the boot.
    sid = rz.open_file()
    rz.post(f"/api/rizin/{sid}/patch", {"addr": "0x140001440", "bytes": "90"})
    rz.flush_and_close(sid)
    rz.rewrite_project_patches([(0xDEADBEEF0000, "90"), (0x140001440, "90")])
    described = rz.open_described()
    assert "could not be applied" in (described["analysis"]["note"] or "")
    assert [r["addr"] for r in rz.get(f"/api/rizin/{described['session']}/patches")] == [0x140001440]


def test_a_project_is_written_for_a_patch_alone(rz):
    sid = rz.open_file()
    assert not rz.project_exists()
    rz.post(f"/api/rizin/{sid}/patch", {"addr": "0x140001440", "bytes": "90"})
    rz.flush_and_close(sid)
    assert rz.project_exists()
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_rizin.py -k "come_back or stale_patch or project_is_written or run_wrote" -v`
Expected: FAIL

- [ ] **Step 3: Extend the `/tdc` namespace**

In `_sanitize_project`, write `patches=` and `breakpoints=` lines beside `level`, `mode` and `done`, each a compact `addr:hex` / `addr:0|1` list separated by commas, so `_read_project_meta`'s 64 KB tail still holds them. In `_read_project_meta`, parse them and drop any entry that does not match the expected shape.

- [ ] **Step 4: Apply them on boot**

In `RizinSession.__init__`, after `_boot` and before the analysis starts, send the saved patches with `wx` (setting `io.cache=true` first) and the breakpoints with `db @ …`, then `dbd` for the disabled ones. An address that `oml.j` places outside the opened file, or a `wx` that errors, is skipped; the skipped ones are collected into one note ("N saved patches could not be applied to this file."). `self._mine` is seeded with the applied addresses, so they stay `mine` and exportable.

- [ ] **Step 5: Make a patch and a breakpoint dirty the project**

Call `_schedule_save()` from `patch`, `patch_op`, `unpatch`, `breakpoint_set` and `breakpoint_clear`, the way `rename` and `comment` already do. Unlike those, patching is **not** refused while the analysis runs — an analysis step does not change bytes.

- [ ] **Step 6: Run the tests**

Run: `python3 -m pytest tests/test_rizin.py -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add webui/rizin_sessions.py tests/test_rizin.py
git commit -m "feat(rizin): keep hand-made patches and breakpoints in the project"
```

---

### Task 7: Re-analyse what the run decrypted

**Files:**
- Modify: `webui/rizin_sessions.py`, `webui/app.py`, `tests/fake_rizin.py`
- Test: `tests/test_rizin.py`

**Interfaces:**
- Consumes: `patches()` for the changed range.
- Produces:
  - `RizinSession.reanalyze(start: int, end: int) -> dict` with `{"functions": int, "strings": int}` — the counts found. Sends `af @ <start>` and `/zj` over the range; both already pass the allowlist, so no filter change belongs to this task.
  - `RizinSession.run_range() -> tuple[int, int] | None` — the lowest and highest address an emulation run wrote, from the non-`mine` cache entries; `None` when the run wrote nothing.

- [ ] **Step 1: Write the failing tests**

```python
def test_reanalyze_runs_af_and_a_string_search_over_the_range(rz):
    sid = rz.open_file()
    rz.post(f"/api/rizin/{sid}/emulation/start", {})
    rz.post(f"/api/rizin/{sid}/emulation/run", {"kind": "step"})
    found = rz.post(f"/api/rizin/{sid}/reanalyze", {})
    assert found["functions"] >= 0 and found["strings"] >= 0
    sent = rz.commands()
    assert any(c.startswith("af @ ") for c in sent)
    assert any(c.startswith("/zj") for c in sent)


def test_reanalyze_refuses_when_the_run_wrote_nothing(rz):
    sid = rz.open_file()
    rz.post(f"/api/rizin/{sid}/emulation/start", {})
    answer, status = rz.post_raw(f"/api/rizin/{sid}/reanalyze", {})
    assert status == 400 and "nothing" in answer["refused"]


def test_reanalyze_lets_the_lists_see_the_new_names(rz):
    sid = rz.open_file()
    before = rz.get(f"/api/rizin/{sid}/functions")
    rz.post(f"/api/rizin/{sid}/emulation/start", {})
    rz.post(f"/api/rizin/{sid}/emulation/run", {"kind": "step"})
    rz.set_fake_extra_function(0x140002000, "fcn.decrypted")
    rz.post(f"/api/rizin/{sid}/reanalyze", {})
    after = rz.get(f"/api/rizin/{sid}/functions")
    assert len(after) == len(before) + 1
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_rizin.py -k reanalyze -v`
Expected: FAIL

- [ ] **Step 3: Model `af` and `/zj` in the fake**

`af [@ addr]` answers empty (rizin does) and, when `FAKE_RIZIN_EXTRA_FUNCTION` names one, adds it to `FUNCTIONS` so `afl` shows it afterwards. `/zj` answers a JSON array of string hits over the current block.

- [ ] **Step 4: Implement `run_range` and `reanalyze`**

`reanalyze` takes the range from `run_range()` when the body gives none and raises `RizinRefused("the run wrote nothing to analyse")` when there is none. It sends `af @ {start:#x}` and `/zj` with the block set to the range, counts what came back, and the route calls `_rizin_forget(session)` so FUNCTIONS, STRINGS and the console's Tab reload.

- [ ] **Step 5: Add `POST /api/rizin/<sid>/reanalyze`**

Optional `start` and `end` in the body. README row.

- [ ] **Step 6: Run the tests**

Run: `python3 -m pytest tests/test_rizin.py tests/test_docs.py -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add webui/rizin_sessions.py webui/app.py tests/fake_rizin.py tests/test_rizin.py README.md
git commit -m "feat(rizin): re-analyse the range an emulation run decrypted"
```

---

### Task 8: The API-call assistant

**Files:**
- Modify: `webui/rizin_emulation.py`, `webui/rizin_sessions.py`, `webui/app.py`, `tests/fake_rizin.py`
- Test: `tests/test_rizin_emulation.py`, `tests/test_rizin.py`

**Interfaces:**
- Consumes: `emulation_run("skip")`, `patch`/`ar` writing from Tasks 3 and 5, the session's `arch` and `bits`.
- Produces:
  - `rizin_emulation.API_TABLE: dict[str, dict]` — per API name: `conv` (`"win64"`, `"stdcall"`, `"cdecl"`), `args` (int), `ret` (`"handle"`, `"buffer"`, `"zero"`, `"tick"`, `"address"`, `"copy"`, `"success"`), and for buffers a `size_arg` index.
  - `rizin_emulation.lookup_api(name: str) -> dict | None` — strips `sym.imp.`, a module prefix and a trailing `A`/`W`, case-insensitively.
  - `rizin_emulation.convention(arch: str, bits: int, api: dict | None) -> dict` with `ret_reg`, `arg_regs`, `stack_args: bool`, `callee_pops: bool`, `word: int`.
  - `rizin_emulation.stack_fix(conv: dict, args: int) -> int` — bytes to add to the stack pointer after `aess`. `0` for win64 and cdecl; `args * word` for stdcall.
  - `RizinSession.call_assist(addr: int) -> dict` — `{"supported": bool, "reason": str | None, "api": str | None, "ret_reg": str | None, "value": int | None, "stack_fix": int, "summary": str}`.
  - `RizinSession.call_skip(addr: int, value: int | None, stack_fix: int) -> dict` — `aess`, then `ar <ret>=<value>` when a value is given, then the stack fix, then the state.

- [ ] **Step 1: Write the failing tests**

```python
def test_lookup_api_strips_prefixes_and_the_ansi_suffix():
    for name in ("sym.imp.KERNEL32.dll_VirtualAlloc", "VirtualAlloc", "sym.imp.LoadLibraryA",
                 "KERNEL32.dll_LoadLibraryW"):
        assert rizin_emulation.lookup_api(name) is not None, name
    assert rizin_emulation.lookup_api("sym.imp.nothing_like_this") is None


def test_convention_picks_the_return_register_per_arch():
    assert rizin_emulation.convention("x86", 64, None)["ret_reg"] == "rax"
    assert rizin_emulation.convention("x86", 32, None)["ret_reg"] == "eax"
    assert rizin_emulation.convention("arm", 64, None) is None


def test_stack_fix_only_applies_to_stdcall():
    # Review Focus 1: a 32-bit stdcall callee pops its arguments. Skipping the call with
    # aess pops nothing, so without this the stack stays too deep and every later step
    # computes on a corrupt stack.
    win64 = rizin_emulation.convention("x86", 64, rizin_emulation.lookup_api("VirtualAlloc"))
    std32 = rizin_emulation.convention("x86", 32, rizin_emulation.lookup_api("VirtualAlloc"))
    cdecl32 = rizin_emulation.convention("x86", 32, rizin_emulation.lookup_api("memcpy"))
    assert rizin_emulation.stack_fix(win64, 4) == 0
    assert rizin_emulation.stack_fix(std32, 4) == 16
    assert rizin_emulation.stack_fix(cdecl32, 3) == 0


def test_skip_a_32bit_stdcall_call_corrects_the_stack(rz):
    sid = rz.open_file(env={"FAKE_RIZIN_BITS": "32"})
    rz.post(f"/api/rizin/{sid}/emulation/start", {})
    before = rz.register(sid, "esp")
    assist = rz.get(f"/api/rizin/{sid}/call?addr=0x140001470")   # a call to sym.imp.Sleep
    assert assist["supported"] and assist["ret_reg"] == "eax" and assist["stack_fix"] > 0
    rz.post(f"/api/rizin/{sid}/call", {"addr": "0x140001470", "value": "0x1",
                                       "stack_fix": assist["stack_fix"]})
    assert rz.register(sid, "esp") == before + assist["stack_fix"]


def test_the_assistant_switches_itself_off_on_another_arch(rz):
    sid = rz.open_file(env={"FAKE_RIZIN_ARCH": "arm"})
    rz.post(f"/api/rizin/{sid}/emulation/start", {})
    assist = rz.get(f"/api/rizin/{sid}/call?addr=0x140001470")
    assert assist["supported"] is False and "arm" in assist["reason"]
    assert assist["value"] is None and assist["stack_fix"] == 0


def test_an_unknown_import_is_named_but_offers_no_value(rz):
    sid = rz.open_file()
    assist = rz.get(f"/api/rizin/{sid}/call?addr=0x140001480")   # a call to an import not in the table
    assert assist["supported"] is True and assist["api"] and assist["value"] is None


def test_the_assistant_refuses_where_there_is_no_call(rz):
    sid = rz.open_file()
    answer, status = rz.get_raw(f"/api/rizin/{sid}/call?addr=0x140001441")
    assert status == 400 and "call" in answer["refused"]
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_rizin_emulation.py tests/test_rizin.py -k "api or convention or stack_fix or assistant or skip_a_32" -v`
Expected: FAIL

- [ ] **Step 3: Write `API_TABLE` and the convention helpers**

`API_TABLE` is **data**, one entry per API, covering the spec's seven groups (memory, memory protection, loader, anti-debug, time, environment, copying) with `conv`, `args`, `ret` and `size_arg`. The CRT entries (`memcpy`, `memmove`, `malloc`) are `cdecl`; the Win32 ones `stdcall` — which `convention` ignores at 64 bits, where everything is `win64`. `convention` returns `None` for an arch other than x86, which is how the assistant switches off.

- [ ] **Step 4: Implement `call_assist` and `call_skip`**

`call_assist` reads the instruction with `pdj 1 @ <addr>`, refuses when its type is not `call`, resolves the target to an import name through the flag at the jump target, looks it up, and builds the offered value: for a `buffer` it picks an address outside the file's maps and the stack and reads the size from `size_arg` (from a register at 64 bits, from the stack at 32), for `tick` a rising counter, for `zero` `0`, for `address` the import's own address. `call_skip` sends `aess`, then `ar <ret_reg>=<value>` when a value came, then `ar <sp>=<sp + stack_fix>` when the fix is non-zero, then a `buffer` value also gets `aeim <addr> <size> assist`.

- [ ] **Step 5: Extend the fake with a 32-bit mode, another arch and import calls**

`FAKE_RIZIN_BITS=32` switches the register set, the `ij` answer and `asm.bits`; `FAKE_RIZIN_ARCH` the arch in `ij` and `e asm.arch`. Add two `call` ops to the op model: one to `sym.imp.KERNEL32.dll_Sleep` and one to an import that is not in the table.

- [ ] **Step 6: Add the routes in `webui/app.py`**

`GET /api/rizin/<sid>/call?addr=…` and `POST /api/rizin/<sid>/call` (`addr`, optional `value`, `stack_fix`). The POST calls `_rizin_forget(session)`. README rows.

- [ ] **Step 7: Run the tests**

Run: `python3 -m pytest tests/test_rizin.py tests/test_rizin_emulation.py tests/test_docs.py -v`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add webui/rizin_emulation.py webui/rizin_sessions.py webui/app.py tests/fake_rizin.py tests/test_rizin.py tests/test_rizin_emulation.py README.md
git commit -m "feat(rizin): offer and apply API-call returns, with the stdcall stack fix"
```

---

### Task 9: Export the patched copy

**Files:**
- Modify: `webui/app.py` (near `_rizin_paddr` at `:5504` and the upload route at `:5801`)
- Test: `tests/test_rizin.py`

**Interfaces:**
- Consumes: `patches()` (only `mine` entries), `_rizin_paddr(session, addr)`, `RIZIN_UPLOAD_DIR`.
- Produces:
  - `_rizin_export(session) -> dict` with `{"path": str, "name": str, "sha256": str, "patched": int, "skipped": list[int], "note": str}`.
  - `POST /api/rizin/<sid>/export` → that dict. The copy lands in `RIZIN_UPLOAD_DIR`, which `/api/file/download` already serves, so the browser can fetch it for the hand-off.
  - A `.patch.txt` note beside the copy: original path, both SHA-256 digests, the time, and one line per patch with address, before and after.

- [ ] **Step 1: Write the failing tests**

```python
def test_export_writes_a_copy_with_the_patches_applied(rz, tmp_path):
    sid = rz.open_file()
    rz.post(f"/api/rizin/{sid}/patch", {"addr": "0x140001440", "bytes": "9090"})
    result = rz.post(f"/api/rizin/{sid}/export", {})
    data = open(result["path"], "rb").read()
    original = open(rz.sample_path, "rb").read()
    paddr = rz.paddr(0x140001440)
    assert data[paddr:paddr + 2] == b"\x90\x90"
    assert data[:paddr] == original[:paddr] and len(data) == len(original)
    assert result["patched"] == 2 and result["skipped"] == []
    assert hashlib.sha256(data).hexdigest() == result["sha256"]
    note = open(result["path"] + ".patch.txt").read()
    assert rz.sample_path in note and result["sha256"] in note and "0x140001440" in note


def test_export_leaves_the_original_untouched(rz):
    before = open(rz.sample_path, "rb").read()
    sid = rz.open_file()
    rz.post(f"/api/rizin/{sid}/patch", {"addr": "0x140001440", "bytes": "90"})
    rz.post(f"/api/rizin/{sid}/export", {})
    assert open(rz.sample_path, "rb").read() == before


def test_export_names_patches_without_a_file_offset_and_writes_the_rest(rz):
    # Review Focus 2: a patch set by hand inside a buffer the emulation created has no
    # place in the file. It must be named, and the others must still be written.
    sid = rz.open_file()
    rz.post(f"/api/rizin/{sid}/emulation/start", {})
    rz.post(f"/api/rizin/{sid}/patch", {"addr": "0x140001440", "bytes": "90"})
    rz.post(f"/api/rizin/{sid}/patch", {"addr": "0xdead0000", "bytes": "90"})  # no map
    result = rz.post(f"/api/rizin/{sid}/export", {})
    assert result["skipped"] == [0xDEAD0000] and result["patched"] == 1
    assert "could not be placed in the file" in result["note"]


def test_export_does_not_write_what_a_run_wrote(rz):
    sid = rz.open_file()
    rz.post(f"/api/rizin/{sid}/emulation/start", {})
    rz.post(f"/api/rizin/{sid}/emulation/run", {"kind": "step"})
    answer, status = rz.post_raw(f"/api/rizin/{sid}/export", {})
    assert status == 400 and "no patches" in answer["refused"]


def test_export_prunes_like_an_upload(rz):
    sid = rz.open_file()
    rz.post(f"/api/rizin/{sid}/patch", {"addr": "0x140001440", "bytes": "90"})
    result = rz.post(f"/api/rizin/{sid}/export", {})
    assert result["name"].endswith(".patched" + rz.sample_suffix)
    assert os.path.dirname(result["path"]) == tdc.RIZIN_UPLOAD_DIR
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_rizin.py -k export -v`
Expected: FAIL

- [ ] **Step 3: Implement `_rizin_export` in `webui/app.py`**

Take the `mine` rows from `session.patches()`, map each address with `_rizin_paddr`, and refuse with "no patches to export" when there are none. Copy the original to a temp file in `RIZIN_UPLOAD_DIR` in 1 MiB chunks like the upload route does, seek to each physical offset and write the `after` bytes, `os.replace` to `<stem>.patched<suffix>`, then write the note file and call `_rizin_prune_uploads(keep=…)` with both files kept. Addresses without an offset go into `skipped` and the note, and the rest is still written.

- [ ] **Step 4: Add `POST /api/rizin/<sid>/export`**

Through `_rizin_call`, so an `OSError` on a full disk becomes the existing 500 wording. README row.

- [ ] **Step 5: Run the tests**

Run: `python3 -m pytest tests/test_rizin.py tests/test_docs.py tests/test_web_security.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add webui/app.py tests/test_rizin.py README.md
git commit -m "feat(rizin): export a patched copy with a note beside it"
```

---

### Task 10: Frontend — the run strip

**Files:**
- Modify: `webui/templates/index.html:1013-1039` (toolbar) and after it, `webui/static/js/app.js` (the RIZIN block), `webui/static/css/style.css:8779-10069`, `webui/static/css/theme-layout.css:1960-2338`
- Test: `tests/test_rizin_ui.py`

**Interfaces:**
- Consumes: `/api/rizin/<sid>/emulation*`, `/call`, `/breakpoints` from Tasks 2-4 and 8.
- Produces:
  - `RIZIN_EMU = {kinds: [...], pollMs: …}`, `rizinState.emu = {running, pc, registers, changed, stopped, assist}`.
  - `rizinEmuStart()`, `rizinEmuStop()`, `rizinEmuRun(kind)`, `rizinEmuSkipCall()`, `rizinEmuGoToPc()`, `rizinRunStripHtml(emu)`, `rizinRenderRunStrip()`, `rizinOnRunClick(event)`.
  - `emulation` is registered in `RIZIN_VIEWS` so a seek and an analysis step refresh it.
  - `rizinSeek(addr, 'emulation')` is the source name a step uses, so the views follow the PC.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_rizin_ui.py`, in the file's existing style (`_scripted`, `SCRIPTED.serve`, `_rizin_prelude`):

```python
@needs_node
def test_rizin_emulation_strip_appears_only_while_running():
    # #rizin-run is hidden after OPEN; START unhides it and the kind buttons appear;
    # STOP hides it again and no further request goes out
    ...

@needs_node
def test_rizin_emulation_step_moves_the_views_and_marks_the_pc():
    # one STEP posts /emulation/run {kind:"step"}, then /seek with the new pc, and
    # DISASSEMBLY, GRAPH, DECOMPILER and HEX all show the new address; the PC row
    # carries the pc class while the breakpoint row keeps its own
    ...

@needs_node
def test_rizin_emulation_strip_shows_only_the_registers_that_changed():
    # the strip lists exactly state.changed, not all of them, and the EMULATION pane lists all
    ...

@needs_node
def test_rizin_emulation_says_why_it_stopped():
    # stopped "breakpoint", "timeout" and "invalid" each produce their own words in
    # #rizin-run-why; a run that answers stopped "step" still says something, never ""
    ...

@needs_node
def test_rizin_emulation_stop_leaves_the_mode_and_does_not_promise_an_abort():
    # while a run is in flight the kind buttons are disabled but STOP is not labelled
    # as an abort, and clicking it during the run does not post anything
    ...

@needs_node
def test_rizin_emulation_offers_a_call_return_and_lets_it_be_edited():
    # at a call to an import, #rizin-run-assist shows the offered value; editing the
    # field and pressing SKIP posts that edited value, not the offered one
    ...

@needs_node
def test_rizin_emulation_busy_and_ended_sessions_behave_like_the_other_views():
    # a 409 busy marks the view for retry and the poll picks it up; a 404 ended
    # clears rizinState.emu so the strip disappears
    ...
```

Register the new functions and consts: add them to `RIZIN_FUNCTIONS` and `RIZIN_CONSTS`, and add the run strip's ids and selectors to the markup and theme assertions in `test_rizin_tab_layout_and_themes` (`:779`).

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_rizin_ui.py -k "emulation or lists_cover or tab_layout" -v`
Expected: FAIL

- [ ] **Step 3: Add the markup**

A `#rizin-run` strip between `#rizin-toolbar` and `#rizin-work`, `hidden` by default, `role="toolbar"`: the kind buttons with `data-rizin-run="step|over|skip|back|to_call|cont|until"`, `#rizin-run-pc`, `#rizin-run-regs`, `#rizin-run-why`, `#rizin-run-assist` (the offered return value plus an editable field), `#rizin-run-stop`, `#rizin-run-gotopc`. One delegated `onclick="rizinOnRunClick(event)"`. A `#rizin-emu-start` button in the toolbar.

- [ ] **Step 4: Implement the JS**

Follow the block's triad: `rizinRunStripHtml(emu)` builds the markup from state, `rizinEmuRun(kind)` posts and stores, `rizinRenderRunStrip()` writes the DOM and compares a signature first, as the other renderers do. After a run, `rizinSeek(emu.pc, 'emulation')` so every view follows; `rizinState.emu` is cleared in `rizinReset()`. A 409 goes through `rizinViewBusy('emulation', …)` like the other views.

- [ ] **Step 5: Style it**

`.rizin-run` in `style.css` inside the RIZIN block, with its `[data-theme]` counterpart in `theme-layout.css`. The PC mark and the changed-register mark must not rely on colour alone. Bump the asset versions.

- [ ] **Step 6: Run the tests**

Run: `python3 -m pytest tests/test_rizin_ui.py tests/test_theme.py tests/test_frontend.py -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add webui/templates/index.html webui/static/js/app.js webui/static/css/style.css webui/static/css/theme-layout.css tests/test_rizin_ui.py
git commit -m "feat(rizin): the emulation run strip above the code"
```

---

### Task 11: Frontend — the EMULATION dock pane

**Files:**
- Modify: `webui/templates/index.html:1086-1131` (dock), `webui/static/js/app.js`, the two CSS files
- Test: `tests/test_rizin_ui.py`

**Interfaces:**
- Consumes: Task 10's `rizinState.emu`, `/patches`, `/breakpoints`, `/reanalyze`, `/export`.
- Produces: `rizinEmuPaneHtml(emu, patches, breakpoints)`, `rizinLoadEmuPane(force)`, `rizinRenderEmuPane()`, `rizinOnEmuPaneClick(event)`, `rizinSetRegister(name, value)`, `rizinUnpatch(addr)`, `rizinReanalyze()`. A `data-rizin-pane="emulation"` pane and its tab.

- [ ] **Step 1: Write the failing tests**

```python
@needs_node
def test_rizin_emulation_pane_shows_registers_stack_breakpoints_and_patches():
    # all four sections render from one state; a click on a stack row, a breakpoint row
    # or a patch row seeks to its data-addr
    ...

@needs_node
def test_rizin_emulation_pane_separates_my_patches_from_what_the_run_wrote():
    # mine:true rows sit under the hand-made heading with Export and Take all back;
    # mine:false rows sit under their own heading, which says they end with the session,
    # and Export is not offered there
    ...

@needs_node
def test_rizin_emulation_pane_edits_a_register_and_takes_a_patch_back():
    # typing into a register field posts /emulation/register, taking a patch back posts
    # DELETE /patch with that addr, and both re-read the state afterwards
    ...

@needs_node
def test_rizin_emulation_pane_escapes_hostile_names():
    # a stack hint and a patch row whose function name is `</script><img onerror=…>`
    # produce no tag and no on* attribute in the pane
    ...

@needs_node
def test_rizin_emulation_pane_reanalyze_refreshes_functions_and_strings():
    # Re-analyse posts /reanalyze and then re-reads /functions and the dock lists
    ...
```

Add the ids to `DOCK_THEMED` and to the ordered tab list in `test_rizin_dock_layout_and_themes` (`:3590`), and the functions to `RIZIN_FUNCTIONS`.

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_rizin_ui.py -k "emulation_pane or dock_layout or lists_cover" -v`
Expected: FAIL

- [ ] **Step 3: Add the tab and the pane**

A tab `data-rizin-tab="emulation"` after IMPORTS and a pane `#rizin-emulation` with `data-rizin-pane="emulation"`, `hidden`, one delegated `onclick`. Four sections: registers, stack, breakpoints, patches — the patches split into "set by hand" (with **Export** and **Take all back**) and "written by the run" (with the note that they end with the session, and **Re-analyse**).

- [ ] **Step 4: Implement the JS**

Register `emulation` in `rizinDockShown` and `rizinRenderDockNote`, clear the state in `rizinReset`, and render from `rizinState.emu` plus the lists. Every name from the file goes through `escapeHtml`; every row carries `data-addr="0x…"` so a click seeks.

- [ ] **Step 5: Style it and bump the versions**

- [ ] **Step 6: Run the tests**

Run: `python3 -m pytest tests/test_rizin_ui.py tests/test_theme.py tests/test_frontend.py -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add webui/templates/index.html webui/static/js/app.js webui/static/css/style.css webui/static/css/theme-layout.css tests/test_rizin_ui.py
git commit -m "feat(rizin): the EMULATION dock pane with registers, stack, breakpoints and patches"
```

---

### Task 12: Frontend — gutter breakpoints and the patch menu

**Files:**
- Modify: `webui/static/js/app.js` (`rizinDisasmHtml` at `:16261`, `rizinOnDisasmClick` at `:17029`, the menu at `:18909-19051`), `webui/templates/index.html:1134-1149` (the menu), the two CSS files
- Test: `tests/test_rizin_ui.py`

**Interfaces:**
- Consumes: `/breakpoints`, `/patch`, `/emulation/run` with `kind: "until"`.
- Produces: a gutter cell per disassembly row, `rizinToggleBreakpoint(addr)`, `rizinPatchOp(addr, kind)`, `rizinRunToHere(addr)`, `rizinPatchBytes(addr)`; four new menu entries plus **Run to here**.

- [ ] **Step 1: Write the failing tests**

```python
@needs_node
def test_rizin_gutter_click_toggles_a_breakpoint_without_seeking():
    ...

@needs_node
def test_rizin_menu_patches_an_instruction_and_runs_to_here():
    # NOP, flip, always, kill call, bytes by hand, and Run to here
    ...

@needs_node
def test_rizin_patched_instruction_is_marked_in_the_disassembly():
    ...

@needs_node
def test_rizin_menu_patch_entries_follow_the_instruction_type():
    # Flip/Always appear only on a cjmp, Kill the call only on a call, NOP and Bytes always
    ...
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_rizin_ui.py -k "gutter or menu_patches or patched_instruction" -v`
Expected: FAIL

- [ ] **Step 3: Add the gutter**

A leading cell in every row of `rizinDisasmHtml`, carrying `data-rizin-gutter="0x…"`. In `rizinOnDisasmClick`, a click on the gutter toggles the breakpoint and **does not** seek; a click anywhere else keeps today's behaviour. The PC row and a patched row get their own classes.

- [ ] **Step 4: Add the menu entries**

In `#rizin-menu`: **NOP out**, **Flip the jump**, **Always jump**, **Kill the call**, **Bytes…**, **Run to here**. The four instruction entries are shown or hidden from the instruction's `type` in the disassembly data the tab already holds (`rizinState.disasm`'s ops carry `type`), the way the menu already hides what does not apply: **Flip the jump** and **Always jump** only on a `cjmp`, **Kill the call** only on a `call`.

- [ ] **Step 5: Style, bump the versions**

- [ ] **Step 6: Run the tests**

Run: `python3 -m pytest tests/test_rizin_ui.py tests/test_theme.py tests/test_frontend.py -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add webui/templates/index.html webui/static/js/app.js webui/static/css/style.css webui/static/css/theme-layout.css tests/test_rizin_ui.py
git commit -m "feat(rizin): breakpoints in the gutter, patch and run-to-here in the menu"
```

---

### Task 13: Frontend — export and the hand-off to Submit

**Files:**
- Modify: `webui/static/js/app.js` (the RIZIN block; reads `handleFileSelect` at `:8147`)
- Test: `tests/test_rizin_ui.py`

**Interfaces:**
- Consumes: `POST /api/rizin/<sid>/export` (Task 9), `GET /api/file/download?path=…`, `handleFileSelect(file)` and `switchTab('submit')`.
- Produces: `rizinExportPatched()`, `rizinDetonatePatched(path, name)`. No new server route: the browser fetches the exported copy, wraps it in a `File`, puts it into `#file-input` through a `DataTransfer`, calls `handleFileSelect` and switches to the Submit tab, where the user picks the target and presses Detonate.

- [ ] **Step 1: Write the failing tests**

```python
@needs_node
def test_rizin_export_then_detonate_fills_the_submit_tab():
    # the exported path is downloaded, put into #file-input, handleFileSelect is called,
    # the tab switches to submit, and nothing is submitted on its own
    ...

@needs_node
def test_rizin_export_reports_patches_it_could_not_place():
    ...
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_rizin_ui.py -k "export_then_detonate or could_not_place" -v`
Expected: FAIL

- [ ] **Step 3: Implement both functions**

`rizinExportPatched` posts, then shows the name, the digest and any skipped addresses in the patches section. `rizinDetonatePatched` fetches the file, builds the `File`, assigns it and switches tabs. It must **not** post to `/api/submit` — the target choice and the press belong to the Submit tab.

- [ ] **Step 4: Run the tests**

Run: `python3 -m pytest tests/test_rizin_ui.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add webui/static/js/app.js tests/test_rizin_ui.py
git commit -m "feat(rizin): export a patched copy and hand it to the Submit tab"
```

---

### Task 14: Documentation

**Files:**
- Modify: `README.md` (`:143` tab table, the Rizin section at `:883-1060`, the allowlist table at `:966`, the API table at `:1707-1733`, the security section at `:2167`, the limitations at `:1036`), `webui/templates/index.html` (the `(i)` texts and the help modal at `:1325-1553`)
- Test: `tests/test_docs.py`, `tests/test_rizin_ui.py`

**Interfaces:**
- Consumes: every route and behaviour from Tasks 1-13.
- Produces: no code interface. `tests/test_docs.py` must pass with the new API rows in place.

- [ ] **Step 1: Write the failing test**

```python
def test_readme_says_what_emulation_can_and_cannot_do():
    section = _section(README, "### Emulation and patching")
    assert "no process" in section and "io.cache" in section
    assert "the original file is never written" in section
    # the limitation that was removed must be gone, and the new ones present
    assert "Static analysis only: no debugging, no patching" not in README
    assert "ESIL does not emulate the Windows API" in section
    assert "what a run wrote ends with the session" in section
    rows = {path for line in README.splitlines() for path in re.findall(r"`(/api/rizin/[^`]+)`", line)}
    assert {"/api/rizin/<sid>/emulation", "/api/rizin/<sid>/emulation/run",
            "/api/rizin/<sid>/breakpoints", "/api/rizin/<sid>/patch",
            "/api/rizin/<sid>/call", "/api/rizin/<sid>/reanalyze",
            "/api/rizin/<sid>/export"} <= rows
```

- [ ] **Step 2: Run it to verify it fails**

Run: `python3 -m pytest tests/test_docs.py -k emulation -v`
Expected: FAIL

- [ ] **Step 3: Write the README changes**

A new `### Emulation and patching` subsection in the Rizin section covering: the run strip and the EMULATION pane; that ESIL runs the code without starting a process and that `io.cache` keeps the file untouched; breakpoints; the API assistant and that ESIL does not emulate the Windows API, so a call is skipped and its return set; byte patching with the four buttons; that hand-made patches persist and what a run wrote ends with the session; re-analysis; export and the hand-off to Submit. Update the tab table row, the allowlist table (from "no writing, no debugging" to "no writing to the file, no real debugging, emulation yes"), the security section, and replace the "Static analysis only" limitation with the real ones: no native debugging, no watchpoints, no assembling, the API limit, and that a run's bytes do not leave the tab.

- [ ] **Step 4: Update the in-tab help and `(i)` texts**

- [ ] **Step 5: Run the whole suite**

Run: `python3 -m pytest tests/ -q`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add README.md webui/templates/index.html tests/test_docs.py tests/test_rizin_ui.py
git commit -m "docs(rizin): emulation, patching, export and the new limits"
```

---

### Task 15: Check it on the VM

**Files:** none (verification only)

**Interfaces:**
- Consumes: everything.
- Produces: a note in the plan of what was seen, and fixes for what was not right.

- [ ] **Step 1: Deploy to the UTM VM**

```bash
python3 scripts/deploy-utm.py --vm-ip <vm> --vm-user tdc --vm-pass tdc
```

- [ ] **Step 2: Walk the feature against a real sample with real rizin**

Open a sample, START, set a breakpoint, CONT, STEP, run TO CALL onto an import, take the offered return, watch a decryption loop change HEX, re-analyse the range, NOP out a check, export, and hand it to Submit without detonating. Note anything that differs from the plan — especially a step that feels slow, since Ansatz 1 blocks for the length of a run.

- [ ] **Step 3: Both themes, 1920 px and 1280 px**

The run strip must stay readable and must not eat the toolbar.

- [ ] **Step 4: Fix what the walk found, then re-run the suite**

Run: `python3 -m pytest tests/ -q`
Expected: PASS

- [ ] **Step 5: Commit any fixes**

```bash
git add -A
git commit -m "fix(rizin): emulation fixes from the VM check"
```
