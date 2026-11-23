"""The RIZIN tab (block RIZIN of static/js/app.js): toolbar, FUNCTIONS and
DISASSEMBLY.

Regressions covered:
  * names, comments and instructions from rizin (the sample decides them)
    inserted as markup: an <img onerror>, a quote that leaves an attribute
  * a 10 000-character line that is cut or turned into markup
  * a row without its address, or the current function / address not marked
  * the filter of the function list missing names in another case or by
    address
  * a click on a function, a jump target or SEEK GO that moves one view but
    not the others, or does not go through POST seek; ◀ ▶ that change the
    history instead of walking it; a refused name that loses what was typed
  * addresses sent as JSON numbers (they lose precision above 2^53)
  * a view that finds rizin busy and is never asked again, polling that goes
    on after the analysis (the session would never idle out), no jump once
    the analysis is done (the toolbar names no function)
  * the tab ID changing within a browser tab, or blocked storage breaking it
  * the session states (busy, moved, ended, not installed) not kept, or set
    by the late answer of a session that is gone
  * a layout that does not fill the window or lists that do not scroll in
    themselves, rules of the tab missing in one theme, colours written out
  * a finished analysis step (the last one too) that does not ask every
    registered view again, or asks one after the other; a busy forced reload
    asked again unforced, or never; a redraw at a step that scrolls the
    lists back to the current row or draws the same lines again
  * patterns that take quadratic time on a long operand or comment
  * a graph whose blocks overlap, whose edges leave or enter a block away
    from its edge, cut through other blocks or run on top of each other, a
    block drawn above the block it comes from (loops aside), a loop drawn
    through the blocks instead of around them, a layout that differs for the
    same function or takes long for a big one, a function whose entry is not
    its lowest block drawn with a block above the entry
  * the block of the current address not marked, the colours of the edges
    (jump, no jump, unconditional) mixed up, a text of the file in the graph
    taken as markup, a big function drawn with all its text
  * a click on a block that does not jump, a drag that jumps (or goes on
    with no button held), zoom and pan that lose the point under the mouse,
    a click in the graph that moves it, ⇱ or the line between the halves
    that do not come back, the halves not turned into tabs below 1400 px
  * a jump to the place already shown that leaves it out of sight; a forced
    reload whose answer a jump dropped, never asked again
  * console output from the file (strings, names) taken as markup, an OSC 8
    hyperlink or another escape sequence that comes through, colours written
    out instead of theme classes, patterns that take long on broken sequences
  * a console command that moves rizin while the views stay, or renames while
    the views keep the old name; ↑ ↓ that lose what was being typed; Tab that
    completes from a late answer or takes the focus away from an empty line
  * a refused or busy command without its reason, or one that moves the views
  * STRINGS and IMPORTS that page or filter in the browser instead of on the
    server, keep a late answer, or do not jump; XREFS asked for while hidden
  * a rename or a comment from the right-click menu that the views do not
    show, a name with markup in the menu, the graph losing its zoom and pan
    across a rename, SEEK and the list keeping a name an analysis step changed
  * a console command that makes a jump in flight or waiting give way (the
    views stay where they were, the jump is dropped), a command that shows
    the prompt of before the command it waited for
  * the menu past the window's edge once its field shows, or closed by a
    scroll of the tab's own; an empty comment field that removes a comment
    no one saw
  * Tab that goes as far as the 200 flags sent agree rather than all that
    match, several /flags requests at once; rows of the file before left to
    click once another file is opened
  * a "Rizin" button missing where a Hex button knows a path, or one whose
    path (a sample names it) leaves its handler; a ThreatScan entry offered
    for a file that is gone
  * a toolbar that does not say busy, why the analysis stopped, that the
    file is open in another tab or that the session ended, without Take it
    back, Reopen or Full analysis; Take it back or Reopen that lose the place
    shown; a status asked for before Full analysis that ends the poll
  * C from rz-ghidra taken as markup, its lines without their address, the
    line of the current address not marked, a click on a line that does not
    jump; a hidden DECOMPILER or HEX that asks rizin, or never catches up; a
    decompile that ended the session without saying so
  * a long function whose disassembly stops after the first page, a page
    asked for twice, a late page for a place left
  * a session left running when its page goes
"""

import json
import os
import re

from test_frontend import ROOT, SOURCE, _function_source, _run_node, needs_node
from test_theme import (INDEX_HTML, LAYOUT_CSS, LITERAL_COLOR, SORT_DOM, STYLE_CSS, THEME_CSS, _const_source, _css_blocks,
                        _cyberpunk_palette, _read, _root_values, _rules, _selectors, _strip_comments, _tab_markup,
                        _unscoped_rules)

# The block RIZIN of app.js. Every function, constant and `let` of it is listed
# here, so a test can hand it to node (test_rizin_lists_cover_the_block).
RIZIN_FUNCTIONS = [
    "rizinTabId", "rizinRandomId", "rizinApi", "rizinUsesPipe", "rizinSetUi", "rizinHex", "rizinNum",
    "rizinSeekTarget", "rizinOpClass", "rizinOperandsHtml", "rizinCommentHtml", "rizinFunctionsHtml",
    "rizinDisasmHtml", "rizinAnalysisText", "rizinFileTag", "rizinOpenSourcesHtml", "rizinReset", "rizinOpen",
    "openInRizin", "rizinOpenPath", "rizinUpload", "rizinLoadFiles", "rizinToggleOpenMenu", "rizinCloseOpenMenu",
    "rizinOnOpenSourceClick", "rizinSchedulePoll", "rizinStopPoll", "rizinPollSoon", "rizinNeedsPoll", "rizinPoll",
    "rizinReloadViews", "rizinLand", "rizinRetryViews", "rizinViewBusy", "rizinLoadFunctions", "rizinPageHolds",
    "rizinLoadDisasm", "rizinSeek", "rizinPushHistory",
    "rizinHistoryStep", "rizinGo", "rizinRefreshViews", "rizinRenderToolbar", "rizinRenderFile",
    "rizinRenderAnalysis", "rizinRenderState", "rizinRenderLocation", "rizinRenderFunctions", "rizinRenderDisasm",
    "rizinOnFunctionClick", "rizinOnDisasmClick", "rizinOnTabClick", "rizinToggleFunctions", "rizinReveal",
    "rizinScrollAnchor", "rizinRestoreScroll", "initRizinTab", "rizinTabShown", "rizinCheckInstalled",
    # The graph (Task 5)
    "rizinGraphBoxSize", "rizinGraphCrossings", "rizinGraphPlaceLayer", "rizinLayoutGraph", "rizinGraphSvg",
    "rizinGraphBoxAt", "rizinGraphFitView", "rizinGraphZoomView", "rizinGraphClampView", "rizinGraphRevealView",
    "rizinGraphVisible", "rizinGraphSection", "rizinGraphHolds", "rizinLoadGraph", "rizinRenderGraph",
    "rizinGraphMark", "rizinGraphApplyView", "rizinGraphSettle", "rizinGraphResized", "rizinGraphShown",
    "rizinGraphOnScreen", "rizinGraphStartView", "rizinGraphPane", "rizinOnGraphClick", "rizinOnGraphPointerDown",
    "rizinOnGraphPointerMove", "rizinOnGraphPointerUp", "rizinOnGraphWheel", "rizinGraphZoomBy", "rizinGraphFit",
    "rizinToggleMax", "rizinApplyCenterLayout", "rizinSplitColumns", "rizinSetSplit", "rizinOnSplitDown",
    "rizinOnSplitMove", "rizinOnSplitUp", "rizinOnSplitKey",
    # The console, the dock and the right-click menu (Task 6)
    "rizinAnsiColor", "rizinAnsi256", "rizinAnsiSgr", "rizinAnsiClass", "rizinAnsiHtml", "rizinVisibleText",
    "rizinConsolePrompt", "rizinRenderPrompt", "rizinConsoleEntry", "rizinConsoleFill", "rizinConsoleNote",
    "rizinConsoleTrim", "rizinConsoleRun", "rizinConsoleRemember", "rizinConsoleBrowse", "rizinCompleteToken",
    "rizinCommonPrefix", "rizinConsoleComplete", "rizinSetCaret", "rizinOnConsoleKey", "rizinOnQuickClick",
    "rizinFunctionRenamed", "rizinAnnotated", "rizinStringsHtml", "rizinImportsHtml", "rizinXrefsHtml",
    "rizinLoadList", "rizinRenderList", "rizinOnListFilter", "rizinListPage", "rizinXrefsHold", "rizinLoadXrefs",
    "rizinRenderXrefs", "rizinOnDockClick", "rizinShowDock", "rizinDockShown", "rizinDockOnScreen",
    "rizinRenderDockNote", "rizinToggleDock", "rizinApplyDockLayout", "rizinSetDockHeight", "rizinOnDockGripDown",
    "rizinOnDockGripMove", "rizinOnDockGripUp", "rizinOnDockGripKey", "rizinOnContextMenu", "rizinOpenMenu",
    "rizinCloseMenu", "rizinOnMenuClick", "rizinOnMenuKey", "rizinMenuForm", "rizinMenuSubmit", "rizinRename",
    "rizinComment",
    # The review of Task 6
    "rizinConsoleFlags", "rizinPlaceMenu", "rizinMenuWaits", "rizinMenuNote", "rizinMenuReadComment",
    # DECOMPILER, HEX, more of a long disassembly, the session's states and the page going (Task 7)
    "rizinCodeOnScreen", "rizinCodeShown", "rizinLineOffsets", "rizinDecompilerMark", "rizinCHtml",
    "rizinDecompilerHtml", "rizinDecompilerHolds", "rizinLoadDecompiler", "rizinRenderDecompiler",
    "rizinOnDecompilerClick", "rizinEndedText", "rizinHexHtml", "rizinHexBarHtml", "rizinHexHolds", "rizinLoadHex",
    "rizinRenderHex", "rizinOnHexClick", "rizinOpenHexTab", "rizinLoadMore", "rizinMoreText", "rizinRenderMore",
    "rizinOnDisasmScroll", "rizinFullAnalysis", "rizinReopen", "rizinCheckSession", "rizinOnPageHide",
    # The review's fixes: DISASSEMBLY's next page once back in sight, decompiles that ended a session
    "rizinDisasmCatchUp", "rizinDecompileSlow", "rizinDecompileAgain",
    # The final review's fixes: the session checked only in the RIZIN tab, marks moved instead of lists drawn
    "rizinTabActive", "rizinOnFunctionFilter", "rizinMoveMark",
    # The run strip (Task 10): the state of the emulation, its runs, the call assistant, the PC's marks
    "rizinEmuHex", "rizinEmuPc", "rizinEmuWhy", "rizinRunAssistHtml", "rizinRunStripHtml", "rizinRenderRunStrip",
    "rizinRenderPcMarks", "rizinMovePc", "rizinEmuAtCall", "rizinEmuAssist", "rizinEmuPost", "rizinEmuStart",
    "rizinEmuStop", "rizinEmuRun", "rizinEmuSkipCall", "rizinEmuGoToPc", "rizinEmuLeave", "rizinLoadEmulation",
    "rizinOnRunClick",
    # The EMULATION pane (Task 11): the registers, the stack, the breakpoints and the patches in their two groups
    "rizinEmuRowAddr", "rizinEmuFunctionAt", "rizinEmuBytes", "rizinEmuNotes", "rizinEmuRegistersHtml",
    "rizinEmuStackHtml", "rizinEmuBreakpointsHtml", "rizinEmuPatchesHtml", "rizinEmuPaneHtml", "rizinRenderEmuPane",
    "rizinLoadEmuPane", "rizinEmuPaneSay", "rizinOnEmuPaneClick", "rizinOnEmuPaneChange", "rizinSetRegister",
    "rizinUnpatch", "rizinUnbreak", "rizinReanalyze", "rizinExportPatched", "rizinEmuEmpty", "rizinEmuHandSignature",
    "rizinEmuPatchesHeadHtml",
    # The hand-off of the exported copy to the Submit tab (Task 13)
    "rizinDetonatePatched",
    # The gutter and the patch menu (Task 12): the marks DISASSEMBLY draws and the lists they come from, a click in the
    # gutter, the four patches of one instruction, the bytes by hand, Run to here
    "rizinSetLists", "rizinLoadMarks", "rizinToggleBreakpoint", "rizinPatchHex", "rizinPatchKinds", "rizinPatchPost",
    "rizinPatchOp", "rizinPatchBytes", "rizinRunToHere", "rizinMenuEntries", "rizinMenuAct", "rizinMenuFinish",
    # The gutter in DECOMPILER: the address a click on a line of C acts on
    "rizinDecompilerStops",
]
RIZIN_CONSTS = ["rizinState", "RIZIN_POLL_MS", "RIZIN_HISTORY_MAX", "RIZIN_TAB_KEY", "RIZIN_VIEWS", "RIZIN_GRAPH",
                "RIZIN_GRAPH_OVERVIEW", "RIZIN_NARROW_PX", "RIZIN_ANSI", "RIZIN_CONSOLE", "RIZIN_CONSOLE_COMMANDS",
                "RIZIN_PAGE", "RIZIN_FILTER_MS", "RIZIN_DOCK", "RIZIN_HEX_LEN", "RIZIN_MORE", "RIZIN_C_WORDS", "RIZIN_EMU", "RIZIN_EMU_PANE",
                "RIZIN_PATCH"]
RIZIN_LETS = []
HELPERS = ["escapeHtml", "jsArg", "jsInt", "cssToken", "formatSize", "handleFileSelect"]

HOSTILE = "<img src=x onerror=alert(1)>"


def _rizin_prelude(poll_ms=None, filter_ms=None):
    """The constants of the block; the poll interval and the wait of a list filter shortened for a test."""
    consts = []
    for name in RIZIN_CONSTS:
        source = _const_source(name)
        if name == "RIZIN_POLL_MS" and poll_ms is not None:
            source = re.sub(r"=\s*\d+;", f"= {poll_ms};", source)
        if name == "RIZIN_FILTER_MS" and filter_ms is not None:
            source = re.sub(r"=\s*\d+;", f"= {filter_ms};", source)
        consts.append(source)
    return "\n".join(consts + RIZIN_LETS)


def _run(script, prelude=""):
    return _run_node(RIZIN_FUNCTIONS + HELPERS, script, prelude)


def test_rizin_lists_cover_the_block():
    """The lists above name every function, constant and `let` of the block,
    and the block has what the later tasks build on."""
    functions = set(re.findall(r"^(?:async )?function ((?:_?rizin|openInRizin|initRizin)\w*)\(", SOURCE, re.M))
    assert functions == set(RIZIN_FUNCTIONS), (sorted(functions - set(RIZIN_FUNCTIONS)),
                                               sorted(set(RIZIN_FUNCTIONS) - functions))
    consts = set(re.findall(r"^const ((?:_?rizin|RIZIN_)\w*) =", SOURCE, re.M))
    assert consts == set(RIZIN_CONSTS)
    lets = re.findall(r"^let ((?:_?rizin|RIZIN_)\w*)\b", SOURCE, re.M)
    assert lets == [re.match(r"let (\w+)", let).group(1) for let in RIZIN_LETS]
    state = _const_source("rizinState")
    for field in ("session: null", "tab: ''", "file: null", "seek: null", "func: null", "history: []",
                  "historyAt: -1"):
        assert field in state, field
    # switchTab opens the tab's start-up, the start-up of the page wires it
    assert re.search(r"tabName === 'rizin'\)\s*\{\s*rizinTabShown\(\)", _function_source("switchTab"))
    start = SOURCE.index("document.addEventListener('DOMContentLoaded', () => {")
    assert re.search(r"^\s*initRizinTab\(\);", SOURCE[start:SOURCE.index("\n});", start)], re.M)


@needs_node
def test_rizin_functions_and_disasm_render_safely():
    r = _run(r"""
        const HOSTILE = HOSTILE_JSON;
        const box = html => { const el = document.createElement('div'); el.innerHTML = html; return el; };
        const attrs = el => [...el.walk()].flatMap(e => Object.keys(e.attrs));
        const addrs = (el, sel) => el.querySelectorAll(sel).map(e => e.getAttribute('data-addr'));
        const funcs = [
            { name: HOSTILE, offset: 0x140001000, size: 1, nbbs: 1 },
            { name: 'x" onmouseover="alert(1)', offset: 0x140001010, size: 7, nbbs: 1 },
            { name: 'sym.watchdog', offset: 0x140001490, size: 38, nbbs: 1 },
            { name: 'sym.main', offset: 0x1400014b7, size: 1382, nbbs: 30 },
            { name: 'dbg.mainCRTStartup', offset: 0x140001440, size: 29, nbbs: 1 },
        ];
        const r = {};
        const list = box(rizinFunctionsHtml(funcs, { filter: '', current: 'sym.main' }));
        r.list = {
            rows: addrs(list, '.rizin-fn'),
            names: list.querySelectorAll('.rizin-fn-name').map(e => e.textContent),
            sizes: list.querySelectorAll('.rizin-fn-size').map(e => e.textContent),
            titles: list.querySelectorAll('.rizin-fn').map(e => e.getAttribute('title')),
            current: addrs(list, '.rizin-fn.current'),
            tags: [...list.walk()].map(e => e.tagName).filter(t => !['DIV', 'SPAN'].includes(t)),
            handlers: attrs(list).filter(a => a.startsWith('on')),
        };
        r.byAddress = addrs(box(rizinFunctionsHtml(funcs, { current: '0x140001490' })), '.current');
        r.noCurrent = addrs(box(rizinFunctionsHtml(funcs, { current: null })), '.current');
        const names = filter => box(rizinFunctionsHtml(funcs, { filter, current: 'sym.main' }))
            .querySelectorAll('.rizin-fn-name').map(e => e.textContent);
        r.filter = { watch: names('WATCH'), main: names(' Main '), address: names('14b7'), hex: names('0X1400014B7'),
                     markup: names('<IMG'), none: names('zzz') };
        r.filteredCurrent = addrs(box(rizinFunctionsHtml(funcs, { filter: 'watch', current: 'sym.main' })), '.current');

        const LONG = 'mov rax, ' + 'A'.repeat(10000);
        const ops = [
            { offset: 0x1400014b7, size: 2, text: 'push r15', type: 'rpush', jump: null, comment: null },
            { offset: 0x140001505, size: 2, text: 'jle 0x140001521', type: 'cjmp', jump: 0x140001521,
              comment: `say "hi" <b>bold</b> & 'q'` },
            { offset: 0x140001507, size: 4, text: LONG, type: 'mov', jump: null, comment: null },
            { offset: 0x140001512, size: 5, text: 'call sym.strcmp', type: 'call', jump: 0x140002ec0, comment: null },
            { offset: 0x14000151b, size: 6, text: 'call qword [sym.imp.KERNEL32.dll_CreateThread]', type: 'ircall',
              jump: null, comment: null },
            { offset: 0x140001521, size: 8, text: 'lea rdx, qword str.child', type: 'lea', jump: null, comment: null },
            { offset: 0x140001529, size: 1, text: HOSTILE + '<script>alert(2)</script>', type: 'invalid', jump: null,
              comment: '"><img src=x onerror=alert(3)>' },
            { offset: 0x14000152a, size: 2, text: 'jmp sym.watchdog', type: 'jmp', jump: 0x140001490, comment: null },
            { offset: 0x1400018b8, size: 1, text: 'ret', type: 'ret', jump: null, comment: null },
        ];
        const dis = box(rizinDisasmHtml(ops, { current: '0x140001506' }));     // inside the 2-byte jle
        const line = addr => dis.querySelector(`.rizin-op[data-addr="${addr}"]`);
        const mnem = addr => line(addr).querySelector('.rz-mnem');
        r.dis = {
            lines: addrs(dis, '.rizin-op'),
            shown: dis.querySelectorAll('.rizin-op .rz-addr').map(e => e.textContent.trim()),
            current: addrs(dis, '.rizin-op.current'),
            targets: dis.querySelectorAll('.rz-target').map(e => [e.getAttribute('data-addr'), e.textContent,
                                                                  e.closest('.rizin-op').getAttribute('data-addr')]),
            kinds: Object.fromEntries(['0x1400014b7', '0x140001505', '0x140001512', '0x14000151b', '0x14000152a',
                                       '0x1400018b8'].map(a => [a, mnem(a).className.split(' ').sort()])),
            mnemonics: dis.querySelectorAll('.rz-mnem').map(e => e.textContent.trim()),
            symbols: dis.querySelectorAll('.rz-sym').map(e => e.textContent),
            comments: dis.querySelectorAll('.rz-comment').map(e => e.textContent),
            strings: dis.querySelectorAll('.rz-str').map(e => e.textContent),
            hostile: line('0x140001529').textContent,
            long: line('0x140001507').textContent.length,
            longAs: line('0x140001507').querySelectorAll('span').length,
            tags: [...dis.walk()].map(e => e.tagName).filter(t => !['DIV', 'SPAN'].includes(t)),
            handlers: attrs(dis).filter(a => a.startsWith('on')),
        };
        r.disByNumber = addrs(box(rizinDisasmHtml(ops, { current: 0x1400018b8 })), '.current');
        r.disNone = addrs(box(rizinDisasmHtml(ops, { current: '0x150000000' })), '.current');
        r.disEmpty = rizinDisasmHtml([], { current: '0x1' });
        console.log(JSON.stringify(r));
    """.replace("HOSTILE_JSON", json.dumps(HOSTILE)), SORT_DOM)
    rows = ["0x140001000", "0x140001010", "0x140001490", "0x1400014b7", "0x140001440"]
    assert r["list"]["rows"] == rows, "every function is a row that carries its address"
    assert r["list"]["names"] == [HOSTILE, 'x" onmouseover="alert(1)', "sym.watchdog", "sym.main", "dbg.mainCRTStartup"]
    assert r["list"]["sizes"] == ["1", "7", "38", "1382", "29"]
    assert all(t.startswith(a) for t, a in zip(r["list"]["titles"], rows)), "the address shows on hover"
    assert r["list"]["titles"][0].endswith(HOSTILE) and r["list"]["titles"][1].endswith('x" onmouseover="alert(1)')
    assert r["list"]["current"] == ["0x1400014b7"]
    assert r["list"]["tags"] == [] and r["list"]["handlers"] == [], "a name became markup"
    assert r["byAddress"] == ["0x140001490"] and r["noCurrent"] == []
    assert r["filter"] == {"watch": ["sym.watchdog"], "main": ["sym.main", "dbg.mainCRTStartup"], "address": ["sym.main"],
                           "hex": ["sym.main"], "markup": [HOSTILE], "none": []}
    assert r["filteredCurrent"] == []

    dis = r["dis"]
    assert dis["lines"] == ["0x1400014b7", "0x140001505", "0x140001507", "0x140001512", "0x14000151b", "0x140001521",
                            "0x140001529", "0x14000152a", "0x1400018b8"]
    assert dis["shown"] == dis["lines"]
    assert dis["current"] == ["0x140001505"], "the instruction that holds the address is marked"
    assert dis["targets"] == [["0x140001521", "0x140001521", "0x140001505"], ["0x140002ec0", "sym.strcmp", "0x140001512"],
                              ["0x140001490", "sym.watchdog", "0x14000152a"]], "jump and call targets take a click"
    kinds = {addr: [c for c in classes if c != "rz-mnem"] for addr, classes in dis["kinds"].items()}
    assert kinds == {"0x1400014b7": [], "0x140001505": ["rz-jump"], "0x140001512": ["rz-call"],
                     "0x14000151b": ["rz-call"], "0x14000152a": ["rz-jump"], "0x1400018b8": ["rz-ret"]}
    assert dis["mnemonics"][:4] == ["push", "jle", "mov", "call"]
    assert {"sym.strcmp", "sym.imp.KERNEL32.dll_CreateThread", "str.child", "sym.watchdog"} <= set(dis["symbols"])
    assert any('say "hi" <b>bold</b> & \'q\'' in c for c in dis["comments"])
    assert '"hi"' in dis["strings"]
    assert HOSTILE + "<script>alert(2)</script>" in dis["hostile"] and '"><img src=x onerror=alert(3)>' in dis["hostile"]
    assert dis["long"] >= 10000 + len("0x140001507"), "the long line is cut"
    assert dis["tags"] == [] and dis["handlers"] == [], "an instruction or a comment became markup"
    assert r["disByNumber"] == ["0x1400018b8"] and r["disNone"] == []
    assert r["disEmpty"] == ""


# Three functions of pipesim.exe and their instructions, as the routes answer them
FAKE_DATA = r"""
const FUNCS = [
    { name: 'entry0', offset: 0x140001000, size: 16, nbbs: 1 },
    { name: 'sym.watchdog', offset: 0x140001490, size: 38, nbbs: 1 },
    { name: 'sym.main', offset: 0x1400014b7, size: 1382, nbbs: 30 },
];
const op = (offset, size, text, type, jump = null, comment = null) => ({ offset, size, text, type, jump, comment });
const OPS = {
    'entry0': [op(0x140001000, 4, 'sub rsp, 0x28', 'sub'), op(0x140001004, 5, 'call sym.main', 'call', 0x1400014b7),
               op(0x140001009, 4, 'add rsp, 0x28', 'add'), op(0x14000100d, 1, 'ret', 'ret')],
    'sym.watchdog': [op(0x140001490, 4, 'sub rsp, 0x28', 'sub'), op(0x140001494, 5, 'mov ecx, 0x3e8', 'mov'),
                     op(0x140001499, 6, 'call qword [sym.imp.KERNEL32.dll_Sleep]', 'ircall'),
                     op(0x14000149f, 2, 'jmp 0x140001494', 'jmp', 0x140001494)],
    'sym.main': [op(0x1400014b7, 2, 'push r15', 'rpush'), op(0x1400014b9, 3, 'cmp ebx, 0x02', 'cmp'),
                 op(0x1400014bc, 2, 'jle 0x140001521', 'cjmp', 0x140001521),
                 op(0x1400014be, 5, 'call sym.watchdog', 'call', 0x140001490),
                 op(0x140001521, 8, 'lea rdx, qword [lpFilename]', 'lea'), op(0x140001529, 1, 'ret', 'ret')],
};
const fnAt = a => FUNCS.find(f => a >= f.offset && a < f.offset + f.size) || null;
// The blocks of each function, as the graph route answers them
const block = (offset, size, lines, jump = null, fail = null, cases = []) => ({ offset, size, lines, jump, fail, cases });
const GRAPHS = {
    'entry0': [block(0x140001000, 14, OPS['entry0'].map(o => o.text))],
    'sym.watchdog': [block(0x140001490, 4, ['sub rsp, 0x28'], 0x140001494),
                     block(0x140001494, 13, ['mov ecx, 0x3e8', 'call qword [sym.imp.KERNEL32.dll_Sleep]', 'jmp 0x140001494'],
                           0x140001494)],
    'sym.main': [block(0x1400014b7, 7, ['push r15', 'cmp ebx, 0x02', 'jle 0x140001521'], 0x140001521, 0x1400014be),
                 block(0x1400014be, 5, ['call sym.watchdog'], 0x140001521),
                 block(0x140001521, 9, ['lea rdx, qword [lpFilename]', 'ret'])],
};
const graphAt = a => { const f = fnAt(a); return f ? { function: f.name, offset: f.offset, nodes: GRAPHS[f.name] } : { function: null, offset: null, nodes: [] }; };
// The strings, imports, flags and cross references, as their routes answer them (Task 6); renameFn
// renames a function in every answer, COMMENTS holds the comments set
const STRINGS = [
    { offset: 0x140005000, string: 'watchdog: giving up', length: 19, section: '.rdata', type: 'ascii' },
    { offset: 0x140005014, string: 'child', length: 5, section: '.rdata', type: 'ascii' },
    { offset: 0x140005024, string: "child: got '%s'\n", length: 16, section: '.rdata', type: 'ascii' },
    { offset: 0x140005041, string: '\\\\.\\pipe\\msagent_%04x%02x', length: 25, section: '.rdata', type: 'ascii' },
    { offset: 0x140005060, string: '<img src=x onerror=alert(1)>\x1b]8;;x\x07', length: 34, section: '.rdata', type: 'ascii' },
    { offset: 0x140005090, string: 'Pipe closed', length: 11, section: '.rdata', type: 'ascii' },
    ...Array.from({ length: 447 }, (_, i) => ({ offset: 0x140006000 + i * 0x10, string: `text ${i}`, length: 5 + String(i).length,
                                                section: '.data', type: 'ascii' })),
];
const IMPORTS = [
    { offset: 0x140009318, name: 'CloseHandle', library: 'KERNEL32.dll', type: 'FUNC', ordinal: 1 },
    { offset: 0x1400093b0, name: 'CreateNamedPipeA', library: 'KERNEL32.dll', type: 'FUNC', ordinal: 4 },
    { offset: 0x1400093a8, name: 'Sleep', library: 'KERNEL32.dll', type: 'FUNC', ordinal: 9 },
    { offset: null, name: 'Ordinal_7', library: 'WS2_32.dll', type: 'FUNC', ordinal: 7 },
];
const FLAG_NAMES = ['sym.mainCRTStartup', 'sym.imp.KERNEL32.dll_CreateNamedPipeA', 'sym.imp.KERNEL32.dll_Sleep', 'str.child'];
const COMMENTS = new Map();
const xref = (from, to, type, text) => ({ from, to, type, text, function: fnAt(from)?.name ?? null });
function xrefsAt(a) {
    const f = fnAt(a), refs = { to: [], from: [] };
    if (a === 0x1400093b0) {
        refs.to = [xref(0x140001521, a, 'CALL', 'call qword [sym.imp.KERNEL32.dll_CreateNamedPipeA]'),
                   xref(0x140003098, a, 'CODE', 'jmp qword [sym.imp.KERNEL32.dll_CreateNamedPipeA]')];
    }
    if (a === 0x1400014b7) {
        refs.to = [xref(0x140001004, a, 'CALL', 'call sym.main')];
        refs.from = [xref(0x1400014be, 0x140001490, 'CALL', 'call sym.watchdog')];
    }
    return { scope: f && f.offset === a ? 'function' : 'address', function: f ? f.name : null, ...refs, truncated: false };
}
function renameFn(f, name) {
    OPS[name] = OPS[f.name];
    GRAPHS[name] = GRAPHS[f.name];
    f.name = name;
}
// rz-ghidra's C of each function, as the decompile route answers it (Task 7): a line's offset is its first
// address in rizin's order, offsets are all of them, sorted
const cline = (text, ...addrs) => ({ text, offset: addrs.length ? addrs[0] : null, offsets: [...addrs].sort((a, b) => a - b) });
const DECOMPILED = {
    'sym.main': [cline('int main(int argc, char **argv)'), cline('{'), cline('    if (argc < 3) {', 0x1400014b9, 0x1400014bc),
                 cline('        watchdog(); /* starts the "watch" */', 0x1400014be),
                 cline('        puts("<img src=x onerror=alert(1)>" & \'q\');', 0x1400014be), cline('    }'), cline(''),
                 cline('    return 0;', 0x140001529, 0x140001521), cline('}')],
    'sym.watchdog': [cline('void watchdog(void)'), cline('{'), cline('    do {', 0x140001494),
                     cline('        sym.imp.KERNEL32.dll_Sleep(1000);', 0x140001499, 0x140001494), cline('    } while (true);', 0x14000149f),
                     cline('}')],
};
function decompileAt(a) {
    const f = fnAt(a);
    if (!f) return { available: true, reason: `No function at 0x${a.toString(16)}`, function: null, lines: [] };
    return { available: true, reason: DECOMPILED[f.name] ? null : `rz-ghidra returned no code for ${f.name}`, function: f.name,
             lines: DECOMPILED[f.name] || [] };
}
// pxj at an address: the bytes count up from its low byte; paddr is its offset in the file (none from 0x140009000)
const hexAt = (a, len) => ({ offset: a, bytes: Array.from({ length: len }, (_, i) => (a + i) % 256),
                             paddr: a >= 0x140000000 && a < 0x140009000 ? a - 0x140000000 : null });
"""

# The server as the tab sees it (rizin_sessions and app.py as in the real
# answers), for session S1; every request is recorded.
FAKE_SERVER = FAKE_DATA + r"""
const server = { analysis: 'running', statusCalls: 0, busyFunctions: 1, seek: 0x140001000, busySeek: 0 };
const calls = [];
let inflight = 0;
const answer = (status, data) => ({ ok: status < 400, status, json: async () => data });
function route(method, url, body) {
    const [path, query] = url.split('?');
    const params = new URLSearchParams(query || '');
    if (method === 'POST' && path === '/api/rizin/open')
        return answer(200, { session: 'S1', analysis: { state: 'running', step: 'aaa', done_steps: [], level: 'aaa', elapsed: 0.1, note: null },
                             file: { path: body.path, sha256: '40bdb0cb' + '0'.repeat(48) + 'bc034c74', size: 155350,
                                     format: 'pe64', arch: 'x86', bits: 64 } });
    if (path === '/api/rizin/S1/status') {
        server.statusCalls++;
        if (server.statusCalls >= 2) server.analysis = 'done';
        const done = server.analysis === 'done';
        return answer(200, { analysis: { state: server.analysis, step: done ? null : 'aaa', done_steps: done ? ['aaa'] : [],
                                         level: 'aaa', elapsed: done ? 1.3 : 0.5, note: null },
                             seek: server.seek, function: fnAt(server.seek)?.name ?? null });
    }
    if (path === '/api/rizin/S1/functions') {
        if (server.analysis === 'running' && server.busyFunctions-- > 0) return answer(409, { busy: true, step: 'aaa' });
        return answer(200, FUNCS);
    }
    if (method === 'POST' && path === '/api/rizin/S1/seek') {
        if (server.busySeek-- > 0) return answer(409, { busy: true, step: 'console' });
        const a = /^0x[0-9a-f]+$/.test(body.addr) ? parseInt(body.addr, 16) : FUNCS.find(f => f.name === body.addr)?.offset;
        if (a === undefined) return answer(400, { refused: `unknown address or name: '${body.addr}'` });
        server.seek = a;
        return answer(200, { seek: a, function: fnAt(a)?.name ?? null });
    }
    if (path === '/api/rizin/S1/disasm') {
        const a = parseInt(params.get('addr'), 16), f = fnAt(a);
        return answer(200, f ? { function: f.name, ops: OPS[f.name], more: false }
                             : { function: null, ops: [op(a, 1, 'nop', 'nop')], more: true });
    }
    if (path === '/api/rizin/S1/graph') return answer(200, graphAt(parseInt(params.get('addr'), 16)));
    return answer(404, { error: 'not found: ' + url });
}
globalThis.fetch = (url, init = {}) => {
    const body = init.body ? JSON.parse(init.body) : undefined;
    calls.push([init.method || 'GET', url, body]);
    inflight++;
    return new Promise(resolve => setTimeout(() => { inflight--; resolve(route(init.method || 'GET', url, body)); }, 1));
};
const stored = new Map();
globalThis.sessionStorage = { getItem: k => (stored.has(k) ? stored.get(k) : null), setItem: (k, v) => stored.set(k, String(v)) };
globalThis.switchTab = name => calls.push(['TAB', name]);
globalThis.showToast = (...args) => calls.push(['TOAST', ...args]);
const tick = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(test, what) {
    for (let i = 0; i < 2000 && !test(); i++) await tick(1);
    if (!test()) throw new Error('timed out: ' + what);
}
// Every request answered and drawn, and nothing asked for 25 ms
async function quiet() {
    for (let quiet = 0; quiet < 25;) {
        const before = calls.length;
        await tick(1);
        quiet = calls.length === before && inflight === 0 ? quiet + 1 : 0;
    }
}
const $ = id => document.getElementById(id);
// What each view shows
function view() {
    const fn = $('rizin-fn-list').querySelectorAll('.rizin-fn.current');
    const line = $('rizin-disasm').querySelectorAll('.rizin-op.current');
    return {
        seek: rizinState.seek, func: rizinState.func,
        toolbar: [$('rizin-seek').value, $('rizin-seek').getAttribute('data-addr')],
        functions: fn.map(e => [e.getAttribute('data-addr'), e.querySelector('.rizin-fn-name').textContent]),
        disasm: line.map(e => e.getAttribute('data-addr')),
        title: $('rizin-code-title').textContent,
        history: [rizinState.history.slice(), rizinState.historyAt],
        buttons: [!!$('rizin-back').disabled, !!$('rizin-forward').disabled],
    };
}
const seeks = () => calls.filter(c => c[0] === 'POST' && c[1] === '/api/rizin/S1/seek').map(c => c[2].addr);
const gets = part => calls.filter(c => c[0] === 'GET' && c[1].includes(part)).length;
"""


@needs_node
def test_rizin_seek_updates_every_view():
    r = _run(r"""
        (async () => {
            document.body.innerHTML = MARKUP;
            initRizinTab();
            const r = {};
            const opened = openInRizin('C:\\Users\\Public\\Downloads\\pipesim.exe');
            await until(() => $('rizin-state').textContent.includes('busy'), 'busy shown');
            r.busy = [$('rizin-state').textContent, $('rizin-state').hidden, [...rizinState.retry.keys()]];
            r.opened = await opened;
            await until(() => rizinState.seek === '0x1400014b7', 'the first jump');
            await quiet();
            r.landed = view();
            r.open = calls.filter(c => c[1] === '/api/rizin/open').map(c => c[2]);
            r.file = [$('rizin-file-path').textContent, $('rizin-file-tag').textContent, $('rizin-file-sha').textContent,
                      $('rizin-file-sha').getAttribute('title'), $('rizin-analysis').textContent];
            r.state = [$('rizin-state').hidden, rizinState.ui.state, [...rizinState.retry.keys()]];
            r.polls = server.statusCalls;
            await tick(60);
            r.pollsLater = server.statusCalls;
            r.tab = calls.find(c => c[0] === 'TAB');

            // A click on a function
            const disasmGets = gets('/disasm');
            click($('rizin-fn-list').querySelector('[data-addr="0x140001490"]'));
            await until(() => rizinState.seek === '0x140001490', 'function click'); await quiet();
            r.function = [view(), gets('/disasm') - disasmGets];

            // A click on a jump target in the same function: no new page of instructions
            const before = gets('/disasm');
            click($('rizin-disasm').querySelector('.rz-target[data-addr="0x140001494"]'));
            await until(() => rizinState.seek === '0x140001494', 'jump target click'); await quiet();
            r.target = [view(), gets('/disasm') - before];

            // A click on an instruction moves there
            click($('rizin-disasm').querySelector('.rizin-op[data-addr="0x140001499"] .rz-addr'));
            await until(() => rizinState.seek === '0x140001499', 'line click'); await quiet();
            r.line = view();

            // SEEK GO with a name, and with an address written in capitals with leading zeros
            $('rizin-seek').value = 'sym.main';
            click($('rizin-go'));
            await until(() => rizinState.seek === '0x1400014b7', 'GO name'); await quiet();
            r.go = view();
            $('rizin-seek').value = '0X0140001490';
            click($('rizin-go'));
            await until(() => rizinState.seek === '0x140001490', 'GO address'); await quiet();
            r.goAddress = view();

            // A call target in the disassembly leaves the function
            click($('rizin-fn-list').querySelector('[data-addr="0x1400014b7"]'));
            await until(() => rizinState.seek === '0x1400014b7', 'back to main'); await quiet();
            click($('rizin-disasm').querySelector('.rz-target[data-addr="0x140001490"]'));
            await until(() => rizinState.seek === '0x140001490', 'call target'); await quiet();
            r.call = view();

            // ◀ ▶ walk the history without changing it
            const walk = [];
            for (const button of ['rizin-back', 'rizin-back', 'rizin-forward', 'rizin-back', 'rizin-back']) {
                const at = rizinState.historyAt;
                click($(button));
                await until(() => rizinState.historyAt !== at, button); await quiet();
                walk.push(view());
            }
            r.walk = walk;
            // A jump after going back drops the steps ahead
            click($('rizin-fn-list').querySelector('[data-addr="0x140001000"]'));
            await until(() => rizinState.seek === '0x140001000', 'entry0'); await quiet();
            r.branch = view();

            // A name rizin does not know: the reason shows, the text stays, nothing moves
            $('rizin-seek').value = 'sym.nothere';
            const seeksBefore = seeks().length;
            click($('rizin-go'));
            await until(() => seeks().length > seeksBefore, 'refused GO'); await quiet();
            r.refused = [view(), $('rizin-state').textContent, $('rizin-state').hidden];
            // A busy rizin: the jump does not happen and the toolbar says so, until the poll finds rizin free
            server.busySeek = 1;
            click($('rizin-fn-list').querySelector('[data-addr="0x140001490"]'));
            await until(() => $('rizin-state').textContent.includes('busy'), 'busy seek');
            r.busySeek = [view().seek, $('rizin-state').textContent, rizinState.history.length];
            const polls = server.statusCalls;
            await quiet();
            r.busyOver = [$('rizin-state').hidden, rizinState.ui.state, server.statusCalls > polls];
            const pollsAfter = server.statusCalls;
            await tick(60);
            r.busyOver.push(server.statusCalls === pollsAfter);

            r.seeks = seeks();
            r.addrs = [...document.body.walk()].map(e => e.getAttribute('data-addr')).filter(a => a !== null);
            r.toasts = calls.filter(c => c[0] === 'TOAST');
            console.log(JSON.stringify(r));
        })().catch(e => { console.log(JSON.stringify({ error: e.stack })); });
    """.replace("MARKUP", json.dumps(_tab_markup("rizin"))), SORT_DOM + _rizin_prelude(poll_ms=5) + FAKE_SERVER)
    assert "error" not in r, r.get("error")
    assert r["busy"] == ["busy (aaa)", False, ["functions"]], "a view that found rizin busy says so and waits"
    assert r["opened"] is True and r["tab"] == ["TAB", "rizin"]
    assert len(r["open"]) == 1 and r["open"][0]["path"] == "C:\\Users\\Public\\Downloads\\pipesim.exe"
    assert re.fullmatch(r"[A-Za-z0-9_-]{1,64}", r["open"][0]["tab"])
    main, watchdog = ["0x1400014b7", "sym.main"], ["0x140001490", "sym.watchdog"]
    # Once the analysis is done: one jump to sym.main, so the toolbar names the function
    assert r["landed"] == {"seek": "0x1400014b7", "func": "sym.main", "toolbar": ["sym.main", "0x1400014b7"],
                           "functions": [main], "disasm": ["0x1400014b7"], "title": "sym.main",
                           "history": [["0x1400014b7"], 0], "buttons": [True, True]}
    assert r["file"][0] == "C:\\Users\\Public\\Downloads\\pipesim.exe"
    assert r["file"][1] == "PE64 · x86-64 · 151.7 KB"
    assert r["file"][2] == "40bdb0cb…bc034c74" and r["file"][3] == "40bdb0cb" + "0" * 48 + "bc034c74"
    assert r["file"][4].startswith("analysed (aaa)")
    assert r["state"] == [True, "", []], "busy stays after rizin answered"
    assert r["pollsLater"] == r["polls"], "the status poll goes on after the analysis: the session never idles out"

    fn, fetched = r["function"]
    assert fn == {"seek": "0x140001490", "func": "sym.watchdog", "toolbar": ["sym.watchdog", "0x140001490"],
                  "functions": [watchdog], "disasm": ["0x140001490"], "title": "sym.watchdog",
                  "history": [["0x1400014b7", "0x140001490"], 1], "buttons": [False, True]}
    assert fetched == 1
    target, fetched = r["target"]
    assert target["toolbar"] == ["0x140001494", "0x140001494"] and target["functions"] == [watchdog]
    assert target["disasm"] == ["0x140001494"] and target["title"] == "sym.watchdog"
    assert fetched == 0, "a jump inside the loaded function fetched its instructions again"
    assert r["line"]["disasm"] == ["0x140001499"] and r["line"]["toolbar"] == ["0x140001499", "0x140001499"]
    assert r["go"]["toolbar"] == ["sym.main", "0x1400014b7"] and r["go"]["functions"] == [main]
    assert r["go"]["disasm"] == ["0x1400014b7"] and r["go"]["title"] == "sym.main"
    assert r["goAddress"]["functions"] == [watchdog] and r["goAddress"]["disasm"] == ["0x140001490"]
    assert r["call"]["functions"] == [watchdog] and r["call"]["disasm"] == ["0x140001490"]
    history = ["0x1400014b7", "0x140001490", "0x140001494", "0x140001499", "0x1400014b7", "0x140001490",
               "0x1400014b7", "0x140001490"]
    assert r["call"]["history"] == [history, 7]
    walked = [(v["history"], v["seek"], v["disasm"], v["functions"][0][1], v["buttons"]) for v in r["walk"]]
    assert walked == [([history, 6], "0x1400014b7", ["0x1400014b7"], "sym.main", [False, False]),
                      ([history, 5], "0x140001490", ["0x140001490"], "sym.watchdog", [False, False]),
                      ([history, 6], "0x1400014b7", ["0x1400014b7"], "sym.main", [False, False]),
                      ([history, 5], "0x140001490", ["0x140001490"], "sym.watchdog", [False, False]),
                      ([history, 4], "0x1400014b7", ["0x1400014b7"], "sym.main", [False, False])]
    assert all(v["toolbar"][1] == v["seek"] for v in r["walk"])
    assert r["branch"]["history"] == [history[:5] + ["0x140001000"], 5] and r["branch"]["buttons"] == [False, True]
    refused, text, hidden = r["refused"]
    assert refused["seek"] == "0x140001000" and refused["history"] == r["branch"]["history"]
    assert refused["toolbar"] == ["sym.nothere", "0x140001000"], "the refused name was replaced"
    assert text == "unknown address or name: 'sym.nothere'" and hidden is False
    assert r["busySeek"] == ["0x140001000", "busy (console)", 6]
    assert r["busyOver"] == [True, "", True, True], "busy stays, or the poll goes on once rizin is free"
    # Every jump went through POST seek, with the address as a "0x…" string
    assert r["seeks"] == ["0x1400014b7", "0x140001490", "0x140001494", "0x140001499", "sym.main", "0x140001490",
                          "0x1400014b7", "0x140001490", "0x1400014b7", "0x140001490", "0x1400014b7", "0x140001490",
                          "0x1400014b7", "0x140001000", "sym.nothere", "0x140001490"]
    assert all(re.fullmatch(r"0x[0-9a-f]+", a) for a in r["addrs"]), "a data-addr that is no 0x… string"
    assert r["toasts"] == []


@needs_node
def test_rizin_first_jump_after_the_analysis():
    """The controller's ruling: once the analysis is over the tab jumps once,
    to main or sym.main (main first), else to where rizin stands (the entry
    point); not when the user jumped already; a jump that finds rizin busy
    is made once the poll finds it free, without loading the list again."""
    def run(setup, script):
        return _run(r"""
            (async () => {
                document.body.innerHTML = MARKUP;
                SETUP
                const opened = await openInRizin('C:\\Users\\Public\\Downloads\\pipesim.exe');
                SCRIPT
                await until(() => rizinState.landed, 'landed');
                await quiet();
                const polls = server.statusCalls;
                await tick(60);
                console.log(JSON.stringify({ opened, seeks: seeks(), functions: gets('/functions'), seek: rizinState.seek,
                                             history: rizinState.history, toolbar: $('rizin-seek').value,
                                             pollsStop: server.statusCalls === polls }));
            })().catch(e => { console.log(JSON.stringify({ error: e.stack })); });
        """.replace("MARKUP", json.dumps(_tab_markup("rizin"))).replace("SETUP", setup).replace("SCRIPT", script),
                    SORT_DOM + _rizin_prelude(poll_ms=5) + FAKE_SERVER)

    both = run("FUNCS.push({ name: 'main', offset: 0x140003000, size: 16, nbbs: 1 }); OPS.main = [op(0x140003000, 1, 'ret', 'ret')];", "")
    assert "error" not in both, both.get("error")
    assert both["seeks"] == ["0x140003000"] and both["toolbar"] == "main", "main goes before sym.main"
    entry = run("FUNCS.splice(2, 1);", "")
    assert entry["seeks"] == ["0x140001000"] and entry["toolbar"] == "entry0", "no main: the entry point"
    own = run("", r"""
        await until(() => rizinState.retry.size, 'busy list');
        $('rizin-seek').value = '0x140001490';
        click($('rizin-go'));
        await until(() => rizinState.seek === '0x140001490', 'own jump');
    """)
    assert own["seeks"] == ["0x140001490"] and own["history"] == ["0x140001490"], "the first jump moved the user away"
    busy = run("server.busySeek = 1;", "")
    assert busy["seeks"] == ["0x1400014b7", "0x1400014b7"] and busy["seek"] == "0x1400014b7"
    assert busy["functions"] == 2, "the list was loaded again for a jump that found rizin busy"
    for r in (both, entry, own, busy):
        assert r["opened"] is True and r["pollsStop"] is True


@needs_node
def test_rizin_tab_id_and_session_states():
    r = _run(r"""
        (async () => {
            document.body.innerHTML = MARKUP;
            const r = {};
            // The tab ID: random, kept in sessionStorage, the same for the life of the browser tab
            const stored = new Map();
            globalThis.sessionStorage = { getItem: k => (stored.has(k) ? stored.get(k) : null),
                                          setItem: (k, v) => stored.set(k, String(v)) };
            const first = rizinTabId();
            r.id = [first, rizinTabId() === first, stored.get(RIZIN_TAB_KEY) === first, rizinState.tab === first];
            rizinState.tab = '';                                    // the page loaded again in the same tab
            r.again = rizinTabId() === first;
            rizinState.tab = '';
            stored.set(RIZIN_TAB_KEY, 'bad id with spaces');
            r.replaced = rizinTabId();
            rizinState.tab = '';
            stored.clear();
            const other = rizinTabId();
            r.differs = other !== first;
            rizinState.tab = '';
            globalThis.sessionStorage = { getItem() { throw new Error('SecurityError'); }, setItem() { throw new Error('x'); } };
            const blocked = rizinTabId();
            r.blocked = [blocked, rizinTabId() === blocked];

            // The states of a session, from the answers of any route
            const answers = [];
            globalThis.fetch = async url => { const [status, data] = answers.shift(); return { ok: status < 400, status, json: async () => data }; };
            const call = async (path, status, data, opts) => {
                answers.push([status, data]);
                const res = await rizinApi(path, opts);
                return [res.ok, res.state, res.error, { ...rizinState.ui }, $('rizin-state').hidden, $('rizin-state').textContent];
            };
            const $ = id => document.getElementById(id);
            rizinState.session = 'S1';
            r.busy = await call('/api/rizin/S1/functions', 409, { busy: true, step: 'aaa' });
            r.statusKeepsBusy = await call('/api/rizin/S1/status', 200, { analysis: { state: 'running' } });
            r.answered = await call('/api/rizin/S1/disasm?addr=0x1', 200, { function: null, ops: [], more: false });
            r.refused = await call('/api/rizin/S1/seek', 400, { refused: 'unknown address or name: \'x\'' }, { method: 'POST', body: { addr: 'x' } });
            r.otherSession = await call('/api/rizin/S0/functions', 404, { error: 'session ended' });
            r.moved = await call('/api/rizin/S1/functions', 409, { moved: true });
            r.ended = await call('/api/rizin/S1/graph', 404, { error: 'session ended', reason: 'rizin did not answer in time' });
            r.notInstalled = await call('/api/rizin/open', 503, { error: 'rizin not installed', path: 'C:\\tools\\cutter\\rizin.exe' }, { method: 'POST', body: { path: 'x', tab: 't' } });
            r.broken = await call('/api/rizin/S1/functions', 500, { error: 'rizin answered something unexpected: x' });
            globalThis.fetch = async () => { throw new TypeError('Failed to fetch'); };
            const offline = await rizinApi('/api/rizin/S1/functions');
            r.offline = [offline.ok, offline.state, offline.status];
            r.pipe = ['/api/rizin/status', '/api/rizin/files', '/api/rizin/upload', '/api/rizin/open', '/api/rizin/S1/status',
                      '/api/rizin/S1/close', '/api/rizin/S1/functions', '/api/rizin/S1/disasm?addr=0x1', '/api/rizin/S1/seek',
                      '/api/rizin/S1/console'].map(rizinUsesPipe);
            // A moved or ended session is not polled any more
            rizinState.ui = { state: 'moved', step: null, reason: null, path: null };
            r.pollMoved = rizinNeedsPoll();
            r.text = [rizinAnalysisText({ state: 'running', step: 'aac', level: 'aaa', elapsed: 12.34 }),
                      rizinAnalysisText({ state: 'running', step: null, level: 'aa', elapsed: 0 }),
                      rizinAnalysisText({ state: 'done', step: null, level: 'aaa', elapsed: 1.3 }),
                      rizinAnalysisText({ state: 'stopped', step: null, level: 'aa', elapsed: 600.04 }),
                      rizinAnalysisText({ state: 'failed', step: null, level: 'aaa', elapsed: 3 }),
                      rizinAnalysisText(null),
                      rizinAnalysisText({ state: 'running', step: null, done_steps: ['aa', 'aac'], level: 'aaa', elapsed: 3 })];
            r.hex = [0, 255, 0x1400014b7, '0x00FF', ' 0x1400014B7 ', '4096', '0x', 'sym.main', '-1', -1, 1.5, null,
                     '0x' + 'f'.repeat(16), '0x1' + '0'.repeat(16), '18446744073709551615', '18446744073709551616'].map(rizinHex);
            console.log(JSON.stringify(r));
        })().catch(e => { console.log(JSON.stringify({ error: e.stack })); });
    """.replace("MARKUP", json.dumps(_tab_markup("rizin"))), SORT_DOM + _rizin_prelude())
    assert "error" not in r, r.get("error")
    first = r["id"][0]
    assert re.fullmatch(r"[A-Za-z0-9_-]{16,64}", first) and r["id"][1:] == [True, True, True]
    assert r["again"] is True and r["differs"] is True
    assert re.fullmatch(r"[A-Za-z0-9_-]{16,64}", r["replaced"]) and r["replaced"] != "bad id with spaces"
    assert re.fullmatch(r"[A-Za-z0-9_-]{16,64}", r["blocked"][0]) and r["blocked"][1] is True
    ui = lambda state, **k: {"state": state, "step": None, "reason": None, "path": None, **k}
    assert r["busy"] == [False, "busy", "HTTP 409", ui("busy", step="aaa"), False, "busy (aaa)"]
    assert r["statusKeepsBusy"][3] == ui("busy", step="aaa"), "the status route does not use rizin: busy stays"
    assert r["answered"][:2] == [True, ""] and r["answered"][3] == ui("") and r["answered"][4] is True
    assert r["refused"][:3] == [False, "refused", "unknown address or name: 'x'"] and r["refused"][3] == ui("")
    assert r["otherSession"][1] == "ended" and r["otherSession"][3] == ui(""), "a session that is gone set the state"
    assert r["moved"][1] == "moved" and r["moved"][3] == ui("moved") and r["moved"][5] == "Open in another tab"
    assert r["ended"][3] == ui("ended", reason="rizin did not answer in time") and r["ended"][5] == "Session ended"
    assert r["notInstalled"][3] == ui("not-installed", path="C:\\tools\\cutter\\rizin.exe")
    assert r["notInstalled"][5] == "rizin not installed: C:\\tools\\cutter\\rizin.exe"
    assert r["broken"][:3] == [False, "error", "rizin answered something unexpected: x"]
    assert r["broken"][3] == ui("not-installed", path="C:\\tools\\cutter\\rizin.exe")
    assert r["offline"] == [False, "error", 0]
    assert r["pipe"] == [False, False, False, False, False, False, True, True, True, True]
    assert r["pollMoved"] is False
    assert r["text"] == ["analysing (aac) 12.3 s", "analysing (aa)", "analysed (aaa) 1.3 s",
                         "analysis stopped (aa) 600.0 s", "analysis failed", "",
                         "analysing (aac done) 3.0 s"], "between two steps of Full analysis the last one finished"
    assert r["hex"] == ["0x0", "0xff", "0x1400014b7", "0xff", "0x1400014b7", "0x1000", None, None, None, None, None, None,
                        "0x" + "f" * 16, None, "0x" + "f" * 16, None]


# --- Layout and themes -----------------------------------------------------------

# The parts of the tab whose look each theme sets: Classic in style.css,
# Cyberpunk in theme-cyberpunk.css under [data-theme="cyberpunk"].
THEMED = [".rizin-toolbar", ".rizin-panel", ".rizin-panel-title", ".rizin-tab", '.rizin-tab[aria-selected="true"]',
          ".rizin-fn", ".rizin-fn.current", ".rizin-fn-name", ".rizin-op", ".rizin-op.current", ".rizin-open-menu",
          ".rizin-open-item", ".rizin-split", ".rizin-file-tag", ".rizin-console", ".rizin-fn-head", ".rizin-state",
          # The run strip and the PC's marks
          ".rizin-run", ".rizin-run-pc", ".rizin-run-reg", ".rizin-run-delta", ".rizin-run-why", ".rizin-run-assist",
          ".rizin-run-value", ".rizin-op.pc", ".rizin-block.pc .rizin-block-box"]
# The colours of the instructions as in the mockup (rizin-ui-v2.html): classes with theme variables, which
# Cyberpunk sets to the mockup's colours
TOKEN_COLOURS = {".rz-addr": ("--accent-cyan", "#37e0ff"), ".rz-call": ("--accent-pink", "#ff4fd8"),
                 ".rz-jump": ("--accent-green", "#39d98a"), ".rz-sym": ("--accent-yellow", "#ffb000"),
                 ".rz-str": ("--c-amber-300", "#ffd060"), ".rz-comment": ("--text-muted", "#8a7fb0")}


def _declared(body, prop):
    found = re.findall(r"(?:^|;)\s*%s\s*:\s*([^;]+)" % re.escape(prop), body or "")
    return found[-1].strip() if found else None


def _rizin_rules(path):
    return {s: b for s, b in _rules(path).items() if re.search(r"rizin|\.rz-", s)}


def _gutter_glyphs():
    """Every `content` declared on a pseudo-element of a gutter, in each sheet, as (sheet, selector, content).

    The boot script of index.html always sets data-theme on <html>, so the [data-theme] rules of theme-layout.css
    apply in BOTH themes and win over style.css (same properties, higher specificity): the glyph and the colours that
    reach the screen are the layout sheet's, in Classic as well. style.css is the fallback for a page without the
    attribute. A test of the glyph has to look at the sheet that draws it, hence the three sheets, and every rule of
    them, not only the one rule the test happens to name."""
    found = []
    for sheet, path in (("style.css", STYLE_CSS), ("theme-cyberpunk.css + theme-layout.css", THEME_CSS)):
        for selector, body in _rules(path).items():
            if "gutter" in selector and re.search(r"::?(?:before|after)\b", selector):
                found.append((sheet, selector, _declared(body, "content")))
    for selector, body in _rules(LAYOUT_CSS).items():
        if "gutter" in selector and re.search(r"::?(?:before|after)\b", selector):
            found.append(("theme-layout.css", selector, _declared(body, "content")))
    return found


def test_rizin_tab_layout_and_themes():
    html = _read(INDEX_HTML)
    assert re.search(r'data-tab="filemap">FileMap</button>\s*<button class="tab" data-tab="rizin">Rizin</button>', html)
    tab = _tab_markup("rizin")
    ids = ["rizin-toolbar", "rizin-open-toggle", "rizin-open-menu", "rizin-path", "rizin-file-input",
           "rizin-open-sources", "rizin-file-path", "rizin-file-tag", "rizin-file-sha", "rizin-analysis", "rizin-state",
           "rizin-seek", "rizin-go", "rizin-back", "rizin-forward", "rizin-work", "rizin-functions", "rizin-fn-fold",
           "rizin-fn-filter", "rizin-fn-list", "rizin-fn-count", "rizin-center", "rizin-code", "rizin-code-title",
           "rizin-disasm", "rizin-decompiler", "rizin-hex", "rizin-split", "rizin-graph-half", "rizin-graph",
           "rizin-dock", "rizin-console", "rizin-xrefs", "rizin-strings", "rizin-imports", "rizin-emulation",
           "rizin-emu-start", "rizin-run", "rizin-run-pc", "rizin-run-regs", "rizin-run-why", "rizin-run-assist",
           "rizin-run-stop", "rizin-run-gotopc"]
    at = [tab.find(f'id="{i}"') for i in ids]
    assert all(a > 0 for a in at), [i for i, a in zip(ids, at) if a < 0]
    # Top to bottom: toolbar, then FUNCTIONS, the code views, the line, the graph, then the dock
    order = ["rizin-toolbar", "rizin-run", "rizin-work", "rizin-functions", "rizin-code", "rizin-split",
             "rizin-graph-half", "rizin-dock"]
    assert [tab.find(f'id="{i}"') for i in order] == sorted(tab.find(f'id="{i}"') for i in order)
    # The run strip sits between the toolbar and the work area, hidden until the emulation starts; the button
    # that starts it is in the toolbar; one delegated click handler; the kinds of run it offers (no BACK: rizin's
    # aesb restores no memory; no UNTIL: it needs an address, which the right-click menu gives)
    strip = re.search(r'<div[^>]*id="rizin-run"[^>]*>', tab).group(0)
    assert re.search(r"\shidden[\s>]", strip) and 'role="toolbar"' in strip and 'onclick="rizinOnRunClick(event)"' in strip, strip
    assert tab.index('id="rizin-emu-start"') < tab.index('id="rizin-run"'), "START is in the toolbar, above the strip"
    assert re.search(r'<button[^>]*id="rizin-emu-start"[^>]*onclick="rizinEmuStart\(\)"', tab)
    assert re.findall(r'data-rizin-run="(\w+)"', tab) == ["cont", "step", "over", "skip", "to_call"]
    assert re.findall(r'data-rizin-act="(\w+)"', tab) == ["gotopc", "stop"]
    assert not re.search(r'>\s*(BACK|UNTIL)\s*<', tab, re.I)
    assert re.findall(r'data-rizin-tab="(\w+)"', tab) == ["disasm", "decompiler", "hex", "graph", "console", "xrefs",
                                                          "strings", "imports", "emulation"]
    assert re.findall(r'data-rizin-tab="\w+"[^>]*>([^<]+)<', tab) == ["DISASSEMBLY", "DECOMPILER", "HEX", "GRAPH",
                                                                     "CONSOLE", "XREFS", "STRINGS", "IMPORTS", "EMULATION"]
    assert re.search(r'<h2 data-info="[^"]+">Rizin</h2>', tab)
    for handler in ('onclick="rizinOnFunctionClick(event)"', 'onclick="rizinOnDisasmClick(event)"'):
        assert handler in tab, "clicks in the lists go to one delegated handler"

    classic, cyberpunk = _rules(STYLE_CSS), _rules(THEME_CSS)
    prefix = '[data-theme="cyberpunk"] '
    missing = [s for s in THEMED if s not in classic] + [prefix + s for s in THEMED if prefix + s not in cyberpunk]
    assert not missing, "parts of the tab without a rule in one theme:\n" + "\n".join(missing)
    for selector, (variable, colour) in TOKEN_COLOURS.items():
        assert _declared(classic.get(selector), "color") == f"var({variable})", selector
        assert _cyberpunk_palette()[variable].lower() == colour, f"{selector}: {variable} is not the mockup's {colour}"
        assert variable in _root_values()
    for path, rules in ((STYLE_CSS, _rizin_rules(STYLE_CSS)), (THEME_CSS, _rizin_rules(THEME_CSS))):
        assert len(rules) >= 15, path
        written = [f"{s}: {m.group(0)}" for s, b in rules.items() for m in LITERAL_COLOR.finditer(b)]
        assert not written, f"colours written out in {path}:\n" + "\n".join(written)
    assert not [s for s in _unscoped_rules(_read(THEME_CSS)) if "rizin" in s or ".rz-" in s]
    assert all(s.startswith(prefix) for s in _rizin_rules(THEME_CSS)), "a Cyberpunk rule of the tab without the prefix"

    # The work area fills the tab below the toolbar, and every list scrolls in itself
    work = classic.get(".rizin-work", "")
    assert _declared(work, "flex") in ("1", "1 1 0", "1 1 auto") and _declared(work, "min-height") == "0"
    main = classic.get(".rizin-main", "")
    assert _declared(main, "display") == "grid" and _declared(main, "min-height") == "0"
    assert "minmax(0, 1fr)" in (_declared(main, "grid-template-columns") or "")
    assert _declared(main, "grid-template-rows") == "minmax(0, 1fr)"
    assert _declared(main, "flex") in ("1", "1 1 0", "1 1 auto")
    for selector in (".rizin-panel", ".rizin-half"):
        body = classic.get(selector, "")
        assert _declared(body, "display") == "flex" and _declared(body, "flex-direction") == "column", selector
        assert _declared(body, "min-height") == "0" and _declared(body, "min-width") == "0", selector
    for selector in (".rizin-fn-list", ".rizin-view"):
        body = classic.get(selector, "")
        assert _declared(body, "overflow") == "auto" and _declared(body, "min-height") == "0", selector
        assert _declared(body, "flex") in ("1", "1 1 0", "1 1 auto"), selector
    assert _declared(classic.get(".rizin-center", ""), "display") == "grid"
    assert re.fullmatch(r"minmax\(0, [\d.]+fr\) \d+px minmax\(0, [\d.]+fr\)",
                        _declared(classic.get(".rizin-center", ""), "grid-template-columns") or "")
    dock = classic.get(".rizin-dock", "")
    assert _declared(dock, "flex") == "0 0 auto" and _declared(dock, "height")
    assert _declared(classic.get(".rizin-op", ""), "white-space") == "pre", "a long line wraps instead of scrolling"
    name = classic.get(".rizin-fn-name", "")
    assert all(_declared(name, p) == v for p, v in (("overflow", "hidden"), ("text-overflow", "ellipsis"),
                                                     ("white-space", "nowrap"))), "a long name widens the list"
    # The tab itself never scrolls (it is a column of the window's height, .tab-content)
    for rules in (classic, cyberpunk):
        for selector, body in rules.items():
            if selector.endswith("#tab-rizin"):
                assert not re.search(r"(?:^|;)\s*overflow(?:-[xy])?\s*:", body), selector
    assert re.search(r"[?&]v=\d+", html) and "style.css?v=60" not in html and "theme-cyberpunk.css?v=20" not in html \
        and "app.js?v=86" not in html, "asset versions not raised"
    # The run strip changed all three sheets
    assert "style.css?v=81" not in html and 'theme-layout.css?v=5"' not in html and "app.js?v=119" not in html, \
        "asset versions not raised for the run strip"
    assert "app.js?v=120" not in html, "app.js changed after the run strip's review (R52, R53), its version did not"


# --- Fix round: polling, step boundaries, errors, quick clicks ----------------------

# A server scripted by each test: routes by method and path, each answer with
# a delay, every request recorded. serve(sid, s) adds the routes of one
# session, driven by its state object s (analysis, step, done, seek, ended;
# hooks onStatus, functions, disasm, graph, seekAnswer; delays statusDelay,
# seekDelay, disasmDelay, graphDelay); opens[path] is the session a path
# opens, or a function that answers the OPEN.
SCRIPTED = FAKE_DATA + r"""
const calls = [];
const inFlight = new Map();
let inflight = 0;
const handlers = [];
const on = (method, path, fn) => handlers.unshift({ method, path, fn });
// A session gone on the server, for every route of it but close: gone.set(sid, [409, { moved: true }])
const gone = new Map();
globalThis.fetch = (url, init = {}) => {
    const method = init.method || 'GET';
    const body = typeof init.body === 'string' ? JSON.parse(init.body) : undefined;
    calls.push([method, url, body]);
    const handler = handlers.find(h => h.method === method && h.path === url.split('?')[0]);
    const sid = /^\/api\/rizin\/([^/?]+)\/([a-z]+)/.exec(url);
    const [status, data, delay = 1] = sid && gone.has(sid[1]) && sid[2] !== 'close' ? gone.get(sid[1])
        : handler ? handler.fn(url, body) : [404, { error: 'no route: ' + url }];
    inflight++;
    inFlight.set(url, (inFlight.get(url) || 0) + 1);
    return new Promise(resolve => setTimeout(() => {
        inflight--;
        inFlight.set(url, inFlight.get(url) - 1);
        resolve({ ok: status < 400, status, json: async () => data,
                  blob: async () => new Blob([data instanceof Uint8Array ? data : JSON.stringify(data)]) });
    }, delay));
};
const flying = prefix => [...inFlight].some(([url, n]) => n > 0 && url.startsWith(prefix));
const count = (method, prefix) => calls.filter(c => c[0] === method && c[1].startsWith(prefix)).length;
const seeksOf = sid => calls.filter(c => c[0] === 'POST' && c[1] === `/api/rizin/${sid}/seek`).map(c => c[2].addr);
const ENDED = [404, { error: 'session ended' }];
// The start that all the names share, as /flags sends it (common)
const sharedStart = names => names.reduce((p, n) => { let i = 0; while (i < p.length && p[i] === n[i]) i++; return p.slice(0, i); },
                                          names[0] ?? '');
function serve(sid, s) {
    s.statusCalls = 0;
    const analysis = () => ({ state: s.analysis, step: s.step ?? null, done_steps: [...(s.done || [])], level: s.level || 'aaa',
                              elapsed: 0.5, note: s.note ?? null });
    s.opened = path => ({ session: sid, analysis: analysis(),
                          file: { path, sha256: sid.padEnd(64, '0'), size: 1000, format: 'pe64', arch: s.arch ?? 'x86', bits: 64 } });
    on('GET', `/api/rizin/${sid}/status`, () => {
        s.statusCalls++;
        if (s.onStatus) s.onStatus(s);
        if (s.ended) return [...ENDED, s.statusDelay ?? 1];
        const at = s.seek ?? 0x140001000;
        return [200, { analysis: analysis(), seek: at, function: fnAt(at)?.name ?? null }, s.statusDelay ?? 1];
    });
    on('GET', `/api/rizin/${sid}/functions`, () => (s.ended ? ENDED : s.functions ? s.functions(s) : [200, FUNCS.map(f => ({ ...f }))]));
    on('POST', `/api/rizin/${sid}/seek`, (url, body) => {
        if (s.ended) return ENDED;
        const scripted = s.seekAnswer && s.seekAnswer(body, s);
        if (scripted) return scripted;
        const a = /^0x[0-9a-f]+$/.test(body.addr) ? parseInt(body.addr, 16) : FUNCS.find(f => f.name === body.addr)?.offset;
        if (a === undefined) return [400, { refused: `unknown address or name: '${body.addr}'` }];
        s.seek = a;
        return [200, { seek: a, function: fnAt(a)?.name ?? null }, s.seekDelay ?? 1];
    });
    on('GET', `/api/rizin/${sid}/disasm`, url => {
        if (s.ended) return ENDED;
        const hex = new URLSearchParams(url.split('?')[1]).get('addr');
        const scripted = s.disasm && s.disasm(hex, s, url);
        if (scripted) return scripted;
        const f = fnAt(parseInt(hex, 16));
        return [200, f ? { function: f.name, more: false,
                           ops: OPS[f.name].map(o => (COMMENTS.has(o.offset) ? { ...o, comment: COMMENTS.get(o.offset) } : o)) }
                       : { function: null, ops: [op(parseInt(hex, 16), 1, 'nop', 'nop')], more: true },
                s.disasmDelay ? s.disasmDelay(hex) : 1];
    });
    on('GET', `/api/rizin/${sid}/graph`, url => {
        if (s.ended) return ENDED;
        const hex = new URLSearchParams(url.split('?')[1]).get('addr');
        const scripted = s.graph && s.graph(hex, s);
        if (scripted) return scripted;
        return [200, graphAt(parseInt(hex, 16)), s.graphDelay ? s.graphDelay(hex) : 1];
    });
    // Task 6: the console (s, @ and afn move or rename as rizin does; '!' is refused), the flags for Tab,
    // the references, the strings and imports (filtered and paged), rename and comment, the comment at an
    // address; hooks console, flags, xrefs, strings, imports, rename, comment, commentAt and the delays
    // consoleDelay, flagsDelay, commentAtDelay
    on('POST', `/api/rizin/${sid}/console`, (url, body) => {
        if (s.ended) return ENDED;
        const scripted = s.console && s.console(body.cmd, s);
        if (scripted) return scripted;
        const cmd = String(body.cmd), at = s.seek ?? 0x140001000;
        if (cmd.startsWith('!')) return [400, { refused: "'!' is not allowed: no shell commands" }];
        const where = t => (/^0x[0-9a-f]+$/i.test(t) ? parseInt(t, 16) : FUNCS.find(f => f.name === t)?.offset);
        let m, output = `fake output for: ${cmd}\n`, changed = false;
        if ((m = /^s (\S+)$/.exec(cmd))) {
            if (where(m[1]) === undefined) output = `ERROR: Cannot seek to unknown address '${m[1]}'\n`;
            else [s.seek, output] = [where(m[1]), ''];
        } else if ((m = /@ (\S+)$/.exec(cmd)) && where(m[1]) !== undefined) {
            s.seek = where(m[1]);
        } else if ((m = /^afn (\S+)$/.exec(cmd)) && fnAt(at)) {
            renameFn(fnAt(at), m[1]);
            [output, changed] = ['', true];
        }
        const here = s.seek ?? 0x140001000;
        return [200, { output, seek: here, function: fnAt(here)?.name ?? null, truncated: false, changed }, s.consoleDelay ?? 1];
    });
    on('GET', `/api/rizin/${sid}/flags`, url => {
        if (s.ended) return ENDED;
        const scripted = s.flags && s.flags(url, s);
        if (scripted) return scripted;
        const p = new URLSearchParams(url.split('?')[1] || ''), q = (p.get('q') || '').toLowerCase();
        const names = [...new Set([...FUNCS.map(f => f.name), ...FLAG_NAMES])].filter(n => n.toLowerCase().startsWith(q)).sort();
        return [200, { total: names.length, names: names.slice(0, Number(p.get('limit') || 200)), common: sharedStart(names) },
                s.flagsDelay ?? 1];
    });
    on('GET', `/api/rizin/${sid}/comment`, url => {
        if (s.ended) return ENDED;
        const hex = new URLSearchParams(url.split('?')[1]).get('addr');
        const scripted = s.commentAt && s.commentAt(hex, s);
        if (scripted) return scripted;
        return [200, { offset: parseInt(hex, 16), comment: COMMENTS.get(parseInt(hex, 16)) ?? '' }, s.commentAtDelay ?? 1];
    });
    on('GET', `/api/rizin/${sid}/xrefs`, url => {
        if (s.ended) return ENDED;
        const hex = new URLSearchParams(url.split('?')[1]).get('addr');
        return (s.xrefs && s.xrefs(hex, s)) || [200, xrefsAt(parseInt(hex, 16))];
    });
    const listed = (rows, text) => url => {
        const p = new URLSearchParams(url.split('?')[1] || '');
        const q = (p.get('q') || '').toLowerCase(), offset = Number(p.get('offset') || 0), limit = Number(p.get('limit') || 200);
        const found = rows.filter(row => text(row).toLowerCase().includes(q));
        return [200, { total: found.length, items: found.slice(offset, offset + limit) }];
    };
    on('GET', `/api/rizin/${sid}/strings`, url => (s.ended ? ENDED : (s.strings && s.strings(url, s)) || listed(STRINGS, row => row.string)(url)));
    on('GET', `/api/rizin/${sid}/imports`, url => (s.ended ? ENDED
        : (s.imports && s.imports(url, s)) || listed(IMPORTS, row => `${row.name}\0${row.library}`)(url)));
    on('POST', `/api/rizin/${sid}/rename`, (url, body) => {
        if (s.ended) return ENDED;
        const scripted = s.rename && s.rename(body, s);
        if (scripted) return scripted;
        if (!/^[A-Za-z_][A-Za-z0-9_.@$:-]{0,127}$/.test(body.name)) {
            return [400, { refused: "a name starts with a letter or '_' and has up to 128 of A-Z a-z 0-9 _ . @ $ : -" }];
        }
        const f = fnAt(parseInt(body.addr, 16));
        if (!f) return [400, { refused: `there is no function at ${body.addr}` }];
        renameFn(f, body.name);
        return [200, { offset: f.offset, name: f.name }];
    });
    on('POST', `/api/rizin/${sid}/comment`, (url, body) => {
        if (s.ended) return ENDED;
        const scripted = s.comment && s.comment(body, s);
        if (scripted) return scripted;
        const a = parseInt(body.addr, 16);
        if (body.text) COMMENTS.set(a, body.text);
        else COMMENTS.delete(a);
        return [200, { offset: a, comment: body.text }];
    });
    // Task 7: the C of a function, the bytes at an address, Full analysis (aa becomes aaa's steps) and close;
    // hooks decompile, hex, analyze and the delays decompileDelay, hexDelay, analyzeDelay
    on('GET', `/api/rizin/${sid}/decompile`, url => {
        if (s.ended) return ENDED;
        const hex = new URLSearchParams(url.split('?')[1]).get('addr');
        const scripted = s.decompile && s.decompile(hex, s);
        if (scripted) return scripted;
        return [200, decompileAt(parseInt(hex, 16)), s.decompileDelay ?? 1];
    });
    on('GET', `/api/rizin/${sid}/hex`, url => {
        if (s.ended) return ENDED;
        const p = new URLSearchParams(url.split('?')[1]);
        const scripted = s.hex && s.hex(p.get('addr'), s);
        if (scripted) return scripted;
        return [200, hexAt(parseInt(p.get('addr'), 16), Number(p.get('len') || 512)), s.hexDelay ?? 1];
    });
    on('POST', `/api/rizin/${sid}/analyze`, () => {
        if (s.ended) return ENDED;
        const scripted = s.analyze && s.analyze(s);
        if (scripted) return scripted;
        if (s.level === 'aa' && s.analysis !== 'running') Object.assign(s, { analysis: 'running', step: null, level: 'aaa' });
        return [200, { analysis: analysis() }, s.analyzeDelay ?? 1];
    });
    on('POST', `/api/rizin/${sid}/close`, () => {
        s.closed = true;
        return [200, { closed: true }];
    });
    // Task 10: the emulation. s.emu is its VM (pc, three registers, the names the last change changed); the
    // answers are the server's, so GET says stopped: null where a run says why it stopped. Hooks emuStart,
    // emuState, emuRun, emuStop, callAssist and callSkip answer instead; stopWith is the reason the next run
    // gives; the delays emuDelay, runDelay and callDelay.
    const notStarted = [400, { refused: 'the emulation is not started' }];
    on('POST', `/api/rizin/${sid}/emulation/start`, (url, body) => {
        if (s.ended) return ENDED;
        const scripted = s.emuStart && s.emuStart(body, s);
        if (scripted) return scripted;
        s.emu = { pc: body.addr === undefined ? s.seek ?? 0x140001000 : parseInt(body.addr, 16), rax: 0, rbx: 0, rcx: 0, changed: [] };
        return [200, emuRead(s.emu), s.emuDelay ?? 1];
    });
    on('GET', `/api/rizin/${sid}/emulation`, () => {
        if (s.ended) return ENDED;
        const scripted = s.emuState && s.emuState(s);
        if (scripted) return scripted;
        return s.emu ? [200, emuRead(s.emu), s.emuDelay ?? 1] : notStarted;
    });
    on('POST', `/api/rizin/${sid}/emulation/stop`, () => {
        if (s.ended) return ENDED;
        const scripted = s.emuStop && s.emuStop(s);
        if (scripted) return scripted;
        s.emu = null;
        return [200, { running: false }, s.emuDelay ?? 1];
    });
    on('POST', `/api/rizin/${sid}/emulation/run`, (url, body) => {
        if (s.ended) return ENDED;
        if (!s.emu) return notStarted;
        const scripted = s.emuRun && s.emuRun(body, s);
        if (scripted) return scripted;
        emuMove(s.emu, body.kind, body.addr);
        const stopped = s.stopWith ?? 'step';
        s.stopWith = undefined;
        return [200, emuRead(s.emu, stopped), s.runDelay ?? 1];
    });
    on('GET', `/api/rizin/${sid}/call`, url => {
        if (s.ended) return ENDED;
        const hex = new URLSearchParams(url.split('?')[1]).get('addr');
        const scripted = s.callAssist && s.callAssist(hex, s);
        if (scripted) return scripted;
        const op = Object.values(OPS).flat().find(o => o.offset === parseInt(hex, 16));
        if (!op || !op.type.includes('call')) return [400, { refused: `rizin decoded no call at ${hex}` }];
        return [200, { supported: true, reason: null, api: 'Sleep', ret_reg: 'rax', value: '0x0', stack_fix: 0,
                       summary: 'skip Sleep: rax = 0x0. The caller cleans the stack.' }, s.callDelay ?? 1];
    });
    on('POST', `/api/rizin/${sid}/call`, (url, body) => {
        if (s.ended) return ENDED;
        if (!s.emu) return notStarted;
        const scripted = s.callSkip && s.callSkip(body, s);
        if (scripted) return scripted;
        emuMove(s.emu, 'skip');
        if (body.value !== null) s.emu.rax = body.value;
        return [200, { ...emuRead(s.emu, 'step'), summary: `skipped the call at ${body.addr}` }, s.callDelay ?? 1];
    });
    // Task 11: the EMULATION pane. s.patches [{addr, size, before, after, mine}] and s.breakpoints [{addr, enabled}] are
    // rizin's (integers, as the routes answer them); s.emu.more are registers beyond the four, s.emu.stack the stack
    // rows. Hooks patchesAnswer, breakpointsAnswer, unpatch, unbreak, setRegister, exportCopy and reanalyze answer instead; the
    // delays listDelay and actDelay.
    const rows = list => (list || []).map(row => ({ ...row }));
    on('GET', `/api/rizin/${sid}/patches`, url => {
        if (s.ended) return ENDED;
        return (s.patchesAnswer && s.patchesAnswer(s)) || [200, { patches: rows(s.patches), waiting: s.waiting || [] }, s.listDelay ?? 1];
    });
    on('GET', `/api/rizin/${sid}/breakpoints`, url => {
        if (s.ended) return ENDED;
        return (s.breakpointsAnswer && s.breakpointsAnswer(s)) || [200, rows(s.breakpoints), s.listDelay ?? 1];
    });
    on('DELETE', `/api/rizin/${sid}/patch`, (url, body) => {
        if (s.ended) return ENDED;
        const scripted = s.unpatch && s.unpatch(body, s);
        if (scripted) return scripted;
        const at = body && body.addr !== undefined ? parseInt(body.addr, 16) : null;
        // like the server: rizin removes every write that overlaps the address, whole, so the answer names the
        // rows that were not patches set by hand and went with it (run_removed)
        const held = s.patches || [];
        const left = at === null ? [] : held.filter(p => !(p.addr <= at && at < p.addr + p.size));
        const gone = held.filter(p => !left.includes(p) && p.mine !== true);
        s.patches = left;
        return [200, { patches: rows(s.patches), run_removed: gone.map(p => ({ addr: p.addr, size: p.size })) },
                s.actDelay ?? 1];
    });
    on('DELETE', `/api/rizin/${sid}/breakpoints`, (url, body) => {
        if (s.ended) return ENDED;
        const scripted = s.unbreak && s.unbreak(body, s);
        if (scripted) return scripted;
        const at = body && body.addr !== undefined ? parseInt(body.addr, 16) : null;
        s.breakpoints = at === null ? [] : (s.breakpoints || []).filter(b => b.addr !== at);
        return [200, { breakpoints: rows(s.breakpoints) }, s.actDelay ?? 1];
    });
    on('POST', `/api/rizin/${sid}/emulation/register`, (url, body) => {
        if (s.ended) return ENDED;
        const scripted = s.setRegister && s.setRegister(body, s);
        if (scripted) return scripted;
        if (!s.emu) return notStarted;
        const extra = (s.emu.more || []).find(m => m.name === body.name);
        if (!extra && !['rax', 'rbx', 'rcx', 'rip'].includes(body.name)) return [400, { refused: `no register named '${body.name}'` }];
        if (!/^0x[0-9a-f]{1,16}$/i.test(String(body.value))) return [400, { refused: `'${body.value}' is no number` }];
        if (extra) extra.value = body.value;
        else if (body.name === 'rip') s.emu.pc = body.value.length <= 14 ? parseInt(body.value, 16) : body.value;
        else s.emu[body.name] = body.value;
        s.emu.changed = [body.name];
        return [200, emuRead(s.emu), s.actDelay ?? 1];
    });
    // Task 12: the gutter sets a breakpoint, the menu patches. POST patch answers as the server does: nop and nocall fill the
    // instruction at the address with 0x90 (nocall only a call), flip and always need a cjmp, bytes are hex pairs, at
    // most 2000 of them, and the kinds are x86's (s.arch, 'x86' unless a test sets it); the row is mine. Hooks
    // setBreakpoint and patchAnswer answer instead.
    on('POST', `/api/rizin/${sid}/breakpoints`, (url, body) => {
        if (s.ended) return ENDED;
        const scripted = s.setBreakpoint && s.setBreakpoint(body, s);
        if (scripted) return scripted;
        const at = parseInt(body.addr, 16);
        if (!/^0x[0-9a-f]+$/.test(body.addr)) return [400, { refused: `'${body.addr}' is no address` }];
        if (!(s.breakpoints || []).some(b => b.addr === at)) {
            s.breakpoints = [...(s.breakpoints || []), { addr: at, enabled: true }].sort((a, b) => a.addr - b.addr);
        }
        return [200, { breakpoints: rows(s.breakpoints) }, s.actDelay ?? 1];
    });
    on('POST', `/api/rizin/${sid}/patch`, (url, body) => {
        if (s.ended) return ENDED;
        const scripted = s.patchAnswer && s.patchAnswer(body, s);
        if (scripted) return scripted;
        const at = parseInt(body.addr, 16);
        let size, after;
        if (body.kind !== undefined) {
            if ((s.arch ?? 'x86') !== 'x86') return [400, { refused: `the patch kinds write x86 bytes, and this file is ${s.arch}: write the bytes by hand` }];
            const o = Object.values(OPS).flat().find(x => x.offset === at);
            if (!o) return [400, { refused: `rizin decoded no instruction at ${body.addr}` }];
            if (['flip', 'always'].includes(body.kind) && o.type !== 'cjmp') return [400, { refused: `'${o.text.split(' ')[0]}' is no x86 conditional jump of the forms 7x rel8 or 0f 8x rel32` }];
            if (body.kind === 'nocall' && !o.type.endsWith('call')) return [400, { refused: `'${o.text.split(' ')[0]}' is no call` }];
            if (!['nop', 'flip', 'always', 'nocall'].includes(body.kind)) return [400, { refused: 'kind must be one of nop, flip, always, nocall' }];
            size = o.size;
            after = body.kind === 'flip' ? '75' + '00'.repeat(size - 1) : body.kind === 'always' ? 'eb' + '00'.repeat(size - 1) : '90'.repeat(size);
        } else {
            if (!/^([0-9a-fA-F]{2})+$/.test(body.bytes || '')) return [400, { refused: 'bytes must be an even number of hex digits, like 9090' }];
            if (body.bytes.length > 4000) return [400, { refused: 'bytes must be at most 2000 bytes' }];
            size = body.bytes.length / 2;
            after = body.bytes;
        }
        s.patches = [...(s.patches || []), { addr: at, size, before: '00'.repeat(size), after, mine: true }].sort((a, b) => a.addr - b.addr);
        return [200, { patches: rows(s.patches) }, s.actDelay ?? 1];
    });
    on('POST', `/api/rizin/${sid}/export`, () => {
        if (s.ended) return ENDED;
        const scripted = s.exportCopy && s.exportCopy(s);
        if (scripted) return scripted;
        const mine = (s.patches || []).filter(p => p.mine);
        if (!mine.length) return [400, { refused: 'no patches to export: only patches set by hand go into the copy' }];
        return [200, { path: 'C:\\Temp\\rizin_uploads\\0123456789abcdef_e.patched.exe', name: '0123456789abcdef_e.patched.exe',
                       sha256: 'ab'.repeat(32), patched: mine.reduce((n, p) => n + p.size, 0), skipped: s.skipped || [],
                       note: 'Patched copy made by TDC (RIZIN tab).\nOriginal: C:\\x\\e.exe\n' }, s.actDelay ?? 1];
    });
    // Task 13: the copy the export wrote is fetched back through /api/file/download?path=…. s.copies {path: Uint8Array} is
    // what the uploads folder holds; a path that is not in it is a 404, as on the server. Hook download answers instead.
    on('GET', '/api/file/download', url => {
        const path = new URLSearchParams(url.split('?')[1]).get('path');
        const scripted = s.download && s.download(path, s);
        if (scripted) return scripted;
        const copy = (s.copies || {})[path];
        return copy ? [200, copy, s.actDelay ?? 1] : [404, { error: 'File not found' }];
    });
    on('POST', `/api/rizin/${sid}/reanalyze`, (url, body) => {
        if (s.ended) return ENDED;
        const scripted = s.reanalyze && s.reanalyze(body, s);
        if (scripted) return scripted;
        if (!(s.patches || []).some(p => !p.mine)) return [400, { refused: 'the run wrote nothing to analyse' }];
        return [200, { start: 0x140001521, end: 0x140001522, functions: 1, strings: 2 }, s.actDelay ?? 1];
    });
}
// The emulation of serve(): the registers as the state lists them (rip is the PC), and a run's move over
// the instructions of the function the PC is in
// A machine word as the server sends it (R52): an exact "0x…" string, whatever the number of its digits; a
// value a test sets as a string (a 64-bit register) goes through as it is
const word = v => (typeof v === 'string' || v === null ? v : '0x' + v.toString(16));
const emuRead = (e, stopped = null) => ({
    running: true, pc: word(e.pc), registers: [{ name: 'rax', value: word(e.rax) }, { name: 'rbx', value: word(e.rbx) },
                                               { name: 'rcx', value: word(e.rcx) }, { name: 'rip', value: word(e.pc) },
                                               ...(e.more || [])],
    changed: [...e.changed], stack: e.stack ?? [], stopped, arch: 'x86', bits: 64 });
function emuMove(e, kind, addr) {
    const ops = OPS[fnAt(e.pc)?.name] || [], at = ops.findIndex(o => o.offset === e.pc);
    let to = ops[at + 1];
    if (kind === 'to_call') to = ops.slice(at + 1).find(o => o.type.includes('call')) || ops[ops.length - 1];
    if (kind === 'cont') to = ops[ops.length - 1];
    if (kind === 'until') to = { offset: parseInt(addr, 16) };
    if (!to) return;
    e.pc = to.offset;
    e.changed = kind === 'skip' ? ['rip'] : ['rax', 'rip'];
    if (kind !== 'skip') e.rax += 1;
}
const opens = {};
on('POST', '/api/rizin/open', (url, body) => {
    const target = opens[body.path];
    if (typeof target === 'function') return target(body);
    return target ? [200, target.opened(body.path)] : [400, { refused: 'the file does not exist' }];
});
globalThis.switchTab = () => {};
globalThis.showToast = () => {};
const stored = new Map();
globalThis.sessionStorage = { getItem: k => (stored.has(k) ? stored.get(k) : null), setItem: (k, v) => stored.set(k, String(v)) };
const tick = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(test, what) {
    for (let i = 0; i < 3000 && !test(); i++) await tick(1);
    if (!test()) throw new Error('timed out: ' + what);
}
// Every request answered and drawn, and none for 25 ms (a poll that never stops fails here)
async function quiet() {
    for (let calm = 0, i = 0; calm < 25; i++) {
        if (i > 3000) throw new Error('never quiet: the tab keeps asking');
        const before = calls.length;
        await tick(1);
        calm = calls.length === before && inflight === 0 ? calm + 1 : 0;
    }
}
const $ = id => document.getElementById(id);
const row = addr => $('rizin-fn-list').querySelector(`.rizin-fn[data-addr="${addr}"]`);
const marked = () => [$('rizin-fn-list').querySelector('.rizin-fn.current')?.getAttribute('data-addr') ?? null,
                      $('rizin-disasm').querySelector('.rizin-op.current')?.getAttribute('data-addr') ?? null];
"""


def _scripted(script):
    # Exits once the result is written: a poll that never stops would keep node running until the timeout.
    # A script that fails reports what it found up to there.
    return _run(r"""
        const done = r => process.stdout.write(JSON.stringify(r) + '\n', () => process.exit(0));
        const r = {};
        (async () => {
            document.body.innerHTML = MARKUP;
            initRizinTab();
            SCRIPT
            done(r);
        })().catch(e => done({ error: `${e.stack}\nfound up to there: ${JSON.stringify(r)}` }));
    """.replace("MARKUP", json.dumps(_tab_markup("rizin"))).replace("SCRIPT", script),
        SORT_DOM + _rizin_prelude(poll_ms=5, filter_ms=5) + SCRIPTED)


@needs_node
def test_rizin_poll_survives_opening_another_file():
    """Review, Important 1: a file opened while the poll of the file before
    still waits for its /status: the new session is polled all the same
    (it lands, its function list loads), and the old poll stops."""
    r = _scripted(r"""
        const A = { analysis: 'running', step: 'aaa', done: [], statusDelay: 60 };
        const B = { analysis: 'done', done: ['aaa'] };
        serve('SA', A); serve('SB', B);
        opens['C:\\x\\a.exe'] = A; opens['C:\\x\\b.exe'] = B;
        await openInRizin('C:\\x\\a.exe');
        await until(() => flying('/api/rizin/SA/status'), 'a status of SA in flight');
        await openInRizin('C:\\x\\b.exe');
        await tick(300);
        r.b = { session: rizinState.session, landed: rizinState.landed, seek: rizinState.seek,
                status: count('GET', '/api/rizin/SB/status'), functions: count('GET', '/api/rizin/SB/functions') };
        const before = count('GET', '/api/rizin/SA/status');
        await tick(100);
        r.aStopped = count('GET', '/api/rizin/SA/status') === before;
    """)
    assert "error" not in r, r.get("error")
    assert r["b"]["session"] == "SB" and r["b"]["landed"] is True and r["b"]["seek"] == "0x1400014b7", r["b"]
    assert r["b"]["status"] >= 1 and r["b"]["functions"] >= 1
    assert r["aStopped"] is True


@needs_node
def test_rizin_opening_another_file_starts_clean():
    """Review, Minors 3 and 4: after OPEN, SEEK no longer shows the place in
    the file before (GO would jump there and the tab would not land); while
    an OPEN waits, the session it replaces is not polled, and its end (404)
    does not show as "session ended"; a failed OPEN shows its reason, also
    when the old session's requests end afterwards."""
    r = _scripted(r"""
        const A = { analysis: 'done', done: ['aaa'] };
        let bStatus = 0;
        const B = { analysis: 'running', step: 'aaa', done: [],
                    onStatus: s => { if (++bStatus >= 8) Object.assign(s, { analysis: 'done', step: null, done: ['aaa'] }); } };
        serve('SA', A); serve('SB', B);
        opens['C:\\x\\a.exe'] = A; opens['C:\\x\\b.exe'] = B;
        await openInRizin('C:\\x\\a.exe');
        await until(() => rizinState.landed, 'A landed'); await quiet();
        r.before = [$('rizin-seek').value, $('rizin-seek').getAttribute('data-addr')];
        await openInRizin('C:\\x\\b.exe');
        r.after = [$('rizin-seek').value, $('rizin-seek').getAttribute('data-addr'), rizinState.seek];
        click($('rizin-go'));
        await tick(10);
        r.emptyGo = seeksOf('SB').length;
        await until(() => rizinState.landed, 'B landed'); await quiet();
        r.landed = [rizinState.seek, $('rizin-seek').value, seeksOf('SB')];

        // C runs and is polled. An OPEN that waits stops the poll; it fails, C is still there: the poll goes on
        const C = { analysis: 'running', step: 'aaa', done: [] };
        serve('SC', C);
        opens['C:\\x\\c.exe'] = C;
        opens['C:\\x\\missing.exe'] = () => [400, { refused: 'the file does not exist' }, 40];
        await openInRizin('C:\\x\\c.exe');
        await until(() => count('GET', '/api/rizin/SC/status') >= 2, 'C polled');
        let polls = count('GET', '/api/rizin/SC/status');
        let opening = openInRizin('C:\\x\\missing.exe');
        await tick(30);
        r.pollDuring = count('GET', '/api/rizin/SC/status') - polls;
        r.missing = [await opening, $('rizin-state').textContent];
        polls = count('GET', '/api/rizin/SC/status');
        await tick(30);
        r.pollAfter = count('GET', '/api/rizin/SC/status') - polls;

        // C ends on the server: its status in flight answers 404 while another OPEN waits, which then fails
        await until(() => !flying('/api/rizin/SC/'), 'no request of C in flight');
        Object.assign(C, { statusDelay: 30, ended: true });
        await until(() => flying('/api/rizin/SC/status'), 'a status of C in flight that answers 404');
        opens['C:\\x\\broken.exe'] = () => [500, { error: 'rizin could not open the file: broken' }, 40];
        opening = openInRizin('C:\\x\\broken.exe');
        await tick(35);
        r.during = [$('rizin-state').hidden, $('rizin-state').textContent];
        r.opened = await opening;
        r.failed = [$('rizin-state').hidden, $('rizin-state').textContent];
        await tick(60);
        r.later = [$('rizin-state').textContent, rizinState.ui.state];
    """)
    assert "error" not in r, r.get("error")
    assert r["before"] == ["sym.main", "0x1400014b7"]
    assert r["after"] == ["", None, None], "SEEK still shows the place in the file before"
    assert r["emptyGo"] == 0
    assert r["landed"] == ["0x1400014b7", "sym.main", ["0x1400014b7"]], "the new file did not land"
    assert r["pollDuring"] == 0, "the session being replaced was polled while the OPEN waited"
    assert r["missing"] == [False, "the file does not exist"] and r["pollAfter"] >= 1
    assert r["during"] == [True, ""], "the end of the session being replaced showed while the OPEN waited"
    assert r["opened"] is False
    assert r["failed"] == [False, "rizin could not open the file: broken"]
    assert r["later"] == ["rizin could not open the file: broken", "ended"], "the failed OPEN's reason went"


@needs_node
def test_rizin_step_boundary_refreshes_the_views():
    """The controller's ruling, UI side: between two steps of Full analysis
    the poll (at most a second apart) sees the finished step and asks for the
    views at once, while rizin serves requests: the function list, and the
    disassembly of the current place even when the page is already shown."""
    r = _scripted(r"""
        const runs = [[{ step: 'aac', done: ['aa'] }, { step: null, done: ['aa', 'aac'] }, { step: 'aar', done: ['aa', 'aac'] },
                       { step: null, done: ['aa', 'aac', 'aar'] }, { state: 'done', step: null, done: ['aa', 'aac', 'aar', 'aaft'] }]];
        let phase = 0;
        const S = { analysis: 'running', step: 'aac', done: ['aa'],
                    onStatus: s => { const p = runs[0][Math.min(phase++, runs[0].length - 1)];
                                     Object.assign(s, { analysis: p.state || 'running', step: p.step, done: p.done }); } };
        serve('S1', S);
        opens['C:\\x\\s.exe'] = S;
        const events = () => calls.filter(c => /\/(status|functions|disasm)/.test(c[1]))
            .map(c => c[1].includes('/status') ? 'S' : c[1].includes('/functions') ? 'F' : 'D').join('');
        await openInRizin('C:\\x\\s.exe');
        await until(() => rizinState.landed, 'landed'); await quiet();
        r.first = events();

        // After the first jump: a later Full analysis (Task 7's button starts it and the poll)
        runs[0] = [{ step: null, done: ['aa', 'aac'] }, { state: 'done', step: null, done: ['aa', 'aac', 'aar'] }];
        phase = 0;
        const mark = calls.length;
        rizinState.analysis = { state: 'running', step: 'aac', done_steps: ['aa'], level: 'aaa', elapsed: 0, note: null };
        rizinPollSoon();
        await until(() => rizinState.analysis.state === 'done', 'second run done'); await quiet();
        r.later = calls.slice(mark).filter(c => /\/(status|functions|disasm)/.test(c[1]))
            .map(c => c[1].includes('/status') ? 'S' : c[1].includes('/functions') ? 'F' : 'D').join('');
        r.view = marked();
    """)
    assert "error" not in r, r.get("error")
    # F at open; S S(gap: F) S S(gap: F) S(done: landing F, then the jump's D)
    assert r["first"].startswith("FSSFSSFSF"), r["first"]
    # After each status of the later run (a finished step, then the end): the list and the shown disassembly
    assert [sorted(after) for after in r["later"].split("S")[1:]] == [["D", "F"], ["D", "F"]], \
        "a finished step did not refresh the list and the shown disassembly: " + r["later"]
    assert r["view"] == ["0x1400014b7", "0x1400014b7"]


@needs_node
def test_rizin_view_errors_are_shown_and_stop_the_poll():
    """Review, Minors 1 and 2: a function list that keeps failing (not busy)
    shows its error and the tab lands without it, so the poll stops (the
    session can idle out); a disassembly that cannot be loaded for the new
    place shows why instead of the old page, busy as well, until it loads."""
    r = _scripted(r"""
        let busyOnce = true;
        const S = { analysis: 'done', done: ['aaa'],
                    functions: () => [500, { error: 'rizin answered something unexpected: <x>' }],
                    disasm: hex => (hex === '0x140001490' ? [500, { error: 'rizin answered something unexpected: <y>' }]
                                   : hex === '0x1400014b7' && busyOnce ? (busyOnce = false, [409, { busy: true, step: 'console' }])
                                   : null) };
        serve('S1', S);
        opens['C:\\x\\s.exe'] = S;
        await openInRizin('C:\\x\\s.exe');
        await until(() => rizinState.landed, 'landed'); await quiet();
        r.landed = [rizinState.seek, $('rizin-fn-list').textContent, marked()[1]];
        const polls = S.statusCalls;
        await tick(60);
        r.pollStopped = S.statusCalls === polls;

        $('rizin-seek').value = '0x140001490';
        click($('rizin-go'));
        await until(() => rizinState.seek === '0x140001490', 'GO watchdog'); await quiet();
        r.failed = [$('rizin-disasm').textContent, $('rizin-disasm').querySelectorAll('.rizin-op').length,
                    $('rizin-code-title').textContent, $('rizin-seek').value];

        $('rizin-seek').value = '0x1400014b7';
        click($('rizin-go'));
        await until(() => rizinState.seek === '0x1400014b7', 'GO main');
        await until(() => $('rizin-disasm').textContent.includes('busy'), 'busy shown');
        r.busy = [$('rizin-disasm').textContent, $('rizin-disasm').querySelectorAll('.rizin-op').length];
        await until(() => marked()[1] === '0x1400014b7', 'the page once rizin is free'); await quiet();
        r.loaded = [$('rizin-disasm').querySelectorAll('.rizin-op').length, $('rizin-state').hidden];
    """)
    assert "error" not in r, r.get("error")
    seek, listed, line = r["landed"]
    assert seek == "0x140001000" and line == "0x140001000", "the tab did not land without the list"
    assert "rizin answered something unexpected: <x>" in listed, listed
    assert r["pollStopped"] is True, "a list that keeps failing keeps the poll (and the session) alive"
    text, lines, title, field = r["failed"]
    assert "rizin answered something unexpected: <y>" in text and lines == 0, "the old page stayed for the new place"
    assert title == "sym.watchdog" and field == "0x140001490"
    assert "busy (console)" in r["busy"][0] and r["busy"][1] == 0
    assert r["loaded"] == [6, True]


@needs_node
def test_rizin_poll_pauses_in_a_hidden_tab():
    """Review, Minor 5: like the other polls of the page, the status poll
    pauses while the browser tab is hidden and goes on when it is shown."""
    r = _scripted(r"""
        let status = 0;
        const S = { analysis: 'running', step: 'aaa', done: [],
                    onStatus: s => { if (++status >= 2) Object.assign(s, { analysis: 'done', step: null, done: ['aaa'] }); } };
        serve('S1', S);
        opens['C:\\x\\s.exe'] = S;
        document.hidden = true;
        await openInRizin('C:\\x\\s.exe');
        await tick(80);
        r.hidden = [S.statusCalls, rizinState.landed];
        document.hidden = false;
        document.listeners.filter(l => l.type === 'visibilitychange').forEach(l => l.fn({ type: 'visibilitychange' }));
        await until(() => rizinState.landed, 'landed once shown'); await quiet();
        r.shown = [S.statusCalls >= 2, rizinState.seek];
    """)
    assert "error" not in r, r.get("error")
    assert r["hidden"] == [0, False], "the poll ran in a hidden tab"
    assert r["shown"] == [True, "0x1400014b7"]


def test_rizin_symbol_pattern_is_linear():
    """Review, Minor 6: the pattern that finds symbols in the operands ran in
    quadratic time on a long token without a dot (Node 20: 700 ms at 30 000
    characters, on every click inside the function). The dots are optional
    now, and each repeated part starts with a dot that the part before it
    cannot match, so every character has one way through: linear."""
    source = _function_source("rizinOperandsHtml")
    assert r"[A-Za-z_][\w$@?]*(?:\.[\w$@?:-]+)*" in source
    assert r"(?:\.[\w$@?:-]+)+" not in source, "the quadratic form is back"


@needs_node
def test_rizin_long_operands_render():
    r = _run(r"""
        const box = html => { const el = document.createElement('div'); el.innerHTML = html; return el; };
        const plain = 'A'.repeat(30000), symbol = 'sym.' + 'b'.repeat(30000), dotted = 'c'.repeat(30000) + '.d';
        const dis = box(rizinDisasmHtml([
            { offset: 0x1000, size: 4, text: 'mov rax, ' + plain, type: 'mov', jump: null, comment: null },
            { offset: 0x1004, size: 5, text: 'call ' + symbol, type: 'call', jump: 0x2000, comment: null },
            { offset: 0x1009, size: 7, text: 'lea rdx, ' + dotted, type: 'lea', jump: null, comment: null },
        ], { current: '0x1004' }));
        const lines = dis.querySelectorAll('.rizin-op');
        console.log(JSON.stringify({
            texts: lines.map(l => l.textContent.length),
            symbols: dis.querySelectorAll('.rz-sym').map(e => e.textContent.length),
            target: dis.querySelector('.rz-target').getAttribute('data-addr'),
            plainAsSymbol: dis.querySelectorAll('.rz-sym').some(e => e.textContent === plain),
        }));
    """, SORT_DOM)
    assert r["texts"] == [len("0x1000 mov rax, ") + 30000, len("0x1004 call ") + 30004, len("0x1009 lea rdx, ") + 30002]
    assert sorted(r["symbols"]) == [30002, 30004] and r["target"] == "0x2000" and r["plainAsSymbol"] is False


@needs_node
def test_rizin_quick_clicks_and_late_answers():
    """Review, Minor 7: three clicks before the first answer jump to the
    first and the last (the one between is replaced, never sent); a late
    page of instructions for a place left meanwhile is dropped; a late
    function list asked for before the newest one is dropped."""
    r = _scripted(r"""
        const S = { analysis: 'done', done: ['aaa'], seekDelay: 15 };
        serve('S1', S);
        opens['C:\\x\\s.exe'] = S;
        await openInRizin('C:\\x\\s.exe');
        await until(() => rizinState.landed, 'landed'); await quiet();
        const sent = seeksOf('S1').length;
        click(row('0x140001000'));
        await until(() => flying('/api/rizin/S1/seek'), 'the first jump in flight');
        click(row('0x140001490')); click(row('0x1400014b7'));
        await until(() => seeksOf('S1').length >= sent + 2 && rizinState.seek === '0x1400014b7', 'clicks'); await quiet();
        r.clicks = [seeksOf('S1').slice(sent), rizinState.history.slice(-3), marked()];

        S.seekDelay = 1;
        S.disasmDelay = hex => (hex === '0x140001000' ? 80 : 1);
        click(row('0x140001000'));
        await until(() => flying('/api/rizin/S1/disasm?addr=0x140001000'), 'slow page in flight');
        click(row('0x140001490'));
        await until(() => rizinState.seek === '0x140001490', 'second jump');
        await tick(120); await quiet();
        r.late = [marked(), $('rizin-code-title').textContent, $('rizin-disasm').querySelectorAll('.rizin-op').length];

        let lists = 0;
        const P = { analysis: 'running', step: 'aaa', done: [],
                    functions: () => (++lists === 1 ? [200, [FUNCS[0]], 80] : [200, FUNCS]),
                    onStatus: s => { if (s.statusCalls >= 2) Object.assign(s, { analysis: 'done', step: null, done: ['aaa'] }); } };
        serve('SP', P);
        opens['C:\\x\\p.exe'] = P;
        await openInRizin('C:\\x\\p.exe');
        await until(() => rizinState.landed, 'P landed');
        await tick(120); await quiet();
        r.list = [lists, $('rizin-fn-list').querySelectorAll('.rizin-fn').length, $('rizin-fn-count').textContent];
    """)
    assert "error" not in r, r.get("error")
    sent, history, view = r["clicks"]
    assert sent == ["0x140001000", "0x1400014b7"], "the click between was sent, or the last one was lost"
    # The first click's jump drew nothing (a newer one came): no place of the history (final review, F3)
    assert history == ["0x1400014b7"] and view == ["0x1400014b7", "0x1400014b7"]
    assert r["late"] == [["0x140001490", "0x140001490"], "sym.watchdog", 4], "a late page replaced the new one"
    assert r["list"] == [2, 3, "3 functions · address on hover"], "a late, older function list replaced the newer one"


@needs_node
def test_rizin_open_sources_escape_paths():
    """Review, Minor 7: OPEN ▾ lists names and paths from the samples (a
    submission's file name is the sample's): they stay text in the label,
    data-path and title, and a click opens the path exactly as listed."""
    r = _scripted(r"""
        const path = 'C:\\Users\\Public\\Downloads\\a"b\'<c>&d.exe';
        const files = { submissions: [{ filename: HOSTILE, path, sha256: 'x', time: '2026-11-12T10:00:00' }],
                        dumps: [{ name: 'run\\x" onmouseover="alert(1).dmp', path: 'C:\\dumps\\run\\x".dmp', size: 2048 }],
                        uploads: [{ name: '0123456789abcdef_<b>u.exe', path: 'C:\\Windows\\Temp\\rizin_uploads\\0123456789abcdef_<b>u.exe', size: 5 }] };
        on('GET', '/api/rizin/files', () => [200, files]);
        click($('rizin-open-toggle'));
        await until(() => !!document.querySelector('#rizin-open-sources .rizin-open-item'), 'listed');
        const items = document.querySelectorAll('#rizin-open-sources .rizin-open-item');
        const box = $('rizin-open-sources');
        r.items = items.map(i => [i.getAttribute('data-path'), i.getAttribute('title'), i.querySelector('.rizin-open-name').textContent]);
        r.tags = [...box.walk()].map(e => e.tagName).filter(t => !['DIV', 'SPAN', 'BUTTON'].includes(t));
        r.handlers = [...box.walk()].flatMap(e => Object.keys(e.attrs)).filter(a => a.startsWith('on'));
        click(items[0].querySelector('.rizin-open-name'));
        await until(() => count('POST', '/api/rizin/open') === 1, 'opened');
        r.opened = calls.find(c => c[1] === '/api/rizin/open')[2].path;
    """.replace("HOSTILE", json.dumps(HOSTILE)))
    assert "error" not in r, r.get("error")
    path = 'C:\\Users\\Public\\Downloads\\a"b\'<c>&d.exe'
    assert r["items"] == [[path, path, HOSTILE],
                          ['C:\\dumps\\run\\x".dmp', 'C:\\dumps\\run\\x".dmp', 'run\\x" onmouseover="alert(1).dmp'],
                          ["C:\\Windows\\Temp\\rizin_uploads\\0123456789abcdef_<b>u.exe",
                           "C:\\Windows\\Temp\\rizin_uploads\\0123456789abcdef_<b>u.exe", "<b>u.exe"]]
    assert r["tags"] == [] and r["handlers"] == [], "a name or path became markup"
    assert r["opened"] == path


# --- Fix round 2: every view at each analysis step ---------------------------------


@needs_node
def test_rizin_every_view_is_refreshed_at_each_step():
    """Re-review, N1 and N2: at every finished step of an analysis, the last
    one too, every view is asked for again, all at once (each request counts
    as waiting while rizin answers the others, so the gap after the step
    stays open for them); a forced reload that found rizin busy is asked
    again, still forced, once rizin is free (also when another request found
    it free meanwhile); an analysis during which the user jumped ends with
    the views at that place asked for again."""
    r = _scripted(r"""
        let version = 0;
        const page = () => ({ function: 'sym.main', more: false,
                              ops: OPS['sym.main'].map((o, i) => (i ? o : { ...o, comment: `version ${version}` })) });
        const S = { analysis: 'done', done: ['aaa'], disasm: () => [200, page()] };
        serve('S1', S);
        opens['C:\\x\\s.exe'] = S;
        const shows = text => $('rizin-disasm').textContent.includes(text);
        await openInRizin('C:\\x\\s.exe');
        await until(() => rizinState.landed, 'landed'); await quiet();
        r.landed = shows('version 0');

        // A Full analysis after the first jump. aac ends: list and disassembly at once; the disassembly finds
        // rizin busy with another request, the list is answered
        Object.assign(S, { analysis: 'running', step: 'aac', done: ['aa'] });
        rizinState.analysis = { state: 'running', step: 'aac', done_steps: ['aa'], level: 'aaa', elapsed: 0, note: null };
        rizinPollSoon();
        await tick(20);
        const sent = [];
        let busy = true;
        S.functions = () => { sent.push(['F', flying('/api/rizin/S1/disasm')]); return [200, FUNCS, 30]; };
        S.disasm = () => {
            sent.push(['D', flying('/api/rizin/S1/functions')]);
            if (!busy) return [200, page()];
            busy = false;
            return [409, { busy: true, step: 'view' }, 30];
        };
        version = 1;
        Object.assign(S, { step: null, done: ['aa', 'aac'] });
        await until(() => sent.filter(s => s[0] === 'D').length === 2 && !flying('/api/rizin/S1/disasm'), 'the busy page asked again');
        await tick(5);
        r.step = [sent.slice(0, 2), sent.slice(2), shows('version 1'), rizinState.retry.size, rizinState.ui.state];

        // The last step: every view once more
        version = 2;
        sent.length = 0;
        Object.assign(S, { analysis: 'done', step: null, done: ['aa', 'aac', 'aar'] });
        await until(() => rizinState.analysis.state === 'done', 'done'); await quiet();
        r.end = [sent.map(s => s[0]).sort(), shows('version 2')];

        // An analysis at open during which the user jumped: at its end no first jump, the views there again
        let run = 0;
        const P = { analysis: 'running', step: 'aaa', done: [],
                    disasm: () => [200, { function: 'sym.watchdog', more: false,
                                          ops: OPS['sym.watchdog'].map((o, i) => (i ? o : { ...o, comment: `run ${run}` })) }] };
        serve('SP', P);
        opens['C:\\x\\p.exe'] = P;
        await openInRizin('C:\\x\\p.exe');
        $('rizin-seek').value = '0x140001490';
        click($('rizin-go'));
        await until(() => shows('run 0'), 'a jump while the analysis runs');
        run = 1;
        const pages = count('GET', '/api/rizin/SP/disasm');
        Object.assign(P, { analysis: 'done', step: null, done: ['aaa'] });
        await until(() => rizinState.landed, 'P landed'); await quiet();
        r.stayed = [seeksOf('SP'), count('GET', '/api/rizin/SP/disasm') - pages, shows('run 1')];
    """)
    assert "error" not in r, r.get("error")
    assert r["landed"] is True
    first, retried, shown, retry, ui = r["step"]
    assert sorted(kind for kind, _ in first) == ["D", "F"] and any(other for _, other in first), \
        "the list and the disassembly were asked for one after the other: " + str(first)
    assert retried == [["D", False]] and shown is True, "the forced reload that found rizin busy was not asked again"
    assert retry == 0 and ui == ""
    assert r["end"] == [["D", "F"], True], "the last step did not refresh the disassembly"
    assert r["stayed"] == [["0x140001490"], 1, True], "the views at the user's place were not asked again at the end"


@needs_node
def test_rizin_analysis_steps_keep_the_scroll_position():
    """Re-review, N3: the views drawn again at the steps of an analysis keep
    what the user scrolled to (a row that comes in above the ones in sight
    pushes the list on, so these stay where they were); a view whose answer
    did not change is not drawn again (a selection stays). Only a jump
    brings the current function or line into sight."""
    r = _scripted(r"""
        // Every element 20 px high, one under the other in its parent; the lists 200 px high
        Object.defineProperties(Element.prototype, {
            offsetTop: { configurable: true, get() { return this.parentNode ? this.parentNode.children.indexOf(this) * 20 : 0; } },
            offsetHeight: { configurable: true, get() { return 20; } },
            clientHeight: { configurable: true, get() { return 200; } },
        });
        const list = $('rizin-fn-list'), pane = $('rizin-disasm');
        list.scrollTop = 0; pane.scrollTop = 0;
        const fcn = i => ({ name: `fcn.${String(i).padStart(2, '0')}`, offset: 0x140010000 + i * 0x100, size: 16, nbbs: 1 });
        let funcs = [FUNCS[0], ...Array.from({ length: 15 }, (_, i) => fcn(i)), FUNCS[2],
                     ...Array.from({ length: 13 }, (_, i) => fcn(15 + i))];
        let note = null;
        const ops = () => Array.from({ length: 40 }, (_, i) => op(0x1400014b7 + i * 4, 4, 'nop', 'nop', null, i ? null : note));
        const S = { analysis: 'done', done: ['aaa'], functions: () => [200, funcs],
                    disasm: () => [200, { function: 'sym.main', ops: ops(), more: false }] };
        serve('S1', S);
        opens['C:\\x\\s.exe'] = S;
        await openInRizin('C:\\x\\s.exe');
        await until(() => rizinState.landed, 'landed'); await quiet();
        r.landed = [list.scrollTop, pane.scrollTop];

        // The user scrolls both away from the current function and line; then a Full analysis runs
        list.scrollTop = 400; pane.scrollTop = 300;
        const views = () => count('GET', '/api/rizin/S1/functions') + count('GET', '/api/rizin/S1/disasm');
        const answered = async n => {
            await until(() => views() >= n && ![...inFlight].some(([url, k]) => k > 0 && !url.includes('/status')), 'views answered');
            await tick(3);
        };
        Object.assign(S, { analysis: 'running', step: 'aac', done: ['aa'] });
        rizinState.analysis = { state: 'running', step: 'aac', done_steps: ['aa'], level: 'aaa', elapsed: 0, note: null };
        rizinPollSoon();
        await tick(20);
        const line = pane.children[15];
        // aac found a function above the rows in sight; the instructions stay the same
        funcs = [...funcs.slice(0, 5), fcn(40), ...funcs.slice(5)];
        let n = views();
        Object.assign(S, { step: null, done: ['aa', 'aac'] });
        await answered(n + 2);
        r.step1 = [list.scrollTop, pane.scrollTop, list.children.length, pane.children[15] === line];
        // aar changed nothing
        const row = list.children[21];
        n = views();
        Object.assign(S, { step: null, done: ['aa', 'aac', 'aar'] });
        await answered(n + 2);
        r.step2 = [list.scrollTop, pane.scrollTop, list.children[21] === row, pane.children[15] === line];
        // The last step changed a comment: drawn again, at the same place
        note = 'found by aaft';
        n = views();
        Object.assign(S, { analysis: 'done', step: null, done: ['aa', 'aac', 'aar', 'aaft'] });
        await answered(n + 2); await quiet();
        r.end = [list.scrollTop, pane.scrollTop, pane.textContent.includes('found by aaft'), pane.children[15] === line];
        // A jump: the new line comes into sight
        $('rizin-seek').value = '0x14000152f';
        click($('rizin-go'));
        await until(() => rizinState.seek === '0x14000152f', 'GO'); await quiet();
        r.jump = [list.scrollTop, pane.scrollTop, pane.querySelector('.rizin-op.current').getAttribute('data-addr')];
    """)
    assert "error" not in r, r.get("error")
    assert r["landed"] == [230, 0], "the first jump did not bring sym.main into sight"
    assert r["step1"] == [420, 300, 31, True], "a step scrolled the views, or drew the same lines again"
    assert r["step2"] == [420, 300, True, True], "a step that changed nothing drew the views again"
    assert r["end"] == [420, 300, True, False]
    assert r["jump"] == [420, 510, "0x14000152f"]


@needs_node
def test_rizin_registered_views_follow_the_analysis():
    """Re-review, N4: a view registered in RIZIN_VIEWS (Tasks 5 to 7 add
    theirs) is loaded after a jump, and again (forced) at every finished
    step and at the end of the analysis, also when it waits in retry; a view
    that found rizin busy is asked again, as forced as before, once the step
    that kept rizin busy is over, not while it runs."""
    r = _scripted(r"""
        const S = { analysis: 'done', done: ['aaa'] };
        serve('S1', S);
        opens['C:\\x\\s.exe'] = S;
        const ok = () => [200, { ok: true }];
        let answer = ok;
        on('GET', '/api/rizin/S1/probe', () => answer());
        const probes = [];
        RIZIN_VIEWS.probe = async force => {
            probes.push(force);
            const res = await rizinApi('/api/rizin/S1/probe');
            if (res.ok) rizinState.retry.delete('probe');
            else if (res.state === 'busy') rizinViewBusy('probe', force);
        };
        await openInRizin('C:\\x\\s.exe');
        await until(() => rizinState.landed, 'landed'); await quiet();
        r.landing = probes.splice(0);
        click(row('0x140001490'));
        await until(() => rizinState.seek === '0x140001490', 'jump'); await quiet();
        r.jump = probes.splice(0);

        // A Full analysis; a jump while aac runs finds rizin busy with it: not asked again while aac runs
        Object.assign(S, { analysis: 'running', step: 'aac', done: ['aa'] });
        rizinState.analysis = { state: 'running', step: 'aac', done_steps: ['aa'], level: 'aaa', elapsed: 0, note: null };
        rizinPollSoon();
        answer = () => [409, { busy: true, step: 'aac' }];
        click(row('0x1400014b7'));
        await until(() => probes.length === 1 && !flying('/api/rizin/S1/probe'), 'the busy view');
        const polls = S.statusCalls;
        await until(() => S.statusCalls >= polls + 4, 'polls while aac runs');
        r.busy = [probes.splice(0), [...rizinState.retry], rizinState.ui.state];

        // aac is over: every registered view at once, forced, the one in retry too
        answer = ok;
        Object.assign(S, { step: null, done: ['aa', 'aac'] });
        await until(() => probes.length === 1 && !flying('/api/rizin/S1/probe'), 'step 1');
        await tick(20);
        r.step1 = [probes.splice(0), rizinState.retry.size];

        // aar is over, but another request holds rizin: asked again, still forced
        answer = () => { answer = ok; return [409, { busy: true, step: 'view' }]; };
        Object.assign(S, { step: null, done: ['aa', 'aac', 'aar'] });
        await until(() => probes.length === 2 && !flying('/api/rizin/S1/probe'), 'step 2 and its retry');
        await tick(20);
        r.step2 = [probes.splice(0), rizinState.retry.size];

        // The end of the analysis
        Object.assign(S, { analysis: 'done', step: null, done: ['aa', 'aac', 'aar', 'aaft'] });
        await until(() => rizinState.analysis.state === 'done', 'done'); await quiet();
        r.end = probes.splice(0);
    """)
    assert "error" not in r, r.get("error")
    assert r["landing"] and set(r["landing"]) == {False} and r["jump"] == [False]
    assert r["busy"] == [[False], [["probe", False]], "busy"], "asked again while the step that kept it busy runs"
    assert r["step1"] == [[True], 0], "a finished step did not reload the registered view"
    assert r["step2"] == [[True, True], 0], "the view was not asked again, or not forced"
    assert r["end"] == [True], "the end of the analysis did not reload the registered view"


def test_rizin_comment_patterns_are_linear():
    """Re-review: rizinCommentHtml ran in quadratic time on whitespace
    without a line break (Node 20: 412 ms at 30 000 characters) and on many
    escaped quotes (183 ms); rizin's own comments have no length limit. Each
    run of whitespace is matched once now (\\s+, nothing to backtrack into),
    and every try of the quote pattern at a quote succeeds: a string, or a
    quote that nothing closes, which takes the rest (no later quote can
    start a string then either)."""
    source = _function_source("rizinCommentHtml")
    assert r"replace(/\s+/g," in source and r"\s*\r?\n\s*" not in source
    assert r'/("(?:[^"\\]|\\[\s\S])*")|"[\s\S]*/g' in source
    assert r'(?:[^"\\]|\\.)*' not in source, "the quadratic form is back"


@needs_node
def test_rizin_long_comments_render():
    r = _run(r"""
        // The patterns before, as the reference where they were quick: every comment of up to 6 characters
        const before = comment => {
            const parts = String(comment).replace(/\s*\r?\n\s*/g, ' ↵ ').split(/("(?:[^"\\]|\\.)*")/);
            return `<span class="rz-comment">; ${parts.map((p, i) => (i % 2 ? `<span class="rz-str">${escapeHtml(p)}</span>` : escapeHtml(p))).join('')}</span>`;
        };
        const alphabet = ['"', '\\', 'a', ' ', '\n', '<'];
        let words = [''], tried = 0;
        const differ = [];
        for (let length = 1; length <= 6; length++) {
            words = words.flatMap(w => alphabet.map(c => w + c));
            for (const w of words) {
                tried++;
                if (rizinCommentHtml(w) !== before(w)) differ.push(w);
            }
        }
        const box = html => { const el = document.createElement('div'); el.innerHTML = html; return el; };
        const spaces = box(rizinCommentHtml('a' + ' '.repeat(30000) + 'b'));
        const lines = box(rizinCommentHtml('a' + ' '.repeat(30000) + '\r\n' + ' '.repeat(30000) + 'b'));
        const open = box(rizinCommentHtml('"' + '\\"'.repeat(15000)));
        const strings = box(rizinCommentHtml('\\"'.repeat(15000) + ' "x" "y'));
        console.log(JSON.stringify({
            differ: differ.slice(0, 5), tried,
            spaces: [spaces.textContent.length, spaces.querySelectorAll('.rz-str').length],
            lines: lines.textContent,
            open: [open.textContent.length, open.querySelectorAll('.rz-str').length],
            strings: strings.querySelectorAll('.rz-str').map(e => e.textContent.length),
        }));
    """, SORT_DOM)
    assert r["differ"] == [] and r["tried"] == sum(6 ** n for n in range(1, 7)), "a comment is drawn otherwise than before"
    assert r["spaces"] == [len("; a") + 30000 + 1, 0]
    assert r["lines"] == "; a ↵ b"
    assert r["open"] == [len('; "') + 30000, 0], "a quote that nothing closes became a string"
    assert r["strings"] == [30001, 3]


# --- Task 5: the control flow graph ------------------------------------------------

# The graph route's answer for sym.main of pipesim.exe (built with mingw -O1), taken from rizin 0.9.1
GRAPH_FIXTURE = os.path.join(ROOT, "tests", "samples", "pipesim-main-graph.json")

# Control flow graphs as a compiler makes them, from a fixed seed (mulberry32): blocks in address order
# that fall through, branch forward or back (loops, a block onto itself), jump far (to the end), switch,
# go to the next block both ways, return, cannot be reached, or name an address that is no block
GRAPH_GEN = r"""
function prng(seed) {
    return () => {
        seed = (seed + 0x6D2B79F5) | 0;
        let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
        t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
}
function randomGraph(n, seed, base = 0x140001000) {
    const rnd = prng(seed);
    const pick = (lo, hi) => lo + Math.floor(rnd() * (hi - lo + 1));
    const offsets = [];
    for (let i = 0, at = base; i < n; i++, at += pick(2, 60)) offsets.push(at);
    const to = i => offsets[Math.max(0, Math.min(n - 1, i))];
    return offsets.map((offset, i) => {
        const lines = Array.from({ length: pick(1, 9) }, () => 'mov rax, qword [rbp - 0x' + 'f'.repeat(pick(1, 4)) + ']'
                                 + (rnd() < 0.05 ? ' ; ' + 'x'.repeat(pick(40, 140)) : ''));
        const next = i + 1 < n ? offsets[i + 1] : null;
        let jump = null, fail = null, cases = [];
        const r = rnd();
        if (i === n - 1 || r < 0.05) { /* returns */ }
        else if (r < 0.12) jump = to(i + pick(2, 8));
        else if (r < 0.40) { jump = to(i + pick(2, 10)); fail = next; }
        else if (r < 0.52) { jump = to(i - pick(0, 15)); fail = next; }
        else if (r < 0.57) { jump = offsets[n - 1]; fail = next; }
        else if (r < 0.61) cases = Array.from({ length: pick(3, 12) }, () => to(i + pick(1, 30)));
        else if (r < 0.63) { jump = offset + 1; fail = next; }
        else if (r < 0.65) { jump = next; fail = next; }
        else if (r < 0.68) jump = to(i - pick(1, 20));
        else jump = next;
        return { offset, size: lines.length * 4, lines, jump, fail, cases };
    });
}
const hex = a => '0x' + a.toString(16);
"""

# What is wrong with a layout: one box per block, apart and inside the drawing; one edge per jump,
# fall-through or case of a block, in its colour; every edge in right angles from the edge of its block
# to the edge of the next, through no block and not on top of another edge; every block below the block
# it comes from, but where the edge closes a loop: such an edge runs around the outside of the blocks
GRAPH_CHECK = r"""
const onBorder = (b, [x, y]) => ((Math.abs(y - b.y) < 0.01 || Math.abs(y - b.y - b.h) < 0.01) && x >= b.x - 0.01 && x <= b.x + b.w + 0.01)
    || ((Math.abs(x - b.x) < 0.01 || Math.abs(x - b.x - b.w) < 0.01) && y >= b.y - 0.01 && y <= b.y + b.h + 0.01);
const crosses = (b, p, q) => Math.max(p[0], q[0]) > b.x + 0.5 && Math.min(p[0], q[0]) < b.x + b.w - 0.5
    && Math.max(p[1], q[1]) > b.y + 0.5 && Math.min(p[1], q[1]) < b.y + b.h - 0.5;
function problems(nodes, layout) {
    const found = [];
    const say = text => { if (found.length < 20) found.push(text); };
    const unique = [], known = new Set();
    for (const node of nodes) {
        if (node && Number.isFinite(node.offset) && !known.has(node.offset)) { known.add(node.offset); unique.push(node); }
    }
    const box = new Map(layout.boxes.map(b => [b.offset, b]));
    if (layout.boxes.length !== unique.length || unique.some(n => !box.has(n.offset))) say('not one box per block');
    const want = new Map();
    for (const node of unique) {
        const jump = known.has(node.jump) ? node.jump : null, fail = known.has(node.fail) ? node.fail : null;
        const both = jump !== null && fail !== null && jump !== fail;
        const add = (to, kind) => { const k = node.offset + '>' + to; if (!want.has(k)) want.set(k, kind); };
        if (jump !== null) add(jump, both ? 'jump' : 'plain');
        if (fail !== null) add(fail, both ? 'fail' : 'plain');
        for (const c of node.cases || []) if (known.has(c)) add(c, 'plain');
    }
    const got = new Map(layout.edges.map(e => [e.from + '>' + e.to, e.kind]));
    if (got.size !== layout.edges.length) say('an edge twice');
    for (const [k, kind] of want) if (got.get(k) !== kind) say(`edge ${k}: ${got.get(k)} instead of ${kind}`);
    for (const k of got.keys()) if (!want.has(k)) say(`edge ${k} that the graph does not have`);
    const boxes = layout.boxes;
    for (const b of boxes) {
        if (!(b.w > 0 && b.h > 0) || b.x < 0 || b.y < 0 || b.x + b.w > layout.width || b.y + b.h > layout.height) {
            say('a block outside the drawing: ' + b.offset);
        }
    }
    for (let i = 0; i < boxes.length; i++) {
        for (let j = i + 1; j < boxes.length; j++) {
            const a = boxes[i], b = boxes[j];
            if (a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h) say(`blocks ${a.offset} and ${b.offset} overlap`);
        }
    }
    const succ = new Map(unique.map(n => [n.offset, []])), preds = new Map(unique.map(n => [n.offset, []]));
    for (const k of want.keys()) {
        const [a, b] = k.split('>').map(Number);
        succ.get(a).push(b);
        if (a !== b) preds.get(b).push(a);
    }
    const reaches = (from, target) => {
        const stack = [from], seen = new Set([from]);
        while (stack.length) {
            const v = stack.pop();
            if (v === target) return true;
            for (const w of succ.get(v)) if (!seen.has(w)) { seen.add(w); stack.push(w); }
        }
        return false;
    };
    const minX = Math.min(...boxes.map(b => b.x)), maxX = Math.max(...boxes.map(b => b.x + b.w));
    const segments = [];
    for (const e of layout.edges) {
        const a = box.get(e.from), b = box.get(e.to), pts = e.points;
        const name = `${e.from}>${e.to}`;
        if (!a || !b || !Array.isArray(pts) || pts.length < 2) { say('an edge without points: ' + name); continue; }
        if (!onBorder(a, pts[0])) say(`edge ${name} does not start at the edge of its block`);
        if (!onBorder(b, pts[pts.length - 1])) say(`edge ${name} does not end at the edge of its block`);
        for (let i = 1; i < pts.length; i++) {
            const p = pts[i - 1], q = pts[i];
            if (p[0] !== q[0] && p[1] !== q[1]) say(`edge ${name}: a slanted segment`);
            if (p[0] === q[0] && p[1] === q[1]) say(`edge ${name}: a segment without length`);
            for (const c of boxes) if (crosses(c, p, q)) say(`edge ${name} cuts through block ${c.offset}`);
            if ([p, q].some(([x, y]) => x < 0 || y < 0 || x > layout.width || y > layout.height)) say(`edge ${name} leaves the drawing`);
            segments.push([e, p, q]);
        }
        const loop = reaches(e.to, e.from);
        if (!loop && b.y < a.y + a.h) say(`block ${e.to} is not below block ${e.from}, which leads to it`);
        if (b.y < a.y + a.h) {
            const outside = pts.some((p, i) => i && p[0] === pts[i - 1][0] && (p[0] < minX || p[0] > maxX));
            if (!outside) say(`the loop ${name} runs through the blocks instead of around them`);
        }
    }
    for (const [v, from] of preds) {
        const b = box.get(v);
        if (from.length && !from.some(p => box.get(p).y + box.get(p).h <= b.y) && !from.every(p => reaches(v, p))) {
            say(`block ${v} lies under none of the blocks that lead to it`);
        }
    }
    const lines = new Map();
    for (const [e, p, q] of segments) {
        const vertical = p[0] === q[0];
        const key = vertical ? 'x' + p[0] : 'y' + p[1];
        const at = vertical ? [p[1], q[1]] : [p[0], q[0]];
        if (!lines.has(key)) lines.set(key, []);
        lines.get(key).push([Math.min(...at), Math.max(...at), e]);
    }
    for (const list of lines.values()) {
        for (let i = 0; i < list.length; i++) {
            for (let j = i + 1; j < list.length; j++) {
                const [lo1, hi1, e1] = list[i], [lo2, hi2, e2] = list[j];
                if (e1 !== e2 && Math.min(hi1, hi2) - Math.max(lo1, lo2) > 0.5) {
                    say(`edges ${e1.from}>${e1.to} and ${e2.from}>${e2.to} run on top of each other`);
                }
            }
        }
    }
    return found;
}
"""


@needs_node
def test_rizin_graph_layout_is_layered_without_overlap():
    """The brief: random graphs with loops and branches; no boxes overlap,
    edges begin and end at the edge of their boxes, every block lies below a
    block it comes from (loops excepted), the same input gives the same
    layout, and 500 blocks stay far below a second in node (every graph's own
    best of three runs after a warm-up; a cold or stalled sample measures the
    machine as much as the layout, follow-up finding 3)."""
    r = _run(GRAPH_GEN + GRAPH_CHECK + r"""
        const r = { problems: {}, sizes: {} };
        const graphs = [[1, 1], [2, 2], [3, 3], [5, 4], [8, 5], [13, 6], [30, 7], [60, 8], [120, 9], [250, 10], [400, 11]]
            .map(([n, seed]) => [`random ${n}/${seed}`, randomGraph(n, seed)]);
        const at = a => ({ offset: a, size: 1, lines: ['nop'], jump: null, fail: null, cases: [] });
        graphs.push(['self loop', [{ ...at(0x10), jump: 0x10 }]],
                    ['two in a loop', [{ ...at(0x10), jump: 0x20 }, { ...at(0x20), jump: 0x10, fail: 0x30 }, at(0x30)]],
                    ['loop into the entry', [{ ...at(0x10), fail: 0x20 }, { ...at(0x20), jump: 0x10, fail: 0x30 }, at(0x30)]],
                    ['nothing reaches it', [at(0x10), { ...at(0x20), jump: 0x30 }, { ...at(0x30), jump: 0x20 }]],
                    ['odd entries', [null, { offset: 'x' }, { ...at(0x10), jump: 0x20, fail: 0x20, cases: [0x20, 0x99, null] },
                                     { ...at(0x20), lines: undefined }, { ...at(0x10), jump: 0x30 }]],
                    ['long lines', [{ ...at(0x10), lines: ['x'.repeat(5000), ''], jump: 0x20 }, { ...at(0x20), lines: Array(900).fill('nop') }]],
                    ['a switch of 300 cases', [{ ...at(0x10), cases: Array.from({ length: 300 }, (_, i) => 0x100 + i) },
                                               ...Array.from({ length: 300 }, (_, i) => ({ ...at(0x100 + i), jump: 0x1000 })),
                                               at(0x1000)]]);
        for (const [name, nodes] of graphs) {
            const layout = rizinLayoutGraph(nodes);
            const again = rizinLayoutGraph(JSON.parse(JSON.stringify(nodes)));
            const found = problems(nodes, layout);
            if (JSON.stringify(layout) !== JSON.stringify(again)) found.push('another layout for the same graph');
            if (JSON.stringify(layout) !== JSON.stringify(rizinLayoutGraph(nodes))) found.push('another layout the second time');
            r.problems[name] = found;
            r.sizes[name] = [layout.boxes.length, layout.edges.length, layout.edges.filter(e => e.back).length];
        }
        r.empty = [rizinLayoutGraph([]), rizinLayoutGraph(null)];
        // 500 blocks: once to warm node up, then three graphs, each laid out three times (its best counts)
        rizinLayoutGraph(randomGraph(500, 99));
        r.times = [];
        for (const seed of [501, 502, 503]) {
            const nodes = randomGraph(500, seed);
            let best = Infinity, layout = null;
            for (let i = 0; i < 3; i++) {
                const t0 = performance.now();
                layout = rizinLayoutGraph(nodes);
                best = Math.min(best, performance.now() - t0);
            }
            r.times.push(best);
            r.problems['random 500/' + seed] = problems(nodes, layout);
            r.sizes['random 500/' + seed] = [layout.boxes.length, layout.edges.length, layout.edges.filter(e => e.back).length];
        }
        console.log(JSON.stringify(r));
    """, _rizin_prelude())
    assert {name: found for name, found in r["problems"].items() if found} == {}
    assert r["empty"] == [{"width": 0, "height": 0, "boxes": [], "edges": []}] * 2
    assert r["sizes"]["self loop"] == [1, 1, 1] and r["sizes"]["two in a loop"] == [3, 3, 1]
    assert r["sizes"]["odd entries"][:2] == [2, 1], "an odd entry became a block, or a duplicate edge stayed"
    # The random graphs have loops and branches
    assert all(r["sizes"][f"random 500/{seed}"][2] >= 20 for seed in (501, 502, 503)), r["sizes"]
    assert max(r["times"]) < 2000, f"500 blocks took {max(r['times']):.0f} ms"


def _graph_fixture():
    with open(GRAPH_FIXTURE, encoding="utf-8") as f:
        return json.load(f)


@needs_node
def test_rizin_graph_marks_current_block_and_colours_edges():
    """The brief, with the real answer of the graph route for sym.main of
    pipesim.exe: the block of the current address is marked; a conditional
    jump is green, its fall-through red, an unconditional edge neutral."""
    graph = _graph_fixture()
    r = _run(r"""
        const graph = GRAPH;
        const layout = rizinLayoutGraph(graph.nodes);
        const draw = current => { const el = document.createElement('div');
                                  el.innerHTML = rizinGraphSvg(layout, graph, { current, overview: false }); return el; };
        const kinds = el => ['jump', 'fail', 'plain'].filter(k => el.classList.contains('rizin-edge-' + k));
        const current = el => el.querySelectorAll('.rizin-block.current').map(b => b.getAttribute('data-addr'));
        const svg = draw('0x140001530');
        const root = svg.firstElementChild;
        console.log(JSON.stringify({
            svg: [root.tagName, root.getAttribute('width'), root.getAttribute('height'), layout.width, layout.height],
            blocks: svg.querySelectorAll('.rizin-block').map(b => b.getAttribute('data-addr')),
            current: [current(svg), current(draw(0x1400018a3)), current(draw('0x1400019ec')), current(draw('0x140001000')),
                      current(draw(null))],
            edges: svg.querySelectorAll('path.rizin-edge').map(e => [e.getAttribute('data-from'), e.getAttribute('data-to'), kinds(e)]),
            arrows: svg.querySelectorAll('path.rizin-arrow').map(kinds),
            texts: svg.querySelectorAll('.rizin-block').map(b => b.querySelectorAll('text').map(t => t.textContent)),
            titles: svg.querySelectorAll('.rizin-block').map(b => b.querySelector('title').textContent),
            up: layout.edges.filter(e => layout.boxes.find(b => b.offset === e.to).y < layout.boxes.find(b => b.offset === e.from).y)
                .map(e => [hex(e.from), hex(e.to), e.kind, e.back]),
        }));
    """.replace("GRAPH", json.dumps(graph)) + "\nfunction hex(a) { return '0x' + a.toString(16); }", SORT_DOM + _rizin_prelude())
    nodes = graph["nodes"]
    assert r["svg"][0] == "SVG" and r["svg"][1:3] == [str(r["svg"][3]), str(r["svg"][4])]
    assert r["blocks"] == [hex(n["offset"]) for n in nodes] and len(r["blocks"]) == 30
    # 0x140001530 lies in the block at 0x140001521 (171 bytes); the end of a block is the next one's
    assert r["current"] == [["0x140001521"], ["0x1400018a3"], ["0x1400019ec"], [], []]
    want = set()
    for n in nodes:
        both = n["jump"] is not None and n["fail"] is not None and n["jump"] != n["fail"]
        if n["jump"] is not None:
            want.add((hex(n["offset"]), hex(n["jump"]), "jump" if both else "plain"))
        if n["fail"] is not None and n["fail"] != n["jump"]:
            want.add((hex(n["offset"]), hex(n["fail"]), "fail" if both else "plain"))
    edges = {(a, b, k[0]) for a, b, k in r["edges"]}
    assert all(len(k) == 1 for _, _, k in r["edges"]), "an edge without its one colour"
    assert edges == want and len(r["edges"]) == len(want) == 44
    assert ("0x1400014b7", "0x140001521", "jump") in edges and ("0x1400014b7", "0x140001507", "fail") in edges
    assert ("0x1400017a6", "0x140001713", "plain") in edges and ("0x14000189e", "0x1400018a3", "plain") in edges
    assert sum(k == ["jump"] for _, _, k in r["edges"]) == sum(k == ["fail"] for _, _, k in r["edges"]) == 15
    assert r["arrows"] == [k for _, _, k in r["edges"]], "an arrow head in another colour than its edge"
    for n, texts, title in zip(nodes, r["texts"], r["titles"]):
        assert texts == [hex(n["offset"])] + n["lines"], hex(n["offset"])
        assert title == f"{hex(n['offset'])} · {len(n['lines'])} instruction{'s' if len(n['lines']) != 1 else ''}"
    # The loops of sym.main go up, around the outside of the blocks: the edges back to their headers
    assert {(a, b) for a, b, _, _ in r["up"]} == {("0x1400017a6", "0x140001713"), ("0x140001853", "0x1400017fc"),
                                                    ("0x1400017ee", "0x1400017fc"), ("0x1400019ec", "0x14000196f")}
    assert all(back for *_, back in r["up"])


@needs_node
def test_rizin_graph_escapes_text():
    """Instructions and names come from the file: they stay text in the
    graph (SVG text, titles, the head), and the long one is cut."""
    r = _scripted(r"""
        globalThis.innerWidth = 1920;
        rizinApplyCenterLayout();
        const nodes = [
            { offset: 0x1400014b7, size: 4, lines: [HOSTILE, '</text><script>alert(2)</script>', `a & b "q" 'r' <b>`, 'x'.repeat(10000)],
              jump: 0x1400014bb, fail: 0x1400014bc, cases: [] },
            { offset: 0x1400014bb, size: 1, lines: ['" onmouseover="alert(1)'], jump: null, fail: null, cases: [] },
            { offset: 0x1400014bc, size: 1, lines: [], jump: 0x1400014b7, fail: null, cases: [] },
        ];
        const S = { analysis: 'done', done: ['aaa'], graph: () => [200, { function: '<b>main</b><img src=x onerror=alert(3)>', nodes }] };
        serve('S1', S);
        opens['C:\\x\\s.exe'] = S;
        await openInRizin('C:\\x\\s.exe');
        await until(() => rizinState.landed, 'landed'); await quiet();
        const pane = $('rizin-graph');
        r.tags = [...new Set([...pane.walk()].map(e => e.tagName))].sort();
        r.handlers = [...pane.walk()].flatMap(e => Object.keys(e.attrs)).filter(a => a.startsWith('on'));
        r.texts = pane.querySelectorAll('text').map(t => t.textContent);
        r.titles = pane.querySelectorAll('title').map(t => t.textContent);
        r.addrs = [...pane.walk()].flatMap(e => ['data-addr', 'data-from', 'data-to'].map(k => e.getAttribute(k))).filter(a => a !== null);
        r.head = [$('rizin-graph-title').textContent, [...$('rizin-graph-title').walk()].length];
        r.cut = RIZIN_GRAPH.lineMax;
    """.replace("HOSTILE", json.dumps(HOSTILE)))
    assert "error" not in r, r.get("error")
    assert r["tags"] == ["G", "PATH", "RECT", "SVG", "TEXT", "TITLE"], "a text of the file became markup"
    assert r["handlers"] == []
    for text in (HOSTILE, "</text><script>alert(2)</script>", "a & b \"q\" 'r' <b>", '" onmouseover="alert(1)'):
        assert text in r["texts"], text
    long = next(t for t in r["texts"] if t.startswith("xxx"))
    assert long == "x" * (r["cut"] - 1) + "…", "the long line is not cut"
    assert r["titles"][0] == "0x1400014b7 · 4 instructions"
    assert all(re.fullmatch(r"0x[0-9a-f]+", a) for a in r["addrs"]) and len(r["addrs"]) >= 3
    assert r["head"] == ["GRAPH · <b>main</b><img src=x onerror=alert(3)>", 0], "the function name became markup"


@needs_node
def test_rizin_graph_overview_over_200_blocks():
    """The brief: from 200 blocks the graph shows as an overview without the
    instructions (no <text>); a click zooms into the part around it, where
    the blocks have their text, and the part holds what is in sight; a
    click there jumps. Below 200 blocks all the text is there."""
    r = _scripted(GRAPH_GEN + r"""
        globalThis.innerWidth = 1920;
        rizinApplyCenterLayout();
        FUNCS[2].size = 0x10000;
        const pane = $('rizin-graph');
        Object.defineProperties(pane, { clientWidth: { value: 800 }, clientHeight: { value: 600 } });
        pane.rect = { left: 0, top: 0, right: 800, bottom: 600, width: 800, height: 600 };
        const BIG = randomGraph(260, 7, 0x1400014b7), SMALL = randomGraph(199, 8, 0x140001490);
        const S = { analysis: 'done', done: ['aaa'],
                    graph: addr => [200, parseInt(addr, 16) >= 0x1400014b7 ? { function: 'sym.main', nodes: BIG }
                                                                           : { function: 'sym.watchdog', nodes: SMALL }] };
        serve('S1', S);
        opens['C:\\x\\s.exe'] = S;
        await openInRizin('C:\\x\\s.exe');
        await until(() => rizinState.landed, 'landed'); await quiet();
        const L = rizinState.graph.layout, v = { ...rizinState.graphView };
        r.overview = [pane.querySelectorAll('text').length, pane.querySelectorAll('.rizin-block').length,
                      pane.querySelectorAll('.rizin-block rect').length, rizinState.graphMode, $('rizin-graph-info').textContent,
                      pane.querySelectorAll('.rizin-block.current').map(b => b.getAttribute('data-addr'))];
        r.fits = [v.x >= -0.5, v.y >= -0.5, v.x + L.width * v.scale <= 800.5, v.y + L.height * v.scale <= 600.5, v.scale < 0.5];
        const pure = document.createElement('div');
        pure.innerHTML = rizinGraphSvg(L, rizinState.graph, { current: null, overview: true });
        r.pure = [pure.querySelectorAll('text').length, pure.querySelectorAll('.rizin-block').length, pure.querySelectorAll('title').length];

        // A click on a block of the overview zooms into the part around it, and does not jump
        const target = L.boxes[150];
        const sx = v.x + (target.x + target.w / 2) * v.scale, sy = v.y + (target.y + target.h / 2) * v.scale;
        const seeks = seeksOf('S1').length;
        dispatch('click', pane.querySelector(`.rizin-block[data-addr="${hex(target.offset)}"] rect`), { clientX: sx, clientY: sy, button: 0 });
        await quiet();
        const z = { ...rizinState.graphView };
        r.zoomed = [z.scale, Math.round(z.x + (target.x + target.w / 2) * z.scale), Math.round(z.y + (target.y + target.h / 2) * z.scale),
                    seeksOf('S1').length - seeks, rizinState.graphMode];
        const sec = rizinState.graphSection, seen = rizinGraphVisible(z, 800, 600);
        r.section = [sec.x <= seen.x, sec.y <= seen.y, sec.x + sec.w >= seen.x + seen.w, sec.y + sec.h >= seen.y + seen.h];
        const meets = b => b.x < sec.x + sec.w && b.x + b.w > sec.x && b.y < sec.y + sec.h && b.y + b.h > sec.y;
        const withText = pane.querySelectorAll('.rizin-block').filter(g => g.querySelectorAll('text').length).map(g => g.getAttribute('data-addr'));
        const inPart = L.boxes.filter(meets).map(b => hex(b.offset));
        r.text = [withText.length > 0, JSON.stringify(withText.sort()) === JSON.stringify(inPart.sort()), withText.includes(hex(target.offset)),
                  withText.length < L.boxes.length, pane.querySelectorAll('.rizin-block').length];

        // Now a click on a block jumps there
        dispatch('click', pane.querySelector(`.rizin-block[data-addr="${hex(target.offset)}"] rect`), { clientX: 400, clientY: 300, button: 0 });
        await until(() => rizinState.seek === hex(target.offset), 'the jump'); await quiet();
        r.jumped = [seeksOf('S1').slice(-1)[0], pane.querySelectorAll('.rizin-block.current').map(b => b.getAttribute('data-addr')),
                    marked()[0], count('GET', '/api/rizin/S1/graph')];
        // FIT shows the overview again
        click($('rizin-graph-fit')); await quiet();
        r.fit = [pane.querySelectorAll('text').length, rizinState.graphMode];
        // 199 blocks: the graph with all its text
        click(row('0x140001490'));
        await until(() => rizinState.graph && rizinState.graph.function === 'sym.watchdog', 'the small graph'); await quiet();
        r.small = [pane.querySelectorAll('.rizin-block').length, pane.querySelectorAll('.rizin-block').every(g => g.querySelectorAll('text').length > 0),
                   rizinState.graphMode, RIZIN_GRAPH_OVERVIEW];
    """)
    assert "error" not in r, r.get("error")
    texts, blocks, rects, mode, info, current = r["overview"]
    assert texts == 0 and blocks == rects == 260 and mode == "overview", r["overview"]
    assert "overview" in info and info.startswith("260 blocks"), info
    assert current == ["0x1400014b7"], "the current block is not marked in the overview"
    assert r["fits"] == [True] * 5, "the overview does not show the whole graph"
    assert r["pure"] == [0, 260, 260]
    scale, cx, cy, seeks, mode = r["zoomed"]
    assert scale == 1 and (cx, cy) == (400, 300) and seeks == 0 and mode == "detail", r["zoomed"]
    assert r["section"] == [True] * 4, "the part with text does not hold what is in sight"
    assert r["text"] == [True, True, True, True, 260], r["text"]
    seek, marked_now, listed, graphs = r["jumped"]
    assert seek == marked_now[0] and marked_now == [seek] and listed == "0x1400014b7" and graphs == 1
    assert r["fit"] == [0, "overview"]
    assert r["small"] == [199, True, "all", 200]


@needs_node
def test_rizin_graph_tabs_below_1400px():
    """The brief: below 1400 px of window width DISASSEMBLY (with DECOMPILER
    and HEX) and GRAPH are tabs of one area; the graph loads once it is
    shown; at 1400 px and wider the two halves stand side by side again."""
    r = _scripted(r"""
        const S = { analysis: 'done', done: ['aaa'] };
        serve('S1', S);
        opens['C:\\x\\s.exe'] = S;
        const center = $('rizin-center');
        const tab = name => document.querySelector(`[data-rizin-tab="${name}"]`);
        const state = () => [center.classList.contains('rizin-narrow'), center.classList.contains('rizin-show-graph'), !tab('graph').hidden,
                             ['disasm', 'decompiler', 'hex', 'graph'].filter(n => tab(n).getAttribute('aria-selected') === 'true'),
                             ['rizin-disasm', 'rizin-decompiler', 'rizin-hex'].filter(id => !$(id).hidden)];
        const resize = width => { globalThis.innerWidth = width; windowListeners.filter(l => l.type === 'resize').forEach(l => l.fn()); };
        r.start = state();                                  // initRizinTab ran at 1280 px
        await openInRizin('C:\\x\\s.exe');
        await until(() => rizinState.landed, 'landed'); await quiet();
        r.hidden = [count('GET', '/api/rizin/S1/graph'), $('rizin-graph').querySelectorAll('.rizin-block').length];
        click(tab('graph'));
        await until(() => count('GET', '/api/rizin/S1/graph') === 1, 'the graph once shown'); await quiet();
        r.graph = [...state(), $('rizin-graph').querySelectorAll('.rizin-block.current').map(b => b.getAttribute('data-addr')), rizinState.views.code];
        click(tab('decompiler'));
        r.code = [...state(), rizinState.views.code];
        click(tab('graph'));
        resize(1920);
        r.wide = state();
        resize(1399);
        r.narrowAgain = state();
        resize(1400);
        r.wideAgain = state();
        // A jump while the graph is hidden below 1400 px: no request until it is shown
        resize(1280);
        click(tab('disasm'));
        const graphs = count('GET', '/api/rizin/S1/graph');
        click(row('0x140001490'));
        await until(() => rizinState.seek === '0x140001490', 'jump'); await quiet();
        r.jumpHidden = count('GET', '/api/rizin/S1/graph') - graphs;
        click(tab('graph'));
        await until(() => count('GET', '/api/rizin/S1/graph') === graphs + 1, 'the graph of the new place'); await quiet();
        r.shownLater = $('rizin-graph').querySelectorAll('.rizin-block.current').map(b => b.getAttribute('data-addr'));
    """)
    assert "error" not in r, r.get("error")
    assert r["start"] == [True, False, True, ["disasm"], ["rizin-disasm"]]
    assert r["hidden"] == [0, 0], "the hidden graph was asked for"
    assert r["graph"] == [True, True, True, ["graph"], ["rizin-disasm"], ["0x1400014b7"], "disasm"]
    assert r["code"] == [True, False, True, ["decompiler"], ["rizin-decompiler"], "decompiler"]
    assert r["wide"] == [False, False, False, ["decompiler"], ["rizin-decompiler"]], "the halves did not come back"
    assert r["narrowAgain"] == [True, True, True, ["graph"], ["rizin-decompiler"]]
    assert r["wideAgain"] == [False, False, False, ["decompiler"], ["rizin-decompiler"]]
    assert r["jumpHidden"] == 0 and r["shownLater"] == ["0x140001490"]

    classic = _rules(STYLE_CSS)
    narrow = ".rizin-center.rizin-narrow"
    assert _declared(classic.get(narrow), "grid-template-columns") == "minmax(0, 1fr) auto"
    assert _declared(classic.get(narrow + " > .rizin-half"), "display") == "contents"
    assert _declared(classic.get(narrow + " > .rizin-split"), "display") == "none"
    assert _declared(classic.get(narrow + ":not(.rizin-show-graph) > .rizin-graph > *"), "display") == "none"
    assert _declared(classic.get(narrow + ".rizin-show-graph > .rizin-code > .rizin-view"), "display") == "none"
    assert _declared(classic.get(narrow + " .rizin-max-btn"), "display") == "none", "⇱ below 1400 px"


@needs_node
def test_rizin_graph_follows_the_seek():
    """The graph shows the function at the current place with its block
    marked; a click on a block jumps there (the other views follow); a jump
    inside the function moves the mark without asking again, a jump into
    another function loads its graph; a finished analysis step asks again;
    busy shows and is asked again; outside a function a note."""
    r = _scripted(r"""
        globalThis.innerWidth = 1920;
        rizinApplyCenterLayout();
        const pane = $('rizin-graph');
        Object.defineProperties(pane, { clientWidth: { value: 800 }, clientHeight: { value: 600 } });
        pane.rect = { left: 0, top: 0, right: 800, bottom: 600, width: 800, height: 600 };
        let busyOnce = false;
        const S = { analysis: 'done', done: ['aaa'],
                    graph: () => (busyOnce ? (busyOnce = false, [409, { busy: true, step: 'console' }]) : null) };
        serve('S1', S);
        opens['C:\\x\\s.exe'] = S;
        const graphs = () => count('GET', '/api/rizin/S1/graph');
        const shown = () => [rizinState.seek, pane.querySelectorAll('.rizin-block.current').map(b => b.getAttribute('data-addr')),
                             ...marked(), $('rizin-seek').value, graphs()];
        await openInRizin('C:\\x\\s.exe');
        await until(() => rizinState.landed, 'landed'); await quiet();
        r.landed = [...shown(), $('rizin-graph-title').textContent, $('rizin-graph-info').textContent,
                    pane.querySelectorAll('.rizin-block').map(b => b.getAttribute('data-addr'))];
        // A block half out of sight: a click on it jumps, and the graph stays where it is
        const half = rizinState.graph.layout.boxes.find(b => b.offset === 0x140001521);
        rizinState.graphView = { scale: 1, x: 800 - half.x - half.w / 2, y: 20 - half.y };
        rizinGraphApplyView();
        const placed = JSON.stringify(rizinState.graphView);
        dispatch('click', pane.querySelector('.rizin-block[data-addr="0x140001521"] text'), { clientX: 10, clientY: 10, button: 0 });
        await until(() => rizinState.seek === '0x140001521', 'block click'); await quiet();
        r.block = [...shown(), seeksOf('S1').slice(-1)[0], JSON.stringify(rizinState.graphView) === placed];
        // The same block from the disassembly: brought into sight
        click($('rizin-disasm').querySelector('.rizin-op[data-addr="0x1400014b7"] .rz-addr'));
        await until(() => rizinState.seek === '0x1400014b7', 'line click'); await quiet();
        rizinState.graphView = JSON.parse(placed);
        rizinGraphApplyView();
        click($('rizin-disasm').querySelector('.rizin-op[data-addr="0x140001521"] .rz-addr'));
        await until(() => rizinState.seek === '0x140001521', 'line click to the block'); await quiet();
        r.revealed = JSON.stringify(rizinState.graphView) !== placed && rizinState.graphView.x + half.x + half.w <= 800;
        click($('rizin-disasm').querySelector('.rizin-op[data-addr="0x1400014be"] .rz-addr'));
        await until(() => rizinState.seek === '0x1400014be', 'line click'); await quiet();
        r.line = shown();
        click(row('0x140001490'));
        await until(() => rizinState.seek === '0x140001490', 'function click'); await quiet();
        r.other = [...shown(), $('rizin-graph-title').textContent];
        $('rizin-seek').value = '0x140001499';
        click($('rizin-go'));
        await until(() => rizinState.seek === '0x140001499', 'GO'); await quiet();
        r.inside = shown();

        // A finished step of a Full analysis asks for the graph again
        Object.assign(S, { analysis: 'running', step: 'aac', done: ['aa'] });
        rizinState.analysis = { state: 'running', step: 'aac', done_steps: ['aa'], level: 'aaa', elapsed: 0, note: null };
        rizinPollSoon();
        await tick(20);
        const before = graphs();
        Object.assign(S, { analysis: 'done', step: null, done: ['aa', 'aac'] });
        await until(() => rizinState.analysis.state === 'done', 'done'); await quiet();
        r.step = graphs() - before;

        // Busy: said in the graph, asked again once rizin is free
        busyOnce = true;
        click(row('0x1400014b7'));
        await until(() => pane.textContent.includes('busy'), 'busy shown');
        r.busy = pane.textContent;
        await until(() => pane.querySelectorAll('.rizin-block.current').length === 1, 'the graph once rizin is free'); await quiet();
        r.free = [...shown(), rizinState.retry.size];

        // Outside a function
        $('rizin-seek').value = '0x140009000';
        click($('rizin-go'));
        await until(() => rizinState.seek === '0x140009000', 'GO outside'); await quiet();
        r.outside = [pane.textContent, pane.querySelectorAll('.rizin-block').length, $('rizin-graph-title').textContent,
                     $('rizin-graph-info').textContent];
    """)
    assert "error" not in r, r.get("error")
    main = ["0x1400014b7", "0x1400014be", "0x140001521"]
    assert r["landed"][:6] == ["0x1400014b7", ["0x1400014b7"], "0x1400014b7", "0x1400014b7", "sym.main", 1]
    assert r["landed"][6] == "GRAPH · sym.main" and r["landed"][7].startswith("3 blocks") and r["landed"][8] == main
    assert r["block"] == ["0x140001521", ["0x140001521"], "0x1400014b7", "0x140001521", "0x140001521", 1, "0x140001521",
                          True], "a click on a block did not jump there, the graph was asked for again, or it moved"
    assert r["revealed"] is True, "a jump from the disassembly left the block half out of sight"
    assert r["line"] == ["0x1400014be", ["0x1400014be"], "0x1400014b7", "0x1400014be", "0x1400014be", 1]
    assert r["other"] == ["0x140001490", ["0x140001490"], "0x140001490", "0x140001490", "sym.watchdog", 2,
                          "GRAPH · sym.watchdog"]
    assert r["inside"] == ["0x140001499", ["0x140001494"], "0x140001490", "0x140001499", "0x140001499", 2]
    assert r["step"] >= 1, "a finished step did not ask for the graph again"
    assert "busy (console)" in r["busy"]
    assert r["free"][:2] == ["0x1400014b7", ["0x1400014b7"]] and r["free"][-1] == 0
    text, blocks, title, info = r["outside"]
    assert "No function at 0x140009000" in text and blocks == 0 and title == "GRAPH" and info == ""


@needs_node
def test_rizin_graph_pan_zoom_fit_and_halves():
    """The brief's controls: dragging moves the graph (and does not jump),
    the wheel zooms around the mouse, − + around the middle, FIT shows it
    all; ⇱ gives one half the whole width and takes it back, and the line
    between the halves can be dragged (also with the keyboard), its place
    kept until the page is loaded again."""
    r = _scripted(r"""
        globalThis.innerWidth = 1920;
        rizinApplyCenterLayout();
        const pane = $('rizin-graph'), center = $('rizin-center'), split = $('rizin-split');
        Object.defineProperties(pane, { clientWidth: { value: 800 }, clientHeight: { value: 600 } });
        pane.rect = { left: 100, top: 50, right: 900, bottom: 650, width: 800, height: 600 };
        const S = { analysis: 'done', done: ['aaa'] };
        serve('S1', S);
        opens['C:\\x\\s.exe'] = S;
        await openInRizin('C:\\x\\s.exe');
        await until(() => rizinState.landed, 'landed'); await quiet();
        const view = () => ({ ...rizinState.graphView });
        const under = (v, cx, cy) => [(cx - v.x) / v.scale, (cy - v.y) / v.scale].map(n => Math.round(n * 100) / 100);
        const svg = () => pane.querySelector('svg');
        r.start = [view().scale, svg().style.transform];

        // The wheel zooms around the mouse
        let v = view();
        const point = under(v, 300 - 100, 250 - 50);
        const wheel = dispatch('wheel', svg(), { deltaY: -200, deltaMode: 0, clientX: 300, clientY: 250 });
        let w = view();
        r.wheel = [w.scale > v.scale, JSON.stringify(under(w, 200, 200)) === JSON.stringify(point), wheel.defaultPrevented,
                   svg().style.transform === `translate(${w.x}px, ${w.y}px) scale(${w.scale})`];
        dispatch('wheel', svg(), { deltaY: 100000, deltaMode: 0, clientX: 300, clientY: 250 });
        r.wheelOut = view().scale >= rizinGraphFitView(rizinState.graph.layout, 800, 600).scale * 0.5;

        // Dragging moves the graph; the click at its end does not jump
        click($('rizin-graph-fit'));
        v = view();
        const block = () => pane.querySelector('.rizin-block[data-addr="0x140001521"] rect');
        const seeks = seeksOf('S1').length;
        dispatch('pointerdown', block(), { clientX: 400, clientY: 300, button: 0, pointerId: 1 });
        dispatch('pointermove', block(), { clientX: 430, clientY: 320, button: 0, pointerId: 1 });
        dispatch('pointermove', block(), { clientX: 460, clientY: 340, button: 0, pointerId: 1 });
        dispatch('pointerup', block(), { clientX: 460, clientY: 340, button: 0, pointerId: 1 });
        dispatch('click', block(), { clientX: 460, clientY: 340, button: 0 });
        await quiet();
        w = view();
        r.drag = [w.x - v.x, w.y - v.y, w.scale === v.scale, seeksOf('S1').length - seeks];
        // A press let go outside the graph before it moved (no button held any more): a hover then moves nothing
        v = view();
        dispatch('pointerdown', block(), { clientX: 400, clientY: 300, button: 0, buttons: 1, pointerId: 1 });
        dispatch('pointermove', block(), { clientX: 402, clientY: 301, button: 0, buttons: 1, pointerId: 1 });
        dispatch('pointermove', block(), { clientX: 600, clientY: 500, button: -1, buttons: 0, pointerId: 1 });
        r.released = [JSON.stringify(view()) === JSON.stringify(v), rizinState.graphDrag];
        // A click without a drag jumps
        dispatch('pointerdown', block(), { clientX: 400, clientY: 300, button: 0, pointerId: 1 });
        dispatch('pointerup', block(), { clientX: 401, clientY: 300, button: 0, pointerId: 1 });
        dispatch('click', block(), { clientX: 401, clientY: 300, button: 0 });
        await until(() => rizinState.seek === '0x140001521', 'click'); await quiet();
        r.click = seeksOf('S1').length - seeks;

        // − + around the middle of the view, FIT shows the whole graph
        v = view();
        click($('rizin-graph-in'));
        w = view();
        r.plus = [Math.round(w.scale / v.scale * 1000) / 1000, JSON.stringify(under(w, 400, 300)) === JSON.stringify(under(v, 400, 300))];
        click($('rizin-graph-out')); click($('rizin-graph-out'));
        r.minus = Math.round(view().scale / w.scale * 1000) / 1000;
        click($('rizin-graph-fit'));
        const L = rizinState.graph.layout, f = view();
        r.fit = [f.scale <= 1, f.x >= 0 && f.x + L.width * f.scale <= 800.01, f.y >= 0 && f.y + L.height * f.scale <= 600.01,
                 Math.abs(f.x + L.width * f.scale / 2 - 400) < 0.01 && Math.abs(f.y + L.height * f.scale / 2 - 300) < 0.01];

        // ⇱ both ways, for each half
        const halves = () => [['rizin-max-code', 'rizin-max-graph'].filter(c => center.classList.contains(c)),
                              $('rizin-graph-max').textContent, $('rizin-graph-max').getAttribute('aria-pressed'),
                              $('rizin-code-max').textContent, $('rizin-code-max').getAttribute('aria-pressed')];
        click($('rizin-graph-max'));
        r.maxGraph = halves();
        click($('rizin-graph-max'));
        r.restored = halves();
        click($('rizin-code-max'));
        r.maxCode = halves();
        // While the graph is hidden a jump does not ask for it; shown again, it does
        const graphs = count('GET', '/api/rizin/S1/graph');
        click(row('0x140001490'));
        await until(() => rizinState.seek === '0x140001490', 'jump'); await quiet();
        r.hiddenJump = count('GET', '/api/rizin/S1/graph') - graphs;
        click($('rizin-code-max'));
        await until(() => count('GET', '/api/rizin/S1/graph') === graphs + 1, 'the graph shown again'); await quiet();
        r.back = [halves(), pane.querySelectorAll('.rizin-block.current').map(b => b.getAttribute('data-addr'))];

        // The line between the halves: dragged, with the keys, kept, and back to the start with a double click
        center.rect = { left: 300, top: 100, right: 1510, bottom: 900, width: 1210, height: 800 };
        dispatch('pointerdown', split, { clientX: 300 + 5 + 0.535 * 1200, clientY: 400, button: 0, pointerId: 2 });
        dispatch('pointermove', split, { clientX: 300 + 5 + 0.4 * 1200, clientY: 400, button: 0, pointerId: 2 });
        dispatch('pointerup', split, { clientX: 300 + 5 + 0.4 * 1200, clientY: 400, button: 0, pointerId: 2 });
        r.split = [center.style.gridTemplateColumns, split.getAttribute('aria-valuenow')];
        dispatch('pointerdown', split, { clientX: 700, clientY: 400, button: 0, pointerId: 2 });
        dispatch('pointermove', split, { clientX: 301, clientY: 400, button: 0, pointerId: 2 });
        dispatch('pointerup', split, { clientX: 301, clientY: 400, button: 0, pointerId: 2 });
        r.splitMin = center.style.gridTemplateColumns;
        dispatch('keydown', split, { key: 'ArrowRight' });
        r.key = center.style.gridTemplateColumns;
        click(row('0x1400014b7'));
        await until(() => rizinState.seek === '0x1400014b7', 'jump back'); await quiet();
        click($('rizin-graph-max'));
        r.splitMax = center.style.gridTemplateColumns;
        click($('rizin-graph-max'));
        r.splitKept = center.style.gridTemplateColumns;
        dispatch('dblclick', split, {});
        r.splitReset = [center.style.gridTemplateColumns, rizinState.layout.split];
    """)
    assert "error" not in r, r.get("error")
    assert r["start"][0] == 1 and r["start"][1].startswith("translate("), r["start"]
    assert r["wheel"] == [True, True, True, True], "the wheel did not zoom around the mouse"
    assert r["wheelOut"] is True, "the wheel zoomed out without end"
    assert r["drag"] == [60, 40, True, 0], "a drag did not move the graph, or it jumped"
    assert r["released"] == [True, None], "the graph moved with no button held"
    assert r["click"] == 1
    assert r["plus"] == [1.25, True] and r["minus"] == 0.64
    assert r["fit"] == [True, True, True, True]
    assert r["maxGraph"] == [["rizin-max-graph"], "⇲", "true", "⇱", "false"]
    assert r["restored"] == [[], "⇱", "false", "⇱", "false"]
    assert r["maxCode"] == [["rizin-max-code"], "⇱", "false", "⇲", "true"]
    assert r["hiddenJump"] == 0
    assert r["back"] == [[[], "⇱", "false", "⇱", "false"], ["0x140001490"]]
    assert r["split"] == ["minmax(0, 0.4fr) 10px minmax(0, 0.6fr)", "40"]
    min_frac = round(280 / 1200, 4)
    assert r["splitMin"] == f"minmax(0, {min_frac}fr) 10px minmax(0, {round(1 - min_frac, 4)}fr)", "a half got too narrow"
    assert r["key"] == f"minmax(0, {round(min_frac + 0.05, 4)}fr) 10px minmax(0, {round(1 - min_frac - 0.05, 4)}fr)"
    assert r["splitMax"] == "" and r["splitKept"] == r["key"], "the place of the line was lost"
    assert r["splitReset"] == ["", None]


@needs_node
def test_rizin_jump_to_the_same_place_reveals_it():
    """Controller ruling R1: a jump to the address already shown brings it
    back into sight (the user scrolled the disassembly or moved the graph
    away); a jump to a line in sight scrolls nothing, nor does a step of the
    analysis."""
    r = _scripted(r"""
        Object.defineProperties(Element.prototype, {
            offsetTop: { configurable: true, get() { return this.parentNode ? this.parentNode.children.indexOf(this) * 20 : 0; } },
            offsetHeight: { configurable: true, get() { return 20; } },
            clientHeight: { configurable: true, get() { return 200; } },
        });
        globalThis.innerWidth = 1920;
        rizinApplyCenterLayout();
        const disasm = $('rizin-disasm'), pane = $('rizin-graph');
        disasm.scrollTop = 0;
        Object.defineProperties(pane, { clientWidth: { value: 800 }, clientHeight: { value: 600 } });
        pane.rect = { left: 0, top: 0, right: 800, bottom: 600, width: 800, height: 600 };
        const ops = Array.from({ length: 40 }, (_, i) => op(0x1400014b7 + i * 4, 4, 'nop', 'nop'));
        const S = { analysis: 'done', done: ['aaa'], disasm: () => [200, { function: 'sym.main', ops, more: false }] };
        serve('S1', S);
        opens['C:\\x\\s.exe'] = S;
        await openInRizin('C:\\x\\s.exe');
        await until(() => rizinState.landed, 'landed'); await quiet();
        const box = () => rizinState.graph.layout.boxes.find(b => b.offset === 0x1400014b7);
        const inSight = () => { const v = rizinState.graphView, b = box();
                                return v.x + b.x * v.scale >= 0 && v.x + (b.x + b.w) * v.scale <= 800 && v.y + b.y * v.scale >= 0
                                    && v.y + (b.y + b.h) * v.scale <= 600; };
        r.landed = [disasm.scrollTop, inSight()];
        const away = () => {
            disasm.scrollTop = 400;
            rizinState.graphView = { scale: 1, x: -4000, y: -4000 };
            rizinGraphApplyView();
        };
        away();
        const pages = count('GET', '/api/rizin/S1/disasm'), graphs = count('GET', '/api/rizin/S1/graph');
        click(row('0x1400014b7'));
        await until(() => seeksOf('S1').length === 2, 'the jump to the same function'); await quiet();
        r.functionClick = [disasm.scrollTop, inSight(), count('GET', '/api/rizin/S1/disasm') - pages, count('GET', '/api/rizin/S1/graph') - graphs];
        away();
        $('rizin-seek').value = '0x1400014b7';
        click($('rizin-go'));
        await until(() => seeksOf('S1').length === 3, 'GO to the same address'); await quiet();
        r.go = [disasm.scrollTop, inSight()];
        // A line in sight: nothing scrolls
        disasm.scrollTop = 100;
        const view = JSON.stringify(rizinState.graphView);
        click(disasm.querySelector('.rizin-op[data-addr="0x1400014cf"] .rz-addr'));
        await until(() => rizinState.seek === '0x1400014cf', 'line click'); await quiet();
        r.inSight = [disasm.scrollTop, JSON.stringify(rizinState.graphView) === view];
        // A step of the analysis keeps the places the user chose
        disasm.scrollTop = 300;
        rizinState.graphView = { scale: 1, x: -4000, y: -4000 };
        rizinGraphApplyView();
        Object.assign(S, { analysis: 'running', step: 'aac', done: ['aa'] });
        rizinState.analysis = { state: 'running', step: 'aac', done_steps: ['aa'], level: 'aaa', elapsed: 0, note: null };
        rizinPollSoon();
        await tick(20);
        Object.assign(S, { analysis: 'done', step: null, done: ['aa', 'aac'] });
        await until(() => rizinState.analysis.state === 'done', 'done'); await quiet();
        r.step = [disasm.scrollTop, rizinState.graphView.x, rizinState.graphView.y];
    """)
    assert "error" not in r, r.get("error")
    assert r["landed"] == [0, True]
    assert r["functionClick"] == [0, True, 0, 0], "a jump to the place shown left it out of sight"
    assert r["go"] == [0, True]
    assert r["inSight"] == [100, True], "a jump to a line in sight scrolled"
    assert r["step"] == [300, -4000, -4000], "a step of the analysis moved the views"


@needs_node
def test_rizin_forced_reload_dropped_by_a_jump_is_asked_again():
    """Controller ruling R2: a forced reload (a finished analysis step)
    whose answer is dropped because the user jumped meanwhile is asked for
    again, still forced, also when the new place lies in the page and the
    graph already shown (the jump itself then asks rizin nothing)."""
    r = _scripted(r"""
        globalThis.innerWidth = 1920;
        rizinApplyCenterLayout();
        const pane = $('rizin-graph');
        Object.defineProperties(pane, { clientWidth: { value: 800 }, clientHeight: { value: 600 } });
        let version = 0, slow = false;
        const page = () => ({ function: 'sym.main', more: false,
                              ops: OPS['sym.main'].map((o, i) => (i ? o : { ...o, comment: `version ${version}` })) });
        const blocks = () => ({ function: 'sym.main',
                                nodes: GRAPHS['sym.main'].map((b, i) => (i ? b : { ...b, lines: [...b.lines, `version ${version}`] })) });
        const S = { analysis: 'done', done: ['aaa'], disasm: () => [200, page(), slow ? 40 : 1], graph: () => [200, blocks(), slow ? 40 : 1] };
        serve('S1', S);
        opens['C:\\x\\s.exe'] = S;
        const shows = (id, text) => $(id).textContent.includes(text);
        await openInRizin('C:\\x\\s.exe');
        await until(() => rizinState.landed, 'landed'); await quiet();
        r.landed = [shows('rizin-disasm', 'version 0'), shows('rizin-graph', 'version 0')];
        // A Full analysis; aac ends and both views are asked for again, forced, slowly
        Object.assign(S, { analysis: 'running', step: 'aac', done: ['aa'] });
        rizinState.analysis = { state: 'running', step: 'aac', done_steps: ['aa'], level: 'aaa', elapsed: 0, note: null };
        rizinPollSoon();
        await tick(20);
        version = 1;
        slow = true;
        const pages = count('GET', '/api/rizin/S1/disasm'), graphs = count('GET', '/api/rizin/S1/graph');
        Object.assign(S, { step: 'aar', done: ['aa', 'aac'] });
        await until(() => flying('/api/rizin/S1/disasm') && flying('/api/rizin/S1/graph'), 'the forced reloads in flight');
        slow = false;
        // The user jumps to a line of the same page and block meanwhile: the jump itself asks for nothing
        click($('rizin-disasm').querySelector('.rizin-op[data-addr="0x1400014b9"] .rz-addr'));
        await until(() => rizinState.seek === '0x1400014b9', 'the jump');
        r.jump = [count('GET', '/api/rizin/S1/disasm') - pages, count('GET', '/api/rizin/S1/graph') - graphs];
        await until(() => shows('rizin-disasm', 'version 1') && shows('rizin-graph', 'version 1'), 'the dropped reloads asked again');
        r.again = [count('GET', '/api/rizin/S1/disasm') - pages, count('GET', '/api/rizin/S1/graph') - graphs, rizinState.seek, marked()[1]];
        Object.assign(S, { analysis: 'done', step: null, done: ['aa', 'aac', 'aar'] });
        await until(() => rizinState.analysis.state === 'done', 'done'); await quiet();
        r.end = rizinState.retry.size;
    """)
    assert "error" not in r, r.get("error")
    assert r["landed"] == [True, True]
    assert r["jump"] == [1, 1], "the jump asked rizin for the page or graph it had"
    assert r["again"] == [2, 2, "0x1400014b9", "0x1400014b9"]
    assert r["end"] == 0


@needs_node
def test_rizin_graph_puts_the_entry_on_top():
    """The route sorts the blocks by address, but a function's entry need
    not be its lowest block: the loader hands the entry to the layout first,
    so that a loop through the entry does not put a block above it."""
    r = _scripted(r"""
        globalThis.innerWidth = 1920;
        rizinApplyCenterLayout();
        const pane = $('rizin-graph');
        Object.defineProperties(pane, { clientWidth: { value: 800 }, clientHeight: { value: 600 } });
        const nodes = [block(0x1400014b0, 7, ['inc eax', 'jmp 0x1400014b7'], 0x1400014b7),
                       block(0x1400014b7, 7, ['test eax, eax', 'jnz 0x1400014b0'], 0x1400014b0, 0x1400014be),
                       block(0x1400014be, 1, ['ret'])];
        const S = { analysis: 'done', done: ['aaa'], graph: () => [200, { function: 'sym.main', nodes }] };
        serve('S1', S);
        opens['C:\\x\\s.exe'] = S;
        await openInRizin('C:\\x\\s.exe');
        await until(() => rizinState.landed && rizinState.graph, 'landed'); await quiet();
        const y = a => rizinState.graph.layout.boxes.find(b => b.offset === a).y;
        r.order = [y(0x1400014b7) < y(0x1400014b0), y(0x1400014b0) <= y(0x1400014be),
                   rizinState.graph.layout.edges.filter(e => e.back).map(e => [hex(e.from), hex(e.to)])];
        r.sorted = rizinState.graph.nodes.map(b => hex(b.offset));
    """.replace("hex(", "rizinHex("))
    assert "error" not in r, r.get("error")
    assert r["order"] == [True, True, [["0x1400014b0", "0x1400014b7"]]], "a block of the loop is above the entry"
    assert r["sorted"] == ["0x1400014b0", "0x1400014b7", "0x1400014be"], "the graph's blocks lost their order"


# The parts of the graph whose look each theme sets
GRAPH_THEMED = [".rizin-graph-view", ".rizin-block-box", ".rizin-block.current .rizin-block-box", ".rizin-block-addr",
                ".rizin-block-line", ".rizin-tool", ".rizin-graph-info", ".rizin-graph-overview .rizin-block-box"]
# The colours of the edges as in the mockup (rizin-c-graph-v3.html): classes with theme variables
EDGE_COLOURS = {".rizin-edge-jump": ("--accent-green", "#39d98a"), ".rizin-edge-fail": ("--accent-red", "#ff3b3b"),
                ".rizin-edge-plain": ("--text-muted", "#8a7fb0")}


def test_rizin_graph_layout_and_themes():
    html = _read(INDEX_HTML)
    tab = _tab_markup("rizin")
    for i in ("rizin-graph-title", "rizin-graph-out", "rizin-graph-in", "rizin-graph-fit", "rizin-graph-max", "rizin-code-max",
              "rizin-graph-info"):
        assert f'id="{i}"' in tab, i
    assert 'onclick="rizinOnGraphClick(event)"' in tab, "clicks in the graph go to one delegated handler"
    head = tab[tab.index('id="rizin-graph-half"'):tab.index('id="rizin-graph"')]
    assert re.search(r'<h3 class="rizin-panel-title" data-info="[^"]+"><span id="rizin-graph-title">GRAPH</span></h3>', head)
    assert [re.sub(r"\s+", " ", t) for t in re.findall(r'class="rizin-tool[^"]*"[^>]*>([^<]+)<', head)] == ["−", "+", "FIT", "⇱"]
    assert re.search(r'id="rizin-split"[^>]*tabindex="0"', tab), "the line between the halves takes the keyboard"

    classic, cyberpunk = _rules(STYLE_CSS), _rules(THEME_CSS)
    prefix = '[data-theme="cyberpunk"] '
    missing = [s for s in GRAPH_THEMED if s not in classic] + [prefix + s for s in GRAPH_THEMED if prefix + s not in cyberpunk]
    assert not missing, "parts of the graph without a rule in one theme:\n" + "\n".join(missing)
    for selector, (variable, colour) in EDGE_COLOURS.items():
        assert _declared(classic.get(selector), "color") == f"var({variable})", selector
        assert _cyberpunk_palette()[variable].lower() == colour, f"{selector}: {variable} is not the mockup's {colour}"
        assert not _declared(cyberpunk.get(prefix + selector), "color"), "Cyberpunk changes the meaning of a colour"
    assert _declared(classic.get(".rizin-edge"), "stroke") == "currentColor"
    assert _declared(classic.get(".rizin-arrow"), "fill") == "currentColor"
    view = classic.get(".rizin-graph-view", "")
    assert _declared(view, "overflow") == "hidden" and _declared(view, "touch-action") == "none"
    assert _declared(classic.get(".rizin-graph-svg"), "transform-origin") == "0 0"
    assert _declared(classic.get(".rizin-split"), "cursor") == "col-resize"
    for selector in (".rizin-center.rizin-max-graph > .rizin-code", ".rizin-center.rizin-max-graph > .rizin-split",
                     ".rizin-center.rizin-max-code > .rizin-graph", ".rizin-center.rizin-max-code > .rizin-split"):
        assert _declared(classic.get(selector), "display") == "none", selector
    assert "style.css?v=61" not in html and "theme-cyberpunk.css?v=21" not in html and "app.js?v=89" not in html, \
        "asset versions not raised"


# --- Task 6: the console, XREFS, STRINGS, IMPORTS and the right-click menu ---------

@needs_node
def test_rizin_ansi_output_is_text():
    """The brief: rizin's console output keeps its colours (16, 256 and 24 bits) as theme classes, and
    bold; every other escape sequence goes, OSC 8 hyperlinks too, and the text is escaped, so nothing of
    it becomes markup or a link. Broken or endless sequences take linear time."""
    r = _run(r"""
        const E = '\x1b';
        const box = html => { const el = document.createElement('div'); el.innerHTML = html; return el; };
        const input = `${E}]8;;javascript:alert(1)${E}\\x${E}]8;;${E}\\ <script>alert(2)</script> `
            + `${E}[38;2;19;161;14m0x1400014b7${E}[0m ${E}[1;38;2;22;198;12mcall${E}[0m ${E}[1mbold${E}[22m plain `
            + `${E}[?25l${E}[2K${E}(B${E}[12;34H${E}]0;a title\x07${E}P1$r${E}\\${E}[5n${E}c${E}[3;1;4;2;7;8;9mall${E}[0m `
            + `${E}[31mred${E}[39m ${E}[38;5;196mcube${E}[0m ${E}[38;5;244mgrey${E}[0m ${E}[48;5;21mback${E}[49m `
            + `${E}[38:2::58:150:221mcolon${E}[m ${E}[94mbright${E}[0m ${E}[38;5;3myellow${E}[0m \r\x07\x00tab\there\nline`;
        const html = rizinAnsiHtml(input);
        const el = box(html);
        const elements = [...el.walk()];
        const classOf = word => elements.filter(e => e.textContent.split(/\s+/).includes(word)).map(e => e.className);
        const r = {
            text: el.textContent,
            tags: [...new Set(elements.map(e => e.tagName))],
            attrs: [...new Set(elements.flatMap(e => Object.keys(e.attrs)))],
            classes: [...new Set(elements.flatMap(e => e.className.split(' ')))].sort(),
            words: Object.fromEntries(['0x1400014b7', 'call', 'bold', 'all', 'red', 'cube', 'grey', 'back', 'colon', 'bright',
                                       'yellow', 'plain'].map(w => [w, classOf(w)])),
            href: html.includes('href') || html.includes('javascript'),
            palette: RIZIN_ANSI.map(([, red, green, blue]) => rizinAnsiColor(red, green, blue)),
            bad: [rizinAnsiColor(256, 0, 0), rizinAnsiColor(NaN, 0, 0), rizinAnsi256(256), rizinAnsi256(-1), rizinAnsi256(1.5)],
            merged: rizinAnsiHtml(`${E}[31ma${E}[0m${E}[31mb${E}[0m`),
            plain: rizinAnsiHtml('a < b & "c"'),
            visible: rizinVisibleText('a\nb\tc\x1b\x7f\u009b\r'),
        };
        const timed = text => {
            // The best of three runs after a warm-up: one cold sample measures node's JIT and the
            // machine's load as much as the patterns (follow-up finding 3). What is pinned is that the
            // patterns stay linear; super-linear ones take seconds to minutes on these inputs.
            rizinAnsiHtml(text);
            let best = Infinity, out = '';
            for (let i = 0; i < 3; i++) {
                const t0 = performance.now();
                out = rizinAnsiHtml(text);
                best = Math.min(best, performance.now() - t0);
            }
            return [best, box(out).textContent.length];
        };
        r.long = [timed(`${E}[`.repeat(100000)), timed(`${E}]`.repeat(100000)), timed(`${E}]8;;` + 'a'.repeat(300000)),
                  timed(`${E}[38;2;` + '1;'.repeat(100000) + 'mX'), timed(`${E}[31ma${E}[0m `.repeat(50000)),
                  timed(`${E}P` + 'x'.repeat(300000)), timed('<'.repeat(300000))];
        console.log(JSON.stringify(r));
    """, SORT_DOM + _rizin_prelude())
    assert r["text"] == ("x <script>alert(2)</script> 0x1400014b7 call bold plain all red cube grey back colon bright "
                         "yellow tab\there\nline"), "an escape sequence or a control character came through"
    assert r["tags"] == ["SPAN"] and r["attrs"] == ["class"], "a tag or an attribute from the output"
    assert r["href"] is False, "the hyperlink came through"
    names = ["black", "red", "green", "yellow", "blue", "magenta", "cyan", "white", "gray", "bright-red", "bright-green",
             "bright-yellow", "bright-blue", "bright-magenta", "bright-cyan", "bright-white"]
    allowed = {f"rz-ansi-{n}" for n in names} | {f"rz-ansi-bg-{n}" for n in names[:8]} | \
        {"rz-ansi-bold", "rz-ansi-dim", "rz-ansi-italic", "rz-ansi-under"}
    assert set(r["classes"]) <= allowed, set(r["classes"]) - allowed
    assert r["words"] == {
        "0x1400014b7": ["rz-ansi-green"], "call": ["rz-ansi-bright-green rz-ansi-bold"], "bold": ["rz-ansi-bold"],
        "all": ["rz-ansi-bold rz-ansi-dim rz-ansi-italic rz-ansi-under"], "red": ["rz-ansi-red"],
        "cube": ["rz-ansi-red"], "grey": ["rz-ansi-gray"], "back": ["rz-ansi-bg-blue"], "colon": ["rz-ansi-cyan"],
        "bright": ["rz-ansi-bright-blue"], "yellow": ["rz-ansi-yellow"], "plain": []}
    # rizin's own theme writes the 16 colours in 24 bits: each finds its own class
    assert r["palette"] == list(range(16))
    assert r["bad"] == [None] * 5
    assert r["merged"] == '<span class="rz-ansi-red">ab</span>', "the same look in two spans"
    assert r["plain"] == "a &lt; b &amp; &quot;c&quot;"
    assert r["visible"] == "a\\nb\\tc\\x1b\\x7f\\x9b\\r"
    assert [length for _, length in r["long"]] == [0, 0, 0, 1, 100000, 0, 300000]
    assert max(ms for ms, _ in r["long"]) < 2000, r["long"]


@needs_node
def test_rizin_console_history_completion_and_sync():
    """The brief: the prompt shows the current address; ↑ ↓ walk the history and back to what was being
    typed; Tab completes commands of a fixed list and function and flag names (sym.ma to sym.main), lists
    them when they share no more, and leaves an empty line to the focus; after each command the views take
    seek and function from the answer, so s sym.watchdog moves the list, the disassembly and SEEK; a
    command that renames (changed) draws the views again at the same place."""
    r = _scripted(r"""
        const S = { analysis: 'done', done: ['aaa'] };
        serve('S1', S);
        opens['C:\\x\\s.exe'] = S;
        Element.prototype.setSelectionRange = function (a, b) { this.selectionStart = a; this.selectionEnd = b; };
        r.before = $('rizin-prompt').textContent;
        await openInRizin('C:\\x\\s.exe');
        await until(() => rizinState.landed, 'landed'); await quiet();
        const input = $('rizin-console-input'), out = $('rizin-console-out');
        const key = (k, extra) => dispatch('keydown', input, { key: k, ...extra });
        const type = (text, caret = text.length) => { input.value = text; input.selectionStart = input.selectionEnd = caret; };
        const consoles = () => count('POST', '/api/rizin/S1/console');
        const run = async text => {
            const n = consoles();
            type(text);
            r.enter = key('Enter').defaultPrevented;
            await until(() => consoles() === n + 1 && !flying('/api/rizin/S1/console'), text);
            await quiet();
        };
        const listed = () => out.querySelectorAll('.rizin-console-complete').map(e => e.textContent).slice(-1)[0];
        r.prompt = $('rizin-prompt').textContent;
        await run('afl~main');
        await run('pdf @ sym.main');
        r.cleared = input.value;
        const pages = count('GET', '/api/rizin/S1/disasm');
        await run('s sym.watchdog');
        r.sync = [rizinState.seek, rizinState.func, $('rizin-seek').value, marked(), $('rizin-prompt').textContent,
                  rizinState.history.slice(), count('GET', '/api/rizin/S1/disasm') - pages, rizinState.jumpFrom];
        r.echo = out.querySelectorAll('.rizin-console-cmd').map(e => e.textContent);
        r.texts = out.querySelectorAll('.rizin-console-text').map(e => e.textContent);
        r.sent = calls.filter(c => c[1] === '/api/rizin/S1/console').map(c => c[2]);

        // ↑ ↓: the history, then back to what was being typed
        type('p');
        r.walk = ['ArrowUp', 'ArrowUp', 'ArrowUp', 'ArrowUp', 'ArrowDown', 'ArrowDown', 'ArrowDown', 'ArrowDown']
            .map(k => [key(k).defaultPrevented, input.value]);

        // Tab: a name, from the function list and the flags; once they share no more, they are listed
        type('pdf @ sym.ma');
        r.tabPrevented = key('Tab').defaultPrevented;
        await until(() => input.value !== 'pdf @ sym.ma', 'completed'); await quiet();
        r.name = [input.value, input.selectionStart];
        key('Tab');
        await until(() => listed(), 'the names listed'); await quiet();
        r.names = [input.value, listed()];
        r.flags = calls.filter(c => c[1].startsWith('/api/rizin/S1/flags')).map(c => c[1]);
        // Commands of the fixed list: one completes with a space, several are listed
        type('axt');
        key('Tab'); await quiet();
        r.command = input.value;
        type('ax');
        key('Tab'); await quiet();
        r.commands = [input.value, listed()];
        // In the middle of a line, and the command after a ';'
        type('s sym.wat; pdf', 9);
        key('Tab');
        await until(() => input.value !== 's sym.wat; pdf', 'in the middle'); await quiet();
        r.middle = [input.value, input.selectionStart];
        type('afl;pd');
        key('Tab'); await quiet();
        r.second = [input.value, listed()];
        r.flagsAfter = calls.filter(c => c[1].startsWith('/api/rizin/S1/flags')).length;
        // Typed on while the names are asked for: the late answer changes nothing
        S.flagsDelay = 30;
        type('pdf @ sym.ma');
        key('Tab');
        await until(() => flying('/api/rizin/S1/flags'), 'names asked for');
        type('pdf @ sym.w');
        await tick(60); await quiet();
        r.late = input.value;
        S.flagsDelay = 1;
        // An empty line: Tab moves the focus as everywhere
        type('');
        r.empty = key('Tab').defaultPrevented;

        // A rename in the console: the views again at the same place, SEEK and the list with the new name
        const lists = count('GET', '/api/rizin/S1/functions'), before = count('GET', '/api/rizin/S1/disasm');
        await run('afn tdc_watch');
        r.renamed = [rizinState.seek, rizinState.func, $('rizin-seek').value,
                     $('rizin-fn-list').querySelector('.rizin-fn.current .rizin-fn-name').textContent,
                     count('GET', '/api/rizin/S1/functions') - lists, count('GET', '/api/rizin/S1/disasm') - before,
                     $('rizin-code-title').textContent, rizinState.history.length];
        // A quick command runs at once
        click(document.querySelector('[data-cmd="axt"]'));
        await until(() => consoles() === 5 && !flying('/api/rizin/S1/console'), 'quick'); await quiet();
        r.quick = [calls.filter(c => c[1] === '/api/rizin/S1/console').slice(-1)[0][2].cmd, document.activeElement === input];
    """)
    assert "error" not in r, r.get("error")
    assert r["before"] == "[-]>" and r["prompt"] == "[0x1400014b7]>"
    assert r["enter"] is True and r["cleared"] == ""
    watchdog = ["0x140001490", "0x140001490"]
    assert r["sync"] == ["0x140001490", "sym.watchdog", "sym.watchdog", watchdog, "[0x140001490]>",
                         ["0x1400014b7", "0x140001490"], 1, "console"], "the views did not follow the console"
    assert r["echo"] == ["[0x1400014b7]> afl~main", "[0x1400014b7]> pdf @ sym.main", "[0x1400014b7]> s sym.watchdog"]
    assert r["texts"][:2] == ["fake output for: afl~main\n", "fake output for: pdf @ sym.main\n"]
    assert r["sent"] == [{"cmd": "afl~main"}, {"cmd": "pdf @ sym.main"}, {"cmd": "s sym.watchdog"}]
    assert r["walk"] == [[True, "s sym.watchdog"], [True, "pdf @ sym.main"], [True, "afl~main"], [True, "afl~main"],
                         [True, "pdf @ sym.main"], [True, "s sym.watchdog"], [True, "p"], [True, "p"]]
    assert r["tabPrevented"] is True
    assert r["name"] == ["pdf @ sym.main", len("pdf @ sym.main")], "Tab did not complete sym.ma to sym.main"
    assert r["names"] == ["pdf @ sym.main", "sym.main  sym.mainCRTStartup"]
    assert r["flags"] == ["/api/rizin/S1/flags?q=sym.ma&limit=200", "/api/rizin/S1/flags?q=sym.main&limit=200"]
    assert r["command"] == "axt " and r["commands"] == ["ax", "axf  axt"]
    assert r["middle"] == ["s sym.watchdog; pdf", len("s sym.watchdog")]
    assert r["second"][0] == "afl;pd" and r["second"][1].split("  ")[:3] == ["pd", "pdf", "pdg"]
    assert r["flagsAfter"] == 3, "a command was completed with flag names"
    assert r["late"] == "pdf @ sym.w", "a late answer completed what was typed over"
    assert r["empty"] is False, "Tab on an empty line kept the focus"
    assert r["renamed"] == ["0x140001490", "tdc_watch", "tdc_watch", "tdc_watch", 1, 1, "tdc_watch", 2], \
        "a rename in the console did not reach the views"
    assert r["quick"] == ["axt", True]


@needs_node
def test_rizin_refused_command_shows_reason():
    """The brief: a refused command shows the server's reason and moves nothing; busy gives a hint (while
    the analysis runs: renames and comments once it is done); an error, a cut output and the end of the
    session say so; HTML in the output stays text."""
    r = _scripted(r"""
        const S = { analysis: 'done', done: ['aaa'] };
        serve('S1', S);
        opens['C:\\x\\s.exe'] = S;
        await openInRizin('C:\\x\\s.exe');
        await until(() => rizinState.landed, 'landed'); await quiet();
        const input = $('rizin-console-input'), out = $('rizin-console-out');
        const consoles = () => count('POST', '/api/rizin/S1/console');
        // While the analysis runs the poll goes on: then only until the answer is drawn
        const run = async (text, running = false) => {
            const n = consoles();
            input.value = text;
            dispatch('keydown', input, { key: 'Enter' });
            await until(() => consoles() === n + 1 && !flying('/api/rizin/S1/console'), text);
            if (running) await tick(5);
            else await quiet();
        };
        const last = () => {
            const entry = out.querySelectorAll('.rizin-console-entry').slice(-1)[0], text = entry.querySelector('.rizin-console-text');
            return [entry.querySelector('.rizin-console-cmd').textContent, text.textContent, text.className];
        };
        const views = () => calls.filter(c => /\/(disasm|graph|functions|seek)/.test(c[1])).length;
        const n = views();
        await run('!calc');
        r.refused = [...last(), views() - n, rizinState.seek, rizinState.console.history.slice(-1)[0], $('rizin-state').hidden];

        // Busy while the analysis runs, then because of another request
        S.console = () => [409, { busy: true, step: 'aaa' }];
        Object.assign(S, { analysis: 'running', step: 'aaa', done: [] });
        rizinState.analysis = { state: 'running', step: 'aaa', done_steps: [], level: 'aaa', elapsed: 0, note: null };
        await run('afn early', true);
        r.analysing = last();
        Object.assign(S, { analysis: 'done', step: null, done: ['aaa'] });
        await until(() => rizinState.analysis.state === 'done', 'done'); await quiet();
        S.console = () => [409, { busy: true, step: 'view' }];
        await run('afl');
        r.busy = last();
        S.console = () => [500, { error: 'rizin answered something unexpected: <x>' }];
        await run('afl');
        r.broken = last();
        S.console = () => [200, { output: '<img src=x onerror=alert(1)>\x1b[31mred\x1b[0m\n' + 'A'.repeat(50), seek: 0x1400014b7,
                                  function: 'sym.main', truncated: true, changed: false }];
        await run('pd 9999');
        r.cut = [last()[1], out.querySelectorAll('.rizin-console-cut').map(e => e.textContent),
                 [...out.walk()].filter(e => !['DIV', 'SPAN'].includes(e.tagName)).length,
                 out.querySelectorAll('.rz-ansi-red').map(e => e.textContent)];
        r.history = rizinState.console.history.slice();
        S.console = () => [404, { error: 'session ended' }];
        await run('afl');
        r.ended = [last()[1], $('rizin-state').textContent];
    """)
    assert "error" not in r, r.get("error")
    assert r["refused"] == ["[0x1400014b7]> !calc", "refused: '!' is not allowed: no shell commands",
                            "rizin-console-text rizin-console-refused", 0, "0x1400014b7", "!calc", True]
    assert r["analysing"][1] == ("busy: the analysis runs (aaa). Commands run between its steps, renames and comments "
                                 "once it is done.") and r["analysing"][2].endswith("rizin-console-busy")
    assert r["busy"][1] == "busy: rizin works on another request (view); try again in a moment."
    assert r["broken"][1] == "rizin answered something unexpected: <x>" and r["broken"][2].endswith("rizin-console-error")
    text, cut, tags, red = r["cut"]
    assert text.startswith("<img src=x onerror=alert(1)>red\n") and tags == 0 and red == ["red"]
    assert cut == ["The output was cut at about 1 MB."]
    assert r["history"] == ["!calc", "afn early", "afl", "pd 9999"], "a refused or busy command is not in the history"
    # Without a reason from the server (rizinEndedText); with one the line says it (final review, F5)
    assert r["ended"] == ["Session ended. Reopen in the toolbar opens the file again.", "Session ended"]


@needs_node
def test_rizin_dock_lists_page_and_filter():
    """The brief: STRINGS and IMPORTS come in pages, filtered on the server; a click jumps there, and a
    click on an import shows its references; XREFS shows the references to the current address or
    function and from it, and is asked for only while it is shown; texts of the file stay text."""
    r = _scripted(r"""
        const S = { analysis: 'done', done: ['aaa'] };
        serve('S1', S);
        opens['C:\\x\\s.exe'] = S;
        await openInRizin('C:\\x\\s.exe');
        await until(() => rizinState.landed, 'landed'); await quiet();
        const tab = name => document.querySelector(`[data-rizin-tab="${name}"]`);
        const gets = part => calls.filter(c => c[0] === 'GET' && c[1].includes(part)).map(c => c[1].replace('/api/rizin/S1/', ''));
        const rows = id => $(id).querySelectorAll('.rizin-row');
        const cells = e => e.children.map(c => c.textContent);
        const pager = kind => [$(`rizin-${kind}-pager`).textContent, !!$(`rizin-${kind}-prev`).disabled, !!$(`rizin-${kind}-next`).disabled];
        const heads = () => $('rizin-xrefs').querySelectorAll('.rizin-xrefs-head').map(e => e.textContent);

        // XREFS is not asked for while it is hidden; shown, it has the references of the current place
        click(row('0x140001490'));
        await until(() => rizinState.seek === '0x140001490', 'jump'); await quiet();
        r.hidden = gets('/xrefs');
        click(tab('xrefs'));
        await until(() => gets('/xrefs').length === 1, 'xrefs shown'); await quiet();
        r.shown = [gets('/xrefs'), heads(), $('rizin-dock-note').textContent];
        click(row('0x1400014b7'));
        await until(() => gets('/xrefs').length === 2, 'the references of main'); await quiet();
        r.main = [heads(), $('rizin-xrefs').querySelectorAll('.rizin-xref').map(e => [e.getAttribute('data-addr'), e.textContent])];
        // A click on a reference from the function jumps to where it goes
        click($('rizin-xrefs').querySelectorAll('.rizin-xref')[1].querySelector('.rizin-xref-text'));
        await until(() => rizinState.seek === '0x140001490', 'xref jump'); await quiet();
        r.xrefJump = [marked(), gets('/xrefs').slice(-1)[0]];

        // STRINGS: pages of 200
        click(tab('strings'));
        await until(() => rows('rizin-strings').length, 'strings'); await quiet();
        r.strings = [gets('/strings'), rows('rizin-strings').length, pager('strings'), $('rizin-xrefs').hidden, $('rizin-strings').hidden,
                     $('rizin-dock-note').textContent, cells(rows('rizin-strings')[0])];
        click($('rizin-strings-next'));
        await until(() => gets('/strings').length === 2, 'page 2'); await quiet();
        r.page2 = [gets('/strings').slice(-1)[0], rows('rizin-strings').length, pager('strings'), rows('rizin-strings')[0].getAttribute('data-addr')];
        click($('rizin-strings-next'));
        await until(() => gets('/strings').length === 3, 'page 3'); await quiet();
        r.page3 = [rows('rizin-strings').length, pager('strings')];
        click($('rizin-strings-next')); await quiet();
        r.past = gets('/strings').length;
        click($('rizin-strings-prev'));
        await until(() => gets('/strings').length === 4, 'back'); await quiet();
        r.back = pager('strings');
        // The filter: on the server, from the first page, a moment after typing; Enter at once
        $('rizin-strings-filter').value = 'PIPE';
        dispatch('input', $('rizin-strings-filter'));
        await until(() => gets('/strings').length === 5, 'filtered'); await quiet();
        r.filtered = [gets('/strings').slice(-1)[0], rows('rizin-strings').map(e => e.querySelector('.rizin-row-text').textContent), pager('strings')];
        $('rizin-strings-filter').value = '<img';
        dispatch('keydown', $('rizin-strings-filter'), { key: 'Enter' });
        await until(() => gets('/strings').length === 6, 'Enter'); await quiet();
        const hostile = rows('rizin-strings')[0];
        r.hostile = [gets('/strings').slice(-1)[0], hostile.querySelector('.rizin-row-text').textContent,
                     hostile.getAttribute('title').includes('<img src=x onerror=alert(1)>'),
                     [...$('rizin-strings').walk()].filter(e => !['DIV', 'SPAN'].includes(e.tagName)).length];
        $('rizin-strings-filter').value = 'child';
        dispatch('keydown', $('rizin-strings-filter'), { key: 'Enter' });
        await until(() => gets('/strings').length === 7, 'child'); await quiet();
        r.child = rows('rizin-strings').map(e => e.querySelector('.rizin-row-text').textContent);
        // A click on a string jumps there, and the string is marked
        click(rows('rizin-strings')[0].querySelector('.rizin-row-text'));
        await until(() => rizinState.seek === '0x140005014', 'string jump'); await quiet();
        r.stringJump = [seeksOf('S1').slice(-1)[0], rows('rizin-strings').filter(e => e.classList.contains('current')).map(e => e.getAttribute('data-addr')),
                        $('rizin-strings').hidden, gets('/strings').length];

        // IMPORTS: a click jumps to the import and shows its references
        click(tab('imports'));
        await until(() => rows('rizin-imports').length, 'imports'); await quiet();
        r.imports = [rows('rizin-imports').map(e => [e.getAttribute('data-addr'), cells(e)]), pager('imports'), $('rizin-dock-note').textContent];
        click(rows('rizin-imports')[1].querySelector('.rizin-row-text'));
        await until(() => !$('rizin-xrefs').hidden && gets('/xrefs').length === 4, 'the references of the import'); await quiet();
        r.importRefs = [seeksOf('S1').slice(-1)[0], gets('/xrefs').slice(-1)[0], heads(),
                        $('rizin-xrefs').querySelectorAll('.rizin-xref').map(e => e.textContent),
                        ['console', 'xrefs', 'strings', 'imports'].map(n => tab(n).getAttribute('aria-selected'))];
        click($('rizin-xrefs').querySelector('.rizin-xref'));
        await until(() => rizinState.seek === '0x140001521', 'the caller'); await quiet();
        r.caller = [marked(), rizinState.func];
        // Back to IMPORTS: the page is still there; an import without an address does not jump
        const importGets = gets('/imports').length;
        click(tab('imports')); await quiet();
        const seeks = seeksOf('S1').length;
        click(rows('rizin-imports')[3]); await quiet();
        r.noAddress = [rows('rizin-imports')[3].getAttribute('data-addr'), seeksOf('S1').length - seeks, gets('/imports').length - importGets];
        $('rizin-imports-filter').value = 'ws2_32';
        dispatch('keydown', $('rizin-imports-filter'), { key: 'Enter' });
        await until(() => gets('/imports').length === importGets + 1, 'by library'); await quiet();
        r.library = [gets('/imports').slice(-1)[0], rows('rizin-imports').map(e => e.querySelector('.rizin-row-text').textContent)];

        // A late answer for a filter typed over is dropped; busy shows and is asked again
        S.strings = url => (url.includes('q=late') ? [200, { total: 1, items: [STRINGS[0]] }, 60] : null);
        click(tab('strings')); await quiet();
        $('rizin-strings-filter').value = 'late';
        dispatch('keydown', $('rizin-strings-filter'), { key: 'Enter' });
        await until(() => flying('/api/rizin/S1/strings?q=late'), 'slow filter');
        $('rizin-strings-filter').value = 'Pipe c';
        dispatch('keydown', $('rizin-strings-filter'), { key: 'Enter' });
        await tick(90); await quiet();
        r.late = rows('rizin-strings').map(e => e.querySelector('.rizin-row-text').textContent);
        let busy = true;
        S.strings = () => (busy ? (busy = false, [409, { busy: true, step: 'view' }]) : null);
        $('rizin-strings-filter').value = 'giving';
        dispatch('keydown', $('rizin-strings-filter'), { key: 'Enter' });
        await until(() => $('rizin-strings').textContent.includes('busy'), 'busy');
        r.busy = $('rizin-strings').textContent;
        await until(() => rows('rizin-strings').length === 1, 'asked again'); await quiet();
        r.free = [rows('rizin-strings').map(e => e.querySelector('.rizin-row-text').textContent), rizinState.retry.size];
        r.pipe = ['/api/rizin/S1/strings', '/api/rizin/S1/imports', '/api/rizin/S1/flags?q=x', '/api/rizin/S1/xrefs?addr=0x1',
                  '/api/rizin/S1/rename', '/api/rizin/S1/comment'].map(rizinUsesPipe);
    """)
    assert "error" not in r, r.get("error")
    assert r["hidden"] == [], "XREFS was asked for while it was hidden"
    assert r["shown"] == [["xrefs?addr=0x140001490"], ["XREFS TO sym.watchdog · 0", "XREFS FROM sym.watchdog · 0"],
                          "a click jumps there"]
    assert r["main"] == [["XREFS TO sym.main · 1", "XREFS FROM sym.main · 1"],
                         [["0x140001004", "0x140001004 entry0 CALL call sym.main"],
                          ["0x140001490", "0x1400014be → 0x140001490 CALL call sym.watchdog"]]]
    assert r["xrefJump"] == [["0x140001490", "0x140001490"], "xrefs?addr=0x140001490"]
    # The columns follow rizin's iz and ii: a string after its section, an import's type before its library
    assert r["strings"] == [["strings?q=&offset=0&limit=200"], 200, ["1–200 of 453", True, False], True, False,
                            "a click jumps there", ["0x140005000", ".rdata", "watchdog: giving up"]]
    assert r["page2"] == ["strings?q=&offset=200&limit=200", 200, ["201–400 of 453", False, False], hex(0x140006000 + 194 * 16)]
    assert r["page3"] == [53, ["401–453 of 453", False, True]]
    assert r["past"] == 3, "a page past the end was asked for"
    assert r["back"] == ["201–400 of 453", False, False]
    assert r["filtered"] == ["strings?q=PIPE&offset=0&limit=200", ["\\\\.\\pipe\\msagent_%04x%02x", "Pipe closed"],
                             ["1–2 of 2", True, True]]
    assert r["hostile"] == ["strings?q=%3Cimg&offset=0&limit=200", "<img src=x onerror=alert(1)>\\x1b]8;;x\\x07", True, 0]
    assert r["child"] == ["child", "child: got '%s'\\n"], "a line break of a string came through"
    assert r["stringJump"] == ["0x140005014", ["0x140005014"], False, 7], "a jump to a string asked for the list again"
    assert r["imports"] == [[["0x140009318", ["0x140009318", "FUNC", "KERNEL32.dll", "CloseHandle"]],
                             ["0x1400093b0", ["0x1400093b0", "FUNC", "KERNEL32.dll", "CreateNamedPipeA"]],
                             ["0x1400093a8", ["0x1400093a8", "FUNC", "KERNEL32.dll", "Sleep"]],
                             [None, ["—", "FUNC", "WS2_32.dll", "Ordinal_7"]]], ["1–4 of 4", True, True],
                            "a click shows its references"]
    assert r["importRefs"] == ["0x1400093b0", "xrefs?addr=0x1400093b0",
                               ["XREFS TO CreateNamedPipeA (KERNEL32.dll) · 2", "XREFS FROM CreateNamedPipeA (KERNEL32.dll) · 0"],
                               ["0x140001521 sym.main CALL call qword [sym.imp.KERNEL32.dll_CreateNamedPipeA]",
                                "0x140003098 (no function) CODE jmp qword [sym.imp.KERNEL32.dll_CreateNamedPipeA]"],
                               ["false", "true", "false", "false"]], "a click on an import did not show its references"
    assert r["caller"] == [["0x1400014b7", "0x140001521"], "sym.main"]
    assert r["noAddress"] == [None, 0, 0]
    assert r["library"] == ["imports?q=ws2_32&offset=0&limit=200", ["Ordinal_7"]]
    assert r["late"] == ["Pipe closed"], "a late answer replaced the newer one"
    assert "busy (view)" in r["busy"] and r["free"] == [["watchdog: giving up"], 0]
    # The lists may come from the server's copy: their answers do not mean that rizin is free
    assert r["pipe"] == [False, False, False, True, True, True]


@needs_node
def test_rizin_rename_and_comment_from_context_menu():
    """The brief: a right-click on a function, a line of the disassembly or a block opens a menu with
    Rename and Comment, which call rename and comment; the views are drawn again. A name with HTML stays
    text; renaming the current function moves SEEK, the list and the heads, and the graph keeps its zoom
    and pan; a refused name shows why, a rename during the analysis waits for its end."""
    r = _scripted(r"""
        globalThis.innerWidth = 1920;
        rizinApplyCenterLayout();
        const pane = $('rizin-graph');
        Object.defineProperties(pane, { clientWidth: { value: 800 }, clientHeight: { value: 600 } });
        FUNCS.push({ name: HOSTILE, offset: 0x140003000, size: 16, nbbs: 1 });
        OPS[HOSTILE] = [op(0x140003000, 1, 'ret', 'ret')];
        GRAPHS[HOSTILE] = [block(0x140003000, 1, ['ret'])];
        const S = { analysis: 'done', done: ['aaa'] };
        serve('S1', S);
        opens['C:\\x\\s.exe'] = S;
        Element.prototype.select = function () { this.selected = true; };
        await openInRizin('C:\\x\\s.exe');
        await until(() => rizinState.landed, 'landed'); await quiet();
        const menu = $('rizin-menu'), input = $('rizin-menu-input');
        const right = (el, x = 100, y = 200) => dispatch('contextmenu', el, { clientX: x, clientY: y, button: 2 });
        const posts = route => calls.filter(c => c[0] === 'POST' && c[1] === `/api/rizin/S1/${route}`).map(c => c[2]);
        const state = () => [menu.hidden, $('rizin-menu-items').hidden, $('rizin-menu-form').hidden];

        // A function with markup in its name: the menu names it as text
        const ev = right(row('0x140003000').querySelector('.rizin-fn-name'), 120, 300);
        r.hostile = [ev.defaultPrevented, ...state(), $('rizin-menu-head').textContent,
                     [...menu.walk()].filter(e => e.tagName === 'IMG').length, menu.style.left, menu.style.top,
                     document.activeElement === $('rizin-menu-rename')];
        click($('rizin-menu-rename'));
        r.form = [...state(), input.value, document.activeElement === input, !!input.selected, $('rizin-menu-label').textContent];
        const esc = dispatch('keydown', input, { key: 'Escape' });
        r.escape = [menu.hidden, esc.stopped, posts('rename').length];

        // Rename another function from its row
        right(row('0x140001490'));
        click($('rizin-menu-rename'));
        input.value = 'tdc_watch';
        const lists = count('GET', '/api/rizin/S1/functions');
        dispatch('keydown', input, { key: 'Enter' });
        await until(() => count('GET', '/api/rizin/S1/functions') > lists, 'views again'); await quiet();
        r.renamed = [posts('rename'), menu.hidden, row('0x140001490').querySelector('.rizin-fn-name').textContent, rizinState.func];

        // The current function from a line of the disassembly: SEEK, the list and the heads follow, the graph stays
        rizinState.graphView = { scale: 0.8, x: -12, y: -34 };
        rizinGraphApplyView();
        right($('rizin-disasm').querySelector('.rizin-op[data-addr="0x1400014be"] .rz-mnem'));
        r.lineHead = $('rizin-menu-head').textContent;
        click($('rizin-menu-rename'));
        r.prefilled = input.value;
        input.value = 'tdc_main';
        const pages = count('GET', '/api/rizin/S1/disasm'), graphs = count('GET', '/api/rizin/S1/graph');
        click($('rizin-menu-save'));
        await until(() => count('GET', '/api/rizin/S1/disasm') > pages, 'views again'); await quiet();
        r.current = [posts('rename').slice(-1)[0], rizinState.func, $('rizin-seek').value,
                     $('rizin-fn-list').querySelector('.rizin-fn.current .rizin-fn-name').textContent,
                     $('rizin-code-title').textContent, $('rizin-graph-title').textContent,
                     JSON.stringify(rizinState.graphView), count('GET', '/api/rizin/S1/graph') - graphs, rizinState.history.length];

        // A name rizin does not take: the reason shows and the menu stays
        right(row('0x140001000'));
        click($('rizin-menu-rename'));
        input.value = 'two words';
        dispatch('keydown', input, { key: 'Enter' });
        await until(() => posts('rename').length === 3 && !flying('/api/rizin/S1/rename'), 'refused'); await quiet();
        r.refused = [menu.hidden, $('rizin-menu-note').textContent, FUNCS[0].name];
        click($('rizin-graph-title'));       // a click beside the menu closes it
        r.outside = menu.hidden;

        // A comment on a line, with markup: kept as text; the menu shows the comment there the next time
        right($('rizin-disasm').querySelector('.rizin-op[data-addr="0x1400014b9"]'));
        click($('rizin-menu-comment'));
        r.empty = [input.value, $('rizin-menu-label').textContent];
        input.value = '<b>note</b> & "x"';
        const before = count('GET', '/api/rizin/S1/disasm');
        dispatch('keydown', input, { key: 'Enter' });
        await until(() => count('GET', '/api/rizin/S1/disasm') > before, 'the disassembly again'); await quiet();
        const line = $('rizin-disasm').querySelector('.rizin-op[data-addr="0x1400014b9"]');
        r.comment = [posts('comment'), line.querySelector('.rz-comment').textContent,
                     [...$('rizin-disasm').walk()].filter(e => !['DIV', 'SPAN'].includes(e.tagName)).length];
        right(line);
        click($('rizin-menu-comment'));
        r.again = input.value;
        rizinCloseMenu();

        // A block of the graph: Comment at the block's address
        right(pane.querySelector('.rizin-block[data-addr="0x140001521"] rect'));
        r.blockHead = $('rizin-menu-head').textContent;
        click($('rizin-menu-comment'));
        input.value = 'block note';
        click($('rizin-menu-save'));
        await until(() => posts('comment').length === 2 && !flying('/api/rizin/S1/comment'), 'block comment'); await quiet();
        r.block = [posts('comment').slice(-1)[0], menu.hidden];

        // While the analysis runs: renames wait for its end
        S.rename = () => [409, { busy: true, step: 'analysis' }];
        right(row('0x140001000'));
        click($('rizin-menu-rename'));
        input.value = 'later';
        dispatch('keydown', input, { key: 'Enter' });
        await until(() => $('rizin-menu-note').textContent && !flying('/api/rizin/S1/rename'), 'busy'); await quiet();
        r.busy = [menu.hidden, $('rizin-menu-note').textContent];
        rizinCloseMenu();
        // Elsewhere the browser's own menu shows
        r.elsewhere = [right($('rizin-graph-title')).defaultPrevented, menu.hidden];
    """.replace("HOSTILE", json.dumps(HOSTILE)))
    assert "error" not in r, r.get("error")
    assert r["hostile"] == [True, False, False, True, f"0x140003000 · {HOSTILE}", 0, "120px", "300px", True], \
        "the menu did not open, or a name became markup"
    assert r["form"] == [False, True, False, HOSTILE, True, True, f"New name for {HOSTILE}"]
    assert r["escape"] == [True, True, 0], "Esc did not close the menu, or went on to the page"
    assert r["renamed"] == [[{"addr": "0x140001490", "name": "tdc_watch"}], True, "tdc_watch", "sym.main"]
    assert r["lineHead"] == "0x1400014be · sym.main" and r["prefilled"] == "sym.main"
    assert r["current"] == [{"addr": "0x1400014be", "name": "tdc_main"}, "tdc_main", "tdc_main", "tdc_main", "tdc_main",
                            "GRAPH · tdc_main", '{"scale":0.8,"x":-12,"y":-34}', 1, 1], \
        "a rename of the current function did not reach every view, or the graph lost its zoom and pan"
    assert r["refused"] == [False, "a name starts with a letter or '_' and has up to 128 of A-Z a-z 0-9 _ . @ $ : -",
                            "entry0"]
    assert r["outside"] is True
    assert r["empty"] == ["", "Comment at 0x1400014b9 (empty removes it)"]
    assert r["comment"] == [[{"addr": "0x1400014b9", "text": '<b>note</b> & "x"'}], '; <b>note</b> & "x"', 0]
    assert r["again"] == '<b>note</b> & "x"'
    assert r["blockHead"] == "0x140001521 · tdc_main"
    assert r["block"] == [{"addr": "0x140001521", "text": "block note"}, True]
    assert r["busy"] == [False, "Available when the analysis is done."]
    assert r["elsewhere"] == [False, True]


@needs_node
def test_rizin_names_from_an_analysis_step_follow():
    """The controller's ruling (Task 4, note b): an analysis step that renames the current function
    (rizin's aan does) moves SEEK, the list's mark and the heads to the new name, and the graph keeps its
    zoom and pan; a name typed in SEEK stays."""
    r = _scripted(r"""
        globalThis.innerWidth = 1920;
        rizinApplyCenterLayout();
        const pane = $('rizin-graph');
        Object.defineProperties(pane, { clientWidth: { value: 800 }, clientHeight: { value: 600 } });
        const S = { analysis: 'done', done: ['aaa'] };
        serve('S1', S);
        opens['C:\\x\\s.exe'] = S;
        await openInRizin('C:\\x\\s.exe');
        await until(() => rizinState.landed, 'landed'); await quiet();
        rizinState.graphView = { scale: 0.9, x: -5, y: -7 };
        rizinGraphApplyView();
        Object.assign(S, { analysis: 'running', step: 'aac', done: ['aa'] });
        rizinState.analysis = { state: 'running', step: 'aac', done_steps: ['aa'], level: 'aaa', elapsed: 0, note: null };
        rizinPollSoon();
        await tick(20);
        renameFn(FUNCS[2], 'main_by_aan');
        Object.assign(S, { step: null, done: ['aa', 'aac'] });
        // The analysis goes on (the poll too): until the views have answered
        await until(() => $('rizin-seek').value === 'main_by_aan' && $('rizin-graph-title').textContent === 'GRAPH · main_by_aan'
                          && ![...inFlight].some(([url, k]) => k > 0 && !url.includes('/status')), 'SEEK follows');
        await tick(5);
        r.step = [rizinState.func, $('rizin-seek').value, $('rizin-fn-list').querySelector('.rizin-fn.current .rizin-fn-name').textContent,
                  $('rizin-code-title').textContent, $('rizin-graph-title').textContent, JSON.stringify(rizinState.graphView)];
        $('rizin-seek').value = 'typed';
        renameFn(FUNCS[2], 'main_again');
        Object.assign(S, { analysis: 'done', step: null, done: ['aa', 'aac', 'aar'] });
        await until(() => rizinState.analysis.state === 'done', 'done'); await quiet();
        r.typed = [$('rizin-seek').value, rizinState.func, $('rizin-fn-list').querySelector('.rizin-fn.current .rizin-fn-name').textContent];
    """)
    assert "error" not in r, r.get("error")
    assert r["step"] == ["main_by_aan", "main_by_aan", "main_by_aan", "main_by_aan", "GRAPH · main_by_aan",
                         '{"scale":0.9,"x":-5,"y":-7}'], "a name an analysis step gave did not reach the views"
    assert r["typed"] == ["typed", "main_again", "main_again"], "the name typed in SEEK was replaced"


@needs_node
def test_rizin_dock_height_and_fold():
    """The dock (spec: its height can be dragged and it folds away): ═ drags its height within bounds,
    ↑ ↓ move it, a double click goes back to the default; ▾ folds it to its head and brings it back,
    and a view in it that was wanted meanwhile loads once it shows."""
    r = _scripted(r"""
        const S = { analysis: 'done', done: ['aaa'] };
        serve('S1', S);
        opens['C:\\x\\s.exe'] = S;
        await openInRizin('C:\\x\\s.exe');
        await until(() => rizinState.landed, 'landed'); await quiet();
        const dock = $('rizin-dock'), grip = $('rizin-dock-grip'), fold = $('rizin-dock-fold');
        dock.rect = { left: 0, top: 500, right: 1200, bottom: 700, width: 1200, height: 200 };
        $('rizin-work').rect = { left: 0, top: 100, right: 1200, bottom: 700, width: 1200, height: 600 };
        const drag = (from, to) => {
            dispatch('pointerdown', grip, { clientY: from, button: 0, buttons: 1, pointerId: 4 });
            dispatch('pointermove', grip, { clientY: to, button: 0, buttons: 1, pointerId: 4 });
            dispatch('pointerup', grip, { clientY: to, button: 0, pointerId: 4 });
            return [dock.style.height, rizinState.layout.dock];
        };
        r.up = drag(500, 400);
        r.more = drag(400, 350);
        r.top = drag(350, 0);
        r.bottom = drag(0, 900);
        r.keys = [dispatch('keydown', grip, { key: 'ArrowUp' }).defaultPrevented, dock.style.height];
        dispatch('keydown', grip, { key: 'ArrowDown' });
        dispatch('keydown', grip, { key: 'ArrowDown' });
        r.keysDown = dock.style.height;
        dispatch('dblclick', grip, {});
        r.reset = [dock.style.height, rizinState.layout.dock];
        drag(500, 300);

        // ▾ folds the dock; a jump while XREFS is folded away asks for nothing, unfolded it loads
        click(document.querySelector('[data-rizin-tab="xrefs"]'));
        await until(() => count('GET', '/api/rizin/S1/xrefs') === 1, 'xrefs'); await quiet();
        click(fold);
        r.folded = [dock.classList.contains('rizin-dock-folded'), dock.style.height, fold.textContent, fold.getAttribute('aria-expanded')];
        click(row('0x140001490'));
        await until(() => rizinState.seek === '0x140001490', 'jump'); await quiet();
        r.foldedJump = count('GET', '/api/rizin/S1/xrefs');
        click(fold);
        await until(() => count('GET', '/api/rizin/S1/xrefs') === 2, 'xrefs once shown'); await quiet();
        r.unfolded = [dock.classList.contains('rizin-dock-folded'), dock.style.height, fold.textContent, fold.getAttribute('aria-expanded'),
                      calls.filter(c => c[1].includes('/xrefs')).slice(-1)[0][1]];
    """)
    assert "error" not in r, r.get("error")
    assert r["up"] == ["300px", 300] and r["more"] == ["350px", 350]
    assert r["top"] == ["420px", 420], "the dock took the room the views need"
    assert r["bottom"] == ["90px", 90], "the dock got smaller than its head and a few lines"
    assert r["keys"] == [True, "114px"] and r["keysDown"] == "90px"
    assert r["reset"] == ["", None]
    assert r["folded"] == [True, "", "▴", "false"]
    assert r["foldedJump"] == 1, "XREFS was asked for while it was folded away"
    assert r["unfolded"] == [False, "400px", "▾", "true", "/api/rizin/S1/xrefs?addr=0x140001490"]


@needs_node
def test_rizin_console_keeps_the_jumps_in_order():
    """Review, Important 1: a console command is no jump. A click whose seek is still on its way, then
    a command: the views follow the click and the command runs there, after it. A click that waits
    behind a running command is sent, and a command typed after it runs at its place, also when another
    click comes meanwhile (that one draws the views). Review, Minor 5: a command shows the prompt of
    where it ran, also one that waited behind s X."""
    r = _scripted(r"""
        const S = { analysis: 'done', done: ['aaa'] };
        serve('S1', S);
        opens['C:\\x\\s.exe'] = S;
        await openInRizin('C:\\x\\s.exe');
        await until(() => rizinState.landed, 'landed'); await quiet();
        const input = $('rizin-console-input'), out = $('rizin-console-out');
        const enter = text => { input.value = text; dispatch('keydown', input, { key: 'Enter' }); };
        const landed = calls.length;
        const order = () => calls.slice(landed).filter(c => c[0] === 'POST' && /\/S1\/(seek|console)$/.test(c[1]))
            .map(c => (c[1].endsWith('/seek') ? 'seek ' + c[2].addr : c[2].cmd));
        const prompts = () => out.querySelectorAll('.rizin-console-cmd').map(e => e.textContent);
        const disasmAt = () => calls.filter(c => c[0] === 'GET' && c[1].startsWith('/api/rizin/S1/disasm'))
            .map(c => new URLSearchParams(c[1].split('?')[1]).get('addr'));

        // A click whose seek answer is still on its way, then Enter on pdf
        S.seekDelay = 40;
        click(row('0x140001490'));
        await until(() => flying('/api/rizin/S1/seek'), 'the jump in flight');
        enter('pdf');
        await until(() => count('POST', '/api/rizin/S1/console') === 1, 'pdf sent'); await quiet();
        S.seekDelay = 1;
        r.inFlight = [rizinState.seek, rizinState.func, marked(), $('rizin-seek').value, $('rizin-code-title').textContent,
                      disasmAt().slice(-1)[0], rizinState.disasm && rizinState.disasm.addr, order(), prompts().slice(-1)[0]];

        // A click that waits behind a running command is sent; the command typed after it runs there
        S.consoleDelay = 40;
        enter('afl');
        await until(() => flying('/api/rizin/S1/console'), 'afl running');
        click(row('0x1400014b7'));
        enter('pdf');
        await quiet();
        r.behind = [order().slice(2), marked(), $('rizin-seek').value, prompts().slice(-2)];

        // A command queued behind s X: its prompt is X, where it ran
        enter('s sym.watchdog');
        await until(() => flying('/api/rizin/S1/console'), 's running');
        enter('pdf');
        await quiet();
        r.afterSeek = [prompts().slice(-2), marked(), $('rizin-prompt').textContent];

        // A click that a waiting command follows is sent, also when a newer click comes; the newest draws
        enter('afl');
        await until(() => flying('/api/rizin/S1/console'), 'afl running again');
        click(row('0x1400014b7'));
        enter('pdf');
        click(row('0x140001000'));
        await quiet();
        S.consoleDelay = 1;
        r.kept = [order().slice(-4), prompts().slice(-2), marked(), $('rizin-seek').value, rizinState.history.slice(-3)];
        // Clicks with no command between them: a waiting one still gives way to the newer one
        S.seekDelay = 30;
        click(row('0x140001490'));
        await until(() => flying('/api/rizin/S1/seek'), 'a jump in flight');
        click(row('0x1400014b7'));
        click(row('0x140001000'));
        await quiet();
        S.seekDelay = 1;
        r.clicks = [order().slice(-2), marked()];
    """)
    assert "error" not in r, r.get("error")
    watchdog, main, entry = ["0x140001490"] * 2, ["0x1400014b7"] * 2, ["0x140001000"] * 2
    assert r["inFlight"] == ["0x140001490", "sym.watchdog", watchdog, "sym.watchdog", "sym.watchdog", "0x140001490",
                             "0x140001490", ["seek 0x140001490", "pdf"], "[0x140001490]> pdf"], \
        "the views stayed where they were after a jump followed by a command"
    assert r["behind"] == [["afl", "seek 0x1400014b7", "pdf"], main, "sym.main",
                           ["[0x140001490]> afl", "[0x1400014b7]> pdf"]], "a jump that waited behind a command was dropped"
    assert r["afterSeek"] == [["[0x1400014b7]> s sym.watchdog", "[0x140001490]> pdf"], watchdog, "[0x140001490]>"], \
        "a command shows the prompt of before the command it waited for"
    # The kept jump runs (pdf runs at its place), but the newer click draws the views: only that one goes into
    # the history (final review, F3)
    assert r["kept"] == [["afl", "seek 0x1400014b7", "pdf", "seek 0x140001000"],
                         ["[0x140001490]> afl", "[0x1400014b7]> pdf"], entry, "entry0",
                         ["0x1400014b7", "0x140001490", "0x140001000"]], "the jump a command waited for was dropped"
    assert r["clicks"] == [["seek 0x140001490", "seek 0x140001000"], entry], "a waiting jump no longer gives way"


@needs_node
def test_rizin_menu_stays_in_the_window_and_closes_on_user_scrolls():
    """Review, Minors 3, 4 and 8: the menu keeps inside the window at its edges, also once the field
    makes it taller; it closes on the user's scrolls (wheel, touch, keys) and presses elsewhere, the
    page's scroll, a new window size and a right-click elsewhere, but not on a scroll of the tab's own
    (the console going to its end, a list keeping its rows), which would lose what is being typed."""
    r = _scripted(r"""
        globalThis.innerWidth = 1920;
        globalThis.innerHeight = 1080;
        const S = { analysis: 'done', done: ['aaa'] };
        serve('S1', S);
        opens['C:\\x\\s.exe'] = S;
        await openInRizin('C:\\x\\s.exe');
        await until(() => rizinState.landed, 'landed'); await quiet();
        const menu = $('rizin-menu'), input = $('rizin-menu-input');
        // The menu as the browser lays it out: short with its two items, taller with the field, and a line
        // taller with a note under the field
        menu.getBoundingClientRect = () => ($('rizin-menu-form').hidden ? { left: 0, top: 0, width: 230, height: 76 }
            : { left: 0, top: 0, width: 320, height: 150 + ($('rizin-menu-note').textContent ? 36 : 0) });
        const right = (el, x, y) => dispatch('contextmenu', el, { clientX: x, clientY: y, button: 2 });
        const at = () => [menu.style.left, menu.style.top];
        const open = () => { right(row('0x140001490'), 600, 400); click($('rizin-menu-rename')); input.value = 'tdc_typed'; };

        // At the bottom right corner: inside the window, the field too, and the note a refused name brings
        right(row('0x140001490'), 1900, 1070);
        r.items = at();
        click($('rizin-menu-rename'));
        r.form = at();
        input.value = 'two words';
        dispatch('keydown', input, { key: 'Enter' });
        await until(() => !flying('/api/rizin/S1/rename') && $('rizin-menu-note').textContent.startsWith('a name'), 'refused');
        r.noted = at();
        rizinCloseMenu();
        right(row('0x140001490'), 40, 30);
        r.corner = at();
        click($('rizin-menu-comment'));
        r.cornerForm = at();
        rizinCloseMenu();

        // The tab's own scrolls: the menu and the name typed stay
        open();
        dispatch('scroll', $('rizin-console-out'));
        dispatch('scroll', $('rizin-disasm'));
        rizinConsoleNote('a line', 'note');
        r.ownScroll = [menu.hidden, input.value];
        dispatch('wheel', input);
        dispatch('keydown', input, { key: 'PageDown' });
        r.inside = menu.hidden;
        // The user's scrolls and presses elsewhere close it
        dispatch('wheel', $('rizin-disasm'));
        r.wheel = menu.hidden;
        open();
        dispatch('touchmove', $('rizin-fn-list'));
        r.touch = menu.hidden;
        open();
        dispatch('keydown', $('rizin-disasm'), { key: 'PageDown' });
        r.key = menu.hidden;
        open();
        dispatch('pointerdown', $('rizin-code-title'), { button: 0 });
        r.press = menu.hidden;
        open();
        windowListeners.filter(l => l.type === 'scroll').forEach(l => l.fn({ target: document }));
        r.page = menu.hidden;
        open();
        windowListeners.filter(l => l.type === 'resize').forEach(l => l.fn({}));
        r.resize = menu.hidden;
        open();
        r.elsewhere = [right($('rizin-graph-title'), 10, 10).defaultPrevented, menu.hidden];
        // A right-click on another row while the menu is open (the press first, as in the browser): the
        // menu for that row, and Esc gives the focus back to where it was before the first menu
        $('rizin-console-input').focus();
        right(row('0x140001490'), 600, 400);
        dispatch('pointerdown', row('0x1400014b7'), { button: 2 });
        right(row('0x1400014b7'), 600, 420);
        r.other = [menu.hidden, $('rizin-menu-head').textContent];
        dispatch('keydown', $('rizin-menu-rename'), { key: 'Escape' });
        r.back = [menu.hidden, document.activeElement === $('rizin-console-input')];
    """)
    assert "error" not in r, r.get("error")
    assert r["items"] == ["1686px", "1000px"], "the menu went past the window's edge"
    assert r["form"] == ["1596px", "926px"], "the field made the menu run past the window's edge"
    assert r["noted"] == ["1596px", "890px"], "the note under the field made the menu run past the window's edge"
    assert r["corner"] == ["40px", "30px"] and r["cornerForm"] == ["40px", "30px"]
    assert r["ownScroll"] == [False, "tdc_typed"], "a scroll of the tab's own closed the menu and lost the name"
    assert r["inside"] is False, "a scroll in the menu's own field closed it"
    assert [r["wheel"], r["touch"], r["key"], r["press"], r["page"], r["resize"]] == [True] * 6
    assert r["elsewhere"] == [False, True]
    assert r["other"] == [False, "0x1400014b7 · sym.main"]
    assert r["back"] == [True, True], "a right-click on another row lost where the focus goes back to"


@needs_node
def test_rizin_comment_field_shows_the_comment_there():
    """Review, Minor 1: Comment… shows the comment at the address also when the disassembly has not
    loaded it (another function's row, a line beyond the page): it is read from rizin first, so that an
    empty field removes only a comment that was seen; while it is read the field waits. If it cannot be
    read, an empty field is not sent; a comment typed is."""
    r = _scripted(r"""
        const S = { analysis: 'done', done: ['aaa'] };
        serve('S1', S);
        opens['C:\\x\\s.exe'] = S;
        Element.prototype.select = function () { this.selected = true; };
        COMMENTS.set(0x1400014b9, 'on the page');
        COMMENTS.set(0x140001490, 'watchdog <i>seen</i>');
        await openInRizin('C:\\x\\s.exe');
        await until(() => rizinState.landed, 'landed'); await quiet();
        const menu = $('rizin-menu'), input = $('rizin-menu-input'), save = $('rizin-menu-save'), note = $('rizin-menu-note');
        const right = el => dispatch('contextmenu', el, { clientX: 100, clientY: 200, button: 2 });
        const reads = () => calls.filter(c => c[0] === 'GET' && c[1].startsWith('/api/rizin/S1/comment')).map(c => c[1]);
        const posts = () => calls.filter(c => c[0] === 'POST' && c[1] === '/api/rizin/S1/comment').map(c => c[2]);

        // A line of the page shown: its comment at once, nothing read
        right($('rizin-disasm').querySelector('.rizin-op[data-addr="0x1400014b9"]'));
        click($('rizin-menu-comment'));
        r.page = [input.value, reads().length, !!input.disabled];
        rizinCloseMenu();

        // Another function's row: the field waits while the comment there is read, then shows it
        S.commentAtDelay = 20;
        right(row('0x140001490'));
        click($('rizin-menu-comment'));
        r.reading = [!!input.disabled, !!save.disabled, note.textContent, input.value];
        await until(() => !input.disabled, 'read'); await quiet();
        r.read = [input.value, reads(), document.activeElement === input, !!input.selected, note.textContent, !!save.disabled];
        // Seen, it can be removed: the empty field goes to rizin
        input.value = '';
        click(save);
        await until(() => posts().length === 1 && !flying('/api/rizin/S1/comment'), 'removed'); await quiet();
        r.removed = [posts(), menu.hidden, COMMENTS.has(0x140001490)];

        // It cannot be read: an empty field is not sent, a comment typed is
        S.commentAtDelay = 1;
        S.commentAt = () => [409, { busy: true, step: 'view' }];
        right(row('0x140001000'));
        click($('rizin-menu-comment'));
        await until(() => !input.disabled, 'not read'); await quiet();
        r.unknown = [input.value, note.textContent];
        click(save); await quiet();
        r.notSent = [posts().length, menu.hidden, note.textContent];
        input.value = 'entry note';
        click(save);
        await until(() => posts().length === 2 && !flying('/api/rizin/S1/comment'), 'sent'); await quiet();
        r.typed = [posts().slice(-1)[0], menu.hidden];
        // A late reading after the menu closed changes nothing
        S.commentAt = () => [200, { offset: 0x140001000, comment: 'late' }, 30];
        right(row('0x140001000'));
        click($('rizin-menu-comment'));
        rizinCloseMenu();
        right(row('0x140001490'));
        click($('rizin-menu-rename'));
        await tick(50); await quiet();
        r.late = [input.value, $('rizin-menu-label').textContent];
    """)
    assert "error" not in r, r.get("error")
    assert r["page"] == ["on the page", 0, False]
    assert r["reading"] == [True, True, "Reading the comment here…", ""], "the field did not wait for the comment"
    assert r["read"] == ["watchdog <i>seen</i>", ["/api/rizin/S1/comment?addr=0x140001490"], True, True, "", False], \
        "the comment of another function's row was not shown"
    assert r["removed"] == [[{"addr": "0x140001490", "text": ""}], True, False]
    assert r["unknown"] == ["", "rizin is busy (view); the comment here could not be read."]
    assert r["notSent"] == [1, False, "Not saved: the comment here could not be read, and an empty field would remove it."], \
        "an empty field removed a comment no one saw"
    assert r["typed"] == [{"addr": "0x140001000", "text": "entry note"}, True]
    assert r["late"] == ["sym.watchdog", "New name for sym.watchdog"], "a late reading changed another field"


@needs_node
def test_rizin_tab_with_more_flags_than_sent():
    """Review, Minors 2, 6 and 8: with more matching flags than /flags sends (200), Tab goes only as far
    as all of them agree (the server's common), not as far as those sent; the list of names ends in …,
    also past 60 names. One /flags request at a time: Tab again while one is out takes its answer when it
    asks the same, else waits for it."""
    r = _scripted(r"""
        const S = { analysis: 'done', done: ['aaa'] };
        serve('S1', S);
        opens['C:\\x\\s.exe'] = S;
        Element.prototype.setSelectionRange = function (a, b) { this.selectionStart = a; this.selectionEnd = b; };
        await openInRizin('C:\\x\\s.exe');
        await until(() => rizinState.landed, 'landed'); await quiet();
        const input = $('rizin-console-input'), out = $('rizin-console-out');
        const type = text => { input.value = text; input.selectionStart = input.selectionEnd = text.length; };
        const tab = () => dispatch('keydown', input, { key: 'Tab' });
        const listed = () => out.querySelectorAll('.rizin-console-complete').map(e => e.textContent).slice(-1)[0] || '';
        const flags = () => calls.filter(c => c[1].startsWith('/api/rizin/S1/flags')).map(c => c[1].split('?')[1]);
        // 250 flags start with sym.imp.: the 200 sent are KERNEL32's, 50 of WS2_32 follow them
        const kernel = Array.from({ length: 200 }, (_, i) => `sym.imp.KERNEL32.dll_F${String(i).padStart(3, '0')}`);
        const many = Array.from({ length: 80 }, (_, i) => `fcn.${String.fromCharCode(97 + (i % 26))}${i}`);
        S.flags = url => {
            const q = new URLSearchParams(url.split('?')[1]).get('q');
            if (q === 'sym.imp.') return [200, { total: 250, names: kernel, common: 'sym.imp.' }];
            if (q === 'sym.imp.k') return [200, { total: 230, names: kernel, common: 'sym.imp.KERNEL32.dll_' }];
            if (q === 'fcn.') return [200, { total: 80, names: many, common: 'fcn.' }];
            return null;
        };
        type('pdf @ sym.imp.');
        tab(); await quiet();
        r.shared = [input.value, listed().split('  ').length, listed().endsWith('  …')];
        type('pdf @ sym.imp.k');
        tab(); await quiet();
        r.further = input.value;
        type('pdf @ fcn.');
        tab(); await quiet();
        const parts = listed().split('  ');
        r.sixty = [input.value, parts.length, parts[59] === [...many].sort()[59], parts[60]];

        // One request at a time
        let out_ = 0;
        r.most = 0;
        const fetched = globalThis.fetch;
        globalThis.fetch = (url, init) => {
            const mine = url.startsWith('/api/rizin/S1/flags');
            if (mine) r.most = Math.max(r.most, ++out_);
            return fetched(url, init).then(resp => { if (mine) out_--; return resp; });
        };
        S.flagsDelay = 30;
        let before = flags().length;
        type('pdf @ sym.ma');
        tab(); tab(); tab();
        await quiet();
        r.same = [flags().slice(before), input.value];
        before = flags().length;
        type('pdf @ sym.ma');
        tab();
        await until(() => flying('/api/rizin/S1/flags'), 'asked');
        type('pdf @ sym.wa');
        tab();
        await quiet();
        r.waited = [flags().slice(before), input.value];
        S.flagsDelay = 1;
    """)
    assert "error" not in r, r.get("error")
    assert r["shared"] == ["pdf @ sym.imp.", 61, True], "Tab went as far as the 200 flags sent agree, not all of them"
    assert r["further"] == "pdf @ sym.imp.KERNEL32.dll_"
    assert r["sixty"] == ["pdf @ fcn.", 61, True, "…"], "past 60 names the list did not end in …"
    assert r["most"] == 1, "more than one /flags request at a time"
    assert r["same"] == [["q=sym.ma&limit=200"], "pdf @ sym.main"], "Tab again asked the same once more"
    assert r["waited"] == [["q=sym.ma&limit=200", "q=sym.wa&limit=200"], "pdf @ sym.watchdog"]


@needs_node
def test_rizin_console_keeps_its_newest_output():
    """Review, Minor 8: the console keeps its newest RIZIN_CONSOLE.entries entries and about
    RIZIN_CONSOLE.keep characters of output; the oldest go first, and the newest stays however long."""
    r = _scripted(r"""
        const out = $('rizin-console-out');
        Object.assign(RIZIN_CONSOLE, { entries: 5, keep: 100 });
        for (let i = 0; i < 8; i++) rizinConsoleNote(`note ${i}`, 'note');
        r.entries = out.children.map(e => e.textContent);
        rizinConsoleFill(rizinConsoleEntry('[0x1]>', 'pdf'), 'output', escapeHtml('x'.repeat(90)));
        r.size = out.children.map(e => e.textContent.slice(0, 12));
        rizinConsoleFill(rizinConsoleEntry('[0x1]>', 'pd 9999'), 'output', escapeHtml('y'.repeat(500)));
        r.long = [out.children.length, out.firstElementChild.textContent.length];
    """)
    assert "error" not in r, r.get("error")
    assert r["entries"] == ["note 3", "note 4", "note 5", "note 6", "note 7"], "the console kept more than its entries"
    assert r["size"] == ["note 7", "[0x1]> pdfxx"], "the console kept more than its characters"
    assert r["long"] == [1, len("[0x1]> pd 9999") + 500], "the newest output went"


@needs_node
def test_rizin_new_file_clears_the_dock_lists():
    """Review, Minor 7: another file opened clears STRINGS, IMPORTS and XREFS at once, so that no row
    of the file before (its address would go to the new session) is there to click while the new lists
    load."""
    r = _scripted(r"""
        const A = { analysis: 'done', done: ['aaa'] }, B = { analysis: 'done', done: ['aaa'] };
        serve('SA', A); serve('SB', B);
        opens['C:\\x\\a.exe'] = A; opens['C:\\x\\b.exe'] = B;
        await openInRizin('C:\\x\\a.exe');
        await until(() => rizinState.landed, 'A landed'); await quiet();
        const tab = name => document.querySelector(`[data-rizin-tab="${name}"]`);
        const rows = id => $(id).querySelectorAll('.rizin-row');
        click(tab('xrefs'));
        await until(() => $('rizin-xrefs').querySelectorAll('.rizin-xref').length, 'xrefs of A');
        click(tab('imports'));
        await until(() => rows('rizin-imports').length, 'imports of A');
        click(tab('strings'));
        await until(() => rows('rizin-strings').length, 'strings of A'); await quiet();
        r.before = [rows('rizin-strings').length, rows('rizin-imports').length, $('rizin-xrefs').querySelectorAll('.rizin-xref').length,
                    $('rizin-strings-pager').textContent];
        B.strings = () => [200, { total: 0, items: [] }, 40];      // B's strings come late
        const opening = openInRizin('C:\\x\\b.exe');
        await until(() => rizinState.session === 'SB', 'B opened');
        r.cleared = [rows('rizin-strings').length, rows('rizin-imports').length, $('rizin-xrefs').querySelectorAll('.rizin-xref').length,
                     $('rizin-strings').textContent, $('rizin-strings-pager').textContent, !!$('rizin-strings-next').disabled];
        await opening;
        await until(() => rizinState.landed, 'B landed'); await quiet();
        r.seeks = seeksOf('SB');
    """)
    assert "error" not in r, r.get("error")
    assert r["before"] == [200, 4, 2, "1–200 of 453"]
    assert r["cleared"] == [0, 0, 0, "Loading…", "", True], "the lists of the file before stayed to be clicked"
    assert r["seeks"] == ["0x1400014b7"]


def test_rizin_console_completions_pass_the_allowlist():
    """Tab completes, and the quick commands run, only what the server's allowlist lets through; the
    quick commands are the brief's."""
    from rizin_sessions import check_console_command

    commands = re.findall(r"'([^']+)'", _const_source("RIZIN_CONSOLE_COMMANDS"))
    assert len(commands) >= 30 and len(set(commands)) == len(commands)
    quick = re.findall(r'data-cmd="([^"]+)"', _tab_markup("rizin"))
    assert quick == ["afl", "pdf", "pdg", "iz", "ii", "axt", "?"]
    refused = {cmd: check_console_command(cmd) for cmd in commands + quick if check_console_command(cmd) is not None}
    assert refused == {}, refused


# The parts of the dock and the menu whose look each theme sets
DOCK_THEMED = [".rizin-dock-grip", ".rizin-dock-note", ".rizin-console-out", ".rizin-console-line", ".rizin-prompt",
               ".rizin-console-input", ".rizin-console-cmd", ".rizin-console-typed", ".rizin-quick .rizin-tool", ".rizin-row",
               ".rizin-row.current", ".rizin-xrefs-head", ".rizin-xref", ".rizin-pager", ".rizin-menu", ".rizin-menu-item",
               ".rizin-menu-head", ".rizin-emu-pane", ".rizin-emu-head", ".rizin-emu-reg", ".rizin-emu-fn", ".rizin-emu-group",
               ".rizin-emu-note"]
ANSI_NAMES = ["black", "red", "green", "yellow", "blue", "magenta", "cyan", "white", "gray", "bright-red", "bright-green",
              "bright-yellow", "bright-blue", "bright-magenta", "bright-cyan", "bright-white"]


def test_rizin_dock_layout_and_themes():
    html = _read(INDEX_HTML)
    tab = _tab_markup("rizin")
    ids = ["rizin-dock-grip", "rizin-dock-fold", "rizin-dock-note", "rizin-dock-body", "rizin-quick", "rizin-console-out",
           "rizin-prompt", "rizin-console-input", "rizin-strings-filter", "rizin-strings-pager", "rizin-strings-prev",
           "rizin-strings-next", "rizin-imports-filter", "rizin-imports-pager", "rizin-imports-prev", "rizin-imports-next",
           "rizin-emulation", "rizin-menu", "rizin-menu-head", "rizin-menu-items", "rizin-menu-rename", "rizin-menu-comment", "rizin-menu-form",
           "rizin-menu-label", "rizin-menu-input", "rizin-menu-save", "rizin-menu-note"]
    missing = [i for i in ids if f'id="{i}"' not in tab]
    assert not missing, missing
    dock = tab[tab.index('id="rizin-dock"'):]
    assert dock.index('id="rizin-dock-grip"') < dock.index('data-rizin-tabs="dock"') < dock.index('id="rizin-console"')
    assert re.search(r'id="rizin-dock-grip"[^>]*tabindex="0"', tab) and re.search(r'id="rizin-dock-grip"[^>]*role="separator"', tab)
    assert re.search(r'<span class="rizin-dock-note" data-info="[^"]+"><span id="rizin-dock-note">', tab), "the dock has no (i)"
    for handler in ('oncontextmenu="rizinOnContextMenu(event, \'functions\')"', 'oncontextmenu="rizinOnContextMenu(event, \'disasm\')"',
                    'oncontextmenu="rizinOnContextMenu(event, \'graph\')"', 'onkeydown="rizinOnConsoleKey(event)"',
                    'onclick="rizinOnQuickClick(event)"', 'onclick="rizinOnDockClick(event, \'xrefs\')"',
                    'onclick="rizinOnDockClick(event, \'strings\')"', 'onclick="rizinOnDockClick(event, \'imports\')"',
                    'onclick="rizinOnEmuPaneClick(event)"', 'onchange="rizinOnEmuPaneChange(event)"',
                    'onclick="rizinOnMenuClick(event)"', 'onkeydown="rizinOnMenuKey(event)"'):
        assert handler in tab, f"{handler}: one delegated handler per list"
    placeholder = re.search(r'id="rizin-console-input"[^>]*placeholder="([^"]+)"', tab).group(1)
    assert "↑↓" in placeholder and "Tab" in placeholder

    classic, cyberpunk = _rules(STYLE_CSS), _rules(THEME_CSS)
    prefix = '[data-theme="cyberpunk"] '
    missing = [s for s in DOCK_THEMED if s not in classic] + [prefix + s for s in DOCK_THEMED if prefix + s not in cyberpunk]
    assert not missing, "parts of the dock without a rule in one theme:\n" + "\n".join(missing)
    # ANSI colours are classes with theme variables, in both themes through the variables
    for name in ANSI_NAMES:
        assert re.fullmatch(r"var\(--[\w-]+\)", _declared(classic.get(f".rz-ansi-{name}"), "color") or ""), name
    for name in ANSI_NAMES[:8]:
        assert re.fullmatch(r"rgba\(var\(--[\w-]+-rgb\), \.\d+\)", _declared(classic.get(f".rz-ansi-bg-{name}"), "background") or ""), name
    assert _declared(classic.get(".rz-ansi-bold"), "font-weight") in ("600", "700", "bold")
    # The console: its output scrolls in itself above the line where commands are typed
    console = classic.get(".rizin-console", "")
    assert _declared(console, "display") == "flex" and _declared(console, "flex-direction") == "column"
    assert _declared(console, "overflow") == "hidden"
    out = classic.get(".rizin-console-out", "")
    assert _declared(out, "flex") in ("1", "1 1 0", "1 1 auto") and _declared(out, "overflow") == "auto"
    assert _declared(out, "min-height") == "0" and _declared(out, "white-space") == "pre"
    for selector in (".rizin-console[hidden]", ".rizin-xrefs[hidden]", ".rizin-dock-tools[hidden]", ".rizin-menu[hidden]",
                     ".rizin-menu-form[hidden]", ".rizin-menu-items[hidden]"):
        assert _declared(classic.get(selector), "display") == "none", f"{selector}: hidden shows"
    assert _declared(classic.get(".rizin-dock.rizin-dock-folded"), "height") == "auto"
    for selector in (".rizin-dock.rizin-dock-folded > .rizin-dock-body", ".rizin-dock.rizin-dock-folded > .rizin-dock-grip"):
        assert _declared(classic.get(selector), "display") == "none", selector
    assert _declared(classic.get(".rizin-dock-grip"), "cursor") == "row-resize"
    assert _declared(classic.get(".rizin-menu"), "position") == "fixed"
    assert _declared(classic.get(".rizin-row > span"), "text-overflow") == "ellipsis", "a long string widens the list"
    assert "style.css?v=62" not in html and "theme-cyberpunk.css?v=22" not in html and "app.js?v=90" not in html, \
        "asset versions not raised"
    assert "app.js?v=91" not in html, "app.js changed after the review, its version did not"


# --- Task 7: the Rizin buttons, the session's states, DECOMPILER, HEX, a long disassembly, pagehide -----------

# A path as a sample may name it: a quote and a closing script tag
EVIL_PATH = 'C:\\Users\\Public\\Downloads\\a"b</script><img src=x onerror=alert(1)>.exe'
OPEN_BUTTON_FUNCTIONS = ["refreshSubmissions", "_submissionTime", "submissionResultArgs", "sortTimeValue",
                         "sortNumberValue", "renderProcessDumpBlock", "renderExitCaptureBlock", "renderScanResult",
                         "renderRawToggle", "renderUnifiedHistory", "_histTime", "_histStatus", "_histScoreKind",
                         "_histPercent", "renderHistoryDetail", "hexOpenInRizin"]
# The markup a test reads back as the page set it (the test DOM parses innerHTML and keeps no text of it)
KEEP_MARKUP = r"""
const _innerHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
Object.defineProperty(Element.prototype, 'innerHTML', { configurable: true,
    set(html) { this._markup = String(html); _innerHTML.set.call(this, html); }, get() { return this._markup; } });
"""


@needs_node
def test_rizin_open_buttons_everywhere_a_path_is_known():
    """The brief: a "Rizin" button beside the Hex button wherever TDC knows the path of a file on the VM: the
    Submit history, the files of Process Dump and Exit Capture, a ThreatScan result and the Hex tab's
    toolbar; in the ThreatScan history where an entry's file is still there (the server's exists). Each
    calls openInRizin with the path through jsArg: a path with " and </script> stays inside its handler."""
    r = _run_node(RIZIN_FUNCTIONS + HELPERS + OPEN_BUTTON_FUNCTIONS, r"""
        (async () => {
            const PATH = PATH_JSON;
            const opened = [];
            globalThis.openInRizin = path => { opened.push(path); return Promise.resolve(true); };
            globalThis._detRawButton = () => '';
            globalThis.renderSubmissionVerdicts = () => {};
            globalThis.renderScoreHistory = () => {};
            const r = {};
            // A place: its Rizin buttons, their handlers as written, what a click on each opens, whether a Hex
            // button stands beside them, the elements the path made, and in the markup: a </script>, and the
            // handlers that keep the path inside &quot;…&quot;
            const look = (el, html) => {
                const all = el.querySelectorAll('button');
                const rizin = all.filter(b => /Rizin/.test(b.textContent));
                const before = opened.length;
                rizin.forEach(b => click(b));
                return { texts: rizin.map(b => b.textContent), handlers: rizin.map(b => b.getAttribute('onclick')),
                         beside: rizin.map(b => all.some(h => /Hex/.test(h.textContent) && h.parentNode === b.parentNode)),
                         opened: opened.slice(before), markup: [...el.walk()].filter(e => ['IMG', 'SCRIPT'].includes(e.tagName)).length,
                         raw: [String(html).includes('</script>'),
                               (String(html).match(/onclick="(?:event\.stopPropagation\(\); )?openInRizin\(&quot;[^"<>]*&quot;\)"/g) || []).length] };
            };
            const box = html => { const el = document.createElement('div'); el.innerHTML = html; document.body.appendChild(el); return el; };

            // The Submit history: a submission with a path and one without
            document.body.innerHTML = '<div id="submissions-list"></div>';
            const sub = (id, filename, path) => ({ id, timestamp: '2026-11-05T11:37:11', filename, sha256: id.repeat(64), size: 10,
                                                   target: 'agent', agent_status: 'success', agent_pid: 7, file_path: path });
            globalThis.fetch = async () => ({ ok: true, json: async () => [sub('a', 'a.exe', PATH), sub('b', 'b.exe', null)] });
            await refreshSubmissions();
            const list = document.getElementById('submissions-list');
            r.submit = { ...look(list, list.innerHTML),
                         rows: list.querySelectorAll('tbody tr').map(tr => tr.querySelectorAll('button').map(b => b.textContent)) };
            // Process Dump and Exit Capture: the files they wrote
            const pd = renderProcessDumpBlock({ dump_count: 1, output_dir: 'C:\\dumps\\x', dumps: [{ filename: 'x.dll', path: PATH,
                                                kind: 'module', arch: 'x64', size: 10, sha256: 'c'.repeat(64) }] });
            r.dump = look(box(pd), pd);
            const ec = renderExitCaptureBlock({ captured: true, modules: 1, regions: 2, threads: 3, captured_bytes: 1048576,
                artifacts: [{ filename: 'a.exe', path: PATH, kind: 'main_image', size: 10, is_pe: true, sha256: 'd'.repeat(64) },
                            { filename: 'blob.bin', path: PATH, kind: 'shellcode', size: 4, is_pe: false }] });
            r.exit = look(box(ec), ec);
            // A ThreatScan result: detected, with its path; a clean one has neither button
            const scan = box('');
            renderScanResult({ tool: 'ThreatCheck', engine: 'Defender', detected: true, clean: false, filepath: PATH, output: 'found' }, scan);
            r.scan = look(scan, scan.innerHTML);
            const clean = box('');
            renderScanResult({ tool: 'ThreatCheck', detected: false, clean: true, filepath: PATH, output: 'none' }, clean);
            r.clean = clean.querySelectorAll('button').length;
            // The ThreatScan history: an entry whose file is there, one whose file is gone, one without a file; a
            // click on the button opens the file, not the entry's details
            document.body.innerHTML = '<div id="threatscan-history-list"></div>';
            const entry = (id, tool, filename, more) => ({ id, timestamp: '2026-11-05T11:37:25', tool, filename, sha256: '', size: null,
                                                         status: 'ok', verdict: 'detected', score: null, detected: true, clean: false, ...more });
            renderUnifiedHistory([entry('h3', 'capa', 'a.exe', { exists: true, result: { filepath: PATH } }),
                                  entry('h2', 'EMBER2024', 'gone.exe', { exists: false, result: { filepath: 'C:\\gone.exe' } }),
                                  entry('h1', 'Process Dump', 'PID 4', { exists: false, result: {} })]);
            const history = document.getElementById('threatscan-history-list');
            r.history = { ...look(history, history.innerHTML),
                          rows: history.querySelectorAll('.scan-history-entry').map(e => e.querySelectorAll('button').length),
                          details: history.querySelectorAll('.scan-history-detail').map(d => d.style.display || d.getAttribute('style')) };
            // The Hex tab's toolbar: the file loaded there, else the path typed, else nothing but a note
            document.body.innerHTML = HEX_MARKUP;
            globalThis.alert = () => { opened.push('ALERT'); };
            const hex = document.querySelectorAll('#tab-hexeditor .header-actions button').find(b => b.textContent === 'Rizin');
            globalThis.state = { hexFilePath: PATH };
            click(hex);
            globalThis.state = { hexFilePath: null };
            document.getElementById('hex-filepath').value = '  C:\\typed.exe  ';
            click(hex);
            document.getElementById('hex-filepath').value = '';
            click(hex);
            r.hexTab = [hex.getAttribute('onclick'), hex.getAttribute('title'), opened.slice(-3)];
            console.log(JSON.stringify(r));
        })().catch(e => console.log(JSON.stringify({ error: e.stack })));
    """.replace("PATH_JSON", json.dumps(EVIL_PATH)).replace("HEX_MARKUP", json.dumps(_tab_markup("hexeditor"))),
        SORT_DOM + KEEP_MARKUP + _rizin_prelude() + "\n" + _const_source("SCAN_HISTORY_CONTAINERS") + "\n"
        + _const_source("EVIDENCE_SCORE_TOOLS"))
    assert "error" not in r, r.get("error")
    for place in ("submit", "dump", "exit", "scan", "history"):
        got = r[place]
        assert got["opened"] and all(p == EVIL_PATH for p in got["opened"]), f"{place}: the click did not open the exact path"
        assert got["markup"] == 0 and got["raw"] == [False, len(got["opened"])], f"{place}: the path left its handler"
        assert all(h.startswith(("openInRizin(", "event.stopPropagation(); openInRizin(")) for h in got["handlers"]), place
    assert r["submit"]["texts"] == ["Rizin"] and r["submit"]["beside"] == [True]
    assert r["submit"]["rows"] == [["Hex", "Rizin", "Results"], ["Results"]], "a submission without a path got a button"
    assert r["dump"]["texts"] == ["Rizin"] and r["dump"]["beside"] == [True]
    assert r["exit"]["texts"] == ["Rizin", "Rizin"] and r["exit"]["beside"] == [True, True]
    assert r["scan"]["texts"] == ["Open in Rizin"] and r["scan"]["beside"] == [True] and r["clean"] == 0
    assert r["history"]["texts"] == ["Rizin"] and r["history"]["rows"] == [1, 0, 0], "an entry whose file is gone got a button"
    assert r["history"]["details"] == ["display:none"] * 3, "the button opened the entry's details too"
    handler, title, opened = r["hexTab"]
    assert handler == "hexOpenInRizin()" and title
    assert opened == [EVIL_PATH, "C:\\typed.exe", "ALERT"], "the Hex tab's Rizin did not open its file"


@needs_node
def test_rizin_session_states_render():
    """The brief's states in the toolbar: rizin not installed with its path (in DISASSEMBLY too); busy; a
    stopped analysis with its reason and, at level aa, Full analysis, after which the poll follows aaa's
    steps and the button goes; the file open in another tab (seen when the browser tab comes back into
    sight) with Take it back, which opens the same path again for this tab and comes back to the place it
    showed, with its history; the session ended with Reopen, which does the same."""
    r = _scripted(r"""
        const st = () => [$('rizin-state').hidden, $('rizin-state').textContent, $('rizin-state').className,
                          $('rizin-state-btn').hidden, $('rizin-state-btn').textContent, $('rizin-full').hidden,
                          $('rizin-toolbar').classList.contains('rizin-crowded')];
        on('GET', '/api/rizin/status', () => [200, { installed: false, path: 'C:\\tools\\cutter\\rizin.exe', version: null, ghidra: false }]);
        rizinTabShown();
        await until(() => rizinState.ui.state === 'not-installed', 'not installed');
        r.notInstalled = [...st(), $('rizin-state').title, $('rizin-disasm').textContent];

        // A big dump: aa, and busy while it runs
        const S = { analysis: 'running', step: 'aa', level: 'aa', done: [],
                    functions: s => (s.analysis === 'running' ? [409, { busy: true, step: 'aa' }] : [200, FUNCS]) };
        serve('S1', S);
        opens['C:\\dumps\\big.dmp'] = S;
        await openInRizin('C:\\dumps\\big.dmp');
        await until(() => $('rizin-state').textContent.startsWith('busy'), 'busy');
        r.busy = [...st(), $('rizin-analysis').textContent];
        // aa had to be stopped: the reason, and Full analysis
        const why = 'Step aa did not finish within 720 s; rizin was restarted and replayed no steps.';
        Object.assign(S, { analysis: 'stopped', step: null, done: [], note: why });
        await until(() => rizinState.landed, 'landed'); await quiet();
        r.stopped = [...st(), $('rizin-state').title, $('rizin-analysis').textContent, $('rizin-analysis').title];
        // Full analysis: the poll follows aaa's steps, the button goes
        click($('rizin-full'));
        await until(() => count('POST', '/api/rizin/S1/analyze') === 1 && rizinState.analysis.state === 'running', 'Full analysis');
        r.full = [...st(), $('rizin-analysis').textContent];
        Object.assign(S, { step: 'aac', done: ['aa'], note: null });
        await until(() => $('rizin-analysis').textContent.startsWith('analysing (aac)'), 'aac');
        Object.assign(S, { analysis: 'done', step: null, done: ['aa', 'aac', 'aar'] });
        await until(() => rizinState.analysis.state === 'done', 'done'); await quiet();
        r.done = [...st(), $('rizin-analysis').textContent];

        // At sym.watchdog, another browser tab takes the file: once this one is in sight again (the RIZIN tab
        // shown) it says so
        click(row('0x140001490'));
        await until(() => rizinState.seek === '0x140001490', 'watchdog'); await quiet();
        gone.set('S1', [409, { moved: true }]);
        $('tab-rizin').classList.add('active');
        dispatch('visibilitychange', document.body);
        await until(() => rizinState.ui.state === 'moved', 'moved'); await quiet();
        r.moved = [...st(), $('rizin-state').title, rizinState.pollTimer];
        // Take it back: the same path for this tab, back at sym.watchdog with the history
        const S2 = { analysis: 'done', done: ['aaa'] };
        serve('S2', S2);
        opens['C:\\dumps\\big.dmp'] = S2;
        click($('rizin-state-btn'));
        await until(() => rizinState.session === 'S2' && rizinState.landed, 'taken back'); await quiet();
        const sent = calls.filter(c => c[1] === '/api/rizin/open').map(c => c[2]);
        r.back = [...st(), sent[sent.length - 1], sent[0].tab, rizinState.seek, rizinState.history.slice(), rizinState.historyAt,
                  seeksOf('S2'), ...marked(), $('rizin-seek').value];

        // The session ends (rizin stopped during a request): Reopen opens the file again, back at the place
        gone.set('S2', [404, { error: 'session ended', reason: 'rizin did not answer in time' }]);
        click(row('0x1400014b7'));
        await until(() => rizinState.ui.state === 'ended', 'ended'); await quiet();
        r.ended = [...st(), $('rizin-state').title, rizinState.seek];
        const S3 = { analysis: 'running', step: 'aaa', done: [] };
        serve('S3', S3);
        opens['C:\\dumps\\big.dmp'] = S3;
        click($('rizin-state-btn'));
        await until(() => rizinState.session === 'S3' && $('rizin-analysis').textContent.startsWith('analysing'), 'reopened');
        await tick(20);
        r.reopening = [...st(), $('rizin-analysis').textContent];
        Object.assign(S3, { analysis: 'done', step: null, done: ['aaa'] });
        await until(() => rizinState.landed, 'reopened and landed'); await quiet();
        r.reopened = [...st(), rizinState.seek, rizinState.history.slice(), seeksOf('S3'), ...marked()];
    """)
    assert "error" not in r, r.get("error")
    # st(): the state's hidden, text and class, its button's hidden and text, Full analysis hidden, the toolbar crowded
    hidden, text, cls, button, _, full, crowded, title, disasm = r["notInstalled"]
    assert [hidden, text, cls, button, full, crowded] == [False, "rizin not installed: C:\\tools\\cutter\\rizin.exe",
                                                          "rizin-state rizin-state-not-installed", True, True, True]
    assert "install-rizin.ps1" in title and "C:\\tools\\cutter\\rizin.exe" in disasm and "install-rizin.ps1" in disasm
    assert r["busy"][:4] == [False, "busy (aa)", "rizin-state rizin-state-busy", True] and r["busy"][5:7] == [True, True]
    assert r["busy"][7].startswith("analysing (aa)")
    why = "Step aa did not finish within 720 s; rizin was restarted and replayed no steps."
    assert r["stopped"][:4] == [False, why, "rizin-state rizin-state-stopped", True], "a stopped analysis without its reason"
    assert r["stopped"][5:7] == [False, True], "no Full analysis at level aa"
    assert r["stopped"][7] == why and r["stopped"][8].startswith("analysis stopped (aa)") and r["stopped"][9] == why
    assert r["full"][0] is True and r["full"][5] is True, "the reason or the button stayed while Full analysis runs"
    assert r["done"][0] is True and r["done"][5:7] == [True, False] and r["done"][7].startswith("analysed (aaa)")
    assert r["moved"][:7] == [False, "Open in another tab", "rizin-state rizin-state-moved", False, "Take it back", True, True]
    assert "Take it back" in r["moved"][7] and r["moved"][8] is None, "a moved session is polled"
    back = r["back"]
    assert back[:4] == [True, "", "rizin-state", True] and back[5:7] == [True, False]
    assert back[7]["path"] == "C:\\dumps\\big.dmp" and back[7]["tab"] == back[8], "Take it back did not open the same path here"
    assert back[9:] == ["0x140001490", ["0x1400014b7", "0x140001490"], 1, ["0x140001490"], "0x140001490", "0x140001490",
                        "sym.watchdog"], "Take it back lost the place or the history"
    assert r["ended"][:7] == [False, "Session ended", "rizin-state rizin-state-ended", False, "Reopen", True, True]
    assert r["ended"][7] == "rizin did not answer in time" and r["ended"][8] == "0x140001490"
    assert r["reopening"][0] is True and r["reopening"][7].startswith("analysing")
    assert r["reopened"][7:] == ["0x140001490", ["0x1400014b7", "0x140001490"], ["0x140001490"], "0x140001490",
                                 "0x140001490"], "Reopen lost the place"


@needs_node
def test_rizin_full_analysis_drops_status_answers_asked_before_it():
    """The controller's ruling: a status asked for before POST /analyze may come back after it and say the
    analysis is over, which would end the poll while the Full analysis runs. Such answers are dropped: the
    poll goes on, follows the steps and lands at the end."""
    r = _scripted(r"""
        const S = { analysis: 'stopped', step: null, level: 'aa', done: ['aa'], note: 'aaa did not finish within 720 s.',
                    statusDelay: 40 };
        serve('S1', S);
        opens['C:\\dumps\\big.dmp'] = S;
        await openInRizin('C:\\dumps\\big.dmp');
        await until(() => flying('/api/rizin/S1/status'), 'a status in flight');
        click($('rizin-full'));
        await until(() => count('POST', '/api/rizin/S1/analyze') === 1 && !flying('/api/rizin/S1/analyze'), 'analyze answered');
        await tick(1);
        r.answered = rizinState.analysis.state;
        await until(() => !flying('/api/rizin/S1/status'), 'the older status answered');
        await tick(2);
        r.older = [rizinState.analysis.state, rizinState.landed];
        S.statusDelay = 1;
        const polls = S.statusCalls;
        await until(() => S.statusCalls >= polls + 3, 'the poll goes on');
        Object.assign(S, { analysis: 'done', step: null, done: ['aa', 'aac', 'aar'] });
        await until(() => rizinState.landed, 'landed'); await quiet();
        r.end = [rizinState.analysis.state, rizinState.seek, $('rizin-full').hidden];
    """)
    assert "error" not in r, r.get("error")
    assert r["answered"] == "running"
    assert r["older"] == ["running", False], "a status asked for before Full analysis ended the poll"
    assert r["end"] == ["done", "0x1400014b7", True]


@needs_node
def test_rizin_decompiler_lines_follow_seek():
    """The brief: DECOMPILER shows rz-ghidra's C of the current function; a line with an address carries it
    in data-addr, the line of the current address is marked (the one with the nearest address at or before
    it), and a click on a line jumps there with the other views following. Hidden it asks nothing and
    catches up once shown (ruling); a jump inside the function asks nothing again; outside a function and
    with rz-ghidra missing it says so instead of an error; busy is asked again; a decompile that ended the
    session says why, with Reopen. Text from rz-ghidra stays text."""
    r = _scripted(r"""
        globalThis.innerWidth = 1920;
        rizinApplyCenterLayout();
        const S = { analysis: 'done', done: ['aaa'] };
        serve('S1', S);
        opens['C:\\x\\s.exe'] = S;
        const pane = $('rizin-decompiler');
        const tab = name => document.querySelector(`[data-rizin-tab="${name}"]`);
        const decs = sid => count('GET', `/api/rizin/${sid || 'S1'}/decompile`);
        const lines = () => pane.querySelectorAll('.rizin-dec-line');
        const mark = () => pane.querySelectorAll('.rizin-dec-line.current').map(l => [Number(l.getAttribute('data-line')), l.textContent]);
        const go = async addr => {
            $('rizin-seek').value = addr;
            click($('rizin-go'));
            await until(() => rizinState.seek === addr, 'GO ' + addr); await quiet();
        };
        await openInRizin('C:\\x\\s.exe');
        await until(() => rizinState.landed, 'landed'); await quiet();
        r.hidden = [decs(), lines().length];
        click(tab('decompiler'));
        await until(() => decs() === 1, 'the decompiler once shown'); await quiet();
        r.shown = [pane.hidden, $('rizin-disasm').hidden, lines().map(l => l.getAttribute('data-addr')), mark(),
                   lines().map(l => l.textContent), lines().map(l => l.getAttribute('title'))];
        r.c = { kw: pane.querySelectorAll('.rz-kw').map(e => e.textContent), fn: pane.querySelectorAll('.rz-fn').map(e => e.textContent),
                str: pane.querySelectorAll('.rz-str').map(e => e.textContent),
                comment: pane.querySelectorAll('.rz-comment').map(e => e.textContent),
                tags: [...pane.walk()].map(e => e.tagName).filter(t => !['DIV', 'SPAN'].includes(t)),
                handlers: [...pane.walk()].flatMap(e => Object.keys(e.attrs)).filter(a => a.startsWith('on')) };
        // Jumps inside the function: the mark moves, nothing is asked again
        await go('0x1400014bc');
        r.inIf = [mark(), decs()];
        await go('0x1400014c0');
        r.inCall = mark();
        await go('0x140001521');
        r.ret = mark();
        // A click on a line jumps to its address; the other views follow, the line clicked stays marked
        click(lines().find(l => l.textContent.includes('puts')));
        await until(() => rizinState.seek === '0x1400014be', 'line click'); await quiet();
        r.click = [mark(), ...marked(), $('rizin-seek').value, seeksOf('S1').slice(-1)[0], decs()];
        click(lines().find(l => l.textContent === '{'));
        await quiet();
        r.noAddress = [rizinState.seek, seeksOf('S1').length];
        // The same address reached another way: the first line that has it
        await go('0x140001521');
        await go('0x1400014be');
        r.first = mark();
        // Another function: its C
        click(row('0x140001490'));
        await until(() => rizinState.seek === '0x140001490', 'watchdog'); await quiet();
        r.other = [decs(), mark(), lines().length, pane.querySelectorAll('.rz-fn').map(e => e.textContent)];
        await go('0x140009000');
        r.outside = [pane.textContent, lines().length, decs()];
        // Hidden: a jump asks nothing, shown again it catches up
        click(tab('disasm'));
        const before = decs();
        click(row('0x1400014b7'));
        await until(() => rizinState.seek === '0x1400014b7', 'main'); await quiet();
        r.whileHidden = decs() - before;
        click(tab('decompiler'));
        await until(() => decs() === before + 1, 'caught up'); await quiet();
        r.caughtUp = [lines().length, pane.hidden];
        // A rename while hidden (the C names it): asked again once shown, though the place is the same
        click(tab('disasm'));
        await rizinAnnotated(); await quiet();
        const renamed = decs();
        click(tab('decompiler'));
        await until(() => decs() === renamed + 1, 'asked again after a rename'); await quiet();
        r.forced = [renamed - before - 1, decs() - renamed];
        // Busy: said in the pane, asked again once rizin is free
        let busyOnce = true;
        S.decompile = () => (busyOnce ? (busyOnce = false, [409, { busy: true, step: 'view' }]) : null);
        click(row('0x140001490'));
        await until(() => pane.textContent.includes('busy'), 'busy shown');
        r.busy = pane.textContent;
        await until(() => lines().length === DECOMPILED['sym.watchdog'].length, 'asked again'); await quiet();
        r.free = rizinState.retry.size;
        // A decompile that took too long ended the session: why, and Reopen
        S.decompile = () => [404, { error: 'session ended', reason: 'Decompiling took too long, the session ended.' }];
        click(row('0x1400014b7'));
        await until(() => rizinState.ui.state === 'ended', 'ended'); await quiet();
        r.ended = [pane.textContent, pane.querySelectorAll('button').map(b => b.textContent), $('rizin-state').textContent];
        const S2 = { analysis: 'done', done: ['aaa'],
                     decompile: () => [200, { available: false, reason: 'Decompiler not available (rz-ghidra missing)', function: null, lines: [] }] };
        serve('S2', S2);
        opens['C:\\x\\s.exe'] = S2;
        click(pane.querySelector('button'));
        await until(() => rizinState.session === 'S2' && rizinState.landed, 'reopened'); await quiet();
        // Back at sym.main, whose decompile ended the session: not asked for again on its own (review, Important 2)
        r.reopened = [pane.textContent, decs('S2'), rizinState.seek];
        // rz-ghidra missing: the note, and no more requests for it
        click(row('0x140001490'));
        await until(() => rizinState.seek === '0x140001490', 'watchdog'); await quiet();
        r.missing = [pane.textContent, decs('S2'), rizinState.seek];
        // Nor after an analysis step, a rename or a comment (forced reloads)
        await rizinReloadViews(); await quiet();
        await rizinAnnotated(); await quiet();
        r.missingForced = [pane.textContent, decs('S2')];
        click(row('0x1400014b7'));
        await until(() => rizinState.seek === '0x1400014b7', 'main'); await quiet();
        r.missingStays = [pane.textContent, decs('S2')];
    """)
    assert "error" not in r, r.get("error")
    assert r["hidden"] == [0, 0], "the hidden decompiler asked rizin"
    hidden, disasm_hidden, addrs, mark, texts, titles = r["shown"]
    assert hidden is False and disasm_hidden is True
    assert addrs == [None, None, "0x1400014b9", "0x1400014be", "0x1400014be", None, None, "0x140001529", None]
    assert mark == [], "at the function's start no line has an address before it"
    assert texts[4] == "        puts(\"<img src=x onerror=alert(1)>\" & 'q');" and texts[6] == " "
    assert titles[2] == "0x1400014b9 0x1400014bc" and titles[7] == "0x140001521 0x140001529" and titles[0] is None
    c = r["c"]
    assert c["kw"] == ["int", "int", "char", "if", "return"] and c["fn"] == ["main", "watchdog", "puts"]
    assert c["str"] == ['"<img src=x onerror=alert(1)>"', "'q'"] and c["comment"] == ['/* starts the "watch" */']
    assert c["tags"] == [] and c["handlers"] == [], "text from rz-ghidra became markup"
    assert r["inIf"] == [[[2, "    if (argc < 3) {"]], 1], "a jump inside the function asked again, or the mark did not move"
    assert r["inCall"] == [[3, "        watchdog(); /* starts the \"watch\" */"]], "not the nearest address before the place"
    assert r["ret"] == [[7, "    return 0;"]]
    click_mark, fn_row, line, seek, posted, decs = r["click"]
    assert click_mark[0][0] == 4 and [fn_row, line, seek, posted, decs] == ["0x1400014b7", "0x1400014be", "0x1400014be",
                                                                              "0x1400014be", 1]
    assert r["noAddress"][0] == "0x1400014be"
    assert r["first"] == [[3, "        watchdog(); /* starts the \"watch\" */"]]
    assert r["other"] == [2, [], 6, ["watchdog", "sym.imp.KERNEL32.dll_Sleep"]], "a called function with dots in its name"
    assert r["outside"] == ["No function at 0x140009000", 0, 3]
    assert r["whileHidden"] == 0 and r["caughtUp"] == [9, False]
    assert r["forced"] == [0, 1], "a rename while the decompiler was hidden was not asked for once it showed"
    assert "busy (view)" in r["busy"] and r["free"] == 0
    assert r["ended"] == ["Decompiling took too long, the session ended. Reopen", ["Reopen"], "Session ended"]
    assert r["reopened"][0].startswith("Decompiling sym.main took too long") and r["reopened"][1:] == [0, "0x1400014b7"]
    assert r["missing"] == ["Decompiler not available (rz-ghidra missing)", 1, "0x140001490"]
    assert r["missingForced"] == ["Decompiler not available (rz-ghidra missing)", 1], \
        "a forced reload asked rizin again although rz-ghidra is missing (review, Minor 4)"
    assert r["missingStays"] == ["Decompiler not available (rz-ghidra missing)", 1], "rz-ghidra missing was asked again"


@needs_node
def test_rizin_decompiler_c_patterns_are_linear():
    """rz-ghidra's lines have no length limit: the C patterns take linear time on long identifiers, strings
    and comments that nothing closes, and on long runs of spaces before a call. Measured as the best of
    three runs after a warm-up, against a wide bound: a cold sample measures the machine as much as the
    patterns, while a super-linear one would take seconds to minutes here (follow-up finding 3)."""
    r = _run(r"""
        const cases = { ident: 'a'.repeat(30000), call: 'f' + ' '.repeat(30000) + '(', string: '"' + '\\"'.repeat(15000),
                        comment: '/*' + '*'.repeat(30000), spaces: 'x '.repeat(15000), dots: 'a.'.repeat(15000) + '(' };
        const out = {};
        for (const [name, text] of Object.entries(cases)) {
            rizinCHtml(text);
            let best = Infinity, html = '';
            for (let i = 0; i < 3; i++) {
                const t0 = performance.now();
                html = rizinCHtml(text);
                best = Math.min(best, performance.now() - t0);
            }
            out[name] = [best, html.replace(/<[^>]*>/g, '').length];
        }
        console.log(JSON.stringify(out));
    """, SORT_DOM + _rizin_prelude())
    for name, (ms, length) in r.items():
        assert ms < 2000, f"{name}: {ms} ms"
    assert r["call"][1] == 30002 and r["ident"][1] == 30000


@needs_node
def test_rizin_decompiler_marks_a_line_of_code_at_the_place():
    """VM check (Task 8): rz-ghidra gives the WARNING comments it writes above a function's signature the
    function's address, and a comment set with CC the address it is at, so the first line with the address
    was a comment: at sym.main's entry DECOMPILER marked "// WARNING: Variable defined which should be
    unmapped: bInheritHandles" instead of the signature. Of the lines with the nearest address the first line
    of code is marked; only a place that has nothing but comments marks the first of them."""
    r = _run(r"""
        const E = 0x1400014b7;
        const cline = (text, ...addrs) => ({ text, offset: addrs.length ? addrs[0] : null, offsets: [...addrs].sort((a, b) => a - b) });
        const lines = [
            cline(' '),
            cline('// WARNING: Variable defined which should be unmapped: bInheritHandles', E),
            cline("// WARNING: [rz-ghidra] Removing arg _Format because it doesn't fit into ProtoModel", E),
            cline(' '),
            cline('undefined4 sym.main(int argc, char **argv, HANDLE hNamedPipe, int64_t arg_f8h)', E),
            cline('{'),
            cline('    dbg.__main();', E + 0x18),
            cline('    // t8: the pipe <b>server</b>', E + 0x102),
            cline('    iVar8 = (*(code *)0x9580)(&__stream, 3, 6, 0xff);', E + 0x102),
            cline('    /* only a comment */', E + 0x200),
            cline('    // set below', E + 0x300),
            cline('    /* a note */ x = 1;', E + 0x300),
            cline('}'),
        ];
        const only = [cline('// WARNING: one', E), cline('// WARNING: two', E), cline('{')];
        console.log(JSON.stringify({
            entry: rizinDecompilerMark(lines, E), inside: rizinDecompilerMark(lines, E + 0x10),
            call: rizinDecompilerMark(lines, E + 0x18), commented: rizinDecompilerMark(lines, E + 0x102),
            commentOnly: rizinDecompilerMark(lines, E + 0x200), noteFirst: rizinDecompilerMark(lines, E + 0x300),
            only: rizinDecompilerMark(only, E), clicked: rizinDecompilerMark(lines, E, 2),
            before: rizinDecompilerMark(lines, E - 1), html: rizinDecompilerHtml(lines, { current: '0x1400014b7' }),
        }));
    """, SORT_DOM + _rizin_prelude())
    html = r.pop("html")
    assert r == {"entry": 4, "inside": 4, "call": 6, "commented": 8, "commentOnly": 9, "noteFirst": 11,
                 "only": 0, "clicked": 2, "before": -1}, "a comment was marked although a line of code has the address"
    marked = re.findall(r'<div class="rizin-dec-line current[^"]*" data-line="(\d+)"', html)
    assert marked == ["4"], "the signature line is not the one marked at the function's entry"


@needs_node
def test_rizin_decompiler_stops_pick_the_address_a_click_acts_on():
    """Review Focus 1, 2 und 3. `offset` ist die erste Annotation in rizins Reihenfolge, nicht die
    niedrigste Adresse der Zeile (gemessen im Modell: 0x1400015BF steht vor 0x1400015B9), also nimmt
    ein Klick die niedrigste: "vor dieser Zeile". Trägt irgendeine Adresse der Zeile schon einen
    Breakpoint, wirkt der Klick auf diese, damit ein zweiter Klick nicht einen weiteren setzt.
    Gehört ein Befehl zu mehreren C-Zeilen, tragen alle die Marke."""
    r = _run(r"""
        const brace = { text: '{', offset: null, offsets: [] };
        const iff = { text: '    if (argc < 3) {', offset: 0x1400014c5, offsets: [0x1400014c5, 0x1400014c8] };
        const pipe = { text: '    hPipe = CreateNamedPipeA(lpName);', offset: 0x1400015bf,
                       offsets: [0x1400015b9, 0x1400015bf] };
        const only = { text: '    y = 1;', offset: 0x1000 };
        const appended = { text: '    z = 2;', offset: 0x9, offsets: [0x10, 0x20] };
        const shared = [{ text: '    if (x) {', offset: 0x1000, offsets: [0x1000] },
                        { text: '        y = 1;', offset: 0x1000, offsets: [0x1000, 0x1004] }];
        console.log(JSON.stringify({
            none: rizinDecompilerStops([brace, iff, pipe], []),
            high: rizinDecompilerStops([pipe], [0x1400015bf]),
            low: rizinDecompilerStops([pipe], [0x1400015b9]),
            both: rizinDecompilerStops([pipe], [0x1400015b9, 0x1400015bf]),
            elsewhere: rizinDecompilerStops([only], [0x9000]),
            offsetOnly: rizinDecompilerStops([only], []),
            appended: rizinDecompilerStops([appended], []),
            shared: rizinDecompilerStops(shared, [0x1000]),
        }));
    """, SORT_DOM + _rizin_prelude())
    assert r["none"] == [None, {"addr": "0x1400014c5", "set": False}, {"addr": "0x1400015b9", "set": False}], \
        "a line without an address is clickable, or the click does not take the line's lowest address"
    assert r["high"] == [{"addr": "0x1400015bf", "set": True}], "a breakpoint inside the line is not found"
    assert r["low"] == [{"addr": "0x1400015b9", "set": True}]
    assert r["both"] == [{"addr": "0x1400015b9", "set": True}], \
        "with two set the lowest must win, or one stays behind after a click"
    assert r["elsewhere"] == [{"addr": "0x1000", "set": False}], "a breakpoint of another function marks a line"
    assert r["offsetOnly"] == [{"addr": "0x1000", "set": False}], "a line with only `offset` is skipped"
    assert r["appended"] == [{"addr": "0x9", "set": False}], \
        "an `offset` that `offsets` lacks and that is the lowest is not the one taken (or the sort is not numeric)"
    assert r["shared"] == [{"addr": "0x1000", "set": True}, {"addr": "0x1000", "set": True}], \
        "an instruction that belongs to two C lines marks only one of them"


@needs_node
def test_rizin_hex_view_shows_the_bytes_and_opens_the_hex_tab():
    """The brief: HEX shows 512 bytes from the current address, 16 a row, with an ASCII column, and Open in
    Hex tab opens the same file in the Hex tab at the file offset of the current address (the route's
    paddr; there is none where no byte of the file is). Hidden it asks nothing and catches up once shown."""
    r = _scripted(r"""
        globalThis.innerWidth = 1920;
        rizinApplyCenterLayout();
        const S = { analysis: 'done', done: ['aaa'] };
        serve('S1', S);
        opens['C:\\x\\s.exe'] = S;
        const hexed = [];
        globalThis.hexOpenFile = (path, offset) => hexed.push([path, offset]);
        const pane = $('rizin-hex');
        const tab = name => document.querySelector(`[data-rizin-tab="${name}"]`);
        const asked = () => calls.filter(c => c[1].startsWith('/api/rizin/S1/hex')).map(c => c[1]);
        const rows = () => pane.querySelectorAll('.rizin-hex-row');
        await openInRizin('C:\\x\\s.exe');
        await until(() => rizinState.landed, 'landed'); await quiet();
        r.hidden = asked().length;
        click(tab('hex'));
        await until(() => asked().length === 1, 'shown'); await quiet();
        const first = rows()[0];
        r.shown = [asked(), rows().length, rows().map(row => row.getAttribute('data-addr')).slice(0, 2),
                   first.querySelector('.rz-addr').textContent, first.querySelector('.rizin-hex-bytes').textContent,
                   first.querySelector('.rizin-hex-ascii').textContent, pane.querySelectorAll('.rizin-hex-cur').map(e => e.textContent),
                   pane.querySelector('.rizin-hex-bar').textContent];
        // Bytes that are markup in ASCII stay text: 0x22 " 0x26 & 0x3c < 0x3e >
        const ascii = rows().map(row => row.querySelector('.rizin-hex-ascii').textContent).join('');
        r.ascii = [ascii.includes('"#$%&\'()*+,-./0123456789:;<=>?'), [...pane.walk()].filter(e => !['DIV', 'SPAN', 'BUTTON'].includes(e.tagName)).length];
        click(pane.querySelector('[data-action="hex-tab"]'));
        r.opened = hexed.slice();
        // An address without a byte of the file: no offset, the button does nothing
        $('rizin-seek').value = '0x140009000';
        click($('rizin-go'));
        await until(() => rizinState.seek === '0x140009000', 'GO'); await quiet();
        const button = pane.querySelector('[data-action="hex-tab"]');
        click(button);
        r.unmapped = [pane.querySelector('.rizin-hex-bar').textContent, button.hasAttribute('disabled'), hexed.length];
        // Hidden: a jump asks nothing; shown again it catches up
        click(tab('disasm'));
        const n = asked().length;
        click(row('0x140001490'));
        await until(() => rizinState.seek === '0x140001490', 'jump'); await quiet();
        r.whileHidden = asked().length - n;
        click(tab('hex'));
        await until(() => asked().length === n + 1, 'caught up'); await quiet();
        r.caughtUp = [rows()[0].getAttribute('data-addr'), asked().slice(-1)[0]];
        // A forced reload while hidden (a finished analysis step): asked again once shown, at the same place
        click(tab('disasm'));
        await rizinReloadViews(); await quiet();
        const m = asked().length;
        click(tab('hex'));
        await until(() => asked().length === m + 1, 'the forced reload once shown'); await quiet();
        r.forced = [m - n - 1, asked().length - m];
    """)
    assert "error" not in r, r.get("error")
    assert r["hidden"] == 0, "the hidden HEX asked rizin"
    asked, n, addrs, addr, hexes, ascii, current, bar = r["shown"]
    assert asked == ["/api/rizin/S1/hex?addr=0x1400014b7&len=512"] and n == 32
    assert addrs == ["0x1400014b7", "0x1400014c7"] and addr == "0x1400014b7"
    assert hexes == "b7 b8 b9 ba bb bc bd be  bf c0 c1 c2 c3 c4 c5 c6" and ascii == "." * 16
    assert current == ["b7", "."], "the byte of the current address is not marked"
    assert "512 bytes at 0x1400014b7" in bar and "file offset 0x14b7" in bar and "Open in Hex tab" in bar
    assert r["ascii"] == [True, 0], "a byte became markup"
    assert r["opened"] == [["C:\\x\\s.exe", 0x14B7]]
    assert "not in the file" in r["unmapped"][0] and r["unmapped"][1:] == [True, 1]
    assert r["whileHidden"] == 0 and r["caughtUp"] == ["0x140001490", "/api/rizin/S1/hex?addr=0x140001490&len=512"]
    assert r["forced"] == [0, 1], "a forced reload while HEX was hidden was not asked for once it showed"


@needs_node
def test_rizin_hex_tab_opens_at_an_offset():
    """Open in Hex tab reuses the Hex tab's own open (hexOpenFile): with an offset the page starts at its
    row of 16 and the byte is selected once loaded; without one it opens at 0 as before. A load that failed
    (the Hex tab shows why) selects nothing: the bytes shown may still be another file's."""
    r = _run_node(["hexOpenFile", "escapeHtml"], r"""
        (async () => {
            document.body.innerHTML = MARKUP;
            const done = [];
            let works = true;
            globalThis.switchTab = name => done.push(['TAB', name]);
            globalThis.hexLoad = async () => {
                done.push(['LOAD', document.getElementById('hex-filepath').value, document.getElementById('hex-offset').value]);
                return works;
            };
            globalThis.hexSelectByte = idx => done.push(['SELECT', idx]);
            await hexOpenFile('C:\\x\\s.exe', 0x14b7);
            await hexOpenFile('C:\\x\\t.exe');
            await hexOpenFile('C:\\x\\u.exe', 0);
            works = false;
            await hexOpenFile('C:\\x\\v.exe', 0x20);
            console.log(JSON.stringify(done));
        })().catch(e => console.log(JSON.stringify({ error: e.stack })));
    """.replace("MARKUP", json.dumps(_tab_markup("hexeditor"))), SORT_DOM)
    assert "error" not in r, r
    assert r == [["TAB", "hexeditor"], ["LOAD", "C:\\x\\s.exe", "5296"], ["SELECT", 7],
                 ["TAB", "hexeditor"], ["LOAD", "C:\\x\\t.exe", "0"],
                 ["TAB", "hexeditor"], ["LOAD", "C:\\x\\u.exe", "0"], ["SELECT", 0],
                 ["TAB", "hexeditor"], ["LOAD", "C:\\x\\v.exe", "32"]], "a byte was selected after a failed load"


@needs_node
def test_rizin_disasm_loads_more_on_scroll():
    """The brief: a long function comes in pages; scrolled near its end, DISASSEMBLY asks for the next one
    (after its last line) and adds it, the lines in sight staying where they are; the page then holds every
    line loaded (a jump there asks nothing, the right-click menu finds a comment there). One request at a
    time (a scroll or a click on the line under the last one while a page is on its way asks nothing); a
    page for a place left is dropped; at the end of the function nothing more is asked; busy says so, and a
    scroll or a click asks again."""
    r = _scripted(r"""
        // Lines 20 px high one under the other, the view 200 px high
        Object.defineProperties(Element.prototype, {
            offsetTop: { configurable: true, get() { return this.parentNode ? this.parentNode.children.indexOf(this) * 20 : 0; } },
            offsetHeight: { configurable: true, get() { return 20; } },
            clientHeight: { configurable: true, get() { return 200; } },
            scrollHeight: { configurable: true, get() { return this.children.length * 20; } },
        });
        RIZIN_MORE.wait = 5;
        const pane = $('rizin-disasm');
        pane.scrollTop = 0;
        // sym.main: 1000 instructions of a byte, 400 a page; the 500th has a comment
        const big = Array.from({ length: 1000 }, (_, i) => op(0x1400014b7 + i, 1, `nop`, 'nop', null, i === 500 ? 'seen' : null));
        const asked = [];
        let delay = 1, busy = false;
        const S = { analysis: 'done', done: ['aaa'], disasm: (hex, s, url) => {
            if (fnAt(parseInt(hex, 16))?.name !== 'sym.main') return null;
            const after = new URLSearchParams(url.split('?')[1]).get('after');
            asked.push(after);
            if (busy) { busy = false; return [409, { busy: true, step: 'view' }]; }
            const from = after === null ? 0 : big.findIndex(o => o.offset > parseInt(after, 16));
            return [200, { function: 'sym.main', ops: big.slice(from, from + 400), more: from + 400 < big.length }, delay];
        } };
        serve('S1', S);
        opens['C:\\x\\s.exe'] = S;
        await openInRizin('C:\\x\\s.exe');
        await until(() => rizinState.landed, 'landed'); await quiet();
        const lines = () => pane.querySelectorAll('.rizin-op').length;
        const more = () => pane.querySelector('.rizin-more')?.textContent ?? null;
        r.first = [lines(), asked.slice(), more()];
        dispatch('scroll', pane);
        await quiet();
        r.top = asked.length;
        // Near the end: the next page, once, after the last line
        pane.scrollTop = 400 * 20 - 200 - 100;
        delay = 20;
        dispatch('scroll', pane);
        r.loading = more();
        dispatch('scroll', pane);
        // A click on the line while the page is on its way asks nothing more either
        click(pane.querySelector('.rizin-more'));
        await quiet();
        r.second = [lines(), asked.slice(), pane.scrollTop, rizinState.disasm.ops.length, more()];
        // The page holds what was added: a jump there asks nothing, the menu has the comment there
        const pages = count('GET', '/api/rizin/S1/disasm');
        $('rizin-seek').value = '0x1400016ab';
        click($('rizin-go'));
        await until(() => rizinState.seek === '0x1400016ab', 'GO'); await quiet();
        dispatch('contextmenu', pane.querySelector('.rizin-op[data-addr="0x1400016ab"] .rz-addr'), { clientX: 10, clientY: 10 });
        r.held = [count('GET', '/api/rizin/S1/disasm') - pages, marked()[1], rizinState.menu && rizinState.menu.comment];
        rizinCloseMenu();
        // Busy: said under the last line; the next scroll asks again
        busy = true;
        pane.scrollTop = 800 * 20 - 300;
        dispatch('scroll', pane);
        await quiet();
        r.busy = [more(), lines(), asked.length];
        await tick(10);
        dispatch('scroll', pane);
        await quiet();
        r.last = [lines(), asked.slice(-2), more(), rizinState.disasm.more];
        // At the end of the function nothing more is asked
        pane.scrollTop = 1000 * 20 - 200;
        dispatch('scroll', pane);
        await quiet();
        r.end = asked.length;
        // A page that comes for a place left is dropped
        click(row('0x140001490'));
        await until(() => rizinState.seek === '0x140001490', 'watchdog'); await quiet();
        click(row('0x1400014b7'));
        await until(() => rizinState.seek === '0x1400014b7' && rizinState.disasm.ops.length === 400, 'the first page again');
        await quiet();
        delay = 40;
        pane.scrollTop = 400 * 20 - 300;
        dispatch('scroll', pane);
        await until(() => flying('/api/rizin/S1/disasm'), 'the next page on its way');
        click(row('0x140001490'));
        await until(() => rizinState.seek === '0x140001490', 'watchdog again'); await quiet();
        r.dropped = [rizinState.disasm.function, rizinState.disasm.ops.length, lines()];
    """)
    assert "error" not in r, r.get("error")
    assert r["first"][0] == 400 and r["first"][1] == [None] and r["first"][2], "the first page or its line for more"
    assert r["top"] == 1, "more was asked for at the top"
    assert r["loading"] and "Loading" in r["loading"]
    lines, asked, top, ops, more = r["second"]
    assert lines == 800 and asked == [None, "0x140001646"], "the next page was not asked for once, after the last line"
    assert top == 400 * 20 - 300 and ops == 800 and more
    assert r["held"] == [0, "0x1400016ab", "seen"], "the page added was not part of the page shown"
    busy, lines, n = r["busy"]
    assert "busy" in busy and lines == 800 and n == 3
    assert r["last"] == [1000, ["0x1400017d6", "0x1400017d6"], None, False]
    assert r["end"] == 4, "more was asked for at the end of the function"
    assert r["dropped"] == ["sym.watchdog", 4, 4], "a late page for a place left was added"


@needs_node
def test_rizin_closes_its_session_on_pagehide():
    """The brief: the page going (a reload, another address, its browser tab closed) ends its session with
    navigator.sendBeacon('/api/rizin/<sid>/close'), which still goes out while the page unloads; nothing
    for a page without a session, nor once the session moved to another tab or ended. Back from the
    browser's cache the toolbar says the session ended, with Reopen."""
    r = _scripted(r"""
        const beacons = [];
        Object.defineProperty(globalThis, 'navigator', { configurable: true, writable: true,
            value: { sendBeacon: (url, body) => { beacons.push([url, body === undefined ? null : String(body)]); return true; } } });
        const hide = () => windowListeners.filter(l => l.type === 'pagehide').forEach(l => l.fn({ type: 'pagehide', persisted: false }));
        r.listeners = windowListeners.filter(l => l.type === 'pagehide').length;
        hide();
        r.none = beacons.length;
        const S = { analysis: 'done', done: ['aaa'] };
        serve('S1', S);
        opens['C:\\x\\s.exe'] = S;
        await openInRizin('C:\\x\\s.exe');
        await until(() => rizinState.landed, 'landed'); await quiet();
        const n = calls.length;
        hide();
        r.sent = [beacons.slice(), calls.length - n, rizinState.ui.state, $('rizin-state').textContent, $('rizin-state-btn').hidden,
                  $('rizin-state-btn').textContent];
        hide();
        r.once = beacons.length;
        // Opened again; then the file moves to another tab: that tab's session now, no beacon
        const S2 = { analysis: 'done', done: ['aaa'] };
        serve('S2', S2);
        opens['C:\\x\\s.exe'] = S2;
        click($('rizin-state-btn'));
        await until(() => rizinState.session === 'S2' && rizinState.landed, 'reopened'); await quiet();
        gone.set('S2', [409, { moved: true }]);
        click(row('0x140001490'));
        await until(() => rizinState.ui.state === 'moved', 'moved');
        hide();
        r.moved = beacons.length;
    """)
    assert "error" not in r, r.get("error")
    assert r["listeners"] == 1 and r["none"] == 0
    beacons, fetched, state, text, hidden, label = r["sent"]
    assert beacons == [["/api/rizin/S1/close", ""]] and fetched == 0, "the session was not closed by a beacon"
    assert [state, text, hidden, label] == ["ended", "Session ended", False, "Reopen"]
    assert r["once"] == 1 and r["moved"] == 1, "a beacon for a session that ended or moved"


# --- Task 7 review fixes ---------------------------------------------------------------------------------------

# The style sheet's layout in the test DOM, as a browser has it: an element that is not laid out (hidden itself
# or inside a hidden one, in a TDC tab in the background, or the code views while GRAPH or ⇱ has their place)
# reports no size and no scroll position; one that is has lines 20 px high in views 200 px high
LAID_OUT = r"""
const laidOut = el => {
    const center = document.getElementById('rizin-center');
    const codeGone = !!center && (center.classList.contains('rizin-max-graph')
        || (center.classList.contains('rizin-narrow') && center.classList.contains('rizin-show-graph')));
    for (let e = el; e && e.tagName; e = e.parentNode) {
        if (e.hidden || (e.classList.contains('tab-content') && !e.classList.contains('active'))) return false;
        if (codeGone && e.id === 'rizin-code') return false;
    }
    return true;
};
Object.defineProperties(Element.prototype, {
    offsetTop: { configurable: true, get() { return laidOut(this) && this.parentNode ? this.parentNode.children.indexOf(this) * 20 : 0; } },
    offsetHeight: { configurable: true, get() { return laidOut(this) ? 20 : 0; } },
    clientHeight: { configurable: true, get() { return laidOut(this) ? 200 : 0; } },
    scrollHeight: { configurable: true, get() { return laidOut(this) ? this.children.length * 20 : 0; } },
    scrollTop: { configurable: true, get() { return laidOut(this) ? this._scrollTop || 0 : 0; },
                 set(v) { if (laidOut(this)) this._scrollTop = Math.max(0, Number(v) || 0); } },
});
document.getElementById('tab-rizin').classList.add('active');
globalThis.innerWidth = 1920;
rizinApplyCenterLayout();
RIZIN_MORE.wait = 5;
const tab = name => document.querySelector(`[data-rizin-tab="${name}"]`);
const go = async addr => {
    $('rizin-seek').value = addr;
    click($('rizin-go'));
    await until(() => rizinState.seek === addr, 'GO ' + addr); await quiet();
};
const lines = () => (rizinState.disasm ? rizinState.disasm.ops.length : 0);
// Outside functions every page goes on, as rizin reads on through zeros (add byte [rax], al): the first page at
// an address has first[addr] lines (pageLines unless set), every next one pageLines; afters: [addr, after] of
// each next page asked for
const first = {}, afters = [];
let pageLines = 400;
const linearPage = (hex, url) => {
    const after = new URLSearchParams(url.split('?')[1]).get('after');
    if (after !== null) afters.push([hex, after]);
    const from = after === null ? parseInt(hex, 16) : parseInt(after, 16) + 2;
    const n = after === null ? first[hex] ?? pageLines : pageLines;
    return [200, { function: null, more: true, ops: Array.from({ length: n }, (_, i) => op(from + 2 * i, 2, 'add byte [rax], al', 'add')) }];
};
"""


@needs_node
def test_rizin_disasm_pages_only_while_in_sight():
    """Review, Critical 1: a DISASSEMBLY that is not laid out (DECOMPILER or HEX chosen, GRAPH chosen below
    1400 px, the RIZIN tab in the background) has no height, which read as scrolled to its end: it asked for
    page after page by itself, outside functions without end. Hidden it asks for none; back in sight a page
    shorter than the view catches up at once (the tab of DISASSEMBLY, the RIZIN tab shown, GRAPH giving the
    place back)."""
    r = _scripted(LAID_OUT + r"""
        const pane = $('rizin-disasm');
        const S = { analysis: 'done', done: ['aaa'], disasm: (hex, s, url) => (fnAt(parseInt(hex, 16)) ? null : linearPage(hex, url)) };
        serve('S1', S);
        opens['C:\\x\\s.exe'] = S;
        await openInRizin('C:\\x\\s.exe');
        await until(() => rizinState.landed, 'landed'); await quiet();
        // HEX chosen: a place outside functions draws its page there, which asks for no next one
        click(tab('hex')); await quiet();
        await go('0x140005010');
        r.hex = [afters.length, lines(), pane.clientHeight];
        // DECOMPILER chosen, and a finished analysis step (a forced reload)
        click(tab('decompiler')); await quiet();
        await go('0x140005800');
        await rizinReloadViews(); await quiet();
        r.decompiler = [afters.length, lines()];
        // In sight at its top: nothing yet
        click(tab('disasm')); await quiet();
        r.inSight = afters.length;
        // Below 1400 px with GRAPH chosen
        globalThis.innerWidth = 1280; rizinApplyCenterLayout();
        click(tab('graph')); await quiet();
        await go('0x140006000');
        r.graph = [afters.length, lines(), pane.clientHeight];
        // The RIZIN tab in the background (another TDC tab shown) while an analysis step ends
        globalThis.innerWidth = 1920; rizinApplyCenterLayout(); await quiet();
        $('tab-rizin').classList.remove('active');
        await rizinReloadViews(); await quiet();
        r.background = [afters.length, lines(), pane.clientHeight];
        $('tab-rizin').classList.add('active');
        rizinTabShown(); await quiet();
        r.backInSight = afters.length;      // a long page: the next one only once scrolled down
        // A page shorter than the view, drawn while hidden, catches up once in sight: HEX to DISASSEMBLY
        first['0x140007000'] = 3;
        click(tab('hex')); await quiet();
        await go('0x140007000');
        r.shortHidden = [afters.length, lines()];
        click(tab('disasm'));
        await until(() => afters.length === 1, 'caught up'); await quiet();
        r.shortShown = [afters[0], lines()];
        // ... the RIZIN tab shown again
        first['0x140008000'] = 3;
        $('tab-rizin').classList.remove('active');
        await rizinSeek('0x140008000', 'console'); await quiet();
        r.tabHidden = [afters.length, lines()];
        $('tab-rizin').classList.add('active');
        rizinTabShown();
        await until(() => afters.length === 2, 'caught up with the tab'); await quiet();
        r.tabShown = [afters[1], lines()];
        // ... GRAPH below 1400 px giving the place back
        first['0x140008800'] = 3;
        globalThis.innerWidth = 1280; rizinApplyCenterLayout();
        click(tab('graph')); await quiet();
        await go('0x140008800');
        r.graphHidden = [afters.length, lines()];
        click(tab('disasm'));
        await until(() => afters.length === 3, 'caught up after GRAPH'); await quiet();
        r.graphShown = [afters[2], lines()];
    """)
    assert "error" not in r, r.get("error")
    assert r["hex"] == [0, 400, 0], "the hidden DISASSEMBLY asked for its next page (HEX chosen)"
    assert r["decompiler"] == [0, 400], "the hidden DISASSEMBLY asked for its next page (DECOMPILER chosen)"
    assert r["inSight"] == 0
    assert r["graph"] == [0, 400, 0], "the hidden DISASSEMBLY asked for its next page (GRAPH chosen below 1400 px)"
    assert r["background"] == [0, 400, 0], "the DISASSEMBLY of a RIZIN tab in the background asked for its next page"
    assert r["backInSight"] == 0
    assert r["shortHidden"] == [0, 3]
    assert r["shortShown"] == [["0x140007000", "0x140007004"], 403], "a short page did not catch up once in sight"
    assert r["tabHidden"] == [1, 3]
    assert r["tabShown"] == [["0x140008000", "0x140008004"], 403], "a short page did not catch up with the RIZIN tab"
    assert r["graphHidden"] == [2, 3]
    assert r["graphShown"] == [["0x140008800", "0x140008804"], 403], "a short page did not catch up after GRAPH"


@needs_node
def test_rizin_linear_disasm_stops_after_its_limit():
    """Review, Critical 1: outside functions rizin reads on without end (zeros are instructions too), so the
    linear disassembly stops after RIZIN_MORE.linear lines, also when it is scrolled, and says how to read
    on; a function goes on to its end however long it is. (Pages of 100 and a limit of 500 here: the test
    DOM finds a line's place slowly.)"""
    r = _scripted(LAID_OUT + r"""
        pageLines = 100;
        RIZIN_MORE.linear = 500;
        const pane = $('rizin-disasm');
        // sym.main: 700 instructions of a byte, in pages of 100
        const big = Array.from({ length: 700 }, (_, i) => op(0x1400014b7 + i, 1, 'nop', 'nop'));
        const S = { analysis: 'done', done: ['aaa'], disasm: (hex, s, url) => {
            if (fnAt(parseInt(hex, 16))?.name !== 'sym.main') return fnAt(parseInt(hex, 16)) ? null : linearPage(hex, url);
            const after = new URLSearchParams(url.split('?')[1]).get('after');
            const from = after === null ? 0 : big.findIndex(o => o.offset > parseInt(after, 16));
            return [200, { function: 'sym.main', ops: big.slice(from, from + 100), more: from + 100 < big.length }];
        } };
        serve('S1', S);
        opens['C:\\x\\s.exe'] = S;
        await openInRizin('C:\\x\\s.exe');
        await until(() => rizinState.landed, 'landed'); await quiet();
        const end = async () => { pane.scrollTop = pane.scrollHeight - 200; dispatch('scroll', pane); await quiet(); };
        await go('0x140005010');
        for (let i = 0; i < 8; i++) await end();
        r.linear = [lines(), afters.length, rizinState.disasm.more, pane.querySelector('.rizin-more')?.textContent ?? null,
                    pane.querySelector('.rizin-disasm-end')?.textContent ?? null];
        click(pane.querySelector('.rizin-disasm-end')); await quiet();
        r.clicked = afters.length;
        // A function longer than the limit goes on to its end
        click(row('0x1400014b7'));
        await until(() => rizinState.seek === '0x1400014b7', 'main'); await quiet();
        for (let i = 0; i < 10; i++) await end();
        r.fn = [lines(), rizinState.disasm.more, !!pane.querySelector('.rizin-disasm-end')];
    """)
    assert "error" not in r, r.get("error")
    n, asked, more, more_line, end = r["linear"]
    assert [n, asked, more, more_line] == [500, 4, False, None], "the linear disassembly did not stop at its limit"
    assert end and "500" in end and "SEEK" in end, "the end of the linear disassembly does not say how to read on"
    assert r["clicked"] == 4
    assert r["fn"] == [700, False, False], "a function did not go on to its end"


@needs_node
def test_rizin_disasm_shows_a_place_reached_while_another_view_was_chosen():
    """VM check (Task 8): with DECOMPILER chosen, a click on a line of C moved the place deep into the
    function; DISASSEMBLY marked that line while it had no size, so it could not scroll to it, and chosen
    again it showed the start of the function with the marked line out of sight (the same after HEX, and
    with the RIZIN tab in the background). A place reached while DISASSEMBLY was not in sight comes into
    sight once it is; without a jump in between it stays where it was scrolled to."""
    r = _scripted(LAID_OUT + r"""
        const pane = $('rizin-disasm');
        // sym.main: 300 instructions, all on its first page
        const base = 0x1400014b7, at = i => '0x' + (base + 4 * i).toString(16);
        const big = Array.from({ length: 300 }, (_, i) => op(base + 4 * i, 4, 'nop', 'nop'));
        const S = { analysis: 'done', done: ['aaa'],
                    disasm: hex => (fnAt(parseInt(hex, 16))?.name === 'sym.main' ? [200, { function: 'sym.main', ops: big, more: false }] : null) };
        serve('S1', S);
        opens['C:\\x\\s.exe'] = S;
        await openInRizin('C:\\x\\s.exe');
        await until(() => rizinState.landed, 'landed'); await quiet();
        const sight = () => {
            const cur = pane.querySelector('.rizin-op.current');
            return cur ? [cur.getAttribute('data-addr'), cur.offsetTop >= pane.scrollTop
                          && cur.offsetTop + cur.offsetHeight <= pane.scrollTop + pane.clientHeight] : null;
        };
        r.landed = sight();
        // DECOMPILER chosen: the place moves deep into the function, then DISASSEMBLY is chosen again
        click(tab('decompiler')); await quiet();
        await go(at(150));
        click(tab('disasm')); await quiet();
        r.decompiler = sight();
        // HEX chosen: back near the start
        click(tab('hex')); await quiet();
        await go(at(10));
        click(tab('disasm')); await quiet();
        r.hex = sight();
        // No jump in between: it stays where it was scrolled to
        pane.scrollTop = 2000;
        click(tab('hex')); await quiet();
        click(tab('disasm')); await quiet();
        r.kept = pane.scrollTop;
        // The RIZIN tab in the background while the place moves
        $('tab-rizin').classList.remove('active');
        await rizinSeek(at(250), 'console'); await quiet();
        $('tab-rizin').classList.add('active');
        rizinTabShown(); await quiet();
        r.tab = sight();
        // A jump while DISASSEMBLY is in sight scrolls it as before
        await go(at(40));
        r.inSight = sight();
    """)
    assert "error" not in r, r.get("error")
    assert r["landed"] == ["0x1400014b7", True]
    assert r["decompiler"] == ["0x14000170f", True], "the place reached with DECOMPILER chosen is out of sight"
    assert r["hex"] == ["0x1400014df", True], "the place reached with HEX chosen is out of sight"
    assert r["kept"] == 2000, "DISASSEMBLY did not keep where it was scrolled to"
    assert r["tab"] == ["0x14000189f", True], "the place reached with the RIZIN tab in the background is out of sight"
    assert r["inSight"] == ["0x140001557", True]
    assert "app.js?v=94" not in _read(INDEX_HTML), "app.js changed after the VM check, its version did not"


@needs_node
def test_rizin_reopen_after_a_slow_decompile_does_not_decompile_again():
    """Review, Important 2: a decompile that took too long ended the session; Reopen lands at the same place
    with DECOMPILER still chosen, which asked rz-ghidra for the same function again, and 120 s later the
    session ended the same way. The function is remembered for the file: in a session of it DECOMPILER says
    so with Decompile again instead of asking on its own (not after an analysis step either), other functions
    and other files decompile as before, and Decompile again asks once."""
    r = _scripted(r"""
        globalThis.innerWidth = 1920;
        rizinApplyCenterLayout();
        const pane = $('rizin-decompiler');
        const tab = name => document.querySelector(`[data-rizin-tab="${name}"]`);
        const decs = sid => count('GET', `/api/rizin/${sid}/decompile`);
        const note = () => [pane.textContent, pane.querySelectorAll('button').map(b => b.textContent)];
        const S = { analysis: 'done', done: ['aaa'] };
        serve('S1', S);
        opens['C:\\x\\s.exe'] = S;
        await openInRizin('C:\\x\\s.exe');
        await until(() => rizinState.landed, 'landed'); await quiet();
        // sym.main's decompile takes too long: rizin is stopped, the session ends
        S.decompile = () => { S.ended = true; return [404, { error: 'session ended', reason: 'Decompiling took too long, the session ended.' }]; };
        click(tab('decompiler'));
        await until(() => rizinState.ui.state === 'ended', 'ended'); await quiet();
        r.ended = [...note(), decs('S1')];
        // Reopen: the same file at the same place; DECOMPILER does not ask for sym.main again on its own
        const S2 = { analysis: 'done', done: ['aaa'] };
        serve('S2', S2);
        opens['C:\\x\\s.exe'] = S2;
        click(pane.querySelector('[data-action="reopen"]'));
        await until(() => rizinState.session === 'S2' && rizinState.landed, 'reopened'); await quiet();
        r.reopened = [rizinState.seek, decs('S2'), ...note()];
        // Nor after an analysis step (a forced reload), nor for another place in the function
        await rizinReloadViews(); await quiet();
        $('rizin-seek').value = '0x1400014c0';
        click($('rizin-go'));
        await until(() => rizinState.seek === '0x1400014c0', 'in sym.main'); await quiet();
        r.stays = [decs('S2'), pane.textContent.includes('took too long')];
        // Another function decompiles as before; back in sym.main the note again
        click(row('0x140001490'));
        await until(() => rizinState.seek === '0x140001490', 'watchdog'); await quiet();
        r.other = [decs('S2'), pane.querySelectorAll('.rizin-dec-line').length];
        click(row('0x1400014b7'));
        await until(() => rizinState.seek === '0x1400014b7', 'main'); await quiet();
        r.back = [decs('S2'), pane.textContent.includes('took too long')];
        // Another file: its sym.main decompiles
        const S3 = { analysis: 'done', done: ['aaa'] };
        serve('S3', S3);
        opens['C:\\x\\t.exe'] = S3;
        await openInRizin('C:\\x\\t.exe');
        await until(() => rizinState.session === 'S3' && rizinState.landed, 'the other file'); await quiet();
        r.otherFile = [decs('S3'), pane.querySelectorAll('.rizin-dec-line').length];
        // The first file again: sym.main waits for Decompile again, which asks once
        const S4 = { analysis: 'done', done: ['aaa'] };
        serve('S4', S4);
        opens['C:\\x\\s.exe'] = S4;
        await openInRizin('C:\\x\\s.exe');
        await until(() => rizinState.session === 'S4' && rizinState.landed, 'the first file again'); await quiet();
        r.again = [decs('S4'), pane.textContent.includes('took too long')];
        click(pane.querySelector('[data-action="decompile-again"]'));
        await until(() => decs('S4') === 1, 'decompiled again'); await quiet();
        r.decompiled = [decs('S4'), pane.querySelectorAll('.rizin-dec-line').length];
        await rizinReloadViews(); await quiet();
        r.normal = decs('S4');
    """)
    assert "error" not in r, r.get("error")
    assert r["ended"] == ["Decompiling took too long, the session ended. Reopen", ["Reopen"], 1]
    seek, asked, text, buttons = r["reopened"]
    assert [seek, asked] == ["0x1400014b7", 0], "Reopen decompiled the function that ended the session again"
    assert text.startswith("Decompiling sym.main took too long") and buttons == ["Decompile again"], text
    assert r["stays"] == [0, True], "an analysis step or another place in the function decompiled it again"
    assert r["other"] == [1, 6] and r["back"] == [1, True]
    assert r["otherFile"] == [1, 9], "another file's function of the same name was not decompiled"
    assert r["again"] == [0, True], "the file opened again decompiled the function on its own"
    assert r["decompiled"] == [1, 9] and r["normal"] == 2


@needs_node
def test_rizin_reopen_keeps_a_jump_made_while_it_lands():
    """Review, Minor 3: Reopen went back to the place first and only then put the history back, after every
    view had loaded (DECOMPILER may take two minutes): a jump made meanwhile dropped out of ◀ ▶ and the
    history pointed at the old place. The history is back as soon as the file is open again, so such a jump
    goes on from it."""
    r = _scripted(r"""
        const S = { analysis: 'done', done: ['aaa'] };
        serve('S1', S);
        opens['C:\\x\\s.exe'] = S;
        await openInRizin('C:\\x\\s.exe');
        await until(() => rizinState.landed, 'landed'); await quiet();
        click(row('0x140001490'));
        await until(() => rizinState.seek === '0x140001490', 'watchdog'); await quiet();
        // The session ends; Reopen goes back to sym.watchdog, whose views load slowly
        gone.set('S1', ENDED);
        click(row('0x1400014b7'));
        await until(() => rizinState.ui.state === 'ended', 'ended'); await quiet();
        const S2 = { analysis: 'done', done: ['aaa'], disasmDelay: () => 80 };
        serve('S2', S2);
        opens['C:\\x\\s.exe'] = S2;
        click($('rizin-state-btn'));
        await until(() => rizinState.session === 'S2' && rizinState.seek === '0x140001490', 'back at watchdog');
        r.opened = [rizinState.history.slice(), rizinState.historyAt, rizinState.landed];
        // While its views load, a jump to sym.main
        click(row('0x1400014b7'));
        await until(() => rizinState.landed, 'landed again'); await quiet();
        r.landed = [rizinState.seek, rizinState.history.slice(), rizinState.historyAt, $('rizin-back').disabled];
        click($('rizin-back'));
        await until(() => rizinState.seek === '0x140001490', 'back'); await quiet();
        r.stepped = [rizinState.historyAt, ...marked()];
    """)
    assert "error" not in r, r.get("error")
    assert r["opened"] == [["0x1400014b7", "0x140001490"], 1, False], "the history is not back while the tab lands"
    assert r["landed"] == ["0x1400014b7", ["0x1400014b7", "0x140001490", "0x1400014b7"], 2, False], \
        "the jump made while the tab landed dropped out of the history"
    assert r["stepped"] == [1, "0x140001490", "0x140001490"]


def test_rizin_review_fixes_styles_and_versions():
    """The end of the linear disassembly has a rule of its own (not the clickable line for more), the limit
    is 2000 lines (the most one page of the route has), and the asset versions moved again with the
    review's fixes."""
    classic = _rules(STYLE_CSS)
    assert _declared(classic.get(".rizin-disasm-end"), "color") == "var(--text-dim)"
    assert _declared(classic.get(".rizin-disasm-end"), "cursor") in (None, "default")
    assert re.search(r"\blinear: 2000\b", _const_source("RIZIN_MORE")), _const_source("RIZIN_MORE")
    html = _read(INDEX_HTML)
    assert "style.css?v=64" not in html and "app.js?v=93" not in html, "asset versions not raised after the review"


# The parts of DECOMPILER, HEX and the toolbar's states whose look each theme sets
CODE_THEMED = [".rizin-decompiler", ".rizin-dec-line", ".rizin-dec-line.current", ".rizin-hex", ".rizin-hex-row",
               ".rizin-hex-bar", ".rizin-hex-bytes", ".rizin-hex-ascii", ".rizin-hex-cur", ".rizin-state-stopped",
               ".rizin-ended"]
# The colours of rz-ghidra's C as in the mockup (rizin-ui-v2.html): keywords violet, called functions magenta,
# strings gold and comments dim, as classes with theme variables
C_COLOURS = {".rz-kw": ("--accent-purple", "#b18cff"), ".rz-fn": ("--accent-pink", "#ff4fd8"),
             ".rz-str": ("--c-amber-300", "#ffd060"), ".rz-comment": ("--text-muted", "#8a7fb0")}


def test_rizin_code_views_and_states_layout_and_themes():
    html = _read(INDEX_HTML)
    tab = _tab_markup("rizin")
    for handler in ('onclick="rizinOnDecompilerClick(event)"', 'onclick="rizinOnHexClick(event)"',
                    'onclick="rizinFullAnalysis()"', 'onclick="rizinReopen()"'):
        assert handler in tab, handler
    toolbar = tab[tab.index('id="rizin-toolbar"'):tab.index('id="rizin-work"')]
    order = ['id="rizin-analysis"', 'id="rizin-full"', 'id="rizin-state"', 'id="rizin-state-btn"', 'rizin-toolbar-gap']
    assert [toolbar.find(i) for i in order] == sorted(toolbar.find(i) for i in order) and toolbar.find(order[0]) > 0
    assert re.search(r'<button[^>]*id="rizin-full"[^>]*hidden', toolbar) and re.search(r'<button[^>]*id="rizin-state-btn"[^>]*hidden', toolbar)
    hexeditor = _tab_markup("hexeditor")
    actions = hexeditor[hexeditor.index('class="header-actions"'):hexeditor.index('id="hex-offset"')]
    assert re.search(r'<button[^>]*onclick="hexOpenInRizin\(\)"[^>]*>Rizin</button>', actions), "no Rizin in the Hex tab's toolbar"

    classic, cyberpunk = _rules(STYLE_CSS), _rules(THEME_CSS)
    prefix = '[data-theme="cyberpunk"] '
    missing = [s for s in CODE_THEMED if s not in classic] + [prefix + s for s in CODE_THEMED if prefix + s not in cyberpunk]
    assert not missing, "parts without a rule in one theme:\n" + "\n".join(missing)
    for selector, (variable, colour) in C_COLOURS.items():
        assert _declared(classic.get(selector), "color") == f"var({variable})", selector
        assert _cyberpunk_palette()[variable].lower() == colour, f"{selector}: {variable} is not {colour}"
    for selector in (".rizin-dec-line", ".rizin-hex-row"):
        assert _declared(classic.get(selector), "white-space") == "pre", f"{selector}: a long line wraps"
    assert _declared(classic.get(".rizin-hex-bar"), "position") == "sticky", "Open in Hex tab scrolls away"
    # The toolbar stays one line at 1280 px: while a state, its button or Full analysis shows (the tab sets
    # .rizin-crowded), the file's details give way; the short states and the buttons keep their size
    for selector in (".rizin-toolbar.rizin-crowded > .rizin-file-sha", ".rizin-toolbar.rizin-crowded > .rizin-file-tag",
                     ".rizin-toolbar.rizin-crowded > .rizin-analysis"):
        body = classic.get(selector, "")
        assert re.fullmatch(r"0 [1-9]\d* auto", _declared(body, "flex") or ""), f"{selector} does not give way"
        assert _declared(body, "min-width") is not None and _declared(body, "text-overflow") == "ellipsis", selector
    assert re.fullmatch(r"0 0 auto", _declared(classic.get(".rizin-toolbar > .rizin-state-btn"), "flex") or "")
    for state in ("busy", "moved", "ended"):
        assert _declared(classic.get(f".rizin-toolbar > .rizin-state-{state}"), "flex-shrink") == "0", state
    assert "classList.toggle('rizin-crowded'" in _function_source("rizinRenderState")
    for path, rules in ((STYLE_CSS, _rizin_rules(STYLE_CSS)), (THEME_CSS, _rizin_rules(THEME_CSS))):
        written = [f"{s}: {m.group(0)}" for s, b in rules.items() for m in LITERAL_COLOR.finditer(b)]
        assert not written, f"colours written out in {path}:\n" + "\n".join(written)
    assert all(s.startswith(prefix) for s in _rizin_rules(THEME_CSS))
    assert "style.css?v=63" not in html and "theme-cyberpunk.css?v=23" not in html and "app.js?v=92" not in html, \
        "asset versions not raised"


# --- The final review's fixes (F1-F7, and the UI side of S1 and S6) ---------------------


@needs_node
def test_rizin_focus_checks_the_session_only_in_the_rizin_tab():
    """Final review, F1: once the poll has stopped, the browser tab coming into sight or the window taking
    the focus asks /status (which counts as use and keeps the session alive) only while the RIZIN tab is
    the TDC tab shown; elsewhere the session may end after its idle time. Showing the RIZIN tab asks once."""
    r = _scripted(r"""
        const S = { analysis: 'done', done: ['aaa'] };
        serve('S1', S);
        opens['C:\\x\\s.exe'] = S;
        await openInRizin('C:\\x\\s.exe');
        await until(() => rizinState.landed, 'landed'); await quiet();
        const focus = () => windowListeners.filter(l => l.type === 'focus').forEach(l => l.fn({ type: 'focus' }));
        const visible = () => dispatch('visibilitychange', document.body);
        const asked = async act => { const before = S.statusCalls; act(); await quiet(); return S.statusCalls - before; };
        r.elsewhere = [await asked(focus), await asked(visible)];
        $('tab-rizin').classList.add('active');
        r.rizin = [await asked(focus), await asked(visible)];
        $('tab-rizin').classList.remove('active');
        r.shown = await asked(() => rizinTabShown());
    """)
    assert "error" not in r, r.get("error")
    assert r["elsewhere"] == [0, 0], "another TDC tab's focus kept the session alive"
    assert r["rizin"] == [1, 1] and r["shown"] == 1


@needs_node
def test_rizin_open_of_the_file_already_open_keeps_the_place():
    """Final review, F2: a Rizin button (or OPEN) for the file the tab has open already gets the same
    session from the server: the place, the history, the console and the views stay as they are; the
    file's details and the analysis are the server's."""
    r = _scripted(r"""
        globalThis.innerWidth = 1920;
        rizinApplyCenterLayout();
        const S = { analysis: 'done', done: ['aaa'] };
        serve('S1', S);
        opens['C:\\x\\s.exe'] = S;
        await openInRizin('C:\\x\\s.exe');
        await until(() => rizinState.landed, 'landed'); await quiet();
        click(row('0x140001490'));
        await until(() => rizinState.seek === '0x140001490', 'watchdog'); await quiet();
        click($('rizin-disasm').querySelector('.rizin-op[data-addr="0x140001499"] .rz-addr'));
        await until(() => rizinState.seek === '0x140001499', 'a line'); await quiet();
        const history = [rizinState.history.slice(), rizinState.historyAt];
        const lines = $('rizin-console-out').children.length, mark = calls.length;
        S.level = 'aa';
        r.opened = await openInRizin('C:\\x\\s.exe');
        await quiet();
        r.after = [rizinState.session, rizinState.seek, [rizinState.history.slice(), rizinState.historyAt], marked(),
                   $('rizin-console-out').children.length - lines, $('rizin-file-path').textContent, rizinState.analysis.level];
        r.asked = calls.slice(mark).map(c => c[1].split('?')[0]);
        r.history = history;
    """)
    assert "error" not in r, r.get("error")
    assert r["history"] == [["0x1400014b7", "0x140001490", "0x140001499"], 2]
    assert r["opened"] is True
    assert r["after"] == ["S1", "0x140001499", r["history"], ["0x140001490", "0x140001499"], 0, "C:\\x\\s.exe", "aa"], \
        "the same file opened again lost the place, the history or the console"
    assert r["asked"] == ["/api/rizin/open"], "the views were loaded again: " + ", ".join(r["asked"])


@needs_node
def test_rizin_history_takes_only_the_jumps_that_draw():
    """Final review, F3: a jump that a newer one replaced (◀ pressed while a click's seek is on its way, or
    while a console command that moves runs) does not go into the history: ◀ ▶ stay on the places the
    views showed, and ▶ goes forward again."""
    r = _scripted(r"""
        const S = { analysis: 'done', done: ['aaa'] };
        serve('S1', S);
        opens['C:\\x\\s.exe'] = S;
        await openInRizin('C:\\x\\s.exe');
        await until(() => rizinState.landed, 'landed'); await quiet();
        click(row('0x140001490'));
        await until(() => rizinState.seek === '0x140001490', 'watchdog'); await quiet();
        const state = () => [rizinState.seek, rizinState.history.slice(), rizinState.historyAt, marked(),
                             !!$('rizin-back').disabled, !!$('rizin-forward').disabled];
        // A click whose seek is on its way, then ◀
        S.seekDelay = 40;
        click(row('0x140001000'));
        await until(() => flying('/api/rizin/S1/seek'), 'the click in flight');
        click($('rizin-back'));
        await quiet();
        S.seekDelay = 1;
        r.click = state();
        click($('rizin-forward'));
        await until(() => rizinState.seek === '0x140001490', 'forward'); await quiet();
        r.forward = state();
        // A console command that moves, and ◀ while it runs
        S.consoleDelay = 40;
        const input = $('rizin-console-input');
        input.value = 's entry0';
        dispatch('keydown', input, { key: 'Enter' });
        await until(() => flying('/api/rizin/S1/console'), 's running');
        click($('rizin-back'));
        await quiet();
        S.consoleDelay = 1;
        r.console = state();
    """)
    assert "error" not in r, r.get("error")
    main, watchdog = "0x1400014b7", "0x140001490"
    assert r["click"] == [main, [main, watchdog], 0, [main, main], True, False], "the history is off by one"
    assert r["forward"] == [watchdog, [main, watchdog], 1, [watchdog, watchdog], False, True]
    assert r["console"] == [main, [main, watchdog], 0, [main, main], True, False], \
        "a console command that ◀ overtook went into the history"


@needs_node
def test_rizin_jumps_move_the_marks_without_drawing_the_lists_again():
    """Final review, F4: a jump within what FUNCTIONS or DISASSEMBLY shows moves the mark instead of
    drawing every row again (10 000 functions are about 1.7 MB of markup); typing in the function filter
    draws the list once per pause."""
    r = _scripted(r"""
        const S = { analysis: 'done', done: ['aaa'] };
        serve('S1', S);
        opens['C:\\x\\s.exe'] = S;
        await openInRizin('C:\\x\\s.exe');
        await until(() => rizinState.landed, 'landed'); await quiet();
        const writes = { 'rizin-fn-list': 0, 'rizin-disasm': 0 };
        const html = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
        for (const id of Object.keys(writes)) {
            Object.defineProperty($(id), 'innerHTML', { set(v) { writes[id]++; html.set.call(this, v); }, configurable: true });
        }
        const drawn = () => [writes['rizin-fn-list'], writes['rizin-disasm']];
        const marks = () => [$('rizin-fn-list').querySelectorAll('.rizin-fn.current').map(e => e.getAttribute('data-addr')),
                             $('rizin-disasm').querySelectorAll('.rizin-op.current').map(e => e.getAttribute('data-addr'))];
        click($('rizin-disasm').querySelector('.rizin-op[data-addr="0x1400014be"] .rz-addr'));
        await until(() => rizinState.seek === '0x1400014be', 'a line'); await quiet();
        r.line = [drawn(), marks()];
        click(row('0x140001490'));
        await until(() => rizinState.seek === '0x140001490', 'watchdog'); await quiet();
        r.fn = [drawn(), marks()];
        click($('rizin-disasm').querySelector('.rizin-op[data-addr="0x14000149f"] .rz-addr'));
        await until(() => rizinState.seek === '0x14000149f', 'a line of watchdog'); await quiet();
        r.again = [drawn(), marks()];
        const filter = $('rizin-fn-filter');
        for (const text of ['m', 'ma', 'mai']) {
            filter.value = text;
            dispatch('input', filter);
        }
        r.typing = drawn()[0];
        await tick(30); await quiet();
        r.filtered = [drawn()[0], $('rizin-fn-list').querySelectorAll('.rizin-fn').map(e => e.getAttribute('data-addr'))];
    """)
    assert "error" not in r, r.get("error")
    assert r["line"] == [[0, 0], [["0x1400014b7"], ["0x1400014be"]]], "a jump inside the page drew it again"
    assert r["fn"] == [[0, 1], [["0x140001490"], ["0x140001490"]]], "a jump to another function drew the whole list"
    assert r["again"] == [[0, 1], [["0x140001490"], ["0x14000149f"]]]
    assert r["typing"] == 0 and r["filtered"] == [1, ["0x1400014b7"]], "the filter drew the list at every key"


@needs_node
def test_rizin_console_end_analysis_time_and_state_writes():
    """Final review, F5, F6 and F7: the console's line for a session that ended says the server's reason;
    the toolbar leaves out a time of 0 s (a project restored, an analysis just started); the state, a live
    region, is written only when its text changes; the dock's ═ says its height (aria-valuenow)."""
    r = _scripted(r"""
        r.times = [rizinAnalysisText({ state: 'done', step: null, level: 'aaa', elapsed: 0 }),
                   rizinAnalysisText({ state: 'running', step: null, level: 'aa', elapsed: 0 }),
                   rizinAnalysisText({ state: 'stopped', step: null, level: 'aaa', elapsed: 0 }),
                   rizinAnalysisText({ state: 'done', step: null, level: 'aaa', elapsed: 1.3 })];
        const S = { analysis: 'running', step: 'aaa', done: [],
                    functions: s => (s.analysis === 'running' ? [409, { busy: true, step: 'aaa' }] : [200, FUNCS]) };
        serve('S1', S);
        opens['C:\\x\\s.exe'] = S;
        const state = $('rizin-state');
        const text = Object.getOwnPropertyDescriptor(Node.prototype, 'textContent');
        let writes = 0;
        Object.defineProperty(state, 'textContent', { get() { return text.get.call(this); },
                                                       set(v) { writes++; text.set.call(this, v); }, configurable: true });
        await openInRizin('C:\\x\\s.exe');
        await until(() => S.statusCalls >= 4, 'polled while it runs');
        r.stateWrites = [writes, state.textContent];
        Object.assign(S, { analysis: 'done', step: null, done: ['aaa'] });
        await until(() => rizinState.landed, 'landed'); await quiet();

        const dock = $('rizin-dock'), grip = $('rizin-dock-grip');
        dock.rect = { left: 0, top: 500, right: 1200, bottom: 700, width: 1200, height: 200 };
        $('rizin-work').rect = { left: 0, top: 100, right: 1200, bottom: 700, width: 1200, height: 600 };
        rizinApplyDockLayout();
        const value = () => [grip.getAttribute('aria-valuenow'), grip.getAttribute('aria-valuemin'), grip.getAttribute('aria-valuemax'),
                             grip.getAttribute('aria-valuetext')];
        r.grip = [value()];
        rizinSetDockHeight(300);
        r.grip.push(value());
        dispatch('keydown', grip, { key: 'ArrowUp' });
        r.grip.push(value());

        gone.set('S1', [404, { error: 'session ended', reason: 'rizin did not answer in time' }]);
        const input = $('rizin-console-input');
        input.value = 'pdf';
        dispatch('keydown', input, { key: 'Enter' });
        await quiet();
        r.ended = $('rizin-console-out').lastElementChild.lastElementChild.textContent;
    """)
    assert "error" not in r, r.get("error")
    assert r["times"] == ["analysed (aaa)", "analysing (aa)", "analysis stopped (aaa)", "analysed (aaa) 1.3 s"]
    assert r["stateWrites"] == [1, "busy (aaa)"], "the state (role=status) was written again with the same text"
    assert r["grip"] == [["200", "90", "420", "200 px"], ["300", "90", "420", "300 px"], ["324", "90", "420", "324 px"]]
    assert r["ended"] == "The session ended (rizin did not answer in time). Reopen in the toolbar opens the file again.", \
        "the console dropped the server's reason"


@needs_node
def test_rizin_full_analysis_goes_on_after_it_stopped_and_big_lists_say_so():
    """Final review, S1 and S6 in the tab: a Full analysis that did not finish (stopped at its limit, a
    hung step, or a project opened again) offers Full analysis to go on; STRINGS whose server copy left
    rows out says so in its pager, and Tab over flags left out never takes a name as the only one."""
    r = _scripted(r"""
        const why = 'Full analysis did not finish; not run: aar, aaft. Full analysis goes on with them.';
        const S = { analysis: 'stopped', step: null, level: 'aaa', done: ['aa', 'aac'], note: why,
                    analyze: s => { Object.assign(s, { analysis: 'running', step: 'aar', note: null }); return null; },
                    strings: () => [200, { total: 200000, items: STRINGS.slice(0, 200), truncated: true }],
                    flags: () => [200, { total: 2, names: ['str.child', 'str.childhood'], common: 'str.child', truncated: true }] };
        serve('S1', S);
        opens['C:\\x\\s.exe'] = S;
        await openInRizin('C:\\x\\s.exe');
        await until(() => rizinState.landed, 'landed'); await quiet();
        r.stopped = [$('rizin-full').hidden, $('rizin-state').textContent];
        click($('rizin-full'));
        await until(() => rizinState.analysis.state === 'running', 'Full analysis goes on');
        r.running = $('rizin-full').hidden;
        Object.assign(S, { analysis: 'done', step: null, done: ['aa', 'aac', 'aar', 'aaft'] });
        await until(() => rizinState.analysis.state === 'done', 'done'); await quiet();
        r.done = $('rizin-full').hidden;

        click(document.querySelector('[data-rizin-tab="strings"]'));
        await until(() => count('GET', '/api/rizin/S1/strings') === 1, 'strings'); await quiet();
        r.pager = [$('rizin-strings-pager').textContent, $('rizin-strings-pager').getAttribute('title')];
        const input = $('rizin-console-input');
        input.value = 'axt str.child';
        input.selectionStart = input.value.length;
        dispatch('keydown', input, { key: 'Tab' });
        await quiet();
        r.tab = [input.value, $('rizin-console-out').lastElementChild.textContent];

        // Over the answer cap the server keeps no flag at all: names [], common '', truncated
        S.flags = () => [200, { total: 0, names: [], common: '', truncated: true }];
        input.value = 'axt sym.ma';
        input.selectionStart = input.value.length;
        dispatch('keydown', input, { key: 'Tab' });
        await quiet();
        r.capped = [input.value, $('rizin-console-out').lastElementChild.textContent];
    """)
    assert "error" not in r, r.get("error")
    assert r["stopped"][0] is False, "no Full analysis for a Full analysis that stopped"
    assert r["stopped"][1].startswith("Full analysis did not finish")
    assert r["running"] is True and r["done"] is True
    assert r["pager"][0] == "1–200 of 200000+" and "console" in (r["pager"][1] or ""), r["pager"]
    assert r["tab"] == ["axt str.child", "str.child  str.childhood  …"], "Tab took the flags sent for all there are"
    # Follow-up finding 2: with no flag and no common from the server, Tab lists the function names it
    # has and completes none of them, not even the only one that matches (docs/rizin.md says so)
    assert r["capped"] == ["axt sym.ma", "sym.main  …"], r["capped"]


def test_rizin_final_review_markup_and_versions():
    """Final review, F7 and F4 in index.html: GRAPH's view is the tabpanel its tab (below 1400 px) points to,
    the dock's ═ is a separator with a value, the function filter waits for a pause; app.js moved on."""
    tab = _tab_markup("rizin")
    assert re.search(r'<div[^>]*id="rizin-graph"[^>]*role="tabpanel"', tab) or \
        re.search(r'<div[^>]*role="tabpanel"[^>]*id="rizin-graph"', tab), "#rizin-graph is no tabpanel"
    assert 'aria-controls="rizin-graph"' in tab
    grip = re.search(r'<div[^>]*id="rizin-dock-grip"[^>]*>', tab).group(0)
    assert 'role="separator"' in grip and 'aria-valuemin="90"' in grip and "aria-valuenow=" in grip, grip
    assert 'oninput="rizinOnFunctionFilter()"' in tab
    assert "app.js?v=95" not in _read(INDEX_HTML), "the asset version of app.js was not raised"


# --- Task 10: the run strip -------------------------------------------------------------
#
# The strip between the toolbar and the work area: only while the emulation runs; CONT, STEP, OVER, SKIP, TO CALL,
# STOP and GO TO PC, the PC, the registers the last run changed, why it stopped, and the call assistant's offer.
# There is no BACK (rizin's aesb restores no memory) and no UNTIL button (it needs an address).

# A file opened and landed at sym.main (0x1400014b7), the strip's buttons, START from an address
EMU_SETUP = r"""
    globalThis.innerWidth = 1920;
    rizinApplyCenterLayout();
    const S = { analysis: 'done', done: ['aaa'] };
    serve('S1', S);
    opens['C:\\x\\e.exe'] = S;
    const strip = $('rizin-run');
    const run = kind => strip.querySelector(`[data-rizin-run="${kind}"]`);
    const act = name => strip.querySelector(`[data-rizin-act="${name}"]`);
    const kinds = ['cont', 'step', 'over', 'skip', 'to_call'];
    const posts = (from, part) => calls.slice(from).filter(c => c[0] === 'POST' && c[1].includes(part));
    const gets = (from, part) => calls.slice(from).filter(c => c[0] === 'GET' && c[1].includes(part));
    const tab = name => document.querySelector(`[data-rizin-tab="${name}"]`);
    const addrs = (box, sel) => box.querySelectorAll(sel).map(e => e.getAttribute('data-addr'));
    const regs = () => $('rizin-run-regs').querySelectorAll('.rizin-run-reg-name').map(e => e.textContent);
    const why = () => $('rizin-run-why').textContent;
    await openInRizin('C:\\x\\e.exe');
    await until(() => rizinState.landed, 'landed'); await quiet();
    // START at an address: the views are there first, as a user who clicked there and pressed START
    const startAt = async addr => {
        await rizinSeek(addr, 'test'); await quiet();
        click($('rizin-emu-start'));
        await until(() => !strip.hidden, 'the strip'); await quiet();
    };
    // A click on a button of the strip and the run it makes, drawn
    const press = async button => {
        const before = rizinState.emu;
        click(button);
        await until(() => rizinState.emu !== before && !rizinState.emuWait, 'the answer'); await quiet();
    };
"""


@needs_node
def test_rizin_emulation_strip_appears_only_while_running():
    # #rizin-run is hidden after OPEN; START unhides it and the kind buttons appear;
    # STOP hides it again and no further request goes out
    r = _scripted(r"""
        const pre = { hidden: $('rizin-run').hidden, start: $('rizin-emu-start').hasAttribute('disabled') };
        """ + EMU_SETUP + r"""
        r.pre = pre;
        r.opened = { hidden: strip.hidden, start: $('rizin-emu-start').disabled, emu: rizinState.emu };
        // START waits while another OPEN does, and is back when that one failed
        opens['C:\\x\\missing.exe'] = () => [400, { refused: 'the file does not exist' }, 60];
        const opening = openInRizin('C:\\x\\missing.exe');
        await until(() => rizinState.opening, 'the OPEN in flight');
        r.whileOpening = $('rizin-emu-start').disabled;
        await opening; await quiet();
        r.afterOpen = $('rizin-emu-start').disabled;
        const from = calls.length;
        await rizinSeek('0x1400014bc', 'test'); await quiet();
        const clickFrom = calls.length;
        click($('rizin-emu-start'));
        await until(() => !strip.hidden, 'the strip'); await quiet();
        r.startSent = calls.slice(clickFrom).filter(c => c[0] === 'POST').map(c => [c[1].replace('/api/rizin/S1', ''), c[2]]);
        r.started = {
            hidden: strip.hidden, emu: rizinState.emu && rizinState.emu.running, start: $('rizin-emu-start').disabled,
            kinds: strip.querySelectorAll('[data-rizin-run]').map(b => b.getAttribute('data-rizin-run')),
            labels: strip.querySelectorAll('button').map(b => b.textContent.trim()),
            disabled: strip.querySelectorAll('button').filter(b => b.disabled).length,
            pc: $('rizin-run-pc').textContent, posts: posts(from, '/emulation/start').map(c => [c[1], c[2]]),
            why: why(),
        };
        const quietFrom = calls.length;
        click(act('stop'));
        await until(() => strip.hidden, 'the strip goes'); await quiet();
        const after = calls.length;
        await tick(60);
        r.stopped = {
            hidden: strip.hidden, emu: rizinState.emu, start: $('rizin-emu-start').disabled,
            stops: posts(quietFrom, '/emulation/stop').length, posts: calls.slice(quietFrom).filter(c => c[0] === 'POST').length,
            more: calls.length - after, pcMarks: $('rizin-disasm').querySelectorAll('.rizin-op.pc').length,
        };
        // START and STOP again: the strip comes back
        click($('rizin-emu-start'));
        await until(() => !strip.hidden, 'the strip comes back'); await quiet();
        r.again = [strip.hidden, $('rizin-run-pc').textContent];
    """)
    assert "error" not in r, r.get("error")
    assert r["pre"] == {"hidden": True, "start": True}, "the strip shows, or START is on, before a file is open"
    assert r["opened"] == {"hidden": True, "start": False, "emu": None}, "the strip shows after OPEN, before START"
    started = r["started"]
    assert started["hidden"] is False and started["emu"] is True
    assert started["kinds"] == ["cont", "step", "over", "skip", "to_call"], "the strip's runs"
    assert started["labels"] == ["CONT", "STEP", "OVER", "SKIP", "TO CALL", "GO TO PC", "STOP"]
    assert not [label for label in started["labels"] if re.search(r"back|until", label, re.I)]
    assert started["disabled"] == 0 and started["start"] is True, "START stays on while the emulation runs"
    assert "0x1400014bc" in started["pc"] and started["why"].strip(), "the PC, and a word on why it stands"
    assert started["posts"] == [["/api/rizin/S1/emulation/start", {"addr": "0x1400014bc"}]]
    assert r["whileOpening"] is True and r["afterOpen"] is False, "START was not off while an OPEN waited, or stayed off after it failed"
    assert r["startSent"] == [["/emulation/start", {"addr": "0x1400014bc"}]], \
        "START asked for a jump to the PC it started at, where the views were already"
    stopped = r["stopped"]
    assert stopped["hidden"] is True and stopped["emu"] is None and stopped["start"] is False
    assert stopped["stops"] == 1 and stopped["posts"] == 1, "STOP posts the stop, and only that"
    assert stopped["more"] == 0, "a request went out after STOP"
    assert stopped["pcMarks"] == 0, "the PC's mark stays in DISASSEMBLY after STOP"
    assert r["again"][0] is False and "0x1400014bc" in r["again"][1]


@needs_node
def test_rizin_emulation_step_moves_the_views_and_marks_the_pc():
    # one STEP posts /emulation/run {kind:"step"}, then /seek with the new pc, and
    # DISASSEMBLY, GRAPH, DECOMPILER and HEX all show the new address; the PC row
    # carries the pc class while the row the user jumped to keeps its own (the breakpoint
    # row's own mark, with the other two on one row, is test_rizin_gutter_breakpoint_pc_and_current_are_three_marks)
    r = _scripted(EMU_SETUP + r"""
        await startAt('0x1400014bc');
        const pane = $('rizin-disasm'), graph = $('rizin-graph');
        r.start = { pc: addrs(pane, '.rizin-op.pc'), current: addrs(pane, '.rizin-op.current'), call: gets(0, '/call').length };
        const from = calls.length;
        await press(run('step'));
        r.requests = calls.slice(from).filter(c => c[0] === 'POST').map(c => [c[1].replace('/api/rizin/S1', ''), c[2]]);
        r.reads = [gets(from, '/emulation').length, gets(from, '/call').map(c => c[1])];
        r.disasm = { current: addrs(pane, '.rizin-op.current'), pc: addrs(pane, '.rizin-op.pc'), title: $('rizin-code-title').textContent };
        r.graph = { current: addrs(graph, '.rizin-block.current'), pc: addrs(graph, '.rizin-block.pc') };
        click(tab('decompiler'));
        await until(() => rizinState.decompiler && rizinState.decompiler.addr === '0x1400014be', 'DECOMPILER'); await quiet();
        r.decompiler = [rizinState.decompiler.addr, $('rizin-decompiler').querySelectorAll('.rizin-dec-line.current').length > 0];
        click(tab('hex'));
        await until(() => rizinState.hex && rizinState.hex.addr === '0x1400014be', 'HEX'); await quiet();
        r.hex = [rizinState.hex.addr, $('rizin-hex').querySelector('.rizin-hex-row').getAttribute('data-addr')];
        click(tab('disasm'));
        await quiet();
        // Another place: the PC's mark stays where the PC is, the current line goes where the user went
        await rizinSeek('0x140001521', 'test'); await quiet();
        r.away = { current: addrs(pane, '.rizin-op.current'), pc: addrs(pane, '.rizin-op.pc'),
                   graphPc: addrs(graph, '.rizin-block.pc'), graphCurrent: addrs(graph, '.rizin-block.current'),
                   strip: $('rizin-run-pc').textContent };
        // GO TO PC brings the views back
        click(act('gotopc'));
        await until(() => rizinState.seek === '0x1400014be', 'GO TO PC'); await quiet();
        r.back = { current: addrs(pane, '.rizin-op.current'), pc: addrs(pane, '.rizin-op.pc') };
        // The next step moves the mark, it does not leave one behind
        await press(run('step'));
        r.next = { current: addrs(pane, '.rizin-op.current'), pc: addrs(pane, '.rizin-op.pc'), state: rizinState.emu.pc };
        // A run into another function: DISASSEMBLY and the GRAPH are drawn for it, with the mark of the PC in them
        S.emuRun = () => { S.emu.pc = 0x140001494; return [200, emuRead(S.emu, 'step')]; };
        await press(run('step'));
        S.emuRun = undefined;
        r.other = { title: $('rizin-code-title').textContent, disasm: addrs(pane, '.rizin-op.pc'), current: addrs(pane, '.rizin-op.current'),
                    graph: addrs(graph, '.rizin-block.pc'), graphTitle: $('rizin-graph-title').textContent };
        // The jump to the PC found rizin busy: the PC's marks still move (the current place stays where it was)
        S.seekAnswer = () => [409, { busy: true, step: 'console' }];
        S.emuRun = () => { S.emu.pc = 0x140001499; return [200, emuRead(S.emu, 'step')]; };
        await press(run('step'));
        S.seekAnswer = undefined; S.emuRun = undefined;
        r.busySeek = { pc: addrs(pane, '.rizin-op.pc'), current: addrs(pane, '.rizin-op.current'), seek: rizinState.seek };
        await until(() => rizinState.ui.state === '', 'the poll found rizin free'); await quiet();
        // The markup builders mark the PC apart from the current place (the marks above are moved, not drawn)
        const drawn = document.createElement('div');
        drawn.innerHTML = rizinGraphSvg(rizinState.graph.layout, rizinState.graph, { current: '0x140001490', pc: '0x140001494' });
        const lines = document.createElement('div');
        lines.innerHTML = rizinDisasmHtml(rizinState.disasm.ops, { current: '0x140001490', pc: '0x140001494' });
        r.drawn = { graph: [addrs(drawn, '.rizin-block.pc'), addrs(drawn, '.rizin-block.current')],
                    disasm: [addrs(lines, '.rizin-op.pc'), addrs(lines, '.rizin-op.current')] };
        // UNTIL has no button; a run to an address (the right-click menu's) posts its address
        const untilFrom = calls.length;
        await rizinEmuRun('until', '0x140001521'); await quiet();
        r.until = posts(untilFrom, '/emulation/run').map(c => c[2]);
        const none = calls.length;
        await rizinEmuRun('until'); await rizinEmuRun('back'); await rizinEmuRun('step ; ar rax=1'); await tick(30);
        r.refused = calls.length - none;
    """)
    assert "error" not in r, r.get("error")
    assert r["start"] == {"pc": ["0x1400014bc"], "current": ["0x1400014bc"], "call": 0}, \
        "the PC's row, and no question to the call assistant at an instruction that is no call"
    assert r["requests"] == [["/emulation/run", {"kind": "step"}], ["/seek", {"addr": "0x1400014be"}]], \
        "a step is the run, then the jump to the PC it answered"
    assert r["reads"][0] == 0, "a step asked for the state again: the pane and the strip share the answer of the run"
    assert r["reads"][1] == ["/api/rizin/S1/call?addr=0x1400014be"], "the call at the PC is asked about once"
    assert r["disasm"] == {"current": ["0x1400014be"], "pc": ["0x1400014be"], "title": "sym.main"}
    assert r["graph"] == {"current": ["0x1400014be"], "pc": ["0x1400014be"]}, "the graph's block of the PC"
    assert r["decompiler"] == ["0x1400014be", True] and r["hex"] == ["0x1400014be", "0x1400014be"]
    assert r["away"]["current"] == ["0x140001521"] and r["away"]["pc"] == ["0x1400014be"], \
        "the PC's mark followed the user, or the current line stayed"
    assert r["away"]["graphPc"] == ["0x1400014be"] and r["away"]["graphCurrent"] == ["0x140001521"]
    assert "0x1400014be" in r["away"]["strip"]
    assert r["back"] == {"current": ["0x1400014be"], "pc": ["0x1400014be"]}
    assert r["next"] == {"current": ["0x140001521"], "pc": ["0x140001521"], "state": "0x140001521"}
    assert r["other"] == {"title": "sym.watchdog", "disasm": ["0x140001494"], "current": ["0x140001494"],
                          "graph": ["0x140001494"], "graphTitle": "GRAPH · sym.watchdog"}, r["other"]
    assert r["busySeek"]["pc"] == ["0x140001499"] and r["busySeek"]["seek"] == "0x140001494", r["busySeek"]
    assert r["drawn"] == {"graph": [["0x140001494"], ["0x140001490"]], "disasm": [["0x140001494"], ["0x140001490"]]}
    assert r["until"] == [{"kind": "until", "addr": "0x140001521"}]
    assert r["refused"] == 0, "a run without an address, a BACK or another word than the six kinds went out"


@needs_node
def test_rizin_emulation_strip_shows_only_the_registers_that_changed():
    # the strip lists exactly state.changed, not all of them, and the EMULATION pane lists all
    r = _scripted(EMU_SETUP + r"""
        await startAt('0x1400014bc');
        r.start = { regs: regs(), text: $('rizin-run-regs').textContent.trim() };
        await press(run('step'));
        const reg = name => $('rizin-run-regs').querySelectorAll('.rizin-run-reg')
            .find(e => e.querySelector('.rizin-run-reg-name').textContent === name);
        r.step = { regs: regs(), values: $('rizin-run-regs').querySelectorAll('.rizin-run-reg-value').map(e => e.textContent),
                   delta: $('rizin-run-regs').querySelectorAll('.rizin-run-delta').map(e => e.textContent),
                   deltaInside: regs().map(name => !!reg(name).querySelector('.rizin-run-delta')),
                   state: [rizinState.emu.registers.map(x => x.name), rizinState.emu.changed] };
        // Skipping changes the PC only: a register the step before changed is not listed any more
        await press(run('skip'));
        r.skip = { regs: regs(), changed: rizinState.emu.changed };
        // A run that changed nothing says so
        S.emuRun = () => [200, { ...emuRead(S.emu, 'step'), changed: [] }];
        await press(run('over'));
        r.none = { regs: regs(), text: $('rizin-run-regs').textContent.trim() };
        // Registers' names come out of the file; a value above 2^53 shows exactly (the server sends words as strings)
        const hostile = '<img src=x onerror=alert(1)>';
        S.emuRun = () => [200, { ...emuRead(S.emu, 'step'), changed: [hostile, 'rax', 'rbx'],
                                 registers: [{ name: hostile, value: '0x1' }, { name: 'rax', value: '0x7ff7a1b2c3d4e5f6' },
                                             { name: 'rbx', value: '0x20000000000001' }] }];
        await press(run('step'));
        r.hostile = { regs: regs(), text: $('rizin-run-regs').textContent,
                      values: $('rizin-run-regs').querySelectorAll('.rizin-run-reg-value').map(e => e.textContent),
                      tags: [...$('rizin-run-regs').walk()].map(e => e.tagName).filter(t => t !== 'SPAN'),
                      handlers: [...$('rizin-run-regs').walk()].flatMap(e => Object.keys(e.attrs)).filter(a => a.startsWith('on')) };
        // Many changed registers: the strip keeps the first few and says how many more
        S.emuRun = () => {
            const names = Array.from({ length: 20 }, (_, i) => `r${i}`);
            return [200, { ...emuRead(S.emu, 'step'), changed: names, registers: names.map((name, i) => ({ name, value: '0x' + i.toString(16) })) }];
        };
        await press(run('step'));
        r.many = { n: regs().length, more: $('rizin-run-regs').textContent, held: rizinState.emu.registers.length };
        // A value that is no word shows as "?", never as an empty cell; a PC that rizin did not name says so, and
        // the views are not asked to follow it
        S.emuRun = () => [200, { ...emuRead(S.emu, 'step'), changed: ['rax', 'rbx'],
                                 registers: [{ name: 'rax', value: null }, { name: 'rbx', value: 'banana' }] }];
        await press(run('step'));
        r.unreadable = $('rizin-run-regs').querySelectorAll('.rizin-run-reg-value').map(e => e.textContent);
        S.emuRun = () => [200, { ...emuRead(S.emu, 'step'), pc: null }];
        const nullFrom = calls.length;
        await press(run('step'));
        r.noPc = { text: $('rizin-run-pc').textContent, seeks: posts(nullFrom, '/seek').length, goto: act('gotopc').disabled,
                   marks: $('rizin-disasm').querySelectorAll('.rizin-op.pc').length };
    """)
    assert "error" not in r, r.get("error")
    assert r["start"]["regs"] == [] and r["start"]["text"], "no register changed yet: the strip still says something"
    assert r["step"]["regs"] == ["rax", "rip"], "the strip lists the registers the step changed, in rizin's order"
    assert r["step"]["values"] == ["0x1", "0x1400014be"]
    assert r["step"]["delta"] == ["Δ", "Δ"] and r["step"]["deltaInside"] == [True, True], \
        "a changed register is marked by a sign, not by its colour alone"
    assert r["step"]["state"] == [["rax", "rbx", "rcx", "rip"], ["rax", "rip"]], \
        "the state holds all four registers for the EMULATION pane, and the names that changed"
    assert r["skip"] == {"regs": ["rip"], "changed": ["rip"]}
    assert r["none"]["regs"] == [] and r["none"]["text"] and "rax" not in r["none"]["text"]
    assert r["hostile"]["regs"] == [HOSTILE, "rax", "rbx"]
    assert r["hostile"]["values"] == ["0x1", "0x7ff7a1b2c3d4e5f6", "0x20000000000001"], \
        "a word above 2^53 lost digits or got a mark"
    assert "~" not in r["hostile"]["text"], "an approximation mark where words are exact"
    assert r["hostile"]["tags"] == [] and r["hostile"]["handlers"] == [], "a register's name became markup"
    assert 1 <= r["many"]["n"] < 20 and "more" in r["many"]["more"] and r["many"]["held"] == 20
    assert r["unreadable"] == ["?", "?"], "an unreadable register shows an empty cell"
    assert "unknown" in r["noPc"]["text"] and r["noPc"]["seeks"] == 0 and r["noPc"]["goto"] is True and r["noPc"]["marks"] == 0, r["noPc"]


@needs_node
def test_rizin_emulation_says_why_it_stopped():
    # stopped "breakpoint", "timeout" and "invalid" each produce their own words in
    # #rizin-run-why; a run that answers stopped "step" still says something, never ""
    r = _scripted(EMU_SETUP + r"""
        await startAt('0x1400014b7');
        r.started = why();
        const said = {};
        for (const [reason, kind] of [['breakpoint', 'cont'], ['timeout', 'cont'], ['invalid', 'step'], ['trap', 'cont'],
                                      ['step', 'step'], ['step', 'over'], ['step', 'skip'], ['step', 'to_call'], ['step', 'cont']]) {
            S.stopWith = reason;
            await press(run(kind));
            said[`${reason}/${kind}`] = why();
        }
        r.said = said;
        // The state read again says no reason (rizin does not keep one): the words of the run stay
        S.stopWith = 'breakpoint';
        await press(run('cont'));
        const stood = why();
        await rizinReloadViews(); await quiet();
        r.kept = [stood, why()];
        // Another PC after a reload (a console command moved it): the old reason no longer holds
        S.emu.pc = 0x140001521;
        await rizinReloadViews(); await quiet();
        r.moved = why();
        // A reason the page does not know, and one that is markup
        S.emuRun = () => [200, { ...emuRead(S.emu, 'gone-wrong') }];
        await press(run('step'));
        r.unknown = why();
        S.emuRun = () => [200, { ...emuRead(S.emu, '<img src=x onerror=alert(1)>') }];
        await press(run('step'));
        r.hostile = [why(), [...$('rizin-run-why').walk()].length];
        // What a skipped call applied comes with the reason, whichever it is
        const withSummary = {};
        for (const reason of ['step', 'breakpoint', 'timeout', 'invalid', 'trap', 'gone-wrong']) {
            S.emuRun = () => [200, { ...emuRead(S.emu, reason), summary: `SUMMARY-${reason}` }];
            await press(run('skip'));
            withSummary[reason] = why();
        }
        r.withSummary = withSummary;
        // An answer that is no state is not taken for one
        S.emuRun = () => [200, {}];
        const emptyBefore = rizinState.emu;
        click(run('step'));
        await until(() => why().includes('without a state') && !rizinState.emuWait, 'the empty answer'); await quiet();
        r.empty = rizinState.emu === emptyBefore;
        // A run the server refused says the reason, and the state stays
        S.emuRun = () => [400, { refused: 'io.cache does not hold' }];
        const stateBefore = rizinState.emu;
        click(run('step'));
        await until(() => why().includes('io.cache does not hold') && !rizinState.emuWait, 'the refusal'); await quiet();
        r.refused = { hidden: strip.hidden, same: rizinState.emu === stateBefore, off: strip.querySelectorAll('button').filter(b => b.disabled).length };
    """)
    assert "error" not in r, r.get("error")
    said = r["said"]
    assert r["started"].strip(), "the strip says nothing before the first run"
    assert re.search(r"breakpoint", said["breakpoint/cont"], re.I)
    assert re.search(r"esil\.timeout", said["timeout/cont"])
    assert re.search(r"decode|invalid", said["invalid/step"], re.I)
    assert re.search(r"memory", said["trap/cont"], re.I)
    assert len({said[k] for k in ("breakpoint/cont", "timeout/cont", "invalid/step", "trap/cont", "step/step")}) == 5, \
        "two reasons share their words"
    for key, text in said.items():
        assert text.strip() and text.strip().lower() not in ("done", "finished", "ok"), f"{key}: {text!r}"
    assert len({said[f"step/{kind}"] for kind in ("step", "over", "skip", "to_call", "cont")}) == 5, \
        "a run that did what was asked says which run it was"
    assert r["kept"][1] == r["kept"][0] and "breakpoint" in r["kept"][0].lower(), \
        "reading the state again lost why the emulation stood"
    assert r["moved"].strip() and "breakpoint" not in r["moved"].lower()
    assert "gone-wrong" in r["unknown"], "a reason the strip does not know is named, not dropped"
    assert HOSTILE in r["hostile"][0] and r["hostile"][1] == 0, "a reason became markup"
    for reason, text in r["withSummary"].items():
        assert f"SUMMARY-{reason}" in text, f"{reason}: the summary of the skipped call went from the line: {text!r}"
    assert r["empty"] is True, "an answer without a state replaced the state"
    assert r["refused"] == {"hidden": False, "same": True, "off": 0}, "a refused run changed the state or left the buttons off"


@needs_node
def test_rizin_emulation_stop_leaves_the_mode_and_does_not_promise_an_abort():
    # while a run is in flight the kind buttons are disabled but STOP is not labelled
    # as an abort, and clicking it during the run does not post anything
    r = _scripted(EMU_SETUP + r"""
        await startAt('0x1400014b7');
        const buttons = () => Object.fromEntries(strip.querySelectorAll('button').map(b => [b.textContent.trim(), b.disabled]));
        const words = () => [act('stop').textContent, act('stop').title, act('stop').getAttribute('aria-label') || ''].join(' | ');
        r.idle = { buttons: buttons(), words: words() };
        S.runDelay = 120;
        const from = calls.length;
        click(run('cont'));
        await until(() => rizinState.emuWait === 'cont', 'the run in flight');
        r.flying = { buttons: buttons(), words: words(), why: why(), start: $('rizin-emu-start').disabled };
        // Another run, STOP and GO TO PC, during the run: nothing goes out, of any kind (GO TO PC would post a seek)
        click(run('step')); click(act('stop')); click(act('gotopc')); rizinEmuRun('over'); rizinEmuStop(); rizinEmuGoToPc();
        rizinLoadEmulation(true);                  // a forced read (an analysis step ended) waits for the run too
        await tick(30);
        r.reads = gets(from, '/emulation').length;
        r.during = calls.slice(from).filter(c => c[0] === 'POST').map(c => [c[1].replace('/api/rizin/S1', ''), c[2]]);
        r.stillRunning = [strip.hidden, !!rizinState.emu];
        await until(() => !rizinState.emuWait, 'the run ends'); await quiet();
        r.after = { buttons: buttons(), emuPc: rizinState.emu.pc };
        // A STOP the server refuses: the mode stays, with the reason in the strip
        S.emuStop = () => [400, { refused: 'rizin could not give the emulation back' }];
        click(act('stop'));
        await until(() => why().includes('give the emulation back') && !rizinState.emuWait, 'the refusal'); await quiet();
        r.refused = { hidden: strip.hidden, running: !!rizinState.emu, buttons: buttons() };
        // STOP leaves the mode
        S.emuStop = undefined;
        const stopFrom = calls.length;
        click(act('stop'));
        await until(() => strip.hidden, 'left'); await quiet();
        r.left = [posts(stopFrom, '/emulation/stop').length, rizinState.emu, strip.hidden];
    """)
    assert "error" not in r, r.get("error")
    runs = ["CONT", "STEP", "OVER", "SKIP", "TO CALL"]
    assert not any(r["idle"]["buttons"].values()), "a button was off with nothing running"
    assert not re.search(r"abort|cancel|kill|interrupt", r["idle"]["words"], re.I), r["idle"]["words"]
    assert r["flying"]["buttons"] == {**{k: True for k in runs}, "GO TO PC": True, "STOP": True}, \
        "the runs were not off while one was in flight"
    assert not re.search(r"abort|cancel|kill|halt", r["flying"]["words"], re.I), r["flying"]["words"]
    assert "STOP" == r["flying"]["words"].split(" | ")[0].strip()
    assert re.search(r"cannot be interrupted", r["flying"]["why"]), r["flying"]["why"]
    assert r["flying"]["start"] is True
    assert r["during"] == [["/emulation/run", {"kind": "cont"}]], "a click during the run posted something: " + str(r["during"])
    assert r["stillRunning"] == [False, True], "STOP during a run left the mode"
    assert not any(r["after"]["buttons"].values()) and r["after"]["emuPc"] == "0x140001529"
    assert r["reads"] == 0, "the state was read while a run was out: its answer would be older than the run's"
    assert r["refused"]["hidden"] is False and r["refused"]["running"] is True, "a refused STOP left the mode"
    assert not any(r["refused"]["buttons"].values()), "the strip stayed off after a refused STOP"
    assert r["left"] == [1, None, True]


@needs_node
def test_rizin_emulation_offers_a_call_return_and_lets_it_be_edited():
    # at a call to an import, #rizin-run-assist shows the offered value; editing the
    # field and pressing SKIP posts that edited value, not the offered one
    r = _scripted(EMU_SETUP + r"""
        const hostile = '"><img src=x onerror=alert(1)>';      // leaves an attribute and makes an element
        const offer = (over = {}) => (addr, s) => [200, { supported: true, reason: null, api: 'VirtualAlloc', ret_reg: 'rax',
            value: '0x140008000', stack_fix: 0, summary: 'skip VirtualAlloc: rax = 0x140008000, a buffer of 65536 bytes', ...over }];
        const box = $('rizin-run-assist'), field = () => $('rizin-run-assist-value');
        // The requests of a press but the jump to the PC it ends in
        const sent = from => calls.slice(from).filter(c => c[0] === 'POST' && !c[1].endsWith('/seek'))
            .map(c => [c[1].replace('/api/rizin/S1', ''), c[2]]);
        const shown = () => ({ hidden: box.hidden, text: box.textContent, value: field() ? field().value : null,
                               aria: field() ? field().getAttribute('aria-label') : null,
                               title: box.querySelectorAll('[title]').map(e => e.getAttribute('title')),
                               tags: [...box.walk()].map(e => e.tagName).filter(t => !['SPAN', 'LABEL', 'INPUT', 'B'].includes(t)),
                               handlers: [...box.walk()].flatMap(e => Object.keys(e.attrs)).filter(a => a.startsWith('on')) });
        S.callAssist = offer();
        r.before = box.hidden;
        const from = calls.length;
        await startAt('0x140001499');                 // call qword [Sleep] in sym.watchdog
        r.offered = shown();
        r.asked = gets(from, '/call').map(c => c[1]);
        // The user edits the offered value; SKIP posts it, to /call, and no plain run
        field().value = '0x140009000';
        const skipFrom = calls.length;
        await press(run('skip'));
        r.edited = { posts: sent(skipFrom),
                     pc: rizinState.emu.pc, rax: S.emu.rax, hidden: box.hidden, why: why() };
        // Untouched, the offered value goes, as a string, with the stack correction the offer named
        S.callAssist = offer({ stack_fix: 8 });
        await rizinEmuStop();
        await startAt('0x140001499');
        const plainFrom = calls.length;
        await press(run('skip'));
        r.untouched = sent(plainFrom);
        // A 64-bit offer (a memcpy returns a register's value): the field shows it exactly and SKIP posts it exactly
        S.callAssist = offer({ value: '0x7ff7a1b2c3d4e5f6' });
        await rizinEmuStop();
        await startAt('0x140001499');
        r.wide = field().value;
        const wideFrom = calls.length;
        await press(run('skip'));
        r.widePosts = sent(wideFrom);
        // A value that is no number is not posted
        await rizinEmuStop();
        await startAt('0x140001499');
        field().value = 'banana';
        const badFrom = calls.length;
        click(run('skip'));
        await tick(30);
        r.bad = { posts: posts(badFrom, '/').length, why: why(), value: field().value, pc: rizinState.emu.pc };
        // Nothing offered (a call the table does not know): an empty field; SKIP leaves the register as it is
        S.callAssist = offer({ api: 'Unknown', value: null, summary: 'the table does not know Unknown: no value is offered' });
        await rizinEmuStop();
        await startAt('0x140001499');
        r.unknown = shown();
        const emptyFrom = calls.length;
        await press(run('skip'));
        r.empty = posts(emptyFrom, '/call').map(c => c[2]);
        // The assistant switched off for this file: the reason shows, no field, SKIP is the plain skip
        S.callAssist = () => [200, { supported: false, reason: 'the assistant covers x86-64 and x86-32, and this file is arm at 64 bits',
                                     api: null, ret_reg: null, value: null, stack_fix: 0, summary: 'no value is offered' }];
        await rizinEmuStop();
        await startAt('0x140001499');
        r.off = shown();
        const offFrom = calls.length;
        await press(run('skip'));
        r.offPosts = sent(offFrom);
        // Where the PC is no call SKIP is the plain skip as well, and nothing is offered, nor asked about
        S.callAssist = undefined;
        await rizinEmuStop();
        const nopeFrom = calls.length;
        await startAt('0x140001490');                 // sub rsp, 0x28
        r.noCall = [box.hidden, gets(nopeFrom, '/call').length];
        const pressFrom = calls.length;
        await press(run('skip'));
        r.noCallPosts = sent(pressFrom);
        // An offer made for another call is not applied to this one: SKIP is the plain skip
        S.callAssist = offer();
        await rizinEmuStop();
        await startAt('0x140001499');
        rizinState.emu.assist = { ...rizinState.emu.assist, addr: '0x1' };
        const staleFrom = calls.length;
        await press(run('skip'));
        r.stale = sent(staleFrom);
        // The PC moved to another call behind the tab's back (the console): the state read again asks about it
        await rizinEmuStop();
        await startAt('0x140001499');
        S.emu.pc = 0x1400014be;
        const moveFrom = calls.length;
        await rizinReloadViews(); await quiet();
        r.moved = { asked: gets(moveFrom, '/call').map(c => c[1]), hidden: box.hidden, value: field() ? field().value : null };
        // SKIP pressed while a run is in flight, with a value that is no number: nothing happens, not even a note
        S.callAssist = offer();
        await rizinEmuStop();
        await startAt('0x140001499');
        S.runDelay = 80;
        click(run('step'));
        await until(() => rizinState.emuWait === 'step', 'the run in flight');
        field().value = 'banana';
        const flightFrom = calls.length;
        click(run('skip'));
        await until(() => !rizinState.emuWait, 'the run ends'); await quiet();
        S.runDelay = 1;
        r.midRun = { why: why(), posts: posts(flightFrom, '/call').length };
        // What the file and the table name is text
        S.callAssist = offer({ api: hostile, summary: `skip ${hostile}`, reason: hostile, ret_reg: hostile });
        await rizinEmuStop();
        await startAt('0x140001499');
        r.hostile = shown();
        // The table's name where no sentence came with it
        S.callAssist = offer({ api: hostile, summary: '', ret_reg: hostile });
        await rizinEmuStop();
        await startAt('0x140001499');
        r.hostileApi = shown();
        S.callAssist = () => [200, { supported: false, reason: hostile, api: hostile, ret_reg: null, value: null, stack_fix: 0, summary: hostile }];
        await rizinEmuStop();
        await startAt('0x140001499');
        r.hostileOff = shown();
    """)
    assert "error" not in r, r.get("error")
    assert r["before"] is True and r["asked"] == ["/api/rizin/S1/call?addr=0x140001499"]
    assert r["offered"]["hidden"] is False and r["offered"]["value"] == "0x140008000"
    assert "VirtualAlloc" in r["offered"]["text"] and "65536" in r["offered"]["text"]
    assert r["edited"]["posts"] == [["/call", {"addr": "0x140001499", "value": "0x140009000", "stack_fix": 0}]], \
        "SKIP did not post the edited value to /call"
    assert r["edited"]["pc"] == "0x14000149f" and r["edited"]["rax"] == "0x140009000", "the offered value was applied, not the edited"
    assert r["edited"]["hidden"] is True, "the offer of a call stayed once the PC left it"
    assert r["edited"]["why"].strip() and "skipped the call" in r["edited"]["why"], "what the skip applied is not said"
    assert r["untouched"] == [["/call", {"addr": "0x140001499", "value": "0x140008000", "stack_fix": 8}]]
    assert r["wide"] == "0x7ff7a1b2c3d4e5f6", "an offered 64-bit value lost digits in the field"
    assert r["widePosts"] == [["/call", {"addr": "0x140001499", "value": "0x7ff7a1b2c3d4e5f6", "stack_fix": 0}]]
    assert r["bad"]["posts"] == 0 and r["bad"]["value"] == "banana" and r["bad"]["pc"] == "0x140001499"
    assert "banana" in r["bad"]["why"], "no word on the value that is no number"
    assert r["unknown"]["value"] == "" and "Unknown" in r["unknown"]["text"]
    assert r["empty"] == [{"addr": "0x140001499", "value": None, "stack_fix": 0}]
    assert r["off"]["value"] is None and "arm at 64 bits" in r["off"]["text"] and r["off"]["hidden"] is False
    assert r["offPosts"] == [["/emulation/run", {"kind": "skip"}]], "SKIP did not fall back to the plain skip"
    assert r["stale"] == [["/emulation/run", {"kind": "skip"}]], r["stale"]
    assert r["moved"] == {"asked": ["/api/rizin/S1/call?addr=0x1400014be"], "hidden": False, "value": "0x140008000"}, r["moved"]
    assert "banana" not in r["midRun"]["why"] and r["midRun"]["posts"] == 0, r["midRun"]
    assert r["noCall"] == [True, 0] and r["noCallPosts"] == [["/emulation/run", {"kind": "skip"}]]
    for key in ("hostile", "hostileApi", "hostileOff"):
        assert HOSTILE in r[key]["text"] and r[key]["tags"] == [] and r[key]["handlers"] == [], f"{key}: markup"
    for key in ("hostile", "hostileApi"):
        assert r[key]["aria"] == "The value SKIP puts into " + '"><img src=x onerror=alert(1)>', f"{key}: the register's name in the field's label"
        assert r[key]["title"] == ["skip " + '"><img src=x onerror=alert(1)>'], f"{key}: the sentence in its title"


@needs_node
def test_rizin_emulation_busy_and_ended_sessions_behave_like_the_other_views():
    # a 409 busy marks the view for retry and the poll picks it up; a 404 ended
    # clears rizinState.emu so the strip disappears
    r = _scripted(EMU_SETUP + r"""
        await startAt('0x1400014bc');
        // The state asked for again (an analysis step ended) finds rizin busy: kept for retry, the strip stays
        let asks = 0;
        S.emuState = () => (++asks === 1 ? [409, { busy: true, step: 'aaa' }, 30] : undefined);
        const busyFrom = calls.length;
        S.emu.rax = 41;
        await rizinReloadViews();
        r.busy = { retry: rizinState.retry.get('emulation'), ui: rizinState.ui.state, hidden: strip.hidden,
                   asked: gets(busyFrom, '/emulation').length };
        // rizin is free again: the poll asks again, forced, and the retry is gone
        await until(() => !rizinState.retry.has('emulation') && gets(busyFrom, '/emulation').length >= 2, 'the poll asked again');
        await quiet();
        r.retried = { asked: gets(busyFrom, '/emulation').length, ui: rizinState.ui.state, hidden: strip.hidden,
                      rax: rizinState.emu.registers.find(x => x.name === 'rax').value };
        // A late answer of a run that was out when the session ended does not bring the emulation back
        S.runDelay = 100;
        click(run('step'));
        await until(() => rizinState.emuWait === 'step', 'the run in flight');
        rizinSetUi('ended', {});
        await tick(160); await quiet();
        r.late = { emu: rizinState.emu, hidden: strip.hidden, wait: rizinState.emuWait };
        S.runDelay = 1;
        rizinState.ui = { state: '', step: null, reason: null, path: null };
        await rizinEmuStart(); await quiet();
        // A run that finds rizin busy did not run: the state stays, and the strip says so
        S.emuRun = () => [409, { busy: true, step: 'console' }];
        S.emuState = undefined;
        const pc = rizinState.emu.pc;
        click(run('step'));
        await until(() => rizinState.ui.state === 'busy' && !rizinState.emuWait, 'busy'); await quiet();
        r.runBusy = { pc: rizinState.emu.pc === pc, why: why(), buttons: strip.querySelectorAll('button').filter(b => b.disabled).length };
        // The state read again once rizin is free takes the note of the run that did not happen away
        await rizinReloadViews(); await quiet();
        r.noteGone = why();
        // The offer for a call that finds rizin busy is asked again by the poll
        S.emuRun = undefined;
        let asked = 0;
        S.callAssist = () => (++asked === 1 ? [409, { busy: true, step: 'console' }] : undefined);
        await rizinEmuStop();
        await rizinSeek('0x140001499', 'test'); await quiet();
        click($('rizin-emu-start'));
        await until(() => rizinState.retry.has('emulation'), 'the offer found rizin busy');
        r.assistBusy = { retry: rizinState.retry.get('emulation'), hidden: $('rizin-run-assist').hidden };
        await until(() => !rizinState.retry.has('emulation') && !$('rizin-run-assist').hidden, 'the offer after the retry'); await quiet();
        S.callAssist = undefined;
        // The server lost the emulation, found out by a read: the mode is left, with the reason in the toolbar
        S.emuState = () => [400, { refused: 'the emulation is not started' }];
        await rizinReloadViews(); await quiet();
        S.emuState = undefined;
        r.lostByRead = { emu: rizinState.emu, hidden: strip.hidden, state: $('rizin-state').textContent };
        await startAt('0x1400014bc');
        // STOP that finds rizin busy: the mode stays, and the poll takes the toolbar's busy away once rizin is free
        S.emuRun = undefined;
        S.emuStop = () => [409, { busy: true, step: 'console' }];
        click(act('stop'));
        await until(() => rizinState.ui.state === 'busy' && !rizinState.emuWait, 'STOP found rizin busy');
        r.stopBusy = { hidden: strip.hidden, why: why() };
        await until(() => rizinState.ui.state === '', 'the poll found rizin free'); await quiet();
        S.emuStop = undefined;
        // The server lost the emulation (a restarted rizin): the mode is left, with the reason in the toolbar
        S.emuRun = () => [400, { refused: 'the emulation is not started' }];
        click(run('step'));
        await until(() => strip.hidden, 'left'); await quiet();
        r.lost = { emu: rizinState.emu, hidden: strip.hidden, state: $('rizin-state').textContent, start: $('rizin-emu-start').disabled };
        // START refused: the reason shows in the toolbar, where the strip is not
        S.emuRun = undefined;
        S.emuStart = () => [400, { refused: 'io.cache could not be switched on' }];
        click($('rizin-emu-start'));
        await until(() => $('rizin-state').textContent.includes('io.cache'), 'the refusal'); await quiet();
        r.refused = [strip.hidden, rizinState.emu, $('rizin-state').textContent];
        // START that finds rizin busy: no strip, START back, and the poll takes the busy away
        S.emuStart = () => [409, { busy: true, step: 'console' }];
        click($('rizin-emu-start'));
        await until(() => rizinState.ui.state === 'busy' && !rizinState.emuWait, 'START found rizin busy');
        r.startBusy = { hidden: strip.hidden, start: $('rizin-emu-start').disabled };
        await until(() => rizinState.ui.state === '', 'the poll found rizin free'); await quiet();
        S.emuStart = undefined;
        // The session ended while a run was out: 404 clears the state, the strip goes, nothing is polled
        await startAt('0x1400014bc');
        S.emuRun = () => ENDED;
        const endFrom = calls.length;
        click(run('step'));
        await until(() => strip.hidden, 'the strip goes'); await quiet();
        r.ended = { emu: rizinState.emu, wait: rizinState.emuWait, hidden: strip.hidden, ui: rizinState.ui.state,
                    start: $('rizin-emu-start').disabled, pcMarks: $('rizin-disasm').querySelectorAll('.rizin-op.pc').length,
                    more: calls.length - endFrom };
        await tick(40);
        r.endedQuiet = calls.length - endFrom === r.ended.more;
        // The state asked for again after the end: 404 from that route alone
        rizinState.ui = { state: '', step: null, reason: null, path: null };
        S.ended = false;
        S.emuRun = undefined;
        await rizinEmuStart(); await quiet();
        r.restarted = !strip.hidden;
        S.emuState = () => ENDED;
        await rizinReloadViews(); await quiet();
        S.emuState = undefined;
        r.endedByRead = [rizinState.emu, strip.hidden, rizinState.ui.state];
        // Another file: the emulation of the file before is gone from the tab
        const T = { analysis: 'done', done: ['aaa'] };
        serve('S2', T);
        opens['C:\\x\\f.exe'] = T;
        S.ended = false;
        rizinState.ui = { state: '', step: null, reason: null, path: null };
        await rizinEmuStart(); await quiet();
        r.beforeOther = !strip.hidden;
        await openInRizin('C:\\x\\f.exe');
        await until(() => rizinState.landed, 'the other file landed'); await quiet();
        r.other = { emu: rizinState.emu, hidden: strip.hidden, wait: rizinState.emuWait, note: rizinState.emuNote,
                    marks: $('rizin-disasm').querySelectorAll('.rizin-op.pc').length };
    """)
    assert "error" not in r, r.get("error")
    assert r["busy"] == {"retry": True, "ui": "busy", "hidden": False, "asked": 1}, r["busy"]
    assert r["retried"]["asked"] >= 2 and r["retried"]["ui"] == "" and r["retried"]["hidden"] is False
    assert r["retried"]["rax"] == "0x29", "the state asked for again after the retry was not taken"
    assert r["runBusy"]["pc"] is True and "busy" in r["runBusy"]["why"] and "console" in r["runBusy"]["why"]
    assert "nothing ran" in r["runBusy"]["why"] and r["runBusy"]["buttons"] == 0, "the buttons stayed off after a busy answer"
    assert r["stopBusy"]["hidden"] is False and "not left" in r["stopBusy"]["why"] and "console" in r["stopBusy"]["why"]
    assert r["startBusy"] == {"hidden": True, "start": False}
    assert r["late"] == {"emu": None, "hidden": True, "wait": ""}, "a late answer brought the emulation back: " + str(r["late"])
    assert "nothing ran" not in r["noteGone"] and r["noteGone"].strip(), r["noteGone"]
    assert r["assistBusy"] == {"retry": True, "hidden": True}, r["assistBusy"]
    assert r["lostByRead"]["emu"] is None and r["lostByRead"]["hidden"] is True and "not started" in r["lostByRead"]["state"]
    assert r["lost"]["emu"] is None and r["lost"]["hidden"] is True and "not started" in r["lost"]["state"]
    assert r["lost"]["start"] is False
    assert r["refused"][0] is True and r["refused"][1] is None and "io.cache" in r["refused"][2]
    assert r["ended"]["emu"] is None and r["ended"]["hidden"] is True and r["ended"]["ui"] == "ended"
    assert r["ended"]["wait"] == "" and r["ended"]["start"] is True and r["ended"]["pcMarks"] == 0
    assert r["endedQuiet"] is True, "the tab went on asking after the session ended"
    assert r["restarted"] is True and r["endedByRead"] == [None, True, "ended"]
    assert r["beforeOther"] is True
    assert r["other"] == {"emu": None, "hidden": True, "wait": "", "note": "", "marks": 0}


@needs_node
def test_rizin_emulation_follow_is_no_navigation_of_the_user():
    # R53: the views following a run are no jump of the user's: ◀ ▶ keep the places the user went to (a run
    # neither adds to the list nor cuts off what ▶ holds), ◀ at the place of the PC returns to the entry the
    # user left, and GO TO PC, which is a jump of theirs, does enter the history
    r = _scripted(EMU_SETUP + r"""
        const history = () => [rizinState.history.slice(), rizinState.historyAt];
        const back = $('rizin-back'), forward = $('rizin-forward');
        await rizinSeek('0x1400014be', 'test'); await quiet();
        await rizinHistoryStep(-1); await quiet();
        r.before = history();
        click($('rizin-emu-start'));
        await until(() => !strip.hidden, 'the strip'); await quiet();
        await press(run('step')); await press(run('step'));
        for (let i = 0; i < 3; i++) await press(run('over'));
        r.afterRuns = [...history(), rizinState.seek, back.disabled, forward.disabled, rizinState.emu.pc];
        click(back);
        await until(() => rizinState.seek === '0x1400014b7', 'back to the entry the user left'); await quiet();
        r.back = [...history(), rizinState.seek, forward.disabled];
        click(act('gotopc'));
        await until(() => rizinState.seek === rizinState.emu.pc, 'GO TO PC'); await quiet();
        r.goto = [...history(), rizinState.seek === rizinState.emu.pc];
    """)
    assert "error" not in r, r.get("error")
    assert r["before"] == [["0x1400014b7", "0x1400014be"], 0]
    assert r["afterRuns"][:2] == [["0x1400014b7", "0x1400014be"], 0], \
        "a run added to the history or cut off what ▶ holds: " + str(r["afterRuns"])
    assert r["afterRuns"][2] == "0x140001529" and r["afterRuns"][3:5] == [False, False], \
        "the views were not at the PC, or ◀ ▶ were off at a place that is no entry of the history"
    assert r["back"] == [["0x1400014b7", "0x1400014be"], 0, "0x1400014b7", False], \
        "◀ at the PC's place went past the entry the user left"
    assert r["goto"] == [["0x1400014b7", "0x140001529"], 1, True], "GO TO PC did not enter the history"


def test_rizin_run_strip_styles():
    """The PC and the changed registers carry their meaning without colour (a sign, a dashed edge), the
    hidden strip is not shown, and the strip wraps to a second line below 1400 px rather than cutting its
    buttons."""
    classic = _rules(STYLE_CSS)
    assert _declared(classic.get(".rizin-run[hidden]"), "display") == "none"
    body = classic.get(".rizin-run", "")
    assert _declared(body, "display") == "flex" and _declared(body, "flex-wrap") == "wrap"
    assert "▶" in (_declared(classic.get(".rizin-op.pc::before"), "content") or ""), "the PC's row has no sign"
    assert "dashed" in (_declared(classic.get(".rizin-op.pc"), "outline") or "")
    assert _declared(classic.get(".rizin-block.pc .rizin-block-box"), "stroke-dasharray"), "the PC's block has no dashed edge"
    assert _declared(classic.get(".rizin-run-reg"), "border-left") and _declared(classic.get(".rizin-run-reg"), "font-weight")
    # The reason and the registers wrap inside their boxes: neither is cut (the assistant's sentence is, in full on hover)
    for selector in (".rizin-run-why", ".rizin-run-regs"):
        body = classic.get(selector, "")
        assert _declared(body, "min-width") == "0" and _declared(body, "text-overflow") is None, selector
        assert _declared(body, "white-space") is None, selector
    assert _declared(classic.get(".rizin-run-why"), "overflow-wrap") == "anywhere", "a long word widens the strip"
    assert _declared(classic.get(".rizin-run-assist-text"), "text-overflow") == "ellipsis"
    assert _declared(classic.get(".rizin-run-reg"), "white-space") == "nowrap", "a register's name and value part"
    text = _strip_comments(_read(STYLE_CSS))
    media = re.search(r"@media \(max-width: 1400px\)\s*\{\s*\.rizin-run\b", text)
    assert media, "no rule for the strip below 1400 px"
    assert "style.css?v=81" not in _read(INDEX_HTML)


# --- Task 11: the EMULATION pane of the dock -------------------------------------------------------
#
# Registers (each one editable), the stack, the breakpoints and the patches, the patches in two groups that decide
# what survives the session. The pane draws the registers, the stack and the PC from rizinState.emu (the state the run
# strip draws from: it asks the route for nothing) and fetches only /patches and /breakpoints, itself.

# The emulation started at 0x1400014bc with a stack and the lists filled, then one step; showPane() opens the tab.
# The patches: two set by hand, two that the run wrote (the stack's words are no row of them: rizin's cache holds them,
# but they are the run's all the same, and one is enough here)
EMU_PANE_SETUP = EMU_SETUP + r"""
    const pane = $('rizin-emulation');
    const text = el => el.textContent.replace(/\s+/g, ' ').trim();
    const attr = (el, name) => el.getAttribute(name);
    const note = () => (pane.querySelector('.rizin-emu-notice') ? text(pane.querySelector('.rizin-emu-notice')) : '');
    const group = name => pane.querySelector(`[data-rizin-group="${name}"]`);
    const acts = el => el.querySelectorAll('button').map(b => attr(b, 'data-rizin-act'));
    const PATCHES = () => [
        { addr: 0x1400014c0, size: 2, before: '7405', after: '9090', mine: true },
        { addr: 0x1400014d0, size: 1, before: '75', after: '74', mine: true },
        { addr: 0x140001521, size: 1, before: '00', after: '41', mine: false },
        { addr: 0x140001522, size: 4, before: '00000000', after: '42434445', mine: false },
    ];
    const BREAKPOINTS = () => [{ addr: 0x140001490, enabled: true }, { addr: 0x1400014b7, enabled: true }];
    const STACK = () => [{ addr: '0x7ffc0000', value: '0x140001490', hint: 'sym.watchdog + 0x4' },
                         { addr: '0x7ffc0008', value: '0x0', hint: null },
                         { addr: '0x7ffc0010', value: '0x7ff7a1b2c3d4e5f6', hint: null }];
    const fill = async () => {
        S.patches = PATCHES(); S.breakpoints = BREAKPOINTS();
        await startAt('0x1400014bc');
        Object.assign(S.emu, { more: [{ name: 'rsp', value: '0x7ffc0000' }], stack: STACK() });
        await press(run('step'));
    };
    const showPane = async () => {
        click(tab('emulation'));
        await until(() => rizinState.views.dock === 'emulation' && pane.querySelector('[data-rizin-section]'), 'the pane'); await quiet();
    };
    const reg = name => pane.querySelectorAll('[data-rizin-reg]').find(i => attr(i, 'data-rizin-reg') === name);
    // A register field typed into, as a browser delivers it: the new value, then change
    const typeInto = async (name, value) => { const input = reg(name); input.value = value; dispatch('change', input); await quiet(); };
"""


@needs_node
def test_rizin_emulation_pane_shows_registers_stack_breakpoints_and_patches():
    # all four sections render from one state; a click on a stack row, a breakpoint row
    # or a patch row seeks to its data-addr
    r = _scripted(EMU_PANE_SETUP + r"""
        await fill();
        const state = rizinState.emu, from = calls.length;
        await showPane();
        r.reads = { emulation: gets(from, '/emulation').length, patches: gets(from, '/patches').map(c => c[1]),
                    breakpoints: gets(from, '/breakpoints').map(c => c[1]), sameState: rizinState.emu === state };
        r.sections = pane.querySelectorAll('[data-rizin-section]').map(e => attr(e, 'data-rizin-section'));
        r.heads = pane.querySelectorAll('.rizin-emu-head').map(text);
        r.dockNote = $('rizin-dock-note').textContent;
        r.registers = pane.querySelectorAll('[data-rizin-reg]').map(i => [attr(i, 'data-rizin-reg'), i.value]);
        r.changed = pane.querySelectorAll('.rizin-emu-reg.changed').map(e => attr(e.querySelector('[data-rizin-reg]'), 'data-rizin-reg'));
        r.deltas = pane.querySelectorAll('.rizin-emu-reg').map(e => [attr(e.querySelector('[data-rizin-reg]'), 'data-rizin-reg'),
                                                                    e.querySelector('.rizin-emu-delta').textContent]);
        r.stack = pane.querySelectorAll('.rizin-emu-stack').map(e => [attr(e, 'data-addr'), text(e)]);
        r.breakpoints = pane.querySelectorAll('.rizin-emu-bp').map(e => [attr(e, 'data-addr'), text(e)]);
        r.patches = pane.querySelectorAll('.rizin-emu-patch').map(e => [attr(e, 'data-addr'), text(e)]);
        const seekOf = async (el, want) => {
            const f = calls.length;
            click(el);
            await until(() => posts(f, '/seek').length >= 1, 'a seek for ' + want); await quiet();
            return [posts(f, '/seek').map(c => c[2].addr), rizinState.seek, want];
        };
        r.clicks = [
            await seekOf(pane.querySelector('.rizin-emu-stack'), '0x7ffc0000'),
            await seekOf(pane.querySelector('.rizin-emu-stack [data-addr="0x140001490"]'), '0x140001490'),
            await seekOf(pane.querySelector('.rizin-emu-bp[data-addr="0x1400014b7"]'), '0x1400014b7'),
            await seekOf(pane.querySelector('.rizin-emu-patch[data-addr="0x140001521"]'), '0x140001521'),
        ];
        // a click in a register field jumps nowhere
        const f = calls.length;
        click(reg('rax')); await tick(20);
        r.regClick = posts(f, '/seek').length;
        // the pane's rows after the clicks are the same rows (a seek draws the pane again, and asks for no list)
        r.after = { patches: gets(from, '/patches').length, breakpoints: gets(from, '/breakpoints').length,
                    emulation: gets(from, '/emulation').length };
    """)
    assert "error" not in r, r.get("error")
    assert r["reads"] == {"emulation": 0, "patches": ["/api/rizin/S1/patches"], "breakpoints": ["/api/rizin/S1/breakpoints"],
                          "sameState": True}, "the pane asked the emulation route (R57), or the lists twice: " + str(r["reads"])
    assert r["sections"] == ["registers", "stack", "breakpoints", "patches"]
    assert r["heads"] == ["REGISTERS 5 · Δ 2 changed", "STACK from rsp", "BREAKPOINTS 2", "PATCHESClear rizin's whole cache"], r["heads"]
    assert "register" in r["dockNote"], "the dock's note says nothing of the pane's fields: " + r["dockNote"]
    assert r["registers"] == [["rax", "0x1"], ["rbx", "0x0"], ["rcx", "0x0"], ["rip", "0x1400014be"], ["rsp", "0x7ffc0000"]], \
        "every register of the state, in rizin's order, each in an editable field"
    assert r["changed"] == ["rax", "rip"], "the registers the last step changed"
    assert dict(r["deltas"]) == {"rax": "Δ", "rbx": "", "rcx": "", "rip": "Δ", "rsp": ""}, "the sign of a changed register"
    assert [row[0] for row in r["stack"]] == ["0x7ffc0000", "0x7ffc0008", "0x7ffc0010"]
    assert "0x140001490" in r["stack"][0][1] and "sym.watchdog + 0x4" in r["stack"][0][1], r["stack"][0]
    assert "0x0" in r["stack"][1][1]
    assert "0x7ff7a1b2c3d4e5f6" in r["stack"][2][1], "a 64-bit stack word came back inexact (a double holds 0x7ff7a1b2c3d4e400)"
    assert [row[0] for row in r["breakpoints"]] == ["0x140001490", "0x1400014b7"]
    assert "sym.watchdog" in r["breakpoints"][0][1] and "sym.main" in r["breakpoints"][1][1], r["breakpoints"]
    assert [row[0] for row in r["patches"]] == ["0x1400014c0", "0x1400014d0", "0x140001521", "0x140001522"]
    assert "7405" in r["patches"][0][1] and "9090" in r["patches"][0][1] and "sym.main" in r["patches"][0][1], r["patches"][0]
    assert [c[0] for c in r["clicks"]] == [["0x7ffc0000"], ["0x140001490"], ["0x1400014b7"], ["0x140001521"]], \
        "a click went out with another address, or with more than one seek: " + str(r["clicks"])
    assert all(c[1] == c[2] for c in r["clicks"]), "the views did not end up at the row's address: " + str(r["clicks"])
    assert r["regClick"] == 0, "a click in a register field jumped"
    assert r["after"] == {"patches": 1, "breakpoints": 1, "emulation": 0}, r["after"]


@needs_node
def test_rizin_emulation_pane_separates_my_patches_from_what_the_run_wrote():
    # mine:true rows sit under the hand-made heading with Export and Take all back;
    # mine:false rows sit under their own heading, which says they end with the session,
    # and Export is not offered there
    # (R61 moved Take all back: it clears rizin's one cache, the run's bytes too, so it is in the head of PATCHES, outside
    # both groups, as "Clear rizin's whole cache"; it is on whenever the cache holds anything)
    r = _scripted(EMU_PANE_SETUP + r"""
        await fill(); await showPane();
        const hand = group('hand'), runG = group('run');
        r.order = pane.querySelectorAll('[data-rizin-group]').map(e => attr(e, 'data-rizin-group'));
        r.apart = [hand !== runG, !hand.contains(runG), !runG.contains(hand), hand.className !== runG.className];
        r.hand = { rows: addrs(hand, '.rizin-emu-patch'), acts: acts(hand), head: text(hand.querySelector('.rizin-emu-subhead')) };
        r.run = { rows: addrs(runG, '.rizin-emu-patch'), acts: acts(runG), head: text(runG.querySelector('.rizin-emu-subhead')),
                  warn: text(runG.querySelector('.rizin-emu-warn')) };
        r.exports = pane.querySelectorAll('[data-rizin-act="export"]').map(b => hand.contains(b));
        r.reanalyse = pane.querySelectorAll('[data-rizin-act="reanalyze"]').map(b => runG.contains(b));
        const cache = pane.querySelectorAll('[data-rizin-act="unpatch-all"]');
        r.cache = { count: cache.length, inGroups: cache.filter(b => hand.contains(b) || runG.contains(b)).length,
                    inHead: cache.filter(b => b.closest('.rizin-emu-head') && b.closest('[data-rizin-section="patches"]')).length,
                    label: cache.map(b => b.textContent), off: cache.map(b => b.hasAttribute('disabled')) };
        r.rowButtons = [hand, runG].map(g => g.querySelectorAll('.rizin-emu-patch [data-rizin-act="unpatch"]').length);
        // Nothing by hand: Export is off, the group says so, the cache button stays on (the run's bytes are in the cache);
        // nothing from a run: Re-analyse is off
        S.patches = PATCHES().filter(p => !p.mine);
        await rizinLoadEmuPane(true);
        r.noHand = { export: pane.querySelector('[data-rizin-act="export"]').hasAttribute('disabled'),
                     cache: pane.querySelector('[data-rizin-act="unpatch-all"]').hasAttribute('disabled'),
                     text: text(group('hand')), run: addrs(group('run'), '.rizin-emu-patch') };
        S.patches = PATCHES().filter(p => p.mine);
        await rizinLoadEmuPane(true);
        r.noRun = { reanalyze: pane.querySelector('[data-rizin-act="reanalyze"]').hasAttribute('disabled'), text: text(group('run')),
                    export: pane.querySelector('[data-rizin-act="export"]').hasAttribute('disabled'),
                    cache: pane.querySelector('[data-rizin-act="unpatch-all"]').hasAttribute('disabled') };
        // The cache holds only what was set by hand: the button still asks first (this clear cannot be undone), and a
        // declined question sends nothing
        const asked = [];
        globalThis.confirm = question => { asked.push(question); return false; };
        const c = calls.length;
        click(pane.querySelector('[data-rizin-act="unpatch-all"]')); await quiet();
        r.handOnly = { asked, deletes: calls.slice(c).filter(x => x[0] === 'DELETE').length };
        // An action in flight puts the button off
        rizinState.emuPane.busy = 'export'; rizinRenderEmuPane();
        r.busyOff = pane.querySelector('[data-rizin-act="unpatch-all"]').hasAttribute('disabled');
        rizinState.emuPane.busy = ''; rizinRenderEmuPane();
        r.busyBack = pane.querySelector('[data-rizin-act="unpatch-all"]').hasAttribute('disabled');
        // An empty cache: the button is off and its title says why; pressing it anyway says so and sends nothing
        S.patches = [];
        await rizinLoadEmuPane(true);
        const empty = pane.querySelector('[data-rizin-act="unpatch-all"]');
        const e = calls.length;
        await rizinUnpatch(); await quiet();
        r.empty = { off: empty.hasAttribute('disabled'), title: attr(empty, 'title'), deletes: calls.slice(e).filter(c => c[0] === 'DELETE').length,
                    said: note() };
        // A run that wrote a byte at a time (a decryption loop): the rows are capped, and the rest is counted, not hidden
        const many = RIZIN_EMU_PANE.rows + 30;
        S.patches = PATCHES().filter(p => p.mine).concat(Array.from({ length: many }, (_, i) => ({ addr: 0x140002000 + i, size: 1, before: '00', after: '41', mine: false })));
        await rizinLoadEmuPane(true);
        r.many = { rows: pane.querySelectorAll('[data-rizin-group="run"] .rizin-emu-patch').length, cap: RIZIN_EMU_PANE.rows,
                  head: text(group('run').querySelector('.rizin-emu-subhead')), more: text(group('run').querySelector('.rizin-emu-empty')) };
    """)
    assert "error" not in r, r.get("error")
    assert r["order"] == ["hand", "run"], "the hand-made group first"
    assert r["apart"] == [True, True, True, True], "the two groups are one element, or look the same"
    assert r["hand"]["rows"] == ["0x1400014c0", "0x1400014d0"], "only the rows with mine: true under the hand-made heading"
    assert "by hand" in r["hand"]["head"].lower(), r["hand"]["head"]
    assert r["hand"]["acts"] == ["export", "unpatch", "unpatch"], r["hand"]["acts"]
    assert r["run"]["rows"] == ["0x140001521", "0x140001522"], "only the rows with mine: false under the run's heading"
    assert "2 · 5 B" in r["run"]["head"], "the run's byte total is the sum of the sizes (1 + 4), not the number of rows: " + r["run"]["head"]
    assert "run" in r["run"]["head"].lower() and "end with the session" in r["run"]["head"].lower(), r["run"]["head"]
    assert re.search(r"end with the session", r["run"]["warn"], re.I) and "not saved" in r["run"]["warn"], r["run"]["warn"]
    assert r["run"]["acts"] == ["reanalyze"], "the run's group carries Re-analyse and nothing that exports or takes back"
    assert r["exports"] == [True], "Export is offered once, and on the hand-made group"
    assert r["reanalyse"] == [True]
    assert r["cache"] == {"count": 1, "inGroups": 0, "inHead": 1, "label": ["Clear rizin's whole cache"], "off": [False]}, r["cache"]
    assert r["rowButtons"] == [2, 0], "a row of the hand-made group takes itself back, a row of the run's does not"
    assert r["noHand"]["export"] is True and r["noHand"]["cache"] is False, \
        "Export offered with nothing to export, or the cache button off while the run's bytes are in it"
    assert "nothing" in r["noHand"]["text"].lower() and r["noHand"]["run"] == ["0x140001521", "0x140001522"], r["noHand"]
    assert r["many"]["rows"] == r["many"]["cap"] and f"{r['many']['cap'] + 30} B" in r["many"]["head"] \
        and "+30 more" in r["many"]["more"], "the run's rows are not capped, or the cap is not said: " + str(r["many"])
    assert r["noRun"]["reanalyze"] is True and r["noRun"]["export"] is False and "nothing" in r["noRun"]["text"].lower(), r["noRun"]
    assert r["noRun"]["cache"] is False, "the cache holds hand-made patches and the button is off"
    assert len(r["handOnly"]["asked"]) == 1 and "2 writes set by hand and 0 writes the run made" in r["handOnly"]["asked"][0] \
        and r["handOnly"]["deletes"] == 0, \
        "the cache button cleared hand-made patches without asking, or asked a different question: " + str(r["handOnly"])
    assert r["busyOff"] is True and r["busyBack"] is False, "the cache button stays on while an action of the pane is out"
    assert r["empty"]["off"] is True and "empty" in r["empty"]["title"] and r["empty"]["deletes"] == 0, r["empty"]
    assert "empty" in r["empty"]["said"] and "nothing to clear" in r["empty"]["said"], "pressing it on an empty cache was silent: " + str(r["empty"])


@needs_node
def test_rizin_emulation_pane_edits_a_register_and_takes_a_patch_back():
    # typing into a register field posts /emulation/register, taking a patch back posts
    # DELETE /patch with that addr, and both re-read the state afterwards
    # (the register's POST answers with the state too, but it is the route's GET that fills rizinState.emu: R57)
    r = _scripted(EMU_PANE_SETUP + r"""
        await fill(); await showPane();
        const asks = [];
        let sure = true;
        globalThis.confirm = question => { asks.push(question); return sure; };
        // A bad address takes nothing back, and not everything: that is the call without an address
        let f = calls.length;
        await rizinUnpatch('banana'); await rizinUnpatch(null); await rizinUnpatch(''); await tick(20);
        r.badAddr = [calls.slice(f).filter(c => c[0] === 'DELETE').length, asks.length];
        // R52: a 64-bit word goes out as the string typed (normalised by rizinHex) and comes back exact: a double
        // holds 0x7ff7a1b2c3d4e400 for it
        f = calls.length;
        await typeInto('rax', '0x7ff7a1b2c3d4e5f6');
        r.exact = { posts: posts(f, '/emulation/register').map(c => c[2]), reads: gets(f, '/emulation').length,
                    state: rizinState.emu.registers.find(x => x.name === 'rax').value, field: reg('rax').value,
                    strip: attr(document.querySelector('#rizin-run-regs .rizin-run-reg'), 'title'),
                    changed: pane.querySelectorAll('.rizin-emu-reg.changed').map(e => attr(e.querySelector('[data-rizin-reg]'), 'data-rizin-reg')) };
        // A decimal word above 2^53 goes through BigInt, not Number
        f = calls.length;
        await typeInto('rbx', '18446744073709551615');
        r.decimal = { posts: posts(f, '/emulation/register').map(c => c[2]), field: reg('rbx').value };
        // What is no number is not sent, and is said
        f = calls.length;
        await typeInto('rcx', 'banana');
        r.bad = { posts: posts(f, '/emulation/register').length, said: note() };
        // A refusal of the server is said, and the state stays
        S.setRegister = () => [400, { refused: "no register named 'rcx'" }];
        await typeInto('rcx', '0x5');
        S.setRegister = undefined;
        r.refused = { said: note(), rcx: rizinState.emu.registers.find(x => x.name === 'rcx').value };
        // A run in flight: nothing is set (the server answers one request at a time), and it is said
        f = calls.length;
        rizinState.emuWait = 'step';
        await typeInto('rcx', '0x7');
        rizinState.emuWait = '';
        r.waiting = { posts: posts(f, '/emulation/register').length, said: note() };
        // rip is the PC: the views follow it
        f = calls.length;
        await typeInto('rip', '0x140001521');
        await until(() => rizinState.seek === '0x140001521', 'the views follow rip'); await quiet();
        r.rip = { posts: posts(f, '/emulation/register').map(c => c[2]), seeks: posts(f, '/seek').map(c => c[2].addr), pc: rizinEmuPc() };
        // A word the state cannot give is a "?" in the field, never an empty one
        S.emuRun = () => [200, { ...emuRead(S.emu, 'step'), changed: [], registers: [{ name: 'rax', value: null }, { name: 'rbx', value: 'banana' }] }];
        await press(run('step'));
        S.emuRun = undefined;
        r.unreadable = [reg('rax').value, reg('rbx').value];
        await press(run('step'));
        // Taking a patch back: DELETE /patch with that addr; the row goes, and the state is read again
        f = calls.length;
        click(pane.querySelector('.rizin-emu-patch[data-addr="0x1400014c0"] [data-rizin-act="unpatch"]'));
        await until(() => !pane.querySelector('.rizin-emu-patch[data-addr="0x1400014c0"]'), 'the row goes'); await quiet();
        const del = calls.slice(f).filter(c => c[0] === 'DELETE');
        r.takeBack = { deletes: del.map(c => [c[1].replace('/api/rizin/S1', ''), c[2]]), reads: gets(f, '/emulation').length,
                       hand: addrs(group('hand'), '.rizin-emu-patch'), run: addrs(group('run'), '.rizin-emu-patch'), asked: asks.length,
                       said: note() };
        // Take all back with the run's bytes in the cache asks first, and what was said no is no request
        f = calls.length;
        sure = false;
        click(pane.querySelector('[data-rizin-act="unpatch-all"]')); await quiet();
        r.declined = { deletes: calls.slice(f).filter(c => c[0] === 'DELETE').length, asked: asks.length, question: asks[0] || '',
                       rows: pane.querySelectorAll('.rizin-emu-patch').length };
        sure = true;
        click(pane.querySelector('[data-rizin-act="unpatch-all"]'));
        await until(() => !pane.querySelector('.rizin-emu-patch'), 'everything is taken back'); await quiet();
        r.all = { deletes: calls.slice(f).filter(c => c[0] === 'DELETE').map(c => c[2]), rows: pane.querySelectorAll('.rizin-emu-patch').length,
                  asked: asks.length };
        // The cache holding only what a run wrote: the button is on, asks, and clears it (the console's wc-* was the only way before)
        S.patches = PATCHES().filter(p => !p.mine);
        await rizinLoadEmuPane(true);
        f = calls.length; asks.length = 0;
        click(pane.querySelector('[data-rizin-act="unpatch-all"]'));
        await until(() => !pane.querySelector('.rizin-emu-patch'), 'the run\'s bytes are cleared'); await quiet();
        r.runOnly = { deletes: calls.slice(f).filter(c => c[0] === 'DELETE').map(c => c[2]), question: asks[0] || '', said: note() };
    """)
    assert "error" not in r, r.get("error")
    exact = r["exact"]
    assert exact["posts"] == [{"name": "rax", "value": "0x7ff7a1b2c3d4e5f6"}], "the word was sent as a number or changed: " + str(exact)
    assert exact["state"] == "0x7ff7a1b2c3d4e5f6" and exact["field"] == "0x7ff7a1b2c3d4e5f6", \
        "the register came back inexact (a double holds 0x7ff7a1b2c3d4e400)"
    assert exact["reads"] == 1, "the state was not read again after the register was set"
    assert exact["changed"] == ["rax"], "the register just set is marked as changed"
    assert exact["strip"] == "rax changed by the last step or edit", "the strip calls an edit a run: " + str(exact["strip"])
    assert r["decimal"] == {"posts": [{"name": "rbx", "value": "0xffffffffffffffff"}], "field": "0xffffffffffffffff"}, r["decimal"]
    assert r["bad"]["posts"] == 0 and "banana" in r["bad"]["said"] and "no number" in r["bad"]["said"], r["bad"]
    assert "no register named" in r["refused"]["said"] and r["refused"]["rcx"] == "0x0", r["refused"]
    assert r["waiting"]["posts"] == 0 and "waits" in r["waiting"]["said"], r["waiting"]
    assert r["unreadable"] == ["?", "?"], r["unreadable"]
    assert r["rip"]["posts"] == [{"name": "rip", "value": "0x140001521"}] and r["rip"]["seeks"] == ["0x140001521"]
    assert r["rip"]["pc"] == "0x140001521", "the PC did not move with rip"
    take = r["takeBack"]
    assert take["deletes"] == [["/patch", {"addr": "0x1400014c0"}]], take["deletes"]
    assert take["reads"] == 1, "the state was not read again after the patch was taken back"
    assert take["hand"] == ["0x1400014d0"] and take["run"] == ["0x140001521", "0x140001522"], "the other rows stayed"
    assert take["asked"] == 0, "taking one patch back asked"
    assert r["declined"]["deletes"] == 0 and r["declined"]["rows"] == 3, "a declined Take all back went out"
    assert "Clear rizin's whole cache?" in r["declined"]["question"] and "1 write set by hand" in r["declined"]["question"] \
        and "2 writes the run made" in r["declined"]["question"], \
        "the cache button drops the run's writes too (rizin has one cache): the question says both: " + r["declined"]["question"]
    assert r["all"] == {"deletes": [{}], "rows": 0, "asked": 2}, r["all"]
    assert r["runOnly"]["deletes"] == [{}] and "0 writes set by hand and 2 writes the run made" in r["runOnly"]["question"], r["runOnly"]
    assert "Cleared rizin's whole cache" in r["runOnly"]["said"], r["runOnly"]
    assert r["badAddr"] == [0, 0], "a bad address took a patch (or all of them) back"


@needs_node
def test_rizin_emulation_pane_marks_a_patch_set_over_bytes_a_run_wrote():
    # R72: for such a row rizin's `before` is the run's byte and not the file's, so the row by itself reads as if the
    # file held those bytes. The row carries a mark, the group says what follows for an export, and a ✕ that takes a
    # run's whole row with it says so instead of only "Took the patch at X back".
    r = _scripted(EMU_PANE_SETUP + r"""
        await fill(); await showPane();
        S.patches = [
            { addr: 0x140001500, size: 4, before: '00000000', after: '41424344', mine: false, over_run: false },
            { addr: 0x140001501, size: 1, before: '42', after: '90', mine: true, over_run: true },
            { addr: 0x1400014d0, size: 1, before: '75', after: '74', mine: true, over_run: false },
        ];
        await rizinLoadEmuPane(true);
        const row = at => pane.querySelector(`.rizin-emu-patch[data-addr="${at}"]`);
        const mark = at => row(at).querySelector('.rizin-emu-over-mark');
        r.marked = { over: !!mark('0x140001501'), plain: !!mark('0x1400014d0'), runRow: !!mark('0x140001500'),
                     glyph: text(mark('0x140001501')), title: attr(row('0x140001501'), 'title'),
                     plainTitle: attr(row('0x1400014d0'), 'title'),
                     bytes: text(row('0x140001501').querySelector('.rizin-emu-bytes')) };
        r.groupWarn = group('hand').querySelectorAll('.rizin-emu-warn').map(text);
        // the ✕ on that patch: rizin drops the run's whole row with it, and the pane says so
        click(row('0x140001501').querySelector('[data-rizin-act="unpatch"]'));
        await until(() => !row('0x140001501'), 'the row goes'); await quiet();
        r.took = { said: note(), kind: attr(pane.querySelector('.rizin-emu-notice'), 'class'),
                   rows: pane.querySelectorAll('.rizin-emu-patch').map(e => attr(e, 'data-addr')),
                   warn: group('hand').querySelectorAll('.rizin-emu-warn').length };
        // and a patch with nothing of the run's under it says only that it went
        click(row('0x1400014d0').querySelector('[data-rizin-act="unpatch"]'));
        await until(() => !pane.querySelector('.rizin-emu-patch'), 'the last row goes'); await quiet();
        r.plainTook = { said: note(), kind: attr(pane.querySelector('.rizin-emu-notice'), 'class') };
        // anything but true is no mark, and a mark on a row of the run's is no warning in the hand group:
        // the flag comes out of rizin's cache through the server, and the group speaks only for its own rows
        S.patches = [{ addr: 0x1400014d0, size: 1, before: '75', after: '74', mine: true, over_run: 'yes' },
                     { addr: 0x140001600, size: 1, before: '00', after: '41', mine: false, over_run: true }];
        await rizinLoadEmuPane(true);
        r.loose = { marks: pane.querySelectorAll('.rizin-emu-over-mark').length,
                    warn: group('hand').querySelectorAll('.rizin-emu-warn').length };
    """)
    assert "error" not in r, r.get("error")
    marked = r["marked"]
    assert marked["over"] is True, "the patch over the run's bytes carries no mark"
    assert marked["plain"] is False and marked["runRow"] is False, "every row is marked: " + str(marked)
    assert marked["glyph"] == "⚠", marked["glyph"]
    assert "written over bytes a run changed" in marked["title"], marked["title"]
    assert "not the file's" in marked["title"] and "export" in marked["title"], marked["title"]
    assert "written over" not in marked["plainTitle"], marked["plainTitle"]
    assert marked["bytes"].startswith("1 B · ⚠42 → 90"), marked["bytes"]
    assert len(r["groupWarn"]) == 1 and "One of these was set over bytes a run changed" in r["groupWarn"][0], r["groupWarn"]
    assert "still encrypted" in r["groupWarn"][0] and "note names them" in r["groupWarn"][0], r["groupWarn"]
    took = r["took"]
    assert "Took the patch at 0x140001501 back" in took["said"], took["said"]
    assert "1 write the run made went with it" in took["said"] and "4 bytes" in took["said"] \
        and "0x140001500" in took["said"], \
        "the run's row went with the patch and the pane did not say so: " + took["said"]
    assert "back only by running again" in took["said"], took["said"]
    assert "rizin-emu-note-error" in took["kind"], took["kind"]
    assert took["rows"] == ["0x1400014d0"], took["rows"]
    assert took["warn"] == 0, "the warning line stayed with no marked row left"
    assert r["plainTook"]["said"] == "Took the patch at 0x1400014d0 back.", r["plainTook"]
    assert "rizin-emu-note-ok" in r["plainTook"]["kind"], r["plainTook"]["kind"]
    assert r["loose"] == {"marks": 0, "warn": 0}, r["loose"]


@needs_node
def test_rizin_emulation_pane_escapes_hostile_names():
    # a stack hint and a patch row whose function name is `</script><img onerror=…>`
    # produce no tag and no on* attribute in the pane
    r = _scripted(EMU_PANE_SETUP + r"""
        const HOSTILE = '</script><img src=x onerror=alert(1)>', QUOTE = 'x" onmouseover="alert(1)';
        await fill();
        S.emu.stack = [{ addr: '0x7ffc0000', value: '0x140001490', hint: HOSTILE }, { addr: '0x7ffc0008', value: '0x1', hint: QUOTE }];
        S.emu.more = [{ name: HOSTILE, value: '0x1' }, { name: QUOTE, value: '0x2' }];
        S.exportCopy = () => [200, { path: 'C:\\x\\' + HOSTILE, name: HOSTILE, sha256: 'ab'.repeat(32), patched: 3, skipped: [0x50000010],
                                     note: HOSTILE + '\nOriginal: ' + QUOTE + '\n' }];
        rizinState.functions = [{ name: HOSTILE, offset: 0x1400014b7, size: 0x600, nbbs: 1 },
                                { name: QUOTE, offset: 0x140001490, size: 38, nbbs: 1 }];
        rizinState.analysis = { ...rizinState.analysis, note: 'Restored: ' + HOSTILE };
        await press(run('step'));
        await showPane();
        await rizinExportPatched(); await quiet();
        const all = pane.querySelectorAll('*');
        r.tags = all.map(e => e.tagName).filter(t => ['IMG', 'SCRIPT', 'IFRAME', 'SVG'].includes(t));
        r.on = all.flatMap(e => Object.keys(e.attrs).filter(k => k.startsWith('on')));
        r.attrNames = [...new Set(all.flatMap(e => Object.keys(e.attrs)))].sort();
        r.shown = { hostile: text(pane).includes(HOSTILE), quote: text(pane).includes(QUOTE) };
        r.where = {
            stack: pane.querySelectorAll('.rizin-emu-stack').map(e => text(e).includes(HOSTILE) || text(e).includes(QUOTE)),
            patch: text(pane.querySelector('.rizin-emu-patch')).includes(HOSTILE),
            bp: text(pane.querySelector('.rizin-emu-bp')).includes(QUOTE),
            reg: pane.querySelectorAll('[data-rizin-reg]').map(i => attr(i, 'data-rizin-reg')).filter(n => n === HOSTILE || n === QUOTE).length,
            note: text(pane).includes('Restored: ' + HOSTILE),
            exported: text(pane.querySelector('.rizin-emu-export')).includes(HOSTILE),
        };
        // the register field of a hostile name sends that name back as it is
        const f = calls.length;
        await typeInto(HOSTILE, '0x9');
        r.sent = posts(f, '/emulation/register').map(c => c[2]);
    """)
    assert "error" not in r, r.get("error")
    assert r["tags"] == [], "a name of the file became an element: " + str(r["tags"])
    assert r["on"] == [], "an event handler attribute in the pane: " + str(r["on"])
    assert r["attrNames"] == ["aria-hidden", "aria-label", "autocomplete", "class", "data-addr", "data-rizin-act", "data-rizin-group",
                              "data-rizin-reg", "data-rizin-section", "role", "spellcheck", "title", "type", "value"], \
        "a name of the file added an attribute: " + str(r["attrNames"])
    assert r["shown"] == {"hostile": True, "quote": True}, "the names are not shown, as text"
    assert r["where"] == {"stack": [True, True], "patch": True, "bp": True, "reg": 2, "note": True, "exported": True}, r["where"]
    assert r["sent"] == [{"name": "</script><img src=x onerror=alert(1)>", "value": "0x9"}]


@needs_node
def test_rizin_emulation_pane_reanalyze_refreshes_functions_and_strings():
    # Re-analyse posts /reanalyze and then re-reads /functions and the dock lists
    r = _scripted(EMU_PANE_SETUP + r"""
        await fill(); await showPane();
        const f = calls.length;
        click(pane.querySelector('[data-rizin-act="reanalyze"]'));
        await until(() => posts(f, '/reanalyze').length === 1 && gets(f, '/functions').length >= 1 && !rizinState.emuPane.busy, 'Re-analyse');
        await quiet();
        r.posts = posts(f, '/reanalyze').map(c => [c[1].replace('/api/rizin/S1', ''), c[2]]);
        r.functions = gets(f, '/functions').length;
        r.said = note();
        r.pending = { strings: rizinState.lists.strings.stale, imports: rizinState.lists.imports.stale, xrefs: rizinState.xrefsPending,
                      emulation: gets(f, '/emulation').length };
        // The lists come when they are shown
        const g = calls.length;
        click(tab('strings'));
        await until(() => gets(g, '/strings').length >= 1, 'STRINGS'); await quiet();
        r.strings = gets(g, '/strings').length;
        click(tab('emulation')); await quiet();
        // A run that wrote nothing: the server's refusal is said, and nothing is reloaded
        S.patches = PATCHES().filter(p => p.mine);
        await rizinLoadEmuPane(true);
        const h = calls.length;
        await rizinReanalyze(); await quiet();
        r.refused = { said: note(), functions: gets(h, '/functions').length, posts: posts(h, '/reanalyze').length };
        // busy: said, not reloaded
        S.patches = PATCHES();
        await rizinLoadEmuPane(true);
        S.reanalyze = () => [409, { busy: true, step: 'console' }];
        const k = calls.length;
        await rizinReanalyze();
        r.busy = { said: note(), functions: gets(k, '/functions').length };
        await until(() => rizinState.ui.state === '', 'the poll found rizin free');
    """)
    assert "error" not in r, r.get("error")
    assert r["posts"] == [["/reanalyze", {}]], "Re-analyse posts the empty object: the range the run wrote"
    assert r["functions"] >= 1, "FUNCTIONS was not read again"
    assert r["pending"] == {"strings": True, "imports": True, "xrefs": True, "emulation": 0}, r["pending"]
    assert "1 function" in r["said"] and "2 strings" in r["said"] and "0x140001521" in r["said"], r["said"]
    assert r["strings"] == 1, "STRINGS was not asked for when shown"
    assert "wrote nothing" in r["refused"]["said"], r["refused"]
    assert r["refused"]["functions"] == 0 and r["refused"]["posts"] == 1
    assert "busy" in r["busy"]["said"] and "console" in r["busy"]["said"] and r["busy"]["functions"] == 0, r["busy"]


@needs_node
def test_rizin_emulation_pane_says_why_it_has_no_stack_or_no_emulation():
    # R58: never a blank section: not running, and running with a stack of no rows, say why
    r = _scripted(EMU_PANE_SETUP + r"""
        S.patches = PATCHES(); S.breakpoints = BREAKPOINTS();
        await showPane();
        const section = name => text(pane.querySelector(`[data-rizin-section="${name}"]`));
        r.idle = { registers: section('registers'), stack: section('stack'), patches: addrs(pane, '.rizin-emu-patch').length,
                   breakpoints: addrs(pane, '.rizin-emu-bp').length, inputs: pane.querySelectorAll('[data-rizin-reg]').length };
        await startAt('0x1400014bc');
        r.empty = { stack: section('stack'), rows: pane.querySelectorAll('.rizin-emu-stack').length };
        S.emu.stack = STACK(); S.emu.more = [{ name: 'rsp', value: '0x7ffc0000' }];
        await press(run('step'));
        r.full = { stack: section('stack'), rows: pane.querySelectorAll('.rizin-emu-stack').length };
        // STOP: the registers and the stack go, the lists stay
        click(act('stop')); await until(() => strip.hidden, 'stopped'); await quiet();
        r.stopped = { registers: section('registers'), stack: section('stack'), patches: addrs(pane, '.rizin-emu-patch').length,
                      inputs: pane.querySelectorAll('[data-rizin-reg]').length };
        // No file: one sentence for the whole pane
        rizinState.session = null; rizinRenderEmuPane();
        r.noFile = text(pane);
    """)
    assert "error" not in r, r.get("error")
    idle = r["idle"]
    assert "no emulation" in idle["registers"].lower() and "EMULATE" in idle["registers"] and idle["inputs"] == 0, idle
    assert "no emulation" in idle["stack"].lower(), idle
    assert idle["patches"] == 4 and idle["breakpoints"] == 2, "the lists need no emulation"
    empty = r["empty"]["stack"]
    assert r["empty"]["rows"] == 0
    assert "stack pointer" in empty and "outside" in empty and "gone" in empty, "R58 names both: " + empty
    assert "STOP" in empty and "EMULATE" in empty and "START" not in empty, "R58 says restarting maps it again, by the button's name: " + empty
    assert 'id="rizin-emu-start"' in _tab_markup("rizin") and ">EMULATE</button>" in _tab_markup("rizin"), "the toolbar's button is the one the sentences name"
    assert r["full"]["rows"] == 3 and "outside" not in r["full"]["stack"]
    assert "no emulation" in r["stopped"]["registers"].lower() and r["stopped"]["inputs"] == 0 and r["stopped"]["patches"] == 4
    assert r["noFile"] == "No file open."


@needs_node
def test_rizin_emulation_pane_puts_the_note_that_cannot_wait_first():
    # R59: the session's note has _WAITING_NOTE last (the server appends it); the pane shows it first
    from rizin_sessions import _WAITING_NOTE
    r = _scripted(EMU_PANE_SETUP + r"""
        const WAITING = WAITING_JSON;
        await fill(); await showPane();
        const withNote = async note => {
            rizinState.analysis = { ...rizinState.analysis, note };
            rizinRenderEmuPane();
            return pane.querySelectorAll('.rizin-emu-session-note').map(e => [e.className, text(e)]);
        };
        r.pinned = RIZIN_EMU_PANE.urgent === WAITING;
        r.none = await withNote(null);
        r.plain = await withNote('Restored from the saved project.');
        r.waiting = await withNote('Restored from the saved project. A saved patch at 0x10 is in none of the maps. ' + WAITING);
        r.only = await withNote(WAITING);
        r.ordered = rizinEmuNotes('One. ' + WAITING + ' Two.');
    """.replace("WAITING_JSON", json.dumps(_WAITING_NOTE)))
    assert "error" not in r, r.get("error")
    assert r["pinned"] is True, "RIZIN_EMU_PANE.urgent is not the sentence the server appends (rizin_sessions._WAITING_NOTE)"
    assert r["none"] == []
    assert [text for _, text in r["plain"]] == ["Restored from the saved project."]
    assert [text for _, text in r["waiting"]] == [
        _WAITING_NOTE, "Restored from the saved project. A saved patch at 0x10 is in none of the maps."], \
        "the sentence that cannot wait is not first, or the rest changed"
    assert "urgent" in r["waiting"][0][0] and "urgent" not in r["waiting"][1][0]
    assert [text for _, text in r["only"]] == [_WAITING_NOTE]
    assert r["ordered"] == [{"urgent": True, "text": _WAITING_NOTE}, {"urgent": False, "text": "One. Two."}]


@needs_node
def test_rizin_emulation_pane_exports_and_says_what_could_not_be_placed():
    # R56: Export posts /export and shows its answer: the bytes patched, the addresses that have no place in the file,
    # and the note; the download and the hand-off to the Submit tab are Task 13's, not here
    r = _scripted(EMU_PANE_SETUP + r"""
        await fill(); await showPane();
        S.skipped = [0x50000010, 0x50000020];
        S.actDelay = 30;
        const f = calls.length;
        click(pane.querySelector('[data-rizin-act="export"]'));
        await until(() => rizinState.emuPane.busy === 'export', 'the export waits');
        r.waiting = { said: note(), disabled: pane.querySelector('[data-rizin-act="export"]').hasAttribute('disabled'),
                      again: await rizinExportPatched() };
        await until(() => pane.querySelector('.rizin-emu-export'), 'the answer'); await quiet();
        S.actDelay = undefined;
        r.posts = posts(f, '/export').map(c => [c[1].replace('/api/rizin/S1', ''), c[2] ?? null]);
        const box = pane.querySelector('.rizin-emu-export');
        r.shown = { text: text(box), note: text(box.querySelector('pre')), group: group('hand').contains(box), run: group('run').contains(box) };
        r.state = { name: rizinState.emuPane.exported.name, patched: rizinState.emuPane.exported.patched, busy: rizinState.emuPane.busy };
        // Every patch placed: it says so
        S.skipped = [];
        const back = await rizinExportPatched(); await quiet();
        r.placed = text(pane.querySelector('.rizin-emu-export'));
        r.returned = back && back.name;
        // The same address patched again with other bytes (the same rows, the same addresses): the copy is out of date
        const copy = () => text(pane.querySelector('.rizin-emu-export'));
        const before = copy();
        S.patches = S.patches.map(p => (p.addr === 0x1400014c0 ? { ...p, after: 'cccc' } : p));
        await rizinLoadEmuPane(true);
        r.repatched = { before: /changed since/.test(before), after: /changed since/.test(copy()), rows: S.patches.length };
        await rizinExportPatched(); await quiet();
        // A patch taken back: the copy is marked as out of date
        const fresh = copy();
        click(pane.querySelector('.rizin-emu-patch[data-addr="0x1400014d0"] [data-rizin-act="unpatch"]'));
        await until(() => !pane.querySelector('.rizin-emu-patch[data-addr="0x1400014d0"]'), 'taken back'); await quiet();
        r.stale = { before: /changed since/.test(fresh), after: /changed since/.test(text(pane.querySelector('.rizin-emu-export'))) };
        // Nothing by hand: no request
        S.patches = PATCHES().filter(p => !p.mine);
        await rizinLoadEmuPane(true);
        const g = calls.length;
        r.none = await rizinExportPatched();
        r.noneSent = posts(g, '/export').length;
        // A refusal is said
        S.patches = PATCHES();
        await rizinLoadEmuPane(true);
        S.exportCopy = () => [400, { refused: 'none of the patches could be placed in the file: 0x1400014c0' }];
        r.refused = [await rizinExportPatched(), note()];
    """)
    assert "error" not in r, r.get("error")
    assert r["waiting"]["disabled"] is True and "building" in r["waiting"]["said"].lower(), r["waiting"]
    assert r["waiting"]["again"] is False, "a second Export while one is out"
    assert r["posts"] == [["/export", None]], "Export posts nothing but the request (and only one)"
    shown = r["shown"]
    assert "3 bytes" in shown["text"] and "0123456789abcdef_e.patched.exe" in shown["text"], shown["text"]
    assert "0x50000010" in shown["text"] and "0x50000020" in shown["text"] and "not placed" in shown["text"].lower(), shown["text"]
    assert shown["note"].startswith("Patched copy made by TDC") and "Original:" in shown["note"], shown["note"]
    assert shown["group"] is True and shown["run"] is False, "the result belongs to the hand-made group"
    assert r["state"] == {"name": "0123456789abcdef_e.patched.exe", "patched": 3, "busy": ""}
    assert "every patch" in r["placed"].lower() and "not placed" not in r["placed"].lower(), r["placed"]
    assert r["returned"] == "0123456789abcdef_e.patched.exe"
    assert r["repatched"] == {"before": False, "after": True, "rows": 4}, \
        "a patch made again at the same address with other bytes left the copy marked as current: " + str(r["repatched"])
    assert r["stale"] == {"before": False, "after": True}, r["stale"]
    assert r["none"] is False and r["noneSent"] == 0
    assert r["refused"][0] is False and "none of the patches could be placed" in r["refused"][1], r["refused"]


# --- Task 13: the exported copy goes to the Submit tab ---------------------------------------------
#
# The copy is fetched through /api/file/download, put into #file-input and shown by the real handleFileSelect; the Submit tab
# opens, and the user picks the target and presses Detonate there. The tests run the real markup of the Submit tab.
# Added to the shim here: a DataTransfer (what assigns input.files in a browser), the Submit tab's markup, and a switchTab
# that records the tab it opened and what the upload zone showed at that moment. File and Blob are Node's own.
HANDOFF_SETUP = EMU_PANE_SETUP + r"""
    class FakeDataTransfer {
        constructor() { this.list = []; this.items = { add: file => { this.list.push(file); } }; }
        get files() { return this.list.slice(); }
    }
    globalThis.DataTransfer = FakeDataTransfer;
    const holder = document.createElement('div');
    holder.innerHTML = SUBMIT_TAB_JSON;
    document.body.appendChild(holder);
    const zone = $('upload-zone'), input = $('file-input'), detonate = $('submit-btn'), submitResult = $('submit-result');
    // handleFileSelect sets the property, the markup the attribute: the shim does not link them
    const isOff = () => (detonate.disabled !== undefined ? detonate.disabled : detonate.hasAttribute('disabled'));
    const zoneText = () => text(zone.querySelector('p'));
    input.files = { length: 0 };
    const switched = [];
    globalThis.switchTab = name => switched.push([name, zoneText(), isOff()]);
    const PATH = 'C:\\Temp\\rizin_uploads\\0123456789abcdef_e.patched.exe', NAME = '0123456789abcdef_e.patched.exe';
    const COPY = new Uint8Array([0x4d, 0x5a, 0x90, 0x90, 0x00, 0x01]);
    const handoff = () => pane.querySelector('[data-rizin-act="detonate"]');
    const exportIt = async () => {
        click(pane.querySelector('[data-rizin-act="export"]'));
        await until(() => pane.querySelector('.rizin-emu-export'), 'the export'); await quiet();
    };
    const submitted = () => calls.filter(c => c[1].includes('/api/submit')).length;
"""


def _handoff(script):
    return _scripted(HANDOFF_SETUP.replace("SUBMIT_TAB_JSON", json.dumps(_tab_markup("submit"))) + script)


@needs_node
def test_rizin_export_then_detonate_fills_the_submit_tab():
    # the exported path is downloaded, put into #file-input, handleFileSelect is called,
    # the tab switches to submit, and nothing is submitted on its own
    r = _handoff(r"""
        await fill(); await showPane();
        S.copies = { [PATH]: COPY };
        r.before = { zone: zoneText(), disabled: isOff(), files: input.files.length };
        await exportIt();
        // Exporting alone does not touch the Submit tab: the copy is handed on by its own button
        r.exported = { zone: zoneText(), files: input.files.length, switched: switched.length,
                       downloads: gets(0, '/api/file/download').length, button: text(handoff()) };
        const f = calls.length;
        click(handoff());
        await until(() => switched.length, 'the Submit tab opens'); await quiet();
        const file = input.files[0];
        r.after = { files: input.files.length, name: file.name, size: file.size,
                    bytes: Array.from(new Uint8Array(await file.arrayBuffer())), zone: zoneText(),
                    disabled: isOff(), switched,
                    downloads: gets(f, '/api/file/download').map(c => new URLSearchParams(c[1].split('?')[1]).get('path')),
                    other: calls.slice(f).filter(c => c[0] !== 'GET').map(c => c[0] + ' ' + c[1]),
                    submits: submitted(), busy: rizinState.emuPane.busy, said: note(),
                    result: [submitResult.className, text(submitResult)] };
        await tick(60); await quiet();
        r.stillNothing = { submits: submitted(), other: calls.slice(f).filter(c => c[0] !== 'GET').length };
    """)
    assert "error" not in r, r.get("error")
    assert r["before"] == {"zone": "Drop file here or click to browse", "disabled": True, "files": 0}, r["before"]
    assert r["exported"]["zone"] == "Drop file here or click to browse" and r["exported"]["files"] == 0, \
        "Export alone filled the Submit tab: " + str(r["exported"])
    assert r["exported"]["switched"] == 0 and r["exported"]["downloads"] == 0, "Export alone fetched the copy or opened the tab"
    assert "Submit" in r["exported"]["button"], r["exported"]
    after = r["after"]
    assert after["downloads"] == ["C:\\Temp\\rizin_uploads\\0123456789abcdef_e.patched.exe"], \
        "the copy is fetched by the path the export answered, and once"
    assert after["files"] == 1 and after["name"] == "0123456789abcdef_e.patched.exe", \
        "the file in #file-input is not the patched copy under its patched name: " + str(after["name"])
    assert after["bytes"] == [0x4d, 0x5a, 0x90, 0x90, 0x00, 0x01] and after["size"] == 6, "the bytes are not the ones downloaded"
    assert after["zone"] == "0123456789abcdef_e.patched.exe (6 B)", \
        "handleFileSelect was not called with the file (the upload zone shows it): " + after["zone"]
    assert after["disabled"] is False, "Detonate stays disabled: handleFileSelect did not run"
    assert after["switched"] == [["submit", "0123456789abcdef_e.patched.exe (6 B)", False]], \
        "the tab is opened once, after the file was chosen: " + str(after["switched"])
    assert after["other"] == [] and after["submits"] == 0 and r["stillNothing"] == {"submits": 0, "other": 0}, \
        "the hand-off asked a route for more than the download: " + str(after["other"])
    assert after["busy"] == "" and "nothing has been submitted" in after["said"].lower(), after["said"]
    assert after["result"] == ["submit-result visible", "Patched copy from the RIZIN tab: 3 bytes patched. Nothing has been submitted yet."], after["result"]
    assert "app.js?v=126" not in _read(INDEX_HTML), "app.js changed for the hand-off to the Submit tab, its version did not"


@needs_node
def test_rizin_export_reports_patches_it_could_not_place():
    # R67: a copy whose patches could not all be placed still goes to the Submit tab, and the user is told which are
    # missing from it BEFORE they press Detonate: beside the hand-off button (the count on it, the addresses as "0x…"
    # strings above it) and, once the file is chosen, in the Submit tab itself, which a later clean copy does not leave
    # standing. A copy that no longer matches the patches does not go. The pane already showed the skipped addresses
    # (Task 11's test); what is proved here is that the hand-off carries them and that nothing is silent.
    r = _handoff(r"""
        await fill(); await showPane();
        S.copies = { [PATH]: COPY };
        S.skipped = [0x50000010, 0x50000020];
        await exportIt();
        const box = pane.querySelector('.rizin-emu-export');
        r.pane = { text: text(box), button: text(handoff()), disabled: handoff().hasAttribute('disabled'),
                   buttonInBox: box.contains(handoff()) };
        r.paneBeforeHandoff = { files: input.files.length, switched: switched.length };
        click(handoff());
        await until(() => switched.length, 'the hand-off'); await quiet();
        r.hand = { name: input.files[0].name, zone: zoneText(), result: [submitResult.className, text(submitResult)],
                   switched: switched.map(s => s[0]), submits: submitted() };
        // A clean copy next: the warning of the one before does not stay in front of it
        S.skipped = [];
        await exportIt();
        r.clean = { button: text(handoff()), box: text(pane.querySelector('.rizin-emu-export')) };
        click(handoff());
        await until(() => switched.length === 2, 'the second hand-off'); await quiet();
        r.cleanHand = { result: [submitResult.className, text(submitResult)], name: input.files[0].name };
        // A patch taken back after the export: the copy is out of date, and the button does not offer it
        const f = calls.length;
        click(pane.querySelector('.rizin-emu-patch[data-addr="0x1400014d0"] [data-rizin-act="unpatch"]'));
        await until(() => !pane.querySelector('.rizin-emu-patch[data-addr="0x1400014d0"]'), 'taken back'); await quiet();
        r.stale = { disabled: handoff().hasAttribute('disabled'), said: /changed since/.test(text(pane.querySelector('.rizin-emu-export'))),
                    downloads: gets(f, '/api/file/download').length };
    """)
    assert "error" not in r, r.get("error")
    p = r["pane"]
    assert "0x50000010" in p["text"] and "0x50000020" in p["text"] and "not placed" in p["text"].lower(), p
    assert p["button"] == "To the Submit tab (2 patches not in it)" and p["disabled"] is False and p["buttonInBox"] is True, \
        "the hand-off does not carry how many patches are missing: " + str(p)
    assert r["paneBeforeHandoff"] == {"files": 0, "switched": 0}, "the copy went on before the user pressed the button"
    h = r["hand"]
    assert h["name"] == "0123456789abcdef_e.patched.exe" and h["zone"].startswith("0123456789abcdef_e.patched.exe"), \
        "a copy with skipped patches did not go to the Submit tab under its patched name: " + str(h)
    assert h["switched"] == ["submit"] and h["submits"] == 0
    assert h["result"][0] == "submit-result visible warning", "the Submit tab shows no warning: " + str(h["result"])
    assert "0x50000010" in h["result"][1] and "0x50000020" in h["result"][1] and "Not in the copy" in h["result"][1], \
        "the Submit tab does not name the addresses that are not in the copy: " + h["result"][1]
    assert "0x" not in r["cleanHand"]["result"][1] and r["cleanHand"]["result"][0] == "submit-result visible", \
        "the warning of the copy before stayed in front of a clean copy: " + str(r["cleanHand"])
    assert r["clean"]["button"] == "To the Submit tab" and "Every patch was placed" in r["clean"]["box"], r["clean"]
    assert r["stale"] == {"disabled": True, "said": True, "downloads": 0}, r["stale"]


@needs_node
def test_rizin_detonate_hand_off_fails_loudly_and_leaves_the_submit_tab_alone():
    # Every way the hand-off can break says why in the pane and leaves #file-input, the upload zone, the result and the
    # tab as they were: a download that is refused or empty, a browser without a DataTransfer, a second press while one
    # is out (one download), and a file opened meanwhile (the old copy does not arrive in the new file's Submit tab)
    r = _handoff(r"""
        await fill(); await showPane();
        await exportIt();
        const untouched = () => ({ files: input.files.length, zone: zoneText(), disabled: isOff(),
                                   result: submitResult.className,
                                   switched: switched.filter(s => s[0] === 'submit').length });
        const handPress = async () => { click(handoff()); await until(() => !rizinState.emuPane.busy, 'the hand-off ends'); await quiet(); };
        r.base = untouched();
        // The folder holds no such file (a copy that was cleaned up): 404
        await handPress();
        r.notFound = { ...untouched(), said: note(), buttonOff: handoff().hasAttribute('disabled') };
        // An empty answer
        S.copies = { [PATH]: new Uint8Array([]) };
        await handPress();
        r.empty = { ...untouched(), said: note() };
        // The web UI does not answer
        const realFetch = globalThis.fetch;
        globalThis.fetch = () => Promise.reject(new TypeError('Failed to fetch'));
        await handPress();
        r.network = { ...untouched(), said: note() };
        globalThis.fetch = realFetch;
        // A browser that cannot build a file list
        S.copies = { [PATH]: COPY };
        const Real = globalThis.DataTransfer;
        globalThis.DataTransfer = function () { throw new TypeError('Illegal constructor'); };
        await handPress();
        r.noTransfer = { ...untouched(), said: note() };
        // ...or one that takes the list and keeps none of it
        globalThis.DataTransfer = class { constructor() { this.items = { add() {} }; this.files = []; } };
        await handPress();
        r.keptNone = { ...untouched(), said: note() };
        // ...or one whose list holds another file than the one put in
        globalThis.DataTransfer = class { constructor() { this.items = { add() {} }; this.files = [new File(['x'], 'other.exe')]; } };
        await handPress();
        r.otherFile = { ...untouched(), said: note() };
        globalThis.DataTransfer = Real;
        // A second press while the first one is out: one download
        S.actDelay = 60;
        const f = calls.length;
        click(handoff());
        await until(() => rizinState.emuPane.busy === 'detonate', 'the fetch waits');
        r.waiting = { said: note(), disabled: handoff().hasAttribute('disabled'), again: await rizinDetonatePatched(PATH, NAME),
                      exportAgain: await rizinExportPatched() };
        await until(() => switched.length === 1, 'the hand-off'); await quiet();
        S.actDelay = undefined;
        r.once = { downloads: gets(f, '/api/file/download').length, posts: posts(f, '/export').length, switched: switched.length };
        // A file opened while the copy is on its way: the old file's copy does not go to the Submit tab
        input.files = { length: 0 }; switched.length = 0; submitResult.className = 'submit-result'; zone.querySelector('p').textContent = 'Drop file here or click to browse';
        detonate.disabled = true;
        S.actDelay = 80;
        click(handoff());
        await until(() => rizinState.emuPane.busy === 'detonate', 'the fetch waits again');
        const T = { analysis: 'done', done: ['aaa'], patches: [], breakpoints: [] };
        serve('S2', T);
        opens['C:\\x\\f.exe'] = T;
        await openInRizin('C:\\x\\f.exe');
        await until(() => rizinState.landed, 'the other file'); await tick(120); await quiet();
        S.actDelay = undefined;
        r.moved = { ...untouched(), session: rizinState.session, busy: rizinState.emuPane.busy };
    """)
    assert "error" not in r, r.get("error")
    base = r["base"]
    assert base == {"files": 0, "zone": "Drop file here or click to browse", "disabled": True, "result": "submit-result", "switched": 0}, base
    for key, why in (("notFound", "http 404"), ("empty", "empty"), ("network", "did not answer"),
                     ("noTransfer", "did not take the file"), ("keptNone", "did not take the file"),
                     ("otherFile", "did not take the file")):
        got = r[key]
        assert {k: got[k] for k in base} == base, f"{key}: the Submit tab was touched: {got}"
        assert "not handed to the submit tab" in got["said"].lower() and why in got["said"].lower(), f"{key}: {got['said']}"
    assert r["notFound"]["buttonOff"] is False, "a failed hand-off took the button away: the user cannot try again"
    w = r["waiting"]
    assert w["disabled"] is True and "fetching" in w["said"].lower() and w["again"] is False and w["exportAgain"] is False, w
    assert r["once"] == {"downloads": 1, "posts": 0, "switched": 1}, "a second press fetched again: " + str(r["once"])
    m = r["moved"]
    assert m["session"] == "S2" and m["switched"] == 0 and m["files"] == 0 and m["disabled"] is True and m["busy"] == "", \
        "the copy of the file before arrived in the Submit tab after another file was opened: " + str(m)


@needs_node
def test_rizin_detonate_hand_off_treats_the_name_and_path_as_text():
    # The name of the copy comes from a filename the analyst uploaded: it reaches the upload zone, the Submit tab's
    # result and the request as text (no element, no handler), and the path leaves in the query string encoded, whatever
    # characters it holds
    r = _handoff(r"""
        const NASTY = '<img src=x onerror=alert(1)>', ODD = 'C:\\Temp\\rizin_uploads\\a&path=C:\\evil #1 100%.patched.exe';
        await fill(); await showPane();
        S.copies = { [ODD]: COPY };
        S.exportCopy = () => [200, { path: ODD, name: NASTY, sha256: 'ab'.repeat(32), patched: 3, skipped: [0x50000010],
                                     note: NASTY + '\n' }];
        await exportIt();
        const f = calls.length;
        click(handoff());
        await until(() => switched.length, 'the hand-off'); await quiet();
        r.url = gets(f, '/api/file/download').map(c => c[1]);
        r.got = new URLSearchParams(r.url[0].split('?')[1]).get('path');
        r.name = input.files[0].name;
        const mine = [pane, zone, submitResult].flatMap(el => [...el.walk()]);
        r.tags = mine.filter(e => ['IMG', 'SCRIPT', 'IFRAME'].includes(e.tagName)).length;
        r.on = mine.flatMap(e => Object.keys(e.attrs).filter(k => k.startsWith('on')));
        r.zone = zoneText(); r.result = text(submitResult);
    """)
    assert "error" not in r, r.get("error")
    assert r["got"] == "C:\\Temp\\rizin_uploads\\a&path=C:\\evil #1 100%.patched.exe", \
        "the path did not survive the query string: " + str(r["url"])
    assert len(r["url"]) == 1 and r["url"][0].count("path=") == 1, r["url"]
    assert r["name"] == "<img src=x onerror=alert(1)>" and r["zone"].startswith("<img src=x onerror=alert(1)> ("), r["zone"]
    assert r["tags"] == 0 and r["on"] == [], "the name of the copy became markup"
    assert "0x50000010" in r["result"]


@needs_node
def test_rizin_emulation_pane_fetches_its_lists_only_when_shown_and_after_what_changes_them():
    # R57: the lists are fetched while the pane is on screen and wanted again after a run; a hidden pane asks for
    # nothing and asks when it is shown; another file's rows never show in this one
    r = _scripted(EMU_PANE_SETUP + r"""
        S.patches = PATCHES(); S.breakpoints = BREAKPOINTS();
        await startAt('0x1400014bc');
        // Hidden: a step asks for nothing, the pane is stale
        let f = calls.length;
        await press(run('step'));
        r.hidden = { lists: gets(f, '/patches').length + gets(f, '/breakpoints').length, stale: rizinState.emuPane.stale };
        f = calls.length;
        await showPane();
        r.shown = { patches: gets(f, '/patches').length, breakpoints: gets(f, '/breakpoints').length, stale: rizinState.emuPane.stale };
        // On screen: a step asks for both lists once, the state not at all; a seek asks for none
        S.patches.push({ addr: 0x140001523, size: 1, before: '00', after: '43', mine: false });
        f = calls.length;
        await press(run('step'));
        r.step = { patches: gets(f, '/patches').length, breakpoints: gets(f, '/breakpoints').length, emulation: gets(f, '/emulation').length,
                   rows: addrs(group('run'), '.rizin-emu-patch') };
        f = calls.length;
        await rizinSeek('0x1400014b7', 'test'); await quiet();
        r.seek = gets(f, '/patches').length + gets(f, '/breakpoints').length;
        // A busy answer is asked for again once rizin is free
        S.patchesAnswer = () => { S.patchesAnswer = undefined; return [409, { busy: true, step: 'console' }]; };
        f = calls.length;
        await rizinLoadEmuPane(true);
        r.busy = { retry: rizinState.retry.has('emuPane'), said: text(pane).includes('busy') };
        await until(() => !rizinState.retry.has('emuPane') && gets(f, '/patches').length >= 2, 'asked again'); await quiet();
        r.retried = { rows: pane.querySelectorAll('.rizin-emu-patch').length, ui: rizinState.ui.state };
        // The patches alone are asked for only where the breakpoints held are known to be current: after a failed read or while
        // the pane waits to be asked whole, the other list is asked for too
        r.partial = [];
        for (const mark of [null, 'problem', 'stale']) {
            Object.assign(rizinState.emuPane, { problem: mark === 'problem' ? 'could not be read' : '', stale: mark === 'stale' });
            const h = calls.length;
            await rizinLoadEmuPane(true, 'patches'); await quiet();
            r.partial.push([mark, gets(h, '/patches').length, gets(h, '/breakpoints').length]);
        }
        // A list that was asked for before another one is dropped when it comes late (the newer holds the newer rows)
        S.listDelay = 120;
        const slow = rizinLoadEmuPane(true);
        await tick(10);
        S.patches.push({ addr: 0x140001524, size: 1, before: '00', after: '44', mine: false });
        S.listDelay = 1;
        await rizinLoadEmuPane(true);
        await slow; await quiet();
        r.late = addrs(group('run'), '.rizin-emu-patch');
        // Another file: its pane starts empty of this one's rows
        const T = { analysis: 'done', done: ['aaa'], listDelay: 60, breakpoints: [],
                    patches: [{ addr: 0x1400014c0, size: 1, before: '74', after: '75', mine: true }] };
        serve('S2', T);
        opens['C:\\x\\f.exe'] = T;
        const opening = openInRizin('C:\\x\\f.exe');
        await until(() => rizinState.session === 'S2', 'the other session');
        r.reset = { patches: rizinState.emuPane.patches, at: rizinState.emuPane.at, emu: rizinState.emu,
                    rows: pane.querySelectorAll('.rizin-emu-patch').length };
        await opening;
        await until(() => rizinState.landed && rizinState.emuPane.at === 'S2', 'the other file'); await quiet();
        r.other = { hand: addrs(pane, '.rizin-emu-patch'), bp: pane.querySelectorAll('.rizin-emu-bp').length, said: text(pane.querySelector('[data-rizin-section="breakpoints"]')) };
    """)
    assert "error" not in r, r.get("error")
    assert r["hidden"]["lists"] == 0 and r["hidden"]["stale"] is True, "a hidden pane fetched its lists, or did not want them again: " + str(r["hidden"])
    assert r["shown"] == {"patches": 1, "breakpoints": 1, "stale": False}, r["shown"]
    assert r["step"]["patches"] == 1 and r["step"]["breakpoints"] == 0 and r["step"]["emulation"] == 0, \
        "a step asks for the patches alone (a run cannot change the breakpoints), and never for the state: " + str(r["step"])
    assert r["step"]["rows"] == ["0x140001521", "0x140001522", "0x140001523"], "the run's new write is not in the list"
    assert r["partial"] == [[None, 1, 0], ["problem", 1, 1], ["stale", 1, 1]], r["partial"]
    assert r["seek"] == 0, "a jump asked for the lists"
    assert r["busy"] == {"retry": True, "said": True}, r["busy"]
    assert r["retried"]["rows"] == 5 and r["retried"]["ui"] == "", r["retried"]
    assert r["late"] == ["0x140001521", "0x140001522", "0x140001523", "0x140001524"], "a late older list replaced a newer one: " + str(r["late"])
    assert r["reset"] == {"patches": None, "at": "", "emu": None, "rows": 0}, "the other file's pane held the rows of this one: " + str(r["reset"])
    assert r["other"]["hand"] == ["0x1400014c0"] and r["other"]["bp"] == 0 and "no breakpoints" in r["other"]["said"].lower(), r["other"]


@needs_node
def test_rizin_emulation_pane_removes_a_breakpoint_and_has_no_switch():
    # R19: a breakpoint is set or removed; rizin 0.9.1 stops at one listed as disabled all the same, so the pane has
    # no on/off, and a row that rizin lists as disabled says it still stops a run. ✕ removes, and does not jump.
    r = _scripted(EMU_PANE_SETUP + r"""
        await fill();
        S.breakpoints = [{ addr: 0x140001490, enabled: false }, { addr: 0x1400014b6, enabled: true }, { addr: 0x1400014b7, enabled: true },
                         { addr: 2 ** 60, enabled: true }];
        await showPane();
        const rows = () => pane.querySelectorAll('.rizin-emu-bp');
        r.rows = rows().map(e => [attr(e, 'data-addr'), text(e), e.querySelectorAll('button').length]);
        r.controls = pane.querySelectorAll('input').filter(i => !i.hasAttribute('data-rizin-reg')).length;
        r.toggles = pane.querySelectorAll('[data-rizin-act]').map(b => attr(b, 'data-rizin-act')).filter(a => /on|off|toggle|enable|disable/.test(a));
        const f = calls.length;
        click(pane.querySelector('.rizin-emu-bp[data-addr="0x140001490"] [data-rizin-act="unbreak"]'));
        await until(() => rows().length === 3, 'the row goes'); await quiet();
        r.removed = { deletes: calls.slice(f).filter(c => c[0] === 'DELETE').map(c => [c[1].replace('/api/rizin/S1', ''), c[2]]),
                      seeks: posts(f, '/seek').length, rows: rows().map(e => attr(e, 'data-addr')), said: note() };
        // A bad address removes nothing (and not all of them: that is the route's call without an address)
        const g = calls.length;
        await rizinUnbreak('banana'); await rizinUnbreak(null); await tick(20);
        r.bad = calls.slice(g).filter(c => c[0] === 'DELETE').length;
        // The server refuses: said, and the row stays
        S.unbreak = () => [400, { refused: 'rizin kept the breakpoint at 0x1400014b7' }];
        click(pane.querySelector('.rizin-emu-bp[data-addr="0x1400014b7"] [data-rizin-act="unbreak"]'));
        await until(() => note().includes('kept the breakpoint'), 'the refusal'); await quiet();
        r.refused = { said: note(), rows: rows().length };
        // The patches alone are on their way (a run's refresh) while a breakpoint is removed with ✕: the list that lands does
        // not bring it back
        S.unbreak = undefined;
        S.listDelay = 120;
        const slow = rizinLoadEmuPane(true, 'patches');
        await tick(10);
        const k = calls.length;
        click(pane.querySelector('.rizin-emu-bp[data-addr="0x1400014b6"] [data-rizin-act="unbreak"]'));
        await until(() => rows().length === 2, 'the row goes while the patches are out');
        const early = rows().map(e => attr(e, 'data-addr'));
        S.listDelay = 1;
        await slow; await quiet();
        r.inFlight = { early, after: rows().map(e => attr(e, 'data-addr')), held: rizinState.emuPane.breakpoints.map(b => b.addr),
                       patches: gets(k, '/patches').length, breakpointGets: gets(k, '/breakpoints').length };
    """)
    assert "error" not in r, r.get("error")
    first, past, second, big = r["rows"]
    assert past[0] == "0x1400014b6" and "sym.watchdog" not in past[1] and "sym.main" not in past[1] and "—" in past[1], \
        "a breakpoint one byte past the end of sym.watchdog (and one before sym.main) takes a function's name: " + str(past)
    assert first[0] == "0x140001490" and "still stops a run" in first[1] and first[2] == 1, first
    assert second[0] == "0x1400014b7" and "still stops" not in second[1] and second[2] == 1, second
    assert big[0] is None and "?" in big[1] and big[2] == 0, \
        "an address a double cannot hold exactly was shown as another one, or could be removed: " + str(big)
    assert r["controls"] == 0 and r["toggles"] == [], "the pane has a switch for a breakpoint: rizin ignores it"
    assert r["removed"]["deletes"] == [["/breakpoints", {"addr": "0x140001490"}]] and r["removed"]["seeks"] == 0, r["removed"]
    assert r["removed"]["rows"] == ["0x1400014b6", "0x1400014b7", None] and "0x140001490" in r["removed"]["said"], r["removed"]
    assert r["bad"] == 0
    assert "kept the breakpoint" in r["refused"]["said"] and r["refused"]["rows"] == 3, r["refused"]
    assert r["inFlight"]["early"] == ["0x1400014b7", None] and r["inFlight"]["after"] == ["0x1400014b7", None], \
        "a list of the patches that was on its way brought a removed breakpoint back: " + str(r["inFlight"])
    assert r["inFlight"]["held"][0] == 0x1400014b7 and len(r["inFlight"]["held"]) == 2 and r["inFlight"]["breakpointGets"] == 0, r["inFlight"]


@needs_node
def test_rizin_emulation_pane_keeps_what_is_typed_and_where_it_is_scrolled():
    # The pane is drawn again when the state moves; a register being typed into keeps its text and focus, a field that
    # was only focused takes the new value, and each column keeps its scroll position
    r = _scripted(EMU_PANE_SETUP + r"""
        await fill(); await showPane();
        const input = reg('rbx');
        input.value = '0x12345';                  // typed, not yet sent
        input.focus();
        const cols = pane.querySelectorAll('.rizin-emu-col');
        cols[0].scrollTop = 40; cols[1].scrollTop = 70;
        // The state moved: rax and rbx now differ
        S.emu.rax = 7; S.emu.rbx = 9;
        rizinState.emu = { ...rizinState.emu, registers: rizinState.emu.registers.map(x => (x.name === 'rbx' ? { ...x, value: '0x9' } : x.name === 'rax' ? { ...x, value: '0x7' } : x)) };
        rizinRenderEmuPane();
        r.typed = { value: reg('rbx').value, focused: document.activeElement === reg('rbx'), rax: reg('rax').value };
        r.scroll = pane.querySelectorAll('.rizin-emu-col').map(c => c.scrollTop);
        // A field only focused (nothing typed) takes the state's value
        reg('rax').focus();
        rizinState.emu = { ...rizinState.emu, registers: rizinState.emu.registers.map(x => (x.name === 'rax' ? { ...x, value: '0x8' } : x)) };
        rizinRenderEmuPane();
        r.focusedOnly = reg('rax').value;
        // The same state drawn again writes nothing
        const before = pane.querySelector('.rizin-emu-col');
        rizinRenderEmuPane();
        r.same = pane.querySelector('.rizin-emu-col') === before;
    """)
    assert "error" not in r, r.get("error")
    assert r["typed"] == {"value": "0x12345", "focused": True, "rax": "0x7"}, r["typed"]
    assert r["scroll"] == [40, 70], "the columns lost their scroll position"
    assert r["focusedOnly"] == "0x8"
    assert r["same"] is True, "an unchanged pane was written again"


# The rules of the pane in both themes
EMU_PANE_THEMED = [".rizin-emu-pane", ".rizin-emu-head", ".rizin-emu-reg", ".rizin-emu-reg.changed", ".rizin-emu-delta",
                   ".rizin-emu-reg-name", ".rizin-emu-reg-input", ".rizin-emu-fn", ".rizin-emu-hint", ".rizin-emu-bytes",
                   ".rizin-emu-group", ".rizin-emu-hand", ".rizin-emu-run", ".rizin-emu-subhead", ".rizin-emu-fate",
                   ".rizin-emu-warn", ".rizin-emu-note", ".rizin-emu-note-error", ".rizin-emu-urgent", ".rizin-emu-export"]


def test_rizin_emulation_pane_styles_and_markup():
    """The pane's markup and rules: a tab after IMPORTS and a pane of its own with one delegated click and one change
    handler; a rule for each theme; the changed register and the run's group carry their meaning without colour; the
    pane's columns scroll in themselves, so the dock keeps its height (the work area is not made narrower or shorter
    at 1280 px); the asset versions are raised."""
    tab = _tab_markup("rizin")
    pane = re.search(r'<div[^>]*id="rizin-emulation"[^>]*>', tab).group(0)
    assert re.search(r"\shidden[\s>]", pane) and 'role="tabpanel"' in pane and 'data-rizin-pane="emulation"' in pane, pane
    assert 'onclick="rizinOnEmuPaneClick(event)"' in pane and 'onchange="rizinOnEmuPaneChange(event)"' in pane, pane
    assert 'aria-controls="rizin-emulation"' in tab and tab.index('data-rizin-tab="imports"') < tab.index('data-rizin-tab="emulation"')
    assert tab.index('id="rizin-imports"') < tab.index('id="rizin-emulation"') < tab.index('</section>', tab.index('id="rizin-dock"'))
    assert 'data-rizin-tools="emulation"' not in tab, "the pane has no tools in the dock's head: its buttons are in its groups"

    classic, cyberpunk = _rules(STYLE_CSS), _rules(THEME_CSS)
    prefix = '[data-theme="cyberpunk"] '
    missing = [s for s in EMU_PANE_THEMED if s not in classic] + [prefix + s for s in EMU_PANE_THEMED if prefix + s not in cyberpunk]
    assert not missing, "parts of the pane without a rule in one theme:\n" + "\n".join(missing)
    for path in (STYLE_CSS, THEME_CSS):
        rules = {s: b for s, b in _rules(path).items() if "rizin-emu-" in s}
        written = [f"{s}: {m.group(0)}" for s, b in rules.items() for m in LITERAL_COLOR.finditer(b)]
        assert not written, f"colours written out in {path}:\n" + "\n".join(written)
    # What is not colour: the sign and the bar of a changed register, a heavier name; a run's group with a dashed edge
    # against the solid one of the hand-made group
    assert _declared(classic.get(".rizin-emu-reg.changed"), "font-weight") in ("600", "700", "bold")
    assert _declared(classic.get(".rizin-emu-reg"), "border-left") and _declared(classic.get(".rizin-emu-reg.changed"), "border-left-color")
    assert "dashed" in (_declared(classic.get(".rizin-emu-run"), "border-left") or "")
    assert "solid" in (_declared(classic.get(".rizin-emu-hand"), "border-left") or "")
    # The columns scroll in themselves: neither the pane nor the dock grows with the rows
    body = classic.get(".rizin-emu-pane", "")
    assert _declared(body, "display") == "grid" and _declared(body, "overflow") == "hidden"
    assert "minmax(0, 1fr)" in (_declared(body, "grid-template-columns") or "") and _declared(body, "grid-template-rows") == "minmax(0, 1fr)"
    col = classic.get(".rizin-emu-col", "")
    assert _declared(col, "overflow") == "auto" and _declared(col, "min-height") == "0" and _declared(col, "min-width") == "0"
    assert _declared(classic.get(".rizin-emu-pane[hidden]"), "display") == "none"
    assert "minmax(" in (_declared(classic.get(".rizin-emu-regs"), "grid-template-columns") or ""), "the registers wrap into the width"
    assert _declared(classic.get(".rizin-emu-export"), "overflow-wrap") == "anywhere", "a long name widens the pane"
    name = classic.get(".rizin-emu-reg-name", "")
    assert _declared(name, "text-overflow") == "ellipsis" and _declared(name, "overflow") == "hidden", "a long register name spills over its field"
    assert _declared(classic.get(".rizin-emu-head-row"), "display") == "flex", "the head of PATCHES holds a button"
    html = _read(INDEX_HTML)
    assert "style.css?v=82" not in html and 'theme-layout.css?v=6"' not in html and "app.js?v=121" not in html, \
        "asset versions not raised for the EMULATION pane"


# --- Task 12: breakpoints in the gutter, the patches and Run to here in the menu -------------------------------
#
# DISASSEMBLY's leading cells (the gutter: a ● where a breakpoint is set, one click sets or removes it; a cell for
# a line patched by hand, ≠) and the entries of the right-click menu that act on the one instruction under it. What
# the lines mark comes from the lists /breakpoints and /patches answered, and from the answer of each change.

GUTTER_SETUP = EMU_SETUP + r"""
    const dis = $('rizin-disasm'), menu = $('rizin-menu'), input = $('rizin-menu-input');
    const line = addr => dis.querySelector(`.rizin-op[data-addr="${addr}"]`);
    const gutter = addr => line(addr).querySelector('[data-rizin-gutter]');
    const right = el => dispatch('contextmenu', el, { clientX: 100, clientY: 200, button: 2 });
    const rightAt = addr => right(line(addr).querySelector('.rz-mnem'));
    // The entries the menu shows (hidden ones are not), and those of them that are off
    const shown = () => menu.querySelectorAll('.rizin-menu-item').filter(b => !b.hidden).map(b => b.getAttribute('data-action'));
    const off = () => menu.querySelectorAll('.rizin-menu-item').filter(b => !b.hidden && b.disabled).map(b => b.getAttribute('data-action'));
    const sent = from => calls.slice(from).filter(c => c[0] !== 'GET').map(c => [c[0], c[1].replace('/api/rizin/S1', ''), c[2]]);
    const text = el => el.textContent.replace(/\s+/g, ' ').trim();
"""


@needs_node
def test_rizin_gutter_click_toggles_a_breakpoint_without_seeking():
    # INTENT: a click on the gutter cell of a line sets the breakpoint at that line's address (POST /breakpoints, the
    # address a "0x…" string) and a second click removes it (DELETE), each with exactly one request and no other: the
    # answer is the list. Neither click moves anything: no POST /seek, and seek, the current line and the history stay.
    # A click anywhere else in the line keeps today's behaviour exactly: it seeks (a jump target too), and sends nothing
    # about breakpoints. A refusal leaves the line unmarked and says why in the toolbar; rizin busy leaves it unmarked
    # and says busy; two clicks before the first answer are one request (the second is ignored, not queued).
    r = _scripted(GUTTER_SETUP + r"""
        r.cells = [dis.querySelectorAll('.rizin-op').length, dis.querySelectorAll('[data-rizin-gutter]').map(e => e.getAttribute('data-rizin-gutter'))];
        r.rows = addrs(dis, '.rizin-op');
        r.before = { marked: addrs(dis, '.rizin-op.bp'), glyphs: dis.querySelectorAll('.rizin-gutter').map(e => e.textContent).join('') };
        r.titles = { unset: gutter('0x1400014be').getAttribute('title') };
        await rizinSeek('0x1400014b9', 'test'); await quiet();
        const history = rizinState.history.slice();
        let f = calls.length;
        click(gutter('0x1400014be'));
        await until(() => line('0x1400014be').classList.contains('bp'), 'the breakpoint'); await quiet();
        r.titles.set = gutter('0x1400014be').getAttribute('title');
        r.set = { sent: sent(f), all: calls.slice(f).length, seeks: posts(f, '/seek').length, seek: rizinState.seek, current: addrs(dis, '.rizin-op.current'),
                  history: JSON.stringify(rizinState.history) === JSON.stringify(history), marked: addrs(dis, '.rizin-op.bp'),
                  glyph: gutter('0x1400014be').textContent, on: gutter('0x1400014be').classList.contains('on'),
                  others: dis.querySelectorAll('.rizin-gutter.on').length };
        f = calls.length;
        click(gutter('0x1400014be'));
        await until(() => !line('0x1400014be').classList.contains('bp'), 'the breakpoint is gone'); await quiet();
        r.unset = { sent: sent(f), all: calls.slice(f).length, seeks: posts(f, '/seek').length, seek: rizinState.seek, marked: addrs(dis, '.rizin-op.bp'),
                    glyph: gutter('0x1400014be').textContent };
        // Anywhere else in the line: today's behaviour
        f = calls.length;
        click(line('0x1400014bc').querySelector('.rz-addr'));
        await until(() => rizinState.seek === '0x1400014bc', 'a click on the address'); await quiet();
        r.address = { seeks: posts(f, '/seek').map(c => c[2].addr), bp: calls.slice(f).filter(c => c[1].includes('/breakpoints')).length, marked: addrs(dis, '.rizin-op.bp') };
        f = calls.length;
        click(line('0x1400014bc').querySelector('.rz-target'));
        await until(() => rizinState.seek === '0x140001521', 'a click on the target'); await quiet();
        r.target = { seeks: posts(f, '/seek').map(c => c[2].addr), bp: calls.slice(f).filter(c => c[1].includes('/breakpoints')).length };
        await rizinSeek('0x1400014b9', 'test'); await quiet();
        // A refusal, and rizin busy
        S.setBreakpoint = () => [400, { refused: 'the address is in no map' }];
        f = calls.length;
        click(gutter('0x1400014be'));
        await until(() => text($('rizin-state')).includes('no map'), 'the reason'); await quiet();
        r.refused = { marked: addrs(dis, '.rizin-op.bp'), state: text($('rizin-state')), requests: sent(f).length };
        rizinState.note = ''; rizinRenderState();
        S.setBreakpoint = () => [409, { busy: true, step: 'aaa' }];
        click(gutter('0x1400014be'));
        await until(() => rizinState.ui.state === 'busy', 'busy');
        r.busy = { marked: addrs(dis, '.rizin-op.bp'), ui: rizinState.ui.state, state: text($('rizin-state')) };
        S.setBreakpoint = undefined;
        await quiet();
        // Two clicks at once are one request
        S.actDelay = 40;
        f = calls.length;
        click(gutter('0x1400014be')); click(gutter('0x1400014be')); click(gutter('0x1400014bc'));
        r.cue = dis.classList.contains('rizin-gutter-busy');
        await until(() => line('0x1400014be').classList.contains('bp'), 'the breakpoint again'); await quiet();
        r.twice = { sent: sent(f).map(c => c[0]), marked: addrs(dis, '.rizin-op.bp'), cue: dis.classList.contains('rizin-gutter-busy') };
        S.actDelay = 1;
    """)
    assert "error" not in r, r.get("error")
    assert r["cells"][0] == len(r["rows"]) and r["cells"][1] == r["rows"], "a line without a gutter cell, or one that does not carry its address"
    assert r["before"] == {"marked": [], "glyphs": ""}, "a breakpoint marked where none is set"
    assert r["set"]["sent"] == [["POST", "/breakpoints", {"addr": "0x1400014be"}]] and r["set"]["all"] == 1, \
        "setting one is one POST with the address as a string, and no other request: " + str(r["set"])
    assert r["set"]["seeks"] == 0 and r["set"]["seek"] == "0x1400014b9" and r["set"]["current"] == ["0x1400014b9"] and r["set"]["history"], \
        "a click in the gutter moved the place: " + str(r["set"])
    assert r["set"]["marked"] == ["0x1400014be"] and r["set"]["glyph"] == "●" and r["set"]["on"] is True and r["set"]["others"] == 1
    assert r["unset"]["sent"] == [["DELETE", "/breakpoints", {"addr": "0x1400014be"}]] and r["unset"]["all"] == 1 and r["unset"]["seeks"] == 0 \
        and r["unset"]["seek"] == "0x1400014b9", r["unset"]
    assert r["unset"]["marked"] == [] and r["unset"]["glyph"] == ""
    assert r["address"] == {"seeks": ["0x1400014bc"], "bp": 0, "marked": []}, "a click beside the gutter did not seek as before: " + str(r["address"])
    assert r["target"] == {"seeks": ["0x140001521"], "bp": 0}, "a jump target did not take its click"
    assert r["refused"]["marked"] == [] and "the address is in no map" in r["refused"]["state"] and r["refused"]["requests"] == 1, r["refused"]
    assert r["busy"]["marked"] == [] and r["busy"]["ui"] == "busy" and "busy" in r["busy"]["state"], r["busy"]
    assert r["twice"] == {"sent": ["POST"], "marked": ["0x1400014be"], "cue": False}, \
        "two clicks (or a click on another line) before the answer were not one request, or the pointer cue stayed: " + str(r["twice"])
    assert r["cue"] is True, "a click that is dropped while one request is out says nothing (no cue on the gutter)"
    assert r["titles"] == {"unset": "Click to set a breakpoint here", "set": "Breakpoint set: click to remove it"}, \
        "the gutter's hover text, the only word that the cell takes a click, changed or is gone: " + str(r["titles"])
    assert "cursor" in "".join(_rules(STYLE_CSS).get(".rizin-gutter-busy .rizin-gutter", ""))


@needs_node
def test_rizin_gutter_marks_belong_to_their_file_and_follow_every_change():
    # INTENT: the breakpoints a file already has (rizin keeps them in the project) are marked when it lands, from one request
    # for each list and none for a jump; another file starts without them; a change made elsewhere (✕ in the EMULATION
    # pane, taking a patch back) moves the marks at once; the answer of a click that comes after another file was opened
    # marks nothing in it; and a click that finds the list unknown asks for it first and then decides from it.
    r = _scripted(GUTTER_SETUP + r"""
        const T = { analysis: 'done', done: ['aaa'], breakpoints: [{ addr: 0x1400014bc, enabled: true }, { addr: 0x1400014b7, enabled: false }],
                    patches: [{ addr: 0x1400014b9, size: 3, before: '83fb02', after: '909090', mine: true },
                              { addr: 0x1400014be, size: 1, before: 'e8', after: '90', mine: false }] };
        serve('S2', T);
        opens['C:\\x\\f.exe'] = T;
        const f = calls.length;
        await openInRizin('C:\\x\\f.exe');
        await until(() => rizinState.landed && rizinState.session === 'S2', 'the other file'); await quiet();
        const lists = path => calls.slice(f).filter(c => c[0] === 'GET' && c[1] === `/api/rizin/S2/${path}`).length;
        r.landed = { bp: addrs(dis, '.rizin-op.bp'), patched: addrs(dis, '.rizin-op.patched'), requests: [lists('breakpoints'), lists('patches')],
                     glyphs: dis.querySelectorAll('.rizin-gutter.on').map(e => e.textContent) };
        const g = calls.length;
        await rizinSeek('0x1400014b9', 'test'); await quiet();
        r.jump = [calls.slice(g).filter(c => /\/(breakpoints|patches)$/.test(c[1])).length, addrs(dis, '.rizin-op.bp')];
        // ✕ in the pane removes the mark; taking the patch back removes the other
        click(tab('emulation'));
        await until(() => rizinState.views.dock === 'emulation' && $('rizin-emulation').querySelector('[data-rizin-section]'), 'the pane'); await quiet();
        click($('rizin-emulation').querySelector('.rizin-emu-bp[data-addr="0x1400014bc"] [data-rizin-act="unbreak"]'));
        await until(() => !addrs(dis, '.rizin-op.bp').includes('0x1400014bc'), 'the mark goes'); await quiet();
        r.unbreak = addrs(dis, '.rizin-op.bp');
        click($('rizin-emulation').querySelector('.rizin-emu-patch[data-addr="0x1400014b9"] [data-rizin-act="unpatch"]'));
        await until(() => !addrs(dis, '.rizin-op.patched').length, 'the patched mark goes'); await quiet();
        r.unpatch = addrs(dis, '.rizin-op.patched');
        // A click whose answer comes after another file was opened marks nothing in that one
        T.actDelay = 80;
        click(gutter('0x1400014be'));
        await tick(10);
        const U = { analysis: 'done', done: ['aaa'], breakpoints: [] };
        serve('S3', U);
        opens['C:\\x\\g.exe'] = U;
        await openInRizin('C:\\x\\g.exe');
        await until(() => rizinState.landed && rizinState.session === 'S3', 'the third file'); await tick(120); await quiet();
        r.late = { bp: addrs(dis, '.rizin-op.bp'), marks: JSON.stringify(rizinState.marks.breakpoints), busy: rizinState.marks.busy };
        // The list not known yet (the first read found rizin busy): a click asks for it, then decides
        rizinState.marks.breakpoints = null; rizinState.marks.patched = null; rizinRenderDisasm();
        U.breakpoints = [{ addr: 0x1400014be, enabled: true }];
        const h = calls.length;
        click(gutter('0x1400014be'));
        await until(() => !rizinState.marks.busy && rizinState.marks.breakpoints !== null, 'the list'); await quiet();
        r.unknown = { sent: sent(h).map(c => c[0]), lists: calls.slice(h).filter(c => c[0] === 'GET' && c[1].endsWith('/breakpoints')).length, bp: addrs(dis, '.rizin-op.bp') };
    """)
    assert "error" not in r, r.get("error")
    assert r["landed"]["bp"] == ["0x1400014b7", "0x1400014bc"], "the breakpoints the file already has are not marked: " + str(r["landed"])
    assert r["landed"]["requests"] == [1, 1], "a list asked for more than once (or not at all) while the file lands: " + str(r["landed"])
    assert r["landed"]["patched"] == ["0x1400014b9"], "only the line of the patch by hand is marked, not the byte a run wrote"
    assert r["landed"]["glyphs"] == ["●", "●"]
    assert r["jump"] == [0, ["0x1400014b7", "0x1400014bc"]], "a jump asked for the lists again: " + str(r["jump"])
    assert r["unbreak"] == ["0x1400014b7"], "removing a breakpoint in the pane left its mark"
    assert r["unpatch"] == [], "taking a patch back in the pane left its mark"
    assert r["late"]["bp"] == [] and r["late"]["marks"] == "[]", "a late answer of the file before marked the one open now: " + str(r["late"])
    assert r["unknown"]["sent"] == ["DELETE"] and r["unknown"]["lists"] == 1 and r["unknown"]["bp"] == [], \
        "a click on an unknown list decided without it (it would have set one that is there), or asked more than once: " + str(r["unknown"])


@needs_node
def test_rizin_gutter_breakpoint_pc_and_current_are_three_marks():
    # INTENT (Task 10's test 2 could not write this before the gutter existed): a line may be the current one, the one at the
    # emulation's PC and a breakpoint all at once, and then the three marks are still three: the breakpoint's ● is in the
    # gutter cell, the PC's is the pc class with a ▶ and a dashed edge, the current line's the current class with a solid
    # bar; moving one (a step moves the PC, a click the current line, the gutter the breakpoint) leaves the other two where
    # they were, also once the lines are drawn again; and none of the three is colour alone.
    r = _scripted(GUTTER_SETUP + r"""
        await startAt('0x1400014bc');
        click(gutter('0x1400014bc'));
        await until(() => line('0x1400014bc').classList.contains('bp'), 'the breakpoint'); await quiet();
        const marks = () => ({ current: addrs(dis, '.rizin-op.current'), pc: addrs(dis, '.rizin-op.pc'), bp: addrs(dis, '.rizin-op.bp'),
                               glyphs: dis.querySelectorAll('.rizin-gutter.on').map(e => e.closest('.rizin-op').getAttribute('data-addr')) });
        r.all = marks();
        r.classes = line('0x1400014bc').className.split(' ').sort();
        r.cell = { inGutter: gutter('0x1400014bc').textContent, row: line('0x1400014bc').querySelector('.rz-addr').textContent };
        // The PC moves on: the breakpoint stays, the current line goes with the PC (the views follow it)
        await press(run('step'));
        r.stepped = marks();
        // The user goes elsewhere: the PC and the breakpoint stay
        await rizinSeek('0x1400014b9', 'test'); await quiet();
        r.away = marks();
        // Drawn again (a forced reload): the three marks are as they were
        await rizinLoadDisasm(true); await quiet();
        r.again = marks();
        // The breakpoint goes: the other two stay
        click(gutter('0x1400014bc'));
        await until(() => !line('0x1400014bc').classList.contains('bp'), 'the breakpoint is gone'); await quiet();
        r.removed = marks();
        // All three on one line, from the markup alone
        const host = document.createElement('div');
        host.innerHTML = rizinDisasmHtml([op(0x1400014bc, 2, 'jle 0x140001521', 'cjmp', 0x140001521)],
            { current: '0x1400014bc', pc: '0x1400014bc', breakpoints: [0x1400014bc] });
        const one = host.querySelector('.rizin-op');
        r.markup = { classes: one.className.split(' ').sort(), gutter: one.querySelector('.rizin-gutter').textContent,
                     aria: one.querySelector('.rizin-gutter').getAttribute('aria-label') };
        // A line that is none of the three has no mark of any
        const plain = document.createElement('div');
        plain.innerHTML = rizinDisasmHtml([op(0x1400014bc, 2, 'jle 0x140001521', 'cjmp', 0x140001521)], { current: '0x1', pc: '0x2' });
        r.plain = { classes: plain.querySelector('.rizin-op').className, gutter: plain.querySelector('.rizin-gutter').textContent };
    """)
    assert "error" not in r, r.get("error")
    assert r["all"] == {"current": ["0x1400014bc"], "pc": ["0x1400014bc"], "bp": ["0x1400014bc"], "glyphs": ["0x1400014bc"]}, r["all"]
    assert r["classes"] == ["bp", "current", "pc", "rizin-op"], "the three marks are not three classes of one line: " + str(r["classes"])
    assert r["cell"]["inGutter"] == "●" and r["cell"]["row"] == "0x1400014bc", "the breakpoint's mark is not a glyph of its own cell"
    assert r["stepped"] == {"current": ["0x1400014be"], "pc": ["0x1400014be"], "bp": ["0x1400014bc"], "glyphs": ["0x1400014bc"]}, \
        "a step moved the breakpoint, or left the PC behind: " + str(r["stepped"])
    assert r["away"] == {"current": ["0x1400014b9"], "pc": ["0x1400014be"], "bp": ["0x1400014bc"], "glyphs": ["0x1400014bc"]}, r["away"]
    assert r["again"] == r["away"], "drawn again, the lines lost or moved a mark: " + str(r["again"])
    assert r["removed"] == {"current": ["0x1400014b9"], "pc": ["0x1400014be"], "bp": [], "glyphs": []}, r["removed"]
    assert r["markup"] == {"classes": ["bp", "current", "pc", "rizin-op"], "gutter": "●", "aria": "breakpoint"}
    assert r["plain"] == {"classes": "rizin-op", "gutter": ""}, "a line with no mark carries one"
    # None of the three is colour alone: the breakpoint is a glyph in a cell of its own, the PC a sign and a dashed edge, the
    # current line a solid bar, in both themes
    classic, layout = _rules(STYLE_CSS), _rules(THEME_CSS)
    prefix = '[data-theme="cyberpunk"] '
    assert "▶" in (_declared(classic.get(".rizin-op.pc::before"), "content") or "") and "dashed" in (_declared(classic.get(".rizin-op.pc"), "outline") or "")
    assert "inset" in (_declared(classic.get(".rizin-op.current"), "box-shadow") or "") and "dashed" not in (_declared(classic.get(".rizin-op.current"), "box-shadow") or "")
    assert "inset" in (_declared(layout.get(prefix + ".rizin-op.current"), "box-shadow") or ""), "Cyberpunk's current line is colour alone"
    assert _declared(classic.get(".rizin-gutter"), "display") == "inline-block" and _declared(classic.get(".rizin-gutter"), "width"), \
        "the gutter has no width of its own: the code would shift with a mark"
    assert _declared(classic.get(".rizin-gutter"), "user-select") == "none" and _declared(classic.get(".rz-pm"), "user-select") == "none", \
        "a copied line carries the marks"
    assert _declared(classic.get(".rizin-gutter.on"), "font-weight") in ("600", "700", "bold")
    for selector in (".rizin-gutter", ".rizin-gutter.on", ".rz-pm", ".rizin-op.patched .rz-mnem"):
        assert selector in classic and prefix + selector in layout, f"{selector} has no rule in one theme"
    assert _declared(classic.get(".rz-pm"), "width") == _declared(classic.get(".rizin-gutter"), "width") == "2ch"


def test_rizin_gutter_shows_a_faint_resting_marker_that_is_not_a_breakpoint_in_both_themes():
    # INTENT: the cell was empty at rest, with a ○ only under the pointer, and a user aimed two characters too far right (at
    # the patch cell, also empty). Every line now carries a faint ○ in the gutter, drawn by the stylesheet (the markup stays
    # empty, so a copied or counted line is unchanged), the same ○ is stronger under the pointer, and neither could be
    # mistaken for the red bold ● of a set breakpoint (a hollow ring in a dim text colour against a solid red disc). A
    # reviewer who removes the resting rule from either sheet fails here. Which sheet draws it: data-theme is always set on
    # <html> (the boot script), so the [data-theme] rules of theme-layout.css apply in BOTH themes and their colours
    # (--cp-text-dim, --cp-text-muted) are what reaches the screen, Classic included; the colours of style.css are the
    # fallback of a page without the attribute. So the glyph is checked in the layout sheet too, and across every rule that
    # gives a gutter's pseudo-element a `content`: a `content: ""` there is the empty gutter again, a `"●"` a dim
    # breakpoint on every line.
    classic, layout = _rules(STYLE_CSS), _rules(THEME_CSS)
    prefix = '[data-theme="cyberpunk"] '
    rest, hover = ".rizin-gutter:not(.on)::before", ".rizin-gutter:not(.on):hover::before"
    for rules, pre, dim, strong in ((classic, "", "var(--text-dim)", "var(--text-secondary)"),
                                    (layout, prefix, "var(--cp-text-dim)", "var(--cp-text-muted)")):
        resting, pointed = rules.get(pre + rest), rules.get(pre + hover)
        assert resting, f"{pre + rest} has no rule: the gutter is empty at rest"
        assert pre + rest in rules and pre + hover in rules
        # style.css declares the glyph; the layout sheet applies in BOTH themes (data-theme is always set), so it must
        # either leave the glyph alone or say the same: a `content` of its own there is what the user sees
        if not pre:
            assert _declared(resting, "content") == '"○"' and _declared(pointed, "content") in (None, '"○"'), \
                "the resting marker is not the hollow ○, or the pointer's is another glyph"
        assert _declared(resting, "content") in (None, '"○"') and _declared(pointed, "content") in (None, '"○"'), \
            f"{pre + rest}: the sheet that draws the marker changes its glyph (an empty gutter, or the breakpoint's ●)"
        assert _declared(resting, "color") == dim and _declared(pointed, "color") == strong, "the resting and hover colours"
        assert "red" not in (_declared(resting, "color") or "") + (_declared(pointed, "color") or ""), "a resting marker in the breakpoint's red"
        # a rule on the pseudo-element that took room would move the address, the mnemonic and the operands
        for prop in ("position", "width", "min-width", "margin", "padding", "font-size", "display", "float", "letter-spacing"):
            assert _declared(resting, prop) is None and _declared(pointed, prop) is None, f"the marker declares {prop}: the columns could shift"
    # whatever rule of whichever sheet gives a pseudo-element of a gutter a `content`, it is the hollow ○ (the layout
    # sheet's rules apply in both themes, so none of them may blank it or turn it into the breakpoint's ●)
    glyphs = _gutter_glyphs()
    assert any(sheet == "theme-layout.css" for sheet, _, _ in glyphs), "the layout sheet's rules were not read"
    assert [g for g in glyphs if g[2] not in (None, '"○"')] == [], "a gutter's marker is blanked or is not the hollow ○: " + str(glyphs)
    # a set breakpoint stays the red, bold, glowing ●; the patch cell gets no marker
    assert _declared(classic.get(".rizin-gutter.on"), "font-weight") == "700" and _declared(classic.get(".rizin-gutter"), "color") == "var(--accent-red)"
    assert _declared(layout.get(prefix + ".rizin-gutter"), "color") == "var(--cp-red)" and "text-shadow" in (layout.get(prefix + ".rizin-gutter.on") or "")
    assert _declared(classic.get(".rizin-gutter"), "width") == _declared(classic.get(".rz-pm"), "width") == "2ch"
    assert ".rz-pm::before" not in classic and prefix + ".rz-pm::before" not in layout, "the patch cell is empty at rest"


# --- the gutter in DECOMPILER ------------------------------------------------------------------------------------------
#
# The same gesture as DISASSEMBLY's: a cell before the C of each line that has an address, a click in it sets or
# removes the breakpoint on the line's lowest address (rizinDecompilerStops) and moves nowhere. Where the work is: the
# lines are drawn again only when the C changes, and a breakpoint changes no C.

DEC_GUTTER_SETUP = EMU_SETUP + r"""
    const dec = $('rizin-decompiler'), dis = $('rizin-disasm');
    const cl = i => dec.querySelector(`.rizin-dec-line[data-line="${i}"]`);
    const cell = i => cl(i).querySelector('[data-rizin-gutter]');
    const lineOf = el => Number(el.closest('.rizin-dec-line').getAttribute('data-line'));
    const on = () => dec.querySelectorAll('.rizin-dec-gutter.on').map(lineOf);
    const current = () => dec.querySelectorAll('.rizin-dec-line.current').map(l => Number(l.getAttribute('data-line')));
    const sent = from => calls.slice(from).filter(c => c[0] !== 'GET').map(c => [c[0], c[1].replace('/api/rizin/S1', ''), c[2]]);
    const decs = () => count('GET', '/api/rizin/S1/decompile');
    const lists = () => count('GET', '/api/rizin/S1/breakpoints');
    const showDecompiler = async () => {
        click(tab('decompiler'));
        await until(() => !dec.hidden && dec.querySelectorAll('.rizin-dec-line').length > 0, 'the C'); await quiet();
    };
    const showDisasm = async () => { click(tab('disasm')); await until(() => !dis.hidden, 'the disassembly'); await quiet(); };
    const disBp = () => addrs(dis, '.rizin-op.bp');
    const server = () => (S.breakpoints || []).map(b => b.addr);
"""


@needs_node
def test_rizin_decompiler_gutter_toggles_a_breakpoint_without_seeking():
    # INTENT: the cell stands in every line of C that has an address and in none without (there, an empty place of the same
    # size so that the C of every line starts on the same column, with no ○ and nothing to click); a click in it sets the
    # breakpoint on the line's LOWEST address (0x1400014b9 + 0x1400014bc, and 0x140001521 + 0x140001529 whose `offset` is
    # the higher one) with one POST and no other request, a second click removes it with one DELETE, and neither moves the
    # place (no POST /seek, seek, the current line and the history stay). A click on the line beside the gutter keeps
    # jumping to `offset`, not to the lowest address, and sends nothing about breakpoints; a click on the empty place does
    # nothing. A refusal leaves the line unmarked and says why in the toolbar. Nothing of rizin's becomes markup.
    r = _scripted(DEC_GUTTER_SETUP + r"""
        await showDecompiler();
        const rows = () => dec.querySelectorAll('.rizin-dec-line');
        r.lines = rows().map(l => ({ addr: l.getAttribute('data-addr'), cells: l.querySelectorAll('[data-rizin-gutter]').map(c => c.getAttribute('data-rizin-gutter')),
                                    gutters: l.querySelectorAll('.rizin-dec-gutter').length, pads: l.querySelectorAll('.rizin-dec-pad').length,
                                    first: l.children[0].className, glyph: l.children[0].textContent }));
        r.titles = { unset: cell(7).getAttribute('title'), line: cl(7).getAttribute('title') };
        r.markup = { tags: [...dec.walk()].map(e => e.tagName).filter(t => !['DIV', 'SPAN'].includes(t)),
                     handlers: [...dec.walk()].flatMap(e => Object.keys(e.attrs)).filter(a => a.startsWith('on')) };
        // A line is the current one before the clicks in the gutter: they must not take it away
        click(cl(4));
        await until(() => rizinState.seek === '0x1400014be', 'a click on a line'); await quiet();
        const history = JSON.stringify(rizinState.history);
        r.before = { seek: rizinState.seek, current: current() };
        let f = calls.length;
        click(cell(7));
        await until(() => on().length === 1, 'the breakpoint'); await quiet();
        r.set = { sent: sent(f), all: calls.slice(f).length, seeks: posts(f, '/seek').length, seek: rizinState.seek, current: current(),
                  history: JSON.stringify(rizinState.history) === history, on: on(), glyph: cell(7).textContent, server: server(),
                  title: cell(7).getAttribute('title'), aria: cell(7).getAttribute('aria-label'), cellAddr: cell(7).getAttribute('data-rizin-gutter') };
        f = calls.length;
        click(cell(7));
        await until(() => on().length === 0, 'the breakpoint is gone'); await quiet();
        r.unset = { sent: sent(f), all: calls.slice(f).length, seeks: posts(f, '/seek').length, seek: rizinState.seek, current: current(),
                    glyph: cell(7).textContent, server: server(), aria: cell(7).getAttribute('aria-label') };
        // The line beside the gutter: today's jump, to `offset` (0x140001529), not to the lowest address
        f = calls.length;
        click(cl(7).querySelector('.rz-kw'));
        await until(() => rizinState.seek === '0x140001529', 'the jump'); await quiet();
        r.jump = { seeks: posts(f, '/seek').map(c => c[2].addr), bp: calls.slice(f).filter(c => c[1].includes('/breakpoints')).length, on: on(), current: current() };
        // The empty place of a line without an address, and its text
        f = calls.length;
        click(cl(1).querySelector('.rizin-dec-pad'));
        click(cl(8).querySelector('.rizin-dec-pad'));
        click(cl(1));
        await quiet();
        r.pad = { requests: calls.length - f, seek: rizinState.seek, on: on() };
        // A refusal
        S.setBreakpoint = () => [400, { refused: 'the address is in no map' }];
        f = calls.length;
        click(cell(2));
        await until(() => $('rizin-state').textContent.includes('no map'), 'the reason'); await quiet();
        r.refused = { on: on(), state: $('rizin-state').textContent.replace(/\s+/g, ' ').trim(), requests: sent(f).length,
                      note: rizinState.note.includes('0x1400014b9') };
        S.setBreakpoint = undefined;
    """)
    assert "error" not in r, r.get("error")
    assert [l["addr"] for l in r["lines"]] == [None, None, "0x1400014b9", "0x1400014be", "0x1400014be", None, None, "0x140001529", None]
    assert [l["cells"] for l in r["lines"]] == [[], [], ["0x1400014b9"], ["0x1400014be"], ["0x1400014be"], [], [], ["0x140001521"], []], \
        "a line without an address has a cell to click, or a line with one does not, or the cell is not its lowest address"
    assert [l["pads"] for l in r["lines"]] == [1, 1, 0, 0, 0, 1, 1, 0, 1] and [l["gutters"] for l in r["lines"]] == [0, 0, 1, 1, 1, 0, 0, 1, 0], \
        "a line without an address has no empty place of the cell's size (its C would start two characters to the left), or has a ○ to aim at"
    assert [l["first"] for l in r["lines"]] == ["rizin-dec-pad", "rizin-dec-pad", "rizin-dec-gutter", "rizin-dec-gutter", "rizin-dec-gutter",
                                                "rizin-dec-pad", "rizin-dec-pad", "rizin-dec-gutter", "rizin-dec-pad"], \
        "the cell is not the first thing in each line"
    assert all(l["glyph"] == "" for l in r["lines"]), "a breakpoint is shown where none is set (the ○ is the stylesheet's)"
    assert r["titles"] == {"unset": "Click to set a breakpoint before this line, at 0x140001521", "line": "0x140001521 0x140001529"}, \
        "the hover text of the cell does not name the address the click uses (and it is not the one of the line)"
    assert r["markup"] == {"tags": [], "handlers": []}, "text from rz-ghidra became markup"
    assert r["before"] == {"seek": "0x1400014be", "current": [4]}
    assert r["set"]["sent"] == [["POST", "/breakpoints", {"addr": "0x140001521"}]] and r["set"]["all"] == 1, \
        "a click is one POST with the lowest address as a string, and no other request: " + str(r["set"])
    assert r["set"]["seeks"] == 0 and r["set"]["seek"] == "0x1400014be" and r["set"]["current"] == [4] and r["set"]["history"], \
        "a click in the gutter moved the place: " + str(r["set"])
    assert r["set"]["on"] == [7] and r["set"]["glyph"] == "●" and r["set"]["server"] == [0x140001521] and r["set"]["aria"] == "breakpoint"
    assert r["set"]["title"] == "Breakpoint at 0x140001521: click to remove it" and r["set"]["cellAddr"] == "0x140001521"
    assert r["unset"]["sent"] == [["DELETE", "/breakpoints", {"addr": "0x140001521"}]] and r["unset"]["all"] == 1 \
        and r["unset"]["seeks"] == 0 and r["unset"]["seek"] == "0x1400014be" and r["unset"]["current"] == [4], r["unset"]
    assert r["unset"]["glyph"] == "" and r["unset"]["server"] == [] and r["unset"]["aria"] is None
    assert r["jump"] == {"seeks": ["0x140001529"], "bp": 0, "on": [], "current": [7]}, \
        "a click beside the gutter no longer jumps to `offset`, or sent something about breakpoints: " + str(r["jump"])
    assert r["pad"] == {"requests": 0, "seek": "0x140001529", "on": []}, "a click on a line without an address did something"
    assert r["refused"]["on"] == [] and "the address is in no map" in r["refused"]["state"] and r["refused"]["requests"] == 1 \
        and r["refused"]["note"], "a refusal marked the line, or did not say why: " + str(r["refused"])


@needs_node
def test_rizin_decompiler_gutter_follows_the_disassembly_and_the_console():
    # INTENT: DECOMPILER and DISASSEMBLY read the one list the marks hold. A breakpoint set in DISASSEMBLY's gutter shows in
    # DECOMPILER's cell of the line it is on, with that address in the cell (the line's other address is not the one); one
    # set here shows in DISASSEMBLY; one set by the console while DECOMPILER is in sight shows without a click; neither
    # side asks for the list again (no GET /breakpoints) or for the C again. A line with two addresses that both carry a
    # breakpoint needs two clicks, each removing the lowest one that is set, and is marked until the last is gone. An
    # instruction that belongs to two lines of C (0x1400014be) marks both, and a click on either removes it.
    r = _scripted(DEC_GUTTER_SETUP + r"""
        await showDecompiler();
        const disGutter = addr => dis.querySelector(`.rizin-op[data-addr="${addr}"] [data-rizin-gutter]`);
        const cellAddr = i => cell(i).getAttribute('data-rizin-gutter');
        const L = lists(), D = decs();
        // Set in DISASSEMBLY (0x1400014bc is the higher of the two addresses of line 2)
        await showDisasm();
        click(disGutter('0x1400014bc'));
        await until(() => disBp().length === 1, 'the breakpoint in DISASSEMBLY'); await quiet();
        await showDecompiler();
        r.fromDisasm = { on: on(), cell: cellAddr(2), title: cell(2).getAttribute('title'), glyph: cell(2).textContent,
                         lists: lists() - L, decs: decs() - D };
        // Removed from here: exactly that one, though 0x1400014b9 is the line's lowest
        let f = calls.length;
        click(cell(2));
        await until(() => on().length === 0, 'removed'); await quiet();
        r.removed = { sent: sent(f), server: server() };
        await showDisasm();
        r.inDisasm = disBp();
        await showDecompiler();
        // Set here, shown in DISASSEMBLY
        click(cell(2));
        await until(() => on().length === 1, 'set'); await quiet();
        r.cellAfter = cellAddr(2);
        await showDisasm();
        r.setHere = disBp();
        await showDecompiler();
        click(cell(2));
        await until(() => on().length === 0, 'cleared'); await quiet();
        // The console while DECOMPILER is in sight: its answer says that something changed
        S.console = (cmd, s) => {
            const m = /^db(-?) @ (0x[0-9a-f]+)$/.exec(cmd);
            if (!m) return null;
            const at = parseInt(m[2], 16);
            s.breakpoints = (s.breakpoints || []).filter(b => b.addr !== at);
            if (!m[1]) s.breakpoints.push({ addr: at, enabled: true });
            return [200, { output: '', seek: s.seek ?? 0x1400014b7, function: 'sym.main', truncated: false, changed: true }];
        };
        r.beforeConsole = { decs: decs() - D, lists: lists() - L };
        const L2 = lists();
        await rizinConsoleRun('db @ 0x1400014b9'); await quiet();
        r.console = { on: on(), cell: cellAddr(2), lists: lists() - L2 };
        // Both addresses of the line carry one: marked at the lowest, then at the other, then not
        await rizinConsoleRun('db @ 0x1400014bc'); await quiet();
        r.both = { on: on(), cell: cellAddr(2), server: server() };
        f = calls.length;
        click(cell(2));
        await until(() => server().length === 1, 'the lowest goes'); await quiet();
        r.firstClick = { sent: sent(f), on: on(), cell: cellAddr(2) };
        f = calls.length;
        click(cell(2));
        await until(() => server().length === 0, 'the other goes'); await quiet();
        r.secondClick = { sent: sent(f), on: on() };
        // One instruction, two lines of C (3 and 4 both end at 0x1400014be)
        click(cell(3));
        await until(() => on().length === 2, 'both lines'); await quiet();
        r.shared = { on: on(), cells: [cellAddr(3), cellAddr(4)], titles: [cell(3).getAttribute('title'), cell(4).getAttribute('title')] };
        f = calls.length;
        click(cell(4));
        await until(() => on().length === 0, 'both lines are clear'); await quiet();
        r.sharedGone = { sent: sent(f), on: on(), server: server() };
        r.requests = { lists: lists() - L2, decs: decs() - D };
    """)
    assert "error" not in r, r.get("error")
    assert r["fromDisasm"] == {"on": [2], "cell": "0x1400014bc", "title": "Breakpoint at 0x1400014bc: click to remove it",
                               "glyph": "●", "lists": 0, "decs": 0}, \
        "a breakpoint set in DISASSEMBLY is not shown here, is shown on the wrong address, or the list or the C was asked for again: " + str(r["fromDisasm"])
    assert r["removed"] == {"sent": [["DELETE", "/breakpoints", {"addr": "0x1400014bc"}]], "server": []}, \
        "a click removed another address than the one that carries the breakpoint: " + str(r["removed"])
    assert r["inDisasm"] == [] and r["setHere"] == ["0x1400014b9"] and r["cellAfter"] == "0x1400014b9", \
        "a breakpoint set here is not in DISASSEMBLY, or removing one there did not clear it here: " + str(r)
    assert r["console"] == {"on": [2], "cell": "0x1400014b9", "lists": 1}, \
        "a breakpoint of the console does not show without a click (the list is read once for its answer): " + str(r["console"])
    assert r["both"] == {"on": [2], "cell": "0x1400014b9", "server": [0x1400014b9, 0x1400014bc]}
    assert r["firstClick"] == {"sent": [["DELETE", "/breakpoints", {"addr": "0x1400014b9"}]], "on": [2], "cell": "0x1400014bc"}, \
        "the line is not marked until the last of its breakpoints is gone: " + str(r["firstClick"])
    assert r["secondClick"] == {"sent": [["DELETE", "/breakpoints", {"addr": "0x1400014bc"}]], "on": []}
    assert r["shared"] == {"on": [3, 4], "cells": ["0x1400014be", "0x1400014be"],
                           "titles": ["Breakpoint at 0x1400014be: click to remove it"] * 2}, \
        "an instruction that belongs to two lines of C marks only one: " + str(r["shared"])
    assert r["sharedGone"] == {"sent": [["DELETE", "/breakpoints", {"addr": "0x1400014be"}]], "on": [], "server": []}
    # Up to the console: every click and each side's change reached the other without a request for the C or the list. The
    # console is the one thing that asks, by design (a command that changed something draws the views again, and reads the
    # list once for its answer): one C and one list for each of its two `db`, and none for any click that followed.
    assert r["beforeConsole"] == {"decs": 0, "lists": 0}, "a click or a change in the other view asked for the C or the list again: " + str(r["beforeConsole"])
    assert r["requests"] == {"lists": 2, "decs": 2}, \
        "after the two console commands, a click asked for the C or the list again, or a command asked for more than its one: " + str(r["requests"])


@needs_node
def test_rizin_decompiler_gutter_does_not_go_stale_on_a_toggle():
    # INTENT (Review Focus 5): the lines of C are drawn again only when the C changes, and a breakpoint changes no C, so
    # the mark has to come with the list itself. After a click in the gutter the lines carry the new mark (set, then
    # removed), and the same holds for a list that changed elsewhere (the pane, the console) while DECOMPILER is in sight
    # and while it is hidden (it catches up once shown). What was there stays: the scroll position (also when the line at
    # the top of the view is the second of two that share an address, which a lookup by address alone would take for the
    # first: the view would creep up by a line with each click; and when it is the FIRST of the two, which a lookup that
    # takes the last match would take for the second: the view would creep down by one), the current line (the second of the two, the one that was
    # clicked), and the C itself, which is not asked for again. A message the pane shows instead of lines (the code could
    # not be loaded) is not written over by a list.
    r = _scripted(LAID_OUT + r"""
        // 80 lines; 40 and 41 share an instruction
        DECOMPILED['sym.main'] = [cline('int main(void)'), cline('{'),
            ...Array.from({ length: 77 }, (_, i) => cline(`    step${i}();`, 0x140001600 + 8 * i)), cline('}')];
        DECOMPILED['sym.main'][41] = cline('    again();', DECOMPILED['sym.main'][40].offset);
        const dec = $('rizin-decompiler');
        const S = { analysis: 'done', done: ['aaa'] };
        serve('S1', S);
        opens['C:\\x\\s.exe'] = S;
        await openInRizin('C:\\x\\s.exe');
        await until(() => rizinState.landed, 'landed'); await quiet();
        const cl = i => dec.querySelector(`.rizin-dec-line[data-line="${i}"]`);
        const cell = i => cl(i).querySelector('[data-rizin-gutter]');
        const lineOf = el => Number(el.closest('.rizin-dec-line').getAttribute('data-line'));
        const on = () => dec.querySelectorAll('.rizin-dec-gutter.on').map(lineOf);
        const current = () => dec.querySelectorAll('.rizin-dec-line.current').map(l => Number(l.getAttribute('data-line')));
        const decs = () => count('GET', '/api/rizin/S1/decompile');
        const server = () => (S.breakpoints || []).map(b => b.addr);
        click(tab('decompiler'));
        await until(() => dec.querySelectorAll('.rizin-dec-line').length === 80, 'the C'); await quiet();
        // The second of the two lines is clicked (it stays the current one), and scrolled to so that it is at the top of the view
        click(cl(41));
        await until(() => rizinState.seek === '0x140001730', 'the click'); await quiet();
        dec.scrollTop = 41 * 20 + 7;
        const shared = DECOMPILED['sym.main'][40].offset;
        const gen = rizinState.decompiler.gen, D = decs(), nodes = cl(41);
        r.start = { current: current(), top: dec.scrollTop, on: on() };
        const state = () => ({ on: on(), current: current(), top: dec.scrollTop, gen: rizinState.decompiler.gen, decs: decs() - D, server: server() });
        // A click in the gutter of the line at the top of the view
        click(cell(41));
        await until(() => on().length === 2, 'both lines marked'); await quiet();
        r.set = { ...state(), redrawn: cl(41) !== nodes, glyphs: [cell(40).textContent, cell(41).textContent], cell: cell(41).getAttribute('data-rizin-gutter') };
        click(cell(41));
        await until(() => on().length === 0, 'both lines clear'); await quiet();
        r.unset = { ...state(), glyphs: [cell(40).textContent, cell(41).textContent] };
        // The same with the FIRST of the two lines at the top of the view: a restore that takes the last line of that address
        // (not the one nearest where the view was) would move the view down by a line with each click
        dec.scrollTop = 40 * 20 + 7;
        r.firstAtTop = { start: state() };
        click(cell(40));
        await until(() => on().length === 2, 'both lines marked (first at the top)'); await quiet();
        r.firstAtTop.set = state();
        click(cell(40));
        await until(() => on().length === 0, 'both lines clear (first at the top)'); await quiet();
        r.firstAtTop.unset = state();
        dec.scrollTop = 41 * 20 + 7;
        // A list that changed elsewhere, DECOMPILER in sight: another line (10), then a breakpoint of no line of the C
        S.breakpoints = [{ addr: DECOMPILED['sym.main'][10].offset, enabled: true }];
        await rizinLoadMarks(true); await quiet();
        r.elsewhere = state();
        S.breakpoints = [{ addr: 0x1400014b7, enabled: true }];
        await rizinLoadMarks(true); await quiet();
        r.unrelated = state();
        // Hidden: the list changes (a breakpoint set on line 20), and once shown the lines carry it, where they were
        click(tab('disasm')); await quiet();
        S.breakpoints = [{ addr: DECOMPILED['sym.main'][20].offset, enabled: true }];
        await rizinLoadMarks(true); await quiet();
        click(tab('decompiler')); await quiet();
        r.hidden = state();
        // The pane says something instead of lines (another function whose C could not be loaded): a list does not write over it
        S.decompile = () => [500, { error: 'rz-ghidra broke' }];
        await go('0x140001490'); await quiet();
        r.message = { text: dec.textContent, lines: dec.querySelectorAll('.rizin-dec-line').length };
        S.breakpoints = [];
        await rizinLoadMarks(true); await quiet();
        r.messageAfter = { text: dec.textContent, lines: dec.querySelectorAll('.rizin-dec-line').length };
        r.shared = shared;
    """)
    assert "error" not in r, r.get("error")
    shared = r["shared"]
    assert r["start"] == {"current": [41], "top": 41 * 20 + 7, "on": []}, "the setup: the second of the two lines is the current one"
    top = 41 * 20 + 7
    assert r["set"]["on"] == [40, 41] and r["set"]["glyphs"] == ["●", "●"] and r["set"]["server"] == [shared] and r["set"]["cell"] == hex(shared), \
        "the mark is stale after a click: " + str(r["set"])
    assert r["set"]["redrawn"] is True, "the test does not draw the lines again, so it cannot tell a stale mark from a fresh one"
    assert r["unset"]["on"] == [] and r["unset"]["glyphs"] == ["", ""] and r["unset"]["server"] == [], "the mark is stale after the second click: " + str(r["unset"])
    for step in ("start", "set", "unset"):
        assert r["firstAtTop"][step]["top"] == 40 * 20 + 7 and r["firstAtTop"][step]["current"] == [41] and r["firstAtTop"][step]["decs"] == 0, \
            f"with the first of two lines that share an address at the top, a click in the gutter moved the view ({step}): " + str(r["firstAtTop"])
    assert r["firstAtTop"]["set"]["on"] == [40, 41] and r["firstAtTop"]["unset"]["on"] == []
    for step in ("set", "unset"):
        assert r[step]["top"] == top, f"a click in the gutter cost the scroll position ({step}): " + str(r[step])
        assert r[step]["current"] == [41], f"a click in the gutter moved the current line ({step}): " + str(r[step])
        assert r[step]["decs"] == 0, f"the C was asked for again after a click in the gutter ({step})"
    assert r["elsewhere"]["on"] == [10] and r["elsewhere"]["top"] == top and r["elsewhere"]["current"] == [41] and r["elsewhere"]["decs"] == 0, \
        "a list that changed elsewhere does not show, or cost the scroll position or the current line: " + str(r["elsewhere"])
    assert r["unrelated"]["on"] == [] and r["unrelated"]["top"] == top and r["unrelated"]["current"] == [41]
    assert r["hidden"]["on"] == [20] and r["hidden"]["top"] == top and r["hidden"]["current"] == [41], \
        "a list that changed while DECOMPILER was hidden was not there when it was shown: " + str(r["hidden"])
    assert r["message"]["lines"] == 0 and "could not be loaded" in r["message"]["text"], r["message"]
    assert r["messageAfter"] == r["message"], "a list wrote over the message the pane shows instead of lines: " + str(r["messageAfter"])


@needs_node
def test_rizin_decompiler_gutter_drops_a_click_while_a_request_is_out():
    # INTENT (Review Focus 4): one request at a time. While one is out (marks.busy) a click in any gutter of DECOMPILER is
    # dropped, not queued: one POST, and a click on another line's cell neither adds a breakpoint nor takes the first one
    # away; and the pointer says so IN THIS PANE (rizin-gutter-busy on #rizin-decompiler, as on #rizin-disasm), which is gone
    # again with the answer, so that a click after it is taken.
    r = _scripted(DEC_GUTTER_SETUP + r"""
        await showDecompiler();
        S.actDelay = 60;
        const f = calls.length;
        click(cell(2));
        r.out = { dec: dec.classList.contains('rizin-gutter-busy'), dis: dis.classList.contains('rizin-gutter-busy'), busy: rizinState.marks.busy };
        click(cell(2)); click(cell(3)); click(cell(7));
        r.dropped = { posts: sent(f).map(c => [c[0], c[2].addr]), on: on(), dec: dec.classList.contains('rizin-gutter-busy') };
        await until(() => on().length === 1, 'the answer'); await quiet();
        r.answered = { sent: sent(f).map(c => [c[0], c[2].addr]), on: on(), server: server(), dec: dec.classList.contains('rizin-gutter-busy'),
                       dis: dis.classList.contains('rizin-gutter-busy'), busy: rizinState.marks.busy };
        // The cue is gone, so a click is taken again
        S.actDelay = 1;
        click(cell(7));
        await until(() => on().length === 2, 'the next click'); await quiet();
        r.next = { on: on(), server: server() };
    """)
    assert "error" not in r, r.get("error")
    assert r["out"] == {"dec": True, "dis": True, "busy": True}, \
        "a click that is dropped while one request is out says nothing in this pane (no cue on DECOMPILER): " + str(r["out"])
    assert r["dropped"] == {"posts": [["POST", "0x1400014b9"]], "on": [], "dec": True}, \
        "a click while a request was out was taken (or queued): " + str(r["dropped"])
    assert r["answered"] == {"sent": [["POST", "0x1400014b9"]], "on": [2], "server": [0x1400014b9], "dec": False, "dis": False, "busy": False}, \
        "the cue stays after the answer, or the dropped clicks left something: " + str(r["answered"])
    assert r["next"] == {"on": [2, 7], "server": [0x1400014b9, 0x140001521]}


@needs_node
def test_rizin_decompiler_gutter_cell_shifts_nothing():
    # INTENT: the cell takes the same room whether the line has a mark or not, whether it has an address or not, and with no
    # `breakpoints` at all: without its cell (a gutter or an empty place, the first thing in each line) the markup of the lines
    # is the same with and without a breakpoint, so the C and the data-addr of a line stay where they are. A line whose address
    # no `0x…` can hold (a JSON number past 2^64) gets the empty place, not a cell that names `null`.
    r = _run(r"""
        const lines = [cline('int main(void)'), cline('{'), cline('    if (a) {', 0x1400015b9, 0x1400015bf), cline('        x();', 0x1400015c0),
                       cline('    y = <b>1</b>;', 1e30), cline('}')];
        const plain = rizinDecompilerHtml(lines, { current: '0x1400015c0', breakpoints: [] });
        const marked = rizinDecompilerHtml(lines, { current: '0x1400015c0', breakpoints: [0x1400015bf, 0x1400015c0] });
        const cellRe = /<span class="rizin-dec-(?:gutter|pad)[^"]*"[^>]*>[^<]*<\/span>/g;
        const bare = html => html.replace(cellRe, '<CELL>');
        console.log(JSON.stringify({
            plain, marked, bare: bare(plain), bareMarked: bare(marked),
            startsWithCell: (html => html.split('</div>').filter(Boolean).map(l => /^<div [^>]*><CELL>/.test(bare(l))))(plain),
            noOptions: [rizinDecompilerHtml(lines), rizinDecompilerHtml(lines, {})].map(h => [(h.match(/data-rizin-gutter/g) || []).length, (h.match(/ on"/g) || []).length]),
            nulls: /null|undefined|NaN/.test(plain + marked),
            cells: (plain.match(/data-rizin-gutter="[^"]*"/g) || []),
        }));
    """, SORT_DOM + _rizin_prelude() + r"""
        const cline = (text, ...addrs) => ({ text, offset: addrs.length ? addrs[0] : null, offsets: [...addrs].sort((a, b) => a - b) });
    """)
    assert r["plain"] != r["marked"], "the breakpoint is not in the markup, so the next assertion proves nothing"
    assert r["bare"] == r["bareMarked"], "a mark changes more than the cell: the C or the data-addr of a line moved"
    assert r["startsWithCell"] == [True] * 6, "a line does not start with a cell (a gutter or an empty place)"
    assert r["cells"] == ['data-rizin-gutter="0x1400015b9"', 'data-rizin-gutter="0x1400015c0"'], \
        "the line with an address a 0x… cannot hold has a cell, or another one does not"
    assert r["noOptions"] == [[2, 0], [2, 0]], "without options the cells are missing or a breakpoint is made up"
    assert r["nulls"] is False


def test_rizin_decompiler_gutter_looks_like_the_disassembly_gutter_in_both_themes():
    # INTENT: DECOMPILER's cell has the glyphs and colours of DISASSEMBLY's in both sheets (the layout sheet applies in both
    # themes and wins; style.css is the fallback, so the glyph is checked in each of them, not in style.css alone) (a faint ○ at rest, stronger under
    # the pointer, a red bold ● when set with the glow of Cyberpunk, and the busy pointer), and its empty place is as wide as
    # the cell, so that the C of a line starts on the same column with or without an address or a mark. A reviewer who takes
    # the resting rule from either sheet, or the busy pointer, fails here; so does a rule of the pseudo-element that takes room.
    classic, layout = _rules(STYLE_CSS), _rules(THEME_CSS)
    prefix = '[data-theme="cyberpunk"] '
    for rules, pre in ((classic, ""), (layout, prefix)):
        for rule in (".rizin-dec-gutter", ".rizin-dec-gutter.on", ".rizin-dec-gutter:not(.on)::before", ".rizin-dec-gutter:not(.on):hover::before",
                     ".rizin-gutter-busy .rizin-dec-gutter"):
            assert rules.get(pre + rule), f"{pre + rule} has no rule"
        # the same colours as the disassembly's cell, whatever they are
        for rule in (".rizin-gutter", ".rizin-gutter:not(.on)::before", ".rizin-gutter:not(.on):hover::before", ".rizin-gutter-busy .rizin-gutter"):
            twin = rule[:rule.rindex(".rizin-gutter")] + ".rizin-dec-gutter" + rule[rule.rindex(".rizin-gutter") + len(".rizin-gutter"):]
            for prop in ("color", "cursor", "content"):
                assert _declared(rules.get(pre + rule), prop) == _declared(rules.get(pre + twin), prop), f"{pre + twin} differs from {pre + rule} in {prop}"
        resting, pointed = rules[pre + ".rizin-dec-gutter:not(.on)::before"], rules[pre + ".rizin-dec-gutter:not(.on):hover::before"]
        assert _declared(resting, "color") == ("var(--cp-text-dim)" if pre else "var(--text-dim)")
        assert _declared(pointed, "color") == ("var(--cp-text-muted)" if pre else "var(--text-secondary)")
        assert _declared(rules[pre + ".rizin-gutter-busy .rizin-dec-gutter"], "cursor") == "progress"
        for prop in ("position", "width", "min-width", "margin", "padding", "font-size", "display", "float", "letter-spacing"):
            assert _declared(resting, prop) is None and _declared(pointed, prop) is None, f"the marker declares {prop}: the columns could shift"
    assert _declared(classic[".rizin-dec-gutter:not(.on)::before"], "content") == '"○"'
    # the layout sheet applies in both themes and wins over style.css: what it says about the glyph is what is drawn, in
    # this gutter as in the disassembly's (the twin comparison above reads both from the same rule, so it cannot tell)
    for rule in (".rizin-gutter:not(.on)::before", ".rizin-gutter:not(.on):hover::before",
                 ".rizin-dec-gutter:not(.on)::before", ".rizin-dec-gutter:not(.on):hover::before"):
        assert _declared(layout[prefix + rule], "content") in (None, '"○"'), f"theme-layout.css changes the glyph of {rule}"
    assert [g for g in _gutter_glyphs() if g[2] not in (None, '"○"')] == [], "a gutter's marker is blanked or is not the hollow ○"
    assert _declared(classic[".rizin-dec-gutter.on"], "font-weight") == "700" and _declared(classic[".rizin-dec-gutter"], "color") == "var(--accent-red)"
    assert _declared(layout[prefix + ".rizin-dec-gutter"], "color") == "var(--cp-red)" and "text-shadow" in layout[prefix + ".rizin-dec-gutter.on"]
    # nothing of a mark takes room: the cell and the empty place are one width, and neither is text to copy
    cell, pad = classic[".rizin-dec-gutter"], classic[".rizin-dec-pad"]
    assert _declared(cell, "display") == _declared(pad, "display") == "inline-block"
    assert _declared(cell, "width") == _declared(pad, "width") == _declared(classic[".rizin-gutter"], "width") == "2ch", \
        "the cell and the empty place are not one width, so the C of lines with and without an address would not line up"
    assert _declared(cell, "user-select") == _declared(pad, "user-select") == "none", "a copied line carries the marks"
    assert _declared(classic[".rizin-dec-gutter.on"], "width") is None and _declared(classic[".rizin-dec-gutter.on"], "padding") is None
    assert _declared(classic.get(".rizin-dec-pad"), "cursor") is None, "the empty place looks like something to click"
    assert ".rizin-dec-pad::before" not in classic and prefix + ".rizin-dec-pad::before" not in layout, "the empty place has a ○"
    html = _read(INDEX_HTML)
    assert "style.css?v=88" not in html and 'theme-layout.css?v=11"' not in html and "app.js?v=130" not in html, \
        "asset versions not raised for the gutter of DECOMPILER"


@needs_node
def test_rizin_menu_patches_an_instruction_and_runs_to_here():
    # INTENT: from the right-click menu of a line, NOP out, Flip the jump, Always jump and Kill the call each POST /patch with
    # the line's address (a string) and their kind and nothing else; Bytes… opens the menu's field, and Save posts the bytes
    # typed (white space dropped, lower case) at that address; Run to here posts /emulation/run {kind: "until", addr}. Each
    # patch needs no emulation (none is running when they are made), closes the menu and draws the views again
    # (DISASSEMBLY asked for again), and marks the line at once; Run to here moves the PC there, with the views. The
    # server refusing a patch keeps the menu open, with its reason, and marks nothing.
    from rizin_emulation import PATCH_KINDS
    r = _scripted(GUTTER_SETUP + r"""
        OPS['sym.watchdog'] = [...OPS['sym.watchdog'], op(0x1400014a1, 6, 'call dword [0x1400093a8]', 'ucall')];
        const patchWith = async (addr, action, where = 'sym.main') => {
            rightAt(addr);
            const f = calls.length, pages = count('GET', '/api/rizin/S1/disasm');
            click($(`rizin-menu-${action}`));
            await until(() => menu.hidden && count('GET', '/api/rizin/S1/disasm') > pages, action); await quiet();
            return { sent: sent(f), hidden: menu.hidden, patched: addrs(dis, '.rizin-op.patched'), glyph: line(addr).querySelector('.rz-pm').textContent,
                     disasm: count('GET', '/api/rizin/S1/disasm') - pages > 0, seeks: posts(f, '/seek').length };
        };
        r.noEmulation = rizinState.emu;
        r.nop = await patchWith('0x1400014b9', 'nop');
        r.flip = await patchWith('0x1400014bc', 'flip');
        r.always = await patchWith('0x1400014bc', 'always');
        r.nocall = await patchWith('0x1400014be', 'nocall');
        await rizinSeek('0x140001490', 'test'); await quiet();
        r.ircall = await patchWith('0x140001499', 'nocall');
        r.ucall = await patchWith('0x1400014a1', 'nocall');
        r.rows = S.patches.map(p => [p.addr, p.size, p.after]);
        // Bytes by hand
        await rizinSeek('0x1400014b7', 'test'); await quiet();
        rightAt('0x1400014b9');
        click($('rizin-menu-bytes'));
        r.form = { items: $('rizin-menu-items').hidden, form: $('rizin-menu-form').hidden, label: $('rizin-menu-label').textContent, value: input.value,
                   maxlength: input.hasAttribute('maxlength'), focused: document.activeElement === input };
        input.value = ' 90 90 EB 05 ';
        let f = calls.length;
        click($('rizin-menu-save'));
        await until(() => menu.hidden && S.patches.some(p => p.after === '9090eb05'), 'the bytes'); await quiet();
        r.bytes = { sent: sent(f), hidden: menu.hidden, patched: addrs(dis, '.rizin-op.patched') };
        // The server refuses: the menu stays, and says why
        S.patchAnswer = () => [400, { refused: 'rizin decoded no instruction at 0x1400014bd' }];
        rightAt('0x1400014b9');
        click($('rizin-menu-nop'));
        await until(() => $('rizin-menu-note').textContent.includes('no instruction'), 'the reason'); await quiet();
        r.refused = { hidden: menu.hidden, note: $('rizin-menu-note').textContent, items: $('rizin-menu-items').hidden, patches: S.patches.length,
                      inForm: $('rizin-menu-form').contains($('rizin-menu-note')) };
        S.patchAnswer = undefined;
        rizinCloseMenu();
        // Run to here, while the emulation runs
        await startAt('0x1400014b7');
        rightAt('0x140001521');
        f = calls.length;
        click($('rizin-menu-until'));
        await until(() => rizinState.emu.pc === '0x140001521' && !rizinState.emuWait, 'the run'); await quiet();
        r.until = { sent: sent(f).filter(c => c[1] !== '/seek'), hidden: menu.hidden, pc: rizinState.emu.pc, pcMarks: addrs(dis, '.rizin-op.pc'),
                    strip: $('rizin-run-pc').textContent, seek: rizinState.seek };
    """)
    assert "error" not in r, r.get("error")
    assert r["noEmulation"] is None, "the patches were made inside an emulation"
    assert PATCH_KINDS == ("nop", "flip", "always", "nocall")
    for name, addr, kind in (("nop", "0x1400014b9", "nop"), ("flip", "0x1400014bc", "flip"), ("always", "0x1400014bc", "always"),
                             ("nocall", "0x1400014be", "nocall"), ("ircall", "0x140001499", "nocall"), ("ucall", "0x1400014a1", "nocall")):
        got = r[name]
        assert got["sent"] == [["POST", "/patch", {"addr": addr, "kind": kind}]], f"{name}: one POST with the address and the kind, nothing else: {got['sent']}"
        assert got["hidden"] is True and got["disasm"] is True and got["seeks"] == 0, f"{name}: the menu stayed, or the views were not drawn again"
        assert addr in got["patched"] and got["glyph"] == "≠", f"{name}: the line is not marked"
    assert [row[0] for row in r["rows"]] == sorted(row[0] for row in r["rows"])
    assert {tuple(row[:2]) for row in r["rows"]} >= {(0x1400014b9, 3), (0x1400014bc, 2), (0x1400014be, 5), (0x140001499, 6), (0x1400014a1, 6)}, r["rows"]
    assert r["form"] == {"items": True, "form": False, "label": "Bytes to write at 0x1400014b9: hex digits, an even number, at most 2000 bytes (4000 digits)",
                         "value": "", "maxlength": False, "focused": True}, r["form"]
    assert r["bytes"]["sent"] == [["POST", "/patch", {"addr": "0x1400014b9", "bytes": "9090eb05"}]], r["bytes"]
    assert r["bytes"]["hidden"] is True and "0x1400014b9" in r["bytes"]["patched"]
    assert r["refused"]["hidden"] is False and "no instruction" in r["refused"]["note"] and r["refused"]["items"] is False, r["refused"]
    assert r["refused"]["inForm"] is False, "the reason is in the field's form, which is hidden while the entries show"
    assert r["refused"]["patches"] == len(r["rows"]) + 1, "a refused patch was kept (six kinds and the bytes by hand are the patches that were made)"
    assert r["until"]["sent"] == [["POST", "/emulation/run", {"kind": "until", "addr": "0x140001521"}]], r["until"]
    assert r["until"]["hidden"] is True and r["until"]["pc"] == "0x140001521" and r["until"]["pcMarks"] == ["0x140001521"], r["until"]
    assert "0x140001521" in r["until"]["strip"] and r["until"]["seek"] == "0x140001521"


@needs_node
def test_rizin_menu_patches_bytes_by_hand_say_their_limit():
    # INTENT: the field of Bytes… says its limit before anything is typed (at most MAX_PATCH_BYTES bytes, an even number of hex
    # digits), has no maxlength that cuts a paste off, and rejects what the server would refuse before it posts: an odd number
    # of digits, a value past the limit, anything that is no hex, nothing at all; exactly the limit goes out; a value the
    # field takes with spaces goes out without them. A rejected value keeps the menu open and keeps what was typed.
    from rizin_emulation import MAX_PATCH_BYTES
    r = _scripted(GUTTER_SETUP + r"""
        const MAX = MAX_JSON;
        const note = () => $('rizin-menu-note').textContent;
        const save = async value => {
            rightAt('0x1400014b9');
            click($('rizin-menu-bytes'));
            input.value = value;
            const f = calls.length;
            dispatch('keydown', input, { key: 'Enter' });
            await tick(30); await quiet();
            return { posts: posts(f, '/patch').map(c => [c[2].addr, c[2].bytes.length]), note: note(), open: !menu.hidden, kept: input.value === value };
        };
        r.limit = RIZIN_PATCH.maxBytes === MAX;
        r.empty = await save('   ');
        r.odd = await save('909');
        r.oddLong = await save('9'.repeat(2 * MAX + 1));
        r.long = await save('90'.repeat(MAX + 1));
        r.huge = await save('90'.repeat(500000));
        r.nothex = await save('90zz');
        r.prefix = await save('0x9090');
        r.exact = await save('90 '.repeat(MAX));
        r.one = await save('c3');
        rizinCloseMenu();
        // Esc closes the field without sending
        rightAt('0x1400014b9'); click($('rizin-menu-bytes')); input.value = '9090';
        const f = calls.length;
        const esc = dispatch('keydown', input, { key: 'Escape' });
        r.escape = [menu.hidden, esc.stopped, posts(f, '/patch').length];
        // Rename and Comment keep their own limits and the field has no placeholder of the bytes
        rightAt('0x1400014b9'); click($('rizin-menu-comment'));
        r.comment = [input.getAttribute('maxlength'), input.hasAttribute('placeholder')];
        rizinCloseMenu();
        rightAt('0x1400014b9'); click($('rizin-menu-bytes'));
        r.placeholder = input.getAttribute('placeholder');
    """.replace("MAX_JSON", str(MAX_PATCH_BYTES)))
    assert "error" not in r, r.get("error")
    assert r["limit"] is True, "the limit of the field is not the server's MAX_PATCH_BYTES"
    for name in ("empty", "odd", "oddLong", "long", "huge", "nothex", "prefix"):
        got = r[name]
        assert got["posts"] == [] and got["open"] is True and got["kept"] is True and got["note"], f"{name} was sent, or closed the menu, or lost what was typed: {got}"
    assert "Type the bytes" in r["empty"]["note"]
    assert "odd" in r["odd"]["note"] and "3 hex digits" in r["odd"]["note"], r["odd"]["note"]
    assert "2000 bytes" in r["long"]["note"] and "That is 2001 bytes" in r["long"]["note"], "a value past the limit does not name the limit: " + r["long"]["note"]
    assert "2001 bytes" in r["oddLong"]["note"] and "500000 bytes" in r["huge"]["note"] and "2000 bytes" in r["huge"]["note"], \
        "a value of an odd number of digits past the limit was told it was odd, or the limit was not named"
    assert "hex digits 0-9" in r["nothex"]["note"] and "hex digits 0-9" in r["prefix"]["note"]
    assert r["exact"]["posts"] == [["0x1400014b9", 2 * MAX_PATCH_BYTES]] and r["exact"]["open"] is False, "exactly the limit was not sent: " + str(r["exact"])
    assert r["one"]["posts"] == [["0x1400014b9", 2]] and r["one"]["open"] is False
    assert r["escape"] == [True, True, 0]
    assert r["comment"] == ["500", False], "the comment's own field limit or placeholder changed"
    assert r["placeholder"] == "90 90 eb 05"


@needs_node
def test_rizin_patched_instruction_is_marked_in_the_disassembly():
    # INTENT: a line that a patch by hand overlaps is marked the moment the patch is made, from the answer: a ≠ in the cell
    # left of the address (a glyph and a wavy underline of the mnemonic, so no colour alone) and the patched class on the
    # line; every instruction the bytes cover is marked, not only the first, and the neighbours are not. A write that
    # a run made (mine: false) marks nothing: the lines show what was set by hand. The mark goes when the patch is taken
    # back, comes back with the file when it is opened again (the patches are kept in the project), and is of that file only.
    r = _scripted(GUTTER_SETUP + r"""
        const marks = () => addrs(dis, '.rizin-op.patched');
        r.none = [marks(), dis.querySelectorAll('.rz-pm').map(e => e.textContent).join(''), dis.querySelectorAll('.rz-pm.on').length];
        // 8 bytes over three instructions: the cmp, the jle and the first byte of the call
        rightAt('0x1400014b9'); click($('rizin-menu-bytes'));
        input.value = '9090909090909090';
        click($('rizin-menu-save'));
        await until(() => marks().length, 'the marks'); await quiet();
        r.bytes = { marked: marks(), cells: dis.querySelectorAll('.rz-pm.on').map(e => e.closest('.rizin-op').getAttribute('data-addr')),
                    glyph: line('0x1400014bc').querySelector('.rz-pm').textContent, title: line('0x1400014bc').querySelector('.rz-pm').getAttribute('title'),
                    text: text(line('0x1400014bc')).slice(0, 12), unmarked: text(line('0x1400014b7')).slice(0, 12), state: JSON.stringify(rizinState.marks.patched) };
        // What a run wrote is not a patch by hand: no mark
        S.patches.push({ addr: 0x140001521, size: 1, before: '00', after: '41', mine: false });
        await rizinLoadMarks(true); await quiet();
        r.run = marks();
        // A patch taken back in the pane: the lines are unmarked
        click(tab('emulation'));
        await until(() => rizinState.views.dock === 'emulation' && $('rizin-emulation').querySelector('[data-rizin-section]'), 'the pane'); await quiet();
        click($('rizin-emulation').querySelector('.rizin-emu-patch [data-rizin-act="unpatch"]'));
        await until(() => !marks().length, 'unmarked'); await quiet();
        r.taken = marks();
        // The file again: the patches the project kept are marked when it opens
        const T = { analysis: 'done', done: ['aaa'], patches: [{ addr: 0x1400014bc, size: 2, before: '7e05', after: '7505', mine: true }] };
        serve('S2', T);
        opens['C:\\x\\f.exe'] = T;
        await openInRizin('C:\\x\\f.exe');
        await until(() => rizinState.landed && rizinState.session === 'S2', 'the other file'); await quiet();
        await rizinSeek('0x1400014b7', 'test'); await quiet();
        r.restored = marks();
        const U = { analysis: 'done', done: ['aaa'] };
        serve('S3', U);
        opens['C:\\x\\g.exe'] = U;
        await openInRizin('C:\\x\\g.exe');
        await until(() => rizinState.landed && rizinState.session === 'S3', 'the third file'); await quiet();
        await rizinSeek('0x1400014b7', 'test'); await quiet();
        r.other = marks();
        // The markup alone: a patch that ends where the line starts does not overlap it
        const host = document.createElement('div');
        host.innerHTML = rizinDisasmHtml([op(0x10, 2, 'nop', 'nop'), op(0x12, 2, 'nop', 'nop'), op(0x14, 2, 'nop', 'nop')], { patched: [[0x11, 2]] });
        r.edges = addrs(host, '.rizin-op.patched');
    """)
    assert "error" not in r, r.get("error")
    assert r["none"] == [[], "", 0], "a line is marked as patched before any patch: " + str(r["none"])
    assert r["bytes"]["marked"] == ["0x1400014b9", "0x1400014bc", "0x1400014be"], \
        "every instruction the bytes cover is marked, and no other: " + str(r["bytes"])
    assert r["bytes"]["cells"] == r["bytes"]["marked"] and r["bytes"]["glyph"] == "≠" and r["bytes"]["title"] == "Patched by hand: these bytes were written here"
    assert r["bytes"]["text"].startswith("≠") and not r["bytes"]["unmarked"].startswith("≠"), "the mark is not text of the line's own cell"
    assert r["bytes"]["state"] == "[[5305,8]]".replace("5305", str(0x1400014b9)), r["bytes"]["state"]
    assert r["run"] == r["bytes"]["marked"], "a write of a run was marked as a patch"
    assert r["taken"] == [], "a patch taken back left its mark"
    assert r["restored"] == ["0x1400014bc"], "the patches the file already has were not marked: " + str(r["restored"])
    assert r["other"] == [], "the marks of the file before are on the one open now"
    assert r["edges"] == ["0x10", "0x12"], "a patch's range is not half-open: " + str(r["edges"])
    classic = _rules(STYLE_CSS)
    assert "underline" in (_declared(classic.get(".rizin-op.patched .rz-mnem"), "text-decoration") or ""), "the patched line is a colour and a glyph only"


@needs_node
def test_rizin_menu_patch_entries_follow_the_instruction_type():
    # INTENT: NOP out and Bytes… are on every line of the disassembly; Flip the jump and Always jump only on a cjmp (the one type
    # the server flips); Kill the call on every type rizin_emulation.is_call takes (it ends with "call": call, ucall, rcall,
    # ircall, icall, ccall: not only "call", for `call qword [import]` is an ircall and `call dword [slot]` a ucall, the
    # import calls that are knocked out to bypass an anti-VM check). The entries that do not apply are hidden, not on and
    # refused. The same decision for every type, from the one function that decides it. On a function of the list or a block
    # of the graph there are no patch entries at all, nor a separator.
    from rizin_emulation import is_call
    types = ["call", "ucall", "rcall", "ircall", "icall", "ccall", "cjmp", "ucjmp", "jmp", "ujmp", "mov", "ret", "invalid", "", "calling", "cmp"]
    r = _scripted(GUTTER_SETUP + r"""
        r.kinds = Object.fromEntries(TYPES.map(t => [t, rizinPatchKinds(t)]));
        r.odd = [rizinPatchKinds(undefined), rizinPatchKinds(null), rizinPatchKinds(7)];
        OPS['sym.watchdog'] = [...OPS['sym.watchdog'], op(0x1400014a1, 6, 'call dword [0x1400093a8]', 'ucall')];
        const menuAt = async (fn, addr) => { await rizinSeek(fn, 'test'); await quiet(); rightAt(addr); return shown(); };
        r.main = {
            cmp: await menuAt('0x1400014b7', '0x1400014b9'), cjmp: await menuAt('0x1400014b7', '0x1400014bc'),
            call: await menuAt('0x1400014b7', '0x1400014be'), ret: await menuAt('0x1400014b7', '0x140001529'),
            ircall: await menuAt('0x140001490', '0x140001499'), ucall: await menuAt('0x140001490', '0x1400014a1'),
            jmp: await menuAt('0x140001490', '0x14000149f'),
        };
        r.enabled = off();
        r.separator = !$('rizin-menu-sep').hidden;
        rizinCloseMenu();
        // A function of the list and a block of the graph: Rename and Comment only
        right(document.querySelector('#rizin-fn-list .rizin-fn'));
        r.list = { shown: shown(), separator: !$('rizin-menu-sep').hidden, note: $('rizin-menu-note').textContent };
        rizinCloseMenu();
        right($('rizin-graph').querySelector('.rizin-block rect'));
        r.graph = { shown: shown(), separator: !$('rizin-menu-sep').hidden };
        rizinCloseMenu();
        // The menu opened for another line shows what that line takes, not what the one before did
        r.after = { cjmp: await menuAt('0x1400014b7', '0x1400014bc'), mov: await menuAt('0x1400014b7', '0x1400014b9') };
    """.replace("TYPES", json.dumps(types)))
    assert "error" not in r, r.get("error")
    expected = {t: ["nop"] + (["flip", "always"] if t == "cjmp" else []) + (["nocall"] if is_call(t) else []) for t in types}
    assert r["kinds"] == expected, "the menu and rizin_emulation disagree on which kind applies to which type: " + str(r["kinds"])
    assert r["odd"] == [["nop"]] * 3
    always = ["rename", "comment"]
    assert r["main"]["cmp"] == always + ["nop", "bytes"] and r["main"]["ret"] == always + ["nop", "bytes"]
    assert r["main"]["cjmp"] == always + ["nop", "flip", "always", "bytes"], r["main"]["cjmp"]
    assert r["main"]["call"] == always + ["nop", "nocall", "bytes"]
    assert r["main"]["ircall"] == always + ["nop", "nocall", "bytes"], "Kill the call is not offered on `call qword [import]` (an ircall): " + str(r["main"]["ircall"])
    assert r["main"]["ucall"] == always + ["nop", "nocall", "bytes"], "Kill the call is not offered on `call dword [slot]` (a ucall)"
    assert r["main"]["jmp"] == always + ["nop", "bytes"], "an unconditional jump is offered Flip or Always"
    assert r["enabled"] == [] and r["separator"] is True, "an entry that applies is off, on an x86 file"
    assert r["list"] == {"shown": always, "separator": False, "note": ""} and r["graph"] == {"shown": always, "separator": False}
    assert r["after"] == {"cjmp": always + ["nop", "flip", "always", "bytes"], "mov": always + ["nop", "bytes"]}


@needs_node
def test_rizin_menu_patch_entries_are_off_with_a_reason_outside_x86():
    # INTENT (R64): where the file is not x86 (the server's patch_op refuses all four kinds there: 0x90 is a nop on x86 and nowhere
    # else) the four entries are shown off, not hidden, with the reason in the menu itself and on each entry, and a click on one
    # sends nothing; Bytes… stays on, and goes out. An x86 file has them on and no reason; a file whose arch rizin did not name is
    # treated as not x86 and says so.
    r = _scripted(GUTTER_SETUP + r"""
        const T = { analysis: 'done', done: ['aaa'], arch: 'arm' };
        serve('S2', T);
        opens['C:\\x\\arm.exe'] = T;
        r.x86 = { off: (rightAt('0x1400014bc'), off()), note: $('rizin-menu-note').textContent };
        rizinCloseMenu();
        await openInRizin('C:\\x\\arm.exe');
        await until(() => rizinState.landed && rizinState.session === 'S2', 'the arm file'); await quiet();
        await rizinSeek('0x1400014b7', 'test'); await quiet();
        rightAt('0x1400014bc');
        r.arm = { shown: shown(), off: off(), note: $('rizin-menu-note').textContent, title: $('rizin-menu-flip').title,
                  hint: $('rizin-menu-note').classList.contains('rizin-menu-hint'), bytes: $('rizin-menu-bytes').disabled === true };
        const f = calls.length;
        click($('rizin-menu-nop')); click($('rizin-menu-flip'));
        await tick(30);
        r.clicked = { sent: sent(f).length, open: !menu.hidden };
        click($('rizin-menu-bytes'));
        input.value = '9090';
        click($('rizin-menu-save'));
        await until(() => menu.hidden && T.patches && T.patches.length, 'the bytes'); await quiet();
        r.bytes = { sent: sent(f), marked: addrs(dis, '.rizin-op.patched') };
        rizinState.file.arch = null;
        rightAt('0x1400014bc');
        r.unnamed = { off: off(), note: $('rizin-menu-note').textContent };
        rizinCloseMenu();
        rizinState.file.arch = 'x86';
        rightAt('0x1400014bc');
        r.back = { off: off(), note: $('rizin-menu-note').textContent, hint: $('rizin-menu-note').classList.contains('rizin-menu-hint') };
        // An action's note replaces the reason, and the next menu starts with its own
        click($('rizin-menu-rename'));
        r.form = $('rizin-menu-note').textContent;
    """)
    assert "error" not in r, r.get("error")
    assert r["x86"] == {"off": [], "note": ""}
    four = ["nop", "flip", "always"]
    assert r["arm"]["shown"] == ["rename", "comment", "nop", "flip", "always", "bytes"] and r["arm"]["off"] == four, \
        "the entries are not shown off on an arm file: " + str(r["arm"])
    assert r["arm"]["note"] == "The patch buttons write x86 bytes, and this file is arm: use Bytes… to write the bytes by hand.", r["arm"]["note"]
    assert r["arm"]["title"] == r["arm"]["note"] and r["arm"]["hint"] is True and r["arm"]["bytes"] is False
    assert r["clicked"] == {"sent": 0, "open": True}, "an entry that is off sent a request, or closed the menu"
    assert r["bytes"]["sent"] == [["POST", "/api/rizin/S2/patch", {"addr": "0x1400014bc", "bytes": "9090"}]] \
        and r["bytes"]["marked"] == ["0x1400014bc"], r["bytes"]
    assert r["unnamed"]["off"] == four and "of an arch rizin did not name" in r["unnamed"]["note"], r["unnamed"]
    assert r["back"] == {"off": [], "note": "", "hint": False}
    assert r["form"] == "", "the reason stayed under the field"


@needs_node
def test_rizin_menu_patch_entries_run_to_here_only_while_the_emulation_runs():
    # INTENT (R65): Run to here is not in the menu until the emulation runs (kind "until" needs one), is there while it does
    # and then only on a line of the disassembly, is off while a run is in flight, and is gone again after STOP; the patch
    # entries are there all the time. A run to an address a breakpoint comes before stops there, and says so.
    r = _scripted(GUTTER_SETUP + r"""
        rightAt('0x140001521');
        r.before = shown();
        rizinCloseMenu();
        await startAt('0x1400014b7');
        rightAt('0x140001521');
        r.running = { shown: shown(), off: off() };
        rizinCloseMenu();
        right(document.querySelector('#rizin-fn-list .rizin-fn'));
        r.list = shown();
        rizinCloseMenu();
        rizinState.emuWait = 'cont';
        rightAt('0x140001521');
        r.inFlight = { shown: shown(), off: off(), title: $('rizin-menu-until').title };
        const f = calls.length;
        click($('rizin-menu-until'));
        await tick(30);
        r.refused = { sent: sent(f).length, open: !menu.hidden };
        rizinState.emuWait = '';
        rizinCloseMenu();
        // A breakpoint on the way: the run stops there, and says so
        S.stopWith = 'breakpoint';
        S.emuRun = (body, s) => { s.emu.pc = 0x1400014be; s.emu.changed = ['rip']; return [200, emuRead(s.emu, 'breakpoint')]; };
        rightAt('0x140001521');
        click($('rizin-menu-until'));
        await until(() => rizinState.emu.stopped === 'breakpoint' && !rizinState.emuWait, 'the stop'); await quiet();
        r.stopped = { pc: rizinState.emu.pc, why: $('rizin-run-why').textContent };
        click(act('stop'));
        await until(() => strip.hidden, 'STOP'); await quiet();
        rightAt('0x140001521');
        r.after = shown();
    """)
    assert "error" not in r, r.get("error")
    before = ["rename", "comment", "nop", "bytes"]
    assert r["before"] == before, "Run to here is offered with no emulation, or a patch entry is missing: " + str(r["before"])
    assert r["running"] == {"shown": before + ["until"], "off": []}, r["running"]
    assert r["list"] == ["rename", "comment"], "Run to here on a function of the list"
    assert r["inFlight"]["shown"] == before + ["until"] and r["inFlight"]["off"] == ["until"] and "in flight" in r["inFlight"]["title"], r["inFlight"]
    assert r["refused"] == {"sent": 0, "open": True}
    assert r["stopped"]["pc"] == "0x1400014be" and "breakpoint" in r["stopped"]["why"].lower(), r["stopped"]
    assert r["after"] == before, "Run to here stayed in the menu after STOP"


def test_rizin_menu_and_gutter_styles_and_assets():
    """The menu's new parts and the gutter have a rule in each theme, hidden entries and the separator are not shown, the
    patch cell and the gutter keep the code in line (one width each, however many lines carry a mark) and the asset versions
    are raised. The menu's own tests ran with the old markup: the entries are in the order the menu shows them."""
    tab = _tab_markup("rizin")
    assert re.findall(r'<button[^>]*id="rizin-menu-(\w+)"[^>]*data-action="(\w+)"', tab) == [
        ("rename", "rename"), ("comment", "comment"), ("nop", "nop"), ("flip", "flip"), ("always", "always"),
        ("nocall", "nocall"), ("bytes", "bytes"), ("until", "until"), ("save", "save")], "the menu's entries, ids and actions"
    assert re.findall(r'<button[^>]*id="rizin-menu-(\w+)"[^>]*data-action="\w+"[^>]*>([^<]+)<', tab)[2:8] == [
        ("nop", "NOP out"), ("flip", "Flip the jump"), ("always", "Always jump"), ("nocall", "Kill the call"),
        ("bytes", "Bytes…"), ("until", "Run to here")]
    for name in ("nop", "flip", "always", "nocall", "bytes", "until"):
        assert re.search(r'id="rizin-menu-%s"[^>]*\shidden[\s>]' % name, tab), f"{name} is shown before the menu has decided"
    classic, cyberpunk = _rules(STYLE_CSS), _rules(THEME_CSS)
    prefix = '[data-theme="cyberpunk"] '
    for selector in (".rizin-gutter", ".rizin-gutter.on", ".rz-pm", ".rizin-op.patched .rz-mnem", ".rizin-menu-sep", ".rizin-menu-note.rizin-menu-hint"):
        assert selector in classic and prefix + selector in cyberpunk, f"{selector} has no rule in one theme"
    assert _declared(classic.get(".rizin-menu-item[hidden]"), "display") == "none" and _declared(classic.get(".rizin-menu-sep[hidden]"), "display") == "none", \
        "a hidden entry is shown (the button's own display wins over the attribute)"
    for path in (STYLE_CSS, THEME_CSS):
        rules = {s: b for s, b in _rules(path).items() if re.search(r"rizin-gutter|rz-pm|rizin-menu-sep|rizin-menu-hint|patched", s)}
        written = [f"{s}: {m.group(0)}" for s, b in rules.items() for m in LITERAL_COLOR.finditer(b)]
        assert rules and not written, f"colours written out in {path}:\n" + "\n".join(written)
    html = _read(INDEX_HTML)
    assert "style.css?v=85" not in html and 'theme-layout.css?v=8"' not in html and "app.js?v=125" not in html, \
        "asset versions not raised for the gutter and the patch menu"


@needs_node
def test_rizin_gutter_marks_take_the_newest_list_and_only_where_a_line_starts():
    # INTENT: a list that was asked for earlier and answers later never replaces a newer one (marks, and the EMULATION pane's
    # rows, which a patch's answer also brings); the list of another file that answers late marks nothing in the file open
    # now; the lists the pane read mark the lines too (a change made in the console shows once the pane has read it); a
    # breakpoint inside an instruction marks no line (a run stops at an instruction's start only); and the kinds of patch
    # the menu knows are the server's PATCH_KINDS.
    from rizin_emulation import PATCH_KINDS
    r = _scripted(GUTTER_SETUP + r"""
        r.kinds = RIZIN_PATCH.kinds;
        // A slow older list and a fast newer one: the newer stays
        S.breakpoints = [{ addr: 0x1400014b7, enabled: true }];
        S.listDelay = 100;
        const slow = rizinLoadMarks(true);
        await tick(10);
        S.breakpoints = [{ addr: 0x1400014bc, enabled: true }];
        S.listDelay = 1;
        await rizinLoadMarks(true);
        await slow; await quiet();
        r.newest = addrs(dis, '.rizin-op.bp');
        // The list of a file left, answering after another one opened
        const T = { analysis: 'done', done: ['aaa'], breakpoints: [{ addr: 0x1400014b9, enabled: true }] };
        serve('S2', T);
        opens['C:\\x\\f.exe'] = T;
        await openInRizin('C:\\x\\f.exe');
        await until(() => rizinState.landed && rizinState.session === 'S2', 'the other file'); await quiet();
        T.breakpoints = [{ addr: 0x1400014be, enabled: true }];
        T.listDelay = 100;
        const late = rizinLoadMarks(true);
        await tick(10);
        const U = { analysis: 'done', done: ['aaa'], breakpoints: [] };
        serve('S3', U);
        opens['C:\\x\\g.exe'] = U;
        await openInRizin('C:\\x\\g.exe');
        await until(() => rizinState.landed && rizinState.session === 'S3', 'the third file'); await late; await tick(50); await quiet();
        await rizinSeek('0x1400014b7', 'test'); await quiet();
        r.other = { bp: addrs(dis, '.rizin-op.bp'), marks: rizinState.marks.breakpoints };
        // What the pane reads marks the lines; a breakpoint inside an instruction (0x1400014bd is in the jle) marks none
        U.breakpoints = [{ addr: 0x1400014bd, enabled: true }, { addr: 0x1400014be, enabled: true }];
        U.patches = [{ addr: 0x1400014b9, size: 1, before: '83', after: '90', mine: true }];
        r.silent = [addrs(dis, '.rizin-op.bp'), addrs(dis, '.rizin-op.patched')];
        click(tab('emulation'));
        await until(() => rizinState.views.dock === 'emulation' && $('rizin-emulation').querySelector('[data-rizin-section]'), 'the pane'); await quiet();
        r.read = { bp: addrs(dis, '.rizin-op.bp'), patched: addrs(dis, '.rizin-op.patched'), marks: rizinState.marks.breakpoints };
        // A patch's answer and a pane list that is still on its way: the answer is the newer
        U.listDelay = 100;
        const old = rizinLoadEmuPane(true);
        await tick(10);
        rizinSetLists({ patches: [{ addr: 0x1400014bc, size: 2, before: '7e05', after: '9090', mine: true }] });
        const rowsNow = () => addrs($('rizin-emulation'), '.rizin-emu-patch');
        r.answer = rowsNow();
        await old; await tick(20);
        r.afterOld = [rowsNow(), addrs(dis, '.rizin-op.patched')];
    """)
    assert "error" not in r, r.get("error")
    assert r["kinds"] == list(PATCH_KINDS), "the menu's kinds are not the server's PATCH_KINDS"
    assert r["newest"] == ["0x1400014bc"], "an older list that answered late replaced the newer one: " + str(r["newest"])
    assert r["other"] == {"bp": [], "marks": []}, "the late list of the file before marked the file open now: " + str(r["other"])
    assert r["silent"] == [[], []]
    assert r["read"] == {"bp": ["0x1400014be"], "patched": ["0x1400014b9"], "marks": [0x1400014bd, 0x1400014be]}, \
        "the lists the pane read did not mark the lines, or a breakpoint inside an instruction marked it: " + str(r["read"])
    assert r["answer"] == ["0x1400014bc"] and r["afterOld"] == [["0x1400014bc"], ["0x1400014bc"]], \
        "a pane list that was asked for before a patch's answer replaced it: " + str(r["afterOld"])


@needs_node
def test_rizin_gutter_marks_survive_a_slow_read_and_the_reads_are_not_doubled():
    # INTENT (fix round 1): a read of both lists that was asked for first and answers last never erases a newer list. Through the
    # production path (the poll's forced reload of every view, with the lists slow) and then a click in the gutter, and with the
    # EMULATION pane open and a patch's answer: the gutter, the marks and the pane's rows all still match the server once the
    # old read answers, and a second click removes what the first set. A read that was asked for for both lists keeps the one
    # that was not replaced (the breakpoints of the first read stay when only the patches had a newer answer). And what a
    # forced reload, taking a patch back and landing cost in requests (R66): the marks read the lists once, and not at all
    # for a reload that the open pane makes already.
    r = _scripted(GUTTER_SETUP + r"""
        const lists = f => [gets(f, '/patches').length, gets(f, '/breakpoints').length];
        // Pane closed, forced reload with slow lists, a click while it is out
        S.listDelay = 120;
        let f = calls.length;
        const reload = rizinReloadViews();
        await tick(15);
        S.listDelay = 1;
        click(gutter('0x1400014be'));
        await until(() => line('0x1400014be').classList.contains('bp'), 'the breakpoint'); r.set = addrs(dis, '.rizin-op.bp');
        await reload; await quiet();
        r.afterStale = { marked: addrs(dis, '.rizin-op.bp'), state: JSON.stringify(rizinState.marks.breakpoints), server: S.breakpoints.map(b => b.addr) };
        click(gutter('0x1400014be'));
        await quiet();
        r.second = { sent: sent(calls.length - 1).map(c => c[0]), marked: addrs(dis, '.rizin-op.bp'), server: S.breakpoints.length };
        r.reload = lists(f);
        // A patch's answer against a read that is out: the patches are the answer's, the breakpoints the read's
        S.breakpoints = [{ addr: 0x1400014b7, enabled: true }];
        S.listDelay = 120;
        const read = rizinLoadMarks(true);
        await tick(15);
        S.listDelay = 1;
        await rizinPatchBytes('0x1400014b9', '9090');
        await read; await quiet();
        r.mixed = { bp: addrs(dis, '.rizin-op.bp'), patched: addrs(dis, '.rizin-op.patched') };
        // The pane open: a read of the marks that is out against a patch's answer: the pane's rows are the answer's
        click(tab('emulation'));
        await until(() => rizinState.views.dock === 'emulation' && $('rizin-emulation').querySelector('[data-rizin-section]'), 'the pane'); await quiet();
        const rowsNow = () => addrs($('rizin-emulation'), '.rizin-emu-patch');
        S.listDelay = 120;
        const stale = rizinLoadMarks(true);
        await tick(15);
        S.listDelay = 1;
        await rizinPatchBytes('0x1400014bc', '9090');
        r.rightAfter = { gutter: addrs(dis, '.rizin-op.patched'), pane: rowsNow() };
        await stale; await quiet();
        r.afterStalePane = { gutter: addrs(dis, '.rizin-op.patched'), pane: rowsNow(), server: S.patches.map(p => p.addr) };
        // Pane open: a forced reload reads each list once (the pane's), and taking a patch back none after its DELETE
        f = calls.length;
        await rizinReloadViews(); await quiet();
        r.reloadOpen = lists(f);
        f = calls.length;
        click($('rizin-emulation').querySelector('.rizin-emu-patch [data-rizin-act="unpatch"]'));
        await until(() => calls.slice(f).some(c => c[0] === 'DELETE'), 'the DELETE'); await quiet();
        r.takeBack = lists(f);
        click(tab('console'));
        await quiet();
        // The same take-back with the pane away (a call, not its button): no read of the marks after the answer either
        f = calls.length;
        await rizinUnpatch('0x1400014b9'); await quiet();
        r.takeBackHidden = lists(f);
        // Landing, pane closed: one read of each
        const T = { analysis: 'done', done: ['aaa'], breakpoints: [{ addr: 0x1400014bc, enabled: true }] };
        serve('S2', T);
        opens['C:\\x\\f.exe'] = T;
        f = calls.length;
        await openInRizin('C:\\x\\f.exe');
        await until(() => rizinState.landed && rizinState.session === 'S2', 'the other file'); await quiet();
        r.landing = lists(f);
    """)
    assert "error" not in r, r.get("error")
    assert r["set"] == ["0x1400014be"]
    assert r["afterStale"] == {"marked": ["0x1400014be"], "state": "[%d]" % 0x1400014be, "server": [0x1400014be]}, \
        "a read asked for before the click erased the breakpoint the click set: " + str(r["afterStale"])
    assert r["second"] == {"sent": ["DELETE"], "marked": [], "server": 0}, "the breakpoint could not be removed from the gutter: " + str(r["second"])
    assert r["mixed"]["bp"] == ["0x1400014b7"] and r["mixed"]["patched"] == ["0x1400014b9"], \
        "a read replaced the patches' newer answer, or dropped its own breakpoints: " + str(r["mixed"])
    assert r["rightAfter"] == {"gutter": ["0x1400014b9", "0x1400014bc"], "pane": ["0x1400014b9", "0x1400014bc"]}, r["rightAfter"]
    assert r["afterStalePane"] == {"gutter": ["0x1400014b9", "0x1400014bc"], "pane": ["0x1400014b9", "0x1400014bc"],
                                   "server": [0x1400014b9, 0x1400014bc]}, \
        "an old read wiped a patch from the gutter and from the pane's list of what is the user's: " + str(r["afterStalePane"])
    assert r["reload"] == [1, 1], "a forced reload with the pane closed reads each list once: " + str(r["reload"])
    assert r["reloadOpen"] == [1, 1], "a forced reload with the pane open reads each list more than once (the pane's and the marks'): " + str(r["reloadOpen"])
    assert r["takeBack"] == [0, 0], "taking a patch back read the lists again after its answer carried them: " + str(r["takeBack"])
    assert r["takeBackHidden"] == [0, 0], "a take-back with the pane closed read the marks' lists again: " + str(r["takeBackHidden"])
    assert r["landing"] == [1, 1], "landing reads each list once: " + str(r["landing"])


@needs_node
def test_rizin_menu_patches_once_and_only_into_the_file_that_asked():
    # INTENT (fix round 1): two clicks on one entry before the answer are one POST (not two identical rows in the write cache);
    # the answer of a patch that comes after another file was opened marks nothing in that one and leaves its lists
    # unread-for-now (null), not set to the other file's.
    r = _scripted(GUTTER_SETUP + r"""
        S.actDelay = 60;
        rightAt('0x1400014b9');
        const f = calls.length;
        click($('rizin-menu-nop')); click($('rizin-menu-nop'));
        await until(() => menu.hidden, 'the patch'); await quiet();
        r.twice = { posts: posts(f, '/patch').length, rows: S.patches.length, marked: addrs(dis, '.rizin-op.patched') };
        S.actDelay = 1;
        // A patch whose answer comes after another file was opened
        S.actDelay = 80;
        const late = rizinPatchBytes('0x1400014bc', '9090');
        await tick(10);
        const T = { analysis: 'done', done: ['aaa'], listDelay: 400 };
        serve('S2', T);
        opens['C:\\x\\f.exe'] = T;
        const opening = openInRizin('C:\\x\\f.exe');
        await until(() => rizinState.session === 'S2', 'the other file');
        await late; await tick(30);
        r.late = { marks: JSON.stringify(rizinState.marks.patched), rows: addrs(dis, '.rizin-op.patched') };
        await opening; await quiet();
    """)
    assert "error" not in r, r.get("error")
    assert r["twice"] == {"posts": 1, "rows": 1, "marked": ["0x1400014b9"]}, "two clicks on one entry patched twice: " + str(r["twice"])
    assert r["late"] == {"marks": "null", "rows": []}, "a patch's late answer marked the lines of the file open now: " + str(r["late"])


def test_rizin_help_and_the_pane_name_the_toolbars_button_and_the_assets_are_raised():
    """Task 14: the pane said START in a toolbar whose button says EMULATE, and the in-tab help told the reader the file
    "is only read" while the tab runs code. Both are corrected, and the asset version moved with them."""
    html = _read(INDEX_HTML)
    assert "app.js?v=128" not in html, "the help of index.html changed again (the project sentence, the 4094 cut), its version did not"
    assert "app.js?v=127" not in html, "app.js and the help changed (the pane's words, the emulation's help), its version did not"
    help_text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html))
    for words in ("never writes the file", "EMULATE runs the code in rizin's ESIL emulator", "ESIL does not emulate the Windows API",
                  "There is no step back", "STOP leaves the emulation instead of aborting a running command",
                  "at most 2000 bytes (4000 digits)", "4 KB of slack", "To the Submit tab", "nothing is submitted until you press Detonate there"):
        assert words in help_text, f"the in-tab help does not say {words!r}"
    assert "START in the toolbar" not in _read(os.path.join(ROOT, "webui", "static", "js", "app.js"))
