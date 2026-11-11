/**
 * Detonation Chamber - Unified Web UI
 * Frontend logic for the tracing/analysis interface
 */

// --- Toast Notification System ---
const _toastThrottle = {}; // track last toast time by title to avoid spam
function showToast(type, title, detail, duration) {
    // type: 'success' | 'error' | 'warning' | 'info'
    // Throttle: suppress duplicate toasts within 15s
    const key = type + ':' + title;
    const now = Date.now();
    if (_toastThrottle[key] && now - _toastThrottle[key] < 15000) return;
    _toastThrottle[key] = now;

    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        container.className = 'toast-container';
        document.body.appendChild(container);
    }
    const icons = { success: '\u2705', error: '\u274C', warning: '\u26A0\uFE0F', info: '\u2139\uFE0F' };
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `
        <span class="toast-icon">${icons[type] || icons.info}</span>
        <div class="toast-body">
            <div class="toast-title">${escapeHtml(title)}</div>
            ${detail ? `<div class="toast-detail">${escapeHtml(detail)}</div>` : ''}
        </div>
        <button class="toast-close" onclick="this.parentElement.classList.add('removing');setTimeout(()=>this.parentElement.remove(),300)">&times;</button>`;
    container.appendChild(toast);
    const autoDismiss = duration || (type === 'error' ? 8000 : 4000);
    setTimeout(() => {
        toast.classList.add('removing');
        setTimeout(() => toast.remove(), 300);
    }, autoDismiss);
}

// --- State ---
let state = {
    alerts: [],
    processes: {},
    selectedProcess: null,
    activeTab: 'dashboard',
    detailOpen: false,
    detailHistory: [],
    sessionStart: null,
    serviceStatus: {},
    emberStatus: null,
    capaStatus: null,
    aetherStatus: null,
    processDumpStatus: null,
    rustinelInfo: null,
    // RTRACE Console state
    rtraceSelectedPid: null,
    rtraceActiveDetailTab: 'live',
    rtraceEvents: [], // All events for the selected process
    // Hex Editor state
    hexData: null,
    hexFileSize: 0,
    hexFilePath: '',
    hexOffset: 0,
    hexSelectedByte: -1,
};

// --- Loading Overlay ---
const LoadingSpinner = (() => {
    let activeRequests = 0;
    let showTimer = null;
    const DELAY_MS = 300; // Only show spinner if loading takes longer than this

    function getOverlay() {
        return document.getElementById('loading-overlay');
    }

    function show() {
        const overlay = getOverlay();
        if (overlay) overlay.classList.remove('hidden');
    }

    function hide() {
        const overlay = getOverlay();
        if (overlay) overlay.classList.add('hidden');
    }

    return {
        start() {
            activeRequests++;
            if (activeRequests === 1) {
                showTimer = setTimeout(show, DELAY_MS);
            }
        },
        stop() {
            activeRequests = Math.max(0, activeRequests - 1);
            if (activeRequests === 0) {
                clearTimeout(showTimer);
                showTimer = null;
                hide();
            }
        },
        /** Wrap a fetch/promise - shows spinner if it takes >300ms */
        async wrap(promiseOrFn) {
            this.start();
            try {
                const result = await (typeof promiseOrFn === 'function' ? promiseOrFn() : promiseOrFn);
                return result;
            } finally {
                this.stop();
            }
        }
    };
})();

// --- Theme colours ---
// A canvas cannot use var(--x), so drawings read the colours of the active
// theme from the CSS variables (style.css :root). Cached until the theme changes.
const _themeColorCache = new Map();

function themeColor(name, alpha) {
    const key = alpha === undefined ? name : `${name}/${alpha}`;
    let color = _themeColorCache.get(key);
    if (color === undefined) {
        const style = getComputedStyle(document.documentElement);
        color = alpha === undefined
            ? style.getPropertyValue(name).trim()
            : `rgba(${style.getPropertyValue(name + '-rgb').trim()}, ${alpha})`;
        _themeColorCache.set(key, color);
    }
    return color;
}

// After a theme switch the colours are read again and the views drawn from
// them are rebuilt (graph and Tracing timeline only while their tab is open;
// the file maps all, from the data they show). The sidebar timeline is left
// alone: its bars take their colours from CSS classes, and a redraw would
// give them new random widths.
function onThemeChange() {
    _themeColorCache.clear();
    if (state.activeTab === 'graph') renderGraph();
    if (state.activeTab === 'tracing') renderRtraceTimeline();
    renderDashboard();
    FileMapView.repaint();
}
document.addEventListener('tdc:themechange', onThemeChange);

// --- Theme switch (✶) ---
// <html data-theme> selects the theme; the inline script in index.html sets it
// from localStorage before the first paint. A switch never reloads the page:
// the tab bar and the service status move between the sidebar (Classic) and
// the top bar (Cyberpunk) as the same nodes, so handlers and state stay.
const THEMES = ['classic', 'cyberpunk'];
const THEME_LABELS = { classic: 'Classic', cyberpunk: 'Cyberpunk' };

function normalizeTheme(value) {
    // Cyberpunk is the default theme (same rule as the boot script in index.html).
    return THEMES.includes(value) ? value : 'cyberpunk';
}

function nextTheme(theme) {
    return THEMES[(THEMES.indexOf(normalizeTheme(theme)) + 1) % THEMES.length];
}

function currentTheme() {
    return normalizeTheme(document.documentElement.dataset.theme);
}

function applyThemeLayout(theme) {
    // Every part is checked: this runs first at start-up, and a missing element
    // must not stop the rest of the page from being set up.
    const nav = document.querySelector('nav.sidebar-tabs');
    const status = document.getElementById('service-status');
    if (theme === 'cyberpunk') {
        const navHome = document.getElementById('topbar-nav');
        const statusHome = document.getElementById('topbar-services-panel');
        if (nav && navHome) navHome.prepend(nav);               // in front of the "…" menu
        if (status && statusHome) statusHome.appendChild(status);
    } else {
        const logo = document.querySelector('.logo-container');
        const sidebar = document.getElementById('sidebar');
        if (nav && logo) logo.after(nav);
        if (status && sidebar) sidebar.appendChild(status);
    }
    // The drawer and the drop-downs start closed in either theme (their state
    // is not kept), and the tabs are fitted to the bar they are now in.
    closeDrawer();
    closeTopbarMenus();
    updateTabOverflow();
    // Set here rather than in setTheme(), so a page loaded in Cyberpunk names
    // the right target as well.
    const label = `Switch to ${THEME_LABELS[nextTheme(theme)]} theme`;
    for (const id of ['theme-toggle', 'theme-toggle-top']) {
        const button = document.getElementById(id);
        if (!button) continue;
        button.title = label;
        button.setAttribute('aria-label', label);
    }
}

function setTheme(name) {
    const theme = normalizeTheme(name);
    const root = document.documentElement;
    const toggleHadFocus = ['theme-toggle', 'theme-toggle-top'].includes(document.activeElement?.id);
    // Both layouts swap at once: no transition may run between them (the
    // drawer slid out of view, the tabs faded). They are off until the next
    // frame; the layout is computed once while they are off.
    root.classList.add('theme-switching');
    try {
        root.dataset.theme = theme;
        try {
            localStorage.setItem('tdc-theme', theme);
        } catch (e) {
            // Storage blocked or full: the choice lasts until the page is reloaded.
        }
        applyThemeLayout(theme);
        // The ✶ just used is hidden in the new theme: keyboard focus moves to the visible one.
        if (toggleHadFocus) document.getElementById(theme === 'cyberpunk' ? 'theme-toggle-top' : 'theme-toggle')?.focus();
        document.dispatchEvent(new CustomEvent('tdc:themechange', { detail: { theme } }));
    } finally {
        // Even after an error transitions come back on, a frame later.
        void document.body?.offsetWidth;    // the new styles, computed while transitions are off
        const transitionsOn = () => root.classList.remove('theme-switching');
        if (typeof requestAnimationFrame === 'function') requestAnimationFrame(transitionsOn);
        else transitionsOn();
    }
}

function toggleTheme() {
    setTheme(nextTheme(currentTheme()));
}

// --- Cyberpunk top bar: drawer, drop-downs, tab overflow ---
// In Cyberpunk the sidebar is a drawer that slides in over the content while
// #app has .drawer-open (theme-cyberpunk.css). Its open state is not kept.
function isDrawerOpen() {
    return !!document.getElementById('app')?.classList.contains('drawer-open');
}

function setDrawerOpen(open) {
    document.getElementById('app')?.classList.toggle('drawer-open', open);
    document.getElementById('drawer-toggle')?.setAttribute('aria-expanded', String(open));
}

function openDrawer() {
    if (currentTheme() === 'cyberpunk') setDrawerOpen(true);     // Classic shows the sidebar anyway
}

function closeDrawer() {
    setDrawerOpen(false);
}

function toggleDrawer() {
    if (isDrawerOpen()) closeDrawer();
    else openDrawer();
}

// The drop-downs of the top bar, button -> panel. A button's aria-expanded
// shows or hides the panel right after it (theme-cyberpunk.css).
const TOPBAR_MENUS = { 'topbar-services': 'topbar-services-panel', 'topbar-more-toggle': 'topbar-more' };

function isTopbarMenuOpen(buttonId) {
    return document.getElementById(buttonId)?.getAttribute('aria-expanded') === 'true';
}

function setTopbarMenu(buttonId, open) {
    document.getElementById(buttonId)?.setAttribute('aria-expanded', String(open));
}

function toggleTopbarMenu(buttonId) {
    const open = !isTopbarMenuOpen(buttonId);
    closeTopbarMenus();
    if (open) setTopbarMenu(buttonId, true);
}

function closeTopbarMenus() {
    Object.keys(TOPBAR_MENUS).forEach(id => setTopbarMenu(id, false));
}

// A click outside an open drop-down closes it, and a click beside the open
// drawer (on the scrim or in the top bar) closes the drawer. A click in the
// (i) popover is not beside it: the popover of a drawer title lies over the
// page, outside the drawer, and a click in it (to select its text) must not
// hide the title it explains. Registered for the capture phase: it sees the
// click before a handler re-renders the target (a process in the drawer),
// which would then no longer be inside anything.
function onTopbarOutsideClick(e) {
    const inside = id => !!document.getElementById(id)?.contains(e.target);
    for (const [button, panel] of Object.entries(TOPBAR_MENUS)) {
        if (isTopbarMenuOpen(button) && !inside(button) && !inside(panel)) setTopbarMenu(button, false);
    }
    if (isDrawerOpen() && !inside('sidebar') && !inside('drawer-toggle') && !inside('info-popover')) closeDrawer();
}
document.addEventListener('click', onTopbarOutsideClick, true);

// Which tabs fit into the top bar: all of them if they do; otherwise the
// active tab and, in their order, as many of the others as fit beside the "…"
// button. Widths in px; returns the indices of the tabs to show, ascending.
function computeVisibleTabs(widths, available, moreWidth, activeIndex) {
    const all = widths.map((_, i) => i);
    if (widths.reduce((sum, w) => sum + w, 0) <= available) return all;
    const active = all.includes(activeIndex) ? activeIndex : -1;
    const visible = active >= 0 ? [active] : [];
    let room = available - moreWidth - (active >= 0 ? widths[active] : 0);
    for (const i of all) {
        if (i === active) continue;
        if (widths[i] > room) break;        // the menu keeps the rest in their order
        room -= widths[i];
        visible.push(i);
    }
    return visible.sort((a, b) => a - b);
}

// Tabs that do not fit into the Cyberpunk top bar get .tab-overflow (hidden)
// and an entry in the "…" menu. Runs when the room changes, after every tab
// switch and on a theme switch; in Classic it only clears what it set.
function updateTabOverflow() {
    const area = document.getElementById('topbar-nav');
    const wrap = document.getElementById('topbar-more-wrap');
    const menu = document.getElementById('topbar-more');
    const nav = document.querySelector('nav.sidebar-tabs');
    if (!area || !wrap || !menu || !nav) return;
    const tabs = [...nav.querySelectorAll('.tab')];
    // Everything is shown first, so that each tab and the "…" button can be measured.
    tabs.forEach(tab => tab.classList.remove('tab-overflow'));
    menu.replaceChildren();
    wrap.hidden = false;
    if (currentTheme() !== 'cyberpunk' || !area.contains(nav)) {
        wrap.hidden = true;
        setTopbarMenu('topbar-more-toggle', false);
        return;
    }
    const px = (el, property) => parseFloat(getComputedStyle(el)[property]) || 0;
    const gap = px(nav, 'columnGap');
    const frame = px(nav, 'paddingLeft') + px(nav, 'paddingRight') + px(nav, 'borderLeftWidth')
        + px(nav, 'borderRightWidth');
    // Each tab counts with the gap after it; the last one has none, hence + gap.
    const widths = tabs.map(tab => tab.getBoundingClientRect().width + gap);
    const available = area.getBoundingClientRect().width - frame + gap;
    const moreWidth = wrap.getBoundingClientRect().width + px(area, 'columnGap');
    const active = tabs.findIndex(tab => tab.classList.contains('active'));
    const visible = new Set(computeVisibleTabs(widths, available, moreWidth, active));
    const hidden = tabs.filter((_, i) => !visible.has(i));
    for (const tab of hidden) {
        tab.classList.add('tab-overflow');
        const item = document.createElement('button');
        item.type = 'button';
        item.className = 'topbar-more-item';
        item.textContent = tab.textContent.trim();
        item.addEventListener('click', () => {
            setTopbarMenu('topbar-more-toggle', false);
            switchTab(tab.dataset.tab);
            tab.focus();                    // the item is gone: the tab now in the bar takes the focus
        });
        menu.appendChild(item);
    }
    wrap.hidden = !hidden.length;
    if (!hidden.length) setTopbarMenu('topbar-more-toggle', false);
}

// The tabs are fitted again whenever the room for them changes (window size,
// a longer service summary).
function initTopbar() {
    const area = document.getElementById('topbar-nav');
    if (!area) return;
    if (typeof ResizeObserver !== 'undefined') {
        new ResizeObserver(() => updateTabOverflow()).observe(area);
    } else {
        window.addEventListener('resize', updateTabOverflow);
    }
}

// --- Initialization ---
document.addEventListener('DOMContentLoaded', () => {
    applyThemeLayout(currentTheme());
    initTabs();
    initTopbar();
    initCardControls();
    initAlertsTab();
    initSysmonTab();
    initDashboardCharts();
    initUpload();
    initHexDropZone();
    initHexResizeHandle();
    initFileMapDropZone();
    initThreatScan();
    initScoreHistory();
    initSubmissionVerdicts();
    initGraphControls();
    initRtraceTabs();
    refreshAll();
    // Polls pause while the browser tab is hidden; refreshAll() above already
    // loaded the dashboard, so it is not fetched a second time here.
    setInterval(() => { if (!document.hidden) refreshAlerts(); }, 5000);
    setInterval(() => { if (!document.hidden) refreshDashboard(); }, 10000);
    document.addEventListener('visibilitychange', () => {
        if (!document.hidden) { refreshAlerts(); refreshDashboard(); }
    });
    loadScanToolStatus();
    loadScanHistory();
});

// --- Tab navigation ---
function initTabs() {
    document.querySelectorAll('.sidebar-tabs .tab').forEach(tab => {
        tab.addEventListener('click', () => {
            const target = tab.dataset.tab;
            switchTab(target);
        });
    });
}

function switchTab(tabName) {
    // Guard: an unknown name used to deactivate every tab and then throw,
    // leaving the main area blank.
    if (!document.getElementById(`tab-${tabName}`)) return;
    state.activeTab = tabName;
    document.querySelectorAll('.sidebar-tabs .tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    document.querySelector(`.tab[data-tab="${tabName}"]`).classList.add('active');
    document.getElementById(`tab-${tabName}`).classList.add('active');
    // Cyberpunk: a tab picked from the "…" menu takes a place in the top bar.
    updateTabOverflow();
    if (tabName === 'dashboard') {
        renderDashboardCharts();
    }
    if (tabName === 'alerts') {
        renderAlertsTab();
    }
    if (tabName === 'sysmon' && sysmonEvents.length === 0) {
        refreshSysmon();
    }
    if (tabName === 'tracing') {
        renderRtraceConsole();
    }
    if (tabName === 'graph') {
        graphRefresh();
    }
    if (tabName === 'pipes') {
        openPipesTab();
    }
    if (tabName === 'submit') {
        refreshSubmissions();
    }
    if (tabName === 'etw') {
        initEtwBrowser();
    }
    if (tabName === 'litterbox') {
        initLitterbox();
    }
    if (tabName === 'threatscan') {
        loadScanToolStatus();
    }
    if (tabName === 'filemap') {
        initFileMapTab();
    }
}

// Fetch scanner/EMBER tool availability and update badges + dashboard state.
async function loadScanToolStatus() {
    try {
        const resp = await fetch('/api/scan/status');
        const data = await resp.json();
        state.emberStatus = data.ember || null;
        state.capaStatus = data.capa || null;
        // Live-memory tools are PID-based, so they are surfaced in the process
        // detail view rather than the file-oriented ThreatScan tab.
        state.aetherStatus = data.aether || null;
        state.processDumpStatus = data.process_dump || null;
        if (typeof updateLiveMemStatus === 'function') updateLiveMemStatus();
        if (typeof memoryBaselineStatus === 'function') memoryBaselineStatus();

        const tc = !!(data.threatcheck && data.threatcheck.installed);
        const dc = !!(data.defendercheck && data.defendercheck.installed);
        const em = !!(data.ember && data.ember.installed);
        const cp = !!(data.capa && data.capa.installed);
        const nModels = (data.ember && data.ember.models || []).length;

        // Mark unavailable tool toggles (disable checkbox, annotate label)
        const avail = {
            threatcheck: tc,
            defendercheck: dc,
            ember: em,
            capa: cp,
        };
        Object.keys(avail).forEach(id => {
            const cb = document.getElementById('ts-tool-' + id);
            if (!cb) return;
            const label = cb.closest('.ts-tool-toggle');
            if (avail[id]) {
                cb.disabled = false;
                if (label) { label.classList.remove('unavailable'); label.title = ''; }
            } else {
                cb.disabled = true;
                cb.checked = false;
                if (label) { label.classList.add('unavailable'); label.title = 'Not installed on this VM'; }
            }
        });
        if (typeof updateThreatScanOptions === 'function') updateThreatScanOptions();

        const badge = document.getElementById('threatscan-status');
        if (badge) {
            const parts = [
                `ThreatCheck ${tc ? '✓' : '✗'}`,
                `DefenderCheck ${dc ? '✓' : '✗'}`,
                `EMBER ${em ? '✓ ' + nModels + ' model' + (nModels === 1 ? '' : 's') : '✗'}`,
                `capa ${cp ? '✓' : '✗'}`,
            ];
            badge.textContent = parts.join(' · ');
            badge.className = 'scanner-status ' + ((tc || dc || em || cp) ? 'online' : 'offline');
        }
    } catch (e) {
        /* non-fatal */
    }
}

// --- Data fetching ---
async function refreshAll() {
    await LoadingSpinner.wrap(
        Promise.all([refreshAlerts(), refreshProcesses(), refreshDashboard()])
    );
}

async function refreshDashboard() {
    try {
        const [statusResp, rustinelResp] = await Promise.all([
            fetch('/api/status'),
            fetch('/api/rustinel'),
        ]);
        if (statusResp.ok) {
            state.serviceStatus = await statusResp.json();
            updateServiceStatus(state.serviceStatus);
        } else {
            showToast('error', 'Status update failed', `Server returned ${statusResp.status}`, 5000);
        }
        if (rustinelResp.ok) {
            state.rustinelInfo = await rustinelResp.json();
        }
        renderDashboard();
        const updated = new Date().toLocaleTimeString('en-GB');
        const timeEl = document.getElementById('dashboard-time');
        if (timeEl) timeEl.textContent = 'Updated ' + updated;
        const topbarTime = document.getElementById('topbar-time');      // the same clock in the Cyberpunk top bar
        if (topbarTime) topbarTime.textContent = updated;
    } catch (e) {
        showToast('error', 'Dashboard unreachable', e.message || 'Connection to server lost', 6000);
    }
}

let _alertsInFlight = null;

function refreshAlerts() {
    // One request at a time: parsing tens of MB can outlast the 5 s interval,
    // and a second request sent with the old ETag downloaded everything again.
    if (_alertsInFlight) return _alertsInFlight;
    _alertsInFlight = _refreshAlertsOnce().finally(() => { _alertsInFlight = null; });
    return _alertsInFlight;
}

async function _refreshAlertsOnce() {
    try {
        // Conditional request: the server answers 304 when nothing changed,
        // which skips both the transfer and re-parsing tens of MB of JSON.
        const headers = state.alertsEtag ? { 'If-None-Match': state.alertsEtag } : {};
        const resp = await fetch('/api/alerts', { headers, cache: 'no-store' });
        if (resp.status === 304) return;
        if (resp.ok) {
            state.alertsEtag = resp.headers.get('ETag') || null;
            const newAlerts = await resp.json();
            // Toast on new alerts arriving
            if (state.alerts.length > 0 && newAlerts.length > state.alerts.length) {
                const diff = newAlerts.length - state.alerts.length;
                showToast('info', `${diff} new alert${diff > 1 ? 's' : ''}`, 'New detections received');
            }
            state.alerts = newAlerts;
            indexAlerts();
            // A loop instead of Math.min(...times): spreading >64k arguments
            // throws a RangeError in Safari.
            let earliest = Infinity;
            for (const a of state.alerts) {
                const t = new Date(a.timestamp).getTime();
                if (t < earliest) earliest = t;
            }
            state.sessionStart = earliest === Infinity ? null : earliest;
            renderTimeline();
            // Processes are derived from alerts on the server; without this
            // the sidebar and the Tracing tree kept their page-load state.
            await refreshProcesses();
            if (state.activeTab === 'tracing') {
                renderRtraceConsole();
            }
            // After the process list: it maps the alerts to their process instances.
            if (state.activeTab === 'alerts') {
                renderAlertsTab();
            } else if (_alertsTabShown) {
                // The table is not on screen: it lets go of the lists it was built
                // from (tens of MB) and keeps its filters, so the place in it stays.
                _alertsTabShown = { filterKey: _alertsTabShown.filterKey };
            }
            // An open dashboard counts the new alerts in its tiles and charts now, not at its next
            // refresh; a hidden one lets go of the lists it counted, as the table above does
            if (state.activeTab === 'dashboard') renderDashboard();
            else releaseDashboardCounts();
        } else if (resp.status >= 500) {
            showToast('error', 'Alert fetch failed', `Server error ${resp.status}`, 5000);
        }
    } catch (e) {
        showToast('error', 'Alerts unreachable', e.message || 'Connection lost', 6000);
    }
}

// Alerts are looked up by id. Rendered rows used positions in state.alerts,
// which changed with every refresh, or object identity, which never matches
// because /api/processes delivers separately parsed copies.
let _alertIndexById = new Map();

function indexAlerts() {
    _alertIndexById = new Map();
    state.alerts.forEach((a, i) => { if (a && a.id != null) _alertIndexById.set(String(a.id), i); });
}

function alertIndexOf(alert) {
    if (!alert) return -1;
    const idx = _alertIndexById.get(String(alert.id));
    return idx === undefined ? -1 : idx;
}

async function refreshProcesses() {
    try {
        const resp = await fetch('/api/processes');
        if (resp.ok) {
            state.processes = await resp.json();
            renderProcessList();
        }
    } catch (e) {
        showToast('error', 'Process list failed', e.message || 'Connection lost', 5000);
    }
}

async function refreshStatus() {
    try {
        const resp = await fetch('/api/status');
        if (resp.ok) {
            const status = await resp.json();
            state.serviceStatus = status;
            updateServiceStatus(status);
        }
    } catch (e) {
        console.error('Failed to fetch status:', e);
    }
}

// --- Dashboard Rendering ---
function renderDashboard() {
    const container = document.getElementById('dashboard-grid');
    const statsContainer = document.getElementById('dashboard-stats');
    const activityFeed = document.getElementById('dashboard-activity-feed');
    if (!container) return;

    const status = state.serviceStatus;
    const rustinel = state.rustinelInfo || {};
    const alerts = state.alerts || [];

    // --- Stats Strip ---
    if (statsContainer) {
        const totalAlerts = alerts.length;
        const processCount = Object.keys(state.processes || {}).length;
        const servicesList = [
            { name: 'Rustinel', key: 'rustinel', online: status.rustinel?.online },
            { name: 'Fibratus', key: 'fibratus', online: status.fibratus?.online },
            { name: 'DetonatorAgent', key: 'detonator_agent', online: status.detonator_agent?.online },
            { name: 'Detonator', key: 'detonator', online: status.detonator?.online },
            { name: 'LitterBox', key: 'litterbox', online: status.litterbox?.online },
            { name: 'Sysmon', key: 'sysmon', online: status.sysmon?.online },
        ];
        const servicesOnline = servicesList.filter(s => s.online).length;
        const servicesTotal = servicesList.length;
        // In any case ("High" and "high" both occur); no severity and "unknown"
        // count as low, as the Alerts tab counts them as info (alertSeverity)
        let highSev = 0, medSev = 0, lowSev = 0;
        for (const alert of alerts) {
            const severity = alertSeverity(alert);
            if (severity === 'critical' || severity === 'high') highSev++;
            else if (severity === 'medium') medSev++;
            else if (severity === 'low' || severity === 'info') lowSev++;
        }
        const rulesLoaded = (rustinel.rules?.sigma || 0) + (rustinel.rules?.yara || 0);

        // Each tile opens what it counts; a severity count opens the Alerts tab
        // filtered by it (and not the tile's whole list as well). A refresh
        // renders the tiles again: the one with the keyboard focus keeps it.
        // TOTAL ALERTS and PROCESSES TRACKED have a slot for their sparkline
        // (renderDashboardCharts), the other tiles have no history to show.
        const active = document.activeElement;
        const focusedTile = active && active.closest ? active.closest('#dashboard-stats .stat-card')?.dataset.tile : null;
        statsContainer.innerHTML = `
            <div class="stat-card stat-alerts" data-tile="alerts" role="button" tabindex="0" onclick="openAlertsTab({})" onkeydown="onTileKey(event, this)">
                <div class="stat-value">${totalAlerts}</div>
                <div class="stat-label">TOTAL ALERTS</div>
                <div class="stat-breakdown">
                    ${highSev ? `<span class="stat-tag high stat-tag-link" title="Show the critical and high alerts" onclick="event.stopPropagation(); openAlertsTab({severities: ['critical', 'high']})">${highSev} high</span>` : ''}
                    ${medSev ? `<span class="stat-tag med stat-tag-link" title="Show the medium alerts" onclick="event.stopPropagation(); openAlertsTab({severities: ['medium']})">${medSev} med</span>` : ''}
                    ${lowSev ? `<span class="stat-tag low stat-tag-link" title="Show the low and info alerts" onclick="event.stopPropagation(); openAlertsTab({severities: ['low', 'info']})">${lowSev} low</span>` : ''}
                </div>
                <div class="stat-spark" id="dashboard-alerts-spark" aria-hidden="true"></div>
            </div>
            <div class="stat-card stat-processes" data-tile="processes" role="button" tabindex="0" onclick="revealProcessList()" onkeydown="onTileKey(event, this)">
                <div class="stat-value">${processCount}</div>
                <div class="stat-label">PROCESSES TRACKED</div>
                <div class="stat-breakdown"><span class="stat-tag dim">via ETW telemetry</span></div>
                <div class="stat-spark" id="dashboard-processes-spark" aria-hidden="true"></div>
            </div>
            <div class="stat-card stat-services" data-tile="services" role="button" tabindex="0" onclick="revealSection('dashboard-grid')" onkeydown="onTileKey(event, this)">
                <div class="stat-value">${servicesOnline}<span class="stat-value-sub">/${servicesTotal}</span></div>
                <div class="stat-label">SERVICES ONLINE</div>
                <div class="stat-breakdown">
                    ${servicesList.map(s => `<span class="stat-tag ${s.online ? 'svc-on' : 'svc-off'}">${s.name}</span>`).join('')}
                </div>
            </div>
            <div class="stat-card stat-rules" data-tile="rules" role="button" tabindex="0" onclick="openHelp('services', 'help-detection-rules')" onkeydown="onTileKey(event, this)">
                <div class="stat-value">${rulesLoaded}</div>
                <div class="stat-label">DETECTION RULES</div>
                <div class="stat-breakdown">
                    <span class="stat-tag dim">${rustinel.rules?.sigma || 0} sigma</span>
                    <span class="stat-tag dim">${rustinel.rules?.yara || 0} yara</span>
                </div>
            </div>
            <div class="stat-card stat-tools" data-tile="tools" role="button" tabindex="0" onclick="switchTab('threatscan')" onkeydown="onTileKey(event, this)">
                <div class="stat-value">4</div>
                <div class="stat-label">SCANNER TOOLS</div>
                <div class="stat-breakdown">
                    <span class="stat-tag dim">ThreatCheck</span>
                    <span class="stat-tag dim">DefenderCheck</span>
                    <span class="stat-tag dim">EMBER2024</span>
                    <span class="stat-tag dim">capa</span>
                </div>
            </div>
        `;
        if (focusedTile) statsContainer.querySelector(`.stat-card[data-tile="${focusedTile}"]`)?.focus({ preventScroll: true });
    }

    // --- Service Cards ---
    const cards = [];

    // Rustinel Card
    const rOnline = rustinel.online || status.rustinel?.online || false;
    const rRules = rustinel.rules || {};
    cards.push(`
        <div class="service-card rustinel-card ${rOnline ? '' : 'offline'}" onclick="openRustinelDetail()">
            <div class="service-card-glow"></div>
            <div class="service-card-header">
                <div class="service-card-title">
                    <div class="service-icon rustinel">R</div>
                    <h3>Rustinel</h3>
                </div>
                <span class="service-status-badge ${rOnline ? 'online' : 'offline'}">${rOnline ? 'Online' : 'Offline'}</span>
            </div>
            <div class="service-card-desc">Sigma/YARA/IOC detection engine via ETW.${rustinel.version ? `<br>${escapeHtml(rustinel.version)}` : ''}</div>
            <div class="service-card-metrics">
                <div class="service-metric"><div class="service-metric-value ${rRules.sigma === 0 ? 'zero' : ''}">${rRules.sigma || 0}</div><div class="service-metric-label">SIGMA</div></div>
                <div class="service-metric"><div class="service-metric-value ${rRules.yara === 0 ? 'zero' : ''}">${rRules.yara || 0}</div><div class="service-metric-label">YARA</div></div>
                <div class="service-metric"><div class="service-metric-value ${rustinel.alerts_count === 0 ? 'zero' : ''}">${rustinel.alerts_count || 0}</div><div class="service-metric-label">ALERTS</div></div>
            </div>
            <div class="service-card-actions">
                <button class="btn btn-sm" onclick="event.stopPropagation(); openRustinelDetail()">Details</button>
                <button class="btn btn-sm" onclick="event.stopPropagation(); switchTab('tracing')">Trace Console</button>
                ${!rOnline ? '<button class="btn btn-sm btn-launch" onclick="event.stopPropagation(); launchService(\'rustinel\', this)">Launch</button>' : ''}
            </div>
        </div>
    `);

    // DetonatorAgent Card
    const aOnline = status.detonator_agent?.online || false;
    const aInUse = status.detonator_agent?.data?.in_use || false;
    cards.push(`
        <div class="service-card agent-card ${aOnline ? '' : 'offline'}" onclick="openAgentDetail()">
            <div class="service-card-glow"></div>
            <div class="service-card-header">
                <div class="service-card-title"><div class="service-icon agent">D</div><h3>DetonatorAgent</h3></div>
                <span class="service-status-badge ${aOnline ? 'online' : 'offline'}">${aOnline ? 'Online' : 'Offline'}</span>
            </div>
            <div class="service-card-desc">.NET execution agent. Detonates samples and collects EDR telemetry on port 8080.</div>
            <div class="service-card-metrics">
                <div class="service-metric"><div class="service-metric-value">${aOnline ? '8080' : '--'}</div><div class="service-metric-label">PORT</div></div>
                <div class="service-metric"><div class="service-metric-value ${aInUse ? '' : 'zero'}" style="${aInUse ? 'color:var(--accent-orange)' : ''}">${aOnline ? (aInUse ? 'Detonating' : 'Idle') : '--'}</div><div class="service-metric-label">ACTIVITY</div></div>
                <div class="service-metric"><div class="service-metric-value">${aOnline ? 'Fibratus' : '--'}</div><div class="service-metric-label">EDR</div></div>
            </div>
            <div class="service-card-actions">
                <button class="btn btn-sm" onclick="event.stopPropagation(); openAgentDetail()">Details</button>
                <button class="btn btn-sm" onclick="event.stopPropagation(); switchTab('submit')">Submit Sample</button>
                ${!aOnline ? '<button class="btn btn-sm btn-launch" onclick="event.stopPropagation(); launchService(\'detonator_agent\', this)">Launch</button>' : ''}
            </div>
        </div>
    `);

    // LitterBox Card
    const lOnline = status.litterbox?.online || false;
    cards.push(`
        <div class="service-card litterbox-card ${lOnline ? '' : 'offline'}" onclick="openLitterboxDetail()">
            <div class="service-card-glow"></div>
            <div class="service-card-header">
                <div class="service-card-title"><div class="service-icon litterbox">L</div><h3>LitterBox</h3></div>
                <span class="service-status-badge ${lOnline ? 'online' : 'offline'}">${lOnline ? 'Online' : 'Offline'}</span>
            </div>
            <div class="service-card-desc">Self-hosted payload analysis sandbox. Static analysis, memory scanning, YARA.</div>
            <div class="service-card-metrics">
                <div class="service-metric"><div class="service-metric-value">${lOnline ? '1337' : '--'}</div><div class="service-metric-label">PORT</div></div>
                <div class="service-metric"><div class="service-metric-value">PE-Sieve</div><div class="service-metric-label">SCANNER</div></div>
                <div class="service-metric"><div class="service-metric-value">MCP</div><div class="service-metric-label">LLM API</div></div>
            </div>
            <div class="service-card-actions">
                <button class="btn btn-sm" onclick="event.stopPropagation(); openLitterboxDetail()">Details</button>
                <button class="btn btn-sm" onclick="event.stopPropagation(); window.open('http://localhost:1337', '_blank')">Open UI</button>
                ${!lOnline ? '<button class="btn btn-sm btn-launch" onclick="event.stopPropagation(); launchService(\'litterbox\', this)">Launch</button>' : ''}
            </div>
        </div>
    `);

    // Sysmon Card
    const sOnline = status.sysmon?.online || false;
    cards.push(`
        <div class="service-card sysmon-card ${sOnline ? '' : 'offline'}" onclick="switchTab('sysmon'); refreshSysmon();">
            <div class="service-card-glow"></div>
            <div class="service-card-header">
                <div class="service-card-title"><div class="service-icon sysmon">S</div><h3>Sysmon</h3></div>
                <span class="service-status-badge ${sOnline ? 'online' : 'offline'}">${sOnline ? 'Online' : 'Offline'}</span>
            </div>
            <div class="service-card-desc">System Monitor v15.14. Logs process creation, network, file, registry, DNS events.</div>
            <div class="service-card-metrics">
                <div class="service-metric"><div class="service-metric-value">${sOnline ? 'Sysmon64' : '--'}</div><div class="service-metric-label">SERVICE</div></div>
                <div class="service-metric"><div class="service-metric-value">ETW</div><div class="service-metric-label">SOURCE</div></div>
                <div class="service-metric"><div class="service-metric-value">SwiftOnSec</div><div class="service-metric-label">CONFIG</div></div>
            </div>
            <div class="service-card-actions">
                <button class="btn btn-sm" onclick="event.stopPropagation(); switchTab('sysmon'); refreshSysmon();">View Events</button>
                ${!sOnline ? '<button class="btn btn-sm btn-launch" onclick="event.stopPropagation(); launchService(\'sysmon\', this)">Launch</button>' : ''}
            </div>
        </div>
    `);

    // Fibratus Card
    const fOnline = status.fibratus?.online || false;
    cards.push(`
        <div class="service-card fibratus-card ${fOnline ? '' : 'offline'}">
            <div class="service-card-glow"></div>
            <div class="service-card-header">
                <div class="service-card-title"><div class="service-icon fibratus">F</div><h3>Fibratus</h3></div>
                <span class="service-status-badge ${fOnline ? 'online' : 'offline'}">${fOnline ? 'Online' : 'Offline'}</span>
            </div>
            <div class="service-card-desc">Kernel-level ETW consumer. Captures process, thread, file, registry, network events.</div>
            <div class="service-card-metrics">
                <div class="service-metric"><div class="service-metric-value">${fOnline ? '8180' : '--'}</div><div class="service-metric-label">PORT</div></div>
                <div class="service-metric"><div class="service-metric-value">Kernel</div><div class="service-metric-label">LEVEL</div></div>
                <div class="service-metric"><div class="service-metric-value">v3.0</div><div class="service-metric-label">VERSION</div></div>
            </div>
            ${!fOnline ? '<div class="service-card-actions"><button class="btn btn-sm btn-launch" onclick="event.stopPropagation(); launchService(\'fibratus\', this)">Launch</button></div>' : ''}
        </div>
    `);

    // Scanner Tools Card
    cards.push(`
        <div class="service-card scanner-card" onclick="switchTab('threatscan')">
            <div class="service-card-glow"></div>
            <div class="service-card-header">
                <div class="service-card-title"><div class="service-icon scanner">T</div><h3>AV/AMSI Scanner</h3></div>
                <span class="service-status-badge online">Ready</span>
            </div>
            <div class="service-card-desc">ThreatCheck + DefenderCheck. Pinpoint exact bytes flagged by Defender/AMSI signatures.</div>
            <div class="service-card-metrics">
                <div class="service-metric"><div class="service-metric-value">TC</div><div class="service-metric-label">THREATCHECK</div></div>
                <div class="service-metric"><div class="service-metric-value">DC</div><div class="service-metric-label">DEFENDERCHK</div></div>
                <div class="service-metric"><div class="service-metric-value">AMSI</div><div class="service-metric-label">ENGINE</div></div>
            </div>
            <div class="service-card-actions">
                <button class="btn btn-sm" onclick="event.stopPropagation(); switchTab('threatscan')">Open Scanner</button>
            </div>
        </div>
    `);

    // EMBER2024 ML Classifier Card
    const emberStatus = state.emberStatus || {};
    const emberOnline = emberStatus.installed !== false; // treat unknown as ready
    const emberModelCount = (emberStatus.models || []).length;
    cards.push(`
        <div class="service-card ember-card ${emberOnline ? '' : 'offline'}" onclick="switchTab('threatscan')">
            <div class="service-card-glow"></div>
            <div class="service-card-header">
                <div class="service-card-title"><div class="service-icon ember">E</div><h3>EMBER2024</h3></div>
                <span class="service-status-badge ${emberOnline ? 'online' : 'offline'}">${emberOnline ? 'Ready' : 'Not installed'}</span>
            </div>
            <div class="service-card-desc">ML malware classifier (thrember). LightGBM scores a file's malicious probability from EMBERv3 static features.</div>
            <div class="service-card-metrics">
                <div class="service-metric"><div class="service-metric-value">LGBM</div><div class="service-metric-label">MODEL</div></div>
                <div class="service-metric"><div class="service-metric-value ${emberModelCount ? '' : 'zero'}">${emberModelCount || '--'}</div><div class="service-metric-label">CLASSIFIERS</div></div>
                <div class="service-metric"><div class="service-metric-value">0&ndash;1</div><div class="service-metric-label">SCORE</div></div>
            </div>
            <div class="service-card-actions">
                <button class="btn btn-sm" onclick="event.stopPropagation(); switchTab('threatscan')">Open EMBER</button>
            </div>
        </div>
    `);

    // capa Capability Detection Card
    const capaStatus = state.capaStatus || {};
    const capaOnline = capaStatus.installed !== false; // treat unknown as ready
    cards.push(`
        <div class="service-card capa-card ${capaOnline ? '' : 'offline'}" onclick="switchTab('threatscan')">
            <div class="service-card-glow"></div>
            <div class="service-card-header">
                <div class="service-card-title"><div class="service-icon capa">C</div><h3>capa</h3></div>
                <span class="service-status-badge ${capaOnline ? 'online' : 'offline'}">${capaOnline ? 'Ready' : 'Not installed'}</span>
            </div>
            <div class="service-card-desc">Mandiant capa. Static capability detection mapped to MITRE ATT&CK &amp; MBC. Answers "what can it do?"</div>
            <div class="service-card-metrics">
                <div class="service-metric"><div class="service-metric-value">ATT&CK</div><div class="service-metric-label">MAPPING</div></div>
                <div class="service-metric"><div class="service-metric-value">Rules</div><div class="service-metric-label">ENGINE</div></div>
                <div class="service-metric"><div class="service-metric-value">Static</div><div class="service-metric-label">MODE</div></div>
            </div>
            <div class="service-card-actions">
                <button class="btn btn-sm" onclick="event.stopPropagation(); switchTab('threatscan')">Open capa</button>
            </div>
        </div>
    `);

    container.innerHTML = cards.join('');

    // --- Recent Activity Feed ---
    if (activityFeed) {
        if (alerts.length === 0) {
            activityFeed.innerHTML = '<div class="activity-empty">No recent activity. Submit a sample to begin.</div>';
        } else {
            const recent = newestAlerts(alerts, 8);
            let html = '';
            recent.forEach(alert => {
                const ts = alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString('en-GB', {hour12:false}) : '--';
                const severity = alertSeverity(alert);      // lower case: the engines write "High" as well
                const sevClass = (severity === 'high' || severity === 'critical') ? 'sev-high' : severity === 'medium' ? 'sev-med' : 'sev-low';
                // sev-high covers critical as well; data-sev keeps them apart (Cyberpunk colours critical on its own)
                const sevKey = ['critical', 'high', 'medium'].includes(severity) ? severity : 'low';
                const ruleName = alert.rule_name || alert.name || 'Unknown Rule';
                const proc = alert.process_name || '';
                const pid = alert.pid || '';
                html += `<div class="activity-entry ${sevClass}" data-sev="${sevKey}">`;
                html += `<span class="activity-time">${ts}</span>`;
                html += `<span class="activity-sev">${escapeHtml((alert.severity || 'info').toUpperCase())}</span>`;
                html += `<span class="activity-rule">${escapeHtml(ruleName)}</span>`;
                html += proc ? `<span class="activity-proc">${escapeHtml(proc)}${pid ? ' (' + escapeHtml(String(pid)) + ')' : ''}</span>` : '';
                html += `</div>`;
            });
            activityFeed.innerHTML = html;
        }
    }

    // --- Alert activity, the donuts and the sparklines of the tiles ---
    renderDashboardCharts();
}

// --- The charts of the dashboard ---
// Between the tiles and the service cards: ALERT ACTIVITY, the alerts per
// hour, day or week stacked by severity over the range of its switch (24H,
// 7D, 30D or ALL), and beside it the donuts SEVERITY and CATEGORY of that
// range. A range drawn across the bars narrows the donuts to it (a chip
// names it, its × takes it off); a bar opens the Alerts tab at its period, a
// segment at its severity or category within the range, so the table there
// lists what the part counted. TOTAL ALERTS and PROCESSES TRACKED show their
// last 45 days as sparklines. Each part counts again only when what it is
// counted from changed (the alerts, the process list, the range), and
// nothing is counted while the dashboard is hidden; alerts without a time or
// with one no clock can have had are in no bar, a note counts them.
const DASHBOARD_RANGES = new Map([['24h', 86400000], ['7d', 7 * 86400000], ['30d', 30 * 86400000]]);
const DASHBOARD_SPARK_DAYS = 45;
// What the donuts count: a preset of the switch ('24h', '7d', '30d' or
// 'all', the default) or a range drawn across the bars ('custom'); from / to
// in epoch ms, from included and to not, null for an open end. A preset runs
// from its start on (to null), so the newest alerts are in it.
const dashboardRange = { preset: 'all', from: null, to: null };
// What the bars span: the preset last chosen (a range drawn across them leaves it)
const dashboardBarsRange = { preset: 'all', from: null };
// Each part's counts with the inputs they were counted from: {inputs, value}
const _dashboardMemo = { bars: null, donuts: null, sparks: null };
// What is on screen: the counts each part was drawn from, the range of the
// switch and the chip, the range the bars mark ('' for none) and their size
const _dashboardDrawn = { bars: null, donuts: null, sparks: null, range: '', marked: '', size: null };
// ALERT ACTIVITY takes a range drawn across its bars (initBarsBrush): it is
// the range of the donuts, from the start of its first bar to the end of its last
const DASHBOARD_BARS_BRUSH = {
    view: 'dashboard-alerts-chart',
    bins: () => (_dashboardDrawn.bars ? _dashboardDrawn.bars.bins : []),
    onRange: (first, last, bins) => setDashboardRange('custom', bins[first].start, bins[last].end),
};

// The switch: a preset from now on ('all', and a name it does not know:
// every alert), or a range drawn across the bars, setDashboardRange('custom',
// from, to) in epoch ms, `to` after `from`; anything else changes nothing
function setDashboardRange(preset, from, to) {
    if (preset === 'custom') {
        const start = _alertsTimeBound(from), end = _alertsTimeBound(to);
        if (start === null || end === null || !(end > start)) return;
        Object.assign(dashboardRange, { preset: 'custom', from: start, to: end });
    } else {
        const name = DASHBOARD_RANGES.has(preset) ? preset : 'all';
        const start = name === 'all' ? null : Date.now() - DASHBOARD_RANGES.get(name);
        Object.assign(dashboardRange, { preset: name, from: start, to: null });
        Object.assign(dashboardBarsRange, { preset: name, from: start });
    }
    renderDashboardCharts();
}

// Draws what changed: renderDashboard calls it after writing the tiles (every
// refresh, and with new alerts), switchTab when the dashboard is shown again
function renderDashboardCharts() {
    if (state.activeTab !== 'dashboard' || !document.getElementById('dashboard-charts')) return;
    for (const id of ['dashboard-alerts', 'dashboard-severity', 'dashboard-category']) {
        // Written once: a refresh keeps the switch (and the keyboard focus on it)
        const slot = document.getElementById(`${id}-toggle`);
        if (slot && !slot.firstElementChild) slot.innerHTML = viewToggleHtml(id);
    }
    const counted = _dashboardCount(Date.now());
    const drawn = _dashboardDrawn;
    _drawDashboardSparks(counted.sparks);
    _drawDashboardRange();
    if (drawn.donuts !== counted.donuts) {
        drawn.donuts = counted.donuts;
        _drawDashboardDonuts(counted.donuts);
    }
    // While a press on the bars lasts (a range may be drawn across them), they stay as they are
    if (barsBrushActive(DASHBOARD_BARS_BRUSH)) return;
    const size = _dashboardBarsSize();
    const marked = dashboardRange.preset === 'custom' ? `${dashboardRange.from}-${dashboardRange.to}` : '';
    if (drawn.bars === counted.bars && drawn.marked === marked
        && (!size.width || (drawn.size && size.width === drawn.size.width && size.height === drawn.size.height))) return;
    Object.assign(drawn, { bars: counted.bars, marked }, size.width && size.height ? { size } : {});
    _drawDashboardBars(drawn);
}

// The counts of the charts, each part's again only when its inputs changed:
// the bars from the alerts and the span of the bars, the donuts from the
// alerts and the range, the sparklines from the alerts, the process list and
// the day it is. A range drawn across the bars that they no longer reach (the
// alerts under it are gone) is taken off: the chip, the mark and the donuts
// name no range the bars do not show.
function _dashboardCount(now) {
    _dashboardFollowTheClock(now);
    const alerts = state.alerts || [];
    const memo = (name, inputs, count) => {
        const last = _dashboardMemo[name];
        if (!last || last.inputs.some((input, i) => input !== inputs[i])) _dashboardMemo[name] = { inputs, value: count() };
        return _dashboardMemo[name].value;
    };
    const { preset, from } = dashboardBarsRange;
    const span = DASHBOARD_RANGES.get(preset);
    // A preset's bars reach up to now: its hours or days without alerts are bars too
    const bars = memo('bars', [alerts, preset, from], () => alertSeverityBins(from === null ? alerts : filterAlerts(alerts, { from }),
                                                                               { from, until: span ? from + span : null, now }));
    const { bins } = bars;
    if (dashboardRange.preset === 'custom' && (!bins.length || dashboardRange.to <= bins[0].start
                                               || dashboardRange.from >= bins[bins.length - 1].end)) {
        Object.assign(dashboardRange, { preset, from, to: null });
    }
    return {
        bars,
        donuts: memo('donuts', [alerts, dashboardRange.preset, dashboardRange.from, dashboardRange.to], () => {
            const matches = filterAlerts(alerts, { from: dashboardRange.from, to: dashboardRange.to });
            return { total: matches.length, severity: alertsSeverityItems(matches), category: dashboardCategoryItems(matches) };
        }),
        sparks: memo('sparks', [alerts, state.processes, _chartPeriodStart(now, 'day')],
                     () => _dashboardSparkCounts(alerts, state.processes, now)),
    };
}

// A preset runs up to now: its start follows the clock by the minute. A
// range drawn across its bars holds them where they are, so the range stays
// on them (the preset starts from now again when the range is taken off).
function _dashboardFollowTheClock(now) {
    const span = DASHBOARD_RANGES.get(dashboardBarsRange.preset);
    if (!span || dashboardRange.preset === 'custom' || Math.abs(now - span - dashboardBarsRange.from) < 60000) return;
    dashboardRange.from = dashboardBarsRange.from = now - span;
}

// While the dashboard is hidden: it lets go of the lists it counted (tens of
// MB of alerts), as the Alerts tab does; shown again, it counts those of then
function releaseDashboardCounts() {
    for (const name of Object.keys(_dashboardMemo)) _dashboardMemo[name] = null;
}

// TOTAL ALERTS and PROCESSES TRACKED: the alerts, and the processes first
// seen, per local day of the last 45 days (today the last), oldest first
function _dashboardSparkCounts(alerts, processes, now) {
    const today = _chartPeriodStart(now, 'day');
    const first = new Date(today);
    first.setDate(first.getDate() - (DASHBOARD_SPARK_DAYS - 1));
    const days = { from: _chartPeriodStart(first.getTime(), 'day'), to: _chartPeriodNext(today, 'day') };
    const perDay = (items, time) => binByTime(items, { ...days, time }).bins.map(bin => bin.total);
    return {
        alerts: perDay(alerts, alert => Date.parse(alert?.timestamp)),
        processes: perDay(Object.values(processes || {}), proc => Date.parse(proc?.first_seen)),
    };
}

// The segments of CATEGORY: the alerts per category (alertCategory, "other"
// for alerts without one), the six most frequent on their own, the rest
// summed up as "other categories": key '', no filter (it stands for several),
// `kinds` the number it sums up. A category keeps its colour whatever the
// range, that of its rank among all alerts; the muted one is the rest's.
function dashboardCategoryItems(matches) {
    const counts = countBy(matches, alertCategory);
    const { keep } = topWithOther(counts, 6, '');
    const rank = new Map(countBy((state.alerts || []).filter(Boolean), alertCategory).map(({ key }, i) => [key, i]));
    const items = counts.filter(({ key }) => keep.has(key)).map(({ key, count }) => ({
        key, label: key, value: count, color: CHART_PALETTE[(rank.has(key) ? rank.get(key) : rank.size) % (CHART_PALETTE.length - 1)],
    }));
    const rest = counts.filter(({ key }) => !keep.has(key));
    if (rest.length) {
        items.push({ key: '', label: 'other categories', value: rest.reduce((sum, c) => sum + c.count, 0),
                     color: 'var(--text-muted)', kinds: rest.length });
    }
    return items;
}

// The sparklines into the slots of their tiles, which renderDashboard writes
// again on every refresh (empty); a slot that shows the counts already is left
function _drawDashboardSparks(sparks) {
    const tiles = [['alerts', 'var(--accent-pink)', 'Alerts'], ['processes', 'var(--accent-cyan)', 'Processes first seen']];
    for (const [kind, color, what] of tiles) {
        const slot = document.getElementById(`dashboard-${kind}-spark`);
        if (!slot || (slot.firstElementChild && _dashboardDrawn.sparks === sparks)) continue;
        const values = sparks[kind];
        slot.setAttribute('title', `${what} per day over the last ${DASHBOARD_SPARK_DAYS} days: `
            + `${_chartNumber(values.reduce((sum, n) => sum + n, 0))} in all`);
        slot.innerHTML = sparklineSvg(values, { width: 120, height: 26, color })
            + `<span class="stat-spark-label">${DASHBOARD_SPARK_DAYS} days</span>`;
    }
    _dashboardDrawn.sparks = sparks;
}

// ALERT ACTIVITY from what renderDashboardCharts counted: the bars for the
// size of their card, a range drawn across them marked, a bar without alerts
// inert; under them how to use them and the alerts in no bar; the table view
function _drawDashboardBars(drawn) {
    const view = document.getElementById('dashboard-alerts-chart'), table = document.getElementById('dashboard-alerts-table');
    const note = document.getElementById('dashboard-alerts-note');
    const time = drawn.bars;
    const empty = time.untimed + time.implausible ? 'No alerts with a time'
        : (state.alerts || []).length ? 'No alerts in this range' : 'No alerts yet';
    const selection = dashboardRange.preset === 'custom' ? { from: dashboardRange.from, to: dashboardRange.to } : null;
    const svg = _alertsTimeBarsSvg(time, { width: drawn.size ? drawn.size.width : 720,
                                           height: drawn.size ? drawn.size.height : 200, selection });
    if (view) {
        view.innerHTML = svg || chartEmptyHtml(empty);
        _alertsChartInert(view, '[data-bin-start]', el => !(Number(el.getAttribute('data-total')) > 0));
    }
    if (note) {
        const missed = _alertsTimeNote(time);
        note.innerHTML = (svg ? '<span class="dashboard-bars-hint">Drag across the bars to narrow the range · click a bar to open its alerts</span>' : '')
            + (missed ? `<span class="dashboard-bars-missed" title="Alerts without a readable time or with one no clock can have had (before 2000, more than a day ahead) are in no bar; the donuts count them">${escapeHtml(missed)}</span>` : '');
    }
    if (table) table.innerHTML = _alertsTimeTableHtml(time, empty, '<table class="view-table" data-sortable data-sort-id="dashboard-alerts">');
}

// SEVERITY and CATEGORY of the range: each donut beside its legend, in its
// middle the alerts or the kinds of category; their table views
function _drawDashboardDonuts(donuts) {
    const empty = donuts.total ? '' : (state.alerts || []).length ? 'No alerts in this range' : 'No alerts yet';
    const kinds = donuts.category.reduce((sum, item) => sum + (item.kinds || 1), 0);
    _drawShareChart('dashboard-severity', 'severity', donuts.severity, empty,
        donutSvg(donuts.severity, { size: 110, thickness: 16, centerSub: 'ALERTS' }),
        '<table class="view-table" data-sortable data-sort-id="dashboard-severity">');
    _drawShareChart('dashboard-category', 'category', donuts.category, empty,
        donutSvg(donuts.category, { size: 110, thickness: 16, centerLabel: kinds, centerSub: kinds === 1 ? 'KIND' : 'KINDS' }),
        '<table class="view-table" data-sortable data-sort-id="dashboard-category">');
}

// The switch shows the preset the donuts count, none while they count a range
// drawn across the bars: that range is a chip before the switch, whose ×
// goes back to the preset of the bars (its keyboard focus moves on to that
// preset). Both are written again only for another range: new alerts leave
// a chip in focus as it is.
function _drawDashboardRange() {
    const { preset, from, to } = dashboardRange, base = dashboardBarsRange.preset;
    const key = preset === 'custom' ? `custom|${from}|${to}|${base}` : preset;
    if (_dashboardDrawn.range === key) return;
    _dashboardDrawn.range = key;
    document.querySelectorAll('#dashboard-alerts-card .chart-range-btn').forEach(button =>
        button.setAttribute('aria-pressed', String(button.getAttribute('data-range') === preset)));
    const holder = document.getElementById('dashboard-range-chip');
    if (!holder) return;
    const focused = holder.contains(document.activeElement);
    if (preset === 'custom') {
        const title = `Remove the range ${formatAlertTime(from)} – ${formatAlertTime(to)} (end not included): back to ${base.toUpperCase()}`;
        holder.innerHTML = filterChipHtml({ value: chartRangeLabel(from, to), title }, `setDashboardRange(${jsArg(base)})`);
    } else {
        holder.innerHTML = '';
    }
    holder.hidden = preset !== 'custom';
    if (focused && preset !== 'custom') document.querySelector('#dashboard-alerts-card .chart-range-btn[aria-pressed="true"]')?.focus();
}

// The size the bars are drawn for: the room between the head of their card
// and its note (0 while the dashboard is hidden)
function _dashboardBarsSize() {
    const rect = document.querySelector('#dashboard-alerts-card .dashboard-bars-area')?.getBoundingClientRect();
    return { width: Math.floor(rect ? rect.width : 0), height: Math.floor(rect ? rect.height : 0) };
}

// A click on a chart of the dashboard opens the Alerts tab filtered by the
// part clicked: a bar at its period, the segment or legend row of a severity
// or a category at it within the range of the dashboard. A bar without
// alerts, a severity no chip names and "other categories" open nothing (each
// would list other alerts than it shows), nor does the release of a press
// that drew a range across the bars. The click of a press on the bars opens
// the bar pressed, wherever the browser sends it (barsClickPeriod).
function onDashboardChartClick(event, chart) {
    const target = event && event.target;
    if (!target || typeof target.closest !== 'function') return;
    if (chart === 'alerts') {
        const period = barsClickPeriod(event, DASHBOARD_BARS_BRUSH);
        if (period) openAlertsTab(period);
        return;
    }
    const part = target.closest('[data-key]');
    const key = part ? part.getAttribute('data-key') : '';
    const range = { from: dashboardRange.from, to: dashboardRange.to };
    if (chart === 'severity' && ALERT_SEVERITIES.includes(key)) openAlertsTab({ severities: [key], ...range });
    else if (chart === 'category' && key) openAlertsTab({ category: key, ...range });
}

// The bars take a range drawn across them (initBarsBrush). They are drawn
// again in the next frame when the size of their card changes (the window,
// the theme, the donut cards beside them).
function initDashboardCharts() {
    initBarsBrush(DASHBOARD_BARS_BRUSH);
    const area = document.querySelector('#dashboard-alerts-card .dashboard-bars-area');
    if (area && typeof ResizeObserver !== 'undefined') {
        new ResizeObserver(() => requestAnimationFrame(redrawDashboardChartsOnResize)).observe(area);
    }
}

// The bars for the new size of their card; nothing while the dashboard is
// hidden, for the size they have or while a press on them lasts
function redrawDashboardChartsOnResize() {
    const drawn = _dashboardDrawn, size = _dashboardBarsSize();
    if (!drawn.bars || barsBrushActive(DASHBOARD_BARS_BRUSH) || !size.width || !size.height
        || (drawn.size && size.width === drawn.size.width && size.height === drawn.size.height)) return;
    drawn.size = size;
    _drawDashboardBars(drawn);
}

// --- A range drawn across bars ---
// ALERT ACTIVITY of the dashboard and OVER TIME of the Alerts tab take a
// range drawn across their bars (mouse, pen or finger) by the same code.
// Each is a host: {view: the id of the element with the bars; bins(): the
// bins of the bars drawn, [{start, end, total}], read when a press begins
// and kept until it ends; onRange(first, last, bins): a range was drawn
// across them, from the bar numbered first to the bar numbered last of
// those bins; onStop(), optional: a press on them is over, whether it drew
// a range or not, also when it was cancelled; no press holds the bars then
// (it comes before onRange)}.
// The press on the bars of a host while it lasts ({host, view, pointerId, x,
// first, last, moved, svg, bins, pressed}: whose bars and where it began,
// the bars it spans, whether it draws a range, the bars on screen then and
// the bar pressed); after its release, until the click of that release (it
// comes in the same task, if at all), what that click stands for: {host,
// drew, pressed}
let _barsBrush = null;
let _barsReleased = null;
// The hosts whose bars take a range (initBarsBrush)
const _barsBrushHosts = new Set();

// The bars of a host take a range drawn across them: a press on them begins
// it, its moves and its end are followed wherever the pointer goes (out of
// the bars, out of the window). The context menu drops a press (macOS opens
// it on Ctrl+click, the release then goes to the menu). The page listens for
// these once for all hosts, the bars of a host for a press once, however
// often it is set up.
function initBarsBrush(host) {
    const view = document.getElementById(host.view);
    if (!view || _barsBrushHosts.has(host)) return;
    if (!_barsBrushHosts.size) {
        document.addEventListener('pointermove', onBarsBrushMove, true);
        document.addEventListener('pointerup', onBarsBrushEnd, true);
        document.addEventListener('pointercancel', onBarsBrushEnd, true);
        document.addEventListener('contextmenu', onBarsBrushCancel, true);
    }
    _barsBrushHosts.add(host);
    view.addEventListener('pointerdown', event => onBarsBrushStart(event, host));
}

// Whether a press on the bars of the host lasts: while it does, they are not
// drawn again (a range drawn is marked on them, its click is to reach them)
function barsBrushActive(host) {
    return !!_barsBrush && _barsBrush.host === host;
}

// What a click on the bars of a host stands for, the period {from, to} of a
// bar or null: after a press on them that drew a range, nothing (that click
// only); after one that did not move, the bar it pressed, wherever the
// browser sends the click (to the bars' common parent when the press ended
// on the next bar); without a press, the bar clicked. A bar without alerts
// stands for nothing, and so does the click of a press on another host's bars.
function barsClickPeriod(event, host) {
    const released = _barsReleased;
    if (released) {
        if (released.host !== host) return null;
        _barsReleased = null;
        return released.drew ? null : released.pressed;
    }
    const target = event && event.target, view = document.getElementById(host.view);
    if (!target || typeof target.closest !== 'function' || !view || !view.contains(target)) return null;
    return _binPeriod(target.closest('[data-bin-start]'));
}

// The period {from, to} of a bar (a [data-bin-start] group) with alerts, else null
function _binPeriod(bin) {
    return bin && Number(bin.getAttribute('data-total')) > 0
        ? { from: Number(bin.getAttribute('data-bin-start')), to: Number(bin.getAttribute('data-bin-end')) } : null;
}

// A press on the bars of a host (the main button) may begin a range: at the
// bar under the pointer, over the bars drawn then. It takes no pointer
// capture yet: a press that does not move is a click, which the browser
// sends to the bar under the pointer. A press still under way (its release
// never came, another finger's) ends first, as a cancelled one; should its
// host draw the bars again then, this press is on bars no longer shown and
// begins nothing.
function onBarsBrushStart(event, host) {
    _barsReleased = null;
    const target = event.target && typeof event.target.closest === 'function' ? event.target : null;
    const svg = target ? target.closest('svg') : null;
    if (event.button !== 0 || !svg) return;
    if (_barsBrush) _barsBrushStop(true);
    const bins = svg.isConnected ? host.bins() : null;
    if (!bins || !bins.length) return;
    const bin = _barsBinAt(svg, event.clientX, bins.length);
    _barsBrush = { host, view: document.getElementById(host.view), pointerId: event.pointerId, x: event.clientX,
                   first: bin, last: bin, moved: false, svg, bins, pressed: _binPeriod(target.closest('[data-bin-start]')) };
}

// Moved by 5 px or more, the press draws a range: from its bar to the bar
// under the pointer, marked as it grows. From then on its bars hold the
// pointer's capture, so its moves and its release reach them wherever it is.
// A move without the main button (its release went elsewhere) ends the press
// as a cancelled one.
function onBarsBrushMove(event) {
    const brush = _barsBrush;
    if (!brush || event.pointerId !== brush.pointerId) return;
    if (typeof event.buttons === 'number' && !(event.buttons & 1)) {
        _barsBrushStop(true);
        return;
    }
    if (!brush.moved) {
        if (Math.abs(event.clientX - brush.x) < 5) return;
        brush.moved = true;
        if (brush.view) {
            brush.view.classList.add('is-brushing');
            try {
                brush.view.setPointerCapture(event.pointerId);
            } catch (e) {
                // not a live pointer: the moves still come while it is over the page
            }
        }
    }
    brush.last = _barsBinAt(brush.svg, event.clientX, brush.bins.length);
    _barsBrushMark(brush);
}

// Released, a range drawn is the host's (onRange with the numbers of its
// first and its last bar), and the click of this release stands for
// nothing; a press that did not move leaves its click the bar it pressed.
// Cancelled, nothing. What the click stands for lasts until the task is
// over: a later click (no press) stands for the bar it is on.
function onBarsBrushEnd(event) {
    const brush = _barsBrush;
    if (!brush || event.pointerId !== brush.pointerId) return;
    _barsBrushStop(false);
    if (event.type !== 'pointerup') return;
    _barsReleased = { host: brush.host, drew: brush.moved, pressed: brush.pressed };
    setTimeout(() => { _barsReleased = null; }, 0);
    if (brush.moved) brush.host.onRange(Math.min(brush.first, brush.last), Math.max(brush.first, brush.last), brush.bins);
}

// The context menu during a press: it ends as a cancelled one
function onBarsBrushCancel() {
    if (_barsBrush) _barsBrushStop(true);
}

// The press is over: no mark; its bars may be drawn again, and its host
// hears of it. `release` lets go of the pointer's capture of a press whose
// release the bars never got (on a release or a cancel the browser lets go
// of it, and the click of the release still goes to the bars)
function _barsBrushStop(release) {
    const brush = _barsBrush;
    _barsBrush = null;
    if (!brush) return;
    brush.svg.querySelector('.chart-brush')?.remove();
    const view = brush.view;
    if (view) {
        view.classList.remove('is-brushing');
        if (release && brush.moved) {
            try {
                view.releasePointerCapture(brush.pointerId);
            } catch (e) {
                // the browser let go of it already
            }
        }
    }
    if (typeof brush.host.onStop === 'function') brush.host.onStop();
}

// The mark of the range being drawn: over its bars, as high as the plot
function _barsBrushMark(brush) {
    const svg = brush.svg, slot = Number(svg.getAttribute('width')) / brush.bins.length;
    let mark = svg.querySelector('.chart-brush');
    if (!mark) {
        const plot = svg.querySelector('.chart-hit');
        mark = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
        mark.setAttribute('class', 'chart-selection chart-brush');
        mark.setAttribute('y', plot ? plot.getAttribute('y') : '0');
        mark.setAttribute('height', plot ? plot.getAttribute('height') : svg.getAttribute('height'));
        svg.appendChild(mark);
    }
    const first = Math.min(brush.first, brush.last), last = Math.max(brush.first, brush.last);
    mark.setAttribute('x', _chartCoord(first * slot));
    mark.setAttribute('width', _chartCoord((last - first + 1) * slot));
}

// The bar under the pointer at clientX: the first or the last beyond the ends
function _barsBinAt(svg, clientX, n) {
    const rect = svg.getBoundingClientRect(), width = Number(svg.getAttribute('width')) || rect.width;
    if (!(width > 0) || !(n > 0)) return 0;
    const x = (clientX - rect.left) * (rect.width > 0 ? width / rect.width : 1);
    return Math.min(n - 1, Math.max(0, Math.floor(x / (width / n))));
}

// =============================================
// ALERTS TAB
// =============================================
// Every alert of state.alerts in one table, newest first, filtered by
// severity, engine and text. The filters are the tab's controls themselves,
// so they outlast a re-render and a theme switch (same nodes). The charts
// filter further, by a time range, a category, a rule and a process
// (alertsExtraFilter); each of these shows as a chip in the filter bar,
// whose × takes it off. A click on a chart, and a range drawn across the
// bars of OVER TIME, is a step of a drilldown, which can be taken back
// (alertsDrilldown): the drilldown bar above the charts shows the steps,
// with BACK. A refresh re-renders the table only while the tab is open and
// only if what it shows changed; the place in the list stays unless the
// filters changed. The tab scrolls as a whole, the drilldown bar and the
// filter bar stand at its top.
const ALERTS_TAB_LIMIT = 2000;
const ALERT_SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
let _alertsTabShown = null;     // {alerts, processes, filterKey, chips, count} of the rendered table
// The filters of the charts: a time range in epoch ms (from included, to
// not), a category, a rule and a process; null = none
const alertsExtraFilter = { from: null, to: null, category: null, rule: null, process: null };

// Lower case, as the engines write "High" as well as "high"; an alert
// without a severity, with the server's default "unknown" (engines that
// have none) or with Sigma's level "informational" counts as info.
function alertSeverity(alert) {
    const severity = String(alert?.severity || '').toLowerCase();
    return !severity || severity === 'unknown' || severity === 'informational' ? 'info' : severity;
}

function alertRuleName(alert) {
    return String(alert?.rule_name || alert?.name || '');
}

// The process by name, else by the file name of its image ('' if neither is known)
function alertProcessName(alert) {
    const name = String(alert?.process_name || '').trim();
    return name || String(alert?.process_image || '').split(/[\\/]/).pop();
}

// filter = {severities: [...], engine, text, from, to, category, rule,
// process}; an empty list, text or name and a missing bound do not filter.
// Severity and engine are compared in any case; the text is searched in the
// rule, the process (name, PID) and the description. from / to are epoch ms,
// `from` included and `to` not, as the bins of a chart (binByTime), so a bar
// lists here exactly what it counted; an alert without a time is in no
// range. category is alertCategory's; rule and process are whole names in
// any case, the process as the table names it (alertProcessName), and
// "(unknown)", the charts' name for none, takes the alerts without one too.
function filterAlerts(alerts, filter) {
    filter = filter || {};
    const severities = new Set((filter.severities || []).map(s => String(s || '').toLowerCase()).filter(Boolean));
    const engine = String(filter.engine || '').toLowerCase();
    const text = String(filter.text || '').trim().toLowerCase();
    const from = _alertsTimeBound(filter.from), to = _alertsTimeBound(filter.to);
    const category = _alertsNameKey(filter.category);
    const rule = _alertsNameKey(filter.rule), proc = _alertsNameKey(filter.process);
    const matches = [];
    (alerts || []).forEach((alert, i) => {
        if (!alert) return;
        if (severities.size && !severities.has(alertSeverity(alert))) return;
        if (engine && String(alert.engine || '').toLowerCase() !== engine) return;
        if (category && alertCategory(alert) !== category) return;
        if (rule && !_alertNameIs(alertRuleName(alert), rule)) return;
        if (proc && !_alertNameIs(alertProcessName(alert), proc)) return;
        if (text && ![alertRuleName(alert), alertProcessName(alert), alert.pid, alert.rule_description]
            .some(value => String(value ?? '').toLowerCase().includes(text))) return;
        const time = Date.parse(alert.timestamp);
        // An alert without a time (NaN) fails both comparisons: it is in no range
        if ((from !== null || to !== null) && !(time >= (from ?? -Infinity) && time < (to ?? Infinity))) return;
        matches.push({ alert, time: Number.isNaN(time) ? -Infinity : time, i });
    });
    // Newest first by time, not by string (time zones differ); alerts without
    // a time last; the same time in reverse list order.
    matches.sort((a, b) => (b.time - a.time) || (b.i - a.i));
    return matches.map(m => m.alert);
}

// A bound of the time range in epoch ms, or null (none): a number, a Date or
// a number as text (a data-* attribute of a chart)
function _alertsTimeBound(value) {
    if (value instanceof Date) value = value.getTime();
    else if (typeof value === 'string' && value.trim()) value = Number(value);
    return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

// A category, rule or process name as the filters compare it: in lower case,
// without the blanks around it ('' = no filter)
function _alertsNameKey(name) {
    return String(name ?? '').trim().toLowerCase();
}

// Whether an alert's rule or process name is the one asked for (a name key);
// "(unknown)", the name the charts give alerts without one, also takes those
function _alertNameIs(name, wanted) {
    const key = _alertsNameKey(name);
    return key === wanted || (!key && wanted === '(unknown)');
}

// The `count` newest alerts, newest first, in the order of the Alerts tab.
// /api/alerts lists them oldest first, sorted by their text, which is not
// their order in time across time zones: neither end of it will do.
function newestAlerts(alerts, count) {
    return filterAlerts(alerts).slice(0, count);
}

// The engines for the engine choice: each once, whatever its case, in the
// spelling it first appears in.
function alertEngines(alerts) {
    const engines = new Map();
    for (const alert of alerts || []) {
        const engine = String(alert?.engine || '');
        if (engine && !engines.has(engine.toLowerCase())) engines.set(engine.toLowerCase(), engine);
    }
    return [...engines.values()].sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase()));
}

// Windows reuses PIDs, and an alert carries no instance key. The process list
// names the alerts of each instance by time and rule, which maps an alert to
// the instance it belongs to; alerts of processes not in the list have none.
function alertInstanceIndex(processes = state.processes) {
    const index = new Map();
    for (const [key, proc] of Object.entries(processes || {})) {
        for (const alert of proc?.alerts || []) index.set(_alertInstanceId(proc.pid ?? key, alert), key);
    }
    return index;
}

function _alertInstanceId(pid, alert) {
    return [pid, alert.timestamp ?? '', alert.rule_name ?? ''].join('|');
}

// Date and time: the list spans days
function formatAlertTime(ts) {
    const d = new Date(ts);
    if (ts === null || ts === undefined || ts === '' || Number.isNaN(d.getTime())) return String(ts ?? '');
    const p = n => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

// Table rows for alerts already filtered and sorted: the first ALERTS_TAB_LIMIT
// of them, under a note when there are more. A row opens the alert, the
// process its instance. Long texts are cut by CSS; the title has them in full.
function alertRowsHtml(alerts) {
    const index = alertInstanceIndex();
    const rows = alerts.slice(0, ALERTS_TAB_LIMIT).map(alert => {
        // Class and badge text alike: only [a-z0-9_-] (a severity can be anything)
        const sevClass = cssToken(alertSeverity(alert));
        const rule = alertRuleName(alert) || 'Unknown Rule';
        const desc = String(alert.rule_description || '');
        const name = alertProcessName(alert);
        const pid = alert.pid === null || alert.pid === undefined ? '' : String(alert.pid);
        const key = alert.key != null ? procKey(alert) : (pid ? index.get(_alertInstanceId(pid, alert)) : undefined);
        const label = name ? `${escapeHtml(name)}${pid ? ` <span class="alerts-proc-pid">${escapeHtml(pid)}</span>` : ''}`
            : pid ? `PID ${escapeHtml(pid)}` : '';
        const procTitle = [alert.process_image || name, pid ? `PID ${pid}` : '', key && key !== pid ? `instance ${key}` : '']
            .filter(Boolean).join(' · ');
        const proc = !label ? '<span class="muted">&mdash;</span>'
            : key ? `<a class="alerts-proc-link" onclick="event.stopPropagation(); openProcessDetail(${jsArg(key)})" title="${escapeHtml(procTitle)}">${label}</a>`
            : `<span title="${escapeHtml(procTitle ? procTitle + ' (not in the process list)' : 'Not in the process list')}">${label}</span>`;
        return `<tr class="alerts-row" onclick="openAlertDetailById(${jsArg(alert.id)})">`
            + `<td class="alerts-time" data-sort-value="${sortTimeValue(alert.timestamp)}" title="${escapeHtml(alert.timestamp || '')}">${escapeHtml(formatAlertTime(alert.timestamp))}</td>`
            + `<td class="alerts-sev" data-sort-value="${severitySortValue(sevClass)}"><span class="event-severity ${sevClass}">${sevClass || 'unknown'}</span></td>`
            + `<td class="alerts-engine">${escapeHtml(alert.engine || '')}</td>`
            + `<td class="alerts-rule" title="${escapeHtml(rule)}">${escapeHtml(rule)}</td>`
            + `<td class="alerts-proc">${proc}</td>`
            + `<td class="alerts-desc" title="${escapeHtml(desc)}">${escapeHtml(desc)}</td>`
            + '</tr>';
    });
    // The note keeps its place on top when the table is sorted (data-sort-skip)
    if (alerts.length > ALERTS_TAB_LIMIT) {
        rows.unshift(`<tr class="alerts-limit-row" data-sort-skip><td colspan="6">Showing newest ${ALERTS_TAB_LIMIT} of ${alerts.length}. Narrow the filters to reach older alerts.</td></tr>`);
    }
    return rows.join('');
}

// "All engines" and the engines of the alerts. A chosen engine that no alert
// has (yet) stays a choice, so the filter in effect is the one on screen.
function setAlertsEngineOptions(select, engines, chosen) {
    const wanted = String(chosen || '');
    const match = engines.find(e => e.toLowerCase() === wanted.toLowerCase());
    const names = wanted && !match ? [...engines, wanted] : engines;
    select.replaceChildren(...['', ...names].map(name => {
        const option = document.createElement('option');
        option.value = name;
        option.textContent = name || 'All engines';
        return option;
    }));
    select.value = match || wanted;
}

function alertsFilterFromControls() {
    return {
        severities: [...document.querySelectorAll('#tab-alerts .alerts-sev-chip')]
            .filter(chip => chip.getAttribute('aria-pressed') === 'true').map(chip => chip.dataset.severity),
        engine: document.getElementById('alerts-filter-engine')?.value || '',
        text: document.getElementById('alerts-filter-text')?.value || '',
        ..._alertsExtraOf(alertsExtraFilter),
    };
}

function renderAlertsTab() {
    const rows = document.getElementById('alerts-rows');
    if (!rows) return;
    const alerts = state.alerts || [];
    const engine = document.getElementById('alerts-filter-engine');
    const shown = _alertsTabShown;
    if (engine && (!shown || shown.alerts !== alerts)) setAlertsEngineOptions(engine, alertEngines(alerts), engine.value);
    const filter = alertsFilterFromControls();
    const filterKey = JSON.stringify([filter.severities, filter.engine.toLowerCase(), filter.text.trim().toLowerCase(),
        filter.from, filter.to, ...[filter.category, filter.rule, filter.process].map(_alertsNameKey)]);
    const chips = JSON.stringify(_alertsExtraOf(alertsExtraFilter));     // the chart filters as the chips show them
    // Nothing else to draw, but the path of the drilldown may be another all the same (the same jump twice)
    if (shown && shown.alerts === alerts && shown.processes === state.processes && shown.filterKey === filterKey
        && shown.chips === chips) {
        renderAlertsDrillBar(shown.count, alerts.length);
        return;
    }
    const matches = filterAlerts(alerts, filter);
    const tab = document.getElementById('tab-alerts');
    const scrollTop = tab ? tab.scrollTop : 0;
    // The charts count the same matches, drawn again only for other alerts or filters (not
    // for a new process list), and first: the layout they measure is still clean
    if (!shown || shown.alerts !== alerts || shown.filterKey !== filterKey) renderAlertsCharts(matches);
    rows.innerHTML = matches.length ? alertRowsHtml(matches)
        : `<tr class="alerts-empty-row" data-sort-skip><td colspan="6">${alerts.length ? 'No alerts match the filters.' : 'No alerts yet.'}</td></tr>`;
    // Re-rendered only when they changed: a chip in focus keeps it when new alerts arrive
    if (!shown || shown.chips !== chips) renderAlertsActiveFilters();
    // Before the place in the list is set: the list starts under the drilldown bar as it is now
    renderAlertsDrillBar(matches.length, alerts.length);
    // The same filters keep the place in the list. Other filters start at its
    // top: with the drilldown bar and the filter bar standing at the top of
    // the tab, the first row right under them, so the bars stay under the
    // pointer; above that, nothing moves.
    if (tab) tab.scrollTop = shown && shown.filterKey === filterKey ? scrollTop : Math.min(scrollTop, _alertsListTop(tab));
    const count = document.getElementById('alerts-count');
    if (count) count.textContent = `${matches.length} of ${alerts.length}`;
    _alertsTabShown = { alerts, processes: state.processes, filterKey, chips, count: matches.length };
}

// How far the tab is scrolled when its list starts at the top: the first row
// right under the filter bar and, while a step shows it, the drilldown bar,
// which then stand at the top of the tab
function _alertsListTop(tab) {
    const top = _tabListTop(tab, tab.querySelector('.alerts-filters'), document.getElementById('alerts-table-wrap'));
    const drillBar = document.getElementById('alerts-drill');
    return drillBar && !drillBar.hidden ? Math.max(0, top - drillBar.getBoundingClientRect().height) : top;
}

// How far a tab that scrolls as a whole is scrolled when `list` starts at
// its top: right under `bar`, the filter bar standing at the top of the tab
// (the Alerts and the Sysmon tab); 0 without them
function _tabListTop(tab, bar, list) {
    if (!bar || !list) return 0;
    const top = list.getBoundingClientRect().top - tab.getBoundingClientRect().top + tab.scrollTop;
    return Math.max(0, top - bar.getBoundingClientRect().height);
}

// The chart filters as chips in the filter bar, one each: "× 14 Jul – 20 Jul",
// "× category: registry", "× rule: …", "× process: …"; a click takes off that
// filter only. The row is hidden while there is none.
function renderAlertsActiveFilters() {
    const holder = document.getElementById('alerts-active-filters');
    if (!holder) return;
    const f = _alertsExtraOf(alertsExtraFilter);
    const chips = [];
    if (f.from !== null || f.to !== null) {
        const range = f.from === null ? `before ${formatAlertTime(f.to)}` : f.to === null ? `from ${formatAlertTime(f.from)}`
            : `${formatAlertTime(f.from)} – ${formatAlertTime(f.to)} (end not included)`;
        chips.push({ kind: 'range', value: chartRangeLabel(f.from, f.to), title: `Remove the time range ${range}` });
    }
    for (const kind of ['category', 'rule', 'process']) {
        if (f[kind] !== null) chips.push({ kind, name: kind, value: f[kind], title: `Remove the ${kind} filter: ${f[kind]}` });
    }
    holder.innerHTML = chips.map(chip => filterChipHtml(chip, `removeAlertsFilter(${jsArg(chip.kind)})`)).join('');
    holder.hidden = chips.length === 0;
}

// A chip of a filter that a chart set (the Alerts tab, the dashboard, the
// Sysmon tab): ×, its kind and its value as text; a click on it takes the
// filter off. `safe` is its click handler, the values in it through jsArg.
function filterChipHtml(chip, safe) {
    return `<button type="button" class="alerts-filter-chip"${chip.kind ? ` data-filter="${escapeHtml(chip.kind)}"` : ''} title="${escapeHtml(chip.title)}" aria-label="${escapeHtml(chip.title)}" onclick="${safe}">`
        + '<span class="alerts-filter-chip-x" aria-hidden="true">&times;</span> '
        + (chip.name ? `<span class="alerts-filter-chip-kind">${escapeHtml(chip.name)}:</span> ` : '')
        + `<span class="alerts-filter-chip-value">${escapeHtml(chip.value)}</span></button>`;
}

// The chart filters of `filter` as alertsExtraFilter keeps them: the bounds
// in epoch ms, the names without the blanks around them, null for none
function _alertsExtraOf(filter) {
    filter = filter || {};
    const name = value => String(value ?? '').trim() || null;
    return { from: _alertsTimeBound(filter.from), to: _alertsTimeBound(filter.to), category: name(filter.category),
             rule: name(filter.rule), process: name(filter.process) };
}

// Sets some of the chart filters and keeps the others, e.g.
// setAlertsFilters({rule: null}); null takes a filter off. This is no step
// of the drilldown, and the steps do not forget the filter: a click on a
// chart sets its filter with drillAlerts, the × of a chip with
// removeAlertsFilter.
function setAlertsFilters(changes) {
    Object.assign(alertsExtraFilter, _alertsExtraOf({ ...alertsExtraFilter, ...changes }));
    renderAlertsTab();
}

// The × of a chip ('range', 'category', 'rule' or 'process') takes off its
// filter by hand: the steps of the drilldown forget it before the tab is
// drawn. A chip in focus hands the focus on to the chip that takes its
// place, the search box after the last.
function removeAlertsFilter(kind) {
    const holder = document.getElementById('alerts-active-filters');
    const chips = () => (holder ? [...holder.querySelectorAll('.alerts-filter-chip')] : []);
    const focused = chips().indexOf(document.activeElement);
    forgetAlertsDrill([kind]);
    setAlertsFilters(kind === 'range' ? { from: null, to: null } : { [kind]: null });
    if (focused < 0) return;
    const left = chips();
    (left[Math.min(focused, left.length - 1)] || document.getElementById('alerts-filter-text'))?.focus();
}

// The drilldown bar stands at the top of the tab, the filter bar right under
// it, the table head under both; each bar grows with what it holds (the
// path, the chips) and when it wraps: --alerts-path-height on the tab (0 px
// while the bar is hidden) and --alerts-bar-height on the head (six cells,
// never rebuilt) follow their heights, border included. The bars and the
// Sankey above the filter bar are drawn for the width of their cards: again,
// in the next frame, when the width of the charts changes (the window, the
// theme, the tab shown again). OVER TIME takes a range drawn across its bars
// (ALERTS_BARS_BRUSH), with ResizeObserver or without.
function initAlertsTab() {
    initBarsBrush(ALERTS_BARS_BRUSH);
    if (typeof ResizeObserver === 'undefined') return;
    const tab = document.getElementById('tab-alerts'), drillBar = document.getElementById('alerts-drill');
    if (tab && drillBar) _followBarHeight(drillBar, tab, '--alerts-path-height');
    const bar = document.querySelector('#tab-alerts .alerts-filters');
    const head = document.querySelector('#alerts-table thead');
    if (bar && head) _followBarHeight(bar, head, '--alerts-bar-height');
    const charts = document.getElementById('alerts-charts');
    if (charts) new ResizeObserver(() => requestAnimationFrame(redrawAlertsChartsOnResize)).observe(charts);
}

// The height of a bar standing at the top of its tab (a filter bar, the
// drilldown bar of the Alerts tab), border included, as the variable `name`
// on `holder`, for what stands under the bar to stand right below it,
// whatever the bar's height (chips, wrapping; 0 while it is hidden)
function _followBarHeight(bar, holder, name) {
    new ResizeObserver(() => holder.style.setProperty(name, `${bar.getBoundingClientRect().height}px`))
        .observe(bar, { box: 'border-box' });
}

// A chip of the filter bar switches its severity on or off, by hand: the
// steps of the drilldown forget the severities before the tab is drawn
function toggleAlertsSeverity(severity) {
    const chip = document.querySelector(`#tab-alerts .alerts-sev-chip[data-severity="${cssToken(severity)}"]`);
    if (!chip) return;
    chip.setAttribute('aria-pressed', String(chip.getAttribute('aria-pressed') !== 'true'));
    forgetAlertsDrill(['severities']);
    renderAlertsTab();
}

// A slice or a legend row of SEVERITY shows the alerts of its severity alone,
// a step of the drilldown: its chip pressed, the others not; no step when it
// is the only one pressed already (a click that let go of it would show
// every severity)
function selectAlertsSeverity(severity) {
    const chip = [...document.querySelectorAll('#tab-alerts .alerts-sev-chip')].find(c => c.dataset.severity === severity);
    if (chip) drillAlerts({ severities: [severity] });
}

// The search renders once typing pauses: a full table takes about 0.1 s to
// lay out, which made every keystroke lag.
let _alertsRenderTimer = null;

function scheduleAlertsRender() {
    clearTimeout(_alertsRenderTimer);
    _alertsRenderTimer = setTimeout(renderAlertsTab, 200);
}

// Opens the Alerts tab with exactly these filters (others cleared, the search
// too unless `text` is given), e.g. openAlertsTab({severities: ['critical',
// 'high']}), or from a chart openAlertsTab({category: 'registry', from, to});
// no filter shows every alert. The jump starts a new drilldown: one step of
// the filters it set, from none (BACK then shows every alert), also when it
// changes nothing; no step without a filter. The tab opens at its top, the
// charts and the filters in view.
function openAlertsTab(filter) {
    filter = filter || {};
    const none = Object.fromEntries(ALERTS_DRILL_KINDS.map(kind => [kind, _alertsDrillNone(kind)]));
    _setAlertsDrillValues({ ...none, ..._alertsDrillOf(filter, none) });
    const text = document.getElementById('alerts-filter-text');
    if (text) text.value = String(filter.text || '');
    const after = alertsDrillValues();
    const kinds = ALERTS_DRILL_KINDS.filter(kind => !_alertsDrillSame(kind, none[kind], after[kind]));
    alertsDrilldown.length = 0;
    if (kinds.length) alertsDrilldown.push(_alertsDrillStep(true, none, after, kinds));
    alertsDrillVersion++;
    switchTab('alerts');
    const tab = document.getElementById('tab-alerts');
    if (tab) tab.scrollTop = 0;
}

// --- The drilldown: the steps that narrowed the tab ---
// A click on a chart that changes the filters, a range drawn across OVER
// TIME and a jump from the dashboard that sets a filter are steps:
// {dashboard, before, after}, the kinds of filter the step changed (of
// ALERTS_DRILL_KINDS) with their values before and after it, as
// alertsDrillValues gives them. BACK and a jump to a step set the values
// before the later steps again, the newest first, and nothing else: not the
// search, nor a filter of another kind. What is set by hand in the filter
// bar (a severity chip, the engine choice, the × of a chip) is no step; the
// steps forget its kind, a step left without one drops out, so the path
// names only what is in effect and BACK never undoes a setting of one's
// own. The steps last until the page is reloaded, as the filters do.
const ALERTS_DRILL_KINDS = ['range', 'severities', 'engine', 'category', 'rule', 'process'];
// The steps, the oldest first
const alertsDrilldown = [];
// Counts the changes of the steps: what shows the path draws it again when
// this changed, also when the filters did not (the same jump twice)
let alertsDrillVersion = 0;
// The drilldown bar shows ALL ALERTS, the last ALERTS_DRILL_VISIBLE steps
// and, before them, the older ones together as "…"
const ALERTS_DRILL_VISIBLE = 3;
// The version of the steps the path of the bar was drawn for (null: none)
let _alertsDrillDrawn = null;

// The filters as the steps hold them: the time range {from, to}, the
// severities pressed (in the order of ALERT_SEVERITIES), the engine chosen
// ('' for all) and the category, rule and process (null for none)
function alertsDrillValues() {
    const f = alertsFilterFromControls();
    return { range: { from: f.from, to: f.to }, severities: ALERT_SEVERITIES.filter(s => f.severities.includes(s)),
             engine: f.engine, category: f.category, rule: f.rule, process: f.process };
}

// A step: sets the filters of `change` (filterAlerts' fields {from, to},
// {severities}, {engine}, {category}, {rule}, {process}, or several; a field
// left out keeps its filter) and draws the tab. The step holds the kinds the
// change changed, compared as the filters compare them: a range by both
// bounds, the severities as a set, the engine and the names in any case and
// without blanks around them. A change that changes none is no step and
// sets nothing: false.
function drillAlerts(change) {
    const before = alertsDrillValues(), wanted = _alertsDrillOf(change || {}, before);
    const kinds = ALERTS_DRILL_KINDS.filter(kind => kind in wanted && !_alertsDrillSame(kind, before[kind], wanted[kind]));
    if (!kinds.length) return false;
    _setAlertsDrillValues(Object.fromEntries(kinds.map(kind => [kind, wanted[kind]])));
    alertsDrilldown.push(_alertsDrillStep(false, before, alertsDrillValues(), kinds));
    alertsDrillVersion++;
    renderAlertsTab();
    return true;
}

// BACK: the last step taken back
function alertsDrillBack() {
    alertsDrillTo(alertsDrilldown.length - 2);
}

// A jump to the step numbered `index` (-1: to before the first): the steps
// after it are taken back, the newest first, each setting the values before
// it again; then the tab is drawn. Nothing to take back, nothing happens.
function alertsDrillTo(index) {
    const keep = Math.max(0, Math.floor(index) + 1);
    if (!(alertsDrilldown.length > keep)) return;
    while (alertsDrilldown.length > keep) _setAlertsDrillValues(alertsDrilldown.pop().before);
    alertsDrillVersion++;
    renderAlertsTab();
}

// Filters set by hand: the steps forget these kinds (names of
// ALERTS_DRILL_KINDS), a step left without a kind drops out
function forgetAlertsDrill(kinds) {
    const forget = new Set([].concat(kinds));
    if (!alertsDrilldown.some(step => Object.keys(step.after).some(kind => forget.has(kind)))) return;
    const left = alertsDrilldown.map(step => _alertsDrillStep(step.dashboard, step.before, step.after,
                                                              Object.keys(step.after).filter(kind => !forget.has(kind))));
    alertsDrilldown.splice(0, alertsDrilldown.length, ...left.filter(step => Object.keys(step.after).length));
    alertsDrillVersion++;
}

// The name of a step, as text: its kinds in the order of ALERTS_DRILL_KINDS
// joined by " · ", a range as its chip names it, the severities in capitals
// joined by " + ", the engine by its name, the others as "category: …",
// "rule: …", "process: …"; a jump from the dashboard begins "Dashboard: "
function alertsStepLabel(step) {
    const after = step?.after || {};
    const names = ALERTS_DRILL_KINDS.filter(kind => kind in after).map(kind => {
        const value = after[kind];
        if (kind === 'range') return chartRangeLabel(value.from, value.to);
        if (kind === 'severities') return value.map(s => s.toUpperCase()).join(' + ');
        return kind === 'engine' ? value : `${kind}: ${value ?? ''}`;
    });
    return (step?.dashboard ? 'Dashboard: ' : '') + names.join(' · ');
}

// The engine chosen by hand in the filter bar: the steps forget the engine
// before the tab is drawn
function onAlertsEngineChange() {
    forgetAlertsDrill(['engine']);
    renderAlertsTab();
}

// The value of a kind of filter that filters nothing
function _alertsDrillNone(kind) {
    return kind === 'range' ? { from: null, to: null } : kind === 'severities' ? [] : kind === 'engine' ? '' : null;
}

// Whether two values of a kind of filter filter alike: a range by both
// bounds, severities as a set, the engine and the names as the filters
// compare them (_alertsNameKey)
function _alertsDrillSame(kind, a, b) {
    if (kind === 'range') return a.from === b.from && a.to === b.to;
    if (kind === 'severities') {
        const x = new Set(a), y = new Set(b);
        return x.size === y.size && [...x].every(s => y.has(s));
    }
    return _alertsNameKey(a) === _alertsNameKey(b);
}

// The values of the kinds of filter `change` sets (drillAlerts' fields; one
// left out or undefined sets nothing), as alertsDrillValues gives them: the
// severities only those of a chip, the engine without the blanks around it
// (as the names), a range with a bound it is not given from `current`
function _alertsDrillOf(change, current) {
    const given = field => change[field] !== undefined;
    const extra = _alertsExtraOf(change), values = {};
    if (given('from') || given('to')) {
        values.range = { from: given('from') ? extra.from : current.range.from, to: given('to') ? extra.to : current.range.to };
    }
    if (given('severities')) {
        const wanted = new Set((change.severities || []).map(s => String(s || '').toLowerCase()));
        values.severities = ALERT_SEVERITIES.filter(s => wanted.has(s));
    }
    if (given('engine')) values.engine = String(change.engine ?? '').trim();
    for (const kind of ['category', 'rule', 'process']) if (given(kind)) values[kind] = extra[kind];
    return values;
}

// Sets the filters of the kinds in `values` (alertsDrillValues' form) and
// leaves the others and the search as they are; draws nothing. Not through
// the handlers of the filter bar, which would make the steps forget them.
// The engine takes the spelling the engine choice offers.
function _setAlertsDrillValues(values) {
    if ('severities' in values) {
        const pressed = new Set(values.severities);
        document.querySelectorAll('#tab-alerts .alerts-sev-chip').forEach(chip =>
            chip.setAttribute('aria-pressed', String(pressed.has(chip.dataset.severity))));
    }
    const select = document.getElementById('alerts-filter-engine');
    if ('engine' in values && select) setAlertsEngineOptions(select, alertEngines(state.alerts), values.engine);
    const extra = { ...alertsExtraFilter, ...('range' in values ? values.range : {}) };
    for (const kind of ['category', 'rule', 'process']) if (kind in values) extra[kind] = values[kind];
    Object.assign(alertsExtraFilter, _alertsExtraOf(extra));
}

// A step of these kinds of filter, with their values before and after it
function _alertsDrillStep(dashboard, before, after, kinds) {
    const pick = values => Object.fromEntries(kinds.map(kind => [kind, values[kind]]));
    return { dashboard, before: pick(before), after: pick(after) };
}

// --- The drilldown bar: BACK and the path above the charts ---
// The bar (#alerts-drill) while a step narrows the tab, hidden without one:
// ‹ BACK, DRILLDOWN, the path of the steps and the count of the table,
// `shown` of `total` alerts (renderAlertsTab, after each drawing). The path
// is drawn again only when the steps changed (alertsDrillVersion), so new
// alerts leave a step in focus as it is; a step in focus drawn anew hands
// the focus to BACK. With the path, BACK's title and its name for screen
// readers say where it goes, as text: "Back to" the step before the last,
// "Back to all alerts" from the only one. A bar that goes with the focus in
// it hands a focus of the keyboard on to the search box; after a click of
// the mouse the focus stays where the browser leaves it (the search box
// would light up, a touch screen open its keyboard).
function renderAlertsDrillBar(shown, total) {
    const bar = document.getElementById('alerts-drill');
    if (!bar) return;
    const path = document.getElementById('alerts-drill-path'), count = document.getElementById('alerts-drill-count');
    const back = bar.querySelector('[data-drill="back"]');
    const focus = document.activeElement;
    const inBar = !!focus && bar.contains(focus);
    // Asked before the path is drawn anew: a step taken out of the page is no longer focused
    const byKeyboard = inBar && _focusFromKeyboard(focus);
    let lost = false;
    if (path && _alertsDrillDrawn !== alertsDrillVersion) {
        lost = inBar && path.contains(focus);
        path.innerHTML = alertsDrilldown.length ? _alertsDrillPathHtml(alertsDrilldown) : '';
        const before = alertsDrilldown[alertsDrilldown.length - 2];
        const where = `Back to ${before ? alertsStepLabel(before) : 'all alerts'}`;
        back?.setAttribute('title', where);
        back?.setAttribute('aria-label', where);
        _alertsDrillDrawn = alertsDrillVersion;
    }
    const text = `${_chartNumber(shown)} of ${_chartNumber(total)} alerts`;
    if (count && count.textContent !== text) count.textContent = text;
    bar.hidden = !alertsDrilldown.length;
    if (inBar && bar.hidden) {
        if (byKeyboard) document.getElementById('alerts-filter-text')?.focus();
    } else if (lost) back?.focus();
}

// Whether the focus on `el` came from the keyboard (it matches
// :focus-visible). A browser that does not know the selector counts as the
// keyboard, so a keyboard user is not left without the focus.
function _focusFromKeyboard(el) {
    try {
        return el.matches(':focus-visible');
    } catch (e) {
        return true;
    }
}

// The path of the drilldown bar: ALL ALERTS, the steps before the last
// ALERTS_DRILL_VISIBLE together as "…" (its title names them, and so does a
// text for screen readers only in it), then those; each a button that jumps
// back to it (data-drill-step: its number, -1 for ALL ALERTS) but the last,
// the current step; › between them. The names as text, each in full in its
// title (a long one is cut by CSS).
function _alertsDrillPathHtml(steps) {
    const labels = steps.map(alertsStepLabel);
    const first = Math.max(0, labels.length - ALERTS_DRILL_VISIBLE);
    const parts = ['<button type="button" class="alerts-drill-step" data-drill-step="-1">ALL ALERTS</button>'];
    if (first > 0) {
        const folded = escapeHtml(labels.slice(0, first).join(' › '));
        parts.push(`<span class="alerts-drill-more" title="${folded}">…<span class="visually-hidden">${folded}</span></span>`);
    }
    for (let i = first; i < labels.length; i++) {
        const name = escapeHtml(labels[i]);
        parts.push(i === labels.length - 1
            ? `<span class="alerts-drill-step is-current" aria-current="step" title="${name}">${name}</span>`
            : `<button type="button" class="alerts-drill-step" data-drill-step="${i}" title="${name}">${name}</button>`);
    }
    return parts.join('<span class="alerts-drill-sep" aria-hidden="true">›</span>');
}

// A click in the drilldown bar, its one handler: BACK takes the last step
// back, a step of the path jumps back to it (its number from data-drill-step,
// -1 for ALL ALERTS); anything else (›, DRILLDOWN, "…", the current step,
// the count) does nothing
function onAlertsDrillClick(event) {
    const target = event && event.target;
    if (!target || typeof target.closest !== 'function') return;
    if (target.closest('[data-drill="back"]')) {
        alertsDrillBack();
        return;
    }
    const step = target.closest('[data-drill-step]');
    if (step) alertsDrillTo(Number(step.getAttribute('data-drill-step')));
}

// --- The charts of the Alerts tab ---
// Above the filter bar: SEVERITY and ENGINE as pies beside their legends,
// OVER TIME (twice as wide) as bars per hour, day or week (seconds or
// minutes for a span of up to 20 hours) stacked by severity, below them
// FLOW, a Sankey engine → rule → process. They count the alerts the filters
// let through, every one (the table shows the newest 2000); an alert without
// a time is in no bar, a note under the bars counts those. A click sets the
// filter of the part clicked (onAlertsChartClick), and a range drawn across
// the bars of OVER TIME their period (ALERTS_BARS_BRUSH), so the table then
// lists what the parts counted. Each card shows its numbers as a table on
// request (CHART / TABLE).
// The Sankey by square roots (small flows stay visible) or, with LINEAR, in
// true proportions, until the page is reloaded
const alertsFlowView = { linear: false };
// What the bars and the Sankey on screen were drawn from, and for which widths:
// a resize or LINEAR draws them again without counting again; timeHeld: the
// bars of OVER TIME are still to be drawn from it (a press on them held them)
let _alertsChartsDrawn = null;
// OVER TIME takes a range drawn across its bars (initBarsBrush), a step of
// the drilldown (_drillAlertsBars). While a press on the bars lasts they are
// not drawn; once it is over they are, if that was put off (_drawAlertsTimeHeld).
// While they are held back so, the bars on screen are not those counted: a
// press on them then begins nothing (no bins).
const ALERTS_BARS_BRUSH = {
    view: 'alerts-time-chart',
    bins: () => (_alertsChartsDrawn && !_alertsChartsDrawn.timeHeld ? _alertsChartsDrawn.time.bins : []),
    onRange: (first, last, bins) => _drillAlertsBars(bins.slice(first, last + 1)),
    onStop: () => setTimeout(_drawAlertsTimeHeld, 0),
};
// The first time an alert or a Sysmon event can plausibly have: one of a
// clock set to 1970 (or a FILETIME of 0, 1601) would squeeze every other bar
// into one
const ALERT_TIME_MIN = Date.UTC(2000, 0, 1);

// Draws the four charts of the alerts of the filters (filterAlerts' list);
// renderAlertsTab calls it when the alerts or the filters changed
function renderAlertsCharts(matches) {
    if (!document.getElementById('alerts-charts')) return;
    for (const id of ['alerts-severity', 'alerts-time', 'alerts-engine', 'alerts-flow']) {
        // Written once: a refresh keeps the switch (and the keyboard focus on it)
        const slot = document.getElementById(`${id}-toggle`);
        if (slot && !slot.firstElementChild) slot.innerHTML = viewToggleHtml(id);
    }
    const list = (matches || []).filter(Boolean);
    // Measured before anything is written, while the layout is still clean
    const widths = _alertsChartWidths();
    const empty = list.length ? '' : (state.alerts || []).length ? 'No alerts match the filters' : 'No alerts yet';
    const engines = alertsEngineItems(list);
    _drawAlertsPie('severity', alertsSeverityItems(list), empty);
    _drawAlertsPie('engine', engines, empty);
    // The bars span the time range of the filters, when one is set; a span of
    // up to 20 hours takes seconds or minutes, so a narrowed range shows detail
    const range = _alertsExtraOf(alertsExtraFilter);
    const time = alertSeverityBins(list, { from: range.from, to: range.to, fine: true });
    const flow = alertFlow(list, { top: 6, names: state.alerts });
    flow.colors = _alertsFlowColors(flow, engines);
    _alertsChartsDrawn = { widths, empty, time, flow };
    _drawAlertsTime(_alertsChartsDrawn);
    _drawAlertsFlow(_alertsChartsDrawn);
}

// The slices of SEVERITY: the alerts per severity as the table reads it (in
// any case; none, "unknown" and "informational" are info), critical first. A
// severity of another name ("warning", say) comes after them, muted: no chip
// filters by it.
function alertsSeverityItems(matches) {
    const rank = key => (SEVERITY_ORDER.includes(key) ? SEVERITY_ORDER.indexOf(key) : SEVERITY_ORDER.length);
    return countBy(matches, alertSeverity).sort((a, b) => rank(a.key) - rank(b.key)).map(({ key, count }) => ({
        key, label: key.toUpperCase(), value: count, color: _alertsSeverityColor(key),
    }));
}

// A severity's colour in SEVERITY and OVER TIME alike: its own for the five of
// the chips, muted for any other
function _alertsSeverityColor(key) {
    return SEVERITY_ORDER.includes(key) ? SEVERITY_COLORS[key] : 'var(--text-muted)';
}

// The slices of ENGINE: the alerts per engine in any case, as the engine
// choice compares them. Name and colour come from every alert, not only those
// of the filters (the first spelling, the colour of its rank), so neither
// changes with a filter. Alerts without an engine are "(unknown)", which the
// engine choice cannot name.
function alertsEngineItems(matches) {
    const keyOf = alert => String(alert?.engine || '').toLowerCase();
    const all = (state.alerts || []).filter(Boolean);
    const spelling = new Map();
    for (const alert of all) {
        if (!spelling.has(keyOf(alert))) spelling.set(keyOf(alert), String(alert.engine || ''));
    }
    const rank = new Map(countBy(all, keyOf).map(({ key }, i) => [key, i]));
    return countBy(matches, keyOf).map(({ key, count }) => ({
        key, label: spelling.get(key) || key || '(unknown)', value: count,
        color: CHART_PALETTE[(rank.has(key) ? rank.get(key) : rank.size) % CHART_PALETTE.length],
    }));
}

// SEVERITY or ENGINE: the pie beside its legend (or the hint) and the table view
function _drawAlertsPie(kind, items, empty) {
    _drawShareChart(`alerts-${kind}`, kind, items, empty, empty ? '' : pieSvg(items, { size: 120 }),
        kind === 'severity' ? '<table class="view-table" data-sortable data-sort-id="alerts-severity">'
            : '<table class="view-table" data-sortable data-sort-id="alerts-engine">');
}

// A pie or a donut (`chart`, its markup) beside its legend in #<id>-chart,
// or the hint; the parts a click sets no filter for marked: a severity no
// chip names, the slice without a key (alerts without an engine, "other
// categories"). The table view in #<id>-table, `table` its <table> tag.
function _drawShareChart(id, kind, items, empty, chart, table) {
    const view = document.getElementById(`${id}-chart`), tableView = document.getElementById(`${id}-table`);
    if (view) {
        view.innerHTML = chart ? `<div class="chart-split">${chart}${chartLegendHtml(items)}</div>` : chartEmptyHtml(empty || 'No alerts');
        _alertsChartInert(view, '[data-key]', el => {
            const key = el.getAttribute('data-key');
            return kind === 'severity' ? !ALERT_SEVERITIES.includes(key) : !key;
        });
    }
    if (tableView) tableView.innerHTML = _alertsShareTableHtml(kind, items, empty, table);
}

// The table view of a pie or a donut of `kind` (severity, engine, category,
// activity: ACTIVITY MIX of the graph detail), `table` its <table> tag: the
// count and share of each slice
function _alertsShareTableHtml(kind, items, empty, table) {
    const total = items.reduce((sum, item) => sum + item.value, 0);
    const rows = empty ? [] : items.map((item, i) => {
        // A severity without a chip in neutral grey: cssToken("High!") would give it the colour of high
        const name = kind === 'severity'
            ? `<td data-sort-value="${severitySortValue(item.key)}"><span class="event-severity ${ALERT_SEVERITIES.includes(item.key) ? cssToken(item.key) : ''}">${escapeHtml(item.key)}</span></td>`
            : `<td class="view-table-text" title="${escapeHtml(item.label)}"><span class="view-table-dot" style="background:${_chartColor(item.color, i)}"></span>${escapeHtml(item.label)}</td>`;
        return `<tr>${name}<td class="view-table-num" data-sort-value="${item.value}">${_chartNumber(item.value)}</td>`
            + `<td class="view-table-num" data-sort-value="${total ? item.value / total : 0}">${escapeHtml(_chartShare(item.value, total))}</td></tr>`;
    });
    if (!rows.length) rows.push(`<tr data-sort-skip><td colspan="3" class="view-table-empty">${escapeHtml(empty || 'No alerts')}.</td></tr>`);
    const head = { severity: 'Severity', engine: 'Engine', category: 'Category', activity: 'Kind' }[kind] || 'Name';
    return `${table}<thead><tr><th>${head}</th><th class="view-table-num">Count</th><th class="view-table-num">Share</th></tr></thead>`
        + `<tbody>${rows.join('')}</tbody></table>`;
}

// The items per period of binByTime, and those in no bar: untimed (without a
// readable timestamp) and implausible (with a time no clock can have had:
// before 2000, a day or more from now). opts as binByTime's (key(item),
// keys, from, to, fine); without `to` the bins reach at least to `until`
// (the end of a range that runs up to now). The bins never reach past the
// plausible times, so a bin's start and end select exactly the items it
// counts. The Alerts tab, the dashboard and the Sysmon tab count with it.
function chartTimeBins(items, opts) {
    opts = opts || {};
    const latest = (Number.isFinite(opts.now) ? opts.now : Date.now()) + 86400000;
    const timed = [];
    let untimed = 0, implausible = 0, last = -Infinity;
    for (const item of items || []) {
        if (!item) continue;
        const t = Date.parse(item.timestamp);
        if (Number.isNaN(t)) untimed++;
        else if (t < ALERT_TIME_MIN || t >= latest) implausible++;
        else {
            timed.push([t, item]);
            last = Math.max(last, t);
        }
    }
    const key = typeof opts.key === 'function' ? opts.key : null;
    const to = Number.isFinite(opts.to) ? opts.to : Number.isFinite(opts.until) ? Math.max(opts.until, last + 1) : undefined;
    const time = binByTime(timed, { time: pair => pair[0], key: key && (pair => key(pair[1])), keys: opts.keys,
                                    from: opts.from, to, fine: opts.fine });
    const head = time.bins[0], tail = time.bins[time.bins.length - 1];
    if (head && head.start < ALERT_TIME_MIN && head.end > ALERT_TIME_MIN) head.start = ALERT_TIME_MIN;
    if (tail && tail.end > latest && tail.start < latest) tail.end = latest;
    return { ...time, untimed, implausible };
}

// The alerts per hour, day or week stacked by severity, for OVER TIME and
// ALERT ACTIVITY: chartTimeBins' {unit, bins, untimed, implausible} (opts:
// from, to, until, now; fine for OVER TIME: a short span in seconds or
// minutes, with their step)
function alertSeverityBins(alerts, opts) {
    return chartTimeBins(alerts, { ...opts, key: alertSeverity, keys: SEVERITY_ORDER });
}

// The note of the alerts in no bar: "12 without time · 1 with implausible time" ('' for none)
function _alertsTimeNote(time) {
    return [time.untimed > 0 ? `${_chartNumber(time.untimed)} without time` : '',
            time.implausible > 0 ? `${_chartNumber(time.implausible)} with implausible time` : ''].filter(Boolean).join(' · ');
}

// Bars of alertSeverityBins (opts: width, height, selection), each severity
// in its colour of SEVERITY, one no chip names muted as there; labelled by
// the unit and step they were counted in
function _alertsTimeBarsSvg(time, opts) {
    const colors = Object.create(null);         // keys from the data: none may be special (__proto__)
    for (const bin of time.bins) Object.keys(bin.counts).forEach(key => { colors[key] = _alertsSeverityColor(key); });
    return stackedBarsSvg(time.bins, { ...opts, keys: SEVERITY_ORDER, colors, unit: time.unit, step: time.step });
}

// OVER TIME from what renderAlertsCharts counted: the bars for the width of
// their card, a bar without alerts marked (it sets no range); on the line
// under them how to use them (as under ALERT ACTIVITY), then the note of the
// alerts in no bar. The bars leave room for that line, so the card keeps the
// height of the pies beside it. The table view. Nothing while a press on the
// bars lasts (a range may be drawn across them): drawn.timeHeld, and they are
// drawn after its end (_drawAlertsTimeHeld).
function _drawAlertsTime(drawn) {
    drawn.timeHeld = barsBrushActive(ALERTS_BARS_BRUSH);
    if (drawn.timeHeld) return;
    const view = document.getElementById('alerts-time-chart'), table = document.getElementById('alerts-time-table');
    const svg = drawn.empty ? '' : _alertsTimeBarsSvg(drawn.time, { width: drawn.widths.time || 560, height: 104 });
    const missed = _alertsTimeNote(drawn.time);
    // The hint breaks after its "·" on a narrow card, not inside a phrase
    const line = (svg ? '<span class="alerts-time-hint"><span>Drag across the bars to narrow the range ·</span> <span>click a bar to show only its period</span></span>' : '')
        + (missed ? '<span class="alerts-time-missed" title="Alerts without a readable time or with one no clock can have had (before 2000, more than a day ahead) are in no bar; SEVERITY, ENGINE and FLOW count them">'
                    + `${escapeHtml(missed)}</span>` : '');
    if (view) {
        view.innerHTML = (svg || chartEmptyHtml(drawn.empty || 'No alerts with a time')) + (line ? `<div class="alerts-chart-note">${line}</div>` : '');
        _alertsChartInert(view, '[data-bin-start]', el => !(Number(el.getAttribute('data-total')) > 0));
    }
    if (table) table.innerHTML = _alertsTimeTableHtml(drawn.time, drawn.empty, '<table class="view-table" data-sortable data-sort-id="alerts-time">');
}

// After a press on the bars of OVER TIME (ALERTS_BARS_BRUSH), once the task
// of its end is over: the bars as renderAlertsCharts counted them last, if
// they were not drawn while it lasted (new alerts, another width). Not within
// that task: Chrome sends the click of the release only to a bar still on
// the page, and the step of that click draws them anyway.
function _drawAlertsTimeHeld() {
    if (_alertsChartsDrawn && _alertsChartsDrawn.timeHeld) _drawAlertsTime(_alertsChartsDrawn);
}

// The table view of bars of alertSeverityBins, `table` its <table> tag: each
// period with alerts by severity and its total, then the severities no chip
// names together as "Other" (a column only when there are some, after the
// total, so a sorted column keeps its place), so a row adds up to its total;
// the alerts in no bar in rows at the end
function _alertsTimeTableHtml(time, empty, table) {
    const others = bin => Object.keys(bin.counts).filter(key => !SEVERITY_ORDER.includes(key) && bin.counts[key] > 0);
    const other = time.bins.some(bin => bin.total > 0 && others(bin).length);
    return _timeBinsTableHtml(time, [
        ...SEVERITY_ORDER.map(s => ({ head: `${s[0].toUpperCase()}${s.slice(1)}`, count: bin => bin.counts[s] || 0 })),
        { head: 'Total', count: bin => bin.total },
        ...(other ? [{ head: 'Other', title: 'Severities no filter chip names',
                       count: bin => others(bin).reduce((sum, key) => sum + bin.counts[key], 0),
                       cellTitle: bin => others(bin).map(key => `${key}: ${_chartNumber(bin.counts[key])}`).join(', ') }] : []),
    ], empty || 'No alerts with a time', table);
}

// The table view of bars of chartTimeBins, `table` its <table> tag: a row
// per period with items, a cell per column [{head, title, count(bin),
// cellTitle(bin)}] after the period, the items in no bar in rows at the end;
// `empty` the only row without any
function _timeBinsTableHtml(time, columns, empty, table) {
    const cell = (n, title) => `<td class="view-table-num" data-sort-value="${n}"${title ? ` title="${escapeHtml(title)}"` : ''}>${_chartNumber(n)}</td>`;
    const cols = columns.length + 1;
    const rows = time.bins.filter(bin => bin.total > 0).map(bin =>
        `<tr><td data-sort-value="${bin.start}">${escapeHtml(_chartPeriodLabel(bin.start, bin.end, time.unit))}</td>`
        + columns.map(column => cell(column.count(bin), column.cellTitle ? column.cellTitle(bin) : '')).join('') + '</tr>');
    for (const [n, what] of [[time.untimed, 'without time'], [time.implausible, 'with implausible time']]) {
        if (n > 0) rows.push(`<tr data-sort-skip><td colspan="${cols}" class="view-table-empty">${_chartNumber(n)} ${what}</td></tr>`);
    }
    if (!rows.length) rows.push(`<tr data-sort-skip><td colspan="${cols}" class="view-table-empty">${escapeHtml(_chartSentence(empty))}</td></tr>`);
    return `${table}<thead><tr><th>Period</th>`
        + columns.map(column => `<th class="view-table-num"${column.title ? ` title="${escapeHtml(column.title)}"` : ''}>${escapeHtml(column.head)}</th>`).join('')
        + `</tr></thead><tbody>${rows.join('')}</tbody></table>`;
}

// FLOW from what renderAlertsCharts counted: the Sankey for the width of its
// card, as high as its fullest column needs, by square roots or in true
// proportions (LINEAR); the parts a click sets nothing for marked; the table view
function _drawAlertsFlow(drawn) {
    const view = document.getElementById('alerts-flow-chart'), table = document.getElementById('alerts-flow-table');
    const { flow } = drawn;
    const nodes = Math.max(0, ...flow.columns.map(column => column.length));
    const layout = layoutSankey(flow.columns, flow.links, { width: drawn.widths.flow || 720,
        height: Math.min(340, Math.max(120, 40 * nodes + 20)), scale: alertsFlowView.linear ? 'linear' : 'sqrt' });
    if (view) {
        view.innerHTML = sankeySvg(layout, { labels: flow.labels, colors: flow.colors }) || chartEmptyHtml(drawn.empty || 'No alerts');
        _flowInert(view, _alertsFlowFilter);
    }
    if (table) table.innerHTML = _alertsFlowTableHtml(flow, drawn.empty);
}

// Marks the parts of a Sankey a click sets no filter for (filterOf(id) gives
// {} for its node): such a node, and a band with such an end, which would
// list more items than it carries
function _flowInert(view, filterOf) {
    const sets = id => Object.keys(filterOf(id)).length > 0;
    _alertsChartInert(view, '[data-sankey-node]', el => !sets(el.getAttribute('data-sankey-node')));
    _alertsChartInert(view, '[data-sankey-link]', el => !sets(el.getAttribute('data-source')) || !sets(el.getAttribute('data-target')));
}

// The filter a click on a Sankey sets: that of its node, or of both ends of
// its band (filterOf as _flowInert's); null where the click stands for none
function _flowClickFilter(target, filterOf) {
    const band = target.closest('[data-sankey-link]'), node = target.closest('[data-sankey-node]');
    const ends = (band ? [band.getAttribute('data-source'), band.getAttribute('data-target')]
        : node ? [node.getAttribute('data-sankey-node')] : []).map(filterOf);
    return ends.length && ends.every(end => Object.keys(end).length) ? Object.assign({}, ...ends) : null;
}

// The table view of FLOW: each band with its two ends and its alerts, the
// bands from the engines first, the largest first
function _alertsFlowTableHtml(flow, empty) {
    return _flowTableHtml(flow, empty || 'No alerts', '<table class="view-table" data-sortable data-sort-id="alerts-flow">',
                          ['Source', 'Target']);
}

// The table view of a Sankey of _chartFlow, `table` its <table> tag, `heads`
// those of the two ends: each band with its ends and its count, the bands of
// the first column first, the largest first; `empty` the only row without any
function _flowTableHtml(flow, empty, table, heads) {
    const label = id => escapeHtml(flow.labels[id] ?? id);
    const step = new Map(flow.columns.flatMap((column, c) => column.map(id => [id, c])));
    const rows = [...flow.links].sort((a, b) => (step.get(a.source) - step.get(b.source)) || (b.value - a.value)).map(link =>
        `<tr><td class="view-table-text" title="${label(link.source)}">${label(link.source)}</td>`
        + `<td class="view-table-text" title="${label(link.target)}">${label(link.target)}</td>`
        + `<td class="view-table-num" data-sort-value="${link.value}">${_chartNumber(link.value)}</td></tr>`);
    if (!rows.length) rows.push(`<tr data-sort-skip><td colspan="3" class="view-table-empty">${escapeHtml(_chartSentence(empty))}</td></tr>`);
    return `${table}<thead><tr><th>${escapeHtml(heads[0])}</th><th>${escapeHtml(heads[1])}</th>`
        + `<th class="view-table-num">Count</th></tr></thead><tbody>${rows.join('')}</tbody></table>`;
}

// The colours of the nodes of FLOW: an engine in its colour of ENGINE (it
// stays when a filter is set), "other rules" / "other processes" muted, the
// others from the palette by their place, without its muted last colour
function _alertsFlowColors(flow, engines) {
    const engineColor = new Map(engines.map(item => [item.key, item.color]));
    const colors = Object.create(null);
    flow.columns.forEach((column, c) => column.forEach((id, i) => {
        colors[id] = c === 0 ? engineColor.get(id.slice('engine:'.length).toLowerCase())
            : id === 'other rules' || id === 'other processes' ? 'var(--text-muted)'
            : CHART_PALETTE[(c + i) % (CHART_PALETTE.length - 1)];
    }));
    return colors;
}

// The filter a node of FLOW stands for: {engine}, {rule} or {process} with
// its name; none ({}) for "other rules", "other processes" and the engine of
// alerts without one
function _alertsFlowFilter(id) {
    const m = /^(engine|rule|process):([\s\S]*)$/.exec(String(id ?? ''));
    return m && m[2] ? { [m[1]]: m[2] } : {};
}

// The widths the bars and the Sankey are drawn for: those of their cards (0 while hidden)
function _alertsChartWidths() {
    const width = kind => Math.floor(document.querySelector(`#alerts-${kind}-card .chart-card-head`)?.getBoundingClientRect().width || 0);
    return { time: width('time'), flow: width('flow') };
}

// Marks the parts of a chart a click sets no filter for: no pointer (.chart-inert)
function _alertsChartInert(view, selector, inert) {
    view.querySelectorAll(selector).forEach(el => { if (inert(el)) el.classList.add('chart-inert'); });
}

// A click on a chart of the Alerts tab sets the filter of the part clicked,
// as a step of the drilldown (drillAlerts): the slice or legend row of a
// severity shows that severity alone (selectAlertsSeverity), of an engine
// chooses the engine; a bar sets its period, that of the bar pressed
// wherever the browser sends the click (barsClickPeriod), and the click of
// a press that drew a range across the bars nothing (the range was the
// step); a node of FLOW its engine, rule or process, a band both of its
// ends. "other rules", "other processes", alerts without an engine, a
// severity without a chip, a band with such an end and a bar without alerts
// set nothing: each would list other alerts than it shows (more, or none).
function onAlertsChartClick(event, chart) {
    const target = event && event.target;
    if (!target || typeof target.closest !== 'function') return;
    if (chart === 'time') {
        const period = barsClickPeriod(event, ALERTS_BARS_BRUSH);
        if (period) drillAlerts(period);
    } else if (chart === 'flow') {
        const change = _flowClickFilter(target, _alertsFlowFilter);
        if (change) _applyAlertsChartFilter(change);
    } else {
        const part = target.closest('[data-key]');
        const key = part ? part.getAttribute('data-key') : '';
        if (chart === 'severity' && ALERT_SEVERITIES.includes(key)) selectAlertsSeverity(key);
        else if (chart === 'engine' && key) drillAlerts({ engine: key });
    }
}

// The engine choice and the rule and process filters of a click on FLOW, in
// one step (drillAlerts); none when the click stands for no filter or
// changes none (false)
function _applyAlertsChartFilter(change) {
    return drillAlerts(change || {});
}

// A range drawn across bars of OVER TIME (ALERTS_BARS_BRUSH; these bins, the
// first to the last): a step from the start of the first to the end of the
// last, so the table lists what they counted. None when no bar of them has
// alerts (it would empty every card, as a click on such a bar would) or when
// it changes nothing (false).
function _drillAlertsBars(bins) {
    return bins.some(bin => bin.total > 0) && drillAlerts({ from: bins[0].start, to: bins[bins.length - 1].end });
}

// LINEAR: the Sankey in true proportions, or by square roots again
function toggleAlertsFlowScale() {
    alertsFlowView.linear = !alertsFlowView.linear;
    _pressFlowScale(document.getElementById('alerts-flow-linear'), alertsFlowView.linear);
    if (_alertsChartsDrawn) _drawAlertsFlow(_alertsChartsDrawn);
}

// The LINEAR switch of a Sankey pressed or not, its title saying what a click does
function _pressFlowScale(button, linear) {
    if (!button) return;
    button.setAttribute('aria-pressed', String(linear));
    button.title = linear ? 'Draw the flows by their square roots, so small flows stay visible' : 'Draw the flows in true proportions';
}

// The bars and the Sankey for the new width of their cards; nothing while the
// tab is hidden or for the widths they were drawn for
function redrawAlertsChartsOnResize() {
    const drawn = _alertsChartsDrawn;
    if (!drawn) return;
    const widths = _alertsChartWidths();
    if (!widths.time || !widths.flow || (widths.time === drawn.widths.time && widths.flow === drawn.widths.flow)) return;
    drawn.widths = widths;
    _drawAlertsTime(drawn);
    _drawAlertsFlow(drawn);
}

// =============================================
// CARD CONTROLS: (i) EXPLANATIONS, SORTABLE TABLES (both themes)
// =============================================
// A heading with data-info="..." gets a small (i) button after its text; the
// button shows the text in the shared #info-popover, as text (never markup).
// A table with data-sortable and data-sort-id="..." sorts by a click on a column
// head: ascending, then descending. tableSortState keeps the order per sort id
// until the page is reloaded. Render functions rebuild their tables (the
// Alerts tab, Sysmon and the pipe events on every refresh): one
// MutationObserver for the page sorts each rebuilt table again and gives the
// headings rendered by JavaScript their (i), before the browser paints.
// sort id -> {col, dir: 'asc' | 'desc'}
const tableSortState = {};
const SORT_COLLATOR = new Intl.Collator(undefined, { numeric: true, sensitivity: 'accent' });
let _cardControlsObserver = null;
// The (i) whose text the popover shows
let _infoPopoverAnchor = null;

// --- (i) explanations ---
function initInfoButtons(root = document) {
    const holders = [...root.querySelectorAll('[data-info]')];
    if (root.nodeType === 1 && root.hasAttribute('data-info')) holders.unshift(root);
    for (const holder of holders) {
        if ([...holder.children].some(child => child.classList.contains('info-btn'))) continue;
        const button = document.createElement('button');
        button.className = 'info-btn';
        button.type = 'button';
        button.setAttribute('aria-label', 'Explain');
        button.textContent = 'i';
        holder.appendChild(button);
    }
}

// Where the popover goes (px, for position: fixed): below the button with
// the left edges aligned, moved left to stay in the window, and above the
// button when there is no room below.
function infoPopoverPosition(anchor, size, viewport, margin = 8) {
    const gap = 6;
    const left = Math.max(margin, Math.min(anchor.left, viewport.width - size.width - margin));
    let top = anchor.bottom + gap;
    if (top + size.height > viewport.height - margin && anchor.top - gap - size.height >= margin) {
        top = anchor.top - gap - size.height;
    }
    top = Math.max(margin, Math.min(top, viewport.height - size.height - margin));
    return { left: Math.round(left), top: Math.round(top) };
}

function isInfoPopoverOpen() {
    const popover = document.getElementById('info-popover');
    return !!popover && !popover.hidden;
}

function openInfoPopover(button) {
    const popover = document.getElementById('info-popover');
    const holder = button.closest('[data-info]');
    if (!popover || !holder) return;
    if (_infoPopoverAnchor && _infoPopoverAnchor !== button) _infoPopoverAnchor.setAttribute('aria-expanded', 'false');
    popover.textContent = holder.getAttribute('data-info');
    popover.hidden = false;
    // Measured where it cannot overflow, then placed (no paint in between)
    popover.style.left = '0px';
    popover.style.top = '0px';
    const size = popover.getBoundingClientRect();
    const at = infoPopoverPosition(button.getBoundingClientRect(), { width: size.width, height: size.height },
                                   { width: window.innerWidth, height: window.innerHeight });
    popover.style.left = `${at.left}px`;
    popover.style.top = `${at.top}px`;
    button.setAttribute('aria-expanded', 'true');
    button.setAttribute('aria-controls', 'info-popover');
    _infoPopoverAnchor = button;
}

// Returns the (i) the popover belonged to, for the focus to go back to
function closeInfoPopover() {
    const popover = document.getElementById('info-popover');
    const anchor = _infoPopoverAnchor;
    if (popover) popover.hidden = true;
    if (anchor) anchor.setAttribute('aria-expanded', 'false');
    _infoPopoverAnchor = null;
    return anchor;
}

// Capture phase: a click on (i) inside a clickable card or a collapsible
// title does not also click that; any other click outside the popover closes it.
function onInfoClick(e) {
    const button = e.target && e.target.closest ? e.target.closest('.info-btn') : null;
    if (button) {
        e.preventDefault();
        e.stopPropagation();
        if (button === _infoPopoverAnchor && isInfoPopoverOpen()) closeInfoPopover();
        else openInfoPopover(button);
        return;
    }
    const popover = document.getElementById('info-popover');
    if (isInfoPopoverOpen() && !popover.contains(e.target)) closeInfoPopover();
}

// The popover is placed for the button where it was: it closes when the page
// or a container around the button scrolls (a container elsewhere may scroll).
function onInfoAnchorScroll(e) {
    const anchor = _infoPopoverAnchor;
    if (!anchor) return;
    const target = e.target;
    if (target === document || target === window || (target && target.contains && target.contains(anchor))) {
        closeInfoPopover();
    }
}

// --- Sortable tables ---
// A value as it is compared: a number (also 0x hex, a sign, a % sign), a
// date and time (ISO), a clock time (HH:MM[:SS]) or text. A placeholder
// (-, --, —, ?, n/a) counts as empty.
function sortKey(value) {
    const text = String(value === null || value === undefined ? '' : value).trim();
    const key = { text, empty: ['', '-', '--', '?', '\u2014', '\u2013', 'n/a'].includes(text.toLowerCase()),
                  num: null, date: null, clock: null };
    if (key.empty) return key;
    if (/^[-+]?(?:\d+\.?\d*|\.\d+)(?:e[-+]?\d+)?%?$/i.test(text)) {
        key.num = parseFloat(text);
    } else if (/^0x[0-9a-f]+$/i.test(text)) {
        key.num = parseInt(text, 16);
    } else if (/^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:[.,]\d+)?)?)?(?:Z|[+-]\d{2}:?\d{2})?$/i.test(text)) {
        const t = Date.parse(text.replace(' ', 'T').replace(',', '.'));
        if (!Number.isNaN(t)) key.date = t;
    } else {
        const m = /^(\d{1,2}):(\d{2})(?::(\d{2}(?:\.\d+)?))?$/.exec(text);
        if (m) key.clock = Number(m[1]) * 3600 + Number(m[2]) * 60 + Number(m[3] || 0);
    }
    return key;
}

// Two numbers numerically, two times chronologically, anything else as text
// in any case ("Alpha" before "beta", "chunk_9" before "chunk_10"); an empty
// value after every other one.
function compareSortKeys(a, b) {
    if (a.empty || b.empty) return Number(a.empty) - Number(b.empty);
    const order = (x, y) => (x > y) - (x < y);
    if (a.num !== null && b.num !== null) return order(a.num, b.num);
    if (a.date !== null && b.date !== null) return order(a.date, b.date);
    if (a.clock !== null && b.clock !== null) return order(a.clock, b.clock);
    return SORT_COLLATOR.compare(a.text, b.text);
}

function compareSortValues(a, b) {
    return compareSortKeys(sortKey(a), sortKey(b));
}

// The cell of a row in column col (columns counted with their colspan)
function sortCellAt(row, col) {
    let x = 0;
    for (const cell of row.cells) {
        x += cell.colSpan || 1;
        if (col < x) return cell;
    }
    return null;
}

// What a cell sorts by: its data-sort-value, else its text
function sortCellValue(row, col) {
    const cell = sortCellAt(row, col);
    if (!cell) return '';
    const value = cell.getAttribute('data-sort-value');
    return value !== null ? value : cell.textContent;
}

// A note or an empty state: marked data-sort-skip, or one cell across the table
function isSortPinnedRow(row) {
    if (row.hasAttribute('data-sort-skip')) return true;
    const cells = row.cells;
    return cells.length === 1 && (cells[0].colSpan || 1) > 1;
}

// The rows of one table body in their new order, by column col, dir 'asc' or
// 'desc'. Rows that belong together move together: a row, the rows its
// rowspan covers and its detail rows (data-sort-detail). A pinned row keeps
// its place. Stable: equal values keep their order in either direction, and
// empty values come last in either direction.
function sortRows(rows, col, dir) {
    const units = [];
    let covered = 0;
    for (const row of rows) {
        const span = Math.max(1, ...[...row.cells].map(cell => cell.rowSpan || 1));
        const detail = row.hasAttribute('data-sort-detail');
        const last = units[units.length - 1];
        if (last && !last.pinned && (covered > 0 || detail)) {
            last.rows.push(row);
            covered = Math.max(covered - 1, span - 1);
            continue;
        }
        const pinned = detail || isSortPinnedRow(row);
        units.push({ rows: [row], pinned, key: pinned ? null : sortKey(sortCellValue(row, col)), index: units.length });
        covered = pinned ? 0 : span - 1;
    }
    const sign = dir === 'desc' ? -1 : 1;
    const sorted = units.filter(unit => !unit.pinned).sort((a, b) => {
        const order = a.key.empty || b.key.empty ? compareSortKeys(a.key, b.key) : sign * compareSortKeys(a.key, b.key);
        return order || a.index - b.index;
    });
    let next = 0;
    return units.flatMap(unit => (unit.pinned ? unit : sorted[next++]).rows);
}

// The row of column heads: the last row of <thead>, else a first row of <th>s
function sortHeaderRow(table) {
    const head = table.tHead;
    if (head && head.rows.length) return head.rows[head.rows.length - 1];
    const first = table.rows[0];
    return first && first.cells.length && [...first.cells].every(cell => cell.tagName === 'TH') ? first : null;
}

// A head without text (a column of buttons) or with data-no-sort does not sort
function isSortHeader(th) {
    return th.tagName === 'TH' && !th.hasAttribute('data-no-sort') && th.textContent.trim() !== '';
}

function sortColumnOf(cell) {
    let col = 0;
    for (const other of cell.parentElement.cells) {
        if (other === cell) return col;
        col += other.colSpan || 1;
    }
    return col;
}

// Applies the stored order to one table: its rows and the state of its heads
// (aria-sort, which style.css shows as ↕ ▲ ▼; tabindex for the keyboard)
function applyTableSort(table) {
    const head = sortHeaderRow(table);
    if (!head) return;
    const sort = tableSortState[table.dataset.sortId];
    for (const th of head.cells) {
        if (!isSortHeader(th)) continue;
        if (!th.hasAttribute('tabindex')) th.setAttribute('tabindex', '0');
        if (sort && sortColumnOf(th) === sort.col) th.setAttribute('aria-sort', sort.dir === 'desc' ? 'descending' : 'ascending');
        else th.removeAttribute('aria-sort');
    }
    if (!sort) return;
    for (const body of table.tBodies) {
        const rows = [...body.rows].filter(row => row !== head);
        const sorted = sortRows(rows, sort.col, sort.dir);
        if (sorted.every((row, i) => row === rows[i])) continue;
        const fragment = document.createDocumentFragment();
        sorted.forEach(row => fragment.appendChild(row));
        body.appendChild(fragment);
    }
}

// Sorts every sortable table in root (or root itself) again by its stored order
function reapplyTableSorts(root = document) {
    const tables = [...root.querySelectorAll('table[data-sortable]')];
    if (root.nodeType === 1 && root.matches('table[data-sortable]')) tables.unshift(root);
    tables.forEach(applyTableSort);
}

// A click on the sorted column turns the order; another column starts ascending.
// Every table of the same sort id on the page takes the new order.
function sortTableBy(table, col) {
    const id = table.dataset.sortId;
    if (!id) return;
    const current = tableSortState[id];
    tableSortState[id] = { col, dir: current && current.col === col && current.dir === 'asc' ? 'desc' : 'asc' };
    document.querySelectorAll('table[data-sortable]').forEach(other => {
        if (other.dataset.sortId === id) applyTableSort(other);
    });
}

function sortHeaderFrom(target) {
    const th = target && target.closest ? target.closest('th') : null;
    const table = th && th.closest('table');
    return table && table.hasAttribute('data-sortable') && th.parentElement === sortHeaderRow(table) && isSortHeader(th)
        ? th : null;
}

function onSortHeaderClick(e) {
    const th = sortHeaderFrom(e.target);
    if (th) sortTableBy(th.closest('table'), sortColumnOf(th));
}

function onSortHeaderKey(e) {
    if (e.key !== 'Enter' && e.key !== ' ') return;
    const th = sortHeaderFrom(e.target);
    if (!th || th !== e.target) return;
    e.preventDefault();
    sortTableBy(th.closest('table'), sortColumnOf(th));
}

// The observer's callback: tables a render function rebuilt or changed are
// sorted again, headings it added get their (i). Its own changes (moved rows,
// new buttons) are taken off the queue, so it never triggers itself.
function onCardControlsMutated(records) {
    const tables = new Set();
    const roots = [];
    for (const record of records) {
        const table = record.target && record.target.closest ? record.target.closest('table[data-sortable]') : null;
        if (table) tables.add(table);
        for (const node of record.addedNodes) {
            if (node.nodeType !== 1) continue;
            // Cheap checks first: a hex page adds thousands of plain spans
            const itself = node.hasAttribute('data-info') || (node.tagName === 'TABLE' && node.hasAttribute('data-sortable'));
            if (itself || (node.firstElementChild && node.querySelector('table[data-sortable], [data-info]'))) roots.push(node);
        }
    }
    for (const root of roots) {
        initInfoButtons(root);
        if (root.matches('table[data-sortable]')) tables.add(root);
        root.querySelectorAll('table[data-sortable]').forEach(table => tables.add(table));
    }
    tables.forEach(table => { if (table.isConnected) applyTableSort(table); });
    // A render removed the (i) the popover was showing
    if (_infoPopoverAnchor && !_infoPopoverAnchor.isConnected) closeInfoPopover();
    if (_cardControlsObserver) _cardControlsObserver.takeRecords();
}

function initCardControls() {
    document.addEventListener('click', onInfoClick, true);
    document.addEventListener('click', onSortHeaderClick);
    document.addEventListener('keydown', onSortHeaderKey);
    document.addEventListener('scroll', onInfoAnchorScroll, true);
    window.addEventListener('resize', () => closeInfoPopover());
    initInfoButtons(document);
    reapplyTableSorts(document);
    if (typeof MutationObserver === 'function' && document.body) {
        _cardControlsObserver = new MutationObserver(onCardControlsMutated);
        _cardControlsObserver.observe(document.body, { childList: true, subtree: true });
    }
}

// --- CHART / TABLE ---
// A card that draws numbers (the timelines, the severity bar, the file
// structure of the binary analysis, the file map strip of the PE analysis)
// shows the same numbers as a sortable table on request. Its render function
// writes both views, marked data-view-of="<card id>" data-view="chart|table"
// (cardViewAttrs, or in the markup of index.html), and the switch from
// viewToggleHtml(id). The view not chosen is hidden, so a switch needs no new
// render; a refresh renders both views again, so the table is as current as
// the chart. The choice lasts per card until the page is reloaded.
// card id -> 'table'; a card not in it shows its chart
const cardViewState = {};

function isTableView(id) {
    return cardViewState[id] === 'table';
}

// The switch reads "TABLE" while the chart shows and "CHART" while the table shows
function viewToggleHtml(id) {
    const table = isTableView(id);
    return `<button type="button" class="view-toggle" data-view-toggle="${escapeHtml(id)}" title="${table ? 'Show the chart' : 'Show the numbers as a table'}" onclick="toggleCardView(${jsArg(id)})">${table ? 'CHART' : 'TABLE'}</button>`;
}

// The attributes of one view of a card: hidden unless it is the one chosen
function cardViewAttrs(id, view) {
    const shown = (view === 'table') === isTableView(id);
    return ` data-view-of="${escapeHtml(id)}" data-view="${view === 'table' ? 'table' : 'chart'}"${shown ? '' : ' hidden'}`;
}

// Shows the other view of every card with this id. The switches keep their
// node (and so the keyboard focus); only their text changes.
function toggleCardView(id) {
    if (isTableView(id)) delete cardViewState[id];
    else cardViewState[id] = 'table';
    const table = isTableView(id);
    document.querySelectorAll('[data-view-of]').forEach(el => {
        if (el.getAttribute('data-view-of') === id) el.hidden = (el.getAttribute('data-view') === 'table') !== table;
    });
    document.querySelectorAll('.view-toggle').forEach(button => {
        if (button.getAttribute('data-view-toggle') !== id) return;
        button.textContent = table ? 'CHART' : 'TABLE';
        button.title = table ? 'Show the chart' : 'Show the numbers as a table';
    });
}

// --- Dashboard tiles ---
// The tiles are <div role="button">s: Enter and Space click them as a button
// would. The severity counts inside the alerts tile are mouse targets of their
// own (no nested buttons); the keyboard reaches their filters in the Alerts tab.
function onTileKey(event, tile) {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    if (event.target !== tile) return;
    event.preventDefault();
    tile.click();
}

// Scrolls an element into view and marks it for a second (.reveal-flash)
function revealSection(id) {
    revealElement(document.getElementById(id), 'nearest', 1000);
}

// Scrolls `el` into view (`block` as scrollIntoView takes it) and marks it
// with .reveal-flash for `ms`, as long as its animation lasts
function revealElement(el, block, ms) {
    if (!el) return;
    el.scrollIntoView({ behavior: 'smooth', block });
    el.classList.remove('reveal-flash');
    void el.offsetWidth;            // the animation starts again on a second click
    el.classList.add('reveal-flash');
    clearTimeout(el._revealTimer);
    el._revealTimer = setTimeout(() => el.classList.remove('reveal-flash'), ms);
}

// PROCESSES TRACKED: the process list, in the sidebar (Classic) or in the drawer (Cyberpunk)
function revealProcessList() {
    if (currentTheme() === 'cyberpunk') openDrawer();
    else revealSection('process-list-section');
}

// =============================================
// CHARTS
// =============================================
// The building blocks of the charts of the Dashboard, the Alerts tab, Sysmon,
// ThreatScan, Submit, the graph detail and the detonation results: counting,
// bins in time, Sankey flows and their layout, then SVG markup. Colours are
// theme variables, var(--...), so a theme switch recolours a chart without
// drawing it again; a colour that is no variable gives way to the palette.
// Every text from the data goes through escapeHtml. A chart with nothing to
// draw is '', so its card can show chartEmptyHtml(...) instead. The views
// handle the clicks: segments, bars, legend rows and points carry data-key,
// the bins of a bar chart data-bin-start / data-bin-end (epoch ms), the nodes
// of a Sankey data-sankey-node, its bands data-sankey-link.
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const SEVERITY_COLORS = {
    critical: 'var(--severity-critical)', high: 'var(--severity-high)', medium: 'var(--severity-medium)',
    low: 'var(--severity-low)', info: 'var(--severity-info)',
};
// Colours for kinds without a colour of their own (categories, engines, event types), in this order
const CHART_PALETTE = ['var(--accent-pink)', 'var(--accent-cyan)', 'var(--accent-yellow)', 'var(--accent-green)',
    'var(--accent-purple)', 'var(--accent-orange)', 'var(--accent-blue)', 'var(--text-muted)'];
const CHART_MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
// A clock set to the year 9999 must not give a chart millions of bins
const CHART_MAX_BINS = 1000;

// --- Counting ---
// An alert's category in lower case: the first of a list (["registry"]) or
// the text ("process"); "other" when it has none.
function alertCategory(alert) {
    const category = alert?.category;
    const first = Array.isArray(category) ? category[0] : category;
    return String(first ?? '').trim().toLowerCase() || 'other';
}

// [{key, count}] of the items by keyFn(item): the most frequent first, ties in
// the order of their keys, so a ranking keeps its order from render to render.
function countBy(items, keyFn) {
    const counts = new Map();
    for (const item of items || []) {
        const key = keyFn ? keyFn(item) : item;
        counts.set(key, (counts.get(key) || 0) + 1);
    }
    return [...counts].map(([key, count]) => ({ key, count })).sort((a, b) => {
        const x = String(a.key), y = String(b.key);
        return (b.count - a.count) || (x < y ? -1 : x > y ? 1 : 0);
    });
}

// --- Bins in time ---
// Items counted per hour, day or week: {unit, bins: [{start, end, counts,
// total}]}, times in epoch ms. time(item) gives an item's time (default: its
// timestamp); items without one are left out. The unit follows the span:
// hours up to 2 days, days up to 120 days, weeks beyond; with `fine` (a
// Sysmon capture of minutes) a span of up to 20 hours takes steps of seconds
// or minutes instead ({unit: 'second' | 'minute', step: ms, bins}, see
// _chartFineStep). Bins begin at a local full hour, a local midnight, a
// Monday or a local multiple of their step, and follow each other without a
// gap, empty ones too, from the first item (or `from`) to the last (or `to`,
// which is not included). With `from` / `to` only the items between count,
// and the first and last bin begin and end there: a bin's start and end
// select exactly the items it counts. counts has every key of `keys` (0 when
// none) and key(item) of each item counted.
function binByTime(items, opts) {
    opts = opts || {};
    const time = typeof opts.time === 'function' ? opts.time : item => Date.parse(item?.timestamp);
    const key = typeof opts.key === 'function' ? opts.key : null;
    const hasFrom = Number.isFinite(opts.from), hasTo = Number.isFinite(opts.to);
    const timed = [];
    let first = Infinity, last = -Infinity;
    for (const item of items || []) {
        let t = time(item);
        if (t instanceof Date) t = t.getTime();
        if (typeof t !== 'number' || !Number.isFinite(t)) continue;
        if ((hasFrom && t < opts.from) || (hasTo && t >= opts.to)) continue;
        timed.push([t, item]);
        first = Math.min(first, t);
        last = Math.max(last, t);
    }
    const from = hasFrom ? opts.from : first, to = hasTo ? opts.to : last;
    const span = to - from;
    const step = opts.fine ? _chartFineStep(span) : 0;
    const unit = step ? (step < 60000 ? 'second' : 'minute')
        : span <= 2 * 86400000 ? 'hour' : span <= 120 * 86400000 ? 'day' : 'week';
    if (!Number.isFinite(span) || span < 0 || (hasTo && span === 0)) return { unit, bins: [] };
    const keys = (opts.keys || []).map(String);
    const bins = [];
    for (let start = _chartPeriodStart(from, unit, step); bins.length < CHART_MAX_BINS;) {
        const next = _chartPeriodNext(start, unit, step);
        const counts = Object.create(null);         // the keys come from the data: none may be special (__proto__)
        keys.forEach(k => { counts[k] = 0; });
        bins.push({ start: hasFrom ? Math.max(start, from) : start, end: hasTo ? Math.min(next, to) : next, counts, total: 0 });
        if (hasTo ? next >= to : next > to) break;
        start = next;
    }
    // Capped at CHART_MAX_BINS: the last bin reaches to the end, so no item is lost
    const tail = bins[bins.length - 1];
    if (hasTo ? tail.end < to : tail.end <= to) tail.end = hasTo ? to : _chartPeriodNext(_chartPeriodStart(to, unit, step), unit, step);
    for (const [t, item] of timed) {
        let lo = 0, hi = bins.length - 1;           // the last bin that starts at or before t
        while (lo < hi) {
            const mid = (lo + hi + 1) >> 1;
            if (bins[mid].start <= t) lo = mid;
            else hi = mid - 1;
        }
        const bin = bins[lo];
        bin.total++;
        if (key) {
            const k = String(key(item) ?? '');
            bin.counts[k] = (bin.counts[k] || 0) + 1;
        }
    }
    return step ? { unit, step, bins } : { unit, bins };
}

// The step of bins of seconds or minutes for a span of `span` ms: the
// shortest of 1, 2, 5, 10, 15 and 30 seconds or minutes that takes at most
// 40 of them; 0 when even half hours would take more (the span gets hours)
function _chartFineStep(span) {
    const steps = [1, 2, 5, 10, 15, 30].map(n => n * 1000).concat([1, 2, 5, 10, 15, 30].map(n => n * 60000));
    return steps.find(step => span / step <= 40) || 0;
}

// The start of the local hour, day or week (Monday) that t lies in, or of
// the step of seconds or minutes ('second' / 'minute', `step` ms)
function _chartPeriodStart(t, unit, step) {
    if (unit === 'hour' || unit === 'second' || unit === 'minute') {
        // By the offset in effect at t: when the clocks go back, the hour that
        // comes twice begins where t's own one does
        const size = unit === 'hour' ? 3600000 : step > 0 ? step : unit === 'second' ? 1000 : 60000;
        const offset = -new Date(t).getTimezoneOffset() * 60000;
        return t - ((((t + offset) % size) + size) % size);
    }
    const d = new Date(t);
    d.setHours(0, 0, 0, 0);
    if (unit === 'week') d.setDate(d.getDate() - (d.getDay() + 6) % 7);
    return d.getTime();
}

// The start of the period after the one that starts at t: an hour or a step
// later, or the next local midnight (a day has 23 or 25 hours when the
// clocks change)
function _chartPeriodNext(t, unit, step) {
    let next = t + 3600000;
    if (unit === 'second' || unit === 'minute') {
        next = t + (step > 0 ? step : unit === 'second' ? 1000 : 60000);
    } else if (unit !== 'hour') {
        const d = new Date(t);
        d.setDate(d.getDate() + (unit === 'week' ? 7 : 1));
        d.setHours(0, 0, 0, 0);
        next = d.getTime();
    }
    return next > t ? next : t + 3600000;
}

// "14 Jul" or "14 Jul 2026", in local time
function _chartDate(t, withYear) {
    const d = new Date(t);
    return `${String(d.getDate()).padStart(2, '0')} ${CHART_MONTHS[d.getMonth()]}${withYear ? ' ' + d.getFullYear() : ''}`;
}

// "22:00" (or with `seconds` "22:00:15") in local time, hours 00-23
// (midnight is never 24:00)
function _chartClock(t, seconds) {
    const d = new Date(t);
    const p = n => String(n).padStart(2, '0');
    return `${p(d.getHours())}:${p(d.getMinutes())}${seconds ? ':' + p(d.getSeconds()) : ''}`;
}

// A bin's period for its tooltip: "14 Jul 2026, 22:00–23:00", "14 Jul 2026",
// "13 Jul – 19 Jul 2026", "10 Nov 2026, 19:30:30–19:31:00" for seconds, and
// so for a bin a range cuts off the full minute ("15:30:17–15:31:00", as the
// chip of its period names it); a day cut short by the range names its hours
function _chartPeriodLabel(start, end, unit) {
    if (unit === 'week') {
        const lastDay = end - 1;
        const sameYear = new Date(start).getFullYear() === new Date(lastDay).getFullYear();
        return `${_chartDate(start, !sameYear)} – ${_chartDate(lastDay, true)}`;
    }
    const wholeDay = start === _chartPeriodStart(start, 'day') && end === _chartPeriodNext(start, 'day');
    const offMinute = t => new Date(t).getSeconds() !== 0 || new Date(t).getMilliseconds() !== 0;
    const seconds = unit === 'second' || offMinute(start) || offMinute(end);
    return unit === 'day' && wholeDay ? _chartDate(start, true)
        : `${_chartDate(start, true)}, ${_chartClock(start, seconds)}–${_chartClock(end, seconds)}`;
}

// A time range (epoch ms, `to` not included) as the chip of a filter names
// it, in local time: "14 Jul – 20 Jul" when both ends are midnights (the last
// day included, as a week's tooltip), else with the times, "14 Jul
// 22:00–23:00" or "14 Jul 23:00 – 15 Jul 00:00", to the second when an end
// is not on a full minute ("27 Jul 11:45:10–11:45:40"); "from …" or
// "before …" with one end. The years show when the ends lie in two.
function chartRangeLabel(from, to) {
    const hasFrom = Number.isFinite(from), hasTo = Number.isFinite(to);
    if (!hasFrom && !hasTo) return '';
    const midnight = t => t === _chartPeriodStart(t, 'day');
    const days = (!hasFrom || midnight(from)) && (!hasTo || midnight(to)) && !(hasFrom && hasTo && to <= from);
    const last = days && hasTo ? to - 1 : to;
    const years = hasFrom && hasTo && new Date(from).getFullYear() !== new Date(last).getFullYear();
    // Both ends with their seconds when one is not on a full minute (a range of bars of seconds)
    const offMinute = t => new Date(t).getSeconds() !== 0 || new Date(t).getMilliseconds() !== 0;
    const seconds = (hasFrom && offMinute(from)) || (hasTo && offMinute(to));
    const at = (t, clock) => `${_chartDate(t, years)}${clock ? ' ' + _chartClock(t, seconds) : ''}`;
    if (!hasTo) return `from ${at(from, !days)}`;
    if (!hasFrom) return `before ${at(to, !days)}`;
    if (days) return _chartPeriodStart(last, 'day') === from ? at(from) : `${at(from)} – ${at(last)}`;
    return to > from && _chartPeriodStart(to, 'day') === _chartPeriodStart(from, 'day')
        ? `${at(from, true)}–${_chartClock(to, seconds)}` : `${at(from, true)} – ${at(to, true)}`;
}

// The bins labelled under a bar chart, with their text: the finest of whole
// hours, days, Mondays, the 1st of a month, of a quarter, of a year that
// leaves 48 px between labels (bars of seconds or minutes: of the round
// times that are multiples of their step, 56 px for labels with seconds);
// the first bin too when there is room.
function _chartTicks(bins, unit, slot, step) {
    const dates = bins.map(bin => new Date(bin.start));
    const fine = unit === 'second' || unit === 'minute';
    // The local time of day in ms, for the round times of bars of seconds or minutes
    const local = d => (((d.getHours() * 60 + d.getMinutes()) * 60 + d.getSeconds()) * 1000) + d.getMilliseconds();
    const rounds = [1, 2, 5, 10, 15, 30].map(n => n * 1000).concat([1, 2, 5, 10, 15, 30].map(n => n * 60000),
                                                                      [1, 2, 3, 6, 12, 24].map(n => n * 3600000));
    const rules = fine ? rounds.filter(ms => ms >= step && ms % step === 0).map(ms => d => local(d) % ms === 0)
        : unit === 'hour' ? [1, 2, 3, 6, 12, 24].map(n => d => d.getHours() % n === 0)
        : unit === 'day' ? [() => true, d => d.getDay() === 1, d => d.getDate() === 1,
            d => d.getDate() === 1 && d.getMonth() % 3 === 0, d => d.getDate() === 1 && d.getMonth() === 0]
        : [() => true, d => d.getDate() <= 7, d => d.getDate() <= 7 && d.getMonth() % 3 === 0,
            d => d.getDate() <= 7 && d.getMonth() === 0];
    const room = unit === 'second' ? 56 : 48;
    const roomy = ticks => ticks.every((i, k) => k === 0 || (i - ticks[k - 1]) * slot >= room);
    let ticks = null;
    for (const rule of rules) {
        const found = dates.flatMap((d, i) => (rule(d) ? [i] : []));
        if (roomy(found)) { ticks = found; break; }
    }
    if (!ticks) {
        const every = Math.ceil(room / slot);
        ticks = dates.flatMap((d, i) => (i % every === 0 ? [i] : []));
    }
    if (ticks[0] !== 0 && (!ticks.length || ticks[0] * slot >= room)) ticks.unshift(0);
    if (fine) {
        // With seconds where one of them is not on a full minute; midnight is its date
        const seconds = unit === 'second' && ticks.some(i => dates[i].getSeconds() !== 0);
        return ticks.map(i => ({ i, text: local(dates[i]) === 0 ? _chartDate(bins[i].start) : _chartClock(bins[i].start, seconds) }));
    }
    return ticks.map(i => ({
        i, text: unit === 'hour' && dates[i].getHours() + dates[i].getMinutes() > 0 ? _chartClock(bins[i].start) : _chartDate(bins[i].start),
    }));
}

// --- SVG ---
// The colour if it is a theme variable, var(--name), else the i-th of the
// palette: a literal would stay the same in every theme, and a colour from
// the data could leave its style attribute.
function _chartColor(color, i) {
    const n = Number.isInteger(i) && i > 0 ? i : 0;
    return typeof color === 'string' && /^var\(--[\w-]+\)$/.test(color) ? color : CHART_PALETTE[n % CHART_PALETTE.length];
}

// A count with thousands separators (9,620)
function _chartNumber(n) {
    const value = Number(n);
    return Number.isFinite(value) ? value.toLocaleString('en-US', { maximumFractionDigits: 2 }) : '0';
}

// A share in per cent with one decimal; "<0.1%" for one too small to show
function _chartShare(value, total) {
    const pct = total > 0 && value > 0 ? value / total * 100 : 0;
    return pct > 0 && pct < 0.05 ? '<0.1%' : `${pct.toFixed(1)}%`;
}

// A coordinate with at most two decimals
function _chartCoord(n) {
    return String(Math.round(n * 100) / 100);
}

// The text cut to at most `max` characters, the last of them "…" where it is cut
function _chartEllipsis(text, max) {
    const chars = Array.from(String(text ?? ''));           // by code point: an emoji is not cut in half
    return chars.length <= max ? chars.join('') : `${chars.slice(0, Math.max(max - 1, 0)).join('')}…`;
}

// The items of a donut or a pie with a value above 0: each with its colour
// (its own, or the palette's by its place in the list, as in its legend), its
// tooltip and its part of the circle; a part too small to see gets a sliver.
function _chartSegments(items) {
    const segments = [];
    (items || []).forEach((item, i) => {
        const value = Number(item?.value);
        if (!(value > 0) || !Number.isFinite(value)) return;
        segments.push({ key: item.key, label: String(item.label ?? item.key ?? ''), value, color: _chartColor(item.color, i) });
    });
    const total = segments.reduce((sum, s) => sum + s.value, 0);
    const shown = segments.map(s => Math.max(s.value / total, 0.004));
    const sum = shown.reduce((a, b) => a + b, 0);
    segments.forEach((s, i) => {
        s.part = shown[i] / sum;
        s.title = `${s.label}: ${_chartNumber(s.value)} (${_chartShare(s.value, total)})`;
    });
    return { total, segments };
}

// A ring of items [{key, label, value, color}], clockwise from 12 o'clock,
// with the total (or centerLabel; '' for none) and centerSub in its middle.
// One item of 100 % is a circle: an arc from a point back to itself draws nothing.
function donutSvg(items, opts) {
    opts = opts || {};
    const { total, segments } = _chartSegments(items);
    if (!segments.length) return '';
    const size = opts.size > 0 ? Number(opts.size) : 120;
    const thickness = opts.thickness > 0 ? Math.min(Number(opts.thickness), size / 2) : 18;
    const c = size / 2, r = (size - thickness) / 2;
    const at = angle => `${_chartCoord(c + r * Math.cos(angle))} ${_chartCoord(c + r * Math.sin(angle))}`;
    let angle = -Math.PI / 2;
    const ring = segments.map(s => {
        const attrs = `class="chart-seg" data-key="${escapeHtml(s.key)}" data-value="${s.value}" fill="none" stroke-width="${_chartCoord(thickness)}" style="stroke:${s.color}"`;
        const title = `<title>${escapeHtml(s.title)}</title>`;
        if (s.part > 0.9999) return `<circle ${attrs} cx="${c}" cy="${c}" r="${_chartCoord(r)}">${title}</circle>`;
        const from = angle;
        angle += s.part * 2 * Math.PI;
        return `<path ${attrs} d="M${at(from)} A${_chartCoord(r)} ${_chartCoord(r)} 0 ${s.part > 0.5 ? 1 : 0} 1 ${at(angle)}">${title}</path>`;
    });
    const label = opts.centerLabel === undefined ? _chartNumber(total)
        : typeof opts.centerLabel === 'number' ? _chartNumber(opts.centerLabel) : String(opts.centerLabel ?? '');
    const sub = String(opts.centerSub ?? '');
    const center = (label ? `<text class="chart-center-label" x="${c}" y="${_chartCoord(sub ? c + 2 : c + 6)}" text-anchor="middle">${escapeHtml(label)}</text>` : '')
        + (sub ? `<text class="chart-center-sub" x="${c}" y="${_chartCoord(label ? c + 16 : c + 3)}" text-anchor="middle">${escapeHtml(sub)}</text>` : '');
    return `<svg class="chart-svg chart-donut" width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">${ring.join('')}${center}</svg>`;
}

// The items as slices of a disc, clockwise from 12 o'clock, apart by a thin
// line in the colour of the card; one item of 100 % is the whole disc.
function pieSvg(items, opts) {
    opts = opts || {};
    const { segments } = _chartSegments(items);
    if (!segments.length) return '';
    const size = opts.size > 0 ? Number(opts.size) : 120;
    const c = size / 2, r = Math.max(size / 2 - 2, 1);
    const at = angle => `${_chartCoord(c + r * Math.cos(angle))} ${_chartCoord(c + r * Math.sin(angle))}`;
    let angle = -Math.PI / 2;
    const slices = segments.map(s => {
        const attrs = `class="chart-seg chart-slice" data-key="${escapeHtml(s.key)}" data-value="${s.value}" style="fill:${s.color}"`;
        const title = `<title>${escapeHtml(s.title)}</title>`;
        if (s.part > 0.9999) return `<circle ${attrs} cx="${c}" cy="${c}" r="${_chartCoord(r)}">${title}</circle>`;
        const from = angle;
        angle += s.part * 2 * Math.PI;
        return `<path ${attrs} d="M${c} ${c} L${at(from)} A${_chartCoord(r)} ${_chartCoord(r)} 0 ${s.part > 0.5 ? 1 : 0} 1 ${at(angle)} Z">${title}</path>`;
    });
    return `<svg class="chart-svg chart-pie" width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">${slices.join('')}</svg>`;
}

// The legend of a donut or a pie: per item its colour, name, count and share
// of `total` (default: the sum of the values), one row with data-key each.
// A long name is cut by CSS; the row's title has it in full.
function chartLegendHtml(items, opts) {
    opts = opts || {};
    const list = items || [];
    const values = list.map(item => {
        const value = Number(item?.value);
        return Number.isFinite(value) && value > 0 ? value : 0;
    });
    const total = Number(opts.total) > 0 ? Number(opts.total) : values.reduce((sum, v) => sum + v, 0);
    const rows = list.map((item, i) => {
        if (!item) return '';
        const label = String(item.label ?? item.key ?? '');
        return `<div class="chart-legend-row" data-key="${escapeHtml(item.key)}" title="${escapeHtml(label)}">`
            + `<span class="chart-legend-swatch" style="background:${_chartColor(item.color, i)}"></span>`
            + `<span class="chart-legend-name">${escapeHtml(label)}</span>`
            + `<span class="chart-legend-count">${_chartNumber(values[i])}</span>`
            + `<span class="chart-legend-pct">${escapeHtml(_chartShare(values[i], total))}</span></div>`;
    }).join('');
    return rows ? `<div class="chart-legend">${rows}</div>` : '';
}

// Bars of bins (binByTime), each a stack of its counts: the first key of
// `keys` on top, keys that are not in `keys` below them; colours from
// `colors` ({key: 'var(--x)'} or a list in the order of `keys`), else the
// palette. Each bin is a <g data-bin-start data-bin-end> whose <title> names
// its period and numbers; labels of times or dates under the plot (`unit`
// and `step` of binByTime, else hours, days or weeks by the length of the
// bins); the highest bin's count at the top left. selection {from, to} marks
// a range.
function stackedBarsSvg(bins, opts) {
    opts = opts || {};
    const list = (bins || []).filter(bin => bin && Number.isFinite(bin.start) && Number.isFinite(bin.end));
    const keys = [...new Set((opts.keys || []).map(String))];
    for (const bin of list) Object.keys(bin.counts || {}).forEach(k => { if (!keys.includes(k)) keys.push(k); });
    // Without keys a bar is its bin's total
    const stacks = list.map(bin => (keys.length ? keys.map(k => [k, Number(bin.counts?.[k]) || 0]).filter(([, n]) => n > 0)
        : Number(bin.total) > 0 ? [['total', Number(bin.total)]] : []));
    const max = Math.max(0, ...stacks.map(stack => stack.reduce((sum, [, n]) => sum + n, 0)));
    if (!(max > 0)) return '';
    const width = opts.width > 0 ? Number(opts.width) : 560, height = opts.height > 0 ? Number(opts.height) : 140;
    const top = 12, plotH = Math.max(height - top - 16, 10), bottom = top + plotH;
    const slot = width / list.length;
    // A bar fills its slot but a 1 px gap, up to 40 px: a single bin is no block across the chart
    const barW = Math.min(Math.max(slot - (slot > 2 ? 1 : 0), 0.5), 40), inset = (slot - barW) / 2;
    const longest = Math.max(...list.map(bin => bin.end - bin.start));
    const unit = ['second', 'minute', 'hour', 'day', 'week'].includes(opts.unit) ? opts.unit
        : longest <= 2 * 3600000 ? 'hour' : longest <= 2 * 86400000 ? 'day' : 'week';
    const step = opts.step > 0 ? Number(opts.step) : longest;
    const color = k => _chartColor(Array.isArray(opts.colors) ? opts.colors[keys.indexOf(k)] : opts.colors?.[k], keys.indexOf(k));
    let svg = [0.25, 0.5, 0.75, 1].map(f => {
        const y = _chartCoord(bottom - plotH * f);
        return `<line class="chart-grid" x1="0" x2="${width}" y1="${y}" y2="${y}"/>`;
    }).join('') + `<text class="chart-ymax" x="0" y="${top - 3}">${_chartNumber(max)}</text>`;
    list.forEach((bin, i) => {
        const x = i * slot;
        let y = bottom, bars = '';
        for (const [k, n] of [...stacks[i]].reverse()) {
            const h = plotH * n / max;
            y -= h;
            bars += `<rect class="chart-bar" data-key="${escapeHtml(k)}" data-count="${n}" x="${_chartCoord(x + inset)}" y="${_chartCoord(y)}" width="${_chartCoord(barW)}" height="${_chartCoord(h)}" style="fill:${color(k)}"/>`;
        }
        const title = [_chartPeriodLabel(bin.start, bin.end, unit), `total: ${_chartNumber(bin.total)}`,
            ...(keys.length ? stacks[i].map(([k, n]) => `${k}: ${_chartNumber(n)}`) : [])].join('\n');
        svg += `<g class="chart-bin" data-bin-start="${bin.start}" data-bin-end="${bin.end}" data-total="${Number(bin.total) || 0}"><title>${escapeHtml(title)}</title>`
            + `<rect class="chart-hit" x="${_chartCoord(x)}" y="${top}" width="${_chartCoord(slot)}" height="${_chartCoord(plotH)}" fill="transparent"/>${bars}</g>`;
    });
    svg += `<line class="chart-axis" x1="0" x2="${width}" y1="${bottom}" y2="${bottom}"/>`;
    if (opts.selection) {
        const xOf = t => {
            if (t <= list[0].start) return 0;
            if (t >= list[list.length - 1].end) return width;
            const i = list.findIndex(bin => t < bin.end);
            return (i + Math.max(0, (t - list[i].start) / (list[i].end - list[i].start))) * slot;
        };
        const x0 = xOf(Number.isFinite(opts.selection.from) ? opts.selection.from : -Infinity);
        const x1 = xOf(Number.isFinite(opts.selection.to) ? opts.selection.to : Infinity);
        if (x1 > x0) svg += `<rect class="chart-selection" x="${_chartCoord(x0)}" y="${top}" width="${_chartCoord(x1 - x0)}" height="${_chartCoord(plotH)}" fill="none"/>`;
    }
    for (const { i, text } of _chartTicks(list, unit, slot, step)) {
        const x = i * slot + inset;
        if (x + text.length * 5.6 > width) continue;     // it would run past the right edge
        svg += `<text class="chart-tick" x="${_chartCoord(x)}" y="${height - 3}">${escapeHtml(text)}</text>`;
    }
    return `<svg class="chart-svg chart-bars" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">${svg}</svg>`;
}

// A small line of values (alerts per day of a tile), its area faintly
// filled: the highest value at the top, 0 on the ground.
function sparklineSvg(values, opts) {
    opts = opts || {};
    const list = (values || []).map(v => (Number.isFinite(Number(v)) ? Math.max(Number(v), 0) : 0));
    if (!list.length) return '';
    const width = opts.width > 0 ? Number(opts.width) : 120, height = opts.height > 0 ? Number(opts.height) : 26;
    const color = _chartColor(opts.color, 0);
    const max = Math.max(...list) || 1;
    const line = list.length === 1 ? [list[0], list[0]] : list;
    const points = line.map((v, i) => `${_chartCoord(i * width / (line.length - 1))},${_chartCoord(height - 3 - (height - 6) * v / max)}`).join(' ');
    return `<svg class="chart-svg chart-spark" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">`
        + `<polygon class="chart-spark-area" points="0,${height} ${points} ${width},${height}" style="fill:${color}"/>`
        + `<polyline class="chart-spark-line" points="${points}" fill="none" style="stroke:${color}"/></svg>`;
}

// Points [{x, y, color, title, key}] along x (a time or a rank) at height y
// (a score; above yMax at the top edge). A point without a score (y null) sits
// in a lane "no score" under the axis. thresholds [{y, label}] are dashed
// lines, labelled "<label> <y>" on the left.
function scatterSvg(points, opts) {
    opts = opts || {};
    const list = (points || []).filter(Boolean);
    if (!list.length) return '';
    const width = opts.width > 0 ? Number(opts.width) : 520, height = opts.height > 0 ? Number(opts.height) : 120;
    const score = point => (point.y === null || point.y === undefined || point.y === '' ? NaN : Number(point.y));
    const scores = list.map(score).filter(Number.isFinite);
    const thresholds = (opts.thresholds || []).filter(th => th && Number.isFinite(Number(th.y)))
        .map(th => ({ y: Number(th.y), label: `${th.label ?? ''} ${_chartNumber(th.y)}`.trim() }));
    const yMax = opts.yMax > 0 ? Number(opts.yMax) : Math.max(1, ...scores, ...thresholds.map(th => th.y)) * 1.1;
    const lane = scores.length < list.length;
    const longest = Math.max(lane ? 'no score'.length : 0, ...thresholds.map(th => th.label.length));
    const left = Math.max(40, Math.ceil(longest * 5.6) + 10), radius = 4, laneH = 16;
    const top = 8, axisY = height - (lane ? laneH + 10 : 6), laneY = axisY + 6;
    const yOf = y => axisY - (axisY - top) * Math.min(Math.max(y, 0), yMax) / yMax;
    const xs = list.map((point, i) => (typeof point.x === 'number' && Number.isFinite(point.x) ? point.x : i));
    const xMin = Math.min(...xs), xMax = Math.max(...xs), inset = radius + 2;
    const xOf = x => (xMax > xMin ? left + inset + (width - left - 2 * inset) * (x - xMin) / (xMax - xMin) : (left + width) / 2);
    let svg = `<line class="chart-axis" x1="${left}" x2="${width}" y1="${axisY}" y2="${axisY}"/>`;
    for (const th of thresholds) {
        if (th.y < 0 || th.y > yMax) continue;
        const y = yOf(th.y);
        svg += `<line class="chart-threshold" x1="${left}" x2="${width}" y1="${_chartCoord(y)}" y2="${_chartCoord(y)}" stroke-dasharray="4 3"/>`
            + `<text class="chart-threshold-label" x="0" y="${_chartCoord(y + 3)}">${escapeHtml(th.label)}</text>`;
    }
    if (lane) {
        svg += `<rect class="chart-lane" x="${left}" y="${laneY}" width="${width - left}" height="${laneH}" fill="none"/>`
            + `<text class="chart-lane-label" x="0" y="${laneY + laneH / 2 + 3}">no score</text>`;
    }
    list.forEach((point, i) => {
        const y = score(point), scored = Number.isFinite(y);
        const title = point.title ?? (scored ? _chartNumber(y) : 'no score');
        svg += `<circle class="chart-point" cx="${_chartCoord(xOf(xs[i]))}" cy="${_chartCoord(scored ? yOf(y) : laneY + laneH / 2)}" r="${radius}" data-key="${escapeHtml(point.key)}" style="fill:${_chartColor(point.color, i)}"><title>${escapeHtml(title)}</title></circle>`;
    });
    return `<svg class="chart-svg chart-scatter" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">${svg}</svg>`;
}

// Bars [{key, y, color, title}] side by side in their order (a submission
// each, the oldest first), each as high as its y (a score; above yMax at the
// top edge). A bar of 0 or without a score (y null) is a stub on the axis, so
// that it shows and takes a click. thresholds [{y, label}] are dashed lines,
// labelled "<label> <y>" on the left. Each bar is a <g class="chart-slot"
// data-key> with its tooltip, over the whole height of its slot.
function verdictBarsSvg(items, opts) {
    opts = opts || {};
    const list = (items || []).filter(Boolean);
    if (!list.length) return '';
    const width = opts.width > 0 ? Number(opts.width) : 520, height = opts.height > 0 ? Number(opts.height) : 120;
    const score = item => (item.y === null || item.y === undefined || item.y === '' ? NaN : Number(item.y));
    const scores = list.map(score).filter(Number.isFinite);
    const thresholds = (opts.thresholds || []).filter(th => th && Number.isFinite(Number(th.y)))
        .map(th => ({ y: Number(th.y), label: `${th.label ?? ''} ${_chartNumber(th.y)}`.trim() }));
    const yMax = opts.yMax > 0 ? Number(opts.yMax) : Math.max(1, ...scores, ...thresholds.map(th => th.y)) * 1.1;
    const longest = Math.max(0, ...thresholds.map(th => th.label.length));
    const left = Math.max(40, Math.ceil(longest * 5.6) + 10), top = 8, axisY = height - 6, stub = 3;
    const plotH = Math.max(axisY - top, 10);
    const yOf = y => axisY - plotH * Math.min(Math.max(y, 0), yMax) / yMax;
    const slot = Math.max(width - left, 1) / list.length;
    // A bar fills its slot but a 1 px gap, up to 24 px
    const barW = Math.min(Math.max(slot - (slot > 2 ? 1 : 0), 0.5), 24), inset = (slot - barW) / 2;
    let svg = '';
    for (const th of thresholds) {
        if (th.y < 0 || th.y > yMax) continue;
        const y = yOf(th.y);
        svg += `<line class="chart-threshold" x1="${left}" x2="${width}" y1="${_chartCoord(y)}" y2="${_chartCoord(y)}" stroke-dasharray="4 3"/>`
            + `<text class="chart-threshold-label" x="0" y="${_chartCoord(y + 3)}">${escapeHtml(th.label)}</text>`;
    }
    list.forEach((item, i) => {
        const y = score(item), x = left + i * slot;
        const h = Math.max(axisY - yOf(Number.isFinite(y) ? y : 0), stub);
        const title = item.title ?? (Number.isFinite(y) ? _chartNumber(y) : 'no score');
        svg += `<g class="chart-slot" data-key="${escapeHtml(item.key)}"><title>${escapeHtml(title)}</title>`
            + `<rect class="chart-hit" x="${_chartCoord(x)}" y="${top}" width="${_chartCoord(slot)}" height="${_chartCoord(plotH)}" fill="transparent"/>`
            + `<rect class="chart-bar" x="${_chartCoord(x + inset)}" y="${_chartCoord(axisY - h)}" width="${_chartCoord(barW)}" height="${_chartCoord(h)}" style="fill:${_chartColor(item.color, i)}"/></g>`;
    });
    svg += `<line class="chart-axis" x1="${left}" x2="${width}" y1="${axisY}" y2="${axisY}"/>`;
    return `<svg class="chart-svg chart-bars" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">${svg}</svg>`;
}

// The hint a card shows instead of a chart without data ("No alerts in this range")
function chartEmptyHtml(text) {
    return `<div class="chart-empty">${escapeHtml(text)}</div>`;
}

// Such a hint as the only row of a table view: with its full stop ("No alerts yet.")
function _chartSentence(text) {
    const words = String(text ?? '');
    return /[.!?…]$/.test(words) ? words : `${words}.`;
}

// --- Sankey ---
// The keys of counts [{key, count}] (countBy) that stand on their own: the
// `top` most frequent, ties in the order of counts. label(key) is the key if
// kept, else otherLabel. An "other" never stands for a single key: when only
// one would be left over, it is kept too.
function topWithOther(counts, top, otherLabel) {
    const n = typeof top === 'number' && top >= 0 ? Math.floor(top) : 6;
    const ranked = (Array.isArray(counts) ? counts : []).filter(Boolean)
        .sort((a, b) => (Number(b.count) || 0) - (Number(a.count) || 0));
    const keep = new Set((ranked.length > n + 1 ? ranked.slice(0, n) : ranked).map(c => c.key));
    return { keep, label: key => (keep.has(key) ? key : otherLabel) };
}

// The alerts as a flow engine → rule → process (the Alerts tab), for
// layoutSankey and sankeySvg: {columns, links, labels}. A column groups its
// names as the filters of the Alerts tab compare them, so a node counts what
// its filter lists: an engine in any case; a rule or a process in any case and
// without the blanks around it, none (or one named so) as "(unknown)", which
// the filters of the rule and the process take for both. A node takes the
// first spelling of its name in opts.names (default: the alerts), e.g. all
// alerts while the flow shows those of the filters, so a name keeps its
// spelling whatever the filters. Every engine stands on its own, so do the
// `top` (default 6) most frequent rules and processes; the rest is "other
// rules" / "other processes", last in its column. A node's id is its kind and
// name: "engine:Sigma", "rule:<name>", "process:<name>" ("engine:" for alerts
// without an engine, labelled "(unknown)"), so a process named like a rule or
// "other processes" stays a node of its own. labels has each id's text.
function alertFlow(alerts, opts) {
    return _chartFlow(alerts, [
        // [kind, an alert's name in the flow, the key it is grouped by, the rest]: an engine in
        // any case, as the engine choice compares it; a rule or a process as its filter does
        ['engine', alert => String(alert.engine || ''), name => name.toLowerCase(), null],
        ['rule', alert => alertRuleName(alert).trim() || '(unknown)', _alertsNameKey, 'other rules'],
        ['process', alert => alertProcessName(alert).trim() || '(unknown)', _alertsNameKey, 'other processes'],
    ], opts);
}

// Items as a flow from column to column (alertFlow, sysmonFlow): steps
// [[kind, name(item), key(name), other], ...], one per column. An item's node
// in a column is its name there, grouped by its key, in the first spelling
// of opts.names (default: the items); with `other`, only the `top` (default
// 6) most frequent names stand on their own, the rest is `other`, last in its
// column. Ids are "<kind>:<name>" ("<kind>:" for an empty name, labelled
// "(unknown)"); each item flows once from each column to the next.
function _chartFlow(items, steps, opts) {
    opts = opts || {};
    const list = (items || []).filter(Boolean);
    const names = Array.isArray(opts.names) ? opts.names.filter(Boolean) : list;
    // Per step, per item: the id of its node
    const ids = steps.map(([kind, name, keyOf, other]) => {
        const first = new Map();                    // the key -> the id of its first spelling
        const spell = item => {
            const text = name(item), key = keyOf(text);
            if (!first.has(key)) first.set(key, `${kind}:${text}`);
            return first.get(key);
        };
        if (names !== list) names.forEach(spell);
        const own = list.map(spell);
        return other ? own.map(topWithOther(countBy(own), opts.top ?? 6, other).label) : own;
    });
    const labels = Object.create(null);
    const columns = steps.map(([kind, , , other], c) => {
        const ranked = countBy(ids[c]).map(x => x.key);
        const column = [...ranked.filter(id => id !== other), ...ranked.filter(id => id === other)];
        column.forEach(id => { labels[id] = id === other ? other : id.slice(kind.length + 1) || '(unknown)'; });
        return column;
    });
    const links = [];
    for (let c = 0; c + 1 < steps.length; c++) {
        const pairs = new Map();                    // source id -> Map(target id -> items)
        for (let i = 0; i < list.length; i++) {
            const source = ids[c][i], target = ids[c + 1][i];
            if (!pairs.has(source)) pairs.set(source, new Map());
            pairs.get(source).set(target, (pairs.get(source).get(target) || 0) + 1);
        }
        pairs.forEach((targets, source) => targets.forEach((value, target) => links.push({ source, target, value })));
    }
    return { columns, links, labels };
}

// Where the nodes and bands of a Sankey go: {nodes: [{id, col, x, y, h,
// value}], links: [{source, target, value, sy, ty, thickness_s,
// thickness_t}], width, height, nodeWidth}. columns [[id, ...], ...] run from
// left to right, links [{source, target, value}] from a column to the next;
// other links, values not above 0, an id listed a second time and nodes
// without flow are left out, the same pair twice adds up. A node's value is
// max(in, out), its height that value or its square root (scale 'sqrt', the
// default, so small flows stay visible; 'linear' for true proportions) times
// one factor for all columns: the largest at which every column fits. The
// nodes of a column keep their order, centred, `gap` apart (less where the
// gaps would take more than a quarter of the height), at least 2 px high
// (less where a crowded column would not fit). A band leaves its source at
// sy and enters its target at ty, as thick as its share of each node; the
// bands of a node lie side by side from its top in the order of their other
// ends, so they do not cross there. The last column keeps labelWidth (a
// quarter of the width) on its right for its labels.
function layoutSankey(columns, links, opts) {
    opts = opts || {};
    const width = opts.width > 0 ? Number(opts.width) : 720, height = opts.height > 0 ? Number(opts.height) : 240;
    const nodeWidth = opts.nodeWidth > 0 ? Number(opts.nodeWidth) : 12;
    const gap = opts.gap >= 0 ? Number(opts.gap) : 10;
    const labelWidth = opts.labelWidth >= 0 ? Number(opts.labelWidth) : width / 4;
    const size = opts.scale === 'linear' ? v => v : Math.sqrt;
    const layout = { nodes: [], links: [], width, height, nodeWidth };
    const colOf = new Map();                        // each id in the first column that lists it
    (columns || []).forEach((column, c) => (column || []).forEach(id => { if (!colOf.has(id)) colOf.set(id, c); }));
    const flows = new Map();                        // source -> Map(target -> value)
    const flowIn = new Map(), flowOut = new Map();
    for (const link of links || []) {
        const value = Number(link?.value), from = colOf.get(link?.source);
        if (!(value > 0) || !Number.isFinite(value) || from === undefined || colOf.get(link.target) !== from + 1) continue;
        if (!flows.has(link.source)) flows.set(link.source, new Map());
        flows.get(link.source).set(link.target, (flows.get(link.source).get(link.target) || 0) + value);
        flowOut.set(link.source, (flowOut.get(link.source) || 0) + value);
        flowIn.set(link.target, (flowIn.get(link.target) || 0) + value);
    }
    const stacks = [];                              // the columns with nodes: {c, nodes, space, least, k}
    colOf.forEach((c, id) => {
        const value = Math.max(flowIn.get(id) || 0, flowOut.get(id) || 0);
        if (!(value > 0)) return;
        if (stacks[stacks.length - 1]?.c !== c) stacks.push({ c, nodes: [] });
        stacks[stacks.length - 1].nodes.push({ id, col: c, x: 0, y: 0, h: 0, value });
    });
    if (stacks.length < 2) return layout;
    for (const stack of stacks) {
        const n = stack.nodes.length;
        stack.space = n > 1 ? Math.min(gap, height / 4 / (n - 1)) : 0;
        stack.least = Math.min(2, height / 2 / n);
        stack.k = _sankeyFit(stack.nodes.map(node => size(node.value)), height - stack.space * (n - 1), stack.least);
    }
    const k = Math.min(...stacks.map(stack => stack.k));
    const first = stacks[0].c, step = Math.max(width - labelWidth - nodeWidth, 0) / (stacks[stacks.length - 1].c - first);
    for (const { c, nodes, space, least } of stacks) {
        nodes.forEach(node => { node.h = Math.max(size(node.value) * k, least); });
        let y = (height - nodes.reduce((sum, node) => sum + node.h, 0) - space * (nodes.length - 1)) / 2;
        for (const node of nodes) {
            node.x = (c - first) * step;
            node.y = y;
            y += node.h + space;
        }
        layout.nodes.push(...nodes);
    }
    const byId = new Map(layout.nodes.map(node => [node.id, node]));
    flows.forEach((targets, source) => targets.forEach((value, target) => {
        const src = byId.get(source), dst = byId.get(target);
        layout.links.push({ source, target, value, sy: 0, ty: 0, thickness_s: src.h * value / src.value, thickness_t: dst.h * value / dst.value });
    }));
    const stackBands = (end, other, at, thick) => {
        const ends = new Map();                     // node id -> its bands at this end
        for (const band of layout.links) {
            if (!ends.has(band[end])) ends.set(band[end], []);
            ends.get(band[end]).push(band);
        }
        ends.forEach((bands, id) => {
            let y = byId.get(id).y;
            bands.sort((a, b) => byId.get(a[other]).y - byId.get(b[other]).y)
                .forEach(band => { band[at] = y; y += band[thick]; });
        });
    };
    stackBands('source', 'target', 'sy', 'thickness_s');
    stackBands('target', 'source', 'ty', 'thickness_t');
    return layout;
}

// The largest factor k at which nodes of these sizes, each max(size * k,
// least) high, take no more than `room` (at least `least` per node): the
// smallest go to `least` one by one until the others fit at k.
function _sankeyFit(sizes, room, least) {
    const sorted = [...sizes].sort((a, b) => a - b);
    let rest = sorted.reduce((sum, s) => sum + s, 0);
    for (let i = 0; i < sorted.length; i++) {
        const k = (room - i * least) / rest;
        if (sorted[i] * k >= least - 1e-9) return k;
        rest -= sorted[i];
    }
    return 0;
}

// A Sankey of layoutSankey as SVG: the bands in the colour of their source,
// translucent, the thinnest on top (at least 1 px, so a flow of 1 among
// thousands stays visible), then the nodes, each with its name and value on
// its right. colors: {id: 'var(--x)'} or a function of the node; else the
// palette by the node's place in its column, one colour further per column
// (the first column takes the colours of a pie of the same list). labels:
// {id: text} or a function of the id; else the id. A name is cut with "…" to
// the room up to the next column; the <title> has it in full. A node is a
// <g data-sankey-node="<id>">, a band a <path data-sankey-link=
// '["<source>","<target>"]' data-source data-target>: the pair as JSON, so a
// click gets both ends back whatever their names.
function sankeySvg(layout, opts) {
    opts = opts || {};
    const nodes = (layout?.nodes || []).filter(n => n && [n.x, n.y, n.h].every(Number.isFinite));
    if (!nodes.length) return '';
    const width = layout.width > 0 ? Number(layout.width) : 720, height = layout.height > 0 ? Number(layout.height) : 240;
    const nodeWidth = layout.nodeWidth > 0 ? Number(layout.nodeWidth) : 12;
    const own = (map, id) => (map && typeof map === 'object' && Object.prototype.hasOwnProperty.call(map, id) ? map[id] : undefined);
    const labelOf = id => String((typeof opts.labels === 'function' ? opts.labels(id) : own(opts.labels, id)) ?? id ?? '');
    const colorOf = n => (typeof opts.colors === 'function' ? opts.colors(n) : own(opts.colors, n.id));
    const drawn = new Map(), places = new Map();    // id -> the node to draw; column -> nodes so far
    for (const n of nodes) {
        const i = places.get(n.col) || 0;
        places.set(n.col, i + 1);
        drawn.set(n.id, { ...n, label: labelOf(n.id), color: _chartColor(colorOf(n), (Number(n.col) || 0) + i) });
    }
    const c = _chartCoord;
    const span = (y, t) => (t >= 1 ? [y, t] : [y + t / 2 - 0.5, 1]);
    const bands = (layout.links || []).filter(b => b && drawn.has(b.source) && drawn.has(b.target)
        && [b.sy, b.ty, b.thickness_s, b.thickness_t].every(Number.isFinite)).sort((a, b) => b.value - a.value);
    let svg = '';
    for (const band of bands) {
        const src = drawn.get(band.source), dst = drawn.get(band.target);
        const x0 = src.x + nodeWidth, x1 = dst.x, mx = (x0 + x1) / 2;
        const [y0, t0] = span(band.sy, band.thickness_s), [y1, t1] = span(band.ty, band.thickness_t);
        const value = Number(band.value) || 0;
        const title = `${src.label} → ${dst.label}: ${_chartNumber(value)}`;
        svg += `<path class="sankey-link" data-sankey-link="${escapeHtml(JSON.stringify([String(band.source), String(band.target)]))}"`
            + ` data-source="${escapeHtml(band.source)}" data-target="${escapeHtml(band.target)}" data-value="${value}"`
            + ` d="M${c(x0)} ${c(y0)} C${c(mx)} ${c(y0)} ${c(mx)} ${c(y1)} ${c(x1)} ${c(y1)} L${c(x1)} ${c(y1 + t1)}`
            + ` C${c(mx)} ${c(y1 + t1)} ${c(mx)} ${c(y0 + t0)} ${c(x0)} ${c(y0 + t0)} Z" style="fill:${src.color}"><title>${escapeHtml(title)}</title></path>`;
    }
    // A label has the room from its node to the next column (or the right edge), at about 6 px per character
    const xs = [...new Set(nodes.map(n => n.x))].sort((a, b) => a - b);
    for (const n of drawn.values()) {
        const value = Number(n.value) || 0, count = _chartNumber(value);
        const room = (xs.find(x => x > n.x) ?? width) - n.x - nodeWidth - 12;
        const name = _chartEllipsis(n.label, Math.max(Math.floor(room / 6) - count.length - 1, 4));
        svg += `<g class="sankey-node" data-sankey-node="${escapeHtml(n.id)}" data-value="${value}"><title>${escapeHtml(`${n.label}: ${count}`)}</title>`
            + `<rect class="sankey-bar" x="${c(n.x)}" y="${c(n.y)}" width="${c(nodeWidth)}" height="${c(n.h)}" rx="2" style="fill:${n.color}"/>`
            + `<text class="sankey-label" x="${c(n.x + nodeWidth + 6)}" y="${c(n.y + n.h / 2 + 3.5)}">${escapeHtml(name)} <tspan class="sankey-value">${count}</tspan></text></g>`;
    }
    // 6 px above and below: the label of a node at the edge is not cut off
    return `<svg class="chart-svg chart-sankey" width="${width}" height="${height + 12}" viewBox="0 -6 ${width} ${height + 12}">${svg}</svg>`;
}

// =============================================
// RUSTINEL TRACE ANALYSIS CONSOLE
// =============================================

function initRtraceTabs() {
    document.querySelectorAll('.rtrace-detail-tabs .rtrace-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            const target = tab.dataset.rtab;
            state.rtraceActiveDetailTab = target;
            document.querySelectorAll('.rtrace-tab').forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            renderRtraceEventTable();
        });
    });

    // Process dropdown change
    const dropdown = document.getElementById('rtrace-process-select');
    if (dropdown) {
        dropdown.addEventListener('change', () => {
            const pid = dropdown.value;
            if (pid) {
                selectRtraceProcess(pid);
            }
        });
    }
    initRtraceEventSort();
}

function renderRtraceConsole() {
    renderRtraceProcessDropdown();
    renderRtraceTimeline();
    renderRtraceProcessTree();
    if (state.rtraceSelectedPid) {
        updateRtraceInfoBar();
        renderRtraceDetailTabs();
        renderRtraceEventTable();
    }
}

function renderRtraceProcessDropdown() {
    const dropdown = document.getElementById('rtrace-process-select');
    if (!dropdown) return;

    const searchTerm = (document.getElementById('rtrace-search')?.value || '').toLowerCase().trim();
    let procs = Object.values(state.processes);

    // Apply same search filter as tree
    if (searchTerm) {
        procs = procs.filter(proc => {
            const haystack = [
                proc.name, proc.image, proc.command_line, proc.user,
                String(proc.pid || ''),
            ].filter(Boolean).join(' ').toLowerCase();
            if (haystack.includes(searchTerm)) return true;
            const alertHaystack = (proc.alerts || []).map(a => [
                a.name, a.rule, a.process_name,
                JSON.stringify(a.raw || {}),
            ].join(' ')).join(' ').toLowerCase();
            return alertHaystack.includes(searchTerm);
        });
    }

    let html = '<option value="">-- select process --</option>';
    procs.forEach(proc => {
        const hasExited = !!proc.exit_time;
        const alertCount = (proc.alerts || []).length;
        const status = hasExited ? 'stopped' : 'running';
        const selected = state.rtraceSelectedPid == procKey(proc) ? 'selected' : '';
        html += `<option value="${escapeHtml(procKey(proc))}" ${selected}>${escapeHtml(proc.name || 'unknown')} &mdash; ${status} (${alertCount} ev)</option>`;
    });
    dropdown.innerHTML = html;
}

function selectRtraceProcess(pid) {
    pid = String(pid);          // instance key, see procKey()
    state.rtraceSelectedPid = pid;
    state.selectedProcess = pid;

    // Show detail content, hide placeholder
    const placeholder = document.getElementById('rtrace-detail-placeholder');
    const content = document.getElementById('rtrace-detail-content');
    if (placeholder) placeholder.style.display = 'none';
    if (content) content.style.display = 'flex';

    // Update dropdown
    const dropdown = document.getElementById('rtrace-process-select');
    if (dropdown) dropdown.value = pid;

    // Update info bar
    updateRtraceInfoBar();

    // Highlight in tree
    document.querySelectorAll('.rtrace-tree-item').forEach(el => el.classList.remove('active'));
    const treeItem = document.querySelector(`.rtrace-tree-item[data-pid="${CSS.escape(pid)}"]`);
    if (treeItem) treeItem.classList.add('active');

    // Render tabs and events
    renderRtraceDetailTabs();
    renderRtraceEventTable();
    renderProcessList();
}

function updateRtraceInfoBar() {
    const proc = state.processes[state.rtraceSelectedPid] || state.processes[String(state.rtraceSelectedPid)];
    if (!proc) return;

    const hasExited = !!proc.exit_time;
    const alertCount = (proc.alerts || []).length;
    const childCount = (proc.children || []).length + 1;
    const duration = computeLifespan(proc.first_seen, proc.exit_time || proc.last_seen || new Date().toISOString());

    // Calculate verdict score based on threats
    const threats = proc.activity?.threats || 0;
    let verdictScore = Math.min(100, threats * 10);
    let verdictClass = verdictScore >= 50 ? '' : verdictScore > 0 ? '' : 'unknown';
    if (verdictScore === 0) verdictClass = 'clean';

    document.getElementById('rtrace-proc-name').textContent = proc.name || 'unknown';

    const verdictBadge = document.getElementById('rtrace-verdict-badge');
    verdictBadge.textContent = verdictScore > 0 ? `Malicious \u00B7 ${verdictScore}/100` : 'Clean';
    verdictBadge.className = `rtrace-verdict-badge ${verdictClass}`;

    document.getElementById('rtrace-tag-status').textContent = hasExited ? 'stopped' : 'running';
    document.getElementById('rtrace-stat-procs').textContent = `${childCount} processes`;
    document.getElementById('rtrace-stat-events').textContent = `${alertCount} events`;
    document.getElementById('rtrace-stat-duration').textContent = duration || '0m 0s';
    document.getElementById('rtrace-path').textContent = proc.image || proc.command_line || '--';

    // Update severity bar
    updateRtraceSeverityBar(proc);
}

function updateRtraceSeverityBar(proc) {
    const sevCountsEl = document.getElementById('rtrace-sev-counts');
    const enginesEl = document.getElementById('rtrace-engines');
    const rulesEl = document.getElementById('rtrace-top-rules');
    if (!sevCountsEl) return;
    // The counts as pills (CHART) or as a table (TABLE); the switch is written once
    const toggle = document.getElementById('rtrace-sev-view-toggle');
    if (toggle && !toggle.firstElementChild) toggle.innerHTML = viewToggleHtml('rtrace-severity');

    const alerts = proc.alerts || [];

    // Count severities
    const sevCounts = { critical: 0, high: 0, medium: 0, low: 0 };
    const engines = {};
    const rules = {};

    alerts.forEach(a => {
        const sev = (a.severity || 'unknown').toLowerCase();
        if (sevCounts[sev] !== undefined) sevCounts[sev]++;
        const eng = (a.engine || 'unknown').toLowerCase();
        engines[eng] = (engines[eng] || 0) + 1;
        const rule = a.rule_name || '';
        if (rule) rules[rule] = (rules[rule] || { count: 0, sev: sev });
        if (rule) rules[rule].count++;
    });

    // Render severity pills
    let sevHtml = '';
    if (sevCounts.critical > 0) sevHtml += `<span class="rtrace-sev-pill critical"><span class="sev-dot"></span>${sevCounts.critical} Critical</span>`;
    if (sevCounts.high > 0) sevHtml += `<span class="rtrace-sev-pill high"><span class="sev-dot"></span>${sevCounts.high} High</span>`;
    if (sevCounts.medium > 0) sevHtml += `<span class="rtrace-sev-pill medium"><span class="sev-dot"></span>${sevCounts.medium} Medium</span>`;
    if (sevCounts.low > 0) sevHtml += `<span class="rtrace-sev-pill low"><span class="sev-dot"></span>${sevCounts.low} Low</span>`;
    if (!sevHtml) sevHtml = '<span style="font-size:10px;color:var(--text-muted);">No detections</span>';
    sevCountsEl.innerHTML = sevHtml;
    const sevTable = document.getElementById('rtrace-sev-table');
    if (sevTable) sevTable.innerHTML = rtraceSeverityTableHtml(sevCounts);

    // Render engine chips
    let engHtml = '';
    for (const [eng, count] of Object.entries(engines)) {
        engHtml += `<span class="rtrace-engine-chip">${escapeHtml(eng)} (${count})</span>`;
    }
    enginesEl.innerHTML = engHtml;

    // Render top rules (max 4, sorted by count)
    const sortedRules = Object.entries(rules).sort((a, b) => b[1].count - a[1].count).slice(0, 4);
    let ruleHtml = '';
    sortedRules.forEach(([name, info]) => {
        const sevClass = info.sev === 'critical' ? ' critical' : info.sev === 'high' ? ' high' : '';
        ruleHtml += `<span class="rtrace-rule-chip${sevClass}" title="${escapeHtml(name)}">${escapeHtml(name)} (${info.count})</span>`;
    });
    rulesEl.innerHTML = ruleHtml;
}

// The table view of the severity bar: the alerts per severity, zeros included
function rtraceSeverityTableHtml(sevCounts) {
    const rows = ['critical', 'high', 'medium', 'low'].map(sev =>
        `<tr><td data-sort-value="${severitySortValue(sev)}"><span class="event-severity ${cssToken(sev)}">${sev}</span></td>`
        + `<td class="view-table-num">${sevCounts[sev] || 0}</td></tr>`);
    return '<table class="view-table view-table-compact" data-sortable data-sort-id="rtrace-severity-counts"><thead><tr>'
        + `<th>Severity</th><th class="view-table-num">Count</th></tr></thead><tbody>${rows.join('')}</tbody></table>`;
}

// The table view of the Tracing timeline: the alerts of each lane, in lane order
function rtraceTimelineTableHtml(lanes) {
    const rows = lanes.map(lane =>
        `<tr><td><span class="view-table-dot" style="background:${lane.color}"></span>${lane.name}</td>`
        + `<td class="view-table-num">${lane.count}</td></tr>`);
    if (!rows.length) rows.push('<tr data-sort-skip><td colspan="2" class="view-table-empty">No alerts yet.</td></tr>');
    return '<table class="view-table view-table-compact" data-sortable data-sort-id="rtrace-timeline-types"><thead><tr>'
        + `<th>Event type</th><th class="view-table-num">Count</th></tr></thead><tbody>${rows.join('')}</tbody></table>`;
}

function renderRtraceTimeline() {
    const container = document.getElementById('rtrace-timeline-bar');
    const rangeEl = document.getElementById('rtrace-timeline-range');
    // The lanes (CHART) or the alerts per lane (TABLE); the switch is written once
    const toggle = document.getElementById('rtrace-timeline-view-toggle');
    if (toggle && !toggle.firstElementChild) toggle.innerHTML = viewToggleHtml('rtrace-timeline');
    const table = document.getElementById('rtrace-timeline-table');
    if (!container || !state.alerts.length) {
        if (container) container.innerHTML = '<div class="rtrace-timeline-cursor" id="rtrace-timeline-cursor"></div>';
        if (rangeEl) rangeEl.textContent = '';
        if (table) table.innerHTML = rtraceTimelineTableHtml([]);
        return;
    }

    // Category config: lane order and colors (name: in the legend and the table)
    const lanes = [
        { key: 'critical', label: 'CRIT', name: 'Critical/High', color: 'var(--severity-critical)' },
        { key: 'process', label: 'PROC', name: 'Process', color: 'var(--graph-process)' },
        { key: 'network', label: 'NET', name: 'Network', color: 'var(--graph-network)' },
        { key: 'dns', label: 'DNS', name: 'DNS', color: 'var(--graph-dns)' },
        { key: 'file', label: 'FILE', name: 'File', color: 'var(--graph-file)' },
        { key: 'registry', label: 'REG', name: 'Registry', color: 'var(--graph-registry)' },
    ];

    // Parse all alert timestamps and categorize
    // Plain comparison is correct for ISO timestamps and far cheaper than
    // localeCompare on ~10k strings.
    const sorted = [...state.alerts].sort((a, b) => {
        const x = a.timestamp || '', y = b.timestamp || '';
        return x < y ? -1 : x > y ? 1 : 0;
    });
    const timestamps = sorted.map(a => new Date(a.timestamp).getTime()).filter(t => !isNaN(t));
    if (!timestamps.length) {
        container.innerHTML = '<div class="rtrace-timeline-cursor" id="rtrace-timeline-cursor"></div>';
        if (table) table.innerHTML = rtraceTimelineTableHtml(lanes.map(lane => ({ ...lane, count: 0 })));
        return;
    }

    // Spreading the array into Math.min/max fails beyond ~64k arguments.
    let tMin = Infinity, tMax = -Infinity;
    for (const t of timestamps) { if (t < tMin) tMin = t; if (t > tMax) tMax = t; }
    const duration = tMax - tMin || 1; // avoid div by zero

    // Show time range
    if (rangeEl) {
        const startStr = new Date(tMin).toLocaleTimeString();
        const endStr = new Date(tMax).toLocaleTimeString();
        const durSec = Math.round(duration / 1000);
        const durStr = durSec >= 60 ? `${Math.floor(durSec/60)}m ${durSec%60}s` : `${durSec}s`;
        rangeEl.textContent = `${startStr} \u2014 ${endStr} (${durStr})`;
    }

    // Categorize each alert into a lane
    function getLaneKey(alert) {
        // High/Critical severity always goes to the CRIT lane
        const sev = (alert.severity || '').toLowerCase();
        if (sev === 'critical' || sev === 'high') return 'critical';
        const cat = (Array.isArray(alert.category) ? alert.category[0] : alert.category || '').toLowerCase();
        if (cat === 'dns') return 'dns';
        if (cat === 'network') return 'network';
        if (cat === 'file') return 'file';
        if (cat === 'registry') return 'registry';
        if (cat === 'process') return 'process';
        return 'process'; // default
    }

    // Group alerts by lane
    const laneEvents = {};
    lanes.forEach(l => { laneEvents[l.key] = []; });
    sorted.forEach(alert => {
        const t = new Date(alert.timestamp).getTime();
        if (isNaN(t)) return;
        const key = getLaneKey(alert);
        if (laneEvents[key]) {
            laneEvents[key].push({ t, alert });
        }
    });
    // The same alerts the lanes draw (an alert without a valid time has no place on either)
    if (table) table.innerHTML = rtraceTimelineTableHtml(lanes.map(lane => ({ ...lane, count: laneEvents[lane.key].length })));

    // Render lanes
    const containerWidth = container.clientWidth || 600;
    let html = '';

    lanes.forEach(lane => {
        const events = laneEvents[lane.key];
        if (!events.length && lane.key !== 'process') {
            // Skip empty lanes (but always show process lane)
            return;
        }

        html += `<div class="rtrace-timeline-lane">`;
        html += `<span class="rtrace-timeline-lane-label">${lane.label}</span>`;

        // Cluster nearby events to avoid overlapping marks
        // Group events within 0.5% of timeline width
        const clusterThreshold = duration * 0.005;
        const clusters = [];
        events.forEach(ev => {
            if (clusters.length && (ev.t - clusters[clusters.length-1].tEnd) < clusterThreshold) {
                clusters[clusters.length-1].count++;
                clusters[clusters.length-1].tEnd = ev.t;
            } else {
                clusters.push({ tStart: ev.t, tEnd: ev.t, count: 1 });
            }
        });

        clusters.forEach(cluster => {
            const leftPct = ((cluster.tStart - tMin) / duration) * 100;
            const widthPct = Math.max(0.4, ((cluster.tEnd - cluster.tStart) / duration) * 100 + 0.4);
            const opacity = Math.min(1, 0.5 + (cluster.count / 10));
            html += `<div class="rtrace-timeline-event" style="left:${leftPct}%;width:${widthPct}%;background:${lane.color};opacity:${opacity};" title="${lane.label}: ${cluster.count} event${cluster.count>1?'s':''} at ${new Date(cluster.tStart).toLocaleTimeString()}"></div>`;
        });

        html += `</div>`;
    });

    html += `<div class="rtrace-timeline-cursor" id="rtrace-timeline-cursor"></div>`;
    container.innerHTML = html;

    // The container survives re-renders, so the cursor listeners are attached
    // once; previously each render (every alert change) added another pair.
    if (container.dataset.cursorBound) return;
    container.dataset.cursorBound = '1';
    container.addEventListener('mousemove', function(e) {
        const cursor = document.getElementById('rtrace-timeline-cursor');
        if (cursor) {
            const rect = container.getBoundingClientRect();
            const x = e.clientX - rect.left;
            cursor.style.left = x + 'px';
            cursor.style.opacity = '0.8';
        }
    });
    container.addEventListener('mouseleave', function() {
        const cursor = document.getElementById('rtrace-timeline-cursor');
        if (cursor) cursor.style.opacity = '0';
    });
}

function filterRtraceTree() {
    renderRtraceProcessTree();
    renderRtraceProcessDropdown();
}

function renderRtraceProcessTree() {
    const container = document.getElementById('rtrace-tree-list');
    const countEl = document.getElementById('rtrace-tree-count');
    if (!container) return;

    const searchTerm = (document.getElementById('rtrace-search')?.value || '').toLowerCase().trim();
    const procs = Object.values(state.processes);

    // Filter processes by search term (match process name, image path, command line, file activity)
    let filtered = procs;
    if (searchTerm) {
        filtered = procs.filter(proc => {
            const haystack = [
                proc.name, proc.image, proc.command_line, proc.user,
                String(proc.pid || ''),
            ].filter(Boolean).join(' ').toLowerCase();
            if (haystack.includes(searchTerm)) return true;
            // Also search in alerts for file paths, rule names, raw data
            const alertHaystack = (proc.alerts || []).map(a => [
                a.name, a.rule, a.process_name,
                JSON.stringify(a.raw || {}),
            ].join(' ')).join(' ').toLowerCase();
            return alertHaystack.includes(searchTerm);
        });
    }

    if (countEl) countEl.textContent = filtered.length + (searchTerm ? `/${procs.length}` : '');

    if (!filtered.length) {
        const msg = searchTerm
            ? `No processes matching "${escapeHtml(searchTerm)}" (${procs.length} total)`
            : 'No processes tracked yet. Submit a sample to begin.';
        container.innerHTML = `<div style="padding:12px;color:var(--text-muted);font-size:11px;">${msg}</div>`;
        return;
    }

    // Sort by first_seen
    const sorted = [...filtered].sort((a, b) => (a.first_seen || '').localeCompare(b.first_seen || ''));

    // Compute max severity per process
    function getMaxSeverity(proc) {
        const alerts = proc.alerts || [];
        let max = 'low';
        const order = { 'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'unknown': 0 };
        alerts.forEach(a => {
            const sev = (a.severity || 'unknown').toLowerCase();
            if ((order[sev] || 0) > (order[max] || 0)) max = sev;
        });
        return max;
    }

    let html = '';
    sorted.forEach(proc => {
        const relTime = formatRelativeTime(proc.first_seen);
        const isActive = state.rtraceSelectedPid == procKey(proc);
        const indent = proc.parent_key && state.processes[proc.parent_key] ? '<span class="tree-indent"></span>' : '';
        const threats = proc.activity?.threats || 0;
        const maxSev = getMaxSeverity(proc);
        const sevDot = threats > 0 ? `<span class="ev-sev-dot ${cssToken(maxSev)}" style="width:6px;height:6px;display:inline-block;"></span>` : '';

        html += `<div class="rtrace-tree-item ${isActive ? 'active' : ''}" data-pid="${escapeHtml(procKey(proc))}" onclick="selectRtraceProcess(${jsArg(procKey(proc))})">
            ${sevDot}
            <span class="tree-time">${relTime}</span>
            ${indent}<span class="tree-pid">${escapeHtml(String(proc.pid))}</span>
            <span class="tree-name">${escapeHtml(proc.name || 'unknown')}</span>
            ${threats > 0 ? `<span class="tree-threat-count">${threats}</span>` : ''}
        </div>`;
    });
    container.innerHTML = html;
}

function renderRtraceDetailTabs() {
    const proc = state.processes[state.rtraceSelectedPid] || state.processes[String(state.rtraceSelectedPid)];
    if (!proc) return;

    const act = proc.activity || {};
    // Update tab counts
    const tabCountMap = {
        'http': act.http || 0,
        'connections': act.network || 0,
        'dns': act.dns || 0,
        'files': act.file || 0,
        'registry': act.registry || 0,
        'artifacts': act.artifacts || 0,
        'modules': act.modules || 0,
    };

    document.querySelectorAll('.rtrace-tab').forEach(tab => {
        const rtab = tab.dataset.rtab;
        const countEl = tab.querySelector('.rtrace-tab-count');
        if (countEl && tabCountMap[rtab] !== undefined) {
            countEl.textContent = tabCountMap[rtab];
        }
    });
}

function renderRtraceEventTable() {
    const container = document.getElementById('rtrace-event-table-body');
    if (!container) return;

    const proc = state.processes[state.rtraceSelectedPid] || state.processes[String(state.rtraceSelectedPid)];
    if (!proc) {
        container.innerHTML = '<div style="padding:20px;color:var(--text-muted);">Select a process to view events.</div>';
        return;
    }

    // Get alerts for this process (and children)
    let events = (proc.alerts || []).slice();
    // Include children's events too
    (proc.children || []).forEach(childPid => {
        const child = state.processes[childPid] || state.processes[String(childPid)];
        if (child && child.alerts) {
            events = events.concat(child.alerts);
        }
    });

    // Filter by active detail tab
    const activeTab = state.rtraceActiveDetailTab;
    if (activeTab === 'verdict') {
        // Verdict tab: render summary view instead of event table
        renderRtraceVerdictView(container, proc, events);
        return;
    } else if (activeTab === 'dns') {
        events = events.filter(e => {
            const cat = (Array.isArray(e.category) ? e.category[0] : e.category || '').toLowerCase();
            const raw = e.raw || {};
            const action = (raw.event?.action || '').toLowerCase();
            return cat === 'dns' || action === 'dns_query' || action.includes('dns') || !!raw.dns;
        });
    } else if (activeTab === 'http') {
        events = events.filter(e => {
            const raw = e.raw || {};
            const cat = (Array.isArray(e.category) ? e.category[0] : e.category || '').toLowerCase();
            const destPort = raw.destination?.port || raw.network?.destination?.port || '';
            const action = (raw.event?.action || '').toLowerCase();
            // HTTP = network connections on ports 80/443, or explicit http data
            return (cat === 'network' && (destPort == 80 || destPort == 443 || destPort == 8080 || destPort == 8443))
                || !!raw.http || !!raw.url || action.includes('http');
        });
    } else if (activeTab === 'files') {
        events = events.filter(e => {
            const cat = (Array.isArray(e.category) ? e.category[0] : e.category || '').toLowerCase();
            const raw = e.raw || {};
            const action = (raw.event?.action || '').toLowerCase();
            return cat === 'file' || action.includes('file') || !!raw.file;
        });
    } else if (activeTab === 'registry') {
        events = events.filter(e => {
            const cat = (Array.isArray(e.category) ? e.category[0] : e.category || '').toLowerCase();
            const raw = e.raw || {};
            const action = (raw.event?.action || '').toLowerCase();
            return cat === 'registry' || action.startsWith('registry') || !!raw.registry;
        });
    } else if (activeTab === 'connections') {
        events = events.filter(e => {
            const cat = (Array.isArray(e.category) ? e.category[0] : e.category || '').toLowerCase();
            const raw = e.raw || {};
            const action = (raw.event?.action || '').toLowerCase();
            return cat === 'network' || action === 'connection_attempted' || action === 'network_connect'
                || action.includes('connect') || !!raw.network;
        });
    } else if (activeTab === 'modules') {
        events = events.filter(e => {
            const raw = e.raw || {};
            const cat = (Array.isArray(e.category) ? e.category[0] : e.category || '').toLowerCase();
            const action = (raw.event?.action || '').toLowerCase();
            return cat === 'process' || action === 'load' || action === 'image_load'
                || action === 'image_loaded' || action.includes('module') || action.includes('dll');
        });
    } else if (activeTab === 'artifacts') {
        events = events.filter(e => {
            const engine = (e.engine || '').toLowerCase();
            const raw = e.raw || {};
            const action = (raw.event?.action || '').toLowerCase();
            // Artifacts = YARA/IOC matches, dropped files, or suspicious scripts
            return engine === 'yara' || engine === 'ioc'
                || action.includes('drop') || action.includes('write')
                || (e.rule_name && (e.rule_name.toLowerCase().includes('artifact')
                    || e.rule_name.toLowerCase().includes('drop')));
        });
    }
    // 'live' tab: no filter (shows all events)

    // Sort by timestamp, then by the column chosen in the heads (equal values
    // keep their time order); every alerts poll renders the grid in that order
    events.sort((a, b) => (a.timestamp || '').localeCompare(b.timestamp || ''));
    const sort = tableSortState[RTRACE_EVENT_SORT_ID];
    if (sort) events = sortItemsBy(events, ev => rtraceEventSortValue(ev, sort.col), sort.dir);

    if (!events.length) {
        container.innerHTML = '<div style="padding:20px;color:var(--text-muted);font-size:11px;">No events for this filter.</div>';
        return;
    }

    let html = '';
    events.forEach((ev, idx) => {
        const relTime = formatRelativeTime(ev.timestamp);
        const actionShort = rtraceEventAction(ev);
        const actionClass = getActionBadgeClass(actionShort);
        const severity = (ev.severity || 'unknown').toLowerCase();
        const ruleName = ev.rule_name || '';
        const engine = (ev.engine || '').toUpperCase();
        const pid = ev.pid || '?';
        const procName = ev.process_name || '';
        const details = getEventDetails(ev);
        const sevRowClass = (severity === 'critical' || severity === 'high') ? ` sev-${severity}` : '';

        html += `<div class="rtrace-event-row${sevRowClass}" onclick="openAlertDetailById(${jsArg(ev.id)})" title="${escapeHtml(ruleName)}\n${escapeHtml(ev.rule_description || '')}">
            <span class="ev-sev"><span class="ev-sev-dot ${cssToken(severity)}"></span></span>
            <span class="ev-time">${escapeHtml(relTime)}</span>
            <span class="ev-action">
                <span class="rtrace-action-badge ${actionClass}">${escapeHtml(actionShort)}</span>
            </span>
            <span class="ev-rule"><span class="ev-rule-name">${escapeHtml(ruleName)}</span>${engine ? `<span class="ev-engine-tag">${escapeHtml(engine)}</span>` : ''}</span>
            <span class="ev-pid">${escapeHtml(String(pid))}</span>
            <span class="ev-process">${escapeHtml(procName)}</span>
            <span class="ev-details">${escapeHtml(details)}</span>
            ${ev.pid ? `<span class="ev-graph-btn" title="Investigate PID ${escapeHtml(String(ev.pid))} in process graph" onclick="event.stopPropagation(); focusProcessGraph(${jsArg(ev.pid)}, {reset:true, at:${jsArg(ev.timestamp || '')}})">&#9673; Graph</span>` : '<span class="ev-graph-btn-empty"></span>'}
        </div>`;
    });
    container.innerHTML = html;
}

// --- Sorting the event grid ---
// The grid is a CSS grid of <div> rows, not a <table> (its layout would not
// survive the change): its heads sort the events before they are rendered,
// with the order kept in tableSortState and compared like a table's cells
// (sortKey, compareSortKeys).
const RTRACE_EVENT_SORT_ID = 'rtrace-events';

// The action word a row shows ("registry_set" -> "registry")
function rtraceEventAction(ev) {
    const action = ev.raw?.event?.action || ev.engine || 'event';
    return action.replace('_', ' ').split(' ')[0];
}

// What an event sorts by in column col: Sev, Time, Action, Rule / Engine,
// PID, Process, Details. The severity by rank, the time by when.
function rtraceEventSortValue(ev, col) {
    switch (col) {
        case 0: return severitySortValue(alertSeverity(ev));
        case 1: return sortTimeValue(ev.timestamp);
        case 2: return rtraceEventAction(ev);
        case 3: return ev.rule_name || '';
        case 4: return ev.pid || '';
        case 5: return ev.process_name || '';
        default: return getEventDetails(ev);
    }
}

// The items in the order of one value, as sortRows orders rows: stable in
// either direction, empty values last in either direction
function sortItemsBy(items, valueOf, dir) {
    const sign = dir === 'desc' ? -1 : 1;
    return items.map((item, index) => ({ item, index, key: sortKey(valueOf(item)) }))
        .sort((a, b) => (a.key.empty || b.key.empty ? compareSortKeys(a.key, b.key) : sign * compareSortKeys(a.key, b.key))
            || a.index - b.index)
        .map(entry => entry.item);
}

// A click on the sorted column turns the order; another column starts ascending
function sortRtraceEvents(col) {
    const current = tableSortState[RTRACE_EVENT_SORT_ID];
    tableSortState[RTRACE_EVENT_SORT_ID] = { col, dir: current && current.col === col && current.dir === 'asc' ? 'desc' : 'asc' };
    updateRtraceEventSortHeads();
    renderRtraceEventTable();
}

// aria-sort on the sorted head, which style.css shows as ▲ / ▼ (↕ on the others)
function updateRtraceEventSortHeads() {
    const sort = tableSortState[RTRACE_EVENT_SORT_ID];
    document.querySelectorAll('.rtrace-event-table-header .rtrace-col').forEach((head, col) => {
        if (sort && sort.col === col) head.setAttribute('aria-sort', sort.dir === 'desc' ? 'descending' : 'ascending');
        else head.removeAttribute('aria-sort');
    });
}

// The heads take a click, Enter and Space. They are static markup: set up once.
function initRtraceEventSort() {
    const header = document.querySelector('.rtrace-event-table-header');
    if (!header) return;
    const heads = [...header.querySelectorAll('.rtrace-col')];
    header.setAttribute('role', 'row');
    heads.forEach(head => {
        head.setAttribute('role', 'columnheader');
        head.setAttribute('tabindex', '0');
    });
    const columnOf = target => heads.indexOf(target && target.closest ? target.closest('.rtrace-col') : null);
    header.addEventListener('click', e => {
        const col = columnOf(e.target);
        if (col >= 0) sortRtraceEvents(col);
    });
    header.addEventListener('keydown', e => {
        if (e.key !== 'Enter' && e.key !== ' ') return;
        const col = columnOf(e.target);
        if (col < 0) return;
        e.preventDefault();
        sortRtraceEvents(col);
    });
    updateRtraceEventSortHeads();
}

// --- Verdict Summary View ---
function renderRtraceVerdictView(container, proc, events) {
    const act = proc.activity || {};
    const threats = act.threats || 0;
    const verdictScore = Math.min(100, threats * 10);

    // Collect MITRE techniques
    const techniques = new Set();
    const tactics = new Set();
    const engines = {};
    const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };

    events.forEach(ev => {
        (ev.tags || []).forEach(tag => {
            if (tag.startsWith('attack.t')) techniques.add(tag.replace('attack.', '').toUpperCase());
            else if (tag.startsWith('attack.')) tactics.add(tag.replace('attack.', '').toUpperCase());
        });
        const eng = ev.engine || 'unknown';
        engines[eng] = (engines[eng] || 0) + 1;
        const sev = (ev.severity || 'low').toLowerCase();
        if (severityCounts[sev] !== undefined) severityCounts[sev]++;
    });

    let scoreColor = verdictScore >= 70 ? 'var(--accent-red)' : verdictScore >= 40 ? 'var(--accent-orange)' : verdictScore > 0 ? 'var(--accent-yellow)' : 'var(--accent-green)';
    let scoreLabel = verdictScore >= 70 ? 'Malicious' : verdictScore >= 40 ? 'Suspicious' : verdictScore > 0 ? 'Low Risk' : 'Clean';

    let html = `<div style="padding:16px;">`;

    // Score display
    html += `<div style="display:flex;align-items:center;gap:20px;margin-bottom:20px;padding:16px;background:var(--bg-card);border:1px solid var(--border-primary);border-radius:var(--radius-lg);">
        <div style="text-align:center;">
            <div style="font-size:36px;font-weight:700;color:${scoreColor};">${verdictScore}</div>
            <div style="font-size:10px;color:var(--text-muted);">/ 100</div>
        </div>
        <div>
            <div style="font-size:14px;font-weight:700;color:${scoreColor};">${scoreLabel}</div>
            <div style="font-size:11px;color:var(--text-secondary);margin-top:4px;">${threats} detection${threats !== 1 ? 's' : ''} triggered across ${Object.keys(engines).length} engine${Object.keys(engines).length !== 1 ? 's' : ''}</div>
        </div>
    </div>`;

    // Severity breakdown
    html += `<div style="margin-bottom:16px;">
        <div style="font-size:10px;font-weight:600;color:var(--text-muted);letter-spacing:1px;margin-bottom:8px;">SEVERITY BREAKDOWN</div>
        <div style="display:flex;gap:8px;">
            ${severityCounts.critical > 0 ? `<span class="sev-badge critical">${severityCounts.critical} Critical</span>` : ''}
            ${severityCounts.high > 0 ? `<span class="sev-badge high">${severityCounts.high} High</span>` : ''}
            ${severityCounts.medium > 0 ? `<span class="sev-badge medium">${severityCounts.medium} Medium</span>` : ''}
            ${severityCounts.low > 0 ? `<span class="sev-badge low">${severityCounts.low} Low</span>` : ''}
            ${threats === 0 ? '<span style="color:var(--text-muted);font-size:11px;">No detections</span>' : ''}
        </div>
    </div>`;

    // Engine breakdown
    if (Object.keys(engines).length > 0) {
        html += `<div style="margin-bottom:16px;">
            <div style="font-size:10px;font-weight:600;color:var(--text-muted);letter-spacing:1px;margin-bottom:8px;">DETECTION ENGINES</div>
            <div style="display:flex;gap:8px;flex-wrap:wrap;">`;
        for (const [eng, count] of Object.entries(engines)) {
            html += `<span style="font-size:10px;padding:3px 8px;border-radius:var(--radius);background:var(--bg-counter);border:1px solid var(--border-primary);color:var(--text-primary);">${escapeHtml(eng.toUpperCase())} <strong>${count}</strong></span>`;
        }
        html += `</div></div>`;
    }

    // MITRE ATT&CK
    if (tactics.size > 0 || techniques.size > 0) {
        html += `<div style="margin-bottom:16px;">
            <div style="font-size:10px;font-weight:600;color:var(--text-muted);letter-spacing:1px;margin-bottom:8px;">MITRE ATT&CK</div>
            <div style="display:flex;gap:4px;flex-wrap:wrap;">`;
        [...tactics].sort().forEach(t => { html += `<span class="tag tactic">${escapeHtml(t)}</span>`; });
        [...techniques].sort().forEach(t => { html += `<span class="tag technique">${escapeHtml(t)}</span>`; });
        html += `</div></div>`;
    }

    // Activity summary
    html += `<div style="margin-bottom:16px;">
        <div style="font-size:10px;font-weight:600;color:var(--text-muted);letter-spacing:1px;margin-bottom:8px;">ACTIVITY SUMMARY</div>
        <div class="activity-grid" style="grid-template-columns:repeat(4,1fr);">
            ${activityCounter('FILE', act.file)}
            ${activityCounter('NETWORK', act.network)}
            ${activityCounter('DNS', act.dns)}
            ${activityCounter('HTTP', act.http)}
            ${activityCounter('REGISTRY', act.registry)}
            ${activityCounter('MODULES', act.modules)}
            ${activityCounter('ARTIFACTS', act.artifacts)}
            ${activityCounter('THREATS', act.threats)}
        </div>
    </div>`;

    html += `</div>`;
    container.innerHTML = html;
}

function getActionBadgeClass(action) {
    const a = action.toLowerCase();
    if (a === 'miss' || a === 'error' || a === 'fail') return 'miss';
    if (a === 'load' || a === 'image') return 'load';
    if (a === 'create' || a === 'new') return 'create';
    if (a === 'write' || a === 'modify') return 'write';
    if (a === 'connect' || a === 'network') return 'connect';
    if (a === 'query' || a === 'dns') return 'query';
    if (a === 'set' || a === 'registry') return 'set';
    if (a === 'terminate' || a === 'exit') return 'terminate';
    return 'default';
}

function getEventDetails(ev) {
    const raw = ev.raw || {};

    // Try structured fields first
    if (raw.file?.path) return raw.file.path;
    if (raw.dns?.question?.name) return `Query: ${raw.dns.question.name}`;
    if (raw.registry?.path) return raw.registry.path;
    if (raw.destination?.ip) {
        const port = raw.destination?.port || '';
        return `${raw.destination.ip}${port ? ':' + port : ''}`;
    }
    if (raw.network?.destination?.ip) {
        const port = raw.network.destination?.port || '';
        return `${raw.network.destination.ip}${port ? ':' + port : ''}`;
    }

    // ECS-style fields (flat dotted keys from Rustinel)
    const procExe = raw['process.executable'] || raw.process?.executable || '';
    const procCmd = raw['process.command_line'] || raw.process?.command_line || '';
    const matchSummary = raw['edr.match']?.summary || (typeof raw['edr.match'] === 'string' ? raw['edr.match'] : '');
    const targetImage = raw['edr.process.target_image'] || '';

    if (matchSummary) return matchSummary;
    if (targetImage) return `Target: ${targetImage}`;
    if (procCmd && procCmd.length > 5) return procCmd;
    if (procExe) return procExe;
    if (ev.command_line) return ev.command_line;
    if (ev.process_image) return ev.process_image;

    // Fibratus-style: events array
    if (raw.events && raw.events.length) {
        const firstEv = raw.events[0];
        if (firstEv.params?.exe) return firstEv.params.exe;
        if (firstEv.params?.cmdline) return firstEv.params.cmdline;
        if (firstEv.params?.file_name) return firstEv.params.file_name;
    }

    // Fallback: rule description or truncated JSON
    if (ev.rule_description) return ev.rule_description;
    if (ev.rule_name) return ev.rule_name;

    // Last resort: compact JSON excerpt
    const jsonStr = JSON.stringify(raw);
    return jsonStr.length > 140 ? jsonStr.substring(0, 140) + '...' : jsonStr;
}

function clearStoppedProcesses() {
    // Filter out stopped processes from view (client-side only)
    const procs = Object.values(state.processes);
    procs.forEach(proc => {
        if (proc.exit_time) delete state.processes[procKey(proc)];
    });
    releaseDashboardCounts();               // the list changed in place: the dashboard counts it again
    renderRtraceConsole();
    renderProcessList();
}

function clearAllTracing() {
    state.alerts = [];
    state.processes = {};
    releaseDashboardCounts();               // the dashboard (hidden here) holds no counts of the lists cleared
    state.rtraceSelectedPid = null;
    const placeholder = document.getElementById('rtrace-detail-placeholder');
    const content = document.getElementById('rtrace-detail-content');
    if (placeholder) placeholder.style.display = 'flex';
    if (content) content.style.display = 'none';
    renderRtraceConsole();
    renderProcessList();
}

// =============================================
// AV/AMSI SCANNER (ThreatCheck / DefenderCheck)
// =============================================

let threatscanFile = null;

// Unified tool registry. `render` reuses the existing per-tool result renderers.
const THREATSCAN_TOOLS = [
    { id: 'threatcheck',   label: 'ThreatCheck',   icon: '&#x1F50D;', url: '/api/scan/threatcheck',   render: renderScanResult },
    { id: 'defendercheck', label: 'DefenderCheck', icon: '&#x1F6E1;', url: '/api/scan/defendercheck', render: renderScanResult },
    { id: 'ember',         label: 'EMBER2024',     icon: '&#x1F9EC;', url: '/api/scan/ember',         render: renderEmberResult },
    { id: 'capa',          label: 'capa',          icon: '&#x1F9E9;', url: '/api/scan/capa',          render: renderCapaResult },
];

function initThreatScan() {
    const zone = document.getElementById('threatscan-drop-zone');
    const input = document.getElementById('threatscan-file-input');
    if (!zone || !input) return;

    zone.addEventListener('dragover', e => {
        e.preventDefault();
        zone.classList.add('dragover');
    });
    zone.addEventListener('dragleave', () => zone.classList.remove('dragover'));
    zone.addEventListener('drop', e => {
        e.preventDefault();
        zone.classList.remove('dragover');
        if (e.dataTransfer.files.length) {
            threatscanFile = e.dataTransfer.files[0];
            _threatscanShowFile();
        }
    });
    input.addEventListener('change', () => {
        if (input.files.length) {
            threatscanFile = input.files[0];
            _threatscanShowFile();
            input.value = '';
        }
    });

    updateThreatScanOptions();
}

function _threatscanShowFile() {
    const zone = document.getElementById('threatscan-drop-zone');
    zone.classList.add('has-file');
    zone.querySelector('p').innerHTML = `<strong>${escapeHtml(threatscanFile.name)}</strong> (${formatSize(threatscanFile.size)}) <span class="hex-change-file" onclick="threatscanResetDrop()">change</span>`;
}

function threatscanResetDrop() {
    threatscanFile = null;
    const zone = document.getElementById('threatscan-drop-zone');
    zone.classList.remove('has-file');
    zone.querySelector('p').innerHTML = 'Drop a file to scan or <span class="hex-browse-link" onclick="document.getElementById(\'threatscan-file-input\').click()">browse</span>';
}

// Show per-tool option rows only when their tool is selected.
function updateThreatScanOptions() {
    const tc = document.getElementById('ts-tool-threatcheck');
    const em = document.getElementById('ts-tool-ember');
    const tcOpts = document.getElementById('ts-opts-threatcheck');
    const emOpts = document.getElementById('ts-opts-ember');
    if (tcOpts) tcOpts.style.display = (tc && tc.checked) ? '' : 'none';
    if (emOpts) emOpts.style.display = (em && em.checked) ? '' : 'none';
}

function threatscanSelectAll(on) {
    THREATSCAN_TOOLS.forEach(t => {
        const cb = document.getElementById('ts-tool-' + t.id);
        if (cb && !cb.disabled) cb.checked = on;
    });
    updateThreatScanOptions();
}

function _threatscanSelectedTools() {
    return THREATSCAN_TOOLS.filter(t => {
        const cb = document.getElementById('ts-tool-' + t.id);
        return cb && cb.checked && !cb.disabled;
    });
}

// Short verdict label shown in each tool card header.
function _threatscanVerdict(toolId, data) {
    if (toolId === 'ember') {
        const pct = typeof data.score === 'number' ? ' ' + (data.score * 100).toFixed(1) + '%' : '';
        return data.malicious
            ? { text: 'MALICIOUS' + pct, cls: 'ts-state-bad' }
            : { text: 'BENIGN' + pct, cls: 'ts-state-good' };
    }
    if (toolId === 'capa') {
        const c = data.capability_count != null ? data.capability_count : (data.capabilities || []).length;
        return { text: c + ' capabilit' + (c === 1 ? 'y' : 'ies'), cls: 'ts-state-info' };
    }
    // threatcheck / defendercheck
    if (data.detected) return { text: 'DETECTED', cls: 'ts-state-bad' };
    if (data.clean) return { text: 'CLEAN', cls: 'ts-state-good' };
    return { text: 'UNKNOWN', cls: 'ts-state-info' };
}

async function runThreatScan() {
    const pathInput = document.getElementById('threatscan-filepath').value.trim();
    const resultsEl = document.getElementById('threatscan-results');
    const btn = document.getElementById('threatscan-run-btn');

    if (!threatscanFile && !pathInput) {
        resultsEl.innerHTML = '<div class="scanner-error">Please select a file or enter a VM path.</div>';
        return;
    }
    const tools = _threatscanSelectedTools();
    if (!tools.length) {
        resultsEl.innerHTML = '<div class="scanner-error">Select at least one tool to run.</div>';
        return;
    }

    // Snapshot options once, up front.
    const engine = (document.getElementById('scanner-engine') || {}).value || 'Defender';
    const fileType = (document.getElementById('scanner-type') || {}).value || 'Bin';
    const model = (document.getElementById('ember-model') || {}).value || 'EMBER2024_all';
    const threshold = (document.getElementById('ember-threshold') || {}).value || '0.5';

    btn.disabled = true;
    btn.textContent = 'Scanning…';

    // Build one card per selected tool, all starting in the running state.
    resultsEl.innerHTML = tools.map(t => `
        <div class="ts-tool-card" id="ts-card-${t.id}">
            <div class="ts-tool-card-head">
                <span class="ts-tool-icon">${t.icon}</span>
                <span class="ts-tool-name">${escapeHtml(t.label)}</span>
                <span class="ts-tool-state ts-state-running" id="ts-state-${t.id}"><span class="ts-spinner ts-spinner-sm"></span>running</span>
            </div>
            <div class="ts-tool-card-body" id="ts-body-${t.id}">
                <div class="ts-tool-running"><span class="ts-spinner"></span><span>Running ${escapeHtml(t.label)}… this may take up to 2 minutes.</span></div>
            </div>
        </div>`).join('');

    const jobs = tools.map(async (t) => {
        const fd = new FormData();
        if (threatscanFile) fd.append('file', threatscanFile);
        else fd.append('path', pathInput);
        if (t.id === 'threatcheck') { fd.append('engine', engine); fd.append('type', fileType); }
        if (t.id === 'ember') { fd.append('model', model); fd.append('threshold', threshold); }

        const body = document.getElementById('ts-body-' + t.id);
        const state = document.getElementById('ts-state-' + t.id);
        try {
            const resp = await fetch(t.url, { method: 'POST', body: fd });
            const data = await resp.json();
            if (data.error) {
                if (body) body.innerHTML = `<div class="scanner-error">Error: ${escapeHtml(data.error)}</div>` + renderRawToggle(data);
                if (state) { state.textContent = 'error'; state.className = 'ts-tool-state ts-state-error'; }
            } else {
                if (body) t.render(data, body);
                if (state) { const v = _threatscanVerdict(t.id, data); state.textContent = v.text; state.className = 'ts-tool-state ' + v.cls; }
            }
        } catch (e) {
            if (body) body.innerHTML = `<div class="scanner-error">Network error: ${escapeHtml(e.message)}</div>`;
            if (state) { state.textContent = 'error'; state.className = 'ts-tool-state ts-state-error'; }
        }
    });

    await Promise.all(jobs);

    btn.disabled = false;
    btn.textContent = 'Scan';
    loadScanHistory();
}

// Collapsible "raw output" block: the full, unmodified response object the
// tool/endpoint produced, pretty-printed as JSON. Appended to every scan card
// (ThreatCheck/DefenderCheck/EMBER/capa) and history detail so the original
// output is always inspectable as text behind a toggle. DOM-relative toggle
// (no ids) since it's rendered many times across cards + history rows.
function renderRawToggle(data, label) {
    if (data == null) return '';
    label = label || 'Raw output (JSON)';
    let json;
    try {
        json = JSON.stringify(data, null, 2);
    } catch (e) {
        json = String(data);
    }
    if (!json) return '';
    return `<div class="raw-json-toggle" data-label="${escapeHtml(label)}" onclick="toggleRawJson(this)">&#9656; ${escapeHtml(label)}</div>`
         + `<pre class="raw-json" style="display:none">${escapeHtml(json)}</pre>`;
}

function toggleRawJson(el) {
    const pre = el.nextElementSibling;
    if (!pre || !pre.classList.contains('raw-json')) return;
    const open = pre.style.display !== 'none';
    pre.style.display = open ? 'none' : 'block';
    const label = el.getAttribute('data-label') || 'Raw output (JSON)';
    el.innerHTML = (open ? '&#9656; ' : '&#9662; ') + escapeHtml(label);
}

function renderScanResult(data, container) {
    const statusClass = data.clean ? 'scan-clean' : data.detected ? 'scan-detected' : 'scan-unknown';
    const statusText = data.clean ? 'CLEAN - No threat found' : data.detected ? 'DETECTED - Threat signature identified' : 'UNKNOWN';
    const statusIcon = data.clean ? '&#x2705;' : data.detected ? '&#x26A0;' : '&#x2753;';

    let html = `<div class="scan-result ${statusClass}">`;
    html += `<div class="scan-result-header">`;
    html += `<span class="scan-result-icon">${statusIcon}</span>`;
    html += `<span class="scan-result-status">${statusText}</span>`;
    html += `<span class="scan-result-tool">${escapeHtml(data.tool)}${data.engine ? ' (' + escapeHtml(data.engine) + ')' : ''}</span>`;
    html += `</div>`;

    // Output console
    if (data.output) {
        html += `<div class="scan-output-header">Raw Output:</div>`;
        html += `<pre class="scan-output">${escapeHtml(data.output)}</pre>`;
    }

    // If detected, offer to open in hex editor
    if (data.detected && data.filepath) {
        html += `<div class="scan-actions">`;
        html += `<button class="btn btn-sm" onclick="hexOpenFile(${jsArg(data.filepath)})">Open in Hex Editor</button>`;
        html += `</div>`;
    }

    html += renderRawToggle(data);
    html += `</div>`;
    container.innerHTML = html;
}

// ---------------------------------------------------------------
// Unified, server-persisted scan history (shared timeline across
// ThreatCheck / DefenderCheck / EMBER / capa, and any curl/API/MCP
// scan). Rendered identically into all three per-tab containers.
// ---------------------------------------------------------------
const SCAN_HISTORY_CONTAINERS = ['threatscan-history-list'];

async function loadScanHistory() {
    try {
        const resp = await fetch('/api/scan/history?limit=100');
        const data = await resp.json();
        renderUnifiedHistory(data.history || []);
    } catch (e) {
        // history must never break the page; a chart that has nothing yet says why
        if (!_scoreHistoryDrawn) renderScoreHistory(null, 'Scan history not available');
    }
}

// A scan's time in epoch ms (NaN without one) and as the list shows it ("05/11/2026, 11:37:31")
function _histTime(entry) {
    const date = new Date(entry?.timestamp ?? NaN), t = date.getTime();
    return { t, text: Number.isNaN(t) ? '\u2014' : date.toLocaleString('en-GB', { hour12: false }) };
}

// The tools whose score is the evidence score of the memory scans (its own
// scale: suspicious >= 2, malicious >= 6), as app.py's _normalize_scan sets it
const EVIDENCE_SCORE_TOOLS = ['aether', 'exit capture'];

// What a scan's score is: 'evidence' (Aether, Exit Capture), 'probability'
// (EMBER2024 reports the model's malicious probability, 0-1) or '' (any other tool)
function _histScoreKind(entry) {
    const tool = String(entry?.tool ?? '').trim().toLowerCase();
    if (EVIDENCE_SCORE_TOOLS.includes(tool)) return 'evidence';
    return /ember/.test(tool) ? 'probability' : '';
}

// A probability (0-1) in per cent: "33.9%"
function _histPercent(score) {
    return `${(Number(score) * 100).toFixed(1)}%`;
}

// A scan's label in the list: its verdict with its score. A suspicious
// memory scan (the server sets detected for it as well) is SUSPICIOUS, in
// the colour SCORE HISTORY gives it, not DETECTED.
function _histStatus(entry) {
    const v = (entry.verdict || '').toLowerCase();
    const pct = entry.score == null ? ''
        : _histScoreKind(entry) === 'probability' ? ` ${_histPercent(entry.score)}`
        : ` score ${Number(entry.score).toFixed(2)}`;
    if (entry.status === 'timeout') return { cls: 'history-unknown', text: 'TIMEOUT' };
    if (entry.status && entry.status !== 'ok') return { cls: 'history-unknown', text: entry.status.toUpperCase() };
    if (v === 'suspicious') return { cls: 'history-suspicious', text: 'SUSPICIOUS' + pct };
    if (v === 'malicious' || entry.detected === true) return { cls: 'history-detected', text: (v === 'malicious' ? 'MALICIOUS' : 'DETECTED') + pct };
    if (v === 'benign' || v === 'clean' || entry.clean === true) return { cls: 'history-clean', text: (v === 'benign' ? 'BENIGN' : 'CLEAN') + pct };
    if (v === 'analyzed' || v) return { cls: 'history-unknown', text: (v || '?').toUpperCase() };
    return { cls: 'history-unknown', text: '?' };
}

function renderUnifiedHistory(history) {
    const containers = SCAN_HISTORY_CONTAINERS
        .map(id => document.getElementById(id)).filter(Boolean);
    if (!containers.length) return;

    if (!history.length) {
        containers.forEach(c => { c.innerHTML = '<div class="scan-history-empty">No scans yet.</div>'; });
        renderScoreHistory(history);
        return;
    }

    let html = '';
    history.forEach((entry, i) => {
        const ts = _histTime(entry).text;
        const st = _histStatus(entry);
        // data-history-index: the point of SCORE HISTORY that leads here
        html += `<div class="scan-history-entry ${st.cls}" data-history-index="${i}" onclick="toggleHistoryDetail(this)">`;
        html += `<span class="scan-history-more">&#9656;</span>`;
        html += `<span class="scan-history-time">${escapeHtml(ts)}</span>`;
        html += `<span class="scan-history-tool">${escapeHtml(entry.tool || '?')}</span>`;
        html += `<span class="scan-history-file" title="${escapeHtml(entry.filename || '')}">${escapeHtml(entry.filename || '--')}</span>`;
        html += `<span class="scan-history-status">${escapeHtml(st.text)}</span>`;
        html += `</div>`;
        html += `<div class="scan-history-detail" style="display:none">${renderHistoryDetail(entry)}</div>`;
    });
    containers.forEach(c => { c.innerHTML = html; });
    renderScoreHistory(history);
}

function toggleHistoryDetail(el) {
    const panel = el.nextElementSibling;
    if (!panel || !panel.classList.contains('scan-history-detail')) return;
    const open = panel.style.display !== 'none';
    panel.style.display = open ? 'none' : 'block';
    const caret = el.querySelector('.scan-history-more');
    if (caret) caret.innerHTML = open ? '&#9656;' : '&#9662;';
}

function renderHistoryDetail(entry) {
    const r = entry.result || {};
    let h = '<div class="scan-history-detail-inner">';

    const kv = [];
    if (entry.sha256) kv.push(['SHA256', entry.sha256]);
    if (entry.size != null) kv.push(['Size', formatSize(entry.size)]);
    if (r.model) kv.push(['Model', r.model]);
    if (entry.score != null) kv.push(['Score', Number(entry.score).toFixed(4)]);
    if (r.engine) kv.push(['Engine', r.engine]);
    if (r.threat_name) kv.push(['Threat', r.threat_name]);
    if (r.capability_count != null) kv.push(['Capabilities', r.capability_count]);
    if (Array.isArray(r.tactics) && r.tactics.length) kv.push(['ATT&CK', r.tactics.join(', ')]);
    if (r.elapsed_ms != null) kv.push(['Elapsed', r.elapsed_ms + ' ms']);
    if (kv.length) {
        h += '<div class="scan-hist-kv">';
        kv.forEach(([k, v]) => {
            h += `<div><span class="k">${escapeHtml(k)}</span><span class="v">${escapeHtml(String(v))}</span></div>`;
        });
        h += '</div>';
    }

    // EMBER "why" explanation (reuse the rich renderer)
    if (r.explanation && typeof renderEmberExplanation === 'function') {
        h += renderEmberExplanation(r.explanation);
    }

    // capa capabilities
    if (Array.isArray(r.capabilities) && r.capabilities.length) {
        h += '<div class="ember-more-sub">Capabilities</div><div class="ember-api-list">';
        r.capabilities.slice(0, 60).forEach(c => {
            const name = (typeof c === 'string') ? c : (c.name || c.rule || '');
            const ns = (typeof c === 'object' && c.namespace) ? c.namespace : '';
            h += `<span class="ember-api-chip" title="${escapeHtml(ns)}">${escapeHtml(name)}</span>`;
        });
        h += '</div>';
    }

    // raw tool output / error
    if (r.output) h += `<pre class="scan-hist-output">${escapeHtml(String(r.output))}</pre>`;
    if (r.error) h += `<div class="scanner-error">${escapeHtml(String(r.error))}</div>`;

    // Full original response as text (behind a toggle).
    if (Object.keys(r).length) h += renderRawToggle(r);

    h += '</div>';
    return h;
}

async function clearScanHistory() {
    try {
        await fetch('/api/scan/history/clear', { method: 'POST' });
    } catch (e) { /* ignore */ }
    loadScanHistory();
}

// --- SCORE HISTORY of the ThreatScan tab ---
// Above the list of the scan history: a point per scan, the oldest on the
// left, by its place in the history (scans come in bursts, which a time axis
// would pile up), in the colour of its verdict. A memory scan (Aether, Exit
// Capture) stands at the height of its evidence score, which the dashed
// thresholds are of; every other scan, and a memory scan without a score,
// lies in the lane "no score" under the axis (EMBER2024's probability is no
// evidence score: its tooltip and the table show it). A click on a point
// opens its entry of the list, scrolls it into view and marks it; the table
// view lists every scan.
const SCORE_HISTORY_THRESHOLDS = [{ y: 2, label: 'SUSPICIOUS' }, { y: 6, label: 'MALICIOUS' }];
// The verdicts by colour, in the order of the legend; any other verdict (unknown, dumped, analyzed, none) is the last
const SCORE_HISTORY_GROUPS = [
    { key: 'clean', label: 'clean / benign', verdicts: ['clean', 'benign'], color: 'var(--severity-low)' },
    { key: 'suspicious', label: 'suspicious', verdicts: ['suspicious'], color: 'var(--severity-medium)' },
    { key: 'detected', label: 'detected / malicious', verdicts: ['detected', 'malicious'], color: 'var(--severity-critical)' },
    { key: 'other', label: 'no verdict', verdicts: [], color: 'var(--text-muted)' },
];
// The scale reaches a tenth above the highest score or the MALICIOUS line,
// at most this far: a score of 50 sits at the top edge (its tooltip has it)
// instead of pressing the others under the lines
const SCORE_HISTORY_MAX = 10;
// What the chart on screen was drawn from, and for which width: a resize draws it again
let _scoreHistoryDrawn = null;

// Draws SCORE HISTORY of the scan history (the newest scan first, as the
// server lists it): the chart, its legend, its table view; renderUnifiedHistory
// calls it. Without scans it says so, or `hint`.
function renderScoreHistory(history, hint) {
    if (!document.getElementById('score-history-plot')) return;
    // Written once: a render keeps the switch (and the keyboard focus on it)
    const slot = document.getElementById('score-history-toggle');
    if (slot && !slot.firstElementChild) slot.innerHTML = viewToggleHtml('score-history');
    const scans = scoreHistoryScans(history), empty = hint || 'No scans yet';
    const legend = document.getElementById('score-history-legend'), table = document.getElementById('score-history-table');
    // The legend first: it takes its room beside the plot (none without
    // scans), so the plot is measured at the width the points get
    if (legend) legend.innerHTML = scans.length ? chartLegendHtml(_scoreHistoryLegend(scans)) : '';
    _scoreHistoryDrawn = { scans, empty, width: _scoreHistoryWidth() };
    _drawScoreHistory(_scoreHistoryDrawn);
    if (table) table.innerHTML = _scoreHistoryTableHtml(scans, empty);
}

// The scans of the history in the order of the chart, the oldest first: each
// with its place in the history (`index`: the key of its point and of its
// entry in the list), its evidence score (null for any other scan or one
// without), EMBER2024's probability (null for any other scan) and the group
// of its verdict
function scoreHistoryScans(history) {
    const list = Array.isArray(history) ? history : [];
    const scans = [];
    for (let index = list.length - 1; index >= 0; index--) {
        const entry = list[index];
        if (!entry || typeof entry !== 'object') continue;
        const kind = _histScoreKind(entry), value = _scanScore(entry);
        scans.push({ index, entry, score: kind === 'evidence' ? value : null, probability: kind === 'probability' ? value : null,
                     group: scoreHistoryGroup(entry.verdict) });
    }
    return scans;
}

// A scan's score as a number (also one written as text); null for none
function _scanScore(entry) {
    const score = entry?.score;
    const n = typeof score === 'number' ? score : typeof score === 'string' && score.trim() ? Number(score) : NaN;
    return Number.isFinite(n) ? n : null;
}

// The group of SCORE_HISTORY_GROUPS a verdict belongs to, in any case
function scoreHistoryGroup(verdict) {
    const name = String(verdict ?? '').trim().toLowerCase();
    return SCORE_HISTORY_GROUPS.find(group => group.verdicts.includes(name)) || SCORE_HISTORY_GROUPS[SCORE_HISTORY_GROUPS.length - 1];
}

// A scan's verdict as the server wrote it, "unknown" for none
function _scanVerdict(entry) {
    return String(entry?.verdict ?? '').trim() || 'unknown';
}

// The points for the width of the plot (a guess while it is hidden: the
// ResizeObserver draws them again when it shows), or the hint without scans
function _drawScoreHistory(drawn) {
    const plot = document.getElementById('score-history-plot'), area = document.getElementById('score-history-area');
    const { scans } = drawn;
    const highest = Math.max(...SCORE_HISTORY_THRESHOLDS.map(th => th.y), ...scans.map(scan => scan.score ?? 0));
    const points = scans.map((scan, x) => ({ x, y: scan.score, color: scan.group.color, key: String(scan.index),
                                             title: _scoreHistoryTitle(scan) }));
    const svg = scatterSvg(points, { width: drawn.width || 640, height: 160, thresholds: SCORE_HISTORY_THRESHOLDS,
                                     yMax: Math.min(SCORE_HISTORY_MAX, highest * 1.1) });
    if (area) area.classList.toggle('is-empty', !svg);
    if (plot) plot.innerHTML = svg || chartEmptyHtml(drawn.empty);
}

// A point's tooltip: tool and file, evidence score (or EMBER2024's
// probability) and verdict, time
function _scoreHistoryTitle(scan) {
    const { entry, score, probability } = scan;
    const value = score !== null ? `score ${_chartNumber(score)}`
        : probability !== null ? `probability ${_histPercent(probability)}` : 'no score';
    return [`${entry.tool || '?'} \u00b7 ${entry.filename || '--'}`, `${value} \u00b7 ${_scanVerdict(entry)}`,
            _histTime(entry).text].join('\n');
}

// The legend: the scans per group of verdicts, the groups with scans only
function _scoreHistoryLegend(scans) {
    return SCORE_HISTORY_GROUPS.map(group => ({ key: group.key, label: group.label, color: group.color,
        value: scans.filter(scan => scan.group === group).length })).filter(item => item.value > 0);
}

// The table view: every scan in the order of the chart with its time, tool,
// file, score and verdict; `empty` the only row without any. The Score
// column sorts by the evidence scores only: EMBER2024's probability ("33.9%")
// and "—" (none) come after them.
function _scoreHistoryTableHtml(scans, empty) {
    const rows = scans.map(({ entry, score, probability, group }) => {
        const time = _histTime(entry), file = entry.filename || '--';
        const value = score !== null ? _chartNumber(score) : probability !== null ? _histPercent(probability) : '&mdash;';
        return `<tr><td data-sort-value="${Number.isNaN(time.t) ? '' : time.t}">${escapeHtml(time.text)}</td>`
            + `<td>${escapeHtml(entry.tool || '?')}</td>`
            + `<td class="view-table-text" title="${escapeHtml(file)}">${escapeHtml(file)}</td>`
            + `<td class="view-table-num" data-sort-value="${score === null ? '' : score}">${value}</td>`
            + `<td><span class="view-table-dot" style="background:${group.color}"></span>${escapeHtml(_scanVerdict(entry))}</td></tr>`;
    });
    if (!rows.length) rows.push(`<tr data-sort-skip><td colspan="5" class="view-table-empty">${escapeHtml(_chartSentence(empty))}</td></tr>`);
    return '<table class="view-table" data-sortable data-sort-id="score-history"><thead><tr><th>Time</th><th>Tool</th>'
        + `<th>File</th><th class="view-table-num">Score</th><th>Verdict</th></tr></thead><tbody>${rows.join('')}</tbody></table>`;
}

// The width SCORE HISTORY is drawn for: that of its plot (0 while hidden)
function _scoreHistoryWidth() {
    return Math.floor(document.getElementById('score-history-plot')?.getBoundingClientRect().width || 0);
}

// The points for the new width of their plot; not while it is hidden (0) or
// for the width they were drawn for. The legend and the table stay.
function redrawScoreHistoryOnResize() {
    const drawn = _scoreHistoryDrawn;
    const width = _scoreHistoryWidth();
    if (!drawn || !width || width === drawn.width) return;
    drawn.width = width;
    _drawScoreHistory(drawn);
}

// SCORE HISTORY is drawn again, in the next frame, when its plot changes its
// width (the window, the theme, the tab or the chart view shown again)
function initScoreHistory() {
    const plot = document.getElementById('score-history-plot');
    if (plot && typeof ResizeObserver !== 'undefined') {
        new ResizeObserver(() => requestAnimationFrame(redrawScoreHistoryOnResize)).observe(plot);
    }
}

// A click on a point of SCORE HISTORY shows its scan in the list below
function onScoreHistoryClick(event) {
    const point = event?.target?.closest?.('.chart-point');
    if (point) revealHistoryEntry(point.getAttribute('data-key'));
}

// Opens the entry of the scan history at `index` (its place in the history)
// as a click on it does, one already open staying so, scrolls it into the
// middle of the view and marks it for 1.5 s
function revealHistoryEntry(index) {
    const list = document.getElementById('threatscan-history-list');
    const entry = [...(list ? list.querySelectorAll('.scan-history-entry') : [])]
        .find(el => el.getAttribute('data-history-index') === String(index));
    if (entry && entry.nextElementSibling?.style.display === 'none') toggleHistoryDetail(entry);
    revealElement(entry, 'center', 1500);
}

// Roll up per-tool scan summaries into one verdict label (mirrors the backend
// _overall_verdict). Used for graph node/sample badges.
function _nodeVerdict(scans) {
    if (!scans || !scans.length) return 'unknown';
    if (scans.some(s => s.verdict === 'malicious' || s.detected === true)) return 'malicious';
    if (scans.some(s => s.verdict === 'detected')) return 'detected';
    if (scans.some(s => s.verdict === 'clean' || s.verdict === 'benign' || s.clean === true)) return 'clean';
    if (scans.some(s => s.verdict === 'analyzed')) return 'analyzed';
    return 'unknown';
}

const _VERDICT_META = {
    malicious: { text: 'MALICIOUS', cls: 'history-detected' },
    detected:  { text: 'DETECTED',  cls: 'history-detected' },
    clean:     { text: 'CLEAN',     cls: 'history-clean' },
    analyzed:  { text: 'ANALYZED',  cls: 'history-unknown' },
    unknown:   { text: 'UNSCANNED', cls: 'history-unknown' },
};

// Render a scan list (each entry shaped like a history row, carrying .result)
// as collapsible rows reusing the shared history renderers.
function renderGraphScans(scans, heading = 'Static Scans') {
    if (!scans || !scans.length) return '';
    let h = `<div class="gd-section">${escapeHtml(heading)} <span class="gd-count">${scans.length}</span></div>`;
    h += '<div class="gd-scan-list">';
    scans.forEach(sc => {
        const st = _histStatus(sc);
        h += `<div class="scan-history-entry ${st.cls}" onclick="toggleHistoryDetail(this)">`;
        h += `<span class="scan-history-more">&#9656;</span>`;
        h += `<span class="scan-history-tool">${escapeHtml(sc.tool || '?')}</span>`;
        h += `<span class="scan-history-status">${escapeHtml(st.text)}</span>`;
        h += `</div>`;
        h += `<div class="scan-history-detail" style="display:none">${renderHistoryDetail(sc)}</div>`;
    });
    h += '</div>';
    return h;
}

// Back-compat shims: older call sites just refresh the shared timeline.
function renderScanHistory() { loadScanHistory(); }

// =============================================
// EMBER2024 ML CLASSIFIER
// =============================================
function renderEmberResult(data, container) {
    const score = typeof data.score === 'number' ? data.score : 0;
    const pct = Math.round(score * 1000) / 10;
    const malicious = !!data.malicious;
    const statusClass = malicious ? 'scan-detected' : 'scan-clean';
    const statusText = malicious ? `MALICIOUS (${pct}%)` : `BENIGN (${pct}%)`;
    const statusIcon = malicious ? '&#x26A0;' : '&#x2705;';
    // Gauge color: green (low) -> orange -> red (high)
    const barClass = score >= 0.8 ? 'ember-bar-high' : score >= 0.5 ? 'ember-bar-med' : 'ember-bar-low';

    let html = `<div class="scan-result ${statusClass}">`;
    html += `<div class="scan-result-header">`;
    html += `<span class="scan-result-icon">${statusIcon}</span>`;
    html += `<span class="scan-result-status">${statusText}</span>`;
    html += `<span class="scan-result-tool">EMBER2024 (${escapeHtml(data.model || '')})</span>`;
    html += `</div>`;

    // Score gauge
    html += `<div class="ember-gauge">`;
    html += `<div class="ember-gauge-track"><div class="ember-gauge-fill ${barClass}" style="width:${pct}%"></div>`;
    html += `<div class="ember-gauge-threshold" style="left:${(data.threshold || 0.5) * 100}%" title="Threshold ${data.threshold}"></div></div>`;
    html += `<div class="ember-gauge-labels"><span>0.0 benign</span><span>malicious 1.0</span></div>`;
    html += `</div>`;

    // Details
    html += `<div class="ember-detail-grid">`;
    html += `<div class="ember-detail"><span class="ember-detail-k">Score</span><span class="ember-detail-v">${score.toFixed(4)}</span></div>`;
    html += `<div class="ember-detail"><span class="ember-detail-k">Threshold</span><span class="ember-detail-v">${data.threshold}</span></div>`;
    if (data.elapsed_ms != null) html += `<div class="ember-detail"><span class="ember-detail-k">Time</span><span class="ember-detail-v">${data.elapsed_ms} ms</span></div>`;
    if (data.size != null) html += `<div class="ember-detail"><span class="ember-detail-k">Size</span><span class="ember-detail-v">${formatSize(data.size)}</span></div>`;
    html += `</div>`;

    // --- Why: model explanation (per-feature-group SHAP + raw highlights) ---
    html += renderEmberExplanation(data.explanation || {});

    if (data.sha256) {
        html += `<div class="scan-output-header">SHA256:</div>`;
        html += `<pre class="scan-output">${escapeHtml(data.sha256)}</pre>`;
    }

    html += renderRawToggle(data);
    html += `</div>`;
    container.innerHTML = html;
}

// Render the EMBER "why" panel: signed per-feature-group contributions
// (log-odds space; + pushes toward malicious, - toward benign) plus concrete
// raw-feature highlights, with a "> more" expander for the full detail.
function renderEmberExplanation(ex) {
    if (!ex || (!ex.contributions && !ex.details)) return '';
    const det = ex.details || {};
    let html = '';

    // Feature-group contribution bars (top drivers).
    const contribs = (ex.contributions || []).filter(c => Math.abs(c.value) > 0.001);
    if (contribs.length) {
        const maxAbs = Math.max(...contribs.map(c => Math.abs(c.value))) || 1;
        html += `<div class="ember-why-header">Why this verdict &mdash; feature-group contributions <span class="ember-why-sub">(+ &rarr; malicious, &minus; &rarr; benign)</span></div>`;
        html += `<div class="ember-why-list">`;
        contribs.slice(0, 6).forEach(c => {
            const w = Math.round(Math.abs(c.value) / maxAbs * 100);
            const mal = c.value >= 0;
            html += `<div class="ember-why-row">`;
            html += `<span class="ember-why-group">${escapeHtml(c.group)}</span>`;
            html += `<div class="ember-why-bar-track"><div class="ember-why-bar ${mal ? 'why-mal' : 'why-ben'}" style="width:${w}%"></div></div>`;
            html += `<span class="ember-why-val ${mal ? 'why-mal-t' : 'why-ben-t'}">${c.value >= 0 ? '+' : ''}${c.value.toFixed(2)}</span>`;
            html += `</div>`;
        });
        html += `</div>`;
    }

    // Compact highlight chips.
    const chips = [];
    if (det.file_entropy != null) {
        const packed = det.packed_sections && det.packed_sections.length;
        chips.push({ t: `entropy ${det.file_entropy}`, c: (det.file_entropy >= 7 ? 'chip-warn' : '') });
        if (packed) chips.push({ t: `packed: ${det.packed_sections.join(', ')}`, c: 'chip-warn' });
    }
    if (det.dll_count != null) chips.push({ t: `${det.dll_count} DLLs / ${det.import_count} imports`, c: '' });
    const auth = det.authenticode || {};
    const signed = auth.num_certs && auth.num_certs > 0;
    chips.push({ t: signed ? 'signed' : 'unsigned', c: signed ? '' : 'chip-warn' });
    if (det.strings && det.strings.count != null) chips.push({ t: `${det.strings.count} strings`, c: '' });
    if (chips.length) {
        html += `<div class="ember-chip-row">`;
        chips.forEach(ch => html += `<span class="ember-chip ${ch.c}">${escapeHtml(ch.t)}</span>`);
        html += `</div>`;
    }

    // Notable / suspicious APIs actually present in the import table.
    const apis = det.notable_apis || [];
    if (apis.length) {
        html += `<div class="ember-why-header">Notable APIs <span class="ember-why-sub">(${apis.length})</span></div>`;
        html += `<div class="ember-api-list">`;
        apis.slice(0, 14).forEach(n => html += `<span class="ember-api-chip" title="${escapeHtml(n.dll || '')}">${escapeHtml(n.api)}</span>`);
        if (apis.length > 14) {
            html += `<span class="ember-api-chip ember-api-more" onclick="toggleApiMore(this)">+${apis.length - 14}</span>`;
            apis.slice(14).forEach(n => html += `<span class="ember-api-chip api-extra" style="display:none" title="${escapeHtml(n.dll || '')}">${escapeHtml(n.api)}</span>`);
        }
        html += `</div>`;
    }

    // "> more" expander with the full detail dump. DOM-relative toggle (no id):
    // this block is rendered many times (live result + every history row, in
    // three containers), so element ids would collide.
    html += `<div class="ember-more-toggle" onclick="toggleEmberMore(this)">&#9656; more detail</div>`;
    html += `<div class="ember-more" style="display:none">`;

    // All feature-group contributions
    if (ex.contributions && ex.contributions.length) {
        html += `<div class="ember-more-sub">All feature-group contributions (base ${ex.base_value != null ? ex.base_value : '?'})</div>`;
        html += `<table class="ember-more-table" data-sortable data-sort-id="ember-contributions"><thead><tr><th>group</th><th>contribution</th></tr></thead><tbody>`;
        ex.contributions.forEach(c => {
            html += `<tr><td>${escapeHtml(c.group)}</td><td class="${c.value >= 0 ? 'why-mal-t' : 'why-ben-t'}">${c.value >= 0 ? '+' : ''}${c.value}</td></tr>`;
        });
        html += `</tbody></table>`;
    }

    // All sections (entropy-sorted)
    if (det.sections && det.sections.length) {
        html += `<div class="ember-more-sub">Sections (entry: ${escapeHtml(det.entry_section || '?')})</div>`;
        html += `<table class="ember-more-table" data-sortable data-sort-id="ember-sections"><thead><tr><th>name</th><th>entropy</th><th>size</th><th>vsize</th></tr></thead><tbody>`;
        det.sections.forEach(s => {
            const hot = s.entropy >= 7 ? ' class="chip-warn"' : '';
            html += `<tr><td>${escapeHtml(s.name)}</td><td${hot}>${s.entropy}</td>`
                + `<td data-sort-value="${sortNumberValue(s.size)}">${formatSize(s.size)}</td>`
                + `<td data-sort-value="${sortNumberValue(s.vsize)}">${formatSize(s.vsize)}</td></tr>`;
        });
        html += `</tbody></table>`;
    }

    // Top DLLs
    if (det.top_dlls && det.top_dlls.length) {
        html += `<div class="ember-more-sub">Top imported DLLs</div>`;
        html += `<table class="ember-more-table" data-sortable data-sort-id="ember-dlls"><thead><tr><th>dll</th><th>imports</th></tr></thead><tbody>`;
        det.top_dlls.forEach(d => html += `<tr><td>${escapeHtml(d.dll)}</td><td>${d.count}</td></tr>`);
        html += `</tbody></table>`;
    }

    // All notable APIs
    if (apis.length) {
        html += `<div class="ember-more-sub">All notable APIs</div>`;
        html += `<div class="ember-api-list">`;
        apis.forEach(n => html += `<span class="ember-api-chip" title="${escapeHtml(n.dll || '')}">${escapeHtml(n.api)}</span>`);
        html += `</div>`;
    }

    // Strings + PE warnings
    if (det.strings) {
        const s = det.strings;
        html += `<div class="ember-more-sub">Strings</div>`;
        html += `<div class="ember-more-kv">count: ${s.count ?? '?'} &middot; avg len: ${s.avg_length ?? '?'} &middot; entropy: ${s.entropy ?? '?'} &middot; urls: ${s.urls ?? 0} &middot; paths: ${s.paths ?? 0} &middot; registry: ${s.registry ?? 0}</div>`;
    }
    if (det.pe_warnings && det.pe_warnings.length) {
        html += `<div class="ember-more-sub">PE parser warnings</div>`;
        html += `<div class="ember-more-kv">${det.pe_warnings.map(escapeHtml).join(', ')}</div>`;
    }
    if (ex.contributions_error) html += `<div class="ember-more-kv chip-warn">contributions error: ${escapeHtml(ex.contributions_error)}</div>`;
    if (ex.details_error) html += `<div class="ember-more-kv chip-warn">details error: ${escapeHtml(ex.details_error)}</div>`;

    html += `</div>`;
    return html;
}

function toggleEmberMore(el) {
    const panel = el.nextElementSibling;
    if (!panel || !panel.classList.contains('ember-more')) return;
    const open = panel.style.display !== 'none';
    panel.style.display = open ? 'none' : 'block';
    el.innerHTML = (open ? '&#9656;' : '&#9662;') + ' more detail';
}

function toggleApiMore(el) {
    // Reveal/hide the notable-API chips beyond the first 14, scoped to the
    // clicked chip's own list (no ids -> safe across repeated renders).
    const extras = el.parentElement.querySelectorAll('.api-extra');
    if (!extras.length) return;
    const hidden = extras[0].style.display === 'none';
    extras.forEach(e => { e.style.display = hidden ? '' : 'none'; });
    el.textContent = hidden ? 'less' : ('+' + extras.length);
}

function renderEmberHistory() { loadScanHistory(); }

function clearEmberHistory() { clearScanHistory(); }

// =============================================
// CAPA CAPABILITY DETECTION
// =============================================
function renderCapaResult(data, container) {
    const caps = data.capabilities || [];
    const count = data.capability_count != null ? data.capability_count : caps.length;

    let html = `<div class="scan-result ${count > 0 ? 'scan-detected' : 'scan-clean'}">`;
    html += `<div class="scan-result-header">`;
    html += `<span class="scan-result-icon">&#x1F9E9;</span>`;
    html += `<span class="scan-result-status">${count} capabilit${count === 1 ? 'y' : 'ies'} found</span>`;
    html += `<span class="scan-result-tool">capa &middot; ${escapeHtml(data.format || '')} ${escapeHtml(data.arch || '')}</span>`;
    html += `</div>`;

    // ATT&CK tactic summary chips
    if ((data.tactics || []).length) {
        html += `<div class="capa-tactics">`;
        data.tactics.forEach(t => { html += `<span class="capa-tactic-chip">${escapeHtml(t)}</span>`; });
        html += `</div>`;
    }

    if (count === 0) {
        html += `<div class="scanner-placeholder">No capabilities matched. (File may be packed, tiny, or an unsupported format.)</div>`;
    } else {
        // Group capabilities by ATT&CK tactic; unmapped go under "Other".
        const groups = {};
        caps.forEach(c => {
            const tactics = (c.attack || []).map(a => a.split(':')[0].trim()).filter(Boolean);
            const keys = tactics.length ? [...new Set(tactics)] : ['Other capabilities'];
            keys.forEach(k => { (groups[k] = groups[k] || []).push(c); });
        });
        const order = Object.keys(groups).sort((a, b) => {
            if (a === 'Other capabilities') return 1;
            if (b === 'Other capabilities') return -1;
            return a.localeCompare(b);
        });
        html += `<div class="capa-groups">`;
        order.forEach(tactic => {
            html += `<div class="capa-group">`;
            html += `<div class="capa-group-title">${escapeHtml(tactic)} <span class="capa-group-count">${groups[tactic].length}</span></div>`;
            groups[tactic].forEach(c => {
                const attackLine = (c.attack || []).join(' · ');
                const mbcLine = (c.mbc || []).join(' · ');
                html += `<div class="capa-cap">`;
                html += `<div class="capa-cap-name">${escapeHtml(c.name)}${c.matches > 1 ? ` <span class="capa-cap-matches">×${c.matches}</span>` : ''}</div>`;
                if (c.namespace) html += `<div class="capa-cap-ns">${escapeHtml(c.namespace)}</div>`;
                if (attackLine) html += `<div class="capa-cap-tag capa-cap-attack">ATT&amp;CK: ${escapeHtml(attackLine)}</div>`;
                if (mbcLine) html += `<div class="capa-cap-tag capa-cap-mbc">MBC: ${escapeHtml(mbcLine)}</div>`;
                html += `</div>`;
            });
            html += `</div>`;
        });
        html += `</div>`;
    }

    if (data.sha256) {
        html += `<div class="scan-output-header">SHA256:</div>`;
        html += `<pre class="scan-output">${escapeHtml(data.sha256)}</pre>`;
    }

    html += renderRawToggle(data);
    html += `</div>`;
    container.innerHTML = html;
}

function renderCapaHistory() { loadScanHistory(); }

function clearCapaHistory() { clearScanHistory(); }

// =============================================
// HEX EDITOR
// =============================================

function initHexDropZone() {
    const zone = document.getElementById('hex-drop-zone');
    const input = document.getElementById('hex-file-input');
    if (!zone || !input) return;

    zone.addEventListener('dragover', e => {
        e.preventDefault();
        zone.classList.add('dragover');
    });
    zone.addEventListener('dragleave', () => zone.classList.remove('dragover'));
    zone.addEventListener('drop', e => {
        e.preventDefault();
        zone.classList.remove('dragover');
        if (e.dataTransfer.files.length) {
            hexUploadFile(e.dataTransfer.files[0]);
        }
    });
    input.addEventListener('change', () => {
        if (input.files.length) {
            hexUploadFile(input.files[0]);
            input.value = ''; // reset so same file can be re-selected
        }
    });
}

async function hexUploadFile(file) {
    const zone = document.getElementById('hex-drop-zone');
    const fileInfo = document.getElementById('hex-file-info');
    const bytesPerPage = parseInt(document.getElementById('hex-bytes-per-page').value) || 512;

    // Show loading state
    zone.classList.add('loading');
    zone.querySelector('p').textContent = `Uploading ${file.name} (${formatSize(file.size)})...`;

    const formData = new FormData();
    formData.append('file', file);
    formData.append('bytes', bytesPerPage);

    try {
        const resp = await fetch('/api/file/hex/upload', { method: 'POST', body: formData });
        const data = await resp.json();

        if (data.error) {
            fileInfo.innerHTML = `<span class="hex-info-item" style="color:var(--accent-red);">Error: ${escapeHtml(data.error)}</span>`;
            zone.classList.remove('loading');
            zone.querySelector('p').textContent = 'Drop a file here or browse';
            return;
        }

        // Store the server-side path for pagination
        state.hexFilePath = data.path;
        state.hexFileSize = data.size || 0;
        state.hexOffset = 0;
        state.hexData = data.raw_bytes || null;
        state.hexSelectedByte = -1;

        // Update path input so pagination works
        document.getElementById('hex-filepath').value = data.path;
        document.getElementById('hex-offset').value = 0;

        // Collapse drop zone and show file info
        zone.classList.add('has-file');
        zone.classList.remove('loading');
        zone.querySelector('p').innerHTML = `<strong>${escapeHtml(data.filename || file.name)}</strong> (${formatSize(data.size)}) <span class="hex-change-file" onclick="hexResetDropZone()">change</span>`;

        // Update file info bar
        fileInfo.innerHTML = `
            <span class="hex-info-item"><strong>File:</strong> ${escapeHtml(data.filename || file.name)}</span>
            <span class="hex-info-item"><strong>Size:</strong> ${formatSize(data.size)}</span>
            <span class="hex-info-item"><strong>Showing:</strong> ${data.bytes_shown} bytes from offset 0x00000000</span>
        `;

        // Render hex dump
        renderHexView(data.hex, 0, data.bytes_shown);

        // Update status bar
        document.getElementById('hex-status-size').textContent = `Size: ${formatSize(data.size)}`;
        document.getElementById('hex-status-offset').textContent = `Offset: 0x00000000`;
        document.getElementById('hex-inspector').classList.add('visible');

        // Structure minimap for the freshly uploaded file
        hexRenderMinimap();
    } catch (e) {
        fileInfo.innerHTML = `<span class="hex-info-item" style="color:var(--accent-red);">Upload failed: ${escapeHtml(e.message)}</span>`;
        zone.classList.remove('loading');
        zone.querySelector('p').textContent = 'Drop a file here or browse';
    }
}

function hexResetDropZone() {
    const zone = document.getElementById('hex-drop-zone');
    zone.classList.remove('has-file', 'loading');
    zone.querySelector('p').innerHTML = 'Drop a file here or <span class="hex-browse-link" onclick="document.getElementById(\'hex-file-input\').click()">browse</span>';
}

function hexOpenFile(path) {
    // Switch to hex tab and load a specific file
    switchTab('hexeditor');
    document.getElementById('hex-filepath').value = path;
    document.getElementById('hex-offset').value = 0;
    // Collapse drop zone
    const zone = document.getElementById('hex-drop-zone');
    zone.classList.add('has-file');
    zone.querySelector('p').innerHTML = `<strong>${escapeHtml(path.split('\\').pop())}</strong> <span class="hex-change-file" onclick="hexResetDropZone()">change</span>`;
    hexLoad();
}

async function hexLoad() {
    const filepath = document.getElementById('hex-filepath').value.trim();
    const offset = parseInt(document.getElementById('hex-offset').value) || 0;
    const bytesPerPage = parseInt(document.getElementById('hex-bytes-per-page').value) || 512;

    if (!filepath) {
        alert('Enter a file path to load.');
        return;
    }

    state.hexFilePath = filepath;
    state.hexOffset = offset;

    try {
        const resp = await fetch(`/api/file/hex?path=${encodeURIComponent(filepath)}&offset=${offset}&bytes=${bytesPerPage}`);
        const data = await resp.json();

        if (data.error) {
            document.getElementById('hex-file-info').innerHTML = `<span class="hex-info-item" style="color:var(--accent-red);">Error: ${escapeHtml(data.error)}</span>`;
            return;
        }

        state.hexFileSize = data.size || 0;
        state.hexData = data.raw_bytes || null;
        state.hexSelectedByte = -1;

        // Update file info
        document.getElementById('hex-file-info').innerHTML = `
            <span class="hex-info-item"><strong>File:</strong> ${escapeHtml(filepath.split('\\').pop())}</span>
            <span class="hex-info-item"><strong>Size:</strong> ${formatSize(data.size)}</span>
            <span class="hex-info-item"><strong>Showing:</strong> ${data.bytes_shown} bytes from offset 0x${offset.toString(16).padStart(8, '0')}</span>
        `;

        // Render hex dump
        renderHexView(data.hex, offset, data.bytes_shown);

        // Update status bar
        document.getElementById('hex-status-size').textContent = `Size: ${formatSize(data.size)}`;
        document.getElementById('hex-status-offset').textContent = `Offset: 0x${offset.toString(16).padStart(8, '0')}`;

        // Show inspector
        document.getElementById('hex-inspector').classList.add('visible');

        // Structure minimap: render once per file, then just move the viewport
        const minimap = document.getElementById('hex-minimap');
        if (minimap && minimap.dataset.path === filepath) {
            hexUpdateMinimapViewport();
        } else {
            if (minimap) minimap.dataset.path = filepath;
            hexRenderMinimap();
        }

    } catch (e) {
        document.getElementById('hex-file-info').innerHTML = `<span class="hex-info-item" style="color:var(--accent-red);">Failed: ${escapeHtml(e.message)}</span>`;
    }
}

function renderHexView(hexDump, baseOffset, bytesShown) {
    const offsetCol = document.getElementById('hex-offset-col');
    const hexView = document.getElementById('hex-view');
    const asciiCol = document.getElementById('hex-ascii-col');

    if (!hexDump) {
        offsetCol.innerHTML = '';
        hexView.innerHTML = '<div style="padding:20px;color:var(--text-muted);">No data loaded</div>';
        asciiCol.innerHTML = '';
        return;
    }

    // Parse hex dump lines
    const lines = hexDump.split('\n');
    let offsetHtml = '';
    let hexHtml = '';
    let asciiHtml = '';
    let validLineIdx = 0; // Separate counter for actual data lines

    lines.forEach((line) => {
        if (!line.trim()) return;

        // Parse line: "00000000  4d 5a 90 00 ... |MZ..............|"
        const match = line.match(/^([0-9a-f]+)\s+(.+?)\s+\|(.+)\|$/i);
        if (!match) {
            // Fallback: just display raw
            offsetHtml += escapeHtml(line.substring(0, 8)) + '\n';
            hexHtml += escapeHtml(line.substring(10)) + '\n';
            validLineIdx++;
            return;
        }

        const offsetStr = match[1];
        const hexPart = match[2];
        const asciiPart = match[3];

        offsetHtml += offsetStr + '\n';

        // Render hex bytes as clickable spans
        const hexBytes = hexPart.trim().split(/\s+/);
        let lineHexHtml = '';
        hexBytes.forEach((byte, byteIdx) => {
            if (byte === '') return;
            const globalIdx = (validLineIdx * 16) + byteIdx;
            const isNull = byte === '00';
            lineHexHtml += `<span class="hex-byte${isNull ? ' null-byte' : ''}" data-idx="${globalIdx}" onclick="hexSelectByte(${globalIdx})">${escapeHtml(byte)}</span>`;
            // Add gap between bytes 7 and 8
            if (byteIdx === 7) lineHexHtml += '<span class="hex-gap"></span>';
        });
        hexHtml += lineHexHtml + '\n';

        // Render ASCII
        let lineAsciiHtml = '<div class="ascii-line">';
        for (let i = 0; i < asciiPart.length; i++) {
            const ch = asciiPart[i];
            const globalIdx = (validLineIdx * 16) + i;
            const isPrintable = ch !== '.';
            lineAsciiHtml += `<span class="ascii-char${isPrintable ? '' : ' non-printable'}" data-idx="${globalIdx}" onclick="hexSelectByte(${globalIdx})">${escapeHtml(ch)}</span>`;
        }
        lineAsciiHtml += '</div>';
        asciiHtml += lineAsciiHtml;

        validLineIdx++;
    });

    offsetCol.innerHTML = offsetHtml;
    hexView.innerHTML = hexHtml;
    asciiCol.innerHTML = asciiHtml;
}

function hexSelectByte(idx) {
    state.hexSelectedByte = idx;

    // Clear previous selection
    document.querySelectorAll('.hex-byte.selected, .ascii-char.selected').forEach(el => el.classList.remove('selected'));

    // Highlight new selection
    document.querySelectorAll(`[data-idx="${idx}"]`).forEach(el => el.classList.add('selected'));

    // Update status bar
    const byteEl = document.querySelector(`.hex-byte[data-idx="${idx}"]`);
    if (byteEl) {
        const byteVal = parseInt(byteEl.textContent, 16);
        const globalOffset = state.hexOffset + idx;
        document.getElementById('hex-status-offset').textContent = `Offset: 0x${globalOffset.toString(16).padStart(8, '0')}`;
        document.getElementById('hex-status-selection').textContent = `Selected: byte ${idx}`;
        document.getElementById('hex-status-value').textContent = `Value: 0x${byteEl.textContent} (${byteVal})`;

        // Update inspector
        updateHexInspector(idx);
    }
}

function updateHexInspector(idx) {
    // Get surrounding bytes from the displayed hex view
    const allBytes = document.querySelectorAll('.hex-byte');
    const bytes = [];
    for (let i = idx; i < Math.min(idx + 8, allBytes.length); i++) {
        bytes.push(parseInt(allBytes[i].textContent, 16));
    }

    if (bytes.length === 0) return;

    // Int8 / UInt8
    const uint8 = bytes[0];
    const int8 = uint8 > 127 ? uint8 - 256 : uint8;
    document.getElementById('hex-insp-int8').textContent = int8;
    document.getElementById('hex-insp-uint8').textContent = uint8;

    // Int16 LE / UInt16 LE
    if (bytes.length >= 2) {
        const uint16 = bytes[0] | (bytes[1] << 8);
        const int16 = uint16 > 32767 ? uint16 - 65536 : uint16;
        document.getElementById('hex-insp-int16le').textContent = int16;
        document.getElementById('hex-insp-uint16le').textContent = uint16;
    }

    // Int32 LE / UInt32 LE
    if (bytes.length >= 4) {
        const uint32 = (bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24)) >>> 0;
        const int32 = uint32 > 2147483647 ? uint32 - 4294967296 : uint32;
        document.getElementById('hex-insp-int32le').textContent = int32;
        document.getElementById('hex-insp-uint32le').textContent = uint32;
    }

    // Float32
    if (bytes.length >= 4) {
        const buf = new ArrayBuffer(4);
        const view = new DataView(buf);
        bytes.slice(0, 4).forEach((b, i) => view.setUint8(i, b));
        document.getElementById('hex-insp-float32').textContent = view.getFloat32(0, true).toPrecision(6);
    }

    // Float64
    if (bytes.length >= 8) {
        const buf = new ArrayBuffer(8);
        const view = new DataView(buf);
        bytes.slice(0, 8).forEach((b, i) => view.setUint8(i, b));
        document.getElementById('hex-insp-float64').textContent = view.getFloat64(0, true).toPrecision(10);
    }

    // ASCII
    const asciiStr = bytes.slice(0, 8).map(b => (b >= 32 && b < 127) ? String.fromCharCode(b) : '.').join('');
    document.getElementById('hex-insp-ascii').textContent = asciiStr;

    // UTF-16 LE
    if (bytes.length >= 2) {
        let utf16 = '';
        for (let i = 0; i < Math.min(bytes.length - 1, 8); i += 2) {
            const code = bytes[i] | (bytes[i + 1] << 8);
            utf16 += code >= 32 && code < 127 ? String.fromCharCode(code) : '.';
        }
        document.getElementById('hex-insp-utf16').textContent = utf16;
    }
}

function hexPrevPage() {
    const bytesPerPage = parseInt(document.getElementById('hex-bytes-per-page').value) || 512;
    const newOffset = Math.max(0, state.hexOffset - bytesPerPage);
    document.getElementById('hex-offset').value = newOffset;
    state.hexOffset = newOffset;
    hexLoad();
}

function hexNextPage() {
    const bytesPerPage = parseInt(document.getElementById('hex-bytes-per-page').value) || 512;
    const newOffset = state.hexOffset + bytesPerPage;
    if (newOffset < state.hexFileSize) {
        document.getElementById('hex-offset').value = newOffset;
        state.hexOffset = newOffset;
        hexLoad();
    }
}

// --- Hex Editor Resize Handle ---
function initHexResizeHandle() {
    const handle = document.getElementById('hex-ascii-resize');
    const asciiCol = document.getElementById('hex-ascii-col');
    const editorBody = document.querySelector('.hex-editor-body');
    if (!handle || !asciiCol || !editorBody) return;

    let startX = 0;
    let startWidth = 0;
    let isResizing = false;

    handle.addEventListener('mousedown', function(e) {
        e.preventDefault();
        isResizing = true;
        startX = e.clientX;
        startWidth = asciiCol.offsetWidth;
        handle.classList.add('active');
        document.body.classList.add('hex-resizing');

        document.addEventListener('mousemove', onMouseMove);
        document.addEventListener('mouseup', onMouseUp);
    });

    function onMouseMove(e) {
        if (!isResizing) return;
        // Dragging left increases ASCII width, dragging right decreases it
        const delta = startX - e.clientX;
        const newWidth = Math.max(80, Math.min(startWidth + delta, editorBody.offsetWidth * 0.6));
        asciiCol.style.width = newWidth + 'px';
        asciiCol.style.minWidth = newWidth + 'px';
        asciiCol.style.flexShrink = '0';
        asciiCol.style.flexGrow = '0';
    }

    function onMouseUp() {
        isResizing = false;
        handle.classList.remove('active');
        document.body.classList.remove('hex-resizing');
        document.removeEventListener('mousemove', onMouseMove);
        document.removeEventListener('mouseup', onMouseUp);
    }
}

// =============================================
// PE ANALYSIS
// =============================================

async function peAnalyze() {
    const filepath = state.hexFilePath || document.getElementById('hex-filepath').value.trim();
    const panel = document.getElementById('pe-panel');
    const body = document.getElementById('pe-panel-body');

    if (!filepath) {
        panel.style.display = 'block';
        body.innerHTML = '<div class="pe-error">No file loaded. Load a file in the hex editor first.</div>';
        return;
    }

    panel.style.display = 'block';
    body.innerHTML = '<div class="pe-loading"><div class="loading-spinner"></div><span>Parsing PE headers...</span></div>';

    try {
        LoadingSpinner.start();
        const resp = await fetch(`/api/file/pe?path=${encodeURIComponent(filepath)}`);
        const data = await resp.json();
        LoadingSpinner.stop();

        if (data.error) {
            body.innerHTML = `<div class="pe-error">${escapeHtml(data.error)}</div>`;
            return;
        }

        renderPeAnalysis(data, body);
    } catch (e) {
        LoadingSpinner.stop();
        body.innerHTML = `<div class="pe-error">Failed: ${escapeHtml(e.message)}</div>`;
    }
}

// Check the file's Authenticode signature (who signed it + trust status).
async function checkFileSignature() {
    const filepath = state.hexFilePath || document.getElementById('hex-filepath').value.trim();
    const sigBody = document.getElementById('pe-sig-body');
    if (!sigBody) return;
    if (!filepath) {
        sigBody.innerHTML = '<div class="pe-error">No file loaded.</div>';
        return;
    }
    sigBody.innerHTML = '<div class="pe-loading"><div class="loading-spinner"></div><span>Verifying signature...</span></div>';
    try {
        LoadingSpinner.start();
        const resp = await fetch(`/api/file/signature?path=${encodeURIComponent(filepath)}`);
        const data = await resp.json();
        LoadingSpinner.stop();
        if (data.error) {
            sigBody.innerHTML = `<div class="pe-error">${escapeHtml(data.error)}</div>`;
            return;
        }
        sigBody.innerHTML = renderSignature(data);
    } catch (e) {
        LoadingSpinner.stop();
        sigBody.innerHTML = `<div class="pe-error">Failed: ${escapeHtml(e.message)}</div>`;
    }
}

function renderSignature(data) {
    // Map Authenticode status to a verdict badge.
    const status = data.status || 'UnknownError';
    const statusMeta = {
        Valid: { cls: 'ok', label: 'VALID & TRUSTED' },
        NotSigned: { cls: 'bad', label: 'NOT SIGNED' },
        HashMismatch: { cls: 'bad', label: 'HASH MISMATCH (tampered)' },
        NotTrusted: { cls: 'warn', label: 'SIGNED — NOT TRUSTED' },
        UnknownError: { cls: 'warn', label: 'UNKNOWN' },
        NotSupportedFileFormat: { cls: 'dim', label: 'UNSUPPORTED FORMAT' },
        EmbeddedSignaturePresent: { cls: 'warn', label: 'EMBEDDED SIGNATURE (unverified)' },
    };
    const meta = statusMeta[status] || { cls: 'warn', label: escapeHtml(status) };

    let html = `<div class="pe-sig-status ${meta.cls}">${meta.label}</div>`;
    if (data.status_message) {
        html += `<div class="pe-sig-msg">${escapeHtml(data.status_message)}</div>`;
    }

    const s = data.signer;
    if (s) {
        html += '<div class="pe-sig-fields">';
        html += `<div class="pe-field"><span class="pe-label">Signed by</span><span class="pe-value pe-sig-signer">${escapeHtml(s.name || '')}</span></div>`;
        if (s.subject) html += `<div class="pe-field"><span class="pe-label">Subject</span><span class="pe-value mono">${escapeHtml(s.subject)}</span></div>`;
        if (s.issuer_name) html += `<div class="pe-field"><span class="pe-label">Issued by (CA)</span><span class="pe-value">${escapeHtml(s.issuer_name)}</span></div>`;
        if (s.valid_from || s.valid_to) html += `<div class="pe-field"><span class="pe-label">Cert validity</span><span class="pe-value">${escapeHtml((s.valid_from || '?').slice(0,10))} → ${escapeHtml((s.valid_to || '?').slice(0,10))}</span></div>`;
        if (s.thumbprint) html += `<div class="pe-field"><span class="pe-label">Thumbprint</span><span class="pe-value mono">${escapeHtml(s.thumbprint)}</span></div>`;
        if (s.serial) html += `<div class="pe-field"><span class="pe-label">Serial</span><span class="pe-value mono">${escapeHtml(s.serial)}</span></div>`;
        html += '</div>';
    } else if (data.signed) {
        html += '<div class="pe-sig-msg">A signature is present but signer details could not be extracted.</div>';
    }

    if (data.timestamp) {
        html += `<div class="pe-sig-fields"><div class="pe-field"><span class="pe-label">Timestamped by</span><span class="pe-value">${escapeHtml(data.timestamp.name || '')}</span></div></div>`;
    }

    // Embedded vs catalog signing indicator.
    if (data.embedded) {
        const emb = data.embedded.has_embedded
            ? `Embedded (certificate table, ${data.embedded.size} bytes)`
            : (data.signed ? 'Catalog-signed (no embedded certificate table)' : 'None');
        html += `<div class="pe-sig-fields"><div class="pe-field"><span class="pe-label">Signature location</span><span class="pe-value">${escapeHtml(emb)}</span></div></div>`;
    }

    if (data.verification_available === false && data.note) {
        html += `<div class="pe-sig-note">${escapeHtml(data.note)}</div>`;
    }

    return html;
}

/**
 * DiE-style Detection Overview — renders a visual panel showing:
 * 1. Assessment badge (CLEAN/PACKED/ENCRYPTED/PROTECTED)
 * 2. Detection results (Compiler, Linker, Packer, Protector, Overlay)
 * 3. Entropy heatmap (64-block visual gradient)
 * 4. Section layout diagram (proportional file map)
 */
function renderDetectionOverview(detection, prefix) {
    let html = `<div class="die-overview ${prefix}-die-overview">`;
    // The file structure (CHART) or its sections as a table (TABLE); the
    // entropy map shows in both views. Without sections there is nothing to switch.
    const view = `${prefix}-die`;
    const hasSections = (detection.section_layout || []).length > 0;

    // --- Assessment Badge ---
    const assessmentColors = {
        clean: {bg: 'rgba(var(--assess-clean-rgb), 0.08)', border: 'var(--assess-clean)', text: 'var(--assess-clean)', label: 'CLEAN'},
        packed: {bg: 'rgba(var(--assess-packed-rgb), 0.08)', border: 'var(--assess-packed)', text: 'var(--assess-packed)', label: 'PACKED'},
        encrypted: {bg: 'rgba(var(--assess-encrypted-rgb), 0.08)', border: 'var(--assess-encrypted)', text: 'var(--assess-encrypted)', label: 'ENCRYPTED'},
        protected: {bg: 'rgba(var(--assess-protected-tint-rgb), 0.08)', border: 'var(--assess-protected)', text: 'var(--assess-protected)', label: 'PROTECTED'},
        suspicious: {bg: 'rgba(var(--assess-suspicious-rgb), 0.06)', border: 'var(--assess-suspicious)', text: 'var(--assess-suspicious)', label: 'SUSPICIOUS'},
    };
    const assess = assessmentColors[detection.assessment] || assessmentColors.clean;

    html += `<div class="die-header">`;
    html += `<div class="die-title" data-info="Compiler, linker, packer and protector signatures in the style of Detect It Easy, with an overall assessment. The entropy map and the file structure show where packed or encrypted data lies.">BINARY ANALYSIS</div>`;
    html += `<div class="die-header-tools">`;
    html += `<div class="die-assessment" style="background:${assess.bg};border-color:${assess.border};color:${assess.text}">${assess.label}</div>`;
    if (hasSections) html += viewToggleHtml(view);
    html += `</div>`;
    html += `</div>`;

    // --- Detection Results (cards like DiE) ---
    if (detection.detections && detection.detections.length > 0) {
        html += `<div class="die-detections">`;

        // Group by type
        const groups = {};
        detection.detections.forEach(d => {
            if (!groups[d.type]) groups[d.type] = [];
            groups[d.type].push(d);
        });

        const typeIcons = {
            compiler: '\u2699', linker: '\u26D3', packer: '\u26A0',
            protector: '\u26E8', overlay: '\u2630', language: '\u2328', runtime: '\u27F3'
        };
        const typeLabels = {
            compiler: 'Compiler', linker: 'Linker', packer: 'Packer/Crypter',
            protector: 'Protector', overlay: 'Overlay', language: 'Language', runtime: 'Runtime'
        };
        const typeColors = {
            compiler: 'var(--pe-compiler)', linker: 'var(--pe-linker)', packer: 'var(--pe-packer)',
            protector: 'var(--pe-protector)', overlay: 'var(--pe-overlay)', language: 'var(--pe-language)',
            runtime: 'var(--pe-runtime)'
        };

        for (const [type, items] of Object.entries(groups)) {
            const icon = typeIcons[type] || '\u2022';
            const label = typeLabels[type] || type;
            const color = typeColors[type] || 'var(--text-secondary)';

            items.forEach(item => {
                const conf = item.confidence === 'high' ? 'H' : item.confidence === 'medium' ? 'M' : 'L';
                html += `<div class="die-detection-card" style="border-left-color:${color}">`;
                html += `<div class="die-det-icon" style="color:${color}">${icon}</div>`;
                html += `<div class="die-det-body">`;
                html += `<div class="die-det-type" style="color:${color}">${escapeHtml(label)}</div>`;
                html += `<div class="die-det-name">${escapeHtml(item.name)}</div>`;
                if (item.version) html += `<div class="die-det-ver">${escapeHtml(item.version)}</div>`;
                html += `</div>`;
                html += `<div class="die-det-conf" title="Confidence: ${escapeHtml(item.confidence)}">${conf}</div>`;
                html += `</div>`;
            });
        }
        html += `</div>`;
    } else {
        html += `<div class="die-no-detections">No specific tool signatures detected.</div>`;
    }

    // --- Entropy Heatmap ---
    if (detection.entropy_map && detection.entropy_map.length > 0) {
        html += `<div class="die-entropy-section">`;
        html += `<div class="die-section-title">ENTROPY MAP</div>`;
        html += `<div class="die-entropy-legend"><span class="die-legend-low">0.0 (empty)</span><span class="die-legend-mid">4.0 (code)</span><span class="die-legend-high">8.0 (random)</span></div>`;
        html += `<div class="die-entropy-heatmap">`;
        detection.entropy_map.forEach((val, idx) => {
            const pct = (val / 8) * 100;
            // Color gradient: green (low) -> yellow (mid) -> red (high)
            let color;
            if (val < 3.0) color = `hsl(140, 60%, ${30 + val * 5}%)`;
            else if (val < 5.5) color = `hsl(${140 - (val - 3) * 28}, 60%, 45%)`;
            else if (val < 7.0) color = `hsl(${70 - (val - 5.5) * 30}, 70%, 50%)`;
            else color = `hsl(${25 - (val - 7.0) * 25}, 80%, 50%)`;
            const blockPct = (100 / detection.entropy_map.length).toFixed(3);
            html += `<div class="die-entropy-block" style="width:${blockPct}%;background:${color}" title="Block ${idx}: entropy ${val.toFixed(3)}"></div>`;
        });
        html += `</div>`;

        // Mini scale bar below
        html += `<div class="die-entropy-scale">`;
        html += `<span>0x0</span>`;
        if (detection.file_size) html += `<span>${formatSize(detection.file_size)}</span>`;
        html += `</div>`;
        html += `</div>`;
    }

    // --- Section Layout Diagram ---
    if (detection.section_layout && detection.section_layout.length > 0) {
        html += `<div class="die-layout-section"${cardViewAttrs(view, 'chart')}>`;
        html += `<div class="die-section-title">FILE STRUCTURE</div>`;
        html += `<div class="die-layout-bar">`;

        detection.section_layout.forEach(sec => {
            if (sec.pct_size < 0.3) return; // Skip tiny sections
            const secColor = dieSectionKind(sec).color;

            const tooltip = `${sec.name}: ${formatSize(sec.size)} | Entropy: ${sec.entropy.toFixed(2)}${sec.packer ? ' | ' + sec.packer : ''}`;
            html += `<div class="die-layout-seg" style="left:${sec.pct_start}%;width:${Math.max(sec.pct_size, 0.5)}%;background:${secColor}" title="${escapeHtml(tooltip)}">`;
            if (sec.pct_size > 5) html += `<span class="die-layout-label">${escapeHtml(sec.name)}</span>`;
            html += `</div>`;
        });

        // Show overlay if present
        if (detection.overlay && detection.overlay.size > 0 && detection.file_size > 0) {
            const overlayPct = (detection.overlay.size / detection.file_size * 100).toFixed(2);
            const overlayStart = (detection.overlay.offset / detection.file_size * 100).toFixed(2);
            html += `<div class="die-layout-seg die-overlay-seg" style="left:${overlayStart}%;width:${overlayPct}%;background:var(--pe-overlay)" title="Overlay: ${formatSize(detection.overlay.size)}">`;
            if (parseFloat(overlayPct) > 5) html += `<span class="die-layout-label">overlay</span>`;
            html += `</div>`;
        }

        html += `</div>`; // end layout-bar

        // Legend
        html += `<div class="die-layout-legend">`;
        html += `<span class="die-legend-item"><span class="die-legend-dot" style="background:var(--pe-code)"></span>Code</span>`;
        html += `<span class="die-legend-item"><span class="die-legend-dot" style="background:var(--pe-data)"></span>Data</span>`;
        html += `<span class="die-legend-item"><span class="die-legend-dot" style="background:var(--pe-readonly)"></span>Read-only</span>`;
        html += `<span class="die-legend-item"><span class="die-legend-dot" style="background:var(--pe-entropy-high)"></span>High Entropy</span>`;
        html += `<span class="die-legend-item"><span class="die-legend-dot" style="background:var(--pe-packer)"></span>Packer</span>`;
        if (detection.overlay) html += `<span class="die-legend-item"><span class="die-legend-dot" style="background:var(--pe-overlay)"></span>Overlay</span>`;
        html += `</div>`;

        html += `</div>`;
    }

    // --- The same sections as a table (TABLE) ---
    if (hasSections) {
        html += `<div class="die-table-section view-table-wrap"${cardViewAttrs(view, 'table')}>${dieSectionsTableHtml(detection)}</div>`;
    }

    // --- Rich Header (PE only, collapsible) ---
    if (detection.rich_header && detection.rich_header.length > 0) {
        html += `<details class="die-rich-header">`;
        html += `<summary class="die-section-title die-clickable">RICH HEADER (${detection.rich_header.length} entries)</summary>`;
        html += `<div class="die-rich-entries">`;
        detection.rich_header.forEach(entry => {
            html += `<div class="die-rich-entry"><span class="die-rich-tool">${escapeHtml(entry.tool)}</span><span class="die-rich-build">Build ${entry.build}${entry.count ? ' (\u00D7' + entry.count + ')' : ''}</span></div>`;
        });
        html += `</div></details>`;
    }

    html += `</div>`; // end die-overview
    return html;
}

// What the file structure colours a section by, first match: a packer, high
// or suspicious entropy, code, data, read-only
function dieSectionKind(sec) {
    if (sec.packer) return { label: `Packer (${sec.packer})`, color: 'var(--pe-packer)' };
    if (sec.entropy_status === 'high') return { label: 'High Entropy', color: 'var(--pe-entropy-high)' };
    if (sec.entropy_status === 'warn') return { label: 'Suspicious Entropy', color: 'var(--pe-entropy-warn)' };
    if (sec.executable) return { label: 'Code', color: 'var(--pe-code)' };
    if (sec.writable) return { label: 'Data', color: 'var(--pe-data)' };
    return { label: 'Read-only', color: 'var(--pe-readonly)' };
}

// The table view of the file structure: its sections (also those too small to
// draw) and the overlay, in file order, with their offsets
function dieSectionsTableHtml(detection) {
    const parts = (detection.section_layout || []).map(sec => ({ ...sec, kind: dieSectionKind(sec) }));
    if (detection.overlay && detection.overlay.size > 0) {
        parts.push({ name: 'overlay', offset: detection.overlay.offset, size: detection.overlay.size, entropy: null,
                     kind: { label: 'Overlay', color: 'var(--pe-overlay)' } });
    }
    // The section headers need not be in file order; equal offsets keep theirs
    parts.sort((a, b) => (Number(a.offset) || 0) - (Number(b.offset) || 0));
    const rows = parts.map(sec => {
        const entropy = sec.entropy === null || sec.entropy === undefined ? NaN : Number(sec.entropy);
        return `<tr><td class="mono" title="${escapeHtml(sec.name)}"><span class="view-table-clip">${escapeHtml(sec.name)}</span></td>`
            + `<td class="mono" data-sort-value="${sortNumberValue(sec.offset)}">${FileMapView.hexOff(Number(sec.offset) || 0)}</td>`
            + `<td data-sort-value="${sortNumberValue(sec.size)}">${formatSize(sec.size)}</td>`
            + `<td data-sort-value="${Number.isFinite(entropy) ? sortNumberValue(entropy) : ''}">${Number.isFinite(entropy) ? entropy.toFixed(2) : '&mdash;'}</td>`
            + `<td><span class="view-table-dot" style="background:${sec.kind.color}"></span>${escapeHtml(sec.kind.label)}</td></tr>`;
    });
    return '<table class="view-table" data-sortable data-sort-id="die-sections"><thead><tr><th>Section</th><th>Offset</th>'
        + `<th>Size</th><th>Entropy</th><th>Assessment</th></tr></thead><tbody>${rows.join('')}</tbody></table>`;
}

function renderPeAnalysis(pe, container) {
    let html = '';

    // --- DiE-style Detection Overview ---
    if (pe.detection) {
        html += renderDetectionOverview(pe.detection, 'pe');
    }

    // --- File map (planes are painted asynchronously below): the strip (CHART)
    // or its regions as a table (TABLE) ---
    html += fileMapInlineBlock(pe.path, 'pe', 'pe-filemap', viewToggleHtml('pe-filemap'));

    // --- IOC Flags Banner ---
    if (pe.flags && pe.flags.length > 0) {
        html += '<div class="pe-flags-banner">';
        html += `<div class="pe-flags-header"><span class="pe-flags-icon">&#x26A0;</span> <strong>${pe.flags.length} IOC Flag${pe.flags.length > 1 ? 's' : ''} Detected</strong>`;
        html += `<span class="pe-flag-counts">`;
        if (pe.flag_count.high) html += `<span class="pe-flag-badge high">${pe.flag_count.high} HIGH</span>`;
        if (pe.flag_count.medium) html += `<span class="pe-flag-badge med">${pe.flag_count.medium} MED</span>`;
        if (pe.flag_count.low) html += `<span class="pe-flag-badge low">${pe.flag_count.low} LOW</span>`;
        html += `</span></div>`;
        html += '<div class="pe-flags-list">';
        pe.flags.sort((a, b) => {
            const order = {high: 0, medium: 1, low: 2};
            return (order[a.severity] ?? 3) - (order[b.severity] ?? 3);
        }).forEach((f, idx) => {
            const hasEvidence = f.evidence && Object.keys(f.evidence).length > 0;
            html += `<div class="pe-flag-item sev-${cssToken(f.severity)}${hasEvidence ? ' expandable' : ''}" ${hasEvidence ? `onclick="toggleFlagEvidence(this)"` : ''}>`;
            html += `<span class="pe-flag-sev">${escapeHtml(f.severity.toUpperCase())}</span>`;
            html += `<span class="pe-flag-detail">${escapeHtml(f.detail)}</span>`;
            if (hasEvidence) html += `<span class="pe-flag-expand-icon">&#x25BC;</span>`;
            html += `</div>`;
            if (hasEvidence) {
                html += `<div class="pe-flag-evidence" style="display:none;">`;
                html += renderFlagEvidence(f);
                html += `</div>`;
            }
        });
        html += '</div></div>';
    } else {
        html += '<div class="pe-flags-banner clean"><span class="pe-flags-icon">&#x2705;</span> No IOC flags detected.</div>';
    }

    // --- Overview grid ---
    html += '<div class="pe-overview-grid">';

    // File Header card
    const fh = pe.file_header;
    html += `<div class="pe-card">
        <div class="pe-card-title">FILE HEADER</div>
        <div class="pe-field"><span class="pe-label">Machine</span><span class="pe-value">${escapeHtml(fh.machine)} (${fh.machine_raw})</span></div>
        <div class="pe-field"><span class="pe-label">Compiled</span><span class="pe-value">${escapeHtml(fh.timestamp_utc)}</span></div>
        <div class="pe-field"><span class="pe-label">Sections</span><span class="pe-value">${fh.num_sections}</span></div>
        <div class="pe-field"><span class="pe-label">Type</span><span class="pe-value">${fh.is_dll ? 'DLL' : fh.is_exe ? 'EXE' : 'Unknown'}</span></div>
        <div class="pe-field"><span class="pe-label">Characteristics</span><span class="pe-value mono">${fh.characteristics}</span></div>
    </div>`;

    // Optional Header card
    const oh = pe.optional_header;
    html += `<div class="pe-card">
        <div class="pe-card-title">OPTIONAL HEADER</div>
        <div class="pe-field"><span class="pe-label">Format</span><span class="pe-value">${oh.is_pe32_plus ? 'PE32+ (64-bit)' : 'PE32 (32-bit)'}</span></div>
        <div class="pe-field"><span class="pe-label">Entry Point</span><span class="pe-value mono">${oh.entry_point}</span></div>
        <div class="pe-field"><span class="pe-label">Image Base</span><span class="pe-value mono">${oh.image_base}</span></div>
        <div class="pe-field"><span class="pe-label">Linker</span><span class="pe-value">${oh.linker_version}</span></div>
        <div class="pe-field"><span class="pe-label">Subsystem</span><span class="pe-value">${oh.subsystem_name || oh.subsystem}</span></div>
        <div class="pe-field"><span class="pe-label">Checksum</span><span class="pe-value ${oh.checksum_valid ? '' : 'pe-warn'}">${oh.checksum} ${oh.checksum_valid ? '(valid)' : '(INVALID)'}</span></div>
    </div>`;

    // Security features card
    html += `<div class="pe-card">
        <div class="pe-card-title" data-info="Exploit mitigations from the optional header (ASLR, DEP, SEH and CFG) and the entropy of the whole file.">SECURITY FEATURES</div>
        <div class="pe-field"><span class="pe-label">ASLR</span><span class="pe-value ${oh.aslr ? 'pe-ok' : 'pe-bad'}">${oh.aslr ? 'Enabled' : 'Disabled'}</span></div>
        <div class="pe-field"><span class="pe-label">DEP/NX</span><span class="pe-value ${oh.dep_nx ? 'pe-ok' : 'pe-bad'}">${oh.dep_nx ? 'Enabled' : 'Disabled'}</span></div>
        <div class="pe-field"><span class="pe-label">SEH</span><span class="pe-value ${oh.no_seh ? 'pe-bad' : 'pe-ok'}">${oh.no_seh ? 'No SEH' : 'Enabled'}</span></div>
        <div class="pe-field"><span class="pe-label">CFG</span><span class="pe-value ${oh.cfg ? 'pe-ok' : 'pe-dim'}">${oh.cfg ? 'Enabled' : 'Disabled'}</span></div>
        <div class="pe-field"><span class="pe-label">Total Entropy</span><span class="pe-value ${pe.total_entropy >= 7.0 ? 'pe-bad' : pe.total_entropy >= 6.5 ? 'pe-warn' : ''}">${pe.total_entropy.toFixed(3)}</span></div>
    </div>`;

    html += '</div>'; // end overview grid

    // --- Digital Signature (on-demand: signer verification needs PowerShell) ---
    html += `<div class="pe-sig-section" id="pe-sig-section">
        <div class="pe-card-title">DIGITAL SIGNATURE</div>
        <div class="pe-sig-body" id="pe-sig-body">
            <button class="pe-sig-btn" onclick="checkFileSignature()">&#128273; Check who signed this file</button>
        </div>
    </div>`;

    // --- Sections Table with entropy bars ---
    html += '<div class="pe-section-table">';
    html += '<div class="pe-card-title" data-info="Section headers with addresses, sizes, permissions and entropy. Entropy close to 8 means compressed or encrypted data, and Inspect shows the bytes and strings of a section.">SECTIONS</div>';
    html += '<table class="pe-table" data-sortable data-sort-id="pe-sections"><thead><tr><th>Name</th><th>V.Addr</th><th>V.Size</th><th>Raw Size</th><th>Flags</th><th>Entropy</th><th>Status</th><th></th></tr></thead><tbody>';
    pe.sections.forEach((sec, idx) => {
        const rowClass = sec.entropy_status === 'high' ? 'pe-row-high' : sec.entropy_status === 'warn' ? 'pe-row-warn' : '';
        const rwx = sec.rwx_warning ? ' <span class="pe-rwx-badge">RWX</span>' : '';
        const packer = sec.packer_indicator ? ` <span class="pe-packer-badge">${escapeHtml(sec.packer_indicator)}</span>` : '';
        const flags = (sec.readable ? 'R' : '-') + (sec.writable ? 'W' : '-') + (sec.executable ? 'X' : '-');
        const entropyPct = Math.min(100, (sec.entropy / 8) * 100);
        const barColor = sec.entropy_status === 'high' ? 'var(--pe-entropy-high)' : sec.entropy_status === 'warn' ? 'var(--pe-entropy-warn)' : 'var(--pe-entropy-normal)';

        const secOffsetDec = sec.raw_offset_dec != null ? sec.raw_offset_dec : parseInt(sec.raw_offset, 16);
        // The detail row (Inspect) moves with its section when the table is sorted
        html += `<tr class="${rowClass}" id="pe-sec-row-${idx}">
            <td class="mono" data-sort-value="${escapeHtml(sec.name)}"><a class="section-link" href="#" onclick="peJumpToSection(${secOffsetDec}); return false;" title="View in Hex Editor">${escapeHtml(sec.name)}</a>${packer}${rwx}</td>
            <td class="mono">${sec.virtual_address}</td>
            <td data-sort-value="${sortNumberValue(sec.virtual_size)}">${formatSize(sec.virtual_size)}</td>
            <td data-sort-value="${sortNumberValue(sec.raw_size)}">${formatSize(sec.raw_size)}</td>
            <td class="mono">${flags}</td>
            <td>
                <div class="pe-entropy-cell">
                    <div class="pe-entropy-bar"><div class="pe-entropy-fill" style="width:${entropyPct}%;background:${barColor}"></div></div>
                    <span class="pe-entropy-val">${sec.entropy.toFixed(2)}</span>
                </div>
            </td>
            <td><span class="pe-status-tag ${sec.entropy_status}">${sec.entropy_status === 'high' ? 'ENCRYPTED/PACKED' : sec.entropy_status === 'warn' ? 'SUSPICIOUS' : 'Normal'}</span></td>
            <td><button class="btn btn-sm pe-inspect-btn" onclick="peInspectSection(${idx})">Inspect</button></td>
        </tr>
        <tr class="pe-sec-detail-row" id="pe-sec-detail-${idx}" style="display:none;" data-sort-detail>
            <td colspan="8"><div class="pe-sec-detail-container" id="pe-sec-detail-body-${idx}"></div></td>
        </tr>`;
    });
    html += '</tbody></table></div>';

    // --- Suspicious Imports ---
    if (pe.suspicious_imports && Object.keys(pe.suspicious_imports).length > 0) {
        html += '<div class="pe-suspicious-imports">';
        html += '<div class="pe-card-title">SUSPICIOUS IMPORTS</div>';
        Object.entries(pe.suspicious_imports).forEach(([category, items]) => {
            const catClass = ['process_injection', 'process_hollowing', 'credential_access'].includes(category) ? 'high' : 'med';
            html += `<div class="pe-import-category">
                <div class="pe-import-cat-header"><span class="pe-flag-badge ${catClass}">${category.replace(/_/g, ' ').toUpperCase()}</span><span class="pe-import-count">${items.length} API(s)</span></div>
                <div class="pe-import-items">`;
            items.forEach(item => {
                html += `<span class="pe-import-item"><span class="pe-import-dll">${escapeHtml(item.dll)}</span>!<span class="pe-import-func">${escapeHtml(item.function)}</span></span>`;
            });
            html += '</div></div>';
        });
        html += '</div>';
    }

    // --- Imports Summary (collapsible) ---
    html += `<details class="pe-imports-detail">
        <summary class="pe-card-title pe-clickable">IMPORTS (${pe.dll_count} DLLs, ${pe.import_count} functions)</summary>
        <div class="pe-imports-list">`;
    pe.imports.forEach(imp => {
        html += `<div class="pe-dll-entry"><span class="pe-dll-name">${escapeHtml(imp.dll)}</span><span class="pe-dll-count">${imp.count}</span></div>`;
    });
    html += '</div></details>';

    // --- Exports (if any) ---
    if (pe.exports && pe.exports.length > 0) {
        html += `<details class="pe-imports-detail">
            <summary class="pe-card-title pe-clickable">EXPORTS (${pe.exports.length})</summary>
            <div class="pe-imports-list">`;
        pe.exports.slice(0, 100).forEach(exp => {
            html += `<div class="pe-dll-entry"><span class="pe-dll-name mono">${escapeHtml(exp.name)}</span><span class="pe-dll-count">#${exp.ordinal}</span></div>`;
        });
        html += '</div></details>';
    }

    // --- TLS Callbacks ---
    if (pe.tls_callbacks && pe.tls_callbacks.length > 0) {
        html += '<div class="pe-tls-section">';
        html += `<div class="pe-card-title">TLS CALLBACKS (Anti-Debug Indicator)</div>`;
        pe.tls_callbacks.forEach(cb => {
            html += `<div class="pe-tls-entry mono">${cb}</div>`;
        });
        html += '</div>';
    }

    container.innerHTML = html;
    fileMapInlineMount(pe.path, 'pe');
}

async function peInspectSection(idx) {
    const detailRow = document.getElementById(`pe-sec-detail-${idx}`);
    const detailBody = document.getElementById(`pe-sec-detail-body-${idx}`);

    // Toggle visibility
    if (detailRow.style.display !== 'none') {
        detailRow.style.display = 'none';
        return;
    }

    detailRow.style.display = '';
    detailBody.innerHTML = '<div class="pe-loading"><div class="loading-spinner"></div><span>Loading section data...</span></div>';

    const filepath = state.hexFilePath || document.getElementById('hex-filepath').value.trim();
    if (!filepath) {
        detailBody.innerHTML = '<div class="pe-error">No file path available.</div>';
        return;
    }

    try {
        const resp = await fetch(`/api/file/pe/section?path=${encodeURIComponent(filepath)}&index=${idx}`);
        const data = await resp.json();

        if (data.error) {
            detailBody.innerHTML = `<div class="pe-error">${escapeHtml(data.error)}</div>`;
            return;
        }

        renderSectionDetail(data, detailBody);
    } catch (e) {
        detailBody.innerHTML = `<div class="pe-error">Failed: ${escapeHtml(e.message)}</div>`;
    }
}

function renderSectionDetail(sec, container) {
    let html = '';

    // Section header info
    html += '<div class="pe-sec-info-grid">';
    html += `<div class="pe-sec-info-item"><span class="pe-label">Section</span><span class="pe-value mono">${escapeHtml(sec.name)}</span></div>`;
    html += `<div class="pe-sec-info-item"><span class="pe-label">Raw Offset</span><span class="pe-value mono">${sec.raw_offset}</span></div>`;
    html += `<div class="pe-sec-info-item"><span class="pe-label">Raw Size</span><span class="pe-value">${formatSize(sec.raw_size)}</span></div>`;
    html += `<div class="pe-sec-info-item"><span class="pe-label">Virtual Addr</span><span class="pe-value mono">${sec.virtual_address}</span></div>`;
    html += `<div class="pe-sec-info-item"><span class="pe-label">Virtual Size</span><span class="pe-value">${formatSize(sec.virtual_size)}</span></div>`;
    html += `<div class="pe-sec-info-item"><span class="pe-label">Entropy</span><span class="pe-value">${sec.entropy.toFixed(4)}</span></div>`;
    html += '</div>';

    // Characteristics flags
    if (sec.characteristic_flags && sec.characteristic_flags.length > 0) {
        html += '<div class="pe-sec-flags">';
        html += '<div class="pe-sec-subtitle">Characteristics</div>';
        html += '<div class="pe-sec-flag-list">';
        sec.characteristic_flags.forEach(f => {
            html += `<span class="pe-sec-flag-tag" title="${escapeHtml(f.description)}">${escapeHtml(f.flag)}</span>`;
        });
        html += '</div></div>';
    }

    // Hex dump preview
    html += '<div class="pe-sec-hex-section">';
    html += `<div class="pe-sec-subtitle">Hex Dump <span class="pe-sec-meta">(showing ${formatSize(sec.display_size)} of ${formatSize(sec.total_data_size)})</span></div>`;
    html += `<pre class="pe-sec-hexdump">${escapeHtml(sec.hex_dump)}</pre>`;
    if (sec.total_data_size > sec.display_size) {
        html += `<button class="btn btn-sm pe-sec-load-more" onclick="peLoadMoreSection(${sec.index}, ${sec.display_size})">Load more...</button>`;
    }
    html += '</div>';

    // Strings tab view
    const totalStrings = sec.string_count + sec.wide_string_count;
    html += '<div class="pe-sec-strings-section">';
    html += `<div class="pe-sec-subtitle">Strings <span class="pe-sec-meta">(${sec.string_count} ASCII, ${sec.wide_string_count} UTF-16LE)</span></div>`;

    if (totalStrings > 0) {
        html += '<div class="pe-sec-strings-tabs">';
        html += `<button class="pe-sec-str-tab active" onclick="peSwitchStrTab(${sec.index}, 'ascii')">ASCII (${sec.string_count})</button>`;
        html += `<button class="pe-sec-str-tab" onclick="peSwitchStrTab(${sec.index}, 'wide')">UTF-16 (${sec.wide_string_count})</button>`;
        html += '</div>';

        // ASCII strings
        html += `<div class="pe-sec-str-panel" id="pe-sec-str-ascii-${sec.index}">`;
        if (sec.strings.length > 0) {
            html += '<div class="pe-sec-str-list">';
            sec.strings.forEach(s => {
                html += `<div class="pe-sec-str-entry"><span class="pe-sec-str-offset">${s.offset.toString(16).padStart(6, '0')}</span><span class="pe-sec-str-val">${escapeHtml(s.value)}</span></div>`;
            });
            html += '</div>';
        } else {
            html += '<div class="pe-sec-str-empty">No ASCII strings found.</div>';
        }
        html += '</div>';

        // Wide strings
        html += `<div class="pe-sec-str-panel" id="pe-sec-str-wide-${sec.index}" style="display:none;">`;
        if (sec.wide_strings.length > 0) {
            html += '<div class="pe-sec-str-list">';
            sec.wide_strings.forEach(s => {
                html += `<div class="pe-sec-str-entry"><span class="pe-sec-str-offset">${s.offset.toString(16).padStart(6, '0')}</span><span class="pe-sec-str-val">${escapeHtml(s.value)}</span></div>`;
            });
            html += '</div>';
        } else {
            html += '<div class="pe-sec-str-empty">No UTF-16 strings found.</div>';
        }
        html += '</div>';
    } else {
        html += '<div class="pe-sec-str-empty">No strings found in this section.</div>';
    }

    html += '</div>';

    // Jump to hex editor button
    html += `<div class="pe-sec-actions">`;
    html += `<button class="btn btn-sm btn-primary" onclick="peJumpToSection(${sec.raw_offset_dec})">View in Hex Editor</button>`;
    html += `</div>`;

    container.innerHTML = html;
}

function peSwitchStrTab(secIdx, tab) {
    const asciiPanel = document.getElementById(`pe-sec-str-ascii-${secIdx}`);
    const widePanel = document.getElementById(`pe-sec-str-wide-${secIdx}`);
    if (!asciiPanel || !widePanel) return;

    // Toggle panels
    asciiPanel.style.display = tab === 'ascii' ? '' : 'none';
    widePanel.style.display = tab === 'wide' ? '' : 'none';

    // Toggle tab active states
    const container = asciiPanel.closest('.pe-sec-strings-section');
    if (container) {
        container.querySelectorAll('.pe-sec-str-tab').forEach((btn, i) => {
            btn.classList.toggle('active', (i === 0 && tab === 'ascii') || (i === 1 && tab === 'wide'));
        });
    }
}

async function peLoadMoreSection(secIdx, currentBytes) {
    const filepath = state.hexFilePath || document.getElementById('hex-filepath').value.trim();
    if (!filepath) return;

    const newMax = currentBytes + 8192;
    try {
        const resp = await fetch(`/api/file/pe/section?path=${encodeURIComponent(filepath)}&index=${secIdx}&max_bytes=${newMax}`);
        const data = await resp.json();
        if (data.error) return;

        const detailBody = document.getElementById(`pe-sec-detail-body-${secIdx}`);
        if (detailBody) renderSectionDetail(data, detailBody);
    } catch (e) { /* silently fail */ }
}

function peJumpToSection(rawOffset) {
    // Load in hex editor at this offset
    document.getElementById('hex-offset').value = rawOffset;
    state.hexOffset = rawOffset;
    hexLoad();
    // Scroll to hex editor body
    const editorBody = document.querySelector('.hex-editor-body');
    if (editorBody) editorBody.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// --- ELF Analysis ---

async function elfAnalyze() {
    const filepath = state.hexFilePath || document.getElementById('hex-filepath').value.trim();
    const panel = document.getElementById('elf-panel');
    const body = document.getElementById('elf-panel-body');

    // Hide PE panel if open
    document.getElementById('pe-panel').style.display = 'none';

    if (!filepath) {
        panel.style.display = 'block';
        body.innerHTML = '<div class="elf-error">No file loaded. Load a file in the hex editor first.</div>';
        return;
    }

    panel.style.display = 'block';
    body.innerHTML = '<div class="elf-loading"><div class="loading-spinner"></div><span>Parsing ELF binary...</span></div>';

    try {
        LoadingSpinner.start();
        const resp = await fetch(`/api/file/elf?path=${encodeURIComponent(filepath)}`);
        const data = await resp.json();
        LoadingSpinner.stop();

        if (data.error) {
            body.innerHTML = `<div class="elf-error">${escapeHtml(data.error)}</div>`;
            return;
        }

        renderElfAnalysis(data, body);
    } catch (e) {
        LoadingSpinner.stop();
        body.innerHTML = `<div class="elf-error">Failed: ${escapeHtml(e.message)}</div>`;
    }
}

function renderElfAnalysis(elf, container) {
    let html = '';

    // --- DiE-style Detection Overview ---
    if (elf.detection) {
        html += renderDetectionOverview(elf.detection, 'elf');
    }

    // --- File map (planes are painted asynchronously below) ---
    html += fileMapInlineBlock(elf.path, 'elf');

    // --- IOC Flags Banner ---
    if (elf.flags && elf.flags.length > 0) {
        html += '<div class="elf-flags-banner">';
        html += `<div class="elf-flags-header"><span class="elf-flags-icon">&#x26A0;</span> <strong>${elf.flags.length} IOC Flag${elf.flags.length > 1 ? 's' : ''} Detected</strong>`;
        html += `<span class="elf-flag-counts">`;
        if (elf.flag_count.high) html += `<span class="elf-flag-badge high">${elf.flag_count.high} HIGH</span>`;
        if (elf.flag_count.medium) html += `<span class="elf-flag-badge med">${elf.flag_count.medium} MED</span>`;
        if (elf.flag_count.low) html += `<span class="elf-flag-badge low">${elf.flag_count.low} LOW</span>`;
        html += `</span></div>`;
        html += '<div class="elf-flags-list">';
        elf.flags.sort((a, b) => {
            const order = {high: 0, medium: 1, low: 2};
            return (order[a.severity] ?? 3) - (order[b.severity] ?? 3);
        }).forEach((f, idx) => {
            const hasEvidence = f.evidence && Object.keys(f.evidence).length > 0;
            html += `<div class="elf-flag-item sev-${cssToken(f.severity)}${hasEvidence ? ' expandable' : ''}" ${hasEvidence ? `onclick="toggleFlagEvidence(this)"` : ''}>`;
            html += `<span class="elf-flag-sev">${escapeHtml(f.severity.toUpperCase())}</span>`;
            html += `<span class="elf-flag-detail">${escapeHtml(f.detail)}</span>`;
            if (hasEvidence) html += `<span class="elf-flag-expand-icon">&#x25BC;</span>`;
            html += `</div>`;
            if (hasEvidence) {
                html += `<div class="elf-flag-evidence" style="display:none;">`;
                html += renderFlagEvidence(f);
                html += `</div>`;
            }
        });
        html += '</div></div>';
    } else {
        html += '<div class="elf-flags-banner clean"><span class="elf-flags-icon">&#x2705;</span> No IOC flags detected.</div>';
    }

    // --- Overview Grid ---
    html += '<div class="elf-overview-grid">';

    // ELF Identification card
    const ident = elf.ident;
    html += `<div class="elf-card">
        <div class="elf-card-title">ELF IDENTIFICATION</div>
        <div class="elf-field"><span class="elf-label">Class</span><span class="elf-value">${escapeHtml(ident.class)}</span></div>
        <div class="elf-field"><span class="elf-label">Data</span><span class="elf-value">${escapeHtml(ident.data)}</span></div>
        <div class="elf-field"><span class="elf-label">OS/ABI</span><span class="elf-value">${escapeHtml(ident.osabi)}</span></div>
        <div class="elf-field"><span class="elf-label">File Size</span><span class="elf-value">${formatSize(elf.file_size)}</span></div>
        <div class="elf-field"><span class="elf-label">Total Entropy</span><span class="elf-value ${elf.total_entropy >= 7.0 ? 'elf-bad' : elf.total_entropy >= 6.5 ? 'elf-warn' : ''}">${elf.total_entropy.toFixed(3)}</span></div>
    </div>`;

    // ELF Header card
    const hdr = elf.header;
    html += `<div class="elf-card">
        <div class="elf-card-title">ELF HEADER</div>
        <div class="elf-field"><span class="elf-label">Type</span><span class="elf-value">${escapeHtml(hdr.type)}</span></div>
        <div class="elf-field"><span class="elf-label">Machine</span><span class="elf-value">${escapeHtml(hdr.machine)}</span></div>
        <div class="elf-field"><span class="elf-label">Entry Point</span><span class="elf-value mono">${hdr.entry_point}</span></div>
        <div class="elf-field"><span class="elf-label">Sections</span><span class="elf-value">${hdr.sh_count}</span></div>
        <div class="elf-field"><span class="elf-label">Segments</span><span class="elf-value">${hdr.ph_count}</span></div>
        <div class="elf-field"><span class="elf-label">Flags</span><span class="elf-value mono">${hdr.flags}</span></div>
    </div>`;

    // Security Features card
    const sec = elf.security;
    html += `<div class="elf-card">
        <div class="elf-card-title" data-info="Hardening of the binary: PIE for ASLR, a non-executable stack, RELRO, a stack canary and Fortify, and whether its symbols are stripped.">SECURITY FEATURES</div>
        <div class="elf-field"><span class="elf-label">PIE (ASLR)</span><span class="elf-value ${sec.pie ? 'elf-ok' : 'elf-bad'}">${sec.pie ? 'Yes' : 'No'}</span></div>
        <div class="elf-field"><span class="elf-label">NX (Stack)</span><span class="elf-value ${sec.nx ? 'elf-ok' : 'elf-bad'}">${sec.nx ? 'Enabled' : 'Disabled'}</span></div>
        <div class="elf-field"><span class="elf-label">RELRO</span><span class="elf-value ${sec.relro === 'Full' ? 'elf-ok' : sec.relro === 'Partial' ? 'elf-warn' : 'elf-bad'}">${sec.relro}</span></div>
        <div class="elf-field"><span class="elf-label">Stack Canary</span><span class="elf-value ${sec.stack_canary ? 'elf-ok' : 'elf-bad'}">${sec.stack_canary ? 'Yes' : 'No'}</span></div>
        <div class="elf-field"><span class="elf-label">Fortify</span><span class="elf-value ${sec.fortify ? 'elf-ok' : 'elf-dim'}">${sec.fortify ? 'Yes' : 'No'}</span></div>
        <div class="elf-field"><span class="elf-label">Stripped</span><span class="elf-value">${sec.stripped ? 'Yes' : 'No'}</span></div>
    </div>`;

    // Linking info card
    html += `<div class="elf-card">
        <div class="elf-card-title">LINKING</div>
        <div class="elf-field"><span class="elf-label">Interpreter</span><span class="elf-value mono">${escapeHtml(elf.interpreter || 'None (static)')}</span></div>
        <div class="elf-field"><span class="elf-label">SONAME</span><span class="elf-value">${escapeHtml(elf.soname || '—')}</span></div>
        <div class="elf-field"><span class="elf-label">RPATH</span><span class="elf-value ${elf.rpath ? 'elf-warn' : ''}">${escapeHtml(elf.rpath || '—')}</span></div>
        <div class="elf-field"><span class="elf-label">RUNPATH</span><span class="elf-value">${escapeHtml(elf.runpath || '—')}</span></div>
        <div class="elf-field"><span class="elf-label">Libraries</span><span class="elf-value">${elf.needed_libraries ? elf.needed_libraries.length : 0}</span></div>
        <div class="elf-field"><span class="elf-label">Imports</span><span class="elf-value">${elf.import_count || 0} symbols</span></div>
    </div>`;

    html += '</div>'; // end overview grid

    // --- Needed Libraries ---
    if (elf.needed_libraries && elf.needed_libraries.length > 0) {
        html += '<div class="elf-section-block">';
        html += '<div class="elf-card-title">NEEDED LIBRARIES</div>';
        html += '<div class="elf-libs-list">';
        elf.needed_libraries.forEach(lib => {
            html += `<span class="elf-lib-badge">${escapeHtml(lib)}</span>`;
        });
        html += '</div></div>';
    }

    // --- Sections Table ---
    if (elf.sections && elf.sections.length > 0) {
        html += '<div class="elf-section-block">';
        html += '<div class="elf-card-title" data-info="Section headers with type, address, offset, size, flags and entropy. Entropy close to 8 means compressed or encrypted data.">SECTIONS</div>';
        html += '<table class="elf-table" data-sortable data-sort-id="elf-sections"><thead><tr><th>#</th><th>Name</th><th>Type</th><th>Address</th><th>Offset</th><th>Size</th><th>Flags</th><th>Entropy</th><th>Status</th></tr></thead><tbody>';
        elf.sections.forEach(s => {
            const rowClass = s.entropy_status === 'high' ? 'elf-row-high' : s.entropy_status === 'warn' ? 'elf-row-warn' : '';
            const wxBadge = s.wx_warning ? ' <span class="elf-wx-badge">W+X</span>' : '';
            const packerBadge = s.packer_indicator ? ` <span class="elf-packer-badge">${escapeHtml(s.packer_indicator)}</span>` : '';
            const elfSecOffsetDec = s.offset_dec != null ? s.offset_dec : parseInt(s.offset, 16);
            const nameHtml = s.name && s.size > 0
                ? `<a class="section-link" href="#" onclick="elfJumpToSection(${elfSecOffsetDec}); return false;" title="View in Hex Editor">${escapeHtml(s.name)}</a>`
                : (escapeHtml(s.name) || '<em>null</em>');
            html += `<tr class="${rowClass}">
                <td>${s.index}</td>
                <td class="mono" data-sort-value="${escapeHtml(s.name || '')}">${nameHtml}${wxBadge}${packerBadge}</td>
                <td>${escapeHtml(s.type)}</td>
                <td class="mono">${s.address}</td>
                <td class="mono">${s.offset}</td>
                <td data-sort-value="${sortNumberValue(s.size)}">${formatSize(s.size)}</td>
                <td class="mono">${s.flags_str}</td>
                <td><div class="elf-entropy-bar"><div class="elf-entropy-fill ${s.entropy_status}" style="width:${(s.entropy / 8 * 100).toFixed(1)}%"></div><span class="elf-entropy-val">${s.entropy.toFixed(2)}</span></div></td>
                <td><span class="elf-status-badge ${s.entropy_status}">${s.entropy_status}</span></td>
            </tr>`;
        });
        html += '</tbody></table></div>';
    }

    // --- Segments Table ---
    if (elf.segments && elf.segments.length > 0) {
        html += '<div class="elf-section-block">';
        html += '<div class="elf-card-title" data-info="The segments the loader maps into memory, with offsets, addresses, sizes and permissions; the note marks segments that matter for security.">PROGRAM HEADERS (SEGMENTS)</div>';
        html += '<table class="elf-table" data-sortable data-sort-id="elf-segments"><thead><tr><th>#</th><th>Type</th><th>Offset</th><th>VAddr</th><th>FileSz</th><th>MemSz</th><th>Flags</th><th>Note</th></tr></thead><tbody>';
        elf.segments.forEach(seg => {
            const noteHtml = seg.security_note ? `<span class="elf-seg-note">${escapeHtml(seg.security_note)}</span>` :
                             seg.interpreter ? `<span class="elf-seg-note mono">${escapeHtml(seg.interpreter)}</span>` : '';
            html += `<tr>
                <td>${seg.index}</td>
                <td class="mono">${escapeHtml(seg.type)}</td>
                <td class="mono">${seg.offset}</td>
                <td class="mono">${seg.vaddr}</td>
                <td data-sort-value="${sortNumberValue(seg.filesz)}">${formatSize(seg.filesz)}</td>
                <td data-sort-value="${sortNumberValue(seg.memsz)}">${formatSize(seg.memsz)}</td>
                <td class="mono">${seg.flags_str}</td>
                <td>${noteHtml}</td>
            </tr>`;
        });
        html += '</tbody></table></div>';
    }

    // --- Suspicious Imports ---
    if (elf.suspicious_imports && Object.keys(elf.suspicious_imports).length > 0) {
        html += '<div class="elf-section-block">';
        html += '<div class="elf-card-title elf-suspicious-title">SUSPICIOUS IMPORTS</div>';
        html += '<div class="elf-suspicious-grid">';
        for (const [category, symbols] of Object.entries(elf.suspicious_imports)) {
            const catLabel = category.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
            html += `<div class="elf-suspicious-card">
                <div class="elf-suspicious-cat">${escapeHtml(catLabel)}</div>
                <div class="elf-suspicious-syms">${symbols.map(s => `<code>${escapeHtml(s)}</code>`).join(', ')}</div>
            </div>`;
        }
        html += '</div></div>';
    }

    // --- Imported Symbols (collapsible) ---
    if (elf.imported_symbols && elf.imported_symbols.length > 0) {
        html += '<div class="elf-section-block">';
        html += `<div class="elf-card-title elf-collapsible" onclick="elfToggleSection(this)">IMPORTED SYMBOLS (${elf.import_count}) &#x25B6;</div>`;
        html += '<div class="elf-collapse-body" style="display:none;">';
        html += '<table class="elf-table elf-sym-table" data-sortable data-sort-id="elf-imports"><thead><tr><th>Name</th><th>Bind</th><th>Type</th></tr></thead><tbody>';
        elf.imported_symbols.forEach(sym => {
            html += `<tr><td class="mono">${escapeHtml(sym.name)}</td><td>${escapeHtml(sym.bind)}</td><td>${escapeHtml(sym.type)}</td></tr>`;
        });
        if (elf.import_count > elf.imported_symbols.length) {
            html += `<tr data-sort-skip><td colspan="3" class="muted">... and ${elf.import_count - elf.imported_symbols.length} more</td></tr>`;
        }
        html += '</tbody></table></div></div>';
    }

    // --- Exported Symbols (collapsible) ---
    if (elf.exported_symbols && elf.exported_symbols.length > 0) {
        html += '<div class="elf-section-block">';
        html += `<div class="elf-card-title elf-collapsible" onclick="elfToggleSection(this)">EXPORTED SYMBOLS (${elf.export_count}) &#x25B6;</div>`;
        html += '<div class="elf-collapse-body" style="display:none;">';
        html += '<table class="elf-table elf-sym-table" data-sortable data-sort-id="elf-exports"><thead><tr><th>Name</th><th>Bind</th><th>Type</th><th>Value</th><th>Size</th></tr></thead><tbody>';
        elf.exported_symbols.forEach(sym => {
            html += `<tr><td class="mono">${escapeHtml(sym.name)}</td><td>${escapeHtml(sym.bind)}</td><td>${escapeHtml(sym.type)}</td><td class="mono">${escapeHtml(sym.value)}</td><td>${escapeHtml(sym.size)}</td></tr>`;
        });
        if (elf.export_count > elf.exported_symbols.length) {
            html += `<tr data-sort-skip><td colspan="5" class="muted">... and ${elf.export_count - elf.exported_symbols.length} more</td></tr>`;
        }
        html += '</tbody></table></div></div>';
    }

    container.innerHTML = html;
    fileMapInlineMount(elf.path, 'elf');
}

function elfToggleSection(el) {
    const body = el.nextElementSibling;
    if (body.style.display === 'none') {
        body.style.display = 'block';
        el.innerHTML = el.innerHTML.replace('\u25B6', '\u25BC');
    } else {
        body.style.display = 'none';
        el.innerHTML = el.innerHTML.replace('\u25BC', '\u25B6');
    }
}

function elfJumpToSection(rawOffset) {
    // Load section in hex editor at this offset
    document.getElementById('hex-offset').value = rawOffset;
    state.hexOffset = rawOffset;
    hexLoad();
    // Scroll to hex editor body
    const editorBody = document.querySelector('.hex-editor-body');
    if (editorBody) editorBody.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// --- Detail Panels for Dashboard Services ---
async function openAgentDetail() {
    pushDetailHistory('agent', 0);
    setDetailHeader('Service', 'background:rgba(var(--accent-orange-rgb), 0.15);color:var(--accent-orange)', 'DetonatorAgent', '');
    setDetailBody('<div class="muted">Loading...</div>');
    showDetail();

    const online = state.serviceStatus.detonator_agent?.online;
    const inUse = state.serviceStatus.detonator_agent?.data?.in_use;
    let html = `<div class="detail-fields">
        <div class="detail-field"><span class="field-label">Status</span><span class="field-value" style="color:${online ? 'var(--accent-green)' : 'var(--accent-red)'}">${online ? 'Running' : 'Stopped'}</span></div>
        <div class="detail-field"><span class="field-label">Activity</span><span class="field-value" style="color:${inUse ? 'var(--accent-orange)' : 'var(--text-muted)'}">${inUse ? 'Detonating' : 'Idle'}</span></div>
        <div class="detail-field"><span class="field-label">Port</span><span class="field-value">8080</span></div>
        <div class="detail-field"><span class="field-label">Framework</span><span class="field-value">.NET 8.0</span></div>
        <div class="detail-field"><span class="field-label">Install Dir</span><span class="field-value mono">C:\\DetonatorAgent</span></div>
        <div class="detail-field"><span class="field-label">EDR Plugin</span><span class="field-value">Fibratus</span></div>
    </div>`;
    setDetailBody(html);

    // Load the most recent detonations so the agent card links straight to their results
    try {
        const resp = await fetch('/api/submissions');
        if (resp.ok) {
            const subs = await resp.json();
            const executed = (subs || []).filter(s => s.agent_pid || s.agent_status);
            if (executed.length > 0) {
                let recent = '<div class="detail-section"><div class="detail-section-title">RECENT DETONATIONS</div><div class="det-recent-list">';
                executed.slice(0, 8).forEach(s => {
                    const args = [s.litterbox_hash, s.sha256, s.agent_pid, s.filename].map(jsArg).join(', ');
                    const ts = s.timestamp ? new Date(s.timestamp).toLocaleString('en-GB', {hour12:false}) : '';
                    const vlabel = s.verdict && s.verdict.label ? s.verdict.label : '';
                    const vcls = vlabel === 'MALICIOUS' ? 'malicious' : (vlabel === 'SUSPICIOUS' ? 'suspicious' : 'clean');
                    recent += `<div class="det-recent-item" onclick="viewDetonationResult(${args})">
                        <span class="det-recent-name">${escapeHtml(s.filename || s.sha256 || 'unknown')}</span>
                        ${s.agent_pid ? `<span class="det-recent-pid">PID ${escapeHtml(String(s.agent_pid))}</span>` : ''}
                        ${vlabel ? `<span class="det-verdict-badge det-verdict-${cssToken(vcls)}" style="font-size:9px;padding:1px 6px;">${escapeHtml(vlabel)}</span>` : ''}
                        <span class="det-recent-ts muted">${ts}</span>
                    </div>`;
                });
                recent += '</div></div>';
                setDetailBody(html + recent);
            }
        }
    } catch (e) {}
}

async function openLitterboxDetail() {
    pushDetailHistory('litterbox', 0);
    setDetailHeader('Service', 'background:rgba(var(--accent-purple-rgb), 0.15);color:var(--accent-purple)', 'LitterBox', '');
    setDetailBody('<div class="muted">Loading...</div>');
    showDetail();

    const online = state.serviceStatus.litterbox?.online;
    let html = `<div class="detail-fields">
        <div class="detail-field"><span class="field-label">Status</span><span class="field-value" style="color:${online ? 'var(--accent-green)' : 'var(--accent-red)'}">${online ? 'Running' : 'Stopped'}</span></div>
        <div class="detail-field"><span class="field-label">Port</span><span class="field-value">1337</span></div>
        <div class="detail-field"><span class="field-label">URL</span><span class="field-value"><a href="http://localhost:1337" target="_blank" style="color:var(--accent-cyan)">http://localhost:1337</a></span></div>
    </div>`;

    // Fetch recent analyses from LitterBox
    if (online) {
        try {
            const resp = await fetch('/api/litterbox/analyses?status=completed');
            if (resp.ok) {
                const analyses = await resp.json();
                const items = Array.isArray(analyses) ? analyses : (analyses.analyses || analyses.results || []);
                if (items.length > 0) {
                    html += `<div class="detail-section"><div class="detail-section-title">RECENT ANALYSES (${items.length})</div>`;
                    html += '<div class="lb-analyses-list">';
                    items.slice(0, 20).forEach(a => {
                        const hash = a.sha256 || a.hash || a.id || '';
                        const filename = a.filename || a.name || hash.substring(0, 12) + '...';
                        const score = a.score !== undefined ? a.score : '--';
                        const status = a.status || 'completed';
                        const scoreClass = score >= 7 ? 'high' : score >= 4 ? 'med' : 'low';
                        const ts = a.timestamp || a.created_at || '';
                        const timeStr = ts ? new Date(ts).toLocaleString('en-GB', {hour12:false, day:'2-digit', month:'short', hour:'2-digit', minute:'2-digit'}) : '--';
                        html += `<div class="lb-analysis-entry" onclick="viewLitterboxResult(${jsArg(hash)})">
                            <div class="lb-entry-main">
                                <span class="lb-entry-name" title="${escapeHtml(hash)}">${escapeHtml(filename)}</span>
                                <span class="lb-entry-time">${timeStr}</span>
                            </div>
                            <div class="lb-entry-meta">
                                <span class="lb-entry-score ${scoreClass}">${escapeHtml(String(score))}</span>
                                <span class="lb-entry-hash mono">${escapeHtml(String(hash).substring(0, 16))}...</span>
                                <span class="lb-entry-status">${escapeHtml(status)}</span>
                            </div>
                        </div>`;
                    });
                    html += '</div></div>';
                } else {
                    html += '<div class="detail-section"><div class="detail-section-title">RECENT ANALYSES</div><div class="muted" style="padding:8px;font-size:11px;">No completed analyses found.</div></div>';
                }
            }
        } catch (e) {
            html += `<div class="detail-section"><div class="muted" style="padding:8px;font-size:11px;">Could not fetch analyses: ${escapeHtml(e.message)}</div></div>`;
        }
    } else {
        html += '<div class="detail-section"><div class="muted" style="padding:12px;font-size:11px;">LitterBox is offline. Start the service to view analyses.</div></div>';
    }

    setDetailBody(html);
}

async function viewLitterboxResult(hash) {
    pushDetailHistory('litterbox-result', hash);
    setDetailHeader('Analysis', 'background:rgba(var(--accent-purple-rgb), 0.15);color:var(--accent-purple)', 'LitterBox Result', hash.substring(0, 12) + '...');
    setDetailBody('<div class="muted">Fetching analysis results...</div>');
    showDetail();

    let html = '';

    // Fetch static results
    let staticData = null;
    try {
        const resp = await fetch(`/api/litterbox/results/static/${encodeURIComponent(hash)}`);
        if (resp.ok) staticData = await resp.json();
    } catch (e) {}

    // Fetch dynamic results
    let dynamicData = null;
    try {
        const resp = await fetch(`/api/litterbox/results/dynamic/${encodeURIComponent(hash)}`);
        if (resp.ok) dynamicData = await resp.json();
    } catch (e) {}

    // Fetch file info
    let fileInfo = null;
    try {
        const resp = await fetch(`/api/litterbox/results/info/${encodeURIComponent(hash)}`);
        if (resp.ok) fileInfo = await resp.json();
    } catch (e) {}

    // File info section
    if (fileInfo) {
        html += `<div class="detail-fields">`;
        if (fileInfo.filename || fileInfo.name) html += `<div class="detail-field"><span class="field-label">Filename</span><span class="field-value">${escapeHtml(fileInfo.filename || fileInfo.name)}</span></div>`;
        if (fileInfo.sha256) html += `<div class="detail-field"><span class="field-label">SHA-256</span><span class="field-value mono" style="font-size:10px;word-break:break-all">${escapeHtml(fileInfo.sha256)}</span></div>`;
        if (fileInfo.md5) html += `<div class="detail-field"><span class="field-label">MD5</span><span class="field-value mono" style="font-size:10px">${escapeHtml(fileInfo.md5)}</span></div>`;
        if (fileInfo.size !== undefined) html += `<div class="detail-field"><span class="field-label">Size</span><span class="field-value">${formatSize(fileInfo.size)}</span></div>`;
        if (fileInfo.file_type || fileInfo.type) html += `<div class="detail-field"><span class="field-label">Type</span><span class="field-value">${escapeHtml(fileInfo.file_type || fileInfo.type)}</span></div>`;
        if (fileInfo.score !== undefined) html += `<div class="detail-field"><span class="field-label">Score</span><span class="field-value" style="color:${fileInfo.score >= 7 ? 'var(--accent-red)' : fileInfo.score >= 4 ? 'var(--c-amber-400)' : 'var(--accent-green)'};font-weight:700">${fileInfo.score}/10</span></div>`;
        html += `</div>`;
    } else {
        html += `<div class="detail-fields"><div class="detail-field"><span class="field-label">Hash</span><span class="field-value mono" style="font-size:10px;word-break:break-all">${escapeHtml(hash)}</span></div></div>`;
    }

    // Static analysis results
    html += '<div class="detail-section"><div class="detail-section-title">STATIC ANALYSIS</div>';
    if (staticData && !staticData.error) {
        html += '<div class="lb-result-content">';
        html += renderLbStaticResults(staticData);
        html += '</div>';
    } else {
        html += `<div class="muted" style="padding:8px;font-size:11px;">${staticData?.error ? escapeHtml(staticData.error) : 'No static analysis results available.'}</div>`;
    }
    html += '</div>';

    // Dynamic analysis results
    html += '<div class="detail-section"><div class="detail-section-title">DYNAMIC ANALYSIS</div>';
    if (dynamicData && !dynamicData.error) {
        html += '<div class="lb-result-content">';
        html += renderLbDynamicResults(dynamicData);
        html += '</div>';
    } else {
        html += `<div class="muted" style="padding:8px;font-size:11px;">${dynamicData?.error ? escapeHtml(dynamicData.error) : 'No dynamic analysis results available.'}</div>`;
    }
    html += '</div>';

    // Link to LitterBox UI
    html += `<div style="margin-top:12px;"><a href="http://localhost:1337" target="_blank" class="btn btn-sm" style="color:var(--accent-purple);border-color:rgba(var(--accent-purple-rgb), 0.3);">Open in LitterBox UI</a></div>`;

    setDetailBody(html);
}

async function viewDetonationResult(lbHash, sha256, pid, filename) {
    const displayHash = sha256 || lbHash || 'unknown';
    pushDetailHistory('detonation-result', displayHash);
    setDetailHeader('Analysis', 'background:rgba(var(--accent-purple-rgb), 0.15);color:var(--accent-purple)', 'Detonation Results', (filename || displayHash.substring(0, 12) + '...'));
    setDetailBody('<div class="muted">Fetching analysis results...</div>');
    showDetail();

    let html = '';

    // --- Fetch Fibratus/Rustinel alerts via /api/detonation/results ---
    let fibratusAlerts = [];
    let fibratusCount = 0;
    let verdict = null;
    let agentBlock = null;
    let iocFeed = null;
    let detData = null;
    try {
        const params = new URLSearchParams();
        if (sha256) params.set('sha256', sha256);
        if (pid) params.set('pid', pid);
        if (lbHash) params.set('litterbox_hash', lbHash);
        if (filename) params.set('filename', filename);
        const resp = await fetch(`/api/detonation/results?${params}`);
        if (resp.ok) {
            const data = await resp.json();
            detData = data;
            fibratusAlerts = data.fibratus_alerts || [];
            fibratusCount = data.fibratus_alert_count || fibratusAlerts.length;
            verdict = data.verdict || null;
            agentBlock = data.agent || null;
            iocFeed = data.ioc_feed || null;
            noteDetonationVerdict(sha256, pid, verdict);
        }
    } catch (e) {}

    // --- Fetch LitterBox results (if hash available) ---
    let staticData = null, dynamicData = null, fileInfo = null;
    if (lbHash) {
        try {
            const resp = await fetch(`/api/litterbox/results/static/${encodeURIComponent(lbHash)}`);
            if (resp.ok) staticData = await resp.json();
        } catch (e) {}
        try {
            const resp = await fetch(`/api/litterbox/results/dynamic/${encodeURIComponent(lbHash)}`);
            if (resp.ok) dynamicData = await resp.json();
        } catch (e) {}
        try {
            const resp = await fetch(`/api/litterbox/results/info/${encodeURIComponent(lbHash)}`);
            if (resp.ok) fileInfo = await resp.json();
        } catch (e) {}
    }

    // --- File info section ---
    html += `<div class="detail-fields">`;
    if (fileInfo) {
        if (fileInfo.filename || fileInfo.name || filename) html += `<div class="detail-field"><span class="field-label">Filename</span><span class="field-value">${escapeHtml(fileInfo.filename || fileInfo.name || filename)}</span></div>`;
        if (fileInfo.sha256 || sha256) html += `<div class="detail-field"><span class="field-label">SHA-256</span><span class="field-value mono" style="font-size:10px;word-break:break-all">${escapeHtml(fileInfo.sha256 || sha256)}</span></div>`;
        if (fileInfo.md5) html += `<div class="detail-field"><span class="field-label">MD5</span><span class="field-value mono" style="font-size:10px">${escapeHtml(fileInfo.md5)}</span></div>`;
        if (fileInfo.size !== undefined) html += `<div class="detail-field"><span class="field-label">Size</span><span class="field-value">${formatSize(fileInfo.size)}</span></div>`;
        if (fileInfo.file_type || fileInfo.type) html += `<div class="detail-field"><span class="field-label">Type</span><span class="field-value">${escapeHtml(fileInfo.file_type || fileInfo.type)}</span></div>`;
        if (pid) html += `<div class="detail-field"><span class="field-label">PID</span><span class="field-value">${escapeHtml(pid)}</span></div>`;
        if (fileInfo.score !== undefined) html += `<div class="detail-field"><span class="field-label">Score</span><span class="field-value" style="color:${fileInfo.score >= 7 ? 'var(--accent-red)' : fileInfo.score >= 4 ? 'var(--c-amber-400)' : 'var(--accent-green)'};font-weight:700">${fileInfo.score}/10</span></div>`;
    } else {
        if (filename) html += `<div class="detail-field"><span class="field-label">Filename</span><span class="field-value">${escapeHtml(filename)}</span></div>`;
        if (sha256) html += `<div class="detail-field"><span class="field-label">SHA-256</span><span class="field-value mono" style="font-size:10px;word-break:break-all">${escapeHtml(sha256)}</span></div>`;
        if (pid) html += `<div class="detail-field"><span class="field-label">PID</span><span class="field-value">${escapeHtml(pid)}</span></div>`;
    }
    html += `</div>`;

    // --- Verdict banner ---
    if (verdict && verdict.label) {
        const cls = verdict.label === 'MALICIOUS' ? 'malicious' : (verdict.label === 'SUSPICIOUS' ? 'suspicious' : 'clean');
        html += `<div class="det-verdict det-verdict-${cls}" style="margin:8px 0;">
            <span class="det-verdict-badge">${escapeHtml(verdict.label)}</span>
            <span class="det-verdict-reasons">${verdict.reasons && verdict.reasons.length ? escapeHtml(verdict.reasons.join(' · ')) : 'No malicious indicators detected'}</span>
        </div>`;
    }
    if (iocFeed && iocFeed.status) {
        const st = iocFeed.status;
        const label = st === 'added' ? 'Hash added to Rustinel IOC watchlist'
            : st === 'exists' ? 'Hash already on IOC watchlist' : `IOC feed: ${st}`;
        html += `<div class="det-ioc-badge ${st === 'error' ? 'warn' : ''}">&#x1F4CC; ${escapeHtml(label)}</div>`;
    }

    // --- VERDICT FLOW: what the verdict came from (its Sankey drawn once the body is in the page) ---
    if (detData && detData.verdict) html += verdictFlowHtml(detData, 'detail');

    // --- Live memory: scored evidence, exit-time dump, network rhythm ---
    // Shown here as well as in the Submit tab, so a detonation opened later
    // (history, after a reload) still explains its memory verdict.
    if (detData && (detData.memory_evidence || detData.exit_capture_result
            || (detData.network_beaconing && detData.network_beaconing.available))) {
        html += '<div class="detail-section"><div class="detail-section-title" data-info="The memory evidence of the detonation, scored by one model, with the dump written when the sample exited and the rhythm of its network connections. A score of 2.0 or more is SUSPICIOUS, 6.0 or more MALICIOUS.">LIVE MEMORY</div><div style="padding:4px 8px;">';
        if (detData.memory_evidence) html += renderMemoryEvidence(detData.memory_evidence, detData.aether);
        if (detData.exit_capture_result) html += renderExitCaptureBlock(detData.exit_capture_result);
        if (detData.network_beaconing && detData.network_beaconing.available) {
            html += renderNetworkBeaconingBlock(detData.network_beaconing);
        }
        html += '</div></div>';
    }

    // --- Named pipes (Sysmon 17/18) of the sample subtree ---
    if (detData && detData.named_pipes) {
        html += '<div class="detail-section"><div class="detail-section-title" data-info="Pipes that the process tree of the sample created or connected to, from Sysmon EID 17 and 18. C2 catalog names, cross-process use, sensitive system pipes and random names are flagged and scored with the memory evidence.">NAMED PIPES</div><div style="padding:4px 8px;">';
        html += renderNamedPipesBlock(detData.named_pipes);
        html += '</div></div>';
    }

    // --- DetonatorAgent execution section ---
    const exec = agentBlock && agentBlock.execution;
    if (agentBlock) {
        html += '<div class="detail-section"><div class="detail-section-title">DETONATORAGENT EXECUTION</div><div class="detail-fields">';
        html += `<div class="detail-field"><span class="field-label">Status</span><span class="field-value">${agentBlock.online ? 'Online' : 'Offline'}${agentBlock.in_use ? ' · Detonating' : (agentBlock.online ? ' · Idle' : '')}</span></div>`;
        if (exec && exec.pid) html += `<div class="detail-field"><span class="field-label">PID</span><span class="field-value">${escapeHtml(String(exec.pid))}</span></div>`;
        html += '</div>';
        if (exec && exec.stdout) html += `<div class="det-sub-title" style="padding:4px 8px;">stdout</div><pre class="lb-raw" style="margin:0 8px;">${escapeHtml(String(exec.stdout))}</pre>`;
        if (exec && exec.stderr) html += `<div class="det-sub-title" style="padding:4px 8px;">stderr</div><pre class="lb-raw" style="margin:0 8px;">${escapeHtml(String(exec.stderr))}</pre>`;
        if (exec && exec.agent_logs) html += `<div class="det-sub-title" style="padding:4px 8px;">Agent Logs</div><pre class="lb-raw" style="margin:0 8px;max-height:300px;overflow:auto;">${escapeHtml(String(exec.agent_logs))}</pre>`;
        if (!exec || (!exec.stdout && !exec.stderr && !exec.agent_logs)) html += `<div class="muted" style="padding:8px;font-size:11px;">No execution output captured (GUI app, or no detonation matched this sample).</div>`;
        html += '</div>';
    }

    // --- Fibratus / Rustinel Alerts Section ---
    html += '<div class="detail-section"><div class="detail-section-title">FIBRATUS / RUSTINEL ALERTS';
    if (fibratusCount > 0) html += ` <span class="badge badge-red" style="margin-left:6px;">${fibratusCount}</span>`;
    html += '</div>';
    if (fibratusAlerts.length > 0) {
        html += '<div class="det-alerts-list" style="padding:0 8px 8px;">';
        fibratusAlerts.slice(0, 30).forEach(alert => {
            const sev = (alert.severity || 'unknown').toLowerCase();
            const ruleName = alert.rule_name || 'Unknown Rule';
            const procName = alert.process_name || '';
            const engine = alert.engine || '';
            const alertPid = alert.pid || '';
            const ts = alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString('en-GB', {hour12:false}) : '';
            html += `<div class="det-alert-item sev-${cssToken(sev)}">
                <span class="det-alert-sev">${escapeHtml(sev.toUpperCase())}</span>
                <span class="det-alert-rule">${escapeHtml(ruleName)}</span>
                <span class="det-alert-proc">${escapeHtml(procName)}${alertPid ? ' (PID:' + escapeHtml(String(alertPid)) + ')' : ''}</span>
                ${engine ? '<span class="det-alert-engine">' + escapeHtml(engine) + '</span>' : ''}
                ${ts ? '<span class="det-alert-ts" style="color:var(--text-muted);font-size:10px;margin-left:auto;">' + ts + '</span>' : ''}
            </div>`;
        });
        if (fibratusCount > 30) {
            html += `<div class="muted" style="padding:6px 0;font-size:10px;">... and ${fibratusCount - 30} more alerts</div>`;
        }
        html += '</div>';
    } else {
        html += `<div class="muted" style="padding:8px;font-size:11px;">No Fibratus/Rustinel alerts matched for this sample.</div>`;
    }
    html += '</div>';

    // --- Static analysis results ---
    if (lbHash) {
        html += '<div class="detail-section"><div class="detail-section-title">STATIC ANALYSIS (LitterBox)</div>';
        if (staticData && !staticData.error) {
            html += '<div class="lb-result-content">';
            html += renderLbStaticResults(staticData);
            html += '</div>';
        } else {
            html += `<div class="muted" style="padding:8px;font-size:11px;">${staticData?.error ? escapeHtml(staticData.error) : 'No static analysis results available.'}</div>`;
        }
        html += '</div>';

        // --- Dynamic analysis results ---
        html += '<div class="detail-section"><div class="detail-section-title">DYNAMIC ANALYSIS (LitterBox)</div>';
        if (dynamicData && !dynamicData.error) {
            html += '<div class="lb-result-content">';
            html += renderLbDynamicResults(dynamicData);
            html += '</div>';
        } else {
            html += `<div class="muted" style="padding:8px;font-size:11px;">${dynamicData?.error ? escapeHtml(dynamicData.error) : 'No dynamic analysis results available.'}</div>`;
        }
        html += '</div>';
    }

    // Link to LitterBox UI
    if (lbHash) {
        html += `<div style="margin-top:12px;"><a href="http://localhost:1337" target="_blank" class="btn btn-sm" style="color:var(--accent-purple);border-color:rgba(var(--accent-purple-rgb), 0.3);">Open in LitterBox UI</a></div>`;
    }

    setDetailBody(html);
    drawVerdictFlow('detail');
}

function renderLbStaticResults(data) {
    let html = '';

    // YARA matches
    const yara = data.yara_results || data.yara || data.yara_matches;
    if (yara) {
        const matches = Array.isArray(yara) ? yara : (yara.matches || yara.rules || []);
        if (matches.length > 0) {
            html += `<div class="lb-subsection"><div class="lb-sub-title">YARA Matches (${matches.length})</div><div class="lb-tag-list">`;
            matches.forEach(m => {
                const name = typeof m === 'string' ? m : (m.rule || m.name || JSON.stringify(m));
                html += `<span class="lb-yara-tag">${escapeHtml(name)}</span>`;
            });
            html += '</div></div>';
        }
    }

    // CheckPlz results
    const checkplz = data.checkplz_results || data.checkplz;
    if (checkplz) {
        html += '<div class="lb-subsection"><div class="lb-sub-title">CheckPlz</div>';
        if (typeof checkplz === 'object') {
            const detections = checkplz.detections || checkplz.results || [];
            if (Array.isArray(detections) && detections.length > 0) {
                html += '<div class="lb-tag-list">';
                detections.forEach(d => {
                    const label = typeof d === 'string' ? d : (d.name || d.rule || JSON.stringify(d));
                    html += `<span class="lb-detection-tag">${escapeHtml(label)}</span>`;
                });
                html += '</div>';
            } else {
                html += `<pre class="lb-raw">${escapeHtml(JSON.stringify(checkplz, null, 2)).substring(0, 1500)}</pre>`;
            }
        } else {
            html += `<pre class="lb-raw">${escapeHtml(String(checkplz)).substring(0, 1500)}</pre>`;
        }
        html += '</div>';
    }

    // Strings / Stringnalyzer
    const strings = data.stringnalyzer_results || data.strings || data.stringnalyzer;
    if (strings) {
        html += '<div class="lb-subsection"><div class="lb-sub-title">Strings Analysis</div>';
        if (typeof strings === 'object') {
            const suspicious = strings.suspicious || strings.suspicious_strings || [];
            const count = strings.count || strings.total || (Array.isArray(suspicious) ? suspicious.length : 0);
            html += `<div class="lb-meta">Suspicious strings: <strong>${count}</strong></div>`;
            if (Array.isArray(suspicious) && suspicious.length > 0) {
                html += '<div class="lb-strings-list">';
                suspicious.slice(0, 30).forEach(s => {
                    const val = typeof s === 'string' ? s : (s.value || s.string || JSON.stringify(s));
                    html += `<div class="lb-string-entry mono">${escapeHtml(val)}</div>`;
                });
                if (suspicious.length > 30) html += `<div class="lb-string-entry muted">... and ${suspicious.length - 30} more</div>`;
                html += '</div>';
            }
        } else {
            html += `<pre class="lb-raw">${escapeHtml(String(strings)).substring(0, 1500)}</pre>`;
        }
        html += '</div>';
    }

    // Fallback: raw data if nothing matched above
    if (!yara && !checkplz && !strings) {
        html += `<pre class="lb-raw">${escapeHtml(JSON.stringify(data, null, 2)).substring(0, 3000)}</pre>`;
    }

    return html;
}

function renderLbDynamicResults(data) {
    let html = '';

    // PE-Sieve
    const peSieve = data.pe_sieve || data.pe_sieve_results;
    if (peSieve) {
        html += '<div class="lb-subsection"><div class="lb-sub-title">PE-Sieve</div>';
        if (typeof peSieve === 'object') {
            const suspicious = peSieve.suspicious || peSieve.total_suspicious || 0;
            const replaced = peSieve.replaced || peSieve.total_replaced || 0;
            const implanted = peSieve.implanted || 0;
            html += `<div class="lb-dynamic-stats">`;
            html += `<span class="lb-stat ${suspicious > 0 ? 'warn' : 'ok'}">Suspicious: ${suspicious}</span>`;
            html += `<span class="lb-stat ${replaced > 0 ? 'bad' : 'ok'}">Replaced: ${replaced}</span>`;
            html += `<span class="lb-stat ${implanted > 0 ? 'bad' : 'ok'}">Implanted: ${implanted}</span>`;
            html += `</div>`;
            if (peSieve.details || peSieve.modules) {
                html += `<details class="lb-raw-details"><summary>Raw output</summary><pre class="lb-raw">${escapeHtml(JSON.stringify(peSieve.details || peSieve.modules, null, 2)).substring(0, 2000)}</pre></details>`;
            }
        } else {
            html += `<pre class="lb-raw">${escapeHtml(String(peSieve)).substring(0, 1500)}</pre>`;
        }
        html += '</div>';
    }

    // Moneta
    const moneta = data.moneta || data.moneta_results;
    if (moneta) {
        html += '<div class="lb-subsection"><div class="lb-sub-title">Moneta</div>';
        if (typeof moneta === 'object') {
            const iocs = moneta.ioc_count || moneta.iocs || moneta.findings || 0;
            const iocCount = typeof iocs === 'number' ? iocs : (Array.isArray(iocs) ? iocs.length : 0);
            html += `<div class="lb-dynamic-stats"><span class="lb-stat ${iocCount > 0 ? 'bad' : 'ok'}">IOCs: ${iocCount}</span></div>`;
            if (Array.isArray(iocs) && iocs.length > 0) {
                html += '<div class="lb-tag-list">';
                iocs.slice(0, 20).forEach(ioc => {
                    const label = typeof ioc === 'string' ? ioc : (ioc.description || ioc.type || JSON.stringify(ioc));
                    html += `<span class="lb-detection-tag">${escapeHtml(label)}</span>`;
                });
                html += '</div>';
            }
        } else {
            html += `<pre class="lb-raw">${escapeHtml(String(moneta)).substring(0, 1500)}</pre>`;
        }
        html += '</div>';
    }

    // HollowsHunter
    const hollows = data.hollows_hunter || data.hollows_hunter_results;
    if (hollows) {
        html += '<div class="lb-subsection"><div class="lb-sub-title">HollowsHunter</div>';
        if (typeof hollows === 'object') {
            const suspicious = hollows.suspicious || hollows.total_suspicious || 0;
            html += `<div class="lb-dynamic-stats"><span class="lb-stat ${suspicious > 0 ? 'bad' : 'ok'}">Suspicious: ${suspicious}</span></div>`;
        } else {
            html += `<pre class="lb-raw">${escapeHtml(String(hollows)).substring(0, 1500)}</pre>`;
        }
        html += '</div>';
    }

    // RedEdr
    const rededr = data.rededr || data.rededr_results;
    if (rededr) {
        html += '<div class="lb-subsection"><div class="lb-sub-title">RedEdr</div>';
        html += `<pre class="lb-raw">${escapeHtml(typeof rededr === 'object' ? JSON.stringify(rededr, null, 2) : String(rededr)).substring(0, 2000)}</pre>`;
        html += '</div>';
    }

    // Fallback
    if (!peSieve && !moneta && !hollows && !rededr) {
        html += `<pre class="lb-raw">${escapeHtml(JSON.stringify(data, null, 2)).substring(0, 3000)}</pre>`;
    }

    return html;
}

async function openRustinelDetail() {
    pushDetailHistory('rustinel', 0);
    setDetailHeader('Engine', 'background:rgba(var(--accent-cyan-rgb), 0.15);color:var(--accent-cyan)', 'Rustinel', 'loading...');
    setDetailBody('<div class="muted">Fetching Rustinel status...</div>');
    showDetail();

    try {
        const resp = await fetch('/api/rustinel');
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const info = await resp.json();
        renderRustinelDetail(info);
    } catch (e) {
        setDetailBody(`<div class="muted">Failed to fetch Rustinel info: ${escapeHtml(e.message)}</div>`);
    }
}

function renderRustinelDetail(info) {
    const online = info.online;
    const statusColor = online ? 'var(--accent-green)' : 'var(--accent-red)';
    setDetailHeader('Engine', 'background:rgba(var(--accent-cyan-rgb), 0.15);color:var(--accent-cyan)', 'Rustinel', '');

    let html = `<div class="detail-fields">
        <div class="detail-field"><span class="field-label">Version</span><span class="field-value">${escapeHtml(info.version || 'unknown')}</span></div>
        <div class="detail-field"><span class="field-label">Status</span><span class="field-value" style="color:${statusColor}">${online ? 'running' : 'stopped'}</span></div>
        <div class="detail-field"><span class="field-label">Install Dir</span><span class="field-value mono">${escapeHtml(info.install_dir || '')}</span></div>
        <div class="detail-field"><span class="field-label">Alerts Dir</span><span class="field-value mono">${escapeHtml(info.alerts_dir || '')}</span></div>
        <div class="detail-field"><span class="field-label">Alerts Total</span><span class="field-value">${info.alerts_count || 0}</span></div>
    </div>`;

    const rules = info.rules || {};
    html += `<div class="detail-section">
        <div class="detail-section-title">DETECTION RULES</div>
        <div class="activity-grid" style="grid-template-columns: repeat(3, 1fr);">
            <div class="activity-counter"><div class="counter-label">SIGMA</div><div class="counter-value">${rules.sigma || 0}</div></div>
            <div class="activity-counter"><div class="counter-label">YARA</div><div class="counter-value">${rules.yara || 0}</div></div>
            <div class="activity-counter"><div class="counter-label">IOC</div><div class="counter-value">${((rules.ioc?.hashes||0)+(rules.ioc?.ips||0)+(rules.ioc?.domains||0))}</div></div>
        </div>
    </div>`;

    const providers = info.etw_providers || [];
    if (providers.length > 0) {
        html += `<div class="detail-section"><div class="detail-section-title">ETW PROVIDERS (${providers.length})</div><div class="detail-fields">`;
        providers.forEach(p => {
            html += `<div class="detail-field"><span class="field-label" style="font-size:10px">${escapeHtml(p.name.replace('Microsoft-Windows-', ''))}</span><span class="field-value" style="font-size:10px;color:var(--text-muted)">kw: ${escapeHtml(p.keywords)}</span></div>`;
        });
        html += `</div></div>`;
    }

    setDetailBody(html);
}

// --- Alert Detail ---
function openAlertDetailById(id) {
    const idx = _alertIndexById.get(String(id));
    if (idx !== undefined) openAlertDetail(idx);
}

function openAlertDetail(idx) {
    const alert = state.alerts[idx];
    if (!alert) return;

    // History keeps the id: positions shift with every alert refresh.
    pushDetailHistory('alert', alert.id != null ? `id:${alert.id}` : idx);
    const severity = (alert.severity || 'unknown').toLowerCase();
    const tint = 0x20 / 255;
    const badgeStyles = {
        critical: `background:rgba(var(--severity-critical-rgb), ${tint});color:var(--severity-critical)`,
        high: `background:rgba(var(--severity-high-rgb), ${tint});color:var(--severity-high)`,
        medium: `background:rgba(var(--severity-medium-rgb), ${tint});color:var(--severity-medium)`,
        low: `background:rgba(var(--severity-low-rgb), ${tint});color:var(--severity-low)`,
    };

    setDetailHeader(
        severity.charAt(0).toUpperCase() + severity.slice(1),
        badgeStyles[severity] || `background:rgba(var(--text-muted-rgb), ${tint});color:var(--text-secondary)`,
        alert.rule_name || 'Unknown Rule',
        formatRelativeTime(alert.timestamp)
    );

    let html = '';
    if (alert.rule_description) {
        html += `<div class="alert-description">${escapeHtml(alert.rule_description)}</div>`;
    }

    // Pivot into the process graph on this alert's PID (and its parent).
    const pivots = [];
    if (alert.pid) pivots.push(`<button class="pivot-graph-btn" onclick="focusProcessGraph(${jsArg(alert.pid)}, {reset:true, at:${jsArg(alert.timestamp || '')}})">&#9673; PID ${escapeHtml(String(alert.pid))} in graph</button>`);
    if (alert.parent_pid) pivots.push(`<button class="pivot-graph-btn secondary" onclick="focusProcessGraph(${jsArg(alert.parent_pid)}, {reset:true, at:${jsArg(alert.timestamp || '')}})">&#9673; Parent ${escapeHtml(String(alert.parent_pid))} in graph</button>`);
    if (pivots.length) html += `<div class="pivot-graph-bar">${pivots.join('')}</div>`;

    const tags = (alert.tags || []).map(tag => {
        if (tag.startsWith('attack.t')) return `<span class="tag technique">${escapeHtml(tag.replace('attack.', '').toUpperCase())}</span>`;
        if (tag.startsWith('attack.')) return `<span class="tag tactic">${escapeHtml(tag.replace('attack.', '').toUpperCase())}</span>`;
        return `<span class="tag mitre">${escapeHtml(tag)}</span>`;
    }).join('');

    // --- Structured fields ---
    html += `<div class="detail-fields">
        <div class="detail-field"><span class="field-label">Severity</span><span class="field-value"><span class="ev-sev-dot ${cssToken(severity)}" style="display:inline-block;width:8px;height:8px;vertical-align:middle;margin-right:4px;"></span>${escapeHtml(severity.charAt(0).toUpperCase() + severity.slice(1))}</span></div>
        <div class="detail-field"><span class="field-label">Engine</span><span class="field-value">${escapeHtml((alert.engine || 'unknown').toUpperCase())}</span></div>
        <div class="detail-field"><span class="field-label">Rule</span><span class="field-value mono">${escapeHtml(alert.rule_name || '')}</span></div>
        <div class="detail-field"><span class="field-label">PID</span><span class="field-value">${escapeHtml(String(alert.pid || 'N/A'))}</span></div>
        <div class="detail-field"><span class="field-label">Process</span><span class="field-value">${escapeHtml(alert.process_name || '')}</span></div>
        <div class="detail-field"><span class="field-label">Image</span><span class="field-value mono">${escapeHtml(alert.process_image || '')}</span></div>
        <div class="detail-field"><span class="field-label">Category</span><span class="field-value">${escapeHtml(formatCategory(alert.category))}</span></div>
        ${alert.command_line ? `<div class="detail-field"><span class="field-label">Command</span><span class="field-value mono">${escapeHtml(alert.command_line)}</span></div>` : ''}
        ${alert.parent_name ? `<div class="detail-field"><span class="field-label">Parent</span><span class="field-value">${escapeHtml(String(alert.parent_pid || '?'))} (${escapeHtml(alert.parent_name)})</span></div>` : ''}
        ${alert.parent_command_line ? `<div class="detail-field"><span class="field-label">Parent Cmd</span><span class="field-value mono">${escapeHtml(alert.parent_command_line)}</span></div>` : ''}
        ${alert.user ? `<div class="detail-field"><span class="field-label">User</span><span class="field-value">${escapeHtml(alert.user)}</span></div>` : ''}
        ${tags ? `<div class="detail-field"><span class="field-label">ATT&CK</span><span class="field-value">${tags}</span></div>` : ''}
        <div class="detail-field"><span class="field-label">Timestamp</span><span class="field-value">${escapeHtml(alert.timestamp || '')}</span></div>
    </div>`;

    // --- Parsed raw event as structured sections ---
    // The alert list carries a trimmed raw event; the complete one is loaded
    // here, and only if this alert is still the one being shown afterwards.
    html += `<div id="alert-raw-event">${renderStructuredRawEvent(alert.raw || {})}</div>`;

    setDetailBody(html);
    showDetail();

    if (alert.raw_trimmed && alert.id != null) {
        const shownId = alert.id;
        fetch(`/api/alerts/${encodeURIComponent(shownId)}`)
            .then(r => (r.ok ? r.json() : null))
            .then(full => {
                const target = document.getElementById('alert-raw-event');
                if (!full || !target || state.detailHistory.length === 0) return;
                const top = state.detailHistory[state.detailHistory.length - 1];
                if (top.type !== 'alert' || String(top.id) !== `id:${shownId}`) return;
                target.innerHTML = renderStructuredRawEvent(full.raw || {});
            })
            .catch(() => {});
    }
}

function renderStructuredRawEvent(raw) {
    let html = '';

    // Group ECS fields into logical sections
    const sections = {
        'Match Details': {},
        'Event': {},
        'Process': {},
        'Host': {},
        'Rule': {},
        'Other': {},
    };

    // Categorize each key
    const flatEntries = flattenObject(raw);
    flatEntries.forEach(([key, value]) => {
        if (key.startsWith('edr.match') || key.startsWith('edr.rule')) {
            sections['Match Details'][key] = value;
        } else if (key.startsWith('event.') || key === '@timestamp') {
            sections['Event'][key] = value;
        } else if (key.startsWith('process.')) {
            sections['Process'][key] = value;
        } else if (key.startsWith('host.') || key.startsWith('agent.')) {
            sections['Host'][key] = value;
        } else if (key.startsWith('rule.')) {
            sections['Rule'][key] = value;
        } else {
            sections['Other'][key] = value;
        }
    });

    // Render each non-empty section
    for (const [title, fields] of Object.entries(sections)) {
        const entries = Object.entries(fields);
        if (!entries.length) continue;

        html += `<div class="detail-section">
            <div class="detail-section-title">${title.toUpperCase()}</div>
            <div class="raw-structured">`;

        entries.forEach(([key, value]) => {
            const displayValue = formatRawValue(value);
            const isImportant = key.includes('severity') || key.includes('rule.name') || key.includes('match') || key.includes('executable') || key.includes('command_line');
            html += `<div class="raw-field${isImportant ? ' important' : ''}">
                <span class="raw-key">${escapeHtml(key)}</span>
                <span class="raw-value">${displayValue}</span>
            </div>`;
        });

        html += `</div></div>`;
    }

    // Collapsible full JSON (for copy/paste)
    html += `<div class="detail-section">
        <div class="detail-section-title raw-json-toggle" onclick="this.parentElement.classList.toggle('expanded')">
            RAW JSON <span style="font-weight:400;font-size:9px;color:var(--text-muted);margin-left:6px;">(click to expand)</span>
        </div>
        <div class="raw-json-collapsible"><pre class="raw-json-pretty">${syntaxHighlightJson(JSON.stringify(raw, null, 2))}</pre></div>
    </div>`;

    return html;
}

function flattenObject(obj, prefix = '', result = []) {
    if (obj === null || obj === undefined) return result;
    for (const [key, value] of Object.entries(obj)) {
        const fullKey = prefix ? `${prefix}.${key}` : key;
        if (value && typeof value === 'object' && !Array.isArray(value)) {
            flattenObject(value, fullKey, result);
        } else {
            result.push([fullKey, value]);
        }
    }
    return result;
}

function formatRawValue(value) {
    if (value === null || value === undefined) return '<span class="raw-null">null</span>';
    if (typeof value === 'boolean') return `<span class="raw-bool">${value}</span>`;
    if (typeof value === 'number') return `<span class="raw-num">${value}</span>`;
    if (Array.isArray(value)) {
        if (value.length === 0) return '<span class="raw-null">[]</span>';
        // Render arrays inline if simple, or as list if complex
        if (value.every(v => typeof v === 'string' || typeof v === 'number')) {
            return value.map(v => `<span class="raw-str">${escapeHtml(String(v))}</span>`).join(', ');
        }
        return `<span class="raw-str">${escapeHtml(JSON.stringify(value))}</span>`;
    }
    // Strings
    const str = String(value);
    // Color paths
    if (str.match(/^[A-Z]:\\/i) || str.startsWith('/')) {
        return `<span class="raw-path">${escapeHtml(str)}</span>`;
    }
    // Color IPs
    if (str.match(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)) {
        return `<span class="raw-ip">${escapeHtml(str)}</span>`;
    }
    return `<span class="raw-str">${escapeHtml(str)}</span>`;
}

function syntaxHighlightJson(json) {
    return json
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?)/g, function(match) {
            let cls = 'json-str';
            if (match.endsWith(':')) {
                cls = 'json-key';
                match = match.slice(0, -1) + '<span class="json-colon">:</span>';
            }
            return `<span class="${cls}">${match}</span>`;
        })
        .replace(/\b(true|false)\b/g, '<span class="json-bool">$1</span>')
        .replace(/\b(null)\b/g, '<span class="json-null">$1</span>')
        .replace(/\b(-?\d+\.?\d*)\b/g, '<span class="json-num">$1</span>');
}

// --- Process Detail ---
function openProcessDetail(pid) {
    pid = String(pid);          // instance key, see procKey()
    state.selectedProcess = pid;
    renderProcessList();
    pushDetailHistory('process', pid);
    // Cyberpunk: picking a process in the drawer closes it, so the detail view is in sight.
    if (currentTheme() === 'cyberpunk') closeDrawer();

    const proc = state.processes[pid] || state.processes[String(pid)];
    if (!proc) {
        setDetailHeader(`PID ${pid}`, 'background:rgba(var(--accent-blue-rgb), 0.2);color:var(--accent-blue)', `Process ${pid}`, '');
        setDetailBody(`<div class="muted">No detailed information available for PID ${escapeHtml(String(pid))}.</div>`);
        showDetail();
        return;
    }

    const hasExited = !!proc.exit_time;
    const statusText = hasExited ? 'exited' : 'running';
    setDetailHeader(`PID ${proc.pid}`, 'background:rgba(var(--accent-blue-rgb), 0.2);color:var(--accent-blue)', proc.name || 'unknown', statusText);

    let html = `<div class="pivot-graph-bar"><button class="pivot-graph-btn" onclick="focusProcessGraph(${jsArg(procKey(proc))}, {reset:true, at:${jsArg(proc.first_seen || '')}})">&#9673; View in process graph</button></div>`;
    html += `<div class="detail-fields">
        <div class="detail-field"><span class="field-label">Image</span><span class="field-value mono">${escapeHtml(proc.image || '')}</span></div>
        <div class="detail-field"><span class="field-label">Command line</span><span class="field-value mono">${escapeHtml(proc.command_line || '')}</span></div>
        <div class="detail-field"><span class="field-label">User</span><span class="field-value">${escapeHtml(proc.user || '')}</span></div>
        <div class="detail-field"><span class="field-label">Parent</span><span class="field-value">${escapeHtml(String(proc.parent_pid || 'N/A'))} ${proc.parent_name ? '(' + escapeHtml(proc.parent_name) + ')' : ''}</span></div>
        <div class="detail-field"><span class="field-label">Started</span><span class="field-value">${formatRelativeTime(proc.first_seen)}</span></div>
        ${hasExited ? `<div class="detail-field"><span class="field-label">Exited</span><span class="field-value">${formatRelativeTime(proc.exit_time)}</span></div>` : ''}
    </div>`;

    const act = proc.activity || {};
    html += `<div class="detail-section"><div class="detail-section-title">ACTIVITY</div>
        <div class="activity-grid">
            ${activityCounter('FILE', act.file)}
            ${activityCounter('NETWORK', act.network)}
            ${activityCounter('DNS', act.dns)}
            ${activityCounter('REGISTRY', act.registry)}
            ${activityCounter('MODULES', act.modules)}
            ${activityCounter('THREATS', act.threats)}
        </div></div>`;

    const procAlerts = proc.alerts || [];
    if (procAlerts.length > 0) {
        html += `<div class="detail-section"><div class="detail-section-title">ALERTS (${procAlerts.length})</div>`;
        procAlerts.forEach(alert => {
            const sev = (alert.severity || 'unknown').toLowerCase();
            html += `<div class="child-card" onclick="openAlertDetailById(${jsArg(alert.id)})">
                <div class="child-header">
                    <span class="event-severity ${cssToken(sev)}">${escapeHtml(alert.severity)}</span>
                    <span class="child-name" style="margin-left:8px">${escapeHtml(alert.rule_name || '')}</span>
                </div>
            </div>`;
        });
        html += `</div>`;
    }

    // Live-memory tools only make sense while the process still exists.
    html += `<div class="detail-section"><div class="detail-section-title">LIVE MEMORY</div>`;
    if (hasExited) {
        html += `<div class="muted" style="font-size:11px;">Process has exited — memory scanning and dumping are unavailable.</div>`;
    } else {
        const aetherOk = state.aetherStatus ? state.aetherStatus.installed !== false : true;
        const pdOk = state.processDumpStatus ? state.processDumpStatus.installed !== false : true;
        html += `<div class="mem-actions">`;
        html += `<button class="btn btn-sm btn-accent" ${aetherOk ? '' : 'disabled'} `
            + `onclick="runAetherScan(${jsInt(proc.pid)}, 'proc-mem-result')" `
            + `title="${aetherOk ? 'Scan this process for injection and implant structures' : 'Aether is not installed on this VM'}">Aether scan</button>`;
        html += `<button class="btn btn-sm btn-accent" ${pdOk ? '' : 'disabled'} `
            + `onclick="runProcessDump(${jsInt(proc.pid)}, 'proc-mem-result')" `
            + `title="${pdOk ? 'Dump this process memory components to disk' : 'Process Dump is not installed on this VM'}">Dump memory</button>`;
        // Without a baseline every known-good module would be dumped as well.
        if (pdOk && state.processDumpStatus && state.processDumpStatus.clean_db === false) {
            html += `<span class="mem-warn-inline">no clean-hash baseline — dumps will include known-good modules</span>`;
        }
        html += `</div><div class="mem-result" id="proc-mem-result"></div>`;
    }
    html += `</div>`;

    setDetailBody(html);
    showDetail();
}

// --- Render: Process list (sidebar) ---
function renderProcessList() {
    const container = document.getElementById('process-list');
    const count = document.getElementById('process-count');
    const drawerCount = document.getElementById('drawer-count');    // ☰ PROCESSES in the Cyberpunk top bar
    const procs = Object.values(state.processes);
    count.textContent = procs.length;
    if (drawerCount) drawerCount.textContent = procs.length;

    if (!procs.length) {
        container.innerHTML = '<div class="muted" style="padding:8px;font-size:10px;">No processes tracked</div>';
        return;
    }

    container.innerHTML = procs.map(proc => {
        const hasThreats = (proc.activity?.threats || 0) > 0;
        const isActive = state.selectedProcess === procKey(proc);
        return `<div class="process-item ${isActive ? 'active' : ''}" onclick="openProcessDetail(${jsArg(procKey(proc))})">
                <div class="proc-icon ${hasThreats ? 'threat' : ''}"></div>
                <span class="proc-name">${escapeHtml(proc.name || 'unknown')}</span>
                <span class="proc-pid">${escapeHtml(String(proc.pid))}</span>
            </div>`;
    }).join('');
}

// --- Render: Timeline (sidebar) ---
// The 60 newest alerts, newest first, as bars (CHART) or as a table of time,
// severity and rule (TABLE)
function renderTimeline() {
    const container = document.getElementById('timeline');
    const toggle = document.getElementById('timeline-view-toggle');
    // Written once: a refresh keeps the switch (and the keyboard focus on it)
    if (toggle && !toggle.firstElementChild) toggle.innerHTML = viewToggleHtml('timeline');
    const maxBars = 60;
    const alerts = newestAlerts(state.alerts, maxBars);
    const table = document.getElementById('timeline-table');
    if (table) table.innerHTML = timelineTableHtml(alerts);
    if (!alerts.length) {
        container.innerHTML = '';
        return;
    }
    container.innerHTML = alerts.map(alert => {
        const sev = (alert.severity || 'low').toLowerCase();
        const width = 30 + Math.random() * 70;
        return `<div class="timeline-bar severity-${cssToken(sev)}" style="width:${width}%" title="${escapeHtml(alert.rule_name || '')}"></div>`;
    }).join('');
}

// The table view of the sidebar timeline: its alerts, newest first
function timelineTableHtml(alerts) {
    const rows = alerts.map(alert => {
        const sevClass = cssToken(alertSeverity(alert));
        const rule = alertRuleName(alert);
        return `<tr><td data-sort-value="${sortTimeValue(alert.timestamp)}">${escapeHtml(formatTime(alert.timestamp))}</td>`
            + `<td data-sort-value="${severitySortValue(sevClass)}"><span class="event-severity ${sevClass}">${sevClass || 'unknown'}</span></td>`
            + `<td class="view-table-text" title="${escapeHtml(rule)}">${escapeHtml(rule)}</td></tr>`;
    });
    if (!rows.length) rows.push('<tr data-sort-skip><td colspan="3" class="view-table-empty">No alerts yet.</td></tr>');
    return '<table class="view-table" data-sortable data-sort-id="timeline-alerts"><thead><tr><th>Time</th><th>Severity</th>'
        + `<th>Rule</th></tr></thead><tbody>${rows.join('')}</tbody></table>`;
}

// --- Render: Service status ---
// The services of the status row (sidebar; the drop-down of the Cyberpunk top bar)
const STATUS_SERVICES = [
    {key: 'rustinel', id: 'status-rustinel', name: 'Rustinel'},
    {key: 'sysmon', id: 'status-sysmon', name: 'Sysmon'},
    {key: 'detonator_agent', id: 'status-agent', name: 'Agent'},
    {key: 'litterbox', id: 'status-litterbox', name: 'Litterbox'},
    {key: 'fibratus', id: 'status-fibratus', name: 'Fibratus'},
];

function updateServiceStatus(status) {
    // Detect transitions and show toasts
    STATUS_SERVICES.forEach(svc => {
        const nowOnline = !!status[svc.key]?.online;
        const prev = state._prevServiceStatus?.[svc.key]?.online;
        // Only toast on actual transitions (not initial load)
        if (state._prevServiceStatus && prev !== undefined && prev !== nowOnline) {
            if (nowOnline) {
                showToast('success', `${svc.name} online`, 'Service is now running');
            } else {
                showToast('warning', `${svc.name} offline`, 'Service is no longer running');
            }
        }
        setStatus(svc.id, nowOnline);
    });
    state._prevServiceStatus = JSON.parse(JSON.stringify(status));
    updateTopbarServices(status);
}

// Summary on the services button of the Cyberpunk top bar: a dot and "n/m ONLINE"
function updateTopbarServices(status = state.serviceStatus) {
    const button = document.getElementById('topbar-services');
    if (!button) return;
    const online = STATUS_SERVICES.filter(svc => status?.[svc.key]?.online).length;
    const total = STATUS_SERVICES.length;
    const dot = document.createElement('span');
    dot.className = 'topbar-dot ' + (online === total ? 'ok' : online ? 'partial' : 'down');
    button.replaceChildren(dot, `${online}/${total} ONLINE`);
    button.title = `${online} of ${total} services online`;
}

function setStatus(elementId, online) {
    const el = document.getElementById(elementId);
    if (el) {
        el.classList.toggle('online', !!online);
        el.classList.toggle('offline', !online);
    }
}

async function launchService(serviceName, btnElement) {
    const btn = btnElement || (typeof event !== 'undefined' && event ? event.currentTarget : null);
    if (!btn) { console.error('launchService: no button reference'); return; }
    const originalText = btn.textContent;
    const displayName = serviceName.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
    btn.textContent = 'Starting...';
    btn.disabled = true;
    btn.classList.add('launching');
    showToast('info', `Starting ${displayName}...`, 'Sending launch request');

    try {
        const resp = await fetch('/api/service/launch', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({service: serviceName}),
        });
        const data = await resp.json();

        if (data.success) {
            btn.textContent = 'Launched';
            btn.classList.remove('launching');
            btn.classList.add('launched');
            showToast('success', `${displayName} launched`, data.message || 'Service started successfully');
            // Refresh status after a brief delay to let service start
            setTimeout(() => refreshDashboard(), 3000);
        } else {
            btn.textContent = 'Failed';
            btn.classList.remove('launching');
            btn.classList.add('launch-failed');
            const errorDetail = data.error || 'Unknown error';
            showToast('error', `${displayName} failed to start`, errorDetail);
            setTimeout(() => {
                btn.textContent = originalText;
                btn.disabled = false;
                btn.classList.remove('launch-failed');
            }, 5000);
        }
    } catch (e) {
        btn.textContent = 'Error';
        btn.classList.remove('launching');
        btn.classList.add('launch-failed');
        showToast('error', `${displayName} — connection error`, e.message || 'Could not reach the server');
        setTimeout(() => {
            btn.textContent = originalText;
            btn.disabled = false;
            btn.classList.remove('launch-failed');
        }, 5000);
    }
}

// --- Detail Panel: Navigation ---
function pushDetailHistory(type, id) {
    const last = state.detailHistory[state.detailHistory.length - 1];
    if (last && last.type === type && last.id === id) return;
    state.detailHistory.push({ type, id });
}

function goDetailBack() {
    if (state.detailHistory.length > 1) {
        state.detailHistory.pop();
        const prev = state.detailHistory.pop();
        if (prev.type === 'process') openProcessDetail(prev.id);
        else if (prev.type === 'rustinel') openRustinelDetail();
        else if (prev.type === 'agent') openAgentDetail();
        else if (prev.type === 'litterbox') openLitterboxDetail();
        else if (prev.type === 'alert') {
            const ref = String(prev.id);
            if (ref.startsWith('id:')) openAlertDetailById(ref.slice(3));
            else openAlertDetail(prev.id);
        }
    } else {
        closeDetail();
    }
}

function setDetailHeader(badgeText, badgeStyle, title, meta) {
    const headerLeft = document.querySelector('.detail-header-left');
    if (headerLeft) {
        headerLeft.innerHTML = `
            <button class="btn btn-sm" onclick="goDetailBack()">&lt; Back</button>
            <span class="detail-badge" id="detail-badge" style="${escapeHtml(badgeStyle)}">${escapeHtml(badgeText)}</span>
            <span class="detail-title" id="detail-title">${escapeHtml(title)}</span>`;
    }
    const metaEl = document.getElementById('detail-meta');
    if (metaEl) metaEl.textContent = meta || '';
}

function setDetailBody(html) {
    document.getElementById('detail-body').innerHTML = html;
}

function showDetail() {
    document.getElementById('detail-panel').classList.remove('hidden');
    state.detailOpen = true;
}

function closeDetail() {
    document.getElementById('detail-panel').classList.add('hidden');
    state.detailOpen = false;
    state.selectedProcess = null;
    state.detailHistory = [];
    renderProcessList();
}

// --- Upload / Submit ---
function initUpload() {
    const zone = document.getElementById('upload-zone');
    const input = document.getElementById('file-input');
    const btn = document.getElementById('submit-btn');

    zone.addEventListener('click', () => input.click());
    zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('dragover'); });
    zone.addEventListener('dragleave', () => zone.classList.remove('dragover'));
    zone.addEventListener('drop', e => {
        e.preventDefault();
        zone.classList.remove('dragover');
        if (e.dataTransfer.files.length) {
            input.files = e.dataTransfer.files;
            handleFileSelect(e.dataTransfer.files[0]);
        }
    });
    input.addEventListener('change', () => {
        if (input.files.length) handleFileSelect(input.files[0]);
    });
    btn.addEventListener('click', submitSample);
}

function handleFileSelect(file) {
    const zone = document.getElementById('upload-zone');
    zone.classList.add('has-file');
    zone.querySelector('p').textContent = `${file.name} (${formatSize(file.size)})`;
    document.getElementById('submit-btn').disabled = false;
}

async function submitSample() {
    const input = document.getElementById('file-input');
    const target = document.getElementById('submit-target').value;
    const btn = document.getElementById('submit-btn');
    const result = document.getElementById('submit-result');

    if (!input.files.length) return;

    btn.disabled = true;
    btn.textContent = 'Detonating...';
    result.className = 'submit-result visible';
    result.innerHTML = '<div>Submitting sample...</div>';

    const formData = new FormData();
    formData.append('file', input.files[0]);
    formData.append('target', target);

    try {
        LoadingSpinner.start();
        const resp = await fetch('/api/submit', { method: 'POST', body: formData });
        const data = await resp.json();
        LoadingSpinner.stop();

        if (resp.ok) {
            result.className = 'submit-result visible success';
            renderDetonationResults(data, result);
        } else {
            result.className = 'submit-result visible error';
            result.textContent = `Error: ${JSON.stringify(data)}`;
        }
    } catch (e) {
        LoadingSpinner.stop();
        result.className = 'submit-result visible error';
        result.textContent = `Network error: ${e.message}`;
    }

    btn.disabled = false;
    btn.textContent = 'Detonate';
    refreshSubmissions();
}

function renderDetonationResults(data, container) {
    const pid = data.file_info?.agent_pid;
    const sha256 = data.file_info?.sha256;
    const lbHash = data.file_info?.litterbox_hash;
    const filename = data.file_info?.name || 'unknown';

    let html = `<div class="det-results">`;
    // Header
    const fullArgs = [lbHash, sha256, pid, filename].map(jsArg).join(', ');
    html += `<div class="det-results-header">
        <div class="det-filename">${escapeHtml(filename)}</div>
        <div class="det-meta">
            ${sha256 ? `<span class="det-hash mono">${escapeHtml(sha256.substring(0, 16))}...</span>` : ''}
            ${pid ? `<span class="det-pid">PID: ${escapeHtml(String(pid))}</span>` : ''}
            <button class="det-full-btn" onclick="viewDetonationResult(${fullArgs})">Full Results &rarr;</button>
        </div>
    </div>`;

    // Stage cards
    html += `<div class="det-stages">`;

    // Agent stage
    if (data.agent) {
        const ok = data.agent.status >= 200 && data.agent.status < 400;
        html += `<div class="det-stage ${ok ? 'ok' : 'fail'}">
            <div class="det-stage-icon">${ok ? '&#x2705;' : '&#x274C;'}</div>
            <div class="det-stage-info">
                <div class="det-stage-title">DetonatorAgent</div>
                <div class="det-stage-detail">${ok ? 'Executed' : 'Failed'} (HTTP ${escapeHtml(String(data.agent.status))})${pid ? ` — PID ${escapeHtml(String(pid))}` : ''}</div>
            </div>
        </div>`;
    }

    // LitterBox upload stage
    if (data.litterbox) {
        const ok = data.litterbox.status >= 200 && data.litterbox.status < 400;
        const errorDetail = data.litterbox.error ? ` — ${data.litterbox.error}` : '';
        html += `<div class="det-stage ${ok ? 'ok' : 'fail'}">
            <div class="det-stage-icon">${ok ? '&#x2705;' : '&#x274C;'}</div>
            <div class="det-stage-info">
                <div class="det-stage-title">LitterBox Upload</div>
                <div class="det-stage-detail">${ok ? 'Uploaded' : 'Failed (HTTP ' + data.litterbox.status + ')' + escapeHtml(errorDetail)}</div>
            </div>
        </div>`;
    }

    // LitterBox static analysis stage
    if (data.litterbox_static) {
        const ok = data.litterbox_static.triggered;
        const errorDetail = data.litterbox_static.error ? ` — ${data.litterbox_static.error}` : '';
        html += `<div class="det-stage ${ok ? 'ok' : 'fail'}">
            <div class="det-stage-icon">${ok ? '&#x2705;' : '&#x274C;'}</div>
            <div class="det-stage-info">
                <div class="det-stage-title">Static Analysis</div>
                <div class="det-stage-detail">${ok ? 'Triggered (YARA + CheckPlz + Strings)' : 'Not triggered' + escapeHtml(errorDetail)}</div>
            </div>
        </div>`;
    }

    // LitterBox dynamic analysis stage
    if (data.litterbox_dynamic) {
        const ok = data.litterbox_dynamic.triggered;
        const errorDetail = data.litterbox_dynamic.error ? ` — ${data.litterbox_dynamic.error}` : '';
        html += `<div class="det-stage ${ok ? 'ok' : 'fail'}">
            <div class="det-stage-icon">${ok ? '&#x2705;' : '&#x274C;'}</div>
            <div class="det-stage-info">
                <div class="det-stage-title">Dynamic Analysis</div>
                <div class="det-stage-detail">${ok ? `Triggered (PE-Sieve, Moneta, HollowsHunter) — ${escapeHtml(data.litterbox_dynamic.target)}` : 'Not triggered' + escapeHtml(errorDetail)}</div>
            </div>
        </div>`;
    }

    // Exit-capture stage: dump-on-exit armed before the sample started
    if (data.exit_capture) {
        const ec = data.exit_capture;
        html += `<div class="det-stage ${ec.armed ? 'ok' : 'pending'}" id="det-exitcap-stage">
            <div class="det-stage-icon">${ec.armed ? '&#x23F3;' : '&#x2796;'}</div>
            <div class="det-stage-info">
                <div class="det-stage-title">Exit Capture</div>
                <div class="det-stage-detail">${ec.armed
                    ? `Armed for ${escapeHtml(ec.image || '')} (${ec.window}s) — dumps memory the moment it exits`
                    : escapeHtml(ec.reason || 'Not armed')}</div>
            </div>
        </div>`;
    }

    // Live-memory stage (beacon hunters, Aether, Process Dump)
    if (data.beacon_scan) {
        const ok = data.beacon_scan.triggered;
        const tools = data.beacon_scan.tools ? data.beacon_scan.tools.join(', ') : '';
        html += `<div class="det-stage ${ok ? 'ok' : 'pending'}" id="det-beacon-stage">
            <div class="det-stage-icon">${ok ? '&#x2705;' : '&#x23F3;'}</div>
            <div class="det-stage-info">
                <div class="det-stage-title">Live Memory</div>
                <div class="det-stage-detail">${ok ? `Triggered (${tools}) — scanning and dumping process memory...` : escapeHtml(data.beacon_scan.reason || 'Not triggered')}</div>
            </div>
        </div>`;
    }

    // Fibratus/EDR stage (always pending initially, status check happens on first poll)
    html += `<div class="det-stage pending" id="det-fibratus-stage">
        <div class="det-stage-icon">&#x23F3;</div>
        <div class="det-stage-info">
            <div class="det-stage-title">Fibratus / Rustinel EDR</div>
            <div class="det-stage-detail">Checking EDR service status...</div>
        </div>
    </div>`;

    html += `</div>`; // end stages

    // Results panels (filled by polling)
    html += `<div class="det-panels" id="det-results-panels">
        <div class="det-panel-loading"><div class="loading-spinner"></div><span>Polling for analysis results...</span></div>
    </div>`;

    html += `</div>`; // end det-results
    container.innerHTML = html;

    // Start polling for results
    if (sha256 || pid || lbHash) {
        pollDetonationResults(sha256, pid, lbHash, filename, 0);
    }
}

let _detonationPollTimer = null;
// Incremented whenever a new result view starts polling. clearTimeout cannot
// cancel a fetch already in flight; its late response would otherwise render
// the previous sample into the panel and restart the old poll chain.
let _detonationPollGen = 0;

function pollDetonationResults(sha256, pid, lbHash, filename, attempt, gen) {
    if (_detonationPollTimer) clearTimeout(_detonationPollTimer);
    if (gen === undefined) gen = ++_detonationPollGen;
    const current = () => gen === _detonationPollGen && document.getElementById('det-results-panels');
    if (!current()) return;
    const maxAttempts = 30; // Poll for up to ~2.5 minutes
    if (attempt >= maxAttempts) {
        // The last results (verdict, VERDICT FLOW, tabs) stay, as when everything is ready
        endDetonationPolling(document.getElementById('det-results-panels'),
            'Polling complete. Results shown above reflect final state.', 'Polling complete. No results were received.');
        return;
    }

    const params = new URLSearchParams();
    if (sha256) params.set('sha256', sha256);
    if (pid) params.set('pid', pid);
    if (lbHash) params.set('litterbox_hash', lbHash);
    if (filename) params.set('filename', filename);

    fetch(`/api/detonation/results?${params}`)
        .then(r => r.json())
        .then(data => {
            if (!current()) return;
            renderDetonationPanels(data);
            noteDetonationVerdict(sha256, pid, data.verdict);
            // Check service status
            const edrStatus = data.edr_status || {};
            const fibratusOffline = edrStatus.fibratus_online === false;
            const rustinelOffline = edrStatus.rustinel_online === false;
            const bothEdrOffline = fibratusOffline && rustinelOffline;
            const litterboxOffline = data.litterbox_online === false;

            // Update LitterBox stage indicators if LitterBox is offline
            if (litterboxOffline && attempt === 0) {
                // Show warning on static/dynamic stages if they haven't succeeded
                const stageCards = document.querySelectorAll('.det-stage');
                stageCards.forEach(card => {
                    const title = card.querySelector('.det-stage-title')?.textContent || '';
                    const detail = card.querySelector('.det-stage-detail');
                    if ((title.includes('Static') || title.includes('Dynamic')) && card.classList.contains('fail')) {
                        if (detail && !detail.textContent.includes('offline')) {
                            detail.textContent += ' — LitterBox offline';
                        }
                    }
                });
            }

            // Update Fibratus/Rustinel stage indicator based on EDR status
            const fStage = document.getElementById('det-fibratus-stage');
            if (fStage) {
                if (data.fibratus_alert_count > 0) {
                    fStage.className = 'det-stage ok';
                    fStage.querySelector('.det-stage-icon').innerHTML = '&#x2705;';
                    fStage.querySelector('.det-stage-detail').textContent = `${data.fibratus_alert_count} alert(s) detected`;
                } else if (bothEdrOffline) {
                    fStage.className = 'det-stage fail';
                    fStage.querySelector('.det-stage-icon').innerHTML = '&#x26A0;';
                    fStage.querySelector('.det-stage-detail').textContent = 'Fibratus and Rustinel are offline — no detection possible';
                } else if (fibratusOffline) {
                    fStage.querySelector('.det-stage-detail').textContent = 'Fibratus offline — waiting for Rustinel alerts...';
                } else if (rustinelOffline) {
                    fStage.querySelector('.det-stage-detail').textContent = 'Rustinel offline — waiting for Fibratus alerts...';
                }
            }
            // Keep polling until all results are ready (static + dynamic + fibratus)
            // Minimum 8 attempts (~40s) to allow EDR rules to fire and alert_loader to pick them up
            // But skip minimum wait if services are offline
            const staticReady = data.ready && data.ready.static !== false;
            const dynamicReady = data.ready && data.ready.dynamic !== false;
            const fibratusReady = data.ready && data.ready.fibratus;
            const allReady = staticReady && dynamicReady && fibratusReady;
            const allOffline = bothEdrOffline && litterboxOffline;
            const minAttempts = allOffline ? 1 : (bothEdrOffline || litterboxOffline) ? 2 : 8;
            if (!allReady || attempt < minAttempts) {
                _detonationPollTimer = setTimeout(() => pollDetonationResults(sha256, pid, lbHash, filename, attempt + 1, gen), 5000);
            } else {
                // Final update: show polling complete message
                let note;
                if (allOffline) {
                    note = 'Polling complete. All analysis services offline — no results available.';
                } else if (litterboxOffline && bothEdrOffline) {
                    note = 'Polling complete. LitterBox and EDR services offline.';
                } else if (litterboxOffline) {
                    note = 'Polling complete. LitterBox offline — static/dynamic analysis unavailable.';
                } else if (bothEdrOffline) {
                    note = 'Polling complete. EDR services offline — no detection alerts available.';
                } else {
                    note = 'Polling complete. All results collected.';
                }
                endDetonationPolling(document.getElementById('det-results-panels'), note);
            }
        })
        .catch(() => {
            if (!current()) return;
            _detonationPollTimer = setTimeout(() => pollDetonationResults(sha256, pid, lbHash, filename, attempt + 1, gen), 5000);
        });
}

// Polling has ended: its note under the results, once. A spinner still in
// the panel (no poll was answered, or none brought results) goes with it;
// `none`, when given, is the note for a panel that then shows nothing else.
function endDetonationPolling(panels, note, none) {
    if (!panels || panels.querySelector('.det-poll-done')) return;
    panels.querySelectorAll('.det-panel-loading').forEach(spinner => spinner.remove());
    const text = none && !panels.children.length ? none : note;
    panels.insertAdjacentHTML('beforeend', `<div class="det-poll-done">${escapeHtml(text)}</div>`);
}

// Raw-JSON modal support: payloads are rebuilt on every render, opened by index.
let _detRawPayloads = [];
function _detRawButton(label, obj) {
    const idx = _detRawPayloads.push(typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2)) - 1;
    return `<button class="det-raw-btn" onclick="detShowRaw(${idx})">${escapeHtml(label || 'View Raw')}</button>`;
}
function detShowRaw(idx) {
    let modal = document.getElementById('det-raw-modal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'det-raw-modal';
        modal.className = 'det-raw-modal hidden';
        modal.innerHTML = `<div class="det-raw-modal-box">
            <div class="det-raw-modal-head"><span>Raw Data</span>
                <button class="det-raw-modal-close" onclick="detHideRaw()">&times;</button></div>
            <div class="det-raw-modal-body"><pre id="det-raw-modal-pre"></pre></div>
        </div>`;
        document.body.appendChild(modal);
        modal.addEventListener('click', (e) => { if (e.target === modal) detHideRaw(); });
        document.addEventListener('keydown', (e) => { if (e.key === 'Escape') detHideRaw(); });
    }
    document.getElementById('det-raw-modal-pre').textContent = _detRawPayloads[idx] || '(no data)';
    modal.classList.remove('hidden');
}
function detHideRaw() {
    const modal = document.getElementById('det-raw-modal');
    if (modal) modal.classList.add('hidden');
}
function detShowTab(tabId, btn) {
    const root = btn.closest('.det-tabs');
    if (!root) return;
    root.querySelectorAll('.det-tab-content').forEach(c => c.classList.add('hidden'));
    root.querySelectorAll('.det-tab-btn').forEach(b => b.classList.remove('active'));
    const target = root.querySelector('#' + tabId);
    if (target) target.classList.remove('hidden');
    btn.classList.add('active');
}

function renderDetonationPanels(data) {
    const panels = document.getElementById('det-results-panels');
    if (!panels) return;

    _detRawPayloads = [];
    let html = '';

    // --- Verdict banner (aggregated CLEAN / SUSPICIOUS / MALICIOUS) ---
    if (data.verdict && data.verdict.label) {
        const v = data.verdict;
        const cls = v.label === 'MALICIOUS' ? 'malicious' : (v.label === 'SUSPICIOUS' ? 'suspicious' : 'clean');
        html += `<div class="det-verdict det-verdict-${cls}">
            <span class="det-verdict-badge">${escapeHtml(v.label)}</span>
            <span class="det-verdict-reasons">${v.reasons && v.reasons.length ? escapeHtml(v.reasons.join(' · ')) : 'No malicious indicators detected'}</span>
        </div>`;
    }

    // --- IOC feed badge ---
    if (data.ioc_feed && data.ioc_feed.status) {
        const st = data.ioc_feed.status;
        const label = st === 'added' ? 'Hash added to Rustinel IOC watchlist'
            : st === 'exists' ? 'Hash already on IOC watchlist'
            : `IOC feed: ${st}`;
        html += `<div class="det-ioc-badge ${st === 'error' ? 'warn' : ''}">&#x1F4CC; ${escapeHtml(label)}</div>`;
    }

    // --- VERDICT FLOW: what the verdict came from (its Sankey drawn once the panels are in the page) ---
    if (data.verdict) html += verdictFlowHtml(data, 'det');

    // --- Build tabs (only those with data) ---
    const tabs = [];

    // Alerts tab
    const alerts = data.fibratus_alerts || [];
    if (alerts.length > 0) {
        let body = `<table class="det-alert-table" data-sortable data-sort-id="detonation-alerts"><thead><tr>
            <th>Severity</th><th>Rule / Threat</th><th>Process</th><th>Engine</th><th>Time</th><th data-no-sort>Raw</th>
            </tr></thead><tbody>`;
        alerts.forEach(alert => {
            const sev = (alert.severity || 'unknown').toLowerCase();
            const ruleName = alert.rule_name || 'Unknown Rule';
            const procName = alert.process_name || '';
            const engine = alert.engine || '';
            const apid = alert.pid || '';
            const ts = alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString('en-GB', {hour12:false}) : '';
            body += `<tr class="sev-${cssToken(sev)}">
                <td data-sort-value="${severitySortValue(sev)}"><span class="det-alert-sev sev-${cssToken(sev)}">${escapeHtml(sev.toUpperCase())}</span></td>
                <td>${escapeHtml(ruleName)}</td>
                <td>${escapeHtml(procName)}${apid ? ' <span class="muted">(PID:' + escapeHtml(String(apid)) + ')</span>' : ''}</td>
                <td>${escapeHtml(engine)}</td>
                <td class="muted" data-sort-value="${sortTimeValue(alert.timestamp)}">${ts}</td>
                <td>${_detRawButton('View', alert.raw || alert)}</td>
            </tr>`;
        });
        body += `</tbody></table>`;
        tabs.push({ id: 'det-tab-alerts', label: 'Alerts', count: data.fibratus_alert_count || alerts.length, body });
    }

    // Static analysis tab (reuse the richer detail-panel renderer)
    if (data.litterbox_static && !data.litterbox_static.error) {
        let body = `<div class="lb-result-content">${renderLbStaticResults(data.litterbox_static)}</div>`;
        body += _detRawButton('View full static JSON', data.litterbox_static);
        tabs.push({ id: 'det-tab-static', label: 'Static', body });
    }

    // Dynamic analysis tab
    if (data.litterbox_dynamic && !data.litterbox_dynamic.error) {
        let body = `<div class="lb-result-content">${renderLbDynamicResults(data.litterbox_dynamic)}</div>`;
        body += _detRawButton('View full dynamic JSON', data.litterbox_dynamic);
        tabs.push({ id: 'det-tab-dynamic', label: 'Dynamic', body });
    }

    // Process Output tab (agent stdout/stderr + agent server logs)
    const exec = data.agent && data.agent.execution;
    if (exec && (exec.stdout || exec.stderr || exec.agent_logs)) {
        let body = '';
        if (exec.pid) body += `<div class="det-kv"><span class="det-kv-label">PID</span><span class="det-kv-value">${escapeHtml(String(exec.pid))}</span></div>`;
        if (exec.stdout) body += `<div class="det-sub-title">stdout</div><pre class="det-raw det-raw-tall">${escapeHtml(String(exec.stdout))}</pre>`;
        if (exec.stderr) body += `<div class="det-sub-title">stderr</div><pre class="det-raw det-raw-tall">${escapeHtml(String(exec.stderr))}</pre>`;
        if (exec.agent_logs) body += `<div class="det-sub-title">Agent Logs</div><pre class="det-raw det-raw-tall">${escapeHtml(String(exec.agent_logs))}</pre>`;
        if (!exec.stdout && !exec.stderr) body = `<div class="det-sub-value muted">No process stdout/stderr captured (sample may be a GUI app or still running).</div>` + body;
        tabs.push({ id: 'det-tab-procout', label: 'Process Output', body });
    }

    // RedEdr / EDR telemetry tab (from agent or dynamic)
    const rededr = (data.litterbox_dynamic && (data.litterbox_dynamic.rededr || data.litterbox_dynamic.rededr_results)) || (exec && exec.edr);
    if (rededr) {
        const text = typeof rededr === 'string' ? rededr : JSON.stringify(rededr, null, 2);
        const body = `<pre class="det-raw det-raw-tall">${escapeHtml(text)}</pre>` + _detRawButton('View full RedEdr JSON', rededr);
        tabs.push({ id: 'det-tab-rededr', label: 'RedEdr / EDR', body });
    }

    // Memory scanning tab (beacon scanners + live-memory forensics + dumps)
    const hasBeaconResults = data.hunt_sleeping_beacons || data.beaconeye
        || data.aether || data.process_dump || data.exit_capture_result
        || (data.network_beaconing && (data.network_beaconing.evidence_findings || []).length);
    if (hasBeaconResults) {
        let body = '';
        // The aggregated, cross-source verdict comes first: it is what the
        // overall assessment uses, and it is the only place where one tool
        // corroborating another becomes visible.
        if (data.memory_evidence) {
            body += `<div class="det-sub-title" data-info="All memory findings scored together: persistence across samples, corroboration by another tool and the host baseline decide the weight of each. A score of 2.0 or more is SUSPICIOUS, 6.0 or more MALICIOUS.">Memory evidence &mdash; all sources</div>`;
            body += renderMemoryEvidence(data.memory_evidence, data.aether);
        }
        if (data.hunt_sleeping_beacons) {
            const hsb = data.hunt_sleeping_beacons;
            body += `<div class="det-sub-title">Hunt-Sleeping-Beacons</div>`;
            if (hsb.error) {
                body += `<div class="det-sub-value det-warn">${escapeHtml(hsb.error)}</div>`;
            } else {
                const count = hsb.suspicious_count || 0;
                body += `<div class="det-sub-value ${count > 0 ? 'det-warn' : ''}">${count > 0 ? count + ' suspicious indicator(s) found' : 'No sleeping beacons detected'}</div>`;
                if (hsb.limitation) body += `<div class="det-sub-value muted">Limited: ${escapeHtml(hsb.limitation)}</div>`;
                (hsb.findings || []).forEach(f => {
                    const process = f.process || '';
                    const indicators = (f.indicators || []).join('; ');
                    body += `<div class="det-beacon-finding">`;
                    if (process) body += `<span class="det-beacon-proc">${escapeHtml(process)}</span>`;
                    if (indicators) body += `<span class="det-beacon-indicators">${escapeHtml(indicators)}</span>`;
                    body += `</div>`;
                });
                if (hsb.findings && hsb.findings.length) body += _detRawButton('View HSB raw', hsb);
            }
        }
        if (data.beaconeye) {
            const be = data.beaconeye;
            body += `<div class="det-sub-title">BeaconEye</div>`;
            if (be.error) {
                body += `<div class="det-sub-value det-warn">${escapeHtml(be.error)}</div>`;
            } else {
                const count = be.beacons_found || 0;
                body += `<div class="det-sub-value ${count > 0 ? 'det-warn' : ''}">${count > 0 ? count + ' CobaltStrike beacon(s) found' : 'No CobaltStrike beacons detected'}</div>`;
                if (be.limitation) body += `<div class="det-sub-value muted">Limited: ${escapeHtml(be.limitation)}</div>`;
                (be.findings || []).forEach(f => {
                    body += `<div class="det-beacon-finding"><span class="det-beacon-proc">${escapeHtml(f.summary || '')}</span>`;
                    if (f.config && Object.keys(f.config).length > 0) {
                        const cfgStr = Object.entries(f.config).map(([k, v]) => `${k}: ${v}`).join(', ');
                        body += `<span class="det-beacon-indicators">${escapeHtml(cfgStr)}</span>`;
                    }
                    body += `</div>`;
                });
                if (be.findings && be.findings.length) body += _detRawButton('View BeaconEye raw', be);
            }
        }
        if (data.aether) {
            // Per-source evidence is skipped here: the aggregated block above
            // already scored these findings together with the other tools.
            body += renderAetherBlock(data.aether, { showEvidence: !data.memory_evidence });
        }
        if (data.process_dump) {
            body += renderProcessDumpBlock(data.process_dump);
        }
        if (data.exit_capture_result) {
            body += renderExitCaptureBlock(data.exit_capture_result);
        }
        if (data.network_beaconing && data.network_beaconing.available) {
            body += renderNetworkBeaconingBlock(data.network_beaconing);
        }
        tabs.push({ id: 'det-tab-beacons', label: 'Memory', body });
    }

    // Named pipes the sample subtree created or connected to (Sysmon 17/18)
    if (data.named_pipes) {
        const np = data.named_pipes;
        const body = `<div class="det-sub-title" data-info="Pipes that the process tree of the sample created or connected to, from Sysmon EID 17 and 18. C2 catalog names, cross-process use, sensitive system pipes and random names are flagged and scored with the memory evidence.">NAMED PIPES</div>` + renderNamedPipesBlock(np);
        tabs.push({ id: 'det-tab-pipes', label: 'Named Pipes', count: np.available ? (np.pipes || []).length : undefined, body });
    }

    // Raw JSON tab (full response)
    tabs.push({ id: 'det-tab-raw', label: 'Raw JSON', body: `<pre class="det-raw det-raw-tall">${escapeHtml(JSON.stringify(data, null, 2))}</pre>` });

    // Render the tab component
    if (tabs.length > 0) {
        html += `<div class="det-tabs"><div class="det-tab-nav">`;
        tabs.forEach((t, i) => {
            html += `<button class="det-tab-btn ${i === 0 ? 'active' : ''}" onclick="detShowTab(${jsArg(t.id)}, this)">${escapeHtml(t.label)}${t.count !== undefined ? ` <span class="det-tab-count">${t.count}</span>` : ''}</button>`;
        });
        html += `</div>`;
        tabs.forEach((t, i) => {
            html += `<div class="det-tab-content ${i === 0 ? '' : 'hidden'}" id="${t.id}">${t.body}</div>`;
        });
        html += `</div>`;
    }

    // Update the memory stage card once results arrive. The scored evidence
    // is the headline when available, since raw counts overstate findings the
    // host baseline already suppressed.
    if (hasBeaconResults) {
        const bStage = document.getElementById('det-beacon-stage');
        if (bStage) {
            const ev = data.memory_evidence;
            const icon = bStage.querySelector('.det-stage-icon');
            const detail = bStage.querySelector('.det-stage-detail');
            bStage.className = 'det-stage ok';
            if (ev && ev.label && ev.label !== 'CLEAN') {
                icon.innerHTML = '&#x26A0;';
                const parts = [`${ev.label} — memory evidence score ${ev.score}`];
                if (ev.sources && ev.sources.length) parts.push(ev.sources.join(', '));
                if (ev.suppressed_count) parts.push(`${ev.suppressed_count} baseline-suppressed`);
                detail.textContent = parts.join(' · ');
            } else if (ev) {
                icon.innerHTML = '&#x2705;';
                const dumps = data.process_dump?.dump_count || 0;
                detail.textContent = 'No memory evidence scored'
                    + (ev.suppressed_count ? ` (${ev.suppressed_count} suppressed by baseline)` : '')
                    + (dumps ? ` · ${dumps} component(s) dumped` : '');
            } else {
                // No aggregated block yet: fall back to the raw tool counts.
                const raw = (data.hunt_sleeping_beacons?.suspicious_count || 0)
                    + (data.beaconeye?.beacons_found || 0);
                icon.innerHTML = raw > 0 ? '&#x26A0;' : '&#x2705;';
                detail.textContent = raw > 0
                    ? `${raw} beacon indicator(s) found`
                    : 'Scan complete — no beacons detected';
            }
        }
    }

    if (data.exit_capture_result) {
        const ecStage = document.getElementById('det-exitcap-stage');
        if (ecStage) {
            const r = data.exit_capture_result;
            const ev = r.evidence || {};
            const icon = ecStage.querySelector('.det-stage-icon');
            const detail = ecStage.querySelector('.det-stage-detail');
            if (r.error) {
                icon.innerHTML = '&#x26A0;';
                detail.textContent = `Dump captured but analysis failed: ${r.error}`;
            } else if (!r.captured) {
                icon.innerHTML = '&#x2796;';
                detail.textContent = r.note || 'No exit dump';
            } else {
                icon.innerHTML = ev.label && ev.label !== 'CLEAN' ? '&#x26A0;' : '&#x2705;';
                detail.textContent = `Captured at exit · ${ev.label || '?'} (score ${ev.score ?? '?'})`
                    + ` · ${(r.artifacts || []).length} artifact(s) extracted`;
            }
        }
    }

    // Show polling status if nothing yet
    if (!html) {
        html = `<div class="det-panel-loading"><div class="loading-spinner"></div><span>Waiting for results... Analysis may take 1-3 minutes.</span></div>`;
    }

    panels.innerHTML = html;
    drawVerdictFlow('det');
}

// =============================================
// VERDICT FLOW of the detonation results
// =============================================
// What the verdict of a detonation came from, as a Sankey: the processes of
// the findings (left), the kind of each finding (middle), whether the
// verdict counted it (right). Each finding flows once: an EDR alert, the
// LitterBox score of the sample file, or a finding of the memory evidence
// by its source, which is the exit capture, network beaconing, named pipes
// or (Aether, Process Dump, Hunt-Sleeping-Beacons, BeaconEye, PE-Sieve,
// Moneta) live memory. As app.py's _compute_verdict counts them: every EDR
// alert (each severity adds its points); the LitterBox score when it adds
// points (shown only then); a memory finding that keeps a weight once the
// memory evidence reaches SUSPICIOUS, so the counted ones make up the
// evidence score; not one the host baseline suppressed, one capped as a
// repeat of its kind (weight 0), or any of an evidence below SUSPICIOUS
// ("weak memory findings only").
// The Submit tab (scope 'det') and the detail panel ('detail') draw it with
// the same functions, each under ids of its own: both can be open at once.
// The kinds in the order of the middle column, with their colours; the
// LitterBox score first, as the sample file it flows from heads the left
// column: its band crosses none
const VERDICT_FLOW_KINDS = [
    { key: 'litterbox', label: 'LitterBox score', color: 'var(--accent-pink)' },
    { key: 'edr', label: 'EDR alerts', color: 'var(--accent-orange)' },
    { key: 'memory', label: 'live memory', color: 'var(--accent-purple)' },
    { key: 'exit', label: 'exit capture', color: 'var(--accent-blue)' },
    { key: 'network', label: 'network beaconing', color: 'var(--graph-network)' },
    { key: 'pipes', label: 'named pipes', color: 'var(--graph-pipe)' },
];
// The LitterBox score (of 10) from which _compute_verdict adds points to the verdict
const VERDICT_FLOW_LITTERBOX_MIN = 4;
// The sources of the memory evidence that are a kind of their own; any other is live memory
const VERDICT_FLOW_SOURCES = { 'exit-capture': 'exit', 'sysmon-network': 'network', 'sysmon-pipes': 'pipes' };
// LINEAR of each view's flow, until the page is reloaded
const verdictFlowView = { det: { linear: false }, detail: { linear: false } };
// What the flow of each view was drawn from, for which width, and the card head that is watched for its width
const _verdictFlowDrawn = { det: null, detail: null };
let _verdictFlowObserver = null;

// The findings of a detonation's results, each once: [{process, kind,
// counted, count, file}], kind a key of VERDICT_FLOW_KINDS, count 1 but for
// the alerts the server matched beyond those it lists (fibratus_alert_count):
// they are one entry, their process "(not listed)". An alert's process is
// its name as the Alerts tab gives it, a memory finding's its own; the
// LitterBox score, there when it added points, is the sample file's (file).
function detonationFindings(results) {
    const r = results && typeof results === 'object' ? results : {};
    const found = [];
    const lb = r.litterbox_info && typeof r.litterbox_info === 'object' ? r.litterbox_info.score : null;
    if (typeof lb === 'number' && lb >= VERDICT_FLOW_LITTERBOX_MIN) {
        found.push({ process: '(sample file)', kind: 'litterbox', counted: true, count: 1, file: true });
    }
    const alerts = (Array.isArray(r.fibratus_alerts) ? r.fibratus_alerts : []).filter(alert => alert && typeof alert === 'object');
    alerts.forEach(alert => found.push({ process: alertProcessName(alert), kind: 'edr', counted: true, count: 1 }));
    const unlisted = Math.floor(Number(r.fibratus_alert_count)) - alerts.length;
    if (Number.isFinite(unlisted) && unlisted > 0) found.push({ process: '(not listed)', kind: 'edr', counted: true, count: unlisted });
    const ev = r.memory_evidence && typeof r.memory_evidence === 'object' ? r.memory_evidence : null;
    if (!ev) return found;
    const line = Number(ev.thresholds?.suspicious);
    const reached = Number(ev.score) >= (Number.isFinite(line) ? line : 2);
    const add = (list, counts) => (Array.isArray(list) ? list : []).forEach(f => {
        if (!f || typeof f !== 'object') return;
        found.push({ process: String(f.process ?? ''), kind: _verdictFlowKind(f.source), counted: counts(f), count: 1 });
    });
    add(ev.findings, f => reached && Number(f.score) > 0);
    add(ev.suppressed, () => false);
    return found;
}

// The kind of a finding of the memory evidence by its source
function _verdictFlowKind(source) {
    const name = String(source ?? '');
    return Object.prototype.hasOwnProperty.call(VERDICT_FLOW_SOURCES, name) ? VERDICT_FLOW_SOURCES[name] : 'memory';
}

// The findings as a flow process → kind → counted or not, for layoutSankey
// and sankeySvg: {columns, links, labels}. A process in any case and without
// the blanks around it, in its first spelling, none as "(unknown)"; the six
// with the most findings stand on their own, the rest is "other processes",
// last; the sample file of the LitterBox score first, on its own whatever
// the processes. The kinds in the order of VERDICT_FLOW_KINDS, "counted
// (<verdict>)" above "not counted"; a column lists only what has findings.
// Ids "sample file", "process:<name>", "kind:<key>", "verdict:counted",
// "verdict:not counted".
function detonationFlow(results) {
    const found = detonationFindings(results);
    const nameOf = f => f.process.trim() || '(unknown)';
    const spelling = new Map(), totals = new Map();
    for (const f of found) {
        if (f.file) continue;
        const key = _alertsNameKey(nameOf(f));
        if (!spelling.has(key)) spelling.set(key, nameOf(f));
        totals.set(key, (totals.get(key) || 0) + f.count);
    }
    const ranked = [...totals].map(([key, count]) => ({ key, count }))
        .sort((a, b) => (b.count - a.count) || (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
    const top = topWithOther(ranked, 6, 'other processes');
    const processId = f => {
        if (f.file) return 'sample file';
        const key = _alertsNameKey(nameOf(f));
        return top.keep.has(key) ? `process:${spelling.get(key)}` : 'other processes';
    };
    const pairs = new Map();                        // source id -> Map(target id -> findings)
    const flow = (source, target, n) => {
        if (!pairs.has(source)) pairs.set(source, new Map());
        pairs.get(source).set(target, (pairs.get(source).get(target) || 0) + n);
    };
    for (const f of found) {
        flow(processId(f), `kind:${f.kind}`, f.count);
        flow(`kind:${f.kind}`, f.counted ? 'verdict:counted' : 'verdict:not counted', f.count);
    }
    const label = String(results?.verdict?.label ?? '').trim();
    const labels = Object.create(null);             // names from the data: none may be special (__proto__)
    const processes = ranked.filter(({ key }) => top.keep.has(key)).map(({ key }) => `process:${spelling.get(key)}`);
    processes.forEach(id => { labels[id] = id.slice('process:'.length); });
    if (ranked.some(({ key }) => !top.keep.has(key))) {
        processes.push('other processes');
        labels['other processes'] = 'other processes';
    }
    if (pairs.has('sample file')) {
        processes.unshift('sample file');
        labels['sample file'] = '(sample file)';
    }
    const kinds = VERDICT_FLOW_KINDS.filter(kind => pairs.has(`kind:${kind.key}`)).map(kind => {
        labels[`kind:${kind.key}`] = kind.label;
        return `kind:${kind.key}`;
    });
    const used = new Set(kinds.flatMap(id => [...pairs.get(id).keys()]));
    labels['verdict:counted'] = label ? `counted (${label})` : 'counted';
    labels['verdict:not counted'] = 'not counted';
    const verdicts = ['verdict:counted', 'verdict:not counted'].filter(id => used.has(id));
    const links = [];
    pairs.forEach((targets, source) => targets.forEach((value, target) => links.push({ source, target, value })));
    return { columns: [processes, kinds, verdicts], links, labels };
}

// The colours of the nodes of a flow: a process from the palette by its
// place among the processes (without its muted last colour), "other
// processes" and "(not listed)" muted, the sample file grey (no process
// loses its colour to it); a kind its own; "counted" the colour of the
// verdict (as in VERDICT HISTORY), "not counted" muted
function _verdictFlowColors(flow, label) {
    const colors = Object.create(null);
    const [processes = [], kinds = [], verdicts = []] = flow.columns;
    let place = 0;
    processes.forEach(id => {
        colors[id] = id === 'sample file' ? 'var(--text-secondary)'
            : id === 'other processes' || id === 'process:(not listed)' ? 'var(--text-muted)'
            : CHART_PALETTE[place++ % (CHART_PALETTE.length - 1)];
    });
    kinds.forEach(id => { colors[id] = VERDICT_FLOW_KINDS.find(kind => `kind:${kind.key}` === id)?.color; });
    verdicts.forEach(id => { colors[id] = id === 'verdict:counted' ? submissionVerdictGroup(label).color : 'var(--text-muted)'; });
    return colors;
}

// The card VERDICT FLOW of a detonation's results for one of the two views
// (scope 'det': the Submit tab, 'detail': the detail panel; '' for another):
// its head with the (i), LINEAR and CHART / TABLE, the room for the Sankey and
// the table view of its bands. Both views render it with this function and,
// once it is in the page, draw its Sankey with drawVerdictFlow(scope).
function verdictFlowHtml(results, scope) {
    if (!Object.prototype.hasOwnProperty.call(verdictFlowView, scope)) return '';
    const flow = detonationFlow(results);
    flow.colors = _verdictFlowColors(flow, results?.verdict?.label);
    // The head watched so far stays known: the next draw lets go of it
    _verdictFlowDrawn[scope] = { flow, width: 0, head: _verdictFlowDrawn[scope]?.head || null };
    const id = `${scope}-verdict-flow`, linear = verdictFlowView[scope].linear;
    const table = scope === 'detail' ? '<table class="view-table" data-sortable data-sort-id="detail-verdict-flow">'
        : '<table class="view-table" data-sortable data-sort-id="det-verdict-flow">';
    return `<div class="chart-card verdict-flow-card" id="${id}-card"><div class="chart-card-head">`
        + `<h3 class="chart-card-title" data-info="Findings flow process → kind → counted or not: every EDR alert (past 50: (not listed)), the (sample file)'s LitterBox score from 4/10, a weighted memory finding once evidence is SUSPICIOUS, none the baseline suppressed or capped. Named pipes counts pipe findings, not pipes; LINEAR: true proportions.">VERDICT FLOW</h3><span class="chart-card-tools">`
        + `<button type="button" class="view-toggle chart-scale-toggle" id="${id}-linear" aria-pressed="${linear}" `
        + `title="${linear ? 'Draw the flows by their square roots, so small flows stay visible' : 'Draw the flows in true proportions'}" `
        + `onclick="toggleVerdictFlowScale(${jsArg(scope)})"${cardViewAttrs(id, 'chart')}>LINEAR</button>${viewToggleHtml(id)}</span></div>`
        + `<div class="verdict-flow-view" id="${id}-chart"${cardViewAttrs(id, 'chart')}></div>`
        + `<div class="view-table-wrap verdict-flow-table" id="${id}-table"${cardViewAttrs(id, 'table')}>`
        + `${_flowTableHtml(flow, 'No findings', table, ['Source', 'Target'])}</div></div>`;
}

// Draws the Sankey of the VERDICT FLOW of `scope` that verdictFlowHtml
// rendered, for the width of its card, and watches that width (the card of
// an earlier render no more); forgets the flow when the view rendered none
function drawVerdictFlow(scope) {
    if (!Object.prototype.hasOwnProperty.call(_verdictFlowDrawn, scope)) return;
    const drawn = _verdictFlowDrawn[scope];
    if (!drawn) return;
    const head = document.querySelector(`#${scope}-verdict-flow-card .chart-card-head`);
    if (drawn.head && drawn.head !== head) _verdictFlowObserver?.unobserve(drawn.head);
    if (!head) {
        _verdictFlowDrawn[scope] = null;
        return;
    }
    if (!_verdictFlowObserver && typeof ResizeObserver !== 'undefined') {
        _verdictFlowObserver = new ResizeObserver(() => requestAnimationFrame(redrawVerdictFlowsOnResize));
    }
    if (drawn.head !== head) _verdictFlowObserver?.observe(head);
    drawn.head = head;
    drawn.width = _verdictFlowWidth(head);
    _drawVerdictFlowSvg(scope);
}

// The Sankey for the width it was measured at (a guess while the card is
// hidden: the observer draws it again when it shows), as high as its fullest
// column needs, the right column with the room for its names, by square
// roots or in true proportions (LINEAR); "No findings" without any
function _drawVerdictFlowSvg(scope) {
    const drawn = _verdictFlowDrawn[scope], view = document.getElementById(`${scope}-verdict-flow-chart`);
    if (!drawn || !view) return;
    const { flow } = drawn;
    const width = drawn.width || 640;
    const nodes = Math.max(0, ...flow.columns.map(column => column.length));
    const into = new Map();
    flow.links.forEach(link => into.set(link.target, (into.get(link.target) || 0) + link.value));
    const last = flow.columns[flow.columns.length - 1] || [];
    const longest = Math.max(0, ...last.map(id => String(flow.labels[id] ?? id).length + _chartNumber(into.get(id)).length + 1));
    const layout = layoutSankey(flow.columns, flow.links, { width, height: Math.min(300, Math.max(110, 28 * nodes + 24)),
        scale: verdictFlowView[scope].linear ? 'linear' : 'sqrt', labelWidth: Math.max(width / 4, Math.min(width / 2, 6 * longest + 24)) });
    view.innerHTML = sankeySvg(layout, { labels: flow.labels, colors: flow.colors }) || chartEmptyHtml('No findings');
}

// The width a card's Sankey is drawn for: that of its head (0 while hidden)
function _verdictFlowWidth(head) {
    return Math.floor(head?.getBoundingClientRect().width || 0);
}

// LINEAR of one view: its flow in true proportions, or by square roots again
function toggleVerdictFlowScale(scope) {
    if (!Object.prototype.hasOwnProperty.call(verdictFlowView, scope)) return;
    const view = verdictFlowView[scope];
    view.linear = !view.linear;
    _pressFlowScale(document.getElementById(`${scope}-verdict-flow-linear`), view.linear);
    _drawVerdictFlowSvg(scope);
}

// Each flow on screen for the new width of its card; not while it is hidden
// (0), for the width it was drawn for, or once its view showed something else
function redrawVerdictFlowsOnResize() {
    for (const scope of Object.keys(_verdictFlowDrawn)) {
        const drawn = _verdictFlowDrawn[scope];
        if (!drawn || !drawn.head || !drawn.head.isConnected) continue;
        const width = _verdictFlowWidth(drawn.head);
        if (!width || width === drawn.width) continue;
        drawn.width = width;
        _drawVerdictFlowSvg(scope);
    }
}

// --- Submissions History ---
async function refreshSubmissions() {
    const container = document.getElementById('submissions-list');
    if (!container) return;

    try {
        const resp = await fetch('/api/submissions');
        if (!resp.ok) {
            container.innerHTML = '<div style="padding:12px;color:var(--text-muted);font-size:11px;">Failed to load submissions.</div>';
            renderSubmissionVerdicts(null, 'Submissions not available');
            return;
        }
        const submissions = await resp.json();

        if (!submissions.length) {
            container.innerHTML = '<div style="padding:12px;color:var(--text-muted);font-size:11px;">No samples submitted yet. Use the form above to detonate a sample.</div>';
            renderSubmissionVerdicts(submissions);
            return;
        }

        let html = '<table class="submissions-table" data-sortable data-sort-id="submissions"><thead><tr>';
        html += '<th>Time</th><th>Filename</th><th>SHA-256</th><th>Size</th><th>Target</th><th>Status</th><th data-no-sort>Actions</th>';
        html += '</tr></thead><tbody>';

        submissions.forEach(sub => {
            const ts = _submissionTime(sub).text;
            const agentBadge = sub.agent_status === 'success'
                ? '<span class="badge badge-green">Agent OK</span>'
                : sub.agent_status === 'failed'
                ? '<span class="badge badge-red">Agent Fail</span>'
                : '';
            const lbBadge = sub.litterbox_status === 'success'
                ? '<span class="badge badge-green">LB OK</span>'
                : sub.litterbox_status === 'failed'
                ? '<span class="badge badge-red">LB Fail</span>'
                : '';
            const pid = sub.agent_pid ? `<span class="badge badge-dim">PID ${sub.agent_pid}</span>` : '';
            const shortHash = sub.sha256 ? sub.sha256.substring(0, 12) + '...' : '--';
            let actions = sub.file_path
                ? `<button class="btn btn-xs" onclick="hexOpenFile(${jsArg(sub.file_path)})" title="Open in Hex Editor">Hex</button>`
                : '';
            // Results: LitterBox's and the EDRs' results if the submission went to LitterBox, else the EDRs'
            const args = submissionResultArgs(sub);
            if (args && args[0]) {
                actions += ` <button class="btn btn-xs btn-lb-results" onclick="viewDetonationResult(${args.map(jsArg).join(', ')})" title="View analysis results (LitterBox + Fibratus)">Results</button>`;
            } else if (args) {
                actions += ` <button class="btn btn-xs btn-lb-results" onclick="viewDetonationResult(${args.map(jsArg).join(', ')})" title="View Fibratus/Rustinel alerts">Results</button>`;
            }

            html += `<tr>`;
            html += `<td class="td-time" data-sort-value="${sortTimeValue(sub.timestamp)}">${ts}</td>`;
            html += `<td class="td-filename" title="${escapeHtml(sub.filename || '')}">${escapeHtml(sub.filename || '--')}</td>`;
            html += `<td class="td-hash mono" title="${escapeHtml(sub.sha256 || '')}">${shortHash}</td>`;
            html += `<td class="td-size" data-sort-value="${sortNumberValue(sub.size)}">${sub.size ? formatSize(sub.size) : '--'}</td>`;
            html += `<td class="td-target">${escapeHtml(sub.target || '--')}</td>`;
            html += `<td class="td-status">${agentBadge} ${lbBadge} ${pid}</td>`;
            html += `<td class="td-actions">${actions}</td>`;
            html += `</tr>`;
        });

        html += '</tbody></table>';
        container.innerHTML = html;
        renderSubmissionVerdicts(submissions);
    } catch (e) {
        container.innerHTML = `<div style="padding:12px;color:var(--accent-red);font-size:11px;">Error: ${escapeHtml(e.message)}</div>`;
        renderSubmissionVerdicts(null, 'Submissions not available');
    }
}

// A submission's time in epoch ms (NaN without one) and as the list shows it ("05 Nov, 11:37:11")
function _submissionTime(sub) {
    const date = new Date(sub?.timestamp || NaN), t = date.getTime();
    return { t, text: Number.isNaN(t) ? '--' : date.toLocaleString('en-GB', { hour12: false, day: '2-digit', month: 'short',
                                                                             hour: '2-digit', minute: '2-digit', second: '2-digit' }) };
}

// What viewDetonationResult takes to open a submission's results (its
// Results button and its bar in VERDICT HISTORY), as text: LitterBox's hash
// (else the sample's) when it went to LitterBox, '' when not; null without a
// hash and a PID, which have no results
function submissionResultArgs(sub) {
    if (!sub || typeof sub !== 'object') return null;
    const text = value => (value === null || value === undefined ? '' : String(value));
    const lbHash = sub.litterbox_hash || sub.sha256;
    if (lbHash && (sub.target === 'litterbox' || sub.target === 'both' || sub.litterbox_status === 'success')) {
        return [lbHash, sub.sha256, sub.agent_pid, sub.filename].map(text);
    }
    return sub.sha256 || sub.agent_pid ? ['', sub.sha256, sub.agent_pid, sub.filename].map(text) : null;
}

// --- VERDICT HISTORY of the Submit tab ---
// Above the list of the submissions: a bar per submission, the oldest on the
// left, by its place in the list (samples are sent in bursts, which a time
// axis would pile up), as high as the score of the verdict the server keeps
// on it and in that verdict's colour. The score is the verdict's own (points
// for EDR alerts, LitterBox and the memory evidence), which turns SUSPICIOUS
// at 1 and MALICIOUS at 3 (app.py's _compute_verdict), where the dashed
// lines are. A submission with no verdict kept (sent before verdicts were
// kept, or its results never opened) is a grey stub, "not evaluated". A
// click on a bar opens its results, as its Results button does; the table
// view lists every submission.
const SUBMISSION_VERDICT_THRESHOLDS = [{ y: 1, label: 'SUSPICIOUS' }, { y: 3, label: 'MALICIOUS' }];
// The verdicts by colour, in the order of the legend: any other label is "other verdict", none "not evaluated"
const SUBMISSION_VERDICT_GROUPS = [
    { key: 'clean', label: 'clean', labels: ['CLEAN'], color: 'var(--severity-low)' },
    { key: 'suspicious', label: 'suspicious', labels: ['SUSPICIOUS'], color: 'var(--severity-medium)' },
    { key: 'malicious', label: 'malicious', labels: ['MALICIOUS'], color: 'var(--severity-critical)' },
    { key: 'other', label: 'other verdict', labels: [], color: 'var(--text-muted)' },
    { key: 'none', label: 'not evaluated', labels: [], color: 'var(--text-dim)' },
];
// The scale reaches a tenth above the highest score or the MALICIOUS line, at most this far
const SUBMISSION_VERDICT_MAX = 10;
// What the chart on screen was drawn from (the submissions as listed), and for which width
let _submissionVerdictsDrawn = null;
// The verdict the history was last loaded for, of each run (sample and PID)
const _verdictHistoryAsked = new Map();

// Draws VERDICT HISTORY of the submissions (the newest first, as the server
// lists them): the chart, its legend, its table view; refreshSubmissions
// calls it whenever it renders the list. Without submissions it says so, or `hint`.
function renderSubmissionVerdicts(submissions, hint) {
    if (!document.getElementById('submission-verdicts-plot')) return;
    // Written once: a render keeps the switch (and the keyboard focus on it)
    const slot = document.getElementById('submission-verdicts-toggle');
    if (slot && !slot.firstElementChild) slot.innerHTML = viewToggleHtml('submission-verdicts');
    const subs = Array.isArray(submissions) ? submissions : [];
    const items = submissionVerdictItems(subs), empty = hint || 'No submissions yet';
    const legend = document.getElementById('submission-verdicts-legend'), table = document.getElementById('submission-verdicts-table');
    // The legend first: it takes its room beside the plot, so the plot is measured at the width the bars get
    if (legend) legend.innerHTML = items.length ? chartLegendHtml(_submissionVerdictLegend(items)) : '';
    _submissionVerdictsDrawn = { subs, items, empty, width: _submissionVerdictsWidth() };
    _drawSubmissionVerdicts(_submissionVerdictsDrawn);
    if (table) table.innerHTML = _submissionVerdictsTableHtml(items, empty);
}

// The submissions in the order of the chart, the oldest first: each with its
// place in the list (`index`: the key of its bar), the label and score of
// its kept verdict (null for none) and the group of its colour
function submissionVerdictItems(submissions) {
    const list = Array.isArray(submissions) ? submissions : [];
    const items = [];
    for (let index = list.length - 1; index >= 0; index--) {
        const sub = list[index];
        if (!sub || typeof sub !== 'object') continue;
        const { label, score } = _submissionVerdict(sub);
        items.push({ index, sub, label, score, group: submissionVerdictGroup(label) });
    }
    return items;
}

// The verdict kept on a submission as {label, score}: a label of a verdict
// written as text has no score; without a label it is none (null, null)
function _submissionVerdict(sub) {
    const verdict = typeof sub?.verdict === 'string' ? { label: sub.verdict } : sub?.verdict;
    const label = verdict && typeof verdict === 'object' ? String(verdict.label ?? '').trim() : '';
    return { label: label || null, score: label ? _scanScore(verdict) : null };
}

// The group of SUBMISSION_VERDICT_GROUPS a verdict's label belongs to, in any case
function submissionVerdictGroup(label) {
    const name = String(label ?? '').trim().toUpperCase();
    const group = key => SUBMISSION_VERDICT_GROUPS.find(g => g.key === key);
    if (!name) return group('none');
    return SUBMISSION_VERDICT_GROUPS.find(g => g.labels.includes(name)) || group('other');
}

// The bars for the width of the plot (a guess while it is hidden: the
// ResizeObserver draws them again when it shows), or the hint without submissions
function _drawSubmissionVerdicts(drawn) {
    const plot = document.getElementById('submission-verdicts-plot'), area = document.getElementById('submission-verdicts-area');
    const { items } = drawn;
    const highest = Math.max(...SUBMISSION_VERDICT_THRESHOLDS.map(th => th.y), ...items.map(item => item.score ?? 0));
    const bars = items.map(item => ({ key: String(item.index), y: item.score, color: item.group.color,
                                      title: _submissionVerdictTitle(item) }));
    const svg = verdictBarsSvg(bars, { width: drawn.width || 640, height: 160, thresholds: SUBMISSION_VERDICT_THRESHOLDS,
                                       yMax: Math.min(SUBMISSION_VERDICT_MAX, highest * 1.1) });
    if (area) area.classList.toggle('is-empty', !svg);
    if (plot) plot.innerHTML = svg || chartEmptyHtml(drawn.empty);
}

// A bar's tooltip: file, verdict and its score (or "no score"), time
function _submissionVerdictTitle(item) {
    const { sub, label, score } = item;
    const parts = [sub.filename || '--', label || 'not evaluated'];
    if (label) parts.push(score !== null ? `score ${_chartNumber(score)}` : 'no score');
    parts.push(_submissionTime(sub).text);
    return parts.join(' \u00b7 ');
}

// The legend: the submissions per group of verdicts, the groups with submissions only
function _submissionVerdictLegend(items) {
    return SUBMISSION_VERDICT_GROUPS.map(group => ({ key: group.key, label: group.label, color: group.color,
        value: items.filter(item => item.group === group).length })).filter(item => item.value > 0);
}

// The table view: every submission in the order of the chart with its time,
// file, verdict and score ("—" without, sorted last); `empty` the only row without any
function _submissionVerdictsTableHtml(items, empty) {
    const rows = items.map(({ sub, label, score, group }) => {
        const time = _submissionTime(sub), file = sub.filename || '--';
        return `<tr><td data-sort-value="${Number.isNaN(time.t) ? '' : time.t}">${escapeHtml(time.text)}</td>`
            + `<td class="view-table-text" title="${escapeHtml(file)}">${escapeHtml(file)}</td>`
            + `<td><span class="view-table-dot" style="background:${group.color}"></span>${escapeHtml(label || 'not evaluated')}</td>`
            + `<td class="view-table-num" data-sort-value="${score === null ? '' : score}">${score === null ? '&mdash;' : _chartNumber(score)}</td></tr>`;
    });
    if (!rows.length) rows.push(`<tr data-sort-skip><td colspan="4" class="view-table-empty">${escapeHtml(_chartSentence(empty))}</td></tr>`);
    return '<table class="view-table" data-sortable data-sort-id="submission-verdicts"><thead><tr><th>Time</th><th>File</th>'
        + `<th>Verdict</th><th class="view-table-num">Score</th></tr></thead><tbody>${rows.join('')}</tbody></table>`;
}

// The width VERDICT HISTORY is drawn for: that of its plot (0 while hidden)
function _submissionVerdictsWidth() {
    return Math.floor(document.getElementById('submission-verdicts-plot')?.getBoundingClientRect().width || 0);
}

// The bars for the new width of their plot; not while it is hidden (0) or
// for the width they were drawn for. The legend and the table stay.
function redrawSubmissionVerdictsOnResize() {
    const drawn = _submissionVerdictsDrawn;
    const width = _submissionVerdictsWidth();
    if (!drawn || !width || width === drawn.width) return;
    drawn.width = width;
    _drawSubmissionVerdicts(drawn);
}

// VERDICT HISTORY is drawn again, in the next frame, when its plot changes
// its width (the window, the theme, the tab or the chart view shown again)
function initSubmissionVerdicts() {
    const plot = document.getElementById('submission-verdicts-plot');
    if (plot && typeof ResizeObserver !== 'undefined') {
        new ResizeObserver(() => requestAnimationFrame(redrawSubmissionVerdictsOnResize)).observe(plot);
    }
}

// A click on a bar of VERDICT HISTORY opens its submission's results
function onSubmissionVerdictsClick(event) {
    const key = event?.target?.closest?.('.chart-slot')?.getAttribute('data-key');
    const sub = _submissionVerdictsDrawn && /^\d+$/.test(key || '') ? _submissionVerdictsDrawn.subs[Number(key)] : null;
    const args = submissionResultArgs(sub);
    if (args) viewDetonationResult(...args);
}

// A view of a detonation's results computed its verdict, which the server
// keeps on the submission of its run (app.py's _store_submission_verdict:
// the sample run as this PID, without a PID one that ran without; none for
// a PID none of its submissions ran as). While the Submit tab is open, its
// list and VERDICT HISTORY load again when they show another verdict there,
// once for each verdict: a server that could not keep it (a file it cannot
// write) lists the old one after every poll. The tab loads them anyway when
// it opens.
function noteDetonationVerdict(sha256, pid, verdict) {
    const drawn = _submissionVerdictsDrawn;
    const sha = String(sha256 || '').trim().toLowerCase(), run = String(pid || '').trim();
    if (state.activeTab !== 'submit' || !drawn || !sha || !verdict || typeof verdict !== 'object' || !verdict.label) return;
    const sub = drawn.subs.find(s => s && typeof s === 'object' && String(s.sha256 || '').toLowerCase() === sha
                                     && String(s.agent_pid || '') === run);
    if (!sub) return;
    const kept = _submissionVerdict(sub), label = String(verdict.label).trim(), score = _scanScore(verdict);
    if (kept.label === label && kept.score === score) return;
    const key = JSON.stringify([sha, run]), asked = JSON.stringify([label, score]);
    if (_verdictHistoryAsked.get(key) === asked) return;
    _verdictHistoryAsked.set(key, asked);
    refreshSubmissions();
}

// =============================================
// PROCESS ROLLUP GRAPH
// =============================================

const graphState = {
    nodes: [],
    edges: [],
    camera: { x: 0, y: 0, zoom: 1 },
    dragging: null,
    panning: false,
    panStart: { x: 0, y: 0 },
    hoveredNode: null,
    selectedNode: null,
    animFrame: null,
    initialized: false,
    focusPid: null,       // root PID of the current drilldown (null = landing picker)
    focusStack: [],       // breadcrumb lineage of previously-focused PIDs
    downDepth: 0,         // descendant depth (0 = all, capped server-side)
    data: null,           // last /api/process-graph payload
    emptyMessage: '',     // message shown on the canvas when there are no nodes
    isLoading: false,     // true while /api/process-graph is being fetched
    layoutMode: 'tree',   // 'tree' | 'force' | 'iso'
    isoCollapsed: new Set(),  // PIDs whose subtree is folded in the isometric view
    pipesDefaultFor: null,    // focus root the Pipes toggle default was last applied to
};

// Programmatically focus the process graph on a PID (used by alert/process pivots).
function focusProcessGraph(pid, opts = {}) {
    // `at`: a timestamp (alert/event time); with a plain PID the server picks
    // the process that had that PID then, not its newest holder.
    const { push = true, reset = false, at = '' } = opts;
    pid = String(pid);
    graphState.focusAt = at || '';
    if (reset) graphState.focusStack = [];
    else if (push && graphState.focusPid && graphState.focusPid !== pid) {
        graphState.focusStack.push(graphState.focusPid);
    }
    graphState.focusPid = pid;
    graphState.selectedNode = null;
    graphState.isoCollapsed = new Set();
    hideGraphDetail();
    const input = document.getElementById('graph-search');
    if (input) input.value = pid;
    if (state.activeTab !== 'graph') {
        switchTab('graph'); // switchTab() lazily calls graphRefresh() for the graph tab
    } else {
        graphRefresh();
    }
}

async function graphRefresh() {
    if (!graphState.initialized) {
        initGraphCanvas();
        graphState.initialized = true;
    }

    // No focus yet -> show the landing picker with candidate root processes.
    if (!graphState.focusPid) {
        graphState.nodes = [];
        graphState.edges = [];
        renderGraph();
        renderBreadcrumb();
        await renderGraphLanding();
        return;
    }
    hideGraphLanding();

    // Show the spinner while fetching; the empty "no data" message is only
    // rendered once the request has resolved with nothing to show.
    const depth = graphState.downDepth || 0;
    let payload = null;
    graphState.isLoading = true;
    graphState.emptyMessage = '';
    showGraphLoading();
    renderBreadcrumb();
    try {
        const atParam = graphState.focusAt ? `&at=${encodeURIComponent(graphState.focusAt)}` : '';
        const resp = await fetch(`/api/process-graph?pid=${encodeURIComponent(graphState.focusPid)}&down_depth=${depth}&max_nodes=400${atParam}`);
        payload = await resp.json();
        // Pin the instance the server resolved, so refreshes keep showing it.
        if (resp.ok && payload.root_pid) {
            graphState.focusPid = String(payload.root_pid);
            graphState.focusAt = '';
        }
        if (!resp.ok || payload.error) {
            graphState.data = null;
            graphState.nodes = [];
            graphState.edges = [];
            graphState.emptyMessage = payload.error || `Process ${graphState.focusPid} not found.`;
            renderGraph();
            renderBreadcrumb();
            const countEl = document.getElementById('graph-node-count');
            if (countEl) countEl.textContent = graphState.emptyMessage;
            return;
        }
    } catch (e) {
        graphState.nodes = [];
        graphState.edges = [];
        graphState.emptyMessage = 'Failed to load process graph: ' + e.message;
        renderGraph();
        return;
    } finally {
        graphState.isLoading = false;
        hideGraphLoading();
    }

    graphState.data = payload;
    // Pipes are on by default when the focus is a detonated sample; a manual
    // change sticks until the focus moves to another process.
    const pipesToggle = document.getElementById('graph-show-pipes');
    if (pipesToggle && graphState.pipesDefaultFor !== graphState.focusPid) {
        graphState.pipesDefaultFor = graphState.focusPid;
        pipesToggle.checked = !!(payload.processes?.[payload.root_pid]?.detonated);
    }
    buildGraph(payload);
    graphFitView();
    renderGraph();
    renderBreadcrumb();
}

function showGraphLoading() {
    const el = document.getElementById('graph-loading');
    if (el) el.hidden = false;
}

function hideGraphLoading() {
    const el = document.getElementById('graph-loading');
    if (el) el.hidden = true;
}

async function renderGraphLanding() {
    const landing = document.getElementById('graph-landing');
    if (!landing) return;
    landing.classList.add('visible');
    landing.innerHTML = '<div class="graph-landing-loading">Loading candidate processes...</div>';

    let roots = [];
    let samples = [];
    try {
        const [rootsResp, sampResp] = await Promise.all([
            fetch('/api/process-graph/roots'),
            fetch('/api/graph/samples'),
        ]);
        if (rootsResp.ok) roots = await rootsResp.json();
        if (sampResp.ok) { const d = await sampResp.json(); samples = d.samples || []; }
    } catch (e) { /* ignore */ }
    if (!Array.isArray(roots)) roots = [];
    if (!Array.isArray(samples)) samples = [];

    // Optional name/pid filter typed into the focus field.
    const q = (document.getElementById('graph-search')?.value || '').trim().toLowerCase();
    let filtered = roots;
    if (q) {
        filtered = roots.filter(r =>
            String(r.pid).includes(q) ||
            (r.name || '').toLowerCase().includes(q) ||
            (r.image || '').toLowerCase().includes(q));
    }
    let filteredSamples = samples;
    if (q) {
        filteredSamples = samples.filter(s =>
            (s.filename || '').toLowerCase().includes(q) ||
            (s.sha256 || '').toLowerCase().includes(q) ||
            String(s.pid || '').includes(q));
    }
    graphState._landingSamples = filteredSamples;

    let html = '<div class="graph-landing-inner">';

    // Samples rail: submitted/scanned files (executed ones pivot to their tree,
    // static-only ones expand their scan verdicts inline).
    if (filteredSamples.length) {
        html += '<div class="graph-landing-title">Samples</div>';
        html += '<div class="graph-landing-hint">Files submitted or scanned. Executed samples open their process tree; static-only samples expand their scan verdicts.</div>';
        html += '<div class="graph-sample-list">';
        filteredSamples.forEach((s, i) => {
            const vm = _VERDICT_META[s.verdict] || _VERDICT_META.unknown;
            const badges = [];
            if (s.executed) badges.push('<span class="glc-badge exec">executed</span>');
            else badges.push('<span class="glc-badge static">static-only</span>');
            if (s.detonated) badges.push('<span class="glc-badge det">detonated</span>');
            if (s.target) badges.push(`<span class="glc-badge">${escapeHtml(String(s.target))}</span>`);
            let tools = '';
            (s.scans || []).forEach(sc => {
                const st = _histStatus(sc);
                tools += `<span class="gsc-tool ${st.cls}">${escapeHtml(sc.tool || '?')} · ${escapeHtml(st.text)}</span>`;
            });
            html += `<div class="graph-sample-card v-${escapeHtml(s.verdict)}" data-idx="${i}" data-pid="${s.executed ? escapeHtml(String(s.pid)) : ''}">
                <div class="gsc-head">
                    <span class="gsc-name" title="${escapeHtml(s.filename || '')}">${escapeHtml(s.filename || '--')}</span>
                    <span class="gsc-verdict ${vm.cls}">${escapeHtml(vm.text)}</span>
                </div>
                ${s.sha256 ? `<div class="gsc-sha" title="${escapeHtml(s.sha256)}">${escapeHtml(s.sha256)}</div>` : ''}
                <div class="gsc-badges">${badges.join('')}${s.size != null ? `<span class="glc-badge">${escapeHtml(formatSize(s.size))}</span>` : ''}</div>
                ${tools ? `<div class="gsc-tools">${tools}</div>` : ''}
                <div class="gsc-detail" style="display:none"></div>
                <div class="gsc-foot">${s.executed ? '&#9673; Open process tree (PID ' + escapeHtml(String(s.os_pid ?? s.pid)) + ')' : '&#9656; Show scan details'}</div>
            </div>`;
        });
        html += '</div>';
    }

    html += '<div class="graph-landing-title">Investigate a process</div>';
    html += '<div class="graph-landing-hint">Pick a process below, or type a PID / name in the focus field above.</div>';
    if (!filtered.length) {
        html += `<div class="graph-landing-empty">${roots.length ? 'No processes match your filter.' : 'No detonated or alerting processes yet. Submit a sample to populate the graph.'}</div>`;
    } else {
        html += '<div class="graph-landing-list">';
        filtered.forEach(r => {
            const sevClass = r.severity && r.severity !== 'unknown' ? `sev-${cssToken(r.severity)}` : '';
            const badges = [];
            if (r.detonated) badges.push('<span class="glc-badge det">detonated</span>');
            if (r.threats > 0) badges.push(`<span class="glc-badge threat">${r.threats} threats</span>`);
            if (r.children_count > 0) badges.push(`<span class="glc-badge">${r.children_count} children</span>`);
            html += `<div class="graph-landing-card ${sevClass}" data-pid="${escapeHtml(String(r.pid))}" data-at="${escapeHtml(r.first_seen || '')}">
                <div class="glc-head"><span class="glc-name">${escapeHtml(r.name || 'unknown')}</span><span class="glc-pid">PID ${escapeHtml(String(r.os_pid ?? r.pid))}</span></div>
                ${r.image ? `<div class="glc-image">${escapeHtml(r.image)}</div>` : ''}
                <div class="glc-badges">${badges.join('')}</div>
            </div>`;
        });
        html += '</div>';
    }
    html += '</div>';
    landing.innerHTML = html;

    landing.querySelectorAll('.graph-landing-card[data-pid]').forEach(card => {
        // Roots come from the alert tree; its keys can differ from the graph's,
        // so the first-seen time picks the right process instance.
        card.addEventListener('click', () => focusProcessGraph(card.dataset.pid, { reset: true, at: card.dataset.at }));
    });

    // Sample cards: executed samples pivot to their process tree; static-only
    // samples toggle an inline scan-detail panel.
    landing.querySelectorAll('.graph-sample-card').forEach(card => {
        card.addEventListener('click', (e) => {
            // Clicks inside an expanded detail drive its own row toggles.
            if (e.target.closest('.gsc-detail')) return;
            const pid = card.dataset.pid;
            if (pid) { focusProcessGraph(pid, { reset: true }); return; }
            const idx = parseInt(card.dataset.idx);
            const s = (graphState._landingSamples || [])[idx];
            const det = card.querySelector('.gsc-detail');
            const foot = card.querySelector('.gsc-foot');
            if (!det) return;
            if (!det.dataset.filled) {
                det.innerHTML = (s && s.scans && s.scans.length)
                    ? renderGraphScans(s.scans, 'Scan Results')
                    : '<div class="scan-history-empty">No scan details recorded.</div>';
                det.dataset.filled = '1';
            }
            const open = det.style.display !== 'none';
            det.style.display = open ? 'none' : 'block';
            if (foot) foot.innerHTML = (open ? '&#9656;' : '&#9662;') + ' Show scan details';
        });
    });
}

function hideGraphLanding() {
    const landing = document.getElementById('graph-landing');
    if (landing) { landing.classList.remove('visible'); landing.innerHTML = ''; }
}

// Handle the focus field: a numeric value focuses that PID directly; free text
// falls back to the landing picker filtered by that query.
function graphSubmitFocus() {
    const input = document.getElementById('graph-search');
    const val = (input?.value || '').trim();
    if (!val) { graphState.focusPid = null; graphRefresh(); return; }
    if (/^\d+$/.test(val)) {
        focusProcessGraph(val, { reset: true });
    } else {
        // Name search: drop to landing filtered by the query.
        graphState.focusPid = null;
        graphRefresh();
    }
}

function renderBreadcrumb() {
    const bc = document.getElementById('graph-breadcrumb');
    if (!bc) return;
    if (!graphState.focusPid) { bc.innerHTML = ''; bc.classList.remove('visible'); return; }
    bc.classList.add('visible');
    const rootLabel = (n) => {
        const node = (graphState.nodes || []).find(x => x.type === 'process' && String(x.pid) === String(n));
        return node ? `${node.label} (${n})` : `PID ${n}`;
    };
    let html = '<span class="gbc-home" title="Back to process picker">&#8962; All</span>';
    graphState.focusStack.forEach((pid, i) => {
        html += `<span class="gbc-sep">&rsaquo;</span><span class="gbc-item" data-idx="${i}">PID ${escapeHtml(String(pid))}</span>`;
    });
    html += `<span class="gbc-sep">&rsaquo;</span><span class="gbc-current">${escapeHtml(rootLabel(graphState.focusPid))}</span>`;
    if (graphState.data?.truncated) html += '<span class="gbc-trunc" title="Tree truncated at the node cap">&#9888; truncated</span>';
    if (document.getElementById('graph-show-pipes')?.checked) {
        if (graphState.data?.pipes_truncated) html += '<span class="gbc-trunc" title="Pipe events were capped; some pipes may be missing">&#9888; pipe events truncated</span>';
        if (graphState.data?.pipes_error) html += `<span class="gbc-trunc" title="${escapeHtml(graphState.data.pipes_error)}">&#9888; pipes unavailable</span>`;
    }
    bc.innerHTML = html;

    bc.querySelector('.gbc-home')?.addEventListener('click', () => {
        graphState.focusPid = null;
        graphState.focusStack = [];
        const input = document.getElementById('graph-search');
        if (input) input.value = '';
        graphRefresh();
    });
    bc.querySelectorAll('.gbc-item[data-idx]').forEach(el => {
        el.addEventListener('click', () => {
            const idx = parseInt(el.dataset.idx);
            const pid = graphState.focusStack[idx];
            graphState.focusStack = graphState.focusStack.slice(0, idx);
            focusProcessGraph(pid, { push: false });
        });
    });
}

function buildGraph(payload) {
    const nodes = [];
    const edges = [];
    const nodeMap = {};

    const showNetwork = document.getElementById('graph-show-network')?.checked;
    const showDns = document.getElementById('graph-show-dns')?.checked;
    const showFiles = document.getElementById('graph-show-files')?.checked;
    const showRegistry = document.getElementById('graph-show-registry')?.checked;
    const showPipes = document.getElementById('graph-show-pipes')?.checked;
    const layout = document.getElementById('graph-layout')?.value || 'tree';

    const procs = payload.processes || {};

    // 1. Process nodes — the focused subtree: ancestors + root + descendants
    for (const [pid, proc] of Object.entries(procs)) {
        const threats = proc.activity?.threats || 0;
        const node = {
            id: `proc_${pid}`,
            type: 'process',
            key: pid,                      // instance key (dict key)
            pid: String(proc.pid ?? pid),  // real PID for display, scans and Sysmon queries
            started: proc.started || '',
            supersededAt: proc.superseded_at || '',
            label: proc.name || 'unknown',
            image: proc.image || '',
            cmdline: proc.command_line || '',
            user: proc.user || '',
            threats: threats,
            severity: proc.severity || 'unknown',
            children: proc.children || [],
            parentPid: proc.parent_key ?? proc.parent_pid,   // key of the parent instance
            parentOsPid: proc.parent_pid,
            activity: proc.activity || {},
            firstSeen: proc.first_seen || '',
            exited: !!proc.exit_time,
            detonated: !!proc.detonated,
            detonationSources: proc.detonation_sources || [],
            isRoot: !!proc.is_root,
            isAncestor: !!proc.is_ancestor,
            depth: proc.depth || 0,
            alertsCount: proc.alerts_count || 0,
            scans: proc.scans || [],
            scanVerdict: _nodeVerdict(proc.scans || []),
            x: 0, y: 0, vx: 0, vy: 0,
            radius: proc.is_root ? 26 : Math.max(13, Math.min(26, 13 + threats * 2)),
        };
        nodes.push(node);
        nodeMap[pid] = node;
    }

    // 2. Create parent-child edges
    for (const node of nodes) {
        const ppid = node.parentPid != null ? String(node.parentPid) : null;
        if (ppid && nodeMap[ppid]) {
            edges.push({
                source: `proc_${ppid}`,
                target: node.id,
                type: 'spawn',
                label: 'spawned',
            });
        }
    }

    // 3. Network connection nodes (Sysmon event 3), scoped to the subtree
    if (showNetwork) {
        const netTargets = {};  // deduplicate by ip:port
        (payload.network || []).forEach(ev => {
            const key = `${ev.dst_ip}:${ev.dst_port}`;
            if (!netTargets[key]) {
                netTargets[key] = { ip: ev.dst_ip, port: ev.dst_port, hostname: ev.dst_hostname || '', pids: new Set(), protocol: ev.protocol || 'tcp' };
            }
            if (ev.key || ev.pid) netTargets[key].pids.add(String(ev.key || ev.pid));
        });

        for (const [key, info] of Object.entries(netTargets)) {
            const nodeId = `net_${key}`;
            nodes.push({
                id: nodeId,
                type: 'network',
                label: info.hostname || info.ip,
                ip: info.ip,
                port: info.port,
                protocol: info.protocol,
                x: 0, y: 0, vx: 0, vy: 0,
                radius: 10,
            });
            info.pids.forEach(pid => {
                if (nodeMap[pid]) {
                    edges.push({ source: `proc_${pid}`, target: nodeId, type: 'network', label: `${info.protocol}:${info.port}` });
                }
            });
        }
    }

    // 4. DNS nodes (Sysmon event 22)
    if (showDns) {
        const dnsTargets = {};
        (payload.dns || []).forEach(ev => {
            const query = ev.query || '';
            if (!query) return;
            if (!dnsTargets[query]) {
                dnsTargets[query] = { query, result: ev.result || '', pids: new Set() };
            }
            if (ev.key || ev.pid) dnsTargets[query].pids.add(String(ev.key || ev.pid));
        });

        for (const [query, info] of Object.entries(dnsTargets)) {
            const nodeId = `dns_${query}`;
            nodes.push({
                id: nodeId,
                type: 'dns',
                label: query,
                result: info.result,
                x: 0, y: 0, vx: 0, vy: 0,
                radius: 8,
            });
            info.pids.forEach(pid => {
                if (nodeMap[pid]) {
                    edges.push({ source: `proc_${pid}`, target: nodeId, type: 'dns', label: 'query' });
                }
            });
        }
    }

    // 5. Injection edges (Sysmon event 8: CreateRemoteThread)
    (payload.injections || []).forEach(ev => {
        const srcPid = String(ev.source_key || ev.source_pid);
        const tgtPid = String(ev.target_key || ev.target_pid);
        if (srcPid && tgtPid && nodeMap[srcPid] && nodeMap[tgtPid]) {
            edges.push({ source: `proc_${srcPid}`, target: `proc_${tgtPid}`, type: 'inject', label: 'inject' });
        }
    });

    // 6. File nodes (Sysmon event 11: FileCreate)
    if (showFiles) {
        const fileTargets = {};
        (payload.files || []).forEach(ev => {
            const path = ev.target || '';
            if (!path || !ev.pid) return;
            if (!fileTargets[path]) fileTargets[path] = { path, pids: new Set() };
            fileTargets[path].pids.add(String(ev.key || ev.pid));
        });
        for (const [path, info] of Object.entries(fileTargets)) {
            const nodeId = `file_${path}`;
            const shortName = path.split('\\').pop() || path.split('/').pop() || path;
            nodes.push({ id: nodeId, type: 'file', label: shortName, fullPath: path, x: 0, y: 0, vx: 0, vy: 0, radius: 7 });
            info.pids.forEach(pid => {
                if (nodeMap[pid]) edges.push({ source: `proc_${pid}`, target: nodeId, type: 'file', label: 'write' });
            });
        }
    }

    // 7. Registry nodes (Sysmon events 12/13/14)
    if (showRegistry) {
        const regTargets = {};
        (payload.registry || []).forEach(ev => {
            const path = ev.target || '';
            if (!path || !ev.pid) return;
            const shortKey = path.split('\\').slice(-2).join('\\') || path;
            if (!regTargets[shortKey]) regTargets[shortKey] = { path, pids: new Set() };
            regTargets[shortKey].pids.add(String(ev.key || ev.pid));
        });
        for (const [key, info] of Object.entries(regTargets)) {
            const nodeId = `reg_${key}`;
            nodes.push({ id: nodeId, type: 'registry', label: key, fullPath: info.path, x: 0, y: 0, vx: 0, vy: 0, radius: 7 });
            info.pids.forEach(pid => {
                if (nodeMap[pid]) edges.push({ source: `proc_${pid}`, target: nodeId, type: 'registry', label: 'modify' });
            });
        }
    }

    // 8. Named pipe nodes (Sysmon events 17/18): one node per pipe, edges from
    // every process that created or connected to it. The isometric view hides
    // activity nodes, so there two processes on the same pipe get a bridge.
    if (showPipes) {
        const pipeTargets = {};
        (payload.pipes || []).forEach(ev => {
            const name = String(ev.pipe || '');
            const key = String(ev.key || ev.pid || '');
            if (!name || !nodeMap[key]) return;
            const id = name.toLowerCase();
            const t = pipeTargets[id] || (pipeTargets[id] = { name, family: null, created: new Set(), connected: new Set() });
            if (ev.family) t.family = ev.family;
            (ev.action === 'created' ? t.created : t.connected).add(key);
        });
        const links = {};
        for (const [id, info] of Object.entries(pipeTargets)) {
            const nodeId = `pipe_${id}`;
            nodes.push({ id: nodeId, type: 'pipe', label: info.name, family: info.family,
                createdBy: [...info.created], connectedBy: [...info.connected],
                x: 0, y: 0, vx: 0, vy: 0, radius: 9 });
            info.created.forEach(k => edges.push({ source: `proc_${k}`, target: nodeId, type: 'pipe-create', label: 'create' }));
            info.connected.forEach(k => edges.push({ source: `proc_${k}`, target: nodeId, type: 'pipe-connect', label: 'connect' }));
            if (layout === 'iso') {
                info.created.forEach(c => info.connected.forEach(k => {
                    if (c === k) return;
                    const lk = `${c}>${k}`;
                    if (!links[lk]) links[lk] = { source: `proc_${c}`, target: `proc_${k}`, type: 'pipe-link', label: info.name };
                }));
            }
        }
        Object.values(links).forEach(l => edges.push(l));
    }

    // Apply layout: rooted process tree (default) or force-directed
    graphState.layoutMode = layout;
    document.getElementById('graph-container')?.classList.toggle('graph-iso', layout === 'iso');
    if (layout === 'force') {
        applyForceLayout(nodes, edges);
    } else if (layout === 'iso') {
        applyIsometricLayout(nodes, edges, nodeMap);
    } else {
        applyRootedLayout(nodes, edges, nodeMap);
    }

    graphState.nodes = nodes;
    graphState.edges = edges;

    // Update counter / subtitle
    const countEl = document.getElementById('graph-node-count');
    if (countEl) {
        const procCount = nodes.filter(n => n.type === 'process').length;
        let label = `${procCount} processes, ${nodes.length} nodes`;
        if (payload.truncated) label += ' (truncated at cap)';
        if (showPipes) label += `, ${nodes.filter(n => n.type === 'pipe').length} pipes`;
        countEl.textContent = label;
    }
}

// Rooted process-tree layout: ancestors sit above the focus root, descendants
// fan out below, and activity nodes cluster around their owning process.
function applyRootedLayout(nodes, edges, nodeMap) {
    const X_SPACING = 150;
    const Y_LEVEL = 150;

    const procNodes = nodes.filter(n => n.type === 'process');
    // Layout roots = process nodes whose parent is not in the selected set
    // (normally the top-most ancestor of the focused process).
    const layoutRoots = procNodes.filter(n => !n.parentPid || !nodeMap[n.parentPid]);
    if (!layoutRoots.length && procNodes.length) layoutRoots.push(procNodes[0]);

    // Assign a column (leaf index) per node via DFS; internal nodes are centered.
    const colById = {};
    const visited = new Set();
    let leaf = 0;
    function dfs(node) {
        if (visited.has(node.id)) return;
        visited.add(node.id);
        const kids = (node.children || [])
            .map(c => nodeMap[c])
            .filter(k => k && String(k.parentPid) === String(node.key) && !visited.has(k.id));
        if (!kids.length) {
            colById[node.id] = leaf++;
        } else {
            kids.forEach(dfs);
            colById[node.id] = (colById[kids[0].id] + colById[kids[kids.length - 1].id]) / 2;
        }
    }
    layoutRoots.forEach(dfs);
    // Any process not reached (cycles / detached) gets its own column.
    procNodes.forEach(n => { if (colById[n.id] === undefined) colById[n.id] = leaf++; });

    // Place process nodes: x by column, y by tree depth (ancestors are negative -> above).
    procNodes.forEach(n => {
        n.x = colById[n.id] * X_SPACING;
        n.y = (n.depth || 0) * Y_LEVEL;
    });

    // Cluster activity nodes in a fan below their owning process.
    const fullIndex = {};
    nodes.forEach(n => { fullIndex[n.id] = n; });
    const auxByOwner = {};
    nodes.filter(n => n.type !== 'process').forEach(n => {
        const e = edges.find(ed => ed.source === n.id || ed.target === n.id);
        if (!e) { n.x = Math.random() * 200; n.y = Math.random() * 200; return; }
        const ownerId = e.source === n.id ? e.target : e.source;
        (auxByOwner[ownerId] = auxByOwner[ownerId] || []).push(n);
    });
    for (const [ownerId, list] of Object.entries(auxByOwner)) {
        const owner = fullIndex[ownerId];
        if (!owner) continue;
        const count = list.length;
        list.forEach((n, i) => {
            const t = count > 1 ? i / (count - 1) : 0.5;
            const angle = Math.PI * 0.15 + Math.PI * 0.7 * t;  // fan below the owner
            const dist = 70 + (i % 3) * 22;
            n.x = owner.x + Math.cos(angle) * dist;
            n.y = owner.y + 48 + Math.sin(angle) * dist;
        });
    }
}

// --- Isometric process-tree view -----------------------------------------
//
// Two isometric axes: U (down-right) is process depth, V (down-left) lines up
// siblings. Every parent owns a "spine" running along V halfway to its
// children; each child hangs off it by a short tick. The parent sits at the
// head of its spine, so a single-child chain (the ancestor lineage) runs as
// one straight line along U. Process-to-process edges (remote threads) are
// drawn as raised bridges so they never get lost among the tree lines.
const ISO = {
    COS: Math.cos(Math.PI / 6),
    SIN: Math.sin(Math.PI / 6),
    STEP_U: 118,     // world units between depth levels
    STEP_V: 76,      // world units between siblings
    LIFT: 64,        // height of the bridge plane for cross-process edges
    R: 13,           // node radius
};

function isoProject(u, v) {
    return {
        x: (u * ISO.STEP_U - v * ISO.STEP_V) * ISO.COS,
        y: (u * ISO.STEP_U + v * ISO.STEP_V) * ISO.SIN,
    };
}

function applyIsometricLayout(nodes, edges, nodeMap) {
    const procNodes = nodes.filter(n => n.type === 'process');
    const roots = procNodes.filter(n => !n.parentPid || !nodeMap[String(n.parentPid)]);
    if (!roots.length && procNodes.length) roots.push(procNodes[0]);

    const byTime = (a, b) => String(a.firstSeen || '').localeCompare(String(b.firstSeen || ''))
        || (parseInt(a.pid, 10) || 0) - (parseInt(b.pid, 10) || 0);
    const kidsOf = n => (n.children || [])
        .map(c => nodeMap[String(c)])
        .filter(k => k && String(k.parentPid) === String(n.key))
        .sort(byTime);

    const visited = new Set();
    const minDepth = Math.min(0, ...procNodes.map(n => n.depth || 0));
    let nextV = 0;

    function countDescendants(n, seen = new Set()) {
        let total = 0;
        for (const k of kidsOf(n)) {
            if (seen.has(k.id)) continue;
            seen.add(k.id);
            total += 1 + countDescendants(k, seen);
        }
        return total;
    }
    function hideSubtree(n) {
        for (const k of kidsOf(n)) {
            if (visited.has(k.id)) continue;
            visited.add(k.id);
            k.hidden = true;
            hideSubtree(k);
        }
    }
    function place(n, u) {
        visited.add(n.id);
        n.isoU = u;
        n.isoKids = [];
        const kids = kidsOf(n).filter(k => !visited.has(k.id));
        n.isoHasKids = kids.length > 0;
        n.isoCollapsed = graphState.isoCollapsed.has(String(n.key)) && kids.length > 0;
        if (!kids.length || n.isoCollapsed) {
            n.isoV = nextV++;
            if (n.isoCollapsed) {
                n.isoHiddenCount = countDescendants(n);
                hideSubtree(n);
            }
            return;
        }
        n.isoV = nextV;                    // head of its own spine
        kids.forEach(k => { place(k, u + 1); n.isoKids.push(k); });
    }

    roots.sort(byTime).forEach(r => {
        if (visited.has(r.id)) return;
        place(r, (r.depth || 0) - minDepth);
        nextV += 1;                        // gap between separate trees
    });
    procNodes.forEach(n => {               // anything unreachable (cycles)
        if (!visited.has(n.id)) { visited.add(n.id); n.isoU = 0; n.isoV = nextV++; n.isoKids = []; }
    });

    procNodes.forEach(n => {
        const p = isoProject(n.isoU, n.isoV);
        n.x = p.x;
        n.y = p.y;
        n.radius = n.isRoot || n.detonated || n.threats > 0 ? ISO.R + 5 : ISO.R;
        n.isoAct = { network: 0, dns: 0, file: 0, registry: 0, inject: 0, pipe: 0 };
    });

    // Activity is summarised as icons under each process instead of separate
    // nodes; the nodes stay in the model so the detail panel can list them.
    const index = {};
    nodes.forEach(n => { index[n.id] = n; });
    const pipeSeen = new Set();       // a pipe counts once per process (create + connect)
    edges.forEach(e => {
        const src = index[e.source];
        if (!src || src.type !== 'process' || !src.isoAct) return;
        if (e.type === 'pipe-create' || e.type === 'pipe-connect') {
            const k = `${e.source}|${e.target}`;
            if (!pipeSeen.has(k)) { pipeSeen.add(k); src.isoAct.pipe += 1; }
            return;
        }
        if (e.type in src.isoAct) src.isoAct[e.type] += 1;
    });
    nodes.forEach(n => { if (n.type !== 'process') n.hidden = true; });
}

function isoHandleToggleClick(pos) {
    for (const n of graphState.nodes) {
        const t = n.isoToggle;
        if (!t || n.hidden) continue;
        const dx = pos.x - t.x, dy = pos.y - t.y;
        if (dx * dx + dy * dy <= (t.r + 2) * (t.r + 2)) {
            const key = String(n.key);
            if (graphState.isoCollapsed.has(key)) graphState.isoCollapsed.delete(key);
            else graphState.isoCollapsed.add(key);
            if (graphState.data) buildGraph(graphState.data);
            renderGraph();
            return true;
        }
    }
    return false;
}

function _isoNodeStyle(n) {
    const style = (fill, stroke, glyph, big) => ({
        fill: themeColor(fill), stroke: themeColor(stroke), glyph: themeColor(glyph),
        halo: big ? themeColor(stroke, 0x33 / 255) : null, big,
    });
    if (n.detonated) return style('--c-amber-500', '--graph-detonated', '--c-amber-990', true);
    if (n.threats > 0) {
        if (n.severity === 'critical') return style('--c-red-600', '--severity-critical', '--c-white', true);
        if (n.severity === 'high') return style('--c-orange-600', '--severity-high', '--c-white', true);
        return style('--c-yellow-600', '--severity-medium', '--c-white', true);
    }
    return style('--c-slate-800', '--text-dim', '--text-secondary', false);
}

function _isoHexPath(ctx, x, y, r) {
    ctx.beginPath();
    for (let i = 0; i < 6; i++) {
        const a = Math.PI / 6 + i * Math.PI / 3;      // pointy top
        const px = x + r * Math.cos(a), py = y + r * Math.sin(a);
        if (i === 0) ctx.moveTo(px, py); else ctx.lineTo(px, py);
    }
    ctx.closePath();
}

// Small isometric cube - the process glyph inside the hexagon.
function _isoCube(ctx, x, y, s, color) {
    const c = ISO.COS * s, h = ISO.SIN * s;
    ctx.save();
    ctx.fillStyle = color;
    ctx.globalAlpha *= 0.95;
    ctx.beginPath();                                   // top face
    ctx.moveTo(x, y - s); ctx.lineTo(x + c, y - s + h); ctx.lineTo(x, y); ctx.lineTo(x - c, y - s + h);
    ctx.closePath(); ctx.fill();
    ctx.globalAlpha *= 0.7;
    ctx.beginPath();                                   // left face
    ctx.moveTo(x - c, y - s + h); ctx.lineTo(x, y); ctx.lineTo(x, y + s); ctx.lineTo(x - c, y + h);
    ctx.closePath(); ctx.fill();
    ctx.globalAlpha *= 0.65;
    ctx.beginPath();                                   // right face
    ctx.moveTo(x + c, y - s + h); ctx.lineTo(x, y); ctx.lineTo(x, y + s); ctx.lineTo(x + c, y + h);
    ctx.closePath(); ctx.fill();
    ctx.restore();
}

function _isoArrow(ctx, x, y, angle, size, color) {
    ctx.beginPath();
    ctx.moveTo(x, y);
    ctx.lineTo(x - size * Math.cos(angle - 0.45), y - size * Math.sin(angle - 0.45));
    ctx.lineTo(x - size * Math.cos(angle + 0.45), y - size * Math.sin(angle + 0.45));
    ctx.closePath();
    ctx.fillStyle = color;
    ctx.fill();
}

// Activity icons under the label: network, DNS, files, registry, pipes.
function _isoActivityIcons(ctx, x, y, act) {
    const items = [
        ['network', '--graph-network'], ['dns', '--graph-dns'], ['file', '--graph-file'],
        ['registry', '--graph-registry'], ['pipe', '--graph-pipe'],
    ].filter(([k]) => act && act[k] > 0);
    ctx.font = '8px monospace';
    ctx.textBaseline = 'middle';
    ctx.textAlign = 'left';
    for (const [kind, colorVar] of items) {
        const color = themeColor(colorVar);
        ctx.strokeStyle = color;
        ctx.fillStyle = color;
        ctx.lineWidth = 1.1;
        if (kind === 'network') {                        // signal arcs
            for (const rr of [2, 4.5]) {
                ctx.beginPath(); ctx.arc(x + 4, y + 3, rr, Math.PI * 1.2, Math.PI * 1.8); ctx.stroke();
            }
            ctx.beginPath(); ctx.arc(x + 4, y + 3, 0.9, 0, Math.PI * 2); ctx.fill();
        } else if (kind === 'dns') {                     // ring with dot
            ctx.beginPath(); ctx.arc(x + 4, y, 3.6, 0, Math.PI * 2); ctx.stroke();
            ctx.beginPath(); ctx.arc(x + 4, y, 1.2, 0, Math.PI * 2); ctx.fill();
        } else if (kind === 'file') {                    // page
            ctx.strokeRect(x + 1.5, y - 4, 5.5, 8);
        } else if (kind === 'pipe') {                    // diamond
            ctx.beginPath();
            ctx.moveTo(x + 4, y - 4); ctx.lineTo(x + 8, y); ctx.lineTo(x + 4, y + 4); ctx.lineTo(x, y);
            ctx.closePath(); ctx.stroke();
        } else {                                         // registry: stacked bars
            for (let i = 0; i < 3; i++) ctx.fillRect(x + 1, y - 4 + i * 3, 7, 1.6);
        }
        ctx.fillText(String(act[kind]), x + 10, y + 0.5);
        x += 12 + ctx.measureText(String(act[kind])).width + 6;
    }
}

function renderIsometricGraph(ctx) {
    const nodes = graphState.nodes.filter(n => n.type === 'process' && !n.hidden);
    const byId = {};
    graphState.nodes.forEach(n => { byId[n.id] = n; });
    const zoom = graphState.camera.zoom;

    // 1. Tree connectors: parent tick -> spine along V -> child ticks.
    ctx.lineCap = 'round';
    for (const n of nodes) {
        const kids = (n.isoKids || []).filter(k => !k.hidden);
        if (!kids.length) continue;
        const u = n.isoU, uMid = u + 0.5;
        const head = isoProject(uMid, n.isoV);
        const tail = isoProject(uMid, kids[kids.length - 1].isoV);
        ctx.strokeStyle = themeColor('--c-slate-650');
        ctx.lineWidth = 1.2;
        ctx.globalAlpha = n.exited ? 0.6 : 0.95;
        ctx.beginPath();
        ctx.moveTo(n.x, n.y); ctx.lineTo(head.x, head.y);           // parent tick
        ctx.lineTo(tail.x, tail.y);                                // spine
        for (const k of kids) {
            const a = isoProject(uMid, k.isoV);
            ctx.moveTo(a.x, a.y); ctx.lineTo(k.x, k.y);            // child tick
        }
        ctx.stroke();

        // Lineage (ancestors down to the focus root) in blue.
        const lineage = kids.find(k => k.isAncestor || k.isRoot);
        if (lineage && (n.isAncestor || n.isRoot)) {
            const a = isoProject(uMid, lineage.isoV);
            ctx.strokeStyle = themeColor('--accent-blue');
            ctx.lineWidth = 1.6;
            ctx.beginPath();
            ctx.moveTo(n.x, n.y); ctx.lineTo(head.x, head.y);
            ctx.lineTo(a.x, a.y); ctx.lineTo(lineage.x, lineage.y);
            ctx.stroke();
        }
    }
    ctx.globalAlpha = 1;

    // 2. Cross-process edges as raised bridges: remote threads (solid) and
    // named pipes shared by two processes (dashed, lower, creator -> client).
    const teal = themeColor('--c-teal-400');
    for (const e of graphState.edges) {
        if (e.type !== 'inject' && e.type !== 'pipe-link') continue;
        const s = byId[e.source], t = byId[e.target];
        if (!s || !t || s.hidden || t.hidden || s === t) continue;
        const isPipe = e.type === 'pipe-link';
        const L = isPipe ? ISO.LIFT * 0.7 : ISO.LIFT;
        const corner = isoProject(t.isoU, s.isoV);
        const pts = [
            { x: s.x, y: s.y - s.radius },
            { x: s.x, y: s.y - L },
            { x: corner.x, y: corner.y - L },
            { x: t.x, y: t.y - L },
            { x: t.x, y: t.y - t.radius - 3 },
        ];
        ctx.strokeStyle = teal;
        ctx.lineWidth = 1.4;
        if (isPipe) ctx.setLineDash([5, 3]);
        ctx.beginPath();
        pts.forEach((p, i) => (i ? ctx.lineTo(p.x, p.y) : ctx.moveTo(p.x, p.y)));
        ctx.stroke();
        ctx.setLineDash([]);
        _isoArrow(ctx, pts[1].x, pts[1].y + 2, -Math.PI / 2, 7, teal);   // leaves the source
        _isoArrow(ctx, pts[4].x, pts[4].y, Math.PI / 2, 8, teal);       // enters the target
        const midY = (pts[3].y + pts[4].y) / 2;                           // marker on the drop
        ctx.fillStyle = themeColor('--c-teal-500');
        ctx.beginPath();
        if (isPipe) {                                                     // diamond: pipe
            ctx.moveTo(t.x, midY - 6); ctx.lineTo(t.x + 5, midY); ctx.lineTo(t.x, midY + 6); ctx.lineTo(t.x - 5, midY);
            ctx.closePath();
        } else if (ctx.roundRect) ctx.roundRect(t.x - 3.5, midY - 7, 7, 14, 3); else ctx.rect(t.x - 3.5, midY - 7, 7, 14);
        ctx.fill();
    }

    // 3. Nodes, labels, badges.
    for (const n of nodes) {
        const st = _isoNodeStyle(n);
        const hovered = graphState.hoveredNode === n;
        const selected = graphState.selectedNode === n;
        const r = n.radius * (hovered ? 1.08 : 1);
        ctx.globalAlpha = n.exited && !st.big ? 0.6 : 1;

        if (n.isRoot) {                                   // focus ring
            _isoHexPath(ctx, n.x, n.y, r + 6);
            ctx.strokeStyle = themeColor('--c-sky-400');
            ctx.lineWidth = 1.5;
            ctx.setLineDash([3, 3]);
            ctx.stroke();
            ctx.setLineDash([]);
        }
        if (st.big) {                                     // soft halo for notable nodes
            _isoHexPath(ctx, n.x, n.y, r + 4);
            ctx.fillStyle = st.halo;
            ctx.fill();
        }
        _isoHexPath(ctx, n.x, n.y, r);
        ctx.fillStyle = st.fill;
        ctx.fill();
        ctx.strokeStyle = selected ? themeColor('--c-white') : st.stroke;
        ctx.lineWidth = selected ? 2.2 : 1.2;
        ctx.stroke();
        _isoCube(ctx, n.x, n.y + 1, r * 0.48, st.glyph);

        // Threat count (top right) and scan verdict (bottom left)
        if (n.threats > 0) {
            const bx = n.x + r * 0.85, by = n.y - r * 0.85;
            ctx.beginPath(); ctx.arc(bx, by, 6.5, 0, Math.PI * 2);
            ctx.fillStyle = themeColor('--accent-red'); ctx.fill();
            ctx.font = 'bold 7px monospace';
            ctx.fillStyle = themeColor('--c-white'); ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
            ctx.fillText(n.threats > 99 ? '99+' : String(n.threats), bx, by + 0.5);
        }
        if (n.scans && n.scans.length) {
            const vColors = { malicious: '--accent-red', detected: '--accent-red', clean: '--c-green-400', analyzed: '--c-sky-400', unknown: '--text-muted' };
            ctx.beginPath(); ctx.arc(n.x - r * 0.85, n.y + r * 0.85, 4.5, 0, Math.PI * 2);
            ctx.fillStyle = themeColor(vColors[n.scanVerdict] || '--text-muted'); ctx.fill();
            ctx.strokeStyle = themeColor('--c-navy-950'); ctx.lineWidth = 1.2; ctx.stroke();
        }

        // Label to the right, upper case; the focus root in cyan.
        const label = (n.label || 'unknown').toUpperCase();
        ctx.font = `${n.isRoot ? '600 ' : ''}11px -apple-system, "Segoe UI", sans-serif`;
        ctx.textAlign = 'left';
        ctx.textBaseline = 'middle';
        ctx.fillStyle = themeColor(selected || hovered ? '--c-white' : n.isRoot ? '--accent-cyan' : '--c-slate-300');
        const text = label.length > 24 ? label.slice(0, 22) + '…' : label;
        const lx = n.x + r + 7, ly = n.y - 5;
        ctx.fillText(text, lx, ly);
        if (zoom > 0.55) {
            ctx.font = '9px monospace';
            ctx.fillStyle = themeColor('--text-muted');
            ctx.fillText(`PID ${n.pid}`, lx, ly + 12);
            _isoActivityIcons(ctx, lx + ctx.measureText(`PID ${n.pid}`).width + 8, ly + 12, n.isoAct);
        }

        // Fold toggle below-left of the node: labels run to the right and the
        // next sibling's label sits below-right, so that corner stays free.
        n.isoToggle = null;
        if (n.isoHasKids) {
            const tx = n.x - r - 3, ty = n.y + r + 3, tr = 5;
            n.isoToggle = { x: tx, y: ty, r: tr };
            ctx.beginPath(); ctx.arc(tx, ty, tr, 0, Math.PI * 2);
            ctx.fillStyle = themeColor('--c-slate-900'); ctx.fill();
            ctx.strokeStyle = themeColor(n.isoCollapsed ? '--c-teal-400' : '--text-muted'); ctx.lineWidth = 1; ctx.stroke();
            ctx.strokeStyle = themeColor(n.isoCollapsed ? '--c-teal-400' : '--text-secondary');
            ctx.beginPath(); ctx.moveTo(tx - 2.6, ty); ctx.lineTo(tx + 2.6, ty);
            if (n.isoCollapsed) { ctx.moveTo(tx, ty - 2.6); ctx.lineTo(tx, ty + 2.6); }
            ctx.stroke();
            if (n.isoCollapsed && n.isoHiddenCount) {
                ctx.font = '8px monospace'; ctx.fillStyle = themeColor('--c-teal-400');
                ctx.textAlign = 'right'; ctx.textBaseline = 'middle';
                ctx.fillText(`+${n.isoHiddenCount}`, tx - tr - 3, ty);
            }
        }

        if (n.isRoot) {
            ctx.font = 'bold 8px monospace';
            const tw = ctx.measureText('FOCUS').width;
            ctx.fillStyle = themeColor('--c-sky-400');
            ctx.fillRect(n.x - tw / 2 - 4, n.y - r - 20, tw + 8, 11);
            ctx.fillStyle = themeColor('--c-navy-950');
            ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
            ctx.fillText('FOCUS', n.x, n.y - r - 14.5);
        }
        ctx.globalAlpha = 1;
    }
}

function applyForceLayout(nodes, edges) {
    // Initial random placement
    nodes.forEach((n, i) => {
        n.x = Math.cos(i * 0.7) * (150 + i * 10);
        n.y = Math.sin(i * 0.7) * (150 + i * 10);
    });

    // Run force simulation for N iterations
    const nodeIndex = {};
    nodes.forEach(n => { nodeIndex[n.id] = n; });

    for (let iter = 0; iter < 120; iter++) {
        const alpha = 0.3 * (1 - iter / 120);

        // Repulsion. All pairs is O(n^2) per iteration (~10M steps for 400
        // nodes); on larger graphs only nodes in neighbouring grid cells
        // repel - beyond REPULSE_RANGE the force is under 0.03 px anyway.
        const repel = (a, b) => {
            const dx = b.x - a.x;
            const dy = b.y - a.y;
            const dist = Math.sqrt(dx * dx + dy * dy) || 1;
            const force = 3000 / (dist * dist);
            const fx = (dx / dist) * force * alpha;
            const fy = (dy / dist) * force * alpha;
            a.x -= fx;
            a.y -= fy;
            b.x += fx;
            b.y += fy;
        };
        if (nodes.length <= 150) {
            for (let i = 0; i < nodes.length; i++) {
                for (let j = i + 1; j < nodes.length; j++) repel(nodes[i], nodes[j]);
            }
        } else {
            const REPULSE_RANGE = 300;
            const grid = new Map();
            nodes.forEach((n, idx) => {
                const key = `${Math.floor(n.x / REPULSE_RANGE)},${Math.floor(n.y / REPULSE_RANGE)}`;
                let cell = grid.get(key);
                if (!cell) grid.set(key, cell = []);
                cell.push(idx);
            });
            for (const [key, cell] of grid) {
                const [cx, cy] = key.split(',').map(Number);
                for (let ox = -1; ox <= 1; ox++) {
                    for (let oy = -1; oy <= 1; oy++) {
                        const other = grid.get(`${cx + ox},${cy + oy}`);
                        if (!other) continue;
                        for (const i of cell) {
                            for (const j of other) {
                                if (j > i) repel(nodes[i], nodes[j]);
                            }
                        }
                    }
                }
            }
        }

        // Attraction along edges
        edges.forEach(e => {
            const src = nodeIndex[e.source];
            const tgt = nodeIndex[e.target];
            if (!src || !tgt) return;
            const dx = tgt.x - src.x;
            const dy = tgt.y - src.y;
            const dist = Math.sqrt(dx * dx + dy * dy) || 1;
            const idealDist = e.type === 'spawn' ? 150 : 120;
            const force = (dist - idealDist) * 0.01 * alpha;
            const fx = (dx / dist) * force;
            const fy = (dy / dist) * force;
            src.x += fx;
            src.y += fy;
            tgt.x -= fx;
            tgt.y -= fy;
        });
    }
}


function initGraphCanvas() {
    const canvas = document.getElementById('graph-canvas');
    const container = document.getElementById('graph-container');
    if (!canvas || !container) return;

    // The canvas is initialised while its tab may still be hidden (0x0) and
    // the container also changes size without a window resize (detail panel,
    // tab switch), so follow the container itself.
    function resize() {
        const w = container.clientWidth;
        const h = container.clientHeight;
        if (!w || !h || (canvas.width === w && canvas.height === h)) return;
        canvas.width = w;
        canvas.height = h;
        renderGraph();
    }
    resize();
    if (typeof ResizeObserver !== 'undefined') {
        new ResizeObserver(resize).observe(container);
    } else {
        window.addEventListener('resize', resize);
    }

    // Mouse interactions
    let lastMouse = { x: 0, y: 0 };

    canvas.addEventListener('mousedown', e => {
        const pos = screenToWorld(e.offsetX, e.offsetY);
        if (graphState.layoutMode === 'iso' && isoHandleToggleClick(pos)) {
            lastMouse = { x: e.offsetX, y: e.offsetY };
            return;
        }
        const node = findNodeAt(pos.x, pos.y);
        if (node) {
            if (graphState.layoutMode !== 'iso') graphState.dragging = node;
            graphState.selectedNode = node;
            showGraphDetail(node);
        } else {
            graphState.panning = true;
            graphState.panStart = { x: e.offsetX, y: e.offsetY };
            graphState.selectedNode = null;
            hideGraphDetail();
        }
        lastMouse = { x: e.offsetX, y: e.offsetY };
    });

    canvas.addEventListener('mousemove', e => {
        const pos = screenToWorld(e.offsetX, e.offsetY);

        if (graphState.dragging) {
            graphState.dragging.x = pos.x;
            graphState.dragging.y = pos.y;
            renderGraph();
        } else if (graphState.panning) {
            const dx = e.offsetX - graphState.panStart.x;
            const dy = e.offsetY - graphState.panStart.y;
            graphState.camera.x += dx;
            graphState.camera.y += dy;
            graphState.panStart = { x: e.offsetX, y: e.offsetY };
            renderGraph();
        } else {
            // Hover detection
            const node = findNodeAt(pos.x, pos.y);
            if (node !== graphState.hoveredNode) {
                graphState.hoveredNode = node;
                showGraphTooltip(node, e.offsetX, e.offsetY);
                renderGraph();
            }
        }
        lastMouse = { x: e.offsetX, y: e.offsetY };
    });

    canvas.addEventListener('mouseup', () => {
        graphState.dragging = null;
        graphState.panning = false;
    });

    canvas.addEventListener('mouseleave', () => {
        graphState.dragging = null;
        graphState.panning = false;
        graphState.hoveredNode = null;
        hideGraphTooltip();
        renderGraph();
    });

    canvas.addEventListener('wheel', e => {
        e.preventDefault();
        const zoomFactor = e.deltaY > 0 ? 0.9 : 1.1;
        const oldZoom = graphState.camera.zoom;
        graphState.camera.zoom = Math.max(0.1, Math.min(5, oldZoom * zoomFactor));

        // Zoom toward mouse position
        const mx = e.offsetX;
        const my = e.offsetY;
        graphState.camera.x = mx - (mx - graphState.camera.x) * (graphState.camera.zoom / oldZoom);
        graphState.camera.y = my - (my - graphState.camera.y) * (graphState.camera.zoom / oldZoom);

        updateZoomLevel();
        renderGraph();
    });
}

function screenToWorld(sx, sy) {
    return {
        x: (sx - graphState.camera.x) / graphState.camera.zoom,
        y: (sy - graphState.camera.y) / graphState.camera.zoom,
    };
}

function worldToScreen(wx, wy) {
    return {
        x: wx * graphState.camera.zoom + graphState.camera.x,
        y: wy * graphState.camera.zoom + graphState.camera.y,
    };
}

function findNodeAt(wx, wy) {
    for (let i = graphState.nodes.length - 1; i >= 0; i--) {
        const n = graphState.nodes[i];
        if (n.hidden) continue;
        const dx = wx - n.x;
        const dy = wy - n.y;
        if (dx * dx + dy * dy < n.radius * n.radius) return n;
    }
    return null;
}

function graphFitView() {
    const nodes = graphState.nodes;
    if (!nodes.length) return;
    const canvas = document.getElementById('graph-canvas');
    if (!canvas) return;

    let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
    nodes.forEach(n => {
        if (n.hidden) return;
        minX = Math.min(minX, n.x - n.radius);
        maxX = Math.max(maxX, n.x + n.radius);
        minY = Math.min(minY, n.y - n.radius);
        maxY = Math.max(maxY, n.y + n.radius);
    });

    const padding = 60;
    if (graphState.layoutMode === 'iso') maxX += 130;   // labels sit right of the node
    const w = maxX - minX + padding * 2;
    const h = maxY - minY + padding * 2;
    const zoom = Math.min(canvas.width / w, canvas.height / h, 2);

    graphState.camera.zoom = zoom;
    graphState.camera.x = canvas.width / 2 - (minX + maxX) / 2 * zoom;
    graphState.camera.y = canvas.height / 2 - (minY + maxY) / 2 * zoom;
    updateZoomLevel();
    renderGraph();
}

function graphZoomIn() {
    const canvas = document.getElementById('graph-canvas');
    if (!canvas) return;
    const oldZoom = graphState.camera.zoom;
    graphState.camera.zoom = Math.min(5, oldZoom * 1.25);
    // Zoom toward center
    const cx = canvas.width / 2;
    const cy = canvas.height / 2;
    graphState.camera.x = cx - (cx - graphState.camera.x) * (graphState.camera.zoom / oldZoom);
    graphState.camera.y = cy - (cy - graphState.camera.y) * (graphState.camera.zoom / oldZoom);
    updateZoomLevel();
    renderGraph();
}

function graphZoomOut() {
    const canvas = document.getElementById('graph-canvas');
    if (!canvas) return;
    const oldZoom = graphState.camera.zoom;
    graphState.camera.zoom = Math.max(0.1, oldZoom * 0.8);
    const cx = canvas.width / 2;
    const cy = canvas.height / 2;
    graphState.camera.x = cx - (cx - graphState.camera.x) * (graphState.camera.zoom / oldZoom);
    graphState.camera.y = cy - (cy - graphState.camera.y) * (graphState.camera.zoom / oldZoom);
    updateZoomLevel();
    renderGraph();
}

function updateZoomLevel() {
    const el = document.getElementById('graph-zoom-level');
    if (el) el.textContent = Math.round(graphState.camera.zoom * 100) + '%';
}

function renderGraph() {
    const canvas = document.getElementById('graph-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const { nodes, edges, camera } = graphState;

    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Empty state message (suppressed while a fetch is in flight — the
    // #graph-loading overlay shows a spinner during that window instead).
    if (nodes.length === 0) {
        if (graphState.isLoading) return;
        ctx.save();
        ctx.fillStyle = themeColor('--text-muted');
        ctx.font = '14px monospace';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        const msg = graphState.emptyMessage
            || (graphState.focusPid ? `No graph data for PID ${graphState.focusPid}.` : 'Select a process to investigate.');
        ctx.fillText(msg, canvas.width / 2, canvas.height / 2);
        ctx.restore();
        return;
    }

    ctx.save();
    ctx.translate(camera.x, camera.y);
    ctx.scale(camera.zoom, camera.zoom);

    if (graphState.layoutMode === 'iso') {
        renderIsometricGraph(ctx);
        ctx.restore();
        return;
    }

    // Colours by variable name: some are also painted with an alpha
    const nodeColors = {
        process: '--graph-process',
        network: '--graph-network',
        dns: '--graph-dns',
        file: '--graph-file',
        registry: '--graph-registry',
        pipe: '--graph-pipe',
    };

    const edgeColors = {
        spawn: '--text-dim',
        network: '--graph-network',
        dns: '--graph-dns',
        inject: '--accent-red',
        file: '--graph-file',
        registry: '--graph-registry',
        'pipe-create': '--graph-pipe',
        'pipe-connect': '--graph-pipe',
    };

    // Build node index for edge lookup
    const nodeIndex = {};
    nodes.forEach(n => { nodeIndex[n.id] = n; });

    // Draw edges
    edges.forEach(edge => {
        const src = nodeIndex[edge.source];
        const tgt = nodeIndex[edge.target];
        if (!src || !tgt) return;

        ctx.beginPath();
        ctx.moveTo(src.x, src.y);
        ctx.lineTo(tgt.x, tgt.y);
        ctx.strokeStyle = themeColor(edgeColors[edge.type] || '--text-dim');
        ctx.lineWidth = edge.type === 'inject' ? 2 : 1;
        if (edge.type === 'inject') {
            ctx.setLineDash([4, 3]);
        } else if (edge.type === 'pipe-create') {
            ctx.setLineDash([6, 2]);
        } else if (edge.type !== 'spawn') {
            ctx.setLineDash([2, 2]);
        } else {
            ctx.setLineDash([]);
        }
        ctx.globalAlpha = 0.6;
        ctx.stroke();
        ctx.setLineDash([]);
        ctx.globalAlpha = 1;

        // Arrow head for spawn edges
        if (edge.type === 'spawn') {
            const angle = Math.atan2(tgt.y - src.y, tgt.x - src.x);
            const headLen = 8;
            const arrX = tgt.x - Math.cos(angle) * tgt.radius;
            const arrY = tgt.y - Math.sin(angle) * tgt.radius;
            ctx.beginPath();
            ctx.moveTo(arrX, arrY);
            ctx.lineTo(arrX - headLen * Math.cos(angle - 0.4), arrY - headLen * Math.sin(angle - 0.4));
            ctx.lineTo(arrX - headLen * Math.cos(angle + 0.4), arrY - headLen * Math.sin(angle + 0.4));
            ctx.closePath();
            ctx.fillStyle = themeColor(edgeColors[edge.type]);
            ctx.globalAlpha = 0.7;
            ctx.fill();
            ctx.globalAlpha = 1;
        }
    });

    // Draw nodes
    nodes.forEach(node => {
        const isHovered = graphState.hoveredNode === node;
        const isSelected = graphState.selectedNode === node;
        let colorVar = nodeColors[node.type] || '--text-muted';

        // Override color for malicious processes
        if (node.type === 'process' && node.threats > 0) {
            if (node.severity === 'critical') colorVar = '--severity-critical';
            else if (node.severity === 'high') colorVar = '--severity-high';
            else if (node.severity === 'medium') colorVar = '--severity-medium';
        }

        // Override color for detonated processes (gold)
        if (node.detonated) {
            colorVar = '--graph-detonated';
        }

        const r = node.radius * (isHovered ? 1.2 : 1);

        // Ancestors are drawn faded to keep the focus subtree prominent
        ctx.globalAlpha = node.isAncestor ? 0.5 : 1;

        // Focus ring for the root node
        if (node.isRoot) {
            ctx.beginPath();
            ctx.arc(node.x, node.y, r + 8, 0, Math.PI * 2);
            ctx.strokeStyle = themeColor('--c-sky-400');
            ctx.lineWidth = 2;
            ctx.setLineDash([3, 3]);
            ctx.stroke();
            ctx.setLineDash([]);
        }

        // Glow for malicious
        if (node.type === 'process' && node.threats > 0) {
            ctx.beginPath();
            ctx.arc(node.x, node.y, r + 4, 0, Math.PI * 2);
            ctx.fillStyle = themeColor(colorVar, 0x20 / 255);
            ctx.fill();
        }

        // Glow for detonated
        if (node.detonated) {
            ctx.beginPath();
            ctx.arc(node.x, node.y, r + 5, 0, Math.PI * 2);
            ctx.fillStyle = themeColor('--graph-detonated', 0x25 / 255);
            ctx.fill();
        }

        // Node outline: a diamond for pipes, a circle otherwise
        ctx.beginPath();
        if (node.type === 'pipe') {
            ctx.moveTo(node.x, node.y - r * 1.25);
            ctx.lineTo(node.x + r * 1.25, node.y);
            ctx.lineTo(node.x, node.y + r * 1.25);
            ctx.lineTo(node.x - r * 1.25, node.y);
            ctx.closePath();
        } else {
            ctx.arc(node.x, node.y, r, 0, Math.PI * 2);
        }
        ctx.fillStyle = themeColor(colorVar, 0x30 / 255);
        ctx.fill();
        if (node.type === 'pipe' && node.family) colorVar = '--severity-critical';   // known C2 pipe name
        const color = themeColor(colorVar);
        ctx.strokeStyle = isSelected ? themeColor('--c-white') : color;
        ctx.lineWidth = isSelected ? 2.5 : 1.5;
        ctx.stroke();

        // Icon/shape based on type
        ctx.fillStyle = color;
        if (node.type === 'process') {
            // Draw process icon (small square)
            const s = r * 0.4;
            ctx.fillRect(node.x - s, node.y - s, s * 2, s * 2);
        } else if (node.type === 'network') {
            // Draw network icon (diamond)
            ctx.beginPath();
            const d = r * 0.5;
            ctx.moveTo(node.x, node.y - d);
            ctx.lineTo(node.x + d, node.y);
            ctx.lineTo(node.x, node.y + d);
            ctx.lineTo(node.x - d, node.y);
            ctx.closePath();
            ctx.fill();
        } else if (node.type === 'dns') {
            // Dot
            ctx.beginPath();
            ctx.arc(node.x, node.y, r * 0.35, 0, Math.PI * 2);
            ctx.fill();
        } else if (node.type === 'pipe') {
            // Pipe: a short horizontal bar
            ctx.fillRect(node.x - r * 0.5, node.y - r * 0.15, r, r * 0.3);
        } else {
            // Small triangle for file/registry
            ctx.beginPath();
            const t = r * 0.4;
            ctx.moveTo(node.x, node.y - t);
            ctx.lineTo(node.x + t, node.y + t);
            ctx.lineTo(node.x - t, node.y + t);
            ctx.closePath();
            ctx.fill();
        }

        // Label
        ctx.font = `${node.type === 'process' ? '10' : '8'}px monospace`;
        ctx.fillStyle = themeColor(isHovered ? '--c-white' : '--text-secondary');
        ctx.textAlign = 'center';
        ctx.textBaseline = 'top';
        const labelY = node.y + r + 4;
        ctx.fillText(node.label.length > 20 ? node.label.substring(0, 18) + '..' : node.label, node.x, labelY);

        // Threat count badge
        if (node.type === 'process' && node.threats > 0) {
            const bx = node.x + r * 0.7;
            const by = node.y - r * 0.7;
            ctx.beginPath();
            ctx.arc(bx, by, 7, 0, Math.PI * 2);
            ctx.fillStyle = themeColor('--accent-red');
            ctx.fill();
            ctx.font = 'bold 7px monospace';
            ctx.fillStyle = themeColor('--c-white');
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillText(String(node.threats), bx, by);
        }

        // Scan verdict indicator (bottom-left): matched EMBER/capa/TC/DC result
        if (node.type === 'process' && node.scans && node.scans.length) {
            const vColors = { malicious: '--accent-red', detected: '--accent-red',
                              clean: '--c-green-400', analyzed: '--c-sky-400', unknown: '--text-muted' };
            const vc = themeColor(vColors[node.scanVerdict] || '--text-muted');
            const sbx = node.x - r * 0.7;
            const sby = node.y + r * 0.7;
            ctx.beginPath();
            ctx.arc(sbx, sby, 6, 0, Math.PI * 2);
            ctx.fillStyle = vc;
            ctx.fill();
            ctx.strokeStyle = themeColor('--c-navy-950');
            ctx.lineWidth = 1.5;
            ctx.stroke();
            ctx.font = 'bold 7px monospace';
            ctx.fillStyle = themeColor('--c-navy-950');
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillText('S', sbx, sby);
        }

        // FOCUS badge for the root node
        if (node.isRoot) {
            ctx.font = 'bold 8px monospace';
            ctx.textAlign = 'center';
            ctx.textBaseline = 'bottom';
            const badgeY = node.y - r - 8;
            const text = 'FOCUS';
            const tw = ctx.measureText(text).width;
            ctx.fillStyle = themeColor('--c-sky-400');
            ctx.fillRect(node.x - tw / 2 - 4, badgeY - 11, tw + 8, 12);
            ctx.fillStyle = themeColor('--c-navy-950');
            ctx.fillText(text, node.x, badgeY);
        }

        ctx.globalAlpha = 1;
    });

    ctx.restore();
}

function showGraphTooltip(node, sx, sy) {
    const tooltip = document.getElementById('graph-tooltip');
    if (!tooltip) return;
    if (!node) { hideGraphTooltip(); return; }

    let html = `<div class="tt-title">${escapeHtml(node.label)}</div>`;
    if (node.type === 'process') {
        html += `<div class="tt-field"><span>PID:</span> ${escapeHtml(String(node.pid))}</div>`;
        if (node.image) html += `<div class="tt-field"><span>Image:</span> ${escapeHtml(node.image)}</div>`;
        if (node.threats) html += `<div class="tt-field"><span>Threats:</span> ${escapeHtml(String(node.threats))}</div>`;
        if (node.scans && node.scans.length) {
            const vm = _VERDICT_META[node.scanVerdict] || _VERDICT_META.unknown;
            html += `<div class="tt-field"><span>Scan:</span> ${escapeHtml(vm.text)} (${node.scans.length})</div>`;
        }
    } else if (node.type === 'network') {
        html += `<div class="tt-field"><span>IP:</span> ${escapeHtml(node.ip)}:${escapeHtml(String(node.port ?? ''))}</div>`;
        html += `<div class="tt-field"><span>Protocol:</span> ${escapeHtml(node.protocol || 'tcp')}</div>`;
    } else if (node.type === 'dns') {
        html += `<div class="tt-field"><span>Query:</span> ${escapeHtml(node.label)}</div>`;
        if (node.result) html += `<div class="tt-field"><span>Result:</span> ${escapeHtml(node.result)}</div>`;
    } else if (node.type === 'file') {
        html += `<div class="tt-field"><span>Path:</span> ${escapeHtml(node.fullPath || node.label)}</div>`;
    } else if (node.type === 'registry') {
        html += `<div class="tt-field"><span>Key:</span> ${escapeHtml(node.fullPath || node.label)}</div>`;
    } else if (node.type === 'pipe') {
        if (node.family) html += `<div class="tt-field"><span>Family:</span> ${escapeHtml(node.family)}</div>`;
        html += `<div class="tt-field"><span>Created by:</span> ${escapeHtml(String((node.createdBy || []).length))} · <span>connected:</span> ${escapeHtml(String((node.connectedBy || []).length))}</div>`;
    }

    tooltip.innerHTML = html;
    tooltip.style.display = 'block';
    tooltip.style.left = (sx + 16) + 'px';
    tooltip.style.top = (sy - 10) + 'px';
}

function hideGraphTooltip() {
    const tooltip = document.getElementById('graph-tooltip');
    if (tooltip) tooltip.style.display = 'none';
}

// Check the Authenticode signature of a process image from the graph detail panel.
// Reuses renderSignature() from the PE-analysis view (shared .pe-sig-* markup).
async function graphCheckSignature(path) {
    const sigBody = document.getElementById('gd-sig-body');
    if (!sigBody) return;
    if (!path) { sigBody.innerHTML = '<div class="pe-error">No image path for this process.</div>'; return; }
    sigBody.innerHTML = '<div class="pe-loading"><div class="loading-spinner"></div><span>Verifying signature...</span></div>';
    try {
        LoadingSpinner.start();
        const resp = await fetch(`/api/file/signature?path=${encodeURIComponent(path)}`);
        const data = await resp.json();
        LoadingSpinner.stop();
        if (data.error) { sigBody.innerHTML = `<div class="pe-error">${escapeHtml(data.error)}</div>`; return; }
        sigBody.innerHTML = renderSignature(data);
    } catch (e) {
        LoadingSpinner.stop();
        sigBody.innerHTML = `<div class="pe-error">Failed: ${escapeHtml(e.message)}</div>`;
    }
}

async function loadGraphSysmonSections(node) {
    const pidStr = String(node.pid);
    const keyStr = String(node.key);
    // Only this instance's lifetime: before it started, and after another
    // process took over the PID, the events belong to other processes.
    const since = {};
    const start = node.started || (node.supersededAt ? node.firstSeen : '');
    if (start) since.since = start;
    if (node.supersededAt) since.until = node.supersededAt;
    const get = (params) => fetch(`/api/sysmon?${new URLSearchParams(params)}`)
        .then(r => (r.ok ? r.json() : []))
        .then(d => (Array.isArray(d) ? d.filter(e => e && !e.error) : []))
        .catch(() => []);
    const [own, children] = await Promise.all([
        get({ pid: pidStr, max: 500, ...since }),
        get({ parent_pid: pidStr, event_id: '1', max: 200, ...since }),
    ]);
    const target = document.getElementById('gd-sysmon-sections');
    // The user may have selected another node while this was loading.
    if (!target || target.dataset.pid !== keyStr) return;
    target.innerHTML = renderGraphSysmonSections(pidStr, own, children);
}

function renderGraphSysmonSections(pidStr, pidSysmonEvents, childEvents) {
    let html = '';
    if (pidSysmonEvents.length) {
        const eidCounts = {};
        pidSysmonEvents.forEach(ev => {
            const eid = ev.event_id;
            if (!eidCounts[eid]) eidCounts[eid] = { count: 0, type: ev.type || `Event_${eid}` };
            eidCounts[eid].count++;
        });

        html += `<div class="gd-section">Triggered Sysmon Events <span class="gd-count">${pidSysmonEvents.length}</span></div>`;
        html += `<div class="gd-eid-grid">`;
        for (const [eid, info] of Object.entries(eidCounts).sort((a, b) => b[1].count - a[1].count)) {
            const typeClass = getSysmonTypeClass(eid);
            html += `<div class="gd-eid-item"><span class="type-badge ${typeClass}">EID ${escapeHtml(String(eid))}</span><span class="gd-eid-name">${escapeHtml(info.type)}</span><span class="gd-eid-count">${info.count}x</span></div>`;
        }
        html += `</div>`;

        const allWinEids = new Map();
        for (const eid of Object.keys(eidCounts)) {
            getCorrelatedWindowsEvents(parseInt(eid)).forEach(c => {
                if (!allWinEids.has(c.id)) allWinEids.set(c.id, c);
            });
        }
        if (allWinEids.size) {
            html += `<div class="gd-section">Correlated Windows Event IDs <span class="gd-count">${allWinEids.size}</span></div>`;
            html += `<div class="gd-eid-grid">`;
            for (const [weid, info] of allWinEids) {
                html += `<div class="gd-eid-item"><span class="corr-badge">${escapeHtml(String(weid))}</span><span class="gd-eid-name">${escapeHtml(info.name)}</span><span class="gd-eid-log">[${escapeHtml(info.log)}]</span></div>`;
            }
            html += `</div>`;
        }
    }

    // PowerShell started by this process, or this process itself if it is PowerShell
    const psEvents = pidSysmonEvents.concat(childEvents).filter(ev => {
        if (Number(ev.event_id) !== 1) return false;
        const img = (ev.image || '').toLowerCase();
        const cmd = (ev.commandline || '').toLowerCase();
        return (img.includes('powershell') || img.includes('pwsh') || cmd.includes('powershell')) &&
               (String(ev.pid) === pidStr || String(ev.parent_pid) === pidStr);
    });
    if (psEvents.length) {
        html += `<div class="gd-section">PowerShell Commands <span class="gd-count">${psEvents.length}</span></div>`;
        html += `<div class="gd-ps-list">`;
        psEvents.forEach(ev => {
            const time = ev.timestamp ? formatSysmonTime(ev.timestamp) : '';
            html += `<div class="gd-ps-item"><span class="gd-ps-time">${escapeHtml(time)}</span><span class="gd-ps-cmd">${escapeHtml(ev.commandline || '')}</span></div>`;
        });
        html += `</div>`;
    }
    return html;
}

// --- ACTIVITY MIX of a process node ---
// The detail of a process node shows, under its Activity grid (its alerts by
// category), what the process did by Sysmon in the graph data of
// /api/process-graph: a donut of its network connections, DNS queries,
// files created, registry changes, named pipe events and the injections it
// made, beside its legend; its alerts (Threats) are a number of their own
// under it, no part of the ring, which would count them a second time. The
// table view lists the same numbers. The kinds in the order of the ring, each
// with the list of the payload that holds its entries and the colour of its
// nodes (or, for an injection, its edge) in the graph.
const ACTIVITY_MIX_KINDS = [
    { key: 'network', label: 'Network', list: 'network', color: 'var(--graph-network)' },
    { key: 'dns', label: 'DNS', list: 'dns', color: 'var(--graph-dns)' },
    { key: 'file', label: 'File', list: 'files', color: 'var(--graph-file)' },
    { key: 'registry', label: 'Registry', list: 'registry', color: 'var(--graph-registry)' },
    { key: 'pipe', label: 'Named pipes', list: 'pipes', color: 'var(--graph-pipe)' },
    { key: 'injection', label: 'Injection', list: 'injections', color: 'var(--accent-red)' },
];

// The Sysmon activity of one process instance (its key, "1112" or
// "1112@1789000000") in a /api/process-graph payload: [{key, label, value,
// color}] for each kind it has entries of, in the order of ACTIVITY_MIX_KINDS.
// An entry belongs to the instance of its key (to its PID where it has none),
// as the graph draws its edge; an injection to the instance that made it.
// Another process that had the same PID counts apart.
function activityMix(payload, key) {
    const own = String(key ?? '');
    if (!own || !payload || typeof payload !== 'object') return [];
    const ownerOf = (kind, ev) => String((kind === 'injection' ? ev.source_key || ev.source_pid : ev.key || ev.pid) ?? '');
    return ACTIVITY_MIX_KINDS.map(({ key: kind, label, list, color }) => ({
        key: kind, label, color,
        value: (Array.isArray(payload[list]) ? payload[list] : []).filter(ev => ev && typeof ev === 'object' && ownerOf(kind, ev) === own).length,
    })).filter(item => item.value > 0);
}

// ACTIVITY MIX of a process node, for its detail (showGraphDetail): the head
// with its (i) and CHART / TABLE, the donut beside its legend (or why there
// is none) and the table view, then the node's alerts as a number
function graphActivityMixHtml(node) {
    const id = 'graph-activity-mix';
    const items = activityMix(graphState.data, node?.key);
    const empty = items.length ? '' : 'No Sysmon activity for this process';
    const threats = Number(node?.activity?.threats) || 0;
    const chart = empty ? chartEmptyHtml(empty)
        : `<div class="chart-split">${donutSvg(items, { size: 92, thickness: 14, centerSub: 'EVENTS' })}${chartLegendHtml(items)}</div>`;
    return `<div class="gd-mix" id="${id}">`
        + `<div class="gd-section gd-mix-head"><span class="gd-mix-title" data-info="What this process did by Sysmon in the data of the graph (network, DNS, files, registry, named pipes, the injections it made), apart from other processes that had its PID. Threats are its alerts, which the grid above counts by category; they are not part of the ring.">ACTIVITY MIX</span>${viewToggleHtml(id)}</div>`
        + `<div class="gd-mix-view"${cardViewAttrs(id, 'chart')}>${chart}</div>`
        + `<div class="view-table-wrap gd-mix-table"${cardViewAttrs(id, 'table')}>`
        + `${_alertsShareTableHtml('activity', items, empty, '<table class="view-table" data-sortable data-sort-id="graph-activity-mix">')}</div>`
        + `<div class="gd-mix-threats${threats > 0 ? ' has-threats' : ''}" title="The alerts of this process; the Activity grid counts them by category">`
        + `<span class="gd-mix-threats-label">Threats</span> <span class="gd-mix-threats-num">${_chartNumber(threats)}</span> `
        + '<span class="gd-mix-threats-note">&middot; alerts, not part of the ring</span></div></div>';
}

function showGraphDetail(node) {
    const panel = document.getElementById('graph-detail-panel');
    const header = document.getElementById('graph-detail-header');
    const body = document.getElementById('graph-detail-body');
    if (!panel || !header || !body) return;

    panel.classList.add('visible');
    let headerText = '';
    let html = '';

    if (node.type === 'process') {
        headerText = `${node.label} (PID ${node.pid})`;
        if (!node.isRoot) {
            html += `<div class="gd-actions"><button class="gd-focus-btn" data-focus-pid="${escapeHtml(String(node.key))}">&#9673; Focus this process</button></div>`;
        } else {
            html += `<div class="gd-actions"><span class="gd-focus-current">&#9673; Current focus root</span></div>`;
        }
        html += `<div class="gd-field"><span class="gd-label">Image</span><span class="gd-value">${escapeHtml(node.image)}</span></div>`;
        if (node.cmdline) html += `<div class="gd-field"><span class="gd-label">Cmdline</span><span class="gd-value gd-cmdline">${escapeHtml(node.cmdline)}</span></div>`;
        if (node.user) html += `<div class="gd-field"><span class="gd-label">User</span><span class="gd-value">${escapeHtml(node.user)}</span></div>`;
        html += `<div class="gd-field"><span class="gd-label">Status</span><span class="gd-value">${node.exited ? '<span style="color:var(--text-secondary)">Exited</span>' : '<span style="color:var(--c-green-400)">Running</span>'}</span></div>`;
        html += `<div class="gd-field"><span class="gd-label">First seen</span><span class="gd-value">${escapeHtml(node.firstSeen || '--')}</span></div>`;
        if (node.parentPid) {
            const parentNode = graphState.nodes.find(n => n.type === 'process' && String(n.key) === String(node.parentPid));
            if (parentNode) {
                html += `<div class="gd-field"><span class="gd-label">Parent</span><span class="gd-value"><a class="gd-link" data-node-id="${escapeHtml(parentNode.id)}">${escapeHtml(parentNode.label)} (${escapeHtml(parentNode.pid)})</a></span></div>`;
            } else {
                html += `<div class="gd-field"><span class="gd-label">Parent PID</span><span class="gd-value">${escapeHtml(String(node.parentOsPid ?? node.parentPid))}</span></div>`;
            }
        }

        // Activity summary
        const act = node.activity || {};
        const totalActivity = (act.threats||0) + (act.network||0) + (act.dns||0) + (act.file||0) + (act.registry||0);
        html += `<div class="gd-section">Activity <span class="gd-count">${totalActivity} events</span></div>`;
        html += `<div class="gd-activity-grid">`;
        html += `<div class="gd-activity-cell ${(act.threats||0) > 0 ? 'critical' : ''}"><span class="gd-act-num">${act.threats || 0}</span><span class="gd-act-label">Threats</span></div>`;
        html += `<div class="gd-activity-cell"><span class="gd-act-num">${act.network || 0}</span><span class="gd-act-label">Network</span></div>`;
        html += `<div class="gd-activity-cell"><span class="gd-act-num">${act.dns || 0}</span><span class="gd-act-label">DNS</span></div>`;
        html += `<div class="gd-activity-cell"><span class="gd-act-num">${act.file || 0}</span><span class="gd-act-label">File</span></div>`;
        html += `<div class="gd-activity-cell"><span class="gd-act-num">${act.registry || 0}</span><span class="gd-act-label">Registry</span></div>`;
        html += `<div class="gd-activity-cell"><span class="gd-act-num">${act.injection || 0}</span><span class="gd-act-label">Injection</span></div>`;
        html += `</div>`;
        // What the process did by Sysmon, its alerts beside it
        html += graphActivityMixHtml(node);

        // Digital signature (on-demand: signer verification runs Get-AuthenticodeSignature)
        if (node.image) {
            html += `<div class="gd-section">Digital Signature</div>`;
            html += `<div class="gd-sig-body" id="gd-sig-body"><button class="gd-sig-btn" data-sig-path="${escapeHtml(node.image)}">&#128273; Check who signed this</button></div>`;
        }

        // Static-analysis verdicts matched to this image by SHA256
        if (node.scans && node.scans.length) {
            html += renderGraphScans(node.scans);
        }

        // Connections from this node
        const connections = graphState.edges.filter(e => e.source === node.id || e.target === node.id);
        const netConns = connections.filter(e => e.type === 'network');
        const dnsConns = connections.filter(e => e.type === 'dns');

        // Children tree - recursive with details
        const childConns = connections.filter(e => e.type === 'spawn' && e.source === node.id);
        if (childConns.length) {
            html += `<div class="gd-section">Children Processes <span class="gd-count">${childConns.length}</span></div>`;
            html += buildChildrenTree(node.id, 0);
        }

        if (netConns.length) {
            html += `<div class="gd-section">Network Connections <span class="gd-count">${netConns.length}</span></div>`;
            html += `<div class="gd-conn-list">`;
            netConns.forEach(e => {
                const target = graphState.nodes.find(n => n.id === e.target);
                if (target) html += `<div class="gd-conn-item"><span class="gd-conn-icon net"></span><span class="gd-conn-text">${escapeHtml(target.ip || target.label)}:${escapeHtml(String(target.port || ''))}</span><span class="gd-conn-proto">${escapeHtml(target.protocol || 'tcp')}</span></div>`;
            });
            html += `</div>`;
        }

        const pipeConns = connections.filter(e => (e.type === 'pipe-create' || e.type === 'pipe-connect') && e.source === node.id);
        if (pipeConns.length) {
            html += `<div class="gd-section">Named Pipes <span class="gd-count">${pipeConns.length}</span></div>`;
            html += `<div class="gd-conn-list">`;
            pipeConns.forEach(e => {
                const target = graphState.nodes.find(n => n.id === e.target);
                if (target) html += `<div class="gd-conn-item"><span class="gd-conn-icon pipe"></span><a class="gd-link gd-conn-text" data-node-id="${escapeHtml(target.id)}">${escapeHtml(target.label)}</a><span class="gd-conn-proto">${e.type === 'pipe-create' ? 'created' : 'connected'}${target.family ? ' · ' + escapeHtml(target.family) : ''}</span></div>`;
            });
            html += `</div>`;
        }

        if (dnsConns.length) {
            html += `<div class="gd-section">DNS Queries <span class="gd-count">${dnsConns.length}</span></div>`;
            html += `<div class="gd-conn-list">`;
            dnsConns.forEach(e => {
                const target = graphState.nodes.find(n => n.id === e.target);
                if (target) html += `<div class="gd-conn-item"><span class="gd-conn-icon dns"></span><span class="gd-conn-text">${escapeHtml(target.label)}</span>${target.result ? `<span class="gd-conn-proto">${escapeHtml(target.result)}</span>` : ''}</div>`;
            });
            html += `</div>`;
        }

        // Sysmon events of this process and PowerShell children. They were
        // read from graphState._allSysmonEvents, which nothing ever filled, so
        // these sections never appeared; they are now loaded per process.
        html += `<div id="gd-sysmon-sections" data-pid="${escapeHtml(String(node.key))}"><div class="gd-section">Triggered Sysmon Events <span class="gd-count">…</span></div></div>`;

    } else if (node.type === 'network') {
        headerText = `Network: ${node.ip}:${node.port}`;
        html += `<div class="gd-field"><span class="gd-label">IP</span><span class="gd-value">${escapeHtml(node.ip)}</span></div>`;
        html += `<div class="gd-field"><span class="gd-label">Port</span><span class="gd-value">${escapeHtml(String(node.port ?? ''))}</span></div>`;
        html += `<div class="gd-field"><span class="gd-label">Protocol</span><span class="gd-value">${escapeHtml(node.protocol || 'tcp')}</span></div>`;
        const conns = graphState.edges.filter(e => e.target === node.id);
        if (conns.length) {
            html += `<div class="gd-section">Connected from <span class="gd-count">${conns.length}</span></div>`;
            conns.forEach(e => {
                const src = graphState.nodes.find(n => n.id === e.source);
                if (src) html += `<div class="gd-conn-item"><span class="gd-conn-icon proc"></span><a class="gd-link" data-node-id="${escapeHtml(src.id)}">${escapeHtml(src.label)} (${escapeHtml(String(src.pid ?? ''))})</a></div>`;
            });
        }
    } else if (node.type === 'dns') {
        headerText = `DNS: ${node.label}`;
        html += `<div class="gd-field"><span class="gd-label">Query</span><span class="gd-value">${escapeHtml(node.label)}</span></div>`;
        if (node.result) html += `<div class="gd-field"><span class="gd-label">Result</span><span class="gd-value">${escapeHtml(node.result)}</span></div>`;
        const conns = graphState.edges.filter(e => e.target === node.id);
        if (conns.length) {
            html += `<div class="gd-section">Queried by <span class="gd-count">${conns.length}</span></div>`;
            conns.forEach(e => {
                const src = graphState.nodes.find(n => n.id === e.source);
                if (src) html += `<div class="gd-conn-item"><span class="gd-conn-icon proc"></span><a class="gd-link" data-node-id="${escapeHtml(src.id)}">${escapeHtml(src.label)} (${escapeHtml(String(src.pid ?? ''))})</a></div>`;
            });
        }
    } else if (node.type === 'pipe') {
        headerText = `Pipe: ${node.label}`;
        html += `<div class="gd-field"><span class="gd-label">Name</span><span class="gd-value">${escapeHtml(node.label)}</span></div>`;
        if (node.family) html += `<div class="gd-field"><span class="gd-label">Family</span><span class="gd-value"><span class="pipe-family">${escapeHtml(node.family)}</span></span></div>`;
        const procLink = key => {
            const src = graphState.nodes.find(n => n.id === `proc_${key}`);
            return src ? `<div class="gd-conn-item"><span class="gd-conn-icon proc"></span><a class="gd-link" data-node-id="${escapeHtml(src.id)}">${escapeHtml(src.label)} (${escapeHtml(String(src.pid ?? ''))})</a></div>` : '';
        };
        if ((node.createdBy || []).length) {
            html += `<div class="gd-section">Created by <span class="gd-count">${node.createdBy.length}</span></div>`;
            html += node.createdBy.map(procLink).join('');
        }
        if ((node.connectedBy || []).length) {
            html += `<div class="gd-section">Connected by <span class="gd-count">${node.connectedBy.length}</span></div>`;
            html += node.connectedBy.map(procLink).join('');
        }
        html += `<div class="gd-actions"><button class="gd-focus-btn" data-pipe-name="${escapeHtml(node.label)}">Intercept in Pipes tab</button></div>`;
    } else {
        headerText = `${node.type}: ${node.label}`;
        if (node.fullPath) html += `<div class="gd-field"><span class="gd-label">Path</span><span class="gd-value">${escapeHtml(node.fullPath)}</span></div>`;
    }

    header.textContent = headerText;
    body.innerHTML = html;
    if (node.type === 'process' && node.pid != null) loadGraphSysmonSections(node);

    const pipeBtn = body.querySelector('.gd-focus-btn[data-pipe-name]');
    if (pipeBtn) pipeBtn.addEventListener('click', () => pipesInterceptFrom(pipeBtn.dataset.pipeName));

    // Re-root the drilldown on the selected process
    const focusBtn = body.querySelector('.gd-focus-btn[data-focus-pid]');
    if (focusBtn) {
        focusBtn.addEventListener('click', () => focusProcessGraph(focusBtn.dataset.focusPid));
    }

    // Check who signed this process's image (Authenticode)
    const sigBtn = body.querySelector('.gd-sig-btn[data-sig-path]');
    if (sigBtn) {
        sigBtn.addEventListener('click', () => graphCheckSignature(sigBtn.dataset.sigPath));
    }

    // Wire up clickable links in the detail panel
    body.querySelectorAll('.gd-link[data-node-id]').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const targetNode = graphState.nodes.find(n => n.id === link.dataset.nodeId);
            if (targetNode) {
                graphState.selectedNode = targetNode;
                showGraphDetail(targetNode);
                renderGraph();
            }
        });
    });

    // Wire up collapsible child entries
    body.querySelectorAll('.gd-child-header').forEach(hdr => {
        hdr.addEventListener('click', () => {
            const entry = hdr.closest('.gd-child-entry');
            if (entry) entry.classList.toggle('expanded');
        });
    });

    // Wire up "focus" links to navigate to a child node in the graph
    body.querySelectorAll('.gd-child-focus[data-node-id]').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            const targetNode = graphState.nodes.find(n => n.id === btn.dataset.nodeId);
            if (targetNode) {
                graphState.selectedNode = targetNode;
                showGraphDetail(targetNode);
                renderGraph();
            }
        });
    });
}

function buildChildrenTree(parentNodeId, depth) {
    if (depth > 4) return '<div class="gd-child-truncated">... (depth limit)</div>';
    const childEdges = graphState.edges.filter(e => e.type === 'spawn' && e.source === parentNodeId);
    if (!childEdges.length) return '';

    let html = `<div class="gd-children-tree depth-${depth}">`;
    childEdges.forEach(e => {
        const child = graphState.nodes.find(n => n.id === e.target);
        if (!child) return;
        const act = child.activity || {};
        const threats = act.threats || 0;
        const severityClass = threats > 0 ? (child.severity === 'critical' ? 'critical' : 'high') : '';
        const grandchildEdges = graphState.edges.filter(gc => gc.type === 'spawn' && gc.source === child.id);
        const hasChildren = grandchildEdges.length > 0;

        html += `<div class="gd-child-entry ${severityClass}">`;
        html += `<div class="gd-child-header">`;
        html += `<span class="gd-child-expand">${hasChildren ? '&#9654;' : '&#8226;'}</span>`;
        html += `<span class="gd-child-name">${escapeHtml(child.label)}</span>`;
        html += `<span class="gd-child-pid">PID ${escapeHtml(String(child.pid))}</span>`;
        if (threats > 0) html += `<span class="gd-child-threats">${threats}</span>`;
        html += `<span class="gd-child-focus" data-node-id="${escapeHtml(child.id)}" title="Focus this node">&#8599;</span>`;
        html += `</div>`;

        // Collapsible detail body
        html += `<div class="gd-child-body">`;
        if (child.image) html += `<div class="gd-child-detail"><span class="gd-child-dlabel">Image:</span> ${escapeHtml(child.image)}</div>`;
        if (child.cmdline) html += `<div class="gd-child-detail gd-cmdline"><span class="gd-child-dlabel">Cmd:</span> ${escapeHtml(child.cmdline)}</div>`;
        html += `<div class="gd-child-detail"><span class="gd-child-dlabel">Status:</span> ${child.exited ? 'Exited' : 'Running'}</div>`;
        if (child.firstSeen) html += `<div class="gd-child-detail"><span class="gd-child-dlabel">First seen:</span> ${escapeHtml(child.firstSeen)}</div>`;

        // Activity mini-summary
        const actTotal = (act.network||0) + (act.dns||0) + (act.file||0) + (act.registry||0);
        if (actTotal > 0 || threats > 0) {
            html += `<div class="gd-child-activity">`;
            if (threats > 0) html += `<span class="gd-mini-badge threat">${threats} threats</span>`;
            if (act.network > 0) html += `<span class="gd-mini-badge net">${act.network} net</span>`;
            if (act.dns > 0) html += `<span class="gd-mini-badge dns">${act.dns} dns</span>`;
            if (act.file > 0) html += `<span class="gd-mini-badge file">${act.file} file</span>`;
            if (act.registry > 0) html += `<span class="gd-mini-badge reg">${act.registry} reg</span>`;
            html += `</div>`;
        }

        // Recurse into grandchildren
        if (hasChildren) {
            html += buildChildrenTree(child.id, depth + 1);
        }
        html += `</div>`; // .gd-child-body
        html += `</div>`; // .gd-child-entry
    });
    html += `</div>`;
    return html;
}

function hideGraphDetail() {
    const panel = document.getElementById('graph-detail-panel');
    if (panel) panel.classList.remove('visible');
}

function initGraphControls() {
    // Activity toggles re-render the current focus subtree
    ['graph-show-network', 'graph-show-dns', 'graph-show-files', 'graph-show-registry', 'graph-show-pipes'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.addEventListener('change', () => { if (state.activeTab === 'graph' && graphState.focusPid) graphRefresh(); });
    });
    const layoutEl = document.getElementById('graph-layout');
    if (layoutEl) layoutEl.addEventListener('change', () => { if (state.activeTab === 'graph' && graphState.focusPid) graphRefresh(); });

    // Descendant depth control (0 = all, capped server-side)
    const depthEl = document.getElementById('graph-depth');
    if (depthEl) depthEl.addEventListener('change', () => {
        graphState.downDepth = parseInt(depthEl.value) || 0;
        if (state.activeTab === 'graph' && graphState.focusPid) graphRefresh();
    });

    // Focus field: Enter/Go submits (PID -> focus, text -> filtered landing);
    // clearing the field returns to the landing picker.
    const searchInput = document.getElementById('graph-search');
    const searchClear = document.getElementById('graph-search-clear');
    if (searchInput) {
        searchInput.addEventListener('input', () => {
            const val = searchInput.value.trim();
            if (searchClear) searchClear.classList.toggle('visible', val.length > 0);
            // Live-filter the landing picker while no focus is set.
            if (state.activeTab === 'graph' && !graphState.focusPid) renderGraphLanding();
        });
        searchInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                graphSubmitFocus();
            } else if (e.key === 'Escape') {
                searchInput.value = '';
                if (searchClear) searchClear.classList.remove('visible');
                graphState.focusPid = null;
                if (state.activeTab === 'graph') graphRefresh();
            }
        });
    }
    if (searchClear) {
        searchClear.addEventListener('click', () => {
            if (searchInput) searchInput.value = '';
            searchClear.classList.remove('visible');
            graphState.focusPid = null;
            if (state.activeTab === 'graph') graphRefresh();
        });
    }
    const focusGo = document.getElementById('graph-focus-go');
    if (focusGo) focusGo.addEventListener('click', () => graphSubmitFocus());
}

// --- Sysmon Events Tab ---
// The newest Sysmon events (/api/sysmon, as many as chosen; the type, EID
// and PID filters ask the server) in one table, newest first, filtered
// further in the page by the search and the EID filters. Above the filter
// bar, EVENTS OVER TIME and PROCESS → EVENT TYPE count the events the table
// lists (renderSysmonCharts): a bar sets a time window, a node or band an
// image or an event type, each a chip in the filter bar whose × takes it
// off. The tab scrolls as a whole, the filter bar stands at its top.
let sysmonEvents = [];
let sysmonStats = null;
// Why the last query brought no events (the server failed or was not
// reached), shown in place of the table; '' when it brought some
let sysmonLoadError = '';
// The time window of a bar: epoch ms, from included and to not, null for
// none. Only the table takes it: the charts count every event of the other
// filters, so they still show where else to look.
const sysmonTimeWindow = { from: null, to: null };
// The image and the event type a node, a band or a legend row set; null = none
const sysmonFlowFilter = { image: null, type: null };
// {key, chips} of the rendered table: the filters it lists, the chart filters its chips show
let _sysmonTableShown = null;

async function refreshSysmon() {
    const eventType = document.getElementById('sysmon-filter-type')?.value || '';
    const eidFilterRaw = (document.getElementById('sysmon-filter-eid')?.value || '').trim();
    const pidFilter = document.getElementById('sysmon-filter-pid')?.value || '';
    const maxEvents = document.getElementById('sysmon-max-events')?.value || '100';

    let url = `/api/sysmon?max=${maxEvents}`;
    // Dropdown takes precedence; otherwise use the EID text input for server-side filter
    if (eventType) {
        url += `&event_id=${eventType}`;
    } else if (eidFilterRaw) {
        const eids = eidFilterRaw.split(',').map(s => s.trim()).filter(s => /^\d+$/.test(s));
        if (eids.length) url += `&event_id=${eids.join(',')}`;
    }
    if (pidFilter) url += `&pid=${pidFilter}`;

    // Show loading spinner while fetching
    const statsContainer = document.getElementById('sysmon-stats');
    const tableContainer = document.getElementById('sysmon-table');
    if (statsContainer && !sysmonStats) {
        statsContainer.innerHTML = '<div class="sysmon-loading"><div class="loading-spinner"></div><span>Loading Sysmon statistics...</span></div>';
    }
    if (tableContainer && !sysmonEvents.length) {
        tableContainer.innerHTML = '<div class="sysmon-loading"><div class="loading-spinner"></div><span>Querying Sysmon event log...</span></div>';
        renderSysmonCharts([], 'Loading Sysmon events…');
    }

    // Set once the events are in (or known to have failed): an error after that, of the statistics, keeps them
    let eventsDone = false;
    try {
        const [eventsResp, statsResp] = await Promise.all([
            fetch(url),
            fetch('/api/sysmon/stats'),
        ]);
        if (eventsResp.ok) {
            const events = await eventsResp.json();
            sysmonEvents = Array.isArray(events) ? events : [];
            sysmonLoadError = '';
            eventsDone = true;
            // Check if the response contains an error from backend retries
            if (sysmonEvents.length === 1 && sysmonEvents[0]?.error) {
                showToast('warning', 'Sysmon query issue', sysmonEvents[0].error, 6000);
            }
            _sysmonKeepWindow(sysmonEvents);
            renderSysmonTable();
        } else {
            // No events held: the tab asks again when it is opened
            sysmonEvents = [];
            sysmonLoadError = 'Failed to load Sysmon events.';
            eventsDone = true;
            if (tableContainer) showToast('error', 'Sysmon events failed', `Server returned ${eventsResp.status}`, 5000);
            renderSysmonTable();
        }
        if (statsResp.ok) {
            sysmonStats = await statsResp.json();
            renderSysmonStats();
            // Toast if stats returned an error/diagnostic
            if (sysmonStats.error) {
                showToast('error', 'Sysmon stats error', sysmonStats.error, 6000);
            } else if (sysmonStats.diagnostic && !sysmonStats.online) {
                showToast('warning', 'Sysmon', sysmonStats.diagnostic, 5000);
            }
        }
    } catch (e) {
        console.error('Sysmon fetch error:', e);
        showToast('error', 'Sysmon unreachable', e.message || 'Connection failed', 6000);
        if (statsContainer) {
            statsContainer.innerHTML = `<div class="sysmon-diagnostic warning">Connection error: ${escapeHtml(e.message)}</div>`;
        }
        if (!eventsDone) {
            sysmonEvents = [];
            sysmonLoadError = `Connection error: ${e?.message ?? ''}`;
            renderSysmonTable();
        }
    }
}

function renderSysmonStats() {
    const container = document.getElementById('sysmon-stats');
    if (!container || !sysmonStats) return;

    // Show diagnostic message if present (log doesn't exist, is empty, etc.)
    if (sysmonStats.diagnostic) {
        const level = sysmonStats.online ? 'info' : 'warning';
        container.innerHTML = `<div class="sysmon-diagnostic ${level}">${escapeHtml(sysmonStats.diagnostic)}</div>`;
        return;
    }
    if (sysmonStats.error) {
        container.innerHTML = `<div class="sysmon-diagnostic error">Error: ${escapeHtml(sysmonStats.error)}</div>`;
        return;
    }
    if (!sysmonStats.stats || !sysmonStats.stats.length) {
        container.innerHTML = `<div class="sysmon-diagnostic info">No event statistics available.</div>`;
        return;
    }

    const stats = sysmonStats.stats;
    const total = stats.reduce((sum, s) => sum + s.count, 0);

    let html = `<div class="sysmon-stats-bar"><span class="stats-total">${total} events (last 500)</span>`;
    stats.sort((a, b) => b.count - a.count);
    stats.forEach(s => {
        const typeClass = getSysmonTypeClass(s.event_id);
        html += `<span class="stats-chip ${typeClass}" onclick="filterSysmonByType(${jsArg(s.event_id)})">${escapeHtml(s.name)} <strong>${s.count}</strong></span>`;
    });
    html += `</div>`;
    container.innerHTML = html;
}

function filterSysmonByType(eventId) {
    const select = document.getElementById('sysmon-filter-type');
    if (select) { select.value = eventId; refreshSysmon(); }
}

// The filters of the table: the search and the EID filters as typed, the
// image, the event type and the time window the charts set
function sysmonFilterFromControls() {
    return {
        text: document.getElementById('sysmon-search')?.value || '',
        eids: document.getElementById('sysmon-filter-eid')?.value || '',
        winEids: document.getElementById('sysmon-filter-wineid')?.value || '',
        ...sysmonFlowFilter, ...sysmonTimeWindow,
    };
}

// The events the filter lets through, in their order. filter = {text, eids,
// winEids, image, type, from, to}: the search in the event's fields in any
// case; Sysmon and correlated Windows event IDs as the EID filters take them
// ("1, 3, 11"); the image by its file name, as the table names it, and the
// event type, both in any case and without the blanks around them,
// "(unknown)" taking the events without one; the time window, `from`
// included and `to` not, as a bar of EVENTS OVER TIME counts (an event
// without a time is in none). A filter left empty does not filter.
function filterSysmonEvents(events, filter) {
    filter = filter || {};
    const text = String(filter.text || '').toLowerCase().trim();
    const ids = value => String(value || '').split(',').map(s => parseInt(s.trim(), 10)).filter(n => !isNaN(n));
    const eids = ids(filter.eids), winEids = ids(filter.winEids);
    const image = _alertsNameKey(filter.image), type = _alertsNameKey(filter.type);
    const from = _alertsTimeBound(filter.from), to = _alertsTimeBound(filter.to);
    return (events || []).filter(ev => {
        if (!ev) return false;
        if (eids.length && !eids.includes(ev.event_id)) return false;
        if (winEids.length && !getCorrelatedWindowsEvents(ev.event_id).some(c => winEids.includes(c.id))) return false;
        if (image && !_alertNameIs(sysmonImageName(ev), image)) return false;
        if (type && !_alertNameIs(String(ev.type ?? ''), type)) return false;
        if (text) {
            const haystack = [
                ev.image, ev.commandline, ev.type, ev.target, ev.query,
                ev.dst_ip, ev.dst_hostname, ev.loaded_image, ev.source_image,
                ev.target_image, ev.parent_image, ev.user, ev.hashes,
                String(ev.pid || ''), String(ev.event_id || ''),
                ev.details, ev.result
            ].filter(Boolean).join(' ').toLowerCase();
            if (!haystack.includes(text)) return false;
        }
        if (from === null && to === null) return true;
        // An event without a time (NaN) fails both comparisons: it is in no window
        const t = Date.parse(ev.timestamp);
        return t >= (from ?? -Infinity) && t < (to ?? Infinity);
    });
}

// An event's image by its file name, as the table shows it ('' if none)
function sysmonImageName(ev) {
    return String(ev?.image || '').split('\\').pop();
}

// An event's type without the blanks around it, "(unknown)" if it has none
function sysmonEventType(ev) {
    return String(ev?.type ?? '').trim() || '(unknown)';
}

function renderSysmonTable() {
    const container = document.getElementById('sysmon-table');
    if (!container) return;
    const filter = sysmonFilterFromControls();
    // The charts count the events of the filters but the time window
    const loaded = !!sysmonEvents?.length && !sysmonEvents[0]?.error;
    const shown = loaded ? filterSysmonEvents(sysmonEvents, { ...filter, from: null, to: null }) : [];
    renderSysmonCharts(shown);
    // The chips are written again only when the chart filters changed: a chip in focus keeps it
    const chips = JSON.stringify([sysmonTimeWindow, sysmonFlowFilter]);
    if (!_sysmonTableShown || _sysmonTableShown.chips !== chips) renderSysmonActiveFilters();
    // The same filters keep the place in the list. Other filters start at its top: with the filter bar
    // standing at the top of the tab, the first row right under it, so the bar stays under the pointer;
    // above that, nothing moves.
    const key = JSON.stringify([filter.text.toLowerCase().trim(), filter.eids.trim(), filter.winEids.trim(), chips]);
    const tab = document.getElementById('tab-sysmon');
    const scrollTop = tab ? tab.scrollTop : 0;
    container.innerHTML = _sysmonTableHtml(shown, filter);
    if (tab) {
        tab.scrollTop = _sysmonTableShown && _sysmonTableShown.key === key ? scrollTop
            : Math.min(scrollTop, _tabListTop(tab, tab.querySelector('.sysmon-filters'), container));
    }
    _sysmonTableShown = { key, chips };
}

// The table of the events of the filters (`shown`) in their time window, or
// why there is none
function _sysmonTableHtml(shown, filter) {
    if (!sysmonEvents || !sysmonEvents.length) {
        return `<div class="empty-state">${escapeHtml(sysmonLoadError || 'No Sysmon events found')}</div>`;
    }

    if (sysmonEvents[0]?.error) {
        return `<div class="empty-state">Error: ${escapeHtml(sysmonEvents[0].error)}</div>`;
    }

    const searchTerm = filter.text.toLowerCase().trim();
    const eidFilter = filter.eids.trim();
    const winEidFilter = filter.winEids.trim();
    const filtered = filterSysmonEvents(shown, { from: filter.from, to: filter.to });
    const chartFilters = [
        filter.from !== null && filter.to !== null && `time window ${_sysmonWindowLabel(filter.from, filter.to)}`,
        filter.image !== null && `image: ${filter.image}`, filter.type !== null && `type: ${filter.type}`,
    ].filter(Boolean);

    const hasAnyFilter = searchTerm || eidFilter || winEidFilter || chartFilters.length;
    if (!filtered.length) {
        const filterDesc = [searchTerm && `"${searchTerm}"`, eidFilter && `Sysmon EID: ${eidFilter}`, winEidFilter && `Win EID: ${winEidFilter}`,
                            ...chartFilters].filter(Boolean).join(', ');
        return `<div class="empty-state">No events matching ${escapeHtml(filterDesc)} (${sysmonEvents.length} total)</div>`;
    }

    const countInfo = hasAnyFilter ? ` <span class="sysmon-filter-count">(${filtered.length}/${sysmonEvents.length})</span>` : '';
    let html = `<table class="sysmon-events-table" data-sortable data-sort-id="sysmon-events"><thead><tr><th>Time</th><th>Type</th><th>PID</th><th>Image</th><th>Details</th><th class="col-corr">Win. EID</th></tr></thead><tbody>`;
    filtered.forEach(ev => {
        const typeClass = getSysmonTypeClass(String(ev.event_id));
        const time = ev.timestamp ? formatSysmonTime(ev.timestamp) : '';
        const image = ev.image ? ev.image.split('\\').pop() : '';
        const details = getSysmonDetails(ev);
        const correlated = getCorrelatedWindowsEvents(ev.event_id);
        const corrHtml = correlated.length > 0
            ? correlated.map(c => `<span class="corr-badge" title="${escapeHtml(c.name)}">${c.id}</span>`).join('')
            : '';
        // Look the event up by position: embedding the event as JSON in the
        // attribute duplicated every row's data and let an event field that
        // contains the text &quot; break out of the handler. The time shows the
        // clock only, so it sorts by its value (several days in one list).
        html += `<tr onclick="showSysmonDetailAt(${sysmonEvents.indexOf(ev)})">
            <td class="col-time" data-sort-value="${sortTimeValue(ev.timestamp)}">${time}</td>
            <td><span class="type-badge ${typeClass}">${escapeHtml(ev.type || '')}</span></td>
            <td class="col-pid">${escapeHtml(String(ev.pid || ''))}</td>
            <td class="col-image">${escapeHtml(image)}</td>
            <td class="col-details">${escapeHtml(details)}</td>
            <td class="col-corr" data-sort-value="${correlated.map(c => c.id).join(' ')}">${corrHtml}</td>
        </tr>`;
    });
    html += '</tbody></table>';
    if (hasAnyFilter) html = `<div class="sysmon-search-info">Showing ${filtered.length} of ${sysmonEvents.length} events${countInfo}</div>` + html;
    return html;
}

function getSysmonDetails(ev) {
    switch (ev.event_id) {
        case 1: return ev.commandline ? truncate(ev.commandline, 80) : '';
        case 3: return `${ev.dst_ip || ''}:${ev.dst_port || ''}`;
        case 5: return 'Process terminated';
        case 7: return ev.loaded_image ? ev.loaded_image.split('\\').pop() : '';
        case 11: return ev.target ? truncate(ev.target, 80) : '';
        case 22: return ev.query || '';
        default: return '';
    }
}

function getSysmonTypeClass(eventId) {
    const classes = { '1': 'type-process', '3': 'type-network', '5': 'type-terminate', '7': 'type-imageload', '8': 'type-injection', '10': 'type-access', '11': 'type-file', '12': 'type-registry', '13': 'type-registry', '22': 'type-dns' };
    return classes[eventId] || 'type-other';
}

function formatSysmonTime(isoStr) {
    // hourCycle h23: with `hour12: false`, older ICU builds print midnight as "24:00:02".
    try { const d = new Date(isoStr); return d.toLocaleTimeString('en-US', { hourCycle: 'h23' }) + '.' + String(d.getMilliseconds()).padStart(3, '0'); } catch { return isoStr; }
}

function truncate(str, max) {
    return str && str.length > max ? str.substring(0, max) + '...' : (str || '');
}

function showSysmonDetailAt(idx) {
    const ev = sysmonEvents[idx];
    if (ev) showSysmonDetail(ev);
}

function showSysmonDetail(ev) {
    let html = `<div class="detail-section"><div class="detail-section-title">${escapeHtml(ev.type || 'Event')} - PID ${escapeHtml(String(ev.pid || '?'))}</div>
        <div class="detail-fields">
            <div class="detail-field"><span class="field-label">Timestamp</span><span class="field-value">${escapeHtml(ev.timestamp || '')}</span></div>
            <div class="detail-field"><span class="field-label">Event ID</span><span class="field-value">${ev.event_id}</span></div>
            <div class="detail-field"><span class="field-label">PID</span><span class="field-value">${escapeHtml(String(ev.pid || ''))}</span></div>
            <div class="detail-field"><span class="field-label">Image</span><span class="field-value">${escapeHtml(ev.image || '')}</span></div>
        </div></div>`;

    // Show correlated Windows Event IDs
    const correlated = getCorrelatedWindowsEvents(ev.event_id);
    if (correlated.length > 0) {
        html += `<div class="detail-section"><div class="detail-section-title">Correlated Windows Events</div><div class="detail-corr-list">`;
        correlated.forEach(c => {
            html += `<div class="detail-corr-item"><span class="corr-eid">${c.id}</span><span class="corr-name">${escapeHtml(c.name)}</span><span class="corr-log">${escapeHtml(c.log)}</span></div>`;
        });
        html += `</div></div>`;
    }

    setDetailHeader('Sysmon', 'background:rgba(var(--accent-green-rgb), 0.15);color:var(--accent-green)', ev.type || 'Event', '');
    setDetailBody(html);
    showDetail();
}

/** Local client-side search filter (instant, no API call) */
function filterSysmonLocal() {
    renderSysmonTable();
}

/**
 * Sysmon Event ID <-> Windows Event ID Correlation Map.
 * Maps Sysmon events to related standard Windows security/system events.
 */
const SYSMON_WINDOWS_CORRELATION = {
    1: [ // ProcessCreate
        {id: 4688, name: 'Process Creation', log: 'Security'},
        {id: 4689, name: 'Process Exit (pair)', log: 'Security'},
    ],
    3: [ // NetworkConnect
        {id: 5156, name: 'WFP Connection Allowed', log: 'Security'},
        {id: 5157, name: 'WFP Connection Blocked', log: 'Security'},
        {id: 5158, name: 'WFP Bind Allowed', log: 'Security'},
    ],
    5: [ // ProcessTerminate
        {id: 4689, name: 'Process Exit', log: 'Security'},
    ],
    7: [ // ImageLoad (DLL)
        {id: 7045, name: 'Service Installed', log: 'System'},
        {id: 4697, name: 'Service Installed (audit)', log: 'Security'},
    ],
    8: [ // CreateRemoteThread
        {id: 4688, name: 'Source Process Creation', log: 'Security'},
    ],
    10: [ // ProcessAccess
        {id: 4663, name: 'Object Access Attempt', log: 'Security'},
        {id: 4656, name: 'Handle Requested', log: 'Security'},
    ],
    11: [ // FileCreate
        {id: 4663, name: 'Object Access (File)', log: 'Security'},
        {id: 4656, name: 'Handle to Object Requested', log: 'Security'},
        {id: 11707, name: 'Installation Completed (MSI)', log: 'Application'},
    ],
    12: [ // RegistryEvent (CreateKey/DeleteKey)
        {id: 4657, name: 'Registry Value Modified', log: 'Security'},
        {id: 4663, name: 'Object Access (Registry)', log: 'Security'},
    ],
    13: [ // RegistryValueSet
        {id: 4657, name: 'Registry Value Modified', log: 'Security'},
        {id: 4663, name: 'Object Access (Registry)', log: 'Security'},
    ],
    14: [ // RegistryRename
        {id: 4657, name: 'Registry Value Modified', log: 'Security'},
    ],
    22: [ // DNSQuery
        {id: 3008, name: 'DNS Query (DNS Client)', log: 'DNS Client Events'},
    ],
    6: [ // DriverLoad
        {id: 7045, name: 'New Service Installed', log: 'System'},
        {id: 7034, name: 'Service Crashed', log: 'System'},
    ],
    15: [ // FileCreateStreamHash (ADS)
        {id: 4663, name: 'Object Access (File Stream)', log: 'Security'},
    ],
    17: [ // PipeCreated
        {id: 4656, name: 'Handle to Named Pipe', log: 'Security'},
    ],
    23: [ // FileDelete
        {id: 4663, name: 'Object Access (Delete)', log: 'Security'},
        {id: 4660, name: 'Object Deleted', log: 'Security'},
    ],
    25: [ // ProcessTampering
        {id: 4688, name: 'Source Process Creation', log: 'Security'},
    ],
};

function getCorrelatedWindowsEvents(sysmonEventId) {
    return SYSMON_WINDOWS_CORRELATION[sysmonEventId] || [];
}

/** Toggle the correlation reference panel */
function toggleSysmonCorrelation() {
    const panel = document.getElementById('sysmon-correlation-panel');
    if (!panel) return;

    if (panel.style.display !== 'none') {
        panel.style.display = 'none';
        return;
    }

    let html = '<div class="corr-panel-header"><span class="corr-panel-title" data-info="For each Sysmon event, the Windows events that record the same activity and the log they are written to.">Sysmon / Windows Event ID Correlation</span><button class="btn btn-sm" onclick="toggleSysmonCorrelation()">Close</button></div>';
    html += '<div class="corr-panel-body"><table class="corr-ref-table" data-sortable data-sort-id="sysmon-correlation"><thead><tr><th>Sysmon ID</th><th>Sysmon Event</th><th>Related Windows Events</th></tr></thead><tbody>';

    const sysmonNames = {
        1: 'ProcessCreate', 3: 'NetworkConnect', 5: 'ProcessTerminate',
        6: 'DriverLoad', 7: 'ImageLoad', 8: 'CreateRemoteThread',
        10: 'ProcessAccess', 11: 'FileCreate', 12: 'RegistryCreate/Delete',
        13: 'RegistryValueSet', 14: 'RegistryRename', 15: 'FileStreamHash',
        17: 'PipeCreated', 22: 'DNSQuery', 23: 'FileDelete', 25: 'ProcessTampering'
    };

    for (const [sysId, sysName] of Object.entries(sysmonNames)) {
        const corr = SYSMON_WINDOWS_CORRELATION[sysId] || [];
        const corrHtml = corr.map(c =>
            `<span class="corr-ref-item"><span class="corr-ref-eid">${c.id}</span> ${escapeHtml(c.name)} <span class="corr-ref-log">[${escapeHtml(c.log)}]</span></span>`
        ).join('');
        html += `<tr><td class="mono">${sysId}</td><td>${escapeHtml(sysName)}</td><td>${corrHtml || '<span class="muted">—</span>'}</td></tr>`;
    }

    html += '</tbody></table></div>';
    panel.innerHTML = html;
    panel.style.display = 'block';
}

// --- The charts of the Sysmon tab ---
// Above the filter bar, side by side: EVENTS OVER TIME, the events per step
// of seconds or minutes (hours, days for longer spans) stacked by event
// type, with the types' legend; PROCESS → EVENT TYPE, a Sankey image → event
// type. They count the events of the filters but the time window (the table
// takes that, the bars mark it); an event without a time is in no bar, a
// note counts those. A bar sets the time window of its period (Shift: widens
// the window to it), a node, a band or a legend row its image and / or event
// type. Each card shows its numbers as a table on request (CHART / TABLE).
// The colour of an event type, by its name: that of its badge in the table
// (process cyan, network purple, file green, ...), the pipes pink and teal;
// ProcessTerminate a light grey: its badge shares the red of
// CreateRemoteThread, and a process that ends is no alarm
const SYSMON_TYPE_COLORS = {
    processcreate: 'var(--accent-cyan)', networkconnect: 'var(--c-purple-500)', processterminate: 'var(--text-primary)',
    imageload: 'var(--text-secondary)', createremotethread: 'var(--c-red-400)', processaccess: 'var(--c-amber-400)',
    filecreate: 'var(--accent-green)', registryevent: 'var(--accent-orange)', dnsquery: 'var(--c-blue-400)',
    pipecreated: 'var(--accent-pink)', pipeconnected: 'var(--c-teal-400)',
};
// The colours of the other types (Event_23, ...): one each by its name, on
// the hues none of the types above has, in either theme (lime and azure, a
// light and a dark step each)
const SYSMON_OTHER_COLORS = ['var(--c-lime-400)', 'var(--c-sky-400)', 'var(--c-lime-600)', 'var(--c-sky-550)'];
// PROCESS → EVENT TYPE by square roots (small flows stay visible) or, with
// LINEAR, in true proportions, until the page is reloaded
const sysmonFlowView = { linear: false };
// What the charts on screen were drawn from, for which widths and height: a
// resize or LINEAR draws them again without counting again
let _sysmonChartsDrawn = null;

// Draws both charts of the events of the filters (the time window aside);
// renderSysmonTable calls it. Without events they say why ("Sysmon not
// available", "No Sysmon events", "No events match the filters"), or `hint`.
function renderSysmonCharts(events, hint) {
    if (!document.getElementById('sysmon-charts')) return;
    for (const id of ['sysmon-time', 'sysmon-flow']) {
        // Written once: a render keeps the switch (and the keyboard focus on it)
        const slot = document.getElementById(`${id}-toggle`);
        if (slot && !slot.firstElementChild) slot.innerHTML = viewToggleHtml(id);
    }
    const list = (events || []).filter(Boolean);
    const empty = list.length ? '' : hint || _sysmonEmptyText();
    // A type is named as it first appears among the events loaded, in the bars as in the Sankey
    const names = _sysmonTypeNames(sysmonEvents);
    const typeOf = ev => names.get(_alertsNameKey(sysmonEventType(ev))) || sysmonEventType(ev);
    const types = sysmonTypeItems(list, typeOf);
    // The most frequent type at the foot of a bar
    const time = chartTimeBins(list, { key: typeOf, keys: types.map(item => item.key).reverse(), fine: true });
    const flow = sysmonFlow(list, { top: 6, names: sysmonEvents });
    // As high as the fuller column of the Sankey needs: its names stay apart
    const nodes = Math.max(0, ...flow.columns.map(column => column.length));
    const height = empty ? 120 : Math.min(420, Math.max(180, 32 * nodes + 24));
    // The legend first: it takes its room beside the plot of the bars, so the plot is measured at the width they get
    const legend = document.getElementById('sysmon-time-legend');
    if (legend) legend.innerHTML = empty ? '' : chartLegendHtml(types);
    document.querySelectorAll('#sysmon-charts .sysmon-chart-area').forEach(area => { area.style.height = `${height}px`; });
    _sysmonChartsDrawn = { widths: _sysmonChartWidths(), height, empty, time, types, flow };
    _drawSysmonTime(_sysmonChartsDrawn);
    _drawSysmonFlow(_sysmonChartsDrawn);
}

// Why the charts have no events to count
function _sysmonEmptyText() {
    if (sysmonLoadError || sysmonEvents?.[0]?.error) return 'Sysmon not available';
    return sysmonEvents?.length ? 'No events match the filters' : 'No Sysmon events';
}

// Each event type (in lower case, without blanks) with its first spelling among the events
function _sysmonTypeNames(events) {
    const names = new Map();
    for (const ev of events || []) {
        const type = sysmonEventType(ev), key = _alertsNameKey(type);
        if (!names.has(key)) names.set(key, type);
    }
    return names;
}

// The legend of EVENTS OVER TIME: the events per type (typeOf(event)), also
// those in no bar, the most frequent first, each type in its colour
function sysmonTypeItems(events, typeOf) {
    return countBy(events, typeOf).map(({ key, count }) => ({ key, label: key, value: count, color: sysmonTypeColor(key) }));
}

// An event type's colour (SYSMON_TYPE_COLORS), in any case; another type one
// of SYSMON_OTHER_COLORS by its name, so it keeps it whatever else is loaded
function sysmonTypeColor(type) {
    const name = _alertsNameKey(type);
    if (Object.prototype.hasOwnProperty.call(SYSMON_TYPE_COLORS, name)) return SYSMON_TYPE_COLORS[name];
    let hash = 0;
    for (const ch of name) hash = (hash * 31 + ch.codePointAt(0)) % 9973;
    return SYSMON_OTHER_COLORS[hash % SYSMON_OTHER_COLORS.length];
}

// The events as a flow image → event type (PROCESS → EVENT TYPE), _chartFlow's
// {columns, links, labels}: an image by its file name as the table names it,
// in any case and without the blanks around it (as its filter compares it),
// none as "(unknown)"; the `top` (default 6) most frequent on their own, the
// rest "other images". Every event type stands on its own.
function sysmonFlow(events, opts) {
    return _chartFlow(events, [
        ['image', ev => sysmonImageName(ev).trim() || '(unknown)', _alertsNameKey, 'other images'],
        ['type', sysmonEventType, _alertsNameKey, null],
    ], opts);
}

// EVENTS OVER TIME from what renderSysmonCharts counted: the bars for the
// width of their plot (beside the legend renderSysmonCharts wrote) and the
// height of the cards, the time window marked, a bar without events inert,
// under them the note of the events in no bar; the table view (a row per
// bar with events, its total, its events per type)
function _drawSysmonTime(drawn) {
    const plot = document.getElementById('sysmon-time-plot'), table = document.getElementById('sysmon-time-table');
    const { time, types } = drawn;
    const missed = _alertsTimeNote(time);
    const note = missed ? '<div class="sysmon-chart-note" title="Events without a readable time or with one no clock can have had (before 2000, more than a day ahead) are in no bar; the legend and PROCESS → EVENT TYPE count them">'
        + `${escapeHtml(missed)}</div>` : '';
    const colors = Object.create(null);         // types from the data: none may be special (__proto__)
    types.forEach(item => { colors[item.key] = item.color; });
    const { from, to } = sysmonTimeWindow;
    const svg = drawn.empty ? '' : stackedBarsSvg(time.bins, { width: drawn.widths.time || 560, height: drawn.height - (note ? 18 : 0),
        keys: types.map(item => item.key).reverse(), colors, unit: time.unit, step: time.step,
        selection: from !== null && to !== null ? { from, to } : null });
    if (plot) {
        plot.innerHTML = (svg || chartEmptyHtml(drawn.empty || 'No events with a time')) + note;
        _alertsChartInert(plot, '[data-bin-start]', el => !(Number(el.getAttribute('data-total')) > 0));
    }
    if (table) {
        table.innerHTML = _timeBinsTableHtml(time, [{ head: 'Total', count: bin => bin.total },
            ...types.map(item => ({ head: item.label, count: bin => bin.counts[item.key] || 0 }))],
        drawn.empty || 'No events with a time', '<table class="view-table" data-sortable data-sort-id="sysmon-time">');
    }
}

// PROCESS → EVENT TYPE from what renderSysmonCharts counted: the Sankey for
// the width of its card and the height of the cards, the event types on the
// right with the room for their names, by square roots or in true
// proportions (LINEAR); "other images" and its bands inert; the table view
function _drawSysmonFlow(drawn) {
    const view = document.getElementById('sysmon-flow-chart'), table = document.getElementById('sysmon-flow-table');
    const { flow } = drawn;
    const width = drawn.widths.flow || 480;
    const into = new Map();
    flow.links.forEach(link => into.set(link.target, (into.get(link.target) || 0) + link.value));
    const longest = Math.max(0, ...(flow.columns[1] || []).map(id => String(flow.labels[id] ?? id).length + _chartNumber(into.get(id)).length + 1));
    const layout = layoutSankey(flow.columns, flow.links, { width, height: drawn.height - 12, scale: sysmonFlowView.linear ? 'linear' : 'sqrt',
        labelWidth: Math.max(width / 4, Math.min(width / 2, 6 * longest + 24)) });
    if (view) {
        view.innerHTML = sankeySvg(layout, { labels: flow.labels, colors: _sysmonFlowColors(flow) }) || chartEmptyHtml(drawn.empty || 'No events');
        _flowInert(view, _sysmonFlowFilter);
    }
    if (table) {
        table.innerHTML = _flowTableHtml(flow, drawn.empty || 'No events', '<table class="view-table" data-sortable data-sort-id="sysmon-flow">',
                                         ['Image', 'Event type']);
    }
}

// The colours of the nodes: an image from the palette by its place (without
// its muted last colour, which is that of "other images"), an event type in
// its colour of EVENTS OVER TIME
function _sysmonFlowColors(flow) {
    const colors = Object.create(null);
    (flow.columns[0] || []).forEach((id, i) => {
        colors[id] = id === 'other images' ? 'var(--text-muted)' : CHART_PALETTE[i % (CHART_PALETTE.length - 1)];
    });
    (flow.columns[1] || []).forEach(id => { colors[id] = sysmonTypeColor(flow.labels[id]); });
    return colors;
}

// The filter a node of PROCESS → EVENT TYPE stands for: {image} or {type}
// with its name; none ({}) for "other images", which stands for several
function _sysmonFlowFilter(id) {
    const m = /^(image|type):([\s\S]*)$/.exec(String(id ?? ''));
    return m && m[2] ? { [m[1]]: m[2] } : {};
}

// The widths the charts are drawn for: of the plot of the bars (beside the
// legend) and of the Sankey's card (0 while hidden)
function _sysmonChartWidths() {
    const width = el => Math.floor(el?.getBoundingClientRect().width || 0);
    return { time: width(document.getElementById('sysmon-time-plot')),
             flow: width(document.querySelector('#sysmon-flow-card .chart-card-head')) };
}

// A click on a chart of the Sysmon tab sets the filter of the part clicked:
// a bar the time window of its period (with Shift, the window from the one
// set to it), a legend row its event type, a node of the Sankey its image or
// event type, a band both. A bar without events and "other images" (and its
// bands) set nothing: each would list other events than it shows.
function onSysmonChartClick(event, chart) {
    const target = event && event.target;
    if (!target || typeof target.closest !== 'function') return;
    if (chart === 'time') {
        const bin = target.closest('[data-bin-start]');
        const row = bin ? null : target.closest('.chart-legend-row');
        if (bin && Number(bin.getAttribute('data-total')) > 0) {
            let from = Number(bin.getAttribute('data-bin-start')), to = Number(bin.getAttribute('data-bin-end'));
            if (event.shiftKey && sysmonTimeWindow.from !== null && sysmonTimeWindow.to !== null) {
                from = Math.min(from, sysmonTimeWindow.from);
                to = Math.max(to, sysmonTimeWindow.to);
            }
            setSysmonFilters({ from, to });
        } else if (row && row.getAttribute('data-key')) {
            setSysmonFilters({ type: row.getAttribute('data-key') });
        }
    } else if (chart === 'flow') {
        const change = _flowClickFilter(target, _sysmonFlowFilter);
        if (change) setSysmonFilters(change);
    }
}

// Sets some of the filters the charts set and keeps the others: {from, to}
// a time window (null for none), {image}, {type} (null takes one off); then
// renders the table and the charts
function setSysmonFilters(changes) {
    changes = changes || {};
    if ('from' in changes || 'to' in changes) {
        const from = _alertsTimeBound(changes.from), to = _alertsTimeBound(changes.to);
        Object.assign(sysmonTimeWindow, from !== null && to !== null && to > from ? { from, to } : { from: null, to: null });
    }
    for (const kind of ['image', 'type']) {
        if (kind in changes) sysmonFlowFilter[kind] = String(changes[kind] ?? '').trim() || null;
    }
    renderSysmonTable();
}

// The filters the charts set as chips in the filter bar, one each:
// "× 19:32:00 – 19:32:30", "× image: …", "× type: …"; a click takes off
// that filter only. The row is hidden while there is none.
function renderSysmonActiveFilters() {
    const holder = document.getElementById('sysmon-active-filters');
    if (!holder) return;
    const { from, to } = sysmonTimeWindow, { image, type } = sysmonFlowFilter;
    const chips = [];
    if (from !== null && to !== null) {
        chips.push({ kind: 'window', value: _sysmonWindowLabel(from, to),
                     title: `Remove the time window ${formatAlertTime(from)} – ${formatAlertTime(to)} (end not included)` });
    }
    if (image !== null) chips.push({ kind: 'image', name: 'image', value: image, title: `Remove the image filter: ${image}` });
    if (type !== null) chips.push({ kind: 'type', name: 'type', value: type, title: `Remove the event type filter: ${type}` });
    holder.innerHTML = chips.map(chip => filterChipHtml(chip, `removeSysmonFilter(${jsArg(chip.kind)})`)).join('');
    holder.hidden = chips.length === 0;
}

// The × of a chip ('window', 'image' or 'type'). A chip in focus hands it on
// to the chip that takes its place, the search box after the last.
function removeSysmonFilter(kind) {
    if (!['window', 'image', 'type'].includes(kind)) return;
    const holder = document.getElementById('sysmon-active-filters');
    const chips = () => (holder ? [...holder.querySelectorAll('.alerts-filter-chip')] : []);
    const focused = chips().indexOf(document.activeElement);
    setSysmonFilters(kind === 'window' ? { from: null, to: null } : { [kind]: null });
    if (focused < 0) return;
    const left = chips();
    (left[Math.min(focused, left.length - 1)] || document.getElementById('sysmon-search'))?.focus();
}

// A time window as its chip names it: "19:32:00 – 19:32:30" in local time
// (hours 00-23), with the dates when it does not lie within one day or
// covers a whole one (the bar of a day)
function _sysmonWindowLabel(from, to) {
    const day = _chartPeriodStart(from, 'day'), next = _chartPeriodNext(day, 'day');
    const oneDay = to <= next && !(from === day && to === next);
    const at = t => `${oneDay ? '' : _chartDate(t) + ' '}${_chartClock(t, true)}`;
    return `${at(from)} – ${at(to)}`;
}

// New events keep the time window while their plausible times reach it
// (also when none of them lies in it: it may be a quiet stretch between
// them), and drop it when they lie all before or after it
function _sysmonKeepWindow(events) {
    const { from, to } = sysmonTimeWindow;
    if (from === null || to === null) return;
    const latest = Date.now() + 86400000;
    let first = Infinity, last = -Infinity;
    for (const ev of events || []) {
        const t = Date.parse(ev?.timestamp);
        if (!(t >= ALERT_TIME_MIN && t < latest)) continue;
        first = Math.min(first, t);
        last = Math.max(last, t);
    }
    if (!(first < to && last >= from)) Object.assign(sysmonTimeWindow, { from: null, to: null });
}

// LINEAR: the Sankey in true proportions, or by square roots again
function toggleSysmonFlowScale() {
    sysmonFlowView.linear = !sysmonFlowView.linear;
    _pressFlowScale(document.getElementById('sysmon-flow-linear'), sysmonFlowView.linear);
    if (_sysmonChartsDrawn) _drawSysmonFlow(_sysmonChartsDrawn);
}

// The bars and the Sankey for the new widths of their places; neither while
// it is hidden (0) or for the width it was drawn for
function redrawSysmonChartsOnResize() {
    const drawn = _sysmonChartsDrawn;
    if (!drawn) return;
    const widths = _sysmonChartWidths();
    if (widths.time && widths.time !== drawn.widths.time) {
        drawn.widths.time = widths.time;
        _drawSysmonTime(drawn);
    }
    if (widths.flow && widths.flow !== drawn.widths.flow) {
        drawn.widths.flow = widths.flow;
        _drawSysmonFlow(drawn);
    }
}

// The table head stands right under the filter bar (--sysmon-bar-height on
// the table's box, which its renders keep); the charts are drawn for their
// widths again, in the next frame, when the cards or the plot of the bars
// change their size (the window, the theme, the tab or the chart view shown
// again)
function initSysmonTab() {
    if (typeof ResizeObserver === 'undefined') return;
    const bar = document.querySelector('#tab-sysmon .sysmon-filters'), table = document.getElementById('sysmon-table');
    if (bar && table) _followBarHeight(bar, table, '--sysmon-bar-height');
    const charts = document.getElementById('sysmon-charts'), plot = document.getElementById('sysmon-time-plot');
    if (!charts) return;
    const observer = new ResizeObserver(() => requestAnimationFrame(redrawSysmonChartsOnResize));
    observer.observe(charts);
    if (plot) observer.observe(plot);
}

// --- LitterBox Integration ---
let _lbData = null;
let _lbHealth = null;

async function refreshLitterbox() {
    const badge = document.getElementById('lb-status-badge');
    try {
        const [filesResp, healthResp] = await Promise.all([
            fetch('/api/litterbox/files'),
            fetch('/api/litterbox/health'),
        ]);
        if (filesResp.ok) {
            _lbData = await filesResp.json();
        }
        if (healthResp.ok) {
            _lbHealth = await healthResp.json();
        }
        if (badge) {
            const ok = _lbHealth?.status === 'ok';
            badge.textContent = ok ? 'Online' : 'Offline';
            badge.className = 'lb-status-badge ' + (ok ? 'online' : 'offline');
        }
        renderLitterboxScanners();
        renderLitterboxFiles();
    } catch (e) {
        if (badge) { badge.textContent = 'Unreachable'; badge.className = 'lb-status-badge offline'; }
        const table = document.getElementById('lb-files-table');
        if (table) table.innerHTML = `<div class="empty-state">LitterBox unreachable: ${escapeHtml(e.message)}</div>`;
    }
}

function renderLitterboxScanners() {
    const container = document.getElementById('lb-scanners-bar');
    if (!container || !_lbHealth) return;
    const scanners = _lbHealth.scanners?.rows || [];
    const counts = _lbHealth.scanners?.counts || {};
    let html = `<div class="lb-scanners-row"><span class="lb-scanners-title">Scanners: ${counts.ok || 0}/${counts.total || 0} active</span>`;
    scanners.forEach(sc => {
        const cls = sc.status === 'ok' ? 'lb-sc-ok' : 'lb-sc-err';
        html += `<span class="lb-sc-chip ${cls}" title="${escapeHtml(sc.tool_path || '')}">${escapeHtml(sc.name)}</span>`;
    });
    html += '</div>';
    container.innerHTML = html;
}

function renderLitterboxFiles() {
    const container = document.getElementById('lb-files-table');
    if (!container) return;
    if (!_lbData) { container.innerHTML = '<div class="empty-state">No data loaded. Click Refresh.</div>'; return; }

    const payloads = _lbData.payload_based?.payloads || {};
    const drivers = _lbData.driver_based?.drivers || {};
    const pids = _lbData.pid_based?.processes || {};
    const searchTerm = (document.getElementById('lb-search')?.value || '').toLowerCase().trim();

    let entries = [];
    for (const [key, p] of Object.entries(payloads)) {
        if (!p || typeof p !== 'object') continue;
        entries.push({ ...p, _type: 'payload', _key: key });
    }
    for (const [key, d] of Object.entries(drivers)) {
        if (!d || typeof d !== 'object') continue;
        entries.push({ ...d, _type: 'driver', _key: key });
    }
    for (const [key, pr] of Object.entries(pids)) {
        if (!pr || typeof pr !== 'object') continue;
        entries.push({ ...pr, _type: 'pid', _key: key });
    }

    if (searchTerm) {
        entries = entries.filter(e => {
            const hay = [e.filename, e.md5, e.sha256, e.detection_risk, e._key, String(e.file_size||'')].filter(Boolean).join(' ').toLowerCase();
            return hay.includes(searchTerm);
        });
    }

    if (!entries.length) {
        container.innerHTML = `<div class="empty-state">${searchTerm ? `No files matching "${escapeHtml(searchTerm)}"` : 'No files uploaded to LitterBox yet.'}</div>`;
        return;
    }

    let html = `<table class="sysmon-events-table" data-sortable data-sort-id="litterbox-files"><thead><tr><th>File</th><th>Type</th><th>Size</th><th>Risk</th><th>Entropy</th><th>Static</th><th>Dynamic</th><th>EDR</th><th data-no-sort>Actions</th></tr></thead><tbody>`;
    entries.forEach(e => {
        const riskClass = cssToken(e.detection_risk);
        const riskBadge = `<span class="lb-risk-badge lb-risk-${riskClass}">${escapeHtml(e.detection_risk || '?')}</span>`;
        const size = e.file_size ? formatSize(e.file_size) : '--';
        const entropy = e.entropy_value != null ? e.entropy_value.toFixed(2) : '--';
        const staticBadge = e.has_static_analysis ? '<span class="lb-check">&#10003;</span>' : '<span class="lb-x">&#10007;</span>';
        const dynamicBadge = e.has_dynamic_analysis ? '<span class="lb-check">&#10003;</span>' : '<span class="lb-x">&#10007;</span>';
        const edrBadge = e.has_edr_analysis ? '<span class="lb-check">&#10003;</span>' : '<span class="lb-x">&#10007;</span>';
        const md5 = e.md5 || '';

        html += `<tr>
            <td class="col-image" title="${escapeHtml(e.sha256 || '')}">${escapeHtml(e.filename || e._key)}</td>
            <td><span class="lb-type-badge">${escapeHtml(e._type)}</span></td>
            <td data-sort-value="${sortNumberValue(e.file_size)}">${size}</td>
            <td data-sort-value="${severitySortValue(e.detection_risk)}">${riskBadge}</td>
            <td class="mono">${entropy}</td>
            <td class="center">${staticBadge}</td>
            <td class="center">${dynamicBadge}</td>
            <td class="center">${edrBadge}</td>
            <td class="lb-actions">
                <button class="btn btn-xs" onclick="lbRunAnalysis('static',${jsArg(md5)})" title="Run static analysis">Static</button>
                <button class="btn btn-xs" onclick="lbRunAnalysis('dynamic',${jsArg(md5)})" title="Run dynamic analysis">Dynamic</button>
                <button class="btn btn-xs btn-outline" onclick="lbShowDetail(${jsArg(md5)})" title="View results">Detail</button>
            </td>
        </tr>`;
    });
    html += '</tbody></table>';
    container.innerHTML = html;
}

function filterLitterboxFiles() {
    renderLitterboxFiles();
}

async function lbUploadFile(file) {
    if (!file) return;
    const dropZone = document.getElementById('lb-drop-zone');
    if (dropZone) dropZone.classList.add('uploading');

    const formData = new FormData();
    formData.append('file', file);

    try {
        const resp = await fetch('/api/litterbox/upload', { method: 'POST', body: formData });
        if (resp.ok) {
            showToast('success', 'LitterBox', `Uploaded: ${file.name}`, 4000);
            setTimeout(refreshLitterbox, 1500);
        } else {
            const text = await resp.text();
            showToast('error', 'Upload failed', text.substring(0, 100), 5000);
        }
    } catch (e) {
        showToast('error', 'Upload error', e.message, 5000);
    } finally {
        if (dropZone) dropZone.classList.remove('uploading');
    }
}

async function lbRunAnalysis(type, md5) {
    if (!md5) return;
    showToast('info', 'LitterBox', `Starting ${type} analysis...`, 3000);
    try {
        const resp = await fetch(`/api/litterbox/analyze/${type}/${md5}`, { method: 'POST' });
        if (resp.ok) {
            showToast('success', 'LitterBox', `${type} analysis started for ${md5.substring(0,8)}...`, 4000);
            setTimeout(refreshLitterbox, 5000);
        } else {
            const text = await resp.text();
            showToast('error', 'Analysis failed', text.substring(0, 150), 5000);
        }
    } catch (e) {
        showToast('error', 'Analysis error', e.message, 5000);
    }
}

async function lbShowDetail(md5) {
    const panel = document.getElementById('lb-detail-panel');
    if (!panel) return;
    panel.style.display = 'block';
    panel.innerHTML = '<div class="sysmon-loading"><div class="loading-spinner"></div><span>Loading results...</span></div>';

    try {
        const [riskResp, edrResp] = await Promise.all([
            fetch(`/api/litterbox/api/results/risk/${encodeURIComponent(md5)}`),
            fetch(`/api/litterbox/api/results/edr/${encodeURIComponent(md5)}`),
        ]);

        let html = `<div class="lb-detail-header"><span>Results for ${escapeHtml(md5)}</span><button class="btn btn-xs" onclick="document.getElementById('lb-detail-panel').style.display='none'">Close</button></div>`;

        if (riskResp.ok) {
            const risk = await riskResp.json();
            html += `<div class="lb-detail-section"><div class="lb-detail-title">Risk Assessment</div>`;
            html += `<div class="lb-detail-field"><span class="lb-dl">Score</span><span class="lb-dv lb-risk-badge lb-risk-${cssToken(risk.risk_level)}">${escapeHtml(String(risk.risk_score ?? '?'))} / 10 (${escapeHtml(risk.risk_level || '?')})</span></div>`;
            if (risk.risk_factors?.length) {
                html += `<div class="lb-detail-field"><span class="lb-dl">Factors</span><ul class="lb-factors">`;
                risk.risk_factors.forEach(f => { html += `<li>${escapeHtml(f)}</li>`; });
                html += `</ul></div>`;
            }
            html += `</div>`;
        }

        if (edrResp.ok) {
            const edr = await edrResp.json();
            if (edr && !edr.error) {
                html += `<div class="lb-detail-section"><div class="lb-detail-title">EDR Results</div>`;
                html += `<pre class="lb-pre">${escapeHtml(JSON.stringify(edr, null, 2).substring(0, 2000))}</pre>`;
                html += `</div>`;
            }
        }

        // Link to full LitterBox UI
        html += `<div class="lb-detail-section"><a href="http://192.168.64.4:1337/results/static/${encodeURIComponent(md5)}" target="_blank" class="btn btn-sm btn-outline">Open in LitterBox UI</a></div>`;

        panel.innerHTML = html;
    } catch (e) {
        panel.innerHTML = `<div class="empty-state">Error loading results: ${escapeHtml(e.message)}</div>`;
    }
}

// Init LitterBox on tab switch
let _lbInitialized = false;

function initLitterbox() {
    // _lbData is only set after a successful fetch, so it could not stop
    // repeated initialisation: every visit while LitterBox was offline added
    // another set of drop listeners and one drop uploaded the sample N times.
    if (_lbInitialized) {
        if (!_lbData) refreshLitterbox();
        return;
    }
    _lbInitialized = true;
    refreshLitterbox();

    // Setup drag-and-drop
    const dropZone = document.getElementById('lb-drop-zone');
    if (dropZone) {
        dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
        dropZone.addEventListener('dragleave', () => { dropZone.classList.remove('drag-over'); });
        dropZone.addEventListener('drop', e => {
            e.preventDefault();
            dropZone.classList.remove('drag-over');
            if (e.dataTransfer.files.length) lbUploadFile(e.dataTransfer.files[0]);
        });
    }
}

// --- Utilities ---
// --- ETW Browser ---
let _etwInitialized = false;
let _etwAutoInterval = null;
let _etwChannels = {};

async function initEtwBrowser() {
    if (_etwInitialized) return;
    _etwInitialized = true;
    try {
        const resp = await fetch('/api/etw/channels?probe=true');
        _etwChannels = await resp.json();
        const select = document.getElementById('etw-channel-select');
        if (select) {
            select.innerHTML = Object.entries(_etwChannels).map(([key, ch]) => {
                const dot = ch.available === true ? '●' : ch.available === false ? '○' : '○';
                const cls = ch.available === true ? 'etw-ch-active' : 'etw-ch-inactive';
                return `<option value="${key}" class="${cls}">${dot} ${escapeHtml(ch.label)}</option>`;
            }).join('');
            select.addEventListener('change', () => {
                updateEtwChannelInfo();
                refreshEtw();
            });
        }
        updateEtwChannelInfo();
        refreshEtw();
        setupEtwAutoRefresh();
    } catch (e) {
        // Allow a retry on the next visit; the flag was set before the fetch,
        // so one failed load disabled the tab for the rest of the session.
        _etwInitialized = false;
        document.getElementById('etw-event-list').innerHTML =
            `<div class="etw-error">Failed to load ETW channels: ${escapeHtml(e.message)}</div>`;
    }
}

function updateEtwChannelInfo() {
    const key = document.getElementById('etw-channel-select')?.value;
    const info = _etwChannels[key];
    const el = document.getElementById('etw-channel-info');
    if (el && info) {
        let statusHtml = '';
        if (info.available === true) {
            statusHtml = '<span class="etw-info-status active">ACTIVE</span>';
        } else if (info.available === false) {
            statusHtml = '<span class="etw-info-status inactive">NO DATA</span>';
        } else {
            statusHtml = '<span class="etw-info-status unknown">UNKNOWN</span>';
        }
        el.innerHTML = `${statusHtml}<span class="etw-info-name">${escapeHtml(info.name)}</span><span class="etw-info-desc">${escapeHtml(info.description)}</span>`;
    }
}

function setupEtwAutoRefresh() {
    const cb = document.getElementById('etw-auto-refresh');
    if (!cb) return;
    // One interval at most, and only while the box is checked (browsers can
    // restore an unchecked state after reload while the old code still
    // started the timer unconditionally).
    const sync = () => {
        clearInterval(_etwAutoInterval);
        _etwAutoInterval = null;
        if (cb.checked) {
            _etwAutoInterval = setInterval(() => {
                if (state.activeTab === 'etw' && !document.hidden) refreshEtw();
            }, 5000);
        }
    };
    cb.addEventListener('change', sync);
    sync();
}

let _etwRequestSeq = 0;
const _etwExpanded = new Set();   // keys of rows the user expanded

function etwToggleRow(el, key) {
    el.classList.toggle('expanded');
    if (el.classList.contains('expanded')) _etwExpanded.add(key); else _etwExpanded.delete(key);
    if (_etwExpanded.size > 500) _etwExpanded.clear();
}

async function refreshEtw() {
    const channel = document.getElementById('etw-channel-select')?.value || 'security';
    const filter = document.getElementById('etw-filter-input')?.value || '';
    const max = document.getElementById('etw-max-select')?.value || '50';
    const listEl = document.getElementById('etw-event-list');
    if (!listEl) return;

    // A slow answer for a previous channel must not overwrite a newer one.
    const seq = ++_etwRequestSeq;
    try {
        const params = new URLSearchParams({channel, max, filter});
        const resp = await fetch(`/api/etw/events?${params}`);
        const data = await resp.json();
        if (seq !== _etwRequestSeq) return;

        if (data.error) {
            listEl.innerHTML = `<div class="etw-error">${escapeHtml(data.error)}</div>`;
            return;
        }
        if (!data.events || data.events.length === 0) {
            listEl.innerHTML = `<div class="etw-empty">No events found${data.note ? ' — ' + escapeHtml(data.note) : ''}</div>`;
            return;
        }

        let malCount = 0;
        let html = `<div class="etw-event-count">${data.count} events</div>`;
        html += '<div class="etw-events">';
        data.events.forEach(ev => {
            const levelClass = (ev.level || '').toLowerCase().replace(/[^a-z]/g, '');
            const hasData = ev.data && Object.keys(ev.data).length > 0;
            const mal = classifyEtwThreat(ev);
            if (mal) malCount++;
            // Expanded rows stay expanded across the 5 s refresh.
            const rowKey = `${channel}|${ev.timestamp}|${ev.event_id}`;
            const expanded = _etwExpanded.has(rowKey) ? ' expanded' : '';
            html += `<div class="etw-event ${levelClass}${mal ? ' malicious' : ''}${expanded}" `
                + `onclick="etwToggleRow(this, ${jsArg(rowKey)})">`;
            html += `<div class="etw-event-header">`;
            html += `<span class="etw-event-time">${formatEtwTime(ev.timestamp)}</span>`;
            html += `<span class="etw-event-id">ID:${ev.event_id}</span>`;
            html += `<span class="etw-event-level ${levelClass}">${escapeHtml(ev.level || 'Info')}</span>`;
            if (mal) html += `<span class="etw-event-threat">${escapeHtml(mal)}</span>`;
            html += `<span class="etw-event-msg">${escapeHtml(ev.message || ev.provider || '')}</span>`;
            if (hasData) html += `<span class="etw-event-expand">+</span>`;
            html += `</div>`;
            if (hasData) {
                html += `<div class="etw-event-data">`;
                Object.entries(ev.data).forEach(([k, v]) => {
                    if (v) {
                        const isInteresting = /pid|process|image|command|user|target|address|path|hash|url|dns|remote|local/i.test(k);
                        const vStr = String(v);
                        const isMalVal = isEtwValueSuspicious(k, vStr);
                        html += `<div class="etw-data-row${isMalVal ? ' mal-val' : isInteresting ? ' highlight' : ''}"><span class="etw-data-key">${escapeHtml(k)}</span><span class="etw-data-val">${escapeHtml(vStr)}</span></div>`;
                    }
                });
                html += `</div>`;
            }
            html += `</div>`;
        });
        html += '</div>';
        if (malCount > 0) {
            html = `<div class="etw-threat-banner">${malCount} suspicious event${malCount > 1 ? 's' : ''} detected</div>` + html;
        }
        listEl.innerHTML = html;
    } catch (e) {
        listEl.innerHTML = `<div class="etw-error">Fetch error: ${escapeHtml(e.message)}</div>`;
    }
}

const ETW_MALICIOUS_EVENT_IDS = {
    1116: 'Defender: Malware detected',
    1117: 'Defender: Action taken',
    4625: 'Failed logon',
    4648: 'Explicit credential logon',
    4697: 'Service installed',
    4698: 'Scheduled task created',
    4720: 'User account created',
    4732: 'Member added to admin group',
    7045: 'New service installed',
};

const ETW_SUSPICIOUS_COMMANDS = [
    /powershell.*-enc/i, /powershell.*-e\s+[A-Za-z0-9+\/=]{20,}/i,
    /powershell.*downloadstring/i, /powershell.*iex/i, /powershell.*invoke-expression/i,
    /powershell.*bypass/i, /powershell.*hidden/i, /powershell.*nop\s/i,
    /cmd.*\/c.*powershell/i, /cmd.*\/c.*certutil.*-urlcache/i,
    /mshta\s+http/i, /regsvr32.*\/s.*\/u.*scrobj/i, /rundll32.*javascript/i,
    /bitsadmin.*\/transfer/i, /certutil.*-decode/i, /certutil.*-urlcache/i,
    /wmic.*process.*call.*create/i, /wmic.*shadowcopy.*delete/i,
    /vssadmin.*delete.*shadows/i, /bcdedit.*recoveryenabled.*no/i,
    /schtasks.*\/create/i, /reg\s+add.*\\run/i,
    /mimikatz/i, /sekurlsa/i, /lsadump/i, /kerberos.*golden/i,
    /invoke-mimikatz/i, /invoke-shellcode/i, /invoke-pstokenprivilege/i,
    /net\s+(user|localgroup).*\/add/i, /net\s+use.*\\\\.*\$/i,
    /whoami\s*\/priv/i, /nltest.*\/dclist/i, /dsquery/i,
];

const ETW_SUSPICIOUS_VALUES = [
    /\\AppData\\Local\\Temp\\[a-z0-9]{6,}\.(exe|dll|ps1|bat|vbs|js)/i,
    /\\ProgramData\\[a-z0-9]{6,}\.(exe|dll)/i,
    /\\Windows\\Temp\\[^\\]+\.(exe|dll|ps1)/i,
    /\\Users\\Public\\[^\\]+\.(exe|dll|bat|ps1)/i,
    /FromBase64String/i, /Reflection\.Assembly/i, /\[System\.Convert\]/i,
    /AmsiScanBuffer/i, /amsi\.dll/i, /EtwEventWrite/i,
    /VirtualAlloc.*0x3000.*0x40/i, /PAGE_EXECUTE_READWRITE/i,
    /CreateRemoteThread/i, /NtQueueApcThread/i,
    /HKLM\\.*\\Run/i, /CurrentVersion\\Run/i,
    /\.onion/i, /tor2web/i, /pastebin\.com\/raw/i,
];

const ETW_SUSPICIOUS_SYSMON_IDS = {
    1: (d) => ETW_SUSPICIOUS_COMMANDS.some(r => r.test(d.CommandLine || '')),
    3: (d) => /:(4444|5555|6666|8888|9999|1234|31337|443[1-9])/i.test(d.DestinationPort || '') || /^(10\.|192\.168\.|172\.(1[6-9]|2|3[01]))/.test(d.DestinationIp || '') === false && d.Initiated === 'true',
    7: (d) => /\\Temp\\|\\AppData\\.*\.(dll|exe)/i.test(d.ImageLoaded || ''),
    8: (d) => true,
    10: (d) => /lsass\.exe/i.test(d.TargetImage || ''),
    11: (d) => /\.(exe|dll|ps1|bat|vbs|js|hta)$/i.test(d.TargetFilename || '') && /\\(Temp|AppData|ProgramData|Public)/i.test(d.TargetFilename || ''),
    12: (d) => /\\Run\\|\\RunOnce\\|\\Services\\|\\Image File Execution/i.test(d.TargetObject || ''),
    13: (d) => /\\Run\\|\\RunOnce\\|\\Services\\|\\Image File Execution/i.test(d.TargetObject || ''),
    15: (d) => /\.(exe|dll|ps1|bat|hta|js|vbs)/i.test(d.TargetFilename || ''),
    22: (d) => /\.(onion|bit|top|xyz|tk|ml|ga|cf)\b/i.test(d.QueryName || ''),
    25: (d) => true,
};

function classifyEtwThreat(ev) {
    if (ETW_MALICIOUS_EVENT_IDS[ev.event_id]) return ETW_MALICIOUS_EVENT_IDS[ev.event_id];
    const d = ev.data || {};
    const allVals = Object.values(d).join(' ');
    if (ETW_SUSPICIOUS_COMMANDS.some(r => r.test(allVals))) return 'Suspicious command';
    if (ETW_SUSPICIOUS_VALUES.some(r => r.test(allVals))) return 'Suspicious indicator';
    const sysmonCheck = ETW_SUSPICIOUS_SYSMON_IDS[ev.event_id];
    if (sysmonCheck && sysmonCheck(d)) return 'Sysmon IOC';
    if ((ev.level || '').toLowerCase() === 'warning' && /malware|threat|virus|trojan|exploit|suspicious/i.test(ev.message || '')) return 'Threat keyword';
    return null;
}

function isEtwValueSuspicious(key, value) {
    if (ETW_SUSPICIOUS_COMMANDS.some(r => r.test(value))) return true;
    if (ETW_SUSPICIOUS_VALUES.some(r => r.test(value))) return true;
    if (/lsass|mimikatz|sekurlsa|procdump.*lsass/i.test(value)) return true;
    return false;
}

function formatEtwTime(ts) {
    if (!ts) return '';
    try {
        const d = new Date(ts);
        return d.toLocaleTimeString('en-GB', {hour:'2-digit', minute:'2-digit', second:'2-digit', fractionalSecondDigits: 3});
    } catch { return ts.substring(11, 23); }
}

function toggleFlagEvidence(el) {
    const evidence = el.nextElementSibling;
    if (!evidence || !evidence.classList.contains('pe-flag-evidence') && !evidence.classList.contains('elf-flag-evidence')) return;
    const isOpen = evidence.style.display !== 'none';
    evidence.style.display = isOpen ? 'none' : 'block';
    const icon = el.querySelector('.pe-flag-expand-icon, .elf-flag-expand-icon');
    if (icon) icon.innerHTML = isOpen ? '&#x25BC;' : '&#x25B2;';
    el.classList.toggle('expanded', !isOpen);
}

function renderFlagEvidence(flag) {
    const ev = flag.evidence;
    if (!ev) return '';
    let html = '';
    if (ev.why) {
        html += `<div class="flag-evidence-why"><strong>Why:</strong> ${escapeHtml(ev.why)}</div>`;
    }
    if (ev.matched_apis && ev.matched_apis.length > 0) {
        html += `<div class="flag-evidence-section"><strong>Matched (${ev.matched_apis.length}):</strong>`;
        html += '<div class="flag-evidence-apis">';
        ev.matched_apis.forEach(api => {
            html += `<span class="flag-evidence-api">${escapeHtml(api)}</span>`;
        });
        html += '</div></div>';
    }
    if (ev.reference_apis && ev.reference_apis.length > 0) {
        html += `<div class="flag-evidence-section"><strong>Detection rule watches for:</strong>`;
        html += '<div class="flag-evidence-apis ref">';
        ev.reference_apis.forEach(api => {
            const isMatched = ev.matched_apis && ev.matched_apis.some(m => m.includes(api));
            html += `<span class="flag-evidence-api${isMatched ? ' matched' : ''}">${escapeHtml(api)}</span>`;
        });
        html += '</div></div>';
    }
    if (ev.callbacks && ev.callbacks.length > 0) {
        html += `<div class="flag-evidence-section"><strong>Callbacks:</strong> `;
        html += ev.callbacks.map(c => `<code>${escapeHtml(c)}</code>`).join(', ');
        html += '</div>';
    }
    if (ev.section) {
        html += `<div class="flag-evidence-section"><strong>Section:</strong> <code>${escapeHtml(ev.section)}</code>`;
        if (ev.entropy) html += ` | Entropy: ${ev.entropy.toFixed(2)}`;
        if (ev.threshold) html += ` (threshold: ${ev.threshold})`;
        if (ev.packer) html += ` | Packer: ${escapeHtml(ev.packer)}`;
        if (ev.permissions) html += ` | Permissions: ${escapeHtml(ev.permissions)}`;
        html += '</div>';
    }
    if (ev.path) {
        html += `<div class="flag-evidence-section"><strong>Path:</strong> <code>${escapeHtml(ev.path)}</code></div>`;
    }
    if (ev.entropy && !ev.section) {
        html += `<div class="flag-evidence-section"><strong>Entropy:</strong> ${ev.entropy.toFixed(2)} (threshold: ${ev.threshold})</div>`;
    }
    return html;
}

function escapeHtml(str) {
    if (str === null || str === undefined || str === '') return '';
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// A value as a JavaScript string literal that is safe inside an HTML
// attribute such as onclick="fn(${jsArg(x)})". File names, paths and command
// lines come from samples; quoting them by hand ('${...}') let a crafted name
// like a');alert(1);//.exe break out of the handler.
function jsArg(value) {
    return escapeHtml(JSON.stringify(value === null || value === undefined ? '' : String(value)));
}

// An integer (PID, offset) for an inline handler: onclick="fn(${jsInt(pid)})".
// Unquoted ${proc.pid} would execute whatever a non-numeric value contains.
function jsInt(value) {
    const n = parseInt(value, 10);
    return Number.isFinite(n) ? String(n) : 'null';
}

// A value used as part of a CSS class name (severity, status from events).
// Anything but [a-z0-9_-] is dropped so it cannot leave the class attribute.
// Processes are keyed per instance: "<pid>" is the newest process with that
// PID, "<pid>@<start epoch>" an older one (Windows reuses PIDs).
function procKey(proc) {
    return String(proc.key ?? proc.pid);
}

function cssToken(value) {
    return String(value === null || value === undefined ? '' : value).toLowerCase().replace(/[^a-z0-9_-]/g, '');
}

function formatTime(ts) {
    if (!ts) return '';
    try { const d = new Date(ts); return isNaN(d.getTime()) ? ts.substring(0, 19) : d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' }); } catch { return ts.substring(0, 19); }
}

function formatRelativeTime(ts) {
    if (!ts || !state.sessionStart) return formatTime(ts);
    try {
        const t = new Date(ts).getTime();
        if (isNaN(t)) return formatTime(ts);
        const diff = (t - state.sessionStart) / 1000;
        if (diff < 0) return '+0.000s';
        return `+${diff.toFixed(3)}s`;
    } catch { return formatTime(ts); }
}

function computeLifespan(startTs, endTs) {
    if (!startTs || !endTs) return '';
    try {
        const start = new Date(startTs).getTime();
        const end = new Date(endTs).getTime();
        if (isNaN(start) || isNaN(end)) return '';
        const diffMs = end - start;
        if (diffMs < 0) return '0ms';
        if (diffMs < 1000) return `${diffMs}ms`;
        const diffS = diffMs / 1000;
        if (diffS < 60) return `${diffS.toFixed(1)}s`;
        const mins = Math.floor(diffS / 60);
        const secs = Math.floor(diffS % 60);
        return `${mins}m ${secs}s`;
    } catch { return ''; }
}

function formatSize(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

// data-sort-value of a cell that shows a time as text ("23:59:58", "09 Nov,
// 10:00"): epoch ms, so a sortable table orders by when, across days and time
// zones; '' (sorted last) when there is none. Only digits reach the markup.
function sortTimeValue(ts) {
    const t = ts === null || ts === undefined || ts === '' ? NaN : Date.parse(ts);
    return Number.isNaN(t) ? '' : String(t);
}

// data-sort-value of a cell that shows a number formatted ("1.2 KB")
function sortNumberValue(value) {
    const n = value === null || value === undefined || value === '' ? NaN : Number(value);
    return Number.isFinite(n) ? String(n) : '';
}

// data-sort-value of a severity: critical 5 ... info 1 (the server's
// "unknown" counts as info), '' for anything else
function severitySortValue(severity) {
    const s = String(severity || '').toLowerCase();
    const rank = ALERT_SEVERITIES.indexOf(s === 'unknown' ? 'info' : s);
    return rank < 0 ? '' : String(ALERT_SEVERITIES.length - rank);
}

function formatCategory(cat) {
    if (Array.isArray(cat)) return cat.map(c => c.charAt(0).toUpperCase() + c.slice(1)).join(', ');
    if (typeof cat === 'string') return cat.charAt(0).toUpperCase() + cat.slice(1);
    return '';
}

function activityCounter(label, value) {
    const v = value || 0;
    const highlight = (label === 'THREATS' && v > 0) ? ' threats' : (label === 'INJECTION' && v > 0) ? ' injection' : '';
    return `<div class="activity-counter${highlight ? ' ' + highlight : ''}"><div class="counter-label">${label}</div><div class="counter-value ${v === 0 ? 'zero' : ''}">${v}</div></div>`;
}

// --- Keyboard shortcuts ---
// Esc closes one layer per press, the top-most first: the (i) popover (the
// focus goes back to its button), help, a drop-down of the top bar and the
// drawer (the focus goes back to their button), the detail view.
function handleGlobalKeydown(e) {
    if (e.key === 'Escape') {
        const infoPopover = document.getElementById('info-popover');
        if (infoPopover && !infoPopover.hidden) {
            closeInfoPopover()?.focus();
            return;
        }
        const helpModal = document.getElementById('help-modal');
        if (helpModal && !helpModal.classList.contains('hidden')) {
            closeHelp();
            return;
        }
        // An open drop-down closes and gives the focus back to its button.
        const menuButton = Object.keys(TOPBAR_MENUS).find(isTopbarMenuOpen);
        if (menuButton) {
            closeTopbarMenus();
            document.getElementById(menuButton)?.focus();
            return;
        }
        // The drawer gives a focus that is in it to ☰ PROCESSES (it would stay on a hidden element).
        if (isDrawerOpen()) {
            const focusInDrawer = !!document.getElementById('sidebar')?.contains(document.activeElement);
            closeDrawer();
            if (focusInDrawer) document.getElementById('drawer-toggle')?.focus();
            return;
        }
        if (state.detailOpen) closeDetail();
    }
    if (e.key === 'Backspace' && state.detailOpen && !['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement.tagName)) {
        e.preventDefault();
        goDetailBack();
    }
}
document.addEventListener('keydown', handleGlobalKeydown);

// --- Help Modal ---
// Opens the help where it was left, or at a section (overview, usage, api,
// architecture, services) with an element of it scrolled into view.
function openHelp(section, anchorId) {
    const modal = document.getElementById('help-modal');
    if (!modal) return;
    modal.classList.remove('hidden');
    if (section) showHelpSection(section);
    const anchor = anchorId ? document.getElementById(anchorId) : null;
    if (anchor) anchor.scrollIntoView({ block: 'start' });
}

function closeHelp() {
    const modal = document.getElementById('help-modal');
    if (modal) modal.classList.add('hidden');
}

// Shows one section of the help and marks its tab; an unknown name changes nothing
function showHelpSection(name) {
    const section = document.getElementById('help-' + name);
    if (!section || !section.classList.contains('help-section')) return;
    document.querySelectorAll('.help-tab').forEach(tab => tab.classList.toggle('active', tab.dataset.help === name));
    document.querySelectorAll('.help-section').forEach(s => s.classList.toggle('active', s === section));
}

// Help tab switching
document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.help-tab').forEach(tab => {
        tab.addEventListener('click', () => showHelpSection(tab.dataset.help));
    });
});

// =============================================
// FILE MAP (BytePlot / Entropy / Structure)
// Renders the three planes side by side. The same module backs the standalone
// FileMap tab, the hex editor minimap and the inline map in the PE/ELF
// analysis panels.
// =============================================

const FileMapView = (() => {
    // Byte classes must stay in sync with BYTEPLOT_* in app.py.
    const BYTE_COLORS = [
        [0, 0, 0],        // 0 - 0x00
        [255, 255, 255],  // 1 - 0xFF
        [26, 59, 255],    // 2 - visible ASCII
        [0, 200, 20],     // 3 - invisible ASCII
        [230, 230, 0],    // 4 - non-ASCII
    ];

    // Entropy gradient: dark (repetition) -> teal (code) -> cyan (packed).
    const ENTROPY_STOPS = [
        [0.0, [18, 32, 36]],
        [0.2, [47, 79, 84]],
        [0.5, [31, 154, 168]],
        [0.8, [34, 211, 224]],
        [1.0, [224, 255, 255]],
    ];

    const cache = new Map();   // path -> visualization payload
    let tooltipEl = null;

    function b64ToBytes(b64) {
        const bin = atob(b64 || '');
        const out = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
        return out;
    }

    function entropyColor(v) {
        for (let i = 1; i < ENTROPY_STOPS.length; i++) {
            const [hi, hiC] = ENTROPY_STOPS[i];
            if (v <= hi) {
                const [lo, loC] = ENTROPY_STOPS[i - 1];
                const t = hi === lo ? 0 : (v - lo) / (hi - lo);
                return [
                    Math.round(loC[0] + (hiC[0] - loC[0]) * t),
                    Math.round(loC[1] + (hiC[1] - loC[1]) * t),
                    Math.round(loC[2] + (hiC[2] - loC[2]) * t),
                ];
            }
        }
        return ENTROPY_STOPS[ENTROPY_STOPS.length - 1][1];
    }

    function hexOff(n) {
        return '0x' + (n >>> 0).toString(16).padStart(8, '0').toUpperCase();
    }

    const CACHE_LIMIT = 8;

    function load(path, opts = {}) {
        const key = `${path}|${opts.cols || 256}|${opts.rows || 512}`;
        // The promise is cached, not the result, so concurrent callers (the
        // inline map and its import tree) share one request.
        if (cache.has(key) && !opts.force) {
            const hit = cache.get(key);
            cache.delete(key);
            cache.set(key, hit);          // mark as most recently used
            return hit;
        }
        const pending = (async () => {
            const params = new URLSearchParams({ path });
            if (opts.cols) params.set('cols', opts.cols);
            if (opts.rows) params.set('rows', opts.rows);
            const resp = await fetch(`/api/file/visualize?${params}`);
            const data = await resp.json();
            if (data.error) throw new Error(data.error);
            data.bytePlane = b64ToBytes(data.byteplot);
            data.entropyPlane = b64ToBytes(data.entropy);
            // The decoded planes are all that is used; keeping the base64
            // strings as well doubled the memory per cached file.
            delete data.byteplot;
            delete data.entropy;
            return data;
        })();
        cache.set(key, pending);
        // Failed loads are not cached, so a retry can succeed.
        pending.catch(() => { if (cache.get(key) === pending) cache.delete(key); });
        while (cache.size > CACHE_LIMIT) cache.delete(cache.keys().next().value);
        return pending;
    }

    // --- Plane painters -------------------------------------------------

    function paintBytePlot(vis) {
        const { rows, cols } = vis;
        const canvas = document.createElement('canvas');
        canvas.width = cols;
        canvas.height = rows;
        const ctx = canvas.getContext('2d');
        const img = ctx.createImageData(cols, rows);
        const plane = vis.bytePlane;
        const rgbMode = vis.byteplot_mode === 'rgb';
        const cells = rgbMode ? Math.floor(plane.length / 3) : plane.length;
        for (let i = 0; i < rows * cols; i++) {
            const p = i * 4;
            if (i >= cells) {
                // Past end of file: leave transparent so the backdrop shows.
                img.data[p + 3] = 0;
                continue;
            }
            if (rgbMode) {
                // Cells already carry the blended color of the bytes they cover.
                const s = i * 3;
                img.data[p] = plane[s];
                img.data[p + 1] = plane[s + 1];
                img.data[p + 2] = plane[s + 2];
            } else {
                const c = BYTE_COLORS[plane[i]] || BYTE_COLORS[0];
                img.data[p] = c[0];
                img.data[p + 1] = c[1];
                img.data[p + 2] = c[2];
            }
            img.data[p + 3] = 255;
        }
        ctx.putImageData(img, 0, 0);
        return canvas;
    }

    // Color of one byteplot cell, whichever plane mode is in use.
    function cellColor(vis, cellIdx) {
        if (vis.byteplot_mode === 'rgb') {
            const s = cellIdx * 3;
            if (s + 2 >= vis.bytePlane.length) return null;
            return [vis.bytePlane[s], vis.bytePlane[s + 1], vis.bytePlane[s + 2]];
        }
        if (cellIdx >= vis.bytePlane.length) return null;
        return BYTE_COLORS[vis.bytePlane[cellIdx]] || BYTE_COLORS[0];
    }

    function byteCellCount(vis) {
        return vis.byteplot_mode === 'rgb'
            ? Math.floor(vis.bytePlane.length / 3)
            : vis.bytePlane.length;
    }

    function paintEntropy(vis) {
        const rows = vis.rows;
        const cols = vis.entropy_cols;
        const canvas = document.createElement('canvas');
        canvas.width = cols;
        canvas.height = rows;
        const ctx = canvas.getContext('2d');
        const img = ctx.createImageData(cols, rows);
        const plane = vis.entropyPlane;
        for (let i = 0; i < rows * cols; i++) {
            const p = i * 4;
            if (i >= plane.length) {
                img.data[p + 3] = 0;
                continue;
            }
            const c = entropyColor(plane[i] / 255);
            img.data[p] = c[0];
            img.data[p + 1] = c[1];
            img.data[p + 2] = c[2];
            img.data[p + 3] = 255;
        }
        ctx.putImageData(img, 0, 0);
        return canvas;
    }

    // Structure plane: regions painted as vertical bands over the file.
    // Regions arrive sorted by priority, so markers land on top of sections.
    function paintStructure(vis, width = 64) {
        const rows = vis.rows;
        const canvas = document.createElement('canvas');
        canvas.width = width;
        canvas.height = rows * 4;   // 4x oversampling keeps thin regions visible
        const ctx = canvas.getContext('2d');
        const h = canvas.height;
        const size = vis.file_size || 1;

        ctx.fillStyle = themeColor('--c-navy-900');
        ctx.fillRect(0, 0, width, h);

        (vis.regions || []).forEach(r => {
            const y = (r.offset / size) * h;
            const rh = Math.max((r.size / size) * h, 1.2);
            ctx.fillStyle = r.color;
            ctx.fillRect(0, y, width, rh);
        });
        return canvas;
    }

    // --- Lookups for hover/click --------------------------------------

    function regionAt(vis, offset) {
        let hit = null;
        (vis.regions || []).forEach(r => {
            if (offset >= r.offset && offset < r.offset + r.size) hit = r;
        });
        return hit;
    }

    function byteClassLabel(vis, offset) {
        // Only the per-byte plane carries exact classes; blended cells do not.
        if (vis.byteplot_mode === 'rgb') return null;
        const bpc = vis.bytes_per_cell || 1;
        const idx = Math.floor(offset / bpc);
        if (idx >= vis.bytePlane.length) return null;
        const entry = (vis.legend.byteplot || []).find(l => l.id === vis.bytePlane[idx]);
        return entry ? entry.label : null;
    }

    function entropyAt(vis, offset) {
        const cells = vis.rows * vis.entropy_cols;
        if (!cells) return null;
        const idx = Math.min(cells - 1, Math.floor((offset / (vis.file_size || 1)) * cells));
        if (idx >= vis.entropyPlane.length) return null;
        return vis.entropyPlane[idx] / 255;
    }

    // --- Tooltip -------------------------------------------------------

    function ensureTooltip() {
        if (!tooltipEl) {
            tooltipEl = document.createElement('div');
            tooltipEl.className = 'fmap-tooltip';
            document.body.appendChild(tooltipEl);
        }
        return tooltipEl;
    }

    function showTooltip(evt, vis, offset) {
        const tip = ensureTooltip();
        const region = regionAt(vis, offset);
        const cls = byteClassLabel(vis, offset);
        const ent = entropyAt(vis, offset);
        let html = `<div class="fmap-tip-off">${hexOff(offset)}</div>`;
        if (region) {
            html += `<div class="fmap-tip-region"><span class="fmap-dot" style="background:${region.color}"></span>${escapeHtml(region.name)}`;
            html += ` <span class="fmap-tip-dim">(${formatSize(region.size)})</span></div>`;
            const d = region.detail || {};
            const bits = Object.keys(d).slice(0, 4).map(k =>
                `<span class="fmap-tip-kv">${escapeHtml(k.replace(/_/g, ' '))}: ${escapeHtml(String(d[k]))}</span>`);
            if (bits.length) html += `<div class="fmap-tip-detail">${bits.join('')}</div>`;
        } else {
            html += `<div class="fmap-tip-region fmap-tip-dim">unmapped</div>`;
        }
        if (cls) html += `<div class="fmap-tip-kv">byte class: ${escapeHtml(cls)}</div>`;
        if (ent != null) html += `<div class="fmap-tip-kv">entropy: ${ent.toFixed(2)}</div>`;
        html += `<div class="fmap-tip-hint">click to open in hex editor</div>`;
        tip.innerHTML = html;
        tip.classList.add('visible');
        const pad = 14;
        let x = evt.clientX + pad;
        let y = evt.clientY + pad;
        const rect = tip.getBoundingClientRect();
        if (x + rect.width > window.innerWidth) x = evt.clientX - rect.width - pad;
        if (y + rect.height > window.innerHeight) y = evt.clientY - rect.height - pad;
        tip.style.left = `${x}px`;
        tip.style.top = `${y}px`;
    }

    function hideTooltip() {
        if (tooltipEl) tooltipEl.classList.remove('visible');
    }

    // Wire hover + click on a canvas. offsetFor() maps a canvas-relative
    // position to a file offset, which differs per plane and orientation.
    function attachInteraction(canvas, vis, offsetFor) {
        canvas.addEventListener('mousemove', evt => {
            const rect = canvas.getBoundingClientRect();
            const offset = offsetFor(evt, rect);
            if (offset == null) { hideTooltip(); return; }
            showTooltip(evt, vis, offset);
        });
        canvas.addEventListener('mouseleave', hideTooltip);
        canvas.addEventListener('click', evt => {
            const rect = canvas.getBoundingClientRect();
            const offset = offsetFor(evt, rect);
            if (offset != null) jumpToHex(vis.path, offset);
        });
    }

    function jumpToHex(path, offset) {
        hideTooltip();
        const aligned = Math.max(0, Math.floor(offset / 16) * 16);
        const pathInput = document.getElementById('hex-filepath');
        const offsetInput = document.getElementById('hex-offset');
        if (!pathInput || !offsetInput) return;
        switchTab('hexeditor');
        pathInput.value = path;
        offsetInput.value = aligned;
        const zone = document.getElementById('hex-drop-zone');
        if (zone) {
            zone.classList.add('has-file');
            const p = zone.querySelector('p');
            if (p) {
                const name = path.split(/[\\/]/).pop();
                p.innerHTML = `<strong>${escapeHtml(name)}</strong> <span class="hex-change-file" onclick="hexResetDropZone()">change</span>`;
            }
        }
        hexLoad();
    }

    // --- Legend --------------------------------------------------------

    function legendHtml(vis) {
        const l = vis.legend || {};
        let html = '<div class="fmap-legend">';
        const group = (title, items) => {
            html += `<div class="fmap-legend-group"><div class="fmap-legend-title">${title}</div>`;
            items.forEach(it => {
                // Structure entries carry an offset and double as jump targets.
                const jump = it.offset != null
                    ? ` class="fmap-legend-item fmap-legend-jump" title="jump to ${hexOff(it.offset)}" onclick="FileMapView.jumpToHex(${jsArg(vis.path)}, ${jsInt(it.offset)})"`
                    : ' class="fmap-legend-item"';
                html += `<div${jump}><span class="fmap-legend-swatch" style="background:${it.color}"></span>${escapeHtml(it.label)}</div>`;
            });
            html += '</div>';
        };
        group('BytePlot (left)', l.byteplot || []);
        group('Entropy (middle)', l.entropy || []);
        group(`${vis.format} Structure (right)`, l.structure || []);
        html += '</div>';
        return html;
    }

    // --- Standalone / vertical view -----------------------------------

    function renderVertical(container, vis, opts = {}) {
        const height = opts.height || 740;
        container.innerHTML = '';
        container.classList.add('fmap-view');

        const planes = document.createElement('div');
        planes.className = 'fmap-planes';

        const addPlane = (label, canvas, cssWidth, offsetFor) => {
            const wrap = document.createElement('div');
            wrap.className = 'fmap-plane';
            const cap = document.createElement('div');
            cap.className = 'fmap-plane-label';
            cap.textContent = label;
            canvas.className = 'fmap-canvas';
            canvas.style.width = `${cssWidth}px`;
            canvas.style.height = `${height}px`;
            attachInteraction(canvas, vis, offsetFor);
            wrap.appendChild(cap);
            wrap.appendChild(canvas);
            planes.appendChild(wrap);
        };

        // BytePlot: row-major, so both axes carry information.
        // Display each plane at its native cell width to avoid resampling.
        const byteWidth = opts.byteWidth || Math.min(Math.max(vis.cols, 192), 512);
        addPlane('BytePlot', paintBytePlot(vis), byteWidth, (evt, rect) => {
            const col = Math.floor(((evt.clientX - rect.left) / rect.width) * vis.cols);
            const row = Math.floor(((evt.clientY - rect.top) / rect.height) * vis.rows);
            if (row < 0 || col < 0) return null;
            const offset = (row * vis.cols + col) * (vis.bytes_per_cell || 1);
            return offset < vis.file_size ? offset : null;
        });

        // Entropy + Structure are read vertically only.
        const linear = (evt, rect) => {
            const frac = (evt.clientY - rect.top) / rect.height;
            const offset = Math.floor(frac * vis.file_size);
            return offset >= 0 && offset < vis.file_size ? offset : null;
        };
        const entropyWidth = opts.entropyWidth || Math.min(Math.max(vis.entropy_cols, 96), 160);
        addPlane('Entropy', paintEntropy(vis), entropyWidth, linear);
        addPlane('Structure', paintStructure(vis), opts.structWidth || 128, linear);

        container.appendChild(planes);

        const legend = document.createElement('div');
        legend.innerHTML = legendHtml(vis);
        container.appendChild(legend.firstChild);
        keepForRepaint(container, () => renderVertical(container, vis, opts));
    }

    // A theme switch paints every map on the page again (repaint), from the
    // data it was drawn from. Skipped once other content replaced the map.
    function keepForRepaint(container, render) {
        container._fmapRepaint = render;
        container._fmapShown = container.firstChild;
    }

    // Hidden maps are painted as well; a strip keeps its labels where they
    // were and the hex editor's mark of the visible page.
    function repaint() {
        document.querySelectorAll('.fmap-view, .fmap-strip').forEach(container => {
            if (!container._fmapRepaint || container.firstChild !== container._fmapShown) return;
            const old = container._viewportMarker;
            const mark = old && { left: old.style.left, width: old.style.width, visible: old.classList.contains('visible') };
            container._fmapRepaint();
            const marker = container._viewportMarker;
            if (mark && marker) {
                marker.style.left = mark.left;
                marker.style.width = mark.width;
                if (mark.visible) marker.classList.add('visible');
            }
        });
    }

    // --- Horizontal strip (hex minimap + inline analyzer map) ----------

    function renderStrip(container, vis, opts = {}) {
        const trackH = opts.trackHeight || 16;
        const width = opts.width || 1200;
        container.innerHTML = '';
        container.classList.add('fmap-strip');

        const mkTrack = (label, painter) => {
            const row = document.createElement('div');
            row.className = 'fmap-strip-row';
            const cap = document.createElement('span');
            cap.className = 'fmap-strip-label';
            cap.textContent = label;
            const canvas = painter();
            canvas.className = 'fmap-canvas fmap-strip-canvas';
            canvas.style.height = `${trackH}px`;
            attachInteraction(canvas, vis, (evt, rect) => {
                const frac = (evt.clientX - rect.left) / rect.width;
                const offset = Math.floor(frac * vis.file_size);
                return offset >= 0 && offset < vis.file_size ? offset : null;
            });
            row.appendChild(cap);
            row.appendChild(canvas);
            container.appendChild(row);
            return canvas;
        };

        // Horizontal planes: collapse each plane to a single row of cells.
        mkTrack('bytes', () => {
            const total = byteCellCount(vis);
            const cells = Math.min(width, total) || 1;
            const canvas = document.createElement('canvas');
            canvas.width = cells;
            canvas.height = 1;
            const ctx = canvas.getContext('2d');
            const img = ctx.createImageData(cells, 1);
            for (let i = 0; i < cells; i++) {
                const c = cellColor(vis, Math.floor((i / cells) * total)) || BYTE_COLORS[0];
                img.data[i * 4] = c[0];
                img.data[i * 4 + 1] = c[1];
                img.data[i * 4 + 2] = c[2];
                img.data[i * 4 + 3] = 255;
            }
            ctx.putImageData(img, 0, 0);
            return canvas;
        });

        mkTrack('entropy', () => {
            const cells = Math.min(width, Math.max(1, vis.entropyPlane.length));
            const canvas = document.createElement('canvas');
            canvas.width = cells;
            canvas.height = 1;
            const ctx = canvas.getContext('2d');
            const img = ctx.createImageData(cells, 1);
            for (let i = 0; i < cells; i++) {
                const src = Math.floor((i / cells) * vis.entropyPlane.length);
                const c = entropyColor((vis.entropyPlane[src] || 0) / 255);
                img.data[i * 4] = c[0];
                img.data[i * 4 + 1] = c[1];
                img.data[i * 4 + 2] = c[2];
                img.data[i * 4 + 3] = 255;
            }
            ctx.putImageData(img, 0, 0);
            return canvas;
        });

        const structCanvas = mkTrack('structure', () => {
            const canvas = document.createElement('canvas');
            canvas.width = Math.max(width, 1200);
            canvas.height = 1;
            const ctx = canvas.getContext('2d');
            const size = vis.file_size || 1;
            ctx.fillStyle = themeColor('--c-navy-900');
            ctx.fillRect(0, 0, canvas.width, 1);
            (vis.regions || []).forEach(r => {
                ctx.fillStyle = r.color;
                ctx.fillRect((r.offset / size) * canvas.width,
                             0,
                             Math.max((r.size / size) * canvas.width, 1.2),
                             1);
            });
            return canvas;
        });

        // Named labels under the structure track. Labels are placed at their
        // region's offset, so they can collide: biggest regions claim their
        // slot first and any label that would overlap one already placed is
        // dropped (its name stays reachable via tooltip and legend).
        const labels = document.createElement('div');
        labels.className = 'fmap-strip-names';
        container.appendChild(labels);

        const trackWidth = opts.labelWidth || labels.clientWidth || 900;
        const placed = [];   // [left, right] in px, kept sorted-free for simple checks
        const CHAR_PX = 5.3; // approx. width of one 9px monospace glyph
        const DOT_PX = 12;   // color dot + gap
        const GAP_PX = 8;    // breathing room between two labels

        (vis.regions || [])
            .filter(r => r.size / vis.file_size > 0.015)
            .slice()
            .sort((a, b) => b.size - a.size)
            .forEach(r => {
                const left = (r.offset / vis.file_size) * trackWidth;
                const textPx = r.name.length * CHAR_PX + DOT_PX;
                // Never let a label reach past the track's right edge.
                const right = Math.min(left + textPx, trackWidth);
                const collides = placed.some(([l, rr]) =>
                    left < rr + GAP_PX && right + GAP_PX > l);
                if (collides) return;
                placed.push([left, right]);

                const span = document.createElement('span');
                span.className = 'fmap-strip-name';
                span.style.left = `${(left / trackWidth) * 100}%`;
                span.style.maxWidth = `${trackWidth - left}px`;
                span.title = `${r.name} @ ${hexOff(r.offset)} (${formatSize(r.size)}) — click to open in hex editor`;
                span.innerHTML = `<span class="fmap-dot" style="background:${r.color}"></span>${escapeHtml(r.name)}`;
                span.addEventListener('click', () => jumpToHex(vis.path, r.offset));
                labels.appendChild(span);
            });

        if (opts.viewport) {
            const marker = document.createElement('div');
            marker.className = 'fmap-strip-viewport';
            container.appendChild(marker);
            container._viewportMarker = marker;
        }
        container._structCanvas = structCanvas;
        keepForRepaint(container, () => renderStrip(container, vis, { ...opts, labelWidth: trackWidth }));
        return container;
    }

    function updateViewport(container, offset, length, fileSize) {
        const marker = container && container._viewportMarker;
        if (!marker || !fileSize) return;
        marker.style.left = `${(offset / fileSize) * 100}%`;
        marker.style.width = `${Math.max((length / fileSize) * 100, 0.4)}%`;
        marker.classList.add('visible');
    }

    // --- Import / Export trees ----------------------------------------

    function treeHtml(vis) {
        const imports = vis.import_tree || [];
        const exports = vis.export_tree;
        if (!imports.length && !exports) {
            return '<div class="fmap-tree-empty">No import or export table in this file.</div>';
        }

        let html = '<div class="fmap-trees">';

        if (imports.length) {
            const totalFuncs = imports.reduce((a, d) => a + d.count, 0);
            const totalSusp = imports.reduce((a, d) => a + d.suspicious_count, 0);
            html += `<div class="fmap-tree">`;
            html += `<div class="fmap-tree-head">Import Tree <span class="fmap-tree-meta">${imports.length} module(s) &middot; ${totalFuncs} symbol(s)`;
            if (totalSusp) html += ` &middot; <span class="fmap-susp">${totalSusp} suspicious</span>`;
            html += `</span></div>`;
            imports.forEach((dll, i) => {
                const open = i === 0 && dll.count > 0 ? ' open' : '';
                html += `<details class="fmap-node"${open}>`;
                html += `<summary class="fmap-node-head"><span class="fmap-node-icon">\u25B8</span>`;
                html += `<span class="fmap-node-name">${escapeHtml(dll.dll)}</span>`;
                html += `<span class="fmap-node-count">${dll.count}</span>`;
                if (dll.suspicious_count) html += `<span class="fmap-node-susp">${dll.suspicious_count} susp</span>`;
                html += `</summary>`;
                if (dll.note) html += `<div class="fmap-node-note">${escapeHtml(dll.note)}</div>`;
                if (dll.functions && dll.functions.length) {
                    html += '<div class="fmap-leaves">';
                    dll.functions.forEach(fn => {
                        const susp = fn.category ? ' suspicious' : '';
                        html += `<div class="fmap-leaf${susp}">${escapeHtml(fn.name)}`;
                        if (fn.category) html += `<span class="fmap-leaf-tag">${escapeHtml(fn.category.replace(/_/g, ' '))}</span>`;
                        if (fn.type) html += `<span class="fmap-leaf-dim">${escapeHtml(fn.type)}</span>`;
                        html += `</div>`;
                    });
                    if (dll.count > dll.functions.length) {
                        html += `<div class="fmap-leaf fmap-leaf-dim">… ${dll.count - dll.functions.length} more</div>`;
                    }
                    html += '</div>';
                }
                html += '</details>';
            });
            html += '</div>';
        }

        if (exports) {
            html += `<div class="fmap-tree">`;
            html += `<div class="fmap-tree-head">Export Tree <span class="fmap-tree-meta">${exports.count} symbol(s)</span></div>`;
            html += `<details class="fmap-node" open><summary class="fmap-node-head"><span class="fmap-node-icon">\u25B8</span>`;
            html += `<span class="fmap-node-name">${escapeHtml(exports.dll)}</span>`;
            html += `<span class="fmap-node-count">${exports.count}</span></summary>`;
            html += '<div class="fmap-leaves">';
            exports.functions.forEach(fn => {
                html += `<div class="fmap-leaf">${escapeHtml(fn.name)}`;
                if (fn.address) html += `<span class="fmap-leaf-dim">${escapeHtml(fn.address)}</span>`;
                html += `</div>`;
            });
            if (exports.count > exports.functions.length) {
                html += `<div class="fmap-leaf fmap-leaf-dim">… ${exports.count - exports.functions.length} more</div>`;
            }
            html += '</div></details></div>';
        }

        html += '</div>';
        return html;
    }

    return {
        load, renderVertical, renderStrip, updateViewport, repaint,
        treeHtml, legendHtml, hexOff, jumpToHex,
        clearCache: () => cache.clear(),
    };
})();

// --- FileMap tab ----------------------------------------------------

async function fileMapRender(path) {
    const target = path || document.getElementById('filemap-path').value.trim()
        || state.hexFilePath;
    const body = document.getElementById('filemap-body');
    const meta = document.getElementById('filemap-meta');
    const trees = document.getElementById('filemap-trees');
    if (!target) {
        body.innerHTML = '<div class="filemap-empty">Enter a file path (or load a file in the hex editor) and click Render.</div>';
        meta.innerHTML = '';
        trees.innerHTML = '';
        return;
    }

    document.getElementById('filemap-path').value = target;
    body.innerHTML = '<div class="pe-loading"><div class="loading-spinner"></div><span>Building visualization...</span></div>';
    trees.innerHTML = '';

    try {
        LoadingSpinner.start();
        // One plane row per displayed pixel row: avoids upscaling the planes,
        // which is what made large files look blocky.
        const height = parseInt(document.getElementById('filemap-height').value) || 740;
        const vis = await FileMapView.load(target, {
            cols: parseInt(document.getElementById('filemap-cols').value) || 256,
            rows: height,
        });
        LoadingSpinner.stop();

        meta.innerHTML = `
            <span class="hex-info-item"><strong>File:</strong> ${escapeHtml(vis.filename)}</span>
            <span class="hex-info-item"><strong>Format:</strong> ${escapeHtml(vis.format)}</span>
            <span class="hex-info-item"><strong>Size:</strong> ${formatSize(vis.file_size)}</span>
            <span class="hex-info-item"><strong>Entropy:</strong> ${vis.total_entropy}</span>
            <span class="hex-info-item"><strong>Bytes/cell:</strong> ${vis.bytes_per_cell}</span>
            <span class="hex-info-item"><strong>Regions:</strong> ${(vis.regions || []).length}</span>
            ${vis.truncated ? '<span class="hex-info-item" style="color:var(--accent-yellow);">truncated to first 64 MB</span>' : ''}
            ${vis.parse_error ? `<span class="hex-info-item" style="color:var(--accent-red);">${escapeHtml(vis.parse_error)}</span>` : ''}
        `;

        FileMapView.renderVertical(body, vis, {
            height: height,
        });
        trees.innerHTML = FileMapView.treeHtml(vis);
    } catch (e) {
        LoadingSpinner.stop();
        body.innerHTML = `<div class="pe-error">${escapeHtml(e.message)}</div>`;
    }
}

function initFileMapTab() {
    const path = document.getElementById('filemap-path');
    if (path && !path.value && state.hexFilePath) path.value = state.hexFilePath;
    const body = document.getElementById('filemap-body');
    // Auto-render once when a file is already known from the hex editor.
    if (body && !body.dataset.rendered && (path.value || state.hexFilePath)) {
        body.dataset.rendered = '1';
        fileMapRender(path.value || state.hexFilePath);
    }
}

function initFileMapDropZone() {
    const zone = document.getElementById('filemap-drop-zone');
    const input = document.getElementById('filemap-file-input');
    if (!zone || !input) return;

    const upload = async file => {
        const fd = new FormData();
        fd.append('file', file);
        fd.append('bytes', 256);
        zone.classList.add('loading');
        try {
            const resp = await fetch('/api/file/hex/upload', { method: 'POST', body: fd });
            const data = await resp.json();
            zone.classList.remove('loading');
            if (data.error) return;
            state.hexFilePath = data.path;
            document.getElementById('filemap-path').value = data.path;
            fileMapRender(data.path);
        } catch (e) {
            zone.classList.remove('loading');
        }
    };

    zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('dragover'); });
    zone.addEventListener('dragleave', () => zone.classList.remove('dragover'));
    zone.addEventListener('drop', e => {
        e.preventDefault();
        zone.classList.remove('dragover');
        if (e.dataTransfer.files.length) upload(e.dataTransfer.files[0]);
    });
    input.addEventListener('change', () => {
        if (input.files.length) { upload(input.files[0]); input.value = ''; }
    });
}

// --- Hex editor minimap ---------------------------------------------

async function hexRenderMinimap() {
    const container = document.getElementById('hex-minimap');
    if (!container || !state.hexFilePath) return;
    container.dataset.path = state.hexFilePath;
    try {
        const vis = await FileMapView.load(state.hexFilePath, { cols: 256, rows: 512 });
        FileMapView.renderStrip(container, vis, { viewport: true, trackHeight: 14 });
        container.classList.add('visible');
        hexUpdateMinimapViewport();
        const info = document.getElementById('hex-minimap-info');
        if (info) {
            info.innerHTML = `${escapeHtml(vis.format)} &middot; ${(vis.regions || []).length} regions`
                + `<button class="btn btn-sm" onclick="fileMapRender(${jsArg(state.hexFilePath)});switchTab('filemap');">Full map</button>`;
        }
    } catch (e) {
        container.classList.remove('visible');
    }
}

function hexUpdateMinimapViewport() {
    const container = document.getElementById('hex-minimap');
    if (!container) return;
    const bytesPerPage = parseInt(document.getElementById('hex-bytes-per-page').value) || 512;
    FileMapView.updateViewport(container, state.hexOffset, bytesPerPage, state.hexFileSize);
}

// --- Inline map for the PE/ELF analysis panels -----------------------

// Markup placeholder; the canvases need the nodes to exist in the DOM first.
// `scope` keeps the ids unique per panel: the PE and ELF panels both stay in
// the page, and a shared id sent the ELF map into the hidden PE panel. Given
// a card id (`view`) and its switch (`toggle`, viewToggleHtml), the block shows
// the regions of the strip's structure track as a table as well (TABLE).
function fileMapInlineBlock(path, scope = 'pe', view = '', toggle = '') {
    const safe = jsArg(path || '');
    let html = '<div class="fmap-inline">';
    html += '<div class="fmap-inline-head"><span class="die-section-title">FILE MAP</span>';
    html += `<span class="fmap-inline-tools">${toggle}<button class="btn btn-sm" onclick="fileMapRender(${safe});switchTab('filemap');">Open full map</button></span></div>`;
    html += `<div class="fmap-inline-body" id="fmap-inline-map-${scope}"${view ? cardViewAttrs(view, 'chart') : ''}><div class="fmap-inline-wait">building planes…</div></div>`;
    if (view) {
        html += `<div class="fmap-inline-table view-table-wrap" id="fmap-inline-table-${scope}"${cardViewAttrs(view, 'table')}>`
            + '<div class="fmap-inline-wait">building the table…</div></div>';
    }
    html += '<details class="fmap-inline-trees"><summary class="die-section-title die-clickable">IMPORT / EXPORT TREE</summary>';
    html += `<div id="fmap-inline-trees-${scope}"></div></details>`;
    html += '</div>';
    return html;
}

function fileMapInlineMount(path, scope = 'pe') {
    if (!path) return;
    // renderInlineFileMap, the tree and the table share one cached load (see
    // FileMapView.load), so this does not fetch the map twice. Like the strip,
    // the tree and the table are taken before the load: when the analysis of
    // the next file has replaced the panel by then, this file's map goes into
    // its own (detached) nodes and not into the next file's panel.
    const trees = document.getElementById(`fmap-inline-trees-${scope}`);
    const table = document.getElementById(`fmap-inline-table-${scope}`);
    renderInlineFileMap(`fmap-inline-map-${scope}`, path);
    FileMapView.load(path, { cols: 256, rows: 512 }).then(vis => {
        if (trees) trees.innerHTML = FileMapView.treeHtml(vis);
        if (table) table.innerHTML = fileMapRegionsTableHtml(vis);
    }).catch(e => {
        if (table) table.innerHTML = `<div class="pe-error">File map failed: ${escapeHtml(e.message)}</div>`;
    });
}

// The table view of the inline file map: the regions of its structure track
// (headers, sections, data directories, overlay) in file order, with the
// permissions and the entropy the sections (and the overlay) carry
function fileMapRegionsTableHtml(vis) {
    const regions = (vis.regions || []).slice()
        .sort((a, b) => ((Number(a.offset) || 0) - (Number(b.offset) || 0)) || ((a.priority || 0) - (b.priority || 0)));
    const rows = regions.map(region => {
        const detail = region.detail || {};
        const entropy = detail.entropy === null || detail.entropy === undefined ? NaN : Number(detail.entropy);
        // The strip's colour of the region (only a colour reaches the style)
        const color = /^#[0-9a-f]{3,8}$/i.test(String(region.color || '')) ? region.color : '';
        return `<tr><td title="${escapeHtml(region.name)}">${color ? `<span class="view-table-dot" style="background:${color}"></span>` : ''}`
            + `<span class="view-table-clip">${escapeHtml(region.name)}</span></td>`
            + `<td class="mono" data-sort-value="${sortNumberValue(region.offset)}">${FileMapView.hexOff(Number(region.offset) || 0)}</td>`
            + `<td data-sort-value="${sortNumberValue(region.size)}">${formatSize(region.size)}</td>`
            + `<td class="mono">${detail.permissions ? escapeHtml(detail.permissions) : '&mdash;'}</td>`
            + `<td data-sort-value="${Number.isFinite(entropy) ? sortNumberValue(entropy) : ''}">${Number.isFinite(entropy) ? entropy.toFixed(2) : '&mdash;'}</td></tr>`;
    });
    if (!rows.length) rows.push('<tr data-sort-skip><td colspan="5" class="view-table-empty">No structure found in this file.</td></tr>');
    return '<table class="view-table" data-sortable data-sort-id="file-map-regions"><thead><tr><th>Name</th><th>Offset</th>'
        + `<th>Raw Size</th><th>Permissions</th><th>Entropy</th></tr></thead><tbody>${rows.join('')}</tbody></table>`;
}

async function renderInlineFileMap(containerId, path) {
    const container = document.getElementById(containerId);
    if (!container || !path) return;
    try {
        const vis = await FileMapView.load(path, { cols: 256, rows: 512 });
        container.innerHTML = '';
        const strip = document.createElement('div');
        container.appendChild(strip);
        FileMapView.renderStrip(strip, vis, { trackHeight: 18 });
        const legend = document.createElement('div');
        legend.innerHTML = FileMapView.legendHtml(vis);
        legend.firstChild.classList.add('fmap-legend-inline');
        container.appendChild(legend.firstChild);
    } catch (e) {
        container.innerHTML = `<div class="pe-error">File map failed: ${escapeHtml(e.message)}</div>`;
    }
}

// =============================================
// LIVE-MEMORY TOOLS (Aether / Process Dump)
// Aether scans a running process for injection and implant structures;
// Process Dump writes its memory components back to disk so they can be fed
// into the file map, PE analyzer, capa and the scanners.
// =============================================

// Severity order used for sorting findings worst-first.
const AETHER_SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4, unknown: 5 };

function aetherSeverityClass(sev) {
    const s = (sev || '').toLowerCase();
    if (s === 'critical') return 'sev-critical';
    if (s === 'high') return 'sev-high';
    if (s === 'medium') return 'sev-medium';
    if (s === 'low') return 'sev-low';
    return 'sev-info';
}

function renderAetherBlock(aether, opts = {}) {
    let html = `<div class="det-sub-title" data-info="Aether scans the running process for thread start addresses, PE images and .NET assemblies in private memory, heap API tables and in-memory signatures. Its findings feed the memory evidence score.">Aether &mdash; live-memory forensics</div>`;

    if (aether.error) {
        return html + `<div class="det-sub-value det-warn">${escapeHtml(aether.error)}</div>`;
    }
    if (aether.parse_error) {
        html += `<div class="det-sub-value det-warn">${escapeHtml(aether.parse_error)}</div>`;
    }

    // The scored evidence comes first: it is what the verdict is based on,
    // while the raw tool output below is the material it was derived from.
    // Skipped when an aggregated cross-source block is shown above.
    if (aether.evidence && opts.showEvidence !== false) {
        html += renderMemoryEvidence(aether.evidence, aether);
    }

    const s = aether.summary || {};
    const report = aether.report || {};

    // Headline counts
    html += `<div class="mem-chips">`;
    const chip = (label, value, cls) =>
        `<span class="mem-chip ${cls || ''}"><span class="mem-chip-val">${value}</span>${escapeHtml(label)}</span>`;
    // Structural IOCs carry Aether's own corroborated severity; signature
    // groups are graded critical even for low-risk patterns, so they are
    // counted separately to keep the headline honest.
    if (s.structural_critical) html += chip('critical IOC', s.structural_critical, 'sev-critical');
    if (s.structural_high) html += chip('high IOC', s.structural_high, 'sev-high');
    if (s.structural_total) html += chip('structural findings', s.structural_total);
    if (s.signature_high_risk) html += chip('high-risk sig hits', s.signature_high_risk, 'sev-high');
    if (s.signature_hits) html += chip('sig hits total', s.signature_hits, 'sev-info');
    if (s.dotnet_assemblies_in_private)
        html += chip('.NET in private mem', s.dotnet_assemblies_in_private, 'sev-high');
    if (s.pe_headers_in_private)
        html += chip('PE headers in private mem', s.pe_headers_in_private, 'sev-medium');
    html += `</div>`;

    if (!s.findings_total) {
        html += `<div class="det-sub-value">No memory IOCs reported`;
        if (s.regions_scanned) html += ` (${s.regions_scanned} regions scanned)`;
        html += `</div>`;
    }

    // Thread start-address verdicts: the highest-signal subset, so call it out.
    if (s.tsav && Object.keys(s.tsav).length) {
        html += `<div class="mem-section-label">Thread start-address verdicts</div><div class="mem-chips">`;
        Object.entries(s.tsav).forEach(([type, count]) => {
            html += chip(type.replace(/^TSAV_/, '').replace(/_/g, ' ').toLowerCase(), count, 'sev-critical');
        });
        html += `</div>`;
    }

    // Aether reports structural IOCs and signature groups in one array;
    // they have different shapes, so split them apart for display.
    const all = report.findings || [];
    const structural = all.filter(f => f.type);
    const sigGroups = all.filter(f => f.category);

    structural.sort((a, b) =>
        (AETHER_SEVERITY_RANK[(a.severity || 'unknown').toLowerCase()] ?? 5) -
        (AETHER_SEVERITY_RANK[(b.severity || 'unknown').toLowerCase()] ?? 5));

    if (structural.length) {
        html += `<div class="mem-section-label">Structural memory IOCs (${structural.length})</div>`;
        structural.slice(0, 40).forEach(f => {
            html += `<div class="mem-finding ${aetherSeverityClass(f.severity)}">`;
            html += `<div class="mem-finding-head">`;
            html += `<span class="mem-sev">${escapeHtml((f.severity || '?').toUpperCase())}</span>`;
            html += `<span class="mem-type">${escapeHtml(f.type || '?')}</span>`;
            if (f.address) html += `<span class="mem-addr">${escapeHtml(f.address)}</span>`;
            if (f.size) html += `<span class="mem-size">${formatSize(f.size)}</span>`;
            html += `</div>`;
            if (f.description) html += `<div class="mem-desc">${escapeHtml(f.description)}</div>`;
            if (f.evidence) html += `<div class="mem-evidence">${escapeHtml(f.evidence)}</div>`;
            const extra = [];
            ['private_pages', 'region_pages', 'pointer_count', 'module_count', 'thread_id']
                .forEach(k => { if (f[k] != null) extra.push(`${k.replace(/_/g, ' ')}: ${f[k]}`); });
            if (extra.length) html += `<div class="mem-kv">${escapeHtml(extra.join('  \u00B7  '))}</div>`;
            html += `</div>`;
        });
        if (structural.length > 40) {
            html += `<div class="det-sub-value">… ${structural.length - 40} more</div>`;
        }
    }

    // Signature groups: one block per category, highest risk_score first.
    if (sigGroups.length) {
        html += `<div class="mem-section-label">In-memory signatures (${sigGroups.length} categor`
            + `${sigGroups.length === 1 ? 'y' : 'ies'}, ${s.signature_hits || 0} hit(s))</div>`;
        sigGroups.slice().sort((a, b) => (b.score || 0) - (a.score || 0)).forEach(g => {
            const hits = (g.hits || []).slice()
                .sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0));
            const topRisk = hits.length ? (hits[0].risk_score || 0) : 0;
            // Low-risk patterns are common in benign software; mark them as such.
            const cls = topRisk >= 8 ? 'sev-high' : 'sev-info';
            html += `<div class="mem-finding ${cls}">`;
            html += `<div class="mem-finding-head">`;
            html += `<span class="mem-type">${escapeHtml(g.category || '?')}</span>`;
            if (g.mitre) html += `<span class="mem-mitre">${escapeHtml(g.mitre)}</span>`;
            html += `<span class="mem-size">${g.hit_count || hits.length} hit(s)</span>`;
            if (g.score != null) html += `<span class="mem-size">score ${g.score}</span>`;
            html += `<span class="mem-size">max risk ${topRisk}</span>`;
            html += `</div>`;
            hits.slice(0, 6).forEach(h => {
                html += `<div class="mem-kv">`;
                html += `<span class="mem-pattern">${escapeHtml(h.pattern || '')}</span>`;
                if (h.risk_score != null) html += ` risk ${h.risk_score}`;
                if (h.encoding) html += ` · ${escapeHtml(h.encoding)}`;
                if (h.offset) html += ` @ ${escapeHtml(h.offset)}`;
                if (h.description) html += ` — ${escapeHtml(h.description)}`;
                html += `</div>`;
            });
            if (hits.length > 6) html += `<div class="mem-kv">… ${hits.length - 6} more hit(s)</div>`;
            html += `</div>`;
        });
    }

    if (s.mitre && s.mitre.length) {
        html += `<div class="mem-section-label">MITRE techniques</div><div class="mem-chips">`;
        s.mitre.forEach(t => { html += `<span class="mem-chip mem-mitre">${escapeHtml(t)}</span>`; });
        html += `</div>`;
    }

    if (s.scan_time_ms) {
        html += `<div class="mem-foot">${s.regions_scanned || 0} regions in ${s.scan_time_ms} ms</div>`;
    }
    html += _detRawButton('View Aether raw', aether);
    return html;
}

function renderProcessDumpBlock(pd) {
    let html = `<div class="det-sub-title" data-info="Process Dump writes unpacked modules, hidden modules and loose code from memory to disk and skips the modules in its clean-hash database. Map and Hex open a dump in the file map or the hex editor.">Process Dump &mdash; memory extraction</div>`;
    if (pd.error) {
        return html + `<div class="det-sub-value det-warn">${escapeHtml(pd.error)}</div>`;
    }

    html += `<div class="mem-chips">`;
    const chip = (label, value, cls) =>
        `<span class="mem-chip ${cls || ''}"><span class="mem-chip-val">${value}</span>${escapeHtml(label)}</span>`;
    html += chip('dumps', pd.dump_count || 0);
    // Both of these mean "code that no loader put there in a normal way".
    if (pd.hidden_modules) html += chip('hidden modules', pd.hidden_modules, 'sev-high');
    if (pd.code_chunks) html += chip('loose code chunks', pd.code_chunks, 'sev-high');
    html += `</div>`;

    if (!pd.dump_count) {
        html += `<div class="det-sub-value">Nothing dumped — every module matched the clean-hash baseline.</div>`;
        return html + _detRawButton('View Process Dump raw', pd);
    }

    html += `<div class="mem-section-label">Dumped files <span class="mem-foot-inline">${escapeHtml(pd.output_dir || '')}</span></div>`;
    html += `<table class="mem-dump-table" data-sortable data-sort-id="processdump-files"><thead><tr><th>file</th><th>kind</th><th>arch</th><th>size</th><th></th></tr></thead><tbody>`;
    (pd.dumps || []).forEach(d => {
        const kindCls = d.host_class ? 'sev-info'
            : d.kind === 'hiddenmodule' ? 'sev-high'
            : d.kind === 'codechunk' ? 'sev-medium' : '';
        const esc = jsArg(d.path || '');
        html += `<tr>`;
        html += `<td class="mem-dump-name" title="${escapeHtml(d.sha256 || '')}">${escapeHtml(d.filename)}</td>`;
        html += `<td><span class="mem-chip ${kindCls}" title="${escapeHtml(d.host_reason || '')}">`
            + `${escapeHtml(d.host_class ? `${d.kind} (host: ${d.host_class})` : (d.kind || ''))}</span></td>`;
        html += `<td>${escapeHtml(d.arch || '')}</td>`;
        html += `<td data-sort-value="${sortNumberValue(d.size || 0)}">${formatSize(d.size || 0)}</td>`;
        // A dump is just a PE on disk, so hand it to the existing analyzers.
        html += `<td class="mem-dump-actions">`;
        html += `<button class="btn btn-sm" onclick="fileMapRender(${esc});switchTab('filemap');">Map</button>`;
        html += `<button class="btn btn-sm" onclick="hexOpenFile(${esc})">Hex</button>`;
        html += `</td></tr>`;
    });
    html += `</tbody></table>`;
    return html + _detRawButton('View Process Dump raw', pd);
}

// --- On-demand scans from the process views ---

async function runAetherScan(pid, targetId, opts = {}) {
    const target = document.getElementById(targetId);
    const samples = opts.samples
        || parseInt((document.getElementById('livemem-samples') || {}).value) || 1;
    const interval = opts.interval
        || parseInt((document.getElementById('livemem-interval') || {}).value) || 3;
    if (target) {
        const note = samples > 1
            ? `Scanning process memory ${samples}x (${interval}s apart) to separate persistent from transient findings...`
            : 'Scanning process memory with Aether...';
        target.innerHTML = '<div class="pe-loading"><div class="loading-spinner"></div>'
            + `<span>${escapeHtml(note)}</span></div>`;
    }
    try {
        LoadingSpinner.start();
        const resp = await fetch('/api/scan/aether', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ pid: pid, samples: samples, interval: interval }),
        });
        const data = await resp.json();
        LoadingSpinner.stop();
        if (target) {
            target.innerHTML = data.error
                ? `<div class="pe-error">${escapeHtml(data.error)}</div>`
                : renderAetherBlock(data);
        }
        loadScanHistory();
        return data;
    } catch (e) {
        LoadingSpinner.stop();
        if (target) target.innerHTML = `<div class="pe-error">${escapeHtml(e.message)}</div>`;
    }
}

async function runProcessDump(pid, targetId) {
    const target = document.getElementById(targetId);
    if (target) {
        target.innerHTML = '<div class="pe-loading"><div class="loading-spinner"></div>'
            + '<span>Dumping memory components...</span></div>';
    }
    try {
        LoadingSpinner.start();
        const resp = await fetch('/api/scan/processdump', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ pid: pid }),
        });
        const data = await resp.json();
        LoadingSpinner.stop();
        if (target) {
            target.innerHTML = data.error
                ? `<div class="pe-error">${escapeHtml(data.error)}</div>`
                : renderProcessDumpBlock(data);
        }
        loadScanHistory();
        return data;
    } catch (e) {
        LoadingSpinner.stop();
        if (target) target.innerHTML = `<div class="pe-error">${escapeHtml(e.message)}</div>`;
    }
}

// --- Live-memory panel in the ThreatScan tab -------------------------
// The sidebar process list is telemetry-driven and keeps exited processes,
// so this panel talks to the OS process table instead.

async function livememLookup() {
    const name = document.getElementById('livemem-name').value.trim();
    const result = document.getElementById('livemem-result');
    if (!name) {
        result.innerHTML = '<div class="pe-error">Enter a process name to look up.</div>';
        return;
    }
    try {
        const resp = await fetch(`/api/process/lookup?name=${encodeURIComponent(name)}`);
        const data = await resp.json();
        if (data.error) {
            result.innerHTML = `<div class="pe-error">${escapeHtml(data.error)}</div>`;
            return;
        }
        if (!data.count) {
            result.innerHTML = `<div class="det-sub-value">No running process matches "${escapeHtml(name)}".</div>`;
            return;
        }
        let html = `<div class="mem-section-label">${data.count} match(es)</div>`;
        html += '<div class="mem-chips">';
        data.matches.forEach(m => {
            html += `<span class="mem-chip fmap-legend-jump" onclick="livememSelect(${jsInt(m.pid)})" `
                + `title="Use PID ${escapeHtml(String(m.pid))}"><span class="mem-chip-val">${escapeHtml(String(m.pid))}</span>`
                + `${escapeHtml(m.name)}</span>`;
        });
        html += '</div>';
        // One match is unambiguous, so select it right away.
        if (data.count === 1) livememSelect(data.matches[0].pid);
        result.innerHTML = html;
    } catch (e) {
        result.innerHTML = `<div class="pe-error">${escapeHtml(e.message)}</div>`;
    }
}

function livememSelect(pid) {
    document.getElementById('livemem-pid').value = pid;
}

function _livememPid() {
    const pid = parseInt(document.getElementById('livemem-pid').value);
    if (!pid) {
        document.getElementById('livemem-result').innerHTML =
            '<div class="pe-error">Enter a PID (or look one up by name).</div>';
        return null;
    }
    return pid;
}

function livememAether() {
    const pid = _livememPid();
    if (pid) runAetherScan(pid, 'livemem-result');
}

function livememDump() {
    const pid = _livememPid();
    if (pid) runProcessDump(pid, 'livemem-result');
}

// Reflect tool availability in the panel's badge and buttons.
function updateLiveMemStatus() {
    const badge = document.getElementById('livemem-status');
    const aetherOk = state.aetherStatus ? state.aetherStatus.installed !== false : true;
    const pdOk = state.processDumpStatus ? state.processDumpStatus.installed !== false : true;
    if (badge) {
        const parts = [`Aether ${aetherOk ? '\u2713' : '\u2717'}`];
        if (aetherOk && state.aetherStatus && state.aetherStatus.rules != null) {
            parts[0] += ` (${state.aetherStatus.rules} rule files)`;
        }
        parts.push(`Process Dump ${pdOk ? '\u2713' : '\u2717'}`);
        if (pdOk && state.processDumpStatus && state.processDumpStatus.clean_db === false) {
            parts.push('no clean-hash baseline');
        }
        badge.textContent = parts.join('  \u00B7  ');
    }
    const ab = document.getElementById('livemem-aether-btn');
    if (ab) {
        ab.disabled = !aetherOk;
        ab.title = aetherOk ? '' : 'Aether is not installed on this VM';
    }
    const db = document.getElementById('livemem-dump-btn');
    if (db) {
        db.disabled = !pdOk;
        db.title = pdOk ? '' : 'Process Dump is not installed on this VM';
    }
}

// --- Scored memory evidence -----------------------------------------
// Rendered from the tool-agnostic evidence model: every finding shows the
// factors that produced its confidence, so a verdict can be audited instead
// of taken on faith.

function evidenceClassLabel(cls) {
    return {
        structural: 'structural fact',
        behavioral: 'behavioural',
        artifact: 'extracted artifact',
        string: 'byte pattern',
    }[cls] || cls;
}

function confidenceClass(conf) {
    if (conf >= 0.9) return 'sev-critical';
    if (conf >= 0.5) return 'sev-high';
    if (conf > 0) return 'sev-medium';
    return 'sev-info';
}

function renderMemoryEvidence(ev, meta) {
    const verdictCls = ev.label === 'MALICIOUS' ? 'sev-critical'
        : ev.label === 'SUSPICIOUS' ? 'sev-high'
        : ev.label === 'NOT OBSERVED' ? 'sev-medium' : 'sev-low';

    let html = `<div class="mem-verdict ${verdictCls}">`;
    html += `<span class="mem-verdict-label">${escapeHtml(ev.label)}</span>`;
    html += `<span class="mem-verdict-score">score ${ev.score}`;
    if (ev.thresholds) {
        html += ` <span class="mem-foot-inline">(suspicious \u2265 ${ev.thresholds.suspicious}, `
            + `malicious \u2265 ${ev.thresholds.malicious})</span>`;
    }
    html += `</span></div>`;

    // A failed observation is not a clean result; say so prominently.
    if (ev.note) {
        html += `<div class="mem-note">${escapeHtml(ev.note)}</div>`;
    }

    html += `<div class="mem-chips">`;
    const chip = (label, value, cls) =>
        `<span class="mem-chip ${cls || ''}"><span class="mem-chip-val">${value}</span>${escapeHtml(label)}</span>`;
    (ev.sources_present || ev.sources || []).forEach(src => { html += chip(src, '', ''); });
    Object.entries(ev.by_evidence || {}).forEach(([cls, pts]) => {
        html += chip(evidenceClassLabel(cls), pts, confidenceClass(pts > 0 ? 1 : 0));
    });
    if (meta && (meta.samples || 0) > 1) {
        html += chip(`samples (${meta.sample_interval}s apart)`, meta.samples);
    }
    if (ev.suppressed_count) {
        html += chip('suppressed by baseline', ev.suppressed_count, 'sev-info');
    }
    html += `</div>`;

    const scored = ev.findings || [];
    if (scored.length) {
        html += `<div class="mem-section-label">Scored evidence (${scored.length})</div>`;
        scored.slice(0, 30).forEach(f => {
            html += `<div class="mem-finding ${confidenceClass(f.confidence)}">`;
            html += `<div class="mem-finding-head">`;
            html += `<span class="mem-score">${f.score.toFixed(2)}</span>`;
            html += `<span class="mem-type">${escapeHtml(f.label)}</span>`;
            html += `<span class="mem-chip">${escapeHtml(f.source)}</span>`;
            html += `<span class="mem-chip">${escapeHtml(evidenceClassLabel(f.evidence))}</span>`;
            if (f.address) html += `<span class="mem-addr">${escapeHtml(f.address)}</span>`;
            html += `</div>`;
            if (f.detail) html += `<div class="mem-desc">${escapeHtml(f.detail)}</div>`;

            // Why this finding scored what it scored.
            const why = [`confidence ${f.confidence.toFixed(2)}`];
            if ((f.samples || 1) > 1) {
                why.push(`seen in ${f.seen_in}/${f.samples} samples`
                    + (f.persistence < 1 ? ' (transient)' : ' (persistent)'));
            }
            if (f.corroborated_by && f.corroborated_by.length) {
                why.push('corroborated by ' + f.corroborated_by.join(', '));
            } else if (f.needs_corroboration) {
                why.push('uncorroborated \u2014 weight reduced');
            }
            if (f.risk_score != null) why.push(`rule risk ${f.risk_score}`);
            const sat = f.saturation;
            if (sat && sat.group_size > 1) {
                // Explain zeroed rows: the group's cap was already used up.
                why.push(`${sat.rank} of ${sat.group_size} findings of this kind`
                    + ` · group capped at ${sat.group_cap}`
                    + (f.score === 0 ? ' (cap reached, not counted)' : ''));
            }
            html += `<div class="mem-kv">${escapeHtml(why.join('  \u00B7  '))}</div>`;
            html += `</div>`;
        });
        if (scored.length > 30) {
            html += `<div class="det-sub-value">… ${scored.length - 30} more</div>`;
        }
    } else {
        html += `<div class="det-sub-value">No finding carried enough weight to score.</div>`;
    }

    // Baseline-suppressed findings stay visible but collapsed: they are the
    // host's own noise, and hiding them entirely would make the baseline
    // impossible to sanity-check.
    if (ev.suppressed_count) {
        html += `<details class="mem-suppressed"><summary>`
            + `${ev.suppressed_count} finding(s) suppressed by the host baseline</summary>`;
        (ev.suppressed || []).slice(0, 30).forEach(f => {
            html += `<div class="mem-kv">${escapeHtml(f.label)}`;
            if (f.detail) html += ` \u2014 ${escapeHtml(f.detail)}`;
            html += ` <span class="mem-foot-inline">${escapeHtml(f.source)}</span></div>`;
        });
        html += `</details>`;
    }
    return html;
}

// --- Baseline controls ----------------------------------------------

async function memoryBaselineStatus() {
    const target = document.getElementById('livemem-baseline');
    if (!target) return;
    try {
        const resp = await fetch('/api/memory/baseline');
        const d = await resp.json();
        if (d.stale) {
            target.innerHTML = `<span class="mem-warn-inline">${escapeHtml(d.note || 'Baseline is outdated')} `
                + `(${d.stale_keys} old key(s) ignored).</span>`;
            return;
        }
        if (!d.total) {
            target.innerHTML = '<span class="mem-warn-inline">No host baseline — '
                + 'the box\'s own memory noise will count as evidence.</span>';
            return;
        }
        const kinds = Object.entries(d.by_kind || {})
            .sort((a, b) => b[1] - a[1])
            .map(([k, v]) => `${k} ${v}`).join(', ');
        target.innerHTML = `<span class="mem-foot-inline">Baseline: ${d.total} key(s)`
            + (kinds ? ` — ${escapeHtml(kinds)}` : '')
            + (d.updated ? ` · updated ${escapeHtml(d.updated)}` : '') + '</span>';
    } catch (e) {
        target.innerHTML = '';
    }
}

async function memoryBaselineCapture() {
    const target = document.getElementById('livemem-result');
    if (!confirm('Capture a memory baseline now?\n\n'
        + 'Everything the selected processes currently show will stop counting '
        + 'as evidence. Only do this while the box is clean.')) return;
    target.innerHTML = '<div class="pe-loading"><div class="loading-spinner"></div>'
        + '<span>Scanning processes for the baseline (2 samples each)...</span></div>';
    try {
        LoadingSpinner.start();
        const names = (document.getElementById('livemem-baseline-names').value || '').trim();
        const resp = await fetch('/api/memory/baseline/capture', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(names ? { names: names } : {}),
        });
        const d = await resp.json();
        LoadingSpinner.stop();
        if (d.error) {
            target.innerHTML = `<div class="pe-error">${escapeHtml(d.error)}</div>`;
            return;
        }
        let html = `<div class="mem-section-label">Baseline captured</div>`;
        html += `<div class="mem-chips"><span class="mem-chip"><span class="mem-chip-val">`
            + `${d.captured}</span>new key(s)</span>`
            + `<span class="mem-chip"><span class="mem-chip-val">${d.baseline.total}</span>total</span></div>`;
        html += `<table class="mem-dump-table" data-sortable data-sort-id="memory-baseline-capture"><thead><tr><th>process</th><th>pid</th><th>findings</th><th>new keys</th></tr></thead><tbody>`;
        (d.scanned || []).forEach(s => {
            html += `<tr><td class="mem-dump-name">${escapeHtml(s.process || '')}</td>`
                + `<td>${escapeHtml(String(s.pid))}</td><td>${escapeHtml(String(s.findings))}</td><td>${escapeHtml(String(s.new_keys))}</td></tr>`;
        });
        html += `</tbody></table>`;
        (d.failures || []).forEach(f => {
            html += `<div class="mem-kv det-warn">PID ${escapeHtml(String(f.pid))} ${escapeHtml(f.process || '')}: `
                + `${escapeHtml(f.error)}</div>`;
        });
        target.innerHTML = html;
        memoryBaselineStatus();
    } catch (e) {
        LoadingSpinner.stop();
        target.innerHTML = `<div class="pe-error">${escapeHtml(e.message)}</div>`;
    }
}

async function memoryBaselineClear() {
    if (!confirm('Clear the host baseline? Every finding will count as evidence again.')) return;
    try {
        await fetch('/api/memory/baseline', { method: 'DELETE' });
        memoryBaselineStatus();
    } catch (e) { /* status refresh is best-effort */ }
}

// --- Exit capture (post-mortem analysis of the exit-time memory dump) ----

function renderExitCaptureBlock(ec) {
    let html = `<div class="det-sub-title" data-info="Windows writes a full-memory dump the moment the sample exits, and the dump is analyzed offline. It covers samples that exit before the live scanners can run.">Exit Capture &mdash; memory at process exit</div>`;
    if (ec.error) {
        return html + `<div class="det-sub-value det-warn">${escapeHtml(ec.error)}</div>`;
    }
    if (!ec.captured) {
        return html + `<div class="det-sub-value">${escapeHtml(ec.note || 'No exit dump was written.')}</div>`;
    }

    const chip = (label, value, cls) =>
        `<span class="mem-chip ${cls || ''}"><span class="mem-chip-val">${value}</span>${escapeHtml(label)}</span>`;
    html += `<div class="mem-chips">`;
    html += chip('modules', ec.modules);
    html += chip('regions', ec.regions);
    html += chip('threads', ec.threads);
    html += chip('MB captured', ((ec.captured_bytes || 0) / 1048576).toFixed(1));
    if (ec.emulated) html += chip(`under emulation on ${ec.host_arch}`, '', 'sev-info');
    html += `</div>`;

    // Host-explained regions are shown so the classification can be checked.
    if ((ec.host_regions || []).length) {
        html += `<details class="mem-suppressed"><summary>${ec.host_regions.length} private executable `
            + `region(s) explained by the host, not scored</summary>`;
        ec.host_regions.forEach(h => {
            html += `<div class="mem-kv">${escapeHtml(h.base)} · ${formatSize(h.size)} · `
                + `${escapeHtml(h.protect)} — ${escapeHtml(h.reason)}</div>`;
        });
        html += `</details>`;
    }
    (ec.notes || []).forEach(n => { html += `<div class="mem-kv">${escapeHtml(n)}</div>`; });

    const arts = ec.artifacts || [];
    if (arts.length) {
        html += `<div class="mem-section-label">Extracted from memory (${arts.length})</div>`;
        html += `<table class="mem-dump-table" data-sortable data-sort-id="exit-capture-artifacts"><thead><tr><th>file</th><th>kind</th><th>size</th><th></th></tr></thead><tbody>`;
        arts.forEach(a => {
            const esc = jsArg(a.path || '');
            const cls = a.kind === 'main_image' ? '' : 'sev-high';
            html += `<tr><td class="mem-dump-name" title="${escapeHtml(a.sha256 || '')}">${escapeHtml(a.filename)}</td>`
                + `<td><span class="mem-chip ${cls}">${escapeHtml(a.kind)}</span></td>`
                + `<td data-sort-value="${sortNumberValue(a.size || 0)}">${formatSize(a.size || 0)}</td><td class="mem-dump-actions">`;
            if (a.is_pe) {
                html += `<button class="btn btn-sm" onclick="fileMapRender(${esc});switchTab('filemap');">Map</button>`;
            }
            html += `<button class="btn btn-sm" onclick="hexOpenFile(${esc})">Hex</button></td></tr>`;
        });
        html += `</tbody></table>`;
    }
    if (ec.dump_path) {
        html += `<div class="mem-foot">Dump: ${escapeHtml(ec.dump_path)} (${formatSize(ec.dump_size || 0)}) `
            + `— opens in WinDbg for manual analysis</div>`;
    }
    return html + _detRawButton('View Exit Capture raw', ec);
}


// --- Network beaconing (periodicity of outbound connections, from Sysmon) ---

function renderNetworkBeaconingBlock(net) {
    let html = `<div class="det-sub-title" data-info="Outbound connections of the sample from Sysmon EID 3, checked for the regular check-in interval of a beacon. A low coefficient of variation (CoV) means a regular interval.">Network &mdash; connection periodicity</div>`;
    const hits = net.evidence_findings || [];
    html += `<div class="det-sub-value">${net.connections} outbound connection(s) to `
        + `${(net.endpoints || []).length} endpoint(s)`
        + (hits.length ? '' : ' — no regular check-in pattern') + `</div>`;
    hits.forEach(f => {
        html += `<div class="mem-finding sev-high"><div class="mem-finding-head">`
            + `<span class="mem-type">${escapeHtml(f.endpoint || '')}</span>`
            + `<span class="mem-size">${f.connections} conns</span>`
            + `<span class="mem-size">every ${f.mean_interval_s}s</span>`
            + `<span class="mem-size">CoV ${f.cov}</span></div>`
            + `<div class="mem-desc">${escapeHtml(f.detail)}</div></div>`;
    });
    if (!hits.length && (net.endpoints || []).length) {
        html += `<div class="mem-kv">${escapeHtml(net.endpoints.slice(0, 8).join(', '))}</div>`;
    }
    return html;
}

// --- System-wide sweep + Process Dump database --------------------------

let _sweepPoll = null;

async function memorySweepStart(asBaseline) {
    const usePd = !!(document.getElementById('livemem-sweep-pd') || {}).checked;
    if (asBaseline && !confirm('Record a system-wide baseline now?\n\n'
        + 'Every finding in every running process will stop counting as evidence. '
        + 'Only do this on a clean box.')) return;
    if (usePd && !asBaseline && !confirm('Dumping every unknown module writes many files '
        + 'to C:\\dumps and can take a long time. Continue?')) return;
    try {
        const resp = await fetch('/api/memory/sweep', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ aether: true, processdump: usePd, baseline: asBaseline }),
        });
        const d = await resp.json();
        if (d.error) {
            document.getElementById('livemem-sweep-status').textContent = d.error;
            return;
        }
        memorySweepPoll();
    } catch (e) {
        document.getElementById('livemem-sweep-status').textContent = e.message;
    }
}

async function memorySweepPoll() {
    clearTimeout(_sweepPoll);
    const status = document.getElementById('livemem-sweep-status');
    try {
        const d = await (await fetch('/api/memory/sweep')).json();
        if (d.running) {
            status.textContent = `sweep running · ${Math.round(d.elapsed_s || 0)}s`;
            _sweepPoll = setTimeout(memorySweepPoll, 5000);
            return;
        }
        if (d.error) { status.textContent = `sweep failed: ${d.error}`; return; }
        if (d.result) {
            const r = d.result;
            status.textContent = `last sweep: ${r.processes_seen} processes · ${r.duration_s}s`;
            document.getElementById('livemem-result').innerHTML = renderSweepResult(r);
            memoryBaselineStatus();
        }
    } catch (e) { /* polling is best-effort */ }
}

function renderSweepResult(r) {
    let html = `<div class="mem-section-label">System sweep (${escapeHtml(r.mode)}) — `
        + `${r.processes_seen} processes in ${r.duration_s}s</div>`;
    (r.errors || []).forEach(e => { html += `<div class="mem-kv det-warn">${escapeHtml(e)}</div>`; });
    if (r.mode === 'baseline') {
        return html + `<div class="det-sub-value">${r.baseline_keys_added} new baseline key(s) · `
            + `${r.baseline.total} total</div>`;
    }
    const excl = r.excluded_host_tools || [];
    if (excl.length) {
        html += `<div class="mem-kv">Excluded (security tooling that holds detection rules in memory): `
            + `${escapeHtml(excl.map(e => e.process).join(', '))}</div>`;
    }
    // Only processes that still score after the baseline are worth a row.
    const flagged = r.processes.filter(p => p.score > 0);
    if (!flagged.length) {
        return html + `<div class="det-sub-value">No process carries findings beyond the host baseline `
            + `(${r.processes.length} with baseline-known findings only).</div>`;
    }
    html += `<table class="mem-dump-table" data-sortable data-sort-id="memory-sweep"><thead><tr><th>process</th><th>pid</th><th>verdict</th>`
        + `<th>score</th><th>suppressed</th><th>top evidence</th><th></th></tr></thead><tbody>`;
    flagged.forEach(p => {
        const cls = p.label === 'MALICIOUS' ? 'sev-critical' : p.label === 'SUSPICIOUS' ? 'sev-high' : 'sev-low';
        const rank = p.label === 'MALICIOUS' ? 3 : p.label === 'SUSPICIOUS' ? 2 : 1;
        const top = (p.findings || [])[0];
        html += `<tr><td class="mem-dump-name">${escapeHtml(p.process || '?')}</td><td>${escapeHtml(String(p.pid))}</td>`
            + `<td data-sort-value="${rank}"><span class="mem-chip ${cls}">${escapeHtml(p.label)}</span></td>`
            + `<td>${p.score}</td><td>${p.suppressed}</td>`
            + `<td class="mem-dump-name">${top ? escapeHtml(top.label) : ''}</td>`
            + `<td class="mem-dump-actions"><button class="btn btn-sm" `
            + `onclick="document.getElementById('livemem-pid').value=${jsInt(p.pid)};livememAether()">Rescan</button></td></tr>`;
    });
    return html + `</tbody></table>`;
}

async function pdBaselineBuild() {
    if (!confirm('Build the full Process Dump clean-hash database?\n\n'
        + 'Hashes every PE under WINDIR and Program Files (20+ minutes). '
        + 'Only on a clean box - anything hashed now is skipped in later dumps.')) return;
    const status = document.getElementById('livemem-sweep-status');
    try {
        const d = await (await fetch('/api/processdump/baseline', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ mode: 'gen' }),
        })).json();
        status.textContent = d.error ? d.error : 'dump baseline build started';
        if (!d.error) pdBaselinePoll();
    } catch (e) { status.textContent = e.message; }
}

async function pdBaselinePoll() {
    const status = document.getElementById('livemem-sweep-status');
    try {
        const d = await (await fetch('/api/processdump/baseline')).json();
        if (d.running) {
            status.textContent = `dump baseline (${d.mode}) running · ${Math.round(d.elapsed_s || 0)}s`;
            setTimeout(pdBaselinePoll, 10000);
        } else if (d.error) {
            status.textContent = `dump baseline failed: ${d.error}`;
        } else if (d.finished) {
            status.textContent = `dump baseline done · ${d.clean_hashes ?? '?'} clean hashes`;
            loadScanToolStatus();
        }
    } catch (e) { /* best-effort */ }
}

// =============================================
// Named Pipes tab: Sysmon pipe events + interception sessions
// =============================================
// Pipe names, images, families and message bytes come from the sample: every
// value goes through escapeHtml()/jsArg()/jsInt()/cssToken().

const pipesState = {
    initialized: false,
    sessions: [],
    selected: null,          // id of the session shown in the message view
    messages: new Map(),     // seq -> message of the selected session
    rows: new Map(),         // seq -> { el, sig } rendered rows
    lastSeq: 0,
    capped: false,           // more messages than PIPES_MAX_MESSAGES
    editing: null,           // seq of the held message being edited
    finalFetchFor: null,     // ended session whose last messages were loaded
    actionGen: 0,            // bumped by every message action; older polls are dropped
    busy: false,
    eventsSeq: 0,
    gone: new Set(),         // lower-case names the API reported as no longer existing
};
const PIPES_MAX_MESSAGES = 2000;
const PIPES_HEX_PREVIEW = 512;
const PIPES_LIVE = new Set(['starting', 'armed', 'active']);
const PIPE_FLAG_LABELS = {
    c2_default: 'C2 default name',
    cross_process: 'cross-process',
    sensitive_system: 'sensitive system pipe',
    random_name: 'random name',
};

function initPipesTab() {
    if (pipesState.initialized) return;
    pipesState.initialized = true;
    ['pipes-f-how', 'pipes-f-match', 'pipes-f-mode'].forEach(id => {
        document.getElementById(id)?.addEventListener('change', pipesSyncForm);
    });
    ['pipes-filter-name', 'pipes-filter-pid'].forEach(id => {
        document.getElementById(id)?.addEventListener('keydown', e => {
            if (e.key === 'Enter') { e.preventDefault(); refreshPipeEvents(); }
        });
    });
    document.getElementById('pipes-filter-window')?.addEventListener('change', refreshPipeEvents);
    pipesSyncForm();
    // 1 s while the tab is visible and a session can still record something.
    setInterval(() => {
        if (state.activeTab !== 'pipes' || document.hidden || pipesState.busy) return;
        const sel = pipesState.sessions.find(s => s.id === pipesState.selected);
        const needFinal = sel && !PIPES_LIVE.has(sel.state) && pipesState.finalFetchFor !== sel.id;
        if (pipesState.sessions.some(s => PIPES_LIVE.has(s.state)) || needFinal) pipesPoll();
    }, 1000);
}

function openPipesTab() {
    initPipesTab();
    refreshPipeEvents();
    refreshPipeSessions();
}

async function pipesPoll() {
    pipesState.busy = true;
    try {
        await refreshPipeSessions();
    } finally {
        pipesState.busy = false;
    }
}

// --- Form ---
function pipesSyncForm() {
    const how = document.getElementById('pipes-f-how');
    const match = document.getElementById('pipes-f-match');
    const mode = document.getElementById('pipes-f-mode');
    const squat = document.getElementById('pipes-f-squat');
    const squatWrap = document.getElementById('pipes-f-squat-wrap');
    const holdWrap = document.getElementById('pipes-f-hold-wrap');
    if (!how || !match) return;
    // attach opens one known pipe, so only exact names are accepted.
    if (how.value === 'attach') match.value = 'exact';
    match.disabled = how.value === 'attach';
    match.title = match.disabled ? 'attach needs the exact pipe name' : '';
    const squatOk = how.value === 'arm' && match.value === 'exact';
    if (squat) {
        squat.disabled = !squatOk;
        if (!squatOk) squat.checked = false;
    }
    if (squatWrap) squatWrap.classList.toggle('disabled', !squatOk);
    if (holdWrap) holdWrap.hidden = mode?.value !== 'hold';
}

function pipesFormError(msg) {
    const el = document.getElementById('pipes-form-error');
    if (!el) return;
    el.hidden = !msg;
    el.textContent = msg || '';
}

function pipesPrefill(name, how = 'attach') {
    const pattern = document.getElementById('pipes-f-pattern');
    const howEl = document.getElementById('pipes-f-how');
    const match = document.getElementById('pipes-f-match');
    if (pattern) pattern.value = String(name || '');
    if (howEl) howEl.value = how === 'arm' ? 'arm' : 'attach';
    if (match) match.value = 'exact';
    pipesSyncForm();
    pipesFormError('');
    document.getElementById('pipes-form')?.scrollIntoView({ block: 'nearest' });
    document.getElementById('pipes-start-btn')?.focus();
}

// "Intercept" in a detonation result: open the tab with an attach form.
function pipesInterceptFrom(name) {
    // The result may be open in the detail panel, which would cover the form.
    if (state.detailOpen) closeDetail();
    switchTab('pipes');
    pipesPrefill(name, 'attach');
    showToast('info', 'Pipe prefilled', 'Choose observe or hold and press Start session.');
}

// Same as pipe_analysis.canonical_name: "\\.\pipe\x", "x" and "\x" -> "\x".
function pipesCanonical(name) {
    const n = String(name || '').trim().replace(/^\\\\[^\\]+\\pipe(?=\\|$)/i, '');
    return '\\' + n.replace(/^\\+/, '');
}

function pipesIsGone(name) {
    return pipesState.gone.has(pipesCanonical(name).toLowerCase());
}

function pipesMarkGone(name) {
    pipesState.gone.add(pipesCanonical(name).toLowerCase());
    document.querySelectorAll('button[data-pipe-intercept]').forEach(b => {
        if (pipesIsGone(b.dataset.pipeIntercept)) {
            b.disabled = true;
            b.title = 'The pipe no longer exists';
            if (!b.nextElementSibling || !b.nextElementSibling.classList.contains('pipes-gone-hint')) {
                b.insertAdjacentHTML('afterend', '<div class="pipes-gone-hint">pipe no longer exists</div>');
            }
        }
    });
}

async function pipesStartSession() {
    const val = id => (document.getElementById(id)?.value || '').trim();
    const pattern = val('pipes-f-pattern');
    const how = val('pipes-f-how') || 'attach';
    const match = how === 'attach' ? 'exact' : (val('pipes-f-match') || 'exact');
    const mode = val('pipes-f-mode') || 'observe';
    const duration = Number(val('pipes-f-duration'));
    if (!pattern) { pipesFormError('Enter a pipe name or pattern.'); return; }
    if (!Number.isInteger(duration) || duration < 1 || duration > 3600) {
        pipesFormError('Max duration must be a whole number of seconds between 1 and 3600.');
        return;
    }
    const body = { pattern, how, match, mode, max_duration: duration };
    if (mode === 'hold') {
        const hold = Number(val('pipes-f-hold'));
        if (!Number.isInteger(hold) || hold < 1 || hold > duration) {
            pipesFormError('Hold timeout must be a whole number of seconds, at most the max duration.');
            return;
        }
        body.hold_timeout = hold;
    }
    const squat = document.getElementById('pipes-f-squat');
    if (squat && !squat.disabled && squat.checked) body.squat = true;
    const pipeMode = val('pipes-f-pipemode');
    if (pipeMode) body.pipe_mode = pipeMode;

    const btn = document.getElementById('pipes-start-btn');
    if (btn) btn.disabled = true;
    pipesFormError('');
    try {
        const resp = await fetch('/api/pipes/intercept', {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
        });
        const data = await resp.json().catch(() => ({}));
        if (!resp.ok) {
            const msg = data.error || `HTTP ${resp.status}`;
            pipesFormError(msg);
            if (resp.status === 400 && /does not exist/i.test(msg)) pipesMarkGone(pattern);
            return;
        }
        showToast('success', 'Interception started', `${data.how || how} ${data.pattern || pattern}`);
        pipesSelectSession(data.id, true);
        await refreshPipeSessions();
    } catch (e) {
        pipesFormError('Request failed: ' + e.message);
    } finally {
        if (btn) btn.disabled = false;
    }
}

// --- Events ---
function pipesFilterPid(pid) {
    const el = document.getElementById('pipes-filter-pid');
    if (el) el.value = pid == null ? '' : String(pid);
    refreshPipeEvents();
}

async function refreshPipeEvents() {
    const seq = ++pipesState.eventsSeq;
    const box = document.getElementById('pipes-events');
    const note = document.getElementById('pipes-events-note');
    const summary = document.getElementById('pipes-hit-summary');
    if (!box) return;
    const name = (document.getElementById('pipes-filter-name')?.value || '').trim();
    const pid = (document.getElementById('pipes-filter-pid')?.value || '').trim();
    const minutes = parseInt(document.getElementById('pipes-filter-window')?.value, 10) || 60;
    const setNote = (text) => { if (note) { note.hidden = !text; note.textContent = text || ''; } };
    if (pid && !/^\d+$/.test(pid)) { setNote('PID must be a number.'); return; }
    const params = new URLSearchParams({ since: new Date(Date.now() - minutes * 60000).toISOString(), max: '1000' });
    if (name) params.set('name', name);
    if (pid) params.set('pid', pid);
    box.innerHTML = '<div class="pipes-empty"><div class="loading-spinner"></div> Loading pipe events...</div>';
    let data;
    try {
        const resp = await fetch(`/api/pipes?${params}`);
        data = await resp.json().catch(() => ({}));
        if (!resp.ok && !data.error) data.error = `HTTP ${resp.status}`;
    } catch (e) {
        data = { error: e.message };
    }
    if (seq !== pipesState.eventsSeq) return;
    const events = Array.isArray(data.events) ? data.events.slice() : [];
    events.sort((a, b) => String(b.timestamp || '').localeCompare(String(a.timestamp || '')));

    const notes = [];
    if (data.error) notes.push(data.error);
    if (data.available === false) notes.push(data.reason || 'Sysmon is not available.');
    if (data.truncated) notes.push('Event limit reached: only the newest 1000 events of the window are shown. Narrow the filter or the time window.');
    setNote(notes.join(' · '));

    const pipeNames = new Set(events.map(e => String(e.pipe || '').toLowerCase()));
    const hits = events.filter(e => e.family);
    const families = [...new Set(hits.map(e => e.family))];
    if (summary) {
        summary.innerHTML = `<span class="badge badge-dim">${events.length} events</span>`
            + `<span class="badge badge-dim">${pipeNames.size} pipes</span>`
            + (hits.length ? `<span class="badge badge-red" title="${escapeHtml(families.join(', '))}">${hits.length} known C2 pipe name hit(s)</span>` : '');
    }
    if (!events.length) {
        box.innerHTML = `<div class="pipes-empty">No named pipe events${name || pid ? ' match the filter' : ''} in the last ${minutes >= 60 ? minutes / 60 + ' h' : minutes + ' min'}.</div>`;
        return;
    }
    let html = `<table class="pipes-table" data-sortable data-sort-id="pipe-events"><thead><tr>
        <th>Time</th><th>Event</th><th>PID</th><th>Process</th><th>Pipe</th><th>Family</th><th></th>
        </tr></thead><tbody>`;
    events.forEach(ev => {
        const created = ev.type === 'PipeCreated';
        const image = String(ev.image || '');
        const short = image.split('\\').pop() || image;
        html += `<tr class="${ev.family ? 'pipes-row-hit' : ''}">
            <td class="muted" data-sort-value="${sortTimeValue(ev.timestamp)}">${escapeHtml(formatTime(ev.timestamp))}</td>
            <td><span class="pipe-action pipe-action-${created ? 'created' : 'connected'}">${created ? 'created' : 'connected'}</span></td>
            <td><a class="pipes-link" onclick="pipesFilterPid(${jsInt(ev.pid)})" title="Filter by this PID">${escapeHtml(String(ev.pid ?? ''))}</a></td>
            <td class="pipes-proc" title="${escapeHtml(image)}">${escapeHtml(short)}</td>
            <td class="mono pipe-name-cell">${escapeHtml(ev.pipe || '')}</td>
            <td>${ev.family ? `<span class="pipe-family">${escapeHtml(ev.family)}</span>` : '<span class="muted">&mdash;</span>'}</td>
            <td class="pipes-row-actions"><button class="btn btn-xs pipes-intercept-btn" data-pipe-intercept="${escapeHtml(ev.pipe || '')}" ${pipesIsGone(ev.pipe) ? 'disabled title="The pipe no longer exists"' : 'title="Prefill an attach session for this pipe"'} onclick="pipesPrefill(${jsArg(ev.pipe || '')}, 'attach')">Intercept</button></td>
        </tr>`;
    });
    html += '</tbody></table>';
    box.innerHTML = html;
}

// --- Sessions ---
async function refreshPipeSessions() {
    let data;
    try {
        const resp = await fetch('/api/pipes/intercept');
        data = await resp.json().catch(() => ({}));
        if (!resp.ok) throw new Error(data.error || `HTTP ${resp.status}`);
    } catch (e) {
        const box = document.getElementById('pipes-sessions');
        if (box) box.innerHTML = `<div class="pipes-empty">Cannot load sessions: ${escapeHtml(e.message)}</div>`;
        return;
    }
    pipesState.sessions = Array.isArray(data.sessions) ? data.sessions : [];
    renderPipeSessions();
    const sel = pipesState.sessions.find(s => s.id === pipesState.selected);
    if (sel) {
        renderPipeSessionHeader(sel);
        const live = PIPES_LIVE.has(sel.state);
        if (live || pipesState.finalFetchFor !== sel.id) {
            const complete = await pipesLoadMessages();
            if (!live && complete) pipesState.finalFetchFor = sel.id;
        }
    }
}

function pipesFmtEpoch(t) {
    if (t === null || t === undefined || t === '') return '';
    const d = new Date(Number(t) * 1000);
    return isNaN(d.getTime()) ? '' : d.toLocaleTimeString('en-GB', { hour12: false });
}

function renderPipeSessions() {
    const box = document.getElementById('pipes-sessions');
    if (!box) return;
    if (!pipesState.sessions.length) {
        box.innerHTML = '<div class="pipes-empty">No interception sessions yet.</div>';
        return;
    }
    box.innerHTML = pipesState.sessions.map(s => {
        const active = s.id === pipesState.selected;
        const held = Number(s.held_count) || 0;
        return `<div class="pipes-session-item ${active ? 'active' : ''}" onclick="pipesSelectSession(${jsArg(s.id)})">
            <div class="pss-head">
                <span class="pipes-state pipes-state-${cssToken(s.state)}">${escapeHtml(s.state)}</span>
                <span class="pss-pattern" title="${escapeHtml(s.target || s.pattern || '')}">${escapeHtml(s.target || s.pattern || '')}</span>
                ${held ? `<span class="pss-held">${held} held</span>` : ''}
            </div>
            <div class="pss-meta">${escapeHtml(s.how)}/${escapeHtml(s.match)} · ${escapeHtml(s.mode)}${s.squat ? ' · squat' : ''} · ${Number(s.message_count) || 0} msg · ${Number(s.connections) || 0} conn · ${escapeHtml(pipesFmtEpoch(s.started))}</div>
        </div>`;
    }).join('');
}

function pipesSelectSession(sid, fresh = false) {
    sid = String(sid || '');
    if (!fresh && sid === pipesState.selected) return;
    pipesState.selected = sid;
    pipesState.messages = new Map();
    pipesState.rows = new Map();
    pipesState.lastSeq = 0;
    pipesState.capped = false;
    pipesState.editing = null;
    pipesState.finalFetchFor = null;
    const view = document.getElementById('pipes-session-view');
    if (view) view.innerHTML = '<div class="pipes-session-head" id="pipes-session-head"></div><div class="pipes-msgs" id="pipes-msgs"><div class="pipes-empty">Loading messages...</div></div>';
    renderPipeSessions();
    const sel = pipesState.sessions.find(s => s.id === sid);
    if (sel) {
        renderPipeSessionHeader(sel);
        pipesLoadMessages().then(complete => {
            if (complete && !PIPES_LIVE.has(sel.state) && pipesState.selected === sid) pipesState.finalFetchFor = sel.id;
        });
    }
}

function renderPipeSessionHeader(s) {
    const head = document.getElementById('pipes-session-head');
    if (!head) return;
    const live = PIPES_LIVE.has(s.state);
    const held = Number(s.held_count) || 0;
    const sid = String(s.id || '');
    const field = (label, value) => `<div class="pipes-kv"><span>${label}</span><b>${value}</b></div>`;
    let remaining = '';
    if (live && s.started && s.max_duration) {
        const left = Math.max(0, Math.round(Number(s.started) + Number(s.max_duration) - Date.now() / 1000));
        remaining = ` (${left} s left)`;
    }
    let html = `<div class="pipes-sh-top">
        <span class="pipes-state pipes-state-${cssToken(s.state)}">${escapeHtml(s.state)}</span>
        <span class="pipes-sh-name mono">${escapeHtml(s.target || s.pattern || '')}</span>
        <div class="pipes-sh-actions">
            ${live && held ? `<button class="btn btn-sm btn-accent" onclick="pipesReleaseAll(${jsArg(sid)})">Release all (${held})</button>` : ''}
            ${live ? `<button class="btn btn-sm pipes-stop-btn" onclick="pipesStopSession(${jsArg(sid)})">Stop</button>` : ''}
            <a class="btn btn-sm" href="/api/pipes/intercept/${escapeHtml(encodeURIComponent(sid))}/export" download>Export JSON</a>
        </div>
    </div>`;
    html += '<div class="pipes-kv-grid">';
    html += field('Session', escapeHtml(sid));
    if (s.target && s.target !== s.pattern) html += field('Pattern', escapeHtml(s.pattern));
    html += field('How / match', `${escapeHtml(s.how)} / ${escapeHtml(s.match)}${s.squat ? ' · squat' : ''}`);
    html += field('Mode', escapeHtml(s.mode) + (s.mode === 'hold' ? ` · auto-forward after ${escapeHtml(String(s.hold_timeout ?? ''))} s` : ''));
    html += field('Pipe mode', escapeHtml(s.pipe_mode || '—'));
    html += field('Started', escapeHtml(pipesFmtEpoch(s.started)) + escapeHtml(remaining));
    if (s.ended) html += field('Ended', `${escapeHtml(pipesFmtEpoch(s.ended))}${s.end_reason ? ' · ' + escapeHtml(s.end_reason) : ''}`);
    html += field('Connections', `${Number(s.connections) || 0} (${Number(s.active_connections) || 0} open)`);
    html += field('Messages', `${Number(s.message_count) || 0} · ${escapeHtml(formatSize(Number(s.recorded_bytes) || 0))} recorded`);
    html += '</div>';
    const notes = [];
    if (s.state === 'armed') notes.push('Waiting for a pipe that matches the pattern to appear.');
    if (s.state === 'starting') notes.push('Starting: connecting to the real server. Clients connecting in this phase are not intercepted.');
    if (s.recording_truncated) notes.push('Recording limit reached: further messages are relayed but not recorded.');
    if (Number(s.self_connect_retries) > 0) notes.push(`Upstream connect landed on the proxy's own instance ${Number(s.self_connect_retries)} time(s) and was retried.`);
    if (s.last_error) notes.push('Last error: ' + s.last_error);
    if (notes.length) html += `<div class="pipes-note">${notes.map(escapeHtml).join('<br>')}</div>`;
    head.innerHTML = html;
}

// Load new messages (and the current state of held ones) of the selected
// session, page by page until a short page or the UI cap. Returns true when
// everything the server has was seen. A response that started before the
// last Forward/Edit/Drop/Release is dropped: it could still say "held".
const PIPES_PAGE = 1000;   // server maximum per request
async function pipesLoadMessages() {
    const sid = pipesState.selected;
    if (!sid) return false;
    const held = [...pipesState.messages.values()].filter(m => m.state === 'held').map(m => m.seq);
    let after = held.length ? Math.min(...held) - 1 : pipesState.lastSeq;
    let complete = false;
    while (!complete) {
        const gen = pipesState.actionGen;
        let data;
        try {
            const resp = await fetch(`/api/pipes/intercept/${encodeURIComponent(sid)}/messages?after=${jsInt(after)}&limit=${PIPES_PAGE}`);
            data = await resp.json().catch(() => ({}));
            if (!resp.ok) throw new Error(data.error || `HTTP ${resp.status}`);
        } catch (e) {
            if (sid === pipesState.selected) {
                const box = document.getElementById('pipes-msgs');
                if (box && !pipesState.messages.size) box.innerHTML = `<div class="pipes-empty">Cannot load messages: ${escapeHtml(e.message)}</div>`;
            }
            break;
        }
        if (sid !== pipesState.selected || gen !== pipesState.actionGen) break;
        const page = Array.isArray(data.messages) ? data.messages : [];
        for (const m of page) {
            const seq = Number(m && m.seq);
            if (!Number.isInteger(seq)) continue;
            pipesState.lastSeq = Math.max(pipesState.lastSeq, seq);
            after = Math.max(after, seq);
            if (!pipesState.messages.has(seq) && pipesState.messages.size >= PIPES_MAX_MESSAGES) {
                pipesState.capped = true;
                continue;
            }
            pipesState.messages.set(seq, m);
        }
        complete = page.length < PIPES_PAGE || pipesState.capped;
    }
    if (sid === pipesState.selected) renderPipeMessages();
    return complete;
}

function pipesB64Bytes(b64) {
    try {
        const bin = atob(String(b64 || ''));
        const out = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
        return out;
    } catch (e) {
        return new Uint8Array(0);
    }
}

function pipesBytesB64(bytes) {
    let bin = '';
    for (let i = 0; i < bytes.length; i += 0x8000) {
        bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    }
    return btoa(bin);
}

// Hex + ASCII dump, 16 bytes per line, as escaped HTML.
function pipesHexDump(bytes, limit = PIPES_HEX_PREVIEW) {
    const n = Math.min(bytes.length, limit);
    const lines = [];
    for (let off = 0; off < n; off += 16) {
        const row = bytes.subarray(off, Math.min(off + 16, n));
        let hex = '', ascii = '';
        for (let i = 0; i < 16; i++) {
            if (i < row.length) {
                hex += row[i].toString(16).padStart(2, '0') + ' ';
                ascii += row[i] >= 0x20 && row[i] < 0x7f ? String.fromCharCode(row[i]) : '.';
            } else {
                hex += '   ';
            }
            if (i === 7) hex += ' ';
        }
        lines.push(`<span class="ph-off">${off.toString(16).padStart(6, '0')}</span>  ${hex} <span class="ph-ascii">${escapeHtml(ascii)}</span>`);
    }
    let html = lines.join('\n');
    if (bytes.length > n) html += `\n<span class="ph-more">… ${bytes.length - n} more byte(s), see the JSON export</span>`;
    return html;
}

// Hex text (whitespace ignored) -> bytes, or null if it is not whole hex pairs.
function pipesHexToBytes(text) {
    const hex = String(text || '').replace(/\s+/g, '');
    if (!/^([0-9a-fA-F]{2})*$/.test(hex)) return null;
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    return bytes;
}

function pipesHexText(bytes) {
    const parts = [];
    for (let off = 0; off < bytes.length; off += 16) {
        parts.push(Array.from(bytes.subarray(off, off + 16), b => b.toString(16).padStart(2, '0')).join(' '));
    }
    return parts.join('\n');
}

function pipesMessageRow(m, live) {
    const seq = Number(m.seq);
    const st = String(m.state || '');
    const bytes = pipesB64Bytes(m.data_b64);
    const c2s = m.dir === 'c2s';
    const editing = pipesState.editing === seq && st === 'held' && live;
    let html = `<div class="pipe-msg pipe-msg-${cssToken(st)} ${c2s ? 'pipe-msg-c2s' : 'pipe-msg-s2c'}">
        <div class="pipe-msg-head">
            <span class="pipe-msg-seq">#${seq}</span>
            <span class="pipe-msg-dir">${c2s ? 'client &rarr; server' : 'server &rarr; client'}</span>
            <span class="pipe-msg-conn">conn ${escapeHtml(String(m.conn ?? ''))}</span>
            <span class="pipe-msg-size">${Number(m.size) || 0} B${m.truncated ? ' · log truncated' : ''}</span>
            <span class="pipe-msg-ts">${escapeHtml(pipesFmtEpoch(m.ts))}</span>
            <span class="pipe-msg-state pipes-mstate-${cssToken(st)}"${st === 'write_failed' ? ' title="Decided, but writing it to the other side failed (that end has closed)"' : ''}>${escapeHtml(st.replace('_', ' '))}</span>`;
    if (st === 'held' && live && !editing) {
        html += `<span class="pipe-msg-actions">
            <button class="btn btn-xs pipe-btn-forward" onclick="pipesAct(${jsInt(seq)}, 'forward')">Forward</button>
            <button class="btn btn-xs" onclick="pipesEditStart(${jsInt(seq)})">Edit</button>
            <button class="btn btn-xs pipe-btn-drop" onclick="pipesAct(${jsInt(seq)}, 'drop')">Drop</button>
        </span>`;
    }
    html += '</div>';
    if (editing) {
        html += `<div class="pipe-edit">
            ${m.truncated ? '<div class="pipes-note">Only the first part of this message was recorded; the edited bytes replace the whole message.</div>' : ''}
            <textarea class="pipe-edit-hex" id="pipe-edit-${seq}" spellcheck="false">${escapeHtml(pipesHexText(bytes))}</textarea>
            <div class="pipe-edit-actions">
                <span class="muted">Hex bytes, whitespace is ignored.</span>
                <span class="pipe-edit-error" id="pipe-edit-error-${seq}"></span>
                <button class="btn btn-xs" onclick="pipesEditCancel()">Cancel</button>
                <button class="btn btn-xs btn-accent" onclick="pipesEditApply(${jsInt(seq)})">Send edited</button>
            </div>
        </div>`;
    } else if (!bytes.length && (Number(m.size) || 0) > 0) {
        html += '<div class="pipe-hex muted">(not recorded: session recording limit reached)</div>';
    } else if (bytes.length) {
        html += `<pre class="pipe-hex">${pipesHexDump(bytes)}</pre>`;
    }
    if (m.original_b64) {
        html += `<details class="pipe-orig"><summary>original (before edit)</summary><pre class="pipe-hex">${pipesHexDump(pipesB64Bytes(m.original_b64))}</pre></details>`;
    }
    html += '</div>';
    return html;
}

function renderPipeMessages() {
    const box = document.getElementById('pipes-msgs');
    if (!box) return;
    const sel = pipesState.sessions.find(s => s.id === pipesState.selected);
    const live = !!sel && PIPES_LIVE.has(sel.state);
    if (!pipesState.messages.size) {
        box.innerHTML = `<div class="pipes-empty">${live ? 'No messages yet. Waiting for a client to connect...' : 'This session recorded no messages.'}</div>`;
        pipesState.rows = new Map();
        return;
    }
    if (!pipesState.rows.size) box.innerHTML = '';
    const nearBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 40;
    const seqs = [...pipesState.messages.keys()].sort((a, b) => a - b);
    for (const seq of seqs) {
        const m = pipesState.messages.get(seq);
        const sig = `${m.state}|${m.original_b64 ? 1 : 0}|${live ? 1 : 0}|${pipesState.editing === seq ? 1 : 0}`;
        const row = pipesState.rows.get(seq);
        if (row && row.sig === sig) continue;
        const tpl = document.createElement('template');
        tpl.innerHTML = pipesMessageRow(m, live).trim();
        const el = tpl.content.firstElementChild;
        if (row) {
            row.el.replaceWith(el);
        } else {
            box.appendChild(el);
        }
        pipesState.rows.set(seq, { el, sig });
    }
    let capNote = box.querySelector('.pipes-cap-note');
    if (pipesState.capped && !capNote) {
        box.insertAdjacentHTML('beforeend', `<div class="pipes-note pipes-cap-note">Showing the first ${PIPES_MAX_MESSAGES} messages; the JSON export has all of them.</div>`);
    }
    if (nearBottom) box.scrollTop = box.scrollHeight;
}

async function pipesPost(url, body) {
    const resp = await fetch(url, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}),
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) throw new Error(data.error || `HTTP ${resp.status}`);
    return data;
}

function pipesApplyRecord(rec) {
    if (rec && Number.isInteger(Number(rec.seq)) && pipesState.messages.has(Number(rec.seq))) {
        pipesState.messages.set(Number(rec.seq), rec);
    }
}

async function pipesAct(seq, action, dataB64) {
    const sid = pipesState.selected;
    if (!sid) return false;
    try {
        const body = { action };
        if (action === 'edit') body.data_b64 = dataB64;
        pipesState.actionGen += 1;
        const rec = await pipesPost(`/api/pipes/intercept/${encodeURIComponent(sid)}/messages/${jsInt(seq)}`, body);
        if (sid !== pipesState.selected) return true;
        pipesState.actionGen += 1;      // polls that overlapped the request
        pipesApplyRecord(rec);
        if (pipesState.editing === seq) pipesState.editing = null;
        renderPipeMessages();
        refreshPipeSessions();
        return true;
    } catch (e) {
        showToast('error', `Cannot ${action} message #${seq}`, e.message);
        refreshPipeSessions();
        return false;
    }
}

function pipesEditStart(seq) {
    pipesState.editing = seq;
    renderPipeMessages();
    document.getElementById(`pipe-edit-${seq}`)?.focus();
}

function pipesEditCancel() {
    pipesState.editing = null;
    renderPipeMessages();
}

async function pipesEditApply(seq) {
    const ta = document.getElementById(`pipe-edit-${seq}`);
    const err = document.getElementById(`pipe-edit-error-${seq}`);
    if (!ta) return;
    const bytes = pipesHexToBytes(ta.value);
    if (!bytes) {
        if (err) err.textContent = 'Not valid hex: use pairs of 0-9 / a-f.';
        return;
    }
    await pipesAct(seq, 'edit', pipesBytesB64(bytes));
}

async function pipesReleaseAll(sid) {
    try {
        pipesState.actionGen += 1;
        const d = await pipesPost(`/api/pipes/intercept/${encodeURIComponent(sid)}/release`);
        pipesState.actionGen += 1;
        showToast('success', 'Held messages released', `${Number(d.released) || 0} forwarded`);
    } catch (e) {
        showToast('error', 'Release failed', e.message);
    }
    pipesState.editing = null;
    refreshPipeSessions();
}

async function pipesStopSession(sid) {
    try {
        pipesState.actionGen += 1;
        const resp = await fetch(`/api/pipes/intercept/${encodeURIComponent(sid)}`, { method: 'DELETE' });
        pipesState.actionGen += 1;
        const d = await resp.json().catch(() => ({}));
        if (!resp.ok) throw new Error(d.error || `HTTP ${resp.status}`);
        showToast('info', 'Session stopped', String(d.pattern || sid));
    } catch (e) {
        showToast('error', 'Stop failed', e.message);
    }
    pipesState.editing = null;
    pipesState.finalFetchFor = null;
    refreshPipeSessions();
}

// --- Detonation results: NAMED PIPES ---
// Instance keys are "<pid>", "<pid>@<start>" or the sentinel "<pid>?" (the
// sample, whose ProcessCreate was not in the log).
function pipeProcLabel(key) {
    const k = String(key ?? '');
    if (!k) return '';
    if (k.endsWith('?')) return `sample (PID ${k.slice(0, -1)})`;
    const proc = state.processes[k];
    const pid = k.split('@')[0];
    return proc && proc.name ? `${proc.name} (PID ${proc.pid ?? pid})` : `PID ${pid}`;
}

function renderNamedPipesBlock(np) {
    if (!np) return '';
    if (!np.available) {
        return `<div class="det-sub-value muted">Named pipe activity unavailable${np.reason ? ': ' + escapeHtml(np.reason) : ''}.</div>`;
    }
    const pipes = Array.isArray(np.pipes) ? np.pipes : [];
    let html = '';
    if (np.truncated) html += '<div class="pipes-note">Event limit reached: the pipe list may be incomplete.</div>';
    if (!pipes.length) return html + '<div class="det-sub-value muted">The sample created or connected to no named pipes.</div>';
    const findings = Array.isArray(np.evidence_findings) ? np.evidence_findings.length : 0;
    html += `<div class="det-sub-value">${pipes.length} pipe(s)${findings ? ` · ${findings} finding(s) scored in the memory evidence` : ''}</div>`;
    // A pipe's rows (one per process) are one group: sorting moves them together
    html += `<table class="pipes-table pipes-result-table" data-sortable data-sort-id="named-pipes"><thead><tr>
        <th>Time</th><th>Process</th><th>Action</th><th>Pipe</th><th>Family</th><th>Flags</th><th></th>
        </tr></thead><tbody>`;
    pipes.forEach(p => {
        const name = String(p.pipe || '');
        const rows = [
            ...(p.created_by || []).map(k => ['created', k]),
            ...(p.connected_by || []).map(k => ['connected', k]),
        ];
        if (!rows.length) rows.push(['', '']);
        const span = rows.length;
        const gone = pipesIsGone(name);
        const flags = (p.flags || []).map(f =>
            `<span class="pipe-flag pipe-flag-${cssToken(f)}">${escapeHtml(PIPE_FLAG_LABELS[f] || f)}</span>`).join('');
        rows.forEach(([action, key], i) => {
            html += `<tr class="${i === 0 ? 'pipes-group-start' : ''} ${p.family ? 'pipes-row-hit' : ''}">`;
            if (i === 0) html += `<td rowspan="${span}" class="muted" data-sort-value="${sortTimeValue(p.first_seen)}">${escapeHtml(formatTime(p.first_seen))}</td>`;
            html += `<td>${escapeHtml(pipeProcLabel(key))}</td>`;
            html += `<td>${action ? `<span class="pipe-action pipe-action-${cssToken(action)}">${escapeHtml(action)}</span>` : ''}</td>`;
            if (i === 0) {
                html += `<td rowspan="${span}" class="mono pipe-name-cell">${escapeHtml(name)}</td>`;
                html += `<td rowspan="${span}">${p.family ? `<span class="pipe-family" title="${escapeHtml(p.note || '')}">${escapeHtml(p.family)}</span>` : '<span class="muted">&mdash;</span>'}</td>`;
                html += `<td rowspan="${span}" class="pipe-flags">${flags || '<span class="muted">&mdash;</span>'}</td>`;
                html += `<td rowspan="${span}" class="pipes-row-actions"><button class="btn btn-xs pipes-intercept-btn" data-pipe-intercept="${escapeHtml(name)}" ${gone ? 'disabled title="The pipe no longer exists"' : 'title="Open the Pipes tab with an attach session for this pipe"'} onclick="pipesInterceptFrom(${jsArg(name)})">Intercept</button>${gone ? '<div class="pipes-gone-hint">pipe no longer exists</div>' : ''}</td>`;
            }
            html += '</tr>';
        });
    });
    html += '</tbody></table>';
    return html;
}
