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
            <div class="toast-title">${title}</div>
            ${detail ? `<div class="toast-detail">${detail}</div>` : ''}
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

// --- Initialization ---
document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    initUpload();
    initHexDropZone();
    initHexResizeHandle();
    initThreatScan();
    initGraphControls();
    initRtraceTabs();
    refreshAll();
    setInterval(refreshAlerts, 5000);
    setInterval(refreshDashboard, 10000);
    refreshDashboard();
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
    state.activeTab = tabName;
    document.querySelectorAll('.sidebar-tabs .tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    document.querySelector(`.tab[data-tab="${tabName}"]`).classList.add('active');
    document.getElementById(`tab-${tabName}`).classList.add('active');
    if (tabName === 'sysmon' && sysmonEvents.length === 0) {
        refreshSysmon();
    }
    if (tabName === 'tracing') {
        renderRtraceConsole();
    }
    if (tabName === 'graph') {
        graphRefresh();
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
}

// Fetch scanner/EMBER tool availability and update badges + dashboard state.
async function loadScanToolStatus() {
    try {
        const resp = await fetch('/api/scan/status');
        const data = await resp.json();
        state.emberStatus = data.ember || null;
        state.capaStatus = data.capa || null;

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
        const timeEl = document.getElementById('dashboard-time');
        if (timeEl) timeEl.textContent = 'Updated ' + new Date().toLocaleTimeString('en-GB');
    } catch (e) {
        showToast('error', 'Dashboard unreachable', e.message || 'Connection to server lost', 6000);
    }
}

async function refreshAlerts() {
    try {
        const resp = await fetch('/api/alerts');
        if (resp.ok) {
            const newAlerts = await resp.json();
            // Toast on new alerts arriving
            if (state.alerts.length > 0 && newAlerts.length > state.alerts.length) {
                const diff = newAlerts.length - state.alerts.length;
                showToast('info', `${diff} new alert${diff > 1 ? 's' : ''}`, 'New detections received');
            }
            state.alerts = newAlerts;
            if (state.alerts.length) {
                const times = state.alerts.map(a => new Date(a.timestamp).getTime()).filter(t => !isNaN(t));
                state.sessionStart = times.length ? Math.min(...times) : null;
            }
            renderTimeline();
            if (state.activeTab === 'tracing') {
                renderRtraceConsole();
            }
        } else if (resp.status >= 500) {
            showToast('error', 'Alert fetch failed', `Server error ${resp.status}`, 5000);
        }
    } catch (e) {
        showToast('error', 'Alerts unreachable', e.message || 'Connection lost', 6000);
    }
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
        const highSev = alerts.filter(a => a.severity === 'high' || a.severity === 'critical').length;
        const medSev = alerts.filter(a => a.severity === 'medium').length;
        const lowSev = alerts.filter(a => a.severity === 'low' || a.severity === 'info').length;
        const rulesLoaded = (rustinel.rules?.sigma || 0) + (rustinel.rules?.yara || 0);

        statsContainer.innerHTML = `
            <div class="stat-card stat-alerts">
                <div class="stat-value">${totalAlerts}</div>
                <div class="stat-label">TOTAL ALERTS</div>
                <div class="stat-breakdown">
                    ${highSev ? `<span class="stat-tag high">${highSev} high</span>` : ''}
                    ${medSev ? `<span class="stat-tag med">${medSev} med</span>` : ''}
                    ${lowSev ? `<span class="stat-tag low">${lowSev} low</span>` : ''}
                </div>
            </div>
            <div class="stat-card stat-processes">
                <div class="stat-value">${processCount}</div>
                <div class="stat-label">PROCESSES TRACKED</div>
                <div class="stat-breakdown"><span class="stat-tag dim">via ETW telemetry</span></div>
            </div>
            <div class="stat-card stat-services">
                <div class="stat-value">${servicesOnline}<span class="stat-value-sub">/${servicesTotal}</span></div>
                <div class="stat-label">SERVICES ONLINE</div>
                <div class="stat-breakdown">
                    ${servicesList.map(s => `<span class="stat-tag ${s.online ? 'svc-on' : 'svc-off'}">${s.name}</span>`).join('')}
                </div>
            </div>
            <div class="stat-card stat-rules">
                <div class="stat-value">${rulesLoaded}</div>
                <div class="stat-label">DETECTION RULES</div>
                <div class="stat-breakdown">
                    <span class="stat-tag dim">${rustinel.rules?.sigma || 0} sigma</span>
                    <span class="stat-tag dim">${rustinel.rules?.yara || 0} yara</span>
                </div>
            </div>
            <div class="stat-card stat-tools">
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
        <div class="service-card scanner-card" onclick="switchTab('scanner')">
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
                <button class="btn btn-sm" onclick="event.stopPropagation(); switchTab('scanner')">Open Scanner</button>
            </div>
        </div>
    `);

    // EMBER2024 ML Classifier Card
    const emberStatus = state.emberStatus || {};
    const emberOnline = emberStatus.installed !== false; // treat unknown as ready
    const emberModelCount = (emberStatus.models || []).length;
    cards.push(`
        <div class="service-card ember-card ${emberOnline ? '' : 'offline'}" onclick="switchTab('ember')">
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
                <button class="btn btn-sm" onclick="event.stopPropagation(); switchTab('ember')">Open EMBER</button>
            </div>
        </div>
    `);

    // capa Capability Detection Card
    const capaStatus = state.capaStatus || {};
    const capaOnline = capaStatus.installed !== false; // treat unknown as ready
    cards.push(`
        <div class="service-card capa-card ${capaOnline ? '' : 'offline'}" onclick="switchTab('capa')">
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
                <button class="btn btn-sm" onclick="event.stopPropagation(); switchTab('capa')">Open capa</button>
            </div>
        </div>
    `);

    container.innerHTML = cards.join('');

    // --- Recent Activity Feed ---
    if (activityFeed) {
        if (alerts.length === 0) {
            activityFeed.innerHTML = '<div class="activity-empty">No recent activity. Submit a sample to begin.</div>';
        } else {
            const recent = alerts.slice(0, 8);
            let html = '';
            recent.forEach(alert => {
                const ts = alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString('en-GB', {hour12:false}) : '--';
                const sevClass = (alert.severity === 'high' || alert.severity === 'critical') ? 'sev-high' : alert.severity === 'medium' ? 'sev-med' : 'sev-low';
                const ruleName = alert.rule_name || alert.name || 'Unknown Rule';
                const proc = alert.process_name || '';
                const pid = alert.pid || '';
                html += `<div class="activity-entry ${sevClass}">`;
                html += `<span class="activity-time">${ts}</span>`;
                html += `<span class="activity-sev">${escapeHtml((alert.severity || 'info').toUpperCase())}</span>`;
                html += `<span class="activity-rule">${escapeHtml(ruleName)}</span>`;
                html += proc ? `<span class="activity-proc">${escapeHtml(proc)}${pid ? ' (' + pid + ')' : ''}</span>` : '';
                html += `</div>`;
            });
            activityFeed.innerHTML = html;
        }
    }
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
                selectRtraceProcess(parseInt(pid));
            }
        });
    }
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
        const selected = state.rtraceSelectedPid == proc.pid ? 'selected' : '';
        html += `<option value="${proc.pid}" ${selected}>${escapeHtml(proc.name || 'unknown')} &mdash; ${status} (${alertCount} ev)</option>`;
    });
    dropdown.innerHTML = html;
}

function selectRtraceProcess(pid) {
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
    const treeItem = document.querySelector(`.rtrace-tree-item[data-pid="${pid}"]`);
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

function renderRtraceTimeline() {
    const container = document.getElementById('rtrace-timeline-bar');
    const rangeEl = document.getElementById('rtrace-timeline-range');
    if (!container || !state.alerts.length) {
        if (container) container.innerHTML = '<div class="rtrace-timeline-cursor" id="rtrace-timeline-cursor"></div>';
        if (rangeEl) rangeEl.textContent = '';
        return;
    }

    // Category config: lane order and colors
    const lanes = [
        { key: 'critical', label: 'CRIT', color: '#ef4444' },
        { key: 'process', label: 'PROC', color: '#3b82f6' },
        { key: 'network', label: 'NET', color: '#22c55e' },
        { key: 'dns', label: 'DNS', color: '#a78bfa' },
        { key: 'file', label: 'FILE', color: '#f97316' },
        { key: 'registry', label: 'REG', color: '#f472b6' },
    ];

    // Parse all alert timestamps and categorize
    const sorted = [...state.alerts].sort((a, b) => (a.timestamp || '').localeCompare(b.timestamp || ''));
    const timestamps = sorted.map(a => new Date(a.timestamp).getTime()).filter(t => !isNaN(t));
    if (!timestamps.length) {
        container.innerHTML = '<div class="rtrace-timeline-cursor" id="rtrace-timeline-cursor"></div>';
        return;
    }

    const tMin = Math.min(...timestamps);
    const tMax = Math.max(...timestamps);
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

    // Mouse tracking for cursor line
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
        const isActive = state.rtraceSelectedPid == proc.pid;
        const indent = proc.parent_pid && state.processes[proc.parent_pid] ? '<span class="tree-indent"></span>' : '';
        const threats = proc.activity?.threats || 0;
        const maxSev = getMaxSeverity(proc);
        const sevDot = threats > 0 ? `<span class="ev-sev-dot ${maxSev}" style="width:6px;height:6px;display:inline-block;"></span>` : '';

        html += `<div class="rtrace-tree-item ${isActive ? 'active' : ''}" data-pid="${proc.pid}" onclick="selectRtraceProcess(${proc.pid})">
            ${sevDot}
            <span class="tree-time">${relTime}</span>
            ${indent}<span class="tree-pid">${proc.pid}</span>
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

    // Sort by timestamp
    events.sort((a, b) => (a.timestamp || '').localeCompare(b.timestamp || ''));

    if (!events.length) {
        container.innerHTML = '<div style="padding:20px;color:var(--text-muted);font-size:11px;">No events for this filter.</div>';
        return;
    }

    let html = '';
    events.forEach((ev, idx) => {
        const relTime = formatRelativeTime(ev.timestamp);
        const raw = ev.raw || {};
        const action = raw.event?.action || ev.engine || 'event';
        const actionShort = action.replace('_', ' ').split(' ')[0];
        const actionClass = getActionBadgeClass(actionShort);
        const severity = (ev.severity || 'unknown').toLowerCase();
        const ruleName = ev.rule_name || '';
        const engine = (ev.engine || '').toUpperCase();
        const pid = ev.pid || '?';
        const procName = ev.process_name || '';
        const details = getEventDetails(ev);
        const sevRowClass = (severity === 'critical' || severity === 'high') ? ` sev-${severity}` : '';

        html += `<div class="rtrace-event-row${sevRowClass}" onclick="openAlertDetail(${state.alerts.indexOf(ev) >= 0 ? state.alerts.indexOf(ev) : 0})" title="${escapeHtml(ruleName)}\n${escapeHtml(ev.rule_description || '')}">
            <span class="ev-sev"><span class="ev-sev-dot ${severity}"></span></span>
            <span class="ev-time">${relTime}</span>
            <span class="ev-action">
                <span class="rtrace-action-badge ${actionClass}">${escapeHtml(actionShort)}</span>
            </span>
            <span class="ev-rule"><span class="ev-rule-name">${escapeHtml(ruleName)}</span>${engine ? `<span class="ev-engine-tag">${engine}</span>` : ''}</span>
            <span class="ev-pid">${pid}</span>
            <span class="ev-process">${escapeHtml(procName)}</span>
            <span class="ev-details">${escapeHtml(details)}</span>
            ${ev.pid ? `<span class="ev-graph-btn" title="Investigate PID ${ev.pid} in process graph" onclick="event.stopPropagation(); focusProcessGraph('${ev.pid}', {reset:true})">&#9673; Graph</span>` : '<span class="ev-graph-btn-empty"></span>'}
        </div>`;
    });
    container.innerHTML = html;
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
        [...tactics].sort().forEach(t => { html += `<span class="tag tactic">${t}</span>`; });
        [...techniques].sort().forEach(t => { html += `<span class="tag technique">${t}</span>`; });
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
        if (proc.exit_time) {
            delete state.processes[proc.pid];
            delete state.processes[String(proc.pid)];
        }
    });
    renderRtraceConsole();
    renderProcessList();
}

function clearAllTracing() {
    state.alerts = [];
    state.processes = {};
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
        html += `<button class="btn btn-sm" onclick="hexOpenFile('${escapeHtml(data.filepath.replace(/\\/g, '\\\\'))}')">Open in Hex Editor</button>`;
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
        // history must never break the page
    }
}

function _histStatus(entry) {
    const v = (entry.verdict || '').toLowerCase();
    const pct = (entry.score != null) ? ` ${(entry.score * 100).toFixed(1)}%` : '';
    if (entry.status === 'timeout') return { cls: 'history-unknown', text: 'TIMEOUT' };
    if (entry.status && entry.status !== 'ok') return { cls: 'history-unknown', text: entry.status.toUpperCase() };
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
        return;
    }

    let html = '';
    history.forEach(entry => {
        const ts = new Date(entry.timestamp).toLocaleString('en-GB', { hour12: false });
        const st = _histStatus(entry);
        html += `<div class="scan-history-entry ${st.cls}" onclick="toggleHistoryDetail(this)">`;
        html += `<span class="scan-history-more">&#9656;</span>`;
        html += `<span class="scan-history-time">${escapeHtml(ts)}</span>`;
        html += `<span class="scan-history-tool">${escapeHtml(entry.tool || '?')}</span>`;
        html += `<span class="scan-history-file" title="${escapeHtml(entry.filename || '')}">${escapeHtml(entry.filename || '--')}</span>`;
        html += `<span class="scan-history-status">${escapeHtml(st.text)}</span>`;
        html += `</div>`;
        html += `<div class="scan-history-detail" style="display:none">${renderHistoryDetail(entry)}</div>`;
    });
    containers.forEach(c => { c.innerHTML = html; });
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
        html += `<table class="ember-more-table"><tr><th>group</th><th>contribution</th></tr>`;
        ex.contributions.forEach(c => {
            html += `<tr><td>${escapeHtml(c.group)}</td><td class="${c.value >= 0 ? 'why-mal-t' : 'why-ben-t'}">${c.value >= 0 ? '+' : ''}${c.value}</td></tr>`;
        });
        html += `</table>`;
    }

    // All sections (entropy-sorted)
    if (det.sections && det.sections.length) {
        html += `<div class="ember-more-sub">Sections (entry: ${escapeHtml(det.entry_section || '?')})</div>`;
        html += `<table class="ember-more-table"><tr><th>name</th><th>entropy</th><th>size</th><th>vsize</th></tr>`;
        det.sections.forEach(s => {
            const hot = s.entropy >= 7 ? ' class="chip-warn"' : '';
            html += `<tr><td>${escapeHtml(s.name)}</td><td${hot}>${s.entropy}</td><td>${formatSize(s.size)}</td><td>${formatSize(s.vsize)}</td></tr>`;
        });
        html += `</table>`;
    }

    // Top DLLs
    if (det.top_dlls && det.top_dlls.length) {
        html += `<div class="ember-more-sub">Top imported DLLs</div>`;
        html += `<table class="ember-more-table"><tr><th>dll</th><th>imports</th></tr>`;
        det.top_dlls.forEach(d => html += `<tr><td>${escapeHtml(d.dll)}</td><td>${d.count}</td></tr>`);
        html += `</table>`;
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
            offsetHtml += line.substring(0, 8) + '\n';
            hexHtml += line.substring(10) + '\n';
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
            lineHexHtml += `<span class="hex-byte${isNull ? ' null-byte' : ''}" data-idx="${globalIdx}" onclick="hexSelectByte(${globalIdx})">${byte}</span>`;
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

    // --- Assessment Badge ---
    const assessmentColors = {
        clean: {bg: 'rgba(34,197,94,0.08)', border: '#22c55e', text: '#22c55e', label: 'CLEAN'},
        packed: {bg: 'rgba(168,85,247,0.08)', border: '#a855f7', text: '#a855f7', label: 'PACKED'},
        encrypted: {bg: 'rgba(239,68,68,0.08)', border: '#ef4444', text: '#ef4444', label: 'ENCRYPTED'},
        protected: {bg: 'rgba(251,191,36,0.08)', border: '#f59e0b', text: '#f59e0b', label: 'PROTECTED'},
        suspicious: {bg: 'rgba(251,191,36,0.06)', border: '#fbbf24', text: '#fbbf24', label: 'SUSPICIOUS'},
    };
    const assess = assessmentColors[detection.assessment] || assessmentColors.clean;

    html += `<div class="die-header">`;
    html += `<div class="die-title">BINARY ANALYSIS</div>`;
    html += `<div class="die-assessment" style="background:${assess.bg};border-color:${assess.border};color:${assess.text}">${assess.label}</div>`;
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
            compiler: '#60a5fa', linker: '#818cf8', packer: '#a855f7',
            protector: '#f59e0b', overlay: '#6b7280', language: '#22d3ee', runtime: '#34d399'
        };

        for (const [type, items] of Object.entries(groups)) {
            const icon = typeIcons[type] || '\u2022';
            const label = typeLabels[type] || type;
            const color = typeColors[type] || '#94a3b8';

            items.forEach(item => {
                const conf = item.confidence === 'high' ? 'H' : item.confidence === 'medium' ? 'M' : 'L';
                html += `<div class="die-detection-card" style="border-left-color:${color}">`;
                html += `<div class="die-det-icon" style="color:${color}">${icon}</div>`;
                html += `<div class="die-det-body">`;
                html += `<div class="die-det-type" style="color:${color}">${escapeHtml(label)}</div>`;
                html += `<div class="die-det-name">${escapeHtml(item.name)}</div>`;
                if (item.version) html += `<div class="die-det-ver">${escapeHtml(item.version)}</div>`;
                html += `</div>`;
                html += `<div class="die-det-conf" title="Confidence: ${item.confidence}">${conf}</div>`;
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
        html += `<div class="die-layout-section">`;
        html += `<div class="die-section-title">FILE STRUCTURE</div>`;
        html += `<div class="die-layout-bar">`;

        detection.section_layout.forEach(sec => {
            if (sec.pct_size < 0.3) return; // Skip tiny sections
            let secColor;
            if (sec.packer) secColor = '#a855f7'; // purple for packer sections
            else if (sec.entropy_status === 'high') secColor = '#ef4444'; // red for high entropy
            else if (sec.entropy_status === 'warn') secColor = '#fbbf24'; // yellow for warning
            else if (sec.executable) secColor = '#3b82f6'; // blue for code
            else if (sec.writable) secColor = '#22c55e'; // green for data
            else secColor = '#64748b'; // gray for read-only

            const tooltip = `${sec.name}: ${formatSize(sec.size)} | Entropy: ${sec.entropy.toFixed(2)}${sec.packer ? ' | ' + sec.packer : ''}`;
            html += `<div class="die-layout-seg" style="left:${sec.pct_start}%;width:${Math.max(sec.pct_size, 0.5)}%;background:${secColor}" title="${escapeHtml(tooltip)}">`;
            if (sec.pct_size > 5) html += `<span class="die-layout-label">${escapeHtml(sec.name)}</span>`;
            html += `</div>`;
        });

        // Show overlay if present
        if (detection.overlay && detection.overlay.size > 0 && detection.file_size > 0) {
            const overlayPct = (detection.overlay.size / detection.file_size * 100).toFixed(2);
            const overlayStart = (detection.overlay.offset / detection.file_size * 100).toFixed(2);
            html += `<div class="die-layout-seg die-overlay-seg" style="left:${overlayStart}%;width:${overlayPct}%;background:#6b7280" title="Overlay: ${formatSize(detection.overlay.size)}">`;
            if (parseFloat(overlayPct) > 5) html += `<span class="die-layout-label">overlay</span>`;
            html += `</div>`;
        }

        html += `</div>`; // end layout-bar

        // Legend
        html += `<div class="die-layout-legend">`;
        html += `<span class="die-legend-item"><span class="die-legend-dot" style="background:#3b82f6"></span>Code</span>`;
        html += `<span class="die-legend-item"><span class="die-legend-dot" style="background:#22c55e"></span>Data</span>`;
        html += `<span class="die-legend-item"><span class="die-legend-dot" style="background:#64748b"></span>Read-only</span>`;
        html += `<span class="die-legend-item"><span class="die-legend-dot" style="background:#ef4444"></span>High Entropy</span>`;
        html += `<span class="die-legend-item"><span class="die-legend-dot" style="background:#a855f7"></span>Packer</span>`;
        if (detection.overlay) html += `<span class="die-legend-item"><span class="die-legend-dot" style="background:#6b7280"></span>Overlay</span>`;
        html += `</div>`;

        html += `</div>`;
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

function renderPeAnalysis(pe, container) {
    let html = '';

    // --- DiE-style Detection Overview ---
    if (pe.detection) {
        html += renderDetectionOverview(pe.detection, 'pe');
    }

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
            return (order[a.severity] || 3) - (order[b.severity] || 3);
        }).forEach((f, idx) => {
            const hasEvidence = f.evidence && Object.keys(f.evidence).length > 0;
            html += `<div class="pe-flag-item sev-${f.severity}${hasEvidence ? ' expandable' : ''}" ${hasEvidence ? `onclick="toggleFlagEvidence(this)"` : ''}>`;
            html += `<span class="pe-flag-sev">${f.severity.toUpperCase()}</span>`;
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
        <div class="pe-card-title">SECURITY FEATURES</div>
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
    html += '<div class="pe-card-title">SECTIONS</div>';
    html += '<table class="pe-table"><thead><tr><th>Name</th><th>V.Addr</th><th>V.Size</th><th>Raw Size</th><th>Flags</th><th>Entropy</th><th>Status</th><th></th></tr></thead><tbody>';
    pe.sections.forEach((sec, idx) => {
        const rowClass = sec.entropy_status === 'high' ? 'pe-row-high' : sec.entropy_status === 'warn' ? 'pe-row-warn' : '';
        const rwx = sec.rwx_warning ? ' <span class="pe-rwx-badge">RWX</span>' : '';
        const packer = sec.packer_indicator ? ` <span class="pe-packer-badge">${escapeHtml(sec.packer_indicator)}</span>` : '';
        const flags = (sec.readable ? 'R' : '-') + (sec.writable ? 'W' : '-') + (sec.executable ? 'X' : '-');
        const entropyPct = Math.min(100, (sec.entropy / 8) * 100);
        const barColor = sec.entropy_status === 'high' ? '#ef4444' : sec.entropy_status === 'warn' ? '#fbbf24' : '#22c55e';

        const secOffsetDec = sec.raw_offset_dec != null ? sec.raw_offset_dec : parseInt(sec.raw_offset, 16);
        html += `<tr class="${rowClass}" id="pe-sec-row-${idx}">
            <td class="mono"><a class="section-link" href="#" onclick="peJumpToSection(${secOffsetDec}); return false;" title="View in Hex Editor">${escapeHtml(sec.name)}</a>${packer}${rwx}</td>
            <td class="mono">${sec.virtual_address}</td>
            <td>${formatSize(sec.virtual_size)}</td>
            <td>${formatSize(sec.raw_size)}</td>
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
        <tr class="pe-sec-detail-row" id="pe-sec-detail-${idx}" style="display:none;">
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
            return (order[a.severity] || 3) - (order[b.severity] || 3);
        }).forEach((f, idx) => {
            const hasEvidence = f.evidence && Object.keys(f.evidence).length > 0;
            html += `<div class="elf-flag-item sev-${f.severity}${hasEvidence ? ' expandable' : ''}" ${hasEvidence ? `onclick="toggleFlagEvidence(this)"` : ''}>`;
            html += `<span class="elf-flag-sev">${f.severity.toUpperCase()}</span>`;
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
        <div class="elf-card-title">SECURITY FEATURES</div>
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
        html += '<div class="elf-card-title">SECTIONS</div>';
        html += '<table class="elf-table"><thead><tr><th>#</th><th>Name</th><th>Type</th><th>Address</th><th>Offset</th><th>Size</th><th>Flags</th><th>Entropy</th><th>Status</th></tr></thead><tbody>';
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
                <td class="mono">${nameHtml}${wxBadge}${packerBadge}</td>
                <td>${escapeHtml(s.type)}</td>
                <td class="mono">${s.address}</td>
                <td class="mono">${s.offset}</td>
                <td>${formatSize(s.size)}</td>
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
        html += '<div class="elf-card-title">PROGRAM HEADERS (SEGMENTS)</div>';
        html += '<table class="elf-table"><thead><tr><th>#</th><th>Type</th><th>Offset</th><th>VAddr</th><th>FileSz</th><th>MemSz</th><th>Flags</th><th>Note</th></tr></thead><tbody>';
        elf.segments.forEach(seg => {
            const noteHtml = seg.security_note ? `<span class="elf-seg-note">${escapeHtml(seg.security_note)}</span>` :
                             seg.interpreter ? `<span class="elf-seg-note mono">${escapeHtml(seg.interpreter)}</span>` : '';
            html += `<tr>
                <td>${seg.index}</td>
                <td class="mono">${escapeHtml(seg.type)}</td>
                <td class="mono">${seg.offset}</td>
                <td class="mono">${seg.vaddr}</td>
                <td>${formatSize(seg.filesz)}</td>
                <td>${formatSize(seg.memsz)}</td>
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
        html += '<table class="elf-table elf-sym-table"><thead><tr><th>Name</th><th>Bind</th><th>Type</th></tr></thead><tbody>';
        elf.imported_symbols.forEach(sym => {
            html += `<tr><td class="mono">${escapeHtml(sym.name)}</td><td>${sym.bind}</td><td>${sym.type}</td></tr>`;
        });
        if (elf.import_count > elf.imported_symbols.length) {
            html += `<tr><td colspan="3" class="muted">... and ${elf.import_count - elf.imported_symbols.length} more</td></tr>`;
        }
        html += '</tbody></table></div></div>';
    }

    // --- Exported Symbols (collapsible) ---
    if (elf.exported_symbols && elf.exported_symbols.length > 0) {
        html += '<div class="elf-section-block">';
        html += `<div class="elf-card-title elf-collapsible" onclick="elfToggleSection(this)">EXPORTED SYMBOLS (${elf.export_count}) &#x25B6;</div>`;
        html += '<div class="elf-collapse-body" style="display:none;">';
        html += '<table class="elf-table elf-sym-table"><thead><tr><th>Name</th><th>Bind</th><th>Type</th><th>Value</th><th>Size</th></tr></thead><tbody>';
        elf.exported_symbols.forEach(sym => {
            html += `<tr><td class="mono">${escapeHtml(sym.name)}</td><td>${sym.bind}</td><td>${sym.type}</td><td class="mono">${sym.value}</td><td>${sym.size}</td></tr>`;
        });
        if (elf.export_count > elf.exported_symbols.length) {
            html += `<tr><td colspan="5" class="muted">... and ${elf.export_count - elf.exported_symbols.length} more</td></tr>`;
        }
        html += '</tbody></table></div></div>';
    }

    container.innerHTML = html;
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
    setDetailHeader('Service', 'background:rgba(249,115,22,0.15);color:var(--accent-orange)', 'DetonatorAgent', '');
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
                    const args = `'${escapeHtml(s.litterbox_hash || '')}', '${escapeHtml(s.sha256 || '')}', '${escapeHtml(s.agent_pid || '')}', '${escapeHtml((s.filename || '').replace(/'/g, ''))}'`;
                    const ts = s.timestamp ? new Date(s.timestamp).toLocaleString('en-GB', {hour12:false}) : '';
                    const vlabel = s.verdict && s.verdict.label ? s.verdict.label : '';
                    const vcls = vlabel === 'MALICIOUS' ? 'malicious' : (vlabel === 'SUSPICIOUS' ? 'suspicious' : 'clean');
                    recent += `<div class="det-recent-item" onclick="viewDetonationResult(${args})">
                        <span class="det-recent-name">${escapeHtml(s.filename || s.sha256 || 'unknown')}</span>
                        ${s.agent_pid ? `<span class="det-recent-pid">PID ${escapeHtml(String(s.agent_pid))}</span>` : ''}
                        ${vlabel ? `<span class="det-verdict-badge det-verdict-${vcls}" style="font-size:9px;padding:1px 6px;">${vlabel}</span>` : ''}
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
    setDetailHeader('Service', 'background:rgba(167,139,250,0.15);color:var(--accent-purple)', 'LitterBox', '');
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
                        html += `<div class="lb-analysis-entry" onclick="viewLitterboxResult('${escapeHtml(hash)}')">
                            <div class="lb-entry-main">
                                <span class="lb-entry-name" title="${escapeHtml(hash)}">${escapeHtml(filename)}</span>
                                <span class="lb-entry-time">${timeStr}</span>
                            </div>
                            <div class="lb-entry-meta">
                                <span class="lb-entry-score ${scoreClass}">${score}</span>
                                <span class="lb-entry-hash mono">${hash.substring(0, 16)}...</span>
                                <span class="lb-entry-status">${status}</span>
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
    setDetailHeader('Analysis', 'background:rgba(167,139,250,0.15);color:var(--accent-purple)', 'LitterBox Result', hash.substring(0, 12) + '...');
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
        if (fileInfo.score !== undefined) html += `<div class="detail-field"><span class="field-label">Score</span><span class="field-value" style="color:${fileInfo.score >= 7 ? 'var(--accent-red)' : fileInfo.score >= 4 ? '#fbbf24' : 'var(--accent-green)'};font-weight:700">${fileInfo.score}/10</span></div>`;
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
    html += `<div style="margin-top:12px;"><a href="http://localhost:1337" target="_blank" class="btn btn-sm" style="color:var(--accent-purple);border-color:rgba(167,139,250,0.3);">Open in LitterBox UI</a></div>`;

    setDetailBody(html);
}

async function viewDetonationResult(lbHash, sha256, pid, filename) {
    const displayHash = sha256 || lbHash || 'unknown';
    pushDetailHistory('detonation-result', displayHash);
    setDetailHeader('Analysis', 'background:rgba(167,139,250,0.15);color:var(--accent-purple)', 'Detonation Results', (filename || displayHash.substring(0, 12) + '...'));
    setDetailBody('<div class="muted">Fetching analysis results...</div>');
    showDetail();

    let html = '';

    // --- Fetch Fibratus/Rustinel alerts via /api/detonation/results ---
    let fibratusAlerts = [];
    let fibratusCount = 0;
    let verdict = null;
    let agentBlock = null;
    let iocFeed = null;
    try {
        const params = new URLSearchParams();
        if (sha256) params.set('sha256', sha256);
        if (pid) params.set('pid', pid);
        if (lbHash) params.set('litterbox_hash', lbHash);
        if (filename) params.set('filename', filename);
        const resp = await fetch(`/api/detonation/results?${params}`);
        if (resp.ok) {
            const data = await resp.json();
            fibratusAlerts = data.fibratus_alerts || [];
            fibratusCount = data.fibratus_alert_count || fibratusAlerts.length;
            verdict = data.verdict || null;
            agentBlock = data.agent || null;
            iocFeed = data.ioc_feed || null;
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
        if (fileInfo.score !== undefined) html += `<div class="detail-field"><span class="field-label">Score</span><span class="field-value" style="color:${fileInfo.score >= 7 ? 'var(--accent-red)' : fileInfo.score >= 4 ? '#fbbf24' : 'var(--accent-green)'};font-weight:700">${fileInfo.score}/10</span></div>`;
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
            <span class="det-verdict-badge">${verdict.label}</span>
            <span class="det-verdict-reasons">${verdict.reasons && verdict.reasons.length ? escapeHtml(verdict.reasons.join(' · ')) : 'No malicious indicators detected'}</span>
        </div>`;
    }
    if (iocFeed && iocFeed.status) {
        const st = iocFeed.status;
        const label = st === 'added' ? 'Hash added to Rustinel IOC watchlist'
            : st === 'exists' ? 'Hash already on IOC watchlist' : `IOC feed: ${st}`;
        html += `<div class="det-ioc-badge ${st === 'error' ? 'warn' : ''}">&#x1F4CC; ${escapeHtml(label)}</div>`;
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
            html += `<div class="det-alert-item sev-${sev}">
                <span class="det-alert-sev">${sev.toUpperCase()}</span>
                <span class="det-alert-rule">${escapeHtml(ruleName)}</span>
                <span class="det-alert-proc">${escapeHtml(procName)}${alertPid ? ' (PID:' + alertPid + ')' : ''}</span>
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
        html += `<div style="margin-top:12px;"><a href="http://localhost:1337" target="_blank" class="btn btn-sm" style="color:var(--accent-purple);border-color:rgba(167,139,250,0.3);">Open in LitterBox UI</a></div>`;
    }

    setDetailBody(html);
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
    setDetailHeader('Engine', 'background:rgba(34,211,238,0.15);color:var(--accent-cyan)', 'Rustinel', 'loading...');
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
    setDetailHeader('Engine', 'background:rgba(34,211,238,0.15);color:var(--accent-cyan)', 'Rustinel', '');

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
function openAlertDetail(idx) {
    const alert = state.alerts[idx];
    if (!alert) return;

    pushDetailHistory('alert', idx);
    const severity = (alert.severity || 'unknown').toLowerCase();
    const severityColors = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' };

    setDetailHeader(
        severity.charAt(0).toUpperCase() + severity.slice(1),
        `background:${severityColors[severity] || '#64748b'}20;color:${severityColors[severity] || '#94a3b8'}`,
        alert.rule_name || 'Unknown Rule',
        formatRelativeTime(alert.timestamp)
    );

    let html = '';
    if (alert.rule_description) {
        html += `<div class="alert-description">${escapeHtml(alert.rule_description)}</div>`;
    }

    // Pivot into the process graph on this alert's PID (and its parent).
    const pivots = [];
    if (alert.pid) pivots.push(`<button class="pivot-graph-btn" onclick="focusProcessGraph('${alert.pid}', {reset:true})">&#9673; PID ${alert.pid} in graph</button>`);
    if (alert.parent_pid) pivots.push(`<button class="pivot-graph-btn secondary" onclick="focusProcessGraph('${alert.parent_pid}', {reset:true})">&#9673; Parent ${alert.parent_pid} in graph</button>`);
    if (pivots.length) html += `<div class="pivot-graph-bar">${pivots.join('')}</div>`;

    const tags = (alert.tags || []).map(tag => {
        if (tag.startsWith('attack.t')) return `<span class="tag technique">${tag.replace('attack.', '').toUpperCase()}</span>`;
        if (tag.startsWith('attack.')) return `<span class="tag tactic">${tag.replace('attack.', '').toUpperCase()}</span>`;
        return `<span class="tag mitre">${escapeHtml(tag)}</span>`;
    }).join('');

    // --- Structured fields ---
    html += `<div class="detail-fields">
        <div class="detail-field"><span class="field-label">Severity</span><span class="field-value"><span class="ev-sev-dot ${severity}" style="display:inline-block;width:8px;height:8px;vertical-align:middle;margin-right:4px;"></span>${severity.charAt(0).toUpperCase() + severity.slice(1)}</span></div>
        <div class="detail-field"><span class="field-label">Engine</span><span class="field-value">${escapeHtml((alert.engine || 'unknown').toUpperCase())}</span></div>
        <div class="detail-field"><span class="field-label">Rule</span><span class="field-value mono">${escapeHtml(alert.rule_name || '')}</span></div>
        <div class="detail-field"><span class="field-label">PID</span><span class="field-value">${alert.pid || 'N/A'}</span></div>
        <div class="detail-field"><span class="field-label">Process</span><span class="field-value">${escapeHtml(alert.process_name || '')}</span></div>
        <div class="detail-field"><span class="field-label">Image</span><span class="field-value mono">${escapeHtml(alert.process_image || '')}</span></div>
        <div class="detail-field"><span class="field-label">Category</span><span class="field-value">${formatCategory(alert.category)}</span></div>
        ${alert.command_line ? `<div class="detail-field"><span class="field-label">Command</span><span class="field-value mono">${escapeHtml(alert.command_line)}</span></div>` : ''}
        ${alert.parent_name ? `<div class="detail-field"><span class="field-label">Parent</span><span class="field-value">${alert.parent_pid || '?'} (${escapeHtml(alert.parent_name)})</span></div>` : ''}
        ${alert.parent_command_line ? `<div class="detail-field"><span class="field-label">Parent Cmd</span><span class="field-value mono">${escapeHtml(alert.parent_command_line)}</span></div>` : ''}
        ${alert.user ? `<div class="detail-field"><span class="field-label">User</span><span class="field-value">${escapeHtml(alert.user)}</span></div>` : ''}
        ${tags ? `<div class="detail-field"><span class="field-label">ATT&CK</span><span class="field-value">${tags}</span></div>` : ''}
        <div class="detail-field"><span class="field-label">Timestamp</span><span class="field-value">${alert.timestamp || ''}</span></div>
    </div>`;

    // --- Parsed raw event as structured sections ---
    const raw = alert.raw || {};
    html += renderStructuredRawEvent(raw);

    setDetailBody(html);
    showDetail();
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
    state.selectedProcess = pid;
    renderProcessList();
    pushDetailHistory('process', pid);

    const proc = state.processes[pid] || state.processes[String(pid)];
    if (!proc) {
        setDetailHeader(`PID ${pid}`, 'background:rgba(59,130,246,0.2);color:#3b82f6', `Process ${pid}`, '');
        setDetailBody(`<div class="muted">No detailed information available for PID ${pid}.</div>`);
        showDetail();
        return;
    }

    const hasExited = !!proc.exit_time;
    const statusText = hasExited ? 'exited' : 'running';
    setDetailHeader(`PID ${proc.pid}`, 'background:rgba(59,130,246,0.2);color:#3b82f6', proc.name || 'unknown', statusText);

    let html = `<div class="pivot-graph-bar"><button class="pivot-graph-btn" onclick="focusProcessGraph('${proc.pid}', {reset:true})">&#9673; View in process graph</button></div>`;
    html += `<div class="detail-fields">
        <div class="detail-field"><span class="field-label">Image</span><span class="field-value mono">${escapeHtml(proc.image || '')}</span></div>
        <div class="detail-field"><span class="field-label">Command line</span><span class="field-value mono">${escapeHtml(proc.command_line || '')}</span></div>
        <div class="detail-field"><span class="field-label">User</span><span class="field-value">${escapeHtml(proc.user || '')}</span></div>
        <div class="detail-field"><span class="field-label">Parent</span><span class="field-value">${proc.parent_pid || 'N/A'} ${proc.parent_name ? '(' + escapeHtml(proc.parent_name) + ')' : ''}</span></div>
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
            const alertIdx = state.alerts.findIndex(a => a.id === alert.id);
            html += `<div class="child-card" onclick="openAlertDetail(${alertIdx >= 0 ? alertIdx : 0})">
                <div class="child-header">
                    <span class="event-severity ${sev}">${alert.severity}</span>
                    <span class="child-name" style="margin-left:8px">${escapeHtml(alert.rule_name || '')}</span>
                </div>
            </div>`;
        });
        html += `</div>`;
    }

    setDetailBody(html);
    showDetail();
}

// --- Render: Process list (sidebar) ---
function renderProcessList() {
    const container = document.getElementById('process-list');
    const count = document.getElementById('process-count');
    const procs = Object.values(state.processes);
    count.textContent = procs.length;

    if (!procs.length) {
        container.innerHTML = '<div class="muted" style="padding:8px;font-size:10px;">No processes tracked</div>';
        return;
    }

    container.innerHTML = procs.map(proc => {
        const hasThreats = (proc.activity?.threats || 0) > 0;
        const isActive = state.selectedProcess === proc.pid;
        return `<div class="process-item ${isActive ? 'active' : ''}" onclick="openProcessDetail(${proc.pid})">
                <div class="proc-icon ${hasThreats ? 'threat' : ''}"></div>
                <span class="proc-name">${escapeHtml(proc.name || 'unknown')}</span>
                <span class="proc-pid">${proc.pid}</span>
            </div>`;
    }).join('');
}

// --- Render: Timeline (sidebar) ---
function renderTimeline() {
    const container = document.getElementById('timeline');
    if (!state.alerts.length) {
        container.innerHTML = '';
        return;
    }
    const maxBars = 60;
    const alerts = state.alerts.slice(0, maxBars);
    container.innerHTML = alerts.map(alert => {
        const sev = (alert.severity || 'low').toLowerCase();
        const width = 30 + Math.random() * 70;
        return `<div class="timeline-bar severity-${sev}" style="width:${width}%" title="${escapeHtml(alert.rule_name || '')}"></div>`;
    }).join('');
}

// --- Render: Service status ---
function updateServiceStatus(status) {
    // Detect transitions and show toasts
    const services = [
        {key: 'rustinel', id: 'status-rustinel', name: 'Rustinel'},
        {key: 'sysmon', id: 'status-sysmon', name: 'Sysmon'},
        {key: 'detonator_agent', id: 'status-agent', name: 'Agent'},
        {key: 'litterbox', id: 'status-litterbox', name: 'Litterbox'},
        {key: 'fibratus', id: 'status-fibratus', name: 'Fibratus'},
    ];
    services.forEach(svc => {
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
        else if (prev.type === 'alert') openAlertDetail(prev.id);
    } else {
        closeDetail();
    }
}

function setDetailHeader(badgeText, badgeStyle, title, meta) {
    const headerLeft = document.querySelector('.detail-header-left');
    if (headerLeft) {
        headerLeft.innerHTML = `
            <button class="btn btn-sm" onclick="goDetailBack()">&lt; Back</button>
            <span class="detail-badge" id="detail-badge" style="${badgeStyle}">${badgeText}</span>
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
    const fullArgs = `'${lbHash || ''}', '${sha256 || ''}', '${pid || ''}', '${escapeHtml(filename).replace(/'/g, "\\'")}'`;
    html += `<div class="det-results-header">
        <div class="det-filename">${escapeHtml(filename)}</div>
        <div class="det-meta">
            ${sha256 ? `<span class="det-hash mono">${sha256.substring(0, 16)}...</span>` : ''}
            ${pid ? `<span class="det-pid">PID: ${pid}</span>` : ''}
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
                <div class="det-stage-detail">${ok ? 'Executed' : 'Failed'} (HTTP ${data.agent.status})${pid ? ` — PID ${pid}` : ''}</div>
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
                <div class="det-stage-detail">${ok ? `Triggered (PE-Sieve, Moneta, HollowsHunter) — ${data.litterbox_dynamic.target}` : 'Not triggered' + escapeHtml(errorDetail)}</div>
            </div>
        </div>`;
    }

    // Beacon scan stage
    if (data.beacon_scan) {
        const ok = data.beacon_scan.triggered;
        const tools = data.beacon_scan.tools ? data.beacon_scan.tools.join(', ') : '';
        html += `<div class="det-stage ${ok ? 'ok' : 'pending'}" id="det-beacon-stage">
            <div class="det-stage-icon">${ok ? '&#x2705;' : '&#x23F3;'}</div>
            <div class="det-stage-info">
                <div class="det-stage-title">Beacon Scanning</div>
                <div class="det-stage-detail">${ok ? `Triggered (${tools}) — scanning PID for C2 beacons...` : (data.beacon_scan.reason || 'Not triggered')}</div>
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

function pollDetonationResults(sha256, pid, lbHash, filename, attempt) {
    if (_detonationPollTimer) clearTimeout(_detonationPollTimer);
    const maxAttempts = 30; // Poll for up to ~2.5 minutes
    if (attempt >= maxAttempts) {
        const panels = document.getElementById('det-results-panels');
        if (panels) panels.innerHTML = '<div class="det-poll-done">Polling complete. Results shown above reflect final state.</div>';
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
            renderDetonationPanels(data);
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
                _detonationPollTimer = setTimeout(() => pollDetonationResults(sha256, pid, lbHash, filename, attempt + 1), 5000);
            } else {
                // Final update: show polling complete message
                const panels = document.getElementById('det-results-panels');
                if (panels && !panels.querySelector('.det-poll-done')) {
                    let msg;
                    if (allOffline) {
                        msg = '<div class="det-poll-done">Polling complete. All analysis services offline — no results available.</div>';
                    } else if (litterboxOffline && bothEdrOffline) {
                        msg = '<div class="det-poll-done">Polling complete. LitterBox and EDR services offline.</div>';
                    } else if (litterboxOffline) {
                        msg = '<div class="det-poll-done">Polling complete. LitterBox offline — static/dynamic analysis unavailable.</div>';
                    } else if (bothEdrOffline) {
                        msg = '<div class="det-poll-done">Polling complete. EDR services offline — no detection alerts available.</div>';
                    } else {
                        msg = '<div class="det-poll-done">Polling complete. All results collected.</div>';
                    }
                    panels.insertAdjacentHTML('beforeend', msg);
                }
            }
        })
        .catch(() => {
            _detonationPollTimer = setTimeout(() => pollDetonationResults(sha256, pid, lbHash, filename, attempt + 1), 5000);
        });
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
            <span class="det-verdict-badge">${v.label}</span>
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

    // --- Build tabs (only those with data) ---
    const tabs = [];

    // Alerts tab
    const alerts = data.fibratus_alerts || [];
    if (alerts.length > 0) {
        let body = `<table class="det-alert-table"><thead><tr>
            <th>Severity</th><th>Rule / Threat</th><th>Process</th><th>Engine</th><th>Time</th><th>Raw</th>
            </tr></thead><tbody>`;
        alerts.forEach(alert => {
            const sev = (alert.severity || 'unknown').toLowerCase();
            const ruleName = alert.rule_name || 'Unknown Rule';
            const procName = alert.process_name || '';
            const engine = alert.engine || '';
            const apid = alert.pid || '';
            const ts = alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString('en-GB', {hour12:false}) : '';
            body += `<tr class="sev-${sev}">
                <td><span class="det-alert-sev sev-${sev}">${sev.toUpperCase()}</span></td>
                <td>${escapeHtml(ruleName)}</td>
                <td>${escapeHtml(procName)}${apid ? ' <span class="muted">(PID:' + apid + ')</span>' : ''}</td>
                <td>${escapeHtml(engine)}</td>
                <td class="muted">${ts}</td>
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

    // Beacon scanning tab
    const hasBeaconResults = data.hunt_sleeping_beacons || data.beaconeye;
    if (hasBeaconResults) {
        let body = '';
        if (data.hunt_sleeping_beacons) {
            const hsb = data.hunt_sleeping_beacons;
            body += `<div class="det-sub-title">Hunt-Sleeping-Beacons</div>`;
            if (hsb.error) {
                body += `<div class="det-sub-value det-warn">${escapeHtml(hsb.error)}</div>`;
            } else {
                const count = hsb.suspicious_count || 0;
                body += `<div class="det-sub-value ${count > 0 ? 'det-warn' : ''}">${count > 0 ? count + ' suspicious indicator(s) found' : 'No sleeping beacons detected'}</div>`;
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
        tabs.push({ id: 'det-tab-beacons', label: 'Beacons', body });
    }

    // Raw JSON tab (full response)
    tabs.push({ id: 'det-tab-raw', label: 'Raw JSON', body: `<pre class="det-raw det-raw-tall">${escapeHtml(JSON.stringify(data, null, 2))}</pre>` });

    // Render the tab component
    if (tabs.length > 0) {
        html += `<div class="det-tabs"><div class="det-tab-nav">`;
        tabs.forEach((t, i) => {
            html += `<button class="det-tab-btn ${i === 0 ? 'active' : ''}" onclick="detShowTab('${t.id}', this)">${escapeHtml(t.label)}${t.count !== undefined ? ` <span class="det-tab-count">${t.count}</span>` : ''}</button>`;
        });
        html += `</div>`;
        tabs.forEach((t, i) => {
            html += `<div class="det-tab-content ${i === 0 ? '' : 'hidden'}" id="${t.id}">${t.body}</div>`;
        });
        html += `</div>`;
    }

    // Update beacon stage card if results arrived
    if (hasBeaconResults) {
        const bStage = document.getElementById('det-beacon-stage');
        if (bStage) {
            const hsbCount = data.hunt_sleeping_beacons?.suspicious_count || 0;
            const beCount = data.beaconeye?.beacons_found || 0;
            const totalFindings = hsbCount + beCount;
            if (totalFindings > 0) {
                bStage.className = 'det-stage ok';
                bStage.querySelector('.det-stage-icon').innerHTML = '&#x26A0;';
                bStage.querySelector('.det-stage-detail').textContent = `${totalFindings} beacon indicator(s) found`;
            } else {
                bStage.className = 'det-stage ok';
                bStage.querySelector('.det-stage-icon').innerHTML = '&#x2705;';
                bStage.querySelector('.det-stage-detail').textContent = 'Scan complete — no beacons detected';
            }
        }
    }

    // Show polling status if nothing yet
    if (!html) {
        html = `<div class="det-panel-loading"><div class="loading-spinner"></div><span>Waiting for results... Analysis may take 1-3 minutes.</span></div>`;
    }

    panels.innerHTML = html;
}

// --- Submissions History ---
async function refreshSubmissions() {
    const container = document.getElementById('submissions-list');
    if (!container) return;

    try {
        const resp = await fetch('/api/submissions');
        if (!resp.ok) {
            container.innerHTML = '<div style="padding:12px;color:var(--text-muted);font-size:11px;">Failed to load submissions.</div>';
            return;
        }
        const submissions = await resp.json();

        if (!submissions.length) {
            container.innerHTML = '<div style="padding:12px;color:var(--text-muted);font-size:11px;">No samples submitted yet. Use the form above to detonate a sample.</div>';
            return;
        }

        let html = '<table class="submissions-table"><thead><tr>';
        html += '<th>Time</th><th>Filename</th><th>SHA-256</th><th>Size</th><th>Target</th><th>Status</th><th>Actions</th>';
        html += '</tr></thead><tbody>';

        submissions.forEach(sub => {
            const ts = sub.timestamp ? new Date(sub.timestamp).toLocaleString('en-GB', {hour12: false, day:'2-digit', month:'short', hour:'2-digit', minute:'2-digit', second:'2-digit'}) : '--';
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
                ? `<button class="btn btn-xs" onclick="hexOpenFile('${escapeHtml(sub.file_path.replace(/\\/g, '\\\\'))}')" title="Open in Hex Editor">Hex</button>`
                : '';
            // Add LitterBox results button if submission went to LitterBox
            const lbHash = sub.litterbox_hash || sub.sha256;
            if (lbHash && (sub.target === 'litterbox' || sub.target === 'both' || sub.litterbox_status === 'success')) {
                actions += ` <button class="btn btn-xs btn-lb-results" onclick="viewDetonationResult('${escapeHtml(lbHash)}', '${escapeHtml(sub.sha256 || '')}', '${escapeHtml(sub.agent_pid || '')}', '${escapeHtml(sub.filename || '')}')" title="View analysis results (LitterBox + Fibratus)">Results</button>`;
            } else if (sub.sha256 || sub.agent_pid) {
                // Even without LitterBox, show results button for Fibratus/Rustinel alerts
                actions += ` <button class="btn btn-xs btn-lb-results" onclick="viewDetonationResult('', '${escapeHtml(sub.sha256 || '')}', '${escapeHtml(sub.agent_pid || '')}', '${escapeHtml(sub.filename || '')}')" title="View Fibratus/Rustinel alerts">Results</button>`;
            }

            html += `<tr>`;
            html += `<td class="td-time">${ts}</td>`;
            html += `<td class="td-filename" title="${escapeHtml(sub.filename || '')}">${escapeHtml(sub.filename || '--')}</td>`;
            html += `<td class="td-hash mono" title="${escapeHtml(sub.sha256 || '')}">${shortHash}</td>`;
            html += `<td class="td-size">${sub.size ? formatSize(sub.size) : '--'}</td>`;
            html += `<td class="td-target">${escapeHtml(sub.target || '--')}</td>`;
            html += `<td class="td-status">${agentBadge} ${lbBadge} ${pid}</td>`;
            html += `<td class="td-actions">${actions}</td>`;
            html += `</tr>`;
        });

        html += '</tbody></table>';
        container.innerHTML = html;
    } catch (e) {
        container.innerHTML = `<div style="padding:12px;color:var(--accent-red);font-size:11px;">Error: ${escapeHtml(e.message)}</div>`;
    }
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
};

// Programmatically focus the process graph on a PID (used by alert/process pivots).
function focusProcessGraph(pid, opts = {}) {
    const { push = true, reset = false } = opts;
    pid = String(pid);
    if (reset) graphState.focusStack = [];
    else if (push && graphState.focusPid && graphState.focusPid !== pid) {
        graphState.focusStack.push(graphState.focusPid);
    }
    graphState.focusPid = pid;
    graphState.selectedNode = null;
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
        const resp = await fetch(`/api/process-graph?pid=${encodeURIComponent(graphState.focusPid)}&down_depth=${depth}&max_nodes=400`);
        payload = await resp.json();
        if (!resp.ok || payload.error) {
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
                <div class="gsc-foot">${s.executed ? '&#9673; Open process tree (PID ' + escapeHtml(String(s.pid)) + ')' : '&#9656; Show scan details'}</div>
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
            const sevClass = r.severity && r.severity !== 'unknown' ? `sev-${r.severity}` : '';
            const badges = [];
            if (r.detonated) badges.push('<span class="glc-badge det">detonated</span>');
            if (r.threats > 0) badges.push(`<span class="glc-badge threat">${r.threats} threats</span>`);
            if (r.children_count > 0) badges.push(`<span class="glc-badge">${r.children_count} children</span>`);
            html += `<div class="graph-landing-card ${sevClass}" data-pid="${escapeHtml(String(r.pid))}">
                <div class="glc-head"><span class="glc-name">${escapeHtml(r.name || 'unknown')}</span><span class="glc-pid">PID ${escapeHtml(String(r.pid))}</span></div>
                ${r.image ? `<div class="glc-image">${escapeHtml(r.image)}</div>` : ''}
                <div class="glc-badges">${badges.join('')}</div>
            </div>`;
        });
        html += '</div>';
    }
    html += '</div>';
    landing.innerHTML = html;

    landing.querySelectorAll('.graph-landing-card[data-pid]').forEach(card => {
        card.addEventListener('click', () => focusProcessGraph(card.dataset.pid, { reset: true }));
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

    const procs = payload.processes || {};

    // 1. Process nodes — the focused subtree: ancestors + root + descendants
    for (const [pid, proc] of Object.entries(procs)) {
        const threats = proc.activity?.threats || 0;
        const node = {
            id: `proc_${pid}`,
            type: 'process',
            pid: pid,
            label: proc.name || 'unknown',
            image: proc.image || '',
            cmdline: proc.command_line || '',
            user: proc.user || '',
            threats: threats,
            severity: proc.severity || 'unknown',
            children: proc.children || [],
            parentPid: proc.parent_pid,
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
            if (ev.pid) netTargets[key].pids.add(String(ev.pid));
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
            if (ev.pid) dnsTargets[query].pids.add(String(ev.pid));
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
        const srcPid = String(ev.source_pid);
        const tgtPid = String(ev.target_pid);
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
            fileTargets[path].pids.add(String(ev.pid));
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
            regTargets[shortKey].pids.add(String(ev.pid));
        });
        for (const [key, info] of Object.entries(regTargets)) {
            const nodeId = `reg_${key}`;
            nodes.push({ id: nodeId, type: 'registry', label: key, fullPath: info.path, x: 0, y: 0, vx: 0, vy: 0, radius: 7 });
            info.pids.forEach(pid => {
                if (nodeMap[pid]) edges.push({ source: `proc_${pid}`, target: nodeId, type: 'registry', label: 'modify' });
            });
        }
    }

    // Apply layout: rooted process tree (default) or force-directed
    const layout = document.getElementById('graph-layout')?.value || 'tree';
    if (layout === 'force') {
        applyForceLayout(nodes, edges);
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
            .filter(k => k && String(k.parentPid) === String(node.pid) && !visited.has(k.id));
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

        // Repulsion between all nodes
        for (let i = 0; i < nodes.length; i++) {
            for (let j = i + 1; j < nodes.length; j++) {
                const dx = nodes[j].x - nodes[i].x;
                const dy = nodes[j].y - nodes[i].y;
                const dist = Math.sqrt(dx * dx + dy * dy) || 1;
                const force = 3000 / (dist * dist);
                const fx = (dx / dist) * force * alpha;
                const fy = (dy / dist) * force * alpha;
                nodes[i].x -= fx;
                nodes[i].y -= fy;
                nodes[j].x += fx;
                nodes[j].y += fy;
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

    function resize() {
        canvas.width = container.clientWidth;
        canvas.height = container.clientHeight;
        renderGraph();
    }
    resize();
    window.addEventListener('resize', resize);

    // Mouse interactions
    let lastMouse = { x: 0, y: 0 };

    canvas.addEventListener('mousedown', e => {
        const pos = screenToWorld(e.offsetX, e.offsetY);
        const node = findNodeAt(pos.x, pos.y);
        if (node) {
            graphState.dragging = node;
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
        minX = Math.min(minX, n.x - n.radius);
        maxX = Math.max(maxX, n.x + n.radius);
        minY = Math.min(minY, n.y - n.radius);
        maxY = Math.max(maxY, n.y + n.radius);
    });

    const padding = 60;
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
        ctx.fillStyle = '#64748b';
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

    const nodeColors = {
        process: '#3b82f6',
        network: '#22c55e',
        dns: '#a78bfa',
        file: '#f97316',
        registry: '#f472b6',
    };

    const edgeColors = {
        spawn: '#475569',
        network: '#22c55e',
        dns: '#a78bfa',
        inject: '#ef4444',
        file: '#f97316',
        registry: '#f472b6',
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
        ctx.strokeStyle = edgeColors[edge.type] || '#475569';
        ctx.lineWidth = edge.type === 'inject' ? 2 : 1;
        if (edge.type === 'inject') {
            ctx.setLineDash([4, 3]);
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
            ctx.fillStyle = edgeColors[edge.type];
            ctx.globalAlpha = 0.7;
            ctx.fill();
            ctx.globalAlpha = 1;
        }
    });

    // Draw nodes
    nodes.forEach(node => {
        const isHovered = graphState.hoveredNode === node;
        const isSelected = graphState.selectedNode === node;
        let color = nodeColors[node.type] || '#64748b';

        // Override color for malicious processes
        if (node.type === 'process' && node.threats > 0) {
            if (node.severity === 'critical') color = '#ef4444';
            else if (node.severity === 'high') color = '#f97316';
            else if (node.severity === 'medium') color = '#eab308';
        }

        // Override color for detonated processes (gold)
        if (node.detonated) {
            color = '#fbbf24';
        }

        const r = node.radius * (isHovered ? 1.2 : 1);

        // Ancestors are drawn faded to keep the focus subtree prominent
        ctx.globalAlpha = node.isAncestor ? 0.5 : 1;

        // Focus ring for the root node
        if (node.isRoot) {
            ctx.beginPath();
            ctx.arc(node.x, node.y, r + 8, 0, Math.PI * 2);
            ctx.strokeStyle = '#38bdf8';
            ctx.lineWidth = 2;
            ctx.setLineDash([3, 3]);
            ctx.stroke();
            ctx.setLineDash([]);
        }

        // Glow for malicious
        if (node.type === 'process' && node.threats > 0) {
            ctx.beginPath();
            ctx.arc(node.x, node.y, r + 4, 0, Math.PI * 2);
            ctx.fillStyle = color + '20';
            ctx.fill();
        }

        // Glow for detonated
        if (node.detonated) {
            ctx.beginPath();
            ctx.arc(node.x, node.y, r + 5, 0, Math.PI * 2);
            ctx.fillStyle = '#fbbf2425';
            ctx.fill();
        }

        // Node circle
        ctx.beginPath();
        ctx.arc(node.x, node.y, r, 0, Math.PI * 2);
        ctx.fillStyle = color + '30';
        ctx.fill();
        ctx.strokeStyle = isSelected ? '#fff' : color;
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
        ctx.fillStyle = isHovered ? '#fff' : '#94a3b8';
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
            ctx.fillStyle = '#ef4444';
            ctx.fill();
            ctx.font = 'bold 7px monospace';
            ctx.fillStyle = '#fff';
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillText(String(node.threats), bx, by);
        }

        // Scan verdict indicator (bottom-left): matched EMBER/capa/TC/DC result
        if (node.type === 'process' && node.scans && node.scans.length) {
            const vColors = { malicious: '#ef4444', detected: '#ef4444',
                              clean: '#4ade80', analyzed: '#38bdf8', unknown: '#64748b' };
            const vc = vColors[node.scanVerdict] || '#64748b';
            const sbx = node.x - r * 0.7;
            const sby = node.y + r * 0.7;
            ctx.beginPath();
            ctx.arc(sbx, sby, 6, 0, Math.PI * 2);
            ctx.fillStyle = vc;
            ctx.fill();
            ctx.strokeStyle = '#0b1220';
            ctx.lineWidth = 1.5;
            ctx.stroke();
            ctx.font = 'bold 7px monospace';
            ctx.fillStyle = '#0b1220';
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
            ctx.fillStyle = '#38bdf8';
            ctx.fillRect(node.x - tw / 2 - 4, badgeY - 11, tw + 8, 12);
            ctx.fillStyle = '#0b1220';
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
        html += `<div class="tt-field"><span>PID:</span> ${node.pid}</div>`;
        if (node.image) html += `<div class="tt-field"><span>Image:</span> ${escapeHtml(node.image)}</div>`;
        if (node.threats) html += `<div class="tt-field"><span>Threats:</span> ${node.threats}</div>`;
        if (node.scans && node.scans.length) {
            const vm = _VERDICT_META[node.scanVerdict] || _VERDICT_META.unknown;
            html += `<div class="tt-field"><span>Scan:</span> ${escapeHtml(vm.text)} (${node.scans.length})</div>`;
        }
    } else if (node.type === 'network') {
        html += `<div class="tt-field"><span>IP:</span> ${node.ip}:${node.port}</div>`;
        html += `<div class="tt-field"><span>Protocol:</span> ${node.protocol || 'tcp'}</div>`;
    } else if (node.type === 'dns') {
        html += `<div class="tt-field"><span>Query:</span> ${escapeHtml(node.label)}</div>`;
        if (node.result) html += `<div class="tt-field"><span>Result:</span> ${escapeHtml(node.result)}</div>`;
    } else if (node.type === 'file') {
        html += `<div class="tt-field"><span>Path:</span> ${escapeHtml(node.fullPath || node.label)}</div>`;
    } else if (node.type === 'registry') {
        html += `<div class="tt-field"><span>Key:</span> ${escapeHtml(node.fullPath || node.label)}</div>`;
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
            html += `<div class="gd-actions"><button class="gd-focus-btn" data-focus-pid="${escapeHtml(String(node.pid))}">&#9673; Focus this process</button></div>`;
        } else {
            html += `<div class="gd-actions"><span class="gd-focus-current">&#9673; Current focus root</span></div>`;
        }
        html += `<div class="gd-field"><span class="gd-label">Image</span><span class="gd-value">${escapeHtml(node.image)}</span></div>`;
        if (node.cmdline) html += `<div class="gd-field"><span class="gd-label">Cmdline</span><span class="gd-value gd-cmdline">${escapeHtml(node.cmdline)}</span></div>`;
        if (node.user) html += `<div class="gd-field"><span class="gd-label">User</span><span class="gd-value">${escapeHtml(node.user)}</span></div>`;
        html += `<div class="gd-field"><span class="gd-label">Status</span><span class="gd-value">${node.exited ? '<span style="color:#94a3b8">Exited</span>' : '<span style="color:#4ade80">Running</span>'}</span></div>`;
        html += `<div class="gd-field"><span class="gd-label">First seen</span><span class="gd-value">${node.firstSeen || '--'}</span></div>`;
        if (node.parentPid) {
            const parentNode = graphState.nodes.find(n => n.type === 'process' && String(n.pid) === String(node.parentPid));
            if (parentNode) {
                html += `<div class="gd-field"><span class="gd-label">Parent</span><span class="gd-value"><a class="gd-link" data-node-id="${parentNode.id}">${escapeHtml(parentNode.label)} (${parentNode.pid})</a></span></div>`;
            } else {
                html += `<div class="gd-field"><span class="gd-label">Parent PID</span><span class="gd-value">${node.parentPid}</span></div>`;
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
                if (target) html += `<div class="gd-conn-item"><span class="gd-conn-icon net"></span><span class="gd-conn-text">${escapeHtml(target.ip || target.label)}:${target.port || ''}</span><span class="gd-conn-proto">${target.protocol || 'tcp'}</span></div>`;
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

        // Sysmon Event IDs triggered by this process + correlated Windows Event IDs
        const pidSysmonEvents = (graphState._allSysmonEvents || []).filter(ev => String(ev.pid) === String(node.pid));
        if (pidSysmonEvents.length) {
            // Collect unique Sysmon Event IDs with counts
            const eidCounts = {};
            pidSysmonEvents.forEach(ev => {
                const eid = ev.event_id;
                if (!eidCounts[eid]) eidCounts[eid] = { count: 0, type: ev.type || `Event_${eid}` };
                eidCounts[eid].count++;
            });

            html += `<div class="gd-section">Triggered Sysmon Events <span class="gd-count">${pidSysmonEvents.length}</span></div>`;
            html += `<div class="gd-eid-grid">`;
            for (const [eid, info] of Object.entries(eidCounts).sort((a,b) => b[1].count - a[1].count)) {
                const typeClass = getSysmonTypeClass(eid);
                html += `<div class="gd-eid-item"><span class="type-badge ${typeClass}">EID ${eid}</span><span class="gd-eid-name">${escapeHtml(info.type)}</span><span class="gd-eid-count">${info.count}x</span></div>`;
            }
            html += `</div>`;

            // Correlated Windows Event IDs
            const allWinEids = new Map();
            for (const eid of Object.keys(eidCounts)) {
                const corr = getCorrelatedWindowsEvents(parseInt(eid));
                corr.forEach(c => {
                    if (!allWinEids.has(c.id)) allWinEids.set(c.id, c);
                });
            }
            if (allWinEids.size) {
                html += `<div class="gd-section">Correlated Windows Event IDs <span class="gd-count">${allWinEids.size}</span></div>`;
                html += `<div class="gd-eid-grid">`;
                for (const [weid, info] of allWinEids) {
                    html += `<div class="gd-eid-item"><span class="corr-badge">${weid}</span><span class="gd-eid-name">${escapeHtml(info.name)}</span><span class="gd-eid-log">[${escapeHtml(info.log)}]</span></div>`;
                }
                html += `</div>`;
            }
        }

        // PowerShell commands associated with this process (or child powershell processes)
        const psPid = String(node.pid);
        const psEvents = (graphState._allSysmonEvents || []).filter(ev => {
            if (ev.event_id !== 1) return false;
            const img = (ev.image || '').toLowerCase();
            const cmd = (ev.commandline || '').toLowerCase();
            return (img.includes('powershell') || cmd.includes('powershell')) &&
                   (String(ev.pid) === psPid || String(ev.parent_pid) === psPid);
        });
        if (psEvents.length) {
            html += `<div class="gd-section">PowerShell Commands <span class="gd-count">${psEvents.length}</span></div>`;
            html += `<div class="gd-ps-list">`;
            psEvents.forEach(ev => {
                const time = ev.timestamp ? formatSysmonTime(ev.timestamp) : '';
                html += `<div class="gd-ps-item"><span class="gd-ps-time">${time}</span><span class="gd-ps-cmd">${escapeHtml(ev.commandline || '')}</span></div>`;
            });
            html += `</div>`;
        }

    } else if (node.type === 'network') {
        headerText = `Network: ${node.ip}:${node.port}`;
        html += `<div class="gd-field"><span class="gd-label">IP</span><span class="gd-value">${node.ip}</span></div>`;
        html += `<div class="gd-field"><span class="gd-label">Port</span><span class="gd-value">${node.port}</span></div>`;
        html += `<div class="gd-field"><span class="gd-label">Protocol</span><span class="gd-value">${node.protocol || 'tcp'}</span></div>`;
        const conns = graphState.edges.filter(e => e.target === node.id);
        if (conns.length) {
            html += `<div class="gd-section">Connected from <span class="gd-count">${conns.length}</span></div>`;
            conns.forEach(e => {
                const src = graphState.nodes.find(n => n.id === e.source);
                if (src) html += `<div class="gd-conn-item"><span class="gd-conn-icon proc"></span><a class="gd-link" data-node-id="${src.id}">${escapeHtml(src.label)} (${src.pid})</a></div>`;
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
                if (src) html += `<div class="gd-conn-item"><span class="gd-conn-icon proc"></span><a class="gd-link" data-node-id="${src.id}">${escapeHtml(src.label)} (${src.pid})</a></div>`;
            });
        }
    } else {
        headerText = `${node.type}: ${node.label}`;
        if (node.fullPath) html += `<div class="gd-field"><span class="gd-label">Path</span><span class="gd-value">${escapeHtml(node.fullPath)}</span></div>`;
    }

    header.textContent = headerText;
    body.innerHTML = html;

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
        html += `<span class="gd-child-pid">PID ${child.pid}</span>`;
        if (threats > 0) html += `<span class="gd-child-threats">${threats}</span>`;
        html += `<span class="gd-child-focus" data-node-id="${child.id}" title="Focus this node">&#8599;</span>`;
        html += `</div>`;

        // Collapsible detail body
        html += `<div class="gd-child-body">`;
        if (child.image) html += `<div class="gd-child-detail"><span class="gd-child-dlabel">Image:</span> ${escapeHtml(child.image)}</div>`;
        if (child.cmdline) html += `<div class="gd-child-detail gd-cmdline"><span class="gd-child-dlabel">Cmd:</span> ${escapeHtml(child.cmdline)}</div>`;
        html += `<div class="gd-child-detail"><span class="gd-child-dlabel">Status:</span> ${child.exited ? 'Exited' : 'Running'}</div>`;
        if (child.firstSeen) html += `<div class="gd-child-detail"><span class="gd-child-dlabel">First seen:</span> ${child.firstSeen}</div>`;

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
    ['graph-show-network', 'graph-show-dns', 'graph-show-files', 'graph-show-registry'].forEach(id => {
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
let sysmonEvents = [];
let sysmonStats = null;

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
    }

    try {
        const [eventsResp, statsResp] = await Promise.all([
            fetch(url),
            fetch('/api/sysmon/stats'),
        ]);
        if (eventsResp.ok) {
            sysmonEvents = await eventsResp.json();
            // Check if the response contains an error from backend retries
            if (sysmonEvents.length === 1 && sysmonEvents[0]?.error) {
                showToast('warning', 'Sysmon query issue', sysmonEvents[0].error, 6000);
            }
            renderSysmonTable();
        } else if (tableContainer) {
            showToast('error', 'Sysmon events failed', `Server returned ${eventsResp.status}`, 5000);
            tableContainer.innerHTML = '<div class="empty-state">Failed to load Sysmon events.</div>';
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
        if (tableContainer) {
            tableContainer.innerHTML = `<div class="empty-state">Connection error: ${escapeHtml(e.message)}</div>`;
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
        html += `<span class="stats-chip ${typeClass}" onclick="filterSysmonByType('${s.event_id}')">${s.name} <strong>${s.count}</strong></span>`;
    });
    html += `</div>`;
    container.innerHTML = html;
}

function filterSysmonByType(eventId) {
    const select = document.getElementById('sysmon-filter-type');
    if (select) { select.value = eventId; refreshSysmon(); }
}

function renderSysmonTable() {
    const container = document.getElementById('sysmon-table');
    if (!container) return;

    if (!sysmonEvents || !sysmonEvents.length) {
        container.innerHTML = '<div class="empty-state">No Sysmon events found</div>';
        return;
    }

    if (sysmonEvents[0]?.error) {
        container.innerHTML = `<div class="empty-state">Error: ${escapeHtml(sysmonEvents[0].error)}</div>`;
        return;
    }

    // Apply local filters
    const searchTerm = (document.getElementById('sysmon-search')?.value || '').toLowerCase().trim();
    const eidFilter = (document.getElementById('sysmon-filter-eid')?.value || '').trim();
    const winEidFilter = (document.getElementById('sysmon-filter-wineid')?.value || '').trim();
    let filtered = sysmonEvents;

    // Filter by Sysmon Event IDs (comma-separated)
    if (eidFilter) {
        const eids = eidFilter.split(',').map(s => parseInt(s.trim(), 10)).filter(n => !isNaN(n));
        if (eids.length) {
            filtered = filtered.filter(ev => eids.includes(ev.event_id));
        }
    }

    // Filter by correlated Windows Event IDs (comma-separated)
    if (winEidFilter) {
        const winEids = winEidFilter.split(',').map(s => parseInt(s.trim(), 10)).filter(n => !isNaN(n));
        if (winEids.length) {
            filtered = filtered.filter(ev => {
                const correlated = getCorrelatedWindowsEvents(ev.event_id);
                return correlated.some(c => winEids.includes(c.id));
            });
        }
    }

    // Text search filter
    if (searchTerm) {
        filtered = filtered.filter(ev => {
            const haystack = [
                ev.image, ev.commandline, ev.type, ev.target, ev.query,
                ev.dst_ip, ev.dst_hostname, ev.loaded_image, ev.source_image,
                ev.target_image, ev.parent_image, ev.user, ev.hashes,
                String(ev.pid || ''), String(ev.event_id || ''),
                ev.details, ev.result
            ].filter(Boolean).join(' ').toLowerCase();
            return haystack.includes(searchTerm);
        });
    }

    const hasAnyFilter = searchTerm || eidFilter || winEidFilter;
    if (!filtered.length) {
        const filterDesc = [searchTerm && `"${searchTerm}"`, eidFilter && `Sysmon EID: ${eidFilter}`, winEidFilter && `Win EID: ${winEidFilter}`].filter(Boolean).join(', ');
        container.innerHTML = `<div class="empty-state">No events matching ${escapeHtml(filterDesc)} (${sysmonEvents.length} total)</div>`;
        return;
    }

    const countInfo = hasAnyFilter ? ` <span class="sysmon-filter-count">(${filtered.length}/${sysmonEvents.length})</span>` : '';
    let html = `<table class="sysmon-events-table"><thead><tr><th>Time</th><th>Type</th><th>PID</th><th>Image</th><th>Details</th><th class="col-corr">Win. EID</th></tr></thead><tbody>`;
    filtered.forEach(ev => {
        const typeClass = getSysmonTypeClass(String(ev.event_id));
        const time = ev.timestamp ? formatSysmonTime(ev.timestamp) : '';
        const image = ev.image ? ev.image.split('\\').pop() : '';
        const details = getSysmonDetails(ev);
        const correlated = getCorrelatedWindowsEvents(ev.event_id);
        const corrHtml = correlated.length > 0
            ? correlated.map(c => `<span class="corr-badge" title="${escapeHtml(c.name)}">${c.id}</span>`).join('')
            : '';
        html += `<tr onclick="showSysmonDetail(${JSON.stringify(ev).replace(/"/g, '&quot;')})">
            <td class="col-time">${time}</td>
            <td><span class="type-badge ${typeClass}">${escapeHtml(ev.type || '')}</span></td>
            <td class="col-pid">${ev.pid || ''}</td>
            <td class="col-image">${escapeHtml(image)}</td>
            <td class="col-details">${escapeHtml(details)}</td>
            <td class="col-corr">${corrHtml}</td>
        </tr>`;
    });
    html += '</tbody></table>';
    if (hasAnyFilter) html = `<div class="sysmon-search-info">Showing ${filtered.length} of ${sysmonEvents.length} events${countInfo}</div>` + html;
    container.innerHTML = html;
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
    try { const d = new Date(isoStr); return d.toLocaleTimeString('en-US', { hour12: false }) + '.' + String(d.getMilliseconds()).padStart(3, '0'); } catch { return isoStr; }
}

function truncate(str, max) {
    return str && str.length > max ? str.substring(0, max) + '...' : (str || '');
}

function showSysmonDetail(ev) {
    let html = `<div class="detail-section"><div class="detail-section-title">${escapeHtml(ev.type || 'Event')} - PID ${ev.pid || '?'}</div>
        <div class="detail-fields">
            <div class="detail-field"><span class="field-label">Timestamp</span><span class="field-value">${escapeHtml(ev.timestamp || '')}</span></div>
            <div class="detail-field"><span class="field-label">Event ID</span><span class="field-value">${ev.event_id}</span></div>
            <div class="detail-field"><span class="field-label">PID</span><span class="field-value">${ev.pid || ''}</span></div>
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

    setDetailHeader('Sysmon', 'background:rgba(34,197,94,0.15);color:var(--accent-green)', ev.type || 'Event', '');
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

    let html = '<div class="corr-panel-header"><span class="corr-panel-title">Sysmon / Windows Event ID Correlation</span><button class="btn btn-sm" onclick="toggleSysmonCorrelation()">Close</button></div>';
    html += '<div class="corr-panel-body"><table class="corr-ref-table"><thead><tr><th>Sysmon ID</th><th>Sysmon Event</th><th>Related Windows Events</th></tr></thead><tbody>';

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

    let html = `<table class="sysmon-events-table"><thead><tr><th>File</th><th>Type</th><th>Size</th><th>Risk</th><th>Entropy</th><th>Static</th><th>Dynamic</th><th>EDR</th><th>Actions</th></tr></thead><tbody>`;
    entries.forEach(e => {
        const riskClass = (e.detection_risk || '').toLowerCase();
        const riskBadge = `<span class="lb-risk-badge lb-risk-${riskClass}">${escapeHtml(e.detection_risk || '?')}</span>`;
        const size = e.file_size ? formatSize(e.file_size) : '--';
        const entropy = e.entropy_value != null ? e.entropy_value.toFixed(2) : '--';
        const staticBadge = e.has_static_analysis ? '<span class="lb-check">&#10003;</span>' : '<span class="lb-x">&#10007;</span>';
        const dynamicBadge = e.has_dynamic_analysis ? '<span class="lb-check">&#10003;</span>' : '<span class="lb-x">&#10007;</span>';
        const edrBadge = e.has_edr_analysis ? '<span class="lb-check">&#10003;</span>' : '<span class="lb-x">&#10007;</span>';
        const md5 = e.md5 || '';

        html += `<tr>
            <td class="col-image" title="${escapeHtml(e.sha256 || '')}">${escapeHtml(e.filename || e._key)}</td>
            <td><span class="lb-type-badge">${e._type}</span></td>
            <td>${size}</td>
            <td>${riskBadge}</td>
            <td class="mono">${entropy}</td>
            <td class="center">${staticBadge}</td>
            <td class="center">${dynamicBadge}</td>
            <td class="center">${edrBadge}</td>
            <td class="lb-actions">
                <button class="btn btn-xs" onclick="lbRunAnalysis('static','${md5}')" title="Run static analysis">Static</button>
                <button class="btn btn-xs" onclick="lbRunAnalysis('dynamic','${md5}')" title="Run dynamic analysis">Dynamic</button>
                <button class="btn btn-xs btn-outline" onclick="lbShowDetail('${md5}')" title="View results">Detail</button>
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
            fetch(`/api/litterbox/api/results/risk/${md5}`),
            fetch(`/api/litterbox/api/results/edr/${md5}`),
        ]);

        let html = `<div class="lb-detail-header"><span>Results for ${md5}</span><button class="btn btn-xs" onclick="document.getElementById('lb-detail-panel').style.display='none'">Close</button></div>`;

        if (riskResp.ok) {
            const risk = await riskResp.json();
            html += `<div class="lb-detail-section"><div class="lb-detail-title">Risk Assessment</div>`;
            html += `<div class="lb-detail-field"><span class="lb-dl">Score</span><span class="lb-dv lb-risk-badge lb-risk-${(risk.risk_level||'').toLowerCase()}">${risk.risk_score ?? '?'} / 10 (${risk.risk_level || '?'})</span></div>`;
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
        html += `<div class="lb-detail-section"><a href="http://192.168.64.4:1337/results/static/${md5}" target="_blank" class="btn btn-sm btn-outline">Open in LitterBox UI</a></div>`;

        panel.innerHTML = html;
    } catch (e) {
        panel.innerHTML = `<div class="empty-state">Error loading results: ${escapeHtml(e.message)}</div>`;
    }
}

// Init LitterBox on tab switch
function initLitterbox() {
    if (_lbData) return;
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
    cb.addEventListener('change', () => {
        if (cb.checked) {
            _etwAutoInterval = setInterval(() => {
                if (state.activeTab === 'etw') refreshEtw();
            }, 5000);
        } else {
            clearInterval(_etwAutoInterval);
            _etwAutoInterval = null;
        }
    });
    _etwAutoInterval = setInterval(() => {
        if (state.activeTab === 'etw') refreshEtw();
    }, 5000);
}

async function refreshEtw() {
    const channel = document.getElementById('etw-channel-select')?.value || 'etw-ti';
    const filter = document.getElementById('etw-filter-input')?.value || '';
    const max = document.getElementById('etw-max-select')?.value || '50';
    const listEl = document.getElementById('etw-event-list');
    if (!listEl) return;

    try {
        const params = new URLSearchParams({channel, max, filter});
        const resp = await fetch(`/api/etw/events?${params}`);
        const data = await resp.json();

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
            html += `<div class="etw-event ${levelClass}${mal ? ' malicious' : ''}" onclick="this.classList.toggle('expanded')">`;
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
    if (!str) return '';
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
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
document.addEventListener('keydown', e => {
    if (e.key === 'Escape') {
        const helpModal = document.getElementById('help-modal');
        if (helpModal && !helpModal.classList.contains('hidden')) {
            closeHelp();
            return;
        }
        if (state.detailOpen) closeDetail();
    }
    if (e.key === 'Backspace' && state.detailOpen && !['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement.tagName)) {
        e.preventDefault();
        goDetailBack();
    }
});

// --- Help Modal ---
function openHelp() {
    const modal = document.getElementById('help-modal');
    if (modal) modal.classList.remove('hidden');
}

function closeHelp() {
    const modal = document.getElementById('help-modal');
    if (modal) modal.classList.add('hidden');
}

// Help tab switching
document.addEventListener('DOMContentLoaded', () => {
    const helpTabs = document.querySelectorAll('.help-tab');
    helpTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const target = tab.dataset.help;
            helpTabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            document.querySelectorAll('.help-section').forEach(s => s.classList.remove('active'));
            const section = document.getElementById('help-' + target);
            if (section) section.classList.add('active');
        });
    });
});
