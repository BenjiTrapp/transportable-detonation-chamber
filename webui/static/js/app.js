/**
 * Detonation Chamber - Unified Web UI
 * Frontend logic for the tracing/analysis interface
 */

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
    initScannerDropZone();
    initGraphControls();
    initRtraceTabs();
    refreshAll();
    setInterval(refreshAlerts, 5000);
    setInterval(refreshDashboard, 10000);
    refreshDashboard();
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
        }
        if (rustinelResp.ok) {
            state.rustinelInfo = await rustinelResp.json();
        }
        renderDashboard();
        const timeEl = document.getElementById('dashboard-time');
        if (timeEl) timeEl.textContent = 'Updated ' + new Date().toLocaleTimeString('en-GB');
    } catch (e) {
        console.error('Failed to refresh dashboard:', e);
    }
}

async function refreshAlerts() {
    try {
        const resp = await fetch('/api/alerts');
        if (resp.ok) {
            state.alerts = await resp.json();
            if (state.alerts.length) {
                const times = state.alerts.map(a => new Date(a.timestamp).getTime()).filter(t => !isNaN(t));
                state.sessionStart = times.length ? Math.min(...times) : null;
            }
            renderTimeline();
            if (state.activeTab === 'tracing') {
                renderRtraceConsole();
            }
        }
    } catch (e) {
        console.error('Failed to fetch alerts:', e);
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
        console.error('Failed to fetch processes:', e);
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
        const servicesOnline = [
            status.rustinel?.online,
            status.detonator_agent?.online,
            status.litterbox?.online,
            status.sysmon?.online,
        ].filter(Boolean).length;
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
                <div class="stat-value">${servicesOnline}<span class="stat-value-sub">/5</span></div>
                <div class="stat-label">SERVICES ONLINE</div>
                <div class="stat-breakdown"><span class="stat-tag ${servicesOnline >= 4 ? 'ok' : 'warn'}">${servicesOnline >= 4 ? 'Healthy' : 'Degraded'}</span></div>
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
                <div class="stat-value">2</div>
                <div class="stat-label">SCANNER TOOLS</div>
                <div class="stat-breakdown">
                    <span class="stat-tag dim">ThreatCheck</span>
                    <span class="stat-tag dim">DefenderCheck</span>
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
                <div class="service-metric"><div class="service-metric-value ${aInUse ? '' : 'zero'}">${aInUse ? 'Yes' : 'No'}</div><div class="service-metric-label">IN USE</div></div>
                <div class="service-metric"><div class="service-metric-value">${aOnline ? 'Fibratus' : '--'}</div><div class="service-metric-label">EDR</div></div>
            </div>
            <div class="service-card-actions">
                <button class="btn btn-sm" onclick="event.stopPropagation(); openAgentDetail()">Details</button>
                <button class="btn btn-sm" onclick="event.stopPropagation(); switchTab('submit')">Submit Sample</button>
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
            </div>
        </div>
    `);

    // Fibratus Card
    const fOnline = status.fibratus?.online || rOnline; // assumes running if Rustinel is
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

    const procs = Object.values(state.processes);
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

function renderRtraceProcessTree() {
    const container = document.getElementById('rtrace-tree-list');
    const countEl = document.getElementById('rtrace-tree-count');
    if (!container) return;

    const procs = Object.values(state.processes);
    if (countEl) countEl.textContent = procs.length;

    if (!procs.length) {
        container.innerHTML = '<div style="padding:12px;color:var(--text-muted);font-size:11px;">No processes tracked yet. Submit a sample to begin.</div>';
        return;
    }

    // Sort by first_seen
    const sorted = [...procs].sort((a, b) => (a.first_seen || '').localeCompare(b.first_seen || ''));

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

let scanHistory = [];
let scannerFile = null;

function initScannerDropZone() {
    const zone = document.getElementById('scanner-drop-zone');
    const input = document.getElementById('scanner-file-input');
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
            scannerFile = e.dataTransfer.files[0];
            zone.classList.add('has-file');
            zone.querySelector('p').innerHTML = `<strong>${escapeHtml(scannerFile.name)}</strong> (${formatSize(scannerFile.size)}) <span class="hex-change-file" onclick="scannerResetDrop()">change</span>`;
        }
    });
    input.addEventListener('change', () => {
        if (input.files.length) {
            scannerFile = input.files[0];
            zone.classList.add('has-file');
            zone.querySelector('p').innerHTML = `<strong>${escapeHtml(scannerFile.name)}</strong> (${formatSize(scannerFile.size)}) <span class="hex-change-file" onclick="scannerResetDrop()">change</span>`;
            input.value = '';
        }
    });

    // Show/hide engine/type options based on tool selection
    document.getElementById('scanner-tool').addEventListener('change', () => {
        const tool = document.getElementById('scanner-tool').value;
        document.getElementById('scanner-engine-group').style.display = tool === 'threatcheck' ? '' : 'none';
        document.getElementById('scanner-type-group').style.display = tool === 'threatcheck' ? '' : 'none';
    });
}

function scannerResetDrop() {
    scannerFile = null;
    const zone = document.getElementById('scanner-drop-zone');
    zone.classList.remove('has-file');
    zone.querySelector('p').innerHTML = 'Drop a file to scan or <span class="hex-browse-link" onclick="document.getElementById(\'scanner-file-input\').click()">browse</span>';
}

async function runScan() {
    const tool = document.getElementById('scanner-tool').value;
    const engine = document.getElementById('scanner-engine').value;
    const fileType = document.getElementById('scanner-type').value;
    const pathInput = document.getElementById('scanner-filepath').value.trim();
    const resultsEl = document.getElementById('scanner-results');
    const btn = document.getElementById('scanner-run-btn');

    if (!scannerFile && !pathInput) {
        resultsEl.innerHTML = '<div class="scanner-error">Please select a file or enter a VM path.</div>';
        return;
    }

    btn.disabled = true;
    btn.textContent = 'Scanning...';
    resultsEl.innerHTML = '<div class="scanner-running">Running scan... This may take up to 2 minutes.</div>';

    const formData = new FormData();
    if (scannerFile) {
        formData.append('file', scannerFile);
    } else {
        formData.append('path', pathInput);
    }

    let url;
    if (tool === 'threatcheck') {
        formData.append('engine', engine);
        formData.append('type', fileType);
        url = '/api/scan/threatcheck';
    } else {
        url = '/api/scan/defendercheck';
    }

    try {
        LoadingSpinner.start();
        const resp = await fetch(url, { method: 'POST', body: formData });
        const data = await resp.json();

        if (data.error) {
            resultsEl.innerHTML = `<div class="scanner-error">Error: ${escapeHtml(data.error)}</div>`;
        } else {
            renderScanResult(data, resultsEl);
            // Add to history
            scanHistory.unshift({
                ...data,
                timestamp: new Date().toISOString(),
                filename: scannerFile ? scannerFile.name : pathInput.split('\\').pop(),
            });
            if (scanHistory.length > 50) scanHistory.length = 50;
            renderScanHistory();
        }
    } catch (e) {
        resultsEl.innerHTML = `<div class="scanner-error">Network error: ${escapeHtml(e.message)}</div>`;
    }

    LoadingSpinner.stop();
    btn.disabled = false;
    btn.textContent = 'Scan';
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

    html += `</div>`;
    container.innerHTML = html;
}

function renderScanHistory() {
    const container = document.getElementById('scanner-history-list');
    if (!container || scanHistory.length === 0) {
        if (container) container.innerHTML = '';
        return;
    }

    let html = '';
    scanHistory.forEach((entry, idx) => {
        const ts = new Date(entry.timestamp).toLocaleTimeString('en-GB', {hour12: false});
        const statusClass = entry.clean ? 'history-clean' : entry.detected ? 'history-detected' : 'history-unknown';
        const statusText = entry.clean ? 'Clean' : entry.detected ? 'Detected' : '?';
        const toolLabel = entry.tool + (entry.engine ? '/' + entry.engine : '');
        html += `<div class="scan-history-entry ${statusClass}">`;
        html += `<span class="scan-history-time">${ts}</span>`;
        html += `<span class="scan-history-file">${escapeHtml(entry.filename || '--')}</span>`;
        html += `<span class="scan-history-tool">${escapeHtml(toolLabel)}</span>`;
        html += `<span class="scan-history-status">${statusText}</span>`;
        html += `</div>`;
    });
    container.innerHTML = html;
}

function clearScanHistory() {
    scanHistory = [];
    const container = document.getElementById('scanner-history-list');
    if (container) container.innerHTML = '';
}

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
        let lineAsciiHtml = '';
        for (let i = 0; i < asciiPart.length; i++) {
            const ch = asciiPart[i];
            const globalIdx = (validLineIdx * 16) + i;
            const isPrintable = ch !== '.';
            lineAsciiHtml += `<span class="ascii-char${isPrintable ? '' : ' non-printable'}" data-idx="${globalIdx}" onclick="hexSelectByte(${globalIdx})">${escapeHtml(ch)}</span>`;
        }
        asciiHtml += lineAsciiHtml + '\n';

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

function renderPeAnalysis(pe, container) {
    let html = '';

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
        }).forEach(f => {
            html += `<div class="pe-flag-item sev-${f.severity}"><span class="pe-flag-sev">${f.severity.toUpperCase()}</span><span class="pe-flag-detail">${escapeHtml(f.detail)}</span></div>`;
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

    // --- Sections Table with entropy bars ---
    html += '<div class="pe-section-table">';
    html += '<div class="pe-card-title">SECTIONS</div>';
    html += '<table class="pe-table"><thead><tr><th>Name</th><th>V.Addr</th><th>V.Size</th><th>Raw Size</th><th>Flags</th><th>Entropy</th><th>Status</th></tr></thead><tbody>';
    pe.sections.forEach(sec => {
        const rowClass = sec.entropy_status === 'high' ? 'pe-row-high' : sec.entropy_status === 'warn' ? 'pe-row-warn' : '';
        const rwx = sec.rwx_warning ? ' <span class="pe-rwx-badge">RWX</span>' : '';
        const packer = sec.packer_indicator ? ` <span class="pe-packer-badge">${escapeHtml(sec.packer_indicator)}</span>` : '';
        const flags = (sec.readable ? 'R' : '-') + (sec.writable ? 'W' : '-') + (sec.executable ? 'X' : '-');
        const entropyPct = Math.min(100, (sec.entropy / 8) * 100);
        const barColor = sec.entropy_status === 'high' ? '#ef4444' : sec.entropy_status === 'warn' ? '#fbbf24' : '#22c55e';

        html += `<tr class="${rowClass}">
            <td class="mono">${escapeHtml(sec.name)}${packer}${rwx}</td>
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

// --- Detail Panels for Dashboard Services ---
async function openAgentDetail() {
    pushDetailHistory('agent', 0);
    setDetailHeader('Service', 'background:rgba(249,115,22,0.15);color:var(--accent-orange)', 'DetonatorAgent', '');
    setDetailBody('<div class="muted">Loading...</div>');
    showDetail();

    const online = state.serviceStatus.detonator_agent?.online;
    let html = `<div class="detail-fields">
        <div class="detail-field"><span class="field-label">Status</span><span class="field-value" style="color:${online ? 'var(--accent-green)' : 'var(--accent-red)'}">${online ? 'Running' : 'Stopped'}</span></div>
        <div class="detail-field"><span class="field-label">Port</span><span class="field-value">8080</span></div>
        <div class="detail-field"><span class="field-label">Framework</span><span class="field-value">.NET 8.0</span></div>
        <div class="detail-field"><span class="field-label">Install Dir</span><span class="field-value mono">C:\\DetonatorAgent</span></div>
        <div class="detail-field"><span class="field-label">EDR Plugin</span><span class="field-value">Fibratus</span></div>
    </div>`;
    setDetailBody(html);
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
        <div class="detail-field"><span class="field-label">Install Dir</span><span class="field-value mono">C:\\LitterBox</span></div>
    </div>`;
    setDetailBody(html);
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

    let html = `<div class="detail-fields">
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
    setStatus('status-rustinel', status.rustinel?.online);
    setStatus('status-sysmon', status.sysmon?.online);
    setStatus('status-agent', status.detonator_agent?.online);
    setStatus('status-litterbox', status.litterbox?.online);
    setStatus('status-fibratus', status.rustinel?.online);
}

function setStatus(elementId, online) {
    const el = document.getElementById(elementId);
    if (el) {
        el.classList.toggle('online', !!online);
        el.classList.toggle('offline', !online);
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
    html += `<div class="det-results-header">
        <div class="det-filename">${escapeHtml(filename)}</div>
        <div class="det-meta">
            ${sha256 ? `<span class="det-hash mono">${sha256.substring(0, 16)}...</span>` : ''}
            ${pid ? `<span class="det-pid">PID: ${pid}</span>` : ''}
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
        html += `<div class="det-stage ${ok ? 'ok' : 'fail'}">
            <div class="det-stage-icon">${ok ? '&#x2705;' : '&#x274C;'}</div>
            <div class="det-stage-info">
                <div class="det-stage-title">LitterBox Upload</div>
                <div class="det-stage-detail">${ok ? 'Uploaded' : 'Failed'}</div>
            </div>
        </div>`;
    }

    // LitterBox static analysis stage
    if (data.litterbox_static) {
        const ok = data.litterbox_static.triggered;
        html += `<div class="det-stage ${ok ? 'ok' : 'pending'}">
            <div class="det-stage-icon">${ok ? '&#x2705;' : '&#x23F3;'}</div>
            <div class="det-stage-info">
                <div class="det-stage-title">Static Analysis</div>
                <div class="det-stage-detail">${ok ? 'Triggered (YARA + CheckPlz + Strings)' : 'Not triggered'}</div>
            </div>
        </div>`;
    }

    // LitterBox dynamic analysis stage
    if (data.litterbox_dynamic) {
        const ok = data.litterbox_dynamic.triggered;
        html += `<div class="det-stage ${ok ? 'ok' : 'pending'}">
            <div class="det-stage-icon">${ok ? '&#x2705;' : '&#x23F3;'}</div>
            <div class="det-stage-info">
                <div class="det-stage-title">Dynamic Analysis</div>
                <div class="det-stage-detail">${ok ? `Triggered (PE-Sieve, Moneta, HollowsHunter) — ${data.litterbox_dynamic.target}` : 'Not triggered'}</div>
            </div>
        </div>`;
    }

    // Fibratus/EDR stage (always pending initially)
    html += `<div class="det-stage pending" id="det-fibratus-stage">
        <div class="det-stage-icon">&#x23F3;</div>
        <div class="det-stage-info">
            <div class="det-stage-title">Fibratus / Rustinel EDR</div>
            <div class="det-stage-detail">Waiting for detection alerts...</div>
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
        pollDetonationResults(sha256, pid, lbHash, 0);
    }
}

let _detonationPollTimer = null;

function pollDetonationResults(sha256, pid, lbHash, attempt) {
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

    fetch(`/api/detonation/results?${params}`)
        .then(r => r.json())
        .then(data => {
            renderDetonationPanels(data);
            // Update Fibratus stage indicator
            const fStage = document.getElementById('det-fibratus-stage');
            if (fStage && data.fibratus_alert_count > 0) {
                fStage.className = 'det-stage ok';
                fStage.querySelector('.det-stage-icon').innerHTML = '&#x2705;';
                fStage.querySelector('.det-stage-detail').textContent = `${data.fibratus_alert_count} alert(s) detected`;
            }
            // Keep polling if not all results are ready
            const allReady = data.ready && data.ready.static !== false && data.ready.dynamic !== false;
            if (!allReady || attempt < 5) {
                _detonationPollTimer = setTimeout(() => pollDetonationResults(sha256, pid, lbHash, attempt + 1), 5000);
            }
        })
        .catch(() => {
            _detonationPollTimer = setTimeout(() => pollDetonationResults(sha256, pid, lbHash, attempt + 1), 5000);
        });
}

function renderDetonationPanels(data) {
    const panels = document.getElementById('det-results-panels');
    if (!panels) return;

    let html = '';

    // --- Fibratus / Rustinel Alerts ---
    if (data.fibratus_alerts && data.fibratus_alerts.length > 0) {
        html += `<div class="det-panel">
            <div class="det-panel-title">FIBRATUS / RUSTINEL ALERTS (${data.fibratus_alert_count})</div>
            <div class="det-alerts-list">`;
        data.fibratus_alerts.slice(0, 20).forEach(alert => {
            const sev = (alert.severity || alert.rule?.level || 'unknown').toLowerCase();
            const ruleName = alert.rule_name || alert.rule?.name || 'Unknown Rule';
            const procName = alert.process?.name || '';
            html += `<div class="det-alert-item sev-${sev}">
                <span class="det-alert-sev">${sev.toUpperCase()}</span>
                <span class="det-alert-rule">${escapeHtml(ruleName)}</span>
                <span class="det-alert-proc">${escapeHtml(procName)}</span>
            </div>`;
        });
        html += `</div></div>`;
    }

    // --- LitterBox Static Results ---
    if (data.litterbox_static) {
        const st = data.litterbox_static;
        html += `<div class="det-panel">
            <div class="det-panel-title">STATIC ANALYSIS (LitterBox)</div>
            <div class="det-panel-body">`;

        // YARA matches
        if (st.yara_results || st.yara) {
            const yara = st.yara_results || st.yara;
            if (Array.isArray(yara) && yara.length > 0) {
                html += `<div class="det-subsection"><span class="det-sub-label">YARA Matches:</span>`;
                yara.forEach(m => {
                    const name = typeof m === 'string' ? m : (m.rule || m.name || JSON.stringify(m));
                    html += `<span class="det-yara-match">${escapeHtml(name)}</span>`;
                });
                html += `</div>`;
            } else if (typeof yara === 'object' && !Array.isArray(yara)) {
                const matches = yara.matches || yara.rules || [];
                if (matches.length > 0) {
                    html += `<div class="det-subsection"><span class="det-sub-label">YARA Matches:</span>`;
                    matches.forEach(m => {
                        html += `<span class="det-yara-match">${escapeHtml(typeof m === 'string' ? m : m.rule || m.name || '')}</span>`;
                    });
                    html += `</div>`;
                }
            }
        }

        // CheckPlz results
        if (st.checkplz_results || st.checkplz) {
            const cp = st.checkplz_results || st.checkplz;
            html += `<div class="det-subsection"><span class="det-sub-label">CheckPlz:</span><span class="det-sub-value">${escapeHtml(typeof cp === 'string' ? cp : JSON.stringify(cp).substring(0, 200))}</span></div>`;
        }

        // Strings analysis
        if (st.stringnalyzer_results || st.strings) {
            const strs = st.stringnalyzer_results || st.strings;
            if (typeof strs === 'object' && strs.suspicious_count) {
                html += `<div class="det-subsection"><span class="det-sub-label">Suspicious Strings:</span><span class="det-sub-value">${strs.suspicious_count} found</span></div>`;
            }
        }

        // Raw data fallback
        if (!st.yara_results && !st.yara && !st.checkplz_results && !st.checkplz) {
            html += `<pre class="det-raw">${escapeHtml(JSON.stringify(st, null, 2)).substring(0, 2000)}</pre>`;
        }

        html += `</div></div>`;
    }

    // --- LitterBox Dynamic Results ---
    if (data.litterbox_dynamic) {
        const dyn = data.litterbox_dynamic;
        html += `<div class="det-panel">
            <div class="det-panel-title">DYNAMIC ANALYSIS (LitterBox)</div>
            <div class="det-panel-body">`;

        // PE-Sieve results
        if (dyn.pe_sieve || dyn.pe_sieve_results) {
            const ps = dyn.pe_sieve || dyn.pe_sieve_results;
            html += `<div class="det-subsection"><span class="det-sub-label">PE-Sieve:</span>`;
            if (typeof ps === 'object') {
                const suspicious = ps.suspicious || ps.total_suspicious || ps.modified || 0;
                const replaced = ps.replaced || 0;
                html += `<span class="det-sub-value ${suspicious > 0 ? 'det-warn' : ''}">Suspicious: ${suspicious}, Replaced: ${replaced}</span>`;
            } else {
                html += `<span class="det-sub-value">${escapeHtml(String(ps).substring(0, 200))}</span>`;
            }
            html += `</div>`;
        }

        // Moneta results
        if (dyn.moneta || dyn.moneta_results) {
            const mon = dyn.moneta || dyn.moneta_results;
            html += `<div class="det-subsection"><span class="det-sub-label">Moneta:</span>`;
            if (typeof mon === 'object') {
                const iocs = mon.ioc_count || mon.iocs || 0;
                html += `<span class="det-sub-value ${iocs > 0 ? 'det-warn' : ''}">IOCs: ${iocs}</span>`;
            } else {
                html += `<span class="det-sub-value">${escapeHtml(String(mon).substring(0, 200))}</span>`;
            }
            html += `</div>`;
        }

        // HollowsHunter results
        if (dyn.hollows_hunter || dyn.hollows_hunter_results) {
            const hh = dyn.hollows_hunter || dyn.hollows_hunter_results;
            html += `<div class="det-subsection"><span class="det-sub-label">HollowsHunter:</span>`;
            if (typeof hh === 'object') {
                const suspicious = hh.suspicious || hh.total_suspicious || 0;
                html += `<span class="det-sub-value ${suspicious > 0 ? 'det-warn' : ''}">Suspicious: ${suspicious}</span>`;
            } else {
                html += `<span class="det-sub-value">${escapeHtml(String(hh).substring(0, 200))}</span>`;
            }
            html += `</div>`;
        }

        // RedEdr results
        if (dyn.rededr || dyn.rededr_results) {
            const re = dyn.rededr || dyn.rededr_results;
            html += `<div class="det-subsection"><span class="det-sub-label">RedEdr:</span>`;
            html += `<span class="det-sub-value">${escapeHtml(typeof re === 'string' ? re.substring(0, 200) : JSON.stringify(re).substring(0, 200))}</span>`;
            html += `</div>`;
        }

        // Raw data fallback
        if (!dyn.pe_sieve && !dyn.pe_sieve_results && !dyn.moneta && !dyn.moneta_results && !dyn.hollows_hunter && !dyn.hollows_hunter_results) {
            html += `<pre class="det-raw">${escapeHtml(JSON.stringify(dyn, null, 2)).substring(0, 2000)}</pre>`;
        }

        html += `</div></div>`;
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
            const actions = sub.file_path
                ? `<button class="btn btn-xs" onclick="hexOpenFile('${escapeHtml(sub.file_path.replace(/\\/g, '\\\\'))}')" title="Open in Hex Editor">Hex</button>`
                : '';

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
    timeRangeSeconds: 0, // 0 = all time
    searchQuery: '', // search filter for process/filename
};

async function graphRefresh() {
    // Fetch process tree + sysmon network/DNS data in parallel
    const [procResp, sysmonNetResp, sysmonDnsResp, sysmonInjectResp] = await Promise.all([
        fetch('/api/processes'),
        fetch('/api/sysmon?event_id=3&max=300'),
        fetch('/api/sysmon?event_id=22&max=200'),
        fetch('/api/sysmon?event_id=8&max=100'),
    ]);

    let processes = {};
    let networkEvents = [];
    let dnsEvents = [];
    let injectEvents = [];

    if (procResp.ok) processes = await procResp.json();
    if (sysmonNetResp.ok) networkEvents = await sysmonNetResp.json();
    if (sysmonDnsResp.ok) dnsEvents = await sysmonDnsResp.json();
    if (sysmonInjectResp.ok) injectEvents = await sysmonInjectResp.json();

    // Also use the alerts already in state for network info
    const networkAlerts = (state.alerts || []).filter(a => {
        const cat = (Array.isArray(a.category) ? a.category[0] : a.category || '').toLowerCase();
        return cat === 'network';
    });

    buildGraph(processes, networkEvents, dnsEvents, injectEvents, networkAlerts);
    if (!graphState.initialized) {
        initGraphCanvas();
        graphState.initialized = true;
    }
    graphFitView();
    renderGraph();
}

function buildGraph(processes, networkEvents, dnsEvents, injectEvents, networkAlerts) {
    const nodes = [];
    const edges = [];
    const nodeMap = {};

    const showNetwork = document.getElementById('graph-show-network')?.checked;
    const showDns = document.getElementById('graph-show-dns')?.checked;
    const showFiles = document.getElementById('graph-show-files')?.checked;
    const showRegistry = document.getElementById('graph-show-registry')?.checked;
    const showDetonatedOnly = document.getElementById('graph-show-detonated')?.checked;

    // Time range filtering
    const timeRange = graphState.timeRangeSeconds;
    let cutoffTime = null;
    if (timeRange > 0) {
        cutoffTime = new Date(Date.now() - timeRange * 1000).toISOString();
    }

    function isInTimeRange(timestamp) {
        if (!cutoffTime || !timestamp) return true;
        return timestamp >= cutoffTime;
    }

    // Filter sysmon events by time
    if (cutoffTime) {
        networkEvents = networkEvents.filter(e => isInTimeRange(e.timestamp));
        dnsEvents = dnsEvents.filter(e => isInTimeRange(e.timestamp));
        injectEvents = injectEvents.filter(e => isInTimeRange(e.timestamp));
        networkAlerts = networkAlerts.filter(a => isInTimeRange(a.timestamp));
    }

    // 1. Create process nodes - only include interesting ones
    //    (has alerts OR is parent/child of one that does OR has sysmon network/dns activity)
    //    Also apply time range filter to processes
    const sysmonPids = new Set();
    networkEvents.forEach(ev => { if (ev.pid) sysmonPids.add(String(ev.pid)); });
    dnsEvents.forEach(ev => { if (ev.pid) sysmonPids.add(String(ev.pid)); });
    injectEvents.forEach(ev => {
        if (ev.pid) sysmonPids.add(String(ev.pid));
        if (ev.source_pid) sysmonPids.add(String(ev.source_pid));
        if (ev.target_pid) sysmonPids.add(String(ev.target_pid));
    });

    // First pass: identify processes with alerts in the time range
    const alertPids = new Set();
    for (const [pid, proc] of Object.entries(processes)) {
        if ((proc.activity?.threats || 0) > 0) {
            // Check if any of this process's alerts are in time range
            if (cutoffTime) {
                const hasRecentAlert = (proc.alerts || []).some(a => isInTimeRange(a.timestamp));
                if (hasRecentAlert) alertPids.add(pid);
            } else {
                alertPids.add(pid);
            }
        }
    }

    // Also include processes that were active in the time range (first_seen or last_seen)
    if (cutoffTime) {
        for (const [pid, proc] of Object.entries(processes)) {
            if (isInTimeRange(proc.last_seen) || isInTimeRange(proc.first_seen)) {
                if (sysmonPids.has(pid)) alertPids.add(pid); // only if they have sysmon activity
            }
        }
    }

    // Second pass: include parents/children of alert processes + sysmon-active processes
    const includePids = new Set([...alertPids, ...sysmonPids]);
    for (const pid of [...alertPids]) {
        const proc = processes[pid];
        if (proc?.parent_pid && processes[proc.parent_pid]) includePids.add(String(proc.parent_pid));
        (proc?.children || []).forEach(c => includePids.add(String(c)));
    }

    // Search filter: narrow down to processes matching query + their parents/children
    const searchQuery = graphState.searchQuery;
    if (searchQuery) {
        const matchedPids = new Set();
        for (const [pid, proc] of Object.entries(processes)) {
            if (!includePids.has(pid)) continue;
            const name = (proc.name || '').toLowerCase();
            const image = (proc.image || '').toLowerCase();
            const cmdline = (proc.command_line || '').toLowerCase();
            const pidStr = String(pid);
            if (name.includes(searchQuery) || image.includes(searchQuery) || cmdline.includes(searchQuery) || pidStr.includes(searchQuery)) {
                matchedPids.add(pid);
            }
        }
        // Include parents and children of matched processes for context
        const expandedPids = new Set(matchedPids);
        for (const pid of matchedPids) {
            const proc = processes[pid];
            if (proc?.parent_pid && processes[proc.parent_pid]) expandedPids.add(String(proc.parent_pid));
            (proc?.children || []).forEach(c => { if (includePids.has(String(c))) expandedPids.add(String(c)); });
        }
        // Replace includePids with search-filtered set
        includePids.clear();
        for (const pid of expandedPids) includePids.add(pid);
    }

    // Detonated-only filter: narrow to processes that have detonation results
    if (showDetonatedOnly) {
        const detonatedPids = new Set();
        for (const [pid, proc] of Object.entries(processes)) {
            if (!includePids.has(pid)) continue;
            if (proc.detonated) detonatedPids.add(pid);
        }
        // Include parents/children of detonated processes for context
        const expandedDet = new Set(detonatedPids);
        for (const pid of detonatedPids) {
            const proc = processes[pid];
            if (proc?.parent_pid && processes[proc.parent_pid]) expandedDet.add(String(proc.parent_pid));
            (proc?.children || []).forEach(c => { if (includePids.has(String(c))) expandedDet.add(String(c)); });
        }
        includePids.clear();
        for (const pid of expandedDet) includePids.add(pid);
    }

    for (const [pid, proc] of Object.entries(processes)) {
        if (!includePids.has(pid)) continue;
        const threats = proc.activity?.threats || 0;
        const maxSev = getNodeMaxSeverity(proc);
        const node = {
            id: `proc_${pid}`,
            type: 'process',
            pid: pid,
            label: proc.name || 'unknown',
            image: proc.image || '',
            cmdline: proc.command_line || '',
            user: proc.user || '',
            threats: threats,
            severity: maxSev,
            children: proc.children || [],
            parentPid: proc.parent_pid,
            activity: proc.activity || {},
            firstSeen: proc.first_seen || '',
            exited: !!proc.exit_time,
            detonated: !!proc.detonated,
            detonationSources: proc.detonation_sources || [],
            x: 0, y: 0, vx: 0, vy: 0,
            radius: Math.max(14, Math.min(30, 14 + threats * 2)),
        };
        nodes.push(node);
        nodeMap[pid] = node;
    }

    // 2. Create parent-child edges
    for (const node of nodes) {
        if (node.parentPid && nodeMap[node.parentPid]) {
            edges.push({
                source: `proc_${node.parentPid}`,
                target: node.id,
                type: 'spawn',
                label: 'spawned',
            });
        }
    }

    // 3. Network connection nodes (from Sysmon event 3)
    if (showNetwork) {
        const netTargets = {};  // deduplicate by ip:port
        networkEvents.forEach(ev => {
            const key = `${ev.dst_ip}:${ev.dst_port}`;
            if (!netTargets[key]) {
                netTargets[key] = { ip: ev.dst_ip, port: ev.dst_port, hostname: ev.dst_hostname || '', pids: new Set(), protocol: ev.protocol || 'tcp' };
            }
            if (ev.pid) netTargets[key].pids.add(String(ev.pid));
        });

        // Also add network info from alerts
        networkAlerts.forEach(a => {
            const raw = a.raw || {};
            const ip = raw.destination?.ip || raw.network?.destination?.ip || '';
            const port = raw.destination?.port || raw.network?.destination?.port || '';
            if (ip) {
                const key = `${ip}:${port}`;
                if (!netTargets[key]) {
                    netTargets[key] = { ip, port, hostname: '', pids: new Set(), protocol: 'tcp' };
                }
                if (a.pid) netTargets[key].pids.add(String(a.pid));
            }
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

    // 4. DNS nodes (from Sysmon event 22)
    if (showDns) {
        const dnsTargets = {};
        dnsEvents.forEach(ev => {
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

    // 5. Injection edges (from Sysmon event 8: CreateRemoteThread)
    injectEvents.forEach(ev => {
        const srcPid = String(ev.source_pid || ev.pid);
        const tgtPid = String(ev.target_pid);
        if (srcPid && tgtPid && nodeMap[srcPid] && nodeMap[tgtPid]) {
            edges.push({ source: `proc_${srcPid}`, target: `proc_${tgtPid}`, type: 'inject', label: 'inject' });
        }
    });

    // 6. File nodes (from alerts with category=file)
    if (showFiles) {
        const fileTargets = {};
        (state.alerts || []).forEach(a => {
            const cat = (Array.isArray(a.category) ? a.category[0] : a.category || '').toLowerCase();
            if (cat !== 'file') return;
            const raw = a.raw || {};
            const path = raw.file?.path || raw['file.path'] || '';
            if (!path || !a.pid) return;
            if (!fileTargets[path]) fileTargets[path] = { path, pids: new Set() };
            fileTargets[path].pids.add(String(a.pid));
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

    // 7. Registry nodes
    if (showRegistry) {
        const regTargets = {};
        (state.alerts || []).forEach(a => {
            const cat = (Array.isArray(a.category) ? a.category[0] : a.category || '').toLowerCase();
            if (cat !== 'registry') return;
            const raw = a.raw || {};
            const path = raw.registry?.path || raw['registry.path'] || '';
            if (!path || !a.pid) return;
            const shortKey = path.split('\\').slice(-2).join('\\') || path;
            if (!regTargets[shortKey]) regTargets[shortKey] = { path, pids: new Set() };
            regTargets[shortKey].pids.add(String(a.pid));
        });
        for (const [key, info] of Object.entries(regTargets)) {
            const nodeId = `reg_${key}`;
            nodes.push({ id: nodeId, type: 'registry', label: key, fullPath: info.path, x: 0, y: 0, vx: 0, vy: 0, radius: 7 });
            info.pids.forEach(pid => {
                if (nodeMap[pid]) edges.push({ source: `proc_${pid}`, target: nodeId, type: 'registry', label: 'modify' });
            });
        }
    }

    // Apply layout
    const layout = document.getElementById('graph-layout')?.value || 'hierarchy';
    if (layout === 'hierarchy') {
        applyHierarchyLayout(nodes, edges, nodeMap);
    } else if (layout === 'radial') {
        applyRadialLayout(nodes, edges, nodeMap);
    } else if (layout === 'circular') {
        applyCircularLayout(nodes, edges);
    } else if (layout === 'grid') {
        applyGridLayout(nodes, edges);
    } else {
        applyForceLayout(nodes, edges);
    }

    graphState.nodes = nodes;
    graphState.edges = edges;

    // Update counter
    const countEl = document.getElementById('graph-node-count');
    if (countEl) {
        let label = `${nodes.length} nodes, ${edges.length} edges`;
        if (graphState.searchQuery) label += ` (filtered: "${graphState.searchQuery}")`;
        countEl.textContent = label;
    }
}

function getNodeMaxSeverity(proc) {
    let max = 'low';
    const order = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };
    (proc.alerts || []).forEach(a => {
        const sev = (a.severity || 'unknown').toLowerCase();
        if ((order[sev] || 0) > (order[max] || 0)) max = sev;
    });
    return max;
}

function applyHierarchyLayout(nodes, edges, nodeMap) {
    // Build tree levels from process parent relationships
    const procNodes = nodes.filter(n => n.type === 'process');
    const otherNodes = nodes.filter(n => n.type !== 'process');

    // Find roots (no parent or parent not in nodeMap)
    const roots = procNodes.filter(n => !n.parentPid || !nodeMap[n.parentPid]);
    const visited = new Set();
    let col = 0;

    function layoutTree(node, depth) {
        if (visited.has(node.id)) return;
        visited.add(node.id);
        node.x = depth * 200;
        node.y = col * 80;
        col++;
        // Find children
        const children = procNodes.filter(n => n.parentPid && `proc_${n.parentPid}` === node.id && !visited.has(n.id));
        children.forEach(child => layoutTree(child, depth + 1));
    }

    roots.forEach(root => layoutTree(root, 0));
    // Any orphans
    procNodes.filter(n => !visited.has(n.id)).forEach(n => { n.x = 0; n.y = col * 80; col++; });

    // Place non-process nodes around their connected process
    otherNodes.forEach(node => {
        const connEdge = edges.find(e => e.target === node.id || e.source === node.id);
        if (connEdge) {
            const parentId = connEdge.source === node.id ? connEdge.target : connEdge.source;
            const parent = nodes.find(n => n.id === parentId);
            if (parent) {
                const angle = Math.random() * Math.PI * 2;
                const dist = 100 + Math.random() * 60;
                node.x = parent.x + Math.cos(angle) * dist;
                node.y = parent.y + Math.sin(angle) * dist;
                return;
            }
        }
        node.x = Math.random() * 600;
        node.y = Math.random() * 400;
    });
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

function applyRadialLayout(nodes, edges, nodeMap) {
    // Radial layout: root processes at center, children on concentric rings
    const procNodes = nodes.filter(n => n.type === 'process');
    const otherNodes = nodes.filter(n => n.type !== 'process');

    // Find roots
    const roots = procNodes.filter(n => !n.parentPid || !nodeMap[n.parentPid]);
    const visited = new Set();
    const levels = []; // levels[depth] = [nodes...]

    function assignLevel(node, depth) {
        if (visited.has(node.id)) return;
        visited.add(node.id);
        if (!levels[depth]) levels[depth] = [];
        levels[depth].push(node);
        const children = procNodes.filter(n => n.parentPid && `proc_${n.parentPid}` === node.id && !visited.has(n.id));
        children.forEach(child => assignLevel(child, depth + 1));
    }
    roots.forEach(root => assignLevel(root, 0));
    // Orphans go to level 0
    procNodes.filter(n => !visited.has(n.id)).forEach(n => { if (!levels[0]) levels[0] = []; levels[0].push(n); });

    // Place nodes on concentric circles
    const ringSpacing = 160;
    levels.forEach((levelNodes, depth) => {
        const radius = depth * ringSpacing;
        if (radius === 0) {
            // Center the roots
            const count = levelNodes.length;
            levelNodes.forEach((n, i) => {
                const angle = (i / count) * Math.PI * 2;
                n.x = Math.cos(angle) * 40 * count;
                n.y = Math.sin(angle) * 40 * count;
            });
        } else {
            const count = levelNodes.length;
            levelNodes.forEach((n, i) => {
                const angle = (i / count) * Math.PI * 2 - Math.PI / 2;
                n.x = Math.cos(angle) * radius;
                n.y = Math.sin(angle) * radius;
            });
        }
    });

    // Place non-process nodes around their connected process
    otherNodes.forEach(node => {
        const connEdge = edges.find(e => e.target === node.id || e.source === node.id);
        if (connEdge) {
            const parentId = connEdge.source === node.id ? connEdge.target : connEdge.source;
            const parent = nodes.find(n => n.id === parentId);
            if (parent) {
                const angle = Math.random() * Math.PI * 2;
                const dist = 60 + Math.random() * 40;
                node.x = parent.x + Math.cos(angle) * dist;
                node.y = parent.y + Math.sin(angle) * dist;
                return;
            }
        }
        node.x = Math.random() * 300;
        node.y = Math.random() * 300;
    });
}

function applyCircularLayout(nodes, edges) {
    // All nodes placed on a single circle, ordered by type then name
    const sorted = [...nodes].sort((a, b) => {
        if (a.type !== b.type) return a.type.localeCompare(b.type);
        return (a.label || '').localeCompare(b.label || '');
    });

    const count = sorted.length;
    const radius = Math.max(150, count * 20);

    sorted.forEach((n, i) => {
        const angle = (i / count) * Math.PI * 2 - Math.PI / 2;
        n.x = Math.cos(angle) * radius;
        n.y = Math.sin(angle) * radius;
    });
}

function applyGridLayout(nodes, edges) {
    // Grid layout: processes in a grid, non-processes attached nearby
    const procNodes = nodes.filter(n => n.type === 'process');
    const otherNodes = nodes.filter(n => n.type !== 'process');

    const cols = Math.max(1, Math.ceil(Math.sqrt(procNodes.length)));
    const spacing = 160;

    procNodes.forEach((n, i) => {
        const row = Math.floor(i / cols);
        const col = i % cols;
        n.x = col * spacing;
        n.y = row * spacing;
    });

    // Attach non-process nodes to their connected process
    otherNodes.forEach(node => {
        const connEdge = edges.find(e => e.target === node.id || e.source === node.id);
        if (connEdge) {
            const parentId = connEdge.source === node.id ? connEdge.target : connEdge.source;
            const parent = nodes.find(n => n.id === parentId);
            if (parent) {
                const angle = Math.random() * Math.PI * 2;
                const dist = 50 + Math.random() * 30;
                node.x = parent.x + Math.cos(angle) * dist;
                node.y = parent.y + Math.sin(angle) * dist;
                return;
            }
        }
        // Orphan: place after the grid
        const idx = otherNodes.indexOf(node);
        node.x = (idx % cols) * spacing;
        node.y = (Math.floor(procNodes.length / cols) + 1 + Math.floor(idx / cols)) * spacing;
    });
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

        const r = node.radius * (isHovered ? 1.2 : 1);

        // Glow for malicious
        if (node.type === 'process' && node.threats > 0) {
            ctx.beginPath();
            ctx.arc(node.x, node.y, r + 4, 0, Math.PI * 2);
            ctx.fillStyle = color + '20';
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
    // Re-render graph when toggles change
    ['graph-show-network', 'graph-show-dns', 'graph-show-files', 'graph-show-registry', 'graph-show-detonated'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.addEventListener('change', () => { if (state.activeTab === 'graph') graphRefresh(); });
    });
    const layoutEl = document.getElementById('graph-layout');
    if (layoutEl) layoutEl.addEventListener('change', () => { if (state.activeTab === 'graph') graphRefresh(); });

    // Time range buttons
    document.querySelectorAll('.graph-time-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.graph-time-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            graphState.timeRangeSeconds = parseInt(btn.dataset.seconds) || 0;
            if (state.activeTab === 'graph') graphRefresh();
        });
    });

    // Search input
    const searchInput = document.getElementById('graph-search');
    const searchClear = document.getElementById('graph-search-clear');
    let searchDebounce = null;
    if (searchInput) {
        searchInput.addEventListener('input', () => {
            const val = searchInput.value.trim();
            if (searchClear) searchClear.classList.toggle('visible', val.length > 0);
            clearTimeout(searchDebounce);
            searchDebounce = setTimeout(() => {
                graphState.searchQuery = val.toLowerCase();
                if (state.activeTab === 'graph') graphRefresh();
            }, 250);
        });
        searchInput.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                searchInput.value = '';
                graphState.searchQuery = '';
                if (searchClear) searchClear.classList.remove('visible');
                if (state.activeTab === 'graph') graphRefresh();
            }
        });
    }
    if (searchClear) {
        searchClear.addEventListener('click', () => {
            if (searchInput) searchInput.value = '';
            graphState.searchQuery = '';
            searchClear.classList.remove('visible');
            if (state.activeTab === 'graph') graphRefresh();
        });
    }
}

// --- Sysmon Events Tab ---
let sysmonEvents = [];
let sysmonStats = null;

async function refreshSysmon() {
    const eventType = document.getElementById('sysmon-filter-type')?.value || '';
    const pidFilter = document.getElementById('sysmon-filter-pid')?.value || '';
    const maxEvents = document.getElementById('sysmon-max-events')?.value || '100';

    let url = `/api/sysmon?max=${maxEvents}`;
    if (eventType) url += `&event_id=${eventType}`;
    if (pidFilter) url += `&pid=${pidFilter}`;

    try {
        const [eventsResp, statsResp] = await Promise.all([
            fetch(url),
            fetch('/api/sysmon/stats'),
        ]);
        if (eventsResp.ok) {
            sysmonEvents = await eventsResp.json();
            renderSysmonTable();
        }
        if (statsResp.ok) {
            sysmonStats = await statsResp.json();
            renderSysmonStats();
        }
    } catch (e) {
        console.error('Sysmon fetch error:', e);
    }
}

function renderSysmonStats() {
    const container = document.getElementById('sysmon-stats');
    if (!container || !sysmonStats || !sysmonStats.stats) return;

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

    let html = `<table class="sysmon-events-table"><thead><tr><th>Time</th><th>Type</th><th>PID</th><th>Image</th><th>Details</th></tr></thead><tbody>`;
    sysmonEvents.forEach(ev => {
        const typeClass = getSysmonTypeClass(String(ev.event_id));
        const time = ev.timestamp ? formatSysmonTime(ev.timestamp) : '';
        const image = ev.image ? ev.image.split('\\').pop() : '';
        const details = getSysmonDetails(ev);
        html += `<tr onclick="showSysmonDetail(${JSON.stringify(ev).replace(/"/g, '&quot;')})">
            <td class="col-time">${time}</td>
            <td><span class="type-badge ${typeClass}">${escapeHtml(ev.type || '')}</span></td>
            <td class="col-pid">${ev.pid || ''}</td>
            <td class="col-image">${escapeHtml(image)}</td>
            <td class="col-details">${escapeHtml(details)}</td>
        </tr>`;
    });
    html += '</tbody></table>';
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

    setDetailHeader('Sysmon', 'background:rgba(34,197,94,0.15);color:var(--accent-green)', ev.type || 'Event', '');
    setDetailBody(html);
    showDetail();
}

// --- Utilities ---
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
    if (e.key === 'Escape' && state.detailOpen) closeDetail();
    if (e.key === 'Backspace' && state.detailOpen && !['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement.tagName)) {
        e.preventDefault();
        goDetailBack();
    }
});
