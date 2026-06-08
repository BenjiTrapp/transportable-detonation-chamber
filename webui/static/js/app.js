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
    detailHistory: [], // For back navigation
    sessionStart: null, // First event timestamp for relative time calc
    serviceStatus: {},  // Cached service status
    rustinelInfo: null, // Cached Rustinel detail
};

// --- Initialization ---
document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    initUpload();
    refreshAll();
    // Poll for updates
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
    // Load Sysmon data on tab switch
    if (tabName === 'sysmon' && sysmonEvents.length === 0) {
        refreshSysmon();
    }
}

// --- Data fetching ---
async function refreshAll() {
    await Promise.all([refreshAlerts(), refreshProcesses(), refreshDashboard()]);
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
        // Update timestamp
        const timeEl = document.getElementById('dashboard-time');
        if (timeEl) timeEl.textContent = 'Updated ' + new Date().toLocaleTimeString('en-GB');
    } catch (e) {
        console.error('Failed to refresh dashboard:', e);
    }
}

async function refreshAlerts() {
    try {
        const severity = document.getElementById('filter-severity')?.value || '';
        const engine = document.getElementById('filter-engine')?.value || '';
        let url = '/api/alerts?';
        if (severity) url += `severity=${severity}&`;
        if (engine) url += `engine=${engine}&`;

        const resp = await fetch(url);
        if (resp.ok) {
            state.alerts = await resp.json();
            // Compute session start time
            if (state.alerts.length) {
                const times = state.alerts.map(a => new Date(a.timestamp).getTime()).filter(t => !isNaN(t));
                state.sessionStart = times.length ? Math.min(...times) : null;
            }
            renderAlerts();
            renderTimeline();
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
    if (!container) return;

    const status = state.serviceStatus;
    const rustinel = state.rustinelInfo || {};

    const cards = [];

    // Rustinel Card
    const rOnline = rustinel.online || status.rustinel?.online || false;
    const rRules = rustinel.rules || {};
    const rIoc = rRules.ioc || {};
    const totalIoc = (rIoc.hashes || 0) + (rIoc.ips || 0) + (rIoc.domains || 0);
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
            <div class="service-card-desc">
                Sigma/YARA/IOC detection engine via ETW.
                ${rustinel.version ? `<br>${escapeHtml(rustinel.version)}` : ''}
            </div>
            <div class="service-card-metrics">
                <div class="service-metric">
                    <div class="service-metric-value ${rRules.sigma === 0 ? 'zero' : ''}">${rRules.sigma || 0}</div>
                    <div class="service-metric-label">SIGMA</div>
                </div>
                <div class="service-metric">
                    <div class="service-metric-value ${rRules.yara === 0 ? 'zero' : ''}">${rRules.yara || 0}</div>
                    <div class="service-metric-label">YARA</div>
                </div>
                <div class="service-metric">
                    <div class="service-metric-value ${rustinel.alerts_count === 0 ? 'zero' : ''}">${rustinel.alerts_count || 0}</div>
                    <div class="service-metric-label">ALERTS</div>
                </div>
            </div>
            <div class="service-card-actions">
                <button class="btn btn-sm" onclick="event.stopPropagation(); openRustinelDetail()">Details</button>
                <button class="btn btn-sm" onclick="event.stopPropagation(); switchTab('tracing')">View Alerts</button>
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
                <div class="service-card-title">
                    <div class="service-icon agent">D</div>
                    <h3>DetonatorAgent</h3>
                </div>
                <span class="service-status-badge ${aOnline ? 'online' : 'offline'}">${aOnline ? 'Online' : 'Offline'}</span>
            </div>
            <div class="service-card-desc">
                .NET execution agent. Detonates samples and collects EDR telemetry on port 8080.
            </div>
            <div class="service-card-metrics">
                <div class="service-metric">
                    <div class="service-metric-value">${aOnline ? '8080' : '--'}</div>
                    <div class="service-metric-label">PORT</div>
                </div>
                <div class="service-metric">
                    <div class="service-metric-value ${aInUse ? '' : 'zero'}">${aInUse ? 'Yes' : 'No'}</div>
                    <div class="service-metric-label">IN USE</div>
                </div>
                <div class="service-metric">
                    <div class="service-metric-value">${aOnline ? 'Fibratus' : '--'}</div>
                    <div class="service-metric-label">EDR</div>
                </div>
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
                <div class="service-card-title">
                    <div class="service-icon litterbox">L</div>
                    <h3>LitterBox</h3>
                </div>
                <span class="service-status-badge ${lOnline ? 'online' : 'offline'}">${lOnline ? 'Online' : 'Offline'}</span>
            </div>
            <div class="service-card-desc">
                Self-hosted payload analysis sandbox. Static analysis, memory scanning, YARA, detection scoring.
            </div>
            <div class="service-card-metrics">
                <div class="service-metric">
                    <div class="service-metric-value">${lOnline ? '1337' : '--'}</div>
                    <div class="service-metric-label">PORT</div>
                </div>
                <div class="service-metric">
                    <div class="service-metric-value">PE-Sieve</div>
                    <div class="service-metric-label">SCANNER</div>
                </div>
                <div class="service-metric">
                    <div class="service-metric-value">MCP</div>
                    <div class="service-metric-label">LLM API</div>
                </div>
            </div>
            <div class="service-card-actions">
                <button class="btn btn-sm" onclick="event.stopPropagation(); openLitterboxDetail()">Details</button>
                <button class="btn btn-sm" onclick="event.stopPropagation(); window.open('http://localhost:1337', '_blank')">Open UI</button>
            </div>
        </div>
    `);

    // Fibratus Card
    const fOnline = status.rustinel?.online || false; // Inferred from Rustinel
    cards.push(`
        <div class="service-card fibratus-card ${fOnline ? '' : 'offline'}" onclick="openFibratusDetail()">
            <div class="service-card-glow"></div>
            <div class="service-card-header">
                <div class="service-card-title">
                    <div class="service-icon fibratus">F</div>
                    <h3>Fibratus</h3>
                </div>
                <span class="service-status-badge ${fOnline ? 'online' : 'offline'}">${fOnline ? 'Inferred' : 'Offline'}</span>
            </div>
            <div class="service-card-desc">
                Windows kernel-level activity tracing. Captures process, network, file, registry, and driver events.
            </div>
            <div class="service-card-metrics">
                <div class="service-metric">
                    <div class="service-metric-value">${(rustinel.etw_providers || []).length || '--'}</div>
                    <div class="service-metric-label">PROVIDERS</div>
                </div>
                <div class="service-metric">
                    <div class="service-metric-value">ETW</div>
                    <div class="service-metric-label">SOURCE</div>
                </div>
                <div class="service-metric">
                    <div class="service-metric-value">Kernel</div>
                    <div class="service-metric-label">LEVEL</div>
                </div>
            </div>
            <div class="service-card-actions">
                <button class="btn btn-sm" onclick="event.stopPropagation(); openFibratusDetail()">Details</button>
                <button class="btn btn-sm" onclick="event.stopPropagation(); switchTab('tracing')">View Traces</button>
            </div>
        </div>
    `);

    // Sysmon Card
    const sOnline = status.sysmon?.online || false;
    cards.push(`
        <div class="service-card sysmon-card ${sOnline ? '' : 'offline'}" onclick="switchTab('sysmon'); refreshSysmon();">
            <div class="service-card-glow"></div>
            <div class="service-card-header">
                <div class="service-card-title">
                    <div class="service-icon sysmon">S</div>
                    <h3>Sysmon</h3>
                </div>
                <span class="service-status-badge ${sOnline ? 'online' : 'offline'}">${sOnline ? 'Online' : 'Offline'}</span>
            </div>
            <div class="service-card-desc">
                System Monitor v15.14. Logs process creation, network, file, registry, DNS events to Windows Event Log.
            </div>
            <div class="service-card-metrics">
                <div class="service-metric">
                    <div class="service-metric-value">${sOnline ? 'Sysmon64' : '--'}</div>
                    <div class="service-metric-label">SERVICE</div>
                </div>
                <div class="service-metric">
                    <div class="service-metric-value">ETW</div>
                    <div class="service-metric-label">SOURCE</div>
                </div>
                <div class="service-metric">
                    <div class="service-metric-value">SwiftOnSec</div>
                    <div class="service-metric-label">CONFIG</div>
                </div>
            </div>
            <div class="service-card-actions">
                <button class="btn btn-sm" onclick="event.stopPropagation(); switchTab('sysmon'); refreshSysmon();">View Events</button>
            </div>
        </div>
    `);

    container.innerHTML = cards.join('');
}

// --- Detail Panels for Dashboard Services ---
async function openAgentDetail() {
    pushDetailHistory('agent', 0);
    setDetailHeader('Service', 'background:rgba(249,115,22,0.15);color:var(--accent-orange)', 'DetonatorAgent', '');
    setDetailBody('<div class="muted">Loading...</div>');
    showDetail();

    let html = '';
    const online = state.serviceStatus.detonator_agent?.online;

    html += `<div class="detail-fields">
        <div class="detail-field"><span class="field-label">Status</span><span class="field-value" style="color:${online ? 'var(--accent-green)' : 'var(--accent-red)'}">${online ? 'Running' : 'Stopped'}</span></div>
        <div class="detail-field"><span class="field-label">Port</span><span class="field-value">8080</span></div>
        <div class="detail-field"><span class="field-label">Framework</span><span class="field-value">.NET 8.0</span></div>
        <div class="detail-field"><span class="field-label">Install Dir</span><span class="field-value mono">C:\\DetonatorAgent</span></div>
        <div class="detail-field"><span class="field-label">EDR Plugin</span><span class="field-value">Fibratus</span></div>
        <div class="detail-field"><span class="field-label">In Use</span><span class="field-value">${state.serviceStatus.detonator_agent?.data?.in_use ? 'Yes' : 'No'}</span></div>
    </div>`;

    html += `<div class="detail-section">
        <div class="detail-section-title">CAPABILITIES</div>
        <div class="detail-fields">
            <div class="detail-field"><span class="field-label">Execute</span><span class="field-value">PE, DLL, PowerShell, Batch, VBS</span></div>
            <div class="detail-field"><span class="field-label">Collection</span><span class="field-value">EDR logs, process trees, network activity</span></div>
            <div class="detail-field"><span class="field-label">API</span><span class="field-value mono">/api/execute/exec, /api/lock/status, /api/logs</span></div>
        </div>
    </div>`;

    html += `<div class="detail-section">
        <div class="detail-section-title">QUICK ACTIONS</div>
        <div style="display:flex; gap:8px;">
            <button class="btn" onclick="switchTab('submit'); closeDetail();">Submit Sample</button>
            <button class="btn" onclick="window.open('http://localhost:8080', '_blank')">Open API</button>
        </div>
    </div>`;

    setDetailBody(html);
}

async function openLitterboxDetail() {
    pushDetailHistory('litterbox', 0);
    setDetailHeader('Service', 'background:rgba(167,139,250,0.15);color:var(--accent-purple)', 'LitterBox', '');
    setDetailBody('<div class="muted">Loading...</div>');
    showDetail();

    const online = state.serviceStatus.litterbox?.online;
    let html = '';

    html += `<div class="detail-fields">
        <div class="detail-field"><span class="field-label">Status</span><span class="field-value" style="color:${online ? 'var(--accent-green)' : 'var(--accent-red)'}">${online ? 'Running' : 'Stopped'}</span></div>
        <div class="detail-field"><span class="field-label">Port</span><span class="field-value">1337</span></div>
        <div class="detail-field"><span class="field-label">Install Dir</span><span class="field-value mono">C:\\LitterBox</span></div>
        <div class="detail-field"><span class="field-label">Web UI</span><span class="field-value mono">http://localhost:1337</span></div>
    </div>`;

    html += `<div class="detail-section">
        <div class="detail-section-title">SCANNERS</div>
        <div class="activity-grid" style="grid-template-columns: repeat(3, 1fr);">
            <div class="activity-counter"><div class="counter-label">PE-SIEVE</div><div class="counter-value" style="font-size:12px">Static</div></div>
            <div class="activity-counter"><div class="counter-label">HOLLOWS</div><div class="counter-value" style="font-size:12px">Memory</div></div>
            <div class="activity-counter"><div class="counter-label">MONETA</div><div class="counter-value" style="font-size:12px">Memory</div></div>
            <div class="activity-counter"><div class="counter-label">PATRIOT</div><div class="counter-value" style="font-size:12px">Dynamic</div></div>
            <div class="activity-counter"><div class="counter-label">YARA</div><div class="counter-value" style="font-size:12px">Rules</div></div>
            <div class="activity-counter"><div class="counter-label">HUNT-SB</div><div class="counter-value" style="font-size:12px">Beacons</div></div>
        </div>
    </div>`;

    html += `<div class="detail-section">
        <div class="detail-section-title">FEATURES</div>
        <div class="detail-fields">
            <div class="detail-field"><span class="field-label">Analysis</span><span class="field-value">Static + Dynamic + Memory</span></div>
            <div class="detail-field"><span class="field-label">Scoring</span><span class="field-value">Detection scoring with trigger breakdown</span></div>
            <div class="detail-field"><span class="field-label">MCP Server</span><span class="field-value">LLM-driven analysis via MCP protocol</span></div>
            <div class="detail-field"><span class="field-label">EDR Integration</span><span class="field-value">Fibratus, Elastic Defend</span></div>
        </div>
    </div>`;

    html += `<div class="detail-section">
        <div class="detail-section-title">QUICK ACTIONS</div>
        <div style="display:flex; gap:8px;">
            <button class="btn" onclick="switchTab('submit'); closeDetail();">Submit Sample</button>
            <button class="btn" onclick="window.open('http://localhost:1337', '_blank')">Open LitterBox UI</button>
        </div>
    </div>`;

    setDetailBody(html);
}

async function openFibratusDetail() {
    pushDetailHistory('fibratus', 0);
    setDetailHeader('Service', 'background:rgba(244,114,182,0.15);color:var(--accent-pink)', 'Fibratus', '');
    showDetail();

    const rustinel = state.rustinelInfo || {};
    const providers = rustinel.etw_providers || [];
    let html = '';

    html += `<div class="detail-fields">
        <div class="detail-field"><span class="field-label">Status</span><span class="field-value" style="color:var(--accent-green)">Active (via Rustinel ETW)</span></div>
        <div class="detail-field"><span class="field-label">Type</span><span class="field-value">Kernel-level Windows tracing</span></div>
        <div class="detail-field"><span class="field-label">Providers</span><span class="field-value">${providers.length} ETW providers</span></div>
    </div>`;

    if (providers.length > 0) {
        html += `<div class="detail-section">
            <div class="detail-section-title">ETW PROVIDERS (${providers.length})</div>
            <div class="detail-fields">`;
        providers.forEach(p => {
            const shortName = p.name.replace('Microsoft-Windows-', '');
            html += `<div class="detail-field">
                <span class="field-label">${escapeHtml(shortName)}</span>
                <span class="field-value" style="color:var(--text-muted)">keywords: ${escapeHtml(p.keywords)}</span>
            </div>`;
        });
        html += `</div></div>`;
    }

    html += `<div class="detail-section">
        <div class="detail-section-title">EVENT CATEGORIES</div>
        <div class="activity-grid" style="grid-template-columns: repeat(3, 1fr);">
            <div class="activity-counter"><div class="counter-label">PROCESS</div><div class="counter-value" style="font-size:12px">Create/Exit</div></div>
            <div class="activity-counter"><div class="counter-label">NETWORK</div><div class="counter-value" style="font-size:12px">TCP/UDP</div></div>
            <div class="activity-counter"><div class="counter-label">FILE</div><div class="counter-value" style="font-size:12px">I/O Ops</div></div>
            <div class="activity-counter"><div class="counter-label">REGISTRY</div><div class="counter-value" style="font-size:12px">Keys/Values</div></div>
            <div class="activity-counter"><div class="counter-label">DNS</div><div class="counter-value" style="font-size:12px">Queries</div></div>
            <div class="activity-counter"><div class="counter-label">POWERSHELL</div><div class="counter-value" style="font-size:12px">Scripts</div></div>
        </div>
    </div>`;

    setDetailBody(html);
}

// --- Render: Alerts table ---
function renderAlerts() {
    const container = document.getElementById('alerts-table');
    if (!state.alerts.length) {
        container.innerHTML = `
            <div class="empty-state">
                <h3>No alerts detected</h3>
                <p>Submit a sample to start tracing, or check that Rustinel/Fibratus are running.</p>
            </div>`;
        return;
    }

    // Sort by timestamp descending
    const sorted = [...state.alerts].sort((a, b) =>
        (b.timestamp || '').localeCompare(a.timestamp || ''));

    container.innerHTML = sorted.map((alert, idx) => `
        <div class="event-row" onclick="openAlertDetail(${state.alerts.indexOf(alert)})">
            <span class="event-severity ${(alert.severity || 'unknown').toLowerCase()}">${alert.severity || '?'}</span>
            <span class="event-engine">${alert.engine || 'unknown'}</span>
            <span class="event-rule">${escapeHtml(alert.rule_name || 'Unknown')}</span>
            <span class="event-process">${escapeHtml(alert.process_name || '')} (${alert.pid || '?'})</span>
            <span class="event-time">${formatRelativeTime(alert.timestamp)}</span>
        </div>
    `).join('');
}

// --- Render: Process list ---
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
        return `
            <div class="process-item ${isActive ? 'active' : ''}" onclick="openProcessDetail(${proc.pid})">
                <div class="proc-icon ${hasThreats ? 'threat' : ''}"></div>
                <span class="proc-name">${escapeHtml(proc.name || 'unknown')}</span>
                <span class="proc-pid">${proc.pid}</span>
            </div>`;
    }).join('');
}

// --- Render: Timeline ---
function renderTimeline() {
    const container = document.getElementById('timeline');
    if (!state.alerts.length) {
        container.innerHTML = '';
        return;
    }

    // Create bars representing alerts over time
    const maxBars = 60;
    const alerts = state.alerts.slice(0, maxBars);
    container.innerHTML = alerts.map(alert => {
        const sev = (alert.severity || 'low').toLowerCase();
        const width = 30 + Math.random() * 70; // Visual variety
        return `<div class="timeline-bar severity-${sev}" style="width:${width}%" title="${escapeHtml(alert.rule_name || '')}"></div>`;
    }).join('');
}

// --- Render: Service status ---
function updateServiceStatus(status) {
    setStatus('status-rustinel', status.rustinel?.online);
    setStatus('status-sysmon', status.sysmon?.online);
    setStatus('status-agent', status.detonator_agent?.online);
    setStatus('status-litterbox', status.litterbox?.online);
    // Fibratus doesn't have direct API - assume online if rustinel is
    setStatus('status-fibratus', status.rustinel?.online);
}

function setStatus(elementId, online) {
    const el = document.getElementById(elementId);
    if (el) {
        el.classList.toggle('online', !!online);
        el.classList.toggle('offline', !online);
    }
}

// --- Detail Panel: Alert ---
function openAlertDetail(idx) {
    const alert = state.alerts[idx];
    if (!alert) return;

    // Push to history for back navigation
    pushDetailHistory('alert', idx);

    const severity = (alert.severity || 'unknown').toLowerCase();
    const severityColors = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' };

    setDetailHeader(
        severity.charAt(0).toUpperCase() + severity.slice(1),
        `background:${severityColors[severity] || '#64748b'}20;color:${severityColors[severity] || '#94a3b8'}`,
        alert.rule_name || 'Unknown Rule',
        ''
    );

    // Build description with highlighted keywords
    let desc = escapeHtml(alert.rule_description || 'No description available.');
    // Highlight command patterns in backticks
    desc = desc.replace(/`([^`]+)`/g, '<code>$1</code>');

    // Extract ATT&CK tags
    const tags = (alert.tags || []).map(tag => {
        if (tag.startsWith('attack.t')) return `<span class="tag technique">${tag.replace('attack.', '').toUpperCase()}</span>`;
        if (tag.startsWith('attack.')) return `<span class="tag tactic">${tag.replace('attack.', '').toUpperCase()}</span>`;
        return `<span class="tag mitre">${escapeHtml(tag)}</span>`;
    }).join('');

    let html = '';

    // Description
    if (alert.rule_description) {
        html += `<div class="alert-description">${desc}</div>`;
    }

    // Metadata fields
    html += `<div class="detail-fields">
        <div class="detail-field"><span class="field-label">Engine</span><span class="field-value">${alert.engine || 'unknown'}</span></div>
        <div class="detail-field"><span class="field-label">PID</span><span class="field-value">${alert.pid || 'N/A'}</span></div>
        <div class="detail-field"><span class="field-label">Category</span><span class="field-value">${formatCategory(alert.category)}</span></div>
        ${tags ? `<div class="detail-field"><span class="field-label">ATT&CK</span><span class="field-value">${tags}</span></div>` : ''}
    </div>`;

    // Related process card
    if (alert.pid) {
        html += `
        <div class="detail-section">
            <div class="detail-section-title">RELATED</div>
            <div class="related-card">
                <div class="related-card-header">
                    <span class="related-card-title">Process</span>
                    <button class="btn btn-sm" onclick="openProcessDetail(${alert.pid})">Open process &gt;</button>
                </div>
                <div class="detail-field"><span class="field-label">PID</span><span class="field-value">${alert.pid}</span></div>
                <div class="detail-field"><span class="field-label">Image</span><span class="field-value">${escapeHtml(alert.process_name || '')}</span></div>
                <div class="detail-field"><span class="field-label">Command</span><span class="field-value mono">${escapeHtml(alert.command_line || '')}</span></div>
            </div>
        </div>`;
    }

    // Raw event JSON
    html += `
    <div class="detail-section">
        <div class="detail-section-title">RAW EVENT / MATCH</div>
        <div class="raw-json">${escapeHtml(JSON.stringify(alert.raw || alert, null, 2))}</div>
    </div>`;

    setDetailBody(html);
    showDetail();
}

// --- Detail Panel: DNS Event ---
function openDnsDetail(alert) {
    if (!alert) return;
    pushDetailHistory('dns', state.alerts.indexOf(alert));

    const raw = alert.raw || {};
    const dns = raw.dns || {};
    const question = dns.question || {};
    const answers = dns.answers || [];
    const proc = raw.process || {};

    setDetailHeader(
        '\u2014',
        'background:rgba(34,211,238,0.15);color:var(--accent-cyan)',
        question.name || 'DNS Query',
        formatRelativeTime(alert.timestamp)
    );

    let html = '';

    // Basic info
    html += `<div class="detail-fields">
        <div class="detail-field"><span class="field-label">PID</span><span class="field-value">${alert.pid || 'N/A'}</span></div>
        <div class="detail-field"><span class="field-label">Process</span><span class="field-value">${escapeHtml(alert.process_name || '')}</span></div>
        <div class="detail-field"><span class="field-label">Status</span><span class="field-value">0</span></div>
    </div>`;

    // Answers
    if (answers.length > 0) {
        html += `<div class="detail-section">
            <div class="detail-section-title">ANSWERS</div>
            <div class="detail-fields">`;
        answers.forEach((ans, i) => {
            html += `<div class="detail-field"><span class="field-label">#${i + 1}</span><span class="field-value mono">${escapeHtml(ans.data || ans.ip || JSON.stringify(ans))}</span></div>`;
        });
        html += `</div></div>`;
    }

    // Related process card
    html += `
    <div class="detail-section">
        <div class="detail-section-title">RELATED</div>
        <div class="related-card">
            <div class="related-card-header">
                <span class="related-card-title">Process</span>
                <button class="btn btn-sm" onclick="openProcessDetail(${alert.pid})">Open process &gt;</button>
            </div>
            <div class="detail-field"><span class="field-label">PID</span><span class="field-value">${alert.pid || 'N/A'}</span></div>
            <div class="detail-field"><span class="field-label">Image</span><span class="field-value">${escapeHtml(proc.name || alert.process_name || '')}</span></div>
            <div class="detail-field"><span class="field-label">Command</span><span class="field-value mono">${escapeHtml(proc.command_line || alert.command_line || '')}</span></div>
        </div>
    </div>`;

    // Connections info
    html += `
    <div class="detail-section">
        <div class="detail-section-title">Connections</div>
        <p class="muted">None of the resolved IPs were dialled in this session.</p>
    </div>`;

    setDetailBody(html);
    showDetail();
}

// --- Detail Panel: File/Sample Event ---
function openFileDetail(alert) {
    if (!alert) return;
    pushDetailHistory('file', state.alerts.indexOf(alert));

    const raw = alert.raw || {};
    const fileData = raw.file || {};
    const hash = fileData.hash || {};
    const proc = raw.process || {};
    const fileName = fileData.path ? fileData.path.split('\\').pop() : alert.process_name || 'unknown';
    const fileSize = fileData.size || 0;

    setDetailHeader(
        'sample',
        'background:rgba(167,139,250,0.15);color:var(--accent-purple)',
        fileName,
        formatRelativeTime(alert.timestamp)
    );

    let html = '';

    // File metadata
    html += `<div class="detail-fields">
        <div class="detail-field"><span class="field-label">Path</span><span class="field-value mono">${escapeHtml(fileData.path || '')}</span></div>
        <div class="detail-field"><span class="field-label">PID</span><span class="field-value">${alert.pid || 'N/A'}</span></div>
        <div class="detail-field"><span class="field-label">Size</span><span class="field-value">${formatSize(fileSize)}</span></div>
        <div class="detail-field"><span class="field-label">Type</span><span class="field-value">${detectFileType(fileData.path || '')}</span></div>
        ${hash.sha256 ? `<div class="detail-field"><span class="field-label">SHA-256</span><span class="field-value mono hash-value">${escapeHtml(hash.sha256)}</span></div>` : ''}
        ${hash.md5 ? `<div class="detail-field"><span class="field-label">MD5</span><span class="field-value mono hash-value">${escapeHtml(hash.md5)}</span></div>` : ''}
    </div>`;

    // Download link
    if (fileData.path) {
        html += `<div class="detail-section" style="margin-top:12px;">
            <a href="/api/file/download?path=${encodeURIComponent(fileData.path)}" class="btn btn-sm file-download-btn" download>
                Download file
            </a>
        </div>`;
    }

    // Related process card
    html += `
    <div class="detail-section">
        <div class="detail-section-title">RELATED</div>
        <div class="related-card">
            <div class="related-card-header">
                <span class="related-card-title">Process</span>
                <button class="btn btn-sm" onclick="openProcessDetail(${alert.pid})">Open process &gt;</button>
            </div>
            <div class="detail-field"><span class="field-label">PID</span><span class="field-value">${alert.pid || 'N/A'}</span></div>
            <div class="detail-field"><span class="field-label">Image</span><span class="field-value">${escapeHtml(proc.name || alert.process_name || '')}</span></div>
            <div class="detail-field"><span class="field-label">Command</span><span class="field-value mono">${escapeHtml(proc.command_line || alert.command_line || '')}</span></div>
        </div>
    </div>`;

    // IOC alert section
    html += `
    <div class="detail-section">
        <div class="related-card ioc-card">
            <span class="related-card-title">IOC alert</span>
            <p class="muted" style="margin-top:8px">No IOC rule matched this artifact.</p>
        </div>
    </div>`;

    // File events section
    html += `
    <div class="detail-section">
        <div class="detail-section-title" style="display:flex;align-items:center;justify-content:space-between;">
            <span>File events</span>
            <button class="btn btn-sm" onclick="showInFiles('${escapeHtml(fileName)}')">Show in Files &gt;</button>
        </div>
        <div class="detail-fields">
            <div class="detail-field"><span class="field-label">Path</span><span class="field-value mono">${escapeHtml(fileName)}</span></div>
        </div>
    </div>`;

    // Hex preview (loads real file bytes via API)
    const hexId = `hex-preview-${Date.now()}`;
    html += `
    <div class="detail-section">
        <div class="detail-section-title" style="display:flex;align-items:center;justify-content:space-between;">
            <span>PREVIEW</span>
            <span class="muted" style="font-style:normal;font-size:10px" id="${hexId}-meta">loading...</span>
        </div>
        <div class="hex-preview" id="${hexId}">Loading hex preview...</div>
    </div>`;

    setDetailBody(html);
    showDetail();

    // Fetch real hex data asynchronously
    if (fileData.path) {
        fetchHexPreview(fileData.path, hexId);
    } else {
        document.getElementById(hexId).textContent = generateHexPreviewPlaceholder();
        const metaEl = document.getElementById(`${hexId}-meta`);
        if (metaEl) metaEl.textContent = 'placeholder (no file path)';
    }
}

// --- Detail Panel: Registry Event ---
function openRegistryDetail(alert) {
    if (!alert) return;
    pushDetailHistory('registry', state.alerts.indexOf(alert));

    const raw = alert.raw || {};
    const proc = raw.process || {};
    const event = raw.event || {};

    // Determine action from event action field
    const action = event.action || 'registry_set';
    const actionShort = action.replace('registry_', '');

    // Extract registry-specific fields from raw data
    const registry = raw.registry || {};
    const commandLine = proc.command_line || alert.command_line || '';

    // Try to extract TargetObject from command line for reg.exe
    let targetObject = registry.path || registry.key || '';
    let details = registry.value || registry.data || '';

    // Parse reg.exe command line for target/details
    if (proc.name === 'reg.exe' && commandLine) {
        const hkuMatch = commandLine.match(/(HK[A-Z_]+\\[^\s]+)/i);
        if (hkuMatch) targetObject = hkuMatch[1];
        const valueMatch = commandLine.match(/\/v\s+(\S+)/i);
        const dataMatch = commandLine.match(/\/d\s+(.+?)(?:\s+\/|$)/i);
        if (valueMatch && targetObject) targetObject += '\\' + valueMatch[1];
        if (dataMatch) details = dataMatch[1];
    }

    setDetailHeader(
        `<span class="category-badge registry">Registry</span>`,
        '',
        actionShort,
        `${formatRelativeTime(alert.timestamp)}  ${alert.timestamp || ''}`
    );

    // Use raw HTML for header since we need styled badge
    const headerLeft = document.querySelector('.detail-header-left');
    if (headerLeft) {
        headerLeft.innerHTML = `
            <button class="btn btn-sm" onclick="goDetailBack()">&lt; Back</button>
            <span class="category-badge registry">Registry</span>
            <span class="detail-title">${escapeHtml(actionShort)}</span>`;
    }

    let html = '';

    // Process info
    html += `<div class="detail-fields">
        <div class="detail-field"><span class="field-label">PID</span><span class="field-value">${alert.pid || 'N/A'}</span></div>
        <div class="detail-field"><span class="field-label">Process</span><span class="field-value mono">${escapeHtml(proc.executable || alert.process_image || '')}</span></div>
    </div>`;

    // Fields section
    html += `<div class="detail-section">
        <div class="detail-section-title">FIELDS</div>
        <div class="detail-fields">
            ${targetObject ? `<div class="detail-field"><span class="field-label">TargetObject</span><span class="field-value mono">${escapeHtml(targetObject)}</span></div>` : ''}
            ${details ? `<div class="detail-field"><span class="field-label">Details</span><span class="field-value">${escapeHtml(details)}</span></div>` : ''}
            <div class="detail-field"><span class="field-label">ProcessId</span><span class="field-value">${alert.pid || 'N/A'}</span></div>
            <div class="detail-field"><span class="field-label">Image</span><span class="field-value mono">${escapeHtml(proc.executable || alert.process_image || '')}</span></div>
            <div class="detail-field"><span class="field-label">EventType</span><span class="field-value">${escapeHtml(capitalizeAction(actionShort))}</span></div>
            <div class="detail-field"><span class="field-label">User</span><span class="field-value">${escapeHtml(alert.user || '')}</span></div>
        </div>
    </div>`;

    setDetailBody(html);
    showDetail();
}

// --- Detail Panel: Injection Event ---
function openInjectionDetail(alert) {
    if (!alert) return;
    pushDetailHistory('injection', state.alerts.indexOf(alert));

    const raw = alert.raw || {};
    const proc = raw.process || {};

    setDetailHeader(
        'Critical',
        'background:rgba(239,68,68,0.2);color:#ef4444',
        alert.rule_name || 'Injection Detected',
        formatRelativeTime(alert.timestamp)
    );

    let html = '';

    // Description
    html += `<div class="alert-description">${escapeHtml(alert.rule_description || '')}</div>`;

    // Process info
    html += `<div class="detail-fields">
        <div class="detail-field"><span class="field-label">PID</span><span class="field-value">${alert.pid || 'N/A'}</span></div>
        <div class="detail-field"><span class="field-label">Process</span><span class="field-value mono">${escapeHtml(proc.executable || alert.process_image || '')}</span></div>
        <div class="detail-field"><span class="field-label">Technique</span><span class="field-value">WriteProcessMemory + CreateRemoteThread</span></div>
        <div class="detail-field"><span class="field-label">Category</span><span class="field-value">${formatCategory(alert.category)}</span></div>
    </div>`;

    // ATT&CK tags
    const tags = (alert.tags || []).map(tag => {
        if (tag.startsWith('attack.t')) return `<span class="tag technique">${tag.replace('attack.', '').toUpperCase()}</span>`;
        if (tag.startsWith('attack.')) return `<span class="tag tactic">${tag.replace('attack.', '').toUpperCase()}</span>`;
        return `<span class="tag mitre">${escapeHtml(tag)}</span>`;
    }).join('');
    if (tags) {
        html += `<div class="detail-field" style="margin-bottom:16px"><span class="field-label">ATT&CK</span><span class="field-value">${tags}</span></div>`;
    }

    // Related process card
    html += `
    <div class="detail-section">
        <div class="detail-section-title">RELATED</div>
        <div class="related-card">
            <div class="related-card-header">
                <span class="related-card-title">Process</span>
                <button class="btn btn-sm" onclick="openProcessDetail(${alert.pid})">Open process &gt;</button>
            </div>
            <div class="detail-field"><span class="field-label">PID</span><span class="field-value">${alert.pid || 'N/A'}</span></div>
            <div class="detail-field"><span class="field-label">Image</span><span class="field-value">${escapeHtml(proc.name || alert.process_name || '')}</span></div>
            <div class="detail-field"><span class="field-label">Command</span><span class="field-value mono">${escapeHtml(proc.command_line || alert.command_line || '')}</span></div>
        </div>
    </div>`;

    // Raw JSON
    html += `
    <div class="detail-section">
        <div class="detail-section-title">RAW EVENT / MATCH</div>
        <div class="raw-json">${escapeHtml(JSON.stringify(alert.raw || alert, null, 2))}</div>
    </div>`;

    setDetailBody(html);
    showDetail();
}

// --- Smart Alert Router (routes to specialized panels) ---
function openAlertDetail(idx) {
    const alert = state.alerts[idx];
    if (!alert) return;

    const raw = alert.raw || {};
    const event = raw.event || {};
    const action = (event.action || '').toLowerCase();
    const category = Array.isArray(alert.category) ? alert.category[0] : (alert.category || '');
    const catLower = category.toLowerCase();

    // Route to specialized panels based on event type
    if (catLower === 'network' && (action === 'dns_query' || raw.dns)) {
        openDnsDetail(alert);
        return;
    }
    if (catLower === 'file' && (action === 'file_create' || action === 'file_write' || raw.file)) {
        openFileDetail(alert);
        return;
    }
    if (catLower === 'registry' || action.startsWith('registry_')) {
        openRegistryDetail(alert);
        return;
    }
    if (action === 'injection_detected' || action.includes('inject')) {
        openInjectionDetail(alert);
        return;
    }

    // Default: generic alert detail
    openGenericAlertDetail(idx);
}

function openGenericAlertDetail(idx) {
    const alert = state.alerts[idx];
    if (!alert) return;

    pushDetailHistory('alert', idx);

    const severity = (alert.severity || 'unknown').toLowerCase();
    const severityColors = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' };

    setDetailHeader(
        severity.charAt(0).toUpperCase() + severity.slice(1),
        `background:${severityColors[severity] || '#64748b'}20;color:${severityColors[severity] || '#94a3b8'}`,
        alert.rule_name || 'Unknown Rule',
        ''
    );

    // Build description with highlighted keywords
    let desc = escapeHtml(alert.rule_description || 'No description available.');
    desc = desc.replace(/`([^`]+)`/g, '<code>$1</code>');

    // Extract ATT&CK tags
    const tags = (alert.tags || []).map(tag => {
        if (tag.startsWith('attack.t')) return `<span class="tag technique">${tag.replace('attack.', '').toUpperCase()}</span>`;
        if (tag.startsWith('attack.')) return `<span class="tag tactic">${tag.replace('attack.', '').toUpperCase()}</span>`;
        return `<span class="tag mitre">${escapeHtml(tag)}</span>`;
    }).join('');

    let html = '';

    // Description
    if (alert.rule_description) {
        html += `<div class="alert-description">${desc}</div>`;
    }

    // Metadata fields
    html += `<div class="detail-fields">
        <div class="detail-field"><span class="field-label">Engine</span><span class="field-value">${alert.engine || 'unknown'}</span></div>
        <div class="detail-field"><span class="field-label">PID</span><span class="field-value">${alert.pid || 'N/A'}</span></div>
        <div class="detail-field"><span class="field-label">Category</span><span class="field-value">${formatCategory(alert.category)}</span></div>
        ${tags ? `<div class="detail-field"><span class="field-label">ATT&CK</span><span class="field-value">${tags}</span></div>` : ''}
    </div>`;

    // Related process card
    if (alert.pid) {
        html += `
        <div class="detail-section">
            <div class="detail-section-title">RELATED</div>
            <div class="related-card">
                <div class="related-card-header">
                    <span class="related-card-title">Process</span>
                    <button class="btn btn-sm" onclick="openProcessDetail(${alert.pid})">Open process &gt;</button>
                </div>
                <div class="detail-field"><span class="field-label">PID</span><span class="field-value">${alert.pid}</span></div>
                <div class="detail-field"><span class="field-label">Image</span><span class="field-value">${escapeHtml(alert.process_name || '')}</span></div>
                <div class="detail-field"><span class="field-label">Command</span><span class="field-value mono">${escapeHtml(alert.command_line || '')}</span></div>
            </div>
        </div>`;
    }

    // Raw event JSON
    html += `
    <div class="detail-section">
        <div class="detail-section-title">RAW EVENT / MATCH</div>
        <div class="raw-json">${escapeHtml(JSON.stringify(alert.raw || alert, null, 2))}</div>
    </div>`;

    setDetailBody(html);
    showDetail();
}

// --- Detail Panel: Process ---
function openProcessDetail(pid) {
    state.selectedProcess = pid;
    renderProcessList(); // Update active state
    pushDetailHistory('process', pid);

    const proc = state.processes[pid] || state.processes[String(pid)];
    if (!proc) {
        fetch(`/api/processes/${pid}`)
            .then(r => r.json())
            .then(data => {
                if (!data.error) renderProcessDetailPanel(data);
                else showMinimalProcessDetail(pid);
            })
            .catch(() => showMinimalProcessDetail(pid));
        return;
    }
    renderProcessDetailPanel(proc);
}

function renderProcessDetailPanel(proc) {
    // Determine status from exit_time
    const hasExited = !!proc.exit_time;
    const statusText = hasExited ? 'exited' : 'running';
    const lifespan = hasExited ? computeLifespan(proc.first_seen, proc.exit_time) : '';
    const exitMeta = hasExited
        ? `exited ${formatRelativeTime(proc.exit_time)}  \u00B7  lifespan ${lifespan}`
        : `running  \u00B7  started ${formatRelativeTime(proc.first_seen)}`;

    setDetailHeader(
        `PID ${proc.pid}`,
        'background:rgba(59,130,246,0.2);color:#3b82f6',
        proc.name || 'unknown',
        exitMeta
    );

    // Update header with back button, status, and exit info
    const headerLeft = document.querySelector('.detail-header-left');
    if (headerLeft) {
        headerLeft.innerHTML = `
            <button class="btn btn-sm" onclick="goDetailBack()">&lt; Back</button>
            <span class="detail-badge" style="background:rgba(59,130,246,0.2);color:#3b82f6">PID ${proc.pid}</span>
            <span class="detail-status ${statusText}">${statusText}</span>
            <span class="detail-title">${escapeHtml(proc.name || 'unknown')}</span>
            ${hasExited ? `<span class="detail-lifespan">${lifespan}</span>` : ''}`;
    }

    let html = '';

    // Process metadata
    html += `<div class="detail-fields">
        <div class="detail-field"><span class="field-label">Image</span><span class="field-value mono">${escapeHtml(proc.image || '')}</span></div>
        <div class="detail-field"><span class="field-label">Command line</span><span class="field-value mono">${escapeHtml(proc.command_line || '')}</span></div>
        <div class="detail-field"><span class="field-label">User</span><span class="field-value">${escapeHtml(proc.user || '')}</span></div>
        <div class="detail-field"><span class="field-label">Integrity</span><span class="field-value">${escapeHtml(proc.integrity || '')}</span></div>
        <div class="detail-field"><span class="field-label">Working dir</span><span class="field-value mono">${escapeHtml(proc.working_dir || '')}</span></div>
        <div class="detail-field"><span class="field-label">Parent</span><span class="field-value">${proc.parent_pid || 'N/A'} ${proc.parent_name ? '(' + escapeHtml(proc.parent_name) + ')' : ''}</span></div>
        <div class="detail-field"><span class="field-label">Started</span><span class="field-value">${formatRelativeTime(proc.first_seen)} (${proc.first_seen || ''})</span></div>
        ${hasExited ? `<div class="detail-field"><span class="field-label">Exited</span><span class="field-value">${formatRelativeTime(proc.exit_time)} (${proc.exit_time || ''})</span></div>` : ''}
        ${hasExited ? `<div class="detail-field"><span class="field-label">Lifespan</span><span class="field-value">${lifespan}</span></div>` : ''}
        ${proc.exit_code != null ? `<div class="detail-field"><span class="field-label">Exit code</span><span class="field-value">${proc.exit_code}</span></div>` : ''}
    </div>`;

    // Activity counters grid
    const act = proc.activity || {};
    html += `
    <div class="detail-section">
        <div class="detail-section-title">ACTIVITY</div>
        <div class="activity-grid">
            ${activityCounter('FILE', act.file)}
            ${activityCounter('NETWORK', act.network)}
            ${activityCounter('DNS', act.dns)}
            ${activityCounter('HTTP', act.http)}
            ${activityCounter('REGISTRY', act.registry)}
            ${activityCounter('MODULES', act.modules)}
            ${activityCounter('SCRIPTS', act.scripts)}
            ${activityCounter('INJECTION', act.injection)}
            ${activityCounter('WMI', act.wmi)}
            ${activityCounter('SERVICES', act.services)}
            ${activityCounter('TASKS', act.tasks)}
            ${activityCounter('LOGONS', act.logons)}
            ${activityCounter('ARTIFACTS', act.artifacts)}
            ${activityCounter('THREATS', act.threats)}
        </div>
        <p class="muted" style="font-size:10px;">Tip: clicking a counter switches to that tab and pre-filters the table by this PID. Clear the per-column filter to see the rest of the session.</p>
    </div>`;

    // Environment (collapsible)
    html += `
    <div class="detail-section">
        <details class="collapsible-section">
            <summary class="detail-section-title" style="cursor:pointer;border-bottom:none;">\u25B8 ENVIRONMENT</summary>
            <div class="detail-fields" style="padding-top:8px;">
                <div class="detail-field"><span class="field-label">Working Dir</span><span class="field-value mono">${escapeHtml(proc.working_dir || '')}</span></div>
                <div class="detail-field"><span class="field-label">Integrity</span><span class="field-value">${escapeHtml(proc.integrity || '')}</span></div>
            </div>
        </details>
    </div>`;

    // Children
    const children = proc.children || [];
    if (children.length > 0) {
        html += `<div class="detail-section">
            <div class="detail-section-title">CHILDREN</div>`;
        children.forEach(childPid => {
            const child = state.processes[childPid] || state.processes[String(childPid)];
            if (child) {
                const relativeStart = computeRelativeOffset(proc.first_seen, child.first_seen);
                const childExited = !!child.exit_time;
                const childLifespan = childExited ? computeLifespan(child.first_seen, child.exit_time) : '';
                const childStatus = childExited ? 'exited' : 'running';
                html += `
                <div class="child-card" onclick="openProcessDetail(${childPid})">
                    <div class="child-header">
                        <span class="child-name">${escapeHtml(child.name || 'unknown')} &middot; PID ${childPid}</span>
                        <span class="detail-status ${childStatus}" style="font-size:10px;margin-left:auto;margin-right:8px;">${childStatus}</span>
                        <button class="btn btn-sm">Open &gt;</button>
                    </div>
                    <div class="detail-field"><span class="field-label">Started</span><span class="field-value">${relativeStart}</span></div>
                    ${childExited ? `<div class="detail-field"><span class="field-label">Exited</span><span class="field-value">${formatRelativeTime(child.exit_time)} (lifespan ${childLifespan})</span></div>` : ''}
                    <div class="detail-field"><span class="field-label">Image</span><span class="field-value mono">${escapeHtml(child.image || '')}</span></div>
                </div>`;
            } else {
                html += `
                <div class="child-card" onclick="openProcessDetail(${childPid})">
                    <div class="child-header">
                        <span class="child-name">PID ${childPid}</span>
                        <button class="btn btn-sm">Open &gt;</button>
                    </div>
                </div>`;
            }
        });
        html += `</div>`;
    }

    // Alerts for this process
    const procAlerts = proc.alerts || [];
    if (procAlerts.length > 0) {
        html += `<div class="detail-section">
            <div class="detail-section-title">ALERTS (${procAlerts.length})</div>`;
        procAlerts.forEach((alert) => {
            const sev = (alert.severity || 'unknown').toLowerCase();
            const alertIdx = state.alerts.findIndex(a => a.id === alert.id);
            html += `
            <div class="child-card" onclick="openAlertDetail(${alertIdx >= 0 ? alertIdx : 0})">
                <div class="child-header">
                    <span class="event-severity ${sev}" style="font-size:10px">${alert.severity}</span>
                    <span class="child-name" style="margin-left:8px">${escapeHtml(alert.rule_name || '')}</span>
                </div>
                <div class="detail-field"><span class="field-label">Engine</span><span class="field-value">${alert.engine || ''}</span></div>
            </div>`;
        });
        html += `</div>`;
    }

    setDetailBody(html);
    showDetail();
}

function showMinimalProcessDetail(pid) {
    setDetailHeader(`PID ${pid}`, 'background:rgba(59,130,246,0.2);color:#3b82f6', `Process ${pid}`, '');
    setDetailBody(`<div class="muted">No detailed information available for PID ${pid}.</div>`);
    showDetail();
}

// --- Detail Panel: Navigation ---
function pushDetailHistory(type, id) {
    // Don't push duplicates
    const last = state.detailHistory[state.detailHistory.length - 1];
    if (last && last.type === type && last.id === id) return;
    state.detailHistory.push({ type, id });
}

function goDetailBack() {
    if (state.detailHistory.length > 1) {
        state.detailHistory.pop(); // Remove current
        const prev = state.detailHistory.pop(); // Get previous (will be re-pushed by open)
        if (prev.type === 'process') {
            openProcessDetail(prev.id);
        } else if (prev.type === 'rustinel') {
            openRustinelDetail();
        } else if (prev.type === 'agent') {
            openAgentDetail();
        } else if (prev.type === 'litterbox') {
            openLitterboxDetail();
        } else if (prev.type === 'fibratus') {
            openFibratusDetail();
        } else if (prev.type === 'alert' || prev.type === 'dns' || prev.type === 'file' || prev.type === 'registry' || prev.type === 'injection') {
            openAlertDetail(prev.id);
        }
    } else {
        closeDetail();
    }
}

// --- Detail Panel: helpers ---
function setDetailHeader(badgeText, badgeStyle, title, meta) {
    const badge = document.getElementById('detail-badge');
    const titleEl = document.getElementById('detail-title');
    const metaEl = document.getElementById('detail-meta');
    if (badge) {
        badge.innerHTML = badgeText;
        badge.style.cssText = badgeStyle;
    }
    if (titleEl) titleEl.textContent = title;
    if (metaEl) metaEl.textContent = meta;

    // Restore back button
    const headerLeft = document.querySelector('.detail-header-left');
    if (headerLeft) {
        headerLeft.innerHTML = `
            <button class="btn btn-sm" onclick="goDetailBack()">&lt; Back</button>
            <span class="detail-badge" id="detail-badge" style="${badgeStyle}">${badgeText}</span>
            <span class="detail-title" id="detail-title">${escapeHtml(title)}</span>`;
    }
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
    result.innerHTML = '<div class="detonation-status">Submitting sample...</div>';

    const formData = new FormData();
    formData.append('file', input.files[0]);
    formData.append('target', target);

    // Record submission time for post-detonation alert polling
    const submissionTime = new Date().toISOString();
    const fileName = input.files[0].name;

    try {
        const resp = await fetch('/api/submit', { method: 'POST', body: formData });
        const data = await resp.json();

        if (resp.ok) {
            // Render enhanced results panel
            renderDetonationResults(data, submissionTime, fileName, target);
        } else {
            result.className = 'submit-result visible error';
            result.textContent = `Error: ${JSON.stringify(data)}`;
        }
    } catch (e) {
        result.className = 'submit-result visible error';
        result.textContent = `Network error: ${e.message}`;
    }

    btn.disabled = false;
    btn.textContent = 'Detonate';
}

// --- Enhanced Detonation Results Panel ---
let _detonationPollTimer = null;
let _detonationPollCount = 0;

function renderDetonationResults(data, submissionTime, fileName, target) {
    const result = document.getElementById('submit-result');
    result.className = 'submit-result visible';

    // Determine agent result
    const agentResult = data.agent || null;
    const litterboxResult = data.litterbox || null;
    const agentPid = agentResult?.data?.pid || null;
    const agentStatus = agentResult?.data?.status || agentResult?.data?.message || null;
    const agentOk = agentResult && agentResult.status >= 200 && agentResult.status < 400;
    const litterboxOk = litterboxResult && litterboxResult.status >= 200 && litterboxResult.status < 400;

    // Determine execution status
    let execStatus = 'unknown';
    let execColor = 'var(--text-muted)';
    let execIcon = '\u2022';
    if (agentResult) {
        const st = (typeof agentResult.data === 'object' ? agentResult.data?.status : '') || '';
        if (st === 'virus' || st === 'quarantined') {
            execStatus = 'Quarantined by AV';
            execColor = 'var(--accent-orange)';
            execIcon = '\u26A0';
        } else if (agentOk && agentPid) {
            execStatus = `Executed (PID ${agentPid})`;
            execColor = 'var(--accent-green)';
            execIcon = '\u2713';
        } else if (agentOk) {
            execStatus = 'Submitted';
            execColor = 'var(--accent-green)';
            execIcon = '\u2713';
        } else {
            execStatus = `Failed (HTTP ${agentResult.status})`;
            execColor = 'var(--accent-red)';
            execIcon = '\u2717';
        }
    }

    let html = '';

    // Header
    html += `<div class="detonation-header">
        <div class="detonation-filename">${escapeHtml(fileName)}</div>
        <div class="detonation-meta">Detonated at ${new Date(submissionTime).toLocaleTimeString('en-GB')} \u00B7 Target: ${escapeHtml(target)}</div>
        ${data.file_info ? `<div class="detonation-meta mono" style="margin-top:4px;">SHA-256: ${escapeHtml(data.file_info.sha256 || '')}</div>` : ''}
    </div>`;

    // Investigation Pipeline
    html += `<div class="detonation-section pipeline-section">
        <div class="detonation-section-title">Investigation Pipeline</div>
        <div class="pipeline-steps">
            <div class="pipeline-step done">
                <div class="pipeline-step-icon">\u2713</div>
                <div class="pipeline-step-body">
                    <div class="pipeline-step-name">Hash registered</div>
                    <div class="pipeline-step-desc">SHA-256 added to Rustinel IOC feed${data.ioc_feed?.status === 'exists' ? ' (already known)' : ''}</div>
                </div>
            </div>
            <div class="pipeline-step ${agentOk || (target === 'litterbox') ? 'done' : 'failed'}">
                <div class="pipeline-step-icon">${agentOk || (target === 'litterbox') ? '\u2713' : '\u2717'}</div>
                <div class="pipeline-step-body">
                    <div class="pipeline-step-name">Sample delivered</div>
                    <div class="pipeline-step-desc">${target === 'litterbox' ? 'Uploaded to LitterBox' : wasQuarantined ? 'Blocked by AV before execution' : agentOk ? 'Written to C:\\Users\\Public\\Downloads' : 'Delivery failed'}</div>
                </div>
            </div>
            <div class="pipeline-step ${wasQuarantined ? 'failed' : agentPid ? 'done' : 'pending'}">
                <div class="pipeline-step-icon">${wasQuarantined ? '\u2717' : agentPid ? '\u2713' : '\u2022'}</div>
                <div class="pipeline-step-body">
                    <div class="pipeline-step-name">Process execution</div>
                    <div class="pipeline-step-desc">${agentPid ? `Spawned PID ${agentPid}` : wasQuarantined ? 'AV prevented execution' : 'Waiting for agent'}</div>
                </div>
            </div>
            <div class="pipeline-step ${shouldPoll ? 'active' : wasQuarantined ? 'skipped' : 'pending'}">
                <div class="pipeline-step-icon">${shouldPoll ? '\u25B6' : '\u2014'}</div>
                <div class="pipeline-step-body">
                    <div class="pipeline-step-name">ETW monitoring (Fibratus)</div>
                    <div class="pipeline-step-desc">Process, network, registry, file, DNS events</div>
                </div>
            </div>
            <div class="pipeline-step ${shouldPoll ? 'active' : wasQuarantined ? 'skipped' : 'pending'}">
                <div class="pipeline-step-icon">${shouldPoll ? '\u25B6' : '\u2014'}</div>
                <div class="pipeline-step-body">
                    <div class="pipeline-step-name">Rustinel detection</div>
                    <div class="pipeline-step-desc">${state.rustinelInfo ? `${state.rustinelInfo.rules?.sigma || 0} Sigma + ${state.rustinelInfo.rules?.yara || 0} YARA rules + IOC matching` : 'Sigma + YARA + IOC matching'}</div>
                </div>
            </div>
        </div>
    </div>`;

    // Execution section
    if (target === 'agent' || target === 'both') {
        html += `<div class="detonation-section">
            <div class="detonation-section-title">
                <span class="detonation-icon agent">D</span> DetonatorAgent
            </div>
            <div class="detonation-status-row">
                <span style="color:${execColor}">${execIcon} ${escapeHtml(execStatus)}</span>
                ${agentPid ? `<span class="detonation-pid">PID ${agentPid}</span>` : ''}
            </div>`;
        if (agentResult?.data?.message) {
            html += `<div class="detonation-detail muted">${escapeHtml(agentResult.data.message)}</div>`;
        }
        html += `</div>`;
    }

    // LitterBox section
    if (target === 'litterbox' || target === 'both') {
        html += `<div class="detonation-section">
            <div class="detonation-section-title">
                <span class="detonation-icon litterbox">L</span> LitterBox
            </div>
            <div class="detonation-status-row">
                <span style="color:${litterboxOk ? 'var(--accent-green)' : 'var(--accent-red)'}">
                    ${litterboxOk ? '\u2713 Uploaded' : '\u2717 Failed'}
                </span>
            </div>`;
        if (litterboxOk && litterboxResult?.data) {
            const lbData = typeof litterboxResult.data === 'object' ? litterboxResult.data : {};
            if (lbData.file_info) {
                const fi = lbData.file_info;
                html += `<div class="detonation-detail">
                    ${fi.sha256 ? `<div class="detail-field"><span class="field-label">SHA-256</span><span class="field-value mono" style="font-size:10px">${escapeHtml(fi.sha256)}</span></div>` : ''}
                    ${fi.file_type ? `<div class="detail-field"><span class="field-label">Type</span><span class="field-value">${escapeHtml(fi.file_type)}</span></div>` : ''}
                </div>`;
            }
        } else if (litterboxResult?.error) {
            html += `<div class="detonation-detail muted">${escapeHtml(litterboxResult.error)}</div>`;
        }
        html += `</div>`;
    }

    // Rustinel / Fibratus detection results (polling section)
    const wasQuarantined = agentResult && (typeof agentResult.data === 'object') &&
        (agentResult.data?.status === 'virus' || agentResult.data?.status === 'quarantined');
    const shouldPoll = !wasQuarantined && (agentOk || target === 'litterbox');

    html += `<div class="detonation-section" id="detonation-detections">
        <div class="detonation-section-title">
            <span class="detonation-icon rustinel">R</span> Rustinel + Fibratus Detections
            <span class="detonation-poll-badge" id="detonation-poll-status">${shouldPoll ? 'polling...' : 'skipped'}</span>
        </div>
        <div id="detonation-alerts-content">`;

    if (wasQuarantined) {
        html += `<div class="detonation-no-alerts">
            <strong>Sample was quarantined before execution.</strong><br>
            No process was spawned, so Rustinel/Fibratus have no events to detect.<br>
            <span class="muted">Disable real-time AV or add an exclusion to allow detonation.</span>
        </div>`;
    } else if (!agentOk && target !== 'litterbox' && target !== 'both') {
        html += `<div class="detonation-no-alerts">
            Agent submission failed. No process executed — nothing to detect.
        </div>`;
    } else {
        html += `<div class="detonation-loading">
                <div class="detonation-spinner"></div>
                Waiting for detections... (polling every 3s)
            </div>`;
    }

    html += `</div></div>`;

    // Also show existing alerts count for context
    html += `<div class="detonation-section" style="background:transparent;border:none;padding:4px 12px;">
        <div class="muted" style="font-size:10px;">Session total: ${state.alerts.length} alerts loaded from Rustinel logs</div>
    </div>`;

    result.innerHTML = html;

    // Start polling for new alerts (only if sample likely executed)
    if (shouldPoll) {
        startDetonationPolling(submissionTime, agentPid);
    }
}

function startDetonationPolling(sinceTime, pid) {
    // Clear any previous polling
    if (_detonationPollTimer) clearInterval(_detonationPollTimer);
    _detonationPollCount = 0;

    const maxPolls = 20; // Poll for 60s max (20 * 3s)
    let lastAlertCount = 0;
    let stableCount = 0; // How many polls with no new alerts

    const poll = async () => {
        _detonationPollCount++;
        const statusEl = document.getElementById('detonation-poll-status');
        const contentEl = document.getElementById('detonation-alerts-content');
        if (!contentEl) { clearInterval(_detonationPollTimer); return; }

        try {
            // Poll for ALL alerts since submission time (not just PID, since
            // child processes and injected processes get different PIDs)
            let url = `/api/alerts?since=${encodeURIComponent(sinceTime)}`;
            const resp = await fetch(url);
            const alerts = await resp.json();

            if (alerts.length > 0) {
                renderDetonationAlerts(alerts, contentEl);
                // Check if count stabilized
                if (alerts.length === lastAlertCount) {
                    stableCount++;
                } else {
                    stableCount = 0;
                }
                lastAlertCount = alerts.length;
            }

            // Update poll status
            if (statusEl) {
                const elapsed = _detonationPollCount * 3;
                statusEl.textContent = `${elapsed}s \u00B7 ${alerts.length} alert${alerts.length !== 1 ? 's' : ''}`;
            }

            // Stop conditions: max polls reached or results stabilized for 3 consecutive polls
            if (_detonationPollCount >= maxPolls || (stableCount >= 3 && lastAlertCount > 0)) {
                clearInterval(_detonationPollTimer);
                if (statusEl) {
                    statusEl.textContent = `done \u00B7 ${lastAlertCount} alert${lastAlertCount !== 1 ? 's' : ''}`;
                    statusEl.classList.add('done');
                }
                if (lastAlertCount === 0 && contentEl) {
                    contentEl.innerHTML = `<div class="detonation-no-alerts">No detections triggered after ${_detonationPollCount * 3}s. Sample may be benign, evasive, or execution was blocked.</div>`;
                }
                // Final refresh of main alerts view
                refreshAlerts();
            }
        } catch (e) {
            console.error('Detonation poll error:', e);
        }
    };

    // First poll after 3s (give Rustinel + background loader time to process)
    setTimeout(poll, 3000);
    // Then every 3s
    _detonationPollTimer = setInterval(poll, 3000);
}

function renderDetonationAlerts(alerts, container) {
    // Group by engine
    const byEngine = {};
    alerts.forEach(a => {
        const eng = a.engine || 'unknown';
        if (!byEngine[eng]) byEngine[eng] = [];
        byEngine[eng].push(a);
    });

    // Severity summary
    const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
    alerts.forEach(a => {
        const sev = (a.severity || 'low').toLowerCase();
        if (severityCounts[sev] !== undefined) severityCounts[sev]++;
    });

    let html = '';

    // Severity summary bar
    html += `<div class="detonation-severity-bar">`;
    if (severityCounts.critical > 0) html += `<span class="sev-badge critical">${severityCounts.critical} Critical</span>`;
    if (severityCounts.high > 0) html += `<span class="sev-badge high">${severityCounts.high} High</span>`;
    if (severityCounts.medium > 0) html += `<span class="sev-badge medium">${severityCounts.medium} Medium</span>`;
    if (severityCounts.low > 0) html += `<span class="sev-badge low">${severityCounts.low} Low</span>`;
    html += `</div>`;

    // Alerts grouped by engine
    for (const [engine, engineAlerts] of Object.entries(byEngine)) {
        html += `<div class="detonation-engine-group">
            <div class="detonation-engine-title">${escapeHtml(engine.toUpperCase())} (${engineAlerts.length})</div>`;
        engineAlerts.forEach(alert => {
            const sev = (alert.severity || 'low').toLowerCase();
            html += `<div class="detonation-alert-row" onclick="switchTab('tracing'); setTimeout(() => openAlertDetail(${state.alerts.findIndex(a => a.id === alert.id)}), 200);">
                <span class="event-severity ${sev}" style="font-size:10px;padding:2px 6px;">${alert.severity || '?'}</span>
                <span class="detonation-alert-name">${escapeHtml(alert.rule_name || 'Unknown')}</span>
                <span class="detonation-alert-pid">${alert.process_name || ''} (${alert.pid || '?'})</span>
            </div>`;
        });
        html += `</div>`;
    }

    // MITRE ATT&CK tags collected from all alerts
    const allTags = new Set();
    alerts.forEach(a => (a.tags || []).forEach(t => allTags.add(t)));
    if (allTags.size > 0) {
        html += `<div class="detonation-tags">`;
        [...allTags].sort().forEach(tag => {
            if (tag.startsWith('attack.t')) html += `<span class="tag technique">${tag.replace('attack.', '').toUpperCase()}</span>`;
            else if (tag.startsWith('attack.')) html += `<span class="tag tactic">${tag.replace('attack.', '').toUpperCase()}</span>`;
        });
        html += `</div>`;
    }

    container.innerHTML = html;
}

// --- Utilities ---
function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function formatTime(ts) {
    if (!ts) return '';
    try {
        const d = new Date(ts);
        if (isNaN(d.getTime())) return ts.substring(0, 19);
        return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch {
        return ts.substring(0, 19);
    }
}

function formatRelativeTime(ts) {
    if (!ts || !state.sessionStart) return formatTime(ts);
    try {
        const t = new Date(ts).getTime();
        if (isNaN(t)) return formatTime(ts);
        const diff = (t - state.sessionStart) / 1000;
        if (diff < 0) return '+0.000s';
        return `+${diff.toFixed(3)}s`;
    } catch {
        return formatTime(ts);
    }
}

function computeRelativeOffset(parentTs, childTs) {
    if (!parentTs || !childTs) return formatTime(childTs);
    try {
        const pt = new Date(parentTs).getTime();
        const ct = new Date(childTs).getTime();
        if (isNaN(pt) || isNaN(ct)) return formatTime(childTs);
        const diff = (ct - pt) / 1000;
        return `+${diff.toFixed(3)}s`;
    } catch {
        return formatTime(childTs);
    }
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
        if (diffS < 60) return `${diffS.toFixed(2)}s`;
        const mins = Math.floor(diffS / 60);
        const secs = (diffS % 60).toFixed(1);
        if (mins < 60) return `${mins}m ${secs}s`;
        const hours = Math.floor(mins / 60);
        const remainMins = mins % 60;
        return `${hours}h ${remainMins}m`;
    } catch {
        return '';
    }
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

function capitalizeAction(action) {
    if (!action) return '';
    // "set" -> "SetValue", "create" -> "CreateKey"
    const map = { 'set': 'SetValue', 'create': 'CreateKey', 'delete': 'DeleteKey', 'rename': 'RenameKey' };
    return map[action.toLowerCase()] || action.charAt(0).toUpperCase() + action.slice(1);
}

function detectFileType(path) {
    if (!path) return 'Unknown';
    const ext = path.split('.').pop().toLowerCase();
    const types = {
        'exe': 'PE', 'dll': 'PE', 'sys': 'PE', 'scr': 'PE',
        'ps1': 'PowerShell', 'bat': 'Batch', 'cmd': 'Batch',
        'js': 'JavaScript', 'vbs': 'VBScript',
        'doc': 'Office', 'docx': 'Office', 'xls': 'Office', 'xlsx': 'Office',
        'pdf': 'PDF', 'zip': 'Archive', 'rar': 'Archive', '7z': 'Archive',
    };
    return types[ext] || ext.toUpperCase();
}

function activityCounter(label, value) {
    const v = value || 0;
    const highlight = (label === 'THREATS' && v > 0) ? ' threats' :
                      (label === 'INJECTION' && v > 0) ? ' injection' : '';
    return `
        <div class="activity-counter${highlight ? ' ' + highlight : ''}">
            <div class="counter-label">${label}</div>
            <div class="counter-value ${v === 0 ? 'zero' : ''}">${v}</div>
        </div>`;
}

function generateHexPreviewPlaceholder() {
    // Generate a realistic-looking hex dump placeholder (MZ header)
    const lines = [
        '00000000  4d 5a 90 00 03 00 00 00  04 00 00 00 ff ff 00 00  |MZ..............|',
        '00000010  b8 00 00 00 00 00 00 00  40 00 00 00 00 00 00 00  |........@.......|',
        '00000020  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|',
        '00000030  00 00 00 00 00 00 00 00  00 00 00 00 80 00 00 00  |................|',
        '00000040  0e 1f ba 0e 00 b4 09 cd  21 b8 01 4c cd 21 54 68  |........!..L.!Th|',
        '00000050  69 73 20 70 72 6f 67 72  61 6d 20 63 61 6e 6e 6f  |is program canno|',
        '00000060  74 20 62 65 20 72 75 6e  20 69 6e 20 44 4f 53 20  |t be run in DOS |',
        '00000070  6d 6f 64 65 2e 0d 0d 0a  24 00 00 00 00 00 00 00  |mode....$.......|',
    ];
    return lines.join('\n');
}

async function fetchHexPreview(filepath, elementId) {
    try {
        const resp = await fetch(`/api/file/hex?path=${encodeURIComponent(filepath)}&bytes=8192`);
        const data = await resp.json();
        const el = document.getElementById(elementId);
        const metaEl = document.getElementById(`${elementId}-meta`);
        if (el) {
            if (data.hex) {
                el.textContent = data.hex;
                if (metaEl) metaEl.textContent = `first ${data.bytes_shown.toLocaleString()} of ${data.size.toLocaleString()} bytes`;
            } else if (data.error) {
                el.textContent = generateHexPreviewPlaceholder();
                if (metaEl) metaEl.textContent = `unavailable: ${data.error}`;
            }
        }
    } catch (e) {
        const el = document.getElementById(elementId);
        if (el) el.textContent = generateHexPreviewPlaceholder();
        const metaEl = document.getElementById(`${elementId}-meta`);
        if (metaEl) metaEl.textContent = 'failed to load';
    }
}

function showInFiles(filename) {
    // Switch to tracing tab and filter alerts to file category matching this filename
    switchTab('tracing');
    closeDetail();
    // Set engine filter to show file events
    const engineFilter = document.getElementById('filter-engine');
    if (engineFilter) {
        engineFilter.value = '';
    }
    // Refresh with file category context
    refreshAlerts();
}

// --- Filter event listeners ---
document.getElementById('filter-severity')?.addEventListener('change', refreshAlerts);
document.getElementById('filter-engine')?.addEventListener('change', refreshAlerts);

// --- Rustinel Detail Panel ---
async function openRustinelDetail() {
    pushDetailHistory('rustinel', 0);

    // Show loading state
    setDetailHeader(
        'Engine',
        'background:rgba(34,211,238,0.15);color:var(--accent-cyan)',
        'Rustinel',
        'loading...'
    );
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
    const statusText = online ? 'running' : 'stopped';
    const statusColor = online ? 'var(--accent-green)' : 'var(--accent-red)';

    setDetailHeader(
        'Engine',
        'background:rgba(34,211,238,0.15);color:var(--accent-cyan)',
        'Rustinel',
        ''
    );

    // Update header with status
    const headerLeft = document.querySelector('.detail-header-left');
    if (headerLeft) {
        headerLeft.innerHTML = `
            <button class="btn btn-sm" onclick="goDetailBack()">&lt; Back</button>
            <span class="detail-badge" style="background:rgba(34,211,238,0.15);color:var(--accent-cyan)">Engine</span>
            <span class="detail-title">Rustinel</span>
            <span class="detail-status" style="color:${statusColor}">${statusText}</span>`;
    }

    let html = '';

    // Version & process info
    html += `<div class="detail-fields">
        <div class="detail-field"><span class="field-label">Version</span><span class="field-value">${escapeHtml(info.version || 'unknown')}</span></div>
        <div class="detail-field"><span class="field-label">Status</span><span class="field-value" style="color:${statusColor}">${statusText}</span></div>`;

    if (info.process) {
        const proc = info.process;
        html += `<div class="detail-field"><span class="field-label">PID</span><span class="field-value">${proc.Id || 'N/A'}</span></div>`;
        if (proc.StartTime) {
            html += `<div class="detail-field"><span class="field-label">Started</span><span class="field-value">${escapeHtml(proc.StartTime)}</span></div>`;
        }
        if (proc.WorkingSet64) {
            html += `<div class="detail-field"><span class="field-label">Memory</span><span class="field-value">${formatSize(proc.WorkingSet64)}</span></div>`;
        }
    }

    html += `<div class="detail-field"><span class="field-label">Install Dir</span><span class="field-value mono">${escapeHtml(info.install_dir || '')}</span></div>`;
    html += `<div class="detail-field"><span class="field-label">Alerts Dir</span><span class="field-value mono">${escapeHtml(info.alerts_dir || '')}</span></div>`;
    html += `<div class="detail-field"><span class="field-label">Alerts Total</span><span class="field-value">${info.alerts_count || 0}</span></div>`;
    html += `</div>`;

    // Rules section
    const rules = info.rules || {};
    const ioc = rules.ioc || {};
    const totalIoc = (ioc.hashes || 0) + (ioc.ips || 0) + (ioc.domains || 0) + (ioc.paths || 0);

    html += `
    <div class="detail-section">
        <div class="detail-section-title">DETECTION RULES</div>
        <div class="activity-grid" style="grid-template-columns: repeat(3, 1fr);">
            <div class="activity-counter">
                <div class="counter-label">SIGMA</div>
                <div class="counter-value ${rules.sigma === 0 ? 'zero' : ''}">${rules.sigma || 0}</div>
            </div>
            <div class="activity-counter">
                <div class="counter-label">YARA</div>
                <div class="counter-value ${rules.yara === 0 ? 'zero' : ''}">${rules.yara || 0}</div>
            </div>
            <div class="activity-counter">
                <div class="counter-label">IOC</div>
                <div class="counter-value ${totalIoc === 0 ? 'zero' : ''}">${totalIoc}</div>
            </div>
        </div>`;

    if (totalIoc > 0) {
        html += `<div class="detail-fields" style="margin-top:8px;">
            <div class="detail-field"><span class="field-label">Hashes</span><span class="field-value">${ioc.hashes || 0}</span></div>
            <div class="detail-field"><span class="field-label">IPs / CIDRs</span><span class="field-value">${ioc.ips || 0}</span></div>
            <div class="detail-field"><span class="field-label">Domains</span><span class="field-value">${ioc.domains || 0}</span></div>
            <div class="detail-field"><span class="field-label">Path Regex</span><span class="field-value">${ioc.paths || 0}</span></div>
        </div>`;
    }
    html += `</div>`;

    // ETW Providers section
    const providers = info.etw_providers || [];
    if (providers.length > 0) {
        html += `
        <div class="detail-section">
            <div class="detail-section-title">ETW PROVIDERS (${providers.length})</div>
            <div class="detail-fields">`;
        providers.forEach(p => {
            html += `<div class="detail-field">
                <span class="field-label" style="font-size:10px">${escapeHtml(p.name.replace('Microsoft-Windows-', ''))}</span>
                <span class="field-value" style="font-size:10px;color:var(--text-muted)">kw: ${escapeHtml(p.keywords)}</span>
            </div>`;
        });
        html += `</div></div>`;
    }

    // Recent log lines
    const logLines = info.recent_log || [];
    if (logLines.length > 0) {
        html += `
        <div class="detail-section">
            <div class="detail-section-title">RECENT LOG</div>
            <div class="raw-json" style="max-height:300px;">${logLines.map(l => escapeHtml(l.replace(/\x1b\[[0-9;]*m/g, ''))).join('\n')}</div>
        </div>`;
    }

    setDetailBody(html);
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
            // Update sidebar status
            const statusEl = document.getElementById('status-sysmon');
            if (statusEl) {
                const dot = statusEl.querySelector('.dot');
                if (sysmonStats.online) {
                    dot.className = 'dot online';
                } else {
                    dot.className = 'dot offline';
                }
            }
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

    let html = `<div class="sysmon-stats-bar">`;
    html += `<span class="stats-total">${total} events (last 500)</span>`;
    stats.sort((a, b) => b.count - a.count);
    stats.forEach(s => {
        const pct = total > 0 ? ((s.count / total) * 100).toFixed(1) : 0;
        const typeClass = getSysmonTypeClass(s.event_id);
        html += `<span class="stats-chip ${typeClass}" title="${s.name}: ${s.count} (${pct}%)" onclick="filterSysmonByType('${s.event_id}')">${s.name} <strong>${s.count}</strong></span>`;
    });
    html += `</div>`;
    container.innerHTML = html;
}

function filterSysmonByType(eventId) {
    const select = document.getElementById('sysmon-filter-type');
    if (select) {
        select.value = eventId;
        refreshSysmon();
    }
}

function renderSysmonTable() {
    const container = document.getElementById('sysmon-table');
    if (!container) return;

    if (!sysmonEvents || sysmonEvents.length === 0) {
        container.innerHTML = '<div class="empty-state">No Sysmon events found</div>';
        return;
    }

    if (sysmonEvents[0] && sysmonEvents[0].error) {
        container.innerHTML = `<div class="empty-state">Error: ${escapeHtml(sysmonEvents[0].error)}</div>`;
        return;
    }

    let html = `<table class="data-table sysmon-events-table">
        <thead><tr>
            <th>Time</th>
            <th>Type</th>
            <th>PID</th>
            <th>Image</th>
            <th>Details</th>
        </tr></thead><tbody>`;

    sysmonEvents.forEach(ev => {
        const typeClass = getSysmonTypeClass(String(ev.event_id));
        const time = ev.timestamp ? formatSysmonTime(ev.timestamp) : '';
        const image = ev.image ? ev.image.split('\\').pop() : '';
        const details = getSysmonDetails(ev);

        html += `<tr class="sysmon-row ${typeClass}" onclick="showSysmonDetail(${JSON.stringify(ev).replace(/"/g, '&quot;')})">
            <td class="col-time">${time}</td>
            <td class="col-type"><span class="type-badge ${typeClass}">${escapeHtml(ev.type || '')}</span></td>
            <td class="col-pid">${ev.pid || ''}</td>
            <td class="col-image" title="${escapeHtml(ev.image || '')}">${escapeHtml(image)}</td>
            <td class="col-details">${escapeHtml(details)}</td>
        </tr>`;
    });

    html += '</tbody></table>';
    container.innerHTML = html;
}

function getSysmonDetails(ev) {
    switch (ev.event_id) {
        case 1: return ev.commandline ? truncate(ev.commandline, 80) : '';
        case 3: return `${ev.dst_ip || ''}:${ev.dst_port || ''} (${ev.protocol || ''})`;
        case 5: return 'Process terminated';
        case 7: return ev.loaded_image ? ev.loaded_image.split('\\').pop() : '';
        case 8: return `Source PID ${ev.source_pid} -> Target PID ${ev.target_pid}`;
        case 10: return `${(ev.source_image||'').split('\\').pop()} -> ${(ev.target_image||'').split('\\').pop()}`;
        case 11: return ev.target ? truncate(ev.target, 80) : '';
        case 12: case 13: case 14: return ev.target ? truncate(ev.target, 60) : '';
        case 22: return ev.query || '';
        default: return '';
    }
}

function getSysmonTypeClass(eventId) {
    const classes = {
        '1': 'type-process', '3': 'type-network', '5': 'type-terminate',
        '7': 'type-imageload', '8': 'type-injection', '10': 'type-access',
        '11': 'type-file', '12': 'type-registry', '13': 'type-registry',
        '14': 'type-registry', '22': 'type-dns',
    };
    return classes[eventId] || 'type-other';
}

function formatSysmonTime(isoStr) {
    try {
        const d = new Date(isoStr);
        return d.toLocaleTimeString('en-US', { hour12: false }) + '.' + String(d.getMilliseconds()).padStart(3, '0');
    } catch { return isoStr; }
}

function truncate(str, max) {
    if (!str) return '';
    return str.length > max ? str.substring(0, max) + '...' : str;
}

function showSysmonDetail(ev) {
    let html = `
    <div class="detail-section">
        <div class="detail-section-title">${escapeHtml(ev.type || 'Event')} - PID ${ev.pid || '?'}</div>
        <div class="detail-fields">
            <div class="detail-field"><span class="field-label">Timestamp</span><span class="field-value">${escapeHtml(ev.timestamp || '')}</span></div>
            <div class="detail-field"><span class="field-label">Event ID</span><span class="field-value">${ev.event_id}</span></div>
            <div class="detail-field"><span class="field-label">PID</span><span class="field-value">${ev.pid || ''}</span></div>
            <div class="detail-field"><span class="field-label">Image</span><span class="field-value">${escapeHtml(ev.image || '')}</span></div>
            <div class="detail-field"><span class="field-label">User</span><span class="field-value">${escapeHtml(ev.user || '')}</span></div>`;

    // Type-specific fields
    if (ev.event_id === 1) {
        html += `
            <div class="detail-field"><span class="field-label">Command Line</span><span class="field-value cmd-line">${escapeHtml(ev.commandline || '')}</span></div>
            <div class="detail-field"><span class="field-label">Parent Image</span><span class="field-value">${escapeHtml(ev.parent_image || '')}</span></div>
            <div class="detail-field"><span class="field-label">Parent PID</span><span class="field-value">${ev.parent_pid || ''}</span></div>
            <div class="detail-field"><span class="field-label">Integrity</span><span class="field-value">${escapeHtml(ev.integrity || '')}</span></div>
            <div class="detail-field"><span class="field-label">Hashes</span><span class="field-value hash-value">${escapeHtml(ev.hashes || '')}</span></div>`;
    } else if (ev.event_id === 3) {
        html += `
            <div class="detail-field"><span class="field-label">Destination</span><span class="field-value">${escapeHtml(ev.dst_ip || '')}:${ev.dst_port || ''}</span></div>
            <div class="detail-field"><span class="field-label">Hostname</span><span class="field-value">${escapeHtml(ev.dst_hostname || '')}</span></div>
            <div class="detail-field"><span class="field-label">Protocol</span><span class="field-value">${ev.protocol || ''}</span></div>`;
    } else if (ev.event_id === 11) {
        html += `<div class="detail-field"><span class="field-label">Target File</span><span class="field-value">${escapeHtml(ev.target || '')}</span></div>`;
    } else if (ev.event_id === 22) {
        html += `
            <div class="detail-field"><span class="field-label">DNS Query</span><span class="field-value">${escapeHtml(ev.query || '')}</span></div>
            <div class="detail-field"><span class="field-label">Result</span><span class="field-value">${escapeHtml(ev.result || '')}</span></div>`;
    } else if (ev.event_id === 8) {
        html += `
            <div class="detail-field"><span class="field-label">Source PID</span><span class="field-value">${ev.source_pid || ''}</span></div>
            <div class="detail-field"><span class="field-label">Target PID</span><span class="field-value">${ev.target_pid || ''}</span></div>
            <div class="detail-field"><span class="field-label">Target Image</span><span class="field-value">${escapeHtml(ev.target_image || '')}</span></div>`;
    } else if (ev.event_id === 10) {
        html += `
            <div class="detail-field"><span class="field-label">Source</span><span class="field-value">${escapeHtml(ev.source_image || '')}</span></div>
            <div class="detail-field"><span class="field-label">Target</span><span class="field-value">${escapeHtml(ev.target_image || '')}</span></div>
            <div class="detail-field"><span class="field-label">Access Mask</span><span class="field-value">${escapeHtml(ev.access || '')}</span></div>`;
    } else if (ev.raw) {
        html += `<div class="detail-field"><span class="field-label">Raw Data</span></div>
            <div class="raw-json">${escapeHtml(JSON.stringify(ev.raw, null, 2))}</div>`;
    }

    html += `</div></div>`;

    openDetail(`Sysmon ${ev.type || 'Event'}`, html, `event-${ev.event_id}`);
}


// --- Keyboard shortcuts ---
document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && state.detailOpen) closeDetail();
    if (e.key === 'Backspace' && state.detailOpen && !['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement.tagName)) {
        e.preventDefault();
        goDetailBack();
    }
});
