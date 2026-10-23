// SWA AI Autonomous Security Auditor - Frontend Controller
let currentProfile = "full_red_team";
let currentScanId = null;
let scansData = {};
let activeFindings = [];
let ws = null;

document.addEventListener("DOMContentLoaded", () => {
    initWebSocket();
    loadScans();
    loadSettings();
    loadPlugins();

    // Enter key launches scan
    const input = document.getElementById("targetInput");
    if (input) {
        input.addEventListener("keypress", (e) => {
            if (e.key === "Enter") launchScan();
        });
    }
});

// Profile Selection Pills
function selectProfile(profile, element) {
    currentProfile = profile;
    document.querySelectorAll(".pill-item").forEach(p => p.classList.remove("active"));
    if (element) {
        element.classList.add("active");
    }
}

// Toggle Advanced Options
function toggleAdvancedOptions() {
    const el = document.getElementById("advancedOptions");
    const arrow = document.getElementById("advArrow");
    if (el) {
        const isHidden = el.style.display === "none" || !el.style.display;
        el.style.display = isHidden ? "grid" : "none";
        if (arrow) arrow.textContent = isHidden ? "▲" : "▼";
    }
}

// WebSocket Live Feeds
function initWebSocket() {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    
    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
        const statusEl = document.getElementById("connectionStatus");
        if (statusEl) {
            statusEl.innerHTML = `<span class="pulse"></span><span>Engine Ready</span>`;
        }
    };

    ws.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data);
            handleWsEvent(msg);
        } catch (e) {
            console.error("WS Parse error", e);
        }
    };

    ws.onclose = () => {
        const statusEl = document.getElementById("connectionStatus");
        if (statusEl) {
            statusEl.innerHTML = `<span style="width: 8px; height: 8px; background: #ef4444; border-radius: 50%; display: inline-block;"></span><span>Reconnecting...</span>`;
        }
        setTimeout(initWebSocket, 2000);
    };
}

function handleWsEvent(msg) {
    const { type, data } = msg;

    if (type === "SCAN_STARTED") {
        loadScans();
        if (data.scan_id === currentScanId) {
            updateScanHeaderStatus("RUNNING");
        }
    } else if (type === "PROGRESS_UPDATE") {
        if (data.scan_id === currentScanId) {
            setProgress(data.progress_percent, data.current_phase);
        }
        updateScanInList(data.scan_id, data.progress_percent, data.current_phase);
    } else if (type === "LOG_EVENT") {
        if (data.scan_id === currentScanId) {
            appendLog(data);
        }
    } else if (type === "FINDING_DISCOVERED") {
        if (data.scan_id === currentScanId) {
            activeFindings.unshift(data.finding);
            renderFindings(activeFindings);
        }
        loadScans();
    } else if (type === "SCAN_COMPLETED") {
        if (data.scan_id === currentScanId) {
            setProgress(100, "Audit Completed");
            updateScanHeaderStatus("COMPLETED");
            const btnCancel = document.getElementById("btnCancelScan");
            if (btnCancel) btnCancel.style.display = "none";
        }
        loadScans();
    } else if (type === "SCAN_CANCELLED") {
        if (data.scan_id === currentScanId) {
            updateScanHeaderStatus("CANCELLED");
            const btnCancel = document.getElementById("btnCancelScan");
            if (btnCancel) btnCancel.style.display = "none";
        }
        loadScans();
    }
}

// REST Actions
async function launchScan() {
    const targetInput = document.getElementById("targetInput");
    const target = targetInput.value.trim();
    if (!target) {
        alert("Please enter a target domain, URL, or IP address.");
        return;
    }

    const payload = {
        target_url: target,
        profile: currentProfile,
        max_depth: parseInt(document.getElementById("optMaxDepth").value) || 2,
        concurrency: parseInt(document.getElementById("optConcurrency").value) || 5,
        auth_bearer_token: document.getElementById("optBearerToken").value.trim() || null
    };

    const customHeader = document.getElementById("optCustomHeader").value.trim();
    if (customHeader && customHeader.includes(":")) {
        const [k, v] = customHeader.split(":", 2);
        payload.custom_headers = { [k.trim()]: v.trim() };
    }

    const btn = document.getElementById("btnLaunch");
    btn.disabled = true;
    btn.innerHTML = `
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" class="spin"><circle cx="12" cy="12" r="10" stroke-dasharray="32" stroke-dashoffset="10"></circle></svg>
        <span>Dispatching...</span>
    `;

    try {
        const res = await fetch("/api/scans", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });

        if (!res.ok) {
            const err = await res.json();
            alert(`Error: ${err.detail || "Failed to start audit"}`);
            return;
        }

        const job = await res.json();
        targetInput.value = "";
        await loadScans();
        selectScan(job.id);
    } catch (e) {
        alert(`Failed to launch audit: ${e.message}`);
    } finally {
        btn.disabled = false;
        btn.innerHTML = `
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon>
            </svg>
            <span>Start Audit</span>
        `;
    }
}

async function loadScans() {
    try {
        const res = await fetch("/api/scans");
        const list = await res.json();
        
        const container = document.getElementById("scansList");
        if (!list || list.length === 0) {
            container.innerHTML = `<div style="color: var(--text-muted); font-size: 13px; text-align: center; padding: 24px;">No audits recorded yet.</div>`;
            return;
        }

        // Update overall KPIs
        document.getElementById("statTotalScans").textContent = list.length;
        let critTotal = 0, highMedTotal = 0, findingsTotal = 0;
        
        list.forEach(s => {
            scansData[s.id] = s;
            critTotal += s.critical_count || 0;
            highMedTotal += (s.high_count || 0) + (s.medium_count || 0);
            findingsTotal += s.findings_count || 0;
        });

        document.getElementById("statCritical").textContent = critTotal;
        document.getElementById("statHighMed").textContent = highMedTotal;
        document.getElementById("statVerifiedPoC").textContent = findingsTotal;

        container.innerHTML = list.map(s => `
            <div class="history-card ${s.id === currentScanId ? 'selected' : ''}" onclick="selectScan('${s.id}')">
                <div class="history-card-top">
                    <span class="history-domain" title="${s.target_url}">${s.target_url}</span>
                    <span class="badge-status status-${s.status}">${s.status}</span>
                </div>
                <div style="font-size: 11.5px; color: var(--brand); font-weight: 600; margin: 3px 0;">${s.current_phase || 'Active'}</div>
                <div style="font-size: 11.5px; color: var(--text-muted); display: flex; justify-content: space-between;">
                    <span>${s.profile}</span>
                    <span style="color: ${s.critical_count > 0 ? 'var(--crit)' : (s.findings_count > 0 ? 'var(--high)' : 'var(--text-muted)')}; font-weight: 700;">
                        ${s.findings_count} findings
                    </span>
                </div>
            </div>
        `).join("");

        // If nothing selected, select first
        if (!currentScanId && list.length > 0) {
            selectScan(list[0].id);
        }
    } catch (e) {
        console.error("Failed to load scans", e);
    }
}

async function selectScan(scanId) {
    currentScanId = scanId;
    
    // Highlight sidebar
    document.querySelectorAll(".history-card").forEach(item => item.classList.remove("selected"));
    
    document.getElementById("emptyDetailsNotice").style.display = "none";
    document.getElementById("activeDetailsContent").style.display = "block";

    try {
        const [scanRes, findingsRes, logsRes] = await Promise.all([
            fetch(`/api/scans/${scanId}`),
            fetch(`/api/scans/${scanId}/findings`),
            fetch(`/api/scans/${scanId}/logs`)
        ]);

        const scan = await scanRes.json();
        activeFindings = await findingsRes.json();
        const logs = await logsRes.json();

        scansData[scan.id] = scan;

        // Populate Header & Progress
        document.getElementById("activeScanTarget").textContent = scan.target_url;
        document.getElementById("activeScanId").textContent = scan.id;
        document.getElementById("activeScanProfile").textContent = scan.profile;
        updateScanHeaderStatus(scan.status);

        // Calculate Security Posture Score (0 - 100)
        let score = 100;
        score -= (scan.critical_count || 0) * 25;
        score -= (scan.high_count || 0) * 15;
        score -= (scan.medium_count || 0) * 8;
        score -= (scan.low_count || 0) * 2;
        score = Math.max(0, Math.min(100, score));

        let grade = "Grade A (Hardened)";
        let gradeClass = "score-A";
        if (score < 50) { grade = "Grade F (Critical Risk)"; gradeClass = "score-F"; }
        else if (score < 70) { grade = "Grade C (Elevated Risk)"; gradeClass = "score-C"; }
        else if (score < 85) { grade = "Grade B (Moderate Risk)"; gradeClass = "score-B"; }
        else { grade = "Grade A (Hardened)"; gradeClass = "score-A"; }

        const scoreEl = document.getElementById("activeScanScoreBadge");
        if (scoreEl) {
            scoreEl.className = `score-badge ${gradeClass}`;
            scoreEl.textContent = `Security Score: ${score}/100 (${grade})`;
        }

        setProgress(scan.progress_percent, scan.current_phase);

        // Cancel button visibility
        const btnCancel = document.getElementById("btnCancelScan");
        if (btnCancel) {
            btnCancel.style.display = scan.status === "RUNNING" ? "inline-flex" : "none";
        }

        // Reports links
        document.getElementById("btnReportHtml").href = `/api/scans/${scan.id}/report?format=html`;
        document.getElementById("btnReportSarif").href = `/api/scans/${scan.id}/report?format=sarif`;
        document.getElementById("btnReportJson").href = `/api/scans/${scan.id}/report?format=json`;
        document.getElementById("btnReportMd").href = `/api/scans/${scan.id}/report?format=markdown`;

        // Render Recon Chips
        renderReconChips(scan);

        // Render Findings
        renderFindings(activeFindings);

        // Render Subdomains & Fuzzing Assets
        const subs = (scan.recon_data && scan.recon_data.subdomains) ? scan.recon_data.subdomains : [];
        renderSubdomains(subs);

        const fuzzedPaths = (scan.recon_data && scan.recon_data.fuzzing_results) ? scan.recon_data.fuzzing_results : [];
        const fuzzedParams = (scan.recon_data && scan.recon_data.fuzzed_parameters) ? scan.recon_data.fuzzed_parameters : [];
        renderFuzzing(fuzzedPaths, fuzzedParams);

        // Load Blue Team Defenses (WAF, IDS, SIEM)
        loadDefenses();

        // Render Logs
        const term = document.getElementById("terminalLogs");
        term.innerHTML = "";
        logs.forEach(l => appendLog(l));

    } catch (e) {
        console.error("Failed to select scan", e);
    }
}

function updateScanHeaderStatus(status) {
    const pill = document.getElementById("activeScanStatusPill");
    if (pill) {
        pill.className = `badge-status status-${status}`;
        pill.textContent = status;
    }
}

function setProgress(percent, phase) {
    const bar = document.getElementById("activeScanProgressBar");
    const num = document.getElementById("activeScanProgressText");
    const ph = document.getElementById("activeScanPhase");
    if (bar) bar.style.width = `${percent}%`;
    if (num) num.textContent = `${percent}%`;
    if (ph) ph.textContent = phase || "Analyzing target surface...";
}

function updateScanInList(scanId, percent, phase) {
    const items = document.querySelectorAll(".history-card");
    items.forEach(item => {
        if (item.onclick && item.onclick.toString().includes(scanId)) {
            const phaseEl = item.querySelector("div:nth-child(2)");
            if (phaseEl) phaseEl.textContent = phase;
        }
    });
}

function renderSubdomains(subdomains) {
    const badge = document.getElementById("subdomainsCountBadge");
    const container = document.getElementById("subdomainsContainer");
    if (badge) badge.textContent = subdomains.length;

    if (!subdomains || subdomains.length === 0) {
        container.innerHTML = `<div style="color: var(--text-muted); text-align: center; padding: 40px;">No subdomains discovered or target is an IP.</div>`;
        return;
    }

    container.innerHTML = `
        <div style="background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.02);">
            <table style="width: 100%; border-collapse: collapse; text-align: left; font-size: 13px;">
                <thead>
                    <tr style="background: var(--bg-subtle); border-bottom: 1px solid var(--border); color: var(--text-muted); font-size: 11.5px; text-transform: uppercase;">
                        <th style="padding: 12px 16px;">Subdomain</th>
                        <th style="padding: 12px 16px;">IP Address</th>
                        <th style="padding: 12px 16px;">Status</th>
                        <th style="padding: 12px 16px;">Server</th>
                    </tr>
                </thead>
                <tbody>
                    ${subdomains.map(s => {
                        const subName = (typeof s === "string") ? s : (s.subdomain || "");
                        const ip = (typeof s === "object" && s.ip) ? s.ip : "Resolved";
                        const status = (typeof s === "object" && s.status) ? s.status : "Discovered";
                        const server = (typeof s === "object" && s.server) ? s.server : "--";
                        const statusClass = (status === 200) ? "status-COMPLETED" : ((status >= 400 && status < 500) ? "status-PENDING" : "status-RUNNING");

                        return `
                            <tr style="border-bottom: 1px solid var(--border);">
                                <td style="padding: 12px 16px; font-weight: 600; font-family: var(--mono); color: var(--brand);">
                                    <a href="https://${subName}" target="_blank" style="color: inherit; text-decoration: none;">${subName} ↗</a>
                                </td>
                                <td style="padding: 12px 16px; font-family: var(--mono); color: var(--text-muted);">${ip}</td>
                                <td style="padding: 12px 16px;">
                                    <span class="badge-status ${statusClass}">${status}</span>
                                </td>
                                <td style="padding: 12px 16px; color: var(--text-muted);">${server || "Standard"}</td>
                            </tr>
                        `;
                    }).join("")}
                </tbody>
            </table>
        </div>
    `;
}

function renderFuzzing(paths, parameters) {
    const totalCount = (paths.length || 0) + (parameters.length || 0);
    const badge = document.getElementById("fuzzingCountBadge");
    const container = document.getElementById("fuzzingContainer");
    if (badge) badge.textContent = totalCount;

    if (totalCount === 0) {
        container.innerHTML = `<div style="color: var(--text-muted); text-align: center; padding: 40px;">No anomalous fuzzed paths or hidden parameters detected yet.</div>`;
        return;
    }

    let pathsHtml = "";
    if (paths && paths.length > 0) {
        pathsHtml = `
            <h4 style="font-size: 14px; font-weight: 700; margin-bottom: 10px; color: var(--text-title);">Discovered Hidden Paths & Files (${paths.length})</h4>
            <div style="background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; margin-bottom: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.02);">
                <table style="width: 100%; border-collapse: collapse; text-align: left; font-size: 13px;">
                    <thead>
                        <tr style="background: var(--bg-subtle); border-bottom: 1px solid var(--border); color: var(--text-muted); font-size: 11.5px; text-transform: uppercase;">
                            <th style="padding: 10px 16px;">Path</th>
                            <th style="padding: 10px 16px;">Status</th>
                            <th style="padding: 10px 16px;">Length</th>
                            <th style="padding: 10px 16px;">Asset Title / Classification</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${paths.map(p => `
                            <tr style="border-bottom: 1px solid var(--border);">
                                <td style="padding: 10px 16px; font-weight: 600; font-family: var(--mono); color: var(--brand);">
                                    <a href="${p.url}" target="_blank" style="color: inherit; text-decoration: none;">${p.path} ↗</a>
                                </td>
                                <td style="padding: 10px 16px;"><span class="badge-status status-${p.status === 200 ? 'COMPLETED' : 'PENDING'}">HTTP ${p.status}</span></td>
                                <td style="padding: 10px 16px; font-family: var(--mono); color: var(--text-muted);">${p.content_length} B</td>
                                <td style="padding: 10px 16px; color: var(--text-body);">${p.title || p.content_type || 'Exposed Asset'}</td>
                            </tr>
                        `).join("")}
                    </tbody>
                </table>
            </div>
        `;
    }

    let paramsHtml = "";
    if (parameters && parameters.length > 0) {
        paramsHtml = `
            <h4 style="font-size: 14px; font-weight: 700; margin-bottom: 10px; color: var(--text-title);">Hidden Parameter Anomalies (${parameters.length})</h4>
            <div style="background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.02);">
                <table style="width: 100%; border-collapse: collapse; text-align: left; font-size: 13px;">
                    <thead>
                        <tr style="background: var(--bg-subtle); border-bottom: 1px solid var(--border); color: var(--text-muted); font-size: 11.5px; text-transform: uppercase;">
                            <th style="padding: 10px 16px;">Parameter</th>
                            <th style="padding: 10px 16px;">Behavior / Anomaly</th>
                            <th style="padding: 10px 16px;">Input Reflected</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${parameters.map(m => `
                            <tr style="border-bottom: 1px solid var(--border);">
                                <td style="padding: 10px 16px; font-weight: 700; font-family: var(--mono); color: var(--high);">?${m.parameter}=</td>
                                <td style="padding: 10px 16px; color: var(--text-body);">${m.anomaly_type}</td>
                                <td style="padding: 10px 16px;">
                                    <span class="badge-status ${m.reflected ? 'status-FAILED' : 'status-RUNNING'}">${m.reflected ? 'YES (High Risk)' : 'No'}</span>
                                </td>
                            </tr>
                        `).join("")}
                    </tbody>
                </table>
            </div>
        `;
    }

    container.innerHTML = pathsHtml + paramsHtml;
}

function renderReconChips(scan) {
    const container = document.getElementById("activeMetaChips");
    container.innerHTML = "";

    const chips = [];

    if (scan.recon_data) {
        const r = scan.recon_data;
        if (r.ip_addresses && r.ip_addresses.length > 0) {
            chips.push(`<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line></svg><span>IP: ${r.ip_addresses.join(", ")}</span>`);
        }
        if (r.technologies && r.technologies.length > 0) {
            r.technologies.forEach(t => {
                chips.push(`<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="12 2 2 7 12 12 22 7 12 2"></polygon><polyline points="2 17 12 22 22 17"></polyline><polyline points="2 12 12 17 22 12"></polyline></svg><span>${t.technology}</span>`);
            });
        }
        if (r.open_ports && r.open_ports.length > 0) {
            chips.push(`<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg><span>Ports: ${r.open_ports.map(p => p.port).join(", ")}</span>`);
        }
        if (r.ssl_info && r.ssl_info.issuer) {
            chips.push(`<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg><span>TLS Valid</span>`);
        }
        if (r.subdomains && r.subdomains.length > 0) {
            chips.push(`<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle></svg><span>${r.subdomains.length} Subdomains</span>`);
        }
        if (r.fuzzing_results && r.fuzzing_results.length > 0) {
            chips.push(`<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg><span>${r.fuzzing_results.length} Fuzzed Endpoints</span>`);
        }
    }

    if (scan.endpoints_count > 0) {
        chips.push(`<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"></path><circle cx="12" cy="10" r="3"></circle></svg><span>${scan.endpoints_count} Endpoints Mapped</span>`);
    }

    container.innerHTML = chips.map(c => `<div class="meta-pill">${c}</div>`).join("");
}

function renderFindings(findings) {
    const container = document.getElementById("findingsContainer");
    document.getElementById("findingsCountBadge").textContent = findings.length;

    if (!findings || findings.length === 0) {
        container.innerHTML = `<div style="color: var(--text-muted); text-align: center; padding: 40px;">No vulnerabilities confirmed yet. Probing target endpoints...</div>`;
        return;
    }

    container.innerHTML = findings.map(f => `
        <div class="vuln-card border-${f.severity}" onclick="openFindingModal('${f.id}')">
            <div class="vuln-header">
                <div style="display: flex; align-items: center; gap: 8px;">
                    <span class="sev-tag tag-${f.severity}">${f.severity}</span>
                    <span class="cvss-score">CVSS ${f.cvss_score}</span>
                    <strong style="font-size: 14.5px; font-weight: 700; color: var(--text-title);">${f.title}</strong>
                </div>
                <span class="poc-verified-pill">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>
                    PoC Verified
                </span>
            </div>
            <div style="color: var(--text-muted); font-size: 12.5px; margin-top: 6px;">
                <code style="color: var(--brand); font-weight: 600;">${f.method} ${f.endpoint}</code> | ${f.owasp_category || 'OWASP Top 10'}
            </div>
        </div>
    `).join("");
}

function appendLog(log) {
    const term = document.getElementById("terminalLogs");
    if (!term) return;
    const div = document.createElement("div");
    div.className = "log-entry";
    div.innerHTML = `
        <span class="log-time" style="color: #64748b;">[${log.timestamp || ''}]</span>
        <span class="log-agent" style="color: #38bdf8; font-weight: 600;">[${log.agent || 'SYSTEM'}]</span>
        <span style="color: #f8fafc;">${log.message || ''}</span>
    `;
    term.appendChild(div);
    term.scrollTop = term.scrollHeight;
}

function switchTab(tabId, btn) {
    document.querySelectorAll(".tab-content").forEach(el => el.style.display = "none");
    document.querySelectorAll(".tab-item").forEach(el => el.classList.remove("active"));
    
    const targetEl = document.getElementById(tabId);
    if (targetEl) targetEl.style.display = "block";
    if (btn) btn.classList.add("active");
}

// Modals
function openFindingModal(findingId) {
    const f = activeFindings.find(item => item.id === findingId);
    if (!f) return;

    document.getElementById("modalSevBadge").className = `sev-tag tag-${f.severity}`;
    document.getElementById("modalSevBadge").textContent = f.severity;
    document.getElementById("modalCvss").textContent = `CVSS ${f.cvss_score}`;
    document.getElementById("modalTitle").textContent = f.title;
    document.getElementById("modalEndpoint").textContent = `${f.method} ${f.endpoint}`;
    document.getElementById("modalOwasp").textContent = f.owasp_category || 'N/A';
    document.getElementById("modalCwe").textContent = f.cwe_id || 'N/A';
    document.getElementById("modalDesc").textContent = f.description;
    document.getElementById("modalPocCurl").textContent = f.poc_curl || `curl -i '${f.endpoint}'`;
    document.getElementById("modalExplanation").textContent = f.poc_explanation || 'Verified through active probe response anomaly.';
    document.getElementById("modalRemediationAdvice").textContent = f.remediation_advice || 'Apply strict input sanitization and parameterized queries.';

    const patchBox = document.getElementById("modalPatchContainer");
    if (f.remediation_patch) {
        patchBox.style.display = "block";
        document.getElementById("modalPatchCode").textContent = f.remediation_patch;
    } else {
        patchBox.style.display = "none";
    }

    document.getElementById("findingModal").classList.add("open");
}

function closeFindingModal() {
    document.getElementById("findingModal").classList.remove("open");
}

function copyModalCurl() {
    const text = document.getElementById("modalPocCurl").textContent;
    navigator.clipboard.writeText(text);
    alert("cURL Proof of Concept copied to clipboard!");
}

async function cancelActiveScan() {
    if (!currentScanId) return;
    try {
        await fetch(`/api/scans/${currentScanId}/cancel`, { method: "POST" });
    } catch (e) {
        console.error(e);
    }
}

async function deleteActiveScan() {
    if (!currentScanId) return;
    if (!confirm("Delete this scan record and its findings?")) return;

    try {
        await fetch(`/api/scans/${currentScanId}`, { method: "DELETE" });
        currentScanId = null;
        document.getElementById("activeDetailsContent").style.display = "none";
        document.getElementById("emptyDetailsNotice").style.display = "block";
        loadScans();
    } catch (e) {
        console.error(e);
    }
}

// AI Settings
async function loadSettings() {
    try {
        const res = await fetch("/api/settings");
        const cfg = await res.json();
        document.getElementById("setProvider").value = cfg.ai_provider || "auto";
        document.getElementById("setModel").value = cfg.ai_model || "";
        document.getElementById("setBaseUrl").value = cfg.ai_base_url || "";
    } catch (e) {
        console.error("Failed to load settings", e);
    }
}

function openSettingsModal() {
    document.getElementById("settingsModal").classList.add("open");
}

function closeSettingsModal() {
    document.getElementById("settingsModal").classList.remove("open");
}

async function saveSettings() {
    const payload = {
        ai_provider: document.getElementById("setProvider").value,
        ai_model: document.getElementById("setModel").value.trim() || null,
        ai_api_key: document.getElementById("setApiKey").value.trim() || null,
        ai_base_url: document.getElementById("setBaseUrl").value.trim() || null
    };

    try {
        await fetch("/api/settings", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        closeSettingsModal();
        alert("Configuration saved successfully.");
    } catch (e) {
        alert("Failed to save settings.");
    }
}

// OWASP Plugins Management
let pluginsData = [];

async function loadPlugins() {
    try {
        const res = await fetch("/api/plugins");
        pluginsData = await res.json();
        
        const badge = document.getElementById("pluginsCountBadge");
        if (badge) badge.textContent = pluginsData.length;

        renderPluginsList();
    } catch (e) {
        console.error("Failed to load plugins", e);
    }
}

function renderPluginsList() {
    if (!pluginsData || pluginsData.length === 0) return;

    const html = pluginsData.map(p => `
        <div class="plugin-item">
            <div style="flex: 1; margin-right: 16px;">
                <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px; flex-wrap: wrap;">
                    <span class="sev-tag tag-${p.default_severity}">${p.default_severity}</span>
                    <span class="cvss-score">${p.cwe_id}</span>
                    <strong style="font-size: 14px; color: var(--text-title);">${p.name}</strong>
                    <span style="font-size: 11px; color: var(--brand); font-weight: 700; background: var(--brand-light); padding: 2px 7px; border-radius: 4px;">${p.owasp_category.split('-')[0]}</span>
                </div>
                <p style="font-size: 12.5px; color: var(--text-muted); line-height: 1.4;">${p.description}</p>
            </div>
            <div>
                <label class="switch">
                    <input type="checkbox" ${p.enabled ? 'checked' : ''} onchange="togglePlugin('${p.id}', this.checked)">
                    <span class="slider"></span>
                </label>
            </div>
        </div>
    `).join("");

    const tabContainer = document.getElementById("tabPluginsListContainer");
    if (tabContainer) tabContainer.innerHTML = html;

    const modalContainer = document.getElementById("modalPluginsList");
    if (modalContainer) modalContainer.innerHTML = html;
}

async function togglePlugin(pluginId, isChecked) {
    try {
        await fetch(`/api/plugins/${pluginId}/toggle`, {
            method: "POST"
        });
        const p = pluginsData.find(item => item.id === pluginId);
        if (p) p.enabled = isChecked;
        renderPluginsList();
    } catch (e) {
        console.error("Failed to toggle plugin", e);
    }
}

function openPluginsModal() {
    loadPlugins();
    document.getElementById("pluginsModal").classList.add("open");
}

function closePluginsModal() {
    document.getElementById("pluginsModal").classList.remove("open");
}

// Blue Team Defenses (WAF, IDS, SIEM, Hardening)
async function loadDefenses() {
    if (!currentScanId) return;
    const container = document.getElementById("defensesContentArea");
    if (!container) return;

    try {
        const res = await fetch(`/api/scans/${currentScanId}/defenses`);
        if (!res.ok) {
            container.innerHTML = `<div style="color: var(--text-muted); text-align: center; padding: 40px;">Defensive rules unavailable for this scan.</div>`;
            return;
        }

        const data = await res.json();
        
        let html = `
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 14px; margin-bottom: 24px;">
                <div style="background: var(--bg-card); border: 1px solid var(--border); padding: 14px 18px; border-radius: 10px;">
                    <div style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">WAF Rules Generated</div>
                    <div style="font-size: 24px; font-weight: 800; color: var(--brand); margin-top: 2px;">${data.summary.generated_waf_rules}</div>
                </div>
                <div style="background: var(--bg-card); border: 1px solid var(--border); padding: 14px 18px; border-radius: 10px;">
                    <div style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">Suricata / Snort Signatures</div>
                    <div style="font-size: 24px; font-weight: 800; color: var(--safe); margin-top: 2px;">${data.summary.generated_ids_signatures}</div>
                </div>
                <div style="background: var(--bg-card); border: 1px solid var(--border); padding: 14px 18px; border-radius: 10px;">
                    <div style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">SIEM Detection Rules</div>
                    <div style="font-size: 24px; font-weight: 800; color: var(--high); margin-top: 2px;">${data.summary.generated_siem_rules}</div>
                </div>
            </div>
        `;

        // 1. WAF Rules Section
        html += `<h4 style="font-size: 14px; font-weight: 700; color: var(--text-title); margin-bottom: 10px;">🛡️ Web Application Firewall (WAF) Rules</h4>`;
        data.waf_rules.forEach((waf, idx) => {
            html += `
                <div style="background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; padding: 16px; margin-bottom: 16px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                        <span style="font-weight: 700; font-size: 13px; color: var(--brand);">${waf.type} (${waf.filename})</span>
                        <button class="btn btn-secondary" onclick="copyTextToClipboard(this, 'waf_rule_${idx}')" style="padding: 3px 10px; font-size: 11px;">📋 Copy</button>
                    </div>
                    <div class="code-terminal" id="waf_rule_${idx}" style="max-height: 240px; margin: 0;">${escapeHtml(waf.content)}</div>
                </div>
            `;
        });

        // 2. IDS / IPS Signatures
        html += `<h4 style="font-size: 14px; font-weight: 700; color: var(--text-title); margin-top: 24px; margin-bottom: 10px;">📡 Suricata & Snort IDS/IPS Signatures</h4>`;
        data.ids_signatures.forEach((ids, idx) => {
            html += `
                <div style="background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; padding: 16px; margin-bottom: 16px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                        <span style="font-weight: 700; font-size: 13px; color: var(--safe);">${ids.type} (${ids.filename})</span>
                        <button class="btn btn-secondary" onclick="copyTextToClipboard(this, 'ids_rule_${idx}')" style="padding: 3px 10px; font-size: 11px;">📋 Copy</button>
                    </div>
                    <div class="code-terminal" id="ids_rule_${idx}" style="max-height: 240px; margin: 0;">${escapeHtml(ids.content)}</div>
                </div>
            `;
        });

        // 3. SIEM Detection Rules
        html += `<h4 style="font-size: 14px; font-weight: 700; color: var(--text-title); margin-top: 24px; margin-bottom: 10px;">🔍 SIEM Detection Rules (Sigma / Splunk / Elastic)</h4>`;
        data.siem_rules.forEach((siem, idx) => {
            html += `
                <div style="background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; padding: 16px; margin-bottom: 16px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                        <span style="font-weight: 700; font-size: 13px; color: var(--high);">${siem.type} (${siem.filename})</span>
                        <button class="btn btn-secondary" onclick="copyTextToClipboard(this, 'siem_rule_${idx}')" style="padding: 3px 10px; font-size: 11px;">📋 Copy</button>
                    </div>
                    <div class="code-terminal" id="siem_rule_${idx}" style="max-height: 240px; margin: 0;">${escapeHtml(siem.content)}</div>
                </div>
            `;
        });

        // 4. Server Hardening
        html += `<h4 style="font-size: 14px; font-weight: 700; color: var(--text-title); margin-top: 24px; margin-bottom: 10px;">🔒 Server Hardening Blocks (Nginx & Apache)</h4>`;
        data.server_hardening.forEach((srv, idx) => {
            html += `
                <div style="background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; padding: 16px; margin-bottom: 16px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                        <span style="font-weight: 700; font-size: 13px; color: var(--text-title);">${srv.type} (${srv.filename})</span>
                        <button class="btn btn-secondary" onclick="copyTextToClipboard(this, 'srv_rule_${idx}')" style="padding: 3px 10px; font-size: 11px;">📋 Copy</button>
                    </div>
                    <div class="code-terminal" id="srv_rule_${idx}" style="max-height: 240px; margin: 0;">${escapeHtml(srv.content)}</div>
                </div>
            `;
        });

        container.innerHTML = html;
    } catch (e) {
        console.error("Failed to load defenses", e);
    }
}

function escapeHtml(text) {
    if (!text) return "";
    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function copyTextToClipboard(btn, elementId) {
    const el = document.getElementById(elementId);
    if (!el) return;
    navigator.clipboard.writeText(el.innerText || el.textContent);
    const orig = btn.innerHTML;
    btn.innerHTML = "✓ Copied!";
    setTimeout(() => { btn.innerHTML = orig; }, 1800);
}
