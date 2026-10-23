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

        // Calculate Advanced Multi-Dimensional Security Posture Score (0 - 100)
        let score = 100;
        const crit = scan.critical_count || 0;
        const high = scan.high_count || 0;
        const med = scan.medium_count || 0;
        const low = scan.low_count || 0;

        score -= crit * 30;
        score -= high * 18;
        score -= med * 8;
        score -= low * 4;

        // Evaluate defense-in-depth deductions
        if (activeFindings && activeFindings.length > 0) {
            const hasHstsMissing = activeFindings.some(f => f.title.includes("HSTS"));
            const hasCspMissing = activeFindings.some(f => f.title.includes("CSP") || f.title.includes("Content Security Policy"));
            const hasClickjacking = activeFindings.some(f => f.title.includes("Clickjacking"));
            if (hasHstsMissing) score -= 6;
            if (hasCspMissing) score -= 6;
            if (hasClickjacking) score -= 5;
        }

        score = Math.max(0, Math.min(100, Math.round(score)));

        // Strict Industry-Standard Grade Classification
        let grade = "Grade A (Hardened)";
        let gradeClass = "score-A";

        if (crit > 0 || score < 45) {
            grade = "Grade F (Critical Risk)";
            gradeClass = "score-F";
            score = Math.min(score, 40);
        } else if (high > 0 || score < 65) {
            grade = "Grade D (Elevated Risk)";
            gradeClass = "score-F";
            score = Math.min(score, 60);
        } else if (med > 0 || score < 80) {
            grade = "Grade C (Moderate Exposure)";
            gradeClass = "score-C";
        } else if (low > 0 || score < 92) {
            grade = "Grade B (Minor Weaknesses)";
            gradeClass = "score-B";
        } else {
            grade = "Grade A (Hardened)";
            gradeClass = "score-A";
        }

        const scoreEl = document.getElementById("activeScanScoreBadge");
        if (scoreEl) {
            scoreEl.className = `score-badge ${gradeClass}`;
            scoreEl.textContent = `Security Posture: ${score}/100 (${grade})`;
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

        // Load Correlated Threat Hunting Queries
        loadScanForensicsCorrelation();

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

function copyRawText(btn, text) {
    navigator.clipboard.writeText(text);
    const orig = btn.innerHTML;
    btn.innerHTML = "✓ Copied!";
    setTimeout(() => { btn.innerHTML = orig; }, 1800);
}

// ==========================================
// Digital Forensics & Attack Footprints (DFIR)
// ==========================================

let forensicsSamplesCache = null;

async function loadForensicsPreset(key) {
    try {
        if (!forensicsSamplesCache) {
            const res = await fetch("/api/forensics/samples");
            if (res.ok) {
                forensicsSamplesCache = await res.json();
            }
        }
        if (forensicsSamplesCache && forensicsSamplesCache[key]) {
            const sample = forensicsSamplesCache[key];
            const input = document.getElementById("forensicsLogInput");
            if (input) {
                input.value = sample.logs.trim();
                updateForensicsLineCount();
                runForensicsAnalysis();
            }
        }
    } catch (e) {
        console.error("Failed to load forensics preset", e);
    }
}

function updateForensicsLineCount() {
    const input = document.getElementById("forensicsLogInput");
    const counter = document.getElementById("forensicsLineCount");
    if (!input || !counter) return;
    const lines = input.value.split("\n").filter(l => l.trim().length > 0);
    counter.textContent = `${lines.length} lines loaded`;
}

function clearForensicsInput() {
    const input = document.getElementById("forensicsLogInput");
    if (input) input.value = "";
    updateForensicsLineCount();
    const container = document.getElementById("forensicsResultsArea");
    if (container) {
        container.innerHTML = `
            <div style="background: var(--bg-subtle); border: 1px dashed var(--border); border-radius: 12px; padding: 36px 20px; text-align: center; color: var(--text-muted);">
                <div style="font-size: 14px; font-weight: 600; color: var(--text-title); margin-bottom: 4px;">Forensic Analyzer Cleared</div>
                <div style="font-size: 12px; max-width: 500px; margin: 0 auto;">
                    Paste web/server logs above or click a 1-click scenario to extract attack footprints.
                </div>
            </div>
        `;
    }
}

function handleForensicsFileUpload(event) {
    const file = event.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = function(e) {
        const text = e.target.result;
        const input = document.getElementById("forensicsLogInput");
        if (input) {
            input.value = text;
            updateForensicsLineCount();
            runForensicsAnalysis();
        }
    };
    reader.readAsText(file);
}

async function runForensicsAnalysis() {
    const input = document.getElementById("forensicsLogInput");
    const container = document.getElementById("forensicsResultsArea");
    const btn = document.getElementById("btnRunForensics");
    if (!input || !container) return;

    const rawLogs = input.value.trim();
    if (!rawLogs) {
        alert("Please paste server logs or select a 1-click scenario first.");
        return;
    }

    if (btn) btn.innerHTML = `<span>Analyzing...</span>`;
    container.innerHTML = `<div style="text-align: center; padding: 40px; color: var(--brand); font-weight: 600;">Parsing logs and correlating MITRE ATT&CK footprints...</div>`;

    try {
        const res = await fetch("/api/forensics/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ raw_logs: rawLogs })
        });

        if (!res.ok) {
            const err = await res.json();
            throw new Error(err.detail || "Forensic analysis failed");
        }

        const data = await res.json();
        renderForensicsResults(data);
    } catch (e) {
        container.innerHTML = `<div style="color: var(--crit); text-align: center; padding: 30px;">Error: ${e.message}</div>`;
    } finally {
        if (btn) btn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg><span>Analyze Footprints</span>`;
    }
}

function renderForensicsResults(data) {
    const container = document.getElementById("forensicsResultsArea");
    if (!container) return;

    const s = data.summary;
    let bannerClass = "forensics-banner-CLEAN";
    let statusPill = "SAFE";
    if (s.threat_level.includes("CRITICAL")) {
        bannerClass = "forensics-banner-CRITICAL";
        statusPill = "CRITICAL INTRUSION";
    } else if (s.threat_level.includes("HIGH")) {
        bannerClass = "forensics-banner-HIGH";
        statusPill = "HIGH THREAT";
    } else if (s.threat_level.includes("SUSPICIOUS")) {
        bannerClass = "forensics-banner-SUSPICIOUS";
        statusPill = "SUSPICIOUS ACTIVITY";
    }

    let html = `
        <!-- Threat Posture Banner -->
        <div class="forensics-banner ${bannerClass}">
            <div style="flex: 1; min-width: 260px;">
                <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 4px;">
                    <span style="font-size: 11px; font-weight: 800; padding: 3px 8px; border-radius: 6px; background: rgba(0,0,0,0.3); text-transform: uppercase;">
                        ${statusPill}
                    </span>
                    <strong style="font-size: 15px;">${escapeHtml(s.threat_headline)}</strong>
                </div>
                <p style="font-size: 12.5px; opacity: 0.9; margin: 0;">${escapeHtml(s.threat_advice)}</p>
            </div>
        </div>

        <!-- 4-Stat Metric Cards -->
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; margin-bottom: 24px;">
            <div style="background: var(--bg-card); border: 1px solid var(--border); padding: 14px 18px; border-radius: 10px;">
                <div style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">Lines Analyzed</div>
                <div style="font-size: 24px; font-weight: 800; color: var(--text-title); margin-top: 2px;">${s.total_lines_analyzed}</div>
            </div>
            <div style="background: var(--bg-card); border: 1px solid var(--border); padding: 14px 18px; border-radius: 10px;">
                <div style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">Attack Footprints</div>
                <div style="font-size: 24px; font-weight: 800; color: var(--brand); margin-top: 2px;">${s.total_attack_footprints}</div>
            </div>
            <div style="background: var(--bg-card); border: 1px solid var(--border); padding: 14px 18px; border-radius: 10px;">
                <div style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">Threat Actor IPs</div>
                <div style="font-size: 24px; font-weight: 800; color: var(--high); margin-top: 2px;">${s.unique_threat_actors}</div>
            </div>
            <div style="background: var(--bg-card); border: 1px solid var(--border); padding: 14px 18px; border-radius: 10px;">
                <div style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">Critical Exploits</div>
                <div style="font-size: 24px; font-weight: 800; color: var(--crit); margin-top: 2px;">${s.critical_incidents}</div>
            </div>
        </div>

        <!-- Category Breakdown Badges -->
        <div style="background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; padding: 14px 18px; margin-bottom: 24px;">
            <div style="font-size: 12px; font-weight: 700; color: var(--text-title); margin-bottom: 10px;">
                MITRE ATT&CK & Web Vector Footprints:
            </div>
            <div style="display: flex; gap: 8px; flex-wrap: wrap;">
    `;

    for (const [cat, cnt] of Object.entries(data.category_breakdown)) {
        html += `
            <div style="background: var(--bg-subtle); border: 1px solid var(--border); padding: 5px 12px; border-radius: 8px; font-size: 12px; display: inline-flex; align-items: center; gap: 6px;">
                <span style="font-weight: 600; color: var(--text-title);">${escapeHtml(cat)}</span>
                <span style="background: var(--brand-light); color: #818cf8; font-weight: 800; font-size: 11px; padding: 1px 6px; border-radius: 4px;">${cnt}</span>
            </div>
        `;
    }

    html += `
            </div>
        </div>

        <!-- Hostile Attacker IPs & Cross-Platform Firewall Containment -->
        <div style="margin-bottom: 24px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                <h4 style="font-size: 14px; font-weight: 700; color: var(--text-title); margin: 0;">
                    🛡️ Identified Malicious Threat Actors & OS Firewall Drop Commands
                </h4>
                <span class="os-pill">Cross-Platform Containment</span>
            </div>
            <div style="display: flex; flex-direction: column; gap: 12px;">
    `;

    if (data.top_threat_actors.length === 0) {
        html += `<div style="color: var(--text-muted); font-size: 12px; padding: 14px; background: var(--bg-card); border-radius: 8px;">No malicious IPs identified.</div>`;
    } else {
        data.top_threat_actors.forEach((actor, idx) => {
            html += `
                <div style="background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; padding: 14px 18px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; flex-wrap: wrap; gap: 8px;">
                        <div style="display: flex; align-items: center; gap: 10px;">
                            <span style="font-family: var(--mono); font-size: 14px; font-weight: 800; color: #f87171;">${actor.ip}</span>
                            <span style="font-size: 11px; background: rgba(248, 81, 73, 0.15); color: #f87171; padding: 2px 8px; border-radius: 4px; font-weight: 700;">
                                ${actor.incident_count} malicious requests
                            </span>
                        </div>
                    </div>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 10px;">
                        <div style="background: #090d13; border: 1px solid var(--border); border-radius: 6px; padding: 8px 10px;">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                                <span class="os-pill" style="color: #60a5fa;">🐧 Linux (iptables / ufw)</span>
                                <button class="btn btn-secondary" onclick="copyRawText(this, '${escapeHtml(actor.os_block_linux)}')" style="padding: 2px 6px; font-size: 10px;">Copy</button>
                            </div>
                            <code style="font-family: var(--mono); font-size: 11px; color: #94a3b8; display: block; word-break: break-all;">${escapeHtml(actor.os_block_linux)}</code>
                        </div>
                        <div style="background: #090d13; border: 1px solid var(--border); border-radius: 6px; padding: 8px 10px;">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                                <span class="os-pill" style="color: #38bdf8;">🪟 Windows (netsh firewall)</span>
                                <button class="btn btn-secondary" onclick="copyRawText(this, '${escapeHtml(actor.os_block_windows)}')" style="padding: 2px 6px; font-size: 10px;">Copy</button>
                            </div>
                            <code style="font-family: var(--mono); font-size: 11px; color: #94a3b8; display: block; word-break: break-all;">${escapeHtml(actor.os_block_windows)}</code>
                        </div>
                        <div style="background: #090d13; border: 1px solid var(--border); border-radius: 6px; padding: 8px 10px;">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                                <span class="os-pill" style="color: #fb923c;">☁️ Cloudflare / WAF</span>
                                <button class="btn btn-secondary" onclick="copyRawText(this, '${escapeHtml(actor.cloudflare_waf)}')" style="padding: 2px 6px; font-size: 10px;">Copy</button>
                            </div>
                            <code style="font-family: var(--mono); font-size: 11px; color: #94a3b8; display: block; word-break: break-all;">${escapeHtml(actor.cloudflare_waf)}</code>
                        </div>
                    </div>
                </div>
            `;
        });
    }

    html += `
            </div>
        </div>

        <!-- Attack Footprints Timeline Table -->
        <div style="background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; padding: 18px; margin-bottom: 24px; overflow-x: auto;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                <h4 style="font-size: 14px; font-weight: 700; color: var(--text-title); margin: 0;">
                    🔍 Chronological Attack Footprint Records (${data.footprints.length} events)
                </h4>
            </div>
            <table class="forensics-table">
                <thead>
                    <tr>
                        <th style="width: 40px;">Line</th>
                        <th>Timestamp</th>
                        <th>Attacker IP</th>
                        <th>Category & MITRE</th>
                        <th>Method & Target URI</th>
                        <th>Status</th>
                        <th>Matched Payload Footprint</th>
                    </tr>
                </thead>
                <tbody>
    `;

    data.footprints.forEach(fp => {
        const sevColor = fp.severity === "CRITICAL" ? "#f87171" : (fp.severity === "HIGH" ? "#fb923c" : "#facc15");
        const statusBadge = fp.potential_success 
            ? `<span style="background: rgba(248, 81, 73, 0.2); color: #f87171; font-weight: 800; padding: 2px 6px; border-radius: 4px; font-size: 11px;">${fp.status} (EXPLOITED)</span>`
            : `<span style="background: var(--bg-subtle); color: var(--text-muted); font-weight: 600; padding: 2px 6px; border-radius: 4px; font-size: 11px;">${fp.status || '-'}</span>`;

        html += `
            <tr>
                <td style="font-family: var(--mono); color: var(--text-muted);">${fp.line}</td>
                <td style="font-size: 11px; white-space: nowrap; color: var(--text-muted);">${escapeHtml(fp.timestamp)}</td>
                <td style="font-family: var(--mono); font-weight: 700; color: var(--text-title);">${escapeHtml(fp.ip)}</td>
                <td>
                    <span style="color: ${sevColor}; font-weight: 700; font-size: 11.5px;">${escapeHtml(fp.category)}</span>
                    <div style="font-size: 10px; color: var(--text-muted);">${escapeHtml(fp.mitre)}</div>
                </td>
                <td style="font-family: var(--mono); font-size: 11.5px; word-break: break-all; max-width: 280px;">
                    <span style="color: var(--brand); font-weight: 700;">${escapeHtml(fp.method)}</span> 
                    <span style="color: #cbd5e1;">${escapeHtml(fp.uri)}</span>
                </td>
                <td>${statusBadge}</td>
                <td>
                    <code style="font-family: var(--mono); font-size: 11px; color: #38bdf8; background: #090d13; padding: 3px 6px; border-radius: 4px; display: inline-block;">
                        ${escapeHtml(fp.matched_token)}
                    </code>
                </td>
            </tr>
        `;
    });

    html += `
                </tbody>
            </table>
        </div>

        <!-- Cross-Platform Incident Response Playbook -->
        <div style="background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; padding: 20px; margin-bottom: 24px;">
            <h4 style="font-size: 14px; font-weight: 700; color: var(--text-title); margin-bottom: 14px; display: flex; align-items: center; gap: 8px;">
                <span>📋 Cross-Platform Incident Response (DFIR) Playbook</span>
            </h4>
            <div style="display: flex; flex-direction: column; gap: 16px;">
    `;

    data.containment_playbook.forEach(step => {
        html += `
            <div style="background: var(--bg-subtle); border: 1px solid var(--border); border-radius: 8px; padding: 14px;">
                <div style="font-weight: 700; font-size: 13px; color: var(--text-title); margin-bottom: 4px;">${escapeHtml(step.step)}</div>
                <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 10px;">${escapeHtml(step.action)}</div>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 10px;">
                    <div style="background: #090d13; padding: 8px; border-radius: 6px; border: 1px solid var(--border);">
                        <div style="font-size: 10px; font-weight: 700; color: #60a5fa; margin-bottom: 2px;">🐧 Linux</div>
                        <code style="font-family: var(--mono); font-size: 11px; color: #cbd5e1; word-break: break-all;">${escapeHtml(step.linux_cmd)}</code>
                    </div>
                    <div style="background: #090d13; padding: 8px; border-radius: 6px; border: 1px solid var(--border);">
                        <div style="font-size: 10px; font-weight: 700; color: #38bdf8; margin-bottom: 2px;">🪟 Windows PowerShell</div>
                        <code style="font-family: var(--mono); font-size: 11px; color: #cbd5e1; word-break: break-all;">${escapeHtml(step.windows_cmd)}</code>
                    </div>
                    <div style="background: #090d13; padding: 8px; border-radius: 6px; border: 1px solid var(--border);">
                        <div style="font-size: 10px; font-weight: 700; color: #fb923c; margin-bottom: 2px;">🍏 macOS / BSD</div>
                        <code style="font-family: var(--mono); font-size: 11px; color: #cbd5e1; word-break: break-all;">${escapeHtml(step.macos_cmd)}</code>
                    </div>
                </div>
            </div>
        `;
    });

    html += `
            </div>
        </div>
    `;

    container.innerHTML = html;
}

// Correlate current scan findings with forensic hunt patterns
async function loadScanForensicsCorrelation() {
    if (!currentScanId) return;
    const container = document.getElementById("forensicsScanCorrelationArea");
    if (!container) return;

    try {
        const res = await fetch(`/api/scans/${currentScanId}/forensics`);
        if (!res.ok) return;
        const data = await res.json();

        if (!data.threat_hunt_profiles || data.threat_hunt_profiles.length === 0) {
            container.style.display = "none";
            return;
        }

        container.style.display = "block";
        let html = `
            <div style="background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; padding: 18px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; flex-wrap: wrap; gap: 8px;">
                    <div>
                        <h4 style="font-size: 14px; font-weight: 700; color: var(--text-title); margin: 0;">
                            🎯 Threat Hunt Queries for Discovered Findings on ${escapeHtml(data.target)}
                        </h4>
                        <p style="font-size: 12px; color: var(--text-muted); margin-top: 2px;">
                            Run these commands on your web servers or SIEM to identify if anyone has probed or exploited these exact endpoints.
                        </p>
                    </div>
                    <span class="tab-badge" style="background: var(--brand-light); color: #818cf8;">${data.total_findings} findings monitored</span>
                </div>
                <div style="display: flex; flex-direction: column; gap: 12px;">
        `;

        data.threat_hunt_profiles.forEach((hunt, idx) => {
            html += `
                <div style="background: var(--bg-subtle); border: 1px solid var(--border); border-radius: 8px; padding: 12px 14px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                        <span style="font-weight: 700; font-size: 12.5px; color: var(--text-title);">
                            [${hunt.severity}] ${escapeHtml(hunt.title)} (${escapeHtml(hunt.endpoint)})
                        </span>
                    </div>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 8px;">
                        <div style="background: #090d13; padding: 8px; border-radius: 6px; border: 1px solid var(--border);">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                                <span style="font-size: 10px; font-weight: 700; color: #60a5fa;">🐧 Linux Grep</span>
                                <button class="btn btn-secondary" onclick="copyRawText(this, '${escapeHtml(hunt.grep_command)}')" style="padding: 1px 6px; font-size: 10px;">Copy</button>
                            </div>
                            <code style="font-family: var(--mono); font-size: 10.5px; color: #94a3b8; display: block; word-break: break-all;">${escapeHtml(hunt.grep_command)}</code>
                        </div>
                        <div style="background: #090d13; padding: 8px; border-radius: 6px; border: 1px solid var(--border);">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                                <span style="font-size: 10px; font-weight: 700; color: #38bdf8;">🪟 Windows PowerShell</span>
                                <button class="btn btn-secondary" onclick="copyRawText(this, '${escapeHtml(hunt.powershell_command)}')" style="padding: 1px 6px; font-size: 10px;">Copy</button>
                            </div>
                            <code style="font-family: var(--mono); font-size: 10.5px; color: #94a3b8; display: block; word-break: break-all;">${escapeHtml(hunt.powershell_command)}</code>
                        </div>
                    </div>
                </div>
            `;
        });

        html += `
                </div>
            </div>
        `;
        container.innerHTML = html;
    } catch (e) {
        console.error("Failed to load forensics correlation", e);
    }
}

// Jump directly to Forensics section from anywhere
function openForensicsDirect() {
    const pane = document.getElementById("activeDetailsContent");
    const emptyNotice = document.getElementById("emptyDetailsNotice");
    if (pane && pane.style.display === "none") {
        const firstHistory = document.querySelector(".history-card");
        if (firstHistory) {
            firstHistory.click();
        } else {
            pane.style.display = "block";
            if (emptyNotice) emptyNotice.style.display = "none";
        }
    }

    const tabBtn = document.querySelector("button[onclick*='tabForensics']");
    switchTab('tabForensics', tabBtn);

    const forensicsEl = document.getElementById("tabForensics");
    if (forensicsEl) {
        forensicsEl.scrollIntoView({ behavior: "smooth", block: "start" });
    }
}

// Add real-time line count listener
document.addEventListener("DOMContentLoaded", () => {
    const logArea = document.getElementById("forensicsLogInput");
    if (logArea) {
        logArea.addEventListener("input", updateForensicsLineCount);
    }
});

