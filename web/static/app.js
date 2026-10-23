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

    // Bidirectional sync between top search input and all tools input
    const atTargetInput = document.getElementById("allToolsTarget");
    if (input && atTargetInput) {
        input.addEventListener("input", () => {
            atTargetInput.value = input.value;
        });
        atTargetInput.addEventListener("input", () => {
            input.value = atTargetInput.value;
        });
        atTargetInput.addEventListener("keypress", (e) => {
            if (e.key === "Enter") runAllTools();
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
    if (profile === "all_tools") {
        const atSection = document.getElementById("allToolsSection");
        if (atSection) {
            if (typeof atCollapsed !== "undefined" && atCollapsed) toggleAllTools();
            atSection.scrollIntoView({ behavior: "smooth", block: "start" });
        }
        const mainVal = document.getElementById("targetInput")?.value.trim() || "";
        const atInput = document.getElementById("allToolsTarget");
        if (atInput && mainVal) atInput.value = mainVal;
    }
}

// Direct Jump from Top Navigation
function openAllToolsDirect() {
    const pill = document.querySelector('.pill-item[data-profile="all_tools"]');
    if (pill) {
        selectProfile('all_tools', pill);
    } else {
        currentProfile = 'all_tools';
    }
    const atSection = document.getElementById("allToolsSection");
    if (atSection) {
        if (typeof atCollapsed !== "undefined" && atCollapsed) toggleAllTools();
        atSection.scrollIntoView({ behavior: "smooth", block: "start" });
    }
    const mainVal = document.getElementById("targetInput")?.value.trim() || "";
    const atInput = document.getElementById("allToolsTarget");
    if (atInput) {
        if (mainVal) atInput.value = mainVal;
        atInput.focus();
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

    if (currentProfile === "all_tools") {
        const atInput = document.getElementById("allToolsTarget");
        if (atInput) atInput.value = target;
        runAllTools();
        const atSection = document.getElementById("allToolsSection");
        if (atSection) {
            if (typeof atCollapsed !== "undefined" && atCollapsed) toggleAllTools();
            atSection.scrollIntoView({ behavior: "smooth", block: "start" });
        }
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
        const btnPdf = document.getElementById("btnReportPdf");
        if (btnPdf) btnPdf.href = `/api/scans/${scan.id}/report?format=pdf`;
        const btnCsv = document.getElementById("btnReportCsv");
        if (btnCsv) btnCsv.href = `/api/scans/${scan.id}/report?format=csv`;

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





/* ================================================================
   ALL TOOLS — Unified Threat Intelligence Hub  (v11.0)
   ================================================================ */

// ── State ──────────────────────────────────────────────────────
let atAllToolsData = {};
let atScanId = null;
let atPollTimer = null;
let atSelectedTools = new Set(['pentest','recon','fuzzer','waf','forensics','siem']);
let atCollapsed = false;

// ── Toggle tool pill selection ──────────────────────────────────
function toggleToolCheck(name, el) {
    el.classList.toggle('active');
    if (atSelectedTools.has(name)) {
        atSelectedTools.delete(name);
    } else {
        atSelectedTools.add(name);
    }
}

// ── Collapse / expand section body ─────────────────────────────
function toggleAllTools() {
    atCollapsed = !atCollapsed;
    const body = document.getElementById('allToolsBody');
    const results = document.getElementById('allToolsResults');
    const label = document.getElementById('allToolsToggleLabel');
    const arrow = document.getElementById('allToolsArrowIcon');
    if (atCollapsed) {
        if (body) body.style.display = 'none';
        if (results) results.style.display = 'none';
        if (label) label.textContent = 'Expand';
        if (arrow) arrow.innerHTML = '<polyline points="6 9 12 15 18 9"></polyline>';
    } else {
        if (body) body.style.display = '';
        if (label) label.textContent = 'Collapse';
        if (arrow) arrow.innerHTML = '<polyline points="18 15 12 9 6 15"></polyline>';
    }
}

// ── Progress bar helper ─────────────────────────────────────────
function atSetProgress(pct, statusText, subText) {
    const bar = document.getElementById('atProgressBar');
    const st = document.getElementById('atStatusText');
    const ss = document.getElementById('atStatusSub');
    if (bar) bar.style.width = pct + '%';
    if (st && statusText) st.textContent = statusText;
    if (ss && subText !== undefined) ss.textContent = subText;
}

function atSetBadge(panelKey, text, cls) {
    const el = document.getElementById('atBadge_' + panelKey);
    if (!el) return;
    el.textContent = text;
    el.className = 'at-panel-badge' + (cls ? ' ' + cls : '');
}

function atSetBody(panelKey, html) {
    const el = document.getElementById('atBody_' + panelKey);
    if (el) el.innerHTML = html;
}

// ── Main orchestrator ───────────────────────────────────────────
async function runAllTools() {
    const targetInput = document.getElementById('allToolsTarget');
    let rawTarget = targetInput ? targetInput.value.trim() : '';
    if (!rawTarget) {
        const mainInput = document.getElementById('targetInput');
        if (mainInput && mainInput.value.trim()) {
            rawTarget = mainInput.value.trim();
            if (targetInput) targetInput.value = rawTarget;
        }
    }
    if (!rawTarget) {
        if (targetInput) {
            targetInput.focus();
            targetInput.style.borderColor = '#f85149';
            setTimeout(() => { targetInput.style.borderColor = ''; }, 1800);
        }
        return;
    }
    // Also mirror to top input
    const mainInput = document.getElementById('targetInput');
    if (mainInput && !mainInput.value.trim()) mainInput.value = rawTarget;

    // Normalize target URL
    let target = rawTarget;
    if (!target.startsWith('http://') && !target.startsWith('https://')) {
        target = 'https://' + target;
    }

    // Reset UI
    atAllToolsData = { target: rawTarget, startedAt: new Date().toISOString() };
    atScanId = null;
    clearInterval(atPollTimer);

    const resultsEl = document.getElementById('allToolsResults');
    if (resultsEl) resultsEl.style.display = '';

    const summaryRow = document.getElementById('atSummaryRow');
    if (summaryRow) summaryRow.style.display = 'none';
    const exportRow = document.getElementById('atExportRow');
    if (exportRow) exportRow.style.display = 'none';

    ['recon','pentest','fuzzer','waf','forensics','siem'].forEach(k => {
        atSetBody(k, '<div class="at-pending-msg">⏳ Starting scan…</div>');
        atSetBadge(k, 'Running…', 'badge-running');
    });
    atSetProgress(5, '🔍 Launching unified scan for ' + rawTarget + '…', 'Creating scan job…');

    const btn = document.getElementById('btnRunAllTools');
    if (btn) { btn.disabled = true; btn.querySelector('span').textContent = 'Running…'; }

    try {
        // 1. Start scan
        atSetProgress(8, 'Creating scan…', 'POST /api/scans');
        const scanRes = await fetch('/api/scans', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target_url: target, profile: 'full_red_team', include_subdomains: true })
        });
        if (!scanRes.ok) throw new Error('Scan create failed: ' + scanRes.status);
        const scanObj = await scanRes.json();
        atScanId = scanObj.scan_id || scanObj.id || (scanObj.scan && scanObj.scan.scan_id);
        if (!atScanId) throw new Error('No scan ID returned');

        atSetProgress(12, '🚀 Scan running…', 'Scan ID: ' + atScanId);

        // 2. Poll for completion
        await new Promise((resolve, reject) => {
            let elapsed = 0;
            atPollTimer = setInterval(async () => {
                elapsed++;
                try {
                    const pollRes = await fetch('/api/scans/' + atScanId);
                    if (!pollRes.ok) { clearInterval(atPollTimer); reject(new Error('Poll failed')); return; }
                    const poll = await pollRes.json();
                    const scan = poll.scan || poll;
                    const progress = scan.progress_percent || Math.min(elapsed * 4, 85);
                    const status = (scan.status || '').toUpperCase();

                    atSetProgress(Math.max(12, progress),
                        status === 'RUNNING' ? '🔄 Scanning ' + rawTarget + '…' : '✅ Scan complete',
                        'Status: ' + status + '  |  Progress: ' + Math.round(progress) + '%'
                    );

                    // Update recon panel incrementally
                    if (scan.recon_data && !atAllToolsData.reconRendered) {
                        atRenderRecon(scan.recon_data);
                        atAllToolsData.reconRendered = true;
                    }

                    if (status === 'COMPLETED' || status === 'DONE' || status === 'FINISHED') {
                        clearInterval(atPollTimer);
                        atAllToolsData.scan = scan;
                        resolve(scan);
                    } else if (status === 'FAILED' || status === 'ERROR') {
                        clearInterval(atPollTimer);
                        reject(new Error('Scan failed: ' + (scan.error || status)));
                    } else if (elapsed > 90) {
                        // 3-min timeout — render whatever we have
                        clearInterval(atPollTimer);
                        atAllToolsData.scan = scan;
                        resolve(scan);
                    }
                } catch (e) {
                    clearInterval(atPollTimer);
                    reject(e);
                }
            }, 2000);
        });

        atSetProgress(90, '📊 Fetching results…', 'Loading findings, defenses & forensics…');

        // 3. Fetch all data in parallel
        const scan = atAllToolsData.scan;
        const [findingsRes, defensesRes, forensicsRes] = await Promise.allSettled([
            fetch('/api/scans/' + atScanId + '/findings').then(r => r.json()),
            fetch('/api/scans/' + atScanId + '/defenses').then(r => r.json()),
            fetch('/api/scans/' + atScanId + '/forensics').then(r => r.json())
        ]);

        const findings = findingsRes.status === 'fulfilled' ? (findingsRes.value.findings || findingsRes.value || []) : [];
        const defenses = defensesRes.status === 'fulfilled' ? (defensesRes.value.defenses || defensesRes.value || {}) : {};
        const forensics = forensicsRes.status === 'fulfilled' ? (forensicsRes.value || {}) : {};

        atAllToolsData.findings = findings;
        atAllToolsData.defenses = defenses;
        atAllToolsData.forensics = forensics;

        // 4. Render all panels
        const recon = scan.recon_data || {};
        atRenderRecon(recon);
        atRenderPentest(findings);
        atRenderFuzzer(recon.fuzzing_results || recon.paths || []);
        atRenderWaf(defenses);
        atRenderForensics(forensics);
        atRenderSiem(defenses.siem_rules || defenses.sigma_rules || []);

        atSetProgress(100, '✅ All tools complete — ' + rawTarget, 'Analysis finished at ' + new Date().toLocaleTimeString());

        // 5. Show summary + export
        atBuildSummary(findings, recon, defenses, forensics);
        const sr = document.getElementById('atSummaryRow');
        if (sr) sr.style.display = '';
        const er = document.getElementById('atExportRow');
        if (er) er.style.display = '';

        atAllToolsData.completedAt = new Date().toISOString();

    } catch (err) {
        clearInterval(atPollTimer);
        atSetProgress(0, '❌ Error: ' + err.message, 'Check the target and try again.');
        ['recon','pentest','fuzzer','waf','forensics','siem'].forEach(k => {
            atSetBadge(k, 'Error', 'badge-warn');
        });
        console.error('[AllTools]', err);
    } finally {
        if (btn) { btn.disabled = false; btn.querySelector('span').textContent = 'Run All Tools'; }
    }
}

// ── Panel render: Recon & Subdomains ───────────────────────────
function atRenderRecon(recon) {
    let html = '';
    const target = recon.target || '';
    const ips = recon.ip_addresses || recon.ips || [];
    const subs = recon.subdomains || [];
    const ports = recon.open_ports || [];
    const tech = recon.technologies || recon.tech_stack || [];
    const ssl = recon.ssl_info || recon.ssl || null;
    const whois = recon.whois || null;

    if (target) {
        html += `<div class="at-section-head">Target</div>
                 <div class="at-item"><span class="at-mono">${escH(target)}</span></div>`;
    }
    if (ips.length) {
        html += `<div class="at-section-head">IP Addresses (${ips.length})</div>`;
        ips.slice(0, 6).forEach(ip => {
            html += `<div class="at-item">
                <div class="at-item-dot at-sev-info"></div>
                <div class="at-item-text"><span class="at-mono">${escH(String(ip))}</span></div>
            </div>`;
        });
    }
    if (subs.length) {
        html += `<div class="at-section-head">Subdomains Discovered (${subs.length})</div>`;
        subs.slice(0, 12).forEach(s => {
            const name = typeof s === 'object' ? (s.subdomain || s.host || JSON.stringify(s)) : s;
            html += `<div class="at-item">
                <div class="at-item-dot at-sev-low"></div>
                <div class="at-item-text">${escH(String(name))}</div>
            </div>`;
        });
        if (subs.length > 12) html += `<div class="at-item-meta">+${subs.length-12} more…</div>`;
    }
    if (ports.length) {
        html += `<div class="at-section-head">Open Ports</div><div class="at-tag-row">`;
        ports.slice(0, 20).forEach(p => {
            html += `<span class="at-tag">${escH(String(p))}</span>`;
        });
        html += '</div>';
    }
    if (tech.length) {
        html += `<div class="at-section-head">Technologies</div><div class="at-tag-row">`;
        tech.slice(0,15).forEach(t => {
            const name = typeof t === 'object' ? (t.name || t.technology || JSON.stringify(t)) : t;
            html += `<span class="at-tag">${escH(String(name))}</span>`;
        });
        html += '</div>';
    }
    if (ssl) {
        const issuer = ssl.issuer || ssl.issuer_org || '';
        const expiry = ssl.expires || ssl.valid_until || '';
        html += `<div class="at-section-head">SSL Certificate</div>
                 <div class="at-item"><div class="at-item-dot at-sev-info"></div>
                 <div class="at-item-text">Issuer: ${escH(String(issuer))}
                 ${expiry ? '<div class="at-item-meta">Expires: ' + escH(String(expiry)) + '</div>' : ''}</div></div>`;
    }
    if (!html) html = '<div class="at-pending-msg">No recon data returned.</div>';

    atSetBody('recon', html);
    atSetBadge('recon', (subs.length + ips.length) + ' items', 'badge-done');
}

// ── Panel render: Pentest / OWASP ──────────────────────────────
function atRenderPentest(findings) {
    if (!Array.isArray(findings) || !findings.length) {
        atSetBody('pentest', '<div class="at-pending-msg">No OWASP findings returned.</div>');
        atSetBadge('pentest', '0 findings', 'badge-done');
        return;
    }
    const sevOrder = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4 };
    const sorted = [...findings].sort((a, b) => {
        return (sevOrder[a.severity?.toUpperCase()] ?? 9) - (sevOrder[b.severity?.toUpperCase()] ?? 9);
    });
    let html = '';
    let critCount = 0, highCount = 0;
    sorted.forEach(f => {
        const sev = (f.severity || 'INFO').toUpperCase();
        const dotClass = sev === 'CRITICAL' ? 'at-sev-crit' : sev === 'HIGH' ? 'at-sev-high' : sev === 'MEDIUM' ? 'at-sev-med' : sev === 'LOW' ? 'at-sev-low' : 'at-sev-info';
        if (sev === 'CRITICAL') critCount++;
        if (sev === 'HIGH') highCount++;
        html += `<div class="at-item">
            <div class="at-item-dot ${dotClass}"></div>
            <div class="at-item-text">
                <strong>${escH(f.title || f.name || f.check || 'Finding')}</strong>
                <span style="font-size:10.5px;padding:1px 6px;border-radius:4px;margin-left:6px;background:${dotClass==='at-sev-crit'?'rgba(248,81,73,0.15)':dotClass==='at-sev-high'?'rgba(240,136,62,0.15)':dotClass==='at-sev-med'?'rgba(210,153,34,0.15)':'rgba(88,166,255,0.12)'};color:${dotClass==='at-sev-crit'?'#f85149':dotClass==='at-sev-high'?'#f0883e':dotClass==='at-sev-med'?'#d29922':'#58a6ff'}">${sev}</span>
                <div class="at-item-meta">${escH(f.plugin_id || f.category || f.owasp_id || '')}</div>
                ${f.description ? '<div class="at-item-meta">' + escH(String(f.description).slice(0,120)) + '</div>' : ''}
            </div>
        </div>`;
    });
    atSetBody('pentest', html);
    const badge = critCount ? critCount + ' CRITICAL' : highCount ? highCount + ' HIGH' : findings.length + ' total';
    atSetBadge('pentest', badge, critCount ? 'badge-warn' : 'badge-done');
}

// ── Panel render: Fuzzer ───────────────────────────────────────
function atRenderFuzzer(paths) {
    if (!Array.isArray(paths) || !paths.length) {
        atSetBody('fuzzer', '<div class="at-pending-msg">No fuzzed paths discovered.</div>');
        atSetBadge('fuzzer', '0 paths', 'badge-done');
        return;
    }
    const interesting = paths.filter(p => {
        const s = typeof p === 'object' ? (p.status || p.status_code || 0) : 0;
        return s !== 404 && s !== 0;
    });
    let html = `<div class="at-section-head">Discovered Paths & Sensitive Assets (${paths.length} total, ${interesting.length} confirmed)</div>`;
    const toShow = interesting.length ? interesting : paths;
    toShow.slice(0, 35).forEach(p => {
        const path = typeof p === 'object' ? (p.path || p.url || '/') : String(p);
        const status = typeof p === 'object' ? (p.status || p.status_code || '') : '';
        const title = typeof p === 'object' ? (p.title || '') : '';
        const length = typeof p === 'object' ? (p.content_length || p.size || '') : '';
        const statusColor = status >= 200 && status < 300 ? '#3fb950' : status >= 300 && status < 400 ? '#58a6ff' : status === 401 || status === 403 ? '#f85149' : '#8b949e';
        html += `<div class="at-item">
            <div class="at-item-dot" style="background:${statusColor}"></div>
            <div class="at-item-text">
                <span class="at-mono">${escH(path)}</span>
                ${status ? `<span style="font-size:10.5px;font-weight:700;color:${statusColor};margin-left:6px;">HTTP ${status}</span>` : ''}
                ${title ? `<span style="font-size:11px;color:var(--text-muted);margin-left:6px;">${escH(title)}</span>` : ''}
                ${length ? `<div class="at-item-meta">Size: ${length} bytes</div>` : ''}
            </div>
        </div>`;
    });
    if (toShow.length > 35) html += `<div class="at-item-meta">+${toShow.length-35} more paths in export…</div>`;
    atSetBody('fuzzer', html);
    atSetBadge('fuzzer', interesting.length + ' paths', interesting.length > 0 ? 'badge-done' : 'badge-done');
}

// ── Panel render: WAF / Blue Team ──────────────────────────────
function atRenderWaf(defenses) {
    if (!defenses) {
        atSetBody('waf', '<div class="at-pending-msg">No defense data returned.</div>');
        atSetBadge('waf', 'None', 'badge-done');
        return;
    }
    const wafRules = defenses.waf_rules || [];
    const idsRules = defenses.ids_signatures || defenses.ids_rules || [];
    const hardening = defenses.server_hardening || defenses.hardening || [];
    const totalCount = wafRules.length + idsRules.length + hardening.length;

    if (totalCount === 0) {
        atSetBody('waf', '<div class="at-pending-msg">No active defensive rules needed.</div>');
        atSetBadge('waf', '0 rules', 'badge-done');
        return;
    }

    let html = '';

    // WAF Rules (ModSecurity / Cloudflare)
    if (wafRules.length) {
        html += `<div class="at-section-head">Web Application Firewall Rules (${wafRules.length})</div>`;
        wafRules.forEach(r => {
            const ruleType = r.type || "WAF Rule";
            const filename = r.filename || "waf_rule.conf";
            const content = r.content || "";
            html += `<div style="margin-bottom:12px;">
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px;">
                    <span style="font-weight:700;color:var(--text-title);font-size:12px;">🛡️ ${escH(ruleType)}</span>
                    <span class="at-tag">${escH(filename)}</span>
                </div>
                <div class="at-rule-block">${escH(content.slice(0, 240))}${content.length > 240 ? '\n# ... (Full rule in export)' : ''}</div>
            </div>`;
        });
    }

    // IDS / IPS Network Signatures (Suricata / Snort)
    if (idsRules.length) {
        html += `<div class="at-section-head">IDS / Suricata Network Signatures (${idsRules.length})</div>`;
        idsRules.forEach(r => {
            const ruleType = r.type || "IDS Signature";
            const filename = r.filename || "ids.rules";
            const content = r.content || "";
            html += `<div style="margin-bottom:12px;">
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px;">
                    <span style="font-weight:700;color:#38bdf8;font-size:12px;">📡 ${escH(ruleType)}</span>
                    <span class="at-tag">${escH(filename)}</span>
                </div>
                <div class="at-rule-block" style="color:#a5f3fc;">${escH(content.slice(0, 220))}${content.length > 220 ? '\n# ...' : ''}</div>
            </div>`;
        });
    }

    // Server Hardening (Nginx / Apache)
    if (hardening.length) {
        html += `<div class="at-section-head">Server Hardening Directives (${hardening.length})</div>`;
        hardening.forEach(r => {
            const ruleType = r.type || "Hardening Directive";
            const filename = r.filename || "security_headers.conf";
            const content = r.content || "";
            html += `<div style="margin-bottom:10px;">
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px;">
                    <span style="font-weight:700;color:#34d399;font-size:12px;">🔒 ${escH(ruleType)}</span>
                    <span class="at-tag">${escH(filename)}</span>
                </div>
                <div class="at-rule-block" style="color:#86efac;">${escH(content.slice(0, 200))}${content.length > 200 ? '\n# ...' : ''}</div>
            </div>`;
        });
    }

    atSetBody('waf', html);
    atSetBadge('waf', totalCount + ' defenses', 'badge-done');
}

// ── Panel render: Forensics / DFIR ─────────────────────────────
function atRenderForensics(forensics) {
    if (!forensics) {
        atSetBody('forensics', '<div class="at-pending-msg">No forensics data returned.</div>');
        atSetBadge('forensics', 'None', 'badge-done');
        return;
    }

    const threats = forensics.threats || [];
    const huntProfiles = forensics.threat_hunt_profiles || [];
    const events = forensics.events || [];
    const vectors = forensics.attack_vectors || [];
    const summary = forensics.threat_summary || forensics.summary || null;
    const totalCount = threats.length || huntProfiles.length;

    if (totalCount === 0 && !summary) {
        atSetBody('forensics', '<div class="at-pending-msg">No attack footprints detected.<br><small style="display:block;margin-top:8px;opacity:.6">Use the Forensics tab to analyze server logs directly.</small></div>');
        atSetBadge('forensics', '0 threats', 'badge-done');
        return;
    }

    let html = '';

    if (summary) {
        html += `<div class="at-section-head">DFIR Threat Summary</div>
                 <div class="at-item"><div class="at-item-dot at-sev-info"></div>
                 <div class="at-item-text" style="color:#c7d2fe;">${escH(summary)}</div></div>`;
    }

    if (vectors.length) {
        html += `<div class="at-section-head">Identified Attack Vectors</div><div class="at-tag-row">`;
        vectors.forEach(v => {
            html += `<span class="at-tag" style="border-color:rgba(99,102,241,0.4);color:#a5b4fc;">${escH(String(v))}</span>`;
        });
        html += '</div>';
    }

    if (threats.length) {
        html += `<div class="at-section-head">Attack Footprints & Threat Signatures (${threats.length})</div>`;
        threats.slice(0, 6).forEach(t => {
            const title = t.title || t.threat || 'Threat Footprint';
            const sev = (t.severity || 'INFO').toUpperCase();
            const dotClass = sev === 'CRITICAL' ? 'at-sev-crit' : sev === 'HIGH' ? 'at-sev-high' : sev === 'MEDIUM' ? 'at-sev-med' : 'at-sev-low';
            html += `<div class="at-item">
                <div class="at-item-dot ${dotClass}"></div>
                <div class="at-item-text">
                    <div style="font-weight:700;color:var(--text-title);">${escH(title)}</div>
                    ${t.mitre ? '<div class="at-item-meta" style="color:#818cf8;">MITRE: ' + escH(t.mitre) + '</div>' : ''}
                    ${t.log_footprint ? '<div class="at-item-meta" style="font-family:var(--mono);color:#94a3b8;margin-top:2px;">Footprint: ' + escH(t.log_footprint) + '</div>' : ''}
                </div>
            </div>`;
        });
    }

    if (huntProfiles.length) {
        html += `<div class="at-section-head">Threat Hunting Queries (Linux & Windows)</div>`;
        huntProfiles.slice(0, 3).forEach(h => {
            html += `<div style="margin-bottom:8px;">
                <div style="font-size:11.5px;font-weight:600;color:var(--text-muted);margin-bottom:3px;">🔍 ${escH(h.title || 'Log Query')}:</div>
                <div class="at-rule-block" style="color:#c4b5fd;">${escH(h.grep_command || h.powershell_command || '')}</div>
            </div>`;
        });
    }

    atSetBody('forensics', html);
    atSetBadge('forensics', totalCount + ' threat footprints', totalCount > 0 ? 'badge-warn' : 'badge-done');
}

// ── Panel render: SIEM / Sigma ─────────────────────────────────
function atRenderSiem(rules) {
    if (!Array.isArray(rules) || !rules.length) {
        atSetBody('siem', `<div class="at-pending-msg">No SIEM detection rules generated.<br><small style="display:block;margin-top:8px;opacity:.6">SIEM rules are auto-generated based on detected threats and vulnerabilities.</small></div>`);
        atSetBadge('siem', '0 rules', 'badge-done');
        return;
    }
    let html = `<div class="at-section-head">SOC SIEM & Sigma Detection Rules (${rules.length})</div>`;
    rules.forEach((r, idx) => {
        let ruleType = r.type || (idx === 0 ? "Sigma Detection Rule (YAML)" : (idx === 1 ? "Splunk SPL Query" : "Elastic KQL Query"));
        let filename = r.filename || (idx === 0 ? "swa_sigma.yml" : (idx === 1 ? "splunk.spl" : "elastic.kql"));
        let content = r.content || r.rule || r.sigma || r.elastic || r.splunk || r.query || String(r);

        html += `<div style="margin-bottom:12px;">
            <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px;">
                <span style="font-size:12px;font-weight:700;color:var(--text-title);">📊 ${escH(ruleType)}</span>
                <span class="at-tag">${escH(filename)}</span>
            </div>
            <div class="at-rule-block" style="color:#fed7aa;max-height:140px;overflow-y:auto;">${escH(content)}</div>
        </div>`;
    });
    atSetBody('siem', html);
    atSetBadge('siem', rules.length + ' rules', 'badge-done');
}

// ── Summary cards ──────────────────────────────────────────────
function atBuildSummary(findings, recon, defenses, forensics) {
    const crit = findings.filter(f => (f.severity || '').toUpperCase() === 'CRITICAL').length;
    const high = findings.filter(f => (f.severity || '').toUpperCase() === 'HIGH').length;
    const subs = (recon.subdomains || []).length;
    const threats = ((forensics.threats || forensics.findings || forensics.threat_hunt_profiles) || []).length;
    const rules = ((defenses.waf_rules || defenses.rules) || []).length +
                  ((defenses.ids_signatures || defenses.ids_rules) || []).length;
    const ports = (recon.open_ports || []).length;

    const cards = [
        { label: 'Critical Findings', value: crit, sub: 'OWASP Top 10', color: crit > 0 ? '#f85149' : '#3fb950' },
        { label: 'High Severity', value: high, sub: 'Pentest results', color: high > 0 ? '#f0883e' : '#3fb950' },
        { label: 'Subdomains', value: subs, sub: 'Discovered', color: '#58a6ff' },
        { label: 'Open Ports', value: ports, sub: 'Network exposure', color: '#d29922' },
        { label: 'DFIR Threats', value: threats, sub: 'Forensics', color: threats > 0 ? '#818cf8' : '#3fb950' },
        { label: 'Defense Rules', value: rules, sub: 'WAF + IDS', color: '#3fb950' },
    ];

    const row = document.getElementById('atSummaryRow');
    if (!row) return;
    row.innerHTML = cards.map(c => `
        <div class="at-stat-card">
            <div class="at-stat-label">${escH(c.label)}</div>
            <div class="at-stat-value" style="color:${c.color}">${c.value}</div>
            <div class="at-stat-sub">${escH(c.sub)}</div>
        </div>`).join('');
}

// ── Professional Export Helpers ────────────────────────────────
function atExportHTML() {
    if (!atScanId) {
        alert("Please run a scan first before exporting.");
        return;
    }
    window.open('/api/scans/' + atScanId + '/report?format=html', '_blank');
}

function atExportPDF() {
    if (!atScanId) {
        alert("Please run a scan first before exporting.");
        return;
    }
    window.open('/api/scans/' + atScanId + '/report?format=pdf', '_blank');
}

function atExportCSV() {
    if (!atScanId) {
        alert("Please run a scan first before exporting.");
        return;
    }
    window.location.href = '/api/scans/' + atScanId + '/report?format=csv';
}

function atExportJSON() {
    if (!atScanId) {
        const blob = new Blob([JSON.stringify(atAllToolsData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'swa-all-tools-data.json';
        a.click();
        URL.revokeObjectURL(url);
        return;
    }
    window.location.href = '/api/scans/' + atScanId + '/report?format=json';
}

function atExportMarkdown() {
    if (!atScanId) {
        const md = `# SWA AI Audit Report\nTarget: ${atAllToolsData.target || 'Unknown'}`;
        const blob = new Blob([md], { type: 'text/markdown' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'swa-audit-report.md';
        a.click();
        URL.revokeObjectURL(url);
        return;
    }
    window.location.href = '/api/scans/' + atScanId + '/report?format=markdown';
}

// ── Utility ────────────────────────────────────────────────────
function escH(str) {
    return String(str)
        .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
        .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}


// ============================================================================
// WAF & SIEM DEFENSE CENTER (Blue Team Countermeasures Engine)
// ============================================================================
let dcRulesData = null;
let dcCurrentPlatform = 'modsec';

function openDefenseCenterModal() {
    const modal = document.getElementById("defenseCenterModal");
    if (!modal) return;
    modal.classList.add("open");

    // Populate target
    let target = "";
    if (currentScanId && scansData[currentScanId]) {
        target = scansData[currentScanId].target_url;
    } else {
        target = document.getElementById("targetInput")?.value.trim() || document.getElementById("allToolsTarget")?.value.trim() || "target.local";
    }
    const input = document.getElementById("dcTargetInput");
    if (input) input.value = target;

    generateDefenseCenterFromModal();
}

function closeDefenseCenterModal() {
    const modal = document.getElementById("defenseCenterModal");
    if (modal) modal.classList.remove("open");
}

function useActiveScanForDefenseCenter() {
    if (currentScanId && scansData[currentScanId]) {
        const input = document.getElementById("dcTargetInput");
        if (input) input.value = scansData[currentScanId].target_url;
        generateDefenseCenterFromModal();
    } else {
        alert("No active audit selected. Enter a domain or IP above.");
    }
}

async function generateDefenseCenterFromModal() {
    const input = document.getElementById("dcTargetInput");
    const target = input ? input.value.trim() : "target.local";
    if (!target) return;

    const btn = document.getElementById("btnDcGenerate");
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = `<span>Synthesizing...</span>`;
    }

    try {
        const payload = { target_url: target };
        if (currentScanId && scansData[currentScanId] && scansData[currentScanId].target_url === target) {
            payload.scan_id = currentScanId;
        }

        const res = await fetch("/api/defense/generate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });

        if (!res.ok) throw new Error("Failed to generate defenses");
        dcRulesData = await res.json();

        // Render current platform
        renderDcPlatform(dcCurrentPlatform);
    } catch (e) {
        console.error("Defense Center error:", e);
        const preview = document.getElementById("dcCodePreview");
        if (preview) preview.textContent = "// Error generating rules: " + e.message;
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg><span>Generate Countermeasures</span>`;
        }
    }
}

function switchDcPlatform(platformKey, el) {
    dcCurrentPlatform = platformKey;
    document.querySelectorAll("#dcPlatformTabs .pill-item").forEach(p => p.classList.remove("active"));
    if (el) el.classList.add("active");
    renderDcPlatform(platformKey);
}

function renderDcPlatform(platformKey) {
    if (!dcRulesData) return;

    const titleEl = document.getElementById("dcRuleTitle");
    const fnEl = document.getElementById("dcRuleFilename");
    const previewEl = document.getElementById("dcCodePreview");
    const guideEl = document.getElementById("dcDeployGuide");

    let title = "", filename = "", content = "", guide = "";

    const waf = dcRulesData.waf_rules || [];
    const ids = dcRulesData.ids_signatures || [];
    const siem = dcRulesData.siem_rules || [];
    const hardening = dcRulesData.server_hardening || [];

    if (platformKey === "modsec") {
        const item = waf.find(r => r.type.includes("ModSecurity")) || waf[0] || {};
        title = "ModSecurity (OWASP CRS 3.3+) WAF Ruleset";
        filename = item.filename || "swa_modsecurity.conf";
        content = item.content || "# No ModSecurity rules generated";
        guide = "<strong>Deployment Guide (Nginx/Apache):</strong> Include this file in your web server configuration via <code>Include /etc/modsecurity/rules/swa_modsecurity.conf</code> and reload Nginx/Apache. Blocks directory traversal, SQLi, and unauthorized access.";
    } else if (platformKey === "cloudflare") {
        const item = waf.find(r => r.type.includes("Cloudflare")) || waf[1] || {};
        title = "Cloudflare WAF Custom Firewall Rule";
        filename = item.filename || "cloudflare_waf_rules.txt";
        content = item.content || "# No Cloudflare rules generated";
        guide = "<strong>Deployment Guide (Cloudflare Dashboard):</strong> Navigate to <em>Security > WAF > Custom Rules > Create Rule</em>. Paste this expression into the Rule Expression Editor and set Action to <em>Block</em> or <em>Managed Challenge</em>.";
    } else if (platformKey === "awswaf") {
        const item = waf.find(r => r.type.includes("AWS")) || waf[2] || {};
        title = "AWS WAF v2 Rule Group (JSON Statement)";
        filename = item.filename || "aws_waf_v2_rules.json";
        content = item.content || "# No AWS WAF rules generated";
        guide = "<strong>Deployment Guide (AWS Console):</strong> Open <em>AWS WAF & Shield > Web ACLs</em>. Add a Custom Rule Statement using the JSON Rule Editor. Paste this JSON statement and configure CloudWatch metrics.";
    } else if (platformKey === "nginxwaf") {
        const item = waf.find(r => r.type.includes("Nginx WAF")) || waf[3] || {};
        title = "Nginx Perimeter WAF & Rate Limiting Module";
        filename = item.filename || "nginx_waf_guard.conf";
        content = item.content || "# No Nginx WAF rules generated";
        guide = "<strong>Deployment Guide (Nginx):</strong> Paste into <code>/etc/nginx/conf.d/waf_guard.conf</code> or inside your <code>server { }</code> block. Drops aggressive scanner User-Agents and throttles malicious IPs.";
    } else if (platformKey === "suricata") {
        const item = ids.find(r => r.type.includes("Suricata")) || ids[0] || {};
        title = "Suricata 6.x / 7.x Network IDS/IPS Signatures";
        filename = item.filename || "swa_suricata.rules";
        content = item.content || "# No Suricata rules generated";
        guide = "<strong>Deployment Guide (Suricata):</strong> Place in <code>/etc/suricata/rules/swa_suricata.rules</code> and reference in <code>suricata.yaml</code> under <code>rule-files:</code>. Reload Suricata using <code>suricatasc -c reload-rules</code>.";
    } else if (platformKey === "snort") {
        const item = ids.find(r => r.type.includes("Snort")) || ids[1] || {};
        title = "Snort 3 Network Intrusion Detection Signatures";
        filename = item.filename || "swa_snort3.rules";
        content = item.content || "# No Snort rules generated";
        guide = "<strong>Deployment Guide (Snort 3):</strong> Add to your local rules directory and reference in <code>snort.lua</code> via <code>ips = { include = 'swa_snort3.rules' }</code>.";
    } else if (platformKey === "sigma") {
        const item = siem.find(r => r.type.includes("Sigma")) || siem[0] || {};
        title = "Sigma Generic Threat Detection Rule (YAML)";
        filename = item.filename || "swa_sigma_rule.yml";
        content = item.content || "# No Sigma rules generated";
        guide = "<strong>Deployment Guide (SOC & SIEM):</strong> Use <code>sigmac</code> or pySigma to translate this rule into Splunk, Elastic, Sentinel, QRadar, or SumoLogic queries.";
    } else if (platformKey === "splunk") {
        const item = siem.find(r => r.type.includes("Splunk")) || siem[1] || {};
        title = "Splunk Search Processing Language (SPL) Threat Query";
        filename = item.filename || "splunk_investigation.spl";
        content = item.content || "# No Splunk query generated";
        guide = "<strong>Deployment Guide (Splunk Enterprise / Cloud):</strong> Paste into the Search & Reporting search bar. Save as an <em>Alert</em> with real-time or scheduled execution to detect suspicious probing.";
    } else if (platformKey === "elastic") {
        const item = siem.find(r => r.type.includes("Elastic")) || siem[2] || {};
        title = "Elasticsearch KQL / Kibana Query";
        filename = item.filename || "elastic_detection.kql";
        content = item.content || "# No Elastic query generated";
        guide = "<strong>Deployment Guide (Elastic Security / Kibana):</strong> Open <em>Kibana > Discover</em> or <em>Security > Detection Rules</em>. Paste the KQL filter into the query bar or create an automated detection alert.";
    } else if (platformKey === "sentinel") {
        const item = siem.find(r => r.type.includes("Sentinel")) || siem[3] || {};
        title = "Microsoft Sentinel KQL Log Analytics Query";
        filename = item.filename || "sentinel_detection.kql";
        content = item.content || "# No Sentinel query generated";
        guide = "<strong>Deployment Guide (Azure Portal):</strong> Open <em>Microsoft Sentinel > Analytics > Create Scheduled Query Rule</em>. Paste this KQL script to monitor IIS and Azure Application Gateway logs.";
    } else if (platformKey === "hardening") {
        const nginxItem = hardening.find(r => r.type.includes("Nginx")) || {};
        const apacheItem = hardening.find(r => r.type.includes("Apache")) || {};
        title = "Nginx & Apache Server Hardening Configurations";
        filename = "server_hardening_bundle.conf";
        content = (nginxItem.content || "") + "\n\n# ----------------------------------------------------\n\n" + (apacheItem.content || "");
        guide = "<strong>Deployment Guide:</strong> Contains drop-in security headers (HSTS, CSP, X-Frame-Options, Permissions-Policy) and disabled version tokens for Nginx and Apache web servers.";
    }

    if (titleEl) titleEl.textContent = title;
    if (fnEl) fnEl.textContent = filename;
    if (previewEl) previewEl.textContent = content;
    if (guideEl) guideEl.innerHTML = guide;
}

function copyDcRule(btn) {
    const previewEl = document.getElementById("dcCodePreview");
    if (!previewEl || !previewEl.textContent) return;
    navigator.clipboard.writeText(previewEl.textContent).then(() => {
        const originalText = btn.innerHTML;
        btn.innerHTML = `<span style="color: #34d399;">✓ Copied!</span>`;
        setTimeout(() => { btn.innerHTML = originalText; }, 1800);
    });
}

function downloadDcRule() {
    const fnEl = document.getElementById("dcRuleFilename");
    const previewEl = document.getElementById("dcCodePreview");
    if (!previewEl || !previewEl.textContent) return;
    const filename = fnEl ? fnEl.textContent : "swa_defense_rule.txt";
    const blob = new Blob([previewEl.textContent], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
}
