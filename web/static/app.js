// SWA AI Autonomous Security Agent - Frontend Controller
let currentProfile = "full_red_team";
let currentScanId = null;
let scansData = {};
let activeFindings = [];
let ws = null;

document.addEventListener("DOMContentLoaded", () => {
    initWebSocket();
    loadScans();
    loadSettings();

    // Enter key launches scan
    document.getElementById("targetInput").addEventListener("keypress", (e) => {
        if (e.key === "Enter") launchScan();
    });
});

// Profile Selection
function selectProfile(profile, element) {
    currentProfile = profile;
    document.querySelectorAll(".profile-chip").forEach(p => p.classList.remove("active"));
    element.classList.add("active");
}

function toggleAdvancedOptions() {
    const el = document.getElementById("advancedOptions");
    const arrow = document.getElementById("advArrow");
    el.classList.toggle("open");
    arrow.textContent = el.classList.contains("open") ? "▲" : "▼";
}

// WebSocket Live Feeds
function initWebSocket() {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    
    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
        const statusEl = document.getElementById("connectionStatus");
        if (statusEl) {
            statusEl.innerHTML = `<span style="width: 8px; height: 8px; background: #10b981; border-radius: 50%; display: inline-block;"></span> Engine Connected`;
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
            statusEl.innerHTML = `<span style="width: 8px; height: 8px; background: #ef4444; border-radius: 50%; display: inline-block;"></span> Reconnecting...`;
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
            setProgress(100, "Completed");
            updateScanHeaderStatus("COMPLETED");
            document.getElementById("btnCancelScan").style.display = "none";
        }
        loadScans();
    } else if (type === "SCAN_CANCELLED") {
        if (data.scan_id === currentScanId) {
            updateScanHeaderStatus("CANCELLED");
            document.getElementById("btnCancelScan").style.display = "none";
        }
        loadScans();
    }
}

// REST Actions
async function launchScan() {
    const targetInput = document.getElementById("targetInput");
    const target = targetInput.value.trim();
    if (!target) {
        alert("Please enter a target domain, URL, or IP.");
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
    btn.textContent = "⚡ Dispatching Agent...";

    try {
        const res = await fetch("/api/scans", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });

        if (!res.ok) {
            const err = await res.json();
            alert(`Error: ${err.detail || "Failed to start scan"}`);
            return;
        }

        const job = await res.json();
        targetInput.value = "";
        await loadScans();
        selectScan(job.id);
    } catch (e) {
        alert(`Failed to launch scan: ${e.message}`);
    } finally {
        btn.disabled = false;
        btn.textContent = "🚀 Start Autonomous Pentest";
    }
}

async function loadScans() {
    try {
        const res = await fetch("/api/scans");
        const list = await res.json();
        
        const container = document.getElementById("scansList");
        if (!list || list.length === 0) {
            container.innerHTML = `<div style="color: var(--text-muted); font-size: 13px; text-align: center; padding: 20px;">No assessments recorded yet.</div>`;
            return;
        }

        // Update overall stats
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
            <div class="scan-card ${s.id === currentScanId ? 'selected' : ''}" onclick="selectScan('${s.id}')">
                <div class="scan-card-top">
                    <span class="scan-domain" title="${s.target_url}">${s.target_url}</span>
                    <span class="status-pill status-${s.status}">${s.status}</span>
                </div>
                <div style="font-size: 11px; color: var(--brand-cyan); margin: 3px 0;">${s.current_phase || 'Active'}</div>
                <div style="font-size: 11px; color: var(--text-muted); display: flex; justify-content: space-between;">
                    <span>${s.profile}</span>
                    <span style="color: ${s.critical_count > 0 ? '#ff3366' : (s.findings_count > 0 ? '#ff8800' : '#8b9bb4')}; font-weight: 700;">
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
    document.querySelectorAll(".scan-card").forEach(item => item.classList.remove("selected"));
    
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

        setProgress(scan.progress_percent, scan.current_phase);

        // Cancel button visibility
        document.getElementById("btnCancelScan").style.display = scan.status === "RUNNING" ? "inline-flex" : "none";

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
    pill.className = `status-pill status-${status}`;
    pill.textContent = status;
}

function setProgress(percent, phase) {
    document.getElementById("activeScanProgressBar").style.width = `${percent}%`;
    document.getElementById("activeScanProgressText").textContent = `${percent}%`;
    document.getElementById("activeScanPhase").textContent = phase || "Analyzing...";
}

function updateScanInList(scanId, percent, phase) {
    // Light update to avoid full DOM redraw
    const items = document.querySelectorAll(".scan-card");
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
        <div style="background: #ffffff; border: 1px solid var(--border-light); border-radius: 10px; overflow: hidden; box-shadow: var(--shadow-sm);">
            <table style="width: 100%; border-collapse: collapse; text-align: left; font-size: 13px;">
                <thead>
                    <tr style="background: var(--bg-subtle); border-bottom: 1px solid var(--border-light); color: var(--text-secondary); font-size: 12px; text-transform: uppercase;">
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
                        const statusPillClass = (status === 200) ? "status-COMPLETED" : ((status >= 400 && status < 500) ? "status-PENDING" : "status-RUNNING");

                        return `
                            <tr style="border-bottom: 1px solid var(--border-light);">
                                <td style="padding: 12px 16px; font-weight: 600; font-family: var(--font-mono); color: var(--primary-600);">
                                    <a href="https://${subName}" target="_blank" style="color: inherit; text-decoration: none;">${subName} ↗</a>
                                </td>
                                <td style="padding: 12px 16px; font-family: var(--font-mono); color: var(--text-secondary);">${ip}</td>
                                <td style="padding: 12px 16px;">
                                    <span class="status-pill ${statusPillClass}">${status}</span>
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
            <h4 style="font-size: 14px; font-weight: 700; margin-bottom: 10px; color: #0f172a;">Discovered Hidden Paths & Files (${paths.length})</h4>
            <div style="background: #ffffff; border: 1px solid var(--border-light); border-radius: 10px; overflow: hidden; margin-bottom: 24px; box-shadow: var(--shadow-sm);">
                <table style="width: 100%; border-collapse: collapse; text-align: left; font-size: 13px;">
                    <thead>
                        <tr style="background: var(--bg-subtle); border-bottom: 1px solid var(--border-light); color: var(--text-secondary); font-size: 12px; text-transform: uppercase;">
                            <th style="padding: 10px 16px;">Path</th>
                            <th style="padding: 10px 16px;">Status</th>
                            <th style="padding: 10px 16px;">Length</th>
                            <th style="padding: 10px 16px;">Asset Title / Classification</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${paths.map(p => `
                            <tr style="border-bottom: 1px solid var(--border-light);">
                                <td style="padding: 10px 16px; font-weight: 600; font-family: var(--font-mono); color: var(--primary-600);">
                                    <a href="${p.url}" target="_blank" style="color: inherit; text-decoration: none;">${p.path} ↗</a>
                                </td>
                                <td style="padding: 10px 16px;"><span class="status-pill status-${p.status === 200 ? 'COMPLETED' : 'PENDING'}">HTTP ${p.status}</span></td>
                                <td style="padding: 10px 16px; font-family: var(--font-mono); color: var(--text-secondary);">${p.content_length} B</td>
                                <td style="padding: 10px 16px; color: var(--text-primary);">${p.title || p.content_type || 'Exposed Asset'}</td>
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
            <h4 style="font-size: 14px; font-weight: 700; margin-bottom: 10px; color: #0f172a;">Hidden Parameter Anomalies (${parameters.length})</h4>
            <div style="background: #ffffff; border: 1px solid var(--border-light); border-radius: 10px; overflow: hidden; box-shadow: var(--shadow-sm);">
                <table style="width: 100%; border-collapse: collapse; text-align: left; font-size: 13px;">
                    <thead>
                        <tr style="background: var(--bg-subtle); border-bottom: 1px solid var(--border-light); color: var(--text-secondary); font-size: 12px; text-transform: uppercase;">
                            <th style="padding: 10px 16px;">Parameter</th>
                            <th style="padding: 10px 16px;">Behavior / Anomaly</th>
                            <th style="padding: 10px 16px;">Input Reflected</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${parameters.map(m => `
                            <tr style="border-bottom: 1px solid var(--border-light);">
                                <td style="padding: 10px 16px; font-weight: 700; font-family: var(--font-mono); color: #c2410c;">?${m.parameter}=</td>
                                <td style="padding: 10px 16px; color: var(--text-primary);">${m.anomaly_type}</td>
                                <td style="padding: 10px 16px;">
                                    <span class="status-pill ${m.reflected ? 'status-FAILED' : 'status-RUNNING'}">${m.reflected ? 'YES (High Risk)' : 'No'}</span>
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
            chips.push(`🌐 IP: ${r.ip_addresses.join(", ")}`);
        }
        if (r.technologies && r.technologies.length > 0) {
            r.technologies.forEach(t => chips.push(`🛠️ ${t.technology}`));
        }
        if (r.open_ports && r.open_ports.length > 0) {
            chips.push(`🚪 Ports: ${r.open_ports.map(p => p.port).join(", ")}`);
        }
        if (r.ssl_info && r.ssl_info.issuer) {
            chips.push(`🔒 TLS Valid`);
        }
        if (r.subdomains && r.subdomains.length > 0) {
            chips.push(`🌐 ${r.subdomains.length} Subdomains`);
        }
        if (r.fuzzing_results && r.fuzzing_results.length > 0) {
            chips.push(`⚡ ${r.fuzzing_results.length} Fuzzed Endpoints`);
        }
    }

    if (scan.endpoints_count > 0) {
        chips.push(`📍 ${scan.endpoints_count} Endpoints Mapped`);
    }

    container.innerHTML = chips.map(c => `<div class="recon-chip">${c}</div>`).join("");
}

function renderFindings(findings) {
    const container = document.getElementById("findingsContainer");
    document.getElementById("findingsCountBadge").textContent = findings.length;

    if (!findings || findings.length === 0) {
        container.innerHTML = `<div style="color: var(--text-muted); text-align: center; padding: 40px;">No vulnerabilities confirmed yet. Probing target endpoints...</div>`;
        return;
    }

    container.innerHTML = findings.map(f => `
        <div class="finding-item" onclick="openFindingModal('${f.id}')">
            <div class="finding-item-top">
                <div style="display: flex; align-items: center; gap: 8px;">
                    <span class="sev-badge sev-${f.severity}">${f.severity}</span>
                    <span class="cvss-tag">CVSS ${f.cvss_score}</span>
                    <strong style="font-size: 14px; font-weight: 700;">${f.title}</strong>
                </div>
                <span style="color: var(--brand-emerald); font-size: 11px; font-weight: 700;">✓ PoC Verified</span>
            </div>
            <div style="color: var(--text-secondary); font-size: 12px; margin-top: 4px;">
                <code style="color: var(--brand-cyan);">${f.method} ${f.endpoint}</code> | ${f.owasp_category || 'OWASP Misconfiguration'}
            </div>
        </div>
    `).join("");
}

function appendLog(log) {
    const term = document.getElementById("terminalLogs");
    const div = document.createElement("div");
    div.className = "log-entry";
    div.innerHTML = `
        <span class="log-time">[${log.timestamp}]</span>
        <span class="log-agent">[${log.agent}]</span>
        <span class="log-level-${log.level}">${log.message}</span>
    `;
    term.appendChild(div);
    term.scrollTop = term.scrollHeight;
}

function switchTab(tabId, btn) {
    document.querySelectorAll(".tab-content").forEach(el => el.style.display = "none");
    document.querySelectorAll(".tab-btn").forEach(el => el.classList.remove("active"));
    
    document.getElementById(tabId).style.display = "block";
    btn.classList.add("active");
}

// Modals
function openFindingModal(findingId) {
    const f = activeFindings.find(item => item.id === findingId);
    if (!f) return;

    document.getElementById("modalSevBadge").className = `sev-badge sev-${f.severity}`;
    document.getElementById("modalSevBadge").textContent = f.severity;
    document.getElementById("modalCvss").textContent = `CVSS ${f.cvss_score}`;
    document.getElementById("modalTitle").textContent = f.title;
    document.getElementById("modalEndpoint").textContent = `${f.method} ${f.endpoint}`;
    document.getElementById("modalOwasp").textContent = f.owasp_category || 'N/A';
    document.getElementById("modalCwe").textContent = f.cwe_id || 'N/A';
    document.getElementById("modalDesc").textContent = f.description;
    document.getElementById("modalPocCurl").textContent = f.poc_curl || `curl -i '${f.endpoint}'`;
    document.getElementById("modalExplanation").textContent = f.poc_explanation || 'Verified through active probe.';
    document.getElementById("modalRemediationAdvice").textContent = f.remediation_advice || 'Apply standard defensive sanitization.';

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

// Settings
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
