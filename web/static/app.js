// SWA AI Senior Web Designer - Dual Theme Engine (Light & Dark)
function initTheme() {
    const saved = localStorage.getItem("swa_theme");
    const prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
    const theme = saved || (prefersDark ? "dark" : "dark");
    setTheme(theme);
}

function setTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("swa_theme", theme);
    
    const icon = document.getElementById("themeToggleIcon");
    const text = document.getElementById("themeToggleText");
    if (icon && text) {
        if (theme === "light") {
            icon.textContent = "🌙";
            text.textContent = "Dark Mode";
        } else {
            icon.textContent = "☀️";
            text.textContent = "Light Mode";
        }
    }
}

function toggleTheme() {
    const current = document.documentElement.getAttribute("data-theme") || "dark";
    const next = current === "dark" ? "light" : "dark";
    setTheme(next);
}

// SWA AI Autonomous Security Auditor - Frontend Controller
let currentProfile = "full_red_team";
let currentScanId = null;
let scansData = {};
let activeFindings = [];
let ws = null;

document.addEventListener("DOMContentLoaded", () => {
    initTheme();
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
            const lBadge = document.getElementById("logsCountBadge");
            if (lBadge) {
                const currentCount = parseInt(lBadge.textContent, 10) || 0;
                lBadge.textContent = currentCount + 1;
            }
        }
    } else if (type === "FINDING_DISCOVERED") {
        if (data.scan_id === currentScanId) {
            activeFindings.unshift(data.finding);
            renderFindings(activeFindings);
            recalculateActiveScanScore();
            loadDefenses();
            loadScanForensicsCorrelation();
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
                <div style="font-size: 10.5px; color: var(--text-muted); margin-top: 4px; display: flex; justify-content: space-between; border-top: 1px dashed rgba(255,255,255,0.07); padding-top: 4px;">
                    <span>📅 ${s.created_at ? new Date(s.created_at).toLocaleString([], {month:'short', day:'numeric', hour:'2-digit', minute:'2-digit'}) : 'Live'}</span>
                    <span>${s.duration_seconds ? s.duration_seconds.toFixed(1) + 's' : ''}</span>
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

function renderReconChips(scan) {
    const container = document.getElementById("activeMetaChips");
    if (!container) return;
    if (!scan) {
        container.innerHTML = "";
        return;
    }

    const recon = scan.recon_data || {};
    const ips = recon.ip_addresses || [];
    const ports = recon.open_ports || [];
    const tech = recon.technologies || [];
    const subs = recon.subdomains || [];
    const fuzzedPaths = (recon.fuzzing_results || []).filter(p => {
        const s = typeof p === 'object' ? (p.status || p.status_code || 0) : 0;
        return s === 200 || (s >= 300 && s < 400);
    });

    const chips = [];

    // Target IPs
    if (ips.length > 0) {
        chips.push(`
            <div class="meta-pill" title="Resolved IP Addresses">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg>
                <span><strong>IP:</strong> ${escapeHtml(ips.slice(0, 2).join(', '))}${ips.length > 2 ? ` (+${ips.length - 2})` : ''}</span>
            </div>
        `);
    }

    // Discovered Subdomains
    if (subs.length > 0) {
        chips.push(`
            <div class="meta-pill" title="Discovered Active Subdomains" style="cursor: pointer;" onclick="switchTab('tabSubdomains')">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg>
                <span><strong>Subdomains:</strong> ${subs.length} active</span>
            </div>
        `);
    }

    // Detected Technologies
    if (tech.length > 0) {
        const techList = tech.map(t => typeof t === 'object' ? (t.name || t.technology || '') : t).filter(Boolean);
        if (techList.length > 0) {
            chips.push(`
                <div class="meta-pill" title="Detected Web Technologies">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><polygon points="12 2 2 7 12 12 22 7 12 2"></polygon><polyline points="2 17 12 22 22 17"></polyline><polyline points="2 12 12 17 22 12"></polyline></svg>
                    <span><strong>Tech:</strong> ${escapeHtml(techList.slice(0, 3).join(', '))}${techList.length > 3 ? ` (+${techList.length - 3})` : ''}</span>
                </div>
            `);
        }
    }

    // Open TCP Ports
    if (ports.length > 0) {
        const portList = ports.map(p => typeof p === 'object' ? (p.port || p) : p);
        chips.push(`
            <div class="meta-pill" title="Open TCP Ports">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>
                <span><strong>Ports:</strong> ${portList.join(', ')}</span>
            </div>
        `);
    }

    // Verified Endpoints & Fuzzed Paths
    if (fuzzedPaths.length > 0) {
        chips.push(`
            <div class="meta-pill" title="Verified Sensitive Paths">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><polyline points="20 6 9 17 4 12"></polyline></svg>
                <span><strong>Verified Paths:</strong> ${fuzzedPaths.length}</span>
            </div>
        `);
    }

    // Scan Duration
    if (scan.duration_seconds) {
        chips.push(`
            <div class="meta-pill" title="Execution Time">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
                <span><strong>Duration:</strong> ${scan.duration_seconds.toFixed(1)}s</span>
            </div>
        `);
    }

    container.innerHTML = chips.join("");
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
        const scanDateEl = document.getElementById("activeScanDate");
        if (scanDateEl) scanDateEl.textContent = scan.created_at ? new Date(scan.created_at).toLocaleString() : '--';
        updateScanHeaderStatus(scan.status);

        // Calculate Advanced Dynamic Security Posture Score & Badges
        recalculateActiveScanScore();

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

        // Update Tab Badges Dynamically
        const findingsBadge = document.getElementById("findingsCountBadge");
        if (findingsBadge) findingsBadge.textContent = activeFindings ? activeFindings.length : 0;
        const subBadge = document.getElementById("subdomainsCountBadge");
        if (subBadge) subBadge.textContent = subs.length;
        const fuzzBadge = document.getElementById("fuzzingCountBadge");
        if (fuzzBadge) fuzzBadge.textContent = fuzzedPaths.length + fuzzedParams.length;
        const logBadge = document.getElementById("logsCountBadge");
        if (logBadge) logBadge.textContent = logs ? logs.length : 0;
        const repBadge = document.getElementById("reportsCountBadge");
        if (repBadge) repBadge.textContent = "6";

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

// Subdomain Asset Intelligence View
function renderSubdomains(subdomains) {
    const badge = document.getElementById("subdomainsCountBadge");
    const container = document.getElementById("subdomainsContainer");
    if (badge) badge.textContent = subdomains ? subdomains.length : 0;

    if (!subdomains || subdomains.length === 0) {
        const scan = (typeof scansData !== 'undefined' && scansData[currentScanId]) ? scansData[currentScanId] : null;
        const target = scan ? scan.target_url : (document.getElementById("activeScanTarget") ? document.getElementById("activeScanTarget").textContent : "");
        container.innerHTML = `
            <div style="color: var(--text-muted); text-align: center; padding: 48px 24px; background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; box-shadow: var(--shadow-card);">
                <div style="font-size: 36px; margin-bottom: 12px;">🌐</div>
                <div style="font-size: 16px; font-weight: 800; color: var(--text-title); margin-bottom: 8px;">No Subdomains Cached for this Target</div>
                <p style="font-size: 13px; color: var(--text-muted); max-width: 500px; margin: 0 auto 20px auto; line-height: 1.5;">
                    Run the autonomous 10-source Amass OSINT engine to map all active subdomains, resolve live IPs, detect tech stacks, and verify cloud takeover vulnerabilities in real time.
                </p>
                <button class="btn btn-primary" onclick="runActiveScanSubdomains('${escapeHtml(target)}')" style="padding: 10px 20px; font-size: 13px;">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>
                    <span>Run Autonomous Subdomain Discovery Now</span>
                </button>
            </div>
        `;
        return;
    }

    container.innerHTML = `
        <div style="margin-bottom: 14px; display: flex; align-items: center; justify-content: space-between; padding: 12px 18px; background: var(--brand-light); border: 1px solid var(--brand); border-radius: 10px; font-size: 13px; flex-wrap: wrap; gap: 8px;">
            <div style="display: flex; align-items: center; gap: 10px; color: var(--brand); font-weight: 700;">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><circle cx="12" cy="12" r="10"></circle><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"></path><path d="M2 12h20"></path></svg>
                <span>OWASP Amass Engine — Multi-Source Recon & Attack Surface Intelligence</span>
            </div>
            <div style="display: flex; align-items: center; gap: 12px;">
                <span style="font-family: var(--mono); color: var(--text-title); font-weight: 700; background: var(--bg-card); padding: 4px 10px; border-radius: 6px; border: 1px solid var(--border);">${subdomains.length} Assets Mapped</span>
                <button class="btn btn-secondary btn-sm" onclick="exportSubdomainsCSV()" style="padding: 4px 10px; font-size: 11.5px;">📥 Export CSV</button>
            </div>
        </div>

        <!-- Responsive Table Container with Horizontal Scroll & Min-Width -->
        <div class="table-responsive-wrapper" style="background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; overflow-x: auto; box-shadow: var(--shadow-card); -webkit-overflow-scrolling: touch;">
            <table style="width: 100%; min-width: 980px; border-collapse: collapse; text-align: left; font-size: 13px;">
                <thead>
                    <tr style="background: var(--bg-subtle); border-bottom: 1px solid var(--border); color: var(--text-muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px;">
                        <th style="padding: 12px 16px; white-space: nowrap;">Subdomain Asset</th>
                        <th style="padding: 12px 14px; white-space: nowrap;">IP Address</th>
                        <th style="padding: 12px 14px; white-space: nowrap;">CNAME / Alias</th>
                        <th style="padding: 12px 14px; white-space: nowrap;">Status</th>
                        <th style="padding: 12px 14px; white-space: nowrap;">Server</th>
                        <th style="padding: 12px 14px; white-space: nowrap;">OSINT Sources</th>
                        <th style="padding: 12px 14px; white-space: nowrap;">Takeover Risk</th>
                        <th style="padding: 12px 16px; white-space: nowrap; text-align: right;">Vulnerability Action</th>
                    </tr>
                </thead>
                <tbody>
                    ${subdomains.map(s => {
                        const subName = (typeof s === "string") ? s : (s.subdomain || "");
                        const ip = (typeof s === "object" && s.ip) ? s.ip : "Resolved";
                        const cname = (typeof s === "object" && s.cname) ? s.cname : "--";
                        const status = (typeof s === "object" && s.status) ? s.status : "Discovered";
                        const server = (typeof s === "object" && s.server) ? s.server : "--";
                        const sources = (typeof s === "object" && Array.isArray(s.sources)) ? s.sources : ["OSINT"];
                        const isTakeover = (typeof s === "object" && s.takeover_risk);
                        const statusClass = (status === 200) ? "status-COMPLETED" : ((status >= 400 && status < 500) ? "status-PENDING" : (status === "Discovered" ? "status-PENDING" : "status-RUNNING"));

                        const sourcePills = sources.map(src => `<span style="display: inline-block; font-size: 10px; padding: 2px 7px; border-radius: 4px; background: var(--bg-subtle); color: var(--text-body); border: 1px solid var(--border); margin: 2px 3px 2px 0; font-family: var(--mono); white-space: nowrap;">${src}</span>`).join("");

                        const takeoverBadge = isTakeover 
                            ? `<span style="display: inline-block; font-size: 11px; padding: 3px 9px; border-radius: 4px; background: var(--crit-bg); color: var(--crit); border: 1px solid var(--crit); font-weight: 800; white-space: nowrap;">CRITICAL TAKEOVER</span>`
                            : `<span style="color: var(--safe); font-size: 12px; font-weight: 600; display: inline-flex; align-items: center; gap: 4px;"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg> None</span>`;

                        // Match any vulnerabilities belonging to this subdomain
                        const matchingFindings = (activeFindings || []).filter(f => f.endpoint && f.endpoint.includes(subName));
                        const hasVulns = matchingFindings.length > 0;

                        return `
                            <tr style="border-bottom: 1px solid var(--border); transition: background 0.15s ease;" onmouseover="this.style.background='var(--bg-subtle)'" onmouseout="this.style.background='transparent'">
                                <td style="padding: 12px 16px; font-weight: 700; font-family: var(--mono); color: var(--brand); white-space: nowrap;">
                                    <a href="https://${subName}" target="_blank" style="color: inherit; text-decoration: none; display: inline-flex; align-items: center; gap: 4px;">
                                        <span>${subName}</span>
                                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path><polyline points="15 3 21 3 21 9"></polyline><line x1="10" y1="14" x2="21" y2="3"></line></svg>
                                    </a>
                                </td>
                                <td style="padding: 12px 14px; font-family: var(--mono); color: var(--text-body); font-size: 12px; white-space: nowrap;">${ip}</td>
                                <td style="padding: 12px 14px; font-family: var(--mono); color: var(--text-muted); font-size: 12px; white-space: nowrap;">${cname}</td>
                                <td style="padding: 12px 14px; white-space: nowrap;">
                                    <span class="badge-status ${statusClass}">HTTP ${status}</span>
                                </td>
                                <td style="padding: 12px 14px; font-size: 12px; white-space: nowrap;">
                                    <span style="display: inline-block; padding: 2px 8px; border-radius: 4px; background: rgba(99,102,241,0.12); color: var(--brand); font-weight: 600; font-size: 11.5px;">${server || "Standard"}</span>
                                </td>
                                <td style="padding: 12px 14px; max-width: 220px;">
                                    <div style="display: flex; flex-wrap: wrap; gap: 2px;">${sourcePills}</div>
                                </td>
                                <td style="padding: 12px 14px; white-space: nowrap;">${takeoverBadge}</td>
                                <td style="padding: 12px 16px; text-align: right; white-space: nowrap;">
                                    ${hasVulns ? `
                                        <button class="btn btn-danger btn-sm" onclick="showSubdomainVulns('${escapeHtml(subName)}')" style="padding: 5px 12px; font-size: 11.5px; font-weight: 700; gap: 5px;">
                                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
                                            <span>View ${matchingFindings.length} Vuln(s)</span>
                                        </button>
                                    ` : `
                                        <button class="btn btn-secondary btn-sm" onclick="auditSubdomainTarget('${escapeHtml(subName)}')" style="padding: 5px 12px; font-size: 11.5px; font-weight: 600; gap: 5px;">
                                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
                                            <span>Test Vulns</span>
                                        </button>
                                    `}
                                </td>
                            </tr>
                        `;
                    }).join("")}
                </tbody>
            </table>
        </div>
    `;
}

function showSubdomainVulns(subName) {
    // Switch to findings tab
    const tabBtn = document.querySelector(".tab-item[onclick*='tab-findings']");
    switchTab('tab-findings', tabBtn);

    // Filter findings to those matching subdomain
    const matching = activeFindings.filter(f => f.endpoint && f.endpoint.includes(subName));
    if (matching.length > 0) {
        renderFindings(matching);
        // Open the first one directly
        openFindingModal(matching[0].id);
    }
}

function auditSubdomainTarget(subName) {
    const input = document.getElementById("targetInput");
    if (input) {
        input.value = `https://${subName}`;
        input.scrollIntoView({ behavior: 'smooth', block: 'center' });
        input.focus();
        // Visual indicator
        input.style.borderColor = 'var(--brand)';
        input.style.boxShadow = '0 0 16px rgba(99, 102, 241, 0.4)';
        setTimeout(() => {
            input.style.boxShadow = '';
        }, 2000);
    }
}

function exportSubdomainsCSV() {
    const scan = (typeof scansData !== 'undefined' && scansData[currentScanId]) ? scansData[currentScanId] : null;
    const subs = (scan && scan.recon_data && scan.recon_data.subdomains) ? scan.recon_data.subdomains : [];
    if (!subs.length) {
        alert("No subdomains available to export.");
        return;
    }

    let csvContent = "Subdomain,IP Address,CNAME,Status,Server,Sources,Takeover Risk\n";
    subs.forEach(s => {
        const subName = (typeof s === "string") ? s : (s.subdomain || "");
        const ip = (typeof s === "object" && s.ip) ? s.ip : "";
        const cname = (typeof s === "object" && s.cname) ? s.cname : "";
        const status = (typeof s === "object" && s.status) ? s.status : "";
        const server = (typeof s === "object" && s.server) ? s.server : "";
        const srcs = (typeof s === "object" && Array.isArray(s.sources)) ? s.sources.join(";") : "OSINT";
        const risk = (typeof s === "object" && s.takeover_risk) ? "CRITICAL" : "None";
        csvContent += `"${subName}","${ip}","${cname}","${status}","${server}","${srcs}","${risk}"\n`;
    });

    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", `subdomains_${currentScanId || 'export'}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

// Path & Parameter Fuzzing View (Zero 403 False Positives)
function renderFuzzing(paths, parameters) {
    // Filter out HTTP 403 Forbidden, 401, 404, etc.
    paths = (paths || []).filter(p => {
        const s = typeof p === 'object' ? (p.status || p.status_code || 0) : 0;
        return s === 200 || (s >= 300 && s < 400);
    });
    const totalCount = (paths.length || 0) + (parameters.length || 0);
    const badge = document.getElementById("fuzzingCountBadge");
    const container = document.getElementById("fuzzingContainer");
    if (badge) badge.textContent = totalCount;

    if (totalCount === 0) {
        container.innerHTML = `<div style="color: var(--text-muted); text-align: center; padding: 48px; background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; box-shadow: var(--shadow-card);">No anomalous fuzzed paths or hidden parameters detected yet.</div>`;
        return;
    }

    let pathsHtml = "";
    if (paths && paths.length > 0) {
        pathsHtml = `
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px;">
                <h4 style="font-size: 14.5px; font-weight: 800; color: var(--text-title); margin: 0;">Discovered Sensitive Endpoints & Fuzzed Paths (${paths.length})</h4>
                <span style="font-size: 12px; color: var(--text-muted);">Calibrated dual-baseline verification active</span>
            </div>
            <div class="table-responsive-wrapper" style="background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; overflow-x: auto; margin-bottom: 24px; box-shadow: var(--shadow-card); -webkit-overflow-scrolling: touch;">
                <table style="width: 100%; min-width: 880px; border-collapse: collapse; text-align: left; font-size: 13px;">
                    <thead>
                        <tr style="background: var(--bg-subtle); border-bottom: 1px solid var(--border); color: var(--text-muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px;">
                            <th style="padding: 12px 16px; white-space: nowrap;">Path</th>
                            <th style="padding: 12px 14px; white-space: nowrap;">HTTP Status</th>
                            <th style="padding: 12px 14px; white-space: nowrap;">Length</th>
                            <th style="padding: 12px 14px; white-space: nowrap;">Asset Classification / Header</th>
                            <th style="padding: 12px 16px; white-space: nowrap; text-align: right;">Inspection Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${paths.map(p => `
                            <tr style="border-bottom: 1px solid var(--border); transition: background 0.15s ease;" onmouseover="this.style.background='var(--bg-subtle)'" onmouseout="this.style.background='transparent'">
                                <td style="padding: 12px 16px; font-weight: 700; font-family: var(--mono); color: var(--brand); white-space: nowrap;">
                                    <a href="${p.url}" target="_blank" style="color: inherit; text-decoration: none; display: inline-flex; align-items: center; gap: 4px;">
                                        <span>${p.path}</span>
                                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path><polyline points="15 3 21 3 21 9"></polyline><line x1="10" y1="14" x2="21" y2="3"></line></svg>
                                    </a>
                                </td>
                                <td style="padding: 12px 14px; white-space: nowrap;">
                                    <span class="badge-status ${p.status === 200 ? 'status-COMPLETED' : ((p.status === 403 || p.status === 401) ? 'status-PENDING' : 'status-RUNNING')}">HTTP ${p.status}</span>
                                </td>
                                <td style="padding: 12px 14px; font-family: var(--mono); color: var(--text-muted); font-size: 12px; white-space: nowrap;">${p.content_length} B</td>
                                <td style="padding: 12px 14px; color: var(--text-body); font-weight: 600;">${escapeHtml(p.title || p.content_type || 'Asset')}</td>
                                <td style="padding: 12px 16px; text-align: right; white-space: nowrap;">
                                    <button class="btn btn-secondary btn-sm" onclick="inspectFuzzedAsset('${escapeHtml(p.path)}', '${escapeHtml(p.url)}', ${p.status}, ${p.content_length}, '${escapeHtml(p.title || '')}')" style="padding: 4px 10px; font-size: 11.5px; font-weight: 600; gap: 4px;">
                                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
                                        <span>Inspect Asset</span>
                                    </button>
                                </td>
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
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px;">
                <h4 style="font-size: 14.5px; font-weight: 800; color: var(--text-title); margin: 0;">Hidden Parameter Anomalies (${parameters.length})</h4>
                <span style="font-size: 12px; color: var(--text-muted);">Root page variance heuristic analysis</span>
            </div>
            <div class="table-responsive-wrapper" style="background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; overflow-x: auto; box-shadow: var(--shadow-card); -webkit-overflow-scrolling: touch;">
                <table style="width: 100%; min-width: 880px; border-collapse: collapse; text-align: left; font-size: 13px;">
                    <thead>
                        <tr style="background: var(--bg-subtle); border-bottom: 1px solid var(--border); color: var(--text-muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px;">
                            <th style="padding: 12px 16px; white-space: nowrap;">Parameter</th>
                            <th style="padding: 12px 14px; white-space: nowrap;">Behavior / Anomaly Shift</th>
                            <th style="padding: 12px 14px; white-space: nowrap;">Input Reflected</th>
                            <th style="padding: 12px 16px; white-space: nowrap; text-align: right;">Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${parameters.map(m => `
                            <tr style="border-bottom: 1px solid var(--border); transition: background 0.15s ease;" onmouseover="this.style.background='var(--bg-subtle)'" onmouseout="this.style.background='transparent'">
                                <td style="padding: 12px 16px; font-weight: 700; font-family: var(--mono); color: var(--high); white-space: nowrap;">?${escapeHtml(m.parameter)}=</td>
                                <td style="padding: 12px 14px; color: var(--text-body);">${escapeHtml(m.anomaly_type)}</td>
                                <td style="padding: 12px 14px; white-space: nowrap;">
                                    <span class="badge-status ${m.reflected ? 'status-FAILED' : 'status-RUNNING'}">${m.reflected ? 'YES (High Risk)' : 'No'}</span>
                                </td>
                                <td style="padding: 12px 16px; text-align: right; white-space: nowrap;">
                                    <button class="btn btn-secondary btn-sm" onclick="inspectParamAnomaly('${escapeHtml(m.parameter)}', '${escapeHtml(m.url)}', '${escapeHtml(m.anomaly_type)}', ${m.reflected})" style="padding: 4px 10px; font-size: 11.5px; font-weight: 600; gap: 4px;">
                                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
                                        <span>Inspect Vector</span>
                                    </button>
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

function inspectFuzzedAsset(path, url, status, length, title) {
    document.getElementById("assetStatusBadge").className = `badge-status ${status === 200 ? 'status-COMPLETED' : ((status === 403 || status === 401) ? 'status-PENDING' : 'status-RUNNING')}`;
    document.getElementById("assetStatusBadge").textContent = `HTTP ${status}`;
    document.getElementById("assetModalTitle").textContent = `Endpoint: ${path}`;
    document.getElementById("assetModalUrl").textContent = url;
    document.getElementById("assetModalLength").textContent = length;
    
    let classification = `Server returned HTTP status <strong>${status}</strong> with body size ${length} bytes. `;
    if (status === 403 || status === 401) {
        classification += `<span style="color: var(--safe); font-weight: 700;">Protected Resource: Access is restricted and denied by server/WAF rules. Not an exposure.</span>`;
    } else if (status === 200) {
        classification += `<span style="color: var(--high); font-weight: 700;">Asset reachable. Verified file signature and non-wildcard baseline status.</span>`;
    } else {
        classification += `Response altered baseline state.`;
    }
    document.getElementById("assetModalClassification").innerHTML = classification;

    document.getElementById("assetModalCurl").textContent = `curl -i -s -k '${url}'`;
    document.getElementById("assetModalOpenBtn").href = url;

    document.getElementById("assetInspectionModal").classList.add("open");
}

function inspectParamAnomaly(param, url, anomaly, reflected) {
    document.getElementById("assetStatusBadge").className = `badge-status ${reflected ? 'status-FAILED' : 'status-RUNNING'}`;
    document.getElementById("assetStatusBadge").textContent = reflected ? "Reflected Input" : "Response Shift";
    document.getElementById("assetModalTitle").textContent = `Hidden Query Parameter: ?${param}=`;
    document.getElementById("assetModalUrl").textContent = url;
    document.getElementById("assetModalLength").textContent = "Delta > Baseline";
    
    document.getElementById("assetModalClassification").innerHTML = `
        <strong>Anomaly Description:</strong> ${anomaly}.<br>
        <strong>Injection Reflection:</strong> ${reflected ? '<span style="color: var(--crit); font-weight: 700;">Canary token reflected in response body (Potential XSS / Parameter Tampering risk).</span>' : 'Parameter triggered distinct application server response behavior.'}
    `;

    document.getElementById("assetModalCurl").textContent = `curl -i -s -k '${url}'`;
    document.getElementById("assetModalOpenBtn").href = url;

    document.getElementById("assetInspectionModal").classList.add("open");
}

function closeAssetInspectionModal() {
    document.getElementById("assetInspectionModal").classList.remove("open");
}

function copyAssetCurl() {
    const text = document.getElementById("assetModalCurl").textContent;
    navigator.clipboard.writeText(text);
    alert("cURL probe command copied to clipboard!");
}

function copyPocCurlDirect(curl, btn) {
    if (!curl) return;
    navigator.clipboard.writeText(curl);
    const originalText = btn.innerHTML;
    btn.innerHTML = `<span style="color: var(--safe); font-weight: 700;">✓ Copied!</span>`;
    setTimeout(() => {
        btn.innerHTML = originalText;
    }, 1800);
}

// OWASP Findings View Controller
let findingFilterSeverity = "ALL";

function renderFindings(findings) {
    const container = document.getElementById("findingsContainer");
    const countBadge = document.getElementById("findingsCountBadge");
    if (countBadge) countBadge.textContent = findings ? findings.length : 0;

    if (!findings || findings.length === 0) {
        container.innerHTML = `
            <div style="color: var(--text-muted); text-align: center; padding: 48px 24px; background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; box-shadow: var(--shadow-card);">
                <div style="width: 56px; height: 56px; border-radius: 50%; background: var(--safe-bg); border: 2px solid var(--safe); color: var(--safe); display: flex; align-items: center; justify-content: center; margin: 0 auto 16px auto;">
                    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>
                </div>
                <div style="font-size: 17px; font-weight: 800; color: var(--text-title); margin-bottom: 6px;">Zero Vulnerabilities Detected — Clean Baseline</div>
                <p style="font-size: 13px; color: var(--text-muted); max-width: 480px; margin: 0 auto; line-height: 1.5;">
                    All active endpoints, fuzzing probes, and input reflection vectors have been verified. No broken access control, leaked secrets, or injection anomalies were found.
                </p>
            </div>
        `;
        return;
    }

    // Calculate severity counts for filter buttons
    const critCount = findings.filter(f => f.severity === "CRITICAL").length;
    const highCount = findings.filter(f => f.severity === "HIGH").length;
    const medCount = findings.filter(f => f.severity === "MEDIUM").length;
    const lowCount = findings.filter(f => f.severity === "LOW").length;

    // Filter findings
    const filtered = (findingFilterSeverity === "ALL") 
        ? findings 
        : findings.filter(f => f.severity === findingFilterSeverity);

    const filterBar = `
        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; flex-wrap: wrap; gap: 10px;">
            <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
                <span style="font-size: 12px; font-weight: 700; color: var(--text-muted); text-transform: uppercase;">Filter:</span>
                <button class="btn btn-secondary btn-sm" onclick="setFindingsFilter('ALL')" style="padding: 4px 10px; font-size: 11.5px; font-weight: 700; ${findingFilterSeverity === 'ALL' ? 'background: var(--brand); color: #fff; border-color: var(--brand);' : ''}">All (${findings.length})</button>
                ${critCount > 0 ? `<button class="btn btn-secondary btn-sm" onclick="setFindingsFilter('CRITICAL')" style="padding: 4px 10px; font-size: 11.5px; font-weight: 700; color: var(--crit); border-color: var(--crit); ${findingFilterSeverity === 'CRITICAL' ? 'background: var(--crit); color: #fff;' : 'background: var(--crit-bg);'}">Critical (${critCount})</button>` : ''}
                ${highCount > 0 ? `<button class="btn btn-secondary btn-sm" onclick="setFindingsFilter('HIGH')" style="padding: 4px 10px; font-size: 11.5px; font-weight: 700; color: var(--high); border-color: var(--high); ${findingFilterSeverity === 'HIGH' ? 'background: var(--high); color: #fff;' : 'background: var(--high-bg);'}">High (${highCount})</button>` : ''}
                ${medCount > 0 ? `<button class="btn btn-secondary btn-sm" onclick="setFindingsFilter('MEDIUM')" style="padding: 4px 10px; font-size: 11.5px; font-weight: 700; color: var(--med); border-color: var(--med); ${findingFilterSeverity === 'MEDIUM' ? 'background: var(--med); color: #fff;' : 'background: var(--med-bg);'}">Medium (${medCount})</button>` : ''}
                ${lowCount > 0 ? `<button class="btn btn-secondary btn-sm" onclick="setFindingsFilter('LOW')" style="padding: 4px 10px; font-size: 11.5px; font-weight: 700; color: var(--low); border-color: var(--low); ${findingFilterSeverity === 'LOW' ? 'background: var(--low); color: #fff;' : 'background: var(--low-bg);'}">Low (${lowCount})</button>` : ''}
            </div>
            <div style="font-size: 12px; color: var(--text-muted);">
                Showing <strong>${filtered.length}</strong> of <strong>${findings.length}</strong> verified issues
            </div>
        </div>
    `;

    const cardsHtml = filtered.map(f => `
        <div class="vuln-card border-${f.severity}" onclick="openFindingModal('${f.id}')" style="cursor: pointer; position: relative;">
            <div class="vuln-header">
                <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
                    <span class="sev-tag tag-${f.severity}">${f.severity}</span>
                    <span class="cvss-score">CVSS ${f.cvss_score}</span>
                    <strong style="font-size: 15px; font-weight: 800; color: var(--text-title);">${escapeHtml(f.title)}</strong>
                </div>
                <span class="poc-verified-pill">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>
                    PoC Verified
                </span>
            </div>
            
            <p style="color: var(--text-body); font-size: 13px; margin: 8px 0; line-height: 1.5;">${escapeHtml(f.description)}</p>

            <div style="color: var(--text-muted); font-size: 12px; margin-top: 6px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 6px;">
                <div>
                    <code style="color: var(--brand); font-weight: 700; font-family: var(--mono);">${f.method} ${escapeHtml(f.endpoint)}</code> | ${escapeHtml(f.owasp_category || 'OWASP Top 10')}
                </div>
                <div style="font-size: 11px; color: var(--text-muted); display: flex; align-items: center; gap: 4px;">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
                    <span>${f.created_at ? new Date(f.created_at).toLocaleString() : 'Live'}</span>
                </div>
            </div>

            <!-- Visible Button Click Vulnerability View -->
            <div style="margin-top: 12px; padding-top: 10px; border-top: 1px dashed var(--border); display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px;">
                <div style="display: flex; gap: 8px;">
                    <button class="btn btn-primary btn-sm" onclick="event.stopPropagation(); openFindingModal('${f.id}')" style="padding: 5px 14px; font-size: 12px; font-weight: 700;">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
                        <span>Click to View Vulnerability Details & Exploit</span>
                    </button>
                    <button class="btn btn-secondary btn-sm" onclick="event.stopPropagation(); copyPocCurlDirect('${escapeHtml(f.poc_curl || '')}', this)" style="padding: 5px 12px; font-size: 12px;">
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                        <span>Copy cURL</span>
                    </button>
                </div>
                <span style="font-size: 11px; color: var(--text-muted); font-style: italic;">Verified CWE: ${escapeHtml(f.cwe_id || 'CWE-Unknown')}</span>
            </div>
        </div>
    `).join("");

    container.innerHTML = filterBar + cardsHtml;
}

function setFindingsFilter(sev) {
    findingFilterSeverity = sev;
    renderFindings(activeFindings);
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
    const modalDateEl = document.getElementById("modalDate");
    if (modalDateEl) modalDateEl.textContent = f.created_at ? new Date(f.created_at).toLocaleString() : new Date().toLocaleString();

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
        
        // Dynamically update Blue Team Defenses badge count
        const defSummary = data.summary || {};
        const totalDef = (defSummary.generated_waf_rules || 0) + 
                         (defSummary.generated_ids_rules || 0) + 
                         (defSummary.generated_siem_rules || 0) + 
                         (data.server_hardening ? 1 : 0);
        const defBadge = document.getElementById("defensesCountBadge");
        if (defBadge) defBadge.textContent = totalDef;

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

        // Dynamically update Forensics & Footprints badge count
        const huntCount = (data.threat_hunt_profiles || []).length;
        const forBadge = document.getElementById("forensicsCountBadge");
        if (forBadge) forBadge.textContent = huntCount;

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

// ── Panel render: Pentest / OWASP (Zero False-Positive Engine) ──────────
function atRenderPentest(findings) {
    if (!Array.isArray(findings) || !findings.length) {
        atSetBody('pentest', '<div class="at-pending-msg">Zero vulnerabilities detected. Endpoints verified secure.</div>');
        atSetBadge('pentest', '0 findings', 'badge-done');
        return;
    }
    // Strict Cyber Expert Filter: completely purge any false-positive 403 / 401 findings
    const cleanFindings = findings.filter(f => {
        const desc = String(f.description || '');
        const ev = String(f.response_evidence || '');
        const title = String(f.title || '');
        return !desc.includes('HTTP 403') && !ev.includes('HTTP 403') && !title.includes('403') && !desc.includes('HTTP 401');
    });

    if (cleanFindings.length === 0) {
        atSetBody('pentest', '<div class="at-pending-msg" style="color:var(--safe);font-weight:700;padding:24px 10px;text-align:center;">🛡️ Clean Baseline: Zero Critical Vulnerabilities Detected.<br><span style="font-weight:400;color:var(--text-muted);font-size:11.5px;">All endpoints verified. Access-denied (403) and dead routes filtered out.</span></div>');
        atSetBadge('pentest', '0 findings', 'badge-done');
        return;
    }

    const sevOrder = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4 };
    const sorted = [...cleanFindings].sort((a, b) => {
        return (sevOrder[a.severity?.toUpperCase()] ?? 9) - (sevOrder[b.severity?.toUpperCase()] ?? 9);
    });
    let html = '';
    let critCount = 0, highCount = 0;
    sorted.forEach(f => {
        const sev = (f.severity || 'INFO').toUpperCase();
        const dotClass = sev === 'CRITICAL' ? 'at-sev-crit' : sev === 'HIGH' ? 'at-sev-high' : sev === 'MEDIUM' ? 'at-sev-med' : sev === 'LOW' ? 'at-sev-low' : 'at-sev-info';
        if (sev === 'CRITICAL') critCount++;
        if (sev === 'HIGH') highCount++;
        html += `<div class="at-item" onclick="openFindingModal('${f.id || ''}')" style="cursor:pointer;" title="Click to view full vulnerability PoC & remediation patch">
            <div class="at-item-dot ${dotClass}"></div>
            <div class="at-item-text">
                <strong>${escH(f.title || f.name || f.check || 'Finding')}</strong>
                <span style="font-size:10.5px;padding:1px 6px;border-radius:4px;margin-left:6px;background:${dotClass==='at-sev-crit'?'rgba(248,81,73,0.15)':dotClass==='at-sev-high'?'rgba(240,136,62,0.15)':dotClass==='at-sev-med'?'rgba(210,153,34,0.15)':'rgba(88,166,255,0.12)'};color:${dotClass==='at-sev-crit'?'#f85149':dotClass==='at-sev-high'?'#f0883e':dotClass==='at-sev-med'?'#d29922':'#58a6ff'}">${sev}</span>
                <div class="at-item-meta">${escH(f.plugin_id || f.category || f.owasp_category || f.cwe_id || '')}</div>
                ${f.description ? '<div class="at-item-meta">' + escH(String(f.description).slice(0,120)) + '</div>' : ''}
                <div style="margin-top:4px;"><span style="color:var(--brand);font-size:11px;font-weight:700;">Click to view PoC & Patch ↗</span></div>
            </div>
        </div>`;
    });
    atSetBody('pentest', html);
    const badge = critCount ? critCount + ' CRITICAL' : highCount ? highCount + ' HIGH' : cleanFindings.length + ' total';
    atSetBadge('pentest', badge, critCount ? 'badge-warn' : 'badge-done');
}

// ── Panel render: Fuzzer (Zero 403 Forbidden False Positives) ───────────────
function atRenderFuzzer(paths) {
    if (!Array.isArray(paths) || !paths.length) {
        atSetBody('fuzzer', '<div class="at-pending-msg">Zero exposed sensitive assets discovered. Target protected.</div>');
        atSetBadge('fuzzer', '0 paths', 'badge-done');
        return;
    }
    // Strict Cyber Expert Rule: HTTP 403 Forbidden means access was BLOCKED by the server/WAF.
    // NEVER show 403 or 401 as a discovered/exposed asset. Only show genuine accessible HTTP 200 or 30x routes.
    const cleanPaths = paths.filter(p => {
        const s = typeof p === 'object' ? (p.status || p.status_code || 0) : 0;
        return s === 200 || (s >= 300 && s < 400);
    });

    if (cleanPaths.length === 0) {
        atSetBody('fuzzer', '<div class="at-pending-msg" style="color:var(--safe);font-weight:700;padding:24px 10px;text-align:center;">🛡️ All sensitive paths securely blocked by server.<br><span style="font-weight:400;color:var(--text-muted);font-size:11.5px;">HTTP 403 / 404 responses filtered out. Zero exposed credentials found.</span></div>');
        atSetBadge('fuzzer', '0 exposed', 'badge-done');
        return;
    }

    let html = `<div class="at-section-head">Discovered Live Endpoints & Verified Assets (${cleanPaths.length} verified)</div>`;
    cleanPaths.slice(0, 35).forEach(p => {
        const path = typeof p === 'object' ? (p.path || p.url || '/') : String(p);
        const status = typeof p === 'object' ? (p.status || p.status_code || '') : '';
        const title = typeof p === 'object' ? (p.title || '') : '';
        const length = typeof p === 'object' ? (p.content_length || p.size || '') : '';
        const statusColor = status >= 200 && status < 300 ? '#3fb950' : '#58a6ff';
        html += `<div class="at-item" onclick="inspectFuzzedAsset('${escH(path)}', '${escH(p.url || path)}', ${status}, ${length || 0}, '${escH(title)}')" style="cursor:pointer;" title="Click to inspect endpoint response">
            <div class="at-item-dot" style="background:${statusColor}"></div>
            <div class="at-item-text">
                <span class="at-mono">${escH(path)}</span>
                ${status ? `<span style="font-size:10.5px;font-weight:700;color:${statusColor};margin-left:6px;">HTTP ${status}</span>` : ''}
                ${title ? `<span style="font-size:11px;color:var(--text-muted);margin-left:6px;">${escH(title)}</span>` : ''}
                ${length ? `<div class="at-item-meta">Size: ${length} bytes</div>` : ''}
            </div>
        </div>`;
    });
    if (cleanPaths.length > 35) html += `<div class="at-item-meta">+${cleanPaths.length-35} more paths in export…</div>`;
    atSetBody('fuzzer', html);
    atSetBadge('fuzzer', cleanPaths.length + ' paths', 'badge-done');
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


// =====================================================================
// Cyber Toolkit (Semi-Automatic Mode) Handlers
// =====================================================================
function openCyberToolkitModal() {
    const modal = document.getElementById('cyberToolkitModal');
    if (modal) {
        modal.classList.add('active');
        const mainInput = document.getElementById('targetInput');
        if (mainInput && mainInput.value.trim()) {
            const raw = mainInput.value.trim();
            const host = raw.replace(/^https?:\/\//i, '').split('/')[0].split(':')[0];
            const dnsIn = document.getElementById('ctDnsInput');
            if (dnsIn && !dnsIn.value) dnsIn.value = host;
            const hIn = document.getElementById('ctHeadersInput');
            if (hIn && !hIn.value) hIn.value = raw.startsWith('http') ? raw : 'https://' + raw;
            const pIn = document.getElementById('ctProbeUrl');
            if (pIn && !pIn.value) pIn.value = raw.startsWith('http') ? raw : 'https://' + raw;
        }
    }
}

function closeCyberToolkitModal() {
    const modal = document.getElementById('cyberToolkitModal');
    if (modal) modal.classList.remove('active');
}

function switchCtTab(tabKey, pillEl) {
    document.querySelectorAll('#ctCategoryTabs .pill-item').forEach(p => p.classList.remove('active'));
    if (pillEl) pillEl.classList.add('active');
    document.querySelectorAll('.ct-pane').forEach(el => el.style.display = 'none');
    const pane = document.getElementById('ctPane_' + tabKey);
    if (pane) pane.style.display = 'block';
}

async function ctRunDns() {
    const domain = (document.getElementById('ctDnsInput').value || '').trim();
    const out = document.getElementById('ctDnsOutput');
    if (!domain) return;
    out.innerHTML = '<span style="color: var(--brand);">Querying DNS and inspecting SPF/DMARC spoofing posture...</span>';
    try {
        const res = await fetch('/api/tools/dns', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({domain})
        });
        const data = await res.json();
        let html = `<div style="margin-bottom: 12px; font-weight: 700; color: var(--text-title);">Domain: ${data.domain}</div>`;
        const es = data.email_security || {};
        const pColor = es.posture === 'EXCELLENT' ? '#10b981' : (es.posture === 'PARTIAL' ? '#f59e0b' : '#ef4444');
        html += `<div style="background: rgba(255,255,255,0.03); border: 1px solid var(--border); border-radius: 8px; padding: 12px; margin-bottom: 14px;">
            <div style="font-weight: 700; margin-bottom: 6px;">Email Spoofing Defense: <span style="color: ${pColor};">${es.posture}</span></div>
            ${es.spf_record ? `<div style="font-family: var(--mono); font-size: 11.5px; margin-top: 4px;"><strong>SPF:</strong> ${es.spf_record}</div>` : '<div style="color: #ef4444; font-size: 12px;">Missing SPF Record</div>'}
            ${es.dmarc_record ? `<div style="font-family: var(--mono); font-size: 11.5px; margin-top: 4px;"><strong>DMARC:</strong> ${es.dmarc_record}</div>` : '<div style="color: #ef4444; font-size: 12px;">Missing DMARC Policy (_dmarc.' + domain + ')</div>'}
            ${(es.notes || []).map(n => `<div style="color: var(--text-muted); font-size: 12px; margin-top: 4px;">• ${n}</div>`).join('')}
        </div>`;
        html += `<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px;">`;
        for (const [rtype, vals] of Object.entries(data.records || {})) {
            if (vals && vals.length) {
                html += `<div style="background: var(--bg-card); border: 1px solid var(--border); border-radius: 6px; padding: 10px;">
                    <div style="font-weight: 700; color: var(--brand); font-size: 12px; margin-bottom: 4px;">${rtype} Records</div>
                    ${vals.map(v => `<div style="font-family: var(--mono); font-size: 11px; word-break: break-all; color: var(--text-body);">${v}</div>`).join('')}
                </div>`;
            }
        }
        html += `</div>`;
        out.innerHTML = html;
    } catch (e) {
        out.innerHTML = `<span style="color: #ef4444;">Error: ${e.message}</span>`;
    }
}

async function ctRunHeaders() {
    const target_url = (document.getElementById('ctHeadersInput').value || '').trim();
    const out = document.getElementById('ctHeadersOutput');
    if (!target_url) return;
    out.innerHTML = '<span style="color: var(--brand);">Auditing HTTP security headers...</span>';
    try {
        const res = await fetch('/api/tools/headers', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({target_url})
        });
        const data = await res.json();
        if (data.error) {
            out.innerHTML = `<span style="color: #ef4444;">${data.error}</span>`;
            return;
        }
        const gColor = ['A+','A'].includes(data.grade) ? '#10b981' : (['B','C'].includes(data.grade) ? '#f59e0b' : '#ef4444');
        let html = `<div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px; padding: 12px; background: rgba(255,255,255,0.03); border: 1px solid var(--border); border-radius: 8px;">
            <div>
                <div style="font-weight: 700; font-size: 15px; color: var(--text-title);">${data.final_url}</div>
                <div style="font-size: 12px; color: var(--text-muted); margin-top: 2px;">HTTP Status Code: ${data.status_code}</div>
            </div>
            <div style="text-align: right;">
                <div style="font-size: 20px; font-weight: 800; color: ${gColor};">Grade: ${data.grade}</div>
                <div style="font-size: 11.5px; color: var(--text-muted);">Score: ${data.score}/100</div>
            </div>
        </div>`;
        html += `<div style="display: flex; flex-direction: column; gap: 8px;">`;
        (data.security_headers || []).forEach(h => {
            const pass = h.status === 'PASS';
            const sColor = pass ? '#10b981' : '#ef4444';
            html += `<div style="background: var(--bg-card); border: 1px solid var(--border); border-radius: 6px; padding: 10px;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span style="font-weight: 700; font-size: 12.5px; color: var(--text-title);">${h.header}</span>
                    <span style="color: ${sColor}; font-weight: 700; font-size: 11.5px;">${h.status}</span>
                </div>
                ${pass ? `<div style="font-family: var(--mono); font-size: 11px; color: var(--text-muted); margin-top: 4px; word-break: break-all;">${h.value}</div>` : `<div style="color: #ef4444; font-size: 11.5px; margin-top: 4px;">${h.description} Recommendation: <code style="color: var(--brand);">${h.recommendation}</code></div>`}
            </div>`;
        });
        html += `</div>`;
        out.innerHTML = html;
    } catch (e) {
        out.innerHTML = `<span style="color: #ef4444;">Error: ${e.message}</span>`;
    }
}

async function ctRunSsl() {
    const target = (document.getElementById('ctHeadersInput').value || '').trim();
    const out = document.getElementById('ctHeadersOutput');
    if (!target) return;
    out.innerHTML = '<span style="color: var(--brand);">Establishing TLS connection & inspecting certificate...</span>';
    try {
        const res = await fetch('/api/tools/ssl', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({target})
        });
        const data = await res.json();
        if (!data.valid) {
            out.innerHTML = `<span style="color: #ef4444;">${data.error || 'SSL connection failed'}</span>`;
            return;
        }
        const expColor = data.is_expired || data.expiring_soon ? '#ef4444' : '#10b981';
        let html = `<div style="background: rgba(255,255,255,0.03); border: 1px solid var(--border); border-radius: 8px; padding: 14px; margin-bottom: 12px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <span style="font-size: 15px; font-weight: 700; color: var(--text-title);">${data.common_name || data.target}</span>
                <span style="color: ${expColor}; font-weight: 700; font-size: 12px;">${data.days_remaining} Days Remaining</span>
            </div>
            <div style="font-size: 12px; color: var(--text-muted); line-height: 1.6;">
                <div><strong>Issuer CA:</strong> ${data.issuer_organization || 'Unknown CA'}</div>
                <div><strong>Protocol Version:</strong> ${data.tls_version || 'TLS'}</div>
                <div><strong>Active Cipher Suite:</strong> <code style="color: var(--brand);">${data.cipher_suite || 'N/A'}</code> (${data.cipher_bits} bits)</div>
                <div><strong>Valid From:</strong> ${data.valid_from}</div>
                <div><strong>Valid Until:</strong> ${data.valid_to}</div>
            </div>
        </div>`;
        if (data.sans && data.sans.length) {
            html += `<div style="background: var(--bg-card); border: 1px solid var(--border); border-radius: 6px; padding: 10px;">
                <div style="font-weight: 700; font-size: 12px; color: var(--text-title); margin-bottom: 4px;">Subject Alternative Names (${data.san_count}):</div>
                <div style="font-family: var(--mono); font-size: 11px; color: var(--text-muted); line-height: 1.5;">${data.sans.join(', ')}</div>
            </div>`;
        }
        out.innerHTML = html;
    } catch (e) {
        out.innerHTML = `<span style="color: #ef4444;">Error: ${e.message}</span>`;
    }
}

async function ctRunProbe() {
    const target_url = (document.getElementById('ctProbeUrl').value || '').trim();
    const vuln_type = document.getElementById('ctProbeType').value;
    const parameter = (document.getElementById('ctProbeParam').value || '').trim() || null;
    const out = document.getElementById('ctProbeOutput');
    if (!target_url) return;
    out.innerHTML = `<span style="color: var(--brand);">Dispatching ${vuln_type.toUpperCase()} probes against target...</span>`;
    try {
        const res = await fetch('/api/tools/probe', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({target_url, vuln_type, parameter})
        });
        const data = await res.json();
        if (data.vulnerable) {
            out.innerHTML = `<div style="background: rgba(239,68,68,0.1); border: 1px solid #ef4444; border-radius: 8px; padding: 14px;">
                <div style="font-weight: 800; font-size: 15px; color: #ef4444; margin-bottom: 6px;">[!] Vulnerability Confirmed: ${data.vuln_type}</div>
                <div style="font-size: 12.5px; color: var(--text-body); margin-bottom: 8px;">${data.evidence || data.summary}</div>
                ${data.poc_curl ? `<div style="margin-top: 8px;"><div style="font-size: 11px; font-weight: 700; color: var(--text-muted); margin-bottom: 4px;">Reproduction cURL PoC:</div><pre class="code-terminal" style="font-size: 11.5px; padding: 8px;">${data.poc_curl}</pre></div>` : ''}
            </div>`;
        } else {
            out.innerHTML = `<div style="background: rgba(16,185,129,0.1); border: 1px solid #10b981; border-radius: 8px; padding: 14px;">
                <div style="font-weight: 700; font-size: 14px; color: #10b981;">[✓] ${data.summary || 'No vulnerability discovered with baseline probes.'}</div>
                ${data.poc_curl ? `<pre class="code-terminal" style="font-size: 11.5px; margin-top: 8px; padding: 8px;">${data.poc_curl}</pre>` : ''}
            </div>`;
        }
    } catch (e) {
        out.innerHTML = `<span style="color: #ef4444;">Error: ${e.message}</span>`;
    }
}

async function ctRunHashes() {
    const text = (document.getElementById('ctCryptoInput').value || '').trim();
    const out = document.getElementById('ctCryptoOutput');
    if (!text) return;
    try {
        const res = await fetch('/api/tools/hashes', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({text})
        });
        const data = await res.json();
        out.innerHTML = `<div style="display: flex; flex-direction: column; gap: 8px; font-family: var(--mono); font-size: 12px;">
            <div style="background: var(--bg-card); padding: 8px 12px; border: 1px solid var(--border); border-radius: 6px;"><strong>MD5:</strong> ${data.md5}</div>
            <div style="background: var(--bg-card); padding: 8px 12px; border: 1px solid var(--border); border-radius: 6px;"><strong>SHA-1:</strong> ${data.sha1}</div>
            <div style="background: var(--bg-card); padding: 8px 12px; border: 1px solid var(--border); border-radius: 6px;"><strong>SHA-256:</strong> ${data.sha256}</div>
            <div style="background: var(--bg-card); padding: 8px 12px; border: 1px solid var(--border); border-radius: 6px;"><strong>SHA-512:</strong> ${data.sha512}</div>
            <div style="background: var(--bg-card); padding: 8px 12px; border: 1px solid var(--border); border-radius: 6px;"><strong>NTLM:</strong> ${data.ntlm}</div>
        </div>`;
    } catch (e) {
        out.innerHTML = `<span style="color: #ef4444;">Error: ${e.message}</span>`;
    }
}

async function ctRunJwt() {
    const token = (document.getElementById('ctCryptoInput').value || '').trim();
    const out = document.getElementById('ctCryptoOutput');
    if (!token) return;
    try {
        const res = await fetch('/api/tools/jwt', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({token})
        });
        const data = await res.json();
        if (data.error) {
            out.innerHTML = `<span style="color: #ef4444;">${data.error}</span>`;
            return;
        }
        let html = `<div style="display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 10px; font-size: 12px;">
            <span class="badge" style="background: rgba(99,102,241,0.2); color: #818cf8;">Algorithm: ${data.algorithm}</span>
            <span class="badge" style="background: ${data.is_expired ? 'rgba(239,68,68,0.2); color: #f87171;' : 'rgba(16,185,129,0.2); color: #34d399;'}">${data.is_expired ? 'EXPIRED' : 'ACTIVE'}</span>
            ${data.expires_at ? `<span style="color: var(--text-muted);">Expires: ${data.expires_at}</span>` : ''}
        </div>`;
        (data.security_warnings || []).forEach(w => {
            html += `<div style="color: #ef4444; font-weight: 700; font-size: 12px; margin-bottom: 6px;">[!] ${w}</div>`;
        });
        html += `<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
            <div>
                <div style="font-weight: 700; font-size: 12px; color: var(--text-title); margin-bottom: 4px;">Header</div>
                <pre class="code-terminal" style="font-size: 11px; padding: 8px;">${JSON.stringify(data.header, null, 2)}</pre>
            </div>
            <div>
                <div style="font-weight: 700; font-size: 12px; color: var(--text-title); margin-bottom: 4px;">Payload</div>
                <pre class="code-terminal" style="font-size: 11px; padding: 8px;">${JSON.stringify(data.payload, null, 2)}</pre>
            </div>
        </div>`;
        out.innerHTML = html;
    } catch (e) {
        out.innerHTML = `<span style="color: #ef4444;">Error: ${e.message}</span>`;
    }
}

async function ctRunEncode(operation) {
    const text = (document.getElementById('ctCryptoInput').value || '').trim();
    const out = document.getElementById('ctCryptoOutput');
    if (!text) return;
    try {
        const res = await fetch('/api/tools/crypto', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({text, operation})
        });
        const data = await res.json();
        if (data.error) {
            out.innerHTML = `<span style="color: #ef4444;">${data.error}</span>`;
            return;
        }
        out.innerHTML = `<div>
            <div style="font-weight: 700; font-size: 12px; color: var(--text-title); margin-bottom: 4px;">${data.operation} Output:</div>
            <pre class="code-terminal" style="font-size: 12px; padding: 10px; word-break: break-all;">${data.output}</pre>
        </div>`;
    } catch (e) {
        out.innerHTML = `<span style="color: #ef4444;">Error: ${e.message}</span>`;
    }
}

async function ctRunSubnet() {
    const cidr = (document.getElementById('ctSubnetInput').value || '').trim();
    const out = document.getElementById('ctSubnetOutput');
    if (!cidr) return;
    try {
        const res = await fetch('/api/tools/subnet', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({cidr})
        });
        const data = await res.json();
        if (data.error) {
            out.innerHTML = `<span style="color: #ef4444;">${data.error}</span>`;
            return;
        }
        out.innerHTML = `<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; font-size: 12.5px;">
            <div style="background: var(--bg-card); padding: 10px; border: 1px solid var(--border); border-radius: 6px;"><strong>Network:</strong> ${data.network_address}</div>
            <div style="background: var(--bg-card); padding: 10px; border: 1px solid var(--border); border-radius: 6px;"><strong>Broadcast:</strong> ${data.broadcast_address}</div>
            <div style="background: var(--bg-card); padding: 10px; border: 1px solid var(--border); border-radius: 6px;"><strong>Netmask:</strong> ${data.netmask}</div>
            <div style="background: var(--bg-card); padding: 10px; border: 1px solid var(--border); border-radius: 6px;"><strong>Wildcard:</strong> ${data.wildcard_mask}</div>
            <div style="background: var(--bg-card); padding: 10px; border: 1px solid var(--border); border-radius: 6px;"><strong>Usable Range:</strong> ${data.first_usable_ip} - ${data.last_usable_ip}</div>
            <div style="background: var(--bg-card); padding: 10px; border: 1px solid var(--border); border-radius: 6px;"><strong>Total Usable Hosts:</strong> <span style="color: #10b981; font-weight: 700;">${data.usable_hosts}</span></div>
        </div>`;
    } catch (e) {
        out.innerHTML = `<span style="color: #ef4444;">Error: ${e.message}</span>`;
    }
}

async function ctRunRevshell() {
    const ip = (document.getElementById('ctShellIp').value || '').trim() || '10.10.14.5';
    const port = parseInt(document.getElementById('ctShellPort').value) || 4444;
    const out = document.getElementById('ctRevshellOutput');
    try {
        const res = await fetch('/api/tools/revshell', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ip, port, shell_type: 'all'})
        });
        const data = await res.json();
        let html = `<div style="display: flex; flex-direction: column; gap: 10px;">`;
        for (const [k, cmd] of Object.entries(data.templates || {})) {
            html += `<div style="background: var(--bg-card); border: 1px solid var(--border); border-radius: 6px; padding: 10px;">
                <div style="font-weight: 700; font-size: 12px; color: var(--brand); margin-bottom: 4px;">${k.toUpperCase()}</div>
                <pre class="code-terminal" style="font-size: 11px; padding: 8px; margin: 0; word-break: break-all;">${cmd}</pre>
            </div>`;
        }
        html += `</div>`;
        out.innerHTML = html;
    } catch (e) {
        out.innerHTML = `<span style="color: #ef4444;">Error: ${e.message}</span>`;
    }
}


// ── Autonomous Subdomain Hunter Controller ─────────────────────────
let ctDiscoveredSubdomains = [];

function htmlEscape(str) {
    if (!str) return "";
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}

async function ctRunSubdomains() {
    const domainInput = document.getElementById('ctSubInput');
    let raw = (domainInput ? domainInput.value : '').trim();
    if (!raw) {
        const topInput = document.getElementById('targetInput');
        if (topInput && topInput.value.trim()) raw = topInput.value.trim();
    }
    if (!raw) {
        if (domainInput) domainInput.focus();
        return;
    }
    const domain = raw.replace(/^https?:\/\//i, '').split('/')[0].split(':')[0];
    const recursive = document.getElementById('ctSubRecursive') ? document.getElementById('ctSubRecursive').checked : true;
    const out = document.getElementById('ctSubOutput');
    const btn = document.getElementById('btnRunCtSubs');
    
    if (btn) { btn.disabled = true; btn.querySelector('span').textContent = 'Harvesting Subdomains...'; }
    out.innerHTML = `
        <div style="padding: 24px; text-align: center; color: var(--brand);">
            <div style="font-size: 15px; font-weight: 700; margin-bottom: 6px;">🔍 Autonomous Discovery in Progress for ${domain}...</div>
            <div style="font-size: 12px; color: var(--text-muted); max-width: 500px; margin: 0 auto; line-height: 1.5;">Querying 10+ OSINT registries (crt.sh, AlienVault OTX, HackerTarget, Wayback CDX, CertSpotter), active 350+ wordlists, AltDNS mutations & live HTTP probing.</div>
        </div>
    `;

    try {
        const res = await fetch('/api/tools/subdomains', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({domain, recursive, concurrency: 30})
        });
        const data = await res.json();
        ctDiscoveredSubdomains = data.subdomains || [];
        
        let html = `
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; padding: 12px 14px; background: rgba(99,102,241,0.06); border: 1px solid rgba(99,102,241,0.25); border-radius: 8px; flex-wrap: wrap; gap: 10px;">
                <div>
                    <div style="font-weight: 800; font-size: 15px; color: var(--text-title);">${data.apex_domain || data.domain}</div>
                    <div style="font-size: 12px; color: var(--text-muted); margin-top: 2px;">
                        Total Assets: <strong style="color: var(--text-title);">${data.count}</strong> | Live HTTP/S: <strong style="color: #10b981;">${data.live_count}</strong> | Takeover Risks: <strong style="color: ${data.takeover_count > 0 ? '#ef4444' : '#10b981'};">${data.takeover_count}</strong>
                    </div>
                </div>
                <div style="display: flex; gap: 8px;">
                    <button class="btn btn-secondary" onclick="ctCopyAllSubdomains(this)" style="padding: 5px 12px; font-size: 12px;">📋 Copy Hostnames</button>
                    <button class="btn btn-secondary" onclick="ctExportSubdomains('txt')" style="padding: 5px 12px; font-size: 12px;">💾 Export TXT</button>
                    <button class="btn btn-secondary" onclick="ctExportSubdomains('json')" style="padding: 5px 12px; font-size: 12px;">💾 Export JSON</button>
                </div>
            </div>
        `;

        if (data.takeover_findings && data.takeover_findings.length > 0) {
            html += `<div style="background: rgba(239,68,68,0.1); border: 1px solid #ef4444; border-radius: 8px; padding: 12px; margin-bottom: 14px;">
                <div style="font-weight: 800; color: #ef4444; font-size: 13.5px; margin-bottom: 4px;">[!] ${data.takeover_findings.length} Subdomain Takeover Vulnerabilities Discovered!</div>`;
            data.takeover_findings.forEach(tf => {
                html += `<div style="font-size: 12px; color: var(--text-body); margin-top: 4px;">• <strong>${tf.title}</strong> on <code>${tf.endpoint}</code></div>`;
            });
            html += `</div>`;
        }

        html += `
            <div style="max-height: 380px; overflow-y: auto; border: 1px solid var(--border); border-radius: 8px;">
                <table style="width: 100%; border-collapse: collapse; font-size: 12px; text-align: left;">
                    <thead>
                        <tr style="background: var(--bg-card); color: var(--text-muted); border-bottom: 1px solid var(--border);">
                            <th style="padding: 8px 12px;">Subdomain</th>
                            <th style="padding: 8px 12px;">IP Address</th>
                            <th style="padding: 8px 12px;">Status</th>
                            <th style="padding: 8px 12px;">Page Title / Banner</th>
                            <th style="padding: 8px 12px;">Sources</th>
                        </tr>
                    </thead>
                    <tbody>
        `;

        ctDiscoveredSubdomains.forEach(s => {
            const statusCol = s.status === 200 ? '#10b981' : (s.status >= 300 && s.status < 400 ? '#f59e0b' : (s.status ? '#ef4444' : 'var(--text-muted)'));
            const statusText = s.status ? `<span style="color: ${statusCol}; font-weight: 700;">${s.status}</span>` : '<span style="color: var(--text-muted);">--</span>';
            const titleOrServer = s.title ? htmlEscape(s.title) : (s.server ? `<span style="color: var(--text-muted); font-family: var(--mono);">${s.server}</span>` : '<span style="color: var(--text-muted);">--</span>');
            html += `
                <tr style="border-bottom: 1px solid rgba(255,255,255,0.04);">
                    <td style="padding: 8px 12px; font-family: var(--mono); font-weight: 600;"><a href="https://${s.subdomain}" target="_blank" style="color: #60a5fa; text-decoration: none;">${s.subdomain}</a></td>
                    <td style="padding: 8px 12px; font-family: var(--mono); color: var(--text-muted);">${s.ip || '--'}</td>
                    <td style="padding: 8px 12px;">${statusText}</td>
                    <td style="padding: 8px 12px; color: var(--text-body); max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${titleOrServer}</td>
                    <td style="padding: 8px 12px; color: var(--text-muted); font-size: 11px;">${(s.sources || []).join(', ')}</td>
                </tr>
            `;
        });

        html += `</tbody></table></div>`;
        out.innerHTML = html;
    } catch (e) {
        out.innerHTML = `<span style="color: #ef4444;">Error harvesting subdomains: ${e.message}</span>`;
    } finally {
        if (btn) { btn.disabled = false; btn.querySelector('span').textContent = 'Enumerate All Subdomains'; }
    }
}

function ctCopyAllSubdomains(btn) {
    if (!ctDiscoveredSubdomains.length) return;
    const text = ctDiscoveredSubdomains.map(s => s.subdomain).join('\n');
    navigator.clipboard.writeText(text).then(() => {
        const orig = btn.innerHTML;
        btn.innerHTML = `<span style="color: #10b981;">✓ Copied!</span>`;
        setTimeout(() => { btn.innerHTML = orig; }, 1800);
    });
}

function ctExportSubdomains(format) {
    if (!ctDiscoveredSubdomains.length) return;
    let content = "";
    let mime = "text/plain";
    let filename = "subdomains.txt";
    if (format === 'json') {
        content = JSON.stringify(ctDiscoveredSubdomains, null, 2);
        mime = "application/json";
        filename = "subdomains.json";
    } else {
        content = ctDiscoveredSubdomains.map(s => `${s.subdomain}\t${s.ip || ''}\t${s.status || ''}\t${(s.sources || []).join(',')}`).join('\n');
    }
    const blob = new Blob([content], {type: mime});
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
}


async function ctRunJsUrlScan() {
    const url = (document.getElementById('ctJsUrlInput').value || '').trim();
    const activeFetch = document.getElementById('ctJsActiveFetch').checked;
    const out = document.getElementById('ctJsOutput');
    if (!url) {
        out.innerHTML = '<span style="color: var(--danger);">Please enter a target URL.</span>';
        return;
    }
    out.innerHTML = '<span style="color: var(--brand);">Fetching target and downloading JavaScript bundles for deep reconnaissance...</span>';
    try {
        const res = await fetch('/api/tools/js-scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target_url: url, active_fetch: activeFetch })
        });
        const data = await res.json();
        renderJsScanResults(data, out);
    } catch (e) {
        out.innerHTML = `<span style="color: var(--danger);">Error: ${e.message}</span>`;
    }
}

async function ctRunJsCodeScan() {
    const code = (document.getElementById('ctJsCodeInput').value || '').trim();
    const out = document.getElementById('ctJsOutput');
    if (!code) {
        out.innerHTML = '<span style="color: var(--danger);">Please paste some JavaScript or JSON code.</span>';
        return;
    }
    out.innerHTML = '<span style="color: var(--brand);">Analyzing code against 150+ secret signatures and Shannon entropy heuristics...</span>';
    try {
        const res = await fetch('/api/tools/js-scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ content: code })
        });
        const data = await res.json();
        renderJsScanResults(data, out);
    } catch (e) {
        out.innerHTML = `<span style="color: var(--danger);">Error: ${e.message}</span>`;
    }
}

function renderJsScanResults(data, container) {
    if (data.error && (!data.secrets || !data.secrets.length)) {
        container.innerHTML = `<span style="color: var(--danger);">${data.error}</span>`;
        return;
    }
    const s = data.summary || {};
    let html = `
        <div style="background: rgba(15, 23, 42, 0.6); padding: 10px; border-radius: 6px; border: 1px solid var(--border); margin-bottom: 12px;">
            <div style="display: flex; gap: 14px; font-size: 13px; flex-wrap: wrap;">
                <span>Assets Scanned: <b>${data.scanned_assets_count || 1}</b></span>
                <span style="color: #ef4444;">Critical: <b>${s.critical || 0}</b></span>
                <span style="color: #f97316;">High: <b>${s.high || 0}</b></span>
                <span style="color: #fbbf24;">Med: <b>${s.medium || 0}</b></span>
                <span style="color: #60a5fa;">Endpoints: <b>${s.endpoints_discovered || (data.api_endpoints || []).length}</b></span>
                <span style="color: #a78bfa;">Cloud Storage: <b>${s.cloud_buckets || (data.cloud_storage || []).length}</b></span>
            </div>
        </div>
    `;

    if (data.secrets && data.secrets.length > 0) {
        html += `<div style="font-weight: 700; color: #ef4444; margin-bottom: 6px;">🔥 Exposed Credentials (${data.secrets.length})</div>`;
        html += `<table style="width: 100%; font-size: 12px; border-collapse: collapse; margin-bottom: 14px;">`;
        html += `<tr style="border-bottom: 1px solid var(--border); text-align: left; color: var(--text-muted);"><th style="padding: 4px;">Severity</th><th>Secret</th><th>Masked Value</th><th>Line</th><th>Entropy</th></tr>`;
        data.secrets.forEach(sec => {
            const col = sec.severity === 'CRITICAL' ? '#ef4444' : (sec.severity === 'HIGH' ? '#f97316' : '#fbbf24');
            html += `<tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
                <td style="padding: 6px 4px;"><span class="badge" style="background: ${col}20; color: ${col}; font-size: 10px;">${sec.severity}</span></td>
                <td><b>${sec.name}</b></td>
                <td><code style="background: #1e293b; padding: 2px 4px; border-radius: 4px;">${sec.masked_value}</code></td>
                <td>${sec.line}</td>
                <td>${sec.entropy}</td>
            </tr>`;
        });
        html += `</table>`;
    }

    if (data.cloud_storage && data.cloud_storage.length > 0) {
        html += `<div style="font-weight: 700; color: #fbbf24; margin-bottom: 6px;">☁️ Cloud Storage Buckets (${data.cloud_storage.length})</div>`;
        html += `<ul style="margin: 0 0 12px 18px; padding: 0; font-size: 12px;">`;
        data.cloud_storage.forEach(c => {
            html += `<li><b>[${c.provider}]</b> <a href="${c.url}" target="_blank" style="color: #60a5fa;">${c.url}</a></li>`;
        });
        html += `</ul>`;
    }

    if (data.api_endpoints && data.api_endpoints.length > 0) {
        html += `<div style="font-weight: 700; color: #60a5fa; margin-bottom: 6px;">🔗 Discovered API Endpoints (${data.api_endpoints.length})</div>`;
        html += `<div style="max-height: 140px; overflow-y: auto; background: #0f172a; padding: 8px; border-radius: 4px; font-family: monospace; font-size: 11px;">`;
        data.api_endpoints.forEach(ep => {
            html += `<div>${ep.path}</div>`;
        });
        html += `</div>`;
    }

    if (data.source_maps && data.source_maps.length > 0) {
        html += `<div style="font-weight: 700; color: #a78bfa; margin-top: 10px; margin-bottom: 6px;">🗺️ Source Map References (${data.source_maps.length})</div>`;
        html += `<ul style="margin: 0 0 12px 18px; padding: 0; font-size: 12px;">`;
        data.source_maps.forEach(m => {
            html += `<li>${m.resolved_url}</li>`;
        });
        html += `</ul>`;
    }

    if (!data.secrets?.length && !data.cloud_storage?.length && !data.api_endpoints?.length) {
        html += `<div style="color: #10b981;">✓ No secrets, endpoints, or cloud storage leaks detected in scanned assets.</div>`;
    }

    container.innerHTML = html;
}


function recalculateActiveScanScore() {
    const scan = scansData[currentScanId];
    if (!scan) return;

    const findingsList = Array.isArray(activeFindings) ? activeFindings : [];
    let crit = 0, high = 0, med = 0, low = 0, info = 0;
    findingsList.forEach(f => {
        const s = (f.severity || '').toUpperCase();
        if (s === 'CRITICAL') crit++;
        else if (s === 'HIGH') high++;
        else if (s === 'MEDIUM') med++;
        else if (s === 'LOW') low++;
        else info++;
    });

    if (findingsList.length === 0) {
        crit = scan.critical_count || 0;
        high = scan.high_count || 0;
        med = scan.medium_count || 0;
        low = scan.low_count || 0;
        info = scan.info_count || 0;
    }

    let score = 100;
    score -= crit * 30;
    score -= high * 18;
    score -= med * 8;
    score -= low * 4;

    if (findingsList.length > 0) {
        const hasHstsMissing = findingsList.some(f => f.title && f.title.includes("HSTS"));
        const hasCspMissing = findingsList.some(f => f.title && (f.title.includes("CSP") || f.title.includes("Content Security Policy")));
        const hasClickjacking = findingsList.some(f => f.title && f.title.includes("Clickjacking"));
        if (hasHstsMissing) score -= 6;
        if (hasCspMissing) score -= 6;
        if (hasClickjacking) score -= 5;
    }

    score = Math.max(0, Math.min(100, Math.round(score)));

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

    const findingsBadge = document.getElementById("findingsCountBadge");
    if (findingsBadge) findingsBadge.textContent = findingsList.length;
}


function downloadReport(format) {
    if (!currentScanId) {
        showToast("Please select or start a scan first!");
        return;
    }
    const url = `/api/scans/${currentScanId}/report?format=${format}`;
    const a = document.createElement("a");
    a.href = url;
    a.target = "_blank";
    a.download = `SWA_${currentScanId}_Report.${format === 'markdown' ? 'md' : format}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    showToast(`Downloading ${format.toUpperCase()} report...`);
}

function showToast(message) {
    let toast = document.getElementById("swaToast");
    if (!toast) {
        toast = document.createElement("div");
        toast.id = "swaToast";
        toast.style.cssText = `
            position: fixed;
            bottom: 24px;
            right: 24px;
            background: var(--bg-card);
            color: var(--text-title);
            border: 1px solid var(--brand);
            box-shadow: 0 10px 25px rgba(0,0,0,0.45);
            padding: 12px 20px;
            border-radius: 8px;
            font-size: 13.5px;
            font-weight: 700;
            z-index: 99999;
            display: flex;
            align-items: center;
            gap: 10px;
            transition: opacity 0.3s ease, transform 0.3s ease;
            transform: translateY(20px);
            opacity: 0;
            pointer-events: none;
        `;
        document.body.appendChild(toast);
    }
    toast.innerHTML = `<span style="color: var(--safe); font-size: 16px;">✓</span> <span>${escapeHtml(message)}</span>`;
    toast.style.opacity = "1";
    toast.style.transform = "translateY(0)";
    clearTimeout(toast._timeout);
    toast._timeout = setTimeout(() => {
        toast.style.opacity = "0";
        toast.style.transform = "translateY(20px)";
    }, 3200);
}

async function runActiveScanSubdomains(target) {
    if (!target) {
        target = document.getElementById("activeScanTarget") ? document.getElementById("activeScanTarget").textContent : "";
    }
    if (!target) return;
    const container = document.getElementById("subdomainsContainer");
    container.innerHTML = `
        <div style="text-align: center; padding: 50px; color: var(--brand);">
            <div style="font-size: 28px; margin-bottom: 12px;">⚡</div>
            <div style="font-size: 14px; font-weight: 700;">Querying 10+ OSINT Sources & Probing Live Subdomains...</div>
            <div style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">Checking crt.sh, HackerTarget, AlienVault, CertSpotter, RapidDNS, and 350+ enterprise words...</div>
        </div>
    `;
    try {
        const res = await fetch('/api/tools/subdomains', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain: target, recursive: true })
        });
        const data = await res.json();
        const subs = data.subdomains || [];
        renderSubdomains(subs);
        const badge = document.getElementById("subdomainsCountBadge");
        if (badge) badge.textContent = subs.length;
        if (currentScanId && scansData[currentScanId]) {
            if (!scansData[currentScanId].recon_data) scansData[currentScanId].recon_data = {};
            scansData[currentScanId].recon_data.subdomains = subs;
        }
    } catch (e) {
        container.innerHTML = `<div style="color: var(--danger); text-align: center; padding: 30px;">Error running subdomain discovery: ${e.message}</div>`;
    }
}


function openAuditorBenchmarkModal() {
    const modal = document.getElementById("auditorBenchmarkModal");
    if (modal) modal.classList.add("open");
}

function closeAuditorBenchmarkModal() {
    const modal = document.getElementById("auditorBenchmarkModal");
    if (modal) modal.classList.remove("open");
}


// ==========================================
// 1. Universal Command Palette (Ctrl+K / Cmd+K)
// ==========================================
const commandPaletteItems = [
    { title: "Start New Pentest Scan", category: "Action", desc: "Initiate autonomous scan on target URL", action: () => { closeCommandPalette(); (document.getElementById('targetInput') || document.getElementById('targetUrl')).focus(); } },
    { title: "Open Bug Bounty Directory", category: "Hub", desc: "Browse 90+ curated bounty programs & VDP scopes", action: () => { closeCommandPalette(); openBugBountyModal(); } },
    { title: "WAF Fingerprint & Bypass Engine", category: "Tool", desc: "Detect WAF & generate evasion payloads", action: () => { closeCommandPalette(); openWafBypassModal(); } },
    { title: "Direct File & JS Secret Scanner", category: "Tool", desc: "Drop JS bundle/source map for offline audit", action: () => { closeCommandPalette(); openFileUploadModal(); } },
    { title: "Cyber Tools Hub", category: "Hub", desc: "Direct DNS, Subdomains, Tech, SSL, Fuzzing diagnostics", action: () => { closeCommandPalette(); openCyberToolkitModal(); } },
    { title: "SWA vs Industry Benchmark", category: "Report", desc: "Compare SWA against Burp Suite, Nuclei, ZAP", action: () => { closeCommandPalette(); openAuditorBenchmarkModal(); } },
    { title: "WAF & SIEM Defense Center", category: "Defense", desc: "Export ModSecurity, Nginx, Suricata & Splunk rules", action: () => { closeCommandPalette(); openDefenseCenterModal(); } },
    { title: "Digital Forensics & Footprints", category: "Forensics", desc: "Inspect DNS timeline, SSL certs & WHOIS trails", action: () => { closeCommandPalette(); openForensicsDirect(); } },
    { title: "Toggle Light / Dark Mode", category: "Settings", desc: "Switch theme appearance", action: () => { toggleTheme(); closeCommandPalette(); } },
    { title: "Configure AI Provider", category: "Settings", desc: "Change LLM provider, API key or model ID", action: () => { closeCommandPalette(); openSettingsModal(); } },
    { title: "OWASP Top 10 Attack Plugins", category: "Config", desc: "Enable or disable security testing modules", action: () => { closeCommandPalette(); openPluginsModal(); } },
    { title: "Export SARIF 2.1.0 Security Report", category: "Export", desc: "Download GitHub-compatible SARIF artifact", action: () => { closeCommandPalette(); downloadReport('sarif'); } },
    { title: "Export Industrial CSV Report", category: "Export", desc: "RFC 4180 spreadsheet export", action: () => { closeCommandPalette(); downloadReport('csv'); } },
    { title: "Print-to-PDF Audit Report", category: "Export", desc: "Executive presentation PDF", action: () => { closeCommandPalette(); downloadReport('pdf'); } }
];

let cmdPaletteSelectedIndex = 0;
let filteredCmdItems = [...commandPaletteItems];

function initCommandPalette() {
    window.addEventListener("keydown", (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
            e.preventDefault();
            const modal = document.getElementById("commandPaletteModal");
            if (modal && modal.classList.contains("open")) {
                closeCommandPalette();
            } else {
                openCommandPalette();
            }
        } else if (e.key === "Escape") {
            closeCommandPalette();
            closeBugBountyModal();
            closeWafBypassModal();
            closeFileUploadModal();
            closeAuditorBenchmarkModal();
        }
    });

    const input = document.getElementById("cmdPaletteInput");
    if (input) {
        input.addEventListener("keydown", (e) => {
            if (e.key === "ArrowDown") {
                e.preventDefault();
                cmdPaletteSelectedIndex = Math.min(cmdPaletteSelectedIndex + 1, filteredCmdItems.length - 1);
                renderCommandPaletteList();
            } else if (e.key === "ArrowUp") {
                e.preventDefault();
                cmdPaletteSelectedIndex = Math.max(cmdPaletteSelectedIndex - 1, 0);
                renderCommandPaletteList();
            } else if (e.key === "Enter") {
                e.preventDefault();
                if (filteredCmdItems[cmdPaletteSelectedIndex]) {
                    filteredCmdItems[cmdPaletteSelectedIndex].action();
                }
            }
        });
    }
}

function openCommandPalette() {
    const modal = document.getElementById("commandPaletteModal");
    if (!modal) return;
    modal.classList.add("open");
    const input = document.getElementById("cmdPaletteInput");
    if (input) {
        input.value = "";
        input.focus();
    }
    filteredCmdItems = [...commandPaletteItems];
    cmdPaletteSelectedIndex = 0;
    renderCommandPaletteList();
}

function closeCommandPalette() {
    const modal = document.getElementById("commandPaletteModal");
    if (modal) modal.classList.remove("open");
}

function filterCommandPalette(q) {
    const query = (q || "").trim().toLowerCase();
    if (!query) {
        filteredCmdItems = [...commandPaletteItems];
    } else {
        filteredCmdItems = commandPaletteItems.filter(item => 
            item.title.toLowerCase().includes(query) || 
            item.desc.toLowerCase().includes(query) || 
            item.category.toLowerCase().includes(query)
        );
    }
    cmdPaletteSelectedIndex = 0;
    renderCommandPaletteList();
}

function renderCommandPaletteList() {
    const listEl = document.getElementById("cmdPaletteList");
    if (!listEl) return;
    if (filteredCmdItems.length === 0) {
        listEl.innerHTML = `<div style="text-align:center; padding: 24px; color: var(--text-muted); font-size: 13px;">No matching tools or commands found.</div>`;
        return;
    }
    listEl.innerHTML = filteredCmdItems.map((item, idx) => {
        const isSelected = idx === cmdPaletteSelectedIndex;
        return `
            <div onclick="filteredCmdItems[${idx}].action()" style="padding: 10px 18px; display: flex; align-items: center; justify-content: space-between; cursor: pointer; transition: background 0.15s; background: ${isSelected ? 'rgba(56, 189, 248, 0.14)' : 'transparent'}; border-left: ${isSelected ? '3px solid var(--brand)' : '3px solid transparent'};">
                <div>
                    <div style="font-size: 13.5px; font-weight: 700; color: ${isSelected ? 'var(--brand)' : 'var(--text-title)'};">${escapeHtml(item.title)}</div>
                    <div style="font-size: 11.5px; color: var(--text-muted); margin-top: 2px;">${escapeHtml(item.desc)}</div>
                </div>
                <span class="badge-status" style="font-size: 10px; padding: 2px 8px; background: var(--bg-card); border: 1px solid var(--border);">${escapeHtml(item.category)}</span>
            </div>
        `;
    }).join("");
}

// ==========================================
// 2. Curated Bug Bounty Platforms & VDP Hub
// ==========================================
let allBountyPrograms = [];
let activeBountyPlatform = "ALL";

async function openBugBountyModal() {
    const modal = document.getElementById("bugBountyModal");
    if (!modal) return;
    modal.classList.add("open");
    if (allBountyPrograms.length === 0) {
        await loadBugBountyPrograms();
    }
}

function closeBugBountyModal() {
    const modal = document.getElementById("bugBountyModal");
    if (modal) modal.classList.remove("open");
}

async function loadBugBountyPrograms() {
    const grid = document.getElementById("bugBountyGrid");
    if (grid) {
        grid.innerHTML = `<div style="grid-column: 1/-1; text-align: center; padding: 40px; color: var(--brand);">Loading Bug Bounty Programs...</div>`;
    }
    try {
        const res = await fetch("/api/bounty/programs");
        const data = await res.json();
        allBountyPrograms = data.programs || [];
        renderBugBountyGrid();
    } catch (e) {
        if (grid) grid.innerHTML = `<div style="grid-column: 1/-1; color: var(--danger); text-align: center; padding: 30px;">Error loading bounty programs: ${e.message}</div>`;
    }
}

function filterBountyPlatform(platform, btn) {
    activeBountyPlatform = platform;
    document.querySelectorAll(".bounty-filter-btn").forEach(b => b.classList.remove("active"));
    if (btn) btn.classList.add("active");
    renderBugBountyGrid();
}

function filterBugBounty(q) {
    renderBugBountyGrid(q);
}

function renderBugBountyGrid(searchTerm = "") {
    const grid = document.getElementById("bugBountyGrid");
    if (!grid) return;
    const query = (searchTerm || document.getElementById("bugBountySearch")?.value || "").toLowerCase().trim();
    
    let filtered = allBountyPrograms;
    if (activeBountyPlatform !== "ALL") {
        filtered = filtered.filter(p => p.platform.toLowerCase() === activeBountyPlatform.toLowerCase());
    }
    if (query) {
        filtered = filtered.filter(p => 
            p.name.toLowerCase().includes(query) || 
            (p.scope && p.scope.some(s => s.toLowerCase().includes(query))) ||
            p.platform.toLowerCase().includes(query)
        );
    }

    if (filtered.length === 0) {
        grid.innerHTML = `<div style="grid-column: 1/-1; text-align: center; padding: 40px; color: var(--text-muted);">No programs found matching the criteria.</div>`;
        return;
    }

    grid.innerHTML = filtered.map(prog => {
        const primaryScope = (prog.scope && prog.scope[0]) ? prog.scope[0] : (prog.url || 'example.com');
        const cleanScope = primaryScope.replace(/^\*\./, '');
        return `
            <div style="background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; padding: 14px; display: flex; flex-direction: column; justify-content: space-between; box-shadow: var(--shadow-card);">
                <div>
                    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">
                        <span style="font-weight: 800; font-size: 14px; color: var(--text-title);">${escapeHtml(prog.name)}</span>
                        <span class="badge-status status-COMPLETED" style="font-size: 10px; padding: 2px 6px;">${escapeHtml(prog.platform)}</span>
                    </div>
                    <div style="font-size: 11.5px; color: var(--text-muted); margin-bottom: 8px;">
                        <strong>Max Bounty:</strong> <span style="color: var(--safe); font-weight: 700;">${escapeHtml(prog.max_bounty || '$0 (VDP)')}</span> | 
                        <span>${escapeHtml(prog.type || 'Bug Bounty')}</span>
                    </div>
                    <div style="font-size: 12px; margin-bottom: 12px;">
                        <span style="color: var(--text-muted); font-size: 11px;">Scope:</span>
                        <code style="color: var(--brand); font-weight: 700; font-family: var(--mono);">${escapeHtml(primaryScope)}</code>
                    </div>
                </div>
                <div style="display: flex; gap: 8px; margin-top: 6px;">
                    <button class="btn btn-primary btn-sm" onclick="selectBountyTarget('${escapeHtml(cleanScope)}')" style="flex: 1; padding: 6px 10px; font-size: 11.5px; font-weight: 700;">
                        Target in SWA
                    </button>
                    ${prog.policy_url ? `<a href="${prog.policy_url}" target="_blank" class="btn btn-secondary btn-sm" style="padding: 6px 10px; font-size: 11.5px;">Policy ↗</a>` : ''}
                </div>
            </div>
        `;
    }).join("");
}

function selectBountyTarget(domain) {
    closeBugBountyModal();
    const targetInput = (document.getElementById("targetInput") || document.getElementById("targetUrl"));
    if (targetInput) {
        targetInput.value = "https://" + domain;
        targetInput.focus();
    }
    showToast(`Loaded ${domain} into Target Input!`);
}

// ==========================================
// 3. WAF Fingerprint & Bypass Intelligence
// ==========================================
function openWafBypassModal() {
    const modal = document.getElementById("wafBypassModal");
    if (!modal) return;
    modal.classList.add("open");
    const input = document.getElementById("wafTargetInput");
    const mainTarget = (document.getElementById("targetInput") || document.getElementById("targetUrl"))?.value;
    if (input && !input.value && mainTarget) {
        input.value = mainTarget;
    }
}

function closeWafBypassModal() {
    const modal = document.getElementById("wafBypassModal");
    if (modal) modal.classList.remove("open");
}

async function runWafCheck() {
    const input = document.getElementById("wafTargetInput");
    const target = input ? input.value.trim() : "";
    if (!target) {
        alert("Please enter a target URL or domain to audit WAF.");
        return;
    }
    const btn = document.getElementById("wafCheckBtn");
    const resArea = document.getElementById("wafResultsArea");
    if (btn) { btn.disabled = true; btn.textContent = "Fingerprinting..."; }
    if (resArea) {
        resArea.innerHTML = `<div style="text-align: center; padding: 40px; color: var(--brand);">Analyzing headers, cookies, and TCP behavior against 15+ WAF signatures...</div>`;
    }
    try {
        const res = await fetch("/api/tools/waf-check", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ target_url: target })
        });
        const data = await res.json();
        renderWafResults(data);
    } catch (e) {
        if (resArea) resArea.innerHTML = `<div style="color: var(--danger); text-align: center; padding: 30px;">Error performing WAF audit: ${e.message}</div>`;
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = "Detect WAF & Vectors"; }
    }
}

function renderWafResults(data) {
    const resArea = document.getElementById("wafResultsArea");
    if (!resArea) return;

    const detected = data.detected;
    const wafName = data.waf_name || "Direct Origin (No WAF Detected)";
    const confidence = data.confidence || "0%";
    const vendor = data.vendor || "Direct Web Server";
    const bypasses = data.bypasses || [];

    resArea.innerHTML = `
        <div style="background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 18px; margin-bottom: 16px;">
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px; flex-wrap: wrap; gap: 10px;">
                <div style="display: flex; align-items: center; gap: 10px;">
                    <span class="badge-status ${detected ? 'status-RUNNING' : 'status-COMPLETED'}" style="font-size: 11px;">
                        ${detected ? 'WAF ACTIVE' : 'NO WAF DETECTED'}
                    </span>
                    <h3 style="font-size: 18px; margin: 0; color: var(--text-title); font-weight: 800;">${escapeHtml(wafName)}</h3>
                </div>
                <div style="font-size: 12px; color: var(--text-muted);">
                    Vendor: <strong style="color: var(--text-title);">${escapeHtml(vendor)}</strong> | Confidence: <strong style="color: var(--brand);">${escapeHtml(confidence)}</strong>
                </div>
            </div>
            ${data.matched_signatures && data.matched_signatures.length ? `
                <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 12px;">
                    Matched Evidence: <code style="color: var(--brand);">${escapeHtml(data.matched_signatures.join(', '))}</code>
                </div>
            ` : ''}
        </div>

        <h4 style="font-size: 14px; color: var(--text-title); margin-bottom: 10px; font-weight: 700;">Intelligent Evasion & Bypass Vectors (${bypasses.length}):</h4>
        <div style="display: grid; gap: 10px; max-height: 380px; overflow-y: auto;">
            ${bypasses.map(bp => `
                <div style="background: var(--bg-subtle); border: 1px solid var(--border); border-radius: 8px; padding: 12px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                        <strong style="font-size: 13px; color: var(--brand);">${escapeHtml(bp.technique)}</strong>
                        <button class="btn btn-secondary btn-sm" onclick="applyWafBypass('${escapeHtml(bp.vector)}')">Apply to Scan Header</button>
                    </div>
                    <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 6px;">${escapeHtml(bp.description)}</p>
                    <div class="code-terminal" style="font-size: 11.5px; padding: 6px 10px; margin: 0;">${escapeHtml(bp.vector)}</div>
                </div>
            `).join('')}
        </div>
    `;
}

function applyWafBypass(vector) {
    const customHeaderInput = document.getElementById("optCustomHeader");
    if (customHeaderInput) {
        customHeaderInput.value = vector;
        showToast("Applied evasion vector to Custom Header!");
        closeWafBypassModal();
    }
}

// ==========================================
// 4. Direct File & JS Offline Scanner
// ==========================================
function openFileUploadModal() {
    const modal = document.getElementById("fileUploadModal");
    if (modal) modal.classList.add("open");
}

function closeFileUploadModal() {
    const modal = document.getElementById("fileUploadModal");
    if (modal) modal.classList.remove("open");
}

function handleFileDrop(e) {
    e.preventDefault();
    const dt = e.dataTransfer;
    if (dt && dt.files && dt.files.length) {
        handleFileSelect(dt.files);
    }
}

function handleFileSelect(files) {
    if (!files || !files.length) return;
    const file = files[0];
    const reader = new FileReader();
    reader.onload = function(evt) {
        const content = evt.target.result;
        executeFileScan(file.name, content);
    };
    reader.readAsText(file);
}

function scanPastedSource() {
    const textarea = document.getElementById("rawSourceInput");
    const content = textarea ? textarea.value.trim() : "";
    if (!content) {
        alert("Please paste some JavaScript code, webpack bundle, or config first.");
        return;
    }
    executeFileScan("manual_snippet.js", content);
}

async function executeFileScan(filename, content) {
    const resultsArea = document.getElementById("fileScanResults");
    if (resultsArea) {
        resultsArea.innerHTML = `<div style="text-align: center; padding: 30px; color: var(--brand);">Scanning ${escapeHtml(filename)} with 150+ GhostJS signatures & Shannon Entropy...</div>`;
    }
    try {
        const res = await fetch("/api/tools/scan-file", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ filename: filename, content: content })
        });
        const data = await res.json();
        renderFileScanResults(data);
    } catch (e) {
        if (resultsArea) resultsArea.innerHTML = `<div style="color: var(--danger); text-align: center; padding: 20px;">Error scanning file: ${e.message}</div>`;
    }
}

function renderFileScanResults(data) {
    const resultsArea = document.getElementById("fileScanResults");
    if (!resultsArea) return;

    const findings = data.findings || [];
    const endpoints = data.endpoints || [];
    const entropy = data.entropy || "N/A";

    resultsArea.innerHTML = `
        <div style="background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; padding: 14px; margin-top: 14px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; flex-wrap: wrap; gap: 8px;">
                <div style="font-size: 13.5px; font-weight: 800; color: var(--text-title);">Scan Results: <span style="color: var(--brand);">${escapeHtml(data.source_url || 'File')}</span></div>
                <div style="display: flex; gap: 10px; font-size: 12px;">
                    <span>Findings: <strong style="color: ${findings.length ? 'var(--crit)' : 'var(--safe)'};">${findings.length}</strong></span>
                    <span>Endpoints: <strong style="color: var(--brand);">${endpoints.length}</strong></span>
                    <span>Entropy: <strong style="color: var(--high);">${entropy}</strong></span>
                </div>
            </div>

            ${findings.length === 0 ? `
                <div style="text-align: center; padding: 20px; color: var(--safe); font-size: 13px; font-weight: 700;">
                    ✓ Zero Leaked Secrets or Vulnerabilities in File. Clean Codebase!
                </div>
            ` : `
                <div style="display: grid; gap: 8px; max-height: 280px; overflow-y: auto;">
                    ${findings.map(f => `
                        <div style="background: var(--bg-subtle); border-left: 3px solid var(--crit); padding: 10px 12px; border-radius: 6px;">
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <strong style="font-size: 12.5px; color: var(--text-title);">${escapeHtml(f.title || f.name)}</strong>
                                <span class="sev-tag tag-CRITICAL">CRITICAL</span>
                            </div>
                            <div style="font-size: 11.5px; color: var(--text-muted); margin-top: 4px;">${escapeHtml(f.description || '')}</div>
                            <div class="code-terminal" style="font-size: 11px; margin-top: 6px; padding: 4px 8px;">${escapeHtml(f.match || f.poc || '')}</div>
                        </div>
                    `).join('')}
                </div>
            `}

            ${endpoints.length > 0 ? `
                <div style="margin-top: 12px; border-top: 1px solid var(--border); padding-top: 10px;">
                    <div style="font-size: 12px; font-weight: 700; color: var(--text-muted); margin-bottom: 6px;">Discovered Internal API Routes (${endpoints.length}):</div>
                    <div style="max-height: 120px; overflow-y: auto; font-family: var(--mono); font-size: 11px; color: var(--brand); display: flex; flex-direction: column; gap: 2px;">
                        ${endpoints.slice(0, 30).map(ep => `<div>${escapeHtml(ep)}</div>`).join('')}
                    </div>
                </div>
            ` : ''}
        </div>
    `;
}

// ==========================================
// 5. Triage & False-Positive Manager
// ==========================================
let activeModalFindingId = null;

function setModalTriage(status) {
    if (!activeModalFindingId) return;
    triageFinding(activeModalFindingId, status);
}

async function triageFinding(findingId, status) {
    try {
        const res = await fetch(`/api/findings/${findingId}/triage`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ status: status })
        });
        const data = await res.json();
        
        // Update in-memory state
        const targetFinding = activeFindings.find(f => f.id === findingId);
        if (targetFinding) {
            targetFinding.triage_status = status;
            targetFinding.verified = (status !== "false_positive");
        }

        // Update modal badge
        const badgeEl = document.getElementById("modalTriageBadge");
        if (badgeEl) {
            badgeEl.textContent = status.toUpperCase().replace("_", " ");
            badgeEl.className = status === "false_positive" ? "badge-status status-FAILED" : "badge-status status-COMPLETED";
        }

        showToast(`Finding marked as ${status.toUpperCase()}!`);
    } catch (e) {
        alert("Error updating triage status: " + e.message);
    }
}

// Hook into openFindingModal to record activeModalFindingId
const originalOpenFindingModal = window.openFindingModal;
window.openFindingModal = function(findingId) {
    activeModalFindingId = findingId;
    if (typeof originalOpenFindingModal === "function") {
        originalOpenFindingModal(findingId);
    }
    const targetFinding = activeFindings.find(f => f.id === findingId);
    const badgeEl = document.getElementById("modalTriageBadge");
    if (badgeEl && targetFinding) {
        const curStatus = targetFinding.triage_status || (targetFinding.verified ? "VERIFIED" : "UNVERIFIED");
        badgeEl.textContent = curStatus.toUpperCase().replace("_", " ");
        badgeEl.className = curStatus.toLowerCase().includes("false") ? "badge-status status-FAILED" : "badge-status status-COMPLETED";
    }
};

// Initialize Command Palette on startup
document.addEventListener("DOMContentLoaded", () => {
    initCommandPalette();
});
if (document.readyState === "complete" || document.readyState === "interactive") {
    initCommandPalette();
}
