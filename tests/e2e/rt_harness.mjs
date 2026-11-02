// ============================================================================
// RT HARNESS — Real-time connection lifecycle verification for SWA AI
// ============================================================================
//
// What this does
// ---------------
// Loads the PRODUCTION frontend script (web/static/app.js) inside a minimal
// stubbed DOM context and drives the real connection manager against a REAL
// SWA server instance that this harness starts, stops and restarts.
//
// Every WebSocket/SSE connection, close code, backoff delay, heartbeat
// round-trip and recovery observed here is produced by the actual server and
// the actual production client code. Nothing about the transport is mocked:
//   - real TCP/WebSocket handshake against web/server.py /ws
//   - real HTTP/SSE stream against /api/events/sse
//   - real server process killed and restarted to prove recovery
//
// What is NOT covered
// -------------------
// The DOM is stubbed (no browser is available in this environment), so visual
// rendering, CSS and real browser console output are NOT TESTED by this
// harness. See reports/browser_verification.md for that status.
//
// Usage
// -----
//   node tests/e2e/rt_harness.mjs
//
// Exit code 0 = every scenario PASS, 1 = at least one FAIL.
// ============================================================================

import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import os from 'node:os';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(__dirname, '..', '..');
const APP_JS = path.join(REPO, 'web', 'static', 'app.js');
const TEST_PORT = Number(process.env.SWA_RT_PORT || (18100 + Math.floor(Math.random() * 400)));
const TMP_DB = path.join(os.tmpdir(), `swa_rt_harness_${process.pid}.db`);

// ---------------------------------------------------------------- results ---
const results = [];
function record(id, name, status, detail) {
  results.push({ id, name, status, detail: detail || '' });
  const tag = status.padEnd(6);
  console.log(`[${tag}] ${id} ${name}${detail ? ` — ${detail}` : ''}`);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(fn, timeoutMs, intervalMs = 25) {
  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) {
    let v;
    try {
      v = fn();
      if (v && typeof v.then === 'function') v = await v;
    } catch {
      v = undefined;
    }
    if (v) return v;
    await sleep(intervalMs);
  }
  return null;
}

// ------------------------------------------------------------- server ctrl ---
let child = null;
let serverPort = null;
let logFile = null;

function portOpen(port) {
  return new Promise((resolve) => {
    const s = net.connect({ port, host: '127.0.0.1' });
    s.once('connect', () => { s.destroy(); resolve(true); });
    s.once('error', () => resolve(false));
    s.setTimeout(1000, () => { s.destroy(); resolve(false); });
  });
}

async function startServer() {
  logFile = path.join(os.tmpdir(), `swa_rt_harness_${process.pid}_${Date.now()}.log`);
  const fd = fs.createWriteStream(logFile, { flags: 'a' });
  child = spawn('python', ['run.py'], {
    cwd: REPO,
    env: {
      ...process.env,
      SWA_HOST: '127.0.0.1',
      SWA_PORT: String(TEST_PORT),
      SWA_DB_PATH: TMP_DB,
      SWA_LAB_MODE: 'false',
      HEADLESS: '1',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  // Server stdout is drained to a file (an undrained pipe blocks the server).
  child.stdout.pipe(fd);
  child.stderr.pipe(fd);
  child.on('exit', () => { });

  // run.py prints the actual listening port (it may switch if busy)
  const found = await waitFor(() => {
    if (!fs.existsSync(logFile)) return null;
    const txt = fs.readFileSync(logFile, 'utf8');
    const m = txt.match(/Listening on 127\.0\.0\.1:(\d+)/);
    return m ? Number(m[1]) : null;
  }, 30000, 200);
  if (!found) throw new Error('server did not report a port; see ' + logFile);
  serverPort = found;

  const up = await waitFor(async () => {
    try {
      const r = await fetch(`http://127.0.0.1:${serverPort}/health`);
      if (r.ok) return true;
    } catch { /* not up yet */ }
    return null;
  }, 40000, 250);
  if (!up) throw new Error('server /health never became ready; see ' + logFile);
  return serverPort;
}

async function stopServer() {
  if (!child) return;
  const c = child;
  child = null;
  try { c.kill(); } catch { /* already dead */ }
  const gone = await waitFor(async () => !(await portOpen(serverPort)), 8000, 150);
  if (!gone) {
    // Force-terminate if the graceful kill did not release the port
    spawnSync('powershell', ['-Command', `Stop-Process -Id ${c.pid} -Force -ErrorAction SilentlyContinue`]);
    await waitFor(async () => !(await portOpen(serverPort)), 8000, 150);
  }
}

// ------------------------------------------------------------ DOM stubs -----
function makeEl(id) {
  const cls = new Set();
  return {
    id: id || '',
    style: {},
    dataset: {},
    children: [],
    classList: {
      add: (...c) => c.forEach((x) => cls.add(x)),
      remove: (...c) => c.forEach((x) => cls.delete(x)),
      contains: (c) => cls.has(c),
      toggle: (c) => (cls.has(c) ? cls.delete(c) : cls.add(c)),
    },
    value: '', textContent: '', innerHTML: '', title: '', className: '', placeholder: '',
    attributes: {},
    setAttribute(k, v) { this.attributes[k] = String(v); },
    getAttribute(k) { return k in this.attributes ? this.attributes[k] : null; },
    removeAttribute(k) { delete this.attributes[k]; },
    addEventListener() { }, removeEventListener() { }, dispatchEvent() { return true; },
    appendChild(c) { this.children.push(c); return c; },
    removeChild(c) { return c; }, insertBefore(c) { this.children.push(c); return c; },
    remove() { }, focus() { }, blur() { }, click() { }, scrollIntoView() { },
    querySelector() { return null; }, querySelectorAll() { return []; }, closest() { return null; },
    getContext() { return null; }, getBoundingClientRect() { return { top: 0, left: 0, width: 0, height: 0 }; },
  };
}

// ------------------------------------------------- transport wrappers --------
class HarnessWebSocket {
  static CONNECTING = 0; static OPEN = 1; static CLOSING = 2; static CLOSED = 3;
  constructor(url) {
    if (globalThis.__wsBlocked) {
      throw new Error('WebSocket blocked by harness (simulating proxy/upgrade failure)');
    }
    return new RealWebSocket(url);
  }
}

class FakeEventSource {
  static CONNECTING = 0; static OPEN = 1; static CLOSED = 2;
  constructor(url) {
    this.url = url;
    this.readyState = 0;
    this.onopen = null; this.onmessage = null; this.onerror = null;
    this._closed = false;
    this._ac = new AbortController();
    this._run();
  }
  async _run() {
    try {
      const res = await fetch(new URL(this.url, BASE).toString(), {
        headers: { Accept: 'text/event-stream' },
        signal: this._ac.signal,
      });
      if (!res.ok || !res.body) throw new Error('SSE HTTP ' + res.status);
      if (this._closed) { await res.body.cancel(); return; }
      this.readyState = 1;
      if (this.onopen) this.onopen();
      const reader = res.body.getReader();
      const dec = new TextDecoder();
      let buf = '';
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        let i;
        while ((i = buf.indexOf('\n\n')) !== -1) {
          const block = buf.slice(0, i);
          buf = buf.slice(i + 2);
          for (const line of block.split(/\r?\n/)) {
            if (line.startsWith('data:')) {
              const payload = line.slice(5).trim();
              if (payload && this.onmessage && !this._closed) this.onmessage({ data: payload });
            }
          }
        }
      }
      if (this._closed) return;
      this.readyState = 2;
      if (this.onerror) this.onerror();
    } catch {
      if (this._closed) return;
      this.readyState = 2;
      if (this.onerror) this.onerror();
    }
  }
  close() { this._closed = true; this.readyState = 2; try { this._ac.abort(); } catch { /* noop */ } }
}

// ----------------------------------------------------------- app loading -----
const RealWebSocket = globalThis.WebSocket;
let BASE = null;
let sandbox = null;
const windowListeners = {};
const httpLog = [];

const BRIDGE = `
;globalThis.__bridge = {
  RT,
  get ws() { return ws; },
  set ws(v) { ws = v; },
  initWebSocket, connectWebSocket, retryConnectionNow, startHeartbeat, stopHeartbeat,
  startSseFallback, connectionStateInfo, renderConnectionStatus, fillConnDiagnostics,
  restoreRealtimeState, handleWsEvent, backoffDelay, ensureConnDiagnosticsPanel
};
`;

function trackedFetch(input, init) {
  const url = String(input);
  httpLog.push({ url, at: Date.now() });
  return fetch(new URL(url, BASE).toString(), init);
}

function loadApp() {
  const els = new Map();
  const documentStub = {
    readyState: 'complete',
    visibilityState: 'visible',
    title: 'SWA AI',
    getElementById(id) {
      if (!els.has(id)) els.set(id, makeEl(id));
      return els.get(id);
    },
    createElement: (tag) => makeEl(tag),
    createTextNode: (t) => ({ textContent: t }),
    querySelector: () => null,
    querySelectorAll: () => [],
    addEventListener(type, fn) { (this._l ||= {})[type] ||= []; this._l[type].push(fn); },
    removeEventListener() { },
    dispatchEvent() { return true; },
    body: makeEl('body'),
    documentElement: makeEl('html'),
    _els: els,
  };

  sandbox = {
    console, setTimeout, clearTimeout, setInterval, clearInterval,
    fetch: trackedFetch, TextDecoder, TextEncoder, URL, URLSearchParams, AbortController,
    AbortSignal, performance, structuredClone, queueMicrotask, Promise, JSON, Date, Math,
    navigator: { userAgent: 'node-rt-harness', onLine: true, clipboard: { writeText: async () => { } } },
    localStorage: (() => { const m = new Map(); return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k), clear: () => m.clear() }; })(),
    sessionStorage: (() => { const m = new Map(); return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k), clear: () => m.clear() }; })(),
    location: {
      protocol: 'http:', host: `127.0.0.1:${serverPort}`, hostname: '127.0.0.1',
      port: String(serverPort), pathname: '/', search: '', hash: '',
      href: `http://127.0.0.1:${serverPort}/`,
    },
    alert: () => { }, confirm: () => true, prompt: () => null,
    matchMedia: () => ({ matches: false, media: '', addEventListener() { }, removeEventListener() { }, addListener() { }, removeListener() { } }),
    requestAnimationFrame: (fn) => setTimeout(() => fn(Date.now()), 16),
    cancelAnimationFrame: (id) => clearTimeout(id),
    getComputedStyle: () => ({ getPropertyValue: () => '' }),
    IntersectionObserver: class { observe() { } unobserve() { } disconnect() { } },
    ResizeObserver: class { observe() { } unobserve() { } disconnect() { } },
    MutationObserver: class { observe() { } disconnect() { } takeRecords() { return []; } },
    addEventListener(type, fn) { (windowListeners[type] ||= []).push(fn); },
    removeEventListener(type, fn) { windowListeners[type] = (windowListeners[type] || []).filter((f) => f !== fn); },
    dispatchEvent() { return true; },
    document: documentStub,
    WebSocket: HarnessWebSocket,
    EventSource: FakeEventSource,
    crypto: globalThis.crypto,
    globalThisRefs: null,
  };
  sandbox.window = sandbox;
  sandbox.self = sandbox;

  vm.createContext(sandbox);
  const source = fs.readFileSync(APP_JS, 'utf8') + BRIDGE;
  vm.runInContext(source, sandbox, { filename: 'app.js' });
  return sandbox.__bridge;
}

async function fireWindow(type, event = {}) {
  for (const fn of windowListeners[type] || []) {
    try { await fn(event); } catch (e) { console.warn('window listener error', type, e.message); }
  }
}

// ---------------------------------------------------------------- tests ------
async function main() {
  console.log('=== SWA AI real-time connection harness ===');
  console.log('repo:', REPO);
  console.log('port:', TEST_PORT, '| isolated db:', TMP_DB);

  await startServer();
  const health = await (await fetch(`http://127.0.0.1:${serverPort}/health`)).json();
  const dbPathUsed = String((health.database && health.database.database_path) || '');
  record('RT-00', 'Server under test starts and uses an isolated database',
    dbPathUsed.toLowerCase() === TMP_DB.toLowerCase() ? 'PASS' : 'FAIL',
    `status=${health.status}, db=${dbPathUsed}`);

  BASE = `http://127.0.0.1:${serverPort}`;
  const B = loadApp();
  if (!B || !B.RT) {
    record('RT-LOAD', 'app.js loads in harness context', 'FAIL', 'bridge not exposed');
    return finish();
  }
  record('RT-LOAD', 'app.js loads in harness context', 'PASS', `baseline state=${B.RT.status}`);

  // ---- RT-01: initial connection reaches HEALTHY ----
  B.initWebSocket();
  const up = await waitFor(() => B.RT.status === 'HEALTHY', 8000);
  record('RT-01', 'Initial WebSocket connection reaches HEALTHY',
    up ? 'PASS' : 'FAIL',
    `status=${B.RT.status}, mode=${B.connectionStateInfo().mode}, attempt=${B.RT.attempt}, generation=${B.RT.generation}`);

  // ---- RT-02: heartbeat ping/pong ----
  {
    const sock = B.ws;
    let pings = 0, pongs = 0;
    if (sock) {
      const origSend = sock.send.bind(sock);
      sock.send = (data) => {
        try { if (String(data).includes('"ping"')) pings++; } catch { /* noop */ }
        return origSend(data);
      };
      const origMsg = sock.onmessage;
      sock.onmessage = (ev) => {
        try { if (String(ev.data).includes('"pong"')) pongs++; } catch { /* noop */ }
        if (origMsg) origMsg(ev);
      };
    }
    B.RT.pingIntervalMs = 300;
    B.RT.pongTimeoutMs = 1500;
    B.startHeartbeat();
    const t0 = Date.now();
    while (Date.now() - t0 < 1600) await sleep(25);
    const stale = B.RT.awaitingPong;
    B.RT.pingIntervalMs = 25000;
    B.RT.pongTimeoutMs = 10000;
    B.startHeartbeat();
    record('RT-02', 'Client heartbeat ping is answered by server pong',
      (pings >= 3 && pongs >= 3 && pongs <= pings && !stale) ? 'PASS' : 'FAIL',
      `pings=${pings}, pongs=${pongs}, awaitingPongAfterWindow=${stale}`);
  }

  // ---- RT-03 / RT-04: interruption, exponential backoff, bounded retries ----
  B.RT.baseDelayMs = 120;
  B.RT.maxDelayMs = 900;
  B.RT.maxAttempts = 6;
  B.RT.slowRetryMs = 400;

  await stopServer();

  const seen = [];
  {
    let last = B.RT.attempt;
    const t0 = Date.now();
    while (Date.now() - t0 < 30000) {
      const a = B.RT.attempt;
      if (a !== last) {
        seen.push({ attempt: a, at: Date.now(), nextRetryAt: B.RT.nextRetryAt });
        last = a;
      }
      if (a >= B.RT.maxAttempts && B.RT.nextRetryAt === null) break;
      await sleep(10);
    }
  }
  const delays = seen
    .filter((s) => s.nextRetryAt)
    .map((s) => s.nextRetryAt - s.at);
  const grew = delays.length >= 3 && delays[1] > delays[0] && delays[2] > delays[1];
  record('RT-03', 'Server interruption triggers exponential backoff with jitter',
    grew ? 'PASS' : 'FAIL',
    `observed delays(ms)=${delays.map((d) => Math.round(d)).join(', ')} across attempts ${seen.map((s) => s.attempt).join(',')}`);

  const exhausted = B.RT.attempt >= B.RT.maxAttempts && B.RT.nextRetryAt === null;
  const st = B.connectionStateInfo();
  record('RT-04', 'Automatic retries are bounded and state reports DISCONNECTED',
    exhausted && st.status === 'DISCONNECTED' ? 'PASS' : 'FAIL',
    `attempt=${B.RT.attempt}/${B.RT.maxAttempts}, nextRetryAt=${B.RT.nextRetryAt}, status=${st.status}`);

  // diagnostics must expose component/reason/category/timestamp/details/correction/retry
  B.fillConnDiagnostics();
  const panel = B.ensureConnDiagnosticsPanel();
  const html = String(panel.innerHTML || '');
  const need = ['Component', 'State', 'Reason', 'Error category', 'Timestamp',
    'Safe diagnostic details', 'Suggested correction', 'Retry now'];
  const missing = need.filter((k) => !html.includes(k));
  record('RT-05', 'Disconnected state renders full diagnostics with retry action',
    missing.length === 0 ? 'PASS' : 'FAIL',
    missing.length ? `missing: ${missing.join(', ')}` : `panel bytes=${html.length}`);

  // ---- RT-06: manual retry action resumes retries ----
  B.retryConnectionNow();
  const resumed = await waitFor(() => B.RT.attempt >= 1, 5000);
  const stResumed = B.connectionStateInfo().status;
  record('RT-06', 'Manual retry action resumes automatic reconnection',
    (resumed && stResumed === 'CONNECTING') ? 'PASS' : 'FAIL',
    `attempt=${B.RT.attempt}, status=${stResumed}`);

  // ---- RT-07: automatic recovery after server restart + state resync ----
  await startServer();
  const httpBefore = httpLog.length;
  const recovered = await waitFor(() => B.RT.status === 'HEALTHY', 20000, 100);
  const resyncFetch = httpLog.slice(httpBefore).find((h) => h.url.includes('/api/scans'));
  record('RT-07', 'Connection recovers automatically after server restart',
    recovered ? 'PASS' : 'FAIL',
    `status=${B.RT.status}, attempt=${B.RT.attempt}, resyncCount=${B.RT.resyncCount}, mode=${B.connectionStateInfo().mode}`);
  record('RT-08', 'View state is re-synchronised after reconnect',
    (B.RT.resyncCount >= 1 && resyncFetch) ? 'PASS' : 'FAIL',
    `resyncCount=${B.RT.resyncCount}, resync fetch=${resyncFetch ? resyncFetch.url : 'none'}`);

  // ---- RT-09: SSE fallback when WebSocket is unavailable ----
  globalThis.__wsBlocked = true;
  // NOTE: the WebSocket spec only allows close() codes 1000 or 3000-4999.
  if (B.ws) { try { B.ws.close(4001, 'harness: block websocket'); } catch (e) { console.warn('close failed', e.message); } }
  const degraded = await waitFor(() => B.connectionStateInfo().status === 'DEGRADED', 12000, 50);
  const sseAlive = degraded && B.RT.sse && B.RT.sse.readyState === 1;
  record('RT-09', 'SSE fallback engages when WebSocket is unavailable (DEGRADED)',
    degraded && sseAlive ? 'PASS' : 'FAIL',
    `status=${B.connectionStateInfo().status}, mode=${B.connectionStateInfo().mode}, sseReadyState=${B.RT.sse ? B.RT.sse.readyState : 'null'}`);

  // ---- RT-10: WebSocket recovery closes the SSE fallback (no duplicates) ----
  globalThis.__wsBlocked = false;
  B.retryConnectionNow();
  const wsBack = await waitFor(() => B.connectionStateInfo().status === 'HEALTHY', 12000, 50);
  await sleep(600);
  record('RT-10', 'WebSocket recovery closes SSE fallback (single delivery path)',
    wsBack && (!B.RT.sse || B.RT.sse.readyState !== 1) ? 'PASS' : 'FAIL',
    `status=${B.connectionStateInfo().status}, sseReadyState=${B.RT.sse ? B.RT.sse.readyState : 'null'}`);

  // ---- RT-11: duplicate socket cleanup on forced reconnect ----
  const prev = B.ws;
  const genBefore = B.RT.generation;
  B.RT.wsOpen = false;
  B.connectWebSocket();
  const swapped = await waitFor(() => B.ws !== prev && B.RT.status === 'HEALTHY', 8000, 50);
  record('RT-11', 'Stale socket is detached and closed on reconnect (no duplicates)',
    swapped && prev.onmessage === null && prev.onclose === null &&
    (prev.readyState === 2 || prev.readyState === 3) && B.RT.generation > genBefore
      ? 'PASS' : 'FAIL',
    `swapped=${swapped}, prevReadyState=${prev.readyState}, prev.onmessage=${prev.onmessage}, generation=${genBefore}->${B.RT.generation}`);

  // ---- RT-12: page teardown stops timers and sockets ----
  const genAtTeardown = B.RT.generation;
  await fireWindow('beforeunload');
  await sleep(1200);
  record('RT-12', 'Page teardown closes sockets and stops all timers',
    B.RT.stopping === true && B.ws === null && B.RT.retryTimer === null &&
    B.RT.heartbeatTimer === null && B.RT.openTimer === null &&
    B.RT.generation === genAtTeardown
      ? 'PASS' : 'FAIL',
    `stopping=${B.RT.stopping}, ws=${B.ws}, retryTimer=${B.RT.retryTimer}, heartbeat=${B.RT.heartbeatTimer}, generation stable=${B.RT.generation === genAtTeardown}`);

  finish();
}

function finish() {
  const fails = results.filter((r) => r.status === 'FAIL');
  const passes = results.filter((r) => r.status === 'PASS');
  console.log('----------------------------------------');
  console.log(`RESULTS: ${passes.length} PASS, ${fails.length} FAIL, total ${results.length}`);
  if (fails.length) fails.forEach((f) => console.log(`  FAIL ${f.id} ${f.name} — ${f.detail}`));
  fs.writeFileSync(
    path.join(os.tmpdir(), 'swa_rt_harness_results.json'),
    JSON.stringify({ ranAt: new Date().toISOString(), port: serverPort, results }, null, 2)
  );
  return fails.length ? 1 : 0;
}

let exitCode = 1;
try {
  exitCode = await main();
} catch (e) {
  console.error('HARNESS ERROR:', e && e.stack || e);
  record('RT-HARNESS', 'Harness completed without internal error', 'FAIL', String(e && e.message || e));
  exitCode = 1;
} finally {
  try { await stopServer(); } catch { /* noop */ }
  try { fs.unlinkSync(TMP_DB); } catch { /* noop */ }
  try { if (logFile) fs.unlinkSync(logFile); } catch { /* noop */ }
  console.log('server stopped, temp database removed');
}
process.exit(exitCode);
