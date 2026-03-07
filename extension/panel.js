/**
 * HackTools++ Panel - Main application logic
 * Network capture, request editor, replay, response viewer
 */

// State
let capturedRequests = [];
let selectedRequest = null;
let selectedRequestIndex = -1;
let scopeDomains = [];
let blockDomains = [];
let repeaterTabs = [];
let activeRepeaterTabId = null;
let repeaterHistory = [];
const MAX_REPEATER_HISTORY = 75;
let scannerFindingsCache = [];
let scannerAutoTimer = null;
let scannerRunInProgress = false;
let scannerRunQueued = false;
let scannerAutoEnabled = true;
let scannerFilteredFindingsCache = [];
let scannerPreviousFindingKeys = new Set();
let scannerSuppressions = { keys: [], domains: [] };
let scannerLastScanMeta = {
  totalRaw: 0,
  totalDeduped: 0,
  highCount: 0,
  newCount: 0,
  lastScanAt: null,
  jwtAlgNone: 0,
  jwtAlgHS: 0,
  jwtAlgMissing: 0,
};
let techFindingsCache = [];
let techLiveCveEnabled = false;
let techCveCache = {};
const TECH_CVE_CACHE_TTL_MS = 12 * 60 * 60 * 1000;
const TECH_CVE_CACHE_MAX_KEYS = 200;
let techLastRunMeta = {
  total: 0,
  high: 0,
  medium: 0,
  low: 0,
  cveLiveHits: 0,
  cveCacheHits: 0,
  cveFallbackHits: 0,
  cveRateLimited: false,
  lastRunAt: null,
};
let owaspSummaryCache = null;
let secretFindingsCache = [];
let secretFilteredFindingsCache = [];
let secretFindingKeys = new Set();
let secretScanApiJsonEnabled = false;
let secretRulePack = 'extended';
let secretRemoteValidationEnabled = false;
let secretValidationAudit = [];
let secretScanQueue = [];
let secretScanRunning = false;
let secretQueueTimer = null;
const SECRET_SCAN_MAX_BYTES = 500000;
const SECRET_SCAN_SLICE_MS = 30;
let secretScanMeta = {
  total: 0,
  high: 0,
  medium: 0,
  low: 0,
  validatedActive: 0,
  validatedInactive: 0,
  validatedError: 0,
  lastScanAt: null,
};

// DOM Elements
const requestList = document.getElementById('requestList');
const searchInput = document.getElementById('searchInput');
const methodFilter = document.getElementById('methodFilter');
const statusFilter = document.getElementById('statusFilter');
const methodSelect = document.getElementById('methodSelect');
const urlInput = document.getElementById('urlInput');
const headersEditor = document.getElementById('headersEditor');
const bodyEditor = document.getElementById('bodyEditor');
const sendBtn = document.getElementById('sendBtn');
const responsePretty = document.getElementById('responsePretty');
const responseRaw = document.getElementById('responseRaw');
const responseHeaders = document.getElementById('responseHeaders');
const responseTiming = document.getElementById('responseTiming');
const statusCodeEl = document.getElementById('statusCode');
const responseSizeEl = document.getElementById('responseSize');
const contentTypeEl = document.getElementById('contentType');
const endpointAnalysisEl = document.getElementById('endpointAnalysis');
const requestsSidebarEl = document.getElementById('requestsSidebar');
const aiSidebarEl = document.getElementById('aiSidebar');
const repeaterTabsEl = document.getElementById('repeaterTabs');
const repeaterHistoryListEl = document.getElementById('repeaterHistoryList');

// Initialize
document.addEventListener('DOMContentLoaded', async () => {
  await loadScopeBlockLists();
  setupNetworkCapture();
  setupEventListeners();
  setupTabSwitchers();
  setupScopeBlockUI();
  setupContextMenu();
  setupCopyModal();
  setupIntruder();
  setupDecoder();
  setupScanner();
  setupTechDetector();
  setupSecretScanner();
  setupOwaspFindings();
  initRepeaterWorkspace();
  renderRepeaterHistory();
  renderRequestList();
});

/**
 * Check if URL should be captured based on scope and block lists
 */
function shouldCaptureRequest(url) {
  let host;
  let protocol;
  try {
    const parsed = new URL(url);
    host = parsed.hostname.toLowerCase();
    protocol = parsed.protocol.toLowerCase();
  } catch (_) {
    return false;
  }

  // Ignore internal/devtools/extension placeholder traffic.
  if (protocol !== 'http:' && protocol !== 'https:') return false;
  if (!host || host === 'invalid') return false;

  // Block takes precedence
  for (const domain of blockDomains) {
    const d = domain.toLowerCase().replace(/^\./, '');
    if (host === d || host.endsWith('.' + d)) return false;
  }

  // If scope is empty, capture all valid http(s) traffic (except blocked)
  if (scopeDomains.length === 0) return true;

  // Scope: only capture if host matches a scoped domain
  for (const domain of scopeDomains) {
    const d = domain.toLowerCase().replace(/^\./, '');
    if (host === d || host.endsWith('.' + d)) return true;
  }
  return false;
}

function isLikelyJavaScriptRequest(request) {
  const url = String(request?.request?.url || '').toLowerCase();
  const mime = String(request?.response?.content?.mimeType || '').toLowerCase();
  if (/\.(m?js)(\?|$)/i.test(url)) return true;
  if (/javascript|ecmascript|x-javascript/.test(mime)) return true;
  // Build/runtime assets from modern bundlers and code-splitting pipelines.
  if (/\/_next\/|\/_nuxt\/|\/static\/js\/|\/assets\/|chunk|bundle|runtime|vendor|app\.[a-f0-9]{6,}\.js/.test(url)
      && /text\/plain|application\/octet-stream|javascript|json/.test(mime || '')) return true;
  return false;
}

function isLikelyApiJsonRequest(request) {
  if (!secretScanApiJsonEnabled) return false;
  const url = String(request?.request?.url || '').toLowerCase();
  const mime = String(request?.response?.content?.mimeType || '').toLowerCase();
  const method = String(request?.request?.method || 'GET').toUpperCase();
  if (!['GET', 'POST', 'PUT', 'PATCH'].includes(method)) return false;
  if (isStaticAssetUrl(url)) return false;
  const byMime = /application\/json|application\/ld\+json|text\/json/.test(mime);
  const byPath = /(\/api\/|\/graphql|\/v[0-9]+\b|\/rest\/|[?&](format|type)=json\b)/.test(url);
  return byMime || byPath;
}

function detectBuildArtifactKind(url) {
  const u = String(url || '').toLowerCase();
  const host = (() => { try { return new URL(url).hostname; } catch (_) { return ''; } })();
  if (/(cdn|cloudfront|akamai|fastly|gstatic|googletagmanager|doubleclick)/i.test(host)) return 'third-party';
  if (/runtime|runtime\./.test(u)) return 'runtime';
  if (/chunk|lazy|split|code-split|hot-update/.test(u)) return 'code-split';
  if (/vendor|vendors|polyfills/.test(u)) return 'vendor';
  if (/\/_next\/|\/_nuxt\/|\/static\/js\/|\/assets\/|app\.[a-f0-9]{6,}\.js/.test(u)) return 'build-artifact';
  return 'script';
}

/**
 * Capture network requests via Chrome DevTools Network API
 */
function setupNetworkCapture() {
  chrome.devtools.network.onRequestFinished.addListener((request) => {
    if (!shouldCaptureRequest(request.request.url)) return;

    const entry = {
      id: Date.now() + Math.random(),
      method: request.request.method,
      url: request.request.url,
      status: request.response.status,
      statusText: request.response.statusText,
      time: request.time ? new Date(request.time).toLocaleTimeString() : '—',
      request: {
        method: request.request.method,
        url: request.request.url,
        headers: request.request.headers || [],
        postData: request.request.postData || null,
      },
      response: {
        status: request.response.status,
        headers: request.response.headers || [],
        content: request.response.content,
      },
    };
    capturedRequests.unshift(entry);
    if (capturedRequests.length > 500) capturedRequests.pop();
    renderRequestList();
    scheduleAutoSecurityScan();

    const jsLike = isLikelyJavaScriptRequest(request);
    const apiJsonLike = isLikelyApiJsonRequest(request);
    if (jsLike || apiJsonLike) {
      request.getContent((content) => {
        if (!content) return;
        enqueueSecretScan({
          url: request.request.url,
          status: request.response?.status || 0,
          contentType: (request.response?.content?.mimeType || '').toLowerCase(),
          fileKind: jsLike ? undefined : 'api-json',
          body: content,
        });
      });
    }
  });
}

function scheduleAutoSecurityScan() {
  if (!scannerAutoEnabled) return;
  if (scannerAutoTimer) clearTimeout(scannerAutoTimer);
  scannerAutoTimer = setTimeout(() => {
    runSecurityScan({ silent: true });
  }, 1200);
}

/**
 * Load scope and block lists from storage
 */
async function loadScopeBlockLists() {
  return new Promise((resolve) => {
    chrome.storage.local.get(['scopeDomains', 'blockDomains', 'scannerAutoEnabled', 'scannerSuppressions', 'techLiveCveEnabled', 'techCveCache', 'secretScanApiJsonEnabled', 'secretRulePack', 'secretRemoteValidationEnabled'], (result) => {
      scopeDomains = result.scopeDomains || [];
      blockDomains = result.blockDomains || [];
      scannerAutoEnabled = result.scannerAutoEnabled !== false;
      scannerSuppressions = result.scannerSuppressions || { keys: [], domains: [] };
      techLiveCveEnabled = result.techLiveCveEnabled === true;
      techCveCache = result.techCveCache || {};
      secretScanApiJsonEnabled = result.secretScanApiJsonEnabled === true;
      secretRulePack = ['core', 'extended', 'aggressive'].includes(result.secretRulePack) ? result.secretRulePack : 'extended';
      secretRemoteValidationEnabled = result.secretRemoteValidationEnabled === true;
      const autoToggle = document.getElementById('scannerAutoToggle');
      if (autoToggle) autoToggle.checked = scannerAutoEnabled;
      const secretApiToggle = document.getElementById('secretApiJsonToggle');
      if (secretApiToggle) secretApiToggle.checked = secretScanApiJsonEnabled;
      const rulePackSelect = document.getElementById('secretRulePackSelect');
      if (rulePackSelect) rulePackSelect.value = secretRulePack;
      const remoteValidateToggle = document.getElementById('secretRemoteValidationToggle');
      if (remoteValidateToggle) remoteValidateToggle.checked = secretRemoteValidationEnabled;
      resolve();
    });
  });
}

/**
 * Save scope and block lists to storage
 */
function saveScopeBlockLists() {
  chrome.storage.local.set({
    scopeDomains: [...scopeDomains],
    blockDomains: [...blockDomains],
    scannerAutoEnabled,
    scannerSuppressions,
    techLiveCveEnabled,
    techCveCache,
    secretScanApiJsonEnabled,
    secretRulePack,
    secretRemoteValidationEnabled,
  });
}

/**
 * Normalize domain for matching (lowercase, no protocol)
 */
function normalizeDomain(input) {
  const s = String(input).trim().toLowerCase();
  return s.replace(/^https?:\/\//, '').replace(/\/.*$/, '').split(':')[0];
}

/**
 * Add domain to scope or block list
 */
function addDomain(type) {
  const input = type === 'scope' ? document.getElementById('scopeInput') : document.getElementById('blockInput');
  const domain = normalizeDomain(input.value);
  if (!domain) return;

  const list = type === 'scope' ? scopeDomains : blockDomains;
  if (list.includes(domain)) return;

  list.push(domain);
  list.sort();
  saveScopeBlockLists();
  renderDomainLists();
  input.value = '';
}

/**
 * Remove domain from scope or block list
 */
function removeDomain(type, domain) {
  const list = type === 'scope' ? scopeDomains : blockDomains;
  const idx = list.indexOf(domain);
  if (idx >= 0) {
    list.splice(idx, 1);
    saveScopeBlockLists();
    renderDomainLists();
  }
}

/**
 * Render scope and block domain lists
 */
function renderDomainLists() {
  const scopeList = document.getElementById('scopeList');
  const blockList = document.getElementById('blockList');

  scopeList.innerHTML = scopeDomains
    .map(
      (d) =>
        `<li class="domain-item">
          <span class="domain-name">${escapeHtml(d)}</span>
          <button type="button" class="btn-remove" data-type="scope" data-domain="${escapeHtml(d)}" title="Remove">×</button>
        </li>`
    )
    .join('');

  blockList.innerHTML = blockDomains
    .map(
      (d) =>
        `<li class="domain-item">
          <span class="domain-name">${escapeHtml(d)}</span>
          <button type="button" class="btn-remove" data-type="block" data-domain="${escapeHtml(d)}" title="Remove">×</button>
        </li>`
    )
    .join('');

  scopeList.querySelectorAll('.btn-remove').forEach((btn) => {
    btn.addEventListener('click', () => removeDomain(btn.dataset.type, btn.dataset.domain));
  });
  blockList.querySelectorAll('.btn-remove').forEach((btn) => {
    btn.addEventListener('click', () => removeDomain(btn.dataset.type, btn.dataset.domain));
  });
}

/**
 * Toggle scope/block section visibility
 */
function toggleScopeBlock() {
  const content = document.getElementById('scopeBlockContent');
  const icon = document.querySelector('#scopeBlockToggle .toggle-icon');
  content.classList.toggle('collapsed');
  icon.textContent = content.classList.contains('collapsed') ? '▼' : '▲';
}

/**
 * Setup scope/block UI (load lists, render)
 */
function setupScopeBlockUI() {
  renderDomainLists();
}

/**
 * Setup all event listeners
 */
function setupEventListeners() {
  searchInput.addEventListener('input', renderRequestList);
  methodFilter.addEventListener('change', renderRequestList);
  statusFilter.addEventListener('change', renderRequestList);

  requestList.addEventListener('click', (e) => {
    const copyBtn = e.target.closest('.copy-curl-btn');
    if (copyBtn) {
      e.stopPropagation();
      const item = copyBtn.closest('.request-item');
      const req = item && capturedRequests.find((r) => String(r.id) === item.dataset.requestId);
      if (req) copyCurlFromRequest(req);
      return;
    }
    const item = e.target.closest('.request-item');
    if (!item) return;
    const req = capturedRequests.find((r) => String(r.id) === item.dataset.requestId);
    if (req) selectRequest(req);
  });
  requestList.addEventListener('contextmenu', (e) => {
    const item = e.target.closest('.request-item');
    if (!item) return;
    e.preventDefault();
    const req = capturedRequests.find((r) => String(r.id) === item.dataset.requestId);
    if (req) showRequestContextMenu(e, req);
  });

  sendBtn.addEventListener('click', sendRequest);
  document.getElementById('duplicateTabBtn').addEventListener('click', duplicateCurrentRequestToNewTab);
  document.getElementById('newRepeaterTabBtn').addEventListener('click', () => {
    createRepeaterTab({
      method: 'GET',
      url: '',
      headers: {},
      body: '',
    });
  });
  document.getElementById('clearRepeaterHistoryBtn').addEventListener('click', () => {
    repeaterHistory = [];
    renderRepeaterHistory();
  });
  document.getElementById('addHeaderBtn').addEventListener('click', () => addHeaderRow('', ''));
  document.getElementById('scopeBlockToggle').addEventListener('click', toggleScopeBlock);
  document.getElementById('toggleRequestsSidebarBtn').addEventListener('click', () => toggleSidebar('requests'));
  document.getElementById('toggleAiSidebarBtn').addEventListener('click', () => toggleSidebar('ai'));
  document.getElementById('addScopeBtn').addEventListener('click', () => addDomain('scope'));
  document.getElementById('addBlockBtn').addEventListener('click', () => addDomain('block'));
  document.getElementById('scopeInput').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') addDomain('scope');
  });
  document.getElementById('blockInput').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') addDomain('block');
  });
  document.getElementById('sendToIntruderBtn').addEventListener('click', sendToIntruder);

  document.querySelectorAll('.mode-tab').forEach((tab) => {
    tab.addEventListener('click', () => switchMode(tab.dataset.mode));
  });

  repeaterTabsEl.addEventListener('click', (e) => {
    const closeBtn = e.target.closest('.repeater-tab-close');
    if (closeBtn) {
      e.stopPropagation();
      closeRepeaterTab(closeBtn.dataset.tabId);
      return;
    }
    const tab = e.target.closest('.repeater-tab');
    if (tab) switchRepeaterTab(tab.dataset.tabId);
  });

  repeaterHistoryListEl.addEventListener('click', (e) => {
    const item = e.target.closest('.repeater-history-item');
    if (item) loadRepeaterHistoryEntry(item.dataset.historyId);
  });
}

function toggleSidebar(type) {
  const sidebar = type === 'requests' ? requestsSidebarEl : aiSidebarEl;
  const btnId = type === 'requests' ? 'toggleRequestsSidebarBtn' : 'toggleAiSidebarBtn';
  const btn = document.getElementById(btnId);
  if (!sidebar || !btn) return;
  const collapsed = sidebar.classList.toggle('collapsed');
  if (type === 'requests') {
    btn.textContent = collapsed ? '»' : '«';
    btn.title = collapsed ? 'Expand Captured Requests' : 'Minimize Captured Requests';
  } else {
    btn.textContent = collapsed ? '«' : '»';
    btn.title = collapsed ? 'Expand AI Assist' : 'Minimize AI Assist';
  }
}

function getRepeaterTabTitle(request) {
  const method = request?.method || 'REQ';
  if (!request?.url) return `${method} New`;
  try {
    const u = new URL(request.url);
    const shortPath = (u.pathname || '/').slice(0, 24);
    return `${method} ${shortPath || '/'}`;
  } catch (_) {
    return `${method} ${(request.url || '').slice(0, 24)}`;
  }
}

function getRequestModelFromEditor() {
  const bodyPrettyEl = document.getElementById('bodyPrettyView');
  let body = bodyEditor.value || '';
  if (bodyPrettyEl && !bodyPrettyEl.classList.contains('hidden')) {
    body = unformatBodyFromDisplay(bodyPrettyEl.value);
  }
  return {
    method: methodSelect.value || 'GET',
    url: urlInput.value?.trim() || '',
    headers: getHeadersFromEditor(),
    body: body || '',
  };
}

function setRequestModelToEditor(model) {
  methodSelect.value = model.method || 'GET';
  urlInput.value = model.url || '';
  headersEditor.innerHTML = '';
  Object.entries(model.headers || {}).forEach(([k, v]) => addHeaderRow(k, v));
  addHeaderRow('', '');
  bodyEditor.value = model.body || '';
  const prettyView = document.getElementById('bodyPrettyView');
  if (prettyView && !prettyView.classList.contains('hidden')) {
    prettyView.value = formatBodyForDisplay(model.body || '');
  }
}

function saveActiveRepeaterTabFromEditor() {
  const active = repeaterTabs.find((t) => t.id === activeRepeaterTabId);
  if (!active) return;
  active.request = getRequestModelFromEditor();
  active.title = getRepeaterTabTitle(active.request);
}

function createRepeaterTab(requestModel, options = {}) {
  const tab = {
    id: String(Date.now() + Math.random()),
    request: requestModel,
    response: null,
    title: getRepeaterTabTitle(requestModel),
  };
  repeaterTabs.push(tab);
  renderRepeaterTabs();
  if (options.switchTo !== false) switchRepeaterTab(tab.id);
}

function closeRepeaterTab(tabId) {
  if (repeaterTabs.length <= 1) {
    showToast('At least one Repeater tab is required.');
    return;
  }
  const idx = repeaterTabs.findIndex((t) => t.id === tabId);
  if (idx < 0) return;
  const wasActive = repeaterTabs[idx].id === activeRepeaterTabId;
  repeaterTabs.splice(idx, 1);
  if (wasActive) {
    const fallback = repeaterTabs[Math.max(0, idx - 1)];
    activeRepeaterTabId = fallback?.id || null;
    if (fallback) setRequestModelToEditor(fallback.request);
    if (fallback?.response) displayResponse(fallback.response);
    else clearResponseViewer();
  }
  renderRepeaterTabs();
}

function switchRepeaterTab(tabId) {
  if (activeRepeaterTabId === tabId) return;
  saveActiveRepeaterTabFromEditor();
  const tab = repeaterTabs.find((t) => t.id === tabId);
  if (!tab) return;
  activeRepeaterTabId = tab.id;
  setRequestModelToEditor(tab.request);
  if (tab.response) displayResponse(tab.response);
  else clearResponseViewer();
  renderRepeaterTabs();
}

function renderRepeaterTabs() {
  repeaterTabsEl.innerHTML = '';
  repeaterTabs.forEach((tab) => {
    const el = document.createElement('div');
    el.className = `repeater-tab ${tab.id === activeRepeaterTabId ? 'active' : ''}`;
    el.dataset.tabId = tab.id;
    el.innerHTML = `
      <span class="repeater-tab-label">${escapeHtml(tab.title)}</span>
      <button type="button" class="repeater-tab-close" data-tab-id="${escapeHtml(tab.id)}" title="Close tab">×</button>
    `;
    repeaterTabsEl.appendChild(el);
  });
}

function duplicateCurrentRequestToNewTab() {
  const model = getRequestModelFromEditor();
  createRepeaterTab({ ...model, headers: { ...model.headers } });
  showToast('Request duplicated to a new tab.');
}

function initRepeaterWorkspace() {
  if (repeaterTabs.length > 0) return;
  createRepeaterTab(
    {
      method: methodSelect.value || 'GET',
      url: '',
      headers: {},
      body: '',
    },
    { switchTo: true }
  );
}

function addRepeaterHistoryEntry(entry) {
  repeaterHistory.unshift(entry);
  if (repeaterHistory.length > MAX_REPEATER_HISTORY) repeaterHistory.pop();
  renderRepeaterHistory();
}

function renderRepeaterHistory() {
  if (repeaterHistory.length === 0) {
    repeaterHistoryListEl.innerHTML = '<li class="repeater-history-empty">No sent requests yet.</li>';
    return;
  }
  repeaterHistoryListEl.innerHTML = repeaterHistory
    .map((item) => {
      const status = item.status ? String(item.status) : 'ERR';
      const statusClass = item.status >= 400 ? 'error' : '';
      return `
        <li class="repeater-history-item" data-history-id="${escapeHtml(item.id)}">
          <div class="repeater-history-main">
            <div><span class="method">${escapeHtml(item.request.method)}</span> <span class="url">${escapeHtml(item.request.url || '(empty URL)')}</span></div>
            <div class="meta">${escapeHtml(item.time)}</div>
          </div>
          <div class="${statusClass}">${escapeHtml(status)}</div>
        </li>
      `;
    })
    .join('');
}

function loadRepeaterHistoryEntry(historyId) {
  const item = repeaterHistory.find((h) => h.id === historyId);
  if (!item) return;
  createRepeaterTab({
    method: item.request.method,
    url: item.request.url,
    headers: { ...(item.request.headers || {}) },
    body: item.request.body || '',
  });
  const active = repeaterTabs.find((t) => t.id === activeRepeaterTabId);
  if (active) active.response = item.response || null;
  if (item.response) displayResponse(item.response);
}

function clearResponseViewer() {
  statusCodeEl.textContent = '—';
  statusCodeEl.className = '';
  responseSizeEl.textContent = '—';
  contentTypeEl.textContent = '—';
  responsePretty.textContent = '';
  responseRaw.textContent = '';
  responseHeaders.textContent = '';
  responseTiming.textContent = '';
}

/**
 * Format body for readable display (JSON or URL-encoded)
 */
function formatBodyForDisplay(raw) {
  const trimmed = raw.trim();
  if (!trimmed) return '';

  try {
    const parsed = JSON.parse(trimmed);
    return JSON.stringify(parsed, null, 2);
  } catch (_) {}

  try {
    const params = new URLSearchParams(trimmed);
    const entries = [...params];
    if (entries.length > 0) {
      const lines = [];
      for (const [k, v] of entries) {
        try {
          lines.push(`${k} = ${decodeURIComponent(v)}`);
        } catch (_) {
          lines.push(`${k} = ${v}`);
        }
      }
      return lines.join('\n');
    }
  } catch (_) {}

  return trimmed;
}

/**
 * Convert pretty-formatted content back to raw (for request body)
 */
function unformatBodyFromDisplay(prettyContent) {
  const trimmed = (prettyContent || '').trim();
  if (!trimmed) return '';

  try {
    const parsed = JSON.parse(trimmed);
    return JSON.stringify(parsed);
  } catch (_) {}

  const lines = trimmed.split(/\r?\n/).filter(Boolean);
  if (lines.some((l) => l.includes(' = '))) {
    const params = new URLSearchParams();
    for (const line of lines) {
      const idx = line.indexOf(' = ');
      if (idx > 0) {
        const k = line.slice(0, idx).trim();
        const v = line.slice(idx + 3).trim();
        params.set(k, v);
      }
    }
    if (params.toString()) return params.toString();
  }

  return trimmed;
}

/**
 * Tab switching for body editor and response viewer
 */
function setupTabSwitchers() {
  document.querySelectorAll('.tab-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      const tab = btn.dataset.tab;
      const container = btn.closest('.editor-section-inner, .response-section, .section-header')?.parentElement;

      if (btn.closest('.intruder-body-tabs')) {
        const tabs = btn.closest('.intruder-body-tabs');
        tabs.querySelectorAll('.tab-btn').forEach((b) => b.classList.remove('active'));
        btn.classList.add('active');
        const intruderBody = document.getElementById('intruderBody');
        const prettyView = document.getElementById('intruderBodyPrettyView');
        if (tab === 'pretty') {
          prettyView.value = formatBodyForDisplay(intruderBody.value || '');
          prettyView.classList.remove('hidden');
          intruderBody.classList.add('hidden');
        } else {
          intruderBody.value = unformatBodyFromDisplay(prettyView.value);
          prettyView.classList.add('hidden');
          intruderBody.classList.remove('hidden');
        }
      } else if (btn.closest('.body-tabs') && !btn.closest('.intruder-body-tabs')) {
        const tabs = btn.closest('.body-tabs');
        tabs.querySelectorAll('.tab-btn').forEach((b) => b.classList.remove('active'));
        btn.classList.add('active');
        const prettyView = document.getElementById('bodyPrettyView');
        if (tab === 'pretty') {
          prettyView.value = formatBodyForDisplay(bodyEditor.value || '');
          prettyView.classList.remove('hidden');
          bodyEditor.classList.add('hidden');
        } else {
          bodyEditor.value = unformatBodyFromDisplay(prettyView.value);
          prettyView.classList.add('hidden');
          bodyEditor.classList.remove('hidden');
        }
      } else if (btn.closest('.response-tabs')) {
        document.querySelectorAll('.response-tabs .tab-btn').forEach((b) => b.classList.remove('active'));
        btn.classList.add('active');
        responsePretty.classList.toggle('hidden', tab !== 'pretty');
        responseRaw.classList.toggle('hidden', tab !== 'raw');
        responseHeaders.classList.toggle('hidden', tab !== 'headers');
        responseTiming.classList.toggle('hidden', tab !== 'timing');
      }
    });
  });
}

/**
 * Render filtered request list
 */
function renderRequestList() {
  const search = searchInput.value.toLowerCase();
  const method = methodFilter.value;
  const status = statusFilter.value;

  const filtered = capturedRequests.filter((req) => {
    if (search && !req.url.toLowerCase().includes(search)) return false;
    if (method && req.method !== method) return false;
    if (status) {
      const s = req.status;
      const match =
        (status === '2xx' && s >= 200 && s < 300) ||
        (status === '3xx' && s >= 300 && s < 400) ||
        (status === '4xx' && s >= 400 && s < 500) ||
        (status === '5xx' && s >= 500);
      if (!match) return false;
    }
    return true;
  });

  requestList.innerHTML = '';

  if (filtered.length === 0) {
    requestList.innerHTML = `
      <li class="empty-state">
        <p>No requests captured yet.</p>
        <p>Navigate to a page with the DevTools open to capture requests.</p>
      </li>
    `;
    return;
  }

  filtered.forEach((req) => {
    const li = document.createElement('li');
    li.className = `request-item ${selectedRequest?.id === req.id ? 'selected' : ''}`;
    li.dataset.requestId = req.id;
    const statusClass = req.status >= 500 ? 'status-5xx' : req.status >= 400 ? 'status-4xx' : req.status >= 300 ? 'status-3xx' : 'status-2xx';
    li.innerHTML = `
      <div class="request-item-main">
        <div><span class="method">${escapeHtml(req.method)}</span><span class="url">${escapeHtml(req.url)}</span></div>
        <button type="button" class="copy-curl-btn" title="Copy as cURL">⎘</button>
      </div>
      <div class="meta"><span class="${statusClass}">${req.status}</span> · ${escapeHtml(req.time)}</div>
    `;
    requestList.appendChild(li);
  });
}

/**
 * Update selection highlight without full re-render (faster)
 */
function updateRequestListSelection(req) {
  requestList.querySelectorAll('.request-item').forEach((li) => {
    li.classList.toggle('selected', li.dataset.requestId === String(req?.id));
  });
}

/**
 * Select a request and populate editor
 */
function selectRequest(req, index) {
  selectedRequest = req;
  selectedRequestIndex = index;

  methodSelect.value = req.request.method;
  urlInput.value = req.request.url;

  // Headers (exclude HTTP/2 pseudo-headers - they cause fetch "Invalid name")
  const headers = (req.request.headers || []).filter((h) => isValidHeaderName(h.name));
  headersEditor.innerHTML = '';
  headers.forEach((h) => addHeaderRow(h.name, h.value));
  addHeaderRow('', ''); // Empty row for new headers

  // Body
  const bodyText = req.request.postData?.text || '';
  bodyEditor.value = bodyText;
  const prettyView = document.getElementById('bodyPrettyView');
  if (prettyView && !prettyView.classList.contains('hidden')) {
    prettyView.value = formatBodyForDisplay(bodyText);
  }

  updateRequestListSelection(req);
  updateAIAssist(req);
  saveActiveRepeaterTabFromEditor();
  renderRepeaterTabs();
}

/**
 * Add a header row to the editor
 */
function addHeaderRow(key = '', value = '') {
  const row = document.createElement('div');
  row.className = 'header-row';
  row.innerHTML = `
    <input type="text" class="key" placeholder="Header name" value="${escapeHtml(key)}">
    <input type="text" class="value" placeholder="Value" value="${escapeHtml(value)}">
  `;
  headersEditor.appendChild(row);
}

/**
 * Get current headers from editor
 */
function getHeadersFromEditor() {
  const headers = {};
  headersEditor.querySelectorAll('.header-row').forEach((row) => {
    const key = row.querySelector('.key')?.value?.trim();
    const val = row.querySelector('.value')?.value?.trim();
    if (key) headers[key] = val;
  });
  return headers;
}

/**
 * Valid HTTP header name - rejects empty, control chars, and HTTP/2 pseudo-headers.
 * Pseudo-headers (:authority, :method, :path, :scheme) cause fetch "Invalid name" error.
 */
function isValidHeaderName(name) {
  if (!name || typeof name !== 'string') return false;
  const trimmed = name.trim();
  if (!trimmed) return false;
  if (trimmed.startsWith(':')) return false; // HTTP/2 pseudo-headers
  return !/[\x00-\x1f\x7f]/.test(trimmed);
}

/**
 * Send/replay the request
 * Fetch runs in panel context (extension page) to avoid "Extension context invalidated"
 * from service worker lifecycle in Manifest V3.
 */
async function sendRequest() {
  const url = urlInput.value?.trim();
  if (!url) {
    showResponseError('Please enter a URL');
    return;
  }

  const rawHeaders = getHeadersFromEditor();
  const bodyPrettyEl = document.getElementById('bodyPrettyView');
  let body = bodyEditor.value?.trim() || null;
  if (bodyPrettyEl && !bodyPrettyEl.classList.contains('hidden')) {
    body = unformatBodyFromDisplay(bodyPrettyEl.value)?.trim() || null;
  }
  const method = methodSelect.value;
  saveActiveRepeaterTabFromEditor();
  const requestSnapshot = getRequestModelFromEditor();

  sendBtn.disabled = true;
  sendBtn.textContent = 'Sending...';

  try {
    const response = await replayRequestFromPanel({ method, url, headers: rawHeaders, body });
    if (response.error) {
      showResponseError(response.error);
      const activeTab = repeaterTabs.find((t) => t.id === activeRepeaterTabId);
      if (activeTab) activeTab.response = null;
      addRepeaterHistoryEntry({
        id: String(Date.now() + Math.random()),
        time: new Date().toLocaleTimeString(),
        status: 0,
        request: requestSnapshot,
        response: null,
      });
    } else {
      displayResponse(response);
      const activeTab = repeaterTabs.find((t) => t.id === activeRepeaterTabId);
      if (activeTab) activeTab.response = response;
      addRepeaterHistoryEntry({
        id: String(Date.now() + Math.random()),
        time: new Date().toLocaleTimeString(),
        status: response.status,
        request: requestSnapshot,
        response,
      });
    }
  } catch (err) {
    showResponseError(err.message || 'Failed to send request');
  } finally {
    sendBtn.disabled = false;
    sendBtn.textContent = 'Send';
  }
}

/**
 * Replay request via fetch from panel (extension page has host_permissions)
 */
async function replayRequestFromPanel(payload) {
  const { method, url, headers, body } = payload;

  const fetchOptions = {
    method: method || 'GET',
    headers: {},
    redirect: 'follow',
  };

  if (headers && typeof headers === 'object') {
    for (const [key, value] of Object.entries(headers)) {
      if (
        isValidHeaderName(key) &&
        key.toLowerCase() !== 'host' &&
        value != null &&
        String(value).trim() !== ''
      ) {
        fetchOptions.headers[key.trim()] = String(value).trim();
      }
    }
  }

  if (body && ['POST', 'PUT', 'PATCH'].includes(fetchOptions.method)) {
    fetchOptions.body = body;
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(url);
    if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
      throw new Error('Only HTTP and HTTPS URLs are supported');
    }
  } catch (e) {
    return {
      error: e.message || 'Invalid URL',
      status: 0,
      statusText: 'Invalid URL',
      headers: {},
      body: '',
      timing: { duration: 0 },
    };
  }

  const startTime = performance.now();
  let response;

  try {
    response = await fetch(parsedUrl.href, fetchOptions);
  } catch (err) {
    return {
      error: err.message,
      status: 0,
      statusText: 'Network Error',
      headers: {},
      body: '',
      timing: { duration: performance.now() - startTime },
    };
  }

  const duration = performance.now() - startTime;
  const responseBody = await response.text();

  const responseHeaders = {};
  response.headers.forEach((value, key) => {
    responseHeaders[key] = value;
  });

  return {
    status: response.status,
    statusText: response.statusText,
    headers: responseHeaders,
    body: responseBody,
    contentType: response.headers.get('content-type') || '',
    timing: { duration },
  };
}

/**
 * Display response in viewer
 */
function displayResponse(res) {
  statusCodeEl.textContent = res.status ? `${res.status} ${res.statusText}` : '—';
  statusCodeEl.className = res.status >= 400 ? 'error' : '';
  responseSizeEl.textContent = res.body ? `${new Blob([res.body]).size} B` : '—';
  contentTypeEl.textContent = res.contentType || '—';

  // Pretty (JSON)
  try {
    const ct = (res.contentType || '').toLowerCase();
    if (ct.includes('json') && res.body) {
      const parsed = JSON.parse(res.body);
      responsePretty.textContent = JSON.stringify(parsed, null, 2);
    } else {
      responsePretty.textContent = res.body || '(empty)';
    }
  } catch (_) {
    responsePretty.textContent = res.body || '(empty)';
  }

  responseRaw.textContent = res.body || '(empty)';
  responseHeaders.textContent = res.headers
    ? Object.entries(res.headers)
        .map(([k, v]) => `${k}: ${v}`)
        .join('\n')
    : '(no headers)';
  responseTiming.textContent = res.timing
    ? `Duration: ${Math.round(res.timing.duration)}ms`
    : '(no timing)';

  document.querySelector('.response-tabs .tab-btn[data-tab="pretty"]').click();
}

/**
 * Show error in response area
 */
function showResponseError(msg) {
  statusCodeEl.textContent = 'Error';
  statusCodeEl.className = 'error';
  responseSizeEl.textContent = '—';
  contentTypeEl.textContent = '—';
  responsePretty.textContent = msg;
  responseRaw.textContent = msg;
  responseHeaders.textContent = '';
  responseTiming.textContent = '';
}

/**
 * Update AI Assist mock content
 */
function updateAIAssist(req) {
  const suggestionsEl = document.getElementById('securitySuggestions');
  if (!req) {
    endpointAnalysisEl.textContent = 'Select a request to see endpoint analysis...';
    if (suggestionsEl) suggestionsEl.innerHTML = '<li>SQL Injection</li><li>IDOR</li><li>Auth Bypass</li><li>Rate Limit Tests</li>';
    return;
  }

  const analysis = analyzeEndpoint(req);
  endpointAnalysisEl.innerHTML = `
    <strong>${escapeHtml(req.method)} ${escapeHtml(analysis.path)}</strong><br><br>
    ${analysis.description}<br><br>
    <strong>Likely purpose:</strong> ${analysis.purpose}<br><br>
    <strong>Key risks:</strong> ${analysis.risks}
  `;

  if (suggestionsEl) {
    suggestionsEl.innerHTML = analysis.suggestions.map((s) => `<li>${escapeHtml(s)}</li>`).join('');
  }
}

function analyzeEndpoint(req) {
  const url = (req.url || '').toLowerCase();
  const path = (() => { try { return new URL(req.url).pathname; } catch (_) { return url; } })();
  const method = (req.method || 'GET').toUpperCase();
  const body = req.request?.postData?.text || '';
  const host = (() => { try { return new URL(req.url).hostname; } catch (_) { return ''; } })();

  const patterns = [
    { match: /jserrors|js-error|error\.js|nrjs|nr-data|bam\.nr/i, purpose: 'JavaScript error reporting / telemetry (e.g. New Relic)', risks: 'Payload injection in error payload, data exfiltration, PII in error messages', suggestions: ['Payload injection in error payload', 'XSS in error message field', 'IDOR in error ID', 'Check for PII in request body'] },
    { match: /collect|analytics|tracking|clarity|gtm|ga|gtag|segment|mixpanel|amplitude/i, purpose: 'Analytics or tracking data', risks: 'Data injection, event spoofing, PII leakage', suggestions: ['Event spoofing / fake events', 'Parameter tampering', 'Check for PII in payload'] },
    { match: /login|auth|signin|oauth|token|refresh/i, purpose: 'Authentication or session management', risks: 'Credential stuffing, session fixation, token theft', suggestions: ['Brute force / credential stuffing', 'Session fixation', 'Token leakage in response', 'Password reset flow'] },
    { match: /kyc|user_details|profile|account|me/i, purpose: 'User profile or KYC data', risks: 'IDOR, privilege escalation, data exposure', suggestions: ['IDOR (change user ID)', 'Auth bypass', 'Horizontal privilege escalation'] },
    { match: /api\/v?\d*\/?user|users\/|\/user\//i, purpose: 'User resource API', risks: 'IDOR, mass assignment, unauthorized access', suggestions: ['IDOR (user ID in path)', 'Mass assignment', 'Method override (GET to modify)'] },
    { match: /search|query|filter|find/i, purpose: 'Search or query', risks: 'SQL/NoSQL injection, SSRF, blind injection', suggestions: ['SQL/NoSQL injection', 'SSRF via URL params', 'Boolean-based blind injection'] },
    { match: /upload|file|image|media/i, purpose: 'File upload', risks: 'Unrestricted file upload, path traversal', suggestions: ['File type bypass', 'Path traversal', 'Content-Type spoofing'] },
    { match: /payment|checkout|order|cart/i, purpose: 'Payment or checkout', risks: 'Price manipulation, order tampering', suggestions: ['Price tampering', 'Order ID manipulation', 'Quantity overflow'] },
    { match: /admin|internal|manage|config/i, purpose: 'Admin or internal API', risks: 'Unauthorized access, privilege escalation', suggestions: ['Auth bypass', 'Role escalation', 'Direct object access'] },
    { match: /webhook|callback|notify/i, purpose: 'Webhook or callback', risks: 'SSRF, replay attacks', suggestions: ['SSRF via URL params', 'Replay attack', 'Signature bypass'] },
    { match: /firestore|firebase/i, purpose: 'Firebase/Firestore backend', risks: 'Rules misconfiguration, data exposure', suggestions: ['Firestore rules bypass', 'IDOR on document IDs', 'Unauthenticated access'] },
    { match: /cdn-cgi|rum|cloudflare/i, purpose: 'CDN / RUM analytics', risks: 'Limited - typically third-party', suggestions: ['Payload injection in RUM data', 'Check for sensitive headers'] },
  ];

  let match = patterns.find((p) => p.match.test(path) || p.match.test(url));
  if (!match) {
    match = {
      purpose: method === 'POST' ? 'Data submission' : 'Data retrieval',
      risks: 'Depends on implementation',
      suggestions: ['SQL Injection', 'IDOR', 'Auth bypass', 'Rate limit tests'],
    };
  }

  const pathHint = path.length > 50 ? path.slice(0, 47) + '...' : path;
  let description = `${method} request to ${escapeHtml(host || 'unknown')}. `;
  if (body && method === 'POST') {
    try {
      const parsed = JSON.parse(body);
      const keys = Object.keys(parsed).slice(0, 5).join(', ');
      description += `Request body contains: ${escapeHtml(keys || 'empty')}. `;
    } catch (_) {}
  }

  return {
    path: pathHint,
    description,
    purpose: match.purpose,
    risks: match.risks,
    suggestions: match.suggestions,
  };
}

/**
 * Get headers suitable for fetch/cURL (excludes HTTP/2 pseudo-headers)
 */
function getValidHeaders() {
  const headers = getHeadersFromEditor();
  const valid = {};
  for (const [key, value] of Object.entries(headers)) {
    if (key && value && isValidHeaderName(key)) {
      valid[key] = value;
    }
  }
  return valid;
}

/**
 * Build cURL string from a request object
 */
function buildCurlFromRequest(req) {
  const method = req.request?.method || 'GET';
  const url = req.request?.url || req.url || '';
  const headers = req.request?.headers || [];
  const body = req.request?.postData?.text || '';

  const validHeaders = headers
    .filter((h) => h.name && h.value && isValidHeaderName(h.name))
    .reduce((acc, h) => {
      acc[h.name] = h.value;
      return acc;
    }, {});

  const escapeForShell = (s) => String(s).replace(/\\/g, '\\\\').replace(/'/g, "'\\''");
  let curl = `curl -X ${method} '${escapeForShell(url)}'`;

  Object.entries(validHeaders).forEach(([k, v]) => {
    curl += ` \\\n  -H '${escapeForShell(k)}: ${escapeForShell(v)}'`;
  });

  if (body && ['POST', 'PUT', 'PATCH'].includes(method)) {
    curl += ` \\\n  -d '${escapeForShell(body)}'`;
  }
  return curl;
}

/**
 * Show context menu on right-click of request item
 */
function showRequestContextMenu(e, req) {
  const menu = document.getElementById('contextMenu');
  const existing = document.querySelector('.context-menu-visible');
  if (existing) existing.classList.remove('context-menu-visible');

  menu.dataset.requestId = req.id;
  menu.classList.remove('hidden');
  menu.classList.add('context-menu-visible');
  menu.style.left = `${e.clientX}px`;
  menu.style.top = `${e.clientY}px`;
  menu._contextRequest = req;
}

/**
 * Hide context menu
 */
function hideContextMenu() {
  const menu = document.getElementById('contextMenu');
  menu.classList.add('hidden');
  menu.classList.remove('context-menu-visible');
  menu._contextRequest = null;
}

/**
 * Setup context menu
 */
function setupContextMenu() {
  const menu = document.getElementById('contextMenu');
  if (!menu) return;

  menu.querySelector('[data-action="copy-curl"]').addEventListener('click', () => {
    const req = menu._contextRequest;
    if (req) copyCurlFromRequest(req);
    hideContextMenu();
  });

  menu.querySelector('[data-action="send-to-decoder"]').addEventListener('click', () => {
    const req = menu._contextRequest;
    if (req) {
      const text = req.request?.postData?.text || req.request?.url || req.url || '';
      document.getElementById('decoderInput').value = text;
      switchMode('decoder');
    }
    hideContextMenu();
  });

  document.addEventListener('click', hideContextMenu);
  document.addEventListener('contextmenu', (e) => {
    if (!menu.contains(e.target)) hideContextMenu();
  });
}

/**
 * Copy text to clipboard - uses execCommand (Clipboard API is blocked in DevTools due to permissions policy)
 */
function copyToClipboard(text) {
  return new Promise((resolve, reject) => {
    if (execCommandCopy(text)) {
      resolve();
    } else {
      reject();
    }
  });
}

function execCommandCopy(text) {
  const textarea = document.createElement('textarea');
  textarea.value = text;
  textarea.style.cssText = 'position:fixed;left:-9999px;top:0;opacity:0;';
  document.body.appendChild(textarea);
  textarea.focus();
  textarea.select();
  try {
    const ok = document.execCommand('copy');
    textarea.remove();
    return ok;
  } catch (_) {
    textarea.remove();
    return false;
  }
}

/**
 * Copy cURL from request - used by copy button, context menu, and Generate cURL
 */
function copyCurlFromRequest(req) {
  const curl = buildCurlFromRequest(req);
  copyToClipboard(curl)
    .then(() => showToast('cURL copied to clipboard'))
    .catch(() => showCopyModal(curl));
}

/**
 * Show modal with cURL for manual copy (when clipboard fails)
 */
function showCopyModal(curl) {
  const modal = document.getElementById('copyModal');
  const textarea = document.getElementById('copyModalText');
  textarea.value = curl;
  modal.classList.remove('hidden');
  textarea.focus();
  textarea.select();
}

function setupCopyModal() {
  const modal = document.getElementById('copyModal');
  const textarea = document.getElementById('copyModalText');
  document.getElementById('copyModalClose').addEventListener('click', () => {
    modal.classList.add('hidden');
  });
  modal.addEventListener('click', (e) => {
    if (e.target === modal) modal.classList.add('hidden');
  });
}

/**
 * Show brief toast notification
 */
function showToast(message) {
  const existing = document.getElementById('toast');
  if (existing) existing.remove();

  const toast = document.createElement('div');
  toast.id = 'toast';
  toast.className = 'toast';
  toast.textContent = message;
  document.body.appendChild(toast);

  requestAnimationFrame(() => toast.classList.add('toast-visible'));
  setTimeout(() => {
    toast.classList.remove('toast-visible');
    setTimeout(() => toast.remove(), 300);
  }, 2000);
}

/**
 * Switch between Repeater, Intruder, and Decoder modes
 */
function switchMode(mode) {
  document.querySelectorAll('.mode-tab').forEach((t) => t.classList.toggle('active', t.dataset.mode === mode));
  document.getElementById('repeaterPanel').classList.toggle('hidden', mode !== 'repeater');
  document.getElementById('intruderPanel').classList.toggle('hidden', mode !== 'intruder');
  document.getElementById('decoderPanel').classList.toggle('hidden', mode !== 'decoder');
  document.getElementById('scannerPanel').classList.toggle('hidden', mode !== 'scanner');
  document.getElementById('techPanel').classList.toggle('hidden', mode !== 'tech');
  document.getElementById('secretPanel').classList.toggle('hidden', mode !== 'secret');
  document.getElementById('owaspPanel').classList.toggle('hidden', mode !== 'owasp');
  if (mode === 'scanner' && scannerFindingsCache.length > 0) {
    applyScannerFilters();
  }
  if (mode === 'tech' && techFindingsCache.length > 0) {
    renderTechResults();
  }
  if (mode === 'secret') {
    applySecretFilters();
  }
  if (mode === 'owasp') renderOwaspFindings();
}

/**
 * Decoder - encode/decode text in various formats
 */
function setupDecoder() {
  document.getElementById('decodeBtn').addEventListener('click', () => runDecoder('decode'));
  document.getElementById('encodeBtn').addEventListener('click', () => runDecoder('encode'));
  document.getElementById('copyDecodedBtn').addEventListener('click', () => {
    const out = document.getElementById('decoderOutput').value;
    if (out) copyToClipboard(out).then(() => showToast('Copied')).catch(() => showCopyModal(out));
  });

  document.getElementById('decoderFormat').addEventListener('change', () => {
    const format = document.getElementById('decoderFormat').value;
    document.getElementById('encodeBtn').style.display = format === 'jwt' ? 'none' : '';
  });
  document.getElementById('encodeBtn').style.display = document.getElementById('decoderFormat').value === 'jwt' ? 'none' : '';
}

function runDecoder(action) {
  const input = document.getElementById('decoderInput').value;
  const format = document.getElementById('decoderFormat').value;
  const outputEl = document.getElementById('decoderOutput');

  if (!input.trim()) {
    showToast('Enter text to decode/encode.');
    return;
  }

  try {
    let result;
    if (action === 'decode') {
      result = decodeByFormat(input, format);
    } else {
      result = encodeByFormat(input, format);
    }
    outputEl.value = result;
  } catch (err) {
    outputEl.value = `Error: ${err.message}`;
  }
}

function decodeByFormat(input, format) {
  switch (format) {
    case 'base64':
      return base64DecodeUtf8(input.replace(/\s/g, ''));
    case 'url':
      return decodeURIComponent(input.replace(/\+/g, ' '));
    case 'hex':
      return hexToString(input.replace(/\s/g, ''));
    case 'html':
      return decodeHtmlEntities(input);
    case 'jwt':
      return decodeJwt(input.trim());
    default:
      return input;
  }
}

function base64DecodeUtf8(str) {
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

function base64EncodeUtf8(str) {
  const bytes = new TextEncoder().encode(str);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function encodeByFormat(input, format) {
  switch (format) {
    case 'base64':
      return base64EncodeUtf8(input);
    case 'url':
      return encodeURIComponent(input);
    case 'hex':
      return stringToHex(input);
    case 'html':
      return encodeHtmlEntities(input);
    default:
      return input;
  }
}

function hexToString(hex) {
  const bytes = hex.match(/.{1,2}/g) || [];
  return bytes.map((b) => String.fromCharCode(parseInt(b, 16))).join('');
}

function stringToHex(str) {
  return [...str].map((c) => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
}

function decodeHtmlEntities(str) {
  const textarea = document.createElement('textarea');
  textarea.innerHTML = str;
  return textarea.value;
}

function encodeHtmlEntities(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function decodeJwt(token) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid JWT format (expected 3 parts)');
  const fixB64 = (s) => {
    let b64 = s.replace(/-/g, '+').replace(/_/g, '/');
    const pad = b64.length % 4;
    if (pad) b64 += '='.repeat(4 - pad);
    return b64;
  };
  const header = JSON.parse(atob(fixB64(parts[0])));
  const payload = JSON.parse(atob(fixB64(parts[1])));
  return `Header:\n${JSON.stringify(header, null, 2)}\n\nPayload:\n${JSON.stringify(payload, null, 2)}`;
}

/**
 * Tech Detector - passive technology fingerprinting from captured traffic + runtime globals.
 */
function setupTechDetector() {
  document.getElementById('runTechDetectBtn').addEventListener('click', runTechDetection);
  document.getElementById('enrichTechCveBtn').addEventListener('click', enrichTechWithCves);
  document.getElementById('clearTechCveCacheBtn').addEventListener('click', clearTechCveCache);
  document.getElementById('copyTechReconBtn').addEventListener('click', copyTechReconBundle);
  document.getElementById('exportTechJsonBtn').addEventListener('click', () => exportTechReport('json'));
  document.getElementById('exportTechCsvBtn').addEventListener('click', () => exportTechReport('csv'));
  const liveToggle = document.getElementById('techLiveCveToggle');
  if (liveToggle) {
    liveToggle.checked = techLiveCveEnabled;
    liveToggle.addEventListener('change', (e) => {
      techLiveCveEnabled = !!e.target.checked;
      saveScopeBlockLists();
      showToast(`Live CVE fetch ${techLiveCveEnabled ? 'enabled' : 'disabled'}`);
    });
  }
  renderTechMeta();
}

function clearTechCveCache() {
  techCveCache = {};
  techLastRunMeta.cveCacheHits = 0;
  techLastRunMeta.cveLiveHits = 0;
  techLastRunMeta.cveFallbackHits = 0;
  techLastRunMeta.cveRateLimited = false;
  saveScopeBlockLists();
  renderTechMeta();
  showToast('CVE cache cleared.');
}

function getResponseHeadersObject(r) {
  const headers = (r?.response?.headers || []).reduce((a, h) => {
    if (h?.name) a[String(h.name).toLowerCase()] = String(h.value || '');
    return a;
  }, {});
  return headers;
}

function extractVersionFromText(text, regexes) {
  if (!text) return '';
  for (const re of regexes) {
    const m = String(text).match(re);
    if (m && m[1]) return m[1];
  }
  return '';
}

function getTechSignatures() {
  return [
    { name: 'React', category: 'Frontend', source: 'script', pattern: /react(?:[-@.]v?(\d+\.\d+(?:\.\d+)?))?/i, confidence: 'medium' },
    { name: 'Vue.js', category: 'Frontend', source: 'script', pattern: /vue(?:[-@.]v?(\d+\.\d+(?:\.\d+)?))?/i, confidence: 'medium' },
    { name: 'Angular', category: 'Frontend', source: 'script', pattern: /angular(?:[-@.]v?(\d+\.\d+(?:\.\d+)?))?/i, confidence: 'medium' },
    { name: 'jQuery', category: 'Frontend', source: 'script', pattern: /jquery(?:[-.]v?(\d+\.\d+(?:\.\d+)?))?/i, confidence: 'medium' },
    { name: 'Next.js', category: 'Frontend', source: 'script', pattern: /\/_next\//i, confidence: 'high' },
    { name: 'Nuxt', category: 'Frontend', source: 'script', pattern: /\/_nuxt\//i, confidence: 'high' },
    { name: 'Bootstrap', category: 'Frontend', source: 'script', pattern: /bootstrap(?:[-.]v?(\d+\.\d+(?:\.\d+)?))?/i, confidence: 'medium' },
    { name: 'Tailwind CSS', category: 'Frontend', source: 'script', pattern: /tailwind(?:[-.]v?(\d+\.\d+(?:\.\d+)?))?/i, confidence: 'low' },
    { name: 'WordPress', category: 'CMS', source: 'script', pattern: /wp-content|wp-includes/i, confidence: 'high' },
    { name: 'Shopify', category: 'Ecommerce', source: 'script', pattern: /cdn\.shopify\.com|shopifycdn/i, confidence: 'high' },
    { name: 'Google Analytics', category: 'Analytics', source: 'script', pattern: /google-analytics\.com|googletagmanager\.com|gtag\/js/i, confidence: 'high' },
    { name: 'Cloudflare', category: 'CDN', source: 'header', header: 'server', pattern: /cloudflare/i, confidence: 'high' },
    { name: 'Nginx', category: 'Server', source: 'header', header: 'server', pattern: /nginx\/?(\d+\.\d+(?:\.\d+)?)?/i, confidence: 'medium' },
    { name: 'Apache', category: 'Server', source: 'header', header: 'server', pattern: /apache\/?(\d+\.\d+(?:\.\d+)?)?/i, confidence: 'medium' },
    { name: 'Express', category: 'Backend', source: 'header', header: 'x-powered-by', pattern: /express/i, confidence: 'high' },
    { name: 'PHP', category: 'Backend', source: 'header', header: 'x-powered-by', pattern: /php\/?(\d+\.\d+(?:\.\d+)?)?/i, confidence: 'high' },
    { name: 'ASP.NET', category: 'Backend', source: 'header', header: 'x-powered-by', pattern: /asp\.net/i, confidence: 'high' },
  ];
}

function getConfidenceScore(level) {
  if (level === 'high') return 3;
  if (level === 'medium') return 2;
  return 1;
}

function upsertTech(map, tech) {
  const existing = map.get(tech.name);
  if (!existing) {
    map.set(tech.name, {
      ...tech,
      evidence: [tech.evidence],
      paths: tech.path ? [tech.path] : [],
      versions: tech.version ? [tech.version] : [],
    });
    return;
  }
  if (!existing.version && tech.version) existing.version = tech.version;
  if (getConfidenceScore(tech.confidence) > getConfidenceScore(existing.confidence)) {
    existing.confidence = tech.confidence;
  }
  existing.evidence.push(tech.evidence);
  if (tech.path) existing.paths.push(tech.path);
  if (tech.version) existing.versions.push(tech.version);
}

function getFullUrlFromValue(url) {
  try {
    const u = new URL(url);
    return u.href;
  } catch (_) {
    return '';
  }
}

function parseVersionParts(v) {
  return String(v || '')
    .split('.')
    .map((x) => parseInt(x, 10))
    .filter((n) => !isNaN(n));
}

function compareVersions(a, b) {
  const pa = parseVersionParts(a);
  const pb = parseVersionParts(b);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const x = pa[i] || 0;
    const y = pb[i] || 0;
    if (x > y) return 1;
    if (x < y) return -1;
  }
  return 0;
}

function isVersionLessThan(v, threshold) {
  if (!v) return false;
  return compareVersions(v, threshold) < 0;
}

function getTechTestHints(name) {
  const hints = {
    'WordPress': ['Check /wp-json exposure', 'Plugin/theme enumeration', 'XML-RPC abuse checks'],
    'Next.js': ['Inspect exposed /_next assets', 'Probe API routes for auth checks', 'Check source-map exposure'],
    'Nuxt': ['Inspect /_nuxt assets', 'Check SSR data leakage', 'Review public runtime config exposure'],
    'React': ['DOM XSS sink review', 'Token exposure in client state', 'Source-map leakage'],
    'Vue.js': ['Template injection review', 'Client-side auth bypass checks', 'Debug mode artifact exposure'],
    'Angular': ['Legacy sandbox bypass checks', 'Template injection tests', 'Client-side route guard bypass'],
    'jQuery': ['XSS payload tests on legacy sinks', 'Prototype pollution checks', 'Old plugin vuln review'],
    'Bootstrap': ['Outdated dependency checks', 'CSP bypass surface review', 'DOM injection review'],
    'Cloudflare': ['Origin IP leakage checks', 'Cache poisoning checks', 'WAF bypass validation'],
    'Nginx': ['Misconfig (alias/traversal) checks', 'Header hardening review', 'HTTP method abuse checks'],
    'Apache': ['Directory listing checks', 'Misconfig/module exposure', 'HTTP request smuggling checks'],
    'Express': ['Missing helmet/security headers', 'Rate-limit/auth middleware checks', 'Error leakage review'],
    'PHP': ['File inclusion probes', 'Insecure deserialization checks', 'Error disclosure review'],
    'ASP.NET': ['ViewState/trace exposure checks', 'AuthZ bypass checks', 'Misconfigured headers review'],
    'Google Analytics': ['PII in analytics payload checks', 'Event spoofing/tampering', 'Leakage in query params'],
    'Shopify': ['Public app endpoint auth checks', 'Cart/order tampering checks', 'API token leakage checks'],
    'Tailwind CSS': ['Low direct risk: focus on app logic', 'Check generated class-based XSS sinks', 'Source-map exposure'],
  };
  return hints[name] || ['AuthZ checks', 'Input validation tests', 'Security header review'];
}

function getVersionRisk(name, versions) {
  const list = (versions || []).filter(Boolean);
  if (list.length === 0) return { severity: 'low', note: 'Version not detected' };

  const checks = {
    'jQuery': { threshold: '3.5.0', severity: 'high', note: 'Potentially vulnerable jQuery (< 3.5.0)' },
    'Angular': { threshold: '1.8.0', severity: 'medium', note: 'Legacy AngularJS version detected (< 1.8.0)' },
    'Bootstrap': { threshold: '5.0.0', severity: 'low', note: 'Older Bootstrap branch detected (< 5.0.0)' },
    'PHP': { threshold: '8.0.0', severity: 'medium', note: 'Legacy PHP branch detected (< 8.0.0)' },
    'Nginx': { threshold: '1.20.0', severity: 'low', note: 'Older Nginx version detected (< 1.20.0)' },
    'Apache': { threshold: '2.4.50', severity: 'medium', note: 'Apache version may be outdated (< 2.4.50)' },
  };
  const rule = checks[name];
  if (!rule) return { severity: 'low', note: 'No local version rule for this technology' };

  const vulnerable = list.find((v) => isVersionLessThan(v, rule.threshold));
  if (vulnerable) {
    return { severity: rule.severity, note: `${rule.note}. Seen: ${vulnerable}` };
  }
  return { severity: 'low', note: 'No vulnerable version pattern detected in local rules' };
}

function getKnownCvesForTechVersion(name, versions) {
  const unique = [...new Set((versions || []).filter(Boolean))];
  if (unique.length === 0) return [];

  const rules = [
    {
      name: 'jQuery',
      when: (v) => isVersionLessThan(v, '3.5.0'),
      cves: [
        { id: 'CVE-2020-11022', summary: 'jQuery XSS issue in htmlPrefilter handling.' },
        { id: 'CVE-2020-11023', summary: 'jQuery XSS issue related to DOM manipulation.' },
      ],
    },
    {
      name: 'Bootstrap',
      when: (v) => isVersionLessThan(v, '3.4.1'),
      cves: [
        { id: 'CVE-2019-8331', summary: 'Bootstrap tooltip/popover XSS vulnerability.' },
      ],
    },
    {
      name: 'Apache',
      when: (v) => isVersionLessThan(v, '2.4.50'),
      cves: [
        { id: 'CVE-2021-41773', summary: 'Apache path traversal and possible RCE.' },
        { id: 'CVE-2021-42013', summary: 'Apache path traversal/RCE bypass variant.' },
      ],
    },
    {
      name: 'Nginx',
      when: (v) => isVersionLessThan(v, '1.21.0'),
      cves: [
        { id: 'CVE-2021-23017', summary: 'Nginx resolver memory corruption vulnerability.' },
      ],
    },
    {
      name: 'PHP',
      when: (v) => isVersionLessThan(v, '8.1.0'),
      cves: [
        { id: 'CVE-2021-21703', summary: 'PHP bug class from older branches (example reference).' },
      ],
    },
    {
      name: 'Angular',
      when: (v) => isVersionLessThan(v, '1.8.0'),
      cves: [
        { id: 'CVE-2022-25844', summary: 'AngularJS sanitizer bypass affecting older branches.' },
      ],
    },
  ];

  const rule = rules.find((r) => r.name === name);
  if (!rule) return [];

  const hits = [];
  unique.forEach((v) => {
    if (rule.when(v)) {
      rule.cves.forEach((c) => hits.push({
        ...c,
        affectedVersion: v,
        source: 'local-rules',
        url: `https://nvd.nist.gov/vuln/detail/${c.id}`,
      }));
    }
  });
  return hits;
}

function buildTechCveCacheKey(name, versions) {
  const normalized = [...new Set((versions || []).filter(Boolean))].sort().join(',');
  return `${name}|${normalized || 'unknown'}`;
}

function pruneTechCveCache() {
  const entries = Object.entries(techCveCache || {});
  if (entries.length <= TECH_CVE_CACHE_MAX_KEYS) return;
  entries
    .sort((a, b) => Number(a[1]?.fetchedAt || 0) - Number(b[1]?.fetchedAt || 0))
    .slice(0, entries.length - TECH_CVE_CACHE_MAX_KEYS)
    .forEach(([k]) => {
      delete techCveCache[k];
    });
}

function normalizeTechForCveQuery(name) {
  const map = {
    'jQuery': { vendor: 'jquery', product: 'jquery', aliases: ['jquery', 'jQuery'], cpeKeywords: ['jquery:jquery'], cpeProducts: ['jquery'] },
    'Bootstrap': { vendor: 'twbs', product: 'bootstrap', aliases: ['bootstrap'], cpeKeywords: ['twbs:bootstrap', 'getbootstrap:bootstrap', 'bootstrap:bootstrap'], cpeProducts: ['bootstrap'] },
    'Angular': { vendor: 'angularjs', product: 'angular.js', aliases: ['angularjs', 'angular'], cpeKeywords: ['angularjs:angular.js', 'angularjs:angular'], cpeProducts: ['angular.js', 'angular'] },
    'Apache': { vendor: 'apache', product: 'http_server', aliases: ['apache http server', 'apache'], cpeKeywords: ['apache:http_server'], cpeProducts: ['http_server'] },
    'Nginx': { vendor: 'nginx', product: 'nginx', aliases: ['nginx'], cpeKeywords: ['nginx:nginx'], cpeProducts: ['nginx', 'nginx_plus'] },
    'PHP': { vendor: 'php', product: 'php', aliases: ['php'], cpeKeywords: ['php:php'], cpeProducts: ['php'] },
    'WordPress': { vendor: 'wordpress', product: 'wordpress', aliases: ['wordpress'], cpeKeywords: ['wordpress:wordpress'], cpeProducts: ['wordpress'] },
    'Drupal': { vendor: 'drupal', product: 'drupal', aliases: ['drupal'], cpeKeywords: ['drupal:drupal'], cpeProducts: ['drupal'] },
    'React': { vendor: 'facebook', product: 'react', aliases: ['react'], cpeKeywords: ['facebook:react', 'reactjs:react'], cpeProducts: ['react'] },
    'Vue.js': { vendor: 'vuejs', product: 'vue', aliases: ['vue.js', 'vue'], cpeKeywords: ['vuejs:vue'], cpeProducts: ['vue'] },
    'Express': { vendor: 'expressjs', product: 'express', aliases: ['express'], cpeKeywords: ['expressjs:express'], cpeProducts: ['express'] },
  };
  return map[name] || {
    vendor: name.toLowerCase(),
    product: name.toLowerCase(),
    aliases: [name.toLowerCase()],
    cpeKeywords: [`${name.toLowerCase()}:${name.toLowerCase()}`],
    cpeProducts: [name.toLowerCase()],
  };
}

function normalizeVersionString(v) {
  const m = String(v || '').match(/\d+(?:\.\d+){0,4}/);
  return m ? m[0] : '';
}

function isVersionInRange(version, startIncl, startExcl, endIncl, endExcl) {
  const v = normalizeVersionString(version);
  if (!v) return false;
  const sI = normalizeVersionString(startIncl);
  const sE = normalizeVersionString(startExcl);
  const eI = normalizeVersionString(endIncl);
  const eE = normalizeVersionString(endExcl);
  if (sI && compareVersions(v, sI) < 0) return false;
  if (sE && compareVersions(v, sE) <= 0) return false;
  if (eI && compareVersions(v, eI) > 0) return false;
  if (eE && compareVersions(v, eE) >= 0) return false;
  return true;
}

function cpeMatchesTech(criteria, techMeta) {
  const c = String(criteria || '').toLowerCase();
  if (!c) return false;
  if ((techMeta.cpeKeywords || []).some((kw) => c.includes(kw))) return true;
  const vendorOk = c.includes(`:${String(techMeta.vendor || '').toLowerCase()}:`);
  const productOk = (techMeta.cpeProducts || []).some((p) => c.includes(`:${String(p).toLowerCase()}:`));
  return vendorOk && productOk;
}

function cpeExplicitVersion(criteria) {
  const parts = String(criteria || '').split(':');
  const v = parts[5] || '';
  if (!v || v === '*' || v === '-' || v === 'na') return '';
  return normalizeVersionString(v);
}

function cveAffectsVersion(vuln, techMeta, version) {
  const target = normalizeVersionString(version);
  if (!target) return false;
  const cve = vuln?.cve || {};
  const configs = cve?.configurations || vuln?.configurations || [];

  const walk = (nodes) => {
    for (const node of (nodes || [])) {
      for (const match of (node?.cpeMatch || [])) {
        const criteria = match?.criteria || match?.cpe23Uri || '';
        if (!cpeMatchesTech(criteria, techMeta)) continue;
        if (match?.vulnerable === false) continue;

        const direct = cpeExplicitVersion(criteria);
        if (direct && compareVersions(target, direct) === 0) return true;

        if (isVersionInRange(
          target,
          match?.versionStartIncluding,
          match?.versionStartExcluding,
          match?.versionEndIncluding,
          match?.versionEndExcluding
        )) {
          return true;
        }
      }
      if (walk(node?.children || [])) return true;
    }
    return false;
  };

  if (walk(configs)) return true;

  // Fallback: version + alias appears in description.
  const desc = ((cve?.descriptions || []).find((d) => d.lang === 'en')?.value || '').toLowerCase();
  if (!desc) return false;
  const hasAlias = (techMeta.aliases || []).some((a) => desc.includes(String(a).toLowerCase()));
  return hasAlias && desc.includes(target);
}

async function fetchJsonWithTimeout(url, timeoutMs = 7000) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: ctrl.signal });
    if (res.status === 429) {
      const err = new Error('rate-limited');
      err.rateLimited = true;
      throw err;
    }
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}

function extractCvesFromCirclPayload(payload, versions, techMeta) {
  const items = Array.isArray(payload) ? payload : (payload?.results || payload?.data || []);
  const seen = new Set();
  const out = [];
  const normalizedVersions = (versions || []).map(normalizeVersionString).filter(Boolean);
  items.slice(0, 50).forEach((row) => {
    const id = row?.id || row?.cve || row?.CVE || '';
    if (!id || seen.has(id)) return;
    const summary = row?.summary || row?.description || row?.title || 'No summary available';
    const hay = `${summary} ${JSON.stringify(row?.vulnerable_configuration || '')} ${JSON.stringify(row?.vulnerable_product || '')}`.toLowerCase();
    const hasAlias = (techMeta.aliases || []).some((a) => hay.includes(String(a).toLowerCase()));
    if (!hasAlias) return;
    const matchedVersion = normalizedVersions.find((v) => hay.includes(v));
    if (!matchedVersion) return;
    seen.add(id);
    out.push({
      id,
      summary: String(summary).slice(0, 220),
      affectedVersion: matchedVersion || 'unknown',
      source: 'CIRCL',
      url: `https://nvd.nist.gov/vuln/detail/${id}`,
    });
  });
  return out;
}

function extractCvesFromNvdPayload(payload, versions, techMeta) {
  const vulns = Array.isArray(payload?.vulnerabilities) ? payload.vulnerabilities : [];
  const out = [];
  const seen = new Set();
  const normalizedVersions = [...new Set((versions || []).map(normalizeVersionString).filter(Boolean))];
  if (normalizedVersions.length === 0) return [];
  vulns.slice(0, 30).forEach((v) => {
    const cve = v?.cve || {};
    const id = cve?.id || '';
    if (!id || seen.has(id)) return;
    const desc = (cve?.descriptions || []).find((d) => d.lang === 'en')?.value || 'No summary available';
    const matchedVersion = normalizedVersions.find((ver) => cveAffectsVersion(v, techMeta, ver));
    if (!matchedVersion) return;
    seen.add(id);
    out.push({
      id,
      summary: String(desc).slice(0, 220),
      affectedVersion: matchedVersion || 'unknown',
      source: 'NVD',
      url: `https://nvd.nist.gov/vuln/detail/${id}`,
    });
  });
  return out;
}

async function fetchLiveCvesForTech(name, versions) {
  const key = buildTechCveCacheKey(name, versions);
  const cached = techCveCache[key];
  if (cached && (Date.now() - Number(cached.fetchedAt || 0) < TECH_CVE_CACHE_TTL_MS)) {
    return { source: 'cache', cves: cached.cves || [], rateLimited: false };
  }

  const q = normalizeTechForCveQuery(name);
  const normalizedVersions = [...new Set((versions || []).map(normalizeVersionString).filter(Boolean))];
  if (normalizedVersions.length === 0) {
    return { source: 'no-version', cves: [], rateLimited: false };
  }
  const versionTerm = normalizedVersions.slice(0, 2).join(' ');
  let rateLimited = false;
  const cpeProducts = (q.cpeProducts || [q.product]).filter(Boolean);

  try {
    // Free source #1: CIRCL CVE search
    const circlUrl = `https://cve.circl.lu/api/search/${encodeURIComponent(q.vendor)}/${encodeURIComponent(q.product)}`;
    const circlData = await fetchJsonWithTimeout(circlUrl, 7000);
    const circlCves = extractCvesFromCirclPayload(circlData, normalizedVersions, q).slice(0, 8);
    if (circlCves.length > 0) {
      techCveCache[key] = { fetchedAt: Date.now(), cves: circlCves };
      pruneTechCveCache();
      saveScopeBlockLists();
      return { source: 'CIRCL', cves: circlCves, rateLimited: false };
    }
  } catch (err) {
    if (err?.rateLimited) rateLimited = true;
  }

  try {
    // Free source #2: NVD CPE query (best signal for version-specific CVEs).
    const nvdCpeHits = [];
    for (const version of normalizedVersions.slice(0, 2)) {
      for (const product of cpeProducts.slice(0, 2)) {
        const cpe = `cpe:2.3:a:${q.vendor}:${product}:${version}:*:*:*:*:*:*:*`;
        const cpeUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=${encodeURIComponent(cpe)}&resultsPerPage=40`;
        const nvdCpeData = await fetchJsonWithTimeout(cpeUrl, 9000);
        const extracted = extractCvesFromNvdPayload(nvdCpeData, [version], q);
        nvdCpeHits.push(...extracted);
      }
    }
    if (nvdCpeHits.length > 0) {
      const dedup = [];
      const seen = new Set();
      nvdCpeHits.forEach((c) => {
        if (seen.has(c.id)) return;
        seen.add(c.id);
        dedup.push(c);
      });
      techCveCache[key] = { fetchedAt: Date.now(), cves: dedup.slice(0, 8) };
      pruneTechCveCache();
      saveScopeBlockLists();
      return { source: 'NVD-CPE', cves: dedup.slice(0, 8), rateLimited: false };
    }
  } catch (err) {
    if (err?.rateLimited) rateLimited = true;
  }

  try {
    // Free source #2: NVD keyword search (no key required, stricter limits)
    const keyword = encodeURIComponent(`${q.aliases[0]} ${versionTerm}`.trim());
    const nvdUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${keyword}&resultsPerPage=30`;
    const nvdData = await fetchJsonWithTimeout(nvdUrl, 9000);
    const nvdCves = extractCvesFromNvdPayload(nvdData, normalizedVersions, q).slice(0, 8);
    techCveCache[key] = { fetchedAt: Date.now(), cves: nvdCves };
    pruneTechCveCache();
    saveScopeBlockLists();
    return { source: nvdCves.length > 0 ? 'NVD' : 'live-none', cves: nvdCves, rateLimited };
  } catch (err) {
    if (err?.rateLimited) rateLimited = true;
    return { source: 'live-error', cves: [], rateLimited };
  }
}

async function enrichTechWithCves() {
  if (techFindingsCache.length === 0) {
    showToast('Run Detect first.');
    return;
  }
  let liveHits = 0;
  let cacheHits = 0;
  let fallbackHits = 0;
  let sawRateLimit = false;

  if (!techLiveCveEnabled) {
    techFindingsCache = techFindingsCache.map((t) => {
      const cves = getKnownCvesForTechVersion(t.name, t.versions || []);
      return {
        ...t,
        cves,
        cveStatus: cves.length ? `matched ${cves.length} (local)` : 'none matched (local)',
      };
    });
    fallbackHits = techFindingsCache.length;
  } else {
    const updated = [];
    for (const t of techFindingsCache) {
      const detectedVersions = (t.versions || []).map(normalizeVersionString).filter(Boolean);
      if (detectedVersions.length === 0) {
        updated.push({
          ...t,
          cves: [],
          cveStatus: 'version not detected (cannot map CVE precisely)',
        });
        fallbackHits += 1;
        continue;
      }

      const live = await fetchLiveCvesForTech(t.name, detectedVersions);
      const local = getKnownCvesForTechVersion(t.name, t.versions || []);
      sawRateLimit = sawRateLimit || !!live.rateLimited;
      let cves = live.cves || [];
      let status = `matched ${cves.length} (${live.source})`;
      if (live.source === 'cache') cacheHits += 1;
      if ((live.source === 'CIRCL' || live.source === 'NVD') && cves.length > 0) liveHits += 1;
      if (cves.length === 0) {
        cves = local;
        status = cves.length ? `matched ${cves.length} (local fallback)` : 'none matched (fallback)';
        fallbackHits += 1;
      }
      updated.push({
        ...t,
        cves,
        cveStatus: status,
      });
    }
    techFindingsCache = updated;
  }

  techLastRunMeta.cveLiveHits = liveHits;
  techLastRunMeta.cveCacheHits = cacheHits;
  techLastRunMeta.cveFallbackHits = fallbackHits;
  techLastRunMeta.cveRateLimited = sawRateLimit;
  renderTechMeta();
  renderTechResults();
  renderOwaspFindings();
  const withCves = techFindingsCache.filter((t) => (t.cves || []).length > 0).length;
  if (sawRateLimit) {
    showToast(withCves > 0 ? `Rate-limited on live CVE API. Used fallback; matches: ${withCves}.` : 'Rate-limited and no CVE matches.');
    return;
  }
  showToast(withCves > 0 ? `CVE links found for ${withCves} technology entries.` : 'No CVE matches found.');
}

function buildTechReconBundleMarkdown() {
  const lines = [
    '# HackTools++ Tech Recon Bundle',
    '',
    `Generated: ${new Date().toISOString()}`,
    `Detected Technologies: ${techFindingsCache.length}`,
    '',
  ];

  techFindingsCache.forEach((t) => {
    lines.push(`## ${t.name}`);
    lines.push(`- Category: ${t.category}`);
    lines.push(`- Confidence: ${t.confidence}`);
    lines.push(`- Versions: ${(t.versions || []).join(', ') || t.version || 'unknown'}`);
    lines.push(`- Version Drift: ${t.drift ? 'yes (multi-version)' : 'no (single version)'}`);
    lines.push(`- Version Risk: ${t.versionRisk?.severity || 'low'} - ${t.versionRisk?.note || 'n/a'}`);
    lines.push(`- CVE Status: ${t.cveStatus || 'not enriched yet (click Enrich CVEs)'}`);
    const cves = t.cves || [];
    if (cves.length > 0) {
      lines.push('- CVE Matches:');
      cves.slice(0, 8).forEach((c) => {
        lines.push(`  - ${c.id} (${c.affectedVersion}) [${c.source || 'local'}]: ${c.summary}${c.url ? ` (${c.url})` : ''}`);
      });
    }
    lines.push(`- Test Hints: ${(t.testHints || []).join(' | ')}`);
    lines.push('- Full URL Evidence:');
    ((t.paths || []).length ? t.paths : ['n/a']).forEach((p) => lines.push(`  - ${p}`));
    lines.push('- Raw Evidence:');
    ((t.evidence || []).length ? t.evidence : ['n/a']).forEach((e) => lines.push(`  - ${e}`));
    lines.push('');
  });
  return lines.join('\n');
}

function copyTechReconBundle() {
  if (techFindingsCache.length === 0) {
    showToast('No tech results to copy.');
    return;
  }
  const markdown = buildTechReconBundleMarkdown();
  copyToClipboard(markdown).then(() => showToast('Recon bundle copied')).catch(() => showCopyModal(markdown));
}

async function collectRuntimeTechSignals(tabId) {
  const res = await chrome.scripting.executeScript({
    target: { tabId },
    func: () => {
      const scripts = [...document.querySelectorAll('script[src]')].map((s) => s.src).filter(Boolean).slice(0, 300);
      const metaGenerator = document.querySelector('meta[name="generator"]')?.content || '';
      const globals = {
        reactVersion: window.React?.version || '',
        vueVersion: window.Vue?.version || '',
        angularVersion: window.ng?.coreTokens?.VERSION?.full || window.angular?.version?.full || '',
        jqueryVersion: window.jQuery?.fn?.jquery || '',
        hasNextData: !!window.__NEXT_DATA__,
        hasNuxt: !!window.__NUXT__,
      };
      return { scripts, metaGenerator, globals };
    },
  });
  return res?.[0]?.result || { scripts: [], metaGenerator: '', globals: {} };
}

async function runTechDetection() {
  const resultsEl = document.getElementById('techResults');
  resultsEl.innerHTML = '<p class="scanner-loading">Detecting technologies...</p>';

  const techMap = new Map();
  const signatures = getTechSignatures();
  const recent = capturedRequests.slice(0, 400);

  try {
    for (const r of recent) {
      const url = r?.url || r?.request?.url || '';
      const headers = getResponseHeadersObject(r);

      // Script/url based detection
      signatures
        .filter((s) => s.source === 'script')
        .forEach((sig) => {
          if (sig.pattern.test(url)) {
            const m = String(url).match(sig.pattern);
            upsertTech(techMap, {
              name: sig.name,
              category: sig.category,
              version: m?.[1] || '',
              confidence: sig.confidence,
              evidence: `url:${url}`,
              path: getFullUrlFromValue(url),
            });
          }
        });

      // Header based detection
      signatures
        .filter((s) => s.source === 'header')
        .forEach((sig) => {
          const val = headers[sig.header] || '';
          if (val && sig.pattern.test(val)) {
            const m = String(val).match(sig.pattern);
            upsertTech(techMap, {
              name: sig.name,
              category: sig.category,
              version: m?.[1] || '',
              confidence: sig.confidence,
              evidence: `${sig.header}:${val}`,
              path: getFullUrlFromValue(url),
            });
          }
        });
    }

    const tabId = chrome.devtools.inspectedWindow.tabId;
    const runtime = await collectRuntimeTechSignals(tabId);

    (runtime.scripts || []).forEach((src) => {
      signatures
        .filter((s) => s.source === 'script')
        .forEach((sig) => {
          if (sig.pattern.test(src)) {
            const m = String(src).match(sig.pattern);
            upsertTech(techMap, {
              name: sig.name,
              category: sig.category,
              version: m?.[1] || '',
              confidence: 'high',
              evidence: `script:${src}`,
              path: getFullUrlFromValue(src),
            });
          }
        });
    });

    if (runtime.metaGenerator) {
      const g = runtime.metaGenerator;
      if (/wordpress/i.test(g)) {
        upsertTech(techMap, { name: 'WordPress', category: 'CMS', version: extractVersionFromText(g, [/wordpress\s*([0-9.]+)/i]), confidence: 'high', evidence: `meta-generator:${g}` });
      }
      if (/drupal/i.test(g)) {
        upsertTech(techMap, { name: 'Drupal', category: 'CMS', version: extractVersionFromText(g, [/drupal\s*([0-9.]+)/i]), confidence: 'high', evidence: `meta-generator:${g}` });
      }
    }

    if (runtime.globals?.reactVersion) upsertTech(techMap, { name: 'React', category: 'Frontend', version: runtime.globals.reactVersion, confidence: 'high', evidence: `global:React.version=${runtime.globals.reactVersion}` });
    if (runtime.globals?.vueVersion) upsertTech(techMap, { name: 'Vue.js', category: 'Frontend', version: runtime.globals.vueVersion, confidence: 'high', evidence: `global:Vue.version=${runtime.globals.vueVersion}` });
    if (runtime.globals?.angularVersion) upsertTech(techMap, { name: 'Angular', category: 'Frontend', version: runtime.globals.angularVersion, confidence: 'high', evidence: `global:Angular.version=${runtime.globals.angularVersion}` });
    if (runtime.globals?.jqueryVersion) upsertTech(techMap, { name: 'jQuery', category: 'Frontend', version: runtime.globals.jqueryVersion, confidence: 'high', evidence: `global:jQuery.fn.jquery=${runtime.globals.jqueryVersion}` });
    if (runtime.globals?.hasNextData) upsertTech(techMap, { name: 'Next.js', category: 'Frontend', version: '', confidence: 'high', evidence: 'global:__NEXT_DATA__' });
    if (runtime.globals?.hasNuxt) upsertTech(techMap, { name: 'Nuxt', category: 'Frontend', version: '', confidence: 'high', evidence: 'global:__NUXT__' });

    techFindingsCache = [...techMap.values()]
      .map((t) => ({
        ...t,
        evidence: [...new Set(t.evidence)].slice(0, 6),
        paths: [...new Set((t.paths || []).filter(Boolean))].slice(0, 6),
        versions: [...new Set((t.versions || []).filter(Boolean))].slice(0, 5),
      }))
      .map((t) => {
        const versionRisk = getVersionRisk(t.name, t.versions);
        const drift = (t.versions || []).length > 1;
        const cves = getKnownCvesForTechVersion(t.name, t.versions || []);
        return {
          ...t,
          drift,
          versionRisk,
          testHints: getTechTestHints(t.name),
          cves,
          cveStatus: cves.length ? `matched ${cves.length}` : 'none matched',
        };
      })
      .sort((a, b) => a.name.localeCompare(b.name));

    techLastRunMeta.total = techFindingsCache.length;
    techLastRunMeta.high = techFindingsCache.filter((t) => t.confidence === 'high').length;
    techLastRunMeta.medium = techFindingsCache.filter((t) => t.confidence === 'medium').length;
    techLastRunMeta.low = techFindingsCache.filter((t) => t.confidence === 'low').length;
    techLastRunMeta.cveLiveHits = 0;
    techLastRunMeta.cveCacheHits = 0;
    techLastRunMeta.cveFallbackHits = 0;
    techLastRunMeta.cveRateLimited = false;
    techLastRunMeta.lastRunAt = Date.now();
    renderTechMeta();
    renderTechResults();
    renderOwaspFindings();
  } catch (err) {
    resultsEl.innerHTML = `<p class="scanner-error">${escapeHtml(err.message || 'Detection failed')}</p>`;
  }
}

function renderTechMeta() {
  const el = document.getElementById('techMeta');
  const m = techLastRunMeta;
  const last = m.lastRunAt ? new Date(m.lastRunAt).toLocaleTimeString() : '—';
  const cveHits = techFindingsCache.reduce((n, t) => n + ((t.cves || []).length > 0 ? 1 : 0), 0);
  el.innerHTML = `
    <span class="metric">Tech: ${m.total}</span>
    <span class="metric">High: ${m.high}</span>
    <span class="metric">Medium: ${m.medium}</span>
    <span class="metric">Low: ${m.low}</span>
    <span class="metric">CVE hits: ${cveHits}</span>
    <span class="metric">Live CVE: ${techLiveCveEnabled ? 'ON' : 'OFF'}</span>
    <span class="metric">Live hits: ${m.cveLiveHits || 0}</span>
    <span class="metric">Cache hits: ${m.cveCacheHits || 0}</span>
    <span class="metric">Fallback: ${m.cveFallbackHits || 0}</span>
    <span class="metric">Rate-limited: ${m.cveRateLimited ? 'yes' : 'no'}</span>
    <span class="metric">Last detect: ${escapeHtml(last)}</span>
  `;
}

function renderTechResults() {
  const el = document.getElementById('techResults');
  if (techFindingsCache.length === 0) {
    el.innerHTML = '<p class="scanner-ok">No technologies detected yet. Click Run Detect.</p>';
    return;
  }
  const rows = techFindingsCache
    .map((t, idx) => `
      <tr>
        <td class="tech-tech">${escapeHtml(t.name)}</td>
        <td>${escapeHtml(t.category)}</td>
        <td title="${escapeHtml((t.versions || []).join(', '))}">${escapeHtml((t.versions || []).join(', ') || t.version || '—')}</td>
        <td><span class="tag ${escapeHtml(t.confidence)}">${escapeHtml(t.confidence)}</span></td>
        <td>${t.drift ? '<span class="tag medium">multi-version</span>' : '<span class="tag low">single</span>'}</td>
        <td><span class="tag ${escapeHtml(t.versionRisk?.severity || 'low')}">${escapeHtml(t.versionRisk?.severity || 'low')}</span><div class="tech-mini">${escapeHtml(t.versionRisk?.note || '')}</div></td>
        <td class="tech-evidence" title="${escapeHtml((t.cves || []).map((c) => `${c.id} (${c.affectedVersion})`).join('\n'))}">
          ${escapeHtml((t.cves || []).map((c) => c.id).join(' | ') || '—')}
          <div class="tech-mini">${escapeHtml(t.cveStatus || '')}</div>
        </td>
        <td class="tech-evidence" title="${escapeHtml((t.testHints || []).join('\n'))}">${escapeHtml((t.testHints || []).join(' | '))}</td>
        <td class="tech-evidence" title="${escapeHtml((t.paths || []).join('\n'))}">${escapeHtml((t.paths || []).join(' | ') || '—')}</td>
        <td class="tech-evidence" title="${escapeHtml((t.evidence || []).join('\n'))}">${escapeHtml((t.evidence || []).join(' | '))}</td>
        <td class="tech-actions">
          <button type="button" class="btn btn-small copy-tech-url-btn" data-index="${idx}">Copy URL</button>
          <button type="button" class="btn btn-small copy-tech-urls-btn" data-index="${idx}">Copy All</button>
          <button type="button" class="btn btn-small copy-tech-cves-btn" data-index="${idx}">Copy CVEs</button>
        </td>
      </tr>
    `)
    .join('');
  el.innerHTML = `
    <div class="tech-table-wrap">
      <table class="tech-table">
        <thead>
          <tr>
            <th>Technology</th>
            <th>Category</th>
            <th>Version(s)</th>
            <th>Confidence</th>
            <th>Drift</th>
            <th>Version Risk</th>
            <th>CVEs</th>
            <th>Test Hints</th>
            <th>Full URL(s)</th>
            <th>Evidence</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  `;

  el.querySelectorAll('.copy-tech-url-btn').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const idx = parseInt(btn.dataset.index || '-1', 10);
      const t = techFindingsCache[idx];
      if (!t || !(t.paths || []).length) {
        showToast('No URL available for this technology.');
        return;
      }
      const url = t.paths[0];
      copyToClipboard(url).then(() => showToast('Full URL copied')).catch(() => showCopyModal(url));
    });
  });

  el.querySelectorAll('.copy-tech-urls-btn').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const idx = parseInt(btn.dataset.index || '-1', 10);
      const t = techFindingsCache[idx];
      if (!t || !(t.paths || []).length) {
        showToast('No URLs available for this technology.');
        return;
      }
      const all = t.paths.join('\n');
      copyToClipboard(all).then(() => showToast('All full URLs copied')).catch(() => showCopyModal(all));
    });
  });

  el.querySelectorAll('.copy-tech-cves-btn').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const idx = parseInt(btn.dataset.index || '-1', 10);
      const t = techFindingsCache[idx];
      const cves = t?.cves || [];
      if (!t || cves.length === 0) {
        showToast('No CVEs for this technology.');
        return;
      }
      const text = cves.map((c) => `${c.id} (${c.affectedVersion}) [${c.source || 'local'}] - ${c.summary}${c.url ? ` | ${c.url}` : ''}`).join('\n');
      copyToClipboard(text).then(() => showToast('CVE list copied')).catch(() => showCopyModal(text));
    });
  });
}

function exportTechReport(format) {
  if (techFindingsCache.length === 0) {
    showToast('No technology results to export.');
    return;
  }
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  if (format === 'json') {
    downloadText(`tech-detector-${ts}.json`, JSON.stringify({
      generatedAt: new Date().toISOString(),
      metrics: techLastRunMeta,
      technologies: techFindingsCache,
    }, null, 2), 'application/json');
    showToast('Tech JSON exported.');
    return;
  }
  const rows = [['technology', 'category', 'versions', 'confidence', 'drift', 'versionRiskSeverity', 'versionRiskNote', 'cveStatus', 'cves', 'testHints', 'fullUrls', 'evidence']];
  techFindingsCache.forEach((t) => {
    rows.push([
      t.name,
      t.category,
      (t.versions || []).join(' | ') || t.version || '',
      t.confidence,
      t.drift ? 'multi-version' : 'single',
      t.versionRisk?.severity || '',
      t.versionRisk?.note || '',
      t.cveStatus || '',
      (t.cves || []).map((c) => `${c.id} (${c.affectedVersion}) [${c.source || 'local'}]`).join(' | '),
      (t.testHints || []).join(' | '),
      (t.paths || []).join(' | '),
      (t.evidence || []).join(' | '),
    ]);
  });
  const csv = rows.map((r) => r.map((v) => `"${String(v || '').replace(/"/g, '""')}"`).join(',')).join('\n');
  downloadText(`tech-detector-${ts}.csv`, csv, 'text/csv');
  showToast('Tech CSV exported.');
}

/**
 * Scanner - lightweight client-side security checks
 */
function setupScanner() {
  document.getElementById('runScanBtn').addEventListener('click', runSecurityScan);
  document.getElementById('scannerSeverityFilter').addEventListener('change', applyScannerFilters);
  document.getElementById('scannerSearchInput').addEventListener('input', applyScannerFilters);
  document.getElementById('exportScannerJsonBtn').addEventListener('click', () => exportScannerReport('json'));
  document.getElementById('exportScannerCsvBtn').addEventListener('click', () => exportScannerReport('csv'));
  document.getElementById('scannerAutoToggle').addEventListener('change', (e) => {
    scannerAutoEnabled = !!e.target.checked;
    saveScopeBlockLists();
    showToast(`Auto Scan ${scannerAutoEnabled ? 'enabled' : 'disabled'}`);
  });
  document.getElementById('scannerSuppressions').addEventListener('click', (e) => {
    const btn = e.target.closest('[data-remove-suppression]');
    if (!btn) return;
    const type = btn.dataset.type;
    const value = btn.dataset.value;
    if (!type || !value) return;
    if (type === 'key') scannerSuppressions.keys = scannerSuppressions.keys.filter((k) => k !== value);
    if (type === 'domain') scannerSuppressions.domains = scannerSuppressions.domains.filter((d) => d !== value);
    saveScopeBlockLists();
    renderScannerSuppressions();
    applyScannerFilters();
    showToast('Suppression removed.');
  });
  renderScannerMeta();
  renderScannerSuppressions();
}

function extractMatchedSnippet(text, regex, radius = 80) {
  if (!text) return '';
  const match = text.match(regex);
  if (!match || typeof match.index !== 'number') return '';
  const start = Math.max(0, match.index - radius);
  const end = Math.min(text.length, match.index + (match[0]?.length || 0) + radius);
  return text.slice(start, end).replace(/\s+/g, ' ').trim();
}

function decodeJwtHeaderLite(token) {
  try {
    const parts = String(token || '').split('.');
    if (parts.length < 2) return null;
    let b64 = parts[0].replace(/-/g, '+').replace(/_/g, '/');
    const pad = b64.length % 4;
    if (pad) b64 += '='.repeat(4 - pad);
    return JSON.parse(atob(b64));
  } catch (_) {
    return null;
  }
}

function jwtAlgRisk(alg) {
  const a = String(alg || '').toLowerCase();
  if (!a) return { severity: 'medium', msg: 'JWT header missing alg' };
  if (a === 'none') return { severity: 'high', msg: 'JWT uses alg=none (unsigned token)' };
  if (a.startsWith('hs')) return { severity: 'medium', msg: `JWT uses ${alg} (symmetric signing)` };
  return null;
}

function confidenceRank(level) {
  if (level === 'high') return 3;
  if (level === 'medium') return 2;
  return 1;
}

function inferConfidence(finding) {
  if (finding.confidence) return finding.confidence;
  const detail = finding.detail || {};
  let base = finding.severity === 'high' ? 3 : finding.severity === 'medium' ? 2 : 1;

  // Lower confidence for broad regex-only hints.
  if (finding.category === 'storage' && !detail.value) base -= 1;
  if (finding.category === 'postMessage' && !detail.sourceSnippet && !detail.sinkSnippet) base -= 1;

  // Raise confidence for corroborating evidence.
  if (finding.category === 'domxss' && detail.sourceSnippet && detail.sinkSnippet) base += 1;
  if (finding.category === 'cors' && String(detail.acao) === '*' && /true/i.test(String(detail.acac || ''))) base += 1;
  if (finding.category === 'jwt' && (detail.type === 'localStorage' || detail.type === 'sessionStorage')) base += 1;
  if ((finding.count || 1) > 1) base += 1;

  if (base >= 3) return 'high';
  if (base === 2) return 'medium';
  return 'low';
}

function confidenceLabel(level) {
  if (level === 'high') return 'High confidence';
  if (level === 'medium') return 'Medium confidence';
  return 'Low confidence';
}

function findingSortScore(f) {
  const sev = f.severity === 'high' ? 3 : f.severity === 'medium' ? 2 : 1;
  const conf = confidenceRank(inferConfidence(f));
  return sev * 10 + conf;
}

function applySuppression(finding, type) {
  if (type === 'key') {
    const key = buildFindingKey(finding);
    if (!scannerSuppressions.keys.includes(key)) scannerSuppressions.keys.push(key);
  } else if (type === 'domain') {
    const domain = getFindingDomain(finding);
    if (!domain) return;
    if (!scannerSuppressions.domains.includes(domain)) scannerSuppressions.domains.push(domain);
  }
  saveScopeBlockLists();
  renderScannerSuppressions();
  applyScannerFilters();
  showToast('Finding suppressed.');
}

function inferWhyFlagged(finding) {
  if (finding.reason) return finding.reason;
  const reasons = {
    domxss: 'Untrusted browser-controlled input appears to flow into a dangerous DOM sink in inline scripts.',
    postMessage: 'Cross-window messaging is risky when origin checks are weak or wildcard targetOrigin is used.',
    cors: 'Broad CORS can expose API responses to untrusted origins.',
    jwt: 'JWT-like tokens in browser storage/cookies increase token theft impact in XSS scenarios.',
    headers: 'Security headers are missing, reducing browser-side protections.',
    storage: 'Sensitive data in web storage can be read by injected scripts.',
    cookies: 'Cookie flags are weak for sensitive contexts and may increase session theft risk.',
  };
  return reasons[finding.category] || 'Potential security issue based on static rule matching.';
}

function inferFixHint(finding) {
  const hints = {
    domxss: {
      text: 'Avoid dangerous DOM sinks for untrusted input; sanitize and use safe text APIs.',
      url: 'https://owasp.org/www-community/attacks/xss/',
    },
    postMessage: {
      text: 'Validate event.origin and avoid wildcard targetOrigin in postMessage.',
      url: 'https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage',
    },
    cors: {
      text: 'Restrict Access-Control-Allow-Origin to trusted origins and review credentialed CORS.',
      url: 'https://owasp.org/www-project-cheat-sheets/cheatsheets/CORS_Cheat_Sheet.html',
    },
    jwt: {
      text: 'Prefer httpOnly cookies and short-lived tokens; avoid storing JWT in web storage when possible.',
      url: 'https://owasp.org/www-project-cheat-sheets/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html',
    },
    headers: {
      text: 'Set missing browser security headers (CSP, X-Frame-Options, HSTS).',
      url: 'https://owasp.org/www-project-secure-headers/',
    },
    storage: {
      text: 'Do not persist sensitive secrets in local/session storage.',
      url: 'https://owasp.org/www-project-web-security-testing-guide/',
    },
    cookies: {
      text: 'Mark sensitive cookies as Secure and HttpOnly.',
      url: 'https://owasp.org/www-community/controls/SecureCookieAttribute',
    },
  };
  return hints[finding.category] || { text: 'Review this finding and tighten security controls where applicable.', url: '' };
}

function buildFindingKey(f) {
  if (f?.id) return String(f.id);
  return `${f.category}|${f.severity}|${f.title || f.msg}`;
}

function getFindingDomain(f) {
  return f?.detail?.domain || '';
}

function isSuppressedFinding(f) {
  const key = buildFindingKey(f);
  const domain = getFindingDomain(f);
  if (scannerSuppressions.keys.includes(key)) return true;
  if (domain && scannerSuppressions.domains.includes(domain)) return true;
  return false;
}

function renderScannerMeta() {
  const el = document.getElementById('scannerMeta');
  const m = scannerLastScanMeta;
  const last = m.lastScanAt ? new Date(m.lastScanAt).toLocaleTimeString() : '—';
  const jwtBits = [];
  if (m.jwtAlgNone > 0) jwtBits.push(`<span class="metric">JWT alg=none: ${m.jwtAlgNone}</span>`);
  if (m.jwtAlgHS > 0) jwtBits.push(`<span class="metric">JWT HS*: ${m.jwtAlgHS}</span>`);
  if (m.jwtAlgMissing > 0) jwtBits.push(`<span class="metric">JWT missing alg: ${m.jwtAlgMissing}</span>`);
  el.innerHTML = `
    <span class="metric">Raw: ${m.totalRaw}</span>
    <span class="metric">Deduped: ${m.totalDeduped}</span>
    <span class="metric">High: ${m.highCount}</span>
    <span class="metric">New: ${m.newCount}</span>
    <span class="metric">Last scan: ${escapeHtml(last)}</span>
    ${jwtBits.join('')}
  `;
}

function summarizeJwtAlgs(findings) {
  let none = 0;
  let hs = 0;
  let missing = 0;
  findings.forEach((f) => {
    if (f.category !== 'jwt') return;
    const alg = String(f?.detail?.jwtHeader?.alg || '').trim().toLowerCase();
    const n = Math.max(1, Number(f.count || 1));
    if (!alg) {
      missing += n;
      return;
    }
    if (alg === 'none') {
      none += n;
      return;
    }
    if (alg.startsWith('hs')) {
      hs += n;
    }
  });
  return { none, hs, missing };
}

function renderScannerSuppressions() {
  const el = document.getElementById('scannerSuppressions');
  const keyChips = (scannerSuppressions.keys || []).map((k) => `<span class="supp-chip">rule:${escapeHtml(k.slice(0, 36))}…<button type="button" data-remove-suppression="1" data-type="key" data-value="${escapeHtml(k)}">×</button></span>`);
  const domainChips = (scannerSuppressions.domains || []).map((d) => `<span class="supp-chip">domain:${escapeHtml(d)}<button type="button" data-remove-suppression="1" data-type="domain" data-value="${escapeHtml(d)}">×</button></span>`);
  const html = [...keyChips, ...domainChips];
  if (html.length === 0) {
    el.classList.add('hidden');
    el.innerHTML = '';
    return;
  }
  el.classList.remove('hidden');
  el.innerHTML = `<div class="supp-title">Suppressed findings (${html.length})</div><div class="supp-list">${html.join('')}</div>`;
}

function downloadText(filename, content, mime = 'text/plain') {
  const blob = new Blob([content], { type: `${mime};charset=utf-8` });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function exportScannerReport(format) {
  const findings = scannerFilteredFindingsCache.length ? scannerFilteredFindingsCache : scannerFindingsCache.filter((f) => !isSuppressedFinding(f));
  if (findings.length === 0) {
    showToast('No findings to export.');
    return;
  }
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  if (format === 'json') {
    downloadText(`scanner-report-${ts}.json`, JSON.stringify({
      generatedAt: new Date().toISOString(),
      metrics: scannerLastScanMeta,
      suppressions: scannerSuppressions,
      findings,
    }, null, 2), 'application/json');
    showToast('Scanner JSON exported.');
    return;
  }
  const rows = [['severity', 'confidence', 'category', 'message', 'count', 'domain', 'why', 'fixHint', 'docUrl']];
  findings.forEach((f) => {
    const hint = inferFixHint(f);
    rows.push([
      f.severity,
      inferConfidence(f),
      f.category,
      f.msg,
      String(f.count || 1),
      getFindingDomain(f),
      inferWhyFlagged(f),
      hint.text,
      hint.url,
    ]);
  });
  const csv = rows
    .map((r) => r.map((v) => `"${String(v || '').replace(/"/g, '""')}"`).join(','))
    .join('\n');
  downloadText(`scanner-report-${ts}.csv`, csv, 'text/csv');
  showToast('Scanner CSV exported.');
}

function findingToMarkdown(finding) {
  const f = buildFindingRecord(finding);
  const confidence = inferConfidence(finding);
  const why = inferWhyFlagged(finding);
  const hint = inferFixHint(finding);
  const domain = getFindingDomain(finding) || 'n/a';
  const lines = [
    `## ${f.title}`,
    '',
    `- Severity: ${f.severity}`,
    `- Confidence: ${confidence}`,
    `- Category: ${f.category}`,
    `- Domain: ${domain}`,
    f.affected_url ? `- URL: ${f.affected_url}` : null,
    f.evidence ? `- Evidence: ${f.evidence}` : null,
    f.count > 1 ? `- Occurrences: ${f.count}` : null,
    '',
    '### Why flagged',
    f.explanation || why,
    '',
    '### Recommended fix',
    f.mitigation || hint.text,
    hint.url ? `Reference: ${hint.url}` : null,
  ].filter(Boolean);

  if (finding.detail?.sourceSnippet || finding.detail?.sinkSnippet) {
    lines.push('', '### Snippets');
    if (finding.detail.sourceSnippet) lines.push(`- Source: \`${finding.detail.sourceSnippet}\``);
    if (finding.detail.sinkSnippet) lines.push(`- Sink: \`${finding.detail.sinkSnippet}\``);
  }
  return lines.join('\n');
}

function buildFindingRecord(input) {
  const id = input.id || `${input.category || 'misc'}-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`;
  const title = input.title || input.msg || 'Security finding';
  const confidence = input.confidence || 'medium';
  const severity = input.severity || 'low';
  const affectedUrl = input.affected_url || input.affectedUrl || input?.detail?.url || '';
  const evidence = input.evidence || input?.detail?.evidence || '';
  const explanation = input.explanation || input.reason || inferWhyFlagged(input);
  const mitigation = input.mitigation || inferFixHint(input).text;
  const reproduction = input.reproduction_steps || input.reproductionSteps || [];
  return {
    ...input,
    id,
    title,
    msg: input.msg || title,
    severity,
    confidence,
    evidence,
    reproduction_steps: Array.isArray(reproduction) ? reproduction : [String(reproduction)],
    explanation,
    mitigation,
    affected_url: affectedUrl,
    category: input.category || 'misc',
  };
}

function normalizeForDiff(value, keyHint = '') {
  const k = String(keyHint || '').toLowerCase();
  if (k.includes('time') || k.includes('date') || k.includes('nonce') || k.includes('csrf') || k.includes('token')) return '<dynamic>';
  const s = String(value || '');
  if (/\b\d{10,13}\b/.test(s)) return s.replace(/\b\d{10,13}\b/g, '<ts>');
  if (/\b[0-9a-f]{8,}\b/i.test(s)) return s.replace(/\b[0-9a-f]{8,}\b/gi, '<hex>');
  if (/\b[0-9a-f]{8}-[0-9a-f-]{27}\b/i.test(s)) return s.replace(/\b[0-9a-f]{8}-[0-9a-f-]{27}\b/gi, '<uuid>');
  return s;
}

function flattenJson(obj, prefix = '', out = {}) {
  if (!obj || typeof obj !== 'object') return out;
  Object.entries(obj).forEach(([k, v]) => {
    const path = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      flattenJson(v, path, out);
    } else if (Array.isArray(v)) {
      out[path] = `[array:${v.length}]`;
    } else {
      out[path] = normalizeForDiff(v, k);
    }
  });
  return out;
}

function shannonEntropy(text) {
  const s = String(text || '');
  if (!s) return 0;
  const freq = new Map();
  for (const ch of s) freq.set(ch, (freq.get(ch) || 0) + 1);
  let e = 0;
  freq.forEach((count) => {
    const p = count / s.length;
    e -= p * Math.log2(p);
  });
  return e;
}

function computeResponseDiff(base, current) {
  const baseBody = String(base?.body || '');
  const curBody = String(current?.body || '');
  const baseStatus = Number(base?.status || 0);
  const curStatus = Number(current?.status || 0);
  const baseLen = baseBody.length;
  const curLen = curBody.length;
  const sizeDelta = Math.abs(curLen - baseLen);

  let jsonDelta = { addedKeys: [], removedKeys: [], changedKeys: [] };
  try {
    const a = flattenJson(JSON.parse(baseBody));
    const b = flattenJson(JSON.parse(curBody));
    const aKeys = new Set(Object.keys(a));
    const bKeys = new Set(Object.keys(b));
    jsonDelta.addedKeys = [...bKeys].filter((k) => !aKeys.has(k)).slice(0, 15);
    jsonDelta.removedKeys = [...aKeys].filter((k) => !bKeys.has(k)).slice(0, 15);
    jsonDelta.changedKeys = [...aKeys].filter((k) => bKeys.has(k) && a[k] !== b[k]).slice(0, 20);
  } catch (_) {}

  const entA = shannonEntropy(baseBody.slice(0, 5000));
  const entB = shannonEntropy(curBody.slice(0, 5000));
  const entropyDelta = Math.abs(entA - entB);
  const statusChanged = baseStatus !== curStatus;
  const meaningful = statusChanged || sizeDelta > Math.max(120, baseLen * 0.12) || jsonDelta.addedKeys.length > 0 || jsonDelta.removedKeys.length > 0 || jsonDelta.changedKeys.length >= 3 || entropyDelta > 0.25;
  return {
    statusChanged,
    sizeDelta,
    jsonDelta,
    entropyDelta: Number(entropyDelta.toFixed(3)),
    meaningful,
    summary: [
      statusChanged ? `status ${baseStatus}->${curStatus}` : '',
      sizeDelta ? `lenΔ ${sizeDelta}` : '',
      jsonDelta.addedKeys.length ? `+keys ${jsonDelta.addedKeys.length}` : '',
      jsonDelta.removedKeys.length ? `-keys ${jsonDelta.removedKeys.length}` : '',
      jsonDelta.changedKeys.length ? `~keys ${jsonDelta.changedKeys.length}` : '',
      entropyDelta > 0.25 ? `entropyΔ ${entropyDelta.toFixed(2)}` : '',
    ].filter(Boolean).join(', ') || 'no significant diff',
  };
}

function getRegistrableDomain(hostname) {
  const parts = String(hostname || '').toLowerCase().split('.').filter(Boolean);
  if (parts.length <= 2) return parts.join('.');
  return parts.slice(-2).join('.');
}

function isThirdPartyDomain(targetHost, pageHost) {
  return getRegistrableDomain(targetHost) !== getRegistrableDomain(pageHost);
}

function isStaticAssetUrl(url) {
  return /\.(?:png|jpe?g|gif|webp|svg|ico|woff2?|ttf|eot|css|map|mp4|webm|avi|pdf)(?:\?|$)/i.test(String(url || ''));
}

function isNoiseDomain(host) {
  return /(google-analytics|googletagmanager|doubleclick|facebook\.net|segment\.io|hotjar|mixpanel|amplitude|clarity\.ms|ads|adservice)/i.test(String(host || ''));
}

function looksSensitiveBody(body, headers = {}) {
  const text = String(body || '').slice(0, 12000);
  const ct = String(headers['content-type'] || headers['Content-Type'] || '').toLowerCase();
  const pii = /\b(email|phone|ssn|dob|address|customer|account|iban|card|token|access_token|refresh_token|auth|jwt)\b/i.test(text);
  const jsonLike = ct.includes('json') || (/^\s*[\[{]/.test(text) && /[:"]/g.test(text));
  return jsonLike && pii;
}

async function safeReplayWithTimeout(payload, timeoutMs = 4000) {
  return Promise.race([
    replayRequestFromPanel(payload),
    new Promise((resolve) => setTimeout(() => resolve({ status: 0, body: '', headers: {}, error: 'timeout', timing: { duration: timeoutMs } }), timeoutMs)),
  ]);
}

async function probeCorsReflection(url, method, headers, body) {
  const probeA = 'https://hacktools-origin-a.invalid';
  const probeB = 'https://hacktools-origin-b.invalid';
  const hA = { ...(headers || {}), Origin: probeA };
  const hB = { ...(headers || {}), Origin: probeB };
  const [ra, rb] = await Promise.all([
    safeReplayWithTimeout({ method, url, headers: hA, body }),
    safeReplayWithTimeout({ method, url, headers: hB, body }),
  ]);
  const acaoA = String((ra?.headers || {})['access-control-allow-origin'] || '').trim();
  const acaoB = String((rb?.headers || {})['access-control-allow-origin'] || '').trim();
  const reflected = acaoA === probeA && acaoB === probeB;
  return { reflected, acaoA, acaoB, responseA: ra, responseB: rb };
}

async function detectAdvancedCorsFindings({ requests, pageHost }) {
  const findings = [];
  const candidates = requests
    .filter((r) => {
      const u = r.url || r.request?.url || '';
      if (!u || isStaticAssetUrl(u)) return false;
      const host = (() => { try { return new URL(u).hostname; } catch (_) { return ''; } })();
      if (!host) return false;
      const thirdParty = isThirdPartyDomain(host, pageHost);
      if (thirdParty && isNoiseDomain(host)) return false;
      return true;
    })
    .slice(0, 12);

  for (const r of candidates) {
    const url = r.url || r.request?.url || '';
    const host = (() => { try { return new URL(url).hostname; } catch (_) { return ''; } })();
    const headers = getResponseHeadersObject(r);
    const acao = String(headers['access-control-allow-origin'] || '').trim();
    const acac = /true/i.test(String(headers['access-control-allow-credentials'] || ''));
    if (!acao) continue;
    const thirdParty = isThirdPartyDomain(host, pageHost);
    if (thirdParty && !acac) continue;

    if (acao === '*' && acac) {
      findings.push(buildFindingRecord({
        id: `cors-star-cred-${host}`,
        title: `${host}: CORS allows credentials with wildcard origin`,
        severity: 'medium',
        confidence: 'high',
        category: 'cors',
        affected_url: url,
        evidence: `ACAO=${acao}, ACAC=true`,
        reproduction_steps: [`Request ${url}`, 'Observe response headers ACAO=* and ACAC=true'],
        explanation: 'Wildcard ACAO with credentials enables cross-origin authenticated reads in misconfigured browsers/clients.',
        mitigation: 'Set explicit trusted origin list and avoid wildcard ACAO when credentials are enabled.',
        detail: { url, domain: host, acao, acac: 'true', evidence: `ACAO:${acao}; ACAC:true` },
      }));
      continue;
    }

    // High-confidence only with reflection + credentials + sensitive response.
    if (!acac) continue;
    const reqHeaders = {};
    (r.request?.headers || []).forEach((h) => {
      if (h?.name && h?.value && isValidHeaderName(h.name)) reqHeaders[h.name] = h.value;
    });
    const probe = await probeCorsReflection(r.request?.url || url, r.method || r.request?.method || 'GET', reqHeaders, r.request?.postData?.text || '');
    const sensitive = looksSensitiveBody(probe.responseA?.body || '', probe.responseA?.headers || {}) || looksSensitiveBody(probe.responseB?.body || '', probe.responseB?.headers || {});
    if (probe.reflected && sensitive) {
      findings.push(buildFindingRecord({
        id: `cors-reflect-cred-sensitive-${host}`,
        title: `${host}: Reflected credentialed CORS with sensitive response`,
        severity: 'high',
        confidence: 'high',
        category: 'cors',
        affected_url: url,
        evidence: `ProbeA ACAO=${probe.acaoA}; ProbeB ACAO=${probe.acaoB}; ACAC=true; sensitive-content=true`,
        reproduction_steps: [
          `Send request to ${url} with Origin: https://hacktools-origin-a.invalid`,
          `Repeat with Origin: https://hacktools-origin-b.invalid`,
          'Confirm ACAO reflects both arbitrary origins and ACAC=true while sensitive content is returned',
        ],
        explanation: 'Arbitrary-origin reflection + credentials + sensitive response is directly exploitable cross-origin data exfiltration.',
        mitigation: 'Use strict allowlist for ACAO, disallow ACAC unless required, and block sensitive responses to untrusted origins.',
        detail: {
          url,
          domain: host,
          acaoProbeA: probe.acaoA,
          acaoProbeB: probe.acaoB,
          acac: 'true',
          sourceSnippet: String((probe.responseA?.body || '').slice(0, 220)),
        },
      }));
    }
  }
  return findings;
}

function decodeJwtPayloadLite(token) {
  try {
    const parts = String(token || '').split('.');
    if (parts.length < 2) return null;
    const fix = (s) => {
      let b64 = s.replace(/-/g, '+').replace(/_/g, '/');
      const pad = b64.length % 4;
      if (pad) b64 += '='.repeat(4 - pad);
      return JSON.parse(atob(b64));
    };
    return { header: fix(parts[0]), payload: fix(parts[1]) };
  } catch (_) {
    return null;
  }
}

function collectJwtCandidates({ pageData, cookies, requests }) {
  const tokenRe = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g;
  const out = [];
  Object.entries(pageData?.localStorage || {}).forEach(([k, v]) => {
    const m = String(v || '').match(tokenRe);
    if (m) m.forEach((t) => out.push({ token: t, source: `localStorage:${k}`, domain: new URL(pageData.url).hostname, publicContext: true }));
  });
  Object.entries(pageData?.sessionStorage || {}).forEach(([k, v]) => {
    const m = String(v || '').match(tokenRe);
    if (m) m.forEach((t) => out.push({ token: t, source: `sessionStorage:${k}`, domain: new URL(pageData.url).hostname, publicContext: true }));
  });
  (cookies || []).forEach((c) => {
    const m = String(c.value || '').match(tokenRe);
    if (m) m.forEach((t) => out.push({ token: t, source: `cookie:${c.name}`, domain: c.domain || '', publicContext: !c.httpOnly }));
  });
  (requests || []).slice(0, 80).forEach((r) => {
    const auth = (r.request?.headers || []).find((h) => String(h?.name || '').toLowerCase() === 'authorization')?.value || '';
    const m = String(auth).match(tokenRe);
    if (m) m.forEach((t) => out.push({ token: t, source: 'authorization-header', domain: (() => { try { return new URL(r.url).hostname; } catch (_) { return ''; } })(), publicContext: false }));
  });
  return out;
}

function analyzeJwtDeepFindings(jwtCandidates) {
  const findings = [];
  jwtCandidates.forEach((item) => {
    const decoded = decodeJwtPayloadLite(item.token);
    if (!decoded) return;
    const h = decoded.header || {};
    const p = decoded.payload || {};
    const alg = String(h.alg || '').toLowerCase();
    const now = Math.floor(Date.now() / 1000);
    const exp = Number(p.exp || 0);
    const ttlDays = exp > now ? (exp - now) / 86400 : 0;
    const sensitiveClaim = String(p.role || '').toLowerCase() === 'admin' || Array.isArray(p.permissions) || String(p.scope || '').toLowerCase().includes('admin');

    const baseDetail = {
      domain: item.domain,
      source: item.source,
      jwtHeader: h,
      jwtPayloadPreview: JSON.stringify(p).slice(0, 280),
    };
    const add = (title, severity, confidence, explanation, mitigation) => {
      findings.push(buildFindingRecord({
        id: `jwt-${severity}-${title}-${item.source}-${item.domain}`,
        title,
        severity,
        confidence,
        category: 'jwt',
        affected_url: item.domain ? `https://${item.domain}` : '',
        evidence: `${item.source}; alg=${h.alg || 'missing'}; exp=${p.exp || 'missing'}; aud=${p.aud ? 'present' : 'missing'}; iss=${p.iss ? 'present' : 'missing'}`,
        reproduction_steps: [`Extract JWT from ${item.source}`, 'Decode JWT header/payload and inspect claims'],
        explanation,
        mitigation,
        detail: baseDetail,
      }));
    };

    if (alg === 'none') {
      add(`JWT uses alg=none in ${item.source}`, 'high', 'high', 'Unsigned JWTs can be forged by attackers.', 'Reject alg=none and enforce strict signed algorithms server-side.');
    }
    if (alg.startsWith('hs') && item.publicContext) {
      add(`JWT uses symmetric alg (${h.alg}) in public context`, 'medium', 'high', 'Symmetric key material misuse risk rises when tokens are exposed to browser context.', 'Prefer asymmetric signing for externally exposed tokens and rotate secrets.');
    }
    if (!p.exp) {
      add(`JWT missing exp claim in ${item.source}`, 'medium', 'medium', 'Token without expiry increases replay window.', 'Require short-lived exp for all access tokens.');
    } else if (ttlDays > 30) {
      add(`JWT long expiration (${Math.round(ttlDays)} days)`, 'medium', 'medium', 'Overly long expiration increases token theft impact.', 'Reduce token TTL and use refresh token flow.');
    }
    if (!p.aud && !p.iss) {
      add('JWT missing aud and iss claims', 'medium', 'medium', 'Missing issuer and audience weakens contextual validation.', 'Validate both iss and aud claims on every token.');
    } else {
      if (!p.aud) add('JWT missing aud claim', 'low', 'medium', 'Audience claim is absent.', 'Set aud and enforce audience validation.');
      if (!p.iss) add('JWT missing iss claim', 'low', 'medium', 'Issuer claim is absent.', 'Set iss and enforce issuer validation.');
    }
    if (sensitiveClaim) {
      add('JWT carries high-privilege claims', 'medium', 'high', 'Admin/privileged claims are present and should be tightly validated server-side.', 'Apply server-side authorization checks independent of JWT claim trust.');
    }
    if (alg.startsWith('rs')) {
      const suspicious = !!h.jku || !!h.x5u || /\.\.|\/|\\/.test(String(h.kid || ''));
      if (suspicious) {
        add(`RS token with suspicious key reference metadata (${h.alg})`, 'medium', 'high', 'Key lookup metadata may enable key confusion/injection if unsafely handled.', 'Allowlist key sources and sanitize kid/jku/x5u handling.');
      }
    }
  });
  return findings;
}

function extractIdorCandidateFromUrl(url) {
  try {
    const u = new URL(url);
    const pathSegs = u.pathname.split('/').filter(Boolean);
    const idLike = /(id|user|account|order|profile|customer|invoice)/i;
    for (let i = 0; i < pathSegs.length; i++) {
      const seg = pathSegs[i];
      if (/^\d{1,12}$/.test(seg) && (idLike.test(pathSegs[i - 1] || '') || i >= 1)) {
        return { type: 'path-number', value: seg, segmentIndex: i };
      }
      if (/^[0-9a-f]{8}-[0-9a-f-]{27}$/i.test(seg)) {
        return { type: 'path-uuid', value: seg, segmentIndex: i };
      }
    }
    for (const [k, v] of u.searchParams.entries()) {
      if (idLike.test(k) && /^\d{1,12}$/.test(v)) return { type: 'query-number', key: k, value: v };
      if (idLike.test(k) && /^[0-9a-f]{8}-[0-9a-f-]{27}$/i.test(v)) return { type: 'query-uuid', key: k, value: v };
    }
  } catch (_) {}
  return null;
}

function mutateIdCandidateInUrl(url, candidate, delta) {
  try {
    const u = new URL(url);
    if (candidate.type === 'path-number') {
      const segs = u.pathname.split('/');
      const idx = candidate.segmentIndex + 1;
      const next = Math.max(1, Number(candidate.value) + delta);
      segs[idx] = String(next);
      u.pathname = segs.join('/');
      return u.toString();
    }
    if (candidate.type === 'query-number') {
      const next = Math.max(1, Number(candidate.value) + delta);
      u.searchParams.set(candidate.key, String(next));
      return u.toString();
    }
    if (candidate.type === 'path-uuid') {
      const segs = u.pathname.split('/');
      const idx = candidate.segmentIndex + 1;
      segs[idx] = candidate.value.replace(/[0-9a-f]$/i, (c) => (c.toLowerCase() === 'a' ? 'b' : 'a'));
      u.pathname = segs.join('/');
      return u.toString();
    }
    if (candidate.type === 'query-uuid') {
      u.searchParams.set(candidate.key, candidate.value.replace(/[0-9a-f]$/i, (c) => (c.toLowerCase() === 'a' ? 'b' : 'a')));
      return u.toString();
    }
  } catch (_) {}
  return url;
}

async function detectIdorFindings({ requests, pageHost }) {
  const findings = [];
  const candidates = requests
    .filter((r) => ['GET', 'PUT', 'PATCH', 'DELETE'].includes(String(r.method || r.request?.method || 'GET').toUpperCase()))
    .map((r) => ({ req: r, candidate: extractIdorCandidateFromUrl(r.url || r.request?.url || '') }))
    .filter((x) => x.candidate)
    .filter((x) => {
      const host = (() => { try { return new URL(x.req.url || x.req.request?.url || '').hostname; } catch (_) { return ''; } })();
      return host && !isThirdPartyDomain(host, pageHost);
    })
    .slice(0, 4);

  for (const item of candidates) {
    const originalUrl = item.req.url || item.req.request?.url || '';
    const method = item.req.method || item.req.request?.method || 'GET';
    const headers = {};
    (item.req.request?.headers || []).forEach((h) => {
      if (h?.name && h?.value && isValidHeaderName(h.name)) headers[h.name] = h.value;
    });
    const base = await safeReplayWithTimeout({ method, url: originalUrl, headers, body: item.req.request?.postData?.text || '' }, 5000);
    if (Number(base.status) !== 200) continue;
    const delta = item.candidate.type.includes('number') ? 1 : 0;
    const mutatedUrl = mutateIdCandidateInUrl(originalUrl, item.candidate, delta || 1);
    if (mutatedUrl === originalUrl) continue;
    const changed = await safeReplayWithTimeout({ method, url: mutatedUrl, headers, body: item.req.request?.postData?.text || '' }, 5000);
    const diff = computeResponseDiff(base, changed);
    const authError = /(unauthori[sz]ed|forbidden|access denied|not allowed|permission)/i.test(String(changed.body || ''));
    if (Number(changed.status) === 200 && diff.meaningful && !authError) {
      const confidence = diff.jsonDelta.changedKeys.length > 2 || diff.jsonDelta.addedKeys.length > 0 ? 'high' : 'medium';
      findings.push(buildFindingRecord({
        id: `idor-${originalUrl}-${mutatedUrl}`,
        title: 'Potential IDOR: object reference modification changes response',
        severity: confidence === 'high' ? 'high' : 'medium',
        confidence,
        category: 'idor',
        affected_url: originalUrl,
        evidence: `baseStatus=${base.status}, mutatedStatus=${changed.status}, diff=${diff.summary}`,
        reproduction_steps: [
          `Baseline: ${originalUrl}`,
          `Modified object reference: ${mutatedUrl}`,
          'Compare responses and confirm authorization checks are not enforced',
        ],
        explanation: 'Object reference changed and server returned 200 with materially different response without auth error.',
        mitigation: 'Enforce object-level authorization (ownership/ACL) on every object access.',
        detail: {
          domain: (() => { try { return new URL(originalUrl).hostname; } catch (_) { return ''; } })(),
          originalUrl,
          mutatedUrl,
          diffSummary: diff.summary,
          sourceSnippet: String(base.body || '').slice(0, 220),
          sinkSnippet: String(changed.body || '').slice(0, 220),
        },
      }));
    }
  }
  return findings;
}

function mutateQueryParamForSqli(url, key, payload) {
  try {
    const u = new URL(url);
    u.searchParams.set(key, `${u.searchParams.get(key) || ''}${payload}`);
    return u.toString();
  } catch (_) {
    return url;
  }
}

async function detectSqliFindings({ requests, pageHost }) {
  const findings = [];
  const sqlErrors = [
    /sql syntax.*mysql/i,
    /warning.*mysql/i,
    /unclosed quotation mark.*sql server/i,
    /quoted string not properly terminated/i,
    /pg_query\(\)/i,
    /postgresql.*error/i,
    /sqlite.*error/i,
    /ora-\d{4,5}/i,
    /you have an error in your sql syntax/i,
  ];
  const paramHint = /(id|user|account|order|profile|search|q|filter|name|email)/i;

  const candidates = requests
    .filter((r) => {
      const url = r.url || r.request?.url || '';
      if (!url || isStaticAssetUrl(url)) return false;
      let u;
      try { u = new URL(url); } catch (_) { return false; }
      if (isThirdPartyDomain(u.hostname, pageHost) || isNoiseDomain(u.hostname)) return false;
      const keys = [...u.searchParams.keys()];
      return keys.length > 0 && keys.some((k) => paramHint.test(k));
    })
    .slice(0, 3);

  for (const r of candidates) {
    const originalUrl = r.url || r.request?.url || '';
    const u = new URL(originalUrl);
    const targetKey = [...u.searchParams.keys()].find((k) => paramHint.test(k));
    if (!targetKey) continue;

    const reqHeaders = {};
    (r.request?.headers || []).forEach((h) => {
      if (h?.name && h?.value && isValidHeaderName(h.name)) reqHeaders[h.name] = h.value;
    });
    const method = String(r.method || r.request?.method || 'GET').toUpperCase();
    const body = r.request?.postData?.text || '';

    const baseline = await safeReplayWithTimeout({ method, url: originalUrl, headers: reqHeaders, body }, 2500);
    const p1Url = mutateQueryParamForSqli(originalUrl, targetKey, `'`);
    const p2Url = mutateQueryParamForSqli(originalUrl, targetKey, `")`);
    const [p1, p2] = await Promise.all([
      safeReplayWithTimeout({ method, url: p1Url, headers: reqHeaders, body }, 2500),
      safeReplayWithTimeout({ method, url: p2Url, headers: reqHeaders, body }, 2500),
    ]);

    const bText = String(baseline.body || '');
    const p1Text = String(p1.body || '');
    const p2Text = String(p2.body || '');
    const bHas = sqlErrors.some((re) => re.test(bText));
    const p1Has = sqlErrors.some((re) => re.test(p1Text));
    const p2Has = sqlErrors.some((re) => re.test(p2Text));
    const errorTriggered = !bHas && (p1Has || p2Has);
    const statusShift = Number(baseline.status) < 500 && (Number(p1.status) >= 500 || Number(p2.status) >= 500);
    const diff1 = computeResponseDiff(baseline, p1);
    const diff2 = computeResponseDiff(baseline, p2);
    const meaningful = diff1.meaningful || diff2.meaningful;

    // Multi-signal: require SQL error trigger + status/diff corroboration.
    if (errorTriggered && (statusShift || meaningful)) {
      const matchedSnippet = (p1Has ? p1Text : p2Text).slice(0, 220);
      findings.push(buildFindingRecord({
        id: `sqli-${originalUrl}-${targetKey}`,
        title: `Potential SQL Injection at parameter "${targetKey}"`,
        severity: statusShift ? 'high' : 'medium',
        confidence: statusShift ? 'high' : 'medium',
        category: 'sqli',
        affected_url: originalUrl,
        evidence: `baseline=${baseline.status}, payload1=${p1.status}, payload2=${p2.status}, sql-error=true`,
        reproduction_steps: [
          `Baseline request: ${originalUrl}`,
          `Inject ${targetKey} with single quote payload`,
          'Observe SQL error signature and response behavior change',
        ],
        explanation: 'Input with SQL-control characters triggers database error patterns with corroborating response changes.',
        mitigation: 'Use parameterized queries/prepared statements and strict server-side input validation.',
        detail: {
          domain: u.hostname,
          url: originalUrl,
          param: targetKey,
          sourceSnippet: matchedSnippet,
          sinkSnippet: `${diff1.summary}; ${diff2.summary}`,
        },
      }));
    }
  }
  return findings;
}

function getSecretSignatures() {
  const all = [
    { id: 'aws-access-key', label: 'AWS Access Key', category: 'cloud', regex: /\b(AKIA[0-9A-Z]{16})\b/g, base: 3 },
    { id: 'aws-sts-key', label: 'AWS STS Key', category: 'cloud', regex: /\b(ASIA[0-9A-Z]{16})\b/g, base: 3 },
    { id: 'aws-mws-key', label: 'AWS MWS Key', category: 'cloud', regex: /\b(amzn\.mws\.[0-9a-f-]{36})\b/g, base: 3 },
    { id: 'google-api-key', label: 'Google API Key', category: 'cloud', regex: /\b(AIza[0-9A-Za-z\-_]{35})\b/g, base: 3 },
    { id: 'google-oauth-secret', label: 'Google OAuth Secret', category: 'cloud', regex: /google.*client.*secret\s*[:=]\s*["']([A-Za-z0-9\-_]{20,})["']/gi, base: 2 },
    { id: 'firebase-token', label: 'Firebase Token', category: 'cloud', regex: /\b(AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{120,})\b/g, base: 2 },
    { id: 'firebase-web-key', label: 'Firebase Web API Key', category: 'cloud', regex: /firebase.*apiKey\s*[:=]\s*["']([A-Za-z0-9\-_]{20,})["']/gi, base: 2 },
    { id: 'azure-storage-key', label: 'Azure Storage Account Key', category: 'cloud', regex: /AccountKey=([A-Za-z0-9+/=]{40,})/g, base: 3 },
    { id: 'gcp-service-account', label: 'GCP Service Account Email', category: 'cloud', regex: /\b([a-z0-9-]{3,}@[a-z0-9-]{3,}\.iam\.gserviceaccount\.com)\b/gi, base: 2 },
    { id: 'stripe-secret', label: 'Stripe Secret Key', category: 'payment', regex: /\b(sk_(live|test)_[0-9a-zA-Z]{16,64})\b/g, base: 3 },
    { id: 'stripe-restricted', label: 'Stripe Restricted Key', category: 'payment', regex: /\b(rk_(live|test)_[0-9a-zA-Z]{16,64})\b/g, base: 3 },
    { id: 'square-token', label: 'Square Token', category: 'payment', regex: /\b(sq0atp-[0-9A-Za-z\-_]{22,})\b/g, base: 3 },
    { id: 'paypal-braintree-token', label: 'PayPal/Braintree Token', category: 'payment', regex: /\b(access_token\$production\$[0-9a-z]{16}\$[0-9a-z]{32})\b/gi, base: 3 },
    { id: 'mailchimp-key', label: 'Mailchimp API Key', category: 'payment', regex: /\b([0-9a-f]{32}-us[0-9]{1,2})\b/gi, base: 3 },
    { id: 'slack-token', label: 'Slack Token', category: 'communication', regex: /\b(xox[baprs]-[0-9A-Za-z-]{10,120})\b/g, base: 3 },
    { id: 'slack-webhook', label: 'Slack Webhook URL', category: 'communication', regex: /\b(https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/_-]{20,})\b/g, base: 3 },
    { id: 'telegram-bot-token', label: 'Telegram Bot Token', category: 'communication', regex: /\b([0-9]{8,10}:[A-Za-z0-9_-]{35})\b/g, base: 3 },
    { id: 'twilio-key', label: 'Twilio API Key', category: 'communication', regex: /\b(SK[0-9a-fA-F]{32})\b/g, base: 3 },
    { id: 'twilio-account-sid', label: 'Twilio Account SID', category: 'communication', regex: /\b(AC[0-9a-fA-F]{32})\b/g, base: 2 },
    { id: 'discord-bot-token', label: 'Discord Bot Token', category: 'communication', regex: /\b([A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27})\b/g, base: 3 },
    { id: 'github-pat', label: 'GitHub PAT', category: 'development', regex: /\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{70,})\b/g, base: 3 },
    { id: 'gitlab-pat', label: 'GitLab PAT', category: 'development', regex: /\b(glpat-[A-Za-z0-9\-_]{20,})\b/g, base: 3 },
    { id: 'heroku-api-key', label: 'Heroku API Key', category: 'development', regex: /\b(hrku_[0-9a-zA-Z]{32})\b/g, base: 3 },
    { id: 'atlassian-token', label: 'Atlassian API Token', category: 'development', regex: /\b(ATATT3xFf[A-Za-z0-9_-]{20,})\b/g, base: 3 },
    { id: 'sendgrid-key', label: 'SendGrid API Key', category: 'development', regex: /\b(SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,})\b/g, base: 3 },
    { id: 'npm-token', label: 'NPM Token', category: 'development', regex: /\b(npm_[A-Za-z0-9]{36})\b/g, base: 3 },
    { id: 'digitalocean-token', label: 'DigitalOcean Token', category: 'development', regex: /\b(dop_v1_[A-Za-z0-9]{40,})\b/g, base: 3 },
    { id: 'shopify-access-token', label: 'Shopify Access Token', category: 'development', regex: /\b(shpat_[A-Za-z0-9]{20,})\b/g, base: 3 },
    { id: 'openai-key', label: 'OpenAI API Key', category: 'development', regex: /\b(sk-(?:proj-|live-)?[A-Za-z0-9]{20,})\b/g, base: 3 },
    { id: 'anthropic-key', label: 'Anthropic API Key', category: 'development', regex: /\b(sk-ant-[A-Za-z0-9\-_]{20,})\b/g, base: 3 },
    { id: 'jwt-token', label: 'JWT Token', category: 'auth', regex: /\b(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b/g, base: 2 },
    { id: 'bearer-token', label: 'Bearer Token', category: 'auth', regex: /\b(Bearer\s+[A-Za-z0-9\-._~+/]+=*)\b/g, base: 2 },
    { id: 'oauth-access-token', label: 'OAuth Access Token', category: 'auth', regex: /\b(ya29\.[A-Za-z0-9\-_]+)\b/g, base: 3 },
    { id: 'oauth-client-secret', label: 'OAuth Client Secret', category: 'auth', regex: /client_secret\s*[:=]\s*["']([A-Za-z0-9\-_]{16,})["']/gi, base: 2 },
    { id: 'basic-auth-credential', label: 'Basic Auth Credential', category: 'auth', regex: /\b(Authorization:\s*Basic\s+[A-Za-z0-9+/=]{12,})\b/gi, base: 2 },
    { id: 'mongodb-uri', label: 'MongoDB URI', category: 'database', regex: /\b(mongodb(?:\+srv)?:\/\/[^\s"'`]{8,})\b/g, base: 2 },
    { id: 'postgres-uri', label: 'PostgreSQL URI', category: 'database', regex: /\b(postgres(?:ql)?:\/\/[^\s"'`]{8,})\b/g, base: 2 },
    { id: 'redis-uri', label: 'Redis URI', category: 'database', regex: /\b(redis:\/\/[^\s"'`]{8,})\b/g, base: 2 },
    { id: 'mysql-uri', label: 'MySQL URI', category: 'database', regex: /\b(mysql:\/\/[^\s"'`]{8,})\b/g, base: 2 },
    { id: 'mssql-uri', label: 'MSSQL URI', category: 'database', regex: /\b(sqlserver:\/\/[^\s"'`]{8,})\b/g, base: 2 },
    { id: 'db-password-assignment', label: 'Database Password Assignment', category: 'database', regex: /(?:db|database|mongo|postgres|redis|mysql).{0,24}password\s*[:=]\s*["']([^"'\s]{8,})["']/gi, base: 2 },
    { id: 'private-key', label: 'Private Key Block', category: 'auth', regex: /(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)/g, base: 3 },
    { id: 'public-key-block', label: 'Public Key Block', category: 'auth', regex: /(-----BEGIN PUBLIC KEY-----)/g, base: 1 },
    { id: 'pem-certificate', label: 'PEM Certificate Block', category: 'auth', regex: /(-----BEGIN CERTIFICATE-----)/g, base: 1 },
  ];
  return all;
}

function getSecretSignaturesForPack(pack) {
  const all = getSecretSignatures();
  const mode = ['core', 'extended', 'aggressive'].includes(pack) ? pack : 'extended';
  if (mode === 'extended') return all;

  const coreRuleIds = new Set([
    'aws-access-key',
    'aws-sts-key',
    'google-api-key',
    'stripe-secret',
    'slack-token',
    'slack-webhook',
    'github-pat',
    'gitlab-pat',
    'sendgrid-key',
    'openai-key',
    'anthropic-key',
    'jwt-token',
    'bearer-token',
    'oauth-access-token',
    'mongodb-uri',
    'postgres-uri',
    'redis-uri',
    'mysql-uri',
    'private-key',
  ]);
  if (mode === 'core') return all.filter((sig) => coreRuleIds.has(sig.id));

  return all.map((sig) => {
    if (sig.id === 'db-password-assignment' || sig.id === 'basic-auth-credential' || sig.id === 'public-key-block' || sig.id === 'pem-certificate') {
      return { ...sig, base: (sig.base || 1) - 1 };
    }
    return sig;
  });
}

function simpleStringHash(str) {
  let h = 2166136261;
  const s = String(str || '');
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h += (h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24);
  }
  return (h >>> 0).toString(16);
}

function maskSecretValue(value) {
  const v = String(value || '');
  if (v.length <= 12) return `${v.slice(0, 2)}***${v.slice(-2)}`;
  return `${v.slice(0, 4)}***${v.slice(-4)}`;
}

function isLikelyFalsePositiveSecret(value, signatureId) {
  const v = String(value || '').trim();
  const l = v.toLowerCase();
  if (!v) return true;
  if (/(example|sample|dummy|test|fake|placeholder|changeme|your_?key|xxxx)/i.test(l)) return true;
  if (signatureId !== 'jwt-token' && /^[a-f0-9]{32,64}$/i.test(v)) return true;
  if (/^[0-9a-f]{8}-[0-9a-f-]{27}$/i.test(v)) return true;
  return false;
}

function shannonEntropyLite(text) {
  const s = String(text || '');
  if (!s) return 0;
  const f = new Map();
  for (const c of s) f.set(c, (f.get(c) || 0) + 1);
  let e = 0;
  f.forEach((n) => {
    const p = n / s.length;
    e -= p * Math.log2(p);
  });
  return e;
}

function scoreSecretConfidence(signature, value, context) {
  let score = signature.base || 2;
  const entropy = shannonEntropyLite(value);
  if (String(value || '').length >= 20 && entropy >= 3.4) score += 1;
  if (/(api[_-]?key|secret|token|authorization|bearer|password|private[_-]?key)/i.test(context)) score += 1;
  if (/(example|dummy|sample|test|mock|placeholder)/i.test(context)) score -= 2;
  if (signature.validationBonus) score += signature.validationBonus;
  if (score >= 5) return 'high';
  if (score >= 3) return 'medium';
  return 'low';
}

function rulePrefilterMatch(sig, bodyLower) {
  const byCategory = {
    cloud: ['aws', 'gcp', 'google', 'firebase', 'azure', 'key', 'token', 'secret'],
    payment: ['stripe', 'square', 'paypal', 'braintree', 'token', 'secret', 'payment'],
    communication: ['slack', 'telegram', 'twilio', 'discord', 'webhook', 'token'],
    development: ['github', 'gitlab', 'heroku', 'atlassian', 'sendgrid', 'npm', 'shopify', 'openai', 'anthropic', 'key', 'token'],
    auth: ['auth', 'authorization', 'bearer', 'jwt', 'oauth', 'private key', 'token', 'secret'],
    database: ['db', 'database', 'mongo', 'postgres', 'mysql', 'redis', 'password', 'uri', 'connection'],
  };
  const hints = sig.hints || byCategory[sig.category] || [];
  if (hints.length === 0) return true;
  return hints.some((h) => bodyLower.includes(h));
}

function validateSecretLocally(sig, raw, snippet) {
  const value = String(raw || '');
  const ctx = String(snippet || '');
  const low = value.toLowerCase();

  // This is local structural validation only (no outbound credential checks).
  if (sig.id === 'jwt-token') {
    const dec = decodeJwtPayloadLite(value);
    if (!dec || !dec.header || !dec.payload) return { ok: false, bonus: 0, note: 'JWT decode failed' };
    return { ok: true, bonus: 1, note: 'JWT structure decoded locally' };
  }
  if (sig.id === 'bearer-token') {
    const tokenPart = value.replace(/^Bearer\s+/i, '');
    if (tokenPart.length < 20) return { ok: false, bonus: 0, note: 'Bearer token too short' };
    return { ok: true, bonus: 1, note: 'Bearer format and length validated' };
  }
  if (sig.id === 'aws-access-key' || sig.id === 'aws-sts-key') {
    if (/AKIAIOSFODNN7EXAMPLE/i.test(value)) return { ok: false, bonus: 0, note: 'Known example credential' };
    if (!/(aws|amazon|access[_-]?key|secret)/i.test(ctx)) return { ok: false, bonus: 0, note: 'Missing AWS context' };
    return { ok: true, bonus: 1, note: 'AWS key format + context validated' };
  }
  if (sig.id === 'google-api-key') {
    if (!/^AIza[0-9A-Za-z\-_]{35}$/.test(value)) return { ok: false, bonus: 0, note: 'Google key format mismatch' };
    return { ok: true, bonus: 1, note: 'Google API key format validated' };
  }
  if (sig.id === 'github-pat') {
    if (!/^(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{70,})$/.test(value)) return { ok: false, bonus: 0, note: 'GitHub PAT format mismatch' };
    return { ok: true, bonus: 1, note: 'GitHub token format validated' };
  }
  if (sig.id === 'gitlab-pat') {
    if (!/^glpat-[A-Za-z0-9\-_]{20,}$/.test(value)) return { ok: false, bonus: 0, note: 'GitLab PAT format mismatch' };
    return { ok: true, bonus: 1, note: 'GitLab token format validated' };
  }
  if (sig.id === 'slack-token') {
    if (!/^xox[baprs]-[0-9A-Za-z-]{10,120}$/.test(value)) return { ok: false, bonus: 0, note: 'Slack token format mismatch' };
    return { ok: true, bonus: 1, note: 'Slack token format validated' };
  }
  if (sig.id === 'stripe-secret' || sig.id === 'stripe-restricted') {
    if (!/^(sk|rk)_(live|test)_[0-9a-zA-Z]{16,64}$/.test(value)) return { ok: false, bonus: 0, note: 'Stripe key format mismatch' };
    return { ok: true, bonus: 1, note: 'Stripe key format validated' };
  }
  if (sig.id === 'openai-key') {
    if (!/^sk-(?:proj-|live-)?[A-Za-z0-9]{20,}$/.test(value)) return { ok: false, bonus: 0, note: 'OpenAI key format mismatch' };
    return { ok: true, bonus: 1, note: 'OpenAI key format validated' };
  }
  if (sig.id === 'anthropic-key') {
    if (!/^sk-ant-[A-Za-z0-9\-_]{20,}$/.test(value)) return { ok: false, bonus: 0, note: 'Anthropic key format mismatch' };
    return { ok: true, bonus: 1, note: 'Anthropic key format validated' };
  }
  if (sig.id === 'twilio-account-sid') {
    if (!/^AC[0-9a-fA-F]{32}$/.test(value)) return { ok: false, bonus: 0, note: 'Twilio SID format mismatch' };
    return { ok: true, bonus: 1, note: 'Twilio SID format validated' };
  }
  if (sig.id === 'twilio-key') {
    if (!/^SK[0-9a-fA-F]{32}$/.test(value)) return { ok: false, bonus: 0, note: 'Twilio key format mismatch' };
    return { ok: true, bonus: 1, note: 'Twilio key format validated' };
  }
  if (sig.id === 'sendgrid-key') {
    if (!/^SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}$/.test(value)) return { ok: false, bonus: 0, note: 'SendGrid key format mismatch' };
    return { ok: true, bonus: 1, note: 'SendGrid key format validated' };
  }
  if (sig.id === 'private-key') {
    if (!/-----BEGIN .*PRIVATE KEY-----/i.test(value) && !/private key/i.test(ctx)) return { ok: false, bonus: 0, note: 'Private key marker incomplete' };
    return { ok: true, bonus: 1, note: 'Private key marker validated' };
  }
  if (sig.id.endsWith('-uri')) {
    try {
      const u = new URL(value);
      if (!u.protocol || !u.hostname) return { ok: false, bonus: 0, note: 'URI missing protocol/host' };
      return { ok: true, bonus: 1, note: 'Connection URI parsed locally' };
    } catch (_) {
      return { ok: false, bonus: 0, note: 'Malformed URI' };
    }
  }
  if (/(example|dummy|sample|test|placeholder)/i.test(low)) {
    return { ok: false, bonus: 0, note: 'Looks like test/placeholder value' };
  }
  return { ok: true, bonus: 0, note: 'Pattern and context validated locally' };
}

async function validateSecretRemotely(finding) {
  const token = String(finding?.rawValue || '').trim();
  if (!token) return { status: 'error', note: 'Missing raw token value' };

  try {
    if (finding.typeId === 'github-pat') {
      const res = await fetch('https://api.github.com/user', {
        method: 'GET',
        headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json' },
      });
      if (res.status === 200) return { status: 'active', note: 'GitHub user endpoint accepted token' };
      if (res.status === 401 || res.status === 403) return { status: 'inactive', note: `GitHub rejected token (${res.status})` };
      return { status: 'error', note: `GitHub validation unexpected status (${res.status})` };
    }

    if (finding.typeId === 'slack-token') {
      const res = await fetch('https://slack.com/api/auth.test', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
      const body = await res.json().catch(() => ({}));
      if (body && body.ok === true) return { status: 'active', note: 'Slack auth.test accepted token' };
      if (body && body.ok === false) return { status: 'inactive', note: `Slack rejected token (${body.error || 'invalid_auth'})` };
      return { status: 'error', note: 'Slack validation returned unknown response' };
    }

    if (finding.typeId === 'stripe-secret' || finding.typeId === 'stripe-restricted') {
      const res = await fetch('https://api.stripe.com/v1/charges?limit=1', {
        method: 'GET',
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.status === 200) return { status: 'active', note: 'Stripe API accepted key' };
      if (res.status === 401 || res.status === 403) return { status: 'inactive', note: `Stripe rejected key (${res.status})` };
      return { status: 'error', note: `Stripe validation unexpected status (${res.status})` };
    }
  } catch (err) {
    return { status: 'error', note: `Remote validation failed: ${String(err?.message || err)}` };
  }

  return { status: 'error', note: 'No remote validator for this type' };
}

function enqueueSecretScan(task) {
  if (!task?.url || !task?.body) return;
  secretScanQueue.push(task);
  if (secretQueueTimer) return;
  secretQueueTimer = setTimeout(() => {
    secretQueueTimer = null;
    processSecretQueue();
  }, 60);
}

async function processSecretQueue() {
  if (secretScanRunning) return;
  secretScanRunning = true;
  try {
    while (secretScanQueue.length > 0) {
      const sliceStart = performance.now();
      while (secretScanQueue.length > 0 && performance.now() - sliceStart < SECRET_SCAN_SLICE_MS) {
        const task = secretScanQueue.shift();
        scanSecretsInScript(task);
      }
      if (secretScanQueue.length > 0) {
        await new Promise((r) => setTimeout(r, 0));
      }
    }
    refreshSecretMeta();
    if (!document.getElementById('secretPanel').classList.contains('hidden')) {
      applySecretFilters();
    }
  } finally {
    secretScanRunning = false;
  }
}

function scanSecretsInScript(task) {
  const url = String(task.url || '');
  if (!url) return;
  const fileKind = task.fileKind || detectBuildArtifactKind(url);
  const domain = (() => {
    try { return new URL(url).hostname; } catch (_) { return ''; }
  })();
  if (!domain || isNoiseDomain(domain)) return;

  const body = String(task.body || '').slice(0, SECRET_SCAN_MAX_BYTES);
  const bodyLower = body.toLowerCase();
  const signatures = getSecretSignaturesForPack(secretRulePack);
  signatures.forEach((sig) => {
    if (!rulePrefilterMatch(sig, bodyLower)) return;
    sig.regex.lastIndex = 0;
    let m;
    let guard = 0;
    while ((m = sig.regex.exec(body)) && guard < 40) {
      guard += 1;
      const raw = String(m[1] || m[0] || '').trim();
      if (!raw || isLikelyFalsePositiveSecret(raw, sig.id)) continue;
      const idx = typeof m.index === 'number' ? m.index : 0;
      const snippet = body.slice(Math.max(0, idx - 80), Math.min(body.length, idx + raw.length + 80)).replace(/\s+/g, ' ').trim();
      const validation = validateSecretLocally(sig, raw, snippet);
      if (!validation.ok) continue;
      const confidence = scoreSecretConfidence({ ...sig, validationBonus: validation.bonus || 0 }, raw, snippet);
      const key = `${sig.id}|${url}|${simpleStringHash(raw)}`;
      if (secretFindingKeys.has(key)) continue;
      secretFindingKeys.add(key);
      secretFindingsCache.push({
        id: key,
        type: sig.label,
        typeId: sig.id,
        category: sig.category,
        domain,
        fileKind,
        filePath: url,
        confidence,
        masked: maskSecretValue(raw),
        rawValue: raw,
        localValidation: validation.note,
        remoteValidationStatus: 'not-run',
        remoteValidationNote: '',
        lastValidatedAt: null,
        evidence: snippet,
        why: `Pattern matched ${sig.label} in ${fileKind} asset; ${validation.note}.`,
        detectedAt: Date.now(),
      });
    }
  });
}

function refreshSecretMeta() {
  secretFindingsCache.sort((a, b) => b.detectedAt - a.detectedAt);
  const rulePackSize = getSecretSignaturesForPack(secretRulePack).length;
  secretScanMeta.total = secretFindingsCache.length;
  secretScanMeta.high = secretFindingsCache.filter((f) => f.confidence === 'high').length;
  secretScanMeta.medium = secretFindingsCache.filter((f) => f.confidence === 'medium').length;
  secretScanMeta.low = secretFindingsCache.filter((f) => f.confidence === 'low').length;
  secretScanMeta.validatedActive = secretFindingsCache.filter((f) => f.remoteValidationStatus === 'active').length;
  secretScanMeta.validatedInactive = secretFindingsCache.filter((f) => f.remoteValidationStatus === 'inactive').length;
  secretScanMeta.validatedError = secretFindingsCache.filter((f) => f.remoteValidationStatus === 'error').length;
  secretScanMeta.lastScanAt = Date.now();
  const metaEl = document.getElementById('secretMeta');
  if (metaEl) {
    const runtimeHits = secretFindingsCache.filter((f) => f.fileKind === 'runtime').length;
    const buildHits = secretFindingsCache.filter((f) => f.fileKind === 'build-artifact' || f.fileKind === 'code-split' || f.fileKind === 'vendor').length;
    const apiJsonHits = secretFindingsCache.filter((f) => f.fileKind === 'api-json').length;
    const last = secretScanMeta.lastScanAt ? new Date(secretScanMeta.lastScanAt).toLocaleTimeString() : '—';
    metaEl.innerHTML = `
      <span class="metric">Secrets: ${secretScanMeta.total}</span>
      <span class="metric">High: ${secretScanMeta.high}</span>
      <span class="metric">Medium: ${secretScanMeta.medium}</span>
      <span class="metric">Low: ${secretScanMeta.low}</span>
      <span class="metric">Remote Active: ${secretScanMeta.validatedActive}</span>
      <span class="metric">Remote Inactive: ${secretScanMeta.validatedInactive}</span>
      <span class="metric">Remote Errors: ${secretScanMeta.validatedError}</span>
      <span class="metric">Validation Logs: ${secretValidationAudit.length}</span>
      <span class="metric">Rules: ${rulePackSize}</span>
      <span class="metric">Pack: ${escapeHtml(secretRulePack)}</span>
      <span class="metric">Runtime JS: ${runtimeHits}</span>
      <span class="metric">Build JS: ${buildHits}</span>
      <span class="metric">API JSON: ${apiJsonHits}</span>
      <span class="metric">Last scan: ${escapeHtml(last)}</span>
    `;
  }
}

function updateSecretFilterOptions() {
  const domainSelect = document.getElementById('secretDomainFilter');
  const typeSelect = document.getElementById('secretTypeFilter');
  if (!domainSelect || !typeSelect) return;
  const prevDomain = domainSelect.value;
  const prevType = typeSelect.value;
  const domains = [...new Set(secretFindingsCache.map((f) => f.domain).filter(Boolean))].sort();
  const types = [...new Set(secretFindingsCache.map((f) => f.typeId).filter(Boolean))]
    .sort()
    .map((id) => {
      const sample = secretFindingsCache.find((f) => f.typeId === id);
      return { id, label: sample?.type || id };
    });
  domainSelect.innerHTML = `<option value="">All Domains</option>${domains.map((d) => `<option value="${escapeHtml(d)}">${escapeHtml(d)}</option>`).join('')}`;
  typeSelect.innerHTML = `<option value="">All Secret Types</option>${types.map((t) => `<option value="${escapeHtml(t.id)}">${escapeHtml(t.label)}</option>`).join('')}`;
  if (domains.includes(prevDomain)) domainSelect.value = prevDomain;
  if (types.some((t) => t.id === prevType)) typeSelect.value = prevType;
}

function applySecretFilters() {
  updateSecretFilterOptions();
  const domain = document.getElementById('secretDomainFilter')?.value || '';
  const type = document.getElementById('secretTypeFilter')?.value || '';
  const conf = document.getElementById('secretConfidenceFilter')?.value || '';
  const q = (document.getElementById('secretSearchInput')?.value || '').toLowerCase().trim();
  const rank = { high: 3, medium: 2, low: 1 };
  secretFilteredFindingsCache = secretFindingsCache
    .filter((f) => (!domain || f.domain === domain))
    .filter((f) => (!type || f.typeId === type))
    .filter((f) => (!conf || f.confidence === conf))
    .filter((f) => (!q || `${f.type} ${f.typeId} ${f.domain} ${f.fileKind} ${f.filePath} ${f.evidence}`.toLowerCase().includes(q)))
    .sort((a, b) => (rank[b.confidence] || 0) - (rank[a.confidence] || 0) || b.detectedAt - a.detectedAt);
  renderSecretResults();
}

function renderSecretResults() {
  const el = document.getElementById('secretResults');
  if (!el) return;
  const findings = secretFilteredFindingsCache;
  if (findings.length === 0) {
    el.innerHTML = '<p class="scanner-ok">No secrets detected yet. Browse pages to scan loaded JavaScript files.</p>';
    return;
  }
  const rows = findings.map((f) => `
    <tr>
      <td>${escapeHtml(f.type)}</td>
      <td><span class="tag ${escapeHtml(f.confidence)}">${escapeHtml(f.confidence)}</span></td>
      <td>${escapeHtml(f.domain)}</td>
      <td>${escapeHtml(f.fileKind)}</td>
      <td class="tech-evidence" title="${escapeHtml(f.filePath)}">${escapeHtml(f.filePath)}</td>
      <td><code>${escapeHtml(f.masked)}</code></td>
      <td><span class="tag ${escapeHtml(f.remoteValidationStatus === 'active' ? 'high' : f.remoteValidationStatus === 'inactive' ? 'medium' : 'low')}">${escapeHtml(f.remoteValidationStatus || 'not-run')}</span></td>
      <td class="tech-evidence" title="${escapeHtml(f.evidence)}">${escapeHtml(f.evidence)}</td>
      <td class="tech-evidence" title="${escapeHtml(f.why)}">${escapeHtml(f.why)}</td>
    </tr>
  `).join('');
  el.innerHTML = `
    <div class="tech-table-wrap">
      <table class="tech-table">
        <thead>
          <tr>
            <th>Secret Type</th>
            <th>Confidence</th>
            <th>Domain</th>
            <th>File Kind</th>
            <th>File Path</th>
            <th>Masked Value</th>
            <th>Remote Validation</th>
            <th>Evidence Snippet</th>
            <th>Why</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  `;
}

function secretFindingsToMarkdown() {
  const findings = secretFilteredFindingsCache.length ? secretFilteredFindingsCache : secretFindingsCache;
  const lines = [
    '# HackTools++ Secret Scanner Report',
    `Generated: ${new Date().toISOString()}`,
    `Findings: ${findings.length}`,
    '',
  ];
  findings.forEach((f) => {
    lines.push(`- [${f.confidence.toUpperCase()}] ${f.type} @ ${f.domain}`);
    lines.push(`  - File kind: ${f.fileKind}`);
    lines.push(`  - File: ${f.filePath}`);
    lines.push(`  - Value: ${f.masked}`);
    lines.push(`  - Remote validation: ${f.remoteValidationStatus || 'not-run'}${f.remoteValidationNote ? ` (${f.remoteValidationNote})` : ''}`);
    lines.push(`  - Why: ${f.why}`);
    lines.push(`  - Snippet: ${f.evidence}`);
  });
  return lines.join('\n');
}

function exportSecretReport(format) {
  const findings = secretFilteredFindingsCache.length ? secretFilteredFindingsCache : secretFindingsCache;
  if (findings.length === 0) {
    showToast('No secret findings to export.');
    return;
  }
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  if (format === 'json') {
    downloadText(`secret-scanner-${ts}.json`, JSON.stringify({
      generatedAt: new Date().toISOString(),
      metrics: secretScanMeta,
      findings,
    }, null, 2), 'application/json');
    showToast('Secret JSON exported.');
    return;
  }
  const rows = [['type', 'confidence', 'domain', 'fileKind', 'filePath', 'maskedValue', 'remoteValidationStatus', 'remoteValidationNote', 'evidence', 'why']];
  findings.forEach((f) => rows.push([f.type, f.confidence, f.domain, f.fileKind, f.filePath, f.masked, f.remoteValidationStatus || 'not-run', f.remoteValidationNote || '', f.evidence, f.why]));
  const csv = rows.map((r) => r.map((v) => `"${String(v || '').replace(/"/g, '""')}"`).join(',')).join('\n');
  downloadText(`secret-scanner-${ts}.csv`, csv, 'text/csv');
  showToast('Secret CSV exported.');
}

function clearSecretFindings() {
  secretFindingsCache = [];
  secretFilteredFindingsCache = [];
  secretFindingKeys = new Set();
  secretValidationAudit = [];
  secretScanQueue = [];
  refreshSecretMeta();
  applySecretFilters();
  showToast('Secret findings cleared.');
}

async function validateVisibleSecretFindings() {
  if (!secretRemoteValidationEnabled) {
    showToast('Enable "Remote Validate (Dangerous)" first.');
    return;
  }
  const supported = new Set(['github-pat', 'slack-token', 'stripe-secret', 'stripe-restricted']);
  const targets = (secretFilteredFindingsCache.length ? secretFilteredFindingsCache : secretFindingsCache).filter((f) => supported.has(f.typeId)).slice(0, 20);
  if (targets.length === 0) {
    showToast('No visible findings support remote validation.');
    return;
  }

  const proceed = window.confirm(`Dangerous action: this sends up to ${targets.length} candidate secrets to provider APIs for verification. Continue?`);
  if (!proceed) return;

  for (let i = 0; i < targets.length; i++) {
    const finding = targets[i];
    const result = await validateSecretRemotely(finding);
    finding.remoteValidationStatus = result.status || 'error';
    finding.remoteValidationNote = result.note || '';
    finding.lastValidatedAt = Date.now();
    secretValidationAudit.push({
      findingId: finding.id,
      typeId: finding.typeId,
      domain: finding.domain,
      status: finding.remoteValidationStatus,
      note: finding.remoteValidationNote,
      at: finding.lastValidatedAt,
    });
  }

  if (secretValidationAudit.length > 200) {
    secretValidationAudit = secretValidationAudit.slice(-200);
  }

  refreshSecretMeta();
  applySecretFilters();
  showToast(`Remote validation finished for ${targets.length} finding(s).`);
}

function setupSecretScanner() {
  const domainFilter = document.getElementById('secretDomainFilter');
  const typeFilter = document.getElementById('secretTypeFilter');
  const confFilter = document.getElementById('secretConfidenceFilter');
  const search = document.getElementById('secretSearchInput');
  const apiToggle = document.getElementById('secretApiJsonToggle');
  const rulePackSelect = document.getElementById('secretRulePackSelect');
  const remoteToggle = document.getElementById('secretRemoteValidationToggle');
  domainFilter?.addEventListener('change', applySecretFilters);
  typeFilter?.addEventListener('change', applySecretFilters);
  confFilter?.addEventListener('change', applySecretFilters);
  search?.addEventListener('input', applySecretFilters);
  if (apiToggle) {
    apiToggle.checked = secretScanApiJsonEnabled;
    apiToggle.addEventListener('change', (e) => {
      secretScanApiJsonEnabled = !!e.target.checked;
      saveScopeBlockLists();
      showToast(`API JSON secret scan ${secretScanApiJsonEnabled ? 'enabled' : 'disabled'}`);
    });
  }
  if (rulePackSelect) {
    rulePackSelect.value = secretRulePack;
    rulePackSelect.addEventListener('change', (e) => {
      secretRulePack = ['core', 'extended', 'aggressive'].includes(e.target.value) ? e.target.value : 'extended';
      saveScopeBlockLists();
      refreshSecretMeta();
      showToast(`Secret rule pack: ${secretRulePack}`);
    });
  }
  if (remoteToggle) {
    remoteToggle.checked = secretRemoteValidationEnabled;
    remoteToggle.addEventListener('change', (e) => {
      const next = !!e.target.checked;
      if (next) {
        const ok = window.confirm('Dangerous mode: remote validation sends detected secrets to external provider APIs. Enable only in authorized test environments.');
        if (!ok) {
          e.target.checked = false;
          return;
        }
      }
      secretRemoteValidationEnabled = next;
      saveScopeBlockLists();
      showToast(`Remote validation ${secretRemoteValidationEnabled ? 'enabled' : 'disabled'}`);
    });
  }
  document.getElementById('exportSecretJsonBtn')?.addEventListener('click', () => exportSecretReport('json'));
  document.getElementById('exportSecretCsvBtn')?.addEventListener('click', () => exportSecretReport('csv'));
  document.getElementById('copySecretMdBtn')?.addEventListener('click', () => {
    const md = secretFindingsToMarkdown();
    copyToClipboard(md).then(() => showToast('Secret markdown copied')).catch(() => showCopyModal(md));
  });
  document.getElementById('validateSecretVisibleBtn')?.addEventListener('click', validateVisibleSecretFindings);
  document.getElementById('clearSecretFindingsBtn')?.addEventListener('click', clearSecretFindings);
  refreshSecretMeta();
  applySecretFilters();
}

function setupOwaspFindings() {
  const refreshBtn = document.getElementById('refreshOwaspBtn');
  if (!refreshBtn) return;
  refreshBtn.addEventListener('click', async () => {
    await runSecurityScan({ silent: true, deepOwasp: true });
    renderOwaspFindings();
    showToast('OWASP-focused scan completed.');
  });
  document.getElementById('exportOwaspJsonBtn').addEventListener('click', () => exportOwaspFindings('json'));
  document.getElementById('exportOwaspCsvBtn').addEventListener('click', () => exportOwaspFindings('csv'));
  document.getElementById('copyOwaspMdBtn').addEventListener('click', copyOwaspMarkdown);
  renderOwaspFindings();
}

function isOwaspInjectionFocusFinding(finding) {
  const f = buildFindingRecord(finding);
  const category = String(f.category || '').toLowerCase();
  const title = String(f.title || f.msg || '').toLowerCase();
  if (category === 'domxss' || category === 'idor') return true;
  if (category === 'sqli' || category === 'sql-injection') return true;
  if (category === 'jwt') return true;
  if (title.includes('sql injection') || title.includes('sqli')) return true;
  return false;
}

function mapFindingToOwasp(finding) {
  const f = buildFindingRecord(finding);
  const category = String(f.category || '').toLowerCase();
  if (category === 'idor') return { id: 'A01', name: 'Broken Access Control' };
  if (category === 'jwt') return { id: 'A07', name: 'Identification and Authentication Failures' };
  if (category === 'domxss' || category === 'sqli' || category === 'sql-injection') return { id: 'A03', name: 'Injection' };
  if (category === 'cve') return { id: 'A06', name: 'Vulnerable and Outdated Components' };
  if (category === 'cors' || category === 'headers' || category === 'postmessage') return { id: 'A05', name: 'Security Misconfiguration' };
  if (category === 'cookies' || category === 'storage') return { id: 'A02', name: 'Cryptographic Failures' };
  return { id: 'A09', name: 'Security Logging and Monitoring Failures' };
}

function buildOwaspSummary() {
  const scannerFindings = scannerFindingsCache
    .filter((f) => !isSuppressedFinding(f))
    .filter(isOwaspInjectionFocusFinding)
    .map((f) => buildFindingRecord(f));
  const all = dedupeFindings(scannerFindings).map((f) => buildFindingRecord(f));
  const grouped = {};
  all.forEach((f) => {
    const m = mapFindingToOwasp(f);
    const key = `${m.id}: ${m.name}`;
    if (!grouped[key]) grouped[key] = [];
    grouped[key].push({ ...f, owasp: m });
  });
  Object.values(grouped).forEach((arr) => arr.sort((a, b) => findingSortScore(b) - findingSortScore(a)));
  const allCount = all.length;
  const high = all.filter((f) => f.severity === 'high').length;
  const medium = all.filter((f) => f.severity === 'medium').length;
  const low = all.filter((f) => f.severity === 'low').length;
  return { generatedAt: new Date().toISOString(), allCount, high, medium, low, groups: grouped, findings: all };
}

function renderOwaspFindings() {
  const metaEl = document.getElementById('owaspMeta');
  const resultsEl = document.getElementById('owaspResults');
  if (!metaEl || !resultsEl) return;
  owaspSummaryCache = buildOwaspSummary();
  const s = owaspSummaryCache;
  metaEl.innerHTML = `
    <span class="metric">Total: ${s.allCount}</span>
    <span class="metric">High: ${s.high}</span>
    <span class="metric">Medium: ${s.medium}</span>
    <span class="metric">Low: ${s.low}</span>
    <span class="metric">Groups: ${Object.keys(s.groups).length}</span>
    <span class="metric">Updated: ${escapeHtml(new Date(s.generatedAt).toLocaleTimeString())}</span>
  `;
  if (s.allCount === 0) {
    resultsEl.innerHTML = '<p class="scanner-ok">No OWASP findings yet (XSS / SQLi / IDOR / JWT). Click Refresh to run OWASP-focused scan.</p>';
    return;
  }
  const html = Object.entries(s.groups)
    .map(([groupName, items]) => {
      const rows = items.slice(0, 40).map((f) => `
        <li class="severity-${escapeHtml(f.severity)}">
          <div class="finding-summary">
            <span class="finding-msg">${escapeHtml(f.title)}</span>
            <span class="finding-summary-right">
              <span class="confidence-badge conf-${escapeHtml(f.confidence)}">${escapeHtml(f.confidence)}</span>
            </span>
          </div>
          <div class="finding-detail expanded"><pre>Category: ${escapeHtml(f.category)}
Severity: ${escapeHtml(f.severity)}
Confidence: ${escapeHtml(f.confidence)}
Affected URL: ${escapeHtml(f.affected_url || 'n/a')}
Evidence: ${escapeHtml(f.evidence || 'n/a')}
Why: ${escapeHtml(f.explanation || inferWhyFlagged(f))}
Mitigation: ${escapeHtml(f.mitigation || inferFixHint(f).text)}</pre></div>
        </li>
      `).join('');
      return `<div class="finding-group"><h4>${escapeHtml(groupName)} (${items.length})</h4><ul>${rows}</ul></div>`;
    })
    .join('');
  resultsEl.innerHTML = html;
}

function owaspSummaryToMarkdown(summary) {
  const s = summary || owaspSummaryCache || buildOwaspSummary();
  const lines = [
    '# HackTools++ OWASP Findings',
    `Generated: ${s.generatedAt}`,
    '',
    `- Total: ${s.allCount}`,
    `- High: ${s.high}`,
    `- Medium: ${s.medium}`,
    `- Low: ${s.low}`,
    '',
  ];
  Object.entries(s.groups).forEach(([groupName, items]) => {
    lines.push(`## ${groupName}`);
    items.slice(0, 20).forEach((f) => {
      lines.push(`- [${f.severity.toUpperCase()}][${f.confidence}] ${f.title}`);
      if (f.affected_url) lines.push(`  - URL: ${f.affected_url}`);
      if (f.evidence) lines.push(`  - Evidence: ${f.evidence}`);
    });
    lines.push('');
  });
  return lines.join('\n');
}

function exportOwaspFindings(format) {
  const s = owaspSummaryCache || buildOwaspSummary();
  if (s.allCount === 0) {
    showToast('No OWASP findings to export.');
    return;
  }
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  if (format === 'json') {
    downloadText(`owasp-findings-${ts}.json`, JSON.stringify(s, null, 2), 'application/json');
    showToast('OWASP JSON exported.');
    return;
  }
  const rows = [['owasp', 'severity', 'confidence', 'category', 'title', 'affected_url', 'evidence', 'why', 'mitigation']];
  s.findings.forEach((f) => {
    const m = mapFindingToOwasp(f);
    rows.push([`${m.id}: ${m.name}`, f.severity, f.confidence, f.category, f.title, f.affected_url || '', f.evidence || '', f.explanation || '', f.mitigation || '']);
  });
  const csv = rows.map((r) => r.map((v) => `"${String(v || '').replace(/"/g, '""')}"`).join(',')).join('\n');
  downloadText(`owasp-findings-${ts}.csv`, csv, 'text/csv');
  showToast('OWASP CSV exported.');
}

function copyOwaspMarkdown() {
  const md = owaspSummaryToMarkdown(owaspSummaryCache || buildOwaspSummary());
  copyToClipboard(md).then(() => showToast('OWASP markdown copied')).catch(() => showCopyModal(md));
}

async function runSecurityScan(options = {}) {
  const { silent = false, deepOwasp = false } = options;
  if (scannerRunInProgress) {
    scannerRunQueued = true;
    return;
  }
  scannerRunInProgress = true;

  const resultsEl = document.getElementById('scannerResults');
  const scannerVisible = !document.getElementById('scannerPanel').classList.contains('hidden');
  if (!silent || scannerVisible) {
    resultsEl.innerHTML = '<p class="scanner-loading">Scanning...</p>';
  }

  const tabId = chrome.devtools.inspectedWindow.tabId;
  const findings = [];
  let scannedCookies = [];

  try {
    const pageData = await chrome.scripting.executeScript({
      target: { tabId },
      func: () => {
        const ls = {};
        for (let i = 0; i < Math.min(localStorage.length, 20); i++) {
          const k = localStorage.key(i);
          ls[k] = localStorage.getItem(k) || '';
        }
        const ss = {};
        for (let i = 0; i < Math.min(sessionStorage.length, 20); i++) {
          const k = sessionStorage.key(i);
          ss[k] = sessionStorage.getItem(k) || '';
        }
        const scripts = [...document.querySelectorAll('script:not([src])')].map((s) => s.textContent || '').filter(Boolean);
        return { url: location.href, origin: location.origin, localStorage: ls, sessionStorage: ss, inlineScripts: scripts };
      },
    });

    const data = pageData?.[0]?.result;
    if (!data) {
      if (!silent || scannerVisible) {
        resultsEl.innerHTML = '<p class="scanner-error">Cannot access page (try refreshing).</p>';
      }
      return;
    }

    const pageHost = new URL(data.url).hostname;
    const sensitiveKeys = /token|auth|secret|password|key|credential|session|jwt/i;
    const jwtLike = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/;

    Object.entries(data.localStorage || {}).forEach(([k, v]) => {
      if (sensitiveKeys.test(k)) {
        findings.push({
          severity: 'medium',
          category: 'storage',
          msg: `localStorage["${k}"] on ${pageHost}`,
          detail: { type: 'localStorage', key: k, value: v, domain: pageHost },
        });
      }
      if (jwtLike.test(String(v || ''))) {
        const token = String(v || '').match(jwtLike)?.[0] || '';
        const header = decodeJwtHeaderLite(token);
        findings.push({
          severity: 'high',
          category: 'jwt',
          msg: `Potential JWT token stored in localStorage key "${k}" on ${pageHost}`,
          detail: { type: 'localStorage', key: k, value: v, domain: pageHost, jwtHeader: header },
        });
        const risk = jwtAlgRisk(header?.alg);
        if (risk) {
          findings.push({
            severity: risk.severity,
            category: 'jwt',
            msg: `${risk.msg} in localStorage key "${k}" on ${pageHost}`,
            detail: { type: 'localStorage', key: k, value: v, domain: pageHost, jwtHeader: header },
          });
        }
      }
    });
    Object.entries(data.sessionStorage || {}).forEach(([k, v]) => {
      if (sensitiveKeys.test(k)) {
        findings.push({
          severity: 'medium',
          category: 'storage',
          msg: `sessionStorage["${k}"] on ${pageHost}`,
          detail: { type: 'sessionStorage', key: k, value: v, domain: pageHost },
        });
      }
      if (jwtLike.test(String(v || ''))) {
        const token = String(v || '').match(jwtLike)?.[0] || '';
        const header = decodeJwtHeaderLite(token);
        findings.push({
          severity: 'high',
          category: 'jwt',
          msg: `Potential JWT token stored in sessionStorage key "${k}" on ${pageHost}`,
          detail: { type: 'sessionStorage', key: k, value: v, domain: pageHost, jwtHeader: header },
        });
        const risk = jwtAlgRisk(header?.alg);
        if (risk) {
          findings.push({
            severity: risk.severity,
            category: 'jwt',
            msg: `${risk.msg} in sessionStorage key "${k}" on ${pageHost}`,
            detail: { type: 'sessionStorage', key: k, value: v, domain: pageHost, jwtHeader: header },
          });
        }
      }
    });

    const allScripts = (data.inlineScripts || []).join('\n');
    if (/addEventListener\s*\(\s*['"]message['"]|onmessage\s*=|\.on\s*\(\s*['"]message['"]/i.test(allScripts)) {
      const hasOrigin = /\.origin\s*===|event\.origin|e\.origin|origin\s*!==|\.startsWith\s*\(\s*['"]https?:/i.test(allScripts);
      if (!hasOrigin) {
        const listenerRegex = /addEventListener\s*\(\s*['"]message['"][\s\S]{0,220}\)|onmessage\s*=|\.on\s*\(\s*['"]message['"]/i;
        findings.push({
          severity: 'high',
          confidence: 'medium',
          category: 'postMessage',
          msg: 'postMessage listener may lack origin validation',
          reason: 'Listener found but explicit event.origin validation pattern was not detected.',
          detail: {
            type: 'script',
            sourceSnippet: extractMatchedSnippet(allScripts, listenerRegex),
          },
        });
      }
    }
    if (/\.postMessage\s*\([^)]*,\s*['"]\*['"]\s*\)/i.test(allScripts)) {
      findings.push({
        severity: 'high',
        confidence: 'high',
        category: 'postMessage',
        msg: 'postMessage uses wildcard targetOrigin (*)',
        reason: 'Using "*" sends messages to any origin and can leak sensitive data.',
        detail: {
          type: 'script',
          hint: 'Use explicit trusted origin instead of "*".',
          sinkSnippet: extractMatchedSnippet(allScripts, /\.postMessage\s*\([^)]*,\s*['"]\*['"]\s*\)/i),
        },
      });
    }

    const domXssSource = /(location\.(hash|search|href)|document\.(URL|location|cookie|referrer)|window\.name|localStorage|sessionStorage)/i;
    const domXssSink = /(innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|Function\(|setTimeout\(\s*['"`]|setInterval\(\s*['"`])/i;
    if (domXssSource.test(allScripts) && domXssSink.test(allScripts)) {
      findings.push({
        severity: 'high',
        confidence: 'medium',
        category: 'domxss',
        msg: 'Potential DOM XSS pattern detected (source + sink in inline scripts)',
        reason: 'A likely untrusted source and a dangerous DOM sink were both detected in inline script code.',
        detail: {
          type: 'script',
          hint: 'Sanitize untrusted input and avoid dangerous DOM sinks.',
          sourceSnippet: extractMatchedSnippet(allScripts, domXssSource),
          sinkSnippet: extractMatchedSnippet(allScripts, domXssSink),
        },
      });
    }

    try {
      const cookies = await chrome.cookies.getAll({ url: data.url });
      scannedCookies = cookies || [];
      cookies.forEach((c) => {
        const issues = [];
        if (!c.secure && data.url.startsWith('https')) issues.push('missing Secure');
        if (!c.httpOnly && sensitiveKeys.test(c.name)) issues.push('sensitive cookie not httpOnly');
        const sameSite = String(c.sameSite || '').toLowerCase();
        if (sameSite === 'no_restriction' && !c.secure) issues.push('SameSite=None without Secure');
        if (sensitiveKeys.test(c.name) && (sameSite === 'unspecified' || !sameSite)) issues.push('sensitive cookie missing SameSite');
        if (sensitiveKeys.test(c.name) && sameSite === 'no_restriction') issues.push('sensitive cookie uses SameSite=None');
        if (issues.length) {
          const domain = c.domain || pageHost;
          findings.push({
            severity: issues.some((x) => x.includes('SameSite=None without Secure')) ? 'high' : 'low',
            category: 'cookies',
            msg: `Cookie "${c.name}" on ${domain}: ${issues.join(', ')}`,
            detail: { name: c.name, domain, path: c.path, secure: c.secure, httpOnly: c.httpOnly, sameSite: c.sameSite || 'unspecified', value: (c.value || '').slice(0, 100) },
          });
        }
        if (jwtLike.test(String(c.value || ''))) {
          const token = String(c.value || '').match(jwtLike)?.[0] || '';
          const header = decodeJwtHeaderLite(token);
          findings.push({
            severity: c.httpOnly ? 'medium' : 'high',
            category: 'jwt',
            msg: `Potential JWT token in cookie "${c.name}" on ${c.domain || pageHost}`,
            detail: { name: c.name, domain: c.domain || pageHost, path: c.path, secure: c.secure, httpOnly: c.httpOnly, sameSite: c.sameSite || 'unspecified', value: (c.value || '').slice(0, 120), jwtHeader: header },
          });
          const risk = jwtAlgRisk(header?.alg);
          if (risk) {
            findings.push({
              severity: risk.severity,
              category: 'jwt',
              msg: `${risk.msg} in cookie "${c.name}" on ${c.domain || pageHost}`,
              detail: { name: c.name, domain: c.domain || pageHost, path: c.path, secure: c.secure, httpOnly: c.httpOnly, sameSite: c.sameSite || 'unspecified', value: (c.value || '').slice(0, 120), jwtHeader: header },
            });
          }
        }
      });
    } catch (_) {}

    const seen = new Set();
    capturedRequests.slice(0, 10).forEach((r) => {
      const url = r.url || r.request?.url;
      if (!url || seen.has(url)) return;
      seen.add(url);
      const domain = (() => { try { return new URL(url).hostname; } catch (_) { return url.slice(0, 40); } })();
      const resp = r.response || {};
      const headers = (resp.headers || []).reduce((a, h) => { a[h.name?.toLowerCase()] = h.value; return a; }, {});
      if (!headers['content-security-policy']) {
        findings.push({
          severity: 'low',
          category: 'headers',
          msg: `${domain}: No CSP header`,
          detail: { url, domain, missing: 'Content-Security-Policy' },
        });
      }
      if (!headers['x-frame-options'] && !headers['content-security-policy']) {
        findings.push({
          severity: 'low',
          category: 'headers',
          msg: `${domain}: No X-Frame-Options`,
          detail: { url, domain, missing: 'X-Frame-Options' },
        });
      }
      if (String(url).startsWith('https://') && !headers['strict-transport-security']) {
        findings.push({
          severity: 'medium',
          category: 'headers',
          msg: `${domain}: Missing HSTS header`,
          detail: { url, domain, missing: 'Strict-Transport-Security' },
        });
      }
      // Advanced CORS module handles CORS findings with active verification and multi-signal validation.
    });

    const recentRequests = capturedRequests.slice(0, 40);
    const advancedCorsFindings = await detectAdvancedCorsFindings({
      requests: recentRequests,
      pageHost,
    });
    findings.push(...advancedCorsFindings);

    const jwtCandidates = collectJwtCandidates({
      pageData: data,
      cookies: scannedCookies,
      requests: recentRequests,
    });
    const advancedJwtFindings = analyzeJwtDeepFindings(jwtCandidates);
    findings.push(...advancedJwtFindings);

    const idorFindings = await detectIdorFindings({
      requests: recentRequests,
      pageHost,
    });
    findings.push(...idorFindings);

    if (deepOwasp) {
      const sqliFindings = await detectSqliFindings({
        requests: recentRequests,
        pageHost,
      });
      findings.push(...sqliFindings);
    }

    const filteredFindings = findings.filter((f) => {
      // Drop legacy generic JWT presence signals; keep only deep analyzer output.
      if (f.category === 'jwt' && !f.title) return false;
      // Keep CORS only from advanced module (they always include structured title).
      if (f.category === 'cors' && !f.title) return false;
      return true;
    });

    scannerLastScanMeta.totalRaw = filteredFindings.length;
    scannerFindingsCache = dedupeFindings(filteredFindings);
    const currentKeys = new Set(scannerFindingsCache.map(buildFindingKey));
    scannerFindingsCache = scannerFindingsCache.map((f) => ({
      ...f,
      isNew: !scannerPreviousFindingKeys.has(buildFindingKey(f)),
    }));
    scannerPreviousFindingKeys = currentKeys;
    scannerLastScanMeta.totalDeduped = scannerFindingsCache.length;
    scannerLastScanMeta.highCount = scannerFindingsCache.filter((f) => f.severity === 'high').length;
    scannerLastScanMeta.newCount = scannerFindingsCache.filter((f) => f.isNew).length;
    scannerLastScanMeta.lastScanAt = Date.now();
    const jwtSummary = summarizeJwtAlgs(scannerFindingsCache);
    scannerLastScanMeta.jwtAlgNone = jwtSummary.none;
    scannerLastScanMeta.jwtAlgHS = jwtSummary.hs;
    scannerLastScanMeta.jwtAlgMissing = jwtSummary.missing;
    renderScannerMeta();
    renderScannerSuppressions();
    if (scannerVisible) applyScannerFilters();
    renderOwaspFindings();
  } catch (err) {
    if (!silent || scannerVisible) {
      resultsEl.innerHTML = `<p class="scanner-error">${escapeHtml(err.message)}</p>`;
    }
  } finally {
    scannerRunInProgress = false;
    if (scannerRunQueued) {
      scannerRunQueued = false;
      runSecurityScan({ silent: true });
    }
  }
}

function dedupeFindings(findings) {
  const map = new Map();
  findings.forEach((f) => {
    const normalized = buildFindingRecord(f);
    const key = `${normalized.category}|${normalized.severity}|${normalized.title}`;
    if (!map.has(key)) {
      map.set(key, {
        ...normalized,
        confidence: normalized.confidence || inferConfidence(normalized),
        reason: normalized.explanation || inferWhyFlagged(normalized),
        count: 1,
      });
    } else {
      const existing = map.get(key);
      existing.count += 1;
      if (confidenceRank(inferConfidence(normalized)) > confidenceRank(existing.confidence)) {
        existing.confidence = inferConfidence(normalized);
      }
    }
  });
  return [...map.values()];
}

function applyScannerFilters() {
  const severity = document.getElementById('scannerSeverityFilter').value;
  const query = (document.getElementById('scannerSearchInput').value || '').toLowerCase().trim();
  const filtered = scannerFindingsCache.filter((f) => {
    if (isSuppressedFinding(f)) return false;
    if (severity && f.severity !== severity) return false;
    if (!query) return true;
    const blob = `${f.category} ${f.title || f.msg} ${f.evidence || ''} ${inferWhyFlagged(f)} ${JSON.stringify(f.detail || {})}`.toLowerCase();
    return blob.includes(query);
  });
  filtered.sort((a, b) => findingSortScore(b) - findingSortScore(a));
  scannerFilteredFindingsCache = filtered;
  renderScannerFindings(filtered);
}

function renderScannerFindings(findings) {
  const resultsEl = document.getElementById('scannerResults');
  if (findings.length === 0) {
    resultsEl.innerHTML = '<p class="scanner-ok">No issues found for current filter.</p>';
    return;
  }

  const byCat = {};
  const findingIndexMap = new Map();
  findings.forEach((f, i) => findingIndexMap.set(f, i));
  findings.forEach((f) => {
    if (!byCat[f.category]) byCat[f.category] = [];
    byCat[f.category].push(f);
  });

  const html = Object.entries(byCat)
    .map(([cat, items]) => {
      const list = items
        .map((f, idx) => {
          const id = `finding-${cat}-${idx}`;
          const findingIdx = findingIndexMap.get(f);
          const hasDetail = f.detail != null;
          let detailHtml = '';
          if (hasDetail && f.detail) {
            const d = f.detail;
            if (d.type === 'localStorage' || d.type === 'sessionStorage') {
              const value = String(d.value || '');
              detailHtml = `<pre>Key: ${escapeHtml(d.key)}\nDomain: ${escapeHtml(d.domain)}\nValue: ${escapeHtml(value.slice(0, 500))}${value.length > 500 ? '...' : ''}${d.jwtHeader ? `\nJWT header: ${escapeHtml(JSON.stringify(d.jwtHeader))}` : ''}</pre>`;
            } else if (d.name) {
              detailHtml = `<pre>Name: ${escapeHtml(d.name)}\nDomain: ${escapeHtml(d.domain)}\nPath: ${escapeHtml(d.path || '')}\nSecure: ${d.secure}\nHttpOnly: ${d.httpOnly}\nSameSite: ${escapeHtml(String(d.sameSite || 'unspecified'))}\nValue: ${escapeHtml(String(d.value || '').slice(0, 200))}${d.jwtHeader ? `\nJWT header: ${escapeHtml(JSON.stringify(d.jwtHeader))}` : ''}</pre>`;
            } else if (d.url) {
              detailHtml = `<pre>URL: ${escapeHtml(d.url)}\nMissing: ${escapeHtml(d.missing || '')}\n${d.acao ? `ACAO: ${escapeHtml(String(d.acao))}\n` : ''}${d.acac ? `ACAC: ${escapeHtml(String(d.acac))}` : ''}</pre>`;
            } else if (d.hint) {
              detailHtml = `<pre>${escapeHtml(d.hint)}</pre>`;
            }
            if (d.sourceSnippet || d.sinkSnippet) {
              detailHtml += `<pre>${d.sourceSnippet ? `Source snippet: ${escapeHtml(d.sourceSnippet)}\n` : ''}${d.sinkSnippet ? `Sink snippet: ${escapeHtml(d.sinkSnippet)}` : ''}</pre>`;
            }
          }
          const confidence = inferConfidence(f);
          const confClass = confidence === 'high' ? 'conf-high' : confidence === 'medium' ? 'conf-medium' : 'conf-low';
          const whyId = `${id}-why`;
          const whyText = inferWhyFlagged(f);
          const hint = inferFixHint(f);
          const domain = getFindingDomain(f);

          return `
          <li class="finding severity-${f.severity} ${hasDetail ? 'expandable' : ''}" data-id="${id}">
            <div class="finding-summary">
              <span class="finding-msg">${escapeHtml(f.title || f.msg)}${f.count > 1 ? ` (${f.count}x)` : ''}</span>
              <span class="finding-summary-right">
                ${f.isNew ? '<span class="new-badge">new</span>' : ''}
                <span class="confidence-badge ${confClass}" title="${escapeHtml(confidenceLabel(confidence))}">${escapeHtml(confidence)}</span>
                <button type="button" class="why-btn" data-why-target="${whyId}">Why?</button>
                <button type="button" class="suppress-btn" data-copy-finding="1" data-finding-idx="${findingIdx}" data-finding-key="${escapeHtml(buildFindingKey(f))}" data-finding-domain="${escapeHtml(domain)}">Copy</button>
                <button type="button" class="suppress-btn" data-suppress-type="key" data-finding-idx="${findingIdx}" data-finding-key="${escapeHtml(buildFindingKey(f))}" data-finding-domain="${escapeHtml(domain)}">Ignore Rule</button>
                ${domain ? `<button type="button" class="suppress-btn" data-suppress-type="domain" data-finding-idx="${findingIdx}" data-finding-key="${escapeHtml(buildFindingKey(f))}" data-finding-domain="${escapeHtml(domain)}">Ignore Domain</button>` : ''}
                ${hasDetail ? '<span class="expand-icon">▼</span>' : ''}
              </span>
            </div>
            <div class="finding-why" id="${whyId}">
              ${escapeHtml(whyText)}<br><br>
              <strong>Fix:</strong> ${escapeHtml(hint.text)}
              ${hint.url ? `<br><a href="${escapeHtml(hint.url)}" target="_blank" rel="noopener noreferrer">Reference</a>` : ''}
            </div>
            ${hasDetail ? `<div class="finding-detail" id="${id}">${detailHtml}</div>` : ''}
          </li>`;
        })
        .join('');
      return `<div class="finding-group"><h4>${escapeHtml(cat)}</h4><ul>${list}</ul></div>`;
    })
    .join('');
  resultsEl.innerHTML = html;

  resultsEl.querySelectorAll('.finding.expandable').forEach((el) => {
    el.addEventListener('click', () => {
      const detail = el.querySelector('.finding-detail');
      const icon = el.querySelector('.expand-icon');
      if (detail && icon) {
        detail.classList.toggle('expanded');
        icon.textContent = detail.classList.contains('expanded') ? '▲' : '▼';
      }
    });
  });

  resultsEl.querySelectorAll('.why-btn').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const targetId = btn.dataset.whyTarget;
      const whyEl = targetId ? document.getElementById(targetId) : null;
      if (whyEl) whyEl.classList.toggle('expanded');
    });
  });

  resultsEl.querySelectorAll('.suppress-btn').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const idxRaw = btn.dataset.findingIdx;
      const idx = typeof idxRaw === 'string' ? parseInt(idxRaw, 10) : -1;
      const indexedFinding = Number.isInteger(idx) && idx >= 0 ? findings[idx] : null;
      if (btn.dataset.copyFinding) {
        const key = btn.dataset.findingKey;
        const domain = btn.dataset.findingDomain || '';
        const finding = indexedFinding || findings.find((f) => buildFindingKey(f) === key && (!domain || getFindingDomain(f) === domain)) || findings.find((f) => buildFindingKey(f) === key);
        if (!finding) return;
        const md = findingToMarkdown(finding);
        copyToClipboard(md).then(() => showToast('Finding copied as markdown')).catch(() => showCopyModal(md));
        return;
      }
      const type = btn.dataset.suppressType;
      const key = btn.dataset.findingKey;
      const domain = btn.dataset.findingDomain || '';
      const finding = indexedFinding || findings.find((f) => buildFindingKey(f) === key && (!domain || getFindingDomain(f) === domain)) || findings.find((f) => buildFindingKey(f) === key);
      if (finding && type) applySuppression(finding, type);
    });
  });
}

/**
 * Send current request to Intruder
 */
function sendToIntruder() {
  const method = methodSelect.value;
  const url = urlInput.value?.trim();
  const headers = getHeadersFromEditor();
  const body = bodyEditor.value?.trim();

  if (!url) {
    showToast('Please enter a URL first.');
    return;
  }

  document.getElementById('intruderMethod').value = method;
  document.getElementById('intruderUrl').value = url;
  const bodyText = body || '';
  document.getElementById('intruderBody').value = bodyText;
  const intruderPrettyView = document.getElementById('intruderBodyPrettyView');
  if (intruderPrettyView && !intruderPrettyView.classList.contains('hidden')) {
    intruderPrettyView.value = formatBodyForDisplay(bodyText);
  }

  const intruderHeaders = document.getElementById('intruderHeaders');
  intruderHeaders.innerHTML = '';
  Object.entries(headers).forEach(([k, v]) => {
    if (k && v) addIntruderHeaderRow(k, v);
  });
  addIntruderHeaderRow('', '');

  switchMode('intruder');
}

function addIntruderHeaderRow(key = '', value = '') {
  const row = document.createElement('div');
  row.className = 'header-row';
  row.innerHTML = `
    <input type="text" class="key" placeholder="Header name" value="${escapeHtml(key)}">
    <input type="text" class="value" placeholder="Value" value="${escapeHtml(value)}">
  `;
  document.getElementById('intruderHeaders').appendChild(row);
}

/**
 * Get payloads from Intruder config
 */
function getIntruderPayloads() {
  const type = document.getElementById('payloadType').value;
  if (type === 'numbers') {
    let from = parseInt(document.getElementById('payloadFrom').value, 10);
    let to = parseInt(document.getElementById('payloadTo').value, 10);
    const step = Math.abs(parseInt(document.getElementById('payloadStep').value, 10) || 1);
    if (isNaN(from)) from = 0;
    if (isNaN(to)) to = 10;
    if (from > to) [from, to] = [to, from];
    const payloads = [];
    for (let i = from; i <= to; i += step) payloads.push(String(i));
    return payloads;
  }
  const text = document.getElementById('payloadList').value || '';
  return text.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
}

const PAYLOAD_MARKER_REGEX = /(§[^§]*§|\$[^$]*\$)/g;
const HAS_MARKER_REGEX = /(§[^§]*§|\$[^$]*\$)/;

/**
 * Replace §marker§ or $marker$ with payload in string
 */
function replacePayloadMarkers(str, payload) {
  if (!str) return str;
  return String(str).replace(PAYLOAD_MARKER_REGEX, payload);
}

/**
 * Setup Intruder
 */
function setupIntruder() {
  document.getElementById('addIntruderHeaderBtn').addEventListener('click', () => addIntruderHeaderRow('', ''));

  document.getElementById('payloadType').addEventListener('change', () => {
    const listSection = document.getElementById('payloadListSection');
    const numSection = document.getElementById('payloadNumbersSection');
    const isList = document.getElementById('payloadType').value === 'list';
    listSection.classList.toggle('hidden', !isList);
    numSection.classList.toggle('hidden', isList);
  });

  document.getElementById('startAttackBtn').addEventListener('click', runIntruderAttack);
  document.getElementById('stopAttackBtn').addEventListener('click', stopIntruderAttack);

  const resultModal = document.getElementById('intruderResultModal');
  const resultCloseBtn = document.getElementById('resultModalClose');
  if (resultCloseBtn) resultCloseBtn.addEventListener('click', () => resultModal?.classList.add('hidden'));
  if (resultModal) resultModal.addEventListener('click', (e) => { if (e.target === resultModal) resultModal.classList.add('hidden'); });
}

let intruderAbortController = null;

async function runIntruderAttack() {
  const payloads = getIntruderPayloads();
  if (payloads.length === 0) {
    showToast('Add at least one payload.');
    return;
  }

  const method = document.getElementById('intruderMethod').value;
  const url = document.getElementById('intruderUrl').value?.trim();
  const intruderBodyEl = document.getElementById('intruderBody');
  const intruderPrettyEl = document.getElementById('intruderBodyPrettyView');
  if (intruderPrettyEl && !intruderPrettyEl.classList.contains('hidden')) {
    intruderBodyEl.value = unformatBodyFromDisplay(intruderPrettyEl.value);
  }
  const bodyRaw = intruderBodyEl.value?.trim();

  if (!url) {
    showToast('Enter a URL.');
    return;
  }

  const headers = {};
  document.querySelectorAll('#intruderHeaders .header-row').forEach((row) => {
    const key = row.querySelector('.key')?.value?.trim();
    const val = row.querySelector('.value')?.value?.trim();
    if (key && isValidHeaderName(key)) headers[key] = val;
  });

  const hasMarker = (s) => s && HAS_MARKER_REGEX.test(String(s));
  if (!hasMarker(url) && !hasMarker(bodyRaw) && !Object.values(headers).some(hasMarker)) {
    showToast('Add §markers§ or $markers$ in URL, body, or headers.');
    return;
  }

  document.getElementById('startAttackBtn').classList.add('hidden');
  document.getElementById('stopAttackBtn').classList.remove('hidden');
  document.getElementById('intruderResultsBody').innerHTML = '';
  document.getElementById('intruderStatus').textContent = `Running 0/${payloads.length}...`;

  intruderAbortController = new AbortController();
  const results = [];
  const concurrency = Math.min(20, Math.max(1, parseInt(document.getElementById('intruderConcurrency')?.value, 10) || 5));
  const delayMs = Math.min(5000, Math.max(0, parseInt(document.getElementById('intruderDelay')?.value, 10) || 0));
  const delay = (ms) => new Promise((r) => setTimeout(r, ms));

  for (let batchStart = 0; batchStart < payloads.length; batchStart += concurrency) {
    if (intruderAbortController?.signal.aborted) break;

    const batch = payloads.slice(batchStart, batchStart + concurrency);
    const batchResults = await Promise.all(
      batch.map(async (payload, batchIdx) => {
        const i = batchStart + batchIdx;
        const reqUrl = replacePayloadMarkers(url, payload);
        const reqBody = bodyRaw ? replacePayloadMarkers(bodyRaw, payload) : null;
        const reqHeaders = { ...headers };
        Object.keys(reqHeaders).forEach((k) => {
          reqHeaders[k] = replacePayloadMarkers(reqHeaders[k], payload);
        });
        let res;
        try {
          res = await replayRequestFromPanel({ method, url: reqUrl, headers: reqHeaders, body: reqBody });
        } catch (err) {
          res = { error: err.message, status: 0, body: '', timing: { duration: 0 } };
        }
        return {
          index: i + 1,
          payload,
          status: res.status || 0,
          length: res.body ? new Blob([res.body]).size : 0,
          duration: Math.round((res.timing?.duration || 0)),
          body: res.body || res.error || '',
        };
      })
    );

    results.push(...batchResults);
    document.getElementById('intruderStatus').textContent = `Running ${Math.min(batchStart + concurrency, payloads.length)}/${payloads.length}...`;
    renderIntruderResults(results);

    if (delayMs > 0 && batchStart + concurrency < payloads.length) {
      await delay(delayMs);
    }
  }

  document.getElementById('startAttackBtn').classList.remove('hidden');
  document.getElementById('stopAttackBtn').classList.add('hidden');
  document.getElementById('intruderStatus').textContent = `Done. ${results.length} requests.`;
  intruderAbortController = null;
}

function stopIntruderAttack() {
  if (intruderAbortController) {
    intruderAbortController.abort();
  }
}

let intruderResultsCache = [];

function renderIntruderResults(results) {
  intruderResultsCache = results;
  const tbody = document.getElementById('intruderResultsBody');
  const baseline = results[0];
  tbody.innerHTML = results
    .map(
      (r) => {
        const diff = baseline ? computeResponseDiff(baseline, r) : { summary: 'n/a', meaningful: false };
        return `
    <tr class="result-row" data-index="${r.index}">
      <td>${r.index}</td>
      <td class="payload-cell">${escapeHtml(r.payload)}</td>
      <td class="status-cell status-${r.status >= 500 ? '5xx' : r.status >= 400 ? '4xx' : r.status >= 300 ? '3xx' : '2xx'}">${r.status}</td>
      <td>${r.length}</td>
      <td>${r.duration}</td>
      <td class="response-preview">${escapeHtml(diff.summary)}</td>
      <td class="response-preview">${escapeHtml(String(r.body).slice(0, 100))}${r.body.length > 100 ? '...' : ''}</td>
    </tr>
  `;
      }
    )
    .join('');

  tbody.querySelectorAll('.result-row').forEach((row) => {
    row.addEventListener('click', () => {
      const idx = parseInt(row.dataset.index, 10);
      const r = intruderResultsCache.find((x) => x.index === idx);
      if (r) showIntruderResultModal(r);
    });
  });
}

function showIntruderResultModal(r) {
  document.getElementById('resultModalIndex').textContent = r.index;
  document.getElementById('resultModalStatus').textContent = `Status: ${r.status}`;
  document.getElementById('resultModalLength').textContent = `Length: ${r.length}`;
  document.getElementById('resultModalTime').textContent = r.duration;
  const bodyEl = document.getElementById('resultModalBody');
  try {
    const parsed = JSON.parse(r.body);
    bodyEl.textContent = JSON.stringify(parsed, null, 2);
  } catch (_) {
    bodyEl.textContent = r.body;
  }
  document.getElementById('intruderResultModal').classList.remove('hidden');
}


function escapeHtml(str) {
  if (!str) return '';
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}
