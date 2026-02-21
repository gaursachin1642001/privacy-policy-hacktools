/**
 * rep+ Panel - Main application logic
 * Network capture, request editor, replay, response viewer
 */

// State
let capturedRequests = [];
let selectedRequest = null;
let selectedRequestIndex = -1;
let scopeDomains = [];
let blockDomains = [];

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
  renderRequestList();
});

/**
 * Check if URL should be captured based on scope and block lists
 */
function shouldCaptureRequest(url) {
  let host;
  try {
    host = new URL(url).hostname.toLowerCase();
  } catch (_) {
    return false;
  }

  // Block takes precedence
  for (const domain of blockDomains) {
    const d = domain.toLowerCase().replace(/^\./, '');
    if (host === d || host.endsWith('.' + d)) return false;
  }

  // If scope is empty, capture all (except blocked)
  if (scopeDomains.length === 0) return true;

  // Scope: only capture if host matches a scoped domain
  for (const domain of scopeDomains) {
    const d = domain.toLowerCase().replace(/^\./, '');
    if (host === d || host.endsWith('.' + d)) return true;
  }
  return false;
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
  });
}

/**
 * Load scope and block lists from storage
 */
async function loadScopeBlockLists() {
  return new Promise((resolve) => {
    chrome.storage.local.get(['scopeDomains', 'blockDomains'], (result) => {
      scopeDomains = result.scopeDomains || [];
      blockDomains = result.blockDomains || [];
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
  document.getElementById('addHeaderBtn').addEventListener('click', () => addHeaderRow('', ''));
  document.getElementById('scopeBlockToggle').addEventListener('click', toggleScopeBlock);
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

  sendBtn.disabled = true;
  sendBtn.textContent = 'Sending...';

  try {
    const response = await replayRequestFromPanel({ method, url, headers: rawHeaders, body });
    if (response.error) {
      showResponseError(response.error);
    } else {
      displayResponse(response);
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
 * Scanner - lightweight client-side security checks
 */
function setupScanner() {
  document.getElementById('runScanBtn').addEventListener('click', runSecurityScan);
}

async function runSecurityScan() {
  const resultsEl = document.getElementById('scannerResults');
  resultsEl.innerHTML = '<p class="scanner-loading">Scanning...</p>';

  const tabId = chrome.devtools.inspectedWindow.tabId;
  const findings = [];

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
      resultsEl.innerHTML = '<p class="scanner-error">Cannot access page (try refreshing).</p>';
      return;
    }

    const pageHost = new URL(data.url).hostname;
    const sensitiveKeys = /token|auth|secret|password|key|credential|session|jwt/i;

    Object.entries(data.localStorage || {}).forEach(([k, v]) => {
      if (sensitiveKeys.test(k)) {
        findings.push({
          severity: 'medium',
          category: 'storage',
          msg: `localStorage["${k}"] on ${pageHost}`,
          detail: { type: 'localStorage', key: k, value: v, domain: pageHost },
        });
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
    });

    const allScripts = (data.inlineScripts || []).join('\n');
    if (/addEventListener\s*\(\s*['"]message['"]|onmessage\s*=|\.on\s*\(\s*['"]message['"]/i.test(allScripts)) {
      const hasOrigin = /\.origin\s*===|event\.origin|e\.origin|origin\s*!==|\.startsWith\s*\(\s*['"]https?:/i.test(allScripts);
      if (!hasOrigin) {
        findings.push({ severity: 'high', category: 'postMessage', msg: 'postMessage listener may lack origin validation', detail: null });
      }
    }

    try {
      const cookies = await chrome.cookies.getAll({ url: data.url });
      cookies.forEach((c) => {
        const issues = [];
        if (!c.secure && data.url.startsWith('https')) issues.push('missing Secure');
        if (!c.httpOnly && sensitiveKeys.test(c.name)) issues.push('sensitive cookie not httpOnly');
        if (issues.length) {
          const domain = c.domain || pageHost;
          findings.push({
            severity: 'low',
            category: 'cookies',
            msg: `Cookie "${c.name}" on ${domain}: ${issues.join(', ')}`,
            detail: { name: c.name, domain, path: c.path, secure: c.secure, httpOnly: c.httpOnly, value: (c.value || '').slice(0, 100) },
          });
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
    });

    if (findings.length === 0) {
      resultsEl.innerHTML = '<p class="scanner-ok">No issues found.</p>';
      return;
    }

    const byCat = {};
    findings.forEach((f) => {
      if (!byCat[f.category]) byCat[f.category] = [];
      byCat[f.category].push(f);
    });

    const html = Object.entries(byCat).map(([cat, items]) => {
      const list = items.map((f, idx) => {
        const id = `finding-${cat}-${idx}`;
        const hasDetail = f.detail != null;
        let detailHtml = '';
        if (hasDetail && f.detail) {
          const d = f.detail;
          if (d.type === 'localStorage' || d.type === 'sessionStorage') {
            detailHtml = `<pre>Key: ${escapeHtml(d.key)}\nDomain: ${escapeHtml(d.domain)}\nValue: ${escapeHtml(String(d.value).slice(0, 500))}${d.value.length > 500 ? '...' : ''}</pre>`;
          } else if (d.name) {
            detailHtml = `<pre>Name: ${escapeHtml(d.name)}\nDomain: ${escapeHtml(d.domain)}\nPath: ${escapeHtml(d.path || '')}\nSecure: ${d.secure}\nHttpOnly: ${d.httpOnly}\nValue: ${escapeHtml(String(d.value || '').slice(0, 200))}</pre>`;
          } else if (d.url) {
            detailHtml = `<pre>URL: ${escapeHtml(d.url)}\nMissing: ${escapeHtml(d.missing || '')}</pre>`;
          }
        }
        return `
          <li class="finding severity-${f.severity} ${hasDetail ? 'expandable' : ''}" data-id="${id}">
            <div class="finding-summary">
              <span class="finding-msg">${escapeHtml(f.msg)}</span>
              ${hasDetail ? '<span class="expand-icon">▼</span>' : ''}
            </div>
            ${hasDetail ? `<div class="finding-detail" id="${id}">${detailHtml}</div>` : ''}
          </li>`;
      }).join('');
      return `<div class="finding-group"><h4>${escapeHtml(cat)}</h4><ul>${list}</ul></div>`;
    }).join('');
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
  } catch (err) {
    resultsEl.innerHTML = `<p class="scanner-error">${escapeHtml(err.message)}</p>`;
  }
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
  tbody.innerHTML = results
    .map(
      (r) => `
    <tr class="result-row" data-index="${r.index}">
      <td>${r.index}</td>
      <td class="payload-cell">${escapeHtml(r.payload)}</td>
      <td class="status-cell status-${r.status >= 500 ? '5xx' : r.status >= 400 ? '4xx' : r.status >= 300 ? '3xx' : '2xx'}">${r.status}</td>
      <td>${r.length}</td>
      <td>${r.duration}</td>
      <td class="response-preview">${escapeHtml(String(r.body).slice(0, 100))}${r.body.length > 100 ? '...' : ''}</td>
    </tr>
  `
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
