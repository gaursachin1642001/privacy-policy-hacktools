/**
 * rep+ Background Service Worker
 * Handles request replay via fetch (no proxy required)
 */

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'REPLAY_REQUEST') {
    replayRequest(message.payload)
      .then(sendResponse)
      .catch((err) => sendResponse({ error: err.message }));
    return true; // Keep channel open for async response
  }
});

/**
 * Valid HTTP header name - rejects empty or names with control chars.
 * Invalid names cause fetch "Invalid name" error in service worker.
 */
function isValidHeaderName(name) {
  if (!name || typeof name !== 'string') return false;
  const trimmed = name.trim();
  if (!trimmed) return false;
  // Reject control chars, newlines, null bytes - these cause "Invalid name"
  return !/[\x00-\x1f\x7f]/.test(trimmed);
}

/**
 * Replays an HTTP request using fetch from the extension context
 * Extension has host_permissions for <all_urls> so CORS doesn't apply
 */
async function replayRequest(payload) {
  const { method, url, headers, body } = payload;

  const fetchOptions = {
    method: method || 'GET',
    headers: {},
    redirect: 'follow',
  };

  // Add headers - filter invalid names to avoid fetch "Invalid name" error
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

  // Add body for methods that support it
  if (body && ['POST', 'PUT', 'PATCH'].includes(fetchOptions.method)) {
    fetchOptions.body = body;
  }

  // Validate URL - malformed URLs can cause fetch errors
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

  // Build response headers object
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
