/**
 * rep+ Content Script
 * Runs in page context - can be used for future enhancements
 * (e.g., injecting request interceptors, DOM inspection for security testing)
 *
 * Network capture is handled by chrome.devtools.network in the DevTools panel
 */

// Content script runs in isolated world - minimal footprint
// DevTools panel uses chrome.devtools.network.onRequestFinished for capture
