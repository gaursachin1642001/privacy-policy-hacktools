/**
 * HackTools++ UAT DevTools Bootstrap
 * Creates the custom "HackTools++ UAT" tab in Chrome DevTools
 * TODO(prod): Rename "HackTools++ UAT" back to "HackTools++" before production publish.
 */
// Keep UAT suffix during testing builds. Remove " UAT" for production.
chrome.devtools.panels.create(
  'HackTools++ UAT',
  '',
  'panel.html',
  (panel) => {
    panel.onShown.addListener((window) => {
      // Panel is shown - can trigger refresh if needed
    });
  }
);
