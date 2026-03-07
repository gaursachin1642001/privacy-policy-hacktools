/**
 * HackTools++ UAT DevTools Bootstrap
 * Creates the custom "HackTools++ UAT" tab in Chrome DevTools
 */
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
