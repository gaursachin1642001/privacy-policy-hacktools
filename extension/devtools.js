/**
 * rep+ DevTools Bootstrap
 * Creates the custom "rep+" tab in Chrome DevTools
 */
chrome.devtools.panels.create(
  'HackTools+',
  '',
  'panel.html',
  (panel) => {
    panel.onShown.addListener((window) => {
      // Panel is shown - can trigger refresh if needed
    });
  }
);
