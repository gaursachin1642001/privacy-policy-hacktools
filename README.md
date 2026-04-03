# HackTools++

A lightweight security testing toolkit inside Chrome DevTools, including Repeater, Intruder, Decoder, Scanner, Tech Detector, and OWASP Finding.

## Features

- **DevTools Panel**: Custom "HackTools++" tab in Chrome DevTools
- **Request Capture**: Captures all HTTP/HTTPS requests from the active tab
- **Request List**: Method, URL, status code, and time with search and filters
- **Request Editor**: Edit method, URL, headers, and body before replaying
- **Response Viewer**: Pretty (JSON), Raw, Headers, and Timing tabs
- **AI Assist**: Mock endpoint analysis and security test suggestions
- **Intruder**: Fuzzing/brute-force attacks with payload positions (§marker§) and payload lists
- **Decoder**: Encode/decode Base64, URL, Hex, HTML entities, and JWT
- **Tech Detector**: Passive technology + version detection with local CVE mapping
- **OWASP Finding**: OWASP-focused findings view for XSS, SQLi, IDOR, and JWT
- **AI Secret Scanner**: Real-time local scanning of runtime/build JavaScript files (chunks, lazy modules, bundled assets) and optional API JSON responses for leaked secrets
- **No Proxy**: Requests replayed via fetch from the extension — no certificates or proxy setup

## How to Load the Extension

1. Open Chrome and go to `chrome://extensions/`
2. Enable **Developer mode** (toggle in the top-right)
3. Click **Load unpacked**
4. Select the `extension` folder inside this project
5. Open any webpage and open DevTools (F12 or Cmd+Option+I)
6. Click the **HackTools++** tab in DevTools

## Usage

1. **Capture**: With the HackTools++ panel open, navigate or refresh a page. Requests will appear in the left sidebar.
2. **Select**: Click a request to load it into the editor.
3. **Edit**: Change the method, URL, headers, or body as needed.
4. **Send**: Click **Send** to replay the request and view the response.
5. **Intruder**: Click **Send to Intruder** to switch to Intruder mode. Add §payload§ markers in URL, headers, or body. Define payloads (list or number range) and click **Start Attack**.
6. **Decoder**: Switch to the Decoder tab. Select format (Base64, URL, Hex, HTML, JWT), paste text, and click Decode or Encode.
7. **Scanner**: Switch to Scanner and run quick client-side checks for storage, cookies, headers, and postMessage patterns.
8. **Tech Detector**: Detect stack/versions and enrich CVE mappings locally.
9. **OWASP Finding**: View OWASP-focused findings (XSS, SQLi, IDOR, JWT) with export options.
10. **Secret Scanner**: Browse target pages to auto-scan loaded runtime/build JS files for high-signal secrets.

## Project Structure

```
extension/
├── manifest.json      # Extension manifest (Manifest V3)
├── devtools.html      # DevTools entry point
├── devtools.js        # Creates the HackTools++ panel
├── panel.html         # Panel UI
├── panel.js           # Main logic (capture, edit, replay)
└── styles.css         # Dark theme styling
```

## Permissions

- `storage` — Save/load requests
- `scripting` — Runtime page checks for scanner/tech modules
- `cookies` — Cookie security checks and request replay behavior
- `host_permissions: <all_urls>` — Replay requests to any URL

## Publishing

See [PUBLISHING.md](PUBLISHING.md) for step-by-step instructions to publish on the Chrome Web Store.

## Intruder

- **Payload positions**: Use `§payload§` or `$payload$` in URL, headers, or body to mark injection points
- **Payload types**: Simple list (one per line) or number range (from, to, step)
- **Results**: Table with status, length, timing; click a row to view full response
