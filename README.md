# rep+ HTTP Repeater

A lightweight HTTP Repeater Chrome Extension that lives inside Chrome DevTools — similar to Burp Repeater but embedded in your browser.

## Features

- **DevTools Panel**: Custom "rep+" tab in Chrome DevTools
- **Request Capture**: Captures all HTTP/HTTPS requests from the active tab
- **Request List**: Method, URL, status code, and time with search and filters
- **Request Editor**: Edit method, URL, headers, and body before replaying
- **Response Viewer**: Pretty (JSON), Raw, Headers, and Timing tabs
- **AI Assist**: Mock endpoint analysis and security test suggestions
- **Intruder**: Fuzzing/brute-force attacks with payload positions (§marker§) and payload lists
- **Decoder**: Encode/decode Base64, URL, Hex, HTML entities, and JWT
- **No Proxy**: Requests replayed via fetch from the extension — no certificates or proxy setup

## How to Load the Extension

1. Open Chrome and go to `chrome://extensions/`
2. Enable **Developer mode** (toggle in the top-right)
3. Click **Load unpacked**
4. Select the `extension` folder inside this project
5. Open any webpage and open DevTools (F12 or Cmd+Option+I)
6. Click the **rep+** tab in DevTools

## Usage

1. **Capture**: With the rep+ panel open, navigate or refresh a page. Requests will appear in the left sidebar.
2. **Select**: Click a request to load it into the editor.
3. **Edit**: Change the method, URL, headers, or body as needed.
4. **Send**: Click **Send** to replay the request and view the response.
5. **Save/Load**: Use **Save Request** and **Load Request** to store and restore requests locally.
6. **Intruder**: Click **Send to Intruder** to switch to Intruder mode. Add §payload§ markers in URL, headers, or body. Define payloads (list or number range) and click **Start Attack**.
7. **Decoder**: Switch to the Decoder tab. Select format (Base64, URL, Hex, HTML, JWT), paste text, and click Decode or Encode.

## Project Structure

```
extension/
├── manifest.json      # Extension manifest (Manifest V3)
├── devtools.html      # DevTools entry point
├── devtools.js        # Creates the rep+ panel
├── panel.html         # Panel UI
├── panel.js           # Main logic (capture, edit, replay)
├── background.js      # Service worker for request replay
├── content-script.js  # Content script (minimal)
└── styles.css         # Dark theme styling
```

## Permissions

- `storage` — Save/load requests
- `activeTab` — Access active tab
- `scripting` — Script injection
- `webRequest` — Request observation
- `host_permissions: <all_urls>` — Replay requests to any URL

## Intruder

- **Payload positions**: Use `§payload§` (or `§1§`, `§2§`, etc.) in URL, headers, or body to mark injection points
- **Payload types**: Simple list (one per line) or number range (from, to, step)
- **Results**: Table with status, length, timing; click a row to view full response
