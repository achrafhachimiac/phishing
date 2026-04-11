<div align="center">
<img width="1200" height="475" alt="GHBanner" src="https://github.com/user-attachments/assets/0aa67016-6eaf-458a-adb2-6e31a0763ed6" />
</div>

# Run and deploy your AI Studio app

This contains everything you need to run your app locally.

View your app in AI Studio: https://ai.studio/apps/87485238-a188-4a21-b9e7-8d703c9b9f9d

## Run Locally

**Prerequisites:**  Node.js


1. Install dependencies:
   `npm install`
2. Set the environment variables you actually want to use in `.env.local`.
   `GEMINI_API_KEY` is optional for the current backend-driven analysis flow.
   Threat-intelligence free tiers are optional too: `VIRUSTOTAL_API_KEY`, `URLSCAN_API_KEY`, `ABUSEIPDB_API_KEY`, `URLHAUS_AUTH_KEY`.
   Local static-file scanners are optional too: `FILE_ANALYSIS_YARA_COMMAND`, `FILE_ANALYSIS_CLAMAV_COMMAND`.
   Browser sandbox provider settings are optional and let the UI expose a live Chromium session when you have Xvfb/noVNC or a similar gateway available: `BROWSER_SANDBOX_PROVIDER`, `BROWSER_SANDBOX_ACCESS_MODE`, `BROWSER_SANDBOX_ACCESS_BASE_URL`, `BROWSER_SANDBOX_ACCESS_URL_TEMPLATE`, `BROWSER_SANDBOX_ACCESS_PATH_TEMPLATE`, `BROWSER_SANDBOX_START_COMMAND`, `BROWSER_SANDBOX_STOP_COMMAND`.
   Do not commit real API keys into the repository.
3. Start or restart the backend after editing `.env.local`, otherwise new keys will not be visible to the API process.
4. Run the app:
   `npm run dev`

### Environment templates

- `.env.example`: base local template for development.
- `.env.production.example`: production-ready template for the self-hosted browser sandbox path.
- Real secrets stay only in `.env.local` locally and in `APP_ENV_FILE` on GitHub Actions.

### Browser sandbox provider notes

- Default behavior: the backend runs a real Chromium/Playwright evidence collection flow server-side, but returns no live access URL.
- To expose a live browser session through the same domain with noVNC, set for example:
   - `BROWSER_SANDBOX_PROVIDER=local-novnc`
   - `BROWSER_SANDBOX_ACCESS_MODE=embedded`
   - `BROWSER_SANDBOX_ACCESS_URL_TEMPLATE=https://fred.syntrix.ae/novnc/:novncPort/vnc.html?autoconnect=1&resize=remote`
   - `BROWSER_SANDBOX_START_COMMAND=bash scripts/sandbox/start-local-browser-sandbox.sh :jobId :url :displayNumber :vncPort :novncPort :sessionDir`
   - `BROWSER_SANDBOX_STOP_COMMAND=bash scripts/sandbox/stop-local-browser-sandbox.sh :jobId :sessionDir`
- With that configuration, the app returns a clickable `access.url`, can render an embedded iframe analyst console, and can start a local Xvfb + Chromium + x11vnc + noVNC stack on the same Linux host.
- The runtime allocates deterministic ports and session directories from each `jobId`, so the backend and the shell scripts resolve the same display, VNC port, and noVNC port without an external provider.
- Nginx must proxy `/novnc/<port>/...` to `127.0.0.1:<port>` with websocket upgrade headers, otherwise the iframe link will exist but the live browser will not load.
- To install the local runtime during deployment, set `ENABLE_LOCAL_BROWSER_SANDBOX=1` for the deploy script. This installs `xvfb`, `x11vnc`, `novnc`, `websockify`, and the Playwright Chromium binary on the server.

### Static file analysis notes

- The backend now combines binary heuristics with specialized parsers for PDF, PE, script, and Office/ZIP containers.
- YARA and ClamAV are optional command-line integrations. They are not bundled into the Node app; you expose them through env templates:
   - `FILE_ANALYSIS_YARA_COMMAND=yara -r /opt/yara/rules/index.yar :path`
   - `FILE_ANALYSIS_CLAMAV_COMMAND=clamscan --no-summary :path`
- Supported placeholders in those commands are `:path`, `:filename`, and `:sha256`.
- If those variables are unset, the UI and API will report the scanners as `not_configured` instead of failing the whole analysis.
- Uploaded samples, sandbox screenshots, traces, and downloads are now exposed through `/storage/...`, so the UI can render clickable links and image previews for available artifacts.

## CI/CD deployment

The repository includes a GitHub Actions workflow that:

1. installs dependencies
2. runs tests and type checks
3. builds the client and backend bundles
4. deploys the built release to a Linux server over SSH when `main` is updated

The deployment job bootstraps Node.js on the target host if needed, installs production dependencies, writes a `systemd` service, and restarts the app.

### GitHub repository variables

- `SSH_HOST`: target server hostname or IP, for example `109.199.125.137`
- `SSH_USER`: SSH user used by GitHub Actions, for example `root`
- `SSH_PORT`: optional, defaults to `22`
- `APP_DIR`: optional deploy directory, for example `/opt/phishing`
- `SYSTEMD_SERVICE`: optional service name, for example `phishing`
- `APP_NAME`: optional logical application name, for example `phishing`
- `APP_PORT`: optional backend port, defaults to `4000`

### GitHub repository secrets

- `SSH_PRIVATE_KEY`: private key used by GitHub Actions to connect to the server
- `APP_ENV_FILE`: optional full contents of the production `.env` file

Recommended `APP_ENV_FILE` starting point for the current self-hosted setup:

```env
PORT=4000
VIRUSTOTAL_API_KEY=
URLSCAN_API_KEY=
ABUSEIPDB_API_KEY=
URLHAUS_AUTH_KEY=
FILE_ANALYSIS_YARA_COMMAND=yara -r /opt/yara/rules/index.yar :path
FILE_ANALYSIS_CLAMAV_COMMAND=clamscan --no-summary :path
BROWSER_SANDBOX_PROVIDER=local-novnc
BROWSER_SANDBOX_ACCESS_MODE=embedded
BROWSER_SANDBOX_ACCESS_URL_TEMPLATE=https://fred.syntrix.ae/novnc/:novncPort/vnc.html?autoconnect=1&resize=remote
BROWSER_SANDBOX_ACCESS_PATH_TEMPLATE=:jobId
BROWSER_SANDBOX_START_COMMAND=bash scripts/sandbox/start-local-browser-sandbox.sh :jobId :url :displayNumber :vncPort :novncPort :sessionDir
BROWSER_SANDBOX_STOP_COMMAND=bash scripts/sandbox/stop-local-browser-sandbox.sh :jobId :sessionDir
```

If you want evidence collection only without live noVNC access, set `BROWSER_SANDBOX_ACCESS_MODE=none` and leave the start/stop commands empty.

Important: the SSH key already installed on your workstation is not available to GitHub Actions. Create a dedicated deploy keypair for CI, add the public key to `~/.ssh/authorized_keys` on the server, and store the private key in `SSH_PRIVATE_KEY`.
