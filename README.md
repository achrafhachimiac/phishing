# Fred The Phisher

Fred The Phisher is a phishing investigation workbench for analysts. It combines domain reputation, raw email parsing, EML intake, file detonation prep, browser sandboxing, related-domain triage, and CASE-style evidence tracking in one interface.

## Main features

- Domain Analysis with DNS, RDAP, TLS, mail-security, reputation feeds, and OSINT links.
- Full Email Analysis for raw RFC822 content with authentication checks, extracted URLs, inconsistencies, and related-domain inventory.
- THEPHISH EML Intake workflow with attachment analysis, Barracuda URL decoding, remote file launch, and manual per-domain threat scans.
- URL Sandbox with live browser evidence, screenshots, downloads, traces, and session activity.
- Static File Analysis for uploaded files and remote files.
- File scoring with parser reports for PDF, archives, Office containers, scripts, YARA, ClamAV, Cortex, and IOC enrichment.
- CASE journal with saved sessions, export to text or JSON, reopen, delete, and analyst event references.
- Storage-backed evidence links for uploads, downloads, screenshots, traces, and generated reports.

## Local setup

Prerequisites: Node.js 20+ and npm.

1. Install dependencies.

```bash
npm install
```

2. Create `.env.local` from the available examples and set only the integrations you need.

Common optional keys:

- `VIRUSTOTAL_API_KEY`
- `URLSCAN_API_KEY`
- `ABUSEIPDB_API_KEY`
- `URLHAUS_AUTH_KEY`
- `FILE_ANALYSIS_YARA_COMMAND`
- `FILE_ANALYSIS_CLAMAV_COMMAND`
- `BROWSER_SANDBOX_PROVIDER`
- `BROWSER_SANDBOX_ACCESS_MODE`
- `BROWSER_SANDBOX_ACCESS_URL_TEMPLATE`
- `BROWSER_SANDBOX_START_COMMAND`
- `BROWSER_SANDBOX_STOP_COMMAND`

3. Start the development stack.

```bash
npm run dev
```

4. Open the local URL shown by Vite.

## Useful commands

```bash
npm run lint
npm test
npm run build
```

## Browser sandbox notes

- The application supports server-side browser execution and optional live analyst access.
- For self-hosted noVNC access, configure the browser sandbox environment variables and proxy `/novnc/<port>/...` through Nginx.
- The project already contains deployment helpers in `scripts/sandbox/` and `scripts/deploy/`.

## Deployment

The repository is designed to deploy through CI/CD.

- Pushes to `main` run lint, tests, and build.
- Production deployment is done over SSH.
- Production environment values should live in GitHub secrets, especially `APP_ENV_FILE` and `SSH_PRIVATE_KEY`.
- If you apply a temporary production hotfix, backport it to the repository and CI/CD source of truth before the next deployment.

## Project structure

- `src/`: React frontend.
- `backend/`: Express API and analysis services.
- `shared/`: shared Zod schemas and types.
- `scripts/`: deployment and sandbox helper scripts.
- `storage/`: local evidence storage.

## Current investigation workflows

- Send Barracuda-decoded targets from THEPHISH directly to Domain Analysis or URL Sandbox.
- Manually trigger related-domain threat scans inside THEPHISH to preserve free-tier API quotas.
- Launch remote file analysis from parsed URLs or directly from Static File Analysis.
- Review critical scores and states with stronger visual alerts for `CRITICAL`, `100`, `RUNNING`, and `parsing`.

## Security note

This tool is meant for authorized investigations only. Do not commit real secrets, production credentials, or private samples into the repository.
