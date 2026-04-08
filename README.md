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
   Do not commit real API keys into the repository.
3. Start or restart the backend after editing `.env.local`, otherwise new keys will not be visible to the API process.
4. Run the app:
   `npm run dev`

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

Important: the SSH key already installed on your workstation is not available to GitHub Actions. Create a dedicated deploy keypair for CI, add the public key to `~/.ssh/authorized_keys` on the server, and store the private key in `SSH_PRIVATE_KEY`.
