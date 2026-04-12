# Copilot Workspace Instructions

- HYPER IMPORTANT: Always prioritize fixes through the repository and CI/CD pipeline. Treat production application code and deploy configuration as read-only by default.
- HYPER IMPORTANT: Never modify application code directly on production. Any code change must go through the repository and CI/CD pipeline first.
- HYPER IMPORTANT: If an incident requires a temporary production-only operational change, backport the equivalent fix to the repository and to the CI/CD source of truth in the same task so the next deployment preserves it.
- Production server access is available over SSH at `109.199.125.137` using the preconfigured local SSH key.
- For remote execution from this Windows workspace, do not inline complex remote shell commands directly in PowerShell when avoidable.
- Prefer this workflow for production changes or diagnostics:
  1. Create the shell script locally in the workspace.
  2. Copy it to the server with `scp`.
  3. Execute it remotely over `ssh`.
- Reason: PowerShell escaping is error-prone for nested remote shell commands and scripts are more reliable, auditable, and repeatable.
- When mentioning or using production access, assume the server is sensitive and avoid destructive commands unless explicitly requested.