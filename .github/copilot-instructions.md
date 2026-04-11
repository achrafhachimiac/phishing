# Copilot Workspace Instructions

- Production server access is available over SSH at `109.199.125.137` using the preconfigured local SSH key.
- For remote execution from this Windows workspace, do not inline complex remote shell commands directly in PowerShell when avoidable.
- Prefer this workflow for production changes or diagnostics:
  1. Create the shell script locally in the workspace.
  2. Copy it to the server with `scp`.
  3. Execute it remotely over `ssh`.
- Reason: PowerShell escaping is error-prone for nested remote shell commands and scripts are more reliable, auditable, and repeatable.
- When mentioning or using production access, assume the server is sensitive and avoid destructive commands unless explicitly requested.