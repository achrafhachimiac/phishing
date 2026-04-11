import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { config as loadDotenv } from 'dotenv';

const currentFilePath = fileURLToPath(import.meta.url);
const currentDirPath = path.dirname(currentFilePath);
const workspaceRoot = path.resolve(currentDirPath, '..', '..');

export function loadBackendEnvironment(rootPath = workspaceRoot) {
  for (const fileName of ['.env.local', '.env']) {
    const candidatePath = path.join(rootPath, fileName);
    if (fs.existsSync(candidatePath)) {
      loadDotenv({
        path: candidatePath,
        override: false,
      });
    }
  }
}

loadBackendEnvironment();

function parseBrowserSandboxAccessMode(value: string | undefined) {
  switch (value) {
    case 'embedded':
    case 'external':
    case 'none':
      return value;
    default:
      return 'none' as const;
  }
}

export const appConfig = {
  port: Number(process.env.PORT ?? 4000),
  storageRoot: path.resolve(workspaceRoot, 'storage'),
  serviceName: 'phish-hunter-osint-api' as const,
  fileAnalysis: {
    yaraCommandTemplate: process.env.FILE_ANALYSIS_YARA_COMMAND?.trim() || null,
    clamavCommandTemplate: process.env.FILE_ANALYSIS_CLAMAV_COMMAND?.trim() || null,
  },
  browserSandbox: {
    provider: process.env.BROWSER_SANDBOX_PROVIDER ?? 'local-chromium',
    accessMode: parseBrowserSandboxAccessMode(process.env.BROWSER_SANDBOX_ACCESS_MODE),
    accessBaseUrl: process.env.BROWSER_SANDBOX_ACCESS_BASE_URL?.trim() || null,
    accessUrlTemplate: process.env.BROWSER_SANDBOX_ACCESS_URL_TEMPLATE?.trim() || null,
    accessPathTemplate: process.env.BROWSER_SANDBOX_ACCESS_PATH_TEMPLATE?.trim() || ':jobId',
    startCommandTemplate: process.env.BROWSER_SANDBOX_START_COMMAND?.trim() || null,
    stopCommandTemplate: process.env.BROWSER_SANDBOX_STOP_COMMAND?.trim() || null,
  },
};