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

function parseBooleanFlag(value: string | undefined) {
  if (!value) {
    return false;
  }

  return ['1', 'true', 'yes', 'on'].includes(value.trim().toLowerCase());
}

function parseCommaSeparatedList(value: string | undefined) {
  if (!value) {
    return [] as string[];
  }

  return value
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

function parseIntegerFlag(value: string | undefined, fallback: number) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

export function readCortexEnvironment(env: NodeJS.ProcessEnv = process.env) {
  return {
    enabled: parseBooleanFlag(env.CORTEX_ENABLED),
    baseUrl: env.CORTEX_BASE_URL?.trim() || null,
    apiKey: env.CORTEX_API_KEY?.trim() || null,
    timeoutMs: parseIntegerFlag(env.CORTEX_TIMEOUT_MS, 15000),
    analyzers: {
      eml: parseCommaSeparatedList(env.CORTEX_ANALYZERS_EML),
      url: parseCommaSeparatedList(env.CORTEX_ANALYZERS_URL),
      domain: parseCommaSeparatedList(env.CORTEX_ANALYZERS_DOMAIN),
      fileHash: parseCommaSeparatedList(env.CORTEX_ANALYZERS_FILE_HASH),
    },
  };
}

export const appConfig = {
  port: Number(process.env.PORT ?? 4000),
  storageRoot: path.resolve(workspaceRoot, 'storage'),
  serviceName: 'phish-hunter-osint-api' as const,
  cortex: readCortexEnvironment(),
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