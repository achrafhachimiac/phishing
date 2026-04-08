import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { config as loadDotenv } from 'dotenv';

const currentFilePath = fileURLToPath(import.meta.url);
const currentDirPath = path.dirname(currentFilePath);
const workspaceRoot = path.resolve(currentDirPath, '..');

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

export const appConfig = {
  port: Number(process.env.PORT ?? 4000),
  storageRoot: path.resolve(workspaceRoot, 'storage'),
  serviceName: 'phish-hunter-osint-api' as const,
};