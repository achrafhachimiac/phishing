import fs from 'node:fs';
import path from 'node:path';

import type { StoragePaths } from '../shared/analysis-types.js';
import { appConfig } from './config.js';

export function getStoragePaths(): StoragePaths {
  return {
    root: appConfig.storageRoot,
    reports: path.join(appConfig.storageRoot, 'reports'),
    screenshots: path.join(appConfig.storageRoot, 'screenshots'),
    traces: path.join(appConfig.storageRoot, 'traces'),
    sandboxSessions: path.join(appConfig.storageRoot, 'sandbox-sessions'),
    downloads: path.join(appConfig.storageRoot, 'downloads'),
    uploads: path.join(appConfig.storageRoot, 'uploads'),
    fileReports: path.join(appConfig.storageRoot, 'file-reports'),
  };
}

export function ensureStorageDirectories(): StoragePaths {
  const storagePaths = getStoragePaths();

  (Object.values(storagePaths) as string[]).forEach((targetPath) => {
    fs.mkdirSync(targetPath, { recursive: true });
  });

  return storagePaths;
}