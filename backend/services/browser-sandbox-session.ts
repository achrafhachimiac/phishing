import { exec } from 'node:child_process';
import fs from 'node:fs/promises';
import { promisify } from 'node:util';

import type { BrowserSandboxAccess, BrowserSandboxSession } from '../../shared/analysis-types.js';
import type { BrowserSandboxProviderConfig } from './browser-sandbox-provider.js';
import { buildBrowserSandboxAccess } from './browser-sandbox-provider.js';
import { resolveBrowserSandboxRuntime } from './browser-sandbox-runtime.js';
import { getStoragePaths } from '../storage.js';

const execAsync = promisify(exec);

export type BrowserSandboxSessionContext = {
  jobId: string;
  url: string;
};

export type RunBrowserSandboxCommand = (command: string) => Promise<void>;

export async function startBrowserSandboxSession(
  config: BrowserSandboxProviderConfig & {
    startCommandTemplate: string | null;
    stopCommandTemplate: string | null;
  },
  context: BrowserSandboxSessionContext,
  runCommand: RunBrowserSandboxCommand = runBrowserSandboxCommand,
): Promise<BrowserSandboxSession> {
  const runtime = resolveBrowserSandboxRuntime(context.jobId, getStoragePaths().sandboxSessions);
  await fs.mkdir(runtime.sessionDirectory, { recursive: true });

  const access = buildBrowserSandboxAccess(config, {
    jobId: context.jobId,
    displayNumber: runtime.displayNumber,
    vncPort: runtime.vncPort,
    novncPort: runtime.novncPort,
  });
  const session: BrowserSandboxSession = {
    provider: config.provider,
    sessionId: context.jobId,
    status: access.mode === 'none' ? 'unavailable' : 'ready',
    startedAt: new Date().toISOString(),
    stoppedAt: null,
    runtime,
    access,
  };

  if (config.startCommandTemplate) {
    await runCommand(interpolateCommandTemplate(config.startCommandTemplate, context, access));
  }

  return session;
}

export async function stopBrowserSandboxSession(
  config: BrowserSandboxProviderConfig & {
    startCommandTemplate: string | null;
    stopCommandTemplate: string | null;
  },
  session: BrowserSandboxSession,
  context: BrowserSandboxSessionContext,
  runCommand: RunBrowserSandboxCommand = runBrowserSandboxCommand,
): Promise<BrowserSandboxSession> {
  if (config.stopCommandTemplate) {
    await runCommand(interpolateCommandTemplate(config.stopCommandTemplate, context, session.access));
  }

  return {
    ...session,
    status: session.status === 'unavailable' ? 'unavailable' : 'stopped',
    stoppedAt: new Date().toISOString(),
  };
}

async function runBrowserSandboxCommand(command: string) {
  await execAsync(command);
}

function interpolateCommandTemplate(
  template: string,
  context: BrowserSandboxSessionContext,
  access: BrowserSandboxAccess,
) {
  const runtime = resolveBrowserSandboxRuntime(context.jobId, getStoragePaths().sandboxSessions);

  return template
    .replaceAll(':jobId', context.jobId)
    .replaceAll(':url', shellEscape(context.url))
    .replaceAll(':accessUrl', shellEscape(access.url ?? ''))
    .replaceAll(':displayNumber', String(runtime.displayNumber))
    .replaceAll(':vncPort', String(runtime.vncPort))
    .replaceAll(':novncPort', String(runtime.novncPort))
    .replaceAll(':sessionDir', shellEscape(runtime.sessionDirectory));
}

function shellEscape(value: string) {
  return `"${value.replace(/"/g, '\\"')}"`;
}