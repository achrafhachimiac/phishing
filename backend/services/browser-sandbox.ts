import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';

import { chromium } from 'playwright';

import {
  browserSandboxJobSchema,
  type BrowserSandboxArtifact,
  type BrowserSandboxJob,
  type BrowserSandboxResult,
  type ObservedDownload,
  type BrowserSandboxSession,
} from '../../shared/analysis-types.js';
import { appConfig } from '../config.js';
import { getStoragePaths } from '../storage.js';
import { buildBrowserSandboxAccess } from './browser-sandbox-provider.js';
import { startBrowserSandboxSession, stopBrowserSandboxSession } from './browser-sandbox-session.js';

type AnalyzeUrlInSandbox = (
  url: string,
  context: { jobId: string; session: BrowserSandboxSession },
) => Promise<Omit<BrowserSandboxResult, 'originalUrl'>>;

const browserSandboxJobs = new Map<string, BrowserSandboxJob>();
const liveSessionLeaseTimers = new Map<string, NodeJS.Timeout>();
const DEFAULT_LIVE_SESSION_IDLE_TIMEOUT_MS = 5 * 60 * 1000;
let liveSessionIdleTimeoutMs = DEFAULT_LIVE_SESSION_IDLE_TIMEOUT_MS;

export class BrowserSandboxError extends Error {
  code: string;

  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

export async function enqueueBrowserSandboxJob(
  url: string,
  analyzeUrlInSandbox: AnalyzeUrlInSandbox = analyzeUrlInLocalSandbox,
  createJobId: () => string = randomUUID,
): Promise<BrowserSandboxJob> {
  const normalizedUrl = normalizePublicUrl(url);
  const jobId = createJobId();
  const queuedJob = browserSandboxJobSchema.parse({
    jobId,
    status: 'queued',
    requestedUrl: normalizedUrl,
    expiresAt: buildExpiryTimestamp(),
    session: null,
    result: null,
  });

  browserSandboxJobs.set(jobId, queuedJob);
  queueMicrotask(async () => {
    await runBrowserSandboxJob(jobId, normalizedUrl, analyzeUrlInSandbox);
  });

  return queuedJob;
}

export async function getBrowserSandboxJob(jobId: string): Promise<BrowserSandboxJob | null> {
  return browserSandboxJobs.get(jobId) ?? null;
}

export async function touchBrowserSandboxJob(jobId: string): Promise<BrowserSandboxJob | null> {
  const existingJob = browserSandboxJobs.get(jobId);
  if (!existingJob) {
    return null;
  }

  if (existingJob.session?.status === 'ready') {
    scheduleLiveSessionLease(jobId);
  }

  return existingJob;
}

export async function stopBrowserSandboxJob(
  jobId: string,
  reason: 'analyst_stop' | 'idle_timeout' = 'analyst_stop',
): Promise<BrowserSandboxJob | null> {
  const existingJob = browserSandboxJobs.get(jobId);
  if (!existingJob) {
    return null;
  }

  clearLiveSessionLease(jobId);

  const hasLiveSession = existingJob.session?.status === 'ready';
  if (existingJob.status === 'failed' || existingJob.status === 'stopped') {
    return existingJob;
  }
  if (existingJob.status === 'completed' && !hasLiveSession) {
    return existingJob;
  }

  const stopMessage = reason === 'idle_timeout'
    ? 'Sandbox session closed after 5 minutes of inactivity.'
    : 'Sandbox session stopped by analyst.';
  const preserveCompletedResult = existingJob.status === 'completed' && hasLiveSession && existingJob.result;

  const stoppedJob = browserSandboxJobSchema.parse({
    ...existingJob,
    status: preserveCompletedResult ? 'completed' : 'stopped',
    session: existingJob.session,
    result: existingJob.result
      ? {
          ...existingJob.result,
          session: existingJob.result.session,
          status: preserveCompletedResult ? existingJob.result.status : 'stopped',
          error: preserveCompletedResult ? existingJob.result.error : (existingJob.result.error ?? stopMessage),
        }
      : {
          originalUrl: existingJob.requestedUrl,
          finalUrl: null,
          title: null,
          session: existingJob.session ?? {
            provider: appConfig.browserSandbox.provider,
            sessionId: existingJob.jobId,
            status: 'unavailable',
            startedAt: new Date().toISOString(),
            stoppedAt: new Date().toISOString(),
            access: buildBrowserSandboxAccess(appConfig.browserSandbox, { jobId: existingJob.jobId }),
          },
          access: existingJob.session?.access ?? buildBrowserSandboxAccess(appConfig.browserSandbox, { jobId: existingJob.jobId }),
          screenshotPath: null,
          tracePath: null,
          redirectChain: [],
          requestedDomains: [],
          scriptUrls: [],
          consoleErrors: [],
          downloads: [],
          artifacts: [],
          status: 'stopped',
          error: stopMessage,
        },
  });

  if (existingJob.session) {
    const stoppedSession = await stopBrowserSandboxSession(
      appConfig.browserSandbox,
      existingJob.session,
      { jobId, url: existingJob.requestedUrl },
    );
    stoppedJob.session = stoppedSession;
    if (stoppedJob.result) {
      stoppedJob.result.session = stoppedSession;
      stoppedJob.result.access = stoppedSession.access;
    }
  }

  browserSandboxJobs.set(jobId, stoppedJob);
  return stoppedJob;
}

export async function createBrowserSandboxJob(
  url: string,
  analyzeUrlInSandbox: AnalyzeUrlInSandbox,
  createJobId: () => string = randomUUID,
): Promise<BrowserSandboxJob> {
  const normalizedUrl = normalizePublicUrl(url);
  const jobId = createJobId();
  const session = await startBrowserSandboxSession(appConfig.browserSandbox, { jobId, url: normalizedUrl });
  const result = await analyzeUrlInSandbox(normalizedUrl, { jobId, session });

  const job = browserSandboxJobSchema.parse({
    jobId,
    status: result.status === 'completed' ? 'completed' : result.status,
    requestedUrl: normalizedUrl,
    expiresAt: buildExpiryTimestamp(),
    session: result.session,
    result: {
      originalUrl: normalizedUrl,
      ...result,
    },
  });

  if (job.session?.status === 'ready') {
    scheduleLiveSessionLease(jobId);
  }

  return job;
}

async function runBrowserSandboxJob(
  jobId: string,
  normalizedUrl: string,
  analyzeUrlInSandbox: AnalyzeUrlInSandbox,
) {
  const activeJob = browserSandboxJobs.get(jobId);
  if (!activeJob || activeJob.status === 'stopped') {
    return;
  }

  browserSandboxJobs.set(jobId, {
    ...activeJob,
    status: 'running',
  });

  try {
    const session = await startBrowserSandboxSession(appConfig.browserSandbox, { jobId, url: normalizedUrl });
    browserSandboxJobs.set(jobId, {
      ...activeJob,
      status: 'running',
      session,
    });

    const result = await analyzeUrlInSandbox(normalizedUrl, { jobId, session });
    const finalStatus = result.status === 'completed' ? 'completed' : result.status;

    browserSandboxJobs.set(
      jobId,
      browserSandboxJobSchema.parse({
        jobId,
        status: finalStatus,
        requestedUrl: normalizedUrl,
        expiresAt: activeJob.expiresAt,
        session: result.session,
        result: {
          originalUrl: normalizedUrl,
          ...result,
        },
      }),
    );

    const completedJob = browserSandboxJobs.get(jobId);
    if (completedJob?.session?.status === 'ready') {
      scheduleLiveSessionLease(jobId);
    }
  } catch (error) {
    clearLiveSessionLease(jobId);
    browserSandboxJobs.set(
      jobId,
      browserSandboxJobSchema.parse({
        jobId,
        status: 'failed',
        requestedUrl: normalizedUrl,
        expiresAt: activeJob.expiresAt,
        session: null,
        result: {
          originalUrl: normalizedUrl,
          finalUrl: null,
          title: null,
          session: {
            provider: appConfig.browserSandbox.provider,
            sessionId: jobId,
            status: 'unavailable',
            startedAt: new Date().toISOString(),
            stoppedAt: null,
            access: buildBrowserSandboxAccess(appConfig.browserSandbox, { jobId }),
          },
          access: buildBrowserSandboxAccess(appConfig.browserSandbox, { jobId }),
          screenshotPath: null,
          tracePath: null,
          redirectChain: [],
          requestedDomains: [],
          scriptUrls: [],
          consoleErrors: [],
          downloads: [],
          artifacts: [],
          status: 'failed',
          error: error instanceof Error ? error.message : 'Browser sandbox failed unexpectedly.',
        },
      }),
    );
  }
}

export function clearBrowserSandboxStateForTesting() {
  for (const timer of liveSessionLeaseTimers.values()) {
    clearTimeout(timer);
  }

  liveSessionLeaseTimers.clear();
  browserSandboxJobs.clear();
  liveSessionIdleTimeoutMs = DEFAULT_LIVE_SESSION_IDLE_TIMEOUT_MS;
}

export function setLiveSessionIdleTimeoutForTesting(timeoutMs: number) {
  liveSessionIdleTimeoutMs = timeoutMs;
}

function scheduleLiveSessionLease(jobId: string) {
  clearLiveSessionLease(jobId);

  const timer = setTimeout(() => {
    liveSessionLeaseTimers.delete(jobId);
    void stopBrowserSandboxJob(jobId, 'idle_timeout');
  }, liveSessionIdleTimeoutMs);

  timer.unref?.();
  liveSessionLeaseTimers.set(jobId, timer);
}

function clearLiveSessionLease(jobId: string) {
  const existingTimer = liveSessionLeaseTimers.get(jobId);
  if (!existingTimer) {
    return;
  }

  clearTimeout(existingTimer);
  liveSessionLeaseTimers.delete(jobId);
}

export async function analyzeUrlInLocalSandbox(
  url: string,
  context: { jobId: string; session: BrowserSandboxSession },
): Promise<Omit<BrowserSandboxResult, 'originalUrl'>> {
  const access = context.session.access;
  const browser = await chromium.launch({ headless: true });
  const browserContext = await browser.newContext({ acceptDownloads: true });
  const page = await browserContext.newPage();
  const redirectChain: string[] = [];
  const requestedDomains = new Set<string>();
  const scriptUrls = new Set<string>();
  const consoleErrors: string[] = [];
  const downloads: ObservedDownload[] = [];
  const traceDirectory = path.join(getStoragePaths().traces, context.jobId);
  const screenshotDirectory = path.join(getStoragePaths().sandboxSessions, context.jobId);
  const downloadsDirectory = path.join(getStoragePaths().downloads, context.jobId);
  const tracePath = path.join(traceDirectory, createSafeTraceFilename(url));

  await fs.mkdir(traceDirectory, { recursive: true });
  await fs.mkdir(screenshotDirectory, { recursive: true });
  await fs.mkdir(downloadsDirectory, { recursive: true });
  await browserContext.tracing.start({ screenshots: true, snapshots: true, sources: true });

  page.on('request', (request) => {
    try {
      const hostname = new URL(request.url()).hostname;
      requestedDomains.add(hostname);
      if (request.resourceType() === 'script') {
        scriptUrls.add(request.url());
      }
    } catch {
      return;
    }
  });

  page.on('response', (response) => {
    if (response.request().isNavigationRequest()) {
      redirectChain.push(response.url());
    }
  });

  page.on('console', (message) => {
    if (message.type() === 'error') {
      consoleErrors.push(message.text());
    }
  });

  page.on('download', async (download) => {
    const suggestedFilename = sanitizeFilename(download.suggestedFilename());
    const targetPath = path.join(downloadsDirectory, suggestedFilename);
    await download.saveAs(targetPath);
    const fileBuffer = await fs.readFile(targetPath);
    downloads.push({
      filename: suggestedFilename,
      path: targetPath,
      url: download.url() || null,
      sha256: createHash('sha256').update(fileBuffer).digest('hex'),
      size: fileBuffer.byteLength,
    });
  });

  let screenshotPath: string | null = null;

  try {
    const response = await page.goto(url, {
      waitUntil: 'domcontentloaded',
      timeout: 15000,
    });

    screenshotPath = path.join(screenshotDirectory, createSafeScreenshotFilename(url));
    await page.screenshot({ path: screenshotPath, fullPage: true });

    const title = await page.title();
    const finalUrl = page.url();

    if (!redirectChain.length && response?.url()) {
      redirectChain.push(response.url());
    }
    if (!redirectChain.includes(finalUrl)) {
      redirectChain.push(finalUrl);
    }

    const artifacts = buildBrowserSandboxArtifacts(screenshotPath, tracePath, downloads);

    return {
      finalUrl,
      title: title || null,
      session: context.session,
      access,
      screenshotPath,
      tracePath,
      redirectChain,
      requestedDomains: [...requestedDomains],
      scriptUrls: [...scriptUrls],
      consoleErrors,
      downloads,
      artifacts,
      status: 'completed',
      error: null,
    };
  } catch (error) {
    return {
      finalUrl: null,
      title: null,
      session: context.session,
      access,
      screenshotPath,
      tracePath: null,
      redirectChain,
      requestedDomains: [...requestedDomains],
      scriptUrls: [...scriptUrls],
      consoleErrors,
      downloads,
      artifacts: buildBrowserSandboxArtifacts(screenshotPath, null, downloads),
      status: 'failed',
      error: error instanceof Error ? error.message : 'Browser sandbox failed unexpectedly.',
    };
  } finally {
    await browserContext.tracing.stop({ path: tracePath }).catch(() => undefined);
    await page.close();
    await browserContext.close();
    await browser.close();
  }
}

function buildBrowserSandboxArtifacts(
  screenshotPath: string | null,
  tracePath: string | null,
  downloads: ObservedDownload[],
): BrowserSandboxArtifact[] {
  const artifacts: BrowserSandboxArtifact[] = [];

  if (screenshotPath) {
    artifacts.push({
      type: 'screenshot',
      label: 'Sandbox screenshot',
      path: screenshotPath,
      mimeType: 'image/png',
      size: null,
    });
  }

  if (tracePath) {
    artifacts.push({
      type: 'trace',
      label: 'Playwright trace',
      path: tracePath,
      mimeType: 'application/zip',
      size: null,
    });
  }

  for (const download of downloads) {
    artifacts.push({
      type: 'download',
      label: download.filename,
      path: download.path,
      mimeType: null,
      size: download.size,
    });
  }

  return artifacts;
}

function normalizePublicUrl(value: string) {
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(value);
  } catch {
    throw new BrowserSandboxError('invalid_url_target', 'The sandbox target URL is invalid.');
  }

  if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
    throw new BrowserSandboxError('invalid_url_target', 'Only HTTP(S) URLs can be opened in the sandbox.');
  }

  const hostname = parsedUrl.hostname.toLowerCase();
  if (
    hostname === 'localhost' ||
    hostname === '::1' ||
    hostname.startsWith('127.') ||
    hostname.startsWith('10.') ||
    hostname.startsWith('192.168.') ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(hostname)
  ) {
    throw new BrowserSandboxError('invalid_url_target', 'Local, loopback, and private-network URLs are blocked.');
  }

  return parsedUrl.toString();
}

function sanitizeFilename(filename: string) {
  const normalized = filename.trim().replace(/[\\/:*?"<>|]+/g, '-');
  return normalized || 'download.bin';
}

function createSafeScreenshotFilename(url: string) {
  const hostname = new URL(url).hostname.replace(/[^a-z0-9.-]/gi, '-');
  return `${hostname}.png`;
}

function createSafeTraceFilename(url: string) {
  const hostname = new URL(url).hostname.replace(/[^a-z0-9.-]/gi, '-');
  return `${hostname}.zip`;
}

function buildExpiryTimestamp() {
  return new Date(Date.now() + 15 * 60 * 1000).toISOString();
}