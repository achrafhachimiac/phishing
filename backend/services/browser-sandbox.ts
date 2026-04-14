import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';

import { chromium } from 'playwright';
import type { Browser, BrowserContext, Page } from 'playwright';

import {
  browserSandboxJobSchema,
  type BrowserSandboxArtifact,
  type BrowserSandboxJob,
  type BrowserSandboxJournalEntry,
  type BrowserSandboxResult,
  type FileUpload,
  type ObservedDownload,
  type BrowserSandboxSession,
} from '../../shared/analysis-types.js';
import { appConfig } from '../config.js';
import { getStoragePaths } from '../storage.js';
import { enqueueFileAnalysisJob } from './file-analysis.js';
import { buildBrowserSandboxAccess } from './browser-sandbox-provider.js';
import { resolveBrowserSandboxRuntime } from './browser-sandbox-runtime.js';
import { startBrowserSandboxSession, stopBrowserSandboxSession } from './browser-sandbox-session.js';

type AnalyzeUrlInSandbox = (
  url: string,
  context: { jobId: string; session: BrowserSandboxSession },
) => Promise<Omit<BrowserSandboxResult, 'originalUrl'>>;

const browserSandboxJobs = new Map<string, BrowserSandboxJob>();
const liveSessionLeaseTimers = new Map<string, NodeJS.Timeout>();
const liveObservationHandles = new Map<string, LiveObservationHandle>();
const DEFAULT_LIVE_SESSION_IDLE_TIMEOUT_MS = 5 * 60 * 1000;
const LIVE_OBSERVATION_POLL_INTERVAL_MS = 3000;
const LIVE_OBSERVATION_SCREENSHOT_INTERVAL_MS = 5000;
let liveSessionIdleTimeoutMs = DEFAULT_LIVE_SESSION_IDLE_TIMEOUT_MS;

type LiveObservationHandle = {
  pollTimer: NodeJS.Timeout;
  browser: Browser | null;
  attachedContexts: WeakSet<BrowserContext>;
  attachedPages: WeakSet<Page>;
  lastScreenshotAt: number;
  syncing: boolean;
};

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
    startLiveObservation(jobId);
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
  stopLiveObservation(jobId);

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
          session: existingJob.session ?? buildUnavailableSandboxSession(existingJob.jobId, true),
          access: existingJob.session?.access ?? buildUnavailableSandboxSession(existingJob.jobId, true).access,
          screenshotPath: null,
          tracePath: null,
          redirectChain: [],
          requestedDomains: [],
          scriptUrls: [],
          consoleErrors: [],
          downloads: [],
          artifacts: [],
          activityJournal: [],
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
      startLiveObservation(jobId);
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
          session: buildUnavailableSandboxSession(jobId),
          access: buildUnavailableSandboxSession(jobId).access,
          screenshotPath: null,
          tracePath: null,
          redirectChain: [],
          requestedDomains: [],
          scriptUrls: [],
          consoleErrors: [],
          downloads: [],
          artifacts: [],
          activityJournal: [],
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

  for (const handle of liveObservationHandles.values()) {
    clearInterval(handle.pollTimer);
    void handle.browser?.close().catch(() => undefined);
  }

  liveSessionLeaseTimers.clear();
  liveObservationHandles.clear();
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

function startLiveObservation(jobId: string) {
  if (liveObservationHandles.has(jobId)) {
    return;
  }

  const pollTimer = setInterval(() => {
    void syncLiveObservation(jobId);
  }, LIVE_OBSERVATION_POLL_INTERVAL_MS);

  pollTimer.unref?.();
  liveObservationHandles.set(jobId, {
    pollTimer,
    browser: null,
    attachedContexts: new WeakSet<BrowserContext>(),
    attachedPages: new WeakSet<Page>(),
    lastScreenshotAt: 0,
    syncing: false,
  });

  void syncLiveObservation(jobId);
}

function stopLiveObservation(jobId: string) {
  const handle = liveObservationHandles.get(jobId);
  if (!handle) {
    return;
  }

  clearInterval(handle.pollTimer);
  liveObservationHandles.delete(jobId);
  void handle.browser?.close().catch(() => undefined);
}

async function syncLiveObservation(jobId: string) {
  const handle = liveObservationHandles.get(jobId);
  const existingJob = browserSandboxJobs.get(jobId);

  if (!handle || !existingJob?.result || existingJob.session?.status !== 'ready' || existingJob.status === 'failed' || existingJob.status === 'stopped') {
    stopLiveObservation(jobId);
    return;
  }

  if (handle.syncing) {
    return;
  }

  handle.syncing = true;

  try {
    if (!handle.browser?.isConnected()) {
      handle.browser = await chromium.connectOverCDP(
        `http://127.0.0.1:${resolveBrowserSandboxRuntime(jobId, getStoragePaths().sandboxSessions).cdpPort}`,
      );
      handle.browser.on('disconnected', () => {
        const currentHandle = liveObservationHandles.get(jobId);
        if (currentHandle === handle) {
          currentHandle.browser = null;
        }
      });
    }

    const pages: Page[] = [];
    for (const context of handle.browser.contexts()) {
      attachLiveObservationContext(jobId, context, handle);
      pages.push(...context.pages().filter((page) => !page.isClosed()));
    }

    const activePage = pages.at(-1) ?? null;
    if (activePage) {
      await refreshLiveObservationPage(jobId, activePage, handle);
    }
  } catch {
    if (handle.browser) {
      await handle.browser.close().catch(() => undefined);
    }
    handle.browser = null;
  } finally {
    handle.syncing = false;
  }
}

function attachLiveObservationContext(jobId: string, context: BrowserContext, handle: LiveObservationHandle) {
  if (!handle.attachedContexts.has(context)) {
    handle.attachedContexts.add(context);
    context.on('page', (page) => {
      attachLiveObservationPage(jobId, page, handle);
      void refreshLiveObservationPage(jobId, page, handle);
    });
  }

  for (const page of context.pages()) {
    attachLiveObservationPage(jobId, page, handle);
  }
}

function attachLiveObservationPage(jobId: string, page: Page, handle: LiveObservationHandle) {
  if (handle.attachedPages.has(page)) {
    return;
  }

  handle.attachedPages.add(page);

  page.on('request', (request) => {
    try {
      const hostname = new URL(request.url()).hostname;
      mergeLiveObservation(jobId, {
        requestedDomains: [hostname],
        scriptUrls: request.resourceType() === 'script' ? [request.url()] : [],
      });
    } catch {
      return;
    }
  });

  page.on('console', (message) => {
    if (message.type() === 'error') {
      mergeLiveObservation(jobId, {
        consoleErrors: [message.text()],
      });
    }
  });

  page.on('download', async (download) => {
    const downloadsDirectory = path.join(getStoragePaths().downloads, jobId);
    await fs.mkdir(downloadsDirectory, { recursive: true });

    const suggestedFilename = sanitizeFilename(download.suggestedFilename());
    const targetPath = path.join(downloadsDirectory, suggestedFilename);

    try {
      await download.saveAs(targetPath);
      const fileBuffer = await fs.readFile(targetPath);
      const fileAnalysisJob = await enqueueObservedDownloadFileAnalysis(suggestedFilename, fileBuffer);
      mergeLiveObservation(jobId, {
        downloads: [{
          filename: suggestedFilename,
          path: targetPath,
          url: download.url() || null,
          sha256: createHash('sha256').update(fileBuffer).digest('hex'),
          size: fileBuffer.byteLength,
          fileAnalysisJobId: fileAnalysisJob.jobId,
        }],
      });
    } catch {
      return;
    }
  });

  page.on('framenavigated', (frame) => {
    if (frame !== page.mainFrame()) {
      return;
    }

    const currentUrl = page.url();
    if (!currentUrl) {
      return;
    }

    mergeLiveObservation(jobId, {
      finalUrl: currentUrl,
      redirectChain: [currentUrl],
    });
  });
}

async function refreshLiveObservationPage(jobId: string, page: Page, handle: LiveObservationHandle) {
  const now = Date.now();
  if (now - handle.lastScreenshotAt < LIVE_OBSERVATION_SCREENSHOT_INTERVAL_MS) {
    return;
  }

  handle.lastScreenshotAt = now;

  const existingJob = browserSandboxJobs.get(jobId);
  if (!existingJob?.result) {
    return;
  }

  const screenshotPath = existingJob.result.screenshotPath
    ?? path.join(getStoragePaths().sandboxSessions, jobId, createSafeScreenshotFilename(existingJob.requestedUrl));

  await fs.mkdir(path.dirname(screenshotPath), { recursive: true });

  try {
    await page.screenshot({ path: screenshotPath, fullPage: true });
  } catch {
    return;
  }

  let pageTitle: string | null = null;
  try {
    pageTitle = (await page.title()) || null;
  } catch {
    pageTitle = null;
  }

  mergeLiveObservation(jobId, {
    finalUrl: page.url() || existingJob.result.finalUrl,
    title: pageTitle,
    screenshotPath,
  });
}

function mergeLiveObservation(
  jobId: string,
  updates: {
    finalUrl?: string | null;
    title?: string | null;
    screenshotPath?: string | null;
    redirectChain?: string[];
    requestedDomains?: string[];
    scriptUrls?: string[];
    consoleErrors?: string[];
    downloads?: ObservedDownload[];
  },
) {
  const existingJob = browserSandboxJobs.get(jobId);
  if (!existingJob?.result) {
    return;
  }

  const nextDownloads = mergeObservedDownloads(existingJob.result.downloads, updates.downloads ?? []);
  browserSandboxJobs.set(jobId, {
    ...existingJob,
    result: {
      ...existingJob.result,
      finalUrl: updates.finalUrl ?? existingJob.result.finalUrl,
      title: updates.title ?? existingJob.result.title,
      screenshotPath: updates.screenshotPath ?? existingJob.result.screenshotPath,
      redirectChain: mergeStringValues(existingJob.result.redirectChain, updates.redirectChain ?? []),
      requestedDomains: mergeStringValues(existingJob.result.requestedDomains, updates.requestedDomains ?? []),
      scriptUrls: mergeStringValues(existingJob.result.scriptUrls, updates.scriptUrls ?? []),
      consoleErrors: mergeStringValues(existingJob.result.consoleErrors, updates.consoleErrors ?? []),
      downloads: nextDownloads,
      artifacts: buildBrowserSandboxArtifacts(
        updates.screenshotPath ?? existingJob.result.screenshotPath,
        existingJob.result.tracePath,
        nextDownloads,
      ),
      activityJournal: buildBrowserSandboxActivityJournal({
        redirectChain: mergeStringValues(existingJob.result.redirectChain, updates.redirectChain ?? []),
        requestedDomains: mergeStringValues(existingJob.result.requestedDomains, updates.requestedDomains ?? []),
        scriptUrls: mergeStringValues(existingJob.result.scriptUrls, updates.scriptUrls ?? []),
        consoleErrors: mergeStringValues(existingJob.result.consoleErrors, updates.consoleErrors ?? []),
        downloads: nextDownloads,
        artifacts: buildBrowserSandboxArtifacts(
          updates.screenshotPath ?? existingJob.result.screenshotPath,
          existingJob.result.tracePath,
          nextDownloads,
        ),
      }),
    },
  });
}

function mergeStringValues(existing: string[], incoming: string[]) {
  if (!incoming.length) {
    return existing;
  }

  const merged = new Set(existing);
  for (const value of incoming) {
    const normalizedValue = value.trim();
    if (normalizedValue) {
      merged.add(normalizedValue);
    }
  }

  return [...merged];
}

function mergeObservedDownloads(existing: ObservedDownload[], incoming: ObservedDownload[]) {
  if (!incoming.length) {
    return existing;
  }

  const merged = new Map(existing.map((download) => [`${download.path}:${download.sha256}`, download]));
  for (const download of incoming) {
    merged.set(`${download.path}:${download.sha256}`, download);
  }

  return [...merged.values()];
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
    const fileAnalysisJob = await enqueueObservedDownloadFileAnalysis(suggestedFilename, fileBuffer);
    downloads.push({
      filename: suggestedFilename,
      path: targetPath,
      url: download.url() || null,
      sha256: createHash('sha256').update(fileBuffer).digest('hex'),
      size: fileBuffer.byteLength,
      fileAnalysisJobId: fileAnalysisJob.jobId,
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
    const activityJournal = buildBrowserSandboxActivityJournal({
      redirectChain,
      requestedDomains: [...requestedDomains],
      scriptUrls: [...scriptUrls],
      consoleErrors,
      downloads,
      artifacts,
    });

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
      activityJournal,
      status: 'completed',
      error: null,
    };
  } catch (error) {
    const artifacts = buildBrowserSandboxArtifacts(screenshotPath, null, downloads);
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
      artifacts,
      activityJournal: buildBrowserSandboxActivityJournal({
        redirectChain,
        requestedDomains: [...requestedDomains],
        scriptUrls: [...scriptUrls],
        consoleErrors,
        downloads,
        artifacts,
      }),
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

function buildBrowserSandboxActivityJournal(input: {
  redirectChain: string[];
  requestedDomains: string[];
  scriptUrls: string[];
  consoleErrors: string[];
  downloads: ObservedDownload[];
  artifacts: BrowserSandboxArtifact[];
}): BrowserSandboxJournalEntry[] {
  const entries: BrowserSandboxJournalEntry[] = [];

  input.redirectChain.forEach((url, index) => {
    entries.push({
      kind: 'navigation',
      label: index === input.redirectChain.length - 1 ? 'Final navigation target' : 'Redirect hop',
      value: url,
      path: null,
      url,
      severity: 'info',
    });
  });

  input.requestedDomains.forEach((domain) => {
    entries.push({
      kind: 'request_domain',
      label: 'Requested domain',
      value: domain,
      path: null,
      url: null,
      severity: 'info',
    });
  });

  input.scriptUrls.forEach((scriptUrl) => {
    entries.push({
      kind: 'script_url',
      label: 'Loaded script',
      value: scriptUrl,
      path: null,
      url: scriptUrl,
      severity: 'warning',
    });
  });

  input.consoleErrors.forEach((consoleError) => {
    entries.push({
      kind: 'console_error',
      label: 'Console error',
      value: consoleError,
      path: null,
      url: null,
      severity: 'danger',
    });
  });

  input.downloads.forEach((download) => {
    entries.push({
      kind: 'download',
      label: `Downloaded file: ${download.filename}`,
      value: download.sha256,
      path: download.path,
      url: download.url,
      severity: 'warning',
    });
  });

  input.artifacts.forEach((artifact) => {
    entries.push({
      kind: 'artifact',
      label: `Captured artifact: ${artifact.label}`,
      value: artifact.type,
      path: artifact.path,
      url: null,
      severity: artifact.type === 'download' ? 'warning' : 'info',
    });
  });

  return entries;
}

function buildUnavailableSandboxSession(jobId: string, includeStoppedAt = false): BrowserSandboxSession {
  const runtime = resolveBrowserSandboxRuntime(jobId, getStoragePaths().sandboxSessions);
  const access = buildBrowserSandboxAccess(appConfig.browserSandbox, {
    jobId,
    displayNumber: runtime.displayNumber,
    vncPort: runtime.vncPort,
    novncPort: runtime.novncPort,
  });

  return {
    provider: appConfig.browserSandbox.provider,
    sessionId: jobId,
    status: 'unavailable',
    startedAt: new Date().toISOString(),
    stoppedAt: includeStoppedAt ? new Date().toISOString() : null,
    runtime,
    access,
  };
}

function normalizePublicUrl(value: string) {
  const trimmedValue = value.trim();
  const candidateUrl = /^[a-z][a-z\d+.-]*:\/\//i.test(trimmedValue) ? trimmedValue : `https://${trimmedValue}`;

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(candidateUrl);
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

async function enqueueObservedDownloadFileAnalysis(filename: string, fileBuffer: Buffer) {
  const fileUpload: FileUpload = {
    filename,
    contentType: null,
    contentBase64: fileBuffer.toString('base64'),
  };

  return enqueueFileAnalysisJob([fileUpload]);
}