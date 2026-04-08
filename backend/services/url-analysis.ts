import fs from 'node:fs/promises';
import path from 'node:path';
import { randomUUID } from 'node:crypto';

import { chromium } from 'playwright';

import { type UrlAnalysisJob, urlAnalysisJobSchema, type UrlAnalysisResult } from '../../shared/analysis-types.js';
import { getStoragePaths } from '../storage.js';
import { lookupUrlThreatIntel, type ExternalScans } from './threat-intel.js';

type AnalyzeUrlWithBrowser = (
  url: string,
  context: { jobId: string; index: number },
) => Promise<Omit<UrlAnalysisResult, 'originalUrl' | 'externalScans'>>;
type EnrichUrlWithThreatIntel = (url: string) => Promise<ExternalScans>;

const urlAnalysisJobs = new Map<string, UrlAnalysisJob>();

export class UrlAnalysisError extends Error {
  code: string;

  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

export async function enqueueUrlAnalysisJob(
  urls: string[],
  analyzeUrlWithBrowser: AnalyzeUrlWithBrowser = analyzeUrlWithPlaywright,
  enrichUrlWithThreatIntel: EnrichUrlWithThreatIntel = lookupUrlThreatIntel,
  createJobId: () => string = randomUUID,
): Promise<UrlAnalysisJob> {
  const normalizedUrls = normalizeAndValidateUrls(urls);
  const jobId = createJobId();
  const queuedJob = urlAnalysisJobSchema.parse({
    jobId,
    status: 'queued',
    queuedUrls: normalizedUrls.map((entry) => entry.originalUrl),
    results: [],
  });

  urlAnalysisJobs.set(jobId, queuedJob);
  queueMicrotask(async () => {
    await runUrlAnalysisJob(jobId, normalizedUrls, analyzeUrlWithBrowser, enrichUrlWithThreatIntel);
  });

  return queuedJob;
}

export async function getUrlAnalysisJob(jobId: string): Promise<UrlAnalysisJob | null> {
  return urlAnalysisJobs.get(jobId) ?? null;
}

export async function createUrlAnalysisJob(
  urls: string[],
  analyzeUrlWithBrowser: AnalyzeUrlWithBrowser,
  enrichUrlWithThreatIntel: EnrichUrlWithThreatIntel = lookupUrlThreatIntel,
  createJobId: () => string = randomUUID,
): Promise<UrlAnalysisJob> {
  const normalizedUrls = normalizeAndValidateUrls(urls);
  const jobId = createJobId();
  const results = await Promise.all(
    normalizedUrls.map(async ({ originalUrl, normalizedUrl }, index) => {
      const [browserResult, externalScans] = await Promise.all([
        analyzeUrlWithBrowser(normalizedUrl, { jobId, index }),
        enrichUrlWithThreatIntel(normalizedUrl),
      ]);

      return {
        originalUrl,
        ...browserResult,
        externalScans,
      };
    }),
  );

  return urlAnalysisJobSchema.parse({
    jobId,
    status: results.every((result) => result.status === 'completed') ? 'completed' : 'failed',
    queuedUrls: normalizedUrls.map((entry) => entry.originalUrl),
    results,
  });
}

async function runUrlAnalysisJob(
  jobId: string,
  normalizedUrls: Array<{ originalUrl: string; normalizedUrl: string }>,
  analyzeUrlWithBrowser: AnalyzeUrlWithBrowser,
  enrichUrlWithThreatIntel: EnrichUrlWithThreatIntel,
) {
  urlAnalysisJobs.set(jobId, {
    jobId,
    status: 'running',
    queuedUrls: normalizedUrls.map((entry) => entry.originalUrl),
    results: [],
  });

  const results: UrlAnalysisResult[] = [];

  for (const [index, entry] of normalizedUrls.entries()) {
    try {
      const [browserResult, externalScans] = await Promise.all([
        analyzeUrlWithBrowser(entry.normalizedUrl, { jobId, index }),
        enrichUrlWithThreatIntel(entry.normalizedUrl),
      ]);

      results.push({
        originalUrl: entry.originalUrl,
        ...browserResult,
        externalScans,
      });
    } catch (error) {
      results.push({
        externalScans: {
          urlhaus: {
            status: 'unavailable',
            reference: null,
            tags: [],
            permalink: null,
          },
          virustotal: {
            status: 'unavailable',
            malicious: null,
            suspicious: null,
            reference: null,
          },
          urlscan: {
            status: 'unavailable',
            resultUrl: null,
          },
          alienVault: {
            status: 'unavailable',
            pulseCount: null,
            reference: null,
          },
        },
        originalUrl: entry.originalUrl,
        finalUrl: null,
        title: null,
        screenshotPath: null,
        tracePath: null,
        redirectChain: [],
        requestedDomains: [],
        scriptUrls: [],
        consoleErrors: [],
        status: 'failed',
        error: error instanceof Error ? error.message : 'URL analysis failed unexpectedly.',
      });
    }
  }

  urlAnalysisJobs.set(
    jobId,
    urlAnalysisJobSchema.parse({
      jobId,
      status: results.every((result) => result.status === 'completed') ? 'completed' : 'failed',
      queuedUrls: normalizedUrls.map((entry) => entry.originalUrl),
      results,
    }),
  );
}

export async function analyzeUrlWithPlaywright(
  url: string,
  context: { jobId: string; index: number },
): Promise<Omit<UrlAnalysisResult, 'originalUrl'>> {
  const browser = await chromium.launch({ headless: true });
  const browserContext = await browser.newContext();
  const page = await browserContext.newPage();
  const redirectChain: string[] = [];
  const requestedDomains = new Set<string>();
  const scriptUrls = new Set<string>();
  const consoleErrors: string[] = [];
  const traceDirectory = path.join(getStoragePaths().traces, context.jobId);
  const tracePath = path.join(traceDirectory, createSafeTraceFilename(url, context.index));

  await fs.mkdir(traceDirectory, { recursive: true });
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

  try {
    const response = await page.goto(url, {
      waitUntil: 'domcontentloaded',
      timeout: 15000,
    });

    const screenshotDirectory = path.join(getStoragePaths().screenshots, context.jobId);
    await fs.mkdir(screenshotDirectory, { recursive: true });
    const screenshotPath = path.join(screenshotDirectory, createSafeFilename(url, context.index));
    await page.screenshot({ path: screenshotPath, fullPage: true });

    const title = await page.title();
    const finalUrl = page.url();

    if (!redirectChain.length && response?.url()) {
      redirectChain.push(response.url());
    }
    if (!redirectChain.includes(finalUrl)) {
      redirectChain.push(finalUrl);
    }

    return {
      finalUrl,
      title: title || null,
      screenshotPath,
      tracePath,
      redirectChain,
      requestedDomains: [...requestedDomains],
      scriptUrls: [...scriptUrls],
      consoleErrors,
      status: 'completed',
      error: null,
      externalScans: {
        urlhaus: {
          status: 'unavailable',
          reference: null,
          tags: [],
          permalink: null,
        },
        virustotal: {
          status: 'unavailable',
          malicious: null,
          suspicious: null,
          reference: null,
        },
        urlscan: {
          status: 'unavailable',
          resultUrl: null,
        },
        alienVault: {
          status: 'unavailable',
          pulseCount: null,
          reference: null,
        },
      },
    };
  } catch (error) {
    return {
      externalScans: {
        urlhaus: {
          status: 'unavailable',
          reference: null,
          tags: [],
          permalink: null,
        },
        virustotal: {
          status: 'unavailable',
          malicious: null,
          suspicious: null,
          reference: null,
        },
        urlscan: {
          status: 'unavailable',
          resultUrl: null,
        },
        alienVault: {
          status: 'unavailable',
          pulseCount: null,
          reference: null,
        },
      },
      finalUrl: null,
      title: null,
      screenshotPath: null,
      tracePath: null,
      redirectChain,
      requestedDomains: [...requestedDomains],
      scriptUrls: [...scriptUrls],
      consoleErrors,
      status: 'failed',
      error: error instanceof Error ? error.message : 'Playwright analysis failed unexpectedly.',
    };
  } finally {
    await browserContext.tracing.stop({ path: tracePath });
    await page.close();
    await browserContext.close();
    await browser.close();
  }
}

function normalizeAndValidateUrls(urls: string[]) {
  const normalizedUrls = [...new Map(urls.map((url) => {
    const trimmedUrl = url.trim();
    const normalizedUrl = normalizePublicUrl(trimmedUrl);
    return [normalizedUrl, { originalUrl: trimmedUrl, normalizedUrl }] as const;
  })).values()];
  if (normalizedUrls.length === 0) {
    throw new UrlAnalysisError('invalid_url_target', 'At least one public URL is required for analysis.');
  }

  return normalizedUrls;
}

function normalizePublicUrl(value: string) {
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(value);
  } catch {
    throw new UrlAnalysisError('invalid_url_target', 'One or more URLs are invalid.');
  }

  if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
    throw new UrlAnalysisError('invalid_url_target', 'Only HTTP(S) URLs can be analyzed.');
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
    throw new UrlAnalysisError('invalid_url_target', 'Local, loopback, and private-network URLs are blocked.');
  }

  return parsedUrl.toString();
}

function createSafeFilename(url: string, index: number) {
  const hostname = new URL(url).hostname.replace(/[^a-z0-9.-]/gi, '-');
  return `${index.toString().padStart(2, '0')}-${hostname}.png`;
}

function createSafeTraceFilename(url: string, index: number) {
  const hostname = new URL(url).hostname.replace(/[^a-z0-9.-]/gi, '-');
  return `${index.toString().padStart(2, '0')}-${hostname}.zip`;
}