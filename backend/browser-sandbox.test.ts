import { afterEach, describe, expect, it, vi } from 'vitest';

import { appConfig } from './config.js';
import {
  clearBrowserSandboxStateForTesting,
  createBrowserSandboxJob,
  enqueueBrowserSandboxJob,
  getBrowserSandboxJob,
  setLiveSessionIdleTimeoutForTesting,
} from './services/browser-sandbox.js';

const previousAccessMode = process.env.BROWSER_SANDBOX_ACCESS_MODE;
const previousAccessBaseUrl = process.env.BROWSER_SANDBOX_ACCESS_BASE_URL;
const previousAccessPathTemplate = process.env.BROWSER_SANDBOX_ACCESS_PATH_TEMPLATE;
const previousBrowserSandboxConfig = { ...appConfig.browserSandbox };

describe('createBrowserSandboxJob', () => {
  afterEach(() => {
    vi.useRealTimers();
    clearBrowserSandboxStateForTesting();
    Object.assign(appConfig.browserSandbox, previousBrowserSandboxConfig);

    if (previousAccessMode === undefined) {
      delete process.env.BROWSER_SANDBOX_ACCESS_MODE;
    } else {
      process.env.BROWSER_SANDBOX_ACCESS_MODE = previousAccessMode;
    }

    if (previousAccessBaseUrl === undefined) {
      delete process.env.BROWSER_SANDBOX_ACCESS_BASE_URL;
    } else {
      process.env.BROWSER_SANDBOX_ACCESS_BASE_URL = previousAccessBaseUrl;
    }

    if (previousAccessPathTemplate === undefined) {
      delete process.env.BROWSER_SANDBOX_ACCESS_PATH_TEMPLATE;
    } else {
      process.env.BROWSER_SANDBOX_ACCESS_PATH_TEMPLATE = previousAccessPathTemplate;
    }
  });

  it('rejects local or private targets before any sandbox execution', async () => {
    await expect(
      createBrowserSandboxJob('http://127.0.0.1/login', async () => ({
        session: {
          provider: 'local-chromium',
          sessionId: 'blocked',
          status: 'unavailable',
          startedAt: '2026-04-11T18:00:00.000Z',
          stoppedAt: null,
          runtime: {
            displayNumber: 100,
            vncPort: 5900,
            novncPort: 7600,
            sessionDirectory: 'storage/sandbox-sessions/blocked',
          },
          access: {
            mode: 'none',
            url: null,
            note: 'blocked',
          },
        },
        finalUrl: 'http://127.0.0.1/login',
        title: 'blocked',
        access: {
          mode: 'none',
          url: null,
          note: 'blocked',
        },
        screenshotPath: null,
        tracePath: null,
        redirectChain: [],
        requestedDomains: [],
        scriptUrls: [],
        consoleErrors: [],
        downloads: [],
        artifacts: [],
        activityJournal: [],
        status: 'completed',
        error: null,
      })),
    ).rejects.toMatchObject({
      code: 'invalid_url_target',
    });
  });

  it('creates a completed browser sandbox job with captured artifacts', async () => {
    const job = await createBrowserSandboxJob(
      'https://example.org',
      async (url) => ({
        finalUrl: `${url}/`,
        title: 'Example Domain',
        session: {
          provider: 'local-chromium',
          sessionId: 'job_test_123',
          status: 'unavailable',
          startedAt: '2026-04-11T18:00:00.000Z',
          stoppedAt: null,
          runtime: {
            displayNumber: 120,
            vncPort: 5920,
            novncPort: 7620,
            sessionDirectory: 'storage/sandbox-sessions/job_test_123',
          },
          access: {
            mode: 'none',
            url: null,
            note: 'Interactive access is not enabled on this provider yet.',
          },
        },
        access: {
          mode: 'none',
          url: null,
          note: 'Interactive access is not enabled on this provider yet.',
        },
        screenshotPath: 'storage/sandbox-sessions/job_test_123/example-org.png',
        tracePath: 'storage/traces/job_test_123/example-org.zip',
        redirectChain: [url, `${url}/`],
        requestedDomains: ['example.org'],
        scriptUrls: ['https://example.org/app.js'],
        consoleErrors: [],
        downloads: [
          {
            filename: 'payload.iso',
            path: 'storage/downloads/job_test_123/payload.iso',
            url: 'https://example.org/payload.iso',
            sha256: 'abc123',
            size: 5120,
          },
        ],
        artifacts: [
          {
            type: 'screenshot',
            label: 'Sandbox screenshot',
            path: 'storage/sandbox-sessions/job_test_123/example-org.png',
            mimeType: 'image/png',
            size: null,
          },
          {
            type: 'download',
            label: 'payload.iso',
            path: 'storage/downloads/job_test_123/payload.iso',
            mimeType: null,
            size: 5120,
          },
        ],
        activityJournal: [],
        status: 'completed',
        error: null,
      }),
      () => 'job_test_123',
    );

    expect(job.jobId).toBe('job_test_123');
    expect(job.status).toBe('completed');
    expect(job.result).toEqual(
      expect.objectContaining({
        originalUrl: 'https://example.org/',
        title: 'Example Domain',
        requestedDomains: ['example.org'],
      }),
    );
    expect(job.session?.sessionId).toBe('job_test_123');
    expect(job.result?.downloads[0].filename).toBe('payload.iso');
    expect(job.result?.artifacts).toHaveLength(2);
  });

  it('accepts a bare hostname and normalizes it to https', async () => {
    const job = await createBrowserSandboxJob(
      'example.org/login',
      async (url) => ({
        finalUrl: url,
        title: 'Example Domain',
        session: {
          provider: 'local-chromium',
          sessionId: 'job_test_789',
          status: 'unavailable',
          startedAt: '2026-04-11T18:00:00.000Z',
          stoppedAt: null,
          runtime: {
            displayNumber: 122,
            vncPort: 5922,
            novncPort: 7622,
            sessionDirectory: 'storage/sandbox-sessions/job_test_789',
          },
          access: {
            mode: 'none',
            url: null,
            note: 'Interactive access is not enabled on this provider yet.',
          },
        },
        access: {
          mode: 'none',
          url: null,
          note: 'Interactive access is not enabled on this provider yet.',
        },
        screenshotPath: null,
        tracePath: null,
        redirectChain: [url],
        requestedDomains: ['example.org'],
        scriptUrls: [],
        consoleErrors: [],
        downloads: [],
        artifacts: [],
        activityJournal: [],
        status: 'completed',
        error: null,
      }),
      () => 'job_test_789',
    );

    expect(job.requestedUrl).toBe('https://example.org/login');
    expect(job.result?.originalUrl).toBe('https://example.org/login');
  });

  it('preserves a live access url when the provider returns one', async () => {
    const job = await createBrowserSandboxJob(
      'https://example.org',
      async (url) => ({
        finalUrl: `${url}/`,
        title: 'Example Domain',
        session: {
          provider: 'novnc',
          sessionId: 'job_test_456',
          status: 'ready',
          startedAt: '2026-04-11T18:00:00.000Z',
          stoppedAt: null,
          runtime: {
            displayNumber: 121,
            vncPort: 5921,
            novncPort: 7621,
            sessionDirectory: 'storage/sandbox-sessions/job_test_456',
          },
          access: {
            mode: 'external',
            url: 'https://sandbox.example.test/live/sessions/job_test_456',
            note: 'Live Chromium access is exposed through the novnc provider.',
          },
        },
        access: {
          mode: 'external',
          url: 'https://sandbox.example.test/live/sessions/job_test_456',
          note: 'Live Chromium access is exposed through the novnc provider.',
        },
        screenshotPath: null,
        tracePath: null,
        redirectChain: [url, `${url}/`],
        requestedDomains: ['example.org'],
        scriptUrls: [],
        consoleErrors: [],
        downloads: [],
        artifacts: [],
        activityJournal: [],
        status: 'completed',
        error: null,
      }),
      () => 'job_test_456',
    );

    expect(job.result?.access.mode).toBe('external');
    expect(job.result?.access.url).toBe('https://sandbox.example.test/live/sessions/job_test_456');
    expect(job.session?.status).toBe('ready');
  });

  it('auto-stops a live session after five minutes without heartbeats', async () => {
    Object.assign(appConfig.browserSandbox, {
      provider: 'local-novnc',
      accessMode: 'embedded',
      accessBaseUrl: null,
      accessUrlTemplate: 'https://fred.syntrix.ae/novnc/:novncPort/vnc.html?autoconnect=1&resize=remote',
      accessPathTemplate: ':jobId',
      startCommandTemplate: null,
      stopCommandTemplate: null,
    });
    setLiveSessionIdleTimeoutForTesting(25);

    await enqueueBrowserSandboxJob(
      'https://example.org',
      async (url, context) => ({
        finalUrl: url,
        title: 'Example Domain',
        session: context.session,
        access: context.session.access,
        screenshotPath: null,
        tracePath: null,
        redirectChain: [url],
        requestedDomains: ['example.org'],
        scriptUrls: [],
        consoleErrors: [],
        downloads: [],
        artifacts: [],
        activityJournal: [],
        status: 'completed',
        error: null,
      }),
      () => 'idle_timeout_job_123',
    );

    await waitForJobState('idle_timeout_job_123', (job) => job?.status === 'completed' && job.session?.status === 'ready');
    await waitForJobState('idle_timeout_job_123', (job) => job?.session?.status === 'stopped');

    const expiredJob = await getBrowserSandboxJob('idle_timeout_job_123');
    expect(expiredJob?.status).toBe('completed');
    expect(expiredJob?.session?.status).toBe('stopped');
    expect(expiredJob?.result?.status).toBe('completed');
    expect(expiredJob?.result?.error).toBeNull();
  });

  it('marks a queued job as failed without crashing when sandbox analysis throws', async () => {
    await enqueueBrowserSandboxJob(
      'https://example.org',
      async () => {
        throw new Error('sandbox launch exploded');
      },
      () => 'job_failed_123',
    );

    await waitForJobState('job_failed_123', (job) => job?.status === 'failed');

    const failedJob = await getBrowserSandboxJob('job_failed_123');
    expect(failedJob?.status).toBe('failed');
    expect(failedJob?.result?.status).toBe('failed');
    expect(failedJob?.result?.error).toBe('sandbox launch exploded');
    expect(failedJob?.result?.session.runtime).toBeDefined();
  });
});

async function waitForJobState(
  jobId: string,
  predicate: (job: Awaited<ReturnType<typeof getBrowserSandboxJob>>) => boolean,
  timeoutMs = 250,
) {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    const job = await getBrowserSandboxJob(jobId);
    if (predicate(job)) {
      return job;
    }

    await new Promise((resolve) => setTimeout(resolve, 10));
  }

  return getBrowserSandboxJob(jobId);
}