import { afterEach, describe, expect, it } from 'vitest';

import { createBrowserSandboxJob } from './services/browser-sandbox.js';

const previousAccessMode = process.env.BROWSER_SANDBOX_ACCESS_MODE;
const previousAccessBaseUrl = process.env.BROWSER_SANDBOX_ACCESS_BASE_URL;
const previousAccessPathTemplate = process.env.BROWSER_SANDBOX_ACCESS_PATH_TEMPLATE;

describe('createBrowserSandboxJob', () => {
  afterEach(() => {
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
        status: 'completed',
        error: null,
      }),
      () => 'job_test_456',
    );

    expect(job.result?.access.mode).toBe('external');
    expect(job.result?.access.url).toBe('https://sandbox.example.test/live/sessions/job_test_456');
    expect(job.session?.status).toBe('ready');
  });
});