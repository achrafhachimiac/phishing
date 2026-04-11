import { describe, expect, it, vi } from 'vitest';

import { startBrowserSandboxSession, stopBrowserSandboxSession } from './services/browser-sandbox-session.js';

describe('browser sandbox session lifecycle', () => {
  it('starts a remote session and interpolates command placeholders', async () => {
    const runCommand = vi.fn(async () => undefined);

    const session = await startBrowserSandboxSession(
      {
        provider: 'novnc',
        accessMode: 'external',
        accessBaseUrl: null,
        accessUrlTemplate: 'http://127.0.0.1::novncPort/vnc.html?autoconnect=1',
        accessPathTemplate: '/sessions/:jobId',
        startCommandTemplate: 'start-session --job :jobId --target :url --access :accessUrl --display :displayNumber --vnc :vncPort --novnc :novncPort --dir :sessionDir',
        stopCommandTemplate: 'stop-session --job :jobId',
      },
      {
        jobId: 'sandbox_job_123',
        url: 'https://example.org/login',
      },
      runCommand,
    );

    expect(runCommand).toHaveBeenCalledWith(
      expect.stringContaining('start-session --job sandbox_job_123 --target "https://example.org/login" --access "http://127.0.0.1:'),
    );
    expect(session.status).toBe('ready');
    expect(session.access.url).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/vnc\.html\?autoconnect=1$/);
    expect(session.runtime.sessionDirectory).toContain('sandbox_job_123');
  });

  it('stops a ready session and executes the configured stop command', async () => {
    const runCommand = vi.fn(async () => undefined);

    const stoppedSession = await stopBrowserSandboxSession(
      {
        provider: 'novnc',
        accessMode: 'external',
        accessBaseUrl: null,
        accessUrlTemplate: 'http://127.0.0.1::novncPort/vnc.html?autoconnect=1',
        accessPathTemplate: '/sessions/:jobId',
        startCommandTemplate: null,
        stopCommandTemplate: 'stop-session --job :jobId --access :accessUrl',
      },
      {
        provider: 'novnc',
        sessionId: 'sandbox_job_123',
        status: 'ready',
        startedAt: '2026-04-11T18:00:00.000Z',
        stoppedAt: null,
        runtime: {
          displayNumber: 101,
          vncPort: 5901,
          novncPort: 7601,
          sessionDirectory: '/tmp/sandbox_job_123',
        },
        access: {
          mode: 'external',
          url: 'http://127.0.0.1:7601/vnc.html?autoconnect=1',
          note: 'Live Chromium access is exposed through the novnc provider.',
        },
      },
      {
        jobId: 'sandbox_job_123',
        url: 'https://example.org/login',
      },
      runCommand,
    );

    expect(runCommand).toHaveBeenCalledWith(
      'stop-session --job sandbox_job_123 --access "http://127.0.0.1:7601/vnc.html?autoconnect=1"',
    );
    expect(stoppedSession.status).toBe('stopped');
    expect(stoppedSession.stoppedAt).not.toBeNull();
  });
});