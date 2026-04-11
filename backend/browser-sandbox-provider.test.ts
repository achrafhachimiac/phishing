import { describe, expect, it } from 'vitest';

import { buildBrowserSandboxAccess } from './services/browser-sandbox-provider.js';

describe('buildBrowserSandboxAccess', () => {
  it('returns a none access mode when no remote base url is configured', () => {
    const access = buildBrowserSandboxAccess(
      {
        provider: 'local-chromium',
        accessMode: 'none',
        accessBaseUrl: null,
        accessPathTemplate: ':jobId',
      },
      { jobId: 'sandbox_job_123' },
    );

    expect(access.mode).toBe('none');
    expect(access.url).toBeNull();
  });

  it('builds a live external access url when a remote provider is configured', () => {
    const access = buildBrowserSandboxAccess(
      {
        provider: 'novnc',
        accessMode: 'external',
        accessBaseUrl: 'https://sandbox.example.test/live',
        accessUrlTemplate: null,
        accessPathTemplate: '/sessions/:jobId',
      },
      { jobId: 'sandbox_job_123' },
    );

    expect(access).toEqual({
      mode: 'external',
      url: 'https://sandbox.example.test/live/sessions/sandbox_job_123',
      note: 'Live Chromium access is exposed through the novnc provider.',
    });
  });

  it('appends the job id when the path template does not contain :jobId', () => {
    const access = buildBrowserSandboxAccess(
      {
        provider: 'novnc',
        accessMode: 'embedded',
        accessBaseUrl: 'https://sandbox.example.test/live',
        accessUrlTemplate: null,
        accessPathTemplate: '/sessions',
      },
      { jobId: 'sandbox_job_456' },
    );

    expect(access.url).toBe('https://sandbox.example.test/live/sessions/sandbox_job_456');
  });

  it('builds a direct noVNC url from a full template with runtime placeholders', () => {
    const access = buildBrowserSandboxAccess(
      {
        provider: 'local-novnc',
        accessMode: 'external',
        accessBaseUrl: null,
        accessUrlTemplate: 'http://109.199.125.137::novncPort/vnc.html?autoconnect=1&resize=remote',
        accessPathTemplate: ':jobId',
      },
      {
        jobId: 'sandbox_job_789',
        novncPort: 7612,
      },
    );

    expect(access.url).toBe('http://109.199.125.137:7612/vnc.html?autoconnect=1&resize=remote');
  });

  it('auto-injects the WebSocket path for proxied noVNC URLs', () => {
    const access = buildBrowserSandboxAccess(
      {
        provider: 'local-novnc',
        accessMode: 'embedded',
        accessBaseUrl: null,
        accessUrlTemplate: 'https://fred.syntrix.ae/novnc/:novncPort/vnc.html?autoconnect=1&resize=remote',
        accessPathTemplate: ':jobId',
      },
      {
        jobId: 'sandbox_ws_01',
        novncPort: 7665,
      },
    );

    expect(access.url).toBe(
      'https://fred.syntrix.ae/novnc/7665/vnc.html?autoconnect=1&resize=remote&path=novnc%2F7665%2Fwebsockify',
    );
  });

  it('preserves an explicit path parameter in the noVNC URL template', () => {
    const access = buildBrowserSandboxAccess(
      {
        provider: 'local-novnc',
        accessMode: 'embedded',
        accessBaseUrl: null,
        accessUrlTemplate: 'https://example.test/novnc/:novncPort/vnc.html?autoconnect=1&path=custom/ws',
        accessPathTemplate: ':jobId',
      },
      {
        jobId: 'sandbox_ws_02',
        novncPort: 7700,
      },
    );

    expect(access.url).toBe('https://example.test/novnc/7700/vnc.html?autoconnect=1&path=custom/ws');
  });
});