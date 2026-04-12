import path from 'node:path';

import { describe, expect, it } from 'vitest';

import { resolveBrowserSandboxRuntime } from './services/browser-sandbox-runtime.js';

describe('resolveBrowserSandboxRuntime', () => {
  it('maps a job id to a deterministic runtime slot', () => {
    const runtime = resolveBrowserSandboxRuntime('sandbox_job_123', path.join('storage', 'sandbox-sessions'));

    expect(runtime.displayNumber).toBeGreaterThanOrEqual(100);
    expect(runtime.vncPort).toBeGreaterThanOrEqual(5900);
    expect(runtime.novncPort).toBeGreaterThanOrEqual(7600);
    expect(runtime.cdpPort).toBeGreaterThanOrEqual(9200);
    expect(runtime.sessionDirectory).toContain(path.join('storage', 'sandbox-sessions', 'sandbox_job_123'));
  });

  it('returns the same ports for the same job id', () => {
    const first = resolveBrowserSandboxRuntime('sandbox_job_repeat', path.join('storage', 'sandbox-sessions'));
    const second = resolveBrowserSandboxRuntime('sandbox_job_repeat', path.join('storage', 'sandbox-sessions'));

    expect(second).toEqual(first);
  });
});