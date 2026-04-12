import { afterEach, describe, expect, it, vi } from 'vitest';

import { appConfig } from './config.js';
import {
  CortexClientError,
  getCortexJob,
  submitCortexAnalyzerJob,
  waitForCortexJobReport,
} from './services/cortex-client.js';

describe('cortex-client', () => {
  const previousCortexConfig = {
    ...appConfig.cortex,
    analyzers: {
      ...appConfig.cortex.analyzers,
    },
  };

  afterEach(() => {
    Object.assign(appConfig.cortex, {
      ...previousCortexConfig,
      analyzers: {
        ...previousCortexConfig.analyzers,
      },
    });
  });

  it('submits an analyzer run with Cortex auth headers', async () => {
    Object.assign(appConfig.cortex, {
      enabled: true,
      baseUrl: 'https://cortex.example.test',
      apiKey: 'top-secret',
    });
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(JSON.stringify({ id: 'job-123' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    );

    const result = await submitCortexAnalyzerJob({
      analyzerId: 'PhishTank_1',
      dataType: 'url',
      data: 'https://evil.example/login',
    }, {
      fetch: fetchMock,
    });

    expect(result).toEqual({ jobId: 'job-123' });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://cortex.example.test/api/analyzer/PhishTank_1/run',
      expect.objectContaining({
        method: 'POST',
        headers: {
          Authorization: 'Bearer top-secret',
          'Content-Type': 'application/json',
        },
      }),
    );
  });

  it('polls Cortex until the job succeeds and then returns the report', async () => {
    Object.assign(appConfig.cortex, {
      enabled: true,
      baseUrl: 'https://cortex.example.test',
      apiKey: 'top-secret',
      timeoutMs: 5000,
    });
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ id: 'job-123', status: 'Waiting' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ id: 'job-123', status: 'Success' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ full: 'report' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      );

    const result = await waitForCortexJobReport('job-123', { pollIntervalMs: 1 }, {
      fetch: fetchMock,
      wait: async () => undefined,
    });

    expect(result).toEqual({
      job: {
        id: 'job-123',
        status: 'Success',
        report: undefined,
      },
      report: { full: 'report' },
    });
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it('maps Cortex auth failures to a typed error', async () => {
    Object.assign(appConfig.cortex, {
      enabled: true,
      baseUrl: 'https://cortex.example.test',
      apiKey: 'bad-key',
    });

    await expect(getCortexJob('job-123', {
      fetch: vi.fn<typeof fetch>().mockResolvedValue(new Response('forbidden', { status: 403 })),
    })).rejects.toMatchObject({
      code: 'cortex_unauthorized',
      statusCode: 403,
    });
  });

  it('fails fast when Cortex is disabled', async () => {
    Object.assign(appConfig.cortex, {
      enabled: false,
      baseUrl: null,
      apiKey: null,
    });

    await expect(submitCortexAnalyzerJob({
      analyzerId: 'PhishTank_1',
      dataType: 'url',
      data: 'https://evil.example/login',
    })).rejects.toMatchObject({
      code: 'cortex_not_enabled',
      statusCode: null,
    });
  });
});