import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { appConfig } from './config.js';
import { lookupDomainReputation, lookupUrlThreatIntel } from './services/threat-intel.js';

describe('threat-intel abuse.ch integration', () => {
  const originalUrlhausKey = process.env.URLHAUS_AUTH_KEY;
  const previousCortexConfig = {
    ...appConfig.cortex,
    analyzers: { ...appConfig.cortex.analyzers },
  };

  beforeEach(() => {
    process.env.URLHAUS_AUTH_KEY = 'test-auth-key';
  });

  afterEach(() => {
    vi.restoreAllMocks();
    Object.assign(appConfig.cortex, {
      ...previousCortexConfig,
      analyzers: { ...previousCortexConfig.analyzers },
    });
    if (originalUrlhausKey === undefined) {
      delete process.env.URLHAUS_AUTH_KEY;
    } else {
      process.env.URLHAUS_AUTH_KEY = originalUrlhausKey;
    }
  });

  it('sends Auth-Key when querying URLhaus URL lookups', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input);
      if (url.includes('urlhaus-api.abuse.ch/v1/url/')) {
        expect(init?.headers).toEqual(
          expect.objectContaining({
            'Auth-Key': 'test-auth-key',
            'Content-Type': 'application/x-www-form-urlencoded',
          }),
        );

        return {
          ok: true,
          json: async () => ({
            query_status: 'ok',
            urlhaus_reference: 'https://urlhaus.abuse.ch/url/123/',
            url: 'https://example.test/login',
            tags: ['phishing'],
          }),
        } as Response;
      }

      if (url.includes('virustotal.com')) {
        return { ok: false, json: async () => ({}) } as Response;
      }

      if (url.includes('urlscan.io')) {
        return { ok: false, json: async () => ({}) } as Response;
      }

      if (url.includes('otx.alienvault.com')) {
        return { ok: false, json: async () => ({}) } as Response;
      }

      throw new Error(`Unexpected fetch: ${url}`);
    });

    const result = await lookupUrlThreatIntel('https://example.test/login');

    expect(fetchMock).toHaveBeenCalled();
    expect(result.urlhaus.status).toBe('listed');
    expect(result.urlhaus.reference).toBe('https://urlhaus.abuse.ch/url/123/');
  });

  it('includes Cortex URL enrichment when Cortex analyzers are configured', async () => {
    Object.assign(appConfig.cortex, {
      enabled: true,
      baseUrl: 'https://cortex.example.test',
      apiKey: 'top-secret',
      timeoutMs: 5000,
      analyzers: {
        eml: [],
        url: ['PhishTank_1'],
        domain: [],
        fileHash: [],
      },
    });

    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input);

      if (url.includes('urlhaus-api.abuse.ch/v1/url/')) {
        return { ok: false, json: async () => ({}) } as Response;
      }

      if (url.includes('virustotal.com') || url.includes('urlscan.io') || url.includes('otx.alienvault.com')) {
        return { ok: false, json: async () => ({}) } as Response;
      }

      if (url === 'https://cortex.example.test/api/analyzer/PhishTank_1/run') {
        expect(init?.headers).toEqual(expect.objectContaining({ Authorization: 'Bearer top-secret' }));
        return new Response(JSON.stringify({ id: 'cortex-job-1' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      if (url === 'https://cortex.example.test/api/job/cortex-job-1') {
        return new Response(JSON.stringify({
          id: 'cortex-job-1',
          status: 'Success',
          report: {
            summary: 'Phishing URL listed in Cortex analyzer.',
            taxonomies: [{ namespace: 'Cortex', predicate: 'URL', value: 'listed', level: 'malicious' }],
          },
        }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      throw new Error(`Unexpected fetch: ${url}`);
    });

    const result = await lookupUrlThreatIntel('https://example.test/login');

    expect(result.cortex).toEqual(expect.objectContaining({
      status: 'malicious',
      analyzerCount: 1,
      matchedAnalyzerCount: 1,
    }));
  });

  it('queries URLhaus host intelligence for domains with Auth-Key', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input);
      if (url.includes('urlhaus-api.abuse.ch/v1/host/')) {
        expect(init?.headers).toEqual(
          expect.objectContaining({
            'Auth-Key': 'test-auth-key',
            'Content-Type': 'application/x-www-form-urlencoded',
          }),
        );

        return {
          ok: true,
          json: async () => ({
            query_status: 'ok',
            urls: [
              {
                urlhaus_reference: 'https://urlhaus.abuse.ch/url/999/',
                url: 'http://example.test/dropper',
              },
            ],
          }),
        } as Response;
      }

      if (url.includes('otx.alienvault.com')) {
        return {
          ok: true,
          json: async () => ({ pulse_info: { count: 0 } }),
        } as Response;
      }

      if (url.includes('virustotal.com') || url.includes('urlscan.io')) {
        return { ok: false, json: async () => ({}) } as Response;
      }

      if (url.includes('abuseipdb.com')) {
        return { ok: false, json: async () => ({}) } as Response;
      }

      throw new Error(`Unexpected fetch: ${url}`);
    });

    const result = await lookupDomainReputation('example.test', ['203.0.113.10']);

    expect(fetchMock).toHaveBeenCalled();
    expect(result.urlhausHost.status).toBe('listed');
    expect(result.urlhausHost.urls).toEqual(['http://example.test/dropper']);
    expect(result.urlhausHost.reference).toBe('https://urlhaus.abuse.ch/url/999/');
  });
});