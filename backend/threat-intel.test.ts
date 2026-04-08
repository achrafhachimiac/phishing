import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { lookupDomainReputation, lookupUrlThreatIntel } from './services/threat-intel.js';

describe('threat-intel abuse.ch integration', () => {
  const originalUrlhausKey = process.env.URLHAUS_AUTH_KEY;

  beforeEach(() => {
    process.env.URLHAUS_AUTH_KEY = 'test-auth-key';
  });

  afterEach(() => {
    vi.restoreAllMocks();
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