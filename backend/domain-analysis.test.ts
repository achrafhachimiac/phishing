import { describe, expect, it, vi } from 'vitest';

import { analyzeDomain } from './services/domain-analysis.js';

describe('analyzeDomain', () => {
  it('normalizes the domain and computes a high-risk verdict for recent suspicious domains', async () => {
    const result = await analyzeDomain('HTTPS://Secure-Login-Update.com/path', {
      resolveDns: vi.fn(async (domain: string) => ({
        a: ['203.0.113.10'],
        aaaa: [],
        mx: [],
        ns: [`ns1.${domain}`],
        txt: ['v=spf1 -all'],
        caa: ['0 issue "letsencrypt.org"'],
        soa: `ns1.${domain} hostmaster.${domain} 2026040801 7200 3600 1209600 3600`,
      })),
      lookupRdap: vi.fn(async () => ({
        registrar: 'NameCheap, Inc.',
        createdAt: '2026-04-07T00:00:00.000Z',
        updatedAt: null,
        expiresAt: '2027-04-07T00:00:00.000Z',
      })),
      inspectTls: vi.fn(async () => ({
        issuer: 'Test CA',
        subject: 'CN=Secure-Login-Update.com',
        validFrom: '2026-04-07T00:00:00.000Z',
        validTo: '2026-07-07T00:00:00.000Z',
        subjectAltNames: ['secure-login-update.com', 'www.secure-login-update.com'],
      })),
      lookupIpIntelligence: vi.fn(async () => [
        {
          ip: '203.0.113.10',
          reverseDns: ['mail.secure-login-update.com'],
          country: 'US',
          city: 'Ashburn',
          asn: 'AS64500',
          organization: 'Example Hosting',
        },
      ]),
      lookupHistory: vi.fn(async () => ({
        waybackSnapshots: 1,
        firstSeen: '2026-04-07T12:00:00.000Z',
        lastSeen: '2026-04-07T12:00:00.000Z',
      })),
      lookupCertificateTransparency: vi.fn(async () => ({
        certificateCount: 2,
        observedSubdomains: ['www.secure-login-update.com', 'mail.secure-login-update.com'],
      })),
      lookupReputation: vi.fn(async () => ({
        alienVault: {
          status: 'listed' as const,
          pulseCount: 3,
          reference: 'https://otx.alienvault.com/indicator/domain/secure-login-update.com',
        },
        virustotal: {
          status: 'not_configured' as const,
          malicious: null,
          suspicious: null,
          reference: null,
        },
        urlscan: {
          status: 'not_configured' as const,
          resultUrl: null,
        },
        abuseIpDb: {
          status: 'not_configured' as const,
          confidenceScore: null,
          reports: null,
          reference: null,
        },
        urlhausHost: {
          status: 'listed' as const,
          reference: 'https://urlhaus.abuse.ch/url/999/',
          urls: ['http://secure-login-update.com/dropper'],
        },
      })),
      now: () => new Date('2026-04-08T00:00:00.000Z'),
    });

    expect(result.normalizedDomain).toBe('secure-login-update.com');
    expect(result.score).toBeGreaterThanOrEqual(70);
    expect(result.riskLevel).toBe('HIGH');
    expect(result.riskFactors).toEqual(
      expect.arrayContaining([
        expect.stringContaining('recent'),
        expect.stringContaining('keyword'),
        expect.stringContaining('No MX'),
        expect.stringContaining('No DMARC'),
        expect.stringContaining('AlienVault'),
        expect.stringContaining('URLhaus'),
      ]),
    );
    expect(result.mailSecurity.spf.present).toBe(true);
    expect(result.mailSecurity.spf.mode).toBe('-all');
    expect(result.mailSecurity.dmarc.present).toBe(false);
    expect(result.infrastructure.ipIntelligence[0].asn).toBe('AS64500');
    expect(result.history.waybackSnapshots).toBe(1);
    expect(result.certificates.certificateTransparency.certificateCount).toBe(2);
    expect(result.reputation.alienVault.status).toBe('listed');
    expect(result.reputation.urlhausHost.status).toBe('listed');
    expect(result.osint.virustotal).toContain('secure-login-update.com');
    expect(result.osint.wayback).toContain('secure-login-update.com');
  });

  it('rejects malformed domains before performing lookups', async () => {
    const resolveDns = vi.fn();

    await expect(
      analyzeDomain('ht!tp://bad domain', {
        resolveDns,
        lookupRdap: vi.fn(),
        inspectTls: vi.fn(),
        now: () => new Date('2026-04-08T00:00:00.000Z'),
      }),
    ).rejects.toMatchObject({
      code: 'invalid_domain',
    });

    expect(resolveDns).not.toHaveBeenCalled();
  });
});