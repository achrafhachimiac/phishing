import { describe, expect, it } from 'vitest';

import { analyzeEmail } from './services/email-analysis.js';

const sampleRawEmail = `Return-Path: <bounce@mailer.secure-example.test>
From: Alerts Team <alerts@secure-example.test>
To: victim@example.org
Subject: Urgent account review
Date: Tue, 08 Apr 2026 10:00:00 +0000
Message-ID: <abc@example.test>
Authentication-Results: mx.example.org; spf=fail smtp.mailfrom=secure-example.test; dkim=pass header.d=secure-example.test; dmarc=fail action=quarantine header.from=secure-example.test
Received: from mail.secure-example.test (203.0.113.50)
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Please review your account immediately:
https://secure-example.test/login
`;

describe('analyzeEmail', () => {
  it('builds a deterministic threat report from the parsed email evidence', async () => {
    const result = await analyzeEmail(sampleRawEmail, {
      analyzeRelatedDomain: async (domain) => ({
        domain,
        normalizedDomain: domain,
        score: domain.includes('secure-example') ? 82 : 15,
        riskLevel: domain.includes('secure-example') ? 'HIGH' : 'LOW',
        summary: `Synthetic intelligence for ${domain}`,
        dns: {
          a: ['203.0.113.10'],
          aaaa: [],
          mx: [],
          ns: [`ns1.${domain}`],
          txt: ['v=spf1 -all'],
          caa: [],
          soa: null,
        },
        rdap: {
          registrar: 'Test Registrar',
          createdAt: '2026-04-01T00:00:00.000Z',
          updatedAt: null,
          expiresAt: null,
        },
        mailSecurity: {
          spf: {
            present: true,
            record: 'v=spf1 -all',
            mode: '-all',
          },
          dmarc: {
            present: false,
            record: null,
            policy: null,
          },
          mtaSts: {
            present: false,
            record: null,
          },
          tlsRpt: {
            present: false,
            record: null,
          },
        },
        infrastructure: {
          ipAddresses: ['203.0.113.10'],
          ipIntelligence: [],
          tls: null,
        },
        history: {
          waybackSnapshots: 0,
          firstSeen: null,
          lastSeen: null,
        },
        certificates: {
          certificateTransparency: {
            certificateCount: 0,
            observedSubdomains: [],
            observedCertificates: [],
          },
        },
        reputation: {
          alienVault: {
            status: 'clean',
            pulseCount: 0,
            reference: null,
          },
          virustotal: {
            status: 'not_configured',
            malicious: null,
            suspicious: null,
            reference: null,
          },
          urlscan: {
            status: 'not_configured',
            resultUrl: null,
          },
          abuseIpDb: {
            status: 'not_configured',
            confidenceScore: null,
            reports: null,
            reference: null,
          },
          urlhausHost: {
            status: 'not_listed',
            reference: null,
            urls: [],
          },
        },
        riskFactors: ['Suspicious keyword detected: secure'],
        osint: {
          virustotal: `https://www.virustotal.com/gui/domain/${domain}`,
          urlscan: `https://urlscan.io/search/#domain:${domain}`,
          viewdns: `https://viewdns.info/reverseip/?host=${domain}&t=1`,
          crtSh: `https://crt.sh/?q=${domain}`,
          wayback: `https://web.archive.org/web/*/${domain}`,
          dnsdumpster: 'https://dnsdumpster.com/',
          builtwith: `https://builtwith.com/${domain}`,
          alienVault: `https://otx.alienvault.com/indicator/domain/${domain}`,
          abuseIpDb: 'https://www.abuseipdb.com/',
          urlhausHost: `https://urlhaus.abuse.ch/browse.php?search=${domain}`,
        },
      }),
    });

    expect(result.threatLevel).toBe('HIGH');
    expect(result.inconsistencies).toEqual(
      expect.arrayContaining([
        expect.stringContaining('SPF failed'),
        expect.stringContaining('DMARC failed'),
      ]),
    );
    expect(result.executiveSummary).toMatch(/authentication/i);
    expect(result.urls[0]).toEqual(
      expect.objectContaining({
        suspicious: true,
      }),
    );
    expect(result.relatedDomains).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          domain: 'secure-example.test',
          relation: 'url',
          analysis: expect.objectContaining({
            riskLevel: 'HIGH',
          }),
        }),
      ]),
    );
  });

  it('surfaces explicit auth failure reasons and Barracuda wrapper analysis', async () => {
    const result = await analyzeEmail(`Return-Path: <bounce@mailer.secure-example.test>
From: Alerts Team <alerts@secure-example.test>
To: victim@example.org
Subject: Review document
Authentication-Results: mx.example.org; spf=pass smtp.mailfrom=secure-example.test; dkim=fail (No key [DKIM DNS record not found]) header.d=tournoi7decoeur.com; dmarc=fail action=reject header.from=secure-example.test

Open:
https://linkprotect.cudasvc.com/url?a=https%3A%2F%2Ftournoi7decoeur.com%2Fwp-content%2Fuploads%2F2026%2F03%2Fbrochure.pdf&c=E,1,test
`, {
      analyzeRelatedDomain: async (domain) => ({
        domain,
        normalizedDomain: domain,
        score: 15,
        riskLevel: 'LOW',
        summary: `Synthetic intelligence for ${domain}`,
        dns: { a: [], aaaa: [], mx: [], ns: [], txt: [], caa: [], soa: null },
        rdap: { registrar: null, createdAt: null, updatedAt: null, expiresAt: null },
        mailSecurity: {
          spf: { present: false, record: null, mode: null },
          dmarc: { present: false, record: null, policy: null },
          mtaSts: { present: false, record: null },
          tlsRpt: { present: false, record: null },
        },
        infrastructure: { ipAddresses: [], ipIntelligence: [], tls: null },
        history: { waybackSnapshots: 0, firstSeen: null, lastSeen: null },
        certificates: { certificateTransparency: { certificateCount: 0, observedSubdomains: [], observedCertificates: [] } },
        reputation: {
          alienVault: { status: 'clean', pulseCount: 0, reference: null },
          virustotal: { status: 'not_configured', malicious: null, suspicious: null, reference: null },
          urlscan: { status: 'not_configured', resultUrl: null },
          abuseIpDb: { status: 'not_configured', confidenceScore: null, reports: null, reference: null },
          urlhausHost: { status: 'not_listed', reference: null, urls: [] },
        },
        riskFactors: [],
        osint: {
          virustotal: `https://www.virustotal.com/gui/domain/${domain}`,
          urlscan: `https://urlscan.io/search/#domain:${domain}`,
          viewdns: `https://viewdns.info/reverseip/?host=${domain}&t=1`,
          crtSh: `https://crt.sh/?q=${domain}`,
          wayback: `https://web.archive.org/web/*/${domain}`,
          dnsdumpster: 'https://dnsdumpster.com/',
          builtwith: `https://builtwith.com/${domain}`,
          alienVault: `https://otx.alienvault.com/indicator/domain/${domain}`,
          abuseIpDb: 'https://www.abuseipdb.com/',
          urlhausHost: `https://urlhaus.abuse.ch/browse.php?search=${domain}`,
        },
      }),
    });

    expect(result.inconsistencies).toEqual(
      expect.arrayContaining([
        'DKIM failed: No key [DKIM DNS record not found].',
        'DMARC failed for the visible sender domain (action=reject).',
      ]),
    );
    expect(result.urls[0]).toEqual(expect.objectContaining({ wrapperType: 'barracuda', suspicious: true }));
    expect(result.urls[0].reason).toMatch(/Barracuda LinkProtect/i);
  });
});