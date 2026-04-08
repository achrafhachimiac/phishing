import request from 'supertest';
import { describe, expect, it } from 'vitest';

import { createApp } from './app.js';

describe('backend app', () => {
  it('returns health status and storage paths', async () => {
    const app = createApp();

    const response = await request(app).get('/api/health');

    expect(response.status).toBe(200);
    expect(response.body.status).toBe('ok');
    expect(response.body.service).toBe('phish-hunter-osint-api');
    expect(response.body.storage).toEqual(
      expect.objectContaining({
        root: expect.any(String),
        reports: expect.any(String),
        screenshots: expect.any(String),
        traces: expect.any(String),
      }),
    );
  });

  it('returns a typed 404 payload for unknown routes', async () => {
    const app = createApp();

    const response = await request(app).get('/api/missing');

    expect(response.status).toBe(404);
    expect(response.body).toEqual({
      error: 'not_found',
      message: 'Route not found',
    });
  });

  it('returns a domain analysis payload for valid requests', async () => {
    const app = createApp({
      analyzeDomain: async (domain) => ({
        domain,
        normalizedDomain: domain,
        score: 82,
        riskLevel: 'HIGH',
        summary: 'Recently created domain with suspicious keyword patterns.',
        dns: {
          a: ['203.0.113.10'],
          aaaa: [],
          mx: [],
          ns: ['ns1.example.test'],
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
        riskFactors: ['Domain is very recent', 'Keyword "secure" detected'],
        osint: {
          virustotal: 'https://www.virustotal.com/gui/domain/secure-example.test',
          urlscan: 'https://urlscan.io/search/#domain:secure-example.test',
          viewdns: 'https://viewdns.info/reverseip/?host=secure-example.test&t=1',
          crtSh: 'https://crt.sh/?q=secure-example.test',
          wayback: 'https://web.archive.org/web/*/secure-example.test',
          dnsdumpster: 'https://dnsdumpster.com/',
          builtwith: 'https://builtwith.com/secure-example.test',
          alienVault: 'https://otx.alienvault.com/indicator/domain/secure-example.test',
          abuseIpDb: 'https://www.abuseipdb.com/',
          urlhausHost: 'https://urlhaus.abuse.ch/browse.php?search=secure-example.test',
        },
      }),
    });

    const response = await request(app)
      .post('/api/analyze/domain')
      .send({ domain: 'secure-example.test' });

    expect(response.status).toBe(200);
    expect(response.body.normalizedDomain).toBe('secure-example.test');
    expect(response.body.riskLevel).toBe('HIGH');
  });

  it('rejects invalid domain analysis requests', async () => {
    const app = createApp();

    const response = await request(app)
      .post('/api/analyze/domain')
      .send({ domain: 'not a domain' });

    expect(response.status).toBe(400);
    expect(response.body.error).toBe('invalid_domain');
  });

  it('returns parsed email evidence for valid raw email submissions', async () => {
    const app = createApp({
      parseEmail: async () => ({
        headers: {
          from: 'alerts@secure-example.test',
          to: 'victim@example.org',
          subject: 'Urgent account review',
          date: 'Tue, 08 Apr 2026 10:00:00 +0000',
          messageId: '<abc@example.test>',
          returnPath: '<bounce@mailer.secure-example.test>',
        },
        authentication: {
          spf: 'fail',
          dkim: 'pass',
          dmarc: 'fail',
        },
        urls: [
          {
            originalUrl: 'https://secure-example.test/login',
            decodedUrl: 'https://secure-example.test/login',
          },
        ],
        emailAddresses: ['alerts@secure-example.test', 'victim@example.org'],
        domains: ['secure-example.test', 'example.org'],
        ipAddresses: ['203.0.113.50'],
        attachments: [],
      }),
    });

    const response = await request(app)
      .post('/api/analyze/email/parse')
      .send({ rawEmail: 'From: alerts@secure-example.test' });

    expect(response.status).toBe(200);
    expect(response.body.headers.subject).toBe('Urgent account review');
    expect(response.body.authentication.spf).toBe('fail');
    expect(response.body.urls).toHaveLength(1);
  });

  it('rejects invalid email parsing requests', async () => {
    const app = createApp();

    const response = await request(app)
      .post('/api/analyze/email/parse')
      .send({ rawEmail: '' });

    expect(response.status).toBe(400);
    expect(response.body.error).toBe('invalid_email');
  });

  it('returns an enriched email analysis report', async () => {
    const app = createApp({
      analyzeEmail: async () => ({
        headers: {
          from: 'alerts@secure-example.test',
          to: 'victim@example.org',
          subject: 'Urgent account review',
          date: 'Tue, 08 Apr 2026 10:00:00 +0000',
          messageId: '<abc@example.test>',
          returnPath: 'bounce@mailer.secure-example.test',
        },
        authentication: {
          spf: 'fail',
          dkim: 'pass',
          dmarc: 'fail',
        },
        urls: [
          {
            originalUrl: 'https://secure-example.test/login',
            decodedUrl: 'https://secure-example.test/login',
            suspicious: true,
            reason: 'The domain uses urgent credential-themed wording.',
          },
        ],
        inconsistencies: ['SPF failed for the sending domain.', 'From and Return-Path domains are misaligned.'],
        threatLevel: 'HIGH',
        executiveSummary: 'The email shows authentication failures and urgent phishing indicators.',
        emailAddresses: ['alerts@secure-example.test', 'victim@example.org'],
        domains: ['secure-example.test', 'example.org'],
        ipAddresses: ['203.0.113.50'],
        attachments: [],
        relatedDomains: [
          {
            domain: 'secure-example.test',
            relation: 'url',
            analysis: {
              domain: 'secure-example.test',
              normalizedDomain: 'secure-example.test',
              score: 82,
              riskLevel: 'HIGH',
              summary: 'Recently created domain with suspicious keyword patterns.',
              dns: {
                a: ['203.0.113.10'],
                aaaa: [],
                mx: [],
                ns: ['ns1.secure-example.test'],
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
              riskFactors: ['Domain is very recent'],
              osint: {
                virustotal: 'https://www.virustotal.com/gui/domain/secure-example.test',
                urlscan: 'https://urlscan.io/search/#domain:secure-example.test',
                viewdns: 'https://viewdns.info/reverseip/?host=secure-example.test&t=1',
                crtSh: 'https://crt.sh/?q=secure-example.test',
                wayback: 'https://web.archive.org/web/*/secure-example.test',
                dnsdumpster: 'https://dnsdumpster.com/',
                builtwith: 'https://builtwith.com/secure-example.test',
                alienVault: 'https://otx.alienvault.com/indicator/domain/secure-example.test',
                abuseIpDb: 'https://www.abuseipdb.com/',
                urlhausHost: 'https://urlhaus.abuse.ch/browse.php?search=secure-example.test',
              },
            },
          },
        ],
      }),
    });

    const response = await request(app)
      .post('/api/analyze/email')
      .send({ rawEmail: 'From: alerts@secure-example.test' });

    expect(response.status).toBe(200);
    expect(response.body.threatLevel).toBe('HIGH');
    expect(response.body.inconsistencies).toHaveLength(2);
    expect(response.body.urls[0].suspicious).toBe(true);
    expect(response.body.relatedDomains[0].relation).toBe('url');
  });

  it('creates a URL analysis job and returns its initial state', async () => {
    const app = createApp({
      enqueueUrlAnalysis: async () => ({
        jobId: 'job_test_123',
        status: 'queued',
        queuedUrls: ['https://example.org'],
        results: [],
      }),
      getUrlAnalysisJob: async () => null,
    });

    const response = await request(app)
      .post('/api/analyze/urls')
      .send({ urls: ['https://example.org'] });

    expect(response.status).toBe(202);
    expect(response.body.jobId).toBe('job_test_123');
    expect(response.body.status).toBe('queued');
  });

  it('returns a URL analysis job by id', async () => {
    const app = createApp({
      enqueueUrlAnalysis: async () => ({
        jobId: 'unused',
        status: 'queued',
        queuedUrls: [],
        results: [],
      }),
      getUrlAnalysisJob: async () => ({
        jobId: 'job_test_123',
        status: 'completed',
        queuedUrls: ['https://example.org'],
        results: [
          {
            originalUrl: 'https://example.org',
            finalUrl: 'https://example.org/',
            title: 'Example Domain',
            screenshotPath: 'storage/screenshots/job_test_123/example-org.png',
            tracePath: 'storage/traces/job_test_123/example-org.zip',
            redirectChain: ['https://example.org', 'https://example.org/'],
            requestedDomains: ['example.org'],
            scriptUrls: [],
            consoleErrors: [],
            status: 'completed',
            error: null,
            externalScans: {
              urlhaus: {
                status: 'not_listed',
                reference: null,
                tags: [],
                permalink: null,
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
              alienVault: {
                status: 'unavailable',
                pulseCount: null,
                reference: null,
              },
            },
          },
        ],
      }),
    });

    const response = await request(app).get('/api/analyze/urls/job_test_123');

    expect(response.status).toBe(200);
    expect(response.body.status).toBe('completed');
    expect(response.body.results[0].title).toBe('Example Domain');
    expect(response.body.results[0].externalScans.urlhaus.status).toBe('not_listed');
    expect(response.body.results[0].tracePath).toContain('storage/traces');
  });
});