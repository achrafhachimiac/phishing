import fs from 'node:fs';
import path from 'node:path';

import request from 'supertest';
import { describe, expect, it } from 'vitest';

import { createApp } from './app.js';
import { appConfig } from './config.js';

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

  it('serves the frontend entrypoint from the release dist directory', async () => {
    const clientDistPath = path.resolve(appConfig.storageRoot, '..', 'dist');
    const clientEntryPath = path.join(clientDistPath, 'index.html');
    const originalIndexHtml = fs.existsSync(clientEntryPath)
      ? fs.readFileSync(clientEntryPath, 'utf8')
      : null;
    const testIndexHtml = '<!doctype html><html><body><div>frontend regression test</div></body></html>';

    fs.mkdirSync(clientDistPath, { recursive: true });
    fs.writeFileSync(clientEntryPath, testIndexHtml, 'utf8');

    try {
      const app = createApp();

      const response = await request(app).get('/');

      expect(response.status).toBe(200);
      expect(response.headers['content-type']).toContain('text/html');
      expect(response.text).toContain('frontend regression test');
    } finally {
      if (originalIndexHtml === null) {
        fs.rmSync(clientEntryPath, { force: true });
      } else {
        fs.writeFileSync(clientEntryPath, originalIndexHtml, 'utf8');
      }
    }
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

  it('creates a browser sandbox job and returns its initial state', async () => {
    const app = createApp({
      enqueueBrowserSandboxJob: async () => ({
        jobId: 'sandbox_job_123',
        status: 'queued',
        requestedUrl: 'https://example.org/',
        expiresAt: '2026-04-11T12:15:00.000Z',
        session: null,
        result: null,
      }),
    });

    const response = await request(app)
      .post('/api/sandbox/browser')
      .send({ url: 'https://example.org' });

    expect(response.status).toBe(202);
    expect(response.body.jobId).toBe('sandbox_job_123');
    expect(response.body.status).toBe('queued');
  });

  it('stops a browser sandbox job by id', async () => {
    const app = createApp({
      stopBrowserSandboxJob: async () => ({
        jobId: 'sandbox_job_123',
        status: 'stopped',
        requestedUrl: 'https://example.org/',
        expiresAt: '2026-04-11T12:15:00.000Z',
        session: {
          provider: 'novnc',
          sessionId: 'sandbox_job_123',
          status: 'stopped',
          startedAt: '2026-04-11T12:00:00.000Z',
          stoppedAt: '2026-04-11T12:02:00.000Z',
          runtime: {
            displayNumber: 101,
            vncPort: 5901,
            novncPort: 7601,
            sessionDirectory: 'storage/sandbox-sessions/sandbox_job_123',
          },
          access: {
            mode: 'none',
            url: null,
            note: 'Stopped by analyst.',
          },
        },
        result: {
          originalUrl: 'https://example.org/',
          finalUrl: null,
          title: null,
          session: {
            provider: 'novnc',
            sessionId: 'sandbox_job_123',
            status: 'stopped',
            startedAt: '2026-04-11T12:00:00.000Z',
            stoppedAt: '2026-04-11T12:02:00.000Z',
            runtime: {
              displayNumber: 101,
              vncPort: 5901,
              novncPort: 7601,
              sessionDirectory: 'storage/sandbox-sessions/sandbox_job_123',
            },
            access: {
              mode: 'none',
              url: null,
              note: 'Stopped by analyst.',
            },
          },
          access: {
            mode: 'none',
            url: null,
            note: 'Stopped by analyst.',
          },
          screenshotPath: null,
          tracePath: null,
          redirectChain: [],
          requestedDomains: [],
          scriptUrls: [],
          consoleErrors: [],
          downloads: [],
          artifacts: [],
          status: 'stopped',
          error: 'Sandbox session stopped by analyst.',
        },
      }),
    });

    const response = await request(app).post('/api/sandbox/browser/sandbox_job_123/stop');

    expect(response.status).toBe(200);
    expect(response.body.status).toBe('stopped');
    expect(response.body.result.status).toBe('stopped');
  });

  it('renews a browser sandbox live session heartbeat by id', async () => {
    const app = createApp({
      touchBrowserSandboxJob: async () => ({
        jobId: 'sandbox_job_123',
        status: 'completed',
        requestedUrl: 'https://example.org/',
        expiresAt: '2026-04-11T12:15:00.000Z',
        session: {
          provider: 'local-novnc',
          sessionId: 'sandbox_job_123',
          status: 'ready',
          startedAt: '2026-04-11T12:00:00.000Z',
          stoppedAt: null,
          runtime: {
            displayNumber: 101,
            vncPort: 5901,
            novncPort: 7601,
            sessionDirectory: 'storage/sandbox-sessions/sandbox_job_123',
          },
          access: {
            mode: 'embedded',
            url: 'https://fred.syntrix.ae/novnc/7601/vnc.html?autoconnect=1&resize=remote',
            note: 'Live Chromium access is exposed through the local-novnc provider.',
          },
        },
        result: {
          originalUrl: 'https://example.org/',
          finalUrl: 'https://example.org/',
          title: 'Example Domain',
          session: {
            provider: 'local-novnc',
            sessionId: 'sandbox_job_123',
            status: 'ready',
            startedAt: '2026-04-11T12:00:00.000Z',
            stoppedAt: null,
            runtime: {
              displayNumber: 101,
              vncPort: 5901,
              novncPort: 7601,
              sessionDirectory: 'storage/sandbox-sessions/sandbox_job_123',
            },
            access: {
              mode: 'embedded',
              url: 'https://fred.syntrix.ae/novnc/7601/vnc.html?autoconnect=1&resize=remote',
              note: 'Live Chromium access is exposed through the local-novnc provider.',
            },
          },
          access: {
            mode: 'embedded',
            url: 'https://fred.syntrix.ae/novnc/7601/vnc.html?autoconnect=1&resize=remote',
            note: 'Live Chromium access is exposed through the local-novnc provider.',
          },
          screenshotPath: null,
          tracePath: null,
          redirectChain: ['https://example.org/'],
          requestedDomains: ['example.org'],
          scriptUrls: [],
          consoleErrors: [],
          downloads: [],
          artifacts: [],
          status: 'completed',
          error: null,
        },
      }),
    });

    const response = await request(app).post('/api/sandbox/browser/sandbox_job_123/heartbeat');

    expect(response.status).toBe(200);
    expect(response.body.session.status).toBe('ready');
    expect(response.body.result.access.mode).toBe('embedded');
  });

  it('creates a file analysis job and returns its initial state', async () => {
    const app = createApp({
      enqueueFileAnalysisJob: async (files) => ({
        jobId: 'file_job_123',
        status: 'queued',
        queuedFiles: files.map((file) => file.filename),
        results: [],
      }),
    });

    const response = await request(app)
      .post('/api/analyze/files')
      .send({
        files: [
          {
            filename: 'invoice.pdf',
            contentBase64: Buffer.from('%PDF-1.7').toString('base64'),
            contentType: 'application/pdf',
          },
        ],
      });

    expect(response.status).toBe(202);
    expect(response.body.jobId).toBe('file_job_123');
    expect(response.body.queuedFiles).toEqual(['invoice.pdf']);
  });

  it('returns a file analysis job by id', async () => {
    const app = createApp({
      getFileAnalysisJob: async () => ({
        jobId: 'file_job_123',
        status: 'completed',
        queuedFiles: ['invoice.pdf'],
        results: [
          {
            filename: 'invoice.pdf',
            contentType: 'application/pdf',
            detectedType: 'pdf',
            extension: 'pdf',
            size: 128,
            sha256: 'abc123',
            extractedUrls: ['https://example.org'],
            indicators: [
              {
                kind: 'embedded_url',
                severity: 'medium',
                value: '1 embedded URL(s)',
              },
            ],
            parserReports: [
              {
                parser: 'pdf',
                summary: 'PDF parser found 1 object(s) and 0 auto-action marker(s).',
                details: ['Embedded URLs: 1'],
                snippets: [],
              },
            ],
            riskScore: 20,
            verdict: 'clean',
            summary: 'No high-confidence malicious indicators were found during static analysis.',
            storagePath: 'storage/uploads/file_job_123/00-invoice.pdf',
            artifacts: [
              {
                type: 'upload',
                label: 'invoice.pdf',
                path: 'storage/uploads/file_job_123/00-invoice.pdf',
                mimeType: 'application/pdf',
                size: 128,
              },
            ],
            externalScans: {
              virustotal: {
                status: 'unavailable',
                malicious: null,
                suspicious: null,
                reference: null,
              },
              clamav: {
                status: 'not_configured',
                signature: null,
                engine: null,
                detail: null,
              },
              yara: {
                status: 'not_configured',
                rules: [],
                detail: null,
              },
            },
          },
        ],
      }),
    });

    const response = await request(app).get('/api/analyze/files/file_job_123');

    expect(response.status).toBe(200);
    expect(response.body.status).toBe('completed');
    expect(response.body.results[0].detectedType).toBe('pdf');
  });
});