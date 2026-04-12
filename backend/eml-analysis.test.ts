import { describe, expect, it } from 'vitest';

import { createEmlAnalysisJob } from './services/eml-analysis.js';

const sampleRawEmail = `From: Alerts Team <alerts@secure-example.test>
To: victim@example.org
Subject: Urgent invoice review
Date: Tue, 08 Apr 2026 10:00:00 +0000
Message-ID: <abc@example.test>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="frontier"

--frontier
Content-Type: text/plain; charset=UTF-8

Please review the attached invoice immediately.

--frontier
Content-Type: application/pdf; name="invoice.pdf"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="invoice.pdf"

JVBERi0xLjcKL0phdmFTY3JpcHQgaHR0cHM6Ly9ldmlsLmV4YW1wbGUvbG9naW4K
--frontier--
`;

describe('createEmlAnalysisJob', () => {
  it('builds a consolidated EML result from email and attachment analysis', async () => {
    const job = await createEmlAnalysisJob('suspicious.eml', sampleRawEmail, {
      createJobId: () => 'job_eml_123',
      analyzeEmail: async () => ({
        headers: {
          from: 'alerts@secure-example.test',
          to: 'victim@example.org',
          subject: 'Urgent invoice review',
          date: 'Tue, 08 Apr 2026 10:00:00 +0000',
          messageId: '<abc@example.test>',
          returnPath: 'bounce@secure-example.test',
        },
        authentication: {
          spf: 'fail',
          dkim: 'pass',
          dmarc: 'fail',
        },
        urls: [
          {
            originalUrl: 'https://evil.example/login',
            decodedUrl: 'https://evil.example/login',
            suspicious: true,
            reason: 'Credential lure detected.',
          },
        ],
        inconsistencies: ['SPF failed for the sending domain.'],
        threatLevel: 'HIGH',
        executiveSummary: 'The email contains multiple phishing indicators.',
        emailAddresses: ['alerts@secure-example.test', 'victim@example.org'],
        domains: ['secure-example.test', 'example.org'],
        ipAddresses: ['203.0.113.50'],
        attachments: [
          {
            filename: 'invoice.pdf',
            contentType: 'application/pdf',
            size: 32,
            checksum: 'abc123',
          },
        ],
        relatedDomains: [],
      }),
      enqueueFileAnalysisJob: async () => ({
        jobId: 'file_job_123',
        status: 'queued',
        queuedFiles: ['invoice.pdf'],
        results: [],
      }),
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
            size: 32,
            sha256: 'deadbeef',
            extractedUrls: ['https://evil.example/login'],
            indicators: [
              {
                kind: 'pdf_javascript',
                severity: 'high',
                value: 'Embedded PDF JavaScript markers found',
              },
            ],
            parserReports: [],
            riskScore: 80,
            riskScoreBreakdown: {
              totalScore: 80,
              thresholds: { suspicious: 25, malicious: 70 },
              factors: [
                {
                  label: 'PDF JavaScript',
                  severity: 'high',
                  contribution: 40,
                  evidence: 'Embedded PDF JavaScript markers found',
                },
              ],
            },
            iocEnrichment: {
              status: 'completed',
              extractedUrls: ['https://evil.example/login'],
              extractedDomains: ['evil.example'],
              results: [],
              summary: 'No additional IOC hits returned.',
              updatedAt: '2026-04-12T12:00:00.000Z',
            },
            verdict: 'malicious',
            summary: 'Suspicious PDF JavaScript present.',
            storagePath: 'storage/uploads/file_job_123/00-invoice.pdf',
            artifacts: [],
            externalScans: {
              virustotal: {
                status: 'unavailable',
                malicious: null,
                suspicious: null,
                reference: null,
              },
              clamav: {
                status: 'clean',
                signature: null,
                engine: null,
                detail: null,
              },
              yara: {
                status: 'clean',
                rules: [],
                detail: null,
              },
            },
          },
        ],
      }),
      wait: async () => undefined,
    });

    expect(job.jobId).toBe('job_eml_123');
    expect(job.status).toBe('completed');
    expect(job.fileAnalysisJobId).toBe('file_job_123');
    expect(job.attachmentCount).toBe(1);
    expect(job.analyzedAttachmentCount).toBe(1);
    expect(job.consolidatedThreatLevel).toBe('CRITICAL');
    expect(job.attachmentResults[0].filename).toBe('invoice.pdf');
    expect(job.externalEnrichment?.status).toBe('unavailable');
  });

  it('completes without child file analysis when the email has no attachments', async () => {
    const job = await createEmlAnalysisJob('no-attachment.eml', 'From: alerts@secure-example.test', {
      createJobId: () => 'job_eml_456',
      parseEmailForAnalysis: async () => ({
        parsedEmail: {
          headers: {
            from: 'alerts@secure-example.test',
            to: 'victim@example.org',
            subject: 'No attachment',
            date: 'Tue, 08 Apr 2026 10:00:00 +0000',
            messageId: '<def@example.test>',
            returnPath: 'bounce@secure-example.test',
          },
          authentication: {
            spf: 'pass',
            dkim: 'pass',
            dmarc: 'pass',
          },
          urls: [],
          emailAddresses: ['alerts@secure-example.test', 'victim@example.org'],
          domains: ['secure-example.test', 'example.org'],
          ipAddresses: [],
          attachments: [],
        },
        attachmentUploads: [],
      }),
      analyzeEmail: async () => ({
        headers: {
          from: 'alerts@secure-example.test',
          to: 'victim@example.org',
          subject: 'No attachment',
          date: 'Tue, 08 Apr 2026 10:00:00 +0000',
          messageId: '<def@example.test>',
          returnPath: 'bounce@secure-example.test',
        },
        authentication: {
          spf: 'pass',
          dkim: 'pass',
          dmarc: 'pass',
        },
        urls: [],
        inconsistencies: [],
        threatLevel: 'LOW',
        executiveSummary: 'No major suspicious evidence detected.',
        emailAddresses: ['alerts@secure-example.test', 'victim@example.org'],
        domains: ['secure-example.test', 'example.org'],
        ipAddresses: [],
        attachments: [],
        relatedDomains: [],
      }),
      wait: async () => undefined,
    });

    expect(job.status).toBe('completed');
    expect(job.fileAnalysisJobId).toBeNull();
    expect(job.attachmentResults).toEqual([]);
    expect(job.consolidatedThreatLevel).toBe('LOW');
    expect(job.externalEnrichment?.attachments).toEqual([]);
  });

  it('aggregates Cortex enrichment results onto the EML job', async () => {
    const job = await createEmlAnalysisJob('with-cortex.eml', sampleRawEmail, {
      createJobId: () => 'job_eml_789',
      analyzeEmail: async () => ({
        headers: {
          from: 'alerts@secure-example.test',
          to: 'victim@example.org',
          subject: 'Urgent invoice review',
          date: 'Tue, 08 Apr 2026 10:00:00 +0000',
          messageId: '<abc@example.test>',
          returnPath: 'bounce@secure-example.test',
        },
        authentication: {
          spf: 'fail',
          dkim: 'pass',
          dmarc: 'fail',
        },
        urls: [
          {
            originalUrl: 'https://evil.example/login',
            decodedUrl: 'https://evil.example/login',
            suspicious: true,
            reason: 'Credential lure detected.',
          },
        ],
        inconsistencies: ['SPF failed for the sending domain.'],
        threatLevel: 'HIGH',
        executiveSummary: 'The email contains multiple phishing indicators.',
        emailAddresses: ['alerts@secure-example.test', 'victim@example.org'],
        domains: ['secure-example.test', 'evil.example'],
        ipAddresses: ['203.0.113.50'],
        attachments: [
          {
            filename: 'invoice.pdf',
            contentType: 'application/pdf',
            size: 32,
            checksum: 'abc123',
          },
        ],
        relatedDomains: [],
      }),
      enqueueFileAnalysisJob: async () => ({
        jobId: 'file_job_789',
        status: 'queued',
        queuedFiles: ['invoice.pdf'],
        results: [],
      }),
      getFileAnalysisJob: async () => ({
        jobId: 'file_job_789',
        status: 'completed',
        queuedFiles: ['invoice.pdf'],
        results: [
          {
            filename: 'invoice.pdf',
            contentType: 'application/pdf',
            detectedType: 'pdf',
            extension: 'pdf',
            size: 32,
            sha256: 'deadbeef',
            extractedUrls: ['https://evil.example/login'],
            indicators: [],
            parserReports: [],
            riskScore: 65,
            riskScoreBreakdown: {
              totalScore: 65,
              thresholds: { suspicious: 25, malicious: 70 },
              factors: [],
            },
            iocEnrichment: {
              status: 'completed',
              extractedUrls: ['https://evil.example/login'],
              extractedDomains: ['evil.example'],
              results: [],
              summary: 'No additional IOC hits returned.',
              updatedAt: '2026-04-12T12:00:00.000Z',
            },
            verdict: 'suspicious',
            summary: 'Suspicious embedded URL found.',
            storagePath: 'storage/uploads/file_job_789/00-invoice.pdf',
            artifacts: [],
            externalScans: {
              virustotal: {
                status: 'unavailable',
                malicious: null,
                suspicious: null,
                reference: null,
              },
              clamav: {
                status: 'clean',
                signature: null,
                engine: null,
                detail: null,
              },
              yara: {
                status: 'clean',
                rules: [],
                detail: null,
              },
            },
          },
        ],
      }),
      analyzeEmailWithCortex: async () => ({
        status: 'completed',
        summary: 'Cortex email analyzers completed successfully.',
        results: [
          {
            provider: 'cortex',
            analyzerId: 'EmlParser_1',
            analyzerName: 'EmlParser_1',
            targetType: 'eml',
            target: 'with-cortex.eml',
            status: 'completed',
            verdict: 'suspicious',
            summary: 'Analyzer extracted suspicious observables.',
            confidence: 70,
            reference: null,
            taxonomies: [],
            artifacts: [],
            rawReport: { summary: 'Analyzer extracted suspicious observables.' },
          },
        ],
        updatedAt: '2026-04-12T12:00:01.000Z',
      }),
      analyzeObservablesWithCortex: async () => ({
        status: 'completed',
        summary: 'Cortex observable analyzers completed successfully.',
        results: [
          {
            provider: 'cortex',
            analyzerId: 'PhishTank_1',
            analyzerName: 'PhishTank_1',
            targetType: 'url',
            target: 'https://evil.example/login',
            status: 'completed',
            verdict: 'malicious',
            summary: 'URL found in phishing database.',
            confidence: 90,
            reference: 'https://phishtank.example/report/1',
            taxonomies: [],
            artifacts: [],
            rawReport: { summary: 'URL found in phishing database.' },
          },
        ],
        updatedAt: '2026-04-12T12:00:02.000Z',
      }),
      analyzeFileHashesWithCortex: async () => ({
        status: 'completed',
        summary: 'Cortex file hash analyzers completed successfully.',
        results: [
          {
            provider: 'cortex',
            analyzerId: 'VirusTotal_GetReport_3_1',
            analyzerName: 'VirusTotal_GetReport_3_1',
            targetType: 'file_hash',
            target: 'invoice.pdf',
            status: 'completed',
            verdict: 'suspicious',
            summary: 'Hash has prior reputation hits.',
            confidence: 70,
            reference: null,
            taxonomies: [],
            artifacts: [],
            rawReport: { summary: 'Hash has prior reputation hits.' },
          },
        ],
        updatedAt: '2026-04-12T12:00:03.000Z',
      }),
      wait: async () => undefined,
    });

    expect(job.externalEnrichment?.status).toBe('completed');
    expect(job.externalEnrichment?.email).toHaveLength(1);
    expect(job.externalEnrichment?.observables).toHaveLength(1);
    expect(job.externalEnrichment?.attachments).toHaveLength(1);
    expect(job.externalEnrichment?.updatedAt).toBe('2026-04-12T12:00:03.000Z');
  });
});