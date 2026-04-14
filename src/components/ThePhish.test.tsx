// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ThePhish } from './ThePhish';

describe('ThePhish', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    cleanup();
  });

  it('uploads an eml file, polls the backend, and renders the consolidated verdict', async () => {
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          jobId: 'job_eml_123',
          status: 'queued',
          filename: 'suspicious.eml',
          emailAnalysis: null,
          attachmentCount: 0,
          analyzedAttachmentCount: 0,
          ignoredAttachments: [],
          fileAnalysisJobId: null,
          attachmentResults: [],
          consolidatedThreatLevel: null,
          consolidatedRiskScore: null,
          executiveSummary: null,
          error: null,
        }),
      } as Response)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          jobId: 'job_eml_123',
          status: 'analyzing_files',
          filename: 'suspicious.eml',
          emailAnalysis: {
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
              spfDetails: {
                status: 'fail',
                reason: 'Envelope sender IP is not authorized',
                smtpMailFrom: 'secure-example.test',
                headerFrom: null,
                headerDomain: null,
                selector: null,
                action: null,
              },
              dkimDetails: {
                status: 'pass',
                reason: null,
                smtpMailFrom: null,
                headerFrom: null,
                headerDomain: 'secure-example.test',
                selector: null,
                action: null,
              },
              dmarcDetails: {
                status: 'fail',
                reason: null,
                smtpMailFrom: null,
                headerFrom: 'secure-example.test',
                headerDomain: null,
                selector: null,
                action: 'quarantine',
              },
            },
            urls: [],
            inconsistencies: ['SPF failed for the sending domain.'],
            threatLevel: 'HIGH',
            executiveSummary: 'The email contains multiple phishing indicators.',
            emailAddresses: ['alerts@secure-example.test', 'victim@example.org'],
            domains: ['secure-example.test', 'example.org'],
            ipAddresses: ['198.51.100.20'],
            attachments: [
              {
                filename: 'invoice.pdf',
                contentType: 'application/pdf',
                size: 32,
                checksum: null,
              },
            ],
            relatedDomains: [
              {
                domain: 'secure-example.test',
                relation: 'from',
                analysis: {
                  domain: 'secure-example.test',
                  normalizedDomain: 'secure-example.test',
                  score: 72,
                  riskLevel: 'HIGH',
                  summary: 'Domain has phishing-related reputation signals.',
                  dns: {
                    a: [],
                    aaaa: [],
                    mx: [],
                    ns: [],
                    txt: [],
                    caa: [],
                    soa: null,
                  },
                  rdap: {
                    registrar: null,
                    createdAt: null,
                    updatedAt: null,
                    expiresAt: null,
                  },
                  mailSecurity: {
                    spf: { present: false, record: null, mode: null },
                    dmarc: { present: false, record: null, policy: null },
                    mtaSts: { present: false, record: null },
                    tlsRpt: { present: false, record: null },
                  },
                  infrastructure: {
                    ipAddresses: [],
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
                    alienVault: { status: 'clean', pulseCount: null, reference: null },
                    virustotal: { status: 'clean', malicious: 0, suspicious: 0, reference: null },
                    urlscan: { status: 'not_configured', resultUrl: null },
                    abuseIpDb: { status: 'not_configured', confidenceScore: null, reports: null, reference: null },
                    urlhausHost: { status: 'not_listed', reference: null, urls: [] },
                    cortex: {
                      status: 'suspicious',
                      analyzerCount: 1,
                      matchedAnalyzerCount: 1,
                      summary: 'Cortex flagged domain as suspicious.',
                    },
                  },
                  riskFactors: ['Domain matched suspicious reputation feeds.'],
                  osint: {
                    virustotal: 'https://example.test/virustotal',
                    urlscan: 'https://example.test/urlscan',
                    viewdns: 'https://example.test/viewdns',
                    crtSh: 'https://example.test/crtsh',
                    wayback: 'https://example.test/wayback',
                    dnsdumpster: 'https://example.test/dnsdumpster',
                    builtwith: 'https://example.test/builtwith',
                    alienVault: 'https://example.test/otx',
                    abuseIpDb: 'https://example.test/abuseipdb',
                    urlhausHost: 'https://example.test/urlhaushost',
                  },
                },
              },
            ],
          },
          attachmentCount: 1,
          analyzedAttachmentCount: 1,
          ignoredAttachments: [],
          fileAnalysisJobId: 'file_job_123',
          attachmentResults: [],
          consolidatedThreatLevel: null,
          consolidatedRiskScore: null,
          executiveSummary: null,
          error: null,
        }),
      } as Response)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          jobId: 'job_eml_123',
          status: 'completed',
          filename: 'suspicious.eml',
          emailAnalysis: {
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
              spfDetails: {
                status: 'fail',
                reason: 'Envelope sender IP is not authorized',
                smtpMailFrom: 'secure-example.test',
                headerFrom: null,
                headerDomain: null,
                selector: null,
                action: null,
              },
              dkimDetails: {
                status: 'pass',
                reason: null,
                smtpMailFrom: null,
                headerFrom: null,
                headerDomain: 'secure-example.test',
                selector: null,
                action: null,
              },
              dmarcDetails: {
                status: 'fail',
                reason: null,
                smtpMailFrom: null,
                headerFrom: 'secure-example.test',
                headerDomain: null,
                selector: null,
                action: 'quarantine',
              },
            },
            urls: [
              {
                originalUrl: 'https://evil.example/login',
                decodedUrl: 'https://evil.example/login',
                suspicious: true,
                reason: 'Known credential harvesting pattern.',
              },
            ],
            inconsistencies: ['SPF failed for the sending domain.'],
            threatLevel: 'HIGH',
            executiveSummary: 'The email contains multiple phishing indicators.',
            emailAddresses: ['alerts@secure-example.test', 'victim@example.org'],
            domains: ['secure-example.test', 'example.org'],
            ipAddresses: ['198.51.100.20'],
            attachments: [
              {
                filename: 'invoice.pdf',
                contentType: 'application/pdf',
                size: 32,
                checksum: null,
              },
            ],
            relatedDomains: [
              {
                domain: 'secure-example.test',
                relation: 'from',
                analysis: {
                  domain: 'secure-example.test',
                  normalizedDomain: 'secure-example.test',
                  score: 72,
                  riskLevel: 'HIGH',
                  summary: 'Domain has phishing-related reputation signals.',
                  dns: {
                    a: [],
                    aaaa: [],
                    mx: [],
                    ns: [],
                    txt: [],
                    caa: [],
                    soa: null,
                  },
                  rdap: {
                    registrar: null,
                    createdAt: null,
                    updatedAt: null,
                    expiresAt: null,
                  },
                  mailSecurity: {
                    spf: { present: false, record: null, mode: null },
                    dmarc: { present: false, record: null, policy: null },
                    mtaSts: { present: false, record: null },
                    tlsRpt: { present: false, record: null },
                  },
                  infrastructure: {
                    ipAddresses: [],
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
                    alienVault: { status: 'clean', pulseCount: null, reference: null },
                    virustotal: { status: 'clean', malicious: 0, suspicious: 0, reference: null },
                    urlscan: { status: 'not_configured', resultUrl: null },
                    abuseIpDb: { status: 'not_configured', confidenceScore: null, reports: null, reference: null },
                    urlhausHost: { status: 'not_listed', reference: null, urls: [] },
                    cortex: {
                      status: 'suspicious',
                      analyzerCount: 1,
                      matchedAnalyzerCount: 1,
                      summary: 'Cortex flagged domain as suspicious.',
                    },
                  },
                  riskFactors: ['Domain matched suspicious reputation feeds.'],
                  osint: {
                    virustotal: 'https://example.test/virustotal',
                    urlscan: 'https://example.test/urlscan',
                    viewdns: 'https://example.test/viewdns',
                    crtSh: 'https://example.test/crtsh',
                    wayback: 'https://example.test/wayback',
                    dnsdumpster: 'https://example.test/dnsdumpster',
                    builtwith: 'https://example.test/builtwith',
                    alienVault: 'https://example.test/otx',
                    abuseIpDb: 'https://example.test/abuseipdb',
                    urlhausHost: 'https://example.test/urlhaushost',
                  },
                },
              },
            ],
          },
          attachmentCount: 1,
          analyzedAttachmentCount: 1,
          ignoredAttachments: [],
          fileAnalysisJobId: 'file_job_123',
          attachmentResults: [
            {
              filename: 'invoice.pdf',
              contentType: 'application/pdf',
              detectedType: 'pdf',
              extension: 'pdf',
              size: 32,
              sha256: 'deadbeef',
              extractedUrls: [],
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
                factors: [],
              },
              iocEnrichment: {
                status: 'completed',
                extractedUrls: ['https://evil.example/login'],
                extractedDomains: ['evil.example'],
                results: [
                  {
                    type: 'url',
                    value: 'https://evil.example/login',
                    derivedFrom: null,
                    verdict: 'malicious',
                    summary: 'Observable matched external phishing intelligence.',
                    providerResults: [
                      {
                        provider: 'virustotal',
                        status: 'malicious',
                        detail: '5 malicious, 1 suspicious engine verdict(s)',
                        reference: 'https://virustotal.example/report/abc',
                      },
                      {
                        provider: 'cortex',
                        status: 'malicious',
                        detail: 'Cortex URL analyzers confirmed the phishing hit.',
                        reference: null,
                      },
                    ],
                  },
                ],
                summary: '1 malicious IOC hit returned across extracted observables.',
                updatedAt: '2026-04-12T12:00:00.000Z',
              },
              verdict: 'malicious',
              summary: 'Suspicious PDF JavaScript present.',
              storagePath: 'storage/uploads/file_job_123/00-invoice.pdf',
              artifacts: [],
              externalScans: {
                virustotal: {
                  status: 'malicious',
                  malicious: 5,
                  suspicious: 1,
                  reference: 'https://virustotal.example/file/deadbeef',
                },
                cortex: {
                  status: 'malicious',
                  analyzerCount: 2,
                  matchedAnalyzerCount: 2,
                  summary: 'Cortex file-hash analyzers marked the sample malicious.',
                },
                clamav: {
                  status: 'malicious',
                  signature: 'Phishing.PDF.Invoice',
                  engine: null,
                  detail: null,
                },
                yara: {
                  status: 'match',
                  rules: ['phishing_invoice_pdf'],
                  detail: null,
                },
              },
            },
          ],
          consolidatedThreatLevel: 'CRITICAL',
          consolidatedRiskScore: 80,
          executiveSummary: 'Email threat HIGH. Attachments analyzed: 1, malicious: 1, suspicious: 0. Consolidated threat level: CRITICAL.',
          externalEnrichment: {
            status: 'completed',
            summary: 'Cortex analyzers processed 2 runs (2 completed, 0 failed, 0 unavailable).',
            email: [
              {
                provider: 'cortex',
                analyzerId: 'EmlParser_1',
                analyzerName: 'EmlParser_1',
                targetType: 'eml',
                target: 'suspicious.eml',
                status: 'completed',
                verdict: 'suspicious',
                summary: 'Analyzer extracted suspicious observables.',
                confidence: 70,
                reference: null,
                taxonomies: [
                  {
                    level: 'suspicious',
                    namespace: 'email',
                    predicate: 'classification',
                    value: 'phishing',
                  },
                ],
                artifacts: [
                  {
                    dataType: 'domain',
                    data: 'secure-example.test',
                    message: 'Sender domain extracted from the message.',
                    tags: ['sender'],
                  },
                ],
                rawReport: null,
              },
            ],
            observables: [
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
                taxonomies: [
                  {
                    level: 'malicious',
                    namespace: 'threat',
                    predicate: 'phishing',
                    value: 'confirmed',
                  },
                ],
                artifacts: [
                  {
                    dataType: 'domain',
                    data: 'evil.example',
                    message: 'Resolved phishing hostname.',
                    tags: ['ioc'],
                  },
                ],
                rawReport: null,
              },
            ],
            attachments: [],
            updatedAt: '2026-04-12T12:00:03.000Z',
          },
          error: null,
        }),
      } as Response);

    render(<ThePhish />);

    const file = new File(['From: alerts@secure-example.test'], 'suspicious.eml', {
      type: 'message/rfc822',
    });

    fireEvent.change(screen.getByLabelText(/upload \.eml evidence/i), { target: { files: [file] } });
    fireEvent.click(screen.getByRole('button', { name: /analyze eml/i }));

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenNthCalledWith(1, '/api/analyze/eml', expect.objectContaining({ method: 'POST' }));
      expect(globalThis.fetch).toHaveBeenNthCalledWith(2, '/api/analyze/eml/job_eml_123', expect.anything());
      expect(globalThis.fetch).toHaveBeenNthCalledWith(3, '/api/analyze/eml/job_eml_123', expect.anything());
    });

    expect(await screen.findByText(/consolidated threat level: critical/i)).toBeInTheDocument();
    expect(screen.getByText(/urgent invoice review/i)).toBeInTheDocument();
    expect(screen.getByText(/file analysis job: file_job_123/i)).toBeInTheDocument();
    expect(screen.getByText(/authentication/i)).toBeInTheDocument();
    expect(screen.getAllByText(/spf fail/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/envelope sender ip is not authorized/i)).toBeInTheDocument();
    expect(screen.getByText(/observable inventory/i)).toBeInTheDocument();
    expect(screen.getByText(/destination: https:\/\/evil.example\/login/i)).toBeInTheDocument();
    expect(screen.getByText(/related domains/i)).toBeInTheDocument();
    expect(screen.getByText(/domain has phishing-related reputation signals/i)).toBeInTheDocument();
    expect(screen.getByText(/external analyzer results/i)).toBeInTheDocument();
    expect(screen.getByText(/analyzer runs: 2/i)).toBeInTheDocument();
    expect(screen.getByText(/analyzer extracted suspicious observables/i)).toBeInTheDocument();
    expect(screen.getByText(/url found in phishing database/i)).toBeInTheDocument();
    expect(screen.getByText(/confidence: 90%/i)).toBeInTheDocument();
    expect(screen.getByText(/threat \/ phishing \/ confirmed/i)).toBeInTheDocument();
    expect(screen.getByText(/resolved phishing hostname/i)).toBeInTheDocument();
    expect(screen.getByText(/external scans/i)).toBeInTheDocument();
    expect(screen.getByText(/cortex file-hash analyzers marked the sample malicious/i)).toBeInTheDocument();
    expect(screen.getByText(/clamav signature: phishing.pdf.invoice/i)).toBeInTheDocument();
    expect(screen.getByText(/yara rules: phishing_invoice_pdf/i)).toBeInTheDocument();
    expect(screen.getByText(/ioc enrichment/i)).toBeInTheDocument();
    expect(screen.getByText(/observable matched external phishing intelligence/i)).toBeInTheDocument();
    expect(screen.getAllByText(/cortex malicious/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/invoice.pdf/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/malicious/i).length).toBeGreaterThan(0);
  });

  it('accepts a dropped .eml file and rejects non-eml uploads', async () => {
    render(<ThePhish />);

    const dropzone = screen.getByTestId('thephish-dropzone');
    const emlFile = new File(['From: alerts@secure-example.test'], 'dropped.eml', {
      type: 'message/rfc822',
    });

    fireEvent.dragOver(dropzone, {
      dataTransfer: { files: [emlFile] },
    });
    fireEvent.drop(dropzone, {
      dataTransfer: { files: [emlFile] },
    });

    expect(screen.getByText(/selected evidence:/i)).toBeInTheDocument();
    expect(screen.getByText(/dropped.eml/i)).toBeInTheDocument();

    const invalidFile = new File(['hello'], 'notes.txt', {
      type: 'text/plain',
    });

    fireEvent.change(screen.getByLabelText(/upload \.eml evidence/i), {
      target: { files: [invalidFile] },
    });

    expect(screen.getByText(/only \.eml evidence files are supported/i)).toBeInTheDocument();
  });

  it('renders ignored attachments with human-readable reasons and metadata', async () => {
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          jobId: 'job_eml_ignored',
          status: 'queued',
          filename: 'ignored.eml',
          emailAnalysis: null,
          attachmentCount: 0,
          analyzedAttachmentCount: 0,
          ignoredAttachments: [],
          fileAnalysisJobId: null,
          attachmentResults: [],
          consolidatedThreatLevel: null,
          consolidatedRiskScore: null,
          executiveSummary: null,
          error: null,
        }),
      } as Response)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          jobId: 'job_eml_ignored',
          status: 'completed',
          filename: 'ignored.eml',
          emailAnalysis: {
            headers: {
              from: 'alerts@secure-example.test',
              to: 'victim@example.org',
              subject: 'Ignored attachments test',
              date: 'Tue, 08 Apr 2026 10:00:00 +0000',
              messageId: '<ghi@example.test>',
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
          },
          attachmentCount: 4,
          analyzedAttachmentCount: 1,
          ignoredAttachments: [
            {
              filename: 'duplicate.pdf',
              contentType: 'application/pdf',
              size: 1024,
              reason: 'duplicate_attachment',
            },
            {
              filename: 'large.zip',
              contentType: 'application/zip',
              size: 10485760,
              reason: 'attachment_too_large',
            },
          ],
          fileAnalysisJobId: 'file_job_ignored',
          attachmentResults: [],
          consolidatedThreatLevel: 'LOW',
          consolidatedRiskScore: 10,
          executiveSummary: 'Email-only analysis completed with a consolidated threat level of LOW.',
          error: null,
        }),
      } as Response);

    render(<ThePhish />);

    const file = new File(['From: alerts@secure-example.test'], 'ignored.eml', {
      type: 'message/rfc822',
    });

    fireEvent.change(screen.getByLabelText(/upload \.eml evidence/i), { target: { files: [file] } });
    fireEvent.click(screen.getByRole('button', { name: /analyze eml/i }));

    expect((await screen.findAllByText(/ignored attachments/i)).length).toBeGreaterThan(0);
    expect(screen.getAllByText((_, element) => element?.textContent?.includes('1x duplicate') ?? false).length).toBeGreaterThan(0);
    expect(screen.getAllByText((_, element) => element?.textContent?.includes('1x too large') ?? false).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/duplicate.pdf/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText((_, element) => element?.textContent?.includes('Type: application/pdf') ?? false).length).toBeGreaterThan(0);
    expect(screen.getAllByText((_, element) => element?.textContent?.includes('Size: 1024 bytes') ?? false).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/large.zip/i).length).toBeGreaterThan(0);
  });
});