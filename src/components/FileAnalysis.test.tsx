// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { FileAnalysis } from './FileAnalysis';

describe('FileAnalysis', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    cleanup();
  });

  it('uploads a file, polls the backend, and renders the static analysis verdict', async () => {
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          jobId: 'file_job_123',
          status: 'queued',
          queuedFiles: ['invoice.pdf'],
          results: [],
        }),
      } as Response)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          jobId: 'file_job_123',
          status: 'running',
          queuedFiles: ['invoice.pdf'],
          results: [
            {
              filename: 'invoice.pdf',
              contentType: 'application/pdf',
              detectedType: 'pdf',
              extension: 'pdf',
              size: 128,
              sha256: 'abc123',
              extractedUrls: ['https://evil.example/login'],
              indicators: [
                {
                  kind: 'pdf_javascript',
                  severity: 'high',
                  value: 'Embedded PDF JavaScript markers found',
                },
              ],
              riskScoreBreakdown: {
                totalScore: 40,
                thresholds: {
                  suspicious: 25,
                  malicious: 70,
                },
                factors: [
                  {
                    label: 'PDF JavaScript',
                    severity: 'high',
                    contribution: 40,
                    evidence: 'Embedded PDF JavaScript markers found',
                  },
                ],
              },
              riskScore: 40,
              iocEnrichment: {
                status: 'pending',
                extractedUrls: ['https://evil.example/login'],
                extractedDomains: ['evil.example'],
                results: [],
                summary: 'IOC enrichment queued for extracted URLs and derived domains.',
                updatedAt: null,
              },
              verdict: 'suspicious',
              summary: 'Static analysis found 1 suspicious indicator.',
              storagePath: 'storage/uploads/file_job_123/00-invoice.pdf',
              externalScans: {
                virustotal: {
                  status: 'pending',
                  malicious: null,
                  suspicious: null,
                  reference: null,
                },
                clamav: {
                  status: 'malicious',
                  signature: 'Win.Test.EICAR',
                  engine: 'ClamAV',
                  detail: 'invoice.pdf: Win.Test.EICAR FOUND',
                },
                yara: {
                  status: 'match',
                  rules: ['suspicious_pdf'],
                  detail: null,
                },
              },
              parserReports: [
                {
                  parser: 'pdf',
                  summary: 'PDF parser found 1 object(s) and 1 auto-action marker(s).',
                  details: ['Embedded URLs: 1', 'JavaScript markers: present'],
                  snippets: ['1 0 obj << /JavaScript /JS (app.alert("phish")) >>'],
                },
              ],
              artifacts: [
                {
                  type: 'upload',
                  label: 'invoice.pdf',
                  path: 'storage/uploads/file_job_123/00-invoice.pdf',
                  mimeType: 'application/pdf',
                  size: 128,
                },
              ],
            },
          ],
        }),
      } as Response)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
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
              extractedUrls: ['https://evil.example/login'],
              indicators: [
                {
                  kind: 'pdf_javascript',
                  severity: 'high',
                  value: 'Embedded PDF JavaScript markers found',
                },
              ],
              riskScoreBreakdown: {
                totalScore: 40,
                thresholds: {
                  suspicious: 25,
                  malicious: 70,
                },
                factors: [
                  {
                    label: 'PDF JavaScript',
                    severity: 'high',
                    contribution: 40,
                    evidence: 'Embedded PDF JavaScript markers found',
                  },
                ],
              },
              riskScore: 40,
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
                    summary: 'https://evil.example/login flagged by URLhaus, AlienVault OTX.',
                    providerResults: [
                      {
                        provider: 'urlhaus',
                        status: 'listed',
                        detail: 'phishing',
                        reference: 'https://urlhaus.example/report',
                      },
                      {
                        provider: 'alienvault',
                        status: 'listed',
                        detail: '3 pulse(s)',
                        reference: 'https://otx.example/report',
                      },
                    ],
                  },
                ],
                summary: '1 malicious and 0 suspicious IOC found across extracted URLs and domains.',
                updatedAt: '2026-04-12T12:00:00.000Z',
              },
              verdict: 'suspicious',
              summary: 'Static analysis found 1 suspicious indicator.',
              storagePath: 'storage/uploads/file_job_123/00-invoice.pdf',
              externalScans: {
                virustotal: {
                  status: 'unavailable',
                  malicious: null,
                  suspicious: null,
                  reference: null,
                },
                clamav: {
                  status: 'malicious',
                  signature: 'Win.Test.EICAR',
                  engine: 'ClamAV',
                  detail: 'invoice.pdf: Win.Test.EICAR FOUND',
                },
                yara: {
                  status: 'match',
                  rules: ['suspicious_pdf'],
                  detail: null,
                },
              },
              parserReports: [
                {
                  parser: 'pdf',
                  summary: 'PDF parser found 1 object(s) and 1 auto-action marker(s).',
                  details: ['Embedded URLs: 1', 'JavaScript markers: present'],
                  snippets: ['1 0 obj << /JavaScript /JS (app.alert("phish")) >>'],
                },
              ],
              artifacts: [
                {
                  type: 'upload',
                  label: 'invoice.pdf',
                  path: 'storage/uploads/file_job_123/00-invoice.pdf',
                  mimeType: 'application/pdf',
                  size: 128,
                },
              ],
            },
          ],
        }),
      } as Response);

    render(<FileAnalysis />);

    const input = screen.getByLabelText(/upload files for static analysis/i) as HTMLInputElement;
    const file = new File(['%PDF-1.7 /JavaScript https://evil.example/login'], 'invoice.pdf', {
      type: 'application/pdf',
    });

    fireEvent.change(input, { target: { files: [file] } });
    fireEvent.click(screen.getByRole('button', { name: /analyze files/i }));

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenNthCalledWith(1, '/api/analyze/files', expect.objectContaining({
        method: 'POST',
      }));
      expect(globalThis.fetch).toHaveBeenNthCalledWith(2, '/api/analyze/files/file_job_123', expect.anything());
      expect(globalThis.fetch).toHaveBeenNthCalledWith(3, '/api/analyze/files/file_job_123', expect.anything());
      expect(screen.getAllByText((_, element) => element?.textContent?.includes('completed [file_job_123]') ?? false).length).toBeGreaterThan(0);
    });

    expect(screen.getAllByText(/invoice.pdf/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/suspicious/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/embedded pdf javascript markers found/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/https:\/\/evil.example\/login/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/clamav:/i)).toBeInTheDocument();
    expect(screen.getAllByText('malicious').length).toBeGreaterThan(0);
    expect(screen.getByText(/yara:/i)).toBeInTheDocument();
    expect(screen.getByText('match')).toBeInTheDocument();
    expect(screen.getByText(/risk score breakdown/i)).toBeInTheDocument();
    expect(screen.getByText(/suspicious at 25\+ points/i)).toBeInTheDocument();
    expect(screen.getByText(/ioc enrichment/i)).toBeInTheDocument();
    expect(screen.getByText(/1 malicious and 0 suspicious ioc/i)).toBeInTheDocument();
    expect(screen.getAllByText(/urlhaus/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/specialized parsers/i)).toBeInTheDocument();
    expect(screen.getByText(/detected code \/ snippets/i)).toBeInTheDocument();
    expect(screen.getByText(/app.alert\("phish"\)/i)).toBeInTheDocument();
  });

  it('renders archive tree details when the parser report includes extracted tree metadata', async () => {
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          jobId: 'file_job_tree',
          status: 'queued',
          queuedFiles: ['bundle.zip'],
          results: [],
        }),
      } as Response)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          jobId: 'file_job_tree',
          status: 'completed',
          queuedFiles: ['bundle.zip'],
          results: [
            {
              filename: 'bundle.zip',
              contentType: 'application/zip',
              detectedType: 'zip',
              extension: 'zip',
              size: 256,
              sha256: 'tree123',
              extractedUrls: [],
              indicators: [
                {
                  kind: 'archive',
                  severity: 'medium',
                  value: 'Archive container detected',
                },
              ],
              riskScoreBreakdown: {
                totalScore: 20,
                thresholds: {
                  suspicious: 25,
                  malicious: 70,
                },
                factors: [
                  {
                    label: 'Archive Container',
                    severity: 'medium',
                    contribution: 20,
                    evidence: 'Archive container detected',
                  },
                ],
              },
              riskScore: 20,
              iocEnrichment: {
                status: 'completed',
                extractedUrls: [],
                extractedDomains: [],
                results: [],
                summary: 'No enrichable URLs or domains were extracted from this file.',
                updatedAt: '2026-04-12T12:00:00.000Z',
              },
              verdict: 'clean',
              summary: 'Archive inspected successfully.',
              storagePath: 'storage/uploads/file_job_tree/00-bundle.zip',
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
                  engine: 'ClamAV',
                  detail: null,
                },
                yara: {
                  status: 'clean',
                  rules: [],
                  detail: null,
                },
              },
              parserReports: [
                {
                  parser: 'archive',
                  summary: 'Archive parser inspected 2 extracted entries.',
                  details: ['Entries: 2', 'Max depth: 2'],
                  snippets: [],
                  extractedTree: {
                    totalEntries: 2,
                    maxDepth: 2,
                    totalExtractedSize: 128,
                    truncated: false,
                    warnings: [],
                    root: {
                      path: 'bundle.zip',
                      filename: 'bundle.zip',
                      isDirectory: true,
                      size: null,
                      detectedType: 'archive',
                      indicators: [],
                      children: [
                        {
                          path: 'docs',
                          filename: 'docs',
                          isDirectory: true,
                          size: null,
                          detectedType: null,
                          indicators: [],
                          children: [
                            {
                              path: 'docs/readme.txt',
                              filename: 'readme.txt',
                              isDirectory: false,
                              size: 5,
                              detectedType: 'txt',
                              indicators: [],
                              children: [],
                            },
                          ],
                        },
                        {
                          path: 'payload.js',
                          filename: 'payload.js',
                          isDirectory: false,
                          size: 25,
                          detectedType: 'script',
                          indicators: [
                            {
                              kind: 'suspicious_script',
                              severity: 'high',
                              value: 'eval(',
                            },
                          ],
                          children: [],
                        },
                      ],
                    },
                  },
                },
              ],
              artifacts: [
                {
                  type: 'upload',
                  label: 'bundle.zip',
                  path: 'storage/uploads/file_job_tree/00-bundle.zip',
                  mimeType: 'application/zip',
                  size: 256,
                },
              ],
            },
          ],
        }),
      } as Response);

    render(<FileAnalysis />);

    const input = screen.getByLabelText(/upload files for static analysis/i) as HTMLInputElement;
    const file = new File(['fake zip'], 'bundle.zip', {
      type: 'application/zip',
    });

    fireEvent.change(input, { target: { files: [file] } });
    fireEvent.click(screen.getByRole('button', { name: /analyze files/i }));

    await waitFor(() => {
      expect(screen.getByText(/archive tree/i)).toBeInTheDocument();
    });

    expect(screen.getAllByText(/entries: 2/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/docs\/readme.txt/i)).toBeInTheDocument();
    expect(screen.getByText(/payload.js/i)).toBeInTheDocument();
    expect(screen.getByText(/suspicious script: eval\(/i)).toBeInTheDocument();
  });
});