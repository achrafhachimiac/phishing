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
            },
            urls: [],
            inconsistencies: ['SPF failed for the sending domain.'],
            threatLevel: 'HIGH',
            executiveSummary: 'The email contains multiple phishing indicators.',
            emailAddresses: ['alerts@secure-example.test', 'victim@example.org'],
            domains: ['secure-example.test', 'example.org'],
            ipAddresses: [],
            attachments: [
              {
                filename: 'invoice.pdf',
                contentType: 'application/pdf',
                size: 32,
                checksum: null,
              },
            ],
            relatedDomains: [],
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
            },
            urls: [],
            inconsistencies: ['SPF failed for the sending domain.'],
            threatLevel: 'HIGH',
            executiveSummary: 'The email contains multiple phishing indicators.',
            emailAddresses: ['alerts@secure-example.test', 'victim@example.org'],
            domains: ['secure-example.test', 'example.org'],
            ipAddresses: [],
            attachments: [
              {
                filename: 'invoice.pdf',
                contentType: 'application/pdf',
                size: 32,
                checksum: null,
              },
            ],
            relatedDomains: [],
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
                extractedUrls: [],
                extractedDomains: [],
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
          consolidatedThreatLevel: 'CRITICAL',
          consolidatedRiskScore: 80,
          executiveSummary: 'Email threat HIGH. Attachments analyzed: 1, malicious: 1, suspicious: 0. Consolidated threat level: CRITICAL.',
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