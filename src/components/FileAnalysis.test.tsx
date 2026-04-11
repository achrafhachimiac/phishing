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
          results: [],
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
              riskScore: 40,
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
    expect(screen.getByText(/embedded pdf javascript markers found/i)).toBeInTheDocument();
    expect(screen.getByText(/https:\/\/evil.example\/login/i)).toBeInTheDocument();
    expect(screen.getByText(/clamav: malicious/i)).toBeInTheDocument();
    expect(screen.getByText(/yara: match/i)).toBeInTheDocument();
    expect(screen.getByText(/specialized parsers/i)).toBeInTheDocument();
    expect(screen.getByText(/detected code \/ snippets/i)).toBeInTheDocument();
    expect(screen.getByText(/app.alert\("phish"\)/i)).toBeInTheDocument();
  });
});