// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import App from './App';
import * as caseReport from './case-report';

describe('App navigation', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    cleanup();
  });

  it('renders the THEPHISH tab and opens the dedicated workflow view', async () => {
    mockAppFetch();

    render(<App />);

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /\[5\] thephish/i })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /\[5\] thephish/i }));

    expect(await screen.findByText(/thephish eml intake/i)).toBeInTheDocument();
  });

  it('keeps analysis state across tab switches and clears it when the case is reset', async () => {
    mockAppFetch();

    render(<App />);

    const emailTabButton = await screen.findByRole('button', { name: /\[2\] full email analysis/i });
    fireEvent.click(emailTabButton);

    const rawEmailInput = screen.getByPlaceholderText(/paste full raw email source here/i) as HTMLTextAreaElement;
    fireEvent.change(rawEmailInput, {
      target: { value: 'From: alerts@secure-example.test' },
    });

    fireEvent.click(screen.getByRole('button', { name: /\[1\] domain analysis/i }));
    fireEvent.click(screen.getByRole('button', { name: /\[2\] full email analysis/i }));

    expect((screen.getByPlaceholderText(/paste full raw email source here/i) as HTMLTextAreaElement).value).toBe('From: alerts@secure-example.test');
    expect(screen.getByText(/visited tools: domain -> email/i)).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /reset case/i }));
    fireEvent.click(screen.getByRole('button', { name: /\[2\] full email analysis/i }));

    expect((screen.getByPlaceholderText(/paste full raw email source here/i) as HTMLTextAreaElement).value).toBe('');
  });

  it('adds analyst events to the case journal and clears them on reset', async () => {
    mockAppFetch({
      '/api/analyze/email': async () => buildMockEmailAnalysisResponse(),
    });

    render(<App />);

    fireEvent.click(await screen.findByRole('button', { name: /\[2\] full email analysis/i }));
    fireEvent.change(screen.getByPlaceholderText(/paste full raw email source here/i), {
      target: { value: 'From: alerts@secure-example.test' },
    });
    fireEvent.click(screen.getByRole('button', { name: /decode & analyze/i }));

    expect(await screen.findByText(/email :: email analysis completed/i)).toBeInTheDocument();
    expect(screen.getByText(/high threat with 0 url\(s\) and 0 attachment\(s\)/i)).toBeInTheDocument();
    expect(screen.getByText(/email: from -> alerts@secure-example.test/i)).toBeInTheDocument();
    expect(screen.getByText(/domain: domain -> secure-example.test/i)).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /reset case/i }));

    expect(screen.getByText(/no analyst actions recorded for this case yet/i)).toBeInTheDocument();
  });

  it('exports the current case report from the global case panel', async () => {
    const fetchSpy = mockAppFetch({
      '/api/analyze/email': async () => buildMockEmailAnalysisResponse(),
    });
    const downloadSpy = vi.spyOn(caseReport, 'downloadCaseReport').mockImplementation(() => {
      return;
    });

    render(<App />);

    fireEvent.click(await screen.findByRole('button', { name: /\[2\] full email analysis/i }));
    fireEvent.change(screen.getByPlaceholderText(/paste full raw email source here/i), {
      target: { value: 'From: alerts@secure-example.test' },
    });
    fireEvent.click(screen.getByRole('button', { name: /decode & analyze/i }));

    await screen.findByText(/email :: email analysis completed/i);
    fireEvent.click(screen.getByRole('button', { name: /export case report/i }));

    expect(fetchSpy).toHaveBeenCalled();
    expect(downloadSpy).toHaveBeenCalledTimes(1);
    expect(downloadSpy.mock.calls[0]?.[0]).toContain('# CASE REPORT CASE-');
    expect(downloadSpy.mock.calls[0]?.[0]).toContain('EMAIL | WARNING | Email analysis completed');
    expect(downloadSpy.mock.calls[0]?.[1]).toMatch(/case-.*-report\.txt/i);
  });

  it('exports the current case as a structured JSON report', async () => {
    mockAppFetch({
      '/api/analyze/email': async () => buildMockEmailAnalysisResponse(),
    });
    const downloadSpy = vi.spyOn(caseReport, 'downloadCaseJsonReport').mockImplementation(() => {
      return;
    });

    render(<App />);

    fireEvent.click(await screen.findByRole('button', { name: /\[2\] full email analysis/i }));
    fireEvent.change(screen.getByPlaceholderText(/paste full raw email source here/i), {
      target: { value: 'From: alerts@secure-example.test' },
    });
    fireEvent.click(screen.getByRole('button', { name: /decode & analyze/i }));

    await screen.findByText(/email :: email analysis completed/i);
    fireEvent.click(screen.getByRole('button', { name: /export case json/i }));

    expect(downloadSpy).toHaveBeenCalledTimes(1);
    const reportJson = downloadSpy.mock.calls[0]?.[0] ?? '';
    expect(reportJson).toContain('"caseId": "CASE-');
    expect(reportJson).toContain('"tool": "email"');
    expect(reportJson).toContain('"severity": "warning"');
    expect(reportJson).toContain('"references"');
    expect(reportJson).toContain('"kind": "email"');
    expect(reportJson).toContain('"kind": "domain"');
    expect(downloadSpy.mock.calls[0]?.[1]).toMatch(/case-.*-report\.json/i);
  });

  it('restores the persisted case session after authentication', async () => {
    mockAppFetch(
      {},
      {
        case: {
          caseId: 'CASE-202604141230-03',
          startedAt: '2026-04-14T12:30:00.000Z',
          updatedAt: '2026-04-14T12:35:00.000Z',
          activeTab: 'files',
          visitedTabs: ['domain', 'files'],
          events: [
            {
              id: 'evt-1',
              tool: 'files',
              title: 'File analysis completed',
              detail: 'invoice.zip -> completed',
              severity: 'success',
              occurredAt: '2026-04-14T12:34:00.000Z',
              references: [
                {
                  kind: 'job',
                  label: 'file-analysis',
                  value: 'file_job_123',
                },
                {
                  kind: 'artifact',
                  label: 'evidence',
                  value: 'invoice.zip',
                  path: 'storage/uploads/job_file_456/00-invoice.docm',
                  url: null,
                },
              ],
            },
          ],
        },
      },
      {
        cases: [
          {
            caseId: 'CASE-202604141230-03',
            startedAt: '2026-04-14T12:30:00.000Z',
            updatedAt: '2026-04-14T12:35:00.000Z',
            activeTab: 'files',
            visitedTabs: ['domain', 'files'],
            eventCount: 1,
          },
          {
            caseId: 'CASE-202604140945-02',
            startedAt: '2026-04-14T09:45:00.000Z',
            updatedAt: '2026-04-14T10:05:00.000Z',
            activeTab: 'email',
            visitedTabs: ['domain', 'email'],
            eventCount: 4,
          },
        ],
      },
    );

    render(<App />);

    expect(await screen.findByText(/files :: file analysis completed/i)).toBeInTheDocument();
    expect(screen.getByText(/visited tools: domain -> files/i)).toBeInTheDocument();
    expect(screen.getByText(/job: file-analysis -> file_job_123/i)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /artifact: evidence -> invoice.zip/i })).toHaveAttribute('href', '/storage/uploads/job_file_456/00-invoice.docm');
    expect(screen.getByText(/case-202604140945-02/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /analyze files/i })).toBeInTheDocument();
  });

  it('reopens a saved case from the recent case list', async () => {
    const activatedCase = {
      caseId: 'CASE-202604140945-02',
      startedAt: '2026-04-14T09:45:00.000Z',
      updatedAt: '2026-04-14T10:10:00.000Z',
      activeTab: 'email',
      visitedTabs: ['domain', 'email'],
      events: [
        {
          id: 'evt-2',
          tool: 'email',
          title: 'Email analysis completed',
          detail: 'HIGH threat with 1 URL',
          severity: 'warning',
          occurredAt: '2026-04-14T10:00:00.000Z',
          references: [
            {
              kind: 'domain',
              label: 'domain',
              value: 'secure-example.test',
            },
          ],
        },
      ],
    };

    mockAppFetch(
      {
        '/api/cases/CASE-202604140945-02/activate': async () => ({
          ok: true,
          json: async () => activatedCase,
        } as Response),
      },
      { case: null },
      {
        cases: [
          {
            caseId: 'CASE-202604140945-02',
            startedAt: '2026-04-14T09:45:00.000Z',
            updatedAt: '2026-04-14T10:05:00.000Z',
            activeTab: 'email',
            visitedTabs: ['domain', 'email'],
            eventCount: 4,
          },
        ],
      },
    );

    render(<App />);

    fireEvent.click(await screen.findByRole('button', { name: /open case-202604140945-02/i }));

    expect(await screen.findByText(/email :: email analysis completed/i)).toBeInTheDocument();
    expect(screen.getByText(/domain: domain -> secure-example.test/i)).toBeInTheDocument();
    expect(screen.getByText(/visited tools: domain -> email/i)).toBeInTheDocument();
  });

  it('filters, sorts, and deletes saved cases from the recent case list', async () => {
    const fetchSpy = mockAppFetch(
      {
        '/api/cases/CASE-202604140945-02': async () => ({
          ok: true,
          json: async () => ({}),
        } as Response),
      },
      { case: null },
      {
        cases: [
          {
            caseId: 'CASE-202604141230-03',
            startedAt: '2026-04-14T12:30:00.000Z',
            updatedAt: '2026-04-14T12:35:00.000Z',
            activeTab: 'files',
            visitedTabs: ['domain', 'files'],
            eventCount: 1,
          },
          {
            caseId: 'CASE-202604140945-02',
            startedAt: '2026-04-14T09:45:00.000Z',
            updatedAt: '2026-04-14T10:05:00.000Z',
            activeTab: 'email',
            visitedTabs: ['domain', 'email'],
            eventCount: 4,
          },
        ],
      },
    );

    render(<App />);

    fireEvent.change(await screen.findByRole('textbox', { name: /search saved cases/i }), {
      target: { value: 'email' },
    });

    expect(screen.getByText(/case-202604140945-02/i)).toBeInTheDocument();
    expect(screen.queryByText(/case-202604141230-03/i)).not.toBeInTheDocument();

    fireEvent.change(screen.getByRole('combobox', { name: /sort saved cases/i }), {
      target: { value: 'events-desc' },
    });

    fireEvent.click(screen.getByRole('button', { name: /delete case-202604140945-02/i }));

    expect(screen.getByText(/confirm deletion of this case\. this action removes the saved session\./i)).toBeInTheDocument();
    expect(fetchSpy).not.toHaveBeenCalledWith('/api/cases/CASE-202604140945-02', expect.objectContaining({ method: 'DELETE' }));

    fireEvent.click(screen.getByRole('button', { name: /confirm delete case-202604140945-02/i }));

    await waitFor(() => {
      expect(fetchSpy).toHaveBeenCalledWith('/api/cases/CASE-202604140945-02', expect.objectContaining({ method: 'DELETE' }));
    });
    expect(screen.queryByText(/case-202604140945-02/i)).not.toBeInTheDocument();
  });
});

function mockAppFetch(
  routes: Record<string, (init?: RequestInit) => Promise<Response> | Response> = {},
  currentCasePayload: { case: unknown } = { case: null },
  caseListPayload: { cases: unknown[] } = { cases: [] },
) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const url = typeof input === 'string' ? input : input instanceof Request ? input.url : String(input);
    const method = init?.method ?? (input instanceof Request ? input.method : 'GET');

    if (url === '/api/auth/session') {
      return {
        ok: true,
        json: async () => ({ authenticated: true }),
      } as Response;
    }

    if (url === '/api/cases/current' && method === 'GET') {
      return {
        ok: true,
        json: async () => currentCasePayload,
      } as Response;
    }

    if (url === '/api/cases' && method === 'GET') {
      return {
        ok: true,
        json: async () => caseListPayload,
      } as Response;
    }

    if (url === '/api/cases/current' && method === 'PUT') {
      return {
        ok: true,
        json: async () => JSON.parse(String(init?.body ?? '{}')),
      } as Response;
    }

    const handler = routes[url];
    if (handler) {
      return handler(init);
    }

    throw new Error(`Unexpected fetch call: ${url}`);
  });
}

function buildMockEmailAnalysisResponse() {
  return {
    ok: true,
    json: async () => ({
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
      urls: [],
      inconsistencies: [],
      threatLevel: 'HIGH',
      executiveSummary: 'The email shows authentication anomalies and phishing-style lures.',
      emailAddresses: ['alerts@secure-example.test'],
      domains: ['secure-example.test'],
      ipAddresses: [],
      attachments: [],
      relatedDomains: [],
    }),
  } as Response;
}