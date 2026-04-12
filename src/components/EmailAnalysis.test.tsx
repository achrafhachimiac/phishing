// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { EmailAnalysis } from './EmailAnalysis';

describe('EmailAnalysis', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
    cleanup();
  });

  it('submits raw email to the backend and renders the returned threat report', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue({
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
        urls: [
          {
            originalUrl: 'https://secure-example.test/login',
            decodedUrl: 'https://secure-example.test/login',
            suspicious: true,
            reason: 'The URL uses urgent credential-themed wording.',
          },
        ],
        inconsistencies: ['SPF failed for the sending domain.'],
        threatLevel: 'HIGH',
        executiveSummary: 'The email shows authentication anomalies and phishing-style lures.',
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
              },
              rdap: {
                registrar: 'Test Registrar',
                createdAt: '2026-04-01T00:00:00.000Z',
                updatedAt: null,
                expiresAt: null,
              },
              infrastructure: {
                ipAddresses: ['203.0.113.10'],
                tls: null,
              },
              riskFactors: ['Domain appears very recent (7 days old).'],
              osint: {
                virustotal: 'https://www.virustotal.com/gui/domain/secure-example.test',
                urlscan: 'https://urlscan.io/search/#domain:secure-example.test',
                viewdns: 'https://viewdns.info/reverseip/?host=secure-example.test&t=1',
                crtSh: 'https://crt.sh/?q=secure-example.test',
              },
            },
          },
        ],
      }),
    } as Response);

    render(<EmailAnalysis />);

    fireEvent.change(screen.getByPlaceholderText(/paste full raw email source/i), {
      target: { value: 'From: alerts@secure-example.test' },
    });
    fireEvent.click(screen.getByRole('button', { name: /decode & analyze/i }));

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith('/api/analyze/email', expect.objectContaining({
        method: 'POST',
      }));
    });

    expect(await screen.findByText(/the email shows authentication anomalies/i)).toBeInTheDocument();
  expect(screen.getAllByText('HIGH').length).toBeGreaterThan(0);
    expect(screen.getByText('alerts@secure-example.test')).toBeInTheDocument();
    expect(screen.getByText(/spf failed for the sending domain/i)).toBeInTheDocument();
    expect(screen.getByText(/related domains/i)).toBeInTheDocument();
    expect(screen.getByText(/relation: url/i)).toBeInTheDocument();
    expect(screen.getByText(/recently created domain with suspicious keyword patterns/i)).toBeInTheDocument();
  });

  it('launches URL sandbox analysis and renders the returned browser evidence', async () => {
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce({
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
          urls: [
            {
              originalUrl: 'https://example.org',
              decodedUrl: 'https://example.org',
              suspicious: true,
              reason: 'Credential-themed wording.',
            },
          ],
          inconsistencies: ['SPF failed for the sending domain.'],
          threatLevel: 'HIGH',
          executiveSummary: 'The email shows authentication anomalies and phishing-style lures.',
          emailAddresses: ['alerts@secure-example.test', 'victim@example.org'],
          domains: ['secure-example.test', 'example.org'],
          ipAddresses: ['203.0.113.50'],
          attachments: [],
          relatedDomains: [],
        }),
      } as Response)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          jobId: 'job_test_123',
          status: 'queued',
          queuedUrls: ['https://example.org'],
          results: [],
        }),
      } as Response)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          jobId: 'job_test_123',
          status: 'running',
          queuedUrls: ['https://example.org'],
          results: [],
        }),
      } as Response)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          jobId: 'job_test_123',
          status: 'completed',
          queuedUrls: ['https://example.org'],
          results: [
            {
              originalUrl: 'https://example.org',
              finalUrl: 'https://example.org/',
              title: 'Example Domain',
              screenshotPath: 'storage/screenshots/job_test_123/example.png',
              tracePath: 'storage/traces/job_test_123/example.zip',
              redirectChain: ['https://example.org', 'https://example.org/'],
              requestedDomains: ['example.org'],
              scriptUrls: ['https://example.org/app.js'],
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
      } as Response);

    render(<EmailAnalysis />);

    fireEvent.change(screen.getByPlaceholderText(/paste full raw email source/i), {
      target: { value: 'From: alerts@secure-example.test' },
    });
    fireEvent.click(screen.getByRole('button', { name: /decode & analyze/i }));

    expect(await screen.findByText(/the email shows authentication anomalies/i)).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /run url sandbox/i }));

    expect(await screen.findByText(/sandbox job:/i)).toBeInTheDocument();

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith('/api/analyze/urls/job_test_123', expect.anything());
      expect(screen.getAllByText('completed').length).toBeGreaterThan(0);
    });

    expect(screen.getByText(/example domain/i)).toBeInTheDocument();
    expect(screen.getByText(/https:\/\/example.org\/app.js/i)).toBeInTheDocument();
    expect(screen.getByText(/urlhaus:/i)).toBeInTheDocument();
    expect(screen.getByText('not_listed')).toBeInTheDocument();
    expect(screen.getByText(/urlscan:/i)).toBeInTheDocument();
    expect(screen.getAllByText('not_configured').length).toBeGreaterThan(0);
    expect(screen.getByText(/alienvault otx:/i)).toBeInTheDocument();
    expect(screen.getAllByText('unavailable').length).toBeGreaterThan(0);
    expect(screen.getByText(/storage\/traces\/job_test_123\/example.zip/i)).toBeInTheDocument();
  });
});