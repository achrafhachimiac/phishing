// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { BrowserSandbox } from './BrowserSandbox';

function truncateObservedValue(value: string) {
  return `${value.slice(0, 100)}...`;
}

describe('BrowserSandbox', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    cleanup();
  });

  it('launches a browser sandbox job and renders captured evidence', async () => {
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          jobId: 'sandbox_job_123',
          status: 'queued',
          requestedUrl: 'https://example.org/',
          expiresAt: '2026-04-11T12:15:00.000Z',
          result: null,
        }),
      } as Response)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          jobId: 'sandbox_job_123',
          status: 'running',
          requestedUrl: 'https://example.org/',
          expiresAt: '2026-04-11T12:15:00.000Z',
          result: null,
        }),
      } as Response)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          jobId: 'sandbox_job_123',
          status: 'completed',
          requestedUrl: 'https://example.org/',
          expiresAt: '2026-04-11T12:15:00.000Z',
          result: {
            originalUrl: 'https://example.org/',
            finalUrl: 'https://example.org/login',
            title: 'Example Login',
            session: {
              provider: 'novnc',
              sessionId: 'sandbox_job_123',
              status: 'ready',
              startedAt: '2026-04-11T12:00:00.000Z',
              stoppedAt: null,
              access: {
                mode: 'embedded',
                url: 'https://fred.syntrix.ae/novnc/6161/vnc.html?autoconnect=1&resize=remote',
                note: 'Live Chromium access is exposed through the novnc provider.',
              },
            },
            access: {
              mode: 'embedded',
              url: 'https://fred.syntrix.ae/novnc/6161/vnc.html?autoconnect=1&resize=remote',
              note: 'Live Chromium access is exposed through the novnc provider.',
            },
            screenshotPath: 'storage/sandbox-sessions/sandbox_job_123/example-org.png',
            tracePath: 'storage/traces/sandbox_job_123/example-org.zip',
            redirectChain: ['https://example.org/', 'https://example.org/login'],
            requestedDomains: ['example.org', 'cdn.example.org'],
            scriptUrls: ['https://cdn.example.org/app.js'],
            consoleErrors: ['ReferenceError: x is not defined'],
            downloads: [
              {
                filename: 'payload.iso',
                path: 'storage/downloads/sandbox_job_123/payload.iso',
                url: 'https://example.org/payload.iso',
                sha256: 'abc123',
                size: 4096,
              },
            ],
            artifacts: [
              {
                type: 'screenshot',
                label: 'Sandbox screenshot',
                path: 'storage/sandbox-sessions/sandbox_job_123/example-org.png',
                mimeType: 'image/png',
                size: null,
              },
            ],
            status: 'completed',
            error: null,
          },
        }),
      } as Response);

    render(<BrowserSandbox />);

    fireEvent.change(screen.getByPlaceholderText(/siteweb.com/i), {
      target: { value: 'https://example.org' },
    });
    fireEvent.click(screen.getByRole('button', { name: /launch sandbox/i }));

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenNthCalledWith(1, '/api/sandbox/browser', expect.objectContaining({
        method: 'POST',
      }));
      expect(globalThis.fetch).toHaveBeenNthCalledWith(2, '/api/sandbox/browser/sandbox_job_123', expect.anything());
      expect(globalThis.fetch).toHaveBeenNthCalledWith(3, '/api/sandbox/browser/sandbox_job_123', expect.anything());
      expect(screen.getAllByText((_, element) => element?.textContent?.includes('completed [sandbox_job_123]') ?? false).length).toBeGreaterThan(0);
    });

    expect(screen.getByText(/example login/i)).toBeInTheDocument();
    expect(screen.getByText(/cdn.example.org\/app.js/i)).toBeInTheDocument();
    expect(screen.getAllByText(/payload.iso/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/referenceerror: x is not defined/i)).toBeInTheDocument();
    expect(screen.getByText(/provider note/i)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /open remote browser/i })).toHaveAttribute('href', 'https://fred.syntrix.ae/novnc/6161/vnc.html?autoconnect=1&resize=remote');
    expect(screen.getByRole('heading', { name: /live remote browser/i })).toBeInTheDocument();
    expect(screen.getByTitle(/live remote browser session/i)).toHaveAttribute('src', 'https://fred.syntrix.ae/novnc/6161/vnc.html?autoconnect=1&resize=remote');
    expect(screen.getByRole('slider')).toHaveValue('720');
    expect(screen.getByRole('button', { name: /full screen/i })).toBeInTheDocument();
    expect(screen.getByAltText(/sandbox screenshot preview/i)).toHaveAttribute('src', '/storage/sandbox-sessions/sandbox_job_123/example-org.png');
    expect(screen.getByRole('link', { name: /stored copy/i })).toHaveAttribute('href', '/storage/downloads/sandbox_job_123/payload.iso');
  });

  it('truncates long observed values and copies the full value on click', async () => {
    const longScriptUrl = `https://cdn.example.org/${'deep-path/'.repeat(12)}payload.js?token=${'abc123'.repeat(10)}`;
    const writeText = vi.fn(async () => undefined);

    vi.stubGlobal('navigator', {
      clipboard: {
        writeText,
      },
    });

    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          jobId: 'sandbox_job_copy',
          status: 'queued',
          requestedUrl: 'https://example.org/',
          expiresAt: '2026-04-11T12:15:00.000Z',
          result: null,
        }),
      } as Response)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          jobId: 'sandbox_job_copy',
          status: 'completed',
          requestedUrl: 'https://example.org/',
          expiresAt: '2026-04-11T12:15:00.000Z',
          result: {
            originalUrl: 'https://example.org/',
            finalUrl: 'https://example.org/login',
            title: 'Example Login',
            session: {
              provider: 'novnc',
              sessionId: 'sandbox_job_copy',
              status: 'ready',
              startedAt: '2026-04-11T12:00:00.000Z',
              stoppedAt: null,
              access: {
                mode: 'embedded',
                url: 'https://fred.syntrix.ae/novnc/6161/vnc.html?autoconnect=1&resize=remote',
                note: 'Live Chromium access is exposed through the novnc provider.',
              },
            },
            access: {
              mode: 'embedded',
              url: 'https://fred.syntrix.ae/novnc/6161/vnc.html?autoconnect=1&resize=remote',
              note: 'Live Chromium access is exposed through the novnc provider.',
            },
            screenshotPath: 'storage/sandbox-sessions/sandbox_job_copy/example-org.png',
            tracePath: 'storage/traces/sandbox_job_copy/example-org.zip',
            redirectChain: ['https://example.org/', 'https://example.org/login'],
            requestedDomains: ['example.org'],
            scriptUrls: [longScriptUrl],
            consoleErrors: [],
            downloads: [],
            artifacts: [],
            status: 'completed',
            error: null,
          },
        }),
      } as Response);

    render(<BrowserSandbox />);

    fireEvent.change(screen.getByPlaceholderText(/siteweb.com/i), {
      target: { value: 'https://example.org' },
    });
    fireEvent.click(screen.getByRole('button', { name: /launch sandbox/i }));

    const truncatedScriptUrl = truncateObservedValue(longScriptUrl);
    const truncatedValue = await screen.findByText(truncatedScriptUrl);

    expect(screen.queryByText(longScriptUrl)).not.toBeInTheDocument();

    fireEvent.click(truncatedValue.closest('button') as HTMLButtonElement);

    await waitFor(() => {
      expect(writeText).toHaveBeenCalledWith(longScriptUrl);
      expect(screen.getByText(/copied/i)).toBeInTheDocument();
    });
  });
});