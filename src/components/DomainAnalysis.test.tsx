// @vitest-environment jsdom

import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { DomainAnalysis } from './DomainAnalysis';

describe('DomainAnalysis', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('submits the domain to the backend and renders the returned evidence', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      json: async () => ({
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
          caa: ['0 issue "letsencrypt.org"'],
          soa: 'ns1.secure-example.test hostmaster.secure-example.test 2026040801 7200 3600 1209600 3600',
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
          ipIntelligence: [
            {
              ip: '203.0.113.10',
              reverseDns: ['mail.secure-example.test'],
              country: 'US',
              city: 'Ashburn',
              asn: 'AS64500',
              organization: 'Example Hosting',
            },
          ],
          tls: {
            issuer: 'Test CA',
            subject: 'secure-example.test',
            validFrom: '2026-04-01T00:00:00.000Z',
            validTo: '2026-07-01T00:00:00.000Z',
            subjectAltNames: ['secure-example.test', 'www.secure-example.test'],
          },
        },
        history: {
          waybackSnapshots: 3,
          firstSeen: '2026-04-01T00:00:00.000Z',
          lastSeen: '2026-04-07T00:00:00.000Z',
        },
        certificates: {
          certificateTransparency: {
            certificateCount: 4,
            observedSubdomains: ['www.secure-example.test', 'mail.secure-example.test'],
          },
        },
        reputation: {
          alienVault: {
            status: 'listed',
            pulseCount: 2,
            reference: 'https://otx.alienvault.com/indicator/domain/secure-example.test',
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
            status: 'listed',
            reference: 'https://urlhaus.abuse.ch/url/999/',
            urls: ['http://secure-example.test/dropper'],
          },
        },
        riskFactors: ['Domain appears very recent (7 days old).', 'Suspicious keyword detected: secure'],
        osint: {
          virustotal: 'https://www.virustotal.com/gui/domain/secure-example.test',
          urlscan: 'https://urlscan.io/search/#domain:secure-example.test',
          viewdns: 'https://viewdns.info/reverseip/?host=secure-example.test&t=1',
          crtSh: 'https://crt.sh/?q=secure-example.test',
          wayback: 'https://web.archive.org/web/*/secure-example.test',
          dnsdumpster: 'https://dnsdumpster.com/',
          builtwith: 'https://builtwith.com/secure-example.test',
          alienVault: 'https://otx.alienvault.com/indicator/domain/secure-example.test',
          abuseIpDb: 'https://www.abuseipdb.com/check/203.0.113.10',
          urlhausHost: 'https://urlhaus.abuse.ch/browse.php?search=secure-example.test',
        },
      }),
    } as Response);

    render(<DomainAnalysis />);

    fireEvent.change(screen.getByPlaceholderText('e.g., suspicious-login-update.com'), {
      target: { value: 'secure-example.test' },
    });
    fireEvent.click(screen.getByRole('button', { name: /execute/i }));

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith('/api/analyze/domain', expect.objectContaining({
        method: 'POST',
      }));
    });

    expect(await screen.findByText('secure-example.test')).toBeInTheDocument();
    expect(screen.getByText(/recently created domain with suspicious keyword patterns/i)).toBeInTheDocument();
    expect(screen.getAllByText('203.0.113.10').length).toBeGreaterThan(0);
    expect(screen.getByText('Test Registrar')).toBeInTheDocument();
    expect(screen.getByText(/spf mode/i)).toBeInTheDocument();
    expect(screen.getByText(/ashburn, us/i)).toBeInTheDocument();
    expect(screen.getByText(/wayback snapshots/i)).toBeInTheDocument();
    expect(screen.getByText(/otx pulses/i)).toBeInTheDocument();
    expect(screen.getByText(/urlhaus host: listed/i)).toBeInTheDocument();
  });
});