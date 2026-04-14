import { describe, expect, it, vi } from 'vitest';

import { analyzeEmail } from './services/email-analysis.js';

const sampleRawEmail = `Return-Path: <bounce@mailer.secure-example.test>
From: Alerts Team <alerts@secure-example.test>
To: victim@example.org
Subject: Urgent account review
Date: Tue, 08 Apr 2026 10:00:00 +0000
Message-ID: <abc@example.test>
Authentication-Results: mx.example.org; spf=fail smtp.mailfrom=secure-example.test; dkim=pass header.d=secure-example.test; dmarc=fail action=quarantine header.from=secure-example.test
Received: from mail.secure-example.test (203.0.113.50)
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Please review your account immediately:
https://secure-example.test/login
`;

describe('analyzeEmail', () => {
  it('builds a deterministic threat report from the parsed email evidence', async () => {
    const analyzeRelatedDomain = vi.fn();
    const result = await analyzeEmail(sampleRawEmail, { analyzeRelatedDomain } as never);

    expect(result.threatLevel).toBe('HIGH');
    expect(result.inconsistencies).toEqual(
      expect.arrayContaining([
        expect.stringContaining('SPF failed'),
        expect.stringContaining('DMARC failed'),
      ]),
    );
    expect(result.executiveSummary).toMatch(/authentication/i);
    expect(result.urls[0]).toEqual(
      expect.objectContaining({
        suspicious: true,
      }),
    );
    expect(result.relatedDomains).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          domain: 'secure-example.test',
          relation: 'url',
          analysis: null,
        }),
      ]),
    );
    expect(analyzeRelatedDomain).not.toHaveBeenCalled();
  });

  it('surfaces explicit auth failure reasons and Barracuda wrapper analysis', async () => {
    const result = await analyzeEmail(`Return-Path: <bounce@mailer.secure-example.test>
From: Alerts Team <alerts@secure-example.test>
To: victim@example.org
Subject: Review document
Authentication-Results: mx.example.org; spf=pass smtp.mailfrom=secure-example.test; dkim=fail (No key [DKIM DNS record not found]) header.d=tournoi7decoeur.com; dmarc=fail action=reject header.from=secure-example.test

Open:
https://linkprotect.cudasvc.com/url?a=https%3A%2F%2Ftournoi7decoeur.com%2Fwp-content%2Fuploads%2F2026%2F03%2Fbrochure.pdf&c=E,1,test
`);

    expect(result.inconsistencies).toEqual(
      expect.arrayContaining([
        'DKIM failed: No key [DKIM DNS record not found].',
        'DMARC failed for the visible sender domain (action=reject).',
      ]),
    );
    expect(result.urls[0]).toEqual(expect.objectContaining({ wrapperType: 'barracuda', suspicious: true }));
    expect(result.urls[0].reason).toMatch(/Barracuda LinkProtect/i);
    expect(result.relatedDomains).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ domain: 'tournoi7decoeur.com', relation: 'url', analysis: null }),
      ]),
    );
  });
});