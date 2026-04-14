import { describe, expect, it } from 'vitest';

import { parseRawEmail, parseRawEmailForAnalysis } from './services/email-parser.js';

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
Reply to alerts@secure-example.test if you have questions.
`;

describe('parseRawEmail', () => {
  it('extracts headers, URLs, domains, email addresses and auth results from raw email', async () => {
    const result = await parseRawEmail(sampleRawEmail);

    expect(result.headers.from).toContain('alerts@secure-example.test');
    expect(result.headers.returnPath).toContain('bounce@mailer.secure-example.test');
    expect(result.authentication).toEqual({
      spf: 'fail',
      dkim: 'pass',
      dmarc: 'fail',
      spfDetails: {
        status: 'fail',
        reason: null,
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
    });
    expect(result.urls).toEqual([
      {
        originalUrl: 'https://secure-example.test/login',
        decodedUrl: 'https://secure-example.test/login',
      },
    ]);
    expect(result.emailAddresses).toEqual(
      expect.arrayContaining(['alerts@secure-example.test', 'victim@example.org']),
    );
    expect(result.domains).toEqual(expect.arrayContaining(['secure-example.test', 'example.org']));
    expect(result.ipAddresses).toContain('203.0.113.50');
  });

  it('rejects empty raw email input', async () => {
    await expect(parseRawEmail('   ')).rejects.toMatchObject({
      code: 'invalid_email',
    });
  });

  it('extracts attachment uploads for downstream file analysis', async () => {
    const rawEmailWithAttachment = `From: Alerts Team <alerts@secure-example.test>
To: victim@example.org
Subject: Invoice attached
Date: Tue, 08 Apr 2026 10:00:00 +0000
Message-ID: <abc@example.test>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="frontier"

--frontier
Content-Type: text/plain; charset=UTF-8

See attachment.

--frontier
Content-Type: application/pdf; name="invoice.pdf"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="invoice.pdf"

JVBERi0xLjcKJSBzdXNwaWNpb3VzIHBkZg==
--frontier--
`;

    const result = await parseRawEmailForAnalysis(rawEmailWithAttachment);

    expect(result.parsedEmail.attachments).toEqual([
      expect.objectContaining({
        filename: 'invoice.pdf',
        contentType: 'application/pdf',
      }),
    ]);
    expect(result.attachmentUploads).toEqual([
      expect.objectContaining({
        filename: 'invoice.pdf',
        contentType: 'application/pdf',
      }),
    ]);
    expect(Buffer.from(result.attachmentUploads[0].contentBase64, 'base64').toString('latin1')).toContain('%PDF-1.7');
  });

  it('decodes Barracuda LinkProtect URLs and preserves the destination chain', async () => {
    const rawEmailWithBarracuda = `From: sender@example.org
To: victim@example.org
Subject: Wrapped URL
Authentication-Results: mx.example.org; dkim=fail (No key [DKIM DNS record not found]) header.d=tournoi7decoeur.com

Check this link:
https://linkprotect.cudasvc.com/url?a=https%3A%2F%2Ftournoi7decoeur.com%2Fwp-content%2Fuploads%2F2026%2F03%2Fbrochure.pdf&c=E,1,test
`;

    const result = await parseRawEmail(rawEmailWithBarracuda);

    expect(result.authentication.dkimDetails?.reason).toBe('No key [DKIM DNS record not found]');
    expect(result.urls).toEqual([
      {
        originalUrl: 'https://linkprotect.cudasvc.com/url?a=https%3A%2F%2Ftournoi7decoeur.com%2Fwp-content%2Fuploads%2F2026%2F03%2Fbrochure.pdf&c=E,1,test',
        decodedUrl: 'https://tournoi7decoeur.com/wp-content/uploads/2026/03/brochure.pdf',
        wrapperType: 'barracuda',
        resolutionChain: [
          {
            label: 'Original',
            url: 'https://linkprotect.cudasvc.com/url?a=https%3A%2F%2Ftournoi7decoeur.com%2Fwp-content%2Fuploads%2F2026%2F03%2Fbrochure.pdf&c=E,1,test',
          },
          {
            label: 'Percent-decoded',
            url: 'https://linkprotect.cudasvc.com/url?a=https://tournoi7decoeur.com/wp-content/uploads/2026/03/brochure.pdf&c=E,1,test',
          },
          {
            label: 'Barracuda target',
            url: 'https://tournoi7decoeur.com/wp-content/uploads/2026/03/brochure.pdf',
          },
        ],
      },
    ]);
  });
});