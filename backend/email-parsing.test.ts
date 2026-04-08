import { describe, expect, it } from 'vitest';

import { parseRawEmail } from './services/email-parser.js';

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
});