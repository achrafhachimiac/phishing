import { simpleParser, type Attachment } from 'mailparser';

import {
  emailParsingResponseSchema,
  type EmailParsingResponse,
  type FileUpload,
} from '../../shared/analysis-types.js';

export type ParsedEmailForAnalysis = {
  parsedEmail: EmailParsingResponse;
  attachmentUploads: FileUpload[];
};

export class EmailParsingError extends Error {
  code: string;

  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

export async function parseRawEmail(rawEmail: string): Promise<EmailParsingResponse> {
  const parsed = await parseRawEmailWithAttachments(rawEmail);
  return parsed.parsedEmail;
}

export async function parseRawEmailForAnalysis(rawEmail: string): Promise<ParsedEmailForAnalysis> {
  return parseRawEmailWithAttachments(rawEmail);
}

async function parseRawEmailWithAttachments(rawEmail: string): Promise<ParsedEmailForAnalysis> {
  const trimmedEmail = rawEmail.trim();

  if (!trimmedEmail) {
    throw new EmailParsingError('invalid_email', 'Raw email is required.');
  }

  const parsedMessage = await simpleParser(trimmedEmail);
  const authenticationHeader = parsedMessage.headers.get('authentication-results');
  const returnPathHeader = headerValue(parsedMessage.headers.get('return-path')) || extractHeader(trimmedEmail, 'return-path');
  const combinedContent = [parsedMessage.text, parsedMessage.html]
    .filter((part): part is string => typeof part === 'string' && part.length > 0)
    .join('\n');

  const emailAddresses = uniqueMatches(
    `${trimmedEmail}\n${combinedContent}`,
    /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}/gi,
  );
  const domains = [...new Set(emailAddresses.map((emailAddress) => emailAddress.split('@')[1].toLowerCase()))];
  const ipAddresses = uniqueMatches(trimmedEmail, /\b(?:\d{1,3}\.){3}\d{1,3}\b/g);
  const urls = uniqueMatches(combinedContent || trimmedEmail, /https?:\/\/[^\s<>"]+/gi).map((url) => ({
    originalUrl: url,
    decodedUrl: decodeUrl(url),
  }));

  const parsedEmail = emailParsingResponseSchema.parse({
    headers: {
      from: extractAddressText(parsedMessage.from),
      to: extractAddressText(parsedMessage.to),
      subject: parsedMessage.subject || null,
      date: parsedMessage.date?.toUTCString() || null,
      messageId: headerValue(parsedMessage.headers.get('message-id')),
      returnPath: returnPathHeader,
    },
    authentication: {
      spf: extractAuthenticationResult(authenticationHeader, 'spf'),
      dkim: extractAuthenticationResult(authenticationHeader, 'dkim'),
      dmarc: extractAuthenticationResult(authenticationHeader, 'dmarc'),
    },
    urls,
    emailAddresses,
    domains,
    ipAddresses,
    attachments: parsedMessage.attachments.map((attachment: Attachment) => ({
      filename: attachment.filename || null,
      contentType: attachment.contentType,
      size: attachment.size,
      checksum: attachment.checksum || null,
    })),
  });

  return {
    parsedEmail,
    attachmentUploads: parsedMessage.attachments
      .map((attachment, index) => attachmentToFileUpload(attachment, index))
      .filter((attachment): attachment is FileUpload => attachment !== null),
  };
}

function attachmentToFileUpload(attachment: Attachment, index: number): FileUpload | null {
  const content = normalizeAttachmentContent(attachment.content);
  if (!content || content.byteLength === 0) {
    return null;
  }

  return {
    filename: attachment.filename || `attachment-${index + 1}.bin`,
    contentType: attachment.contentType || 'application/octet-stream',
    contentBase64: content.toString('base64'),
  };
}

function normalizeAttachmentContent(content: unknown): Buffer | null {
  if (Buffer.isBuffer(content)) {
    return content;
  }

  if (typeof content === 'string') {
    return Buffer.from(content);
  }

  if (content instanceof Uint8Array) {
    return Buffer.from(content);
  }

  return null;
}

function headerValue(value: unknown): string | null {
  if (typeof value === 'string') {
    return value;
  }

  if (value && typeof value === 'object' && 'text' in value && typeof value.text === 'string') {
    return value.text;
  }

  return null;
}

function extractAddressText(value: unknown): string | null {
  if (value && typeof value === 'object' && 'text' in value && typeof value.text === 'string') {
    return value.text;
  }

  return null;
}

function extractHeader(rawEmail: string, headerName: string): string | null {
  const match = rawEmail.match(new RegExp(`^${headerName}:\s*(.+)$`, 'im'));
  return match?.[1]?.trim() || null;
}

function decodeUrl(url: string): string {
  try {
    return decodeURIComponent(url);
  } catch {
    return url;
  }
}

function uniqueMatches(content: string, pattern: RegExp): string[] {
  return [...new Set(content.match(pattern) ?? [])];
}

function extractAuthenticationResult(header: unknown, key: 'spf' | 'dkim' | 'dmarc'): string | null {
  if (typeof header !== 'string') {
    return null;
  }

  const match = header.match(new RegExp(`${key}=([a-zA-Z]+)`, 'i'));
  return match?.[1]?.toLowerCase() || null;
}