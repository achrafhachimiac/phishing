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
  const authenticationHeader = headerValue(parsedMessage.headers.get('authentication-results')) || extractHeader(trimmedEmail, 'authentication-results');
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
  const urls = uniqueMatches(combinedContent || trimmedEmail, /https?:\/\/[^\s<>"]+/gi).map((url) => decodeParsedUrl(url));
  const spfDetails = extractAuthenticationDetails(authenticationHeader, 'spf');
  const dkimDetails = extractAuthenticationDetails(authenticationHeader, 'dkim');
  const dmarcDetails = extractAuthenticationDetails(authenticationHeader, 'dmarc');

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
      spf: spfDetails.status,
      dkim: dkimDetails.status,
      dmarc: dmarcDetails.status,
      spfDetails,
      dkimDetails,
      dmarcDetails,
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
  const match = rawEmail.match(new RegExp(`^${escapeRegExp(headerName)}:\\s*(.+)$`, 'im'));
  return match?.[1]?.trim() || null;
}

function decodeUrl(url: string): string {
  let current = url;

  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      const decoded = decodeURIComponent(current);
      if (decoded === current) {
        break;
      }
      current = decoded;
    } catch {
      break;
    }
  }

  return current;
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

function extractAuthenticationDetails(header: unknown, key: 'spf' | 'dkim' | 'dmarc') {
  if (typeof header !== 'string') {
    return emptyAuthenticationDetails();
  }

  const segment = header
    .split(';')
    .map((part) => part.trim())
    .find((part) => part.toLowerCase().startsWith(`${key}=`));

  if (!segment) {
    return emptyAuthenticationDetails();
  }

  const statusMatch = segment.match(new RegExp(`^${key}=([a-zA-Z]+)\\b`, 'i'));
  const reasonMatch = segment.match(/\(([^)]*)\)/);

  return {
    status: statusMatch?.[1]?.toLowerCase() || null,
    reason: reasonMatch?.[1]?.trim() || null,
    smtpMailFrom: extractAuthContextValue(segment, 'smtp.mailfrom'),
    headerFrom: extractAuthContextValue(segment, 'header.from'),
    headerDomain: extractAuthContextValue(segment, 'header.d'),
    selector: extractAuthContextValue(segment, 'header.s'),
    action: extractAuthContextValue(segment, 'action'),
  };
}

function emptyAuthenticationDetails() {
  return {
    status: null,
    reason: null,
    smtpMailFrom: null,
    headerFrom: null,
    headerDomain: null,
    selector: null,
    action: null,
  };
}

function extractAuthContextValue(segment: string, key: string): string | null {
  const match = segment.match(new RegExp(`${escapeRegExp(key)}=([^\\s;]+)`, 'i'));
  return match?.[1]?.trim() || null;
}

function decodeParsedUrl(url: string) {
  const percentDecodedUrl = decodeUrl(url);
  const resolutionChain = [{ label: 'Original', url }];
  let decodedUrl = percentDecodedUrl;

  if (percentDecodedUrl !== url) {
    resolutionChain.push({ label: 'Percent-decoded', url: percentDecodedUrl });
  }

  const barracudaTarget = unwrapBarracudaLinkProtect(percentDecodedUrl);
  if (barracudaTarget) {
    decodedUrl = barracudaTarget;
    resolutionChain.push({ label: 'Barracuda target', url: barracudaTarget });
  }

  return {
    originalUrl: url,
    decodedUrl,
    ...(barracudaTarget ? { wrapperType: 'barracuda' as const } : {}),
    ...(resolutionChain.length > 1 ? { resolutionChain } : {}),
  };
}

function unwrapBarracudaLinkProtect(url: string): string | null {
  try {
    const parsedUrl = new URL(url);
    if (parsedUrl.hostname.toLowerCase() !== 'linkprotect.cudasvc.com') {
      return null;
    }

    const target = parsedUrl.searchParams.get('a');
    return target ? decodeUrl(target) : null;
  } catch {
    return null;
  }
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}