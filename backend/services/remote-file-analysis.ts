import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import path from 'node:path';

import type { FileAnalysisJob, FileUpload } from '../../shared/analysis-types.js';
import { enqueueFileAnalysisJob } from './file-analysis.js';

const MAX_REMOTE_FILE_SIZE_BYTES = 10 * 1024 * 1024;
const FALLBACK_REMOTE_FILENAME = 'downloaded-remote-file.bin';

type FetchLike = typeof fetch;

export class RemoteFileAnalysisError extends Error {
  code: string;

  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

export async function enqueueRemoteFileAnalysisJob(
  targetUrl: string,
  enqueueFileJob: typeof enqueueFileAnalysisJob = enqueueFileAnalysisJob,
  fetchImpl: FetchLike = fetch,
): Promise<FileAnalysisJob> {
  const normalizedUrl = await normalizeRemoteFileUrl(targetUrl);
  const remoteFile = await downloadRemoteFile(normalizedUrl, fetchImpl);
  return enqueueFileJob([remoteFile]);
}

async function normalizeRemoteFileUrl(targetUrl: string) {
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(targetUrl);
  } catch {
    throw new RemoteFileAnalysisError('invalid_remote_file_url', 'A valid remote HTTP(S) file URL is required.');
  }

  if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
    throw new RemoteFileAnalysisError('invalid_remote_file_protocol', 'Only HTTP(S) remote files are supported.');
  }

  if (isBlockedHostname(parsedUrl.hostname)) {
    throw new RemoteFileAnalysisError('remote_file_private_host', 'Private, loopback, and local network targets are not allowed.');
  }

  const resolvedAddresses = await lookup(parsedUrl.hostname, { all: true });
  if (resolvedAddresses.length === 0 || resolvedAddresses.some((entry) => isPrivateAddress(entry.address))) {
    throw new RemoteFileAnalysisError('remote_file_private_host', 'Private, loopback, and local network targets are not allowed.');
  }

  return parsedUrl.toString();
}

async function downloadRemoteFile(targetUrl: string, fetchImpl: FetchLike): Promise<FileUpload> {
  const response = await fetchImpl(targetUrl, {
    method: 'GET',
    redirect: 'follow',
    headers: {
      'user-agent': 'phish-hunter-remote-file-analysis/1.0',
    },
  });

  if (!response.ok) {
    throw new RemoteFileAnalysisError('remote_file_download_failed', `Remote file download failed with status ${response.status}.`);
  }

  const contentLengthHeader = response.headers.get('content-length');
  if (contentLengthHeader) {
    const contentLength = Number.parseInt(contentLengthHeader, 10);
    if (Number.isFinite(contentLength) && contentLength > MAX_REMOTE_FILE_SIZE_BYTES) {
      throw new RemoteFileAnalysisError('remote_file_too_large', 'Remote files larger than 10 MB are not supported.');
    }
  }

  const buffer = Buffer.from(await readResponseBody(response));
  if (buffer.byteLength === 0) {
    throw new RemoteFileAnalysisError('remote_file_empty', 'The remote file response was empty.');
  }

  if (buffer.byteLength > MAX_REMOTE_FILE_SIZE_BYTES) {
    throw new RemoteFileAnalysisError('remote_file_too_large', 'Remote files larger than 10 MB are not supported.');
  }

  const contentType = normalizeContentType(response.headers.get('content-type'));
  const filename =
    extractFilenameFromDisposition(response.headers.get('content-disposition')) ||
    extractFilenameFromUrl(response.url || targetUrl) ||
    FALLBACK_REMOTE_FILENAME;

  if (contentType === 'text/html' && !looksLikeDownloadableFilename(filename)) {
    throw new RemoteFileAnalysisError('remote_file_not_downloadable', 'The remote URL resolved to HTML instead of a downloadable file.');
  }

  return {
    filename,
    contentType,
    contentBase64: buffer.toString('base64'),
  };
}

async function readResponseBody(response: Response) {
  if (!response.body) {
    return new Uint8Array();
  }

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }

    if (!value) {
      continue;
    }

    totalBytes += value.byteLength;
    if (totalBytes > MAX_REMOTE_FILE_SIZE_BYTES) {
      throw new RemoteFileAnalysisError('remote_file_too_large', 'Remote files larger than 10 MB are not supported.');
    }

    chunks.push(value);
  }

  return Buffer.concat(chunks.map((chunk) => Buffer.from(chunk)));
}

function normalizeContentType(contentType: string | null) {
  return contentType?.split(';')[0]?.trim() || null;
}

function extractFilenameFromDisposition(contentDisposition: string | null) {
  if (!contentDisposition) {
    return null;
  }

  const encodedMatch = contentDisposition.match(/filename\*=UTF-8''([^;]+)/i);
  if (encodedMatch?.[1]) {
    return sanitizeFilename(decodeURIComponent(encodedMatch[1]));
  }

  const filenameMatch = contentDisposition.match(/filename="?([^";]+)"?/i);
  return filenameMatch?.[1] ? sanitizeFilename(filenameMatch[1]) : null;
}

function extractFilenameFromUrl(targetUrl: string) {
  try {
    const parsedUrl = new URL(targetUrl);
    const basename = path.posix.basename(parsedUrl.pathname);
    if (!basename || basename === '/' || basename === '.') {
      return null;
    }

    return sanitizeFilename(basename);
  } catch {
    return null;
  }
}

function sanitizeFilename(value: string) {
  const normalizedValue = value.trim().replace(/[<>:"/\\|?*\u0000-\u001F]/g, '_');
  return normalizedValue || FALLBACK_REMOTE_FILENAME;
}

function looksLikeDownloadableFilename(filename: string) {
  return /\.(pdf|doc|docx|xls|xlsx|ppt|pptx|zip|7z|rar|eml|msg|rtf|csv|txt)$/i.test(filename);
}

function isBlockedHostname(hostname: string) {
  const normalizedHostname = hostname.trim().toLowerCase();
  return normalizedHostname === 'localhost' || normalizedHostname.endsWith('.local') || isPrivateAddress(normalizedHostname);
}

function isPrivateAddress(value: string) {
  const ipVersion = isIP(value);
  if (ipVersion === 4) {
    const octets = value.split('.').map((part) => Number.parseInt(part, 10));
    return (
      octets[0] === 10 ||
      octets[0] === 127 ||
      (octets[0] === 169 && octets[1] === 254) ||
      (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
      (octets[0] === 192 && octets[1] === 168) ||
      (octets[0] === 100 && octets[1] >= 64 && octets[1] <= 127) ||
      octets[0] === 0
    );
  }

  if (ipVersion === 6) {
    const normalized = value.toLowerCase();
    return normalized === '::1' || normalized.startsWith('fc') || normalized.startsWith('fd') || normalized.startsWith('fe80:');
  }

  return false;
}