import { appConfig } from '../config.js';

export type CortexObservableDataType = 'domain' | 'file' | 'hash' | 'ip' | 'mail' | 'url';

export type CortexAnalyzerRunInput = {
  analyzerId: string;
  dataType: CortexObservableDataType;
  data: string;
  tlp?: number;
  pap?: number;
};

export type CortexJobDetails = {
  id: string;
  status: string;
  report?: unknown;
};

type CortexClientDependencies = {
  fetch?: typeof fetch;
  wait?: (milliseconds: number) => Promise<void>;
};

type EnabledCortexConfig = {
  enabled: true;
  baseUrl: string;
  apiKey: string;
  timeoutMs: number;
  analyzers: {
    eml: string[];
    url: string[];
    domain: string[];
    fileHash: string[];
  };
};

type CortexWaitOptions = {
  pollIntervalMs?: number;
  timeoutMs?: number;
};

const TERMINAL_JOB_STATUSES = new Set(['Success', 'Failure', 'Deleted']);

export class CortexClientError extends Error {
  code: string;
  statusCode: number | null;

  constructor(code: string, message: string, statusCode: number | null = null) {
    super(message);
    this.code = code;
    this.statusCode = statusCode;
  }
}

export async function submitCortexAnalyzerJob(
  input: CortexAnalyzerRunInput,
  dependencies: CortexClientDependencies = {},
) {
  const cortexConfig = assertCortexConfiguration();
  const fetchImpl = dependencies.fetch ?? fetch;
  const response = await fetchImpl(buildCortexUrl(`/api/analyzer/${encodeURIComponent(input.analyzerId)}/run`), {
    method: 'POST',
    headers: buildCortexHeaders(cortexConfig.apiKey),
    body: JSON.stringify({
      dataType: input.dataType,
      data: input.data,
      tlp: input.tlp ?? 2,
      pap: input.pap ?? 2,
    }),
  });

  if (!response.ok) {
    throw await buildCortexResponseError(response, 'Cortex analyzer submission failed.');
  }

  const payload = (await response.json()) as { id?: string; jobId?: string };
  const jobId = payload.id ?? payload.jobId;
  if (!jobId) {
    throw new CortexClientError('invalid_cortex_response', 'Cortex did not return a job identifier.');
  }

  return { jobId };
}

export async function getCortexJob(jobId: string, dependencies: CortexClientDependencies = {}): Promise<CortexJobDetails> {
  const cortexConfig = assertCortexConfiguration();
  const fetchImpl = dependencies.fetch ?? fetch;
  const response = await fetchImpl(buildCortexUrl(`/api/job/${encodeURIComponent(jobId)}`), {
    headers: buildCortexHeaders(cortexConfig.apiKey),
  });

  if (!response.ok) {
    throw await buildCortexResponseError(response, 'Cortex job lookup failed.');
  }

  const payload = (await response.json()) as { id?: string; status?: string; report?: unknown };
  if (!payload.id || !payload.status) {
    throw new CortexClientError('invalid_cortex_response', 'Cortex job response is missing required fields.');
  }

  return {
    id: payload.id,
    status: payload.status,
    report: payload.report,
  };
}

export async function getCortexJobReport(jobId: string, dependencies: CortexClientDependencies = {}) {
  const cortexConfig = assertCortexConfiguration();
  const fetchImpl = dependencies.fetch ?? fetch;
  const response = await fetchImpl(buildCortexUrl(`/api/job/${encodeURIComponent(jobId)}/report`), {
    headers: buildCortexHeaders(cortexConfig.apiKey),
  });

  if (!response.ok) {
    throw await buildCortexResponseError(response, 'Cortex job report lookup failed.');
  }

  return response.json();
}

export async function waitForCortexJobReport(
  jobId: string,
  options: CortexWaitOptions = {},
  dependencies: CortexClientDependencies = {},
) {
  const wait = dependencies.wait ?? defaultWait;
  const timeoutMs = options.timeoutMs ?? appConfig.cortex.timeoutMs;
  const pollIntervalMs = options.pollIntervalMs ?? 500;
  const startedAt = Date.now();

  while (Date.now() - startedAt <= timeoutMs) {
    const job = await getCortexJob(jobId, dependencies);
    if (job.report !== undefined) {
      return {
        job,
        report: job.report,
      };
    }

    if (TERMINAL_JOB_STATUSES.has(job.status)) {
      return {
        job,
        report: job.status === 'Success' ? await getCortexJobReport(jobId, dependencies) : null,
      };
    }

    await wait(pollIntervalMs);
  }

  throw new CortexClientError('cortex_timeout', 'Cortex job did not complete before the configured timeout.');
}

function assertCortexConfiguration() {
  if (!appConfig.cortex.enabled) {
    throw new CortexClientError('cortex_not_enabled', 'Cortex integration is disabled.');
  }

  if (!appConfig.cortex.baseUrl || !appConfig.cortex.apiKey) {
    throw new CortexClientError('cortex_not_configured', 'Cortex base URL or API key is missing.');
  }

  return {
    ...appConfig.cortex,
    enabled: true,
    baseUrl: appConfig.cortex.baseUrl,
    apiKey: appConfig.cortex.apiKey,
  } satisfies EnabledCortexConfig;
}

function buildCortexUrl(pathname: string) {
  const baseUrl = appConfig.cortex.baseUrl;
  if (!baseUrl) {
    throw new CortexClientError('cortex_not_configured', 'Cortex base URL is missing.');
  }

  return new URL(pathname, `${baseUrl.endsWith('/') ? baseUrl : `${baseUrl}/`}`).toString();
}

function buildCortexHeaders(apiKey: string) {
  return {
    Authorization: `Bearer ${apiKey}`,
    'Content-Type': 'application/json',
  };
}

async function buildCortexResponseError(response: Response, fallbackMessage: string) {
  const bodyText = await response.text().catch(() => '');
  const trimmedBody = bodyText.trim();

  if (response.status === 401 || response.status === 403) {
    return new CortexClientError('cortex_unauthorized', trimmedBody || fallbackMessage, response.status);
  }

  if (response.status === 404) {
    return new CortexClientError('cortex_not_found', trimmedBody || fallbackMessage, response.status);
  }

  return new CortexClientError('cortex_request_failed', trimmedBody || fallbackMessage, response.status);
}

function defaultWait(milliseconds: number) {
  return new Promise<void>((resolve) => {
    setTimeout(resolve, milliseconds);
  });
}