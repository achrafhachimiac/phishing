import type { BrowserSandboxAccess } from '../../shared/analysis-types.js';

export type BrowserSandboxProviderConfig = {
  provider: string;
  accessMode: 'none' | 'embedded' | 'external';
  accessBaseUrl: string | null;
  accessUrlTemplate?: string | null;
  accessPathTemplate: string;
  startCommandTemplate?: string | null;
  stopCommandTemplate?: string | null;
};

export type BrowserSandboxProviderContext = {
  jobId: string;
  displayNumber?: number;
  vncPort?: number;
  novncPort?: number;
};

export function buildBrowserSandboxAccess(
  config: BrowserSandboxProviderConfig,
  context: BrowserSandboxProviderContext,
): BrowserSandboxAccess {
  if (config.accessMode === 'none' || !config.accessBaseUrl) {
    if (config.accessMode !== 'none' && config.accessUrlTemplate) {
      return {
        mode: config.accessMode,
        url: interpolateAccessTemplate(config.accessUrlTemplate, context),
        note: `Live Chromium access is exposed through the ${config.provider} provider.`,
      };
    }

    return {
      mode: 'none',
      url: null,
      note: 'This provider currently captures browser evidence server-side only. Configure a remote access base URL to expose a live Chromium session.',
    };
  }

  if (config.accessUrlTemplate) {
    return {
      mode: config.accessMode,
      url: interpolateAccessTemplate(config.accessUrlTemplate, context),
      note: `Live Chromium access is exposed through the ${config.provider} provider.`,
    };
  }

  return {
    mode: config.accessMode,
    url: composeBrowserSandboxAccessUrl(config.accessBaseUrl, config.accessPathTemplate, context.jobId),
    note: `Live Chromium access is exposed through the ${config.provider} provider.`,
  };
}

function interpolateAccessTemplate(template: string, context: BrowserSandboxProviderContext) {
  return template
    .replaceAll(':jobId', encodeURIComponent(context.jobId))
    .replaceAll(':displayNumber', String(context.displayNumber ?? ''))
    .replaceAll(':vncPort', String(context.vncPort ?? ''))
    .replaceAll(':novncPort', String(context.novncPort ?? ''));
}

function composeBrowserSandboxAccessUrl(baseUrl: string, pathTemplate: string, jobId: string) {
  const normalizedBaseUrl = baseUrl.endsWith('/') ? baseUrl : `${baseUrl}/`;
  const resolvedPath = pathTemplate.includes(':jobId')
    ? pathTemplate.replaceAll(':jobId', encodeURIComponent(jobId))
    : `${trimSlashes(pathTemplate)}/${encodeURIComponent(jobId)}`;

  return new URL(trimLeadingSlash(resolvedPath), normalizedBaseUrl).toString();
}

function trimSlashes(value: string) {
  return value.replace(/^\/+|\/+$/g, '');
}

function trimLeadingSlash(value: string) {
  return value.replace(/^\/+/, '');
}