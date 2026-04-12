import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { loadBackendEnvironment, readCortexEnvironment } from './config.js';

describe('loadBackendEnvironment', () => {
  const previousValue = process.env.URLHAUS_AUTH_KEY;
  const previousYaraCommand = process.env.FILE_ANALYSIS_YARA_COMMAND;
  const previousClamAvCommand = process.env.FILE_ANALYSIS_CLAMAV_COMMAND;
  const previousSandboxBaseUrl = process.env.BROWSER_SANDBOX_ACCESS_BASE_URL;
  const previousSandboxUrlTemplate = process.env.BROWSER_SANDBOX_ACCESS_URL_TEMPLATE;
  const previousSandboxAccessMode = process.env.BROWSER_SANDBOX_ACCESS_MODE;
  const previousSandboxStartCommand = process.env.BROWSER_SANDBOX_START_COMMAND;
  const previousSandboxStopCommand = process.env.BROWSER_SANDBOX_STOP_COMMAND;
  const previousCortexEnabled = process.env.CORTEX_ENABLED;
  const previousCortexBaseUrl = process.env.CORTEX_BASE_URL;
  const previousCortexApiKey = process.env.CORTEX_API_KEY;
  const previousCortexTimeout = process.env.CORTEX_TIMEOUT_MS;
  const previousCortexEml = process.env.CORTEX_ANALYZERS_EML;
  const previousCortexUrl = process.env.CORTEX_ANALYZERS_URL;
  const previousCortexDomain = process.env.CORTEX_ANALYZERS_DOMAIN;
  const previousCortexFileHash = process.env.CORTEX_ANALYZERS_FILE_HASH;

  afterEach(() => {
    if (previousValue === undefined) {
      delete process.env.URLHAUS_AUTH_KEY;
    } else {
      process.env.URLHAUS_AUTH_KEY = previousValue;
    }

    if (previousYaraCommand === undefined) {
      delete process.env.FILE_ANALYSIS_YARA_COMMAND;
    } else {
      process.env.FILE_ANALYSIS_YARA_COMMAND = previousYaraCommand;
    }

    if (previousClamAvCommand === undefined) {
      delete process.env.FILE_ANALYSIS_CLAMAV_COMMAND;
    } else {
      process.env.FILE_ANALYSIS_CLAMAV_COMMAND = previousClamAvCommand;
    }

    if (previousSandboxBaseUrl === undefined) {
      delete process.env.BROWSER_SANDBOX_ACCESS_BASE_URL;
    } else {
      process.env.BROWSER_SANDBOX_ACCESS_BASE_URL = previousSandboxBaseUrl;
    }

    if (previousSandboxAccessMode === undefined) {
      delete process.env.BROWSER_SANDBOX_ACCESS_MODE;
    } else {
      process.env.BROWSER_SANDBOX_ACCESS_MODE = previousSandboxAccessMode;
    }

    if (previousSandboxUrlTemplate === undefined) {
      delete process.env.BROWSER_SANDBOX_ACCESS_URL_TEMPLATE;
    } else {
      process.env.BROWSER_SANDBOX_ACCESS_URL_TEMPLATE = previousSandboxUrlTemplate;
    }

    if (previousSandboxStartCommand === undefined) {
      delete process.env.BROWSER_SANDBOX_START_COMMAND;
    } else {
      process.env.BROWSER_SANDBOX_START_COMMAND = previousSandboxStartCommand;
    }

    if (previousSandboxStopCommand === undefined) {
      delete process.env.BROWSER_SANDBOX_STOP_COMMAND;
    } else {
      process.env.BROWSER_SANDBOX_STOP_COMMAND = previousSandboxStopCommand;
    }

    if (previousCortexEnabled === undefined) {
      delete process.env.CORTEX_ENABLED;
    } else {
      process.env.CORTEX_ENABLED = previousCortexEnabled;
    }

    if (previousCortexBaseUrl === undefined) {
      delete process.env.CORTEX_BASE_URL;
    } else {
      process.env.CORTEX_BASE_URL = previousCortexBaseUrl;
    }

    if (previousCortexApiKey === undefined) {
      delete process.env.CORTEX_API_KEY;
    } else {
      process.env.CORTEX_API_KEY = previousCortexApiKey;
    }

    if (previousCortexTimeout === undefined) {
      delete process.env.CORTEX_TIMEOUT_MS;
    } else {
      process.env.CORTEX_TIMEOUT_MS = previousCortexTimeout;
    }

    if (previousCortexEml === undefined) {
      delete process.env.CORTEX_ANALYZERS_EML;
    } else {
      process.env.CORTEX_ANALYZERS_EML = previousCortexEml;
    }

    if (previousCortexUrl === undefined) {
      delete process.env.CORTEX_ANALYZERS_URL;
    } else {
      process.env.CORTEX_ANALYZERS_URL = previousCortexUrl;
    }

    if (previousCortexDomain === undefined) {
      delete process.env.CORTEX_ANALYZERS_DOMAIN;
    } else {
      process.env.CORTEX_ANALYZERS_DOMAIN = previousCortexDomain;
    }

    if (previousCortexFileHash === undefined) {
      delete process.env.CORTEX_ANALYZERS_FILE_HASH;
    } else {
      process.env.CORTEX_ANALYZERS_FILE_HASH = previousCortexFileHash;
    }
  });

  it('loads URLHAUS_AUTH_KEY from .env.local when present', () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'phish-hunter-env-'));
    fs.writeFileSync(path.join(tempRoot, '.env.local'), 'URLHAUS_AUTH_KEY=loaded-from-test\n', 'utf8');
    delete process.env.URLHAUS_AUTH_KEY;

    loadBackendEnvironment(tempRoot);

    expect(process.env.URLHAUS_AUTH_KEY).toBe('loaded-from-test');
  });

  it('loads browser sandbox provider settings from .env.local when present', () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'phish-hunter-env-'));
    fs.writeFileSync(
      path.join(tempRoot, '.env.local'),
      'BROWSER_SANDBOX_ACCESS_BASE_URL=https://sandbox.example.test/live\nBROWSER_SANDBOX_ACCESS_URL_TEMPLATE=http://109.199.125.137::novncPort/vnc.html?autoconnect=1\nBROWSER_SANDBOX_ACCESS_MODE=external\nBROWSER_SANDBOX_START_COMMAND=start-session --job :jobId\nBROWSER_SANDBOX_STOP_COMMAND=stop-session --job :jobId\n',
      'utf8',
    );
    delete process.env.BROWSER_SANDBOX_ACCESS_BASE_URL;
    delete process.env.BROWSER_SANDBOX_ACCESS_URL_TEMPLATE;
    delete process.env.BROWSER_SANDBOX_ACCESS_MODE;
    delete process.env.BROWSER_SANDBOX_START_COMMAND;
    delete process.env.BROWSER_SANDBOX_STOP_COMMAND;

    loadBackendEnvironment(tempRoot);

    expect(process.env.BROWSER_SANDBOX_ACCESS_BASE_URL).toBe('https://sandbox.example.test/live');
    expect(process.env.BROWSER_SANDBOX_ACCESS_URL_TEMPLATE).toBe('http://109.199.125.137::novncPort/vnc.html?autoconnect=1');
    expect(process.env.BROWSER_SANDBOX_ACCESS_MODE).toBe('external');
    expect(process.env.BROWSER_SANDBOX_START_COMMAND).toBe('start-session --job :jobId');
    expect(process.env.BROWSER_SANDBOX_STOP_COMMAND).toBe('stop-session --job :jobId');
  });

  it('loads file analysis scanner settings from .env.local when present', () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'phish-hunter-env-'));
    fs.writeFileSync(
      path.join(tempRoot, '.env.local'),
      'FILE_ANALYSIS_YARA_COMMAND=yara -r /opt/yara/rules.yar :path\nFILE_ANALYSIS_CLAMAV_COMMAND=clamscan --no-summary :path\n',
      'utf8',
    );
    delete process.env.FILE_ANALYSIS_YARA_COMMAND;
    delete process.env.FILE_ANALYSIS_CLAMAV_COMMAND;

    loadBackendEnvironment(tempRoot);

    expect(process.env.FILE_ANALYSIS_YARA_COMMAND).toBe('yara -r /opt/yara/rules.yar :path');
    expect(process.env.FILE_ANALYSIS_CLAMAV_COMMAND).toBe('clamscan --no-summary :path');
  });

  it('loads Cortex settings from .env.local when present', () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'phish-hunter-env-'));
    fs.writeFileSync(
      path.join(tempRoot, '.env.local'),
      'CORTEX_ENABLED=true\nCORTEX_BASE_URL=https://cortex.example.test\nCORTEX_API_KEY=top-secret\nCORTEX_TIMEOUT_MS=22000\nCORTEX_ANALYZERS_EML=EmlParser_1\nCORTEX_ANALYZERS_URL=PhishTank_1,CheckPhish_1\nCORTEX_ANALYZERS_DOMAIN=SpamhausDBL_1\nCORTEX_ANALYZERS_FILE_HASH=VirusTotal_GetReport_3_1\n',
      'utf8',
    );
    delete process.env.CORTEX_ENABLED;
    delete process.env.CORTEX_BASE_URL;
    delete process.env.CORTEX_API_KEY;
    delete process.env.CORTEX_TIMEOUT_MS;
    delete process.env.CORTEX_ANALYZERS_EML;
    delete process.env.CORTEX_ANALYZERS_URL;
    delete process.env.CORTEX_ANALYZERS_DOMAIN;
    delete process.env.CORTEX_ANALYZERS_FILE_HASH;

    loadBackendEnvironment(tempRoot);

    expect(process.env.CORTEX_ENABLED).toBe('true');
    expect(process.env.CORTEX_BASE_URL).toBe('https://cortex.example.test');
    expect(process.env.CORTEX_API_KEY).toBe('top-secret');
    expect(process.env.CORTEX_TIMEOUT_MS).toBe('22000');
  });
});

describe('readCortexEnvironment', () => {
  it('parses the configured Cortex environment', () => {
    const config = readCortexEnvironment({
      CORTEX_ENABLED: 'true',
      CORTEX_BASE_URL: 'https://cortex.example.test ',
      CORTEX_API_KEY: ' api-key ',
      CORTEX_TIMEOUT_MS: '22000',
      CORTEX_ANALYZERS_EML: 'EmlParser_1',
      CORTEX_ANALYZERS_URL: 'PhishTank_1, CheckPhish_1',
      CORTEX_ANALYZERS_DOMAIN: 'SpamhausDBL_1',
      CORTEX_ANALYZERS_FILE_HASH: 'VirusTotal_GetReport_3_1',
    });

    expect(config).toEqual({
      enabled: true,
      baseUrl: 'https://cortex.example.test',
      apiKey: 'api-key',
      timeoutMs: 22000,
      analyzers: {
        eml: ['EmlParser_1'],
        url: ['PhishTank_1', 'CheckPhish_1'],
        domain: ['SpamhausDBL_1'],
        fileHash: ['VirusTotal_GetReport_3_1'],
      },
    });
  });

  it('falls back to safe defaults when Cortex variables are absent', () => {
    expect(readCortexEnvironment({})).toEqual({
      enabled: false,
      baseUrl: null,
      apiKey: null,
      timeoutMs: 15000,
      analyzers: {
        eml: [],
        url: [],
        domain: [],
        fileHash: [],
      },
    });
  });
});