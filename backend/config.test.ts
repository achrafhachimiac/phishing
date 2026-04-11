import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { loadBackendEnvironment } from './config.js';

describe('loadBackendEnvironment', () => {
  const previousValue = process.env.URLHAUS_AUTH_KEY;
  const previousYaraCommand = process.env.FILE_ANALYSIS_YARA_COMMAND;
  const previousClamAvCommand = process.env.FILE_ANALYSIS_CLAMAV_COMMAND;
  const previousSandboxBaseUrl = process.env.BROWSER_SANDBOX_ACCESS_BASE_URL;
  const previousSandboxUrlTemplate = process.env.BROWSER_SANDBOX_ACCESS_URL_TEMPLATE;
  const previousSandboxAccessMode = process.env.BROWSER_SANDBOX_ACCESS_MODE;
  const previousSandboxStartCommand = process.env.BROWSER_SANDBOX_START_COMMAND;
  const previousSandboxStopCommand = process.env.BROWSER_SANDBOX_STOP_COMMAND;

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
});