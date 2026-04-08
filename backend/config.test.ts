import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { loadBackendEnvironment } from './config.js';

describe('loadBackendEnvironment', () => {
  const previousValue = process.env.URLHAUS_AUTH_KEY;

  afterEach(() => {
    if (previousValue === undefined) {
      delete process.env.URLHAUS_AUTH_KEY;
    } else {
      process.env.URLHAUS_AUTH_KEY = previousValue;
    }
  });

  it('loads URLHAUS_AUTH_KEY from .env.local when present', () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'phish-hunter-env-'));
    fs.writeFileSync(path.join(tempRoot, '.env.local'), 'URLHAUS_AUTH_KEY=loaded-from-test\n', 'utf8');
    delete process.env.URLHAUS_AUTH_KEY;

    loadBackendEnvironment(tempRoot);

    expect(process.env.URLHAUS_AUTH_KEY).toBe('loaded-from-test');
  });
});