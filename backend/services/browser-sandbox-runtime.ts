import path from 'node:path';

export type BrowserSandboxRuntime = {
  displayNumber: number;
  vncPort: number;
  novncPort: number;
  sessionDirectory: string;
};

const DISPLAY_BASE = 100;
const VNC_BASE = 5900;
const NOVNC_BASE = 7600;
const SLOT_COUNT = 200;

export function resolveBrowserSandboxRuntime(jobId: string, sandboxRoot: string): BrowserSandboxRuntime {
  const slot = hashJobId(jobId) % SLOT_COUNT;

  return {
    displayNumber: DISPLAY_BASE + slot,
    vncPort: VNC_BASE + slot,
    novncPort: NOVNC_BASE + slot,
    sessionDirectory: path.join(sandboxRoot, jobId),
  };
}

function hashJobId(value: string) {
  let hash = 0;
  for (const character of value) {
    hash = (hash * 31 + character.charCodeAt(0)) >>> 0;
  }
  return hash;
}