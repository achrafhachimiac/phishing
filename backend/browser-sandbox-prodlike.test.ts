import http from 'node:http';

import { afterEach, describe, expect, it } from 'vitest';

import { getStoragePaths } from './storage.js';
import { buildBrowserSandboxAccess } from './services/browser-sandbox-provider.js';
import { resolveBrowserSandboxRuntime } from './services/browser-sandbox-runtime.js';
import { startBrowserSandboxSession } from './services/browser-sandbox-session.js';

describe('browser sandbox prod-like smoke', () => {
  const servers: http.Server[] = [];

  afterEach(async () => {
    await Promise.all(servers.map((server) => new Promise<void>((resolve, reject) => {
      server.close((error) => {
        if (error) {
          reject(error);
          return;
        }

        resolve();
      });
    })));
    servers.length = 0;
  });

  it('returns an embedded noVNC URL that is reachable through a prod-like reverse proxy', async () => {
    const jobId = 'sandbox_smoke_123';
    const runtime = resolveBrowserSandboxRuntime(jobId, getStoragePaths().sandboxSessions);
    const upstreamServer = http.createServer((request, response) => {
      if (request.url?.startsWith('/vnc.html')) {
        response.writeHead(200, { 'Content-Type': 'text/html' });
        response.end('<!doctype html><html><body>Mock noVNC session</body></html>');
        return;
      }

      response.writeHead(404);
      response.end('not found');
    });
    servers.push(upstreamServer);
    await listen(upstreamServer, runtime.novncPort);

    const proxyServer = http.createServer((request, response) => {
      const match = request.url?.match(/^\/novnc\/(\d+)\/(.*)$/);
      if (!match) {
        response.writeHead(404);
        response.end('not found');
        return;
      }

      const [, port, upstreamPath] = match;
      const proxyRequest = http.request(
        {
          hostname: '127.0.0.1',
          port: Number(port),
          path: `/${upstreamPath}`,
          method: request.method,
          headers: request.headers,
        },
        (proxyResponse) => {
          response.writeHead(proxyResponse.statusCode ?? 502, proxyResponse.headers);
          proxyResponse.pipe(response);
        },
      );

      proxyRequest.on('error', () => {
        response.writeHead(502);
        response.end('upstream unavailable');
      });

      request.pipe(proxyRequest);
    });
    servers.push(proxyServer);
    const proxyPort = await listen(proxyServer);

    const expectedAccess = buildBrowserSandboxAccess(
      {
        provider: 'local-novnc',
        accessMode: 'embedded',
        accessBaseUrl: null,
        accessUrlTemplate: `http://127.0.0.1:${proxyPort}/novnc/:novncPort/vnc.html?autoconnect=1&resize=remote`,
        accessPathTemplate: ':jobId',
      },
      {
        jobId,
        displayNumber: runtime.displayNumber,
        vncPort: runtime.vncPort,
        novncPort: runtime.novncPort,
      },
    );

    const session = await startBrowserSandboxSession(
      {
        provider: 'local-novnc',
        accessMode: 'embedded',
        accessBaseUrl: null,
        accessUrlTemplate: `http://127.0.0.1:${proxyPort}/novnc/:novncPort/vnc.html?autoconnect=1&resize=remote`,
        accessPathTemplate: ':jobId',
        startCommandTemplate: null,
        stopCommandTemplate: null,
      },
      { jobId, url: 'https://example.org' },
    );

    expect(session.access.mode).toBe('embedded');
    expect(session.access.url).toBe(expectedAccess.url);

    const response = await fetch(session.access.url ?? '');
    const html = await response.text();

    expect(response.status).toBe(200);
    expect(html).toContain('Mock noVNC session');
  });
});

function listen(server: http.Server, port?: number) {
  return new Promise<number>((resolve, reject) => {
    server.once('error', reject);
    server.listen(port ?? 0, '127.0.0.1', () => {
      server.off('error', reject);
      const address = server.address();
      if (!address || typeof address === 'string') {
        reject(new Error('Server failed to bind to a TCP port.'));
        return;
      }

      resolve(address.port);
    });
  });
}