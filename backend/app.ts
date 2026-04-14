import { createHmac, timingSafeEqual } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

import express from 'express';
import { ZodError } from 'zod';

import {
  caseSessionListResponseSchema,
  browserSandboxRequestSchema,
  caseSessionSchema,
  currentCaseSessionResponseSchema,
  domainAnalysisRequestSchema,
  emlAnalysisRequestSchema,
  emailParsingRequestSchema,
  fileAnalysisRequestSchema,
  healthResponseSchema,
  remoteFileAnalysisRequestSchema,
  urlAnalysisRequestSchema,
} from '../shared/analysis-types.js';
import { appConfig } from './config.js';
import { clearCurrentCaseSession, deleteCaseSession, getCaseSession, getCurrentCaseSession, listCaseSessions, saveCurrentCaseSession } from './services/case-session.js';
import { analyzeDomain, DomainAnalysisError } from './services/domain-analysis.js';
import {
  BrowserSandboxError,
  enqueueBrowserSandboxJob,
  getBrowserSandboxJob,
  stopBrowserSandboxJob,
  touchBrowserSandboxJob,
} from './services/browser-sandbox.js';
import { EmlAnalysisError, enqueueEmlAnalysisJob, getEmlAnalysisJob } from './services/eml-analysis.js';
import { analyzeEmail } from './services/email-analysis.js';
import { EmailParsingError, parseRawEmail } from './services/email-parser.js';
import { enqueueFileAnalysisJob, FileAnalysisError, getFileAnalysisJob } from './services/file-analysis.js';
import { enqueueRemoteFileAnalysisJob, RemoteFileAnalysisError } from './services/remote-file-analysis.js';
import { enqueueUrlAnalysisJob, getUrlAnalysisJob, UrlAnalysisError } from './services/url-analysis.js';
import { ensureStorageDirectories } from './storage.js';

type AppDependencies = {
  analyzeDomain?: typeof analyzeDomain;
  analyzeEmail?: typeof analyzeEmail;
  parseEmail?: typeof parseRawEmail;
  enqueueUrlAnalysis?: typeof enqueueUrlAnalysisJob;
  getUrlAnalysisJob?: typeof getUrlAnalysisJob;
  enqueueBrowserSandboxJob?: typeof enqueueBrowserSandboxJob;
  getBrowserSandboxJob?: typeof getBrowserSandboxJob;
  stopBrowserSandboxJob?: typeof stopBrowserSandboxJob;
  touchBrowserSandboxJob?: typeof touchBrowserSandboxJob;
  enqueueFileAnalysisJob?: typeof enqueueFileAnalysisJob;
  getFileAnalysisJob?: typeof getFileAnalysisJob;
  enqueueRemoteFileAnalysisJob?: typeof enqueueRemoteFileAnalysisJob;
  enqueueEmlAnalysisJob?: typeof enqueueEmlAnalysisJob;
  getEmlAnalysisJob?: typeof getEmlAnalysisJob;
  getCurrentCaseSession?: typeof getCurrentCaseSession;
  getCaseSession?: typeof getCaseSession;
  listCaseSessions?: typeof listCaseSessions;
  saveCurrentCaseSession?: typeof saveCurrentCaseSession;
  clearCurrentCaseSession?: typeof clearCurrentCaseSession;
  deleteCaseSession?: typeof deleteCaseSession;
};

const AUTH_COOKIE_NAME = 'phish_hunter_session';
const AUTH_SESSION_DURATION_MS = 12 * 60 * 60 * 1000;

export function createApp(dependencies: AppDependencies = {}) {
  const app = express();
  const analyzeDomainHandler = dependencies.analyzeDomain ?? analyzeDomain;
  const analyzeEmailHandler = dependencies.analyzeEmail ?? analyzeEmail;
  const parseEmailHandler = dependencies.parseEmail ?? parseRawEmail;
  const enqueueUrlAnalysisHandler = dependencies.enqueueUrlAnalysis ?? enqueueUrlAnalysisJob;
  const getUrlAnalysisJobHandler = dependencies.getUrlAnalysisJob ?? getUrlAnalysisJob;
  const enqueueBrowserSandboxHandler = dependencies.enqueueBrowserSandboxJob ?? enqueueBrowserSandboxJob;
  const getBrowserSandboxJobHandler = dependencies.getBrowserSandboxJob ?? getBrowserSandboxJob;
  const stopBrowserSandboxJobHandler = dependencies.stopBrowserSandboxJob ?? stopBrowserSandboxJob;
  const touchBrowserSandboxJobHandler = dependencies.touchBrowserSandboxJob ?? touchBrowserSandboxJob;
  const enqueueFileAnalysisHandler = dependencies.enqueueFileAnalysisJob ?? enqueueFileAnalysisJob;
  const getFileAnalysisJobHandler = dependencies.getFileAnalysisJob ?? getFileAnalysisJob;
  const enqueueRemoteFileAnalysisHandler = dependencies.enqueueRemoteFileAnalysisJob ?? enqueueRemoteFileAnalysisJob;
  const enqueueEmlAnalysisHandler = dependencies.enqueueEmlAnalysisJob ?? enqueueEmlAnalysisJob;
  const getEmlAnalysisJobHandler = dependencies.getEmlAnalysisJob ?? getEmlAnalysisJob;
  const getCurrentCaseSessionHandler = dependencies.getCurrentCaseSession ?? getCurrentCaseSession;
  const getCaseSessionHandler = dependencies.getCaseSession ?? getCaseSession;
  const listCaseSessionsHandler = dependencies.listCaseSessions ?? listCaseSessions;
  const saveCurrentCaseSessionHandler = dependencies.saveCurrentCaseSession ?? saveCurrentCaseSession;
  const clearCurrentCaseSessionHandler = dependencies.clearCurrentCaseSession ?? clearCurrentCaseSession;
  const deleteCaseSessionHandler = dependencies.deleteCaseSession ?? deleteCaseSession;
  const clientDistPath = path.resolve(appConfig.storageRoot, '..', 'dist');
  const clientEntryPath = path.join(clientDistPath, 'index.html');
  const accessPassword = getConfiguredAccessPassword();
  const sessionSecret = getSessionSecret(accessPassword);

  app.use(express.json({ limit: '2mb' }));

  app.post('/api/auth/login', (request, response) => {
    if (!accessPassword || !sessionSecret) {
      response.status(200).json({ authenticated: true });
      return;
    }

    const password = typeof request.body?.password === 'string' ? request.body.password : '';
    if (!matchesSecret(password, accessPassword)) {
      response.status(401).json({ error: 'unauthorized', message: 'Invalid credentials.' });
      return;
    }

    const token = createSessionToken(sessionSecret);
    response.setHeader('Set-Cookie', buildSessionCookie(token));
    response.status(200).json({ authenticated: true });
  });

  app.get('/api/auth/session', (request, response) => {
    response.status(200).json({ authenticated: !sessionSecret || hasValidSession(request.headers.cookie, sessionSecret) });
  });

  app.get('/api/auth/verify', (request, response) => {
    if (sessionSecret && !hasValidSession(request.headers.cookie, sessionSecret)) {
      response.status(401).end();
      return;
    }

    response.status(204).end();
  });

  app.post('/api/auth/logout', (_request, response) => {
    if (sessionSecret) {
      response.setHeader('Set-Cookie', clearSessionCookie());
    }
    response.status(204).end();
  });

  app.use('/storage', requireAuthenticatedSession(sessionSecret), express.static(ensureStorageDirectories().root));

  app.use('/api', (request, response, next) => {
    if (request.path.startsWith('/auth/')) {
      next();
      return;
    }

    requireAuthenticatedSession(sessionSecret)(request, response, next);
  });

  app.get('/api/health', (_request, response) => {
    const payload = healthResponseSchema.parse({
      status: 'ok',
      service: appConfig.serviceName,
      timestamp: new Date().toISOString(),
      storage: ensureStorageDirectories(),
    });

    response.status(200).json(payload);
  });

  app.get('/api/cases/current', async (_request, response) => {
    const currentCaseSession = await getCurrentCaseSessionHandler();
    response.status(200).json(currentCaseSessionResponseSchema.parse({ case: currentCaseSession }));
  });

  app.get('/api/cases', async (_request, response) => {
    const cases = await listCaseSessionsHandler();
    response.status(200).json(caseSessionListResponseSchema.parse({ cases }));
  });

  app.post('/api/cases/:caseId/activate', async (request, response) => {
    const storedCaseSession = await getCaseSessionHandler(request.params.caseId);

    if (!storedCaseSession) {
      response.status(404).json({
        error: 'case_session_not_found',
        message: 'The requested CASE session could not be found.',
      });
      return;
    }

    const activatedCaseSession = await saveCurrentCaseSessionHandler(storedCaseSession);
    response.status(200).json(activatedCaseSession);
  });

  app.delete('/api/cases/current', async (_request, response) => {
    await clearCurrentCaseSessionHandler();
    response.status(204).end();
  });

  app.delete('/api/cases/:caseId', async (request, response) => {
    await deleteCaseSessionHandler(request.params.caseId);
    response.status(204).end();
  });

  app.put('/api/cases/current', async (request, response) => {
    try {
      const payload = caseSessionSchema.parse(request.body);
      const savedCaseSession = await saveCurrentCaseSessionHandler(payload);

      response.status(200).json(savedCaseSession);
    } catch (error) {
      if (error instanceof ZodError) {
        response.status(400).json({
          error: 'invalid_case_session',
          message: 'A valid CASE session payload is required.',
        });
        return;
      }

      response.status(500).json({
        error: 'case_session_failed',
        message: 'CASE session persistence failed unexpectedly.',
      });
    }
  });

  if (fs.existsSync(clientEntryPath)) {
    app.use(express.static(clientDistPath));
  }

  app.post('/api/analyze/domain', async (request, response) => {
    try {
      const payload = domainAnalysisRequestSchema.parse(request.body);
      const result = await analyzeDomainHandler(payload.domain);

      response.status(200).json(result);
    } catch (error) {
      if (error instanceof DomainAnalysisError) {
        response.status(400).json({
          error: error.code,
          message: error.message,
        });
        return;
      }

      response.status(500).json({
        error: 'domain_analysis_failed',
        message: 'Domain analysis failed unexpectedly.',
      });
    }
  });

  app.post('/api/analyze/email/parse', async (request, response) => {
    try {
      const payload = emailParsingRequestSchema.parse(request.body);
      const result = await parseEmailHandler(payload.rawEmail);

      response.status(200).json(result);
    } catch (error) {
      if (error instanceof EmailParsingError) {
        response.status(400).json({
          error: error.code,
          message: error.message,
        });
        return;
      }

      if (error instanceof ZodError) {
        response.status(400).json({
          error: 'invalid_email',
          message: 'Raw email is required.',
        });
        return;
      }

      response.status(500).json({
        error: 'email_parsing_failed',
        message: 'Email parsing failed unexpectedly.',
      });
    }
  });

  app.post('/api/analyze/email', async (request, response) => {
    try {
      const payload = emailParsingRequestSchema.parse(request.body);
      const result = await analyzeEmailHandler(payload.rawEmail);

      response.status(200).json(result);
    } catch (error) {
      if (error instanceof EmailParsingError) {
        response.status(400).json({
          error: error.code,
          message: error.message,
        });
        return;
      }

      if (error instanceof ZodError) {
        response.status(400).json({
          error: 'invalid_email',
          message: 'Raw email is required.',
        });
        return;
      }

      response.status(500).json({
        error: 'email_analysis_failed',
        message: 'Email analysis failed unexpectedly.',
      });
    }
  });

  app.post('/api/analyze/eml', async (request, response) => {
    try {
      const payload = emlAnalysisRequestSchema.parse(request.body);
      const job = await enqueueEmlAnalysisHandler(payload.filename, payload.rawEmail);

      response.status(202).json(job);
    } catch (error) {
      if (error instanceof EmlAnalysisError) {
        response.status(400).json({
          error: error.code,
          message: error.message,
        });
        return;
      }

      if (error instanceof ZodError) {
        response.status(400).json({
          error: 'invalid_eml',
          message: 'A filename and raw email content are required.',
        });
        return;
      }

      response.status(500).json({
        error: 'eml_analysis_failed',
        message: 'EML analysis job creation failed unexpectedly.',
      });
    }
  });

  app.get('/api/analyze/eml/:jobId', async (request, response) => {
    const job = await getEmlAnalysisJobHandler(request.params.jobId);
    if (!job) {
      response.status(404).json({
        error: 'not_found',
        message: 'EML analysis job not found',
      });
      return;
    }

    response.status(200).json(job);
  });

  app.post('/api/analyze/urls', async (request, response) => {
    try {
      const payload = urlAnalysisRequestSchema.parse(request.body);
      const job = await enqueueUrlAnalysisHandler(payload.urls);

      response.status(202).json(job);
    } catch (error) {
      if (error instanceof UrlAnalysisError) {
        response.status(400).json({
          error: error.code,
          message: error.message,
        });
        return;
      }

      if (error instanceof ZodError) {
        response.status(400).json({
          error: 'invalid_url_target',
          message: 'At least one public URL is required for analysis.',
        });
        return;
      }

      response.status(500).json({
        error: 'url_analysis_failed',
        message: 'URL analysis job creation failed unexpectedly.',
      });
    }
  });

  app.get('/api/analyze/urls/:jobId', async (request, response) => {
    const job = await getUrlAnalysisJobHandler(request.params.jobId);
    if (!job) {
      response.status(404).json({
        error: 'not_found',
        message: 'URL analysis job not found',
      });
      return;
    }

    response.status(200).json(job);
  });

  app.post('/api/sandbox/browser', async (request, response) => {
    try {
      const payload = browserSandboxRequestSchema.parse(request.body);
      const job = await enqueueBrowserSandboxHandler(payload.url);

      response.status(202).json(job);
    } catch (error) {
      if (error instanceof BrowserSandboxError) {
        response.status(400).json({
          error: error.code,
          message: error.message,
        });
        return;
      }

      if (error instanceof ZodError) {
        response.status(400).json({
          error: 'invalid_url_target',
          message: 'A public HTTP(S) URL is required to launch the sandbox.',
        });
        return;
      }

      response.status(500).json({
        error: 'browser_sandbox_failed',
        message: 'Browser sandbox launch failed unexpectedly.',
      });
    }
  });

  app.get('/api/sandbox/browser/:jobId', async (request, response) => {
    const job = await getBrowserSandboxJobHandler(request.params.jobId);
    if (!job) {
      response.status(404).json({
        error: 'not_found',
        message: 'Browser sandbox job not found',
      });
      return;
    }

    response.status(200).json(job);
  });

  app.post('/api/sandbox/browser/:jobId/stop', async (request, response) => {
    const job = await stopBrowserSandboxJobHandler(request.params.jobId);
    if (!job) {
      response.status(404).json({
        error: 'not_found',
        message: 'Browser sandbox job not found',
      });
      return;
    }

    response.status(200).json(job);
  });

  app.post('/api/sandbox/browser/:jobId/heartbeat', async (request, response) => {
    const job = await touchBrowserSandboxJobHandler(request.params.jobId);
    if (!job) {
      response.status(404).json({
        error: 'not_found',
        message: 'Browser sandbox job not found',
      });
      return;
    }

    response.status(200).json(job);
  });

  app.post('/api/analyze/files', async (request, response) => {
    try {
      const payload = fileAnalysisRequestSchema.parse(request.body);
      const job = await enqueueFileAnalysisHandler(payload.files);

      response.status(202).json(redactFileJob(job));
    } catch (error) {
      if (error instanceof FileAnalysisError) {
        response.status(400).json({
          error: error.code,
          message: error.message,
        });
        return;
      }

      if (error instanceof ZodError) {
        response.status(400).json({
          error: 'invalid_file_upload',
          message: 'At least one uploaded file is required for analysis.',
        });
        return;
      }

      response.status(500).json({
        error: 'file_analysis_failed',
        message: 'File analysis job creation failed unexpectedly.',
      });
    }
  });

  app.post('/api/analyze/files/remote', async (request, response) => {
    try {
      const payload = remoteFileAnalysisRequestSchema.parse(request.body);
      const job = await enqueueRemoteFileAnalysisHandler(payload.url);

      response.status(202).json(redactFileJob(job));
    } catch (error) {
      if (error instanceof RemoteFileAnalysisError || error instanceof FileAnalysisError) {
        response.status(400).json({
          error: error.code,
          message: error.message,
        });
        return;
      }

      if (error instanceof ZodError) {
        response.status(400).json({
          error: 'invalid_remote_file_upload',
          message: 'A public HTTP(S) file URL is required for remote analysis.',
        });
        return;
      }

      response.status(500).json({
        error: 'remote_file_analysis_failed',
        message: 'Remote file analysis job creation failed unexpectedly.',
      });
    }
  });

  app.get('/api/analyze/files/:jobId', async (request, response) => {
    const job = await getFileAnalysisJobHandler(request.params.jobId);
    if (!job) {
      response.status(404).json({
        error: 'not_found',
        message: 'File analysis job not found',
      });
      return;
    }

    response.status(200).json(redactFileJob(job));
  });

  if (fs.existsSync(clientEntryPath)) {
    app.get(/^(?!\/api(?:\/|$)).*/, (_request, response) => {
      response.type('html').send(fs.readFileSync(clientEntryPath, 'utf8'));
    });
  }

  app.use((_request, response) => {
    response.status(404).json({
      error: 'not_found',
      message: 'Route not found',
    });
  });

  return app;
}

function getConfiguredAccessPassword() {
  return process.env.APP_ACCESS_PASSWORD?.trim() || process.env.APP_AUTH_PASSWORD?.trim() || null;
}

function getSessionSecret(accessPassword: string | null) {
  if (!accessPassword) {
    return null;
  }

  return process.env.APP_SESSION_SECRET?.trim() || accessPassword;
}

function matchesSecret(candidate: string, expected: string) {
  const candidateBuffer = Buffer.from(candidate);
  const expectedBuffer = Buffer.from(expected);
  return candidateBuffer.length === expectedBuffer.length && timingSafeEqual(candidateBuffer, expectedBuffer);
}

function parseCookieHeader(cookieHeader: string | undefined) {
  return Object.fromEntries(
    (cookieHeader ?? '')
      .split(';')
      .map((part) => part.trim())
      .filter(Boolean)
      .map((part) => {
        const separatorIndex = part.indexOf('=');
        if (separatorIndex < 0) {
          return [part, ''];
        }

        return [part.slice(0, separatorIndex), decodeURIComponent(part.slice(separatorIndex + 1))];
      }),
  );
}

function createSessionToken(secret: string) {
  const payload = Buffer.from(JSON.stringify({ exp: Date.now() + AUTH_SESSION_DURATION_MS })).toString('base64url');
  const signature = createHmac('sha256', secret).update(payload).digest('base64url');
  return `${payload}.${signature}`;
}

function hasValidSession(cookieHeader: string | undefined, secret: string) {
  const token = parseCookieHeader(cookieHeader)[AUTH_COOKIE_NAME];
  if (!token) {
    return false;
  }

  const [payload, providedSignature] = token.split('.');
  if (!payload || !providedSignature) {
    return false;
  }

  const expectedSignature = createHmac('sha256', secret).update(payload).digest('base64url');
  if (!matchesSecret(providedSignature, expectedSignature)) {
    return false;
  }

  try {
    const decoded = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as { exp?: number };
    return typeof decoded.exp === 'number' && decoded.exp > Date.now();
  } catch {
    return false;
  }
}

function buildSessionCookie(token: string) {
  const maxAgeSeconds = Math.floor(AUTH_SESSION_DURATION_MS / 1000);
  return `${AUTH_COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=${maxAgeSeconds}`;
}

function clearSessionCookie() {
  return `${AUTH_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=0`;
}

function requireAuthenticatedSession(secret: string | null) {
  return (request: express.Request, response: express.Response, next: express.NextFunction) => {
    if (secret && !hasValidSession(request.headers.cookie, secret)) {
      response.status(401).json({ error: 'unauthorized', message: 'Authentication required.' });
      return;
    }

    next();
  };
}

function redactFileJob(job: { results?: Array<{ storagePath?: string | null; artifacts?: Array<{ path?: string }> }> }) {
  if (!job.results) return job;
  return {
    ...job,
    results: job.results.map((r) => ({
      ...r,
      storagePath: null,
      artifacts: (r.artifacts ?? []).map((a) => ({ ...a, path: '' })),
    })),
  };
}