import fs from 'node:fs';
import path from 'node:path';

import express from 'express';
import { ZodError } from 'zod';

import {
  browserSandboxRequestSchema,
  domainAnalysisRequestSchema,
  emailParsingRequestSchema,
  fileAnalysisRequestSchema,
  healthResponseSchema,
  urlAnalysisRequestSchema,
} from '../shared/analysis-types.js';
import { appConfig } from './config.js';
import { analyzeDomain, DomainAnalysisError } from './services/domain-analysis.js';
import {
  BrowserSandboxError,
  enqueueBrowserSandboxJob,
  getBrowserSandboxJob,
  stopBrowserSandboxJob,
} from './services/browser-sandbox.js';
import { analyzeEmail } from './services/email-analysis.js';
import { EmailParsingError, parseRawEmail } from './services/email-parser.js';
import { enqueueFileAnalysisJob, FileAnalysisError, getFileAnalysisJob } from './services/file-analysis.js';
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
  enqueueFileAnalysisJob?: typeof enqueueFileAnalysisJob;
  getFileAnalysisJob?: typeof getFileAnalysisJob;
};

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
  const enqueueFileAnalysisHandler = dependencies.enqueueFileAnalysisJob ?? enqueueFileAnalysisJob;
  const getFileAnalysisJobHandler = dependencies.getFileAnalysisJob ?? getFileAnalysisJob;
  const clientDistPath = path.resolve(appConfig.storageRoot, '..', 'dist');
  const clientEntryPath = path.join(clientDistPath, 'index.html');

  app.use(express.json({ limit: '2mb' }));

  app.get('/api/health', (_request, response) => {
    const payload = healthResponseSchema.parse({
      status: 'ok',
      service: appConfig.serviceName,
      timestamp: new Date().toISOString(),
      storage: ensureStorageDirectories(),
    });

    response.status(200).json(payload);
  });

  app.use('/storage', express.static(ensureStorageDirectories().root));

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

  app.post('/api/analyze/files', async (request, response) => {
    try {
      const payload = fileAnalysisRequestSchema.parse(request.body);
      const job = await enqueueFileAnalysisHandler(payload.files);

      response.status(202).json(job);
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

  app.get('/api/analyze/files/:jobId', async (request, response) => {
    const job = await getFileAnalysisJobHandler(request.params.jobId);
    if (!job) {
      response.status(404).json({
        error: 'not_found',
        message: 'File analysis job not found',
      });
      return;
    }

    response.status(200).json(job);
  });

  if (fs.existsSync(clientEntryPath)) {
    app.get(/^(?!\/api(?:\/|$))(?!\/storage(?:\/|$)).*/, (_request, response) => {
      response.sendFile(clientEntryPath);
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