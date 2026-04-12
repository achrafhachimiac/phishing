import { appConfig } from '../config.js';
import { submitCortexAnalyzerJob, waitForCortexJobReport, type CortexObservableDataType } from './cortex-client.js';
import { buildFailedCortexAnalyzerResult, normalizeCortexAnalyzerResult } from './cortex-normalization.js';
import type { CortexAnalyzerResult, CortexProviderSummary, ExternalAnalyzerStatus, FileStaticAnalysisResult } from '../../shared/analysis-types.js';

export type CortexBatchAnalysis = {
  status: ExternalAnalyzerStatus;
  results: CortexAnalyzerResult[];
  summary: string;
  updatedAt: string | null;
};

export async function analyzeEmailWithCortex(filename: string, rawEmail: string): Promise<CortexBatchAnalysis> {
  return runConfiguredCortexAnalyzers({
    analyzerIds: appConfig.cortex.analyzers.eml,
    dataType: 'mail',
    targetType: 'eml',
    target: filename,
    data: rawEmail,
    unavailableSummary: 'No Cortex EML analyzers are configured.',
  });
}

export async function analyzeObservablesWithCortex(
  urls: string[],
  domains: string[],
): Promise<CortexBatchAnalysis> {
  const urlPromises = urls.flatMap((url) => appConfig.cortex.analyzers.url.map((analyzerId) =>
    runSingleCortexAnalyzer({
      analyzerId,
      dataType: 'url',
      targetType: 'url',
      target: url,
      data: url,
    })
  ));
  const domainPromises = domains.flatMap((domain) => appConfig.cortex.analyzers.domain.map((analyzerId) =>
    runSingleCortexAnalyzer({
      analyzerId,
      dataType: 'domain',
      targetType: 'domain',
      target: domain,
      data: domain,
    })
  ));

  const results = await Promise.all([...urlPromises, ...domainPromises]);
  return buildBatchResult(results.flat(), 'No Cortex URL or domain analyzers are configured.');
}

export async function analyzeFileHashesWithCortex(
  fileResults: FileStaticAnalysisResult[],
): Promise<CortexBatchAnalysis> {
  const analyzers = appConfig.cortex.analyzers.fileHash;
  const jobs = fileResults.flatMap((fileResult) => analyzers.map((analyzerId) =>
    runSingleCortexAnalyzer({
      analyzerId,
      dataType: 'hash',
      targetType: 'file_hash',
      target: fileResult.filename,
      data: fileResult.sha256,
    })
  ));

  const results = await Promise.all(jobs);
  return buildBatchResult(results.flat(), 'No Cortex file hash analyzers are configured.');
}

export async function analyzeUrlWithCortex(url: string): Promise<CortexProviderSummary> {
  return summarizeConfiguredAnalyzerResults(
    await runConfiguredCortexAnalyzers({
      analyzerIds: appConfig.cortex.analyzers.url,
      dataType: 'url',
      targetType: 'url',
      target: url,
      data: url,
      unavailableSummary: 'No Cortex URL analyzers are configured.',
    }),
  );
}

export async function analyzeDomainWithCortex(domain: string): Promise<CortexProviderSummary> {
  return summarizeConfiguredAnalyzerResults(
    await runConfiguredCortexAnalyzers({
      analyzerIds: appConfig.cortex.analyzers.domain,
      dataType: 'domain',
      targetType: 'domain',
      target: domain,
      data: domain,
      unavailableSummary: 'No Cortex domain analyzers are configured.',
    }),
  );
}

export async function analyzeFileHashWithCortex(filename: string, sha256: string): Promise<CortexProviderSummary> {
  return summarizeConfiguredAnalyzerResults(
    await runConfiguredCortexAnalyzers({
      analyzerIds: appConfig.cortex.analyzers.fileHash,
      dataType: 'hash',
      targetType: 'file_hash',
      target: filename,
      data: sha256,
      unavailableSummary: 'No Cortex file hash analyzers are configured.',
    }),
  );
}

type RunConfiguredAnalyzerInput = {
  analyzerIds: string[];
  dataType: CortexObservableDataType;
  targetType: CortexAnalyzerResult['targetType'];
  target: string;
  data: string;
  unavailableSummary: string;
};

async function runConfiguredCortexAnalyzers(input: RunConfiguredAnalyzerInput): Promise<CortexBatchAnalysis> {
  const jobs = input.analyzerIds.map((analyzerId) => runSingleCortexAnalyzer({
    analyzerId,
    dataType: input.dataType,
    targetType: input.targetType,
    target: input.target,
    data: input.data,
  }));

  const results = await Promise.all(jobs);
  return buildBatchResult(results.flat(), input.unavailableSummary);
}

type RunSingleAnalyzerInput = {
  analyzerId: string;
  dataType: CortexObservableDataType;
  targetType: CortexAnalyzerResult['targetType'];
  target: string;
  data: string;
};

async function runSingleCortexAnalyzer(input: RunSingleAnalyzerInput): Promise<CortexAnalyzerResult[]> {
  if (!appConfig.cortex.enabled) {
    return [];
  }

  try {
    const submittedJob = await submitCortexAnalyzerJob({
      analyzerId: input.analyzerId,
      dataType: input.dataType,
      data: input.data,
    });
    const completedJob = await waitForCortexJobReport(submittedJob.jobId);

    if (!completedJob.report) {
      return [buildFailedCortexAnalyzerResult({
        analyzerId: input.analyzerId,
        targetType: input.targetType,
        target: input.target,
        status: completedJob.job.status === 'Failure' ? 'failed' : 'unavailable',
        summary: `Cortex analyzer ${input.analyzerId} completed without a usable report.`,
      })];
    }

    return [normalizeCortexAnalyzerResult({
      analyzerId: input.analyzerId,
      targetType: input.targetType,
      target: input.target,
      report: completedJob.report,
    })];
  } catch (error) {
    return [buildFailedCortexAnalyzerResult({
      analyzerId: input.analyzerId,
      targetType: input.targetType,
      target: input.target,
      status: 'unavailable',
      summary: error instanceof Error ? error.message : `Cortex analyzer ${input.analyzerId} failed unexpectedly.`,
    })];
  }
}

function buildBatchResult(results: CortexAnalyzerResult[], unavailableSummary: string): CortexBatchAnalysis {
  if (!appConfig.cortex.enabled || results.length === 0) {
    return {
      status: 'unavailable',
      results: [],
      summary: unavailableSummary,
      updatedAt: null,
    };
  }

  const completedCount = results.filter((result) => result.status === 'completed').length;
  const unavailableCount = results.filter((result) => result.status === 'unavailable').length;
  const failedCount = results.filter((result) => result.status === 'failed').length;

  const status: ExternalAnalyzerStatus = completedCount > 0
    ? 'completed'
    : unavailableCount === results.length
      ? 'unavailable'
      : 'failed';

  return {
    status,
    results,
    summary: `Cortex analyzers processed ${results.length} runs (${completedCount} completed, ${failedCount} failed, ${unavailableCount} unavailable).`,
    updatedAt: new Date().toISOString(),
  };
}

function summarizeConfiguredAnalyzerResults(batch: CortexBatchAnalysis): CortexProviderSummary {
  if (!appConfig.cortex.enabled) {
    return {
      status: 'not_configured',
      analyzerCount: 0,
      matchedAnalyzerCount: 0,
      summary: 'Cortex integration is disabled.',
    };
  }

  if (batch.results.length === 0) {
    return {
      status: 'not_configured',
      analyzerCount: 0,
      matchedAnalyzerCount: 0,
      summary: batch.summary,
    };
  }

  const maliciousCount = batch.results.filter((result) => result.verdict === 'malicious').length;
  const suspiciousCount = batch.results.filter((result) => result.verdict === 'suspicious').length;
  const matchedAnalyzerCount = maliciousCount + suspiciousCount;

  return {
    status: maliciousCount > 0 ? 'malicious' : suspiciousCount > 0 ? 'suspicious' : batch.status === 'unavailable' ? 'unavailable' : 'clean',
    analyzerCount: batch.results.length,
    matchedAnalyzerCount,
    summary: batch.summary,
  };
}