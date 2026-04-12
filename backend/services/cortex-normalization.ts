import type {
  CortexAnalyzerResult,
  CortexArtifact,
  CortexTaxonomy,
  ExternalAnalyzerStatus,
  ExternalAnalyzerVerdict,
} from '../../shared/analysis-types.js';

type CortexNormalizationInput = {
  analyzerId: string;
  analyzerName?: string;
  targetType: CortexAnalyzerResult['targetType'];
  target: string;
  report: unknown;
  status?: ExternalAnalyzerStatus;
};

type CortexFailureInput = {
  analyzerId: string;
  analyzerName?: string;
  targetType: CortexAnalyzerResult['targetType'];
  target: string;
  status: Extract<ExternalAnalyzerStatus, 'failed' | 'unavailable'>;
  summary: string;
};

export function normalizeCortexAnalyzerResult(input: CortexNormalizationInput): CortexAnalyzerResult {
  const taxonomies = extractTaxonomies(input.report);
  const verdict = deriveVerdict(taxonomies);
  const summary = extractSummary(input.report, taxonomies, verdict);

  return {
    provider: 'cortex',
    analyzerId: input.analyzerId,
    analyzerName: input.analyzerName ?? input.analyzerId,
    targetType: input.targetType,
    target: input.target,
    status: input.status ?? 'completed',
    verdict,
    summary,
    confidence: deriveConfidence(verdict),
    reference: extractReference(input.report),
    taxonomies,
    artifacts: extractArtifacts(input.report),
    rawReport: input.report,
  };
}

export function buildFailedCortexAnalyzerResult(input: CortexFailureInput): CortexAnalyzerResult {
  return {
    provider: 'cortex',
    analyzerId: input.analyzerId,
    analyzerName: input.analyzerName ?? input.analyzerId,
    targetType: input.targetType,
    target: input.target,
    status: input.status,
    verdict: input.status === 'unavailable' ? 'unavailable' : 'informational',
    summary: input.summary,
    confidence: null,
    reference: null,
    taxonomies: [],
    artifacts: [],
    rawReport: null,
  };
}

function extractSummary(report: unknown, taxonomies: CortexTaxonomy[], verdict: ExternalAnalyzerVerdict) {
  if (typeof report === 'string' && report.trim().length > 0) {
    return report.trim();
  }

  if (isRecord(report)) {
    const directSummary = coerceNonEmptyString(report.summary);
    if (directSummary) {
      return directSummary;
    }

    if (isRecord(report.summary)) {
      const nestedSummary = coerceNonEmptyString(report.summary.long);
      if (nestedSummary) {
        return nestedSummary;
      }

      const shortSummary = coerceNonEmptyString(report.summary.short);
      if (shortSummary) {
        return shortSummary;
      }

      const operationSummary = coerceNonEmptyString(report.summary.operation);
      if (operationSummary) {
        return operationSummary;
      }
    }
  }

  if (taxonomies.length > 0) {
    return taxonomies.map((taxonomy) => `${taxonomy.namespace}:${taxonomy.predicate}=${taxonomy.value}`).join('; ');
  }

  switch (verdict) {
    case 'malicious':
      return 'Cortex returned malicious evidence.';
    case 'suspicious':
      return 'Cortex returned suspicious evidence.';
    case 'clean':
      return 'Cortex did not return malicious evidence.';
    case 'pending':
      return 'Cortex analysis is still pending.';
    case 'unavailable':
      return 'Cortex results are unavailable.';
    case 'informational':
    default:
      return 'Cortex returned informational evidence.';
  }
}

function extractReference(report: unknown) {
  if (!isRecord(report)) {
    return null;
  }

  const directReference = coerceNonEmptyString(report.reference);
  if (directReference) {
    return directReference;
  }

  const full = report.full;
  if (isRecord(full)) {
    return coerceNonEmptyString(full.reference) ?? coerceNonEmptyString(full.url) ?? null;
  }

  return null;
}

function extractTaxonomies(report: unknown): CortexTaxonomy[] {
  const candidateSources = [
    isRecord(report) ? report.taxonomies : undefined,
    isRecord(report) && isRecord(report.summary) ? report.summary.taxonomies : undefined,
  ];

  for (const source of candidateSources) {
    if (!Array.isArray(source)) {
      continue;
    }

    return source.flatMap((entry) => {
      if (!isRecord(entry)) {
        return [];
      }

      const namespace = coerceNonEmptyString(entry.namespace);
      const predicate = coerceNonEmptyString(entry.predicate);
      const value = coerceNonEmptyString(entry.value);
      if (!namespace || !predicate || !value) {
        return [];
      }

      return [{
        level: coerceNonEmptyString(entry.level),
        namespace,
        predicate,
        value,
      } satisfies CortexTaxonomy];
    });
  }

  return [];
}

function extractArtifacts(report: unknown): CortexArtifact[] {
  if (!isRecord(report) || !Array.isArray(report.artifacts)) {
    return [];
  }

  return report.artifacts.flatMap((entry) => {
    if (!isRecord(entry)) {
      return [];
    }

    const dataType = coerceNonEmptyString(entry.dataType);
    const data = coerceNonEmptyString(entry.data);
    if (!dataType || !data) {
      return [];
    }

    return [{
      dataType,
      data,
      message: coerceNonEmptyString(entry.message),
      tags: Array.isArray(entry.tags) ? entry.tags.filter((tag): tag is string => typeof tag === 'string') : [],
    } satisfies CortexArtifact];
  });
}

function deriveVerdict(taxonomies: CortexTaxonomy[]): ExternalAnalyzerVerdict {
  const levels = taxonomies
    .map((taxonomy) => taxonomy.level?.toLowerCase())
    .filter((level): level is string => Boolean(level));

  if (levels.some((level) => level.includes('malicious'))) {
    return 'malicious';
  }

  if (levels.some((level) => level.includes('suspicious'))) {
    return 'suspicious';
  }

  if (levels.some((level) => level.includes('safe'))) {
    return 'clean';
  }

  return taxonomies.length > 0 ? 'informational' : 'clean';
}

function deriveConfidence(verdict: ExternalAnalyzerVerdict) {
  switch (verdict) {
    case 'malicious':
      return 90;
    case 'suspicious':
      return 70;
    case 'clean':
      return 30;
    case 'informational':
      return 20;
    case 'pending':
    case 'unavailable':
    default:
      return null;
  }
}

function coerceNonEmptyString(value: unknown) {
  return typeof value === 'string' && value.trim().length > 0 ? value.trim() : null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}