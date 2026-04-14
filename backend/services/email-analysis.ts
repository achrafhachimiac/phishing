import { emailAnalysisResponseSchema, type EmailAnalysisResponse } from '../../shared/analysis-types.js';
import { analyzeDomain, type DomainAnalysisError } from './domain-analysis.js';
import { parseRawEmail } from './email-parser.js';

type AnalyzeEmailDependencies = {
  analyzeRelatedDomain?: typeof analyzeDomain;
};

export async function analyzeEmail(
  rawEmail: string,
  dependencies: AnalyzeEmailDependencies = {},
): Promise<EmailAnalysisResponse> {
  const parsedEmail = await parseRawEmail(rawEmail);
  const analyzeRelatedDomain = dependencies.analyzeRelatedDomain ?? analyzeDomain;
  const inconsistencies: string[] = [];

  if (parsedEmail.authentication.spf === 'fail') {
    inconsistencies.push(
      parsedEmail.authentication.spfDetails?.reason
        ? `SPF failed: ${parsedEmail.authentication.spfDetails.reason}.`
        : 'SPF failed for the sending domain.',
    );
  }

  if (parsedEmail.authentication.dkim === 'fail') {
    inconsistencies.push(
      parsedEmail.authentication.dkimDetails?.reason
        ? `DKIM failed: ${parsedEmail.authentication.dkimDetails.reason}.`
        : 'DKIM failed for the visible sender domain.',
    );
  }

  if (parsedEmail.authentication.dmarc === 'fail') {
    const dmarcAction = parsedEmail.authentication.dmarcDetails?.action;
    inconsistencies.push(
      dmarcAction
        ? `DMARC failed for the visible sender domain (action=${dmarcAction}).`
        : 'DMARC failed for the visible sender domain.',
    );
  }

  if (parsedEmail.headers.from && parsedEmail.headers.returnPath) {
    const fromDomain = parsedEmail.headers.from.match(/@([A-Z0-9.-]+\.[A-Z]{2,63})/i)?.[1]?.toLowerCase();
    const returnPathDomain = parsedEmail.headers.returnPath.match(/@?([A-Z0-9.-]+\.[A-Z]{2,63})/i)?.[1]?.toLowerCase();

    if (fromDomain && returnPathDomain && fromDomain !== returnPathDomain) {
      inconsistencies.push('From and Return-Path domains are misaligned.');
    }
  }

  if ((parsedEmail.headers.subject || '').match(/urgent|verify|review|suspend|password|invoice/i)) {
    inconsistencies.push('The subject uses high-pressure or credential-themed wording.');
  }

  const analyzedUrls = parsedEmail.urls.map((url) => {
    const urlSignals: string[] = [];

    if (url.decodedUrl.match(/login|verify|secure|update|password|signin/i)) {
      urlSignals.push('The URL uses urgent credential-themed wording.');
    }

    if (url.wrapperType === 'barracuda' && url.decodedUrl !== url.originalUrl) {
      urlSignals.push('Barracuda LinkProtect rewrote the visible URL to a different destination.');
    }

    if (parsedEmail.authentication.spf === 'fail' || parsedEmail.authentication.dmarc === 'fail') {
      urlSignals.push('The email authentication posture is inconsistent.');
    }

    return {
      ...url,
      suspicious: urlSignals.length > 0,
      reason: urlSignals.join(' ') || 'No high-confidence issue detected from the static checks.',
    };
  });

  const score =
    (parsedEmail.authentication.spf === 'fail' ? 25 : 0) +
    (parsedEmail.authentication.dmarc === 'fail' ? 25 : 0) +
    (parsedEmail.authentication.dkim === 'fail' ? 15 : 0) +
    (parsedEmail.urls.length > 0 ? 5 : 0) +
    (inconsistencies.length * 5);

  const threatLevel = score >= 95 ? 'CRITICAL' : score >= 50 ? 'HIGH' : score >= 25 ? 'MEDIUM' : 'LOW';
  const executiveSummary =
    inconsistencies.length > 0
      ? `The email shows ${inconsistencies.length} risk signals, including authentication anomalies and phishing-style lures.`
      : 'The email contains limited suspicious evidence from the current static analysis.';

  const relatedDomainCandidates = collectRelatedDomains(parsedEmail);
  const relatedDomains = await Promise.all(
    relatedDomainCandidates.map(async ({ domain, relation }) => {
      const analysis = await analyzeRelatedDomain(domain);

      return {
        domain,
        relation,
        analysis,
      };
    }),
  );

  return emailAnalysisResponseSchema.parse({
    ...parsedEmail,
    urls: analyzedUrls,
    inconsistencies,
    threatLevel,
    executiveSummary,
    relatedDomains,
  });
}

function collectRelatedDomains(parsedEmail: Awaited<ReturnType<typeof parseRawEmail>>) {
  const candidates = new Map<string, 'from' | 'return-path' | 'url' | 'discovered'>();

  const fromDomain = extractDomainFromHeader(parsedEmail.headers.from);
  if (fromDomain) {
    upsertCandidate(candidates, fromDomain, 'from');
  }

  const returnPathDomain = extractDomainFromHeader(parsedEmail.headers.returnPath);
  if (returnPathDomain) {
    upsertCandidate(candidates, returnPathDomain, 'return-path');
  }

  parsedEmail.urls.forEach((url) => {
    const domain = extractDomainFromUrl(url.decodedUrl);
    if (domain) {
      upsertCandidate(candidates, domain, 'url');
    }
  });

  parsedEmail.domains.forEach((domain) => {
    upsertCandidate(candidates, domain, 'discovered');
  });

  return [...candidates.entries()].map(([domain, relation]) => ({ domain, relation }));
}

function extractDomainFromHeader(value: string | null): string | null {
  return value?.match(/@([A-Z0-9.-]+\.[A-Z]{2,63})/i)?.[1]?.toLowerCase() ?? null;
}

function extractDomainFromUrl(value: string): string | null {
  try {
    return new URL(value).hostname.toLowerCase();
  } catch {
    return null;
  }
}

function upsertCandidate(
  candidates: Map<string, 'from' | 'return-path' | 'url' | 'discovered'>,
  domain: string,
  relation: 'from' | 'return-path' | 'url' | 'discovered',
) {
  const currentRelation = candidates.get(domain);
  if (!currentRelation || relationPriority(relation) > relationPriority(currentRelation)) {
    candidates.set(domain, relation);
  }
}

function relationPriority(relation: 'from' | 'return-path' | 'url' | 'discovered') {
  switch (relation) {
    case 'url':
      return 4;
    case 'return-path':
      return 3;
    case 'from':
      return 2;
    case 'discovered':
    default:
      return 1;
  }
}