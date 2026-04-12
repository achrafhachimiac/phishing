import type {
  FileEnrichedIoc,
  FileIndicator,
  FileIocEnrichment,
  FileIocProviderResult,
} from '../../shared/analysis-types.js';
import { lookupDomainReputation, lookupUrlThreatIntel } from './threat-intel.js';

const MAX_URL_IOCS = 8;
const MAX_DOMAIN_IOCS = 8;

export async function enrichFileIocs(extractedUrls: string[]): Promise<{
  enrichment: FileIocEnrichment;
  indicators: FileIndicator[];
}> {
  const normalizedUrls = deduplicateValues(extractedUrls)
    .filter((value) => isValidHttpUrl(value))
    .slice(0, MAX_URL_IOCS);
  const extractedDomains = deduplicateValues(
    normalizedUrls
      .map((value) => extractDomain(value))
      .filter((value): value is string => Boolean(value)),
  ).slice(0, MAX_DOMAIN_IOCS);

  if (normalizedUrls.length === 0 && extractedDomains.length === 0) {
    return {
      enrichment: buildIocEnrichmentSnapshot({
        status: 'completed',
        extractedUrls: [],
        extractedDomains: [],
        results: [],
        summary: 'No enrichable URLs or domains were extracted from this file.',
      }),
      indicators: [],
    };
  }

  const [urlResults, domainResults] = await Promise.all([
    Promise.all(normalizedUrls.map((url) => enrichUrlIoc(url))),
    Promise.all(extractedDomains.map((domain) => enrichDomainIoc(domain))),
  ]);

  const results = [...urlResults, ...domainResults];

  return {
    enrichment: buildIocEnrichmentSnapshot({
      status: 'completed',
      extractedUrls: normalizedUrls,
      extractedDomains,
      results,
      summary: buildEnrichmentSummary(results),
    }),
    indicators: buildIocIndicators(results),
  };
}

export function buildPendingIocEnrichment(extractedUrls: string[]): FileIocEnrichment {
  const normalizedUrls = deduplicateValues(extractedUrls)
    .filter((value) => isValidHttpUrl(value))
    .slice(0, MAX_URL_IOCS);
  const extractedDomains = deduplicateValues(
    normalizedUrls
      .map((value) => extractDomain(value))
      .filter((value): value is string => Boolean(value)),
  ).slice(0, MAX_DOMAIN_IOCS);
  const hasWork = normalizedUrls.length > 0 || extractedDomains.length > 0;

  return buildIocEnrichmentSnapshot({
    status: hasWork ? 'pending' : 'completed',
    extractedUrls: normalizedUrls,
    extractedDomains,
    results: [],
    summary: hasWork ? 'IOC enrichment queued for extracted URLs and derived domains.' : 'No enrichable URLs or domains were extracted from this file.',
  });
}

export function buildUnavailableIocEnrichment(extractedUrls: string[], message: string): FileIocEnrichment {
  const pending = buildPendingIocEnrichment(extractedUrls);

  return {
    ...pending,
    status: pending.extractedUrls.length > 0 || pending.extractedDomains.length > 0 ? 'unavailable' : 'completed',
    summary: pending.extractedUrls.length > 0 || pending.extractedDomains.length > 0 ? message : pending.summary,
    updatedAt: new Date().toISOString(),
  };
}

function buildIocEnrichmentSnapshot(context: Omit<FileIocEnrichment, 'updatedAt'>): FileIocEnrichment {
  return {
    ...context,
    updatedAt: context.status === 'pending' ? null : new Date().toISOString(),
  };
}

async function enrichUrlIoc(url: string): Promise<FileEnrichedIoc> {
  const enrichment = await lookupUrlThreatIntel(url);
  const providerResults: FileIocProviderResult[] = [
    {
      provider: 'urlhaus',
      status: enrichment.urlhaus.status,
      detail: enrichment.urlhaus.tags.length ? enrichment.urlhaus.tags.join(', ') : null,
      reference: enrichment.urlhaus.reference ?? enrichment.urlhaus.permalink,
    },
    {
      provider: 'virustotal',
      status: getVirusTotalProviderStatus(enrichment.virustotal.malicious, enrichment.virustotal.suspicious, enrichment.virustotal.status),
      detail: buildVirusTotalDetail(enrichment.virustotal.malicious, enrichment.virustotal.suspicious),
      reference: enrichment.virustotal.reference,
    },
    {
      provider: 'urlscan',
      status: enrichment.urlscan.status,
      detail: enrichment.urlscan.resultUrl ? 'Scan submitted' : null,
      reference: enrichment.urlscan.resultUrl,
    },
    {
      provider: 'alienvault',
      status: enrichment.alienVault.status,
      detail: enrichment.alienVault.pulseCount ? `${enrichment.alienVault.pulseCount} pulse(s)` : null,
      reference: enrichment.alienVault.reference,
    },
  ];

  return {
    type: 'url',
    value: url,
    derivedFrom: null,
    verdict: classifyIocVerdict(providerResults),
    summary: buildIocResultSummary(url, providerResults),
    providerResults,
  };
}

async function enrichDomainIoc(domain: string): Promise<FileEnrichedIoc> {
  const enrichment = await lookupDomainReputation(domain, []);
  const providerResults: FileIocProviderResult[] = [
    {
      provider: 'alienvault',
      status: enrichment.alienVault.status,
      detail: enrichment.alienVault.pulseCount ? `${enrichment.alienVault.pulseCount} pulse(s)` : null,
      reference: enrichment.alienVault.reference,
    },
    {
      provider: 'virustotal',
      status: getVirusTotalProviderStatus(enrichment.virustotal.malicious, enrichment.virustotal.suspicious, enrichment.virustotal.status),
      detail: buildVirusTotalDetail(enrichment.virustotal.malicious, enrichment.virustotal.suspicious),
      reference: enrichment.virustotal.reference,
    },
    {
      provider: 'urlscan',
      status: enrichment.urlscan.status === 'clean' ? 'clean' : enrichment.urlscan.status,
      detail: enrichment.urlscan.resultUrl ? 'Historical observation available' : null,
      reference: enrichment.urlscan.resultUrl,
    },
    {
      provider: 'abuseipdb',
      status: enrichment.abuseIpDb.status,
      detail: enrichment.abuseIpDb.confidenceScore !== null
        ? `Confidence ${enrichment.abuseIpDb.confidenceScore}% across ${enrichment.abuseIpDb.reports ?? 0} report(s)`
        : null,
      reference: enrichment.abuseIpDb.reference,
    },
    {
      provider: 'urlhaus_host',
      status: enrichment.urlhausHost.status,
      detail: enrichment.urlhausHost.urls.length ? `${enrichment.urlhausHost.urls.length} URL(s) listed on this host` : null,
      reference: enrichment.urlhausHost.reference,
    },
  ];

  return {
    type: 'domain',
    value: domain,
    derivedFrom: null,
    verdict: classifyIocVerdict(providerResults),
    summary: buildIocResultSummary(domain, providerResults),
    providerResults,
  };
}

function buildIocIndicators(results: FileEnrichedIoc[]): FileIndicator[] {
  return results.flatMap<FileIndicator>((result) => {
    if (result.verdict === 'malicious') {
      return [{
        kind: result.type === 'url' ? 'ioc_malicious_url' : 'ioc_malicious_domain',
        severity: 'high',
        value: result.summary,
      }];
    }

    if (result.verdict === 'suspicious') {
      return [{
        kind: result.type === 'url' ? 'ioc_suspicious_url' : 'ioc_suspicious_domain',
        severity: 'medium',
        value: result.summary,
      }];
    }

    return [];
  });
}

function classifyIocVerdict(providerResults: FileIocProviderResult[]): FileEnrichedIoc['verdict'] {
  if (providerResults.some((result) => result.status === 'malicious' || result.status === 'listed')) {
    return 'malicious';
  }

  if (providerResults.some((result) => result.status === 'suspicious')) {
    return 'suspicious';
  }

  if (providerResults.some((result) => result.status === 'clean' || result.status === 'not_listed')) {
    return 'clean';
  }

  return 'unavailable';
}

function buildIocResultSummary(value: string, providerResults: FileIocProviderResult[]) {
  const flaggedProviders = providerResults
    .filter((result) => result.status === 'malicious' || result.status === 'listed' || result.status === 'suspicious')
    .map((result) => formatProviderName(result.provider));

  if (flaggedProviders.length > 0) {
    return `${value} flagged by ${flaggedProviders.join(', ')}.`;
  }

  const completedChecks = providerResults.filter((result) => !['unavailable', 'not_configured', 'submitted'].includes(result.status)).length;
  if (completedChecks > 0) {
    return `${value} was checked against ${completedChecks} IOC provider${completedChecks === 1 ? '' : 's'} with no malicious listings.`;
  }

  return `${value} could not be fully enriched with external IOC providers.`;
}

function buildEnrichmentSummary(results: FileEnrichedIoc[]) {
  const maliciousCount = results.filter((result) => result.verdict === 'malicious').length;
  const suspiciousCount = results.filter((result) => result.verdict === 'suspicious').length;

  if (maliciousCount > 0 || suspiciousCount > 0) {
    return `${maliciousCount} malicious and ${suspiciousCount} suspicious IOC${maliciousCount + suspiciousCount === 1 ? '' : 's'} found across extracted URLs and domains.`;
  }

  if (results.length > 0) {
    return `Checked ${results.length} extracted IOC${results.length === 1 ? '' : 's'} with no malicious listings returned.`;
  }

  return 'No enrichable URLs or domains were extracted from this file.';
}

function getVirusTotalProviderStatus(
  malicious: number | null,
  suspicious: number | null,
  fallback: 'malicious' | 'clean' | 'unavailable' | 'not_configured',
): FileIocProviderResult['status'] {
  if ((malicious ?? 0) > 0) {
    return 'malicious';
  }
  if ((suspicious ?? 0) > 0) {
    return 'suspicious';
  }
  return fallback;
}

function buildVirusTotalDetail(malicious: number | null, suspicious: number | null) {
  if (malicious === null && suspicious === null) {
    return null;
  }

  return `${malicious ?? 0} malicious, ${suspicious ?? 0} suspicious engine verdict(s)`;
}

function extractDomain(value: string) {
  try {
    return new URL(value).hostname.toLowerCase();
  } catch {
    return null;
  }
}

function isValidHttpUrl(value: string) {
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

function deduplicateValues(values: string[]) {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))];
}

function formatProviderName(provider: FileIocProviderResult['provider']) {
  const labels: Record<FileIocProviderResult['provider'], string> = {
    abuseipdb: 'AbuseIPDB',
    alienvault: 'AlienVault OTX',
    urlhaus: 'URLhaus',
    urlhaus_host: 'URLhaus Host',
    urlscan: 'URLScan',
    virustotal: 'VirusTotal',
  };

  return labels[provider];
}