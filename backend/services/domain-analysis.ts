import { execFile } from 'node:child_process';
import dns from 'node:dns/promises';
import tls from 'node:tls';
import { domainToASCII } from 'node:url';
import { promisify } from 'node:util';

import {
  domainAnalysisResponseSchema,
  type DomainAnalysisResponse,
  type DomainCertificates,
  type DomainDnsRecords,
  type DomainHistory,
  type DomainIpIntelligence,
  type DomainMailSecurity,
  type DomainReputation,
  type DomainRdap,
  type DomainTls,
} from '../../shared/analysis-types.js';
import {
  lookupCertificateTransparency,
  lookupDomainHistory,
  lookupDomainIpIntelligence,
  lookupDomainReputation,
} from './threat-intel.js';

type AnalyzeDomainDependencies = {
  resolveDns?: (domain: string) => Promise<DomainDnsRecords>;
  resolveMailSecurityRecords?: (domain: string) => Promise<MailSecurityRecords>;
  lookupRdap?: (domain: string) => Promise<DomainRdap>;
  inspectTls?: (domain: string) => Promise<DomainTls | null>;
  lookupIpIntelligence?: (ips: string[]) => Promise<DomainIpIntelligence[]>;
  lookupHistory?: (domain: string) => Promise<DomainHistory>;
  lookupCertificateTransparency?: (domain: string) => Promise<DomainCertificates['certificateTransparency']>;
  lookupReputation?: (domain: string, ips: string[]) => Promise<DomainReputation>;
  now?: () => Date;
};

type CaaRecordLike = {
  critical?: boolean | number;
  issue?: string;
  issuewild?: string;
  iodef?: string;
};

type MailSecurityRecords = {
  apexTxtRecords: string[];
  dmarcTxtRecords: string[];
  mtaStsTxtRecords: string[];
  tlsRptTxtRecords: string[];
};

const execFileAsync = promisify(execFile);

export class DomainAnalysisError extends Error {
  code: string;

  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

export async function analyzeDomain(
  rawInput: string,
  dependencies: AnalyzeDomainDependencies = {},
): Promise<DomainAnalysisResponse> {
  const normalizedDomain = normalizeDomain(rawInput);
  const resolveDns = dependencies.resolveDns ?? defaultResolveDns;
  const resolveMailSecurityRecords = dependencies.resolveMailSecurityRecords ?? defaultResolveMailSecurityRecords;
  const lookupRdap = dependencies.lookupRdap ?? defaultLookupRdap;
  const inspectTls = dependencies.inspectTls ?? defaultInspectTls;
  const lookupIpIntelligence = dependencies.lookupIpIntelligence ?? lookupDomainIpIntelligence;
  const lookupHistory = dependencies.lookupHistory ?? lookupDomainHistory;
  const lookupCt = dependencies.lookupCertificateTransparency ?? lookupCertificateTransparency;
  const lookupReputation = dependencies.lookupReputation ?? lookupDomainReputation;
  const now = dependencies.now ?? (() => new Date());

  const [dnsRecords, mailSecurityRecords, rdap, tlsInfo] = await Promise.all([
    resolveDns(normalizedDomain),
    resolveMailSecurityRecords(normalizedDomain),
    lookupRdap(normalizedDomain),
    inspectTls(normalizedDomain),
  ]);

  const ipAddresses = [...new Set([...dnsRecords.a, ...dnsRecords.aaaa])];
  const [ipIntelligence, history, certificateTransparency, reputation] = await Promise.all([
    lookupIpIntelligence(ipAddresses),
    lookupHistory(normalizedDomain),
    lookupCt(normalizedDomain),
    lookupReputation(normalizedDomain, ipAddresses),
  ]);

  const mailSecurity = buildMailSecurity(mailSecurityRecords);

  const riskFactors = buildRiskFactors(normalizedDomain, dnsRecords, rdap, mailSecurity, reputation, now());
  const score = calculateScore(riskFactors);
  const riskLevel = score >= 70 ? 'HIGH' : score >= 40 ? 'MEDIUM' : 'LOW';
  const summary =
    riskFactors.length > 0
      ? riskFactors.join(' | ')
      : 'No immediate high-confidence infrastructure red flags were detected.';

  return domainAnalysisResponseSchema.parse({
    domain: rawInput,
    normalizedDomain,
    score,
    riskLevel,
    summary,
    dns: dnsRecords,
    rdap,
    mailSecurity,
    infrastructure: {
      ipAddresses,
      ipIntelligence,
      tls: tlsInfo,
    },
    history,
    certificates: {
      certificateTransparency,
    },
    reputation,
    riskFactors,
    osint: buildOsintLinks(normalizedDomain),
  });
}

export function normalizeDomain(rawInput: string): string {
  const trimmedInput = rawInput.trim();

  if (!trimmedInput) {
    throw new DomainAnalysisError('invalid_domain', 'Domain is required.');
  }

  let candidate = trimmedInput;

  if (candidate.includes('://')) {
    try {
      candidate = new URL(candidate).hostname;
    } catch {
      throw new DomainAnalysisError('invalid_domain', 'Domain is not a valid hostname.');
    }
  }

  candidate = candidate.replace(/\/$/, '').trim().toLowerCase();
  const asciiDomain = domainToASCII(candidate);

  if (!asciiDomain || !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(asciiDomain)) {
    throw new DomainAnalysisError('invalid_domain', 'Domain is not a valid hostname.');
  }

  return asciiDomain;
}

async function defaultResolveDns(domain: string): Promise<DomainDnsRecords> {
  const [a, aaaa, mx, ns, txt, caa, soa] = await Promise.all([
    resolveARecords(domain),
    resolveAaaaRecords(domain),
    resolveMxRecords(domain),
    resolveNsRecords(domain),
    resolveTxtRecords(domain),
    resolveCaaRecords(domain),
    resolveSoaRecord(domain),
  ]);

  return { a, aaaa, mx, ns, txt, caa, soa };
}

async function resolveARecords(domain: string): Promise<string[]> {
  try {
    return await dns.resolve4(domain);
  } catch (error) {
    if (!shouldUseSystemDnsFallback(error)) {
      return [];
    }

    return resolveWithLookup(domain, 4);
  }
}

async function resolveAaaaRecords(domain: string): Promise<string[]> {
  try {
    return await dns.resolve6(domain);
  } catch (error) {
    if (!shouldUseSystemDnsFallback(error)) {
      return [];
    }

    return resolveWithLookup(domain, 6);
  }
}

async function resolveMxRecords(domain: string): Promise<string[]> {
  try {
    const records = await dns.resolveMx(domain);
    return records
      .sort((left, right) => left.priority - right.priority)
      .map((record) => `${record.exchange} (priority ${record.priority})`);
  } catch (error) {
    if (!shouldUseSystemDnsFallback(error)) {
      return [];
    }

    return resolveWithWindowsDns(domain, 'MX', (payload) => {
      const rows = Array.isArray(payload) ? payload : [payload];
      return rows
        .filter((row) => row && typeof row.NameExchange === 'string' && typeof row.Preference === 'number')
        .sort((left, right) => left.Preference - right.Preference)
        .map((row) => `${row.NameExchange} (priority ${row.Preference})`);
    });
  }
}

async function resolveNsRecords(domain: string): Promise<string[]> {
  try {
    return await dns.resolveNs(domain);
  } catch (error) {
    if (!shouldUseSystemDnsFallback(error)) {
      return [];
    }

    return resolveWithWindowsDns(domain, 'NS', (payload) => {
      const rows = Array.isArray(payload) ? payload : [payload];
      return rows
        .map((row) => row?.NameHost)
        .filter((value): value is string => typeof value === 'string' && value.length > 0);
    });
  }
}

async function resolveTxtRecords(domain: string): Promise<string[]> {
  try {
    const records = await dns.resolveTxt(domain);
    return records.map((entry) => entry.join(''));
  } catch (error) {
    if (!shouldUseSystemDnsFallback(error)) {
      return [];
    }

    return resolveWithWindowsDns(domain, 'TXT', (payload) => {
      const rows = Array.isArray(payload) ? payload : [payload];
      return rows
        .flatMap((row) => (Array.isArray(row?.Strings) ? [row.Strings.join('')] : []))
        .filter((value) => value.length > 0);
    });
  }
}

async function resolveCaaRecords(domain: string): Promise<string[]> {
  try {
    const records = await dns.resolveCaa(domain);
    return records.map(formatCaaRecord);
  } catch (error) {
    if (!shouldUseSystemDnsFallback(error)) {
      return [];
    }

    return resolveWithWindowsDns(domain, 'CAA', (payload) => {
      const rows = Array.isArray(payload) ? payload : [payload];
      return rows
        .map((row) => {
          if (!row || typeof row !== 'object') {
            return null;
          }

          const tag = typeof row.Tag === 'string' ? row.Tag.toLowerCase() : null;
          const value = typeof row.NameHost === 'string' ? row.NameHost : typeof row.Strings?.[0] === 'string' ? row.Strings[0] : null;
          if (!tag || !value) {
            return null;
          }

          const critical = row.Flags ? 1 : 0;
          return `${critical} ${tag} "${value}"`;
        })
        .filter((value): value is string => typeof value === 'string');
    });
  }
}

async function resolveSoaRecord(domain: string): Promise<string | null> {
  try {
    const record = await dns.resolveSoa(domain);
    return `${record.nsname} ${record.hostmaster} ${record.serial} ${record.refresh} ${record.retry} ${record.expire} ${record.minttl}`;
  } catch (error) {
    if (!shouldUseSystemDnsFallback(error)) {
      return null;
    }

    return resolveWithWindowsDns(domain, 'SOA', (payload) => {
      const row = Array.isArray(payload) ? payload[0] : payload;
      if (!row || typeof row !== 'object' || typeof row.PrimaryServer !== 'string' || typeof row.NameAdministrator !== 'string') {
        return null;
      }

      return `${row.PrimaryServer} ${row.NameAdministrator} ${row.SerialNumber ?? 0} ${row.TimeToZoneRefresh ?? 0} ${row.TimeToZoneFailureRetry ?? 0} ${row.TimeToExpiration ?? 0} ${row.DefaultTTL ?? 0}`;
    });
  }
}

async function resolveWithLookup(domain: string, family: 4 | 6): Promise<string[]> {
  try {
    const records = await dns.lookup(domain, { all: true, family });
    return records.map((record) => record.address);
  } catch {
    return [];
  }
}

async function resolveWithWindowsDns<T>(domain: string, type: string, mapper: (payload: any) => T): Promise<T> {
  if (process.platform !== 'win32') {
    return getEmptyWindowsFallback(type) as T;
  }

  try {
    const escapedDomain = domain.replace(/'/g, "''");
    const command = `$ProgressPreference='SilentlyContinue'; Resolve-DnsName -Name '${escapedDomain}' -Type ${type} -ErrorAction Stop | ConvertTo-Json -Compress`;
    const { stdout } = await execFileAsync('powershell.exe', ['-NoProfile', '-Command', command], {
      timeout: 8000,
      windowsHide: true,
      maxBuffer: 1024 * 1024,
    });

    if (!stdout.trim()) {
      return getEmptyWindowsFallback(type) as T;
    }

    return mapper(JSON.parse(stdout));
  } catch {
    return getEmptyWindowsFallback(type) as T;
  }
}

function shouldUseSystemDnsFallback(error: unknown): boolean {
  const code = typeof error === 'object' && error !== null && 'code' in error ? String((error as { code?: string }).code) : '';
  return code === 'EREFUSED' || code === 'ETIMEOUT' || code === 'SERVFAIL';
}

function getEmptyWindowsFallback(type: string): string[] | string | null {
  if (type === 'SOA') {
    return null;
  }

  return [];
}

async function defaultLookupRdap(domain: string): Promise<DomainRdap> {
  try {
    const response = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      headers: {
        accept: 'application/json',
        'user-agent': 'phish-hunter-osint/1.0',
      },
      signal: AbortSignal.timeout(8000),
    });

    if (!response.ok) {
      return {
        registrar: null,
        createdAt: null,
        updatedAt: null,
        expiresAt: null,
      };
    }

    const data = (await response.json()) as {
      entities?: Array<{ roles?: string[]; vcardArray?: [string, Array<Array<string | Record<string, string> | string[]>>] }>;
      events?: Array<{ eventAction?: string; eventDate?: string }>;
    };

    const registrarEntity = data.entities?.find((entity) => entity.roles?.includes('registrar'));
    const registrar = extractRegistrarName(registrarEntity?.vcardArray?.[1]);
    const createdAt = findEventDate(data.events, 'registration');
    const updatedAt = findEventDate(data.events, 'last changed');
    const expiresAt = findEventDate(data.events, 'expiration');

    return {
      registrar,
      createdAt,
      updatedAt,
      expiresAt,
    };
  } catch {
    return {
      registrar: null,
      createdAt: null,
      updatedAt: null,
      expiresAt: null,
    };
  }
}

function extractRegistrarName(vcardRows?: Array<Array<string | Record<string, string> | string[]>>): string | null {
  if (!vcardRows) {
    return null;
  }

  const fnRow = vcardRows.find((row) => row[0] === 'fn');
  const value = fnRow?.[3];

  return typeof value === 'string' ? value : null;
}

function findEventDate(
  events: Array<{ eventAction?: string; eventDate?: string }> | undefined,
  action: string,
): string | null {
  return events?.find((event) => event.eventAction?.toLowerCase() === action)?.eventDate ?? null;
}

async function defaultInspectTls(domain: string): Promise<DomainTls | null> {
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host: domain,
        port: 443,
        servername: domain,
        timeout: 5000,
        rejectUnauthorized: false,
      },
      () => {
        const certificate = socket.getPeerCertificate();
        socket.end();

        if (!certificate || Object.keys(certificate).length === 0) {
          resolve(null);
          return;
        }

        resolve({
          issuer: pickCertificateValue(certificate.issuer?.O) || pickCertificateValue(certificate.issuer?.CN),
          subject: pickCertificateValue(certificate.subject?.CN),
          validFrom: certificate.valid_from ? new Date(certificate.valid_from).toISOString() : null,
          validTo: certificate.valid_to ? new Date(certificate.valid_to).toISOString() : null,
          subjectAltNames: extractSubjectAltNames(certificate.subjectaltname),
        });
      },
    );

    socket.on('error', () => resolve(null));
    socket.on('timeout', () => {
      socket.destroy();
      resolve(null);
    });
  });
}


function pickCertificateValue(value: string | string[] | undefined): string | null {
  if (!value) {
    return null;
  }

  return Array.isArray(value) ? value[0] ?? null : value;
}

function extractSubjectAltNames(value: string | undefined): string[] {
  if (!value) {
    return [];
  }

  return value
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.startsWith('DNS:'))
    .map((entry) => entry.slice(4));
}

async function defaultResolveMailSecurityRecords(domain: string): Promise<MailSecurityRecords> {
  const [apexTxtRecords, dmarcTxtRecords, mtaStsTxtRecords, tlsRptTxtRecords] = await Promise.all([
    resolveTxtRecords(domain),
    resolveTxtRecords(`_dmarc.${domain}`),
    resolveTxtRecords(`_mta-sts.${domain}`),
    resolveTxtRecords(`_smtp._tls.${domain}`),
  ]);

  return {
    apexTxtRecords,
    dmarcTxtRecords,
    mtaStsTxtRecords,
    tlsRptTxtRecords,
  };
}

function buildMailSecurity(records: MailSecurityRecords): DomainMailSecurity {
  const spfRecord = records.apexTxtRecords.find((entry) => entry.toLowerCase().startsWith('v=spf1')) ?? null;
  const dmarcRecord = records.dmarcTxtRecords.find((entry) => entry.toLowerCase().startsWith('v=dmarc1')) ?? null;
  const mtaStsRecord = records.mtaStsTxtRecords.find((entry) => entry.toLowerCase().includes('v=stsv1')) ?? null;
  const tlsRptRecord = records.tlsRptTxtRecords.find((entry) => entry.toLowerCase().includes('v=tlsrptv1')) ?? null;

  return {
    spf: {
      present: spfRecord !== null,
      record: spfRecord,
      mode: spfRecord ? extractPolicyValue(spfRecord, ['-all', '~all', '?all', '+all']) : null,
    },
    dmarc: {
      present: dmarcRecord !== null,
      record: dmarcRecord,
      policy: dmarcRecord ? extractTagValue(dmarcRecord, 'p') : null,
    },
    mtaSts: {
      present: mtaStsRecord !== null,
      record: mtaStsRecord,
    },
    tlsRpt: {
      present: tlsRptRecord !== null,
      record: tlsRptRecord,
    },
  };
}

function extractTagValue(record: string, tag: string): string | null {
  const match = record.match(new RegExp(`${tag}=([^;\\s]+)`, 'i'));
  return match?.[1] ?? null;
}

function extractPolicyValue(record: string, candidates: string[]): string | null {
  return candidates.find((candidate) => record.toLowerCase().includes(candidate)) ?? null;
}

function buildRiskFactors(
  domain: string,
  dnsRecords: DomainDnsRecords,
  rdap: DomainRdap,
  mailSecurity: DomainMailSecurity,
  reputation: DomainReputation,
  now: Date,
): string[] {
  const riskFactors: string[] = [];
  const suspiciousKeywords = ['login', 'secure', 'verify', 'update', 'account', 'wallet', 'invoice', 'support'];
  const matchedKeywords = suspiciousKeywords.filter((keyword) => domain.includes(keyword));

  if (matchedKeywords.length > 0) {
    riskFactors.push(`Suspicious keyword detected: ${matchedKeywords.join(', ')}`);
  }

  if (!dnsRecords.mx.length) {
    riskFactors.push('No MX record detected for the domain.');
  }

  if (dnsRecords.txt.every((entry) => !entry.toLowerCase().includes('spf'))) {
    riskFactors.push('No SPF-related TXT record detected.');
  }

  if (!mailSecurity.dmarc.present) {
    riskFactors.push('No DMARC policy detected for the domain.');
  }

  if (!dnsRecords.caa.length) {
    riskFactors.push('No CAA record detected for the domain.');
  }

  if (rdap.createdAt) {
    const ageInDays = Math.floor((now.getTime() - new Date(rdap.createdAt).getTime()) / 86400000);
    if (ageInDays <= 30) {
      riskFactors.push(`Domain appears very recent (${ageInDays} days old).`);
    }
  } else {
    riskFactors.push('Domain age could not be determined from RDAP.');
  }

  if (reputation.alienVault.status === 'listed' && (reputation.alienVault.pulseCount ?? 0) > 0) {
    riskFactors.push(`AlienVault OTX reports ${reputation.alienVault.pulseCount} pulses for this domain.`);
  }

  if (reputation.urlhausHost.status === 'listed' && reputation.urlhausHost.urls.length > 0) {
    riskFactors.push(`URLhaus tracks ${reputation.urlhausHost.urls.length} malicious URL(s) on this host.`);
  }

  return riskFactors;
}

function calculateScore(riskFactors: string[]): number {
  return Math.min(
    100,
    riskFactors.reduce((score, factor) => {
      if (factor.includes('very recent')) return score + 35;
      if (factor.includes('Suspicious keyword')) return score + 25;
      if (factor.includes('No MX')) return score + 20;
      if (factor.includes('AlienVault')) return score + 20;
      if (factor.includes('URLhaus')) return score + 25;
      if (factor.includes('No DMARC')) return score + 10;
      if (factor.includes('No CAA')) return score + 5;
      if (factor.includes('No SPF')) return score + 10;
      if (factor.includes('could not be determined')) return score + 10;
      return score + 5;
    }, 5),
  );
}

function buildOsintLinks(domain: string) {
  return {
    virustotal: `https://www.virustotal.com/gui/domain/${domain}`,
    urlscan: `https://urlscan.io/search/#domain:${domain}`,
    viewdns: `https://viewdns.info/reverseip/?host=${domain}&t=1`,
    crtSh: `https://crt.sh/?q=${domain}`,
    wayback: `https://web.archive.org/web/*/${domain}`,
    dnsdumpster: 'https://dnsdumpster.com/',
    builtwith: `https://builtwith.com/${domain}`,
    alienVault: `https://otx.alienvault.com/indicator/domain/${domain}`,
    abuseIpDb: 'https://www.abuseipdb.com/',
    urlhausHost: `https://urlhaus.abuse.ch/browse.php?search=${encodeURIComponent(domain)}`,
  };
}

function formatCaaRecord(record: CaaRecordLike): string {
  if ('issue' in record) {
    return `${record.critical ? 1 : 0} issue "${record.issue}"`;
  }

  if ('issuewild' in record) {
    return `${record.critical ? 1 : 0} issuewild "${record.issuewild}"`;
  }

  if ('iodef' in record) {
    return `${record.critical ? 1 : 0} iodef "${record.iodef}"`;
  }

  return `${record.critical ? 1 : 0} caa`;
}