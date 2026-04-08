export type ExternalScans = {
  urlhaus: {
    status: 'listed' | 'not_listed' | 'unavailable';
    reference: string | null;
    tags: string[];
    permalink: string | null;
  };
  virustotal: {
    status: 'malicious' | 'clean' | 'unavailable' | 'not_configured';
    malicious: number | null;
    suspicious: number | null;
    reference: string | null;
  };
  urlscan: {
    status: 'submitted' | 'not_configured' | 'unavailable';
    resultUrl: string | null;
  };
  alienVault: {
    status: 'listed' | 'clean' | 'unavailable';
    pulseCount: number | null;
    reference: string | null;
  };
};

export type DomainIpIntelligenceResult = {
  ip: string;
  reverseDns: string[];
  country: string | null;
  city: string | null;
  asn: string | null;
  organization: string | null;
};

export type DomainHistoryResult = {
  waybackSnapshots: number;
  firstSeen: string | null;
  lastSeen: string | null;
};

export type DomainCertificateTransparencyResult = {
  certificateCount: number;
  observedSubdomains: string[];
};

export type DomainReputationResult = {
  alienVault: {
    status: 'listed' | 'clean' | 'unavailable';
    pulseCount: number | null;
    reference: string | null;
  };
  virustotal: {
    status: 'malicious' | 'clean' | 'unavailable' | 'not_configured';
    malicious: number | null;
    suspicious: number | null;
    reference: string | null;
  };
  urlscan: {
    status: 'submitted' | 'clean' | 'unavailable' | 'not_configured';
    resultUrl: string | null;
  };
  abuseIpDb: {
    status: 'listed' | 'clean' | 'unavailable' | 'not_configured';
    confidenceScore: number | null;
    reports: number | null;
    reference: string | null;
  };
  urlhausHost: {
    status: 'listed' | 'not_listed' | 'unavailable';
    reference: string | null;
    urls: string[];
  };
};

export async function lookupUrlThreatIntel(url: string): Promise<ExternalScans> {
  const [urlhaus, virustotal, urlscan, alienVault] = await Promise.all([
    lookupUrlhaus(url),
    lookupVirusTotal(url),
    lookupUrlscan(url),
    lookupAlienVault(url),
  ]);

  return {
    urlhaus,
    virustotal,
    urlscan,
    alienVault,
  };
}

async function lookupUrlhaus(url: string): Promise<ExternalScans['urlhaus']> {
  try {
    const response = await fetch('https://urlhaus-api.abuse.ch/v1/url/', {
      method: 'POST',
      headers: buildUrlhausHeaders(),
      body: new URLSearchParams({ url }),
      signal: AbortSignal.timeout(8000),
    });

    if (!response.ok) {
      return { status: 'unavailable', reference: null, tags: [], permalink: null };
    }

    const payload = (await response.json()) as {
      query_status?: string;
      urlhaus_reference?: string;
      url?: string;
      tags?: string[];
    };

    if (payload.query_status === 'ok') {
      return {
        status: 'listed',
        reference: payload.urlhaus_reference ?? null,
        tags: payload.tags ?? [],
        permalink: payload.url ?? null,
      };
    }

    return { status: 'not_listed', reference: null, tags: [], permalink: null };
  } catch {
    return { status: 'unavailable', reference: null, tags: [], permalink: null };
  }
}

async function lookupVirusTotal(url: string): Promise<ExternalScans['virustotal']> {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) {
    return {
      status: 'not_configured',
      malicious: null,
      suspicious: null,
      reference: null,
    };
  }

  try {
    const encodedUrl = Buffer.from(url).toString('base64url');
    const response = await fetch(`https://www.virustotal.com/api/v3/urls/${encodedUrl}`, {
      headers: {
        'x-apikey': apiKey,
      },
      signal: AbortSignal.timeout(8000),
    });

    if (!response.ok) {
      return {
        status: 'unavailable',
        malicious: null,
        suspicious: null,
        reference: null,
      };
    }

    const payload = (await response.json()) as {
      data?: {
        links?: { self?: string };
        attributes?: {
          last_analysis_stats?: {
            malicious?: number;
            suspicious?: number;
          };
        };
      };
    };

    const malicious = payload.data?.attributes?.last_analysis_stats?.malicious ?? 0;
    const suspicious = payload.data?.attributes?.last_analysis_stats?.suspicious ?? 0;

    return {
      status: malicious > 0 || suspicious > 0 ? 'malicious' : 'clean',
      malicious,
      suspicious,
      reference: payload.data?.links?.self ?? null,
    };
  } catch {
    return {
      status: 'unavailable',
      malicious: null,
      suspicious: null,
      reference: null,
    };
  }
}

async function lookupUrlscan(url: string): Promise<ExternalScans['urlscan']> {
  const apiKey = process.env.URLSCAN_API_KEY;
  if (!apiKey) {
    return {
      status: 'not_configured',
      resultUrl: null,
    };
  }

  try {
    const response = await fetch('https://urlscan.io/api/v1/scan/', {
      method: 'POST',
      headers: {
        'API-Key': apiKey,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ url, visibility: 'unlisted' }),
      signal: AbortSignal.timeout(8000),
    });

    if (!response.ok) {
      return {
        status: 'unavailable',
        resultUrl: null,
      };
    }

    const payload = (await response.json()) as { result?: string };
    return {
      status: 'submitted',
      resultUrl: payload.result ?? null,
    };
  } catch {
    return {
      status: 'unavailable',
      resultUrl: null,
    };
  }
}

async function lookupAlienVault(url: string): Promise<ExternalScans['alienVault']> {
  try {
    const response = await fetch(`https://otx.alienvault.com/api/v1/indicators/url/${encodeURIComponent(url)}/general`, {
      signal: AbortSignal.timeout(8000),
      headers: {
        accept: 'application/json',
      },
    });

    if (!response.ok) {
      return {
        status: 'unavailable',
        pulseCount: null,
        reference: null,
      };
    }

    const payload = (await response.json()) as { pulse_info?: { count?: number } };
    const pulseCount = payload.pulse_info?.count ?? 0;

    return {
      status: pulseCount > 0 ? 'listed' : 'clean',
      pulseCount,
      reference: `https://otx.alienvault.com/indicator/url/${encodeURIComponent(url)}`,
    };
  } catch {
    return {
      status: 'unavailable',
      pulseCount: null,
      reference: null,
    };
  }
}

export async function lookupDomainIpIntelligence(ips: string[]): Promise<DomainIpIntelligenceResult[]> {
  return Promise.all(ips.map(async (ip) => lookupSingleIpIntelligence(ip)));
}

export async function lookupDomainHistory(domain: string): Promise<DomainHistoryResult> {
  try {
    const response = await fetch(
      `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(domain)}/*&output=json&fl=timestamp&filter=statuscode:200`,
      {
        signal: AbortSignal.timeout(8000),
      },
    );

    if (!response.ok) {
      return {
        waybackSnapshots: 0,
        firstSeen: null,
        lastSeen: null,
      };
    }

    const payload = (await response.json()) as string[][];
    const rows = payload.slice(1).map((row) => row[0]).filter(Boolean);

    return {
      waybackSnapshots: rows.length,
      firstSeen: rows[0] ? cdxTimestampToIso(rows[0]) : null,
      lastSeen: rows.at(-1) ? cdxTimestampToIso(rows.at(-1) as string) : null,
    };
  } catch {
    return {
      waybackSnapshots: 0,
      firstSeen: null,
      lastSeen: null,
    };
  }
}

export async function lookupCertificateTransparency(domain: string): Promise<DomainCertificateTransparencyResult> {
  try {
    const response = await fetch(`https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json`, {
      headers: {
        accept: 'application/json',
      },
      signal: AbortSignal.timeout(8000),
    });

    if (!response.ok) {
      return {
        certificateCount: 0,
        observedSubdomains: [],
      };
    }

    const payload = (await response.json()) as Array<{ name_value?: string }>;
    const observedSubdomains = [...new Set(
      payload
        .flatMap((entry) => (entry.name_value ?? '').split('\n'))
        .map((value) => value.trim().toLowerCase())
        .filter((value) => value.endsWith(domain) && value !== domain),
    )].slice(0, 25);

    return {
      certificateCount: payload.length,
      observedSubdomains,
    };
  } catch {
    return {
      certificateCount: 0,
      observedSubdomains: [],
    };
  }
}

export async function lookupDomainReputation(domain: string, ips: string[]): Promise<DomainReputationResult> {
  const [alienVault, virustotal, urlscan, abuseIpDb, urlhausHost] = await Promise.all([
    lookupAlienVaultDomain(domain),
    lookupVirusTotalDomain(domain),
    lookupUrlscanDomain(domain),
    lookupAbuseIpDb(ips[0] ?? null),
    lookupUrlhausHost(domain),
  ]);

  return {
    alienVault,
    virustotal,
    urlscan,
    abuseIpDb,
    urlhausHost,
  };
}

async function lookupSingleIpIntelligence(ip: string): Promise<DomainIpIntelligenceResult> {
  try {
    const [reverseDns, ipInfoResponse] = await Promise.all([
      lookupReverseDns(ip),
      fetch(`https://ipwho.is/${encodeURIComponent(ip)}`, {
        signal: AbortSignal.timeout(8000),
      }),
    ]);

    if (!ipInfoResponse.ok) {
      return {
        ip,
        reverseDns,
        country: null,
        city: null,
        asn: null,
        organization: null,
      };
    }

    const payload = (await ipInfoResponse.json()) as {
      country_code?: string;
      city?: string;
      connection?: {
        asn?: number | string;
        org?: string;
      };
    };

    return {
      ip,
      reverseDns,
      country: payload.country_code ?? null,
      city: payload.city ?? null,
      asn: payload.connection?.asn ? `AS${payload.connection.asn}` : null,
      organization: payload.connection?.org ?? null,
    };
  } catch {
    return {
      ip,
      reverseDns: await lookupReverseDns(ip),
      country: null,
      city: null,
      asn: null,
      organization: null,
    };
  }
}

async function lookupReverseDns(ip: string): Promise<string[]> {
  try {
    const dns = await import('node:dns/promises');
    return await dns.reverse(ip);
  } catch {
    return [];
  }
}

async function lookupAlienVaultDomain(domain: string): Promise<DomainReputationResult['alienVault']> {
  try {
    const response = await fetch(`https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}/general`, {
      signal: AbortSignal.timeout(8000),
      headers: {
        accept: 'application/json',
      },
    });

    if (!response.ok) {
      return {
        status: 'unavailable',
        pulseCount: null,
        reference: null,
      };
    }

    const payload = (await response.json()) as { pulse_info?: { count?: number } };
    const pulseCount = payload.pulse_info?.count ?? 0;

    return {
      status: pulseCount > 0 ? 'listed' : 'clean',
      pulseCount,
      reference: `https://otx.alienvault.com/indicator/domain/${encodeURIComponent(domain)}`,
    };
  } catch {
    return {
      status: 'unavailable',
      pulseCount: null,
      reference: null,
    };
  }
}

async function lookupVirusTotalDomain(domain: string): Promise<DomainReputationResult['virustotal']> {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) {
    return {
      status: 'not_configured',
      malicious: null,
      suspicious: null,
      reference: null,
    };
  }

  try {
    const response = await fetch(`https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`, {
      headers: {
        'x-apikey': apiKey,
      },
      signal: AbortSignal.timeout(8000),
    });

    if (!response.ok) {
      return {
        status: 'unavailable',
        malicious: null,
        suspicious: null,
        reference: null,
      };
    }

    const payload = (await response.json()) as {
      data?: {
        links?: { self?: string };
        attributes?: {
          last_analysis_stats?: {
            malicious?: number;
            suspicious?: number;
          };
        };
      };
    };
    const malicious = payload.data?.attributes?.last_analysis_stats?.malicious ?? 0;
    const suspicious = payload.data?.attributes?.last_analysis_stats?.suspicious ?? 0;

    return {
      status: malicious > 0 || suspicious > 0 ? 'malicious' : 'clean',
      malicious,
      suspicious,
      reference: payload.data?.links?.self ?? null,
    };
  } catch {
    return {
      status: 'unavailable',
      malicious: null,
      suspicious: null,
      reference: null,
    };
  }
}

async function lookupUrlscanDomain(domain: string): Promise<DomainReputationResult['urlscan']> {
  const apiKey = process.env.URLSCAN_API_KEY;
  if (!apiKey) {
    return {
      status: 'not_configured',
      resultUrl: null,
    };
  }

  try {
    const response = await fetch(`https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(domain)}`, {
      headers: {
        'API-Key': apiKey,
      },
      signal: AbortSignal.timeout(8000),
    });

    if (!response.ok) {
      return {
        status: 'unavailable',
        resultUrl: null,
      };
    }

    const payload = (await response.json()) as { results?: Array<{ result?: string }> };
    return {
      status: 'clean',
      resultUrl: payload.results?.[0]?.result ?? null,
    };
  } catch {
    return {
      status: 'unavailable',
      resultUrl: null,
    };
  }
}

async function lookupAbuseIpDb(ip: string | null): Promise<DomainReputationResult['abuseIpDb']> {
  const apiKey = process.env.ABUSEIPDB_API_KEY;
  if (!ip || !apiKey) {
    return {
      status: 'not_configured',
      confidenceScore: null,
      reports: null,
      reference: ip ? `https://www.abuseipdb.com/check/${ip}` : null,
    };
  }

  try {
    const response = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`, {
      headers: {
        Key: apiKey,
        Accept: 'application/json',
      },
      signal: AbortSignal.timeout(8000),
    });

    if (!response.ok) {
      return {
        status: 'unavailable',
        confidenceScore: null,
        reports: null,
        reference: `https://www.abuseipdb.com/check/${ip}`,
      };
    }

    const payload = (await response.json()) as { data?: { abuseConfidenceScore?: number; totalReports?: number } };
    const confidenceScore = payload.data?.abuseConfidenceScore ?? 0;

    return {
      status: confidenceScore > 0 ? 'listed' : 'clean',
      confidenceScore,
      reports: payload.data?.totalReports ?? 0,
      reference: `https://www.abuseipdb.com/check/${ip}`,
    };
  } catch {
    return {
      status: 'unavailable',
      confidenceScore: null,
      reports: null,
      reference: `https://www.abuseipdb.com/check/${ip}`,
    };
  }
}

function cdxTimestampToIso(timestamp: string): string | null {
  if (!/^\d{14}$/.test(timestamp)) {
    return null;
  }

  const iso = `${timestamp.slice(0, 4)}-${timestamp.slice(4, 6)}-${timestamp.slice(6, 8)}T${timestamp.slice(8, 10)}:${timestamp.slice(10, 12)}:${timestamp.slice(12, 14)}.000Z`;
  return new Date(iso).toISOString();
}

async function lookupUrlhausHost(host: string): Promise<DomainReputationResult['urlhausHost']> {
  try {
    const response = await fetch('https://urlhaus-api.abuse.ch/v1/host/', {
      method: 'POST',
      headers: buildUrlhausHeaders(),
      body: new URLSearchParams({ host }),
      signal: AbortSignal.timeout(8000),
    });

    if (!response.ok) {
      return {
        status: 'unavailable',
        reference: null,
        urls: [],
      };
    }

    const payload = (await response.json()) as {
      query_status?: string;
      urls?: Array<{ url?: string; urlhaus_reference?: string }>;
    };

    if (payload.query_status !== 'ok') {
      return {
        status: 'not_listed',
        reference: null,
        urls: [],
      };
    }

    const urls = (payload.urls ?? [])
      .map((entry) => entry.url)
      .filter((entry): entry is string => typeof entry === 'string');

    return {
      status: 'listed',
      reference: payload.urls?.[0]?.urlhaus_reference ?? `https://urlhaus.abuse.ch/browse.php?search=${encodeURIComponent(host)}`,
      urls,
    };
  } catch {
    return {
      status: 'unavailable',
      reference: null,
      urls: [],
    };
  }
}

function buildUrlhausHeaders(): Record<string, string> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/x-www-form-urlencoded',
  };

  if (process.env.URLHAUS_AUTH_KEY) {
    headers['Auth-Key'] = process.env.URLHAUS_AUTH_KEY;
  }

  return headers;
}