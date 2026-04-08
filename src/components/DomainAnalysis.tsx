import React, { useState } from 'react';
import { Globe, Search, ExternalLink, Activity, Server, AlertTriangle } from 'lucide-react';

import type { DomainAnalysisResponse } from '../../shared/analysis-types';

export function DomainAnalysis() {
  const [domain, setDomain] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [results, setResults] = useState<DomainAnalysisResponse | null>(null);
  const [error, setError] = useState('');

  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!domain) return;

    setIsAnalyzing(true);
    setResults(null);
    setError('');

    try {
      const response = await fetch('/api/analyze/domain', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ domain }),
      });

      const payload = await response.json();

      if (!response.ok) {
        throw new Error(payload.message || 'Domain analysis failed.');
      }

      setResults(payload as DomainAnalysisResponse);
    } catch (analysisError) {
      setError(analysisError instanceof Error ? analysisError.message : 'Domain analysis failed.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const threatColor =
    results?.riskLevel === 'HIGH'
      ? 'text-red-500'
      : results?.riskLevel === 'MEDIUM'
        ? 'text-yellow-500'
        : 'text-green-500';

  const dnsEntries = results
    ? [
        ...results.dns.a.map((value) => ({ type: 'A', value })),
        ...results.dns.aaaa.map((value) => ({ type: 'AAAA', value })),
        ...results.dns.mx.map((value) => ({ type: 'MX', value })),
        ...results.dns.ns.map((value) => ({ type: 'NS', value })),
        ...results.dns.txt.map((value) => ({ type: 'TXT', value })),
        ...results.dns.caa.map((value) => ({ type: 'CAA', value })),
        ...(results.dns.soa ? [{ type: 'SOA', value: results.dns.soa }] : []),
      ]
    : [];

  return (
    <div className="space-y-6">
      <div className="cli-border p-4">
        <h2 className="text-xl mb-4 flex items-center uppercase tracking-wider">
          <Globe className="mr-2" /> Target Domain Analysis
        </h2>
        <form onSubmit={handleAnalyze} className="flex gap-4">
          <input
            type="text"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="e.g., suspicious-login-update.com"
            className="cli-input flex-1 p-2"
          />
          <button type="submit" disabled={isAnalyzing || !domain} className="cli-button px-6 flex items-center">
            {isAnalyzing ? <span className="animate-pulse">SCANNING...</span> : <><Search size={16} className="mr-2" /> EXECUTE</>}
          </button>
        </form>
        {error && <div className="mt-4 text-red-500 text-sm border border-red-500 p-2 bg-red-500/10">[!] ERROR: {error}</div>}
      </div>

      {isAnalyzing && (
        <div className="cli-border p-6 text-center animate-pulse">
          <Activity className="mx-auto mb-4" size={32} />
          <p>[*] Initiating WHOIS lookup...</p>
          <p>[*] Scanning DNS records...</p>
          <p>[*] Cross-referencing threat intelligence databases...</p>
        </div>
      )}

      {results && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="cli-border p-4 space-y-4">
            <h3 className="text-lg border-b border-cyber-red-dim pb-2 uppercase">Intelligence Report</h3>
            <p className="text-sm leading-relaxed border-l-2 border-cyber-red pl-3">{results.summary}</p>
            
            <div className="grid grid-cols-2 gap-2 text-sm">
              <span className="opacity-70">Target:</span>
              <span className="font-bold break-all">{results.normalizedDomain}</span>
              
              <span className="opacity-70">Threat Score:</span>
              <span className={`font-bold ${threatColor} ${results.score > 70 ? 'animate-pulse' : ''}`}>
                {results.score}/100 {results.score > 70 && <AlertTriangle size={14} className="inline ml-1" />}
              </span>

              <span className="opacity-70">Risk Level:</span>
              <span className={`font-bold ${threatColor}`}>{results.riskLevel}</span>
              
              <span className="opacity-70">Creation Date:</span>
              <span>{results.rdap.createdAt ? new Date(results.rdap.createdAt).toLocaleString() : 'Unknown'}</span>
              
              <span className="opacity-70">Registrar:</span>
              <span>{results.rdap.registrar || 'Unknown'}</span>
              
              <span className="opacity-70">Resolved IPs:</span>
              <span className="break-all">{results.infrastructure.ipAddresses.join(', ') || 'None resolved'}</span>
            </div>

            <div className="mt-4 pt-4 border-t border-cyber-red-dim">
              <h4 className="text-sm uppercase mb-2 opacity-70">Detected Risk Factors</h4>
              <ul className="list-disc list-inside text-sm space-y-1">
                {results.riskFactors.length > 0 ? (
                  results.riskFactors.map((riskFactor, index) => <li key={index}>{riskFactor}</li>)
                ) : (
                  <li>No explicit risk factors detected.</li>
                )}
              </ul>
            </div>

            <div className="mt-4 pt-4 border-t border-cyber-red-dim text-sm">
              <div className="opacity-70 uppercase mb-2 flex items-center"><Server size={14} className="mr-2" /> TLS Snapshot</div>
              <div className="space-y-1">
                <div>Subject: {results.infrastructure.tls?.subject || 'Unavailable'}</div>
                <div>Issuer: {results.infrastructure.tls?.issuer || 'Unavailable'}</div>
                <div>Valid To: {results.infrastructure.tls?.validTo ? new Date(results.infrastructure.tls.validTo).toLocaleString() : 'Unavailable'}</div>
                <div>SANs: {results.infrastructure.tls?.subjectAltNames.join(', ') || 'Unavailable'}</div>
              </div>
            </div>

            <div className="mt-4 pt-4 border-t border-cyber-red-dim text-sm">
              <div className="opacity-70 uppercase mb-2">Mail Security</div>
              <div className="space-y-1">
                <div>SPF Mode: {results.mailSecurity.spf.mode || 'Unavailable'}</div>
                <div>DMARC Policy: {results.mailSecurity.dmarc.policy || 'Unavailable'}</div>
                <div>MTA-STS: {results.mailSecurity.mtaSts.present ? 'Present' : 'Absent'}</div>
                <div>TLS-RPT: {results.mailSecurity.tlsRpt.present ? 'Present' : 'Absent'}</div>
              </div>
            </div>
          </div>

          <div className="space-y-6">
            <div className="cli-border p-4">
              <h3 className="text-lg border-b border-cyber-red-dim pb-2 uppercase mb-4">Infrastructure Intelligence</h3>
              <div className="space-y-3 text-sm">
                {results.infrastructure.ipIntelligence.length > 0 ? (
                  results.infrastructure.ipIntelligence.map((entry) => (
                    <div key={entry.ip} className="border border-cyber-red-dim p-3">
                      <div className="font-bold break-all">{entry.ip}</div>
                      <div>{entry.city && entry.country ? `${entry.city}, ${entry.country}` : entry.country || 'Unknown location'}</div>
                      <div>ASN: {entry.asn || 'Unknown'}</div>
                      <div>Provider: {entry.organization || 'Unknown'}</div>
                      <div>Reverse DNS: {entry.reverseDns.join(', ') || 'None'}</div>
                    </div>
                  ))
                ) : (
                  <div className="opacity-70">No IP intelligence returned.</div>
                )}
              </div>
            </div>

            <div className="cli-border p-4">
              <h3 className="text-lg border-b border-cyber-red-dim pb-2 uppercase mb-4">DNS Ramifications</h3>
              <div className="space-y-2 text-sm">
                {dnsEntries.length > 0 ? (
                  dnsEntries.map((entry, index) => (
                    <div key={`${entry.type}-${entry.value}-${index}`} className="flex gap-4">
                      <span className="w-12 opacity-70">[{entry.type}]</span>
                      <span className="break-all">{entry.value}</span>
                    </div>
                  ))
                ) : (
                  <div className="opacity-70">No DNS data returned.</div>
                )}
              </div>
            </div>

            <div className="cli-border p-4 text-sm space-y-2">
              <h3 className="text-lg border-b border-cyber-red-dim pb-2 uppercase mb-4">Historical Evidence</h3>
              <div>Wayback Snapshots: {results.history.waybackSnapshots}</div>
              <div>First Seen: {results.history.firstSeen ? new Date(results.history.firstSeen).toLocaleString() : 'Unavailable'}</div>
              <div>Last Seen: {results.history.lastSeen ? new Date(results.history.lastSeen).toLocaleString() : 'Unavailable'}</div>
              <div>CT Certificates: {results.certificates.certificateTransparency.certificateCount}</div>
              <div>Observed Subdomains: {results.certificates.certificateTransparency.observedSubdomains.join(', ') || 'None observed'}</div>
            </div>

            <div className="cli-border p-4 text-sm space-y-2">
              <h3 className="text-lg border-b border-cyber-red-dim pb-2 uppercase mb-4">Reputation Signals</h3>
              <div>URLhaus Host: {results.reputation.urlhausHost.status}</div>
              <div>URLhaus URLs: {results.reputation.urlhausHost.urls.length}</div>
              <div>AlienVault OTX: {results.reputation.alienVault.status}</div>
              <div>OTX Pulses: {results.reputation.alienVault.pulseCount ?? 'Unavailable'}</div>
              <div>VirusTotal: {results.reputation.virustotal.status}</div>
              <div>URLScan: {results.reputation.urlscan.status}</div>
              <div>AbuseIPDB: {results.reputation.abuseIpDb.status}</div>
            </div>

            <div className="cli-border p-4">
              <h3 className="text-lg border-b border-cyber-red-dim pb-2 uppercase mb-4">External OSINT Tools</h3>
              <div className="grid grid-cols-2 gap-2">
                <a href={results.osint.virustotal} target="_blank" rel="noreferrer" className="cli-button p-2 text-center text-xs flex items-center justify-center">
                  VirusTotal <ExternalLink size={12} className="ml-2" />
                </a>
                <a href={results.osint.urlscan} target="_blank" rel="noreferrer" className="cli-button p-2 text-center text-xs flex items-center justify-center">
                  URLScan.io <ExternalLink size={12} className="ml-2" />
                </a>
                <a href={results.osint.viewdns} target="_blank" rel="noreferrer" className="cli-button p-2 text-center text-xs flex items-center justify-center">
                  ViewDNS <ExternalLink size={12} className="ml-2" />
                </a>
                <a href={results.osint.crtSh} target="_blank" rel="noreferrer" className="cli-button p-2 text-center text-xs flex items-center justify-center">
                  crt.sh (Certs) <ExternalLink size={12} className="ml-2" />
                </a>
                <a href={results.osint.wayback} target="_blank" rel="noreferrer" className="cli-button p-2 text-center text-xs flex items-center justify-center">
                  Wayback <ExternalLink size={12} className="ml-2" />
                </a>
                <a href={results.osint.alienVault} target="_blank" rel="noreferrer" className="cli-button p-2 text-center text-xs flex items-center justify-center">
                  AlienVault OTX <ExternalLink size={12} className="ml-2" />
                </a>
                <a href={results.osint.dnsdumpster} target="_blank" rel="noreferrer" className="cli-button p-2 text-center text-xs flex items-center justify-center">
                  DNSdumpster <ExternalLink size={12} className="ml-2" />
                </a>
                <a href={results.osint.builtwith} target="_blank" rel="noreferrer" className="cli-button p-2 text-center text-xs flex items-center justify-center">
                  BuiltWith <ExternalLink size={12} className="ml-2" />
                </a>
                <a href={results.osint.urlhausHost} target="_blank" rel="noreferrer" className="cli-button p-2 text-center text-xs flex items-center justify-center">
                  URLhaus Host <ExternalLink size={12} className="ml-2" />
                </a>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
