import React, { useState } from 'react';
import { Mail, Cpu, AlertOctagon, Link as LinkIcon, CheckCircle, XCircle } from 'lucide-react';

import type { EmailAnalysisResponse, UrlAnalysisJob } from '../../shared/analysis-types';

const SANDBOX_POLL_INTERVAL_MS = import.meta.env.MODE === 'test' ? 1 : 1000;
const SANDBOX_MAX_POLL_ATTEMPTS = 5;

export function EmailAnalysis() {
  const [rawEmail, setRawEmail] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisResult, setAnalysisResult] = useState<EmailAnalysisResponse | null>(null);
  const [sandboxJob, setSandboxJob] = useState<UrlAnalysisJob | null>(null);
  const [isSandboxing, setIsSandboxing] = useState(false);
  const [error, setError] = useState('');

  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!rawEmail) return;

    setIsAnalyzing(true);
    setError('');
    setAnalysisResult(null);
    setSandboxJob(null);

    try {
      const response = await fetch('/api/analyze/email', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ rawEmail }),
      });

      const payload = await response.json();

      if (!response.ok) {
        throw new Error(payload.message || 'Email analysis failed.');
      }
      setAnalysisResult(payload as EmailAnalysisResponse);

    } catch (analysisError) {
      console.error(analysisError);
      setError(analysisError instanceof Error ? analysisError.message : 'An error occurred during analysis.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleRunUrlSandbox = async () => {
    if (!analysisResult || analysisResult.urls.length === 0) {
      return;
    }

    setIsSandboxing(true);
    setError('');

    try {
      const createResponse = await fetch('/api/analyze/urls', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ urls: analysisResult.urls.map((url) => url.decodedUrl) }),
      });
      const createdJob = (await createResponse.json()) as UrlAnalysisJob | { message?: string };

      if (!createResponse.ok || !('jobId' in createdJob)) {
        throw new Error(('message' in createdJob && createdJob.message) || 'URL sandbox launch failed.');
      }

      setSandboxJob(createdJob);
      const completedJob = await pollSandboxJob(createdJob.jobId);
      setSandboxJob(completedJob);
    } catch (sandboxError) {
      setError(sandboxError instanceof Error ? sandboxError.message : 'URL sandbox failed.');
    } finally {
      setIsSandboxing(false);
    }
  };

  const pollSandboxJob = async (jobId: string) => {
    for (let attempt = 0; attempt < SANDBOX_MAX_POLL_ATTEMPTS; attempt += 1) {
      const jobResponse = await fetch(`/api/analyze/urls/${jobId}`, {
        method: 'GET',
      });
      const jobPayload = (await jobResponse.json()) as UrlAnalysisJob | { message?: string };
      if (!jobResponse.ok || !('jobId' in jobPayload)) {
        throw new Error(('message' in jobPayload && jobPayload.message) || 'URL sandbox polling failed.');
      }

      setSandboxJob(jobPayload);
      if (jobPayload.status === 'completed' || jobPayload.status === 'failed') {
        return jobPayload;
      }

      await new Promise((resolve) => {
        setTimeout(resolve, SANDBOX_POLL_INTERVAL_MS);
      });
    }

    throw new Error('URL sandbox polling timed out.');
  };

  const getThreatColor = (level: string) => {
    switch (level?.toUpperCase()) {
      case 'CRITICAL': return 'text-red-600 animate-pulse font-bold';
      case 'HIGH': return 'text-red-500 font-bold';
      case 'MEDIUM': return 'text-yellow-500 font-bold';
      case 'LOW': return 'text-green-500 font-bold';
      default: return 'text-cyber-red';
    }
  };

  const AuthIcon = ({ status }: { status: string }) => {
    const s = status?.toLowerCase();
    if (s === 'pass') return <CheckCircle size={14} className="inline text-green-500 ml-1" />;
    if (s === 'fail' || s === 'softfail') return <XCircle size={14} className="inline text-red-500 ml-1" />;
    return <span className="text-gray-500 ml-1 text-xs">({status})</span>;
  };

  return (
    <div className="space-y-6">
      <div className="cli-border p-4">
        <h2 className="text-xl mb-4 flex items-center uppercase tracking-wider">
          <Mail className="mr-2" /> Raw Email Ingestion
        </h2>
        <form onSubmit={handleAnalyze} className="space-y-4">
          <textarea
            value={rawEmail}
            onChange={(e) => setRawEmail(e.target.value)}
            placeholder="Paste full raw email source here (including headers)..."
            className="cli-input w-full h-48 p-4 font-mono text-xs resize-y"
          />
          <button type="submit" disabled={isAnalyzing || !rawEmail} className="cli-button w-full py-3 flex items-center justify-center">
            {isAnalyzing ? (
              <span className="animate-pulse flex items-center"><Cpu size={16} className="mr-2 animate-spin" /> ANALYZING EMAIL EVIDENCE...</span>
            ) : (
              <>DECODE & ANALYZE</>
            )}
          </button>
        </form>
        {error && <div className="mt-4 text-red-500 text-sm border border-red-500 p-2 bg-red-500/10">[!] ERROR: {error}</div>}
      </div>

      {analysisResult && (
        <div className="space-y-6 animate-in fade-in duration-500">
          <div className="cli-border p-6 bg-cyber-red-dim/10">
            <div className="flex justify-between items-start mb-4">
              <h3 className="text-2xl uppercase font-bold flex items-center">
                <AlertOctagon className="mr-2" /> Threat Report
              </h3>
              <div className="text-right">
                <div className="text-xs opacity-70 uppercase">Threat Level</div>
                <div className={`text-2xl tracking-widest ${getThreatColor(analysisResult.threatLevel)}`}>
                  [{analysisResult.threatLevel}]
                </div>
              </div>
            </div>
            <p className="text-sm leading-relaxed border-l-2 border-cyber-red pl-4 opacity-90">
              {analysisResult.executiveSummary}
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="cli-border p-4">
              <h4 className="text-lg border-b border-cyber-red-dim pb-2 uppercase mb-4">Parsed Headers</h4>
              <div className="space-y-2 text-sm">
                <div className="grid grid-cols-3 gap-2 border-b border-cyber-red-dim/30 pb-1">
                  <span className="opacity-70">From:</span>
                  <span className="col-span-2 break-all">{analysisResult.headers?.from || 'N/A'}</span>
                </div>
                <div className="grid grid-cols-3 gap-2 border-b border-cyber-red-dim/30 pb-1">
                  <span className="opacity-70">To:</span>
                  <span className="col-span-2 break-all">{analysisResult.headers?.to || 'N/A'}</span>
                </div>
                <div className="grid grid-cols-3 gap-2 border-b border-cyber-red-dim/30 pb-1">
                  <span className="opacity-70">Subject:</span>
                  <span className="col-span-2 break-all">{analysisResult.headers?.subject || 'N/A'}</span>
                </div>
                <div className="grid grid-cols-3 gap-2 border-b border-cyber-red-dim/30 pb-1">
                  <span className="opacity-70">Date:</span>
                  <span className="col-span-2 break-all">{analysisResult.headers?.date || 'N/A'}</span>
                </div>
                <div className="grid grid-cols-3 gap-2 border-b border-cyber-red-dim/30 pb-1">
                  <span className="opacity-70">Return-Path:</span>
                  <span className="col-span-2 break-all">{analysisResult.headers?.returnPath || 'N/A'}</span>
                </div>
              </div>
            </div>

            <div className="cli-border p-4">
              <h4 className="text-lg border-b border-cyber-red-dim pb-2 uppercase mb-4">Authentication</h4>
              <div className="space-y-4 text-sm">
                <div className="flex justify-between items-center p-2 bg-black/50 border border-cyber-red-dim">
                  <span>SPF</span>
                  <span className="uppercase font-bold flex items-center">
                    {analysisResult.authentication?.spf || 'UNKNOWN'}
                    <AuthIcon status={analysisResult.authentication?.spf} />
                  </span>
                </div>
                <div className="flex justify-between items-center p-2 bg-black/50 border border-cyber-red-dim">
                  <span>DKIM</span>
                  <span className="uppercase font-bold flex items-center">
                    {analysisResult.authentication?.dkim || 'UNKNOWN'}
                    <AuthIcon status={analysisResult.authentication?.dkim} />
                  </span>
                </div>
                <div className="flex justify-between items-center p-2 bg-black/50 border border-cyber-red-dim">
                  <span>DMARC</span>
                  <span className="uppercase font-bold flex items-center">
                    {analysisResult.authentication?.dmarc || 'UNKNOWN'}
                    <AuthIcon status={analysisResult.authentication?.dmarc} />
                  </span>
                </div>
              </div>
            </div>
          </div>

          <div className="cli-border p-4">
            <h4 className="text-lg border-b border-cyber-red-dim pb-2 uppercase mb-4 flex items-center">
              <LinkIcon className="mr-2" size={18} /> URL Analysis
            </h4>
            {analysisResult.urls && analysisResult.urls.length > 0 ? (
              <div className="space-y-4">
                <button
                  type="button"
                  onClick={handleRunUrlSandbox}
                  disabled={isSandboxing}
                  className="cli-button w-full py-2 flex items-center justify-center"
                >
                  {isSandboxing ? 'RUNNING URL SANDBOX...' : 'RUN URL SANDBOX'}
                </button>
                {sandboxJob && (
                  <div className="text-xs opacity-80 border border-cyber-red-dim p-2">
                    Sandbox Job: {sandboxJob.status.toUpperCase()} [{sandboxJob.jobId}]
                  </div>
                )}
                {analysisResult.urls.map((url, idx: number) => (
                  <div key={idx} className={`p-3 border ${url.suspicious ? 'border-red-500 bg-red-500/10' : 'border-cyber-red-dim bg-black/50'}`}>
                    <div className="text-xs opacity-70 mb-1">Original:</div>
                    <div className="text-sm break-all mb-2">{url.originalUrl}</div>
                    {url.decodedUrl && url.decodedUrl !== url.originalUrl && (
                      <>
                        <div className="text-xs opacity-70 mb-1">Decoded/Destination:</div>
                        <div className="text-sm break-all mb-2 text-yellow-500">{url.decodedUrl}</div>
                      </>
                    )}
                    {url.suspicious && (
                      <div className="text-xs text-red-400 mt-2 flex items-start">
                        <AlertOctagon size={12} className="mr-1 mt-0.5 flex-shrink-0" />
                        <span>{url.reason}</span>
                      </div>
                    )}
                  </div>
                ))}
                {sandboxJob?.results.length ? (
                  <div className="space-y-3 pt-2">
                    {sandboxJob.results.map((result, index) => (
                      <div key={`${result.originalUrl}-${index}`} className="border border-cyber-red-dim bg-black/40 p-3 text-sm">
                        <div className="flex flex-col md:flex-row md:justify-between gap-2 mb-2">
                          <div className="font-bold break-all">{result.title || result.originalUrl}</div>
                          <div className={`${result.status === 'completed' ? 'text-green-500' : 'text-red-500'} uppercase font-bold`}>
                            {result.status}
                          </div>
                        </div>
                        <div className="space-y-1 opacity-90">
                          <div>Final URL: {result.finalUrl || 'Unavailable'}</div>
                          <div>Screenshot: {result.screenshotPath || 'Unavailable'}</div>
                          <div>Trace: {result.tracePath || 'Unavailable'}</div>
                          <div>Redirects: {result.redirectChain.join(' -> ') || 'None observed'}</div>
                          <div>Scripts: {result.scriptUrls.join(', ') || 'None observed'}</div>
                          <div>URLhaus: {result.externalScans.urlhaus.status}</div>
                          <div>VirusTotal: {result.externalScans.virustotal.status}</div>
                          <div>URLScan: {result.externalScans.urlscan.status}</div>
                          <div>AlienVault OTX: {result.externalScans.alienVault.status}</div>
                          {result.error && <div className="text-red-400">Error: {result.error}</div>}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : null}
              </div>
            ) : (
              <p className="text-sm opacity-70">No URLs detected in the email.</p>
            )}
          </div>

          <div className="cli-border p-4">
            <h4 className="text-lg border-b border-cyber-red-dim pb-2 uppercase mb-4">Detected Inconsistencies</h4>
            {analysisResult.inconsistencies && analysisResult.inconsistencies.length > 0 ? (
              <ul className="list-none space-y-2">
                {analysisResult.inconsistencies.map((inc: string, idx: number) => (
                  <li key={idx} className="text-sm flex items-start">
                    <span className="text-red-500 mr-2">[{idx + 1}]</span>
                    <span>{inc}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm opacity-70 text-green-500">No major inconsistencies detected.</p>
            )}
          </div>

          <div className="cli-border p-4">
            <h4 className="text-lg border-b border-cyber-red-dim pb-2 uppercase mb-4">Related Domains</h4>
            {analysisResult.relatedDomains && analysisResult.relatedDomains.length > 0 ? (
              <div className="space-y-3">
                {analysisResult.relatedDomains.map((entry, index) => (
                  <div key={`${entry.domain}-${entry.relation}-${index}`} className="border border-cyber-red-dim bg-black/40 p-3 text-sm">
                    <div className="flex flex-col md:flex-row md:justify-between md:items-start gap-2">
                      <div>
                        <div className="font-bold break-all">{entry.domain}</div>
                        <div className="opacity-70 uppercase text-xs">Relation: {entry.relation}</div>
                      </div>
                      <div className={`font-bold ${getThreatColor(entry.analysis.riskLevel)}`}>
                        {entry.analysis.riskLevel} / {entry.analysis.score}
                      </div>
                    </div>
                    <p className="mt-2 opacity-90">{entry.analysis.summary}</p>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm opacity-70">No related domains were correlated from the current email evidence.</p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
