import React, { useState } from 'react';
import { Mail, Cpu, AlertOctagon, Link as LinkIcon, CheckCircle, XCircle } from 'lucide-react';

import type { EmailAnalysisResponse, EmailAuthenticationDetail, FileAnalysisJob, UrlAnalysisJob } from '../../shared/analysis-types';
import { caseDomainReference, caseEmailReference, caseFileReference, caseJobReference, caseUrlReference } from '../case-event-references';
import { useCaseContext } from '../case-context';
import { SignalBadge, SignalPanel, SignalText, isBlinkingSignal, toneFromBinaryFlag, toneFromRiskLevel, toneFromRiskScore, toneFromScannerStatus } from './signal-display';

const SANDBOX_POLL_INTERVAL_MS = import.meta.env.MODE === 'test' ? 1 : 1000;
const SANDBOX_MAX_POLL_ATTEMPTS = 5;

export function EmailAnalysis() {
  const { addCaseEvent } = useCaseContext();
  const [rawEmail, setRawEmail] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisResult, setAnalysisResult] = useState<EmailAnalysisResponse | null>(null);
  const [sandboxJob, setSandboxJob] = useState<UrlAnalysisJob | null>(null);
  const [remoteFileJobs, setRemoteFileJobs] = useState<Record<string, FileAnalysisJob>>({});
  const [remoteFileErrors, setRemoteFileErrors] = useState<Record<string, string>>({});
  const [remoteFileLoadingUrl, setRemoteFileLoadingUrl] = useState<string | null>(null);
  const [isSandboxing, setIsSandboxing] = useState(false);
  const [error, setError] = useState('');

  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!rawEmail) return;

    setIsAnalyzing(true);
    setError('');
    setAnalysisResult(null);
    setSandboxJob(null);
    setRemoteFileJobs({});
    setRemoteFileErrors({});
    setRemoteFileLoadingUrl(null);
    addCaseEvent({
      tool: 'email',
      severity: 'info',
      title: 'Raw email submitted',
      detail: `${rawEmail.length} characters submitted for parsing`,
    });

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
      const result = payload as EmailAnalysisResponse;
      setAnalysisResult(result);
      addCaseEvent({
        tool: 'email',
        severity: result.threatLevel === 'LOW' ? 'success' : 'warning',
        title: 'Email analysis completed',
        detail: `${result.threatLevel} threat with ${result.urls.length} URL(s) and ${result.attachments.length} attachment(s)`,
        references: [
          ...(result.headers.from ? [caseEmailReference(result.headers.from, 'from')] : []),
          ...result.domains.slice(0, 3).map((domain) => caseDomainReference(domain)),
          ...result.urls.slice(0, 3).map((url) => caseUrlReference(url.decodedUrl, 'decoded-url')),
        ],
      });

    } catch (analysisError) {
      console.error(analysisError);
      const message = analysisError instanceof Error ? analysisError.message : 'An error occurred during analysis.';
      setError(message);
      addCaseEvent({
        tool: 'email',
        severity: 'danger',
        title: 'Email analysis failed',
        detail: message,
      });
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
    addCaseEvent({
      tool: 'email',
      severity: 'info',
      title: 'Email URL sandbox started',
      detail: `${analysisResult.urls.length} extracted URL(s) queued from raw email analysis`,
      references: analysisResult.urls.slice(0, 3).map((url) => caseUrlReference(url.decodedUrl, 'sandbox-target')),
    });

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
      addCaseEvent({
        tool: 'email',
        severity: completedJob.status === 'completed' ? 'success' : 'warning',
        title: 'Email URL sandbox finished',
        detail: `${completedJob.results.length} URL result(s) returned with status ${completedJob.status}`,
        references: [
          caseJobReference('url-analysis', completedJob.jobId),
          ...completedJob.queuedUrls.slice(0, 3).map((url) => caseUrlReference(url, 'sandbox-target')),
        ],
      });
    } catch (sandboxError) {
      const message = sandboxError instanceof Error ? sandboxError.message : 'URL sandbox failed.';
      setError(message);
      addCaseEvent({
        tool: 'email',
        severity: 'danger',
        title: 'Email URL sandbox failed',
        detail: message,
      });
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

  const handleAnalyzeRemoteFile = async (url: string) => {
    setRemoteFileLoadingUrl(url);
    setRemoteFileErrors((current) => ({ ...current, [url]: '' }));
    addCaseEvent({
      tool: 'email',
      severity: 'info',
      title: 'Remote file queued from email',
      detail: url,
      references: [caseUrlReference(url, 'remote-file')],
    });

    try {
      const createResponse = await fetch('/api/analyze/files/remote', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url }),
      });
      const createdJob = (await createResponse.json()) as FileAnalysisJob | { message?: string };

      if (!createResponse.ok || !('jobId' in createdJob)) {
        throw new Error(('message' in createdJob && createdJob.message) || 'Remote file analysis launch failed.');
      }

      setRemoteFileJobs((current) => ({ ...current, [url]: createdJob }));
      const completedJob = await pollRemoteFileJob(createdJob.jobId, url);
      setRemoteFileJobs((current) => ({ ...current, [url]: completedJob }));
      addCaseEvent({
        tool: 'email',
        severity: completedJob.status === 'completed' ? 'success' : 'warning',
        title: 'Remote file analysis finished',
        detail: `${url} -> ${completedJob.status}`,
        references: [
          caseUrlReference(url, 'remote-file'),
          caseJobReference('file-analysis', completedJob.jobId),
          ...completedJob.results.slice(0, 1).map((result) => caseFileReference(result.filename, result.storagePath, url, 'analyzed-file')),
        ],
      });
    } catch (remoteFileError) {
      const message = remoteFileError instanceof Error ? remoteFileError.message : 'Remote file analysis failed.';
      setRemoteFileErrors((current) => ({
        ...current,
        [url]: message,
      }));
      addCaseEvent({
        tool: 'email',
        severity: 'danger',
        title: 'Remote file analysis failed',
        detail: `${url}: ${message}`,
        references: [caseUrlReference(url, 'remote-file')],
      });
    } finally {
      setRemoteFileLoadingUrl((current) => (current === url ? null : current));
    }
  };

  const pollRemoteFileJob = async (jobId: string, url: string) => {
    for (let attempt = 0; attempt < SANDBOX_MAX_POLL_ATTEMPTS; attempt += 1) {
      const jobResponse = await fetch(`/api/analyze/files/${jobId}`, {
        method: 'GET',
      });
      const jobPayload = (await jobResponse.json()) as FileAnalysisJob | { message?: string };
      if (!jobResponse.ok || !('jobId' in jobPayload)) {
        throw new Error(('message' in jobPayload && jobPayload.message) || 'Remote file analysis polling failed.');
      }

      setRemoteFileJobs((current) => ({ ...current, [url]: jobPayload }));
      if (jobPayload.status === 'completed' || jobPayload.status === 'failed') {
        return jobPayload;
      }

      await new Promise((resolve) => {
        setTimeout(resolve, SANDBOX_POLL_INTERVAL_MS);
      });
    }

    throw new Error('Remote file analysis polling timed out.');
  };

  const AuthIcon = ({ status }: { status: string | null | undefined }) => {
    const s = status?.toLowerCase();
    if (s === 'pass') return <CheckCircle size={14} className="inline text-green-500 ml-1" />;
    if (s === 'fail' || s === 'softfail') return <XCircle size={14} className="inline text-red-500 ml-1" />;
    return <span className="text-gray-500 ml-1 text-xs">({status || 'unknown'})</span>;
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
                <SignalBadge tone={toneFromRiskLevel(analysisResult.threatLevel)} blink={isBlinkingSignal(toneFromRiskLevel(analysisResult.threatLevel), analysisResult.threatLevel !== 'LOW')} className="text-base">
                  {analysisResult.threatLevel}
                </SignalBadge>
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
                <AuthenticationDetailCard label="SPF" status={analysisResult.authentication?.spf} detail={analysisResult.authentication?.spfDetails} AuthIcon={AuthIcon} />
                <AuthenticationDetailCard label="DKIM" status={analysisResult.authentication?.dkim} detail={analysisResult.authentication?.dkimDetails} AuthIcon={AuthIcon} />
                <AuthenticationDetailCard label="DMARC" status={analysisResult.authentication?.dmarc} detail={analysisResult.authentication?.dmarcDetails} AuthIcon={AuthIcon} />
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
                  <div key={idx}>
                    <SignalPanel tone={toneFromBinaryFlag(url.suspicious)} blink={url.suspicious} className="p-3">
                      <div className="flex flex-wrap items-center gap-2 mb-2">
                        <SignalBadge tone={toneFromBinaryFlag(url.suspicious)}>{url.suspicious ? 'suspicious' : 'clean'}</SignalBadge>
                        {url.wrapperType ? <SignalBadge tone={url.wrapperType === 'barracuda' ? 'warning' : 'neutral'}>{url.wrapperType}</SignalBadge> : null}
                      </div>
                      <div className="text-xs opacity-70 mb-1">Original:</div>
                      <div className="text-sm break-all mb-2">{url.originalUrl}</div>
                      {url.decodedUrl && url.decodedUrl !== url.originalUrl && (
                        <>
                          <div className="text-xs opacity-70 mb-1">Decoded/Destination:</div>
                          <div className="text-sm break-all mb-2 text-orange-300">{url.decodedUrl}</div>
                        </>
                      )}
                      {url.resolutionChain && url.resolutionChain.length > 0 ? (
                        <div className="mt-3 space-y-1">
                          <div className="text-xs opacity-70">Resolution Chain:</div>
                          {url.resolutionChain.map((step) => (
                            <div key={`${step.label}-${step.url}`} className="text-xs break-all opacity-80">
                              {step.label}: {step.url}
                            </div>
                          ))}
                        </div>
                      ) : null}
                      {url.suspicious && (
                        <div className="text-xs text-orange-300 mt-2 flex items-start">
                          <AlertOctagon size={12} className="mr-1 mt-0.5 flex-shrink-0" />
                          <span>{url.reason}</span>
                        </div>
                      )}
                      {looksLikeDownloadableFileUrl(url.decodedUrl) ? (
                        <div className="mt-3 space-y-2">
                          <button
                            type="button"
                            onClick={() => handleAnalyzeRemoteFile(url.decodedUrl)}
                            disabled={remoteFileLoadingUrl === url.decodedUrl}
                            className="cli-button py-2 px-3 text-xs"
                          >
                            {remoteFileLoadingUrl === url.decodedUrl ? 'ANALYZING REMOTE FILE...' : 'ANALYZE REMOTE FILE'}
                          </button>
                          {remoteFileErrors[url.decodedUrl] ? (
                            <div className="text-xs text-red-400">{remoteFileErrors[url.decodedUrl]}</div>
                          ) : null}
                          {remoteFileJobs[url.decodedUrl] ? <RemoteFileJobCard job={remoteFileJobs[url.decodedUrl]} /> : null}
                        </div>
                      ) : null}
                    </SignalPanel>
                  </div>
                ))}
                {sandboxJob?.results.length ? (
                  <div className="space-y-3 pt-2">
                    {sandboxJob.results.map((result, index) => (
                      <div key={`${result.originalUrl}-${index}`} className="border border-cyber-red-dim bg-black/40 p-3 text-sm">
                        <div className="flex flex-col md:flex-row md:justify-between gap-2 mb-2">
                          <div className="font-bold break-all">{result.title || result.originalUrl}</div>
                          <SignalBadge tone={toneFromScannerStatus(result.status)} blink={result.status !== 'completed'}>{result.status}</SignalBadge>
                        </div>
                        <div className="space-y-1 opacity-90">
                          <div>Final URL: {result.finalUrl || 'Unavailable'}</div>
                          <div>Screenshot: {result.screenshotPath || 'Unavailable'}</div>
                          <div>Trace: {result.tracePath || 'Unavailable'}</div>
                          <div>Redirects: {result.redirectChain.join(' -> ') || 'None observed'}</div>
                          <div>Scripts: {result.scriptUrls.join(', ') || 'None observed'}</div>
                          <div className="flex flex-wrap items-center gap-2"><span>URLhaus:</span><SignalBadge tone={toneFromScannerStatus(result.externalScans.urlhaus.status)} blink={result.externalScans.urlhaus.status === 'listed'}>{result.externalScans.urlhaus.status}</SignalBadge></div>
                          <div className="flex flex-wrap items-center gap-2"><span>VirusTotal:</span><SignalBadge tone={toneFromScannerStatus(result.externalScans.virustotal.status)} blink={result.externalScans.virustotal.status === 'malicious'}>{result.externalScans.virustotal.status}</SignalBadge></div>
                          <div className="flex flex-wrap items-center gap-2"><span>URLScan:</span><SignalBadge tone={toneFromScannerStatus(result.externalScans.urlscan.status)} blink={result.externalScans.urlscan.status === 'submitted'}>{result.externalScans.urlscan.status}</SignalBadge></div>
                          <div className="flex flex-wrap items-center gap-2"><span>AlienVault OTX:</span><SignalBadge tone={toneFromScannerStatus(result.externalScans.alienVault.status)} blink={result.externalScans.alienVault.status === 'listed'}>{result.externalScans.alienVault.status}</SignalBadge></div>
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
                      {entry.analysis ? (
                        <div className="flex items-center gap-2">
                          <SignalBadge tone={toneFromRiskLevel(entry.analysis.riskLevel)} blink={entry.analysis.riskLevel !== 'LOW'}>{entry.analysis.riskLevel}</SignalBadge>
                          <SignalText tone={toneFromRiskScore(entry.analysis.score)} blink={entry.analysis.score >= 25}>{entry.analysis.score}</SignalText>
                        </div>
                      ) : (
                        <SignalBadge tone="neutral">manual scan</SignalBadge>
                      )}
                    </div>
                    <p className="mt-2 opacity-90">{entry.analysis?.summary ?? 'Threat scans are now manual per related domain to avoid unnecessary free-tier provider consumption.'}</p>
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

function RemoteFileJobCard({ job }: { job: FileAnalysisJob }) {
  const result = job.results[0];

  return (
    <div className="border border-cyber-red-dim bg-black/40 p-3 text-xs space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <SignalBadge tone={toneFromScannerStatus(job.status)}>{job.status}</SignalBadge>
        <div className="opacity-70">Job {job.jobId}</div>
      </div>
      {result ? (
        <>
          <div className="font-bold break-all">{result.filename}</div>
          <div className="flex flex-wrap gap-2">
            <SignalBadge tone={toneFromFileVerdict(result.verdict)}>{result.verdict}</SignalBadge>
            <SignalBadge tone={toneFromRiskScore(result.riskScore)}>{result.riskScore}</SignalBadge>
          </div>
          <div className="opacity-85">{result.summary}</div>
        </>
      ) : null}
    </div>
  );
}

function toneFromFileVerdict(verdict: FileAnalysisJob['results'][number]['verdict']) {
  return verdict === 'malicious' || verdict === 'suspicious' ? 'warning' : 'safe';
}

function looksLikeDownloadableFileUrl(url: string) {
  try {
    const parsedUrl = new URL(url);
    return /\.(pdf|doc|docx|xls|xlsx|ppt|pptx|zip|7z|rar|eml|msg|rtf|csv|txt)$/i.test(parsedUrl.pathname);
  } catch {
    return false;
  }
}

function AuthenticationDetailCard({
  label,
  status,
  detail,
  AuthIcon,
}: {
  label: string;
  status: string | null | undefined;
  detail: EmailAuthenticationDetail | undefined;
  AuthIcon: ({ status }: { status: string | null | undefined }) => React.JSX.Element;
}) {
  const detailRows = [
    detail?.reason ? `Reason: ${detail.reason}` : null,
    detail?.smtpMailFrom ? `Envelope sender: ${detail.smtpMailFrom}` : null,
    detail?.headerFrom ? `Header from: ${detail.headerFrom}` : null,
    detail?.headerDomain ? `Header domain: ${detail.headerDomain}` : null,
    detail?.selector ? `Selector: ${detail.selector}` : null,
    detail?.action ? `Policy action: ${detail.action}` : null,
  ].filter((value): value is string => Boolean(value));

  return (
    <div className="p-2 bg-black/50 border border-cyber-red-dim space-y-2">
      <div className="flex justify-between items-center gap-3">
        <span>{label}</span>
        <span className="uppercase font-bold flex items-center">
          {status || 'UNKNOWN'}
          <AuthIcon status={status} />
        </span>
      </div>
      {detailRows.length > 0 ? (
        <div className="space-y-1 text-xs opacity-80">
          {detailRows.map((row) => (
            <div key={row}>{row}</div>
          ))}
        </div>
      ) : null}
    </div>
  );
}
