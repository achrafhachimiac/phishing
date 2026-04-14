import React, { useMemo, useState } from 'react';
import { AlertOctagon, Cpu, FileWarning, Inbox, Mail, Paperclip, ShieldCheck, Upload } from 'lucide-react';

import type { CortexAnalyzerResult, DomainAnalysisResponse, EmailAuthenticationDetail, EmlAnalysisJob, FileAnalysisJob, FileIocProviderResult, FileStaticAnalysisResult } from '../../shared/analysis-types';
import { caseFileReference, caseJobReference, caseUrlReference } from '../case-event-references';
import { useCaseContext } from '../case-context';
import { SignalBadge, SignalPanel, toneFromFileVerdict, toneFromRiskLevel, toneFromRiskScore, toneFromScannerStatus } from './signal-display';

const EML_POLL_INTERVAL_MS = import.meta.env.MODE === 'test' ? 1 : 1000;
const EML_MAX_POLL_ATTEMPTS = 120;

export function ThePhish({
  onRouteToDomainAnalysis,
  onRouteToBrowserSandbox,
}: {
  onRouteToDomainAnalysis?: (domain: string) => void;
  onRouteToBrowserSandbox?: (url: string) => void;
}) {
  const { addCaseEvent } = useCaseContext();
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [job, setJob] = useState<EmlAnalysisJob | null>(null);
  const [remoteFileJobs, setRemoteFileJobs] = useState<Record<string, FileAnalysisJob>>({});
  const [remoteFileErrors, setRemoteFileErrors] = useState<Record<string, string>>({});
  const [remoteFileLoadingUrl, setRemoteFileLoadingUrl] = useState<string | null>(null);
  const [relatedDomainScans, setRelatedDomainScans] = useState<Record<string, { status: 'loading' | 'completed' | 'failed'; analysis?: DomainAnalysisResponse; error?: string }>>({});
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [isDragActive, setIsDragActive] = useState(false);
  const [error, setError] = useState('');

  const ignoredAttachmentSummary = useMemo(() => {
    if (!job || job.ignoredAttachments.length === 0) {
      return [];
    }

    const counts = new Map<string, number>();
    job.ignoredAttachments.forEach((attachment) => {
      const label = formatIgnoredAttachmentReason(attachment.reason);
      counts.set(label, (counts.get(label) ?? 0) + 1);
    });

    return [...counts.entries()].map(([label, count]) => ({ label, count }));
  }, [job]);

  const handleAnalyze = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!selectedFile) {
      return;
    }

    setIsAnalyzing(true);
    setError('');
    setJob(null);
    setRemoteFileJobs({});
    setRemoteFileErrors({});
    setRemoteFileLoadingUrl(null);
    setRelatedDomainScans({});
    addCaseEvent({
      tool: 'thephish',
      severity: 'info',
      title: 'THEPHISH intake started',
      detail: `${selectedFile.name} (${selectedFile.size} bytes)`,
      references: [caseFileReference(selectedFile.name)],
    });

    try {
      setSelectedFile(validateEmlFile(selectedFile));
      const rawEmail = await selectedFile.text();
      const createResponse = await fetch('/api/analyze/eml', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          filename: selectedFile.name,
          rawEmail,
        }),
      });
      const createdJob = (await createResponse.json()) as EmlAnalysisJob | { message?: string };

      if (!createResponse.ok || !('jobId' in createdJob)) {
        throw new Error(('message' in createdJob && createdJob.message) || 'EML analysis failed to start.');
      }

      setJob(createdJob);
      const completedJob = await pollEmlJob(createdJob.jobId);
      setJob(completedJob);
      addCaseEvent({
        tool: 'thephish',
        severity: completedJob.consolidatedThreatLevel && completedJob.consolidatedThreatLevel !== 'LOW' ? 'warning' : 'success',
        title: 'THEPHISH intake completed',
        detail: `${completedJob.filename} -> ${completedJob.consolidatedThreatLevel || completedJob.status}, ${completedJob.attachmentResults.length} attachment result(s)`,
        references: [
          caseFileReference(completedJob.filename),
          caseJobReference('eml-analysis', completedJob.jobId),
          ...(completedJob.fileAnalysisJobId ? [caseJobReference('file-analysis', completedJob.fileAnalysisJobId)] : []),
        ],
      });
    } catch (analysisError) {
      const message = analysisError instanceof Error ? analysisError.message : 'EML analysis failed.';
      setError(message);
      addCaseEvent({
        tool: 'thephish',
        severity: 'danger',
        title: 'THEPHISH intake failed',
        detail: message,
      });
    } finally {
      setIsAnalyzing(false);
    }
  };

  const pollEmlJob = async (jobId: string) => {
    for (let attempt = 0; attempt < EML_MAX_POLL_ATTEMPTS; attempt += 1) {
      const response = await fetch(`/api/analyze/eml/${jobId}`, {
        method: 'GET',
      });
      const payload = (await response.json()) as EmlAnalysisJob | { message?: string };

      if (!response.ok || !('jobId' in payload)) {
        throw new Error(('message' in payload && payload.message) || 'EML analysis polling failed.');
      }

      setJob(payload);
      if (payload.status === 'completed' || payload.status === 'failed') {
        return payload;
      }

      await new Promise((resolve) => {
        setTimeout(resolve, EML_POLL_INTERVAL_MS);
      });
    }

    throw new Error('EML analysis polling timed out.');
  };

  const handleFileSelection = (file: File | null) => {
    try {
      const validatedFile = validateEmlFile(file);
      setSelectedFile(validatedFile);
      setError('');
      if (validatedFile) {
        addCaseEvent({
          tool: 'thephish',
          severity: 'info',
          title: 'EML evidence selected',
          detail: `${validatedFile.name} (${validatedFile.size} bytes)`,
          references: [caseFileReference(validatedFile.name)],
        });
      }
    } catch (validationError) {
      setSelectedFile(null);
      const message = validationError instanceof Error ? validationError.message : 'Invalid EML file.';
      setError(message);
      addCaseEvent({
        tool: 'thephish',
        severity: 'danger',
        title: 'Invalid EML evidence',
        detail: message,
      });
    }
  };

  const handleDrop = (event: React.DragEvent<HTMLLabelElement>) => {
    event.preventDefault();
    setIsDragActive(false);
    handleFileSelection(event.dataTransfer.files?.[0] ?? null);
  };

  const handleAnalyzeRemoteFile = async (url: string) => {
    setRemoteFileLoadingUrl(url);
    setRemoteFileErrors((current) => ({ ...current, [url]: '' }));
    addCaseEvent({
      tool: 'thephish',
      severity: 'info',
      title: 'Remote file queued from THEPHISH',
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
        throw new Error(('message' in createdJob && createdJob.message) || 'Remote file analysis failed to start.');
      }

      setRemoteFileJobs((current) => ({ ...current, [url]: createdJob }));
      const completedJob = await pollRemoteFileJob(createdJob.jobId, url);
      setRemoteFileJobs((current) => ({ ...current, [url]: completedJob }));
      addCaseEvent({
        tool: 'thephish',
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
        tool: 'thephish',
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
    for (let attempt = 0; attempt < EML_MAX_POLL_ATTEMPTS; attempt += 1) {
      const response = await fetch(`/api/analyze/files/${jobId}`, {
        method: 'GET',
      });
      const payload = (await response.json()) as FileAnalysisJob | { message?: string };

      if (!response.ok || !('jobId' in payload)) {
        throw new Error(('message' in payload && payload.message) || 'Remote file analysis polling failed.');
      }

      setRemoteFileJobs((current) => ({ ...current, [url]: payload }));
      if (payload.status === 'completed' || payload.status === 'failed') {
        return payload;
      }

      await new Promise((resolve) => {
        setTimeout(resolve, EML_POLL_INTERVAL_MS);
      });
    }

    throw new Error('Remote file analysis polling timed out.');
  };

  const handleAnalyzeRelatedDomain = async (domain: string) => {
    setRelatedDomainScans((current) => ({
      ...current,
      [domain]: { status: 'loading' },
    }));
    addCaseEvent({
      tool: 'thephish',
      severity: 'info',
      title: 'Related domain threat scan started',
      detail: domain,
    });

    try {
      const response = await fetch('/api/analyze/domain', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ domain }),
      });
      const payload = (await response.json()) as DomainAnalysisResponse | { message?: string };

      if (!response.ok || !('domain' in payload)) {
        throw new Error(('message' in payload && payload.message) || 'Related domain threat scan failed.');
      }

      setRelatedDomainScans((current) => ({
        ...current,
        [domain]: {
          status: 'completed',
          analysis: payload,
        },
      }));
      addCaseEvent({
        tool: 'thephish',
        severity: payload.riskLevel === 'LOW' ? 'success' : 'warning',
        title: 'Related domain threat scan completed',
        detail: `${payload.normalizedDomain} scored ${payload.score}/100 (${payload.riskLevel})`,
      });
    } catch (scanError) {
      const message = scanError instanceof Error ? scanError.message : 'Related domain threat scan failed.';
      setRelatedDomainScans((current) => ({
        ...current,
        [domain]: {
          status: 'failed',
          error: message,
        },
      }));
      addCaseEvent({
        tool: 'thephish',
        severity: 'danger',
        title: 'Related domain threat scan failed',
        detail: `${domain}: ${message}`,
      });
    }
  };

  return (
    <div className="space-y-6">
      <div className="cli-border p-4">
        <h2 className="text-xl mb-4 flex items-center uppercase tracking-wider">
          <Mail className="mr-2" /> THEPHISH EML Intake
        </h2>
        <form onSubmit={handleAnalyze} className="space-y-4">
          <div>
            <label htmlFor="thephish-eml-upload" className="block text-sm mb-2 uppercase tracking-wide">
              Upload .eml evidence
            </label>
            <label
              htmlFor="thephish-eml-upload"
              data-testid="thephish-dropzone"
              onDragOver={(event) => {
                event.preventDefault();
                setIsDragActive(true);
              }}
              onDragEnter={(event) => {
                event.preventDefault();
                setIsDragActive(true);
              }}
              onDragLeave={(event) => {
                event.preventDefault();
                if (!event.currentTarget.contains(event.relatedTarget as Node | null)) {
                  setIsDragActive(false);
                }
              }}
              onDrop={handleDrop}
              className={`block border p-4 transition-colors cursor-pointer ${isDragActive ? 'border-cyber-red bg-cyber-red-dim/20' : 'border-cyber-red-dim bg-black/40'}`}
            >
              <div className="flex items-center gap-3 text-sm uppercase tracking-wide">
                {isDragActive ? <Inbox size={18} /> : <Upload size={18} />}
                <span>{isDragActive ? 'Drop .eml file to analyze' : 'Drag and drop a .eml file or click to browse'}</span>
              </div>
              <div className="mt-2 text-xs opacity-70">
                Supported intake: RFC822 `.eml` evidence only for this workflow.
              </div>
              {selectedFile ? (
                <div className="mt-3 border border-cyber-red-dim p-3 text-xs bg-black/50">
                  Selected evidence: <span className="font-bold">{selectedFile.name}</span> ({selectedFile.size} bytes)
                </div>
              ) : null}
            </label>
            <input
              id="thephish-eml-upload"
              type="file"
              accept=".eml,message/rfc822"
              onChange={(event) => {
                handleFileSelection(event.target.files?.[0] ?? null);
              }}
              className="sr-only"
            />
          </div>
          <button type="submit" disabled={isAnalyzing || !selectedFile} className="cli-button w-full py-3 flex items-center justify-center">
            {isAnalyzing ? (
              <span className="animate-pulse flex items-center"><Cpu size={16} className="mr-2 animate-spin" /> ANALYZING EML WORKFLOW...</span>
            ) : (
              <>ANALYZE EML</>
            )}
          </button>
        </form>
        {error ? <div className="mt-4 text-red-500 text-sm border border-red-500 p-2 bg-red-500/10">[!] ERROR: {error}</div> : null}
      </div>

      {job ? (
        <div className="space-y-6 animate-in fade-in duration-500">
          <div className="cli-border p-4 bg-cyber-red-dim/10">
            <div className="flex flex-col md:flex-row md:items-start md:justify-between gap-3">
              <div>
                <h3 className="text-2xl uppercase font-bold flex items-center">
                  <AlertOctagon className="mr-2" /> Consolidated Verdict
                </h3>
                <p className="text-sm opacity-80 mt-2">{job.executiveSummary || 'EML workflow running.'}</p>
              </div>
              <div className="text-right space-y-2">
                <div className="text-xs opacity-70 uppercase">Job Status</div>
                <SignalBadge tone={toneFromScannerStatus(job.status)}>{job.status} [{job.jobId}]</SignalBadge>
                {job.consolidatedThreatLevel ? (
                  <div>
                    <div className="text-xs opacity-70 uppercase mt-2">Threat Level</div>
                    <SignalBadge tone={toneFromRiskLevel(job.consolidatedThreatLevel)}>{job.consolidatedThreatLevel}</SignalBadge>
                  </div>
                ) : null}
              </div>
            </div>
            {job.consolidatedRiskScore !== null ? (
              <div className="mt-4 text-sm">Consolidated risk score: <SignalBadge tone={toneFromRiskScore(job.consolidatedRiskScore)}>{job.consolidatedRiskScore}</SignalBadge></div>
            ) : null}
          </div>

          {job.emailAnalysis ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="cli-border p-4">
                <h4 className="text-lg border-b border-cyber-red-dim pb-2 uppercase mb-4">Email Summary</h4>
                <div className="space-y-2 text-sm">
                  <div className="grid grid-cols-3 gap-2 border-b border-cyber-red-dim/30 pb-1">
                    <span className="opacity-70">Subject:</span>
                    <span className="col-span-2 break-all">{job.emailAnalysis.headers.subject || 'N/A'}</span>
                  </div>
                  <div className="grid grid-cols-3 gap-2 border-b border-cyber-red-dim/30 pb-1">
                    <span className="opacity-70">From:</span>
                    <span className="col-span-2 break-all">{job.emailAnalysis.headers.from || 'N/A'}</span>
                  </div>
                  <div className="grid grid-cols-3 gap-2 border-b border-cyber-red-dim/30 pb-1">
                    <span className="opacity-70">Return-Path:</span>
                    <span className="col-span-2 break-all">{job.emailAnalysis.headers.returnPath || 'N/A'}</span>
                  </div>
                  <div className="grid grid-cols-3 gap-2 border-b border-cyber-red-dim/30 pb-1">
                    <span className="opacity-70">Threat:</span>
                    <span className="col-span-2"><SignalBadge tone={toneFromRiskLevel(job.emailAnalysis.threatLevel)}>{job.emailAnalysis.threatLevel}</SignalBadge></span>
                  </div>
                  <div className="pt-2">
                    <div className="uppercase text-xs opacity-70 mb-2 flex items-center gap-2">
                      <ShieldCheck size={14} /> Authentication
                    </div>
                    <div className="space-y-2">
                      <CompactAuthenticationDetail label="SPF" status={job.emailAnalysis.authentication.spf} detail={job.emailAnalysis.authentication.spfDetails} />
                      <CompactAuthenticationDetail label="DKIM" status={job.emailAnalysis.authentication.dkim} detail={job.emailAnalysis.authentication.dkimDetails} />
                      <CompactAuthenticationDetail label="DMARC" status={job.emailAnalysis.authentication.dmarc} detail={job.emailAnalysis.authentication.dmarcDetails} />
                    </div>
                  </div>
                </div>
              </div>

              <div className="cli-border p-4">
                <h4 className="text-lg border-b border-cyber-red-dim pb-2 uppercase mb-4">Attachment Intake</h4>
                <div className="text-sm space-y-3">
                  <div>Total attachments detected: {job.attachmentCount}</div>
                  <div>Attachments analyzed: {job.analyzedAttachmentCount}</div>
                  {job.fileAnalysisJobId ? <div>File analysis job: {job.fileAnalysisJobId}</div> : null}
                  {job.ignoredAttachments.length > 0 ? (
                    <div>
                      <div className="uppercase text-xs opacity-70 mb-2">Ignored attachments</div>
                      <div className="flex flex-wrap gap-2 mb-3">
                        {ignoredAttachmentSummary.map((entry) => (
                          <div key={entry.label}>
                            <SignalBadge tone="neutral">{entry.count}x {entry.label}</SignalBadge>
                          </div>
                        ))}
                      </div>
                      <div className="space-y-2">
                        {job.ignoredAttachments.map((attachment, index) => (
                          <div key={`${attachment.filename || 'attachment'}-${index}`}>
                            <SignalPanel tone="neutral" className="p-3 text-xs space-y-2">
                              <div className="flex items-start justify-between gap-3">
                                <div className="font-bold break-all flex items-center gap-2">
                                  <FileWarning size={14} />
                                  <span>{attachment.filename || 'Unnamed attachment'}</span>
                                </div>
                                <SignalBadge tone="neutral">{formatIgnoredAttachmentReason(attachment.reason)}</SignalBadge>
                              </div>
                              <div className="grid grid-cols-1 md:grid-cols-2 gap-2 opacity-80">
                                <div>Type: {attachment.contentType}</div>
                                <div>Size: {attachment.size} bytes</div>
                              </div>
                            </SignalPanel>
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : null}
                </div>
              </div>
            </div>
          ) : null}

          {job.emailAnalysis ? (
            <div className="cli-border p-4">
              <h4 className="text-lg border-b border-cyber-red-dim pb-2 uppercase mb-4">Observable Inventory</h4>
              <div className="grid grid-cols-1 xl:grid-cols-2 gap-4 text-sm">
                <ParsedUrlList
                  urls={job.emailAnalysis.urls}
                  remoteFileJobs={remoteFileJobs}
                  remoteFileErrors={remoteFileErrors}
                  remoteFileLoadingUrl={remoteFileLoadingUrl}
                  onAnalyzeRemoteFile={handleAnalyzeRemoteFile}
                  onRouteToDomainAnalysis={onRouteToDomainAnalysis}
                  onRouteToBrowserSandbox={onRouteToBrowserSandbox}
                />
                <PanelList title="Email Addresses" values={job.emailAnalysis.emailAddresses} emptyMessage="No email addresses extracted." />
                <PanelList title="Domains" values={job.emailAnalysis.domains} emptyMessage="No domains extracted." />
                <PanelList title="IP Addresses" values={job.emailAnalysis.ipAddresses} emptyMessage="No IP addresses extracted." />
                <PanelList title="Header Inconsistencies" values={job.emailAnalysis.inconsistencies} emptyMessage="No header inconsistencies detected." tone="warning" />
                <RelatedDomainList domains={job.emailAnalysis.relatedDomains} scans={relatedDomainScans} onAnalyzeDomain={handleAnalyzeRelatedDomain} />
              </div>
            </div>
          ) : null}

          {job.externalEnrichment ? (
            <div className="cli-border p-4">
              <div className="flex flex-col md:flex-row md:items-start md:justify-between gap-3 mb-4">
                <div>
                  <h4 className="text-lg border-b border-cyber-red-dim pb-2 uppercase">External Analyzer Results</h4>
                  <p className="text-sm opacity-80 mt-2">{job.externalEnrichment.summary}</p>
                </div>
                <div>
                  <div className="text-xs opacity-70 uppercase">External Status</div>
                  <SignalBadge tone={toneFromScannerStatus(job.externalEnrichment.status)}>{job.externalEnrichment.status}</SignalBadge>
                </div>
              </div>
              <ExternalAnalyzerOverview enrichment={job.externalEnrichment} />
              {job.externalEnrichment.updatedAt ? (
                <div className="text-xs opacity-60 mb-4">Last updated: {job.externalEnrichment.updatedAt}</div>
              ) : null}
              <div className="grid grid-cols-1 xl:grid-cols-3 gap-4 text-sm">
                <div>
                  <div className="uppercase text-xs opacity-70 mb-2">Email analyzers</div>
                  <ExternalAnalyzerList results={job.externalEnrichment.email} emptyMessage="No external email analyzer results." />
                </div>
                <div>
                  <div className="uppercase text-xs opacity-70 mb-2">Observable analyzers</div>
                  <ExternalAnalyzerList results={job.externalEnrichment.observables} emptyMessage="No external observable analyzer results." />
                </div>
                <div>
                  <div className="uppercase text-xs opacity-70 mb-2">Attachment analyzers</div>
                  <ExternalAnalyzerList results={job.externalEnrichment.attachments} emptyMessage="No external attachment analyzer results." />
                </div>
              </div>
            </div>
          ) : null}

          <div className="cli-border p-4">
            <h4 className="text-lg border-b border-cyber-red-dim pb-2 uppercase mb-4 flex items-center">
              <Paperclip className="mr-2" size={18} /> Attachment Analysis
            </h4>
            {job.attachmentResults.length > 0 ? (
              <div className="space-y-4">
                {job.attachmentResults.map((result) => (
                  <div key={`${result.filename}-${result.sha256}`}>
                    <SignalPanel tone={toneFromFileVerdict(result.verdict)} className="p-4">
                      <div className="flex flex-col md:flex-row md:justify-between gap-2 mb-3">
                        <div>
                          <div className="font-bold break-all">{result.filename}</div>
                          <div className="text-xs opacity-70 uppercase">{result.detectedType} :: {result.contentType || 'unknown'}</div>
                        </div>
                        <div className="flex flex-wrap items-center gap-2">
                          <SignalBadge tone={toneFromFileVerdict(result.verdict)}>{result.verdict}</SignalBadge>
                          <SignalBadge tone={toneFromRiskScore(result.riskScore)}>{result.riskScore}</SignalBadge>
                        </div>
                      </div>
                      <p className="text-sm opacity-90 mb-3">{result.summary}</p>
                      {result.indicators.length > 0 ? (
                        <div className="space-y-1 text-xs">
                          {result.indicators.map((indicator, index) => (
                            <div key={`${indicator.kind}-${index}`}>{indicator.kind}: {indicator.value}</div>
                          ))}
                        </div>
                      ) : null}
                      <AttachmentExternalScans result={result} />
                      <AttachmentIocEnrichment result={result} />
                    </SignalPanel>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm opacity-70">No attachments have completed analysis yet.</p>
            )}
          </div>
        </div>
      ) : null}
    </div>
  );
}

function validateEmlFile(file: File | null) {
  if (!file) {
    throw new Error('An .eml evidence file is required.');
  }

  const normalizedName = file.name.toLowerCase();
  const normalizedType = file.type.toLowerCase();
  const isAcceptedType = normalizedName.endsWith('.eml') || normalizedType === 'message/rfc822';

  if (!isAcceptedType) {
    throw new Error('Only .eml evidence files are supported in THEPHISH.');
  }

  return file;
}

function formatIgnoredAttachmentReason(reason: EmlAnalysisJob['ignoredAttachments'][number]['reason']) {
  switch (reason) {
    case 'empty_attachment':
      return 'empty attachment';
    case 'duplicate_attachment':
      return 'duplicate';
    case 'attachment_too_large':
      return 'too large';
    case 'attachment_limit_exceeded':
      return 'count limit';
    case 'total_attachment_size_exceeded':
      return 'total size limit';
    default:
      return reason;
  }
}

function ExternalAnalyzerList({
  results,
  emptyMessage,
}: {
  results: NonNullable<EmlAnalysisJob['externalEnrichment']>['email'];
  emptyMessage: string;
}) {
  if (results.length === 0) {
    return <p className="opacity-70 text-xs">{emptyMessage}</p>;
  }

  return (
    <div className="space-y-3">
      {results.map((result) => (
        <div key={`${result.analyzerId}-${result.target}`}>
          <SignalPanel tone={toneFromExternalVerdict(result.verdict)} className="p-3 space-y-2">
            <div className="flex items-start justify-between gap-2">
              <div>
                <div className="font-bold break-all">{result.analyzerName}</div>
                <div className="text-xs opacity-70 break-all">{result.target}</div>
              </div>
              <div className="flex flex-wrap gap-2 justify-end">
                <SignalBadge tone="neutral">{result.targetType}</SignalBadge>
                <SignalBadge tone={toneFromScannerStatus(result.status)}>{result.status}</SignalBadge>
                <SignalBadge tone={toneFromExternalVerdict(result.verdict)}>{result.verdict}</SignalBadge>
              </div>
            </div>
            <div className="text-xs opacity-90">{result.summary}</div>
            {result.confidence !== null ? <div className="text-[11px] opacity-80">Confidence: {result.confidence}%</div> : null}
            {result.taxonomies.length > 0 ? (
              <div className="space-y-1">
                <div className="text-[11px] uppercase opacity-70">Taxonomies</div>
                <div className="flex flex-wrap gap-2">
                  {result.taxonomies.map((taxonomy, index) => (
                    <div key={`${taxonomy.namespace}-${taxonomy.predicate}-${taxonomy.value}-${index}`}>
                      <SignalBadge tone={toneFromExternalTaxonomy(taxonomy.level)}>
                        {formatTaxonomy(taxonomy)}
                      </SignalBadge>
                    </div>
                  ))}
                </div>
              </div>
            ) : null}
            {result.artifacts.length > 0 ? (
              <div className="space-y-1">
                <div className="text-[11px] uppercase opacity-70">Artifacts</div>
                <div className="space-y-1 text-[11px] opacity-80">
                  {result.artifacts.map((artifact, index) => (
                    <div key={`${artifact.dataType}-${artifact.data}-${index}`} className="break-all">
                      {artifact.dataType}: {artifact.data}
                      {artifact.message ? ` :: ${artifact.message}` : ''}
                    </div>
                  ))}
                </div>
              </div>
            ) : null}
            {result.reference ? <div className="text-[11px] opacity-60 break-all">Ref: {result.reference}</div> : null}
          </SignalPanel>
        </div>
      ))}
    </div>
  );
}

function PanelList({
  title,
  values,
  emptyMessage,
  tone = 'neutral',
}: {
  title: string;
  values: string[];
  emptyMessage: string;
  tone?: 'safe' | 'warning' | 'neutral';
}) {
  return (
    <div>
      <div className="uppercase text-xs opacity-70 mb-2">{title}</div>
      {values.length === 0 ? (
        <p className="text-xs opacity-70">{emptyMessage}</p>
      ) : (
        <div className="flex flex-wrap gap-2">
          {values.map((value) => (
            <div key={value}>
              <SignalBadge tone={tone} className="break-all max-w-full">
                {value}
              </SignalBadge>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function ParsedUrlList({
  urls,
  remoteFileJobs,
  remoteFileErrors,
  remoteFileLoadingUrl,
  onAnalyzeRemoteFile,
  onRouteToDomainAnalysis,
  onRouteToBrowserSandbox,
}: {
  urls: NonNullable<EmlAnalysisJob['emailAnalysis']>['urls'];
  remoteFileJobs: Record<string, FileAnalysisJob>;
  remoteFileErrors: Record<string, string>;
  remoteFileLoadingUrl: string | null;
  onAnalyzeRemoteFile: (url: string) => Promise<void>;
  onRouteToDomainAnalysis?: (domain: string) => void;
  onRouteToBrowserSandbox?: (url: string) => void;
}) {
  return (
    <div>
      <div className="uppercase text-xs opacity-70 mb-2">Parsed URLs</div>
      {urls.length === 0 ? (
        <p className="text-xs opacity-70">No URLs extracted from the message.</p>
      ) : (
        <div className="space-y-2">
          {urls.map((url) => (
            <div key={`${url.originalUrl}-${url.decodedUrl}`}>
              {(() => {
                const handoffDomain = extractDomainFromUrl(url.decodedUrl);
                const showHandoffButtons = url.wrapperType === 'barracuda';

                return (
              <SignalPanel tone={url.suspicious ? 'warning' : 'neutral'} className="p-3 text-xs space-y-2">
                <div className="flex flex-wrap gap-2">
                  <SignalBadge tone={url.suspicious ? 'warning' : 'safe'}>{url.suspicious ? 'suspicious' : 'clean'}</SignalBadge>
                  {url.wrapperType ? <SignalBadge tone={url.wrapperType === 'barracuda' ? 'warning' : 'neutral'}>{url.wrapperType}</SignalBadge> : null}
                </div>
                <div className="break-all">Original: {url.originalUrl}</div>
                <div className="break-all">Destination: {url.decodedUrl}</div>
                {showHandoffButtons ? (
                  <div className="flex flex-wrap gap-2">
                    <button
                      type="button"
                      disabled={!handoffDomain}
                      onClick={() => {
                        if (handoffDomain) {
                          onRouteToDomainAnalysis?.(handoffDomain);
                        }
                      }}
                      className="cli-button py-2 px-3 text-xs"
                    >
                      SEND TO DOMAIN ANALYSIS
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        onRouteToBrowserSandbox?.(url.decodedUrl);
                      }}
                      className="cli-button py-2 px-3 text-xs"
                    >
                      SEND TO URL SANDBOX
                    </button>
                  </div>
                ) : null}
                {url.resolutionChain && url.resolutionChain.length > 0 ? (
                  <div className="space-y-1 opacity-80">
                    {url.resolutionChain.map((step) => (
                      <div key={`${step.label}-${step.url}`} className="break-all">{step.label}: {step.url}</div>
                    ))}
                  </div>
                ) : null}
                <div className="opacity-85">{url.reason}</div>
                {looksLikeDownloadableFileUrl(url.decodedUrl) ? (
                  <div className="space-y-2">
                    <button
                      type="button"
                      onClick={() => void onAnalyzeRemoteFile(url.decodedUrl)}
                      disabled={remoteFileLoadingUrl === url.decodedUrl}
                      className="cli-button py-2 px-3 text-xs"
                    >
                      {remoteFileLoadingUrl === url.decodedUrl ? 'ANALYZING REMOTE FILE...' : 'ANALYZE REMOTE FILE'}
                    </button>
                    {remoteFileErrors[url.decodedUrl] ? <div className="text-red-400">{remoteFileErrors[url.decodedUrl]}</div> : null}
                    {remoteFileJobs[url.decodedUrl] ? <RemoteFileJobCard job={remoteFileJobs[url.decodedUrl]} /> : null}
                  </div>
                ) : null}
              </SignalPanel>
                );
              })()}
            </div>
          ))}
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

function CompactAuthenticationDetail({
  label,
  status,
  detail,
}: {
  label: string;
  status: string | null | undefined;
  detail: EmailAuthenticationDetail | undefined;
}) {
  const extraDetail = detail?.reason
    ? detail.reason
    : detail?.action
      ? `action=${detail.action}`
      : detail?.headerDomain
        ? `domain=${detail.headerDomain}`
        : null;

  return (
    <div className="space-y-1">
      <div className="flex flex-wrap gap-2">
        <SignalBadge tone={toneFromScannerStatus(status)}>
          {label} {status || 'unknown'}
        </SignalBadge>
      </div>
      {extraDetail ? <div className="text-xs opacity-75">{extraDetail}</div> : null}
    </div>
  );
}

function looksLikeDownloadableFileUrl(url: string) {
  try {
    const parsedUrl = new URL(url);
    return /\.(pdf|doc|docx|xls|xlsx|ppt|pptx|zip|7z|rar|eml|msg|rtf|csv|txt)$/i.test(parsedUrl.pathname);
  } catch {
    return false;
  }
}

function extractDomainFromUrl(url: string) {
  try {
    return new URL(url).hostname || null;
  } catch {
    return null;
  }
}

function RelatedDomainList({
  domains,
  scans,
  onAnalyzeDomain,
}: {
  domains: NonNullable<EmlAnalysisJob['emailAnalysis']>['relatedDomains'];
  scans: Record<string, { status: 'loading' | 'completed' | 'failed'; analysis?: DomainAnalysisResponse; error?: string }>;
  onAnalyzeDomain: (domain: string) => Promise<void>;
}) {
  return (
    <div>
      <div className="uppercase text-xs opacity-70 mb-2">Related Domains</div>
      {domains.length === 0 ? (
        <p className="text-xs opacity-70">No related domains analyzed.</p>
      ) : (
        <div className="space-y-2">
          {domains.map((entry) => (
            <div key={`${entry.domain}-${entry.relation}`}>
              {(() => {
                const scanState = scans[entry.domain];
                const analysis = scanState?.analysis ?? entry.analysis ?? null;
                const tone = analysis ? toneFromRiskLevel(analysis.riskLevel) : scanState?.status === 'failed' ? 'warning' : 'neutral';

                return (
              <SignalPanel tone={tone} className="p-3 text-xs space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="font-bold break-all">{entry.domain}</div>
                  <div className="flex flex-wrap gap-2">
                    <SignalBadge tone="neutral">{entry.relation}</SignalBadge>
                    {scanState?.status === 'loading' ? <SignalBadge tone="warning" blink>RUNNING</SignalBadge> : null}
                    {analysis ? <SignalBadge tone={toneFromRiskLevel(analysis.riskLevel)} blink={analysis.riskLevel !== 'LOW'}>{analysis.riskLevel}</SignalBadge> : null}
                    {analysis ? <SignalBadge tone={toneFromRiskScore(analysis.score)} blink={analysis.score >= 100}>{analysis.score}</SignalBadge> : null}
                  </div>
                </div>
                {analysis ? (
                  <>
                    <div className="opacity-85">{analysis.summary}</div>
                    <div className="flex flex-wrap gap-2">
                      <SignalBadge tone={toneFromScannerStatus(analysis.reputation.urlhausHost.status)}>URLhaus {analysis.reputation.urlhausHost.status}</SignalBadge>
                      <SignalBadge tone={toneFromScannerStatus(analysis.reputation.alienVault.status)}>OTX {analysis.reputation.alienVault.status}</SignalBadge>
                      <SignalBadge tone={toneFromScannerStatus(analysis.reputation.virustotal.status)} blink={analysis.reputation.virustotal.status === 'malicious'}>VirusTotal {analysis.reputation.virustotal.status}</SignalBadge>
                      <SignalBadge tone={toneFromScannerStatus(analysis.reputation.urlscan.status)}>URLScan {analysis.reputation.urlscan.status}</SignalBadge>
                      <SignalBadge tone={toneFromScannerStatus(analysis.reputation.abuseIpDb.status)}>AbuseIPDB {analysis.reputation.abuseIpDb.status}</SignalBadge>
                      {analysis.reputation.cortex ? <SignalBadge tone={toneFromScannerStatus(analysis.reputation.cortex.status)}>Cortex {analysis.reputation.cortex.status}</SignalBadge> : null}
                    </div>
                    <div className="flex flex-wrap gap-2">
                      <a href={analysis.osint.virustotal} target="_blank" rel="noreferrer" className="cli-button py-2 px-3 text-[11px]">VirusTotal</a>
                      <a href={analysis.osint.urlscan} target="_blank" rel="noreferrer" className="cli-button py-2 px-3 text-[11px]">URLScan</a>
                      <a href={analysis.osint.alienVault} target="_blank" rel="noreferrer" className="cli-button py-2 px-3 text-[11px]">AlienVault OTX</a>
                      <a href={analysis.osint.urlhausHost} target="_blank" rel="noreferrer" className="cli-button py-2 px-3 text-[11px]">URLhaus Host</a>
                    </div>
                  </>
                ) : (
                  <div className="space-y-2">
                    <div className="opacity-80">Threat scans are manual here to avoid burning external free-tier quota on every related domain automatically.</div>
                    <button
                      type="button"
                      onClick={() => void onAnalyzeDomain(entry.domain)}
                      disabled={scanState?.status === 'loading'}
                      className="cli-button py-2 px-3 text-xs"
                    >
                      {scanState?.status === 'loading' ? 'RUNNING' : 'RUN THREAT SCANS'}
                    </button>
                    {scanState?.status === 'failed' && scanState.error ? <div className="text-red-400">{scanState.error}</div> : null}
                  </div>
                )}
              </SignalPanel>
                );
              })()}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function ExternalAnalyzerOverview({ enrichment }: { enrichment: NonNullable<EmlAnalysisJob['externalEnrichment']> }) {
  const allResults = [...enrichment.email, ...enrichment.observables, ...enrichment.attachments];
  const completed = allResults.filter((result) => result.status === 'completed').length;
  const malicious = allResults.filter((result) => result.verdict === 'malicious').length;
  const suspicious = allResults.filter((result) => result.verdict === 'suspicious').length;
  const unavailable = allResults.filter((result) => result.status === 'unavailable' || result.verdict === 'unavailable').length;

  return (
    <div className="flex flex-wrap gap-2 mb-4 text-xs">
      <SignalBadge tone="neutral">Analyzer runs: {allResults.length}</SignalBadge>
      <SignalBadge tone="safe">Completed: {completed}</SignalBadge>
      <SignalBadge tone={malicious > 0 ? 'warning' : 'neutral'}>Malicious hits: {malicious}</SignalBadge>
      <SignalBadge tone={suspicious > 0 ? 'warning' : 'neutral'}>Suspicious hits: {suspicious}</SignalBadge>
      <SignalBadge tone={unavailable > 0 ? 'warning' : 'neutral'}>Unavailable: {unavailable}</SignalBadge>
    </div>
  );
}

function AttachmentExternalScans({ result }: { result: FileStaticAnalysisResult }) {
  const hasCortex = Boolean(result.externalScans.cortex);

  return (
    <div className="mt-4 space-y-2 text-xs">
      <div className="uppercase opacity-70">External Scans</div>
      <div className="flex flex-wrap gap-2">
        <SignalBadge tone={toneFromScannerStatus(result.externalScans.virustotal.status)}>
          VirusTotal {result.externalScans.virustotal.status}
        </SignalBadge>
        {result.externalScans.virustotal.malicious !== null || result.externalScans.virustotal.suspicious !== null ? (
          <SignalBadge tone={toneFromScannerStatus(result.externalScans.virustotal.status)}>
            {result.externalScans.virustotal.malicious ?? 0} malicious / {result.externalScans.virustotal.suspicious ?? 0} suspicious
          </SignalBadge>
        ) : null}
        <SignalBadge tone={toneFromScannerStatus(result.externalScans.clamav.status)}>ClamAV {result.externalScans.clamav.status}</SignalBadge>
        <SignalBadge tone={toneFromScannerStatus(result.externalScans.yara.status)}>YARA {result.externalScans.yara.status}</SignalBadge>
        {hasCortex ? (
          <SignalBadge tone={toneFromScannerStatus(result.externalScans.cortex?.status)}>
            Cortex {result.externalScans.cortex?.status}
          </SignalBadge>
        ) : null}
      </div>
      {hasCortex ? <div className="opacity-80">{result.externalScans.cortex?.summary}</div> : null}
      {result.externalScans.clamav.signature ? <div className="opacity-80">ClamAV signature: {result.externalScans.clamav.signature}</div> : null}
      {result.externalScans.yara.rules.length > 0 ? <div className="opacity-80">YARA rules: {result.externalScans.yara.rules.join(', ')}</div> : null}
    </div>
  );
}

function AttachmentIocEnrichment({ result }: { result: FileStaticAnalysisResult }) {
  return (
    <div className="mt-4 space-y-2 text-xs">
      <div className="uppercase opacity-70">IOC Enrichment</div>
      <div className="flex flex-wrap gap-2">
        <SignalBadge tone={toneFromScannerStatus(result.iocEnrichment.status)}>{result.iocEnrichment.status}</SignalBadge>
        <SignalBadge tone="neutral">URLs: {result.iocEnrichment.extractedUrls.length}</SignalBadge>
        <SignalBadge tone="neutral">Domains: {result.iocEnrichment.extractedDomains.length}</SignalBadge>
        <SignalBadge tone="neutral">Hits: {result.iocEnrichment.results.length}</SignalBadge>
      </div>
      <div className="opacity-80">{result.iocEnrichment.summary}</div>
      {result.iocEnrichment.results.length > 0 ? (
        <div className="space-y-2">
          {result.iocEnrichment.results.map((ioc, index) => (
            <div key={`${ioc.type}-${ioc.value}-${index}`}>
              <SignalPanel tone={toneFromIocVerdict(ioc.verdict)} className="p-3 space-y-2">
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div className="font-bold break-all">{ioc.value}</div>
                  <div className="flex flex-wrap gap-2">
                    <SignalBadge tone="neutral">{ioc.type}</SignalBadge>
                    <SignalBadge tone={toneFromIocVerdict(ioc.verdict)}>{ioc.verdict}</SignalBadge>
                  </div>
                </div>
                <div className="opacity-85">{ioc.summary}</div>
                <div className="flex flex-wrap gap-2">
                  {ioc.providerResults.map((provider, providerIndex) => (
                    <div key={`${provider.provider}-${providerIndex}`}>
                      <SignalBadge tone={toneFromScannerStatus(provider.status)}>
                        {formatProviderName(provider.provider)} {provider.status}
                      </SignalBadge>
                    </div>
                  ))}
                </div>
              </SignalPanel>
            </div>
          ))}
        </div>
      ) : null}
    </div>
  );
}

function toneFromExternalTaxonomy(level: string | null) {
  const normalizedLevel = level?.toLowerCase();

  if (normalizedLevel === 'malicious' || normalizedLevel === 'high' || normalizedLevel === 'suspicious') {
    return 'warning';
  }

  if (normalizedLevel === 'safe' || normalizedLevel === 'info') {
    return 'safe';
  }

  return 'neutral';
}

function toneFromIocVerdict(verdict: FileStaticAnalysisResult['iocEnrichment']['results'][number]['verdict']) {
  switch (verdict) {
    case 'malicious':
    case 'suspicious':
      return 'warning';
    case 'clean':
      return 'safe';
    case 'unavailable':
    case 'pending':
    default:
      return 'neutral';
  }
}

function formatTaxonomy(taxonomy: CortexAnalyzerResult['taxonomies'][number]) {
  return [taxonomy.namespace, taxonomy.predicate, taxonomy.value].filter(Boolean).join(' / ');
}

function formatProviderName(provider: FileIocProviderResult['provider']) {
  switch (provider) {
    case 'abuseipdb':
      return 'AbuseIPDB';
    case 'alienvault':
      return 'AlienVault OTX';
    case 'cortex':
      return 'Cortex';
    case 'urlhaus':
      return 'URLhaus';
    case 'urlhaus_host':
      return 'URLhaus Host';
    case 'urlscan':
      return 'URLScan';
    case 'virustotal':
      return 'VirusTotal';
    default:
      return provider;
  }
}

function toneFromExternalVerdict(verdict: NonNullable<EmlAnalysisJob['externalEnrichment']>['email'][number]['verdict']) {
  switch (verdict) {
    case 'malicious':
    case 'suspicious':
      return 'warning';
    case 'clean':
      return 'safe';
    case 'informational':
    case 'pending':
    case 'unavailable':
    default:
      return 'neutral';
  }
}