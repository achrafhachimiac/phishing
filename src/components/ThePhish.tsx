import React, { useMemo, useState } from 'react';
import { AlertOctagon, Cpu, FileWarning, Inbox, Mail, Paperclip, Upload } from 'lucide-react';

import type { EmlAnalysisJob } from '../../shared/analysis-types';
import { SignalBadge, SignalPanel, toneFromFileVerdict, toneFromRiskLevel, toneFromRiskScore, toneFromScannerStatus } from './signal-display';

const EML_POLL_INTERVAL_MS = import.meta.env.MODE === 'test' ? 1 : 1000;
const EML_MAX_POLL_ATTEMPTS = 120;

export function ThePhish() {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [job, setJob] = useState<EmlAnalysisJob | null>(null);
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
    } catch (analysisError) {
      setError(analysisError instanceof Error ? analysisError.message : 'EML analysis failed.');
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
    } catch (validationError) {
      setSelectedFile(null);
      setError(validationError instanceof Error ? validationError.message : 'Invalid EML file.');
    }
  };

  const handleDrop = (event: React.DragEvent<HTMLLabelElement>) => {
    event.preventDefault();
    setIsDragActive(false);
    handleFileSelection(event.dataTransfer.files?.[0] ?? null);
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