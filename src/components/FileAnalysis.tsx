import React, { useState } from 'react';
import { Cpu, FileArchive, Upload } from 'lucide-react';

import type { FileAnalysisJob, FileUpload } from '../../shared/analysis-types';
import { formatSignalLabel } from './signal-format';
import {
  SignalBadge,
  SignalPanel,
  SignalText,
  isBlinkingSignal,
  toneFromFileVerdict,
  toneFromRiskScore,
  toneFromScannerStatus,
} from './signal-display';

const FILE_ANALYSIS_POLL_INTERVAL_MS = import.meta.env.MODE === 'test' ? 1 : 1000;
const FILE_ANALYSIS_MAX_POLL_DURATION_MS = import.meta.env.MODE === 'test' ? 50 : 120000;

export function FileAnalysis() {
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [analysisJob, setAnalysisJob] = useState<FileAnalysisJob | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [error, setError] = useState('');

  const handleAnalyzeFiles = async (event: React.FormEvent) => {
    event.preventDefault();
    if (selectedFiles.length === 0) {
      return;
    }

    setIsAnalyzing(true);
    setError('');
    setAnalysisJob(null);

    try {
      const filesPayload = await Promise.all(selectedFiles.map(fileToPayload));
      const createResponse = await fetch('/api/analyze/files', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ files: filesPayload }),
      });
      const createdJob = (await createResponse.json()) as FileAnalysisJob | { message?: string };

      if (!createResponse.ok || !('jobId' in createdJob)) {
        throw new Error(('message' in createdJob && createdJob.message) || 'File analysis launch failed.');
      }

      setAnalysisJob(createdJob);
      const completedJob = await pollFileAnalysisJob(createdJob.jobId);
      setAnalysisJob(completedJob);
    } catch (analysisError) {
      setError(analysisError instanceof Error ? analysisError.message : 'File analysis failed.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const pollFileAnalysisJob = async (jobId: string) => {
    const startedAt = Date.now();

    while (Date.now() - startedAt < FILE_ANALYSIS_MAX_POLL_DURATION_MS) {
      const jobResponse = await fetch(`/api/analyze/files/${jobId}`, {
        method: 'GET',
      });
      const jobPayload = (await jobResponse.json()) as FileAnalysisJob | { message?: string };
      if (!jobResponse.ok || !('jobId' in jobPayload)) {
        throw new Error(('message' in jobPayload && jobPayload.message) || 'File analysis polling failed.');
      }

      setAnalysisJob(jobPayload);
      if (jobPayload.status === 'completed' || jobPayload.status === 'failed') {
        return jobPayload;
      }

      await new Promise((resolve) => {
        setTimeout(resolve, FILE_ANALYSIS_POLL_INTERVAL_MS);
      });
    }

    throw new Error('File analysis polling timed out.');
  };

  return (
    <div className="space-y-6">
      <div className="cli-border p-4">
        <h2 className="text-xl mb-4 flex items-center uppercase tracking-wider">
          <FileArchive className="mr-2" /> Static File Analysis
        </h2>
        <form onSubmit={handleAnalyzeFiles} className="space-y-4">
          <label className="block text-sm uppercase tracking-wider">
            Upload files for static analysis
            <input
              type="file"
              multiple
              onChange={(event) => setSelectedFiles(Array.from(event.target.files ?? []))}
              className="cli-input w-full mt-3 p-3"
              aria-label="Upload files for static analysis"
            />
          </label>
          {selectedFiles.length ? (
            <div className="border border-cyber-red-dim bg-black/40 p-3 text-sm space-y-1">
              {selectedFiles.map((file) => (
                <div key={`${file.name}-${file.size}`} className="flex justify-between gap-4 break-all">
                  <span>{file.name}</span>
                  <span className="opacity-70">{file.size} bytes</span>
                </div>
              ))}
            </div>
          ) : null}
          <button type="submit" disabled={isAnalyzing || selectedFiles.length === 0} className="cli-button w-full py-3 flex items-center justify-center">
            {isAnalyzing ? (
              <span className="animate-pulse flex items-center"><Cpu size={16} className="mr-2 animate-spin" /> ANALYZING FILES...</span>
            ) : (
              <span className="flex items-center"><Upload size={16} className="mr-2" /> ANALYZE FILES</span>
            )}
          </button>
        </form>
        {error && <div className="mt-4 text-red-500 text-sm border border-red-500 p-2 bg-red-500/10">[!] ERROR: {error}</div>}
      </div>

      {analysisJob && (
        <div className="space-y-4 animate-in fade-in duration-500">
          <div className="cli-border p-4 bg-black/40 text-sm">
            <div className="flex flex-col md:flex-row md:justify-between gap-3">
              <div>
                <div className="text-xs opacity-70 uppercase">File Analysis Job</div>
                <div className="font-bold uppercase">{analysisJob.status} [{analysisJob.jobId}]</div>
              </div>
              <div className="text-right">
                <div className="text-xs opacity-70 uppercase">Queued Files</div>
                <div>{analysisJob.queuedFiles.join(', ') || 'None'}</div>
              </div>
            </div>
          </div>

          {analysisJob.results.length ? (
            <div className="space-y-4">
              {analysisJob.results.map((result) => {
                const clamav = result.externalScans.clamav ?? {
                  status: 'not_configured',
                  signature: null,
                  engine: null,
                  detail: null,
                };
                const yara = result.externalScans.yara ?? {
                  status: 'not_configured',
                  rules: [],
                  detail: null,
                };
                const parserReports = result.parserReports ?? [];
                const artifacts = result.artifacts ?? [];

                return (
                  <div key={`${result.filename}-${result.sha256}`} className="cli-border p-4">
                  <div className="flex flex-col md:flex-row md:justify-between md:items-start gap-3 mb-4">
                    <div>
                      <div className="text-lg font-bold break-all">{result.filename}</div>
                      <div className="text-xs opacity-70 uppercase">Detected type: {result.detectedType}</div>
                    </div>
                    <SignalBadge
                      tone={toneFromFileVerdict(result.verdict)}
                      blink={isBlinkingSignal(toneFromFileVerdict(result.verdict), result.verdict !== 'clean')}
                      className="text-sm md:text-base"
                    >
                      {result.verdict}
                    </SignalBadge>
                  </div>

                  <div className="grid grid-cols-1 xl:grid-cols-2 gap-6 text-sm">
                    <div className="space-y-2">
                      <div>Summary: {result.summary}</div>
                      <div>SHA256: {result.sha256}</div>
                      <div className="flex flex-wrap items-center gap-2">
                        <span>Risk Score:</span>
                        <SignalBadge
                          tone={toneFromRiskScore(result.riskScore)}
                          blink={isBlinkingSignal(toneFromRiskScore(result.riskScore), result.riskScore >= 25)}
                        >
                          {result.riskScore}
                        </SignalBadge>
                      </div>

                      <div className="flex flex-wrap items-center gap-2">
                        <span>VirusTotal:</span>
                        <SignalBadge tone={toneFromScannerStatus(result.externalScans.virustotal.status)}>
                          {result.externalScans.virustotal.status}
                        </SignalBadge>
                      </div>
                      <div className="flex flex-wrap items-center gap-2">
                        <span>ClamAV:</span>
                        <SignalBadge tone={toneFromScannerStatus(clamav.status)} blink={isBlinkingSignal(toneFromScannerStatus(clamav.status), clamav.status === 'malicious')}>
                          {clamav.status}
                        </SignalBadge>
                        {clamav.signature ? <SignalText tone="warning">({clamav.signature})</SignalText> : ''}
                      </div>
                      <div className="flex flex-wrap items-center gap-2">
                        <span>YARA:</span>
                        <SignalBadge tone={toneFromScannerStatus(yara.status)} blink={isBlinkingSignal(toneFromScannerStatus(yara.status), yara.status === 'match')}>
                          {yara.status}
                        </SignalBadge>
                        {yara.rules.length ? <SignalText tone="warning">({yara.rules.join(', ')})</SignalText> : ''}
                      </div>
                    </div>
                    <div className="space-y-3">
                      <div>
                        <div className="text-xs opacity-70 uppercase mb-2">Indicators</div>
                        {result.indicators.length ? result.indicators.map((indicator) => (
                          <div key={`${indicator.kind}-${indicator.value}`}>
                            <SignalPanel
                              tone={indicator.severity === 'low' ? 'neutral' : indicator.severity === 'medium' ? 'warning' : 'warning'}
                              blink={indicator.severity !== 'low'}
                              className="mb-2"
                            >
                              <div className="font-bold uppercase">{formatSignalLabel(indicator.kind)}</div>
                              <div>{indicator.value}</div>
                            </SignalPanel>
                          </div>
                        )) : <div className="opacity-70">No indicators found</div>}
                      </div>
                      <div>
                        <div className="text-xs opacity-70 uppercase mb-2">Extracted URLs</div>
                        {result.extractedUrls.length ? result.extractedUrls.map((url) => (
                          <div key={url} className="break-all">
                            <a href={url} target="_blank" rel="noreferrer" className="text-cyber-red underline">{url}</a>
                          </div>
                        )) : <div className="opacity-70">None extracted</div>}
                      </div>
                      <div>
                        <div className="text-xs opacity-70 uppercase mb-2">Specialized Parsers</div>
                        {parserReports.length ? parserReports.map((report) => (
                          <div key={`${report.parser}-${report.summary}`}>
                            <SignalPanel tone="neutral" className="mb-2">
                              <div className="font-bold uppercase">{report.parser}</div>
                              <div>{report.summary}</div>
                              <div className="mt-2 space-y-1 opacity-80">
                                {report.details.map((detail) => (
                                  <div key={detail}>{detail}</div>
                                ))}
                              </div>
                              {(report.snippets ?? []).length ? (
                                <div className="mt-3">
                                  <div className="text-xs opacity-70 uppercase mb-2">Detected Code / Snippets</div>
                                  <div className="space-y-2">
                                    {(report.snippets ?? []).map((snippet) => (
                                      <pre key={snippet} className="overflow-x-auto whitespace-pre-wrap border border-orange-400/40 bg-black/70 p-2 text-xs opacity-90 text-orange-200">{snippet}</pre>
                                    ))}
                                  </div>
                                </div>
                              ) : null}
                            </SignalPanel>
                          </div>
                        )) : <div className="opacity-70">No parser reports</div>}
                      </div>
                      <div>
                        <div className="text-xs opacity-70 uppercase mb-2">Artifacts</div>
                        {artifacts.length ? artifacts.map((artifact) => {
                          return (
                            <div key={`${artifact.type}-${artifact.path}`}>
                              <SignalPanel tone="neutral" className="mb-2">
                                <div className="font-bold uppercase">{artifact.type}</div>
                                <div>{artifact.label}</div>
                              </SignalPanel>
                            </div>
                          );
                        }) : <div className="opacity-70">No artifacts available</div>}
                      </div>
                    </div>
                  </div>
                  </div>
                );
              })}
            </div>
          ) : null}

        </div>
      )}
    </div>
  );
}

async function fileToPayload(file: File): Promise<FileUpload> {
  const arrayBuffer = await file.arrayBuffer();
  const bytes = new Uint8Array(arrayBuffer);
  let binary = '';
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });

  return {
    filename: file.name,
    contentType: file.type || null,
    contentBase64: btoa(binary),
  };
}