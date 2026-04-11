import React, { useState } from 'react';
import { AlertOctagon, Cpu, ExternalLink, FileArchive, Upload } from 'lucide-react';

import type { FileAnalysisJob, FileUpload } from '../../shared/analysis-types';
import { isPreviewableImage, toStorageUrl } from './storage-assets';

const FILE_ANALYSIS_POLL_INTERVAL_MS = import.meta.env.MODE === 'test' ? 1 : 1000;
const FILE_ANALYSIS_MAX_POLL_ATTEMPTS = 8;

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
    for (let attempt = 0; attempt < FILE_ANALYSIS_MAX_POLL_ATTEMPTS; attempt += 1) {
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
                    <div className={`text-lg font-bold uppercase ${result.verdict === 'malicious' ? 'text-red-500' : result.verdict === 'suspicious' ? 'text-yellow-500' : 'text-green-500'}`}>
                      {result.verdict}
                    </div>
                  </div>

                  <div className="grid grid-cols-1 xl:grid-cols-2 gap-6 text-sm">
                    <div className="space-y-2">
                      <div>Summary: {result.summary}</div>
                      <div>SHA256: {result.sha256}</div>
                      <div>Risk Score: {result.riskScore}</div>
                      <div>
                        Stored At: {toStorageUrl(result.storagePath) ? (
                          <a href={toStorageUrl(result.storagePath) || '#'} target="_blank" rel="noreferrer" className="text-cyber-red underline inline-flex items-center gap-1 break-all">
                            {result.storagePath} <ExternalLink size={12} />
                          </a>
                        ) : (result.storagePath || 'Unavailable')}
                      </div>
                      <div>VirusTotal: {result.externalScans.virustotal.status}</div>
                      <div>ClamAV: {clamav.status}{clamav.signature ? ` (${clamav.signature})` : ''}</div>
                      <div>YARA: {yara.status}{yara.rules.length ? ` (${yara.rules.join(', ')})` : ''}</div>
                    </div>
                    <div className="space-y-3">
                      <div>
                        <div className="text-xs opacity-70 uppercase mb-2">Indicators</div>
                        {result.indicators.length ? result.indicators.map((indicator) => (
                          <div key={`${indicator.kind}-${indicator.value}`} className="border border-cyber-red-dim bg-black/40 p-2 mb-2">
                            <div className="font-bold uppercase">{indicator.kind}</div>
                            <div>{indicator.value}</div>
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
                          <div key={`${report.parser}-${report.summary}`} className="border border-cyber-red-dim bg-black/40 p-2 mb-2">
                            <div className="font-bold uppercase">{report.parser}</div>
                            <div>{report.summary}</div>
                            <div className="mt-2 space-y-1 opacity-80">
                              {report.details.map((detail) => (
                                <div key={detail}>{detail}</div>
                              ))}
                            </div>
                          </div>
                        )) : <div className="opacity-70">No parser reports</div>}
                      </div>
                      <div>
                        <div className="text-xs opacity-70 uppercase mb-2">Artifacts</div>
                        {artifacts.length ? artifacts.map((artifact) => {
                          const href = toStorageUrl(artifact.path);
                          return (
                            <div key={`${artifact.type}-${artifact.path}`} className="border border-cyber-red-dim bg-black/40 p-2 mb-2">
                              <div className="font-bold uppercase">{artifact.type}</div>
                              {href ? (
                                <a href={href} target="_blank" rel="noreferrer" className="text-cyber-red underline inline-flex items-center gap-1 break-all">
                                  {artifact.label} <ExternalLink size={12} />
                                </a>
                              ) : (
                                <div>{artifact.label}</div>
                              )}
                              {isPreviewableImage(artifact.path, artifact.mimeType) && href ? (
                                <a href={href} target="_blank" rel="noreferrer" className="block mt-3">
                                  <img src={href} alt={artifact.label} className="max-h-40 w-full object-contain border border-cyber-red-dim bg-black/50" />
                                </a>
                              ) : null}
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

          <div className="cli-border p-4 bg-cyber-red-dim/10 text-sm">
            <div className="flex items-start">
              <AlertOctagon className="mr-2 mt-0.5 flex-shrink-0" size={16} />
              <span>This MVP provides static file analysis only. Dynamic detonation in Linux or Windows VMs remains a later phase.</span>
            </div>
          </div>
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