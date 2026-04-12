import React, { useState } from 'react';
import { Cpu, FileArchive, Upload } from 'lucide-react';

import type { ArchiveTreeNode, ExtractedArchiveTree, FileAnalysisJob, FileIocEnrichment, FileUpload } from '../../shared/analysis-types';
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
                      <RiskScoreBreakdownCard
                        totalScore={result.riskScoreBreakdown.totalScore}
                        factors={result.riskScoreBreakdown.factors}
                        suspiciousThreshold={result.riskScoreBreakdown.thresholds.suspicious}
                        maliciousThreshold={result.riskScoreBreakdown.thresholds.malicious}
                      />

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
                        <div className="text-xs opacity-70 uppercase mb-2">IOC Enrichment</div>
                        <IocEnrichmentCard enrichment={result.iocEnrichment} />
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
                              {report.extractedTree ? (
                                <div className="mt-3">
                                  <div className="text-xs opacity-70 uppercase mb-2">Archive Tree</div>
                                  <ArchiveTreeCard tree={report.extractedTree} />
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

function RiskScoreBreakdownCard(props: {
  totalScore: number;
  suspiciousThreshold: number;
  maliciousThreshold: number;
  factors: Array<{
    label: string;
    severity: 'low' | 'medium' | 'high';
    contribution: number;
    evidence: string;
  }>;
}) {
  const filledColumns = Math.max(1, Math.round(props.totalScore / 10));

  return (
    <SignalPanel tone={toneFromRiskScore(props.totalScore)} className="mt-3">
      <div className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="text-xs uppercase opacity-70">Risk Score Breakdown</div>
          <SignalBadge tone={toneFromRiskScore(props.totalScore)}>{props.totalScore}/100</SignalBadge>
        </div>
        <div className="grid grid-cols-10 gap-1">
          {Array.from({ length: 10 }, (_, index) => (
            <div
              key={`risk-bar-${index}`}
              className={`h-2 rounded-sm border ${index < filledColumns ? 'border-orange-300 bg-orange-300/80' : 'border-white/20 bg-white/5'}`}
            />
          ))}
        </div>
        <div className="text-xs opacity-80">
          Suspicious at {props.suspiciousThreshold}+ points. Malicious at {props.maliciousThreshold}+ points.
        </div>
        <div className="space-y-2">
          {props.factors.length ? props.factors.map((factor) => (
            <div key={`${factor.label}-${factor.evidence}`} className="border border-white/10 bg-black/30 p-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <SignalText tone={factor.severity === 'low' ? 'neutral' : 'warning'}>{factor.label}</SignalText>
                <span className="text-xs uppercase opacity-80">+{factor.contribution}</span>
              </div>
              <div className="mt-1 text-xs break-all opacity-80">{factor.evidence}</div>
            </div>
          )) : <div className="text-xs opacity-70">No contributing factors.</div>}
        </div>
      </div>
    </SignalPanel>
  );
}

function ArchiveTreeCard({ tree }: { tree: ExtractedArchiveTree }) {
  return (
    <SignalPanel tone={tree.truncated ? 'warning' : 'neutral'}>
      <div className="space-y-3 text-xs">
        <div className="flex flex-wrap gap-3 opacity-80">
          <span>Entries: {tree.totalEntries}</span>
          <span>Depth: {tree.maxDepth}</span>
          <span>Size: {tree.totalExtractedSize} bytes</span>
        </div>
        {tree.warnings.length ? (
          <div className="space-y-1">
            {tree.warnings.map((warning) => (
              <div key={warning}>
                <SignalText tone="warning">{warning}</SignalText>
              </div>
            ))}
          </div>
        ) : null}
        <div className="space-y-1">
          {tree.root.children.map((node) => (
            <div key={node.path}>
              <ArchiveTreeNodeView node={node} depth={0} />
            </div>
          ))}
        </div>
      </div>
    </SignalPanel>
  );
}

function ArchiveTreeNodeView({ node, depth }: { node: ArchiveTreeNode; depth: number }) {
  const hasIndicators = node.indicators.length > 0;
  const hasChildren = node.children.length > 0;
  const paddingLeft = `${depth * 0.85}rem`;

  if (!hasChildren) {
    return (
      <div className="border border-white/10 bg-black/20 p-2" style={{ marginLeft: paddingLeft }}>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <SignalText tone={hasIndicators ? 'warning' : 'neutral'}>{node.path}</SignalText>
          <span className="opacity-60">{node.detectedType ?? 'unknown'}</span>
        </div>
        {hasIndicators ? (
          <div className="mt-1 space-y-1">
            {node.indicators.map((indicator) => (
              <div key={`${node.path}-${indicator.kind}-${indicator.value}`} className="text-[11px] break-all opacity-80">
                {formatSignalLabel(indicator.kind)}: {indicator.value}
              </div>
            ))}
          </div>
        ) : null}
      </div>
    );
  }

  return (
    <details className="border border-white/10 bg-black/20 p-2" style={{ marginLeft: paddingLeft }} open={depth < 1 || hasIndicators}>
      <summary className="cursor-pointer list-none flex flex-wrap items-center justify-between gap-2">
        <SignalText tone={hasIndicators ? 'warning' : 'neutral'}>{node.path}</SignalText>
        <span className="opacity-60">{node.detectedType ?? (node.isDirectory ? 'directory' : 'unknown')}</span>
      </summary>
      {hasIndicators ? (
        <div className="mt-2 space-y-1">
          {node.indicators.map((indicator) => (
            <div key={`${node.path}-${indicator.kind}-${indicator.value}`} className="text-[11px] break-all opacity-80">
              {formatSignalLabel(indicator.kind)}: {indicator.value}
            </div>
          ))}
        </div>
      ) : null}
      <div className="mt-2 space-y-1">
        {node.children.map((child) => (
          <div key={child.path}>
            <ArchiveTreeNodeView node={child} depth={depth + 1} />
          </div>
        ))}
      </div>
    </details>
  );
}

function IocEnrichmentCard({ enrichment }: { enrichment: FileIocEnrichment }) {
  const flaggedResults = enrichment.results.filter((result) => result.verdict === 'malicious' || result.verdict === 'suspicious');

  return (
    <SignalPanel tone={toneFromScannerStatus(enrichment.status)} className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <SignalText tone={toneFromScannerStatus(enrichment.status)}>{enrichment.summary}</SignalText>
        <SignalBadge tone={toneFromScannerStatus(enrichment.status)}>{enrichment.status}</SignalBadge>
      </div>
      <div className="flex flex-wrap gap-3 text-xs opacity-80">
        <span>URLs: {enrichment.extractedUrls.length}</span>
        <span>Domains: {enrichment.extractedDomains.length}</span>
        <span>Flagged: {flaggedResults.length}</span>
      </div>
      {enrichment.results.length ? (
        <div className="space-y-2">
          {enrichment.results.map((result) => (
            <div key={`${result.type}-${result.value}`} className="border border-white/10 bg-black/30 p-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <SignalText tone={toneFromScannerStatus(result.verdict)}>{result.value}</SignalText>
                <SignalBadge tone={toneFromScannerStatus(result.verdict)}>{result.verdict}</SignalBadge>
              </div>
              <div className="mt-1 text-xs opacity-80 break-all">{result.summary}</div>
              <div className="mt-2 flex flex-wrap gap-2">
                {result.providerResults.map((providerResult) => (
                  <div key={`${result.value}-${providerResult.provider}`} className="border border-white/10 px-2 py-1 text-[11px]">
                    <div className="uppercase opacity-70">{providerResult.provider}</div>
                    <SignalText tone={toneFromScannerStatus(providerResult.status)}>{providerResult.status}</SignalText>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="text-xs opacity-70">No IOC provider verdicts yet.</div>
      )}
    </SignalPanel>
  );
}