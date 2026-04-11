import React, { useEffect, useRef, useState } from 'react';
import { AlertOctagon, Cpu, ExternalLink, Globe, MonitorSmartphone } from 'lucide-react';

import type { BrowserSandboxJob } from '../../shared/analysis-types';
import { isPreviewableImage, toStorageUrl } from './storage-assets';

const SANDBOX_POLL_INTERVAL_MS = import.meta.env.MODE === 'test' ? 1 : 1000;
const SANDBOX_MAX_POLL_DURATION_MS = import.meta.env.MODE === 'test' ? 50 : 120000;
const LIVE_SESSION_HEARTBEAT_INTERVAL_MS = 60 * 1000;
const LIVE_SESSION_IDLE_TIMEOUT_MINUTES = 5;

export function BrowserSandbox() {
  const [targetUrl, setTargetUrl] = useState('');
  const [sandboxJob, setSandboxJob] = useState<BrowserSandboxJob | null>(null);
  const [isLaunching, setIsLaunching] = useState(false);
  const [error, setError] = useState('');
  const [iframeHeight, setIframeHeight] = useState(720);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const liveBrowserContainerRef = useRef<HTMLDivElement | null>(null);

  const liveAccess = sandboxJob?.result?.access ?? null;
  const liveAccessUrl = liveAccess?.url ?? null;
  const isEmbeddedAccess = liveAccess?.mode === 'embedded' && Boolean(liveAccessUrl);

  useEffect(() => {
    const updateFullscreenState = () => {
      setIsFullscreen(Boolean(document.fullscreenElement));
    };

    document.addEventListener('fullscreenchange', updateFullscreenState);

    return () => {
      document.removeEventListener('fullscreenchange', updateFullscreenState);
    };
  }, []);

  useEffect(() => {
    if (!sandboxJob?.jobId || !isEmbeddedAccess || sandboxJob.result?.session.status !== 'ready') {
      return;
    }

    let cancelled = false;

    const sendHeartbeat = async () => {
      if (document.visibilityState !== 'visible' || !document.hasFocus()) {
        return;
      }

      try {
        const heartbeatResponse = await fetch(`/api/sandbox/browser/${sandboxJob.jobId}/heartbeat`, {
          method: 'POST',
        });
        const heartbeatJob = (await heartbeatResponse.json()) as BrowserSandboxJob | { message?: string };

        if (!cancelled && heartbeatResponse.ok && 'jobId' in heartbeatJob) {
          setSandboxJob(heartbeatJob);
        }
      } catch {
        return;
      }
    };

    const heartbeatTimer = window.setInterval(() => {
      void sendHeartbeat();
    }, LIVE_SESSION_HEARTBEAT_INTERVAL_MS);

    const handleFocus = () => {
      void sendHeartbeat();
    };

    document.addEventListener('visibilitychange', handleFocus);
    window.addEventListener('focus', handleFocus);

    return () => {
      cancelled = true;
      window.clearInterval(heartbeatTimer);
      document.removeEventListener('visibilitychange', handleFocus);
      window.removeEventListener('focus', handleFocus);
    };
  }, [isEmbeddedAccess, sandboxJob?.jobId, sandboxJob?.result?.session.status]);

  const handleLaunchSandbox = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!targetUrl) {
      return;
    }

    setIsLaunching(true);
    setError('');
    setSandboxJob(null);

    try {
      const createResponse = await fetch('/api/sandbox/browser', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: targetUrl }),
      });
      const createdJob = (await createResponse.json()) as BrowserSandboxJob | { message?: string };

      if (!createResponse.ok || !('jobId' in createdJob)) {
        throw new Error(('message' in createdJob && createdJob.message) || 'Browser sandbox launch failed.');
      }

      setSandboxJob(createdJob);
      const completedJob = await pollSandboxJob(createdJob.jobId);
      setSandboxJob(completedJob);
    } catch (launchError) {
      setError(launchError instanceof Error ? launchError.message : 'Browser sandbox failed.');
    } finally {
      setIsLaunching(false);
    }
  };

  const handleStopSandbox = async () => {
    if (!sandboxJob) {
      return;
    }

    try {
      const stopResponse = await fetch(`/api/sandbox/browser/${sandboxJob.jobId}/stop`, {
        method: 'POST',
      });
      const stoppedJob = (await stopResponse.json()) as BrowserSandboxJob | { message?: string };

      if (!stopResponse.ok || !('jobId' in stoppedJob)) {
        throw new Error(('message' in stoppedJob && stoppedJob.message) || 'Browser sandbox stop failed.');
      }

      setSandboxJob(stoppedJob);
    } catch (stopError) {
      setError(stopError instanceof Error ? stopError.message : 'Browser sandbox stop failed.');
    }
  };

  const handleToggleFullscreen = async () => {
    const container = liveBrowserContainerRef.current;
    if (!container) {
      return;
    }

    if (document.fullscreenElement) {
      await document.exitFullscreen();
      return;
    }

    await container.requestFullscreen();
  };

  const pollSandboxJob = async (jobId: string) => {
    const startedAt = Date.now();

    while (Date.now() - startedAt < SANDBOX_MAX_POLL_DURATION_MS) {
      const jobResponse = await fetch(`/api/sandbox/browser/${jobId}`, {
        method: 'GET',
      });
      const jobPayload = (await jobResponse.json()) as BrowserSandboxJob | { message?: string };
      if (!jobResponse.ok || !('jobId' in jobPayload)) {
        throw new Error(('message' in jobPayload && jobPayload.message) || 'Browser sandbox polling failed.');
      }

      setSandboxJob(jobPayload);
      if (jobPayload.status === 'completed' || jobPayload.status === 'failed' || jobPayload.status === 'stopped') {
        return jobPayload;
      }

      await new Promise((resolve) => {
        setTimeout(resolve, SANDBOX_POLL_INTERVAL_MS);
      });
    }

    throw new Error('Browser sandbox polling timed out.');
  };

  return (
    <div className="space-y-6">
      <div className="cli-border p-4">
        <h2 className="text-xl mb-4 flex items-center uppercase tracking-wider">
          <MonitorSmartphone className="mr-2" /> Remote Browser Sandbox
        </h2>
        <form onSubmit={handleLaunchSandbox} className="space-y-4">
          <input
            value={targetUrl}
            onChange={(event) => setTargetUrl(event.target.value)}
            placeholder="https://suspicious.example/login"
            className="cli-input w-full p-4 font-mono text-sm"
          />
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <button type="submit" disabled={isLaunching || !targetUrl} className="cli-button w-full py-3 flex items-center justify-center">
              {isLaunching ? (
                <span className="animate-pulse flex items-center"><Cpu size={16} className="mr-2 animate-spin" /> LAUNCHING SANDBOX...</span>
              ) : (
                <>LAUNCH SANDBOX</>
              )}
            </button>
            <button
              type="button"
              disabled={!sandboxJob || (sandboxJob.status !== 'running' && sandboxJob.result?.session.status !== 'ready')}
              onClick={handleStopSandbox}
              className="cli-button w-full py-3 flex items-center justify-center"
            >
              STOP SANDBOX
            </button>
          </div>
        </form>
        {error && <div className="mt-4 text-red-500 text-sm border border-red-500 p-2 bg-red-500/10">[!] ERROR: {error}</div>}
      </div>

      {sandboxJob && (
        <div className="space-y-4 animate-in fade-in duration-500">
          <div className="cli-border p-4 bg-black/40">
            <div className="flex flex-col md:flex-row md:justify-between gap-3 text-sm">
              <div>
                <div className="text-xs opacity-70 uppercase">Requested URL</div>
                <div className="break-all">{sandboxJob.requestedUrl}</div>
              </div>
              <div className="text-right">
                <div className="text-xs opacity-70 uppercase">Sandbox Job</div>
                <div className="font-bold uppercase">{sandboxJob.status} [{sandboxJob.jobId}]</div>
              </div>
            </div>
            <div className="mt-2 text-xs opacity-70">Expires At: {sandboxJob.expiresAt || 'n/a'}</div>
          </div>

          {sandboxJob.result ? (
            <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
              <div className="cli-border p-4">
                <h3 className="text-lg border-b border-cyber-red-dim pb-2 uppercase mb-4">Navigation Evidence</h3>
                <div className="space-y-2 text-sm">
                  <div className="font-bold break-all">{sandboxJob.result.title || sandboxJob.result.originalUrl}</div>
                  <div>Final URL: {sandboxJob.result.finalUrl || 'Unavailable'}</div>
                  <div>Provider: {sandboxJob.result.session.provider}</div>
                  <div>Session: {sandboxJob.result.session.sessionId} [{sandboxJob.result.session.status}]</div>
                  <div><ArtifactLink filePath={sandboxJob.result.screenshotPath} label="Screenshot" /></div>
                  <div><ArtifactLink filePath={sandboxJob.result.tracePath} label="Trace" /></div>
                  <div>Redirects: {sandboxJob.result.redirectChain.join(' -> ') || 'None observed'}</div>
                  {isPreviewableImage(sandboxJob.result.screenshotPath, 'image/png') && toStorageUrl(sandboxJob.result.screenshotPath) ? (
                    <a href={toStorageUrl(sandboxJob.result.screenshotPath) || '#'} target="_blank" rel="noreferrer" className="block mt-3">
                      <img
                        src={toStorageUrl(sandboxJob.result.screenshotPath) || undefined}
                        alt="Sandbox screenshot preview"
                        className="max-h-64 w-full object-contain border border-cyber-red-dim bg-black/50"
                      />
                    </a>
                  ) : null}
                  <div className="border border-cyber-red-dim p-2 bg-black/40">
                    <div className="text-xs opacity-70 uppercase mb-1">Provider Note</div>
                    <div>{sandboxJob.result.access.note || 'No provider note.'}</div>
                    {liveAccessUrl ? (
                      <div className="mt-3 flex flex-col gap-3">
                        <a href={liveAccessUrl} target="_blank" rel="noreferrer" className="cli-button inline-flex items-center justify-center px-4 py-2 text-xs md:text-sm w-full md:w-auto">
                          Open Remote Browser <ExternalLink size={12} className="ml-2" />
                        </a>
                        {isEmbeddedAccess ? (
                          <div className="text-xs opacity-70">
                            Embedded analyst console is available below. Open in a separate tab if you need a larger viewport.
                          </div>
                        ) : null}
                      </div>
                    ) : null}
                  </div>
                  {sandboxJob.result.error && <div className="text-red-400">Error: {sandboxJob.result.error}</div>}
                </div>
              </div>

              <div className="cli-border p-4">
                <h3 className="text-lg border-b border-cyber-red-dim pb-2 uppercase mb-4 flex items-center">
                  <Globe className="mr-2" size={18} /> Observed Activity
                </h3>
                <div className="space-y-4 text-sm">
                  <div>
                    <div className="text-xs opacity-70 uppercase mb-2">Requested Domains</div>
                    <div className="space-y-1">
                      {sandboxJob.result.requestedDomains.length ? sandboxJob.result.requestedDomains.map((domain) => (
                        <div key={domain} className="break-all">{domain}</div>
                      )) : <div className="opacity-70">None observed</div>}
                    </div>
                  </div>
                  <div>
                    <div className="text-xs opacity-70 uppercase mb-2">Script URLs</div>
                    <div className="space-y-1">
                      {sandboxJob.result.scriptUrls.length ? sandboxJob.result.scriptUrls.map((scriptUrl) => (
                        <div key={scriptUrl} className="break-all">{scriptUrl}</div>
                      )) : <div className="opacity-70">None observed</div>}
                    </div>
                  </div>
                  <div>
                    <div className="text-xs opacity-70 uppercase mb-2">Console Errors</div>
                    <div className="space-y-1">
                      {sandboxJob.result.consoleErrors.length ? sandboxJob.result.consoleErrors.map((consoleError) => (
                        <div key={consoleError} className="text-red-400 break-all">{consoleError}</div>
                      )) : <div className="opacity-70">None observed</div>}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          ) : null}

          {sandboxJob.result ? (
            <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
              <div className="cli-border p-4">
                <h3 className="text-lg border-b border-cyber-red-dim pb-2 uppercase mb-4">Observed Downloads</h3>
                {sandboxJob.result.downloads.length ? (
                  <div className="space-y-3 text-sm">
                    {sandboxJob.result.downloads.map((download) => (
                      <div key={`${download.filename}-${download.sha256}`} className="border border-cyber-red-dim bg-black/40 p-3">
                        <div className="font-bold break-all">{download.filename}</div>
                        <div className="break-all">
                          URL: {download.url ? <a href={download.url} target="_blank" rel="noreferrer" className="text-cyber-red underline">{download.url}</a> : 'Unavailable'}
                        </div>
                        <div><ArtifactLink filePath={download.path} label="Stored copy" /></div>
                        <div className="break-all">SHA256: {download.sha256}</div>
                        <div>Size: {download.size} bytes</div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm opacity-70">No downloads were observed during this sandbox run.</p>
                )}
              </div>
              <div className="cli-border p-4">
                <h3 className="text-lg border-b border-cyber-red-dim pb-2 uppercase mb-4">Artifacts</h3>
                {sandboxJob.result.artifacts.length ? (
                  <div className="space-y-3 text-sm">
                    {sandboxJob.result.artifacts.map((artifact) => (
                      <div key={`${artifact.type}-${artifact.path}`} className="border border-cyber-red-dim bg-black/40 p-3">
                        <div className="font-bold uppercase">{artifact.type}</div>
                        <div>{artifact.label}</div>
                        <div><ArtifactLink filePath={artifact.path} label="Open artifact" /></div>
                        {isPreviewableImage(artifact.path, artifact.mimeType) && toStorageUrl(artifact.path) ? (
                          <a href={toStorageUrl(artifact.path) || '#'} target="_blank" rel="noreferrer" className="block mt-3">
                            <img src={toStorageUrl(artifact.path) || undefined} alt={artifact.label} className="max-h-40 w-full object-contain border border-cyber-red-dim bg-black/50" />
                          </a>
                        ) : null}
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm opacity-70">No artifacts were captured for this job.</p>
                )}
              </div>
            </div>
          ) : null}

          {sandboxJob.result && isEmbeddedAccess ? (
            <div className="cli-border p-4">
              <h3 className="text-lg border-b border-cyber-red-dim pb-2 uppercase mb-4 flex items-center">
                <MonitorSmartphone className="mr-2" size={18} /> Live Remote Browser
              </h3>
              <div className="text-xs opacity-70 mb-3">
                This embedded console is the live noVNC session running on the server. If the page is left inactive, the server closes the live session after {LIVE_SESSION_IDLE_TIMEOUT_MINUTES} minutes.
              </div>
              <div className="mb-4 flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                <label className="flex flex-col gap-2 text-xs uppercase tracking-wider lg:min-w-80">
                  <span>Viewport Height: {iframeHeight}px</span>
                  <input
                    type="range"
                    min={480}
                    max={1080}
                    step={40}
                    value={iframeHeight}
                    onChange={(event) => setIframeHeight(Number(event.target.value))}
                  />
                </label>
                <button type="button" className="cli-button px-4 py-2 text-xs md:text-sm" onClick={() => void handleToggleFullscreen()}>
                  {isFullscreen ? 'Exit Full Screen' : 'Full Screen'}
                </button>
              </div>
              <div ref={liveBrowserContainerRef} className="border border-cyber-red-dim bg-black/60 min-h-[720px]">
                <iframe
                  title="Live remote browser session"
                  src={liveAccessUrl ?? undefined}
                  className="w-full bg-black"
                  style={{ minHeight: `${iframeHeight}px`, height: `${iframeHeight}px` }}
                  allow="clipboard-read; clipboard-write"
                />
              </div>
            </div>
          ) : null}

          <div className="cli-border p-4 bg-cyber-red-dim/10 text-sm">
            <div className="flex items-start">
              <AlertOctagon className="mr-2 mt-0.5 flex-shrink-0" size={16} />
              <span>This MVP runs a hardened server-side browser evidence collection flow. It is not a full disposable VM sandbox yet.</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function ArtifactLink({ filePath, label }: { filePath: string | null; label: string }) {
  const href = toStorageUrl(filePath);

  if (!href) {
    return <span>{label}: {filePath || 'Unavailable'}</span>;
  }

  return (
    <a href={href} target="_blank" rel="noreferrer" className="text-cyber-red underline inline-flex items-center gap-1 break-all">
      {label} <ExternalLink size={12} />
    </a>
  );
}