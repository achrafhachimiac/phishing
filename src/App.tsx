import React, { useEffect, useRef, useState } from 'react';
import { Login } from './components/Login';
import { DomainAnalysis } from './components/DomainAnalysis';
import { EmailAnalysis } from './components/EmailAnalysis';
import { BrowserSandbox } from './components/BrowserSandbox';
import { FileAnalysis } from './components/FileAnalysis';
import { ThePhish } from './components/ThePhish';
import { toStorageUrl } from './components/storage-assets';
import { CaseContextProvider, type CaseEvent, type CaseEventSeverity, type CaseEventTool } from './case-context';
import { buildCaseJsonReport, buildCaseReport, downloadCaseJsonReport, downloadCaseReport } from './case-report';
import { Shield, LogOut, RotateCcw, Download } from 'lucide-react';
import type { CaseEventReference, CaseSession, CaseSessionListResponse, CaseSessionSummary, CurrentCaseSessionResponse } from '../shared/analysis-types';

type AppTab = 'domain' | 'email' | 'sandbox' | 'files' | 'thephish';

type TabPrefill = {
  value: string;
  nonce: number;
};

export default function App() {
  const [authState, setAuthState] = useState<'checking' | 'authenticated' | 'unauthenticated'>('checking');
  const [activeTab, setActiveTab] = useState<AppTab>('domain');
  const [caseRevision, setCaseRevision] = useState(1);
  const [caseStartedAt, setCaseStartedAt] = useState(() => new Date().toISOString());
  const [visitedTabs, setVisitedTabs] = useState<AppTab[]>(['domain']);
  const [caseEvents, setCaseEvents] = useState<CaseEvent[]>([]);
  const [casePersistenceReady, setCasePersistenceReady] = useState(false);
  const [caseLibrary, setCaseLibrary] = useState<CaseSessionSummary[]>([]);
  const [caseLibraryReady, setCaseLibraryReady] = useState(false);
  const [isActivatingCase, setIsActivatingCase] = useState(false);
  const [caseLibraryQuery, setCaseLibraryQuery] = useState('');
  const [caseLibrarySort, setCaseLibrarySort] = useState<'updated-desc' | 'updated-asc' | 'events-desc'>('updated-desc');
  const [casePendingDeletion, setCasePendingDeletion] = useState<string | null>(null);
  const [isDeletingCase, setIsDeletingCase] = useState<string | null>(null);
  const [domainPrefill, setDomainPrefill] = useState<TabPrefill | null>(null);
  const [sandboxPrefill, setSandboxPrefill] = useState<TabPrefill | null>(null);
  const lastPersistedCaseSnapshotRef = useRef<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    const loadSession = async () => {
      try {
        const response = await fetch('/api/auth/session');
        const payload = (await response.json()) as { authenticated?: boolean };
        if (!cancelled) {
          setAuthState(payload.authenticated ? 'authenticated' : 'unauthenticated');
        }
      } catch {
        if (!cancelled) {
          setAuthState('unauthenticated');
        }
      }
    };

    void loadSession();

    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (authState !== 'authenticated') {
      setCasePersistenceReady(false);
      setCaseLibraryReady(false);
      setCaseLibrary([]);
      lastPersistedCaseSnapshotRef.current = null;
      return;
    }

    let cancelled = false;

    const loadPersistedCase = async () => {
      try {
        const [currentCaseResponse, caseListResponse] = await Promise.all([
          fetch('/api/cases/current'),
          fetch('/api/cases'),
        ]);
        if (!currentCaseResponse.ok) {
          throw new Error('Unable to restore persisted case session.');
        }

        const payload = (await currentCaseResponse.json()) as CurrentCaseSessionResponse;
        if (cancelled) {
          return;
        }

        if (caseListResponse.ok) {
          const caseListPayload = (await caseListResponse.json()) as CaseSessionListResponse;
          setCaseLibrary(caseListPayload.cases);
        }

        if (payload.case) {
          applyCaseSession(payload.case, setActiveTab, setCaseStartedAt, setVisitedTabs, setCaseEvents, lastPersistedCaseSnapshotRef, setCaseRevision);
        } else {
          lastPersistedCaseSnapshotRef.current = serializeCaseSnapshot({
            caseId: currentCaseId,
            startedAt: caseStartedAt,
            activeTab,
            visitedTabs,
            events: caseEvents,
          });
        }
      } catch {
        if (!cancelled) {
          lastPersistedCaseSnapshotRef.current = serializeCaseSnapshot({
            caseId: currentCaseId,
            startedAt: caseStartedAt,
            activeTab,
            visitedTabs,
            events: caseEvents,
          });
        }
      } finally {
        if (!cancelled) {
          setCasePersistenceReady(true);
          setCaseLibraryReady(true);
        }
      }
    };

    void loadPersistedCase();

    return () => {
      cancelled = true;
    };
  }, [authState]);

  const handleLogout = async () => {
    try {
      await fetch('/api/auth/logout', { method: 'POST' });
    } finally {
      setAuthState('unauthenticated');
    }
  };

  const handleSelectTab = (tab: AppTab) => {
    setActiveTab(tab);
    setVisitedTabs((currentTabs) => (currentTabs.includes(tab) ? currentTabs : [...currentTabs, tab]));
  };

  const handleResetCase = () => {
    setCaseRevision((currentRevision) => currentRevision + 1);
    setCaseStartedAt(new Date().toISOString());
    setVisitedTabs([activeTab]);
    setCaseEvents([]);
    setDomainPrefill(null);
    setSandboxPrefill(null);
  };

  const handleRouteToDomainAnalysis = (domain: string) => {
    setDomainPrefill({ value: domain, nonce: Date.now() });
    handleSelectTab('domain');
  };

  const handleRouteToBrowserSandbox = (url: string) => {
    setSandboxPrefill({ value: url, nonce: Date.now() });
    handleSelectTab('sandbox');
  };

  const handleActivateCase = async (caseId: string) => {
    setIsActivatingCase(true);

    try {
      const response = await fetch(`/api/cases/${encodeURIComponent(caseId)}/activate`, {
        method: 'POST',
      });
      if (!response.ok) {
        throw new Error('Unable to reopen the selected CASE.');
      }

      const payload = (await response.json()) as CaseSession;
      applyCaseSession(payload, setActiveTab, setCaseStartedAt, setVisitedTabs, setCaseEvents, lastPersistedCaseSnapshotRef, setCaseRevision);
      setCaseLibrary((currentCases) => upsertCaseSummary(currentCases, toCaseSummary(payload)));
    } finally {
      setIsActivatingCase(false);
    }
  };

  const handleDeleteCase = async (caseId: string) => {
    setIsDeletingCase(caseId);

    try {
      const response = await fetch(`/api/cases/${encodeURIComponent(caseId)}`, {
        method: 'DELETE',
      });
      if (!response.ok) {
        throw new Error('Unable to delete the selected CASE.');
      }

      setCaseLibrary((currentCases) => currentCases.filter((entry) => entry.caseId !== caseId));
      if (caseId === currentCaseId) {
        lastPersistedCaseSnapshotRef.current = null;
        setCaseRevision((currentRevision) => currentRevision + 1);
        setCaseStartedAt(new Date().toISOString());
        setVisitedTabs([activeTab]);
        setCaseEvents([]);
      }
    } finally {
      setIsDeletingCase(null);
      setCasePendingDeletion(null);
    }
  };

  const handleExportCaseReport = () => {
    const reportText = buildCaseReport({
      caseId: currentCaseId,
      startedAt: caseStartedAt,
      visitedTools: visitedTabs,
      events: caseEvents,
    });

    downloadCaseReport(reportText, `${currentCaseId.toLowerCase()}-report.txt`);
  };

  const handleExportCaseJsonReport = () => {
    const reportJson = buildCaseJsonReport({
      caseId: currentCaseId,
      startedAt: caseStartedAt,
      visitedTools: visitedTabs,
      events: caseEvents,
    });

    downloadCaseJsonReport(reportJson, `${currentCaseId.toLowerCase()}-report.json`);
  };

  const currentCaseId = buildCaseId(caseStartedAt, caseRevision);
  const latestEvents = [...caseEvents].reverse().slice(0, 6);
  const filteredCaseLibrary = caseLibrary
    .filter((entry) => {
      const normalizedQuery = caseLibraryQuery.trim().toLowerCase();
      if (!normalizedQuery) {
        return true;
      }

      return entry.caseId.toLowerCase().includes(normalizedQuery)
        || entry.visitedTabs.some((tool) => formatTabLabel(tool).toLowerCase().includes(normalizedQuery));
    })
    .sort((left, right) => {
      if (caseLibrarySort === 'updated-asc') {
        return left.updatedAt.localeCompare(right.updatedAt);
      }

      if (caseLibrarySort === 'events-desc') {
        return right.eventCount - left.eventCount || right.updatedAt.localeCompare(left.updatedAt);
      }

      return right.updatedAt.localeCompare(left.updatedAt);
    });
  const currentCaseSessionSnapshot = serializeCaseSnapshot({
    caseId: currentCaseId,
    startedAt: caseStartedAt,
    activeTab,
    visitedTabs,
    events: caseEvents,
  });
  const caseContextValue = {
    caseId: currentCaseId,
    events: caseEvents,
    addCaseEvent: (event: Omit<CaseEvent, 'id' | 'occurredAt'>) => {
      setCaseEvents((currentEvents) => [
        ...currentEvents.slice(-39),
        {
          ...event,
          id: `${Date.now()}-${currentEvents.length + 1}`,
          occurredAt: new Date().toISOString(),
        },
      ]);
    },
  };

  useEffect(() => {
    if (authState !== 'authenticated' || !casePersistenceReady) {
      return;
    }

    if (lastPersistedCaseSnapshotRef.current === currentCaseSessionSnapshot) {
      return;
    }

    let cancelled = false;

    const persistCase = async () => {
      try {
        const caseSessionPayload = {
          caseId: currentCaseId,
          startedAt: caseStartedAt,
          updatedAt: new Date().toISOString(),
          activeTab,
          visitedTabs,
          events: caseEvents,
        };
        const response = await fetch('/api/cases/current', {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(caseSessionPayload),
        });

        if (!cancelled && response.ok) {
          lastPersistedCaseSnapshotRef.current = currentCaseSessionSnapshot;
          setCaseLibrary((currentCases) => upsertCaseSummary(currentCases, toCaseSummary(caseSessionPayload)));
        }
      } catch {
        return;
      }
    };

    void persistCase();

    return () => {
      cancelled = true;
    };
  }, [activeTab, authState, caseEvents, casePersistenceReady, caseStartedAt, currentCaseId, currentCaseSessionSnapshot, visitedTabs]);

  if (authState === 'checking') {
    return (
      <div className="min-h-screen flex items-center justify-center bg-cyber-bg text-cyber-red font-mono crt">
        <div className="scanline"></div>
        <div className="cli-border p-8 bg-black/80 relative z-10 text-center">
          <Shield className="mx-auto mb-4 animate-pulse" size={36} />
          <div className="tracking-widest uppercase">Restoring Secure Session...</div>
        </div>
      </div>
    );
  }

  if (authState !== 'authenticated') {
    return <Login onLogin={() => setAuthState('authenticated')} />;
  }

  return (
    <CaseContextProvider value={caseContextValue}>
      <div className="min-h-screen bg-cyber-bg text-cyber-red font-mono crt relative overflow-x-hidden">
      <div className="scanline"></div>
      
      <div className="max-w-6xl mx-auto p-4 md:p-8 relative z-10">
        <header className="flex flex-col md:flex-row justify-between items-center mb-8 border-b border-cyber-red pb-4">
          <div className="flex items-center mb-4 md:mb-0">
            <Shield className="mr-3 animate-pulse" size={32} />
            <div>
              <h1 className="text-2xl font-bold tracking-widest uppercase">Phish_Hunter_OSINT</h1>
              <p className="text-xs opacity-70">v2.4 // SECURE CONNECTION ESTABLISHED</p>
            </div>
          </div>
          
          <button 
            onClick={() => {
              void handleLogout();
            }}
            className="cli-button px-4 py-2 text-xs flex items-center"
          >
            <LogOut size={14} className="mr-2" /> TERMINATE SESSION
          </button>
        </header>

        <section className="cli-border p-4 mb-8 bg-black/40">
          <div className="grid gap-4 xl:grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)] xl:items-start">
            <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
              <div className="space-y-2 text-sm">
                <div className="text-xs opacity-70 uppercase">Global Case</div>
                <div className="font-bold uppercase">{currentCaseId}</div>
                <div className="opacity-75">Started: {new Date(caseStartedAt).toLocaleString()}</div>
                <div className="opacity-75">Visited tools: {visitedTabs.map(formatTabLabel).join(' -> ')}</div>
                <div className="opacity-75">Journal entries: {caseEvents.length}</div>
                <div className="opacity-75">Saved CASES: {caseLibrary.length}</div>
              </div>
              <div className="flex flex-col gap-3 sm:flex-row">
                <button
                  type="button"
                  onClick={handleExportCaseReport}
                  className="cli-button px-4 py-2 text-xs flex items-center justify-center"
                  aria-label="Export CASE report"
                >
                  <Download size={14} className="mr-2" /> EXPORT REPORT
                </button>
                <button
                  type="button"
                  onClick={handleExportCaseJsonReport}
                  className="cli-button px-4 py-2 text-xs flex items-center justify-center"
                  aria-label="Export CASE JSON"
                >
                  <Download size={14} className="mr-2" /> EXPORT JSON
                </button>
                <button
                  type="button"
                  onClick={handleResetCase}
                  className="cli-button px-4 py-2 text-xs flex items-center justify-center"
                  aria-label="Reset CASE"
                >
                  <RotateCcw size={14} className="mr-2" /> RESET CASE
                </button>
              </div>
            </div>
            <div className="border border-cyber-red-dim bg-black/30 p-3 text-xs space-y-3">
              <div className="opacity-70 uppercase">Recent CASES</div>
              <div className="space-y-2">
                <input
                  type="text"
                  value={caseLibraryQuery}
                  onChange={(event) => setCaseLibraryQuery(event.target.value)}
                  placeholder="Search CASE ID or tool"
                  className="cli-input w-full p-2 text-xs"
                  aria-label="Search saved CASES"
                />
                <select
                  value={caseLibrarySort}
                  onChange={(event) => setCaseLibrarySort(event.target.value as 'updated-desc' | 'updated-asc' | 'events-desc')}
                  className="cli-input w-full p-2 text-xs"
                  aria-label="Sort saved CASES"
                >
                  <option value="updated-desc">Newest updated first</option>
                  <option value="updated-asc">Oldest updated first</option>
                  <option value="events-desc">Most events first</option>
                </select>
              </div>
              {caseLibraryReady && filteredCaseLibrary.length ? (
                filteredCaseLibrary.slice(0, 8).map((caseSummary) => (
                  <div key={caseSummary.caseId} className="border border-cyber-red-dim/50 bg-black/30 p-2 space-y-2">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-bold uppercase">{caseSummary.caseId}</span>
                      <div className="flex gap-2">
                        <button
                          type="button"
                          onClick={() => {
                            setCasePendingDeletion(null);
                            void handleActivateCase(caseSummary.caseId);
                          }}
                          disabled={isActivatingCase || caseSummary.caseId === currentCaseId}
                          className="cli-button px-2 py-1 text-[11px]"
                          aria-label={`Open ${caseSummary.caseId}`}
                        >
                          {caseSummary.caseId === currentCaseId ? 'CURRENT' : isActivatingCase ? 'OPENING...' : 'OPEN'}
                        </button>
                        {casePendingDeletion === caseSummary.caseId ? (
                          <>
                            <button
                              type="button"
                              onClick={() => {
                                void handleDeleteCase(caseSummary.caseId);
                              }}
                              disabled={isDeletingCase === caseSummary.caseId}
                              className="cli-button px-2 py-1 text-[11px]"
                              aria-label={`Confirm delete ${caseSummary.caseId}`}
                            >
                              {isDeletingCase === caseSummary.caseId ? 'DELETING...' : 'CONFIRM'}
                            </button>
                            <button
                              type="button"
                              onClick={() => {
                                setCasePendingDeletion(null);
                              }}
                              disabled={isDeletingCase === caseSummary.caseId}
                              className="cli-button px-2 py-1 text-[11px]"
                              aria-label={`Cancel delete ${caseSummary.caseId}`}
                            >
                              CANCEL
                            </button>
                          </>
                        ) : (
                          <button
                            type="button"
                            onClick={() => {
                              setCasePendingDeletion(caseSummary.caseId);
                            }}
                            disabled={isDeletingCase === caseSummary.caseId}
                            className="cli-button px-2 py-1 text-[11px]"
                            aria-label={`Delete ${caseSummary.caseId}`}
                          >
                            DELETE
                          </button>
                        )}
                      </div>
                    </div>
                    {casePendingDeletion === caseSummary.caseId ? (
                      <div className="text-[11px] text-orange-300 uppercase">
                        Confirm deletion of this CASE. This action removes the saved session.
                      </div>
                    ) : null}
                    <div className="opacity-75">Updated: {new Date(caseSummary.updatedAt).toLocaleString()}</div>
                    <div className="opacity-75">Tools: {caseSummary.visitedTabs.map(formatTabLabel).join(' -> ')}</div>
                    <div className="opacity-75">Events: {caseSummary.eventCount}</div>
                  </div>
                ))
              ) : (
                <div className="opacity-70">{caseLibraryReady && caseLibrary.length ? 'No CASE sessions match the current filter.' : 'No saved CASE sessions yet.'}</div>
              )}
            </div>
            <div className="border border-cyber-red-dim bg-black/30 p-3 text-xs space-y-3">
              <div className="opacity-70 uppercase">Case Journal</div>
              {latestEvents.length ? (
                latestEvents.map((event) => (
                  <div key={event.id} className="border border-cyber-red-dim/50 bg-black/30 p-2 space-y-1">
                    <div className="flex items-center justify-between gap-2">
                      <span className={`uppercase ${journalToneClass(event.severity)}`}>{formatToolLabel(event.tool)} :: {event.title}</span>
                      <span className="opacity-60">{new Date(event.occurredAt).toLocaleTimeString()}</span>
                    </div>
                    <div className="opacity-85 break-all">{event.detail}</div>
                    {event.references?.length ? <CaseEventReferenceList references={event.references} /> : null}
                  </div>
                ))
              ) : (
                <div className="opacity-70">No analyst actions recorded for this CASE yet.</div>
              )}
            </div>
          </div>
        </section>

        <div className="flex space-x-4 mb-8">
          <button
            onClick={() => handleSelectTab('domain')}
            className={`cli-button px-6 py-3 flex-1 md:flex-none ${activeTab === 'domain' ? 'bg-cyber-red text-cyber-bg shadow-[0_0_15px_rgba(255,42,42,0.5)]' : ''}`}
          >
            [1] DOMAIN ANALYSIS
          </button>
          <button
            onClick={() => handleSelectTab('email')}
            className={`cli-button px-6 py-3 flex-1 md:flex-none ${activeTab === 'email' ? 'bg-cyber-red text-cyber-bg shadow-[0_0_15px_rgba(255,42,42,0.5)]' : ''}`}
          >
            [2] FULL EMAIL ANALYSIS
          </button>
          <button
            onClick={() => handleSelectTab('sandbox')}
            className={`cli-button px-6 py-3 flex-1 md:flex-none ${activeTab === 'sandbox' ? 'bg-cyber-red text-cyber-bg shadow-[0_0_15px_rgba(255,42,42,0.5)]' : ''}`}
          >
            [3] URL SANDBOX
          </button>
          <button
            onClick={() => handleSelectTab('files')}
            className={`cli-button px-6 py-3 flex-1 md:flex-none ${activeTab === 'files' ? 'bg-cyber-red text-cyber-bg shadow-[0_0_15px_rgba(255,42,42,0.5)]' : ''}`}
          >
            [4] FILE ANALYSIS
          </button>
          <button
            onClick={() => handleSelectTab('thephish')}
            className={`cli-button px-6 py-3 flex-1 md:flex-none ${activeTab === 'thephish' ? 'bg-cyber-red text-cyber-bg shadow-[0_0_15px_rgba(255,42,42,0.5)]' : ''}`}
          >
            [5] THEPHISH
          </button>
        </div>

        <main className="animate-in fade-in slide-in-from-bottom-4 duration-500">
          <div key={caseRevision} className="space-y-6">
            <div className={activeTab === 'domain' ? 'block' : 'hidden'} aria-hidden={activeTab !== 'domain'}>
              <DomainAnalysis prefilledDomain={domainPrefill?.value} prefillNonce={domainPrefill?.nonce} />
            </div>
            <div className={activeTab === 'email' ? 'block' : 'hidden'} aria-hidden={activeTab !== 'email'}>
              <EmailAnalysis />
            </div>
            <div className={activeTab === 'sandbox' ? 'block' : 'hidden'} aria-hidden={activeTab !== 'sandbox'}>
              <BrowserSandbox prefilledUrl={sandboxPrefill?.value} prefillNonce={sandboxPrefill?.nonce} />
            </div>
            <div className={activeTab === 'files' ? 'block' : 'hidden'} aria-hidden={activeTab !== 'files'}>
              <FileAnalysis />
            </div>
            <div className={activeTab === 'thephish' ? 'block' : 'hidden'} aria-hidden={activeTab !== 'thephish'}>
              <ThePhish onRouteToDomainAnalysis={handleRouteToDomainAnalysis} onRouteToBrowserSandbox={handleRouteToBrowserSandbox} />
            </div>
          </div>
        </main>
        
        <footer className="mt-12 text-center text-xs opacity-50 border-t border-cyber-red-dim pt-4">
          <p>WARNING: USE FOR AUTHORIZED INVESTIGATIONS ONLY.</p>
          <p>ALL QUERIES ARE LOGGED.</p>
        </footer>
      </div>
      </div>
    </CaseContextProvider>
  );
}

function buildCaseId(caseStartedAt: string, caseRevision: number) {
  const compactTimestamp = caseStartedAt.replace(/[-:TZ.]/g, '').slice(0, 12);
  return `CASE-${compactTimestamp}-${String(caseRevision).padStart(2, '0')}`;
}

function formatTabLabel(tab: AppTab) {
  switch (tab) {
    case 'domain':
      return 'DOMAIN';
    case 'email':
      return 'EMAIL';
    case 'sandbox':
      return 'SANDBOX';
    case 'files':
      return 'FILES';
    case 'thephish':
      return 'THEPHISH';
  }
}

function formatToolLabel(tool: CaseEventTool) {
  switch (tool) {
    case 'domain':
      return 'DOMAIN';
    case 'email':
      return 'EMAIL';
    case 'sandbox':
      return 'SANDBOX';
    case 'files':
      return 'FILES';
    case 'thephish':
      return 'THEPHISH';
  }
}

function journalToneClass(severity: CaseEventSeverity) {
  switch (severity) {
    case 'success':
      return 'text-green-400';
    case 'warning':
      return 'text-orange-300';
    case 'danger':
      return 'text-red-400';
    default:
      return 'text-cyber-red';
  }
}

function serializeCaseSnapshot(snapshot: {
  caseId: string;
  startedAt: string;
  activeTab: AppTab;
  visitedTabs: AppTab[];
  events: CaseEvent[];
}) {
  return JSON.stringify(snapshot);
}

function applyCaseSession(
  caseSession: CaseSession,
  setActiveTab: React.Dispatch<React.SetStateAction<AppTab>>,
  setCaseStartedAt: React.Dispatch<React.SetStateAction<string>>,
  setVisitedTabs: React.Dispatch<React.SetStateAction<AppTab[]>>,
  setCaseEvents: React.Dispatch<React.SetStateAction<CaseEvent[]>>,
  lastPersistedCaseSnapshotRef: React.MutableRefObject<string | null>,
  setCaseRevision: React.Dispatch<React.SetStateAction<number>>,
) {
  setActiveTab(caseSession.activeTab);
  setCaseStartedAt(caseSession.startedAt);
  setVisitedTabs(caseSession.visitedTabs);
  setCaseEvents(caseSession.events);
  lastPersistedCaseSnapshotRef.current = serializeCaseSnapshot({
    caseId: caseSession.caseId,
    startedAt: caseSession.startedAt,
    activeTab: caseSession.activeTab,
    visitedTabs: caseSession.visitedTabs,
    events: caseSession.events,
  });

  const parsedRevision = Number(caseSession.caseId.split('-').at(-1));
  if (Number.isFinite(parsedRevision) && parsedRevision > 0) {
    setCaseRevision(parsedRevision);
  }
}

function toCaseSummary(caseSession: Pick<CaseSession, 'caseId' | 'startedAt' | 'updatedAt' | 'activeTab' | 'visitedTabs' | 'events'>): CaseSessionSummary {
  return {
    caseId: caseSession.caseId,
    startedAt: caseSession.startedAt,
    updatedAt: caseSession.updatedAt,
    activeTab: caseSession.activeTab,
    visitedTabs: caseSession.visitedTabs,
    eventCount: caseSession.events.length,
  };
}

function upsertCaseSummary(currentCases: CaseSessionSummary[], nextCase: CaseSessionSummary) {
  return [nextCase, ...currentCases.filter((entry) => entry.caseId !== nextCase.caseId)]
    .sort((left, right) => right.updatedAt.localeCompare(left.updatedAt));
}

function CaseEventReferenceList({ references }: { references: CaseEventReference[] }) {
  return (
    <div className="flex flex-wrap gap-2 pt-1">
      {references.map((reference, index) => {
        const storageUrl = toStorageUrl(reference.path);
        const href = reference.url ?? storageUrl;
        const label = `${formatCaseReferenceLabel(reference.kind)}: ${reference.label}`;
        const value = reference.value;
        const key = `${reference.kind}-${reference.label}-${reference.value}-${index}`;

        if (href) {
          return (
            <a
              key={key}
              href={href}
              target={reference.url ? '_blank' : undefined}
              rel={reference.url ? 'noreferrer' : undefined}
              className="border border-cyber-red-dim/60 bg-black/40 px-2 py-1 text-[11px] break-all underline"
            >
              {label} {'->'} {value}
            </a>
          );
        }

        return (
          <span key={key} className="border border-cyber-red-dim/60 bg-black/40 px-2 py-1 text-[11px] break-all">
            {label} {'->'} {value}
          </span>
        );
      })}
    </div>
  );
}

function formatCaseReferenceLabel(kind: CaseEventReference['kind']) {
  switch (kind) {
    case 'job':
      return 'job';
    case 'artifact':
      return 'artifact';
    case 'url':
      return 'url';
    case 'domain':
      return 'domain';
    case 'email':
      return 'email';
    case 'file':
      return 'file';
    case 'session':
      return 'session';
    default:
      return kind;
  }
}

