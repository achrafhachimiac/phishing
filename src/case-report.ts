import type { CaseEvent, CaseEventSeverity, CaseEventTool, CaseSession } from '../shared/analysis-types';

export type CaseReportInput = {
  caseId: string;
  startedAt: string;
  exportedAt?: string;
  visitedTools: CaseEventTool[];
  events: CaseEvent[];
};

export type CaseJsonReport = {
  exportedAt: string;
  case: CaseSession;
  summary: {
    totalEvents: number;
    severity: Record<CaseEventSeverity, number>;
    tools: Array<{
      tool: CaseEventTool;
      eventCount: number;
    }>;
  };
};

export function buildCaseReport(input: CaseReportInput) {
  const exportedAt = input.exportedAt ?? new Date().toISOString();
  const severitySummary = summarizeSeverities(input.events);
  const toolSummary = summarizeTools(input.visitedTools, input.events);

  return [
    `# CASE REPORT ${input.caseId}`,
    '',
    '## Session Overview',
    `- Case ID: ${input.caseId}`,
    `- Started At: ${new Date(input.startedAt).toLocaleString()}`,
    `- Exported At: ${new Date(exportedAt).toLocaleString()}`,
    `- Visited Tools: ${input.visitedTools.map(formatToolLabel).join(' -> ') || 'None'}`,
    `- Total Events: ${input.events.length}`,
    '',
    '## Severity Summary',
    `- Info: ${severitySummary.info}`,
    `- Success: ${severitySummary.success}`,
    `- Warning: ${severitySummary.warning}`,
    `- Danger: ${severitySummary.danger}`,
    '',
    '## Tool Activity',
    ...toolSummary,
    '',
    '## Timeline',
    ...(input.events.length
      ? input.events.map((event) => `- [${new Date(event.occurredAt).toLocaleString()}] ${formatToolLabel(event.tool)} | ${event.severity.toUpperCase()} | ${event.title} | ${event.detail}`)
      : ['- No analyst actions were recorded for this CASE.']),
    '',
  ].join('\n');
}

export function buildCaseJsonReport(input: CaseReportInput): string {
  const exportedAt = input.exportedAt ?? new Date().toISOString();
  const caseSession: CaseSession = {
    caseId: input.caseId,
    startedAt: input.startedAt,
    updatedAt: exportedAt,
    activeTab: input.visitedTools.at(-1) ?? 'domain',
    visitedTabs: input.visitedTools,
    events: input.events,
  };
  const report: CaseJsonReport = {
    exportedAt,
    case: caseSession,
    summary: {
      totalEvents: input.events.length,
      severity: summarizeSeverities(input.events),
      tools: input.visitedTools.map((tool) => ({
        tool,
        eventCount: input.events.filter((event) => event.tool === tool).length,
      })),
    },
  };

  return JSON.stringify(report, null, 2);
}

export function downloadCaseReport(reportText: string, filename: string) {
  downloadCaseArtifact(reportText, filename, 'text/plain;charset=utf-8');
}

export function downloadCaseJsonReport(reportJson: string, filename: string) {
  downloadCaseArtifact(reportJson, filename, 'application/json;charset=utf-8');
}

function summarizeSeverities(events: CaseEvent[]) {
  return events.reduce(
    (summary, event) => ({
      ...summary,
      [event.severity]: summary[event.severity] + 1,
    }),
    {
      info: 0,
      success: 0,
      warning: 0,
      danger: 0,
    } satisfies Record<CaseEventSeverity, number>,
  );
}

function summarizeTools(visitedTools: CaseEventTool[], events: CaseEvent[]) {
  return visitedTools.map((tool) => {
    const toolEvents = events.filter((event) => event.tool === tool);
    return `- ${formatToolLabel(tool)}: ${toolEvents.length} event(s)`;
  });
}

function downloadCaseArtifact(content: string, filename: string, contentType: string) {
  const reportBlob = new Blob([content], { type: contentType });
  const reportUrl = URL.createObjectURL(reportBlob);
  const anchor = document.createElement('a');

  anchor.href = reportUrl;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  URL.revokeObjectURL(reportUrl);
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