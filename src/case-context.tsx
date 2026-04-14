import React, { createContext, useContext } from 'react';

import type { CaseEvent, CaseEventSeverity, CaseEventTool, CaseSession } from '../shared/analysis-types';

export type { CaseEvent, CaseEventSeverity, CaseEventTool };

export type CaseContextValue = {
  caseId: string;
  events: CaseEvent[];
  addCaseEvent: (event: Omit<CaseEvent, 'id' | 'occurredAt'>) => void;
};

export type PersistedCaseSession = CaseSession;

const defaultCaseContextValue: CaseContextValue = {
  caseId: 'CASE-UNSCOPED',
  events: [],
  addCaseEvent: () => {
    return;
  },
};

const CaseContext = createContext<CaseContextValue>(defaultCaseContextValue);

export function CaseContextProvider({ value, children }: { value: CaseContextValue; children: React.ReactNode }) {
  return <CaseContext.Provider value={value}>{children}</CaseContext.Provider>;
}

export function useCaseContext() {
  return useContext(CaseContext);
}