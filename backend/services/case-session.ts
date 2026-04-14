import fs from 'node:fs/promises';
import path from 'node:path';

import { caseSessionSchema, type CaseSession, type CaseSessionSummary } from '../../shared/analysis-types.js';
import { ensureStorageDirectories } from '../storage.js';

export async function getCurrentCaseSession() {
  try {
    const rawCase = await fs.readFile(getCurrentCaseSessionPath(), 'utf8');
    return caseSessionSchema.parse(JSON.parse(rawCase));
  } catch (error) {
    if (isMissingFileError(error)) {
      return null;
    }

    throw error;
  }
}

export async function saveCurrentCaseSession(caseSession: CaseSession) {
  const validatedCaseSession = caseSessionSchema.parse({
    ...caseSession,
    updatedAt: new Date().toISOString(),
  });
  const targetPath = getCurrentCaseSessionPath();
  const archivedPath = getCaseSessionPath(validatedCaseSession.caseId);

  await fs.mkdir(path.dirname(targetPath), { recursive: true });
  await fs.writeFile(targetPath, JSON.stringify(validatedCaseSession, null, 2), 'utf8');
  await fs.writeFile(archivedPath, JSON.stringify(validatedCaseSession, null, 2), 'utf8');

  return validatedCaseSession;
}

export async function listCaseSessions() {
  const casesDirectory = getCasesDirectoryPath();

  try {
    const entries = await fs.readdir(casesDirectory, { withFileTypes: true });
    const caseFiles = entries.filter((entry) => entry.isFile() && entry.name.endsWith('.json') && entry.name !== 'current.json');
    const cases = await Promise.all(
      caseFiles.map(async (entry) => {
        const rawCase = await fs.readFile(path.join(casesDirectory, entry.name), 'utf8');
        return caseSessionSchema.parse(JSON.parse(rawCase));
      }),
    );

    return cases
      .map(toCaseSessionSummary)
      .sort((left, right) => right.updatedAt.localeCompare(left.updatedAt));
  } catch (error) {
    if (isMissingFileError(error)) {
      return [] satisfies CaseSessionSummary[];
    }

    throw error;
  }
}

export async function getCaseSession(caseId: string) {
  try {
    const rawCase = await fs.readFile(getCaseSessionPath(caseId), 'utf8');
    return caseSessionSchema.parse(JSON.parse(rawCase));
  } catch (error) {
    if (isMissingFileError(error)) {
      return null;
    }

    throw error;
  }
}

export async function clearCurrentCaseSession() {
  try {
    await fs.rm(getCurrentCaseSessionPath(), { force: true });
  } catch (error) {
    if (!isMissingFileError(error)) {
      throw error;
    }
  }
}

export async function deleteCaseSession(caseId: string) {
  try {
    const archivedCasePath = getCaseSessionPath(caseId);
    const currentCaseSession = await getCurrentCaseSession();

    await fs.rm(archivedCasePath, { force: true });
    if (currentCaseSession?.caseId === caseId) {
      await clearCurrentCaseSession();
    }
  } catch (error) {
    if (!isMissingFileError(error)) {
      throw error;
    }
  }
}

function getCurrentCaseSessionPath() {
  return path.join(getCasesDirectoryPath(), 'current.json');
}

function getCaseSessionPath(caseId: string) {
  return path.join(getCasesDirectoryPath(), `${sanitizeCaseId(caseId)}.json`);
}

function getCasesDirectoryPath() {
  const storagePaths = ensureStorageDirectories();
  return path.join(storagePaths.reports, 'cases');
}

function sanitizeCaseId(caseId: string) {
  return caseId.replace(/[^a-z0-9_-]/gi, '_');
}

function toCaseSessionSummary(caseSession: CaseSession): CaseSessionSummary {
  return {
    caseId: caseSession.caseId,
    startedAt: caseSession.startedAt,
    updatedAt: caseSession.updatedAt,
    activeTab: caseSession.activeTab,
    visitedTabs: caseSession.visitedTabs,
    eventCount: caseSession.events.length,
  };
}

function isMissingFileError(error: unknown) {
  return error instanceof Error && 'code' in error && error.code === 'ENOENT';
}