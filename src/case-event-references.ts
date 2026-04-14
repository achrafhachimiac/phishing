import type { CaseEventReference } from '../shared/analysis-types';

export function caseJobReference(label: string, jobId: string): CaseEventReference {
  return {
    kind: 'job',
    label,
    value: jobId,
  };
}

export function caseUrlReference(url: string, label = 'url'): CaseEventReference {
  return {
    kind: 'url',
    label,
    value: url,
    url,
  };
}

export function caseDomainReference(domain: string, label = 'domain'): CaseEventReference {
  return {
    kind: 'domain',
    label,
    value: domain,
  };
}

export function caseEmailReference(emailAddress: string, label = 'email'): CaseEventReference {
  return {
    kind: 'email',
    label,
    value: emailAddress,
  };
}

export function caseFileReference(filename: string, path?: string | null, url?: string | null, label = 'file'): CaseEventReference {
  return {
    kind: path ? 'artifact' : 'file',
    label,
    value: filename,
    path: path ?? null,
    url: url ?? null,
  };
}

export function caseSessionReference(sessionId: string, url?: string | null, label = 'session'): CaseEventReference {
  return {
    kind: 'session',
    label,
    value: sessionId,
    url: url ?? null,
  };
}