import type { SolutionStatus } from '@/types';

export const REMEDIATION_STORAGE_KEY = 'df-remediation-v1';

export const SOLUTION_STATUS_ORDER: SolutionStatus[] = ['open', 'triage', 'assigned', 'resolved'];

export const DEFAULT_STATUS_LABELS: Record<SolutionStatus, string> = {
  open: 'Not started',
  triage: 'Under review',
  assigned: 'In progress',
  resolved: 'Done',
};

export const STATUS_COLORS: Record<SolutionStatus, string> = {
  open: 'var(--sev-critical)',
  triage: 'var(--sev-medium)',
  assigned: 'var(--accent)',
  resolved: 'var(--status-resolved)',
};

/** Default statuses counted as pending in posture metrics and the remediation donut. */
export const DEFAULT_PENDING_STATUSES: SolutionStatus[] = ['open', 'triage'];

export const STATUS_RANK: Record<SolutionStatus, number> = {
  open: 0,
  triage: 1,
  assigned: 2,
  resolved: 3,
};

export interface RemediationPersistedState {
  statusOverrides: Record<string, SolutionStatus>;
  labelOverrides: Partial<Record<SolutionStatus, string>>;
  pendingStatuses?: SolutionStatus[];
}

export function emptyRemediationState(): RemediationPersistedState {
  return { statusOverrides: {}, labelOverrides: {} };
}

export function resolvePendingStatuses(overrides?: SolutionStatus[]): SolutionStatus[] {
  if (!overrides?.length) return [...DEFAULT_PENDING_STATUSES];
  return SOLUTION_STATUS_ORDER.filter((status) => overrides.includes(status));
}

export function isSolutionStatus(value: string): value is SolutionStatus {
  return SOLUTION_STATUS_ORDER.includes(value as SolutionStatus);
}

export function resolveStatusLabels(
  overrides: Partial<Record<SolutionStatus, string>>,
): Record<SolutionStatus, string> {
  return { ...DEFAULT_STATUS_LABELS, ...overrides };
}
