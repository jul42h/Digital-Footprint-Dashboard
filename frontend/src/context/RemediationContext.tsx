import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from 'react';
import type { CveSolution, SolutionStatus } from '@/types';
import {
  DEFAULT_PENDING_STATUSES,
  DEFAULT_STATUS_LABELS,
  emptyRemediationState,
  isSolutionStatus,
  REMEDIATION_STORAGE_KEY,
  resolvePendingStatuses,
  resolveStatusLabels,
  type RemediationPersistedState,
} from '@/lib/remediationConfig';

interface RemediationContextValue {
  statusLabels: Record<SolutionStatus, string>;
  pendingStatuses: SolutionStatus[];
  getStatusLabel: (status: SolutionStatus) => string;
  isPendingStatus: (status: SolutionStatus) => boolean;
  setStatusLabel: (status: SolutionStatus, label: string) => void;
  resetStatusLabels: () => void;
  togglePendingStatus: (status: SolutionStatus) => void;
  resetPendingStatuses: () => void;
  setSolutionStatus: (solutionId: string, status: SolutionStatus) => void;
  clearSolutionStatus: (solutionId: string) => void;
  applyOverrides: (solutions: CveSolution[]) => CveSolution[];
}

const RemediationContext = createContext<RemediationContextValue | null>(null);

function readStoredState(): RemediationPersistedState {
  try {
    const raw = localStorage.getItem(REMEDIATION_STORAGE_KEY);
    if (!raw) return emptyRemediationState();
    const parsed = JSON.parse(raw) as Partial<RemediationPersistedState>;
    const statusOverrides: Record<string, SolutionStatus> = {};
    for (const [id, status] of Object.entries(parsed.statusOverrides ?? {})) {
      if (isSolutionStatus(status)) statusOverrides[id] = status;
    }
    const labelOverrides: Partial<Record<SolutionStatus, string>> = {};
    for (const [key, label] of Object.entries(parsed.labelOverrides ?? {})) {
      if (isSolutionStatus(key) && typeof label === 'string' && label.trim()) {
        labelOverrides[key] = label.trim();
      }
    }
    const pendingStatuses = (parsed.pendingStatuses ?? []).filter(isSolutionStatus);
    return {
      statusOverrides,
      labelOverrides,
      pendingStatuses: pendingStatuses.length ? pendingStatuses : undefined,
    };
  } catch {
    return emptyRemediationState();
  }
}

function writeStoredState(state: RemediationPersistedState) {
  try {
    localStorage.setItem(REMEDIATION_STORAGE_KEY, JSON.stringify(state));
  } catch {
    // localStorage unavailable
  }
}

export function RemediationProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<RemediationPersistedState>(readStoredState);

  const persist = useCallback((updater: (prev: RemediationPersistedState) => RemediationPersistedState) => {
    setState((prev) => {
      const next = updater(prev);
      writeStoredState(next);
      return next;
    });
  }, []);

  const statusLabels = useMemo(
    () => resolveStatusLabels(state.labelOverrides),
    [state.labelOverrides],
  );

  const pendingStatuses = useMemo(
    () => resolvePendingStatuses(state.pendingStatuses),
    [state.pendingStatuses],
  );

  const getStatusLabel = useCallback(
    (status: SolutionStatus) => statusLabels[status] ?? DEFAULT_STATUS_LABELS[status],
    [statusLabels],
  );

  const isPendingStatus = useCallback(
    (status: SolutionStatus) => pendingStatuses.includes(status),
    [pendingStatuses],
  );

  const setStatusLabel = useCallback(
    (status: SolutionStatus, label: string) => {
      const trimmed = label.trim();
      persist((prev) => {
        const labelOverrides = { ...prev.labelOverrides };
        if (!trimmed || trimmed === DEFAULT_STATUS_LABELS[status]) {
          delete labelOverrides[status];
        } else {
          labelOverrides[status] = trimmed;
        }
        return { ...prev, labelOverrides };
      });
    },
    [persist],
  );

  const resetStatusLabels = useCallback(() => {
    persist((prev) => ({ ...prev, labelOverrides: {} }));
  }, [persist]);

  const togglePendingStatus = useCallback(
    (status: SolutionStatus) => {
      persist((prev) => {
        const current = resolvePendingStatuses(prev.pendingStatuses);
        const next = current.includes(status)
          ? current.filter((item) => item !== status)
          : [...current, status];
        const isDefault =
          next.length === DEFAULT_PENDING_STATUSES.length &&
          DEFAULT_PENDING_STATUSES.every((item) => next.includes(item));
        return {
          ...prev,
          pendingStatuses: isDefault ? undefined : next,
        };
      });
    },
    [persist],
  );

  const resetPendingStatuses = useCallback(() => {
    persist((prev) => ({ ...prev, pendingStatuses: undefined }));
  }, [persist]);

  const setSolutionStatus = useCallback(
    (solutionId: string, status: SolutionStatus) => {
      persist((prev) => ({
        ...prev,
        statusOverrides: { ...prev.statusOverrides, [solutionId]: status },
      }));
    },
    [persist],
  );

  const clearSolutionStatus = useCallback(
    (solutionId: string) => {
      persist((prev) => {
        const statusOverrides = { ...prev.statusOverrides };
        delete statusOverrides[solutionId];
        return { ...prev, statusOverrides };
      });
    },
    [persist],
  );

  const applyOverrides = useCallback(
    (solutions: CveSolution[]) =>
      solutions.map((solution) => {
        const override = state.statusOverrides[solution.id];
        return override ? { ...solution, status: override } : solution;
      }),
    [state.statusOverrides],
  );

  const value = useMemo(
    () => ({
      statusLabels,
      pendingStatuses,
      getStatusLabel,
      isPendingStatus,
      setStatusLabel,
      resetStatusLabels,
      togglePendingStatus,
      resetPendingStatuses,
      setSolutionStatus,
      clearSolutionStatus,
      applyOverrides,
    }),
    [
      statusLabels,
      pendingStatuses,
      getStatusLabel,
      isPendingStatus,
      setStatusLabel,
      resetStatusLabels,
      togglePendingStatus,
      resetPendingStatuses,
      setSolutionStatus,
      clearSolutionStatus,
      applyOverrides,
    ],
  );

  return <RemediationContext.Provider value={value}>{children}</RemediationContext.Provider>;
}

export function useRemediation(): RemediationContextValue {
  const ctx = useContext(RemediationContext);
  if (!ctx) throw new Error('useRemediation must be used within RemediationProvider');
  return ctx;
}
