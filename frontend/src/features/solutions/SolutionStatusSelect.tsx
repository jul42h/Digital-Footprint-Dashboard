import type { SolutionStatus } from '@/types';
import { useRemediation } from '@/context/RemediationContext';
import { SOLUTION_STATUS_ORDER } from '@/lib/remediationConfig';

interface SolutionStatusSelectProps {
  solutionId: string;
  status: SolutionStatus;
  compact?: boolean;
}

export function SolutionStatusSelect({ solutionId, status, compact = false }: SolutionStatusSelectProps) {
  const { getStatusLabel, setSolutionStatus } = useRemediation();

  return (
    <label
      className={`status-select-wrap${compact ? ' status-select-wrap--compact' : ''}`}
      title="Change remediation status"
      onClick={(e) => e.stopPropagation()}
    >
      <span className="status-select-wrap__hint">Status</span>
      <select
        className={`status-select status-select--${status}${compact ? ' status-select--compact' : ''}`}
        value={status}
        aria-label="Change remediation status"
        onClick={(e) => e.stopPropagation()}
        onChange={(e) => {
          e.stopPropagation();
          setSolutionStatus(solutionId, e.target.value as SolutionStatus);
        }}
      >
        {SOLUTION_STATUS_ORDER.map((option) => (
          <option key={option} value={option}>
            {getStatusLabel(option)}
          </option>
        ))}
      </select>
    </label>
  );
}
