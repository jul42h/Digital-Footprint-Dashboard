import type { SolutionStatus as Status } from '@/types';
import { useRemediation } from '@/context/RemediationContext';

export function SolutionStatus({ status }: { status: Status }) {
  const { getStatusLabel } = useRemediation();
  return <span className={`status status--${status}`}>{getStatusLabel(status)}</span>;
}
