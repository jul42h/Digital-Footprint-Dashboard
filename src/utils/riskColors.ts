import type { Severity } from '@/types';

export const SEVERITY_COLORS: Record<Severity, { bg: string; text: string; border: string; chart: string }> = {
  Critical: {
    bg: 'bg-red-500/15',
    text: 'text-red-400',
    border: 'border-red-500/40',
    chart: '#ef4444',
  },
  High: {
    bg: 'bg-orange-500/15',
    text: 'text-orange-400',
    border: 'border-orange-500/40',
    chart: '#f97316',
  },
  Medium: {
    bg: 'bg-yellow-500/15',
    text: 'text-yellow-400',
    border: 'border-yellow-500/40',
    chart: '#eab308',
  },
  Low: {
    bg: 'bg-blue-500/15',
    text: 'text-blue-400',
    border: 'border-blue-500/40',
    chart: '#3b82f6',
  },
  Informational: {
    bg: 'bg-slate-500/15',
    text: 'text-slate-400',
    border: 'border-slate-500/40',
    chart: '#64748b',
  },
};

export function getSeverityColor(severity: string) {
  return SEVERITY_COLORS[severity as Severity] ?? SEVERITY_COLORS.Informational;
}

export function getSeverityBadgeClass(severity: string) {
  const colors = getSeverityColor(severity);
  return `${colors.bg} ${colors.text} ${colors.border} border`;
}
