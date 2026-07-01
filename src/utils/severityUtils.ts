import type { SourceSeverity } from '@/types/data';

export function scoreToSeverity(score: number): SourceSeverity {
  if (score >= 9.0) return 'Critical';
  if (score >= 7.0) return 'High';
  if (score >= 4.0) return 'Medium';
  if (score >= 0.1) return 'Low';
  return 'Informational';
}

export function normalizeSeverity(value: string | undefined): SourceSeverity {
  if (!value) return 'Informational';
  const normalized = value.trim().toLowerCase();
  if (normalized.startsWith('crit')) return 'Critical';
  if (normalized.startsWith('high')) return 'High';
  if (normalized.startsWith('med')) return 'Medium';
  if (normalized.startsWith('low')) return 'Low';
  if (normalized.startsWith('info')) return 'Informational';
  return scoreToSeverity(parseFloat(value) || 0);
}

export const SEVERITY_ORDER: Record<SourceSeverity, number> = {
  Critical: 5,
  High: 4,
  Medium: 3,
  Low: 2,
  Informational: 1,
};
