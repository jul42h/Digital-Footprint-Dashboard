export function parseDate(value: string | undefined): Date | null {
  if (!value) return null;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

export function formatDate(value: string | undefined): string {
  const date = parseDate(value);
  if (!date) return '—';
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
}

export function toMonthKey(value: string | undefined): string | null {
  const date = parseDate(value);
  if (!date) return null;
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}`;
}

export function formatMonthKey(key: string): string {
  const [year, month] = key.split('-');
  const date = new Date(Number(year), Number(month) - 1);
  return date.toLocaleDateString('en-US', { year: 'numeric', month: 'short' });
}

export function formatDayKey(isoDay: string): string {
  const [year, month, day] = isoDay.split('-').map(Number);
  const date = new Date(year, month - 1, day);
  return date.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
}

export function formatShortDay(isoDay: string): string {
  const [year, month, day] = isoDay.split('-').map(Number);
  const date = new Date(year, month - 1, day);
  return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

export function formatHourLabel(hour: number): string {
  const date = new Date();
  date.setHours(hour, 0, 0, 0);
  return date.toLocaleTimeString('en-US', { hour: 'numeric' });
}

export function toDayKey(date: Date): string {
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`;
}
