const API_BASE = import.meta.env.VITE_API_URL ?? "";

export function getApiBaseUrl(): string {
  return API_BASE.replace(/\/$/, "");
}

export function apiUrl(path: string): string {
  const base = getApiBaseUrl();
  const normalized = path.startsWith("/") ? path : `/${path}`;
  return base ? `${base}${normalized}` : normalized;
}
