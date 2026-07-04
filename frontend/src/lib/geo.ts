import type { DashboardData } from '@/types/data';

export interface GeoPoint {
  id: string;
  label: string;
  countryCode: string;
  city?: string;
  lat: number;
  lng: number;
  assetCount: number;
  cveCount: number;
  maxCvss: number;
}

const COUNTRY_NAMES: Record<string, string> = {
  US: 'United States',
  GB: 'United Kingdom',
  DE: 'Germany',
  FR: 'France',
  CA: 'Canada',
  AU: 'Australia',
  NL: 'Netherlands',
  JP: 'Japan',
  CN: 'China',
  IN: 'India',
  BR: 'Brazil',
  SG: 'Singapore',
  IE: 'Ireland',
  SE: 'Sweden',
  CH: 'Switzerland',
  MX: 'Mexico',
  IT: 'Italy',
  ES: 'Spain',
  KR: 'South Korea',
};

const COUNTRY_ALIASES: Record<string, string> = {
  USA: 'US',
  'U.S.': 'US',
  'U.S.A.': 'US',
  'UNITED STATES': 'US',
  'UNITED STATES OF AMERICA': 'US',
  UK: 'GB',
  'GREAT BRITAIN': 'GB',
  'UNITED KINGDOM': 'GB',
  ENGLAND: 'GB',
  DEUTSCHLAND: 'DE',
  GERMANY: 'DE',
  FRANCE: 'FR',
  CANADA: 'CA',
  AUSTRALIA: 'AU',
  NETHERLANDS: 'NL',
  HOLLAND: 'NL',
  JAPAN: 'JP',
  CHINA: 'CN',
  INDIA: 'IN',
  BRAZIL: 'BR',
  SINGAPORE: 'SG',
  IRELAND: 'IE',
  SWEDEN: 'SE',
  SWITZERLAND: 'CH',
  MEXICO: 'MX',
  ITALY: 'IT',
  SPAIN: 'ES',
  'SOUTH KOREA': 'KR',
  KOREA: 'KR',
};

const COUNTRY_COORDS: Record<string, [number, number]> = {
  US: [39.8, -98.5],
  GB: [54.0, -2.5],
  DE: [51.2, 10.5],
  FR: [46.2, 2.2],
  CA: [56.1, -106.3],
  AU: [-25.3, 133.8],
  NL: [52.1, 5.3],
  JP: [36.2, 138.3],
  CN: [35.9, 104.2],
  IN: [20.6, 78.9],
  BR: [-14.2, -51.9],
  SG: [1.35, 103.8],
  IE: [53.4, -8.2],
  SE: [60.1, 18.6],
  CH: [46.8, 8.2],
  MX: [23.6, -102.5],
  IT: [41.9, 12.6],
  ES: [40.5, -3.7],
  KR: [36.5, 127.9],
};

const CITY_COORDS: Record<string, [number, number]> = {
  'Fresno,US': [36.74, -119.79],
  'Los Angeles,US': [34.05, -118.24],
  'San Francisco,US': [37.77, -122.42],
  'San Jose,US': [37.34, -121.89],
  'Sacramento,US': [38.58, -121.49],
  'Oakland,US': [37.8, -122.27],
  'San Diego,US': [32.72, -117.16],
  'Seattle,US': [47.61, -122.33],
  'Chicago,US': [41.88, -87.63],
  'Dallas,US': [32.78, -96.8],
  'Houston,US': [29.76, -95.37],
  'Miami,US': [25.76, -80.19],
  'Atlanta,US': [33.75, -84.39],
  'Denver,US': [39.74, -104.99],
  'Phoenix,US': [33.45, -112.07],
  'New York,US': [40.71, -74.0],
  'Washington,US': [38.91, -77.04],
  'London,GB': [51.51, -0.13],
  'Frankfurt,DE': [50.11, 8.68],
  'Paris,FR': [48.86, 2.35],
  'Toronto,CA': [43.65, -79.38],
  'Sydney,AU': [-33.87, 151.21],
  'Singapore,SG': [1.35, 103.82],
};

const FULL_VIEWBOX = '0 0 360 180';

/** Normalize country values from Shodan (US, United States, etc.) to ISO-2. */
export function normalizeCountryCode(raw?: string | null): string | null {
  if (!raw?.trim()) return null;

  const upper = raw.trim().toUpperCase();
  if (upper === 'XX' || upper === 'UNKNOWN' || upper === 'N/A') return null;

  if (upper.length === 2 && COUNTRY_COORDS[upper]) return upper;
  if (COUNTRY_ALIASES[upper]) return COUNTRY_ALIASES[upper];

  for (const [code, name] of Object.entries(COUNTRY_NAMES)) {
    if (name.toUpperCase() === upper) return code;
  }

  if (upper.length === 2) return upper;

  return null;
}

export function countryLabel(code: string): string {
  const normalized = normalizeCountryCode(code) ?? code.toUpperCase();
  return COUNTRY_NAMES[normalized] ?? normalized;
}

export function formatIpLocation(city?: string, countryRaw?: string): string {
  const code = normalizeCountryCode(countryRaw);
  const country = code ? countryLabel(code) : countryRaw?.trim();
  const place = city?.trim();

  if (place && country) return `${place}, ${country}`;
  if (place) return place;
  if (country) return country;
  return '';
}

function titleCaseCity(city: string): string {
  return city
    .trim()
    .split(/\s+/)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
    .join(' ');
}

function lookupCityCoords(city: string, countryCode: string): [number, number] | null {
  const normalizedCity = titleCaseCity(city);
  const target = `${normalizedCity},${countryCode}`.toLowerCase();

  for (const [key, coords] of Object.entries(CITY_COORDS)) {
    if (key.toLowerCase() === target) return coords;
  }

  return null;
}

function resolveCoords(countryCode: string, city?: string): [number, number] | null {
  const code = normalizeCountryCode(countryCode);
  if (!code) return null;

  if (city?.trim()) {
    const cityCoords = lookupCityCoords(city, code);
    if (cityCoords) return cityCoords;
  }

  return COUNTRY_COORDS[code] ?? null;
}

/** Equirectangular projection for SVG map (viewBox 0 0 360 180). */
export function project(lat: number, lng: number): { x: number; y: number } {
  return {
    x: lng + 180,
    y: 90 - lat,
  };
}

export function computeMapViewBox(points: GeoPoint[]): { viewBox: string; zoomed: boolean } {
  if (points.length === 0) return { viewBox: FULL_VIEWBOX, zoomed: false };

  const projected = points.map((p) => project(p.lat, p.lng));
  const minX = Math.min(...projected.map((p) => p.x));
  const maxX = Math.max(...projected.map((p) => p.x));
  const minY = Math.min(...projected.map((p) => p.y));
  const maxY = Math.max(...projected.map((p) => p.y));

  const spreadX = maxX - minX;
  const spreadY = maxY - minY;

  if (spreadX > 95 || spreadY > 65 || points.length > 10) {
    return { viewBox: FULL_VIEWBOX, zoomed: false };
  }

  const padX = Math.max(14, spreadX * 0.4 + 10);
  const padY = Math.max(12, spreadY * 0.4 + 8);

  let x = minX - padX;
  let y = minY - padY;
  let w = spreadX + padX * 2;
  let h = spreadY + padY * 2;

  if (points.length === 1) {
    w = Math.max(w, 36);
    h = Math.max(h, 28);
    x = projected[0].x - w / 2;
    y = projected[0].y - h / 2;
  }

  x = Math.max(0, x);
  y = Math.max(0, y);
  w = Math.min(360 - x, w);
  h = Math.min(180 - y, h);

  return {
    viewBox: `${x.toFixed(1)} ${y.toFixed(1)} ${w.toFixed(1)} ${h.toFixed(1)}`,
    zoomed: true,
  };
}

export function countUnlocatedVulnerableIps(data: DashboardData): number {
  return data.ips.filter(
    (ip) => ip.cves.length > 0 && !normalizeCountryCode(ip.country),
  ).length;
}

export function buildGeoPoints(data: DashboardData): GeoPoint[] {
  const buckets = new Map<string, GeoPoint>();

  for (const ip of data.ips.filter((item) => item.cves.length > 0)) {
    const countryCode = normalizeCountryCode(ip.country);
    if (!countryCode) continue;

    const city = ip.city?.trim() ? titleCaseCity(ip.city) : undefined;
    const coords = resolveCoords(countryCode, city);
    if (!coords) continue;

    const [lat, lng] = coords;
    const key = `${countryCode}::${city ?? ''}`;
    const maxCvss = Math.max(...ip.cves.map((c) => c.score));

    const existing = buckets.get(key);
    if (existing) {
      existing.assetCount += 1;
      existing.cveCount += ip.cves.length;
      existing.maxCvss = Math.max(existing.maxCvss, maxCvss);
    } else {
      buckets.set(key, {
        id: key,
        label: city ? `${city}, ${countryLabel(countryCode)}` : countryLabel(countryCode),
        countryCode,
        city,
        lat,
        lng,
        assetCount: 1,
        cveCount: ip.cves.length,
        maxCvss,
      });
    }
  }

  return [...buckets.values()].sort((a, b) => b.cveCount - a.cveCount);
}

export function findIpsForGeoPoint(data: DashboardData, point: GeoPoint): string[] {
  return data.ips
    .filter((ip) => {
      const code = normalizeCountryCode(ip.country);
      if (!code || code !== point.countryCode) return false;
      if (point.city) {
        const city = ip.city?.trim() ? titleCaseCity(ip.city) : undefined;
        if (city !== point.city) return false;
      }
      return ip.cves.length > 0;
    })
    .map((ip) => ip.ip);
}
