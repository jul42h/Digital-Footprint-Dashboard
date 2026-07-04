import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Card } from "@/components/Card";
import { ViewAllLink } from "@/components/ViewAllLink";
import { FilterChip } from "@/components/TableToolbar";
import { useDashboard } from "@/context/DashboardContext";
import { HELP_TEXT } from "@/lib/copy";
import {
  buildGeoPoints,
  computeMapViewBox,
  countUnlocatedVulnerableIps,
  findIpsForGeoPoint,
  project,
  type GeoPoint,
} from "@/lib/geo";
import { cvssToSeverity, SEVERITY_LABEL, SEVERITY_ORDER } from "@/lib/severity";
import type { Severity } from "@/types";
import { WORLD_LAND_PATHS } from "@/lib/worldLandPaths";

const SEVERITY_DOT: Record<string, string> = {
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
};

function markerRadius(cveCount: number, maxCves: number, zoomed: boolean): number {
  const t = Math.sqrt(cveCount / maxCves);
  const base = zoomed ? 2.2 : 1.6;
  const range = zoomed ? 2.8 : 2;
  return base + t * range;
}

export function GeoExposureMap() {
  const navigate = useNavigate();
  const { data } = useDashboard();
  const allPoints = useMemo(() => buildGeoPoints(data), [data]);
  const unlocatedCount = useMemo(() => countUnlocatedVulnerableIps(data), [data]);
  const [severityFilter, setSeverityFilter] = useState<Severity | "all">("all");

  const points = useMemo(() => {
    if (severityFilter === "all") return allPoints;
    return allPoints.filter((point) => cvssToSeverity(point.maxCvss) === severityFilter);
  }, [allPoints, severityFilter]);

  const maxCves = Math.max(...points.map((p) => p.cveCount), 1);
  const { viewBox, zoomed } = useMemo(() => computeMapViewBox(points), [points]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const active = points.find((p) => p.id === activeId) ?? points[0];

  useEffect(() => {
    setActiveId(points[0]?.id ?? null);
  }, [points]);

  const openLocation = (point: GeoPoint) => {
    const ips = findIpsForGeoPoint(data, point);
    if (ips.length === 1) {
      navigate(`/ips/${encodeURIComponent(ips[0])}`);
    } else {
      navigate("/ips");
    }
  };

  return (
    <Card
      title="Vulnerability locations"
      className={`chart-card geo-map-card${zoomed ? " geo-map-card--zoomed" : ""}`}
      action={
        points.length > 0 ? (
          <span className="geo-map__meta-badge">
            {points.length} location{points.length !== 1 ? "s" : ""}
          </span>
        ) : (
          <ViewAllLink to="/ips" />
        )
      }
    >
      <p className="card-footnote card-footnote--tight">{HELP_TEXT.geoMap}</p>
      <div className="table-toolbar__filters" style={{ marginBottom: 10 }}>
        <FilterChip active={severityFilter === "all"} onClick={() => setSeverityFilter("all")}>
          All severities
        </FilterChip>
        {SEVERITY_ORDER.map((s) => (
          <FilterChip key={s} active={severityFilter === s} onClick={() => setSeverityFilter(s)}>
            {SEVERITY_LABEL[s]}
          </FilterChip>
        ))}
      </div>
      <div className="geo-map geo-map--compact">
        <div className="geo-map__canvas">
          <svg
            viewBox={viewBox}
            preserveAspectRatio="xMidYMid meet"
            className="geo-map__svg"
            role="img"
            aria-label="Map of vulnerability locations by country and city"
          >
            <rect x="-360" y="-180" width="1080" height="540" className="geo-map__ocean" />
            <g className="geo-map__landmass">
              {WORLD_LAND_PATHS.map((d, i) => (
                <path key={i} d={d} />
              ))}
            </g>
            {!zoomed && (
              <line x1={0} y1={90} x2={360} y2={90} className="geo-map__equator" />
            )}
            {points.map((point) => {
              const { x, y } = project(point.lat, point.lng);
              const r = markerRadius(point.cveCount, maxCves, zoomed);
              const sev = cvssToSeverity(point.maxCvss);
              const isActive = point.id === activeId;
              const color = SEVERITY_DOT[sev];
              return (
                <g
                  key={point.id}
                  className={`geo-map__point${isActive ? " geo-map__point--active" : ""}`}
                  onMouseEnter={() => setActiveId(point.id)}
                  onFocus={() => setActiveId(point.id)}
                  onClick={() => openLocation(point)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault();
                      openLocation(point);
                    }
                  }}
                  tabIndex={0}
                  role="link"
                  aria-label={`${point.label}: ${point.cveCount} vulnerabilities across ${point.assetCount} assets`}
                >
                  <title>
                    {point.label}: {point.cveCount} vulnerabilities · {point.assetCount} assets · highest CVSS {point.maxCvss.toFixed(1)}
                  </title>
                  {isActive && (
                    <circle cx={x} cy={y} r={r + 2.5} className="geo-map__halo" style={{ fill: color }} />
                  )}
                  <circle cx={x} cy={y} r={r + 1.2} fill="none" stroke={color} strokeWidth={0.6} opacity={0.85} />
                  <circle cx={x} cy={y} r={r * 0.45} fill={color} stroke="var(--surface)" strokeWidth={0.4} />
                </g>
              );
            })}
          </svg>
        </div>

        <div className="geo-map__aside">
          {points.length === 0 ? (
            <p className="geo-map__empty">{HELP_TEXT.geoMapEmpty}</p>
          ) : (
            <>
              <ul className="geo-map__list">
                {points.slice(0, 5).map((point) => {
                  const sev = cvssToSeverity(point.maxCvss);
                  const isActive = point.id === activeId;
                  return (
                    <li key={point.id}>
                      <button
                        type="button"
                        className={`geo-map__list-item${isActive ? " geo-map__list-item--active" : ""}`}
                        onMouseEnter={() => setActiveId(point.id)}
                        onClick={() => openLocation(point)}
                      >
                        <span className="geo-map__list-dot" style={{ background: SEVERITY_DOT[sev] }} />
                        <span className="geo-map__list-label">{point.label}</span>
                        <span className="geo-map__list-count">{point.cveCount}</span>
                      </button>
                    </li>
                  );
                })}
              </ul>
              {active && (
                <p className="geo-map__detail">
                  {active.assetCount} asset{active.assetCount !== 1 ? "s" : ""} · {active.cveCount} vulnerabilities · highest CVSS {active.maxCvss.toFixed(1)}
                </p>
              )}
            </>
          )}
        </div>
      </div>
      {unlocatedCount > 0 && (
        <p className="card-footnote card-footnote--tight">{HELP_TEXT.geoMapUnlocated(unlocatedCount)}</p>
      )}
    </Card>
  );
}
