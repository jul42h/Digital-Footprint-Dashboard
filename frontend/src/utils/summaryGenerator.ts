import type { DashboardStats } from '@/types/data';

/**
 * Whole-footprint risk score, 0–100.
 *
 * Mirrors the weighted-driver model the analyzer Lambda uses for its
 * `risk_score` (RISK_WEIGHTS / RISK_RATINGS in
 * footprint-api/ask_ai/lambda_ai_risk_analyzer.py) so the home ring and the
 * AI risk score tell one story. The numbers can still differ: the Lambda
 * scores the top-ranked findings sample it receives, while this scores every
 * finding in the footprint.
 */
const RISK_WEIGHTS = { exploitation: 0.45, severity: 0.35, exposure: 0.2 } as const;

/** This many vulnerable assets saturates the exposure driver (Lambda EXPOSURE_SATURATION_ASSETS). */
const EXPOSURE_SATURATION_ASSETS = 10;

const SEVERITY_POINTS = { critical: 100, high: 75, medium: 45, low: 15 } as const;

type RiskRating = 'Critical' | 'High' | 'Elevated' | 'Moderate' | 'Low';

/** Score → rating, matching Lambda RISK_RATINGS so both surfaces share one vocabulary. */
export function riskRatingLabel(score: number): RiskRating {
  if (score >= 90) return 'Critical';
  if (score >= 75) return 'High';
  if (score >= 50) return 'Elevated';
  if (score >= 25) return 'Moderate';
  return 'Low';
}

export function computeNetworkRiskScore(
  stats: DashboardStats,
  maxEpss?: number | null,
): number {
  if (stats.totalCVEs === 0) return 0;

  const drivers: Array<{ weight: number; score: number }> = [];

  // Exploitation: known exploitation outranks predicted exploitation.
  if (stats.kevFindings > 0) {
    drivers.push({
      weight: RISK_WEIGHTS.exploitation,
      score: 70 + 30 * (stats.kevFindings / stats.totalCVEs),
    });
  } else if (maxEpss != null) {
    drivers.push({ weight: RISK_WEIGHTS.exploitation, score: 100 * maxEpss });
  }

  // Severity: the CVSS mix across scored findings (informational counts as low).
  const lowBucket = stats.lowCVEs + stats.informationalCVEs;
  const scored = stats.criticalCVEs + stats.highCVEs + stats.mediumCVEs + lowBucket;
  if (scored > 0) {
    drivers.push({
      weight: RISK_WEIGHTS.severity,
      score:
        (stats.criticalCVEs * SEVERITY_POINTS.critical +
          stats.highCVEs * SEVERITY_POINTS.high +
          stats.mediumCVEs * SEVERITY_POINTS.medium +
          lowBucket * SEVERITY_POINTS.low) /
        scored,
    });
  }

  // Exposure: how much of the estate carries findings. Every host here is an
  // internet-facing Shodan observation, so asset spread is the proxy.
  if (stats.vulnerableIPs > 0) {
    drivers.push({
      weight: RISK_WEIGHTS.exposure,
      score: 100 * Math.min(1, stats.vulnerableIPs / EXPOSURE_SATURATION_ASSETS),
    });
  }

  if (drivers.length === 0) return 0;

  // A driver with no data is dropped and the remaining weights renormalized,
  // same as the Lambda.
  const totalWeight = drivers.reduce((sum, d) => sum + d.weight, 0);
  const score = drivers.reduce((sum, d) => sum + d.score * d.weight, 0) / totalWeight;
  return Math.max(0, Math.min(100, Math.round(score)));
}
