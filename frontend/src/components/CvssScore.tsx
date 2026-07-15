import { cvssToSeverity, SEVERITY_COLOR } from "@/lib/severity";

export function CvssScore({ score }: { score: number }) {
  const severity = cvssToSeverity(score);
  return (
    <span
      className="mono"
      style={{
        fontWeight: 500,
        fontSize: 13,
        color: SEVERITY_COLOR[severity],
      }}
    >
      {score.toFixed(1)}
    </span>
  );
}
