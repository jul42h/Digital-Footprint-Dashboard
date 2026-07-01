import { cvssToSeverity, SEVERITY_COLOR } from "@/lib/severity";

export function CvssScore({ score }: { score: number }) {
  const severity = cvssToSeverity(score);
  return (
    <span
      style={{
        fontFamily: "var(--font-mono)",
        fontWeight: 500,
        fontSize: 13,
        color: SEVERITY_COLOR[severity],
      }}
    >
      {score.toFixed(1)}
    </span>
  );
}
