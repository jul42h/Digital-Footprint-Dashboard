import { pickPriorityCveIds } from "./cveSelection";
import { MAX_CVE_IDS_PER_REQUEST } from "./types";
import { useCves } from "@/features/cves/hooks";

export function CveQuickPicks({
  disabled,
  selectedIds,
  onToggle,
}: {
  disabled?: boolean;
  selectedIds: string[];
  onToggle: (cveId: string) => void;
}) {
  const cves = useCves();
  const picks = pickPriorityCveIds(cves, 5);

  if (picks.length === 0) return null;

  return (
    <div className="ask-ai-quick ask-ai-quick--compact" role="group" aria-label="Priority CVEs">
      {picks.map((id) => {
        const active = selectedIds.includes(id);
        const atCap = !active && selectedIds.length >= MAX_CVE_IDS_PER_REQUEST;
        return (
          <button
            key={id}
            type="button"
            className={`ask-ai-quick__btn${active ? " ask-ai-quick__btn--active" : ""}`}
            disabled={disabled || atCap}
            onClick={() => onToggle(id)}
            title={active ? "Remove" : "Add"}
          >
            {id}
          </button>
        );
      })}
    </div>
  );
}
