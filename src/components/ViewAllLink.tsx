import { Link } from "react-router-dom";
import { LABELS } from "@/lib/copy";

export function ViewAllLink({ to }: { to: string }) {
  return (
    <Link to={to} className="view-all-link">
      {LABELS.viewAll} →
    </Link>
  );
}
