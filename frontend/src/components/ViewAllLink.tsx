import { Link } from "react-router-dom";
import { LABELS } from "@/lib/copy";

export function ViewAllLink({ to, className }: { to: string; className?: string }) {
  return (
    <Link to={to} className={["view-all-link", className].filter(Boolean).join(" ")}>
      {LABELS.viewAll} →
    </Link>
  );
}
