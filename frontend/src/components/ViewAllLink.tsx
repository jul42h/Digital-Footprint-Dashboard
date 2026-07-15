import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { LABELS } from "@/lib/copy";

export function ViewAllLink({
  to,
  className,
  children,
}: {
  to: string;
  className?: string;
  children?: ReactNode;
}) {
  return (
    <Link to={to} className={["view-all-link", className].filter(Boolean).join(" ")}>
      {children ?? LABELS.viewAll} →
    </Link>
  );
}
