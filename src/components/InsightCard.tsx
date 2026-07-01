import { Link } from "react-router-dom";

interface InsightCardProps {
  title: string;
  value: string;
  detail: string;
  to: string;
}

export function InsightCard({ title, value, detail, to }: InsightCardProps) {
  return (
    <Link to={to} className="insight-card">
      <p className="insight-card__label">{title}</p>
      <p className="insight-card__value">{value}</p>
      <p className="insight-card__detail">{detail}</p>
      <span className="insight-card__link">See details →</span>
    </Link>
  );
}
