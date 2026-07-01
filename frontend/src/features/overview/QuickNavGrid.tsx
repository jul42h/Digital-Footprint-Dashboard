import { Link } from "react-router-dom";
import { Card } from "@/components/Card";
import { useHomeInsights } from "./homeHooks";

export function QuickNavGrid() {
  const insights = useHomeInsights();

  return (
    <Card title="Explore in detail">
      <div className="dashboard-nav">
        {insights.map((item) => (
          <Link key={item.to} to={item.to} className="dashboard-nav__item">
            <span className="dashboard-nav__label">{item.title}</span>
            <span className="dashboard-nav__value">{item.value}</span>
            <span className="dashboard-nav__detail">{item.detail}</span>
            <span className="dashboard-nav__link">Open →</span>
          </Link>
        ))}
      </div>
    </Card>
  );
}
