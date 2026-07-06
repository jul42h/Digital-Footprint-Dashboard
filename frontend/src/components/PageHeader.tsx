import type { ReactNode } from "react";

interface PageHeaderProps {
  title: string;
  subtitle?: string;
  eyebrow?: string;
  action?: ReactNode;
}

export function PageHeader({ title, subtitle, eyebrow, action }: PageHeaderProps) {
  return (
    <header className="page-header">
      {eyebrow && <span className="page-header__eyebrow">{eyebrow}</span>}
      <div className="page-header__row">
        <div>
          <h1 className="page-header__title">{title}</h1>
          {subtitle && <p className="page-header__subtitle">{subtitle}</p>}
        </div>
        {action && <div className="page-header__action">{action}</div>}
      </div>
    </header>
  );
}
