import type { ReactNode } from "react";

interface CardProps {
  title?: ReactNode;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
  style?: React.CSSProperties;
}

export function Card({ title, action, children, className, style }: CardProps) {
  const classes = ["card", className].filter(Boolean).join(" ");

  return (
    <section className={classes} style={style}>
      {(title || action) && (
        <header className="card__header">
          {title && <h3 className="card-title">{title}</h3>}
          {action && <div className="card__action">{action}</div>}
        </header>
      )}
      {children}
    </section>
  );
}
