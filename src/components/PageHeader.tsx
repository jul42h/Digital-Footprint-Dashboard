interface PageHeaderProps {
  title: string;
  subtitle?: string;
}

export function PageHeader({ title, subtitle }: PageHeaderProps) {
  return (
    <header style={{ marginBottom: 4 }}>
      <h1 style={{ fontSize: 22, fontWeight: 600, letterSpacing: "-0.02em" }}>{title}</h1>
      {subtitle && (
        <p style={{ margin: "6px 0 0", fontSize: 14, color: "var(--text-secondary)", maxWidth: 680, lineHeight: 1.5 }}>
          {subtitle}
        </p>
      )}
    </header>
  );
}
