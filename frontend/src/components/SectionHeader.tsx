interface SectionHeaderProps {
  id?: string;
  title: string;
  description?: string;
}

export function SectionHeader({ id, title, description }: SectionHeaderProps) {
  return (
    <div className="section-header">
      <h2 id={id} className="section-header__title">{title}</h2>
      {description && <p className="section-header__desc">{description}</p>}
    </div>
  );
}
