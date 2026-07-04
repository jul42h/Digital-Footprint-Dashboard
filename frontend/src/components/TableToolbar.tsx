import type { ReactNode } from "react";

export interface TableSelectFilter {
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: Array<{ value: string; label: string }>;
}

interface TableToolbarProps {
  query: string;
  onQueryChange: (value: string) => void;
  shown: number;
  total: number;
  placeholder?: string;
  filters?: ReactNode;
  selects?: TableSelectFilter[];
}

export function TableToolbar({
  query,
  onQueryChange,
  shown,
  total,
  placeholder = "Search…",
  filters,
  selects,
}: TableToolbarProps) {
  const filtered = shown !== total;

  return (
    <div className="table-toolbar">
      <div className="table-toolbar__row">
        <label className="table-toolbar__search">
          <span className="sr-only">Search table</span>
          <input
            type="search"
            className="table-toolbar__input"
            value={query}
            onChange={(e) => onQueryChange(e.target.value)}
            placeholder={placeholder}
            aria-label="Search table"
          />
        </label>
        {selects?.map((select) => (
          <label key={select.label} className="table-toolbar__select-wrap">
            <span className="table-toolbar__select-label">{select.label}</span>
            <select
              className="table-toolbar__select"
              value={select.value}
              onChange={(e) => select.onChange(e.target.value)}
              aria-label={select.label}
            >
              {select.options.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </label>
        ))}
        <span className="table-toolbar__count" aria-live="polite">
          {filtered ? `${shown} of ${total}` : `${total} total`}
        </span>
      </div>
      {filters ? <div className="table-toolbar__filters">{filters}</div> : null}
    </div>
  );
}

export function FilterChip({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: ReactNode;
}) {
  return (
    <button
      type="button"
      className={`filter-chip${active ? " filter-chip--active" : ""}`}
      onClick={onClick}
      aria-pressed={active}
    >
      {children}
    </button>
  );
}
