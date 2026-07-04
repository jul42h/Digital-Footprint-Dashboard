import type { SortDirection } from "@/hooks/useTableState";

interface SortableThProps<K extends string> {
  label: string;
  sortKey: K;
  activeKey: K;
  direction: SortDirection;
  onSort: (key: K) => void;
  style?: React.CSSProperties;
}

export function SortableTh<K extends string>({
  label,
  sortKey,
  activeKey,
  direction,
  onSort,
  style,
}: SortableThProps<K>) {
  const active = activeKey === sortKey;
  const indicator = active ? (direction === "asc" ? " ↑" : " ↓") : "";

  return (
    <th style={style}>
      <button
        type="button"
        className={`sortable-th${active ? " sortable-th--active" : ""}`}
        onClick={() => onSort(sortKey)}
        aria-sort={active ? (direction === "asc" ? "ascending" : "descending") : "none"}
      >
        {label}
        <span className="sortable-th__indicator" aria-hidden>
          {indicator}
        </span>
      </button>
    </th>
  );
}
