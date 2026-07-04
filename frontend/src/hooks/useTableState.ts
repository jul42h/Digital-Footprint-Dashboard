import { useMemo, useState } from "react";

export type SortDirection = "asc" | "desc";

export interface SortState<K extends string> {
  key: K;
  direction: SortDirection;
}

interface UseTableStateOptions<T, K extends string> {
  items: T[];
  defaultSort: SortState<K>;
  getSortValue: (item: T, key: K) => string | number;
  search?: (item: T, query: string) => boolean;
  limit?: number;
}

export function useTableState<T, K extends string>({
  items,
  defaultSort,
  getSortValue,
  search,
  limit,
}: UseTableStateOptions<T, K>) {
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState<SortState<K>>(defaultSort);

  const rows = useMemo(() => {
    let list = items;
    const trimmed = query.trim().toLowerCase();

    if (trimmed && search) {
      list = list.filter((item) => search(item, trimmed));
    }

    const sorted = [...list].sort((a, b) => {
      const av = getSortValue(a, sort.key);
      const bv = getSortValue(b, sort.key);
      const cmp =
        typeof av === "number" && typeof bv === "number"
          ? av - bv
          : String(av).localeCompare(String(bv), undefined, { numeric: true, sensitivity: "base" });
      return sort.direction === "asc" ? cmp : -cmp;
    });

    return limit ? sorted.slice(0, limit) : sorted;
  }, [items, query, search, sort, getSortValue, limit]);

  const toggleSort = (key: K) => {
    setSort((prev) =>
      prev.key === key
        ? { key, direction: prev.direction === "asc" ? "desc" : "asc" }
        : { key, direction: "desc" },
    );
  };

  return {
    query,
    setQuery,
    sort,
    toggleSort,
    rows,
    total: items.length,
    shown: rows.length,
  };
}
