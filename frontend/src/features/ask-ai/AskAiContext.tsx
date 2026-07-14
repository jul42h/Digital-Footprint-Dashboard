import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

interface AskAiUiContextValue {
  open: boolean;
  setOpen: (open: boolean) => void;
  openWithCves: (cveIds: string[]) => void;
  pendingCveIds: string[] | null;
  consumePendingCveIds: () => string[] | null;
}

const AskAiUiContext = createContext<AskAiUiContextValue | null>(null);

export function AskAiProvider({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(false);
  const [pendingCveIds, setPendingCveIds] = useState<string[] | null>(null);

  const openWithCves = useCallback((cveIds: string[]) => {
    const unique = [...new Set(cveIds.map((id) => id.toUpperCase()).filter(Boolean))];
    setPendingCveIds(unique.length ? unique : null);
    setOpen(true);
  }, []);

  const consumePendingCveIds = useCallback(() => {
    const next = pendingCveIds;
    setPendingCveIds(null);
    return next;
  }, [pendingCveIds]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape" || !open) return;
      const tag = (e.target as HTMLElement)?.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA") return;
      setOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  const value = useMemo(
    () => ({
      open,
      setOpen,
      openWithCves,
      pendingCveIds,
      consumePendingCveIds,
    }),
    [open, openWithCves, pendingCveIds, consumePendingCveIds],
  );

  return <AskAiUiContext.Provider value={value}>{children}</AskAiUiContext.Provider>;
}

export function useAskAiUi() {
  const ctx = useContext(AskAiUiContext);
  if (!ctx) throw new Error("useAskAiUi must be used within AskAiProvider");
  return ctx;
}
