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
  toggle: () => void;
  openWithPrompt: (prompt: string) => void;
  pendingPrompt: string | null;
  consumePendingPrompt: () => string | null;
}

const AskAiUiContext = createContext<AskAiUiContextValue | null>(null);

export function AskAiProvider({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(false);
  const [pendingPrompt, setPendingPrompt] = useState<string | null>(null);

  const toggle = useCallback(() => setOpen((v) => !v), []);

  const openWithPrompt = useCallback((prompt: string) => {
    setPendingPrompt(prompt);
    setOpen(true);
  }, []);

  const consumePendingPrompt = useCallback(() => {
    const next = pendingPrompt;
    setPendingPrompt(null);
    return next;
  }, [pendingPrompt]);

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
      toggle,
      openWithPrompt,
      pendingPrompt,
      consumePendingPrompt,
    }),
    [open, toggle, openWithPrompt, pendingPrompt, consumePendingPrompt],
  );

  return <AskAiUiContext.Provider value={value}>{children}</AskAiUiContext.Provider>;
}

export function useAskAiUi() {
  const ctx = useContext(AskAiUiContext);
  if (!ctx) throw new Error("useAskAiUi must be used within AskAiProvider");
  return ctx;
}
