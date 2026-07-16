import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import {
  DEFAULT_THEME_ID,
  THEME_STORAGE_KEY,
  getThemeDefinition,
  migrateThemeId,
  type ThemeId,
} from "@/lib/themes";

type ThemeContextValue = {
  themeId: ThemeId;
  setThemeId: (id: ThemeId) => void;
};

const ThemeContext = createContext<ThemeContextValue | null>(null);

function readStoredTheme(): ThemeId {
  try {
    const stored = localStorage.getItem(THEME_STORAGE_KEY);
    const migrated = migrateThemeId(stored);
    if (migrated) {
      if (migrated !== stored) localStorage.setItem(THEME_STORAGE_KEY, migrated);
      return migrated;
    }
  } catch {
    // localStorage unavailable
  }
  const attr = document.documentElement.getAttribute("data-theme");
  const migratedAttr = migrateThemeId(attr);
  if (migratedAttr) return migratedAttr;
  return DEFAULT_THEME_ID;
}

function applyTheme(id: ThemeId) {
  document.documentElement.setAttribute("data-theme", id);
  try {
    localStorage.setItem(THEME_STORAGE_KEY, id);
  } catch {
    // ignore
  }
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [themeId, setThemeIdState] = useState<ThemeId>(readStoredTheme);

  useEffect(() => {
    applyTheme(themeId);
  }, [themeId]);

  const setThemeId = useCallback((id: ThemeId) => {
    /* Apply synchronously, not just via the effect above: some charts read
       resolved CSS custom properties (getComputedStyle) during render to
       fill SVG attributes that can't take var(). Those consumer components
       re-render in the same pass as this context update, which is before
       the effect above would run — so the DOM attribute has to already be
       current by then, or they'd paint with the outgoing theme's colors. */
    applyTheme(id);
    setThemeIdState(id);
  }, []);

  const value = useMemo(() => ({ themeId, setThemeId }), [themeId, setThemeId]);

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme() {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error("useTheme must be used within ThemeProvider");
  return { ...ctx, theme: getThemeDefinition(ctx.themeId) };
}
