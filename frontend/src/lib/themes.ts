export type ThemeId =
  | "fresno"
  | "fresno-dark"
  | "valley-pride";

type ThemeGroup = "brand" | "variant";

interface ThemeDefinition {
  id: ThemeId;
  label: string;
  description: string;
  group: ThemeGroup;
  swatches: [string, string];
}

const BRAND_COLORS = {
  cardinal: "#c41230",
  blue: "#13284c",
  green: "#007935",
} as const;

export const DEFAULT_THEME_ID: ThemeId = "fresno";
export const THEME_STORAGE_KEY = "df-dashboard-theme";

export const THEME_GROUPS: { id: ThemeGroup; label: string }[] = [
  { id: "brand", label: "Fresno State" },
  { id: "variant", label: "Valley Pride" },
];

export const THEMES: ThemeDefinition[] = [
  {
    id: "fresno",
    label: "Fresno State",
    description: "Light canvas with white panels and cardinal accents",
    group: "brand",
    swatches: [BRAND_COLORS.cardinal, BRAND_COLORS.blue],
  },
  {
    id: "fresno-dark",
    label: "Fresno State Dark",
    description: "Navy canvas with lifted panels and cardinal accents",
    group: "brand",
    swatches: [BRAND_COLORS.blue, BRAND_COLORS.cardinal],
  },
  {
    id: "valley-pride",
    label: "Valley Pride",
    description: "Valley sage canvas with Fresno State and Green V accents",
    group: "variant",
    swatches: [BRAND_COLORS.green, BRAND_COLORS.cardinal],
  },
];

const THEME_IDS = new Set(THEMES.map((t) => t.id));

function isThemeId(value: string | null | undefined): value is ThemeId {
  return value != null && THEME_IDS.has(value as ThemeId);
}

/** Normalize theme IDs previously shipped under Valley Pride's old names. */
export function migrateThemeId(value: string | null | undefined): ThemeId | null {
  if (value === "valley" || value === "valley-dark" || value === "valley-pride-dark") {
    return "valley-pride";
  }
  return isThemeId(value) ? value : null;
}

export function getThemeDefinition(id: ThemeId): ThemeDefinition {
  return THEMES.find((t) => t.id === id) ?? THEMES[0];
}
