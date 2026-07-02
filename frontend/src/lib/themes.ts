export type ThemeId =
  | "fresno"
  | "fresno-dark"
  | "valley"
  | "valley-dark";

export type ThemeGroup = "brand" | "variant";

export interface ThemeDefinition {
  id: ThemeId;
  label: string;
  description: string;
  group: ThemeGroup;
  swatches: [string, string];
}

export const BRAND_COLORS = {
  cardinal: "#c41230",
  blue: "#13284c",
  coolGray: "#ced1d4",
  white: "#ffffff",
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
    id: "valley",
    label: "Valley Pride",
    description: "Sage canvas with white panels and valley-green accents",
    group: "variant",
    swatches: [BRAND_COLORS.green, BRAND_COLORS.cardinal],
  },
  {
    id: "valley-dark",
    label: "Valley Pride Dark",
    description: "Navy canvas with lifted panels and valley-green accents",
    group: "variant",
    swatches: [BRAND_COLORS.green, BRAND_COLORS.blue],
  },
];

const THEME_IDS = new Set(THEMES.map((t) => t.id));

export function isThemeId(value: string | null | undefined): value is ThemeId {
  return value != null && THEME_IDS.has(value as ThemeId);
}

export function getThemeDefinition(id: ThemeId): ThemeDefinition {
  return THEMES.find((t) => t.id === id) ?? THEMES[0];
}
