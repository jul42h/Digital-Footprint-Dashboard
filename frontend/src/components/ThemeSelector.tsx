import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { useTheme } from "@/context/ThemeContext";
import { THEME_GROUPS, THEMES } from "@/lib/themes";

export function ThemeSelector() {
  const { themeId, setThemeId, theme } = useTheme();
  const [open, setOpen] = useState(false);
  const [menuStyle, setMenuStyle] = useState<React.CSSProperties>({});
  const rootRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);

  const positionMenu = () => {
    const trigger = triggerRef.current;
    if (!trigger) return;
    const rect = trigger.getBoundingClientRect();
    const menuWidth = Math.min(320, window.innerWidth - 16);
    let left = rect.right - menuWidth;
    left = Math.max(8, Math.min(left, window.innerWidth - menuWidth - 8));
    const top = rect.bottom + 8;
    const maxHeight = Math.min(480, window.innerHeight - top - 12);
    setMenuStyle({
      position: "fixed",
      top,
      left,
      width: menuWidth,
      maxHeight,
      zIndex: 200,
    });
  };

  useLayoutEffect(() => {
    if (!open) return;
    positionMenu();
    window.addEventListener("resize", positionMenu);
    window.addEventListener("scroll", positionMenu, true);
    return () => {
      window.removeEventListener("resize", positionMenu);
      window.removeEventListener("scroll", positionMenu, true);
    };
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const onPointerDown = (e: MouseEvent) => {
      const target = e.target as Node;
      if (rootRef.current?.contains(target) || menuRef.current?.contains(target)) return;
      setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onPointerDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onPointerDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const menu = open ? (
    <div
      ref={menuRef}
      className="theme-selector__menu"
      style={menuStyle}
      role="listbox"
      aria-label="Dashboard themes"
    >
      {THEME_GROUPS.map((group) => {
        const options = THEMES.filter((t) => t.group === group.id);
        if (options.length === 0) return null;
        return (
          <div key={group.id} className="theme-selector__group">
            <p className="theme-selector__group-label">{group.label}</p>
            <ul className="theme-selector__list">
              {options.map((option) => (
                <li key={option.id}>
                  <button
                    type="button"
                    role="option"
                    aria-selected={themeId === option.id}
                    className={`theme-selector__option${themeId === option.id ? " theme-selector__option--active" : ""}`}
                    onClick={() => {
                      setThemeId(option.id);
                      setOpen(false);
                    }}
                  >
                    <span className="theme-selector__swatches" aria-hidden>
                      <span style={{ background: option.swatches[0] }} />
                      <span style={{ background: option.swatches[1] }} />
                    </span>
                    <span className="theme-selector__option-text">
                      <span className="theme-selector__option-label">{option.label}</span>
                      <span className="theme-selector__option-desc">{option.description}</span>
                    </span>
                    {themeId === option.id && (
                      <span className="theme-selector__check" aria-hidden>
                        ✓
                      </span>
                    )}
                  </button>
                </li>
              ))}
            </ul>
          </div>
        );
      })}
    </div>
  ) : null;

  return (
    <div className="theme-selector" ref={rootRef}>
      <button
        ref={triggerRef}
        type="button"
        className="btn btn--ghost theme-selector__trigger"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        aria-haspopup="listbox"
        aria-label="Choose color theme"
        title="Color theme"
      >
        <span className="theme-selector__swatch-preview" aria-hidden>
          <span style={{ background: theme.swatches[0] }} />
          <span style={{ background: theme.swatches[1] }} />
        </span>
        <span className="theme-selector__trigger-label">{theme.label}</span>
      </button>
      {menu && createPortal(menu, document.body)}
    </div>
  );
}
