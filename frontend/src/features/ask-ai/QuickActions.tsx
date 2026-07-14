import { QUICK_ACTIONS } from "./askAiPrompts";

export function QuickActions({
  disabled,
  onSelect,
  compact = false,
}: {
  disabled?: boolean;
  onSelect: (prompt: string) => void;
  compact?: boolean;
}) {
  const actions = compact ? QUICK_ACTIONS.slice(0, 5) : QUICK_ACTIONS;

  return (
    <div
      className={`ask-ai-quick${compact ? " ask-ai-quick--compact" : ""}`}
      role="group"
      aria-label="Quick analyst actions"
    >
      {actions.map((action) => (
        <button
          key={action.id}
          type="button"
          className="ask-ai-quick__btn"
          disabled={disabled}
          onClick={() => onSelect(action.prompt)}
        >
          {action.label}
        </button>
      ))}
    </div>
  );
}
