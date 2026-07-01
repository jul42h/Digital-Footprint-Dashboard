import { useEffect, useState } from "react";

export function BackToTop() {
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    const main = document.querySelector(".main");
    if (!main) return;

    const onScroll = () => setVisible(main.scrollTop > 360);
    main.addEventListener("scroll", onScroll, { passive: true });
    return () => main.removeEventListener("scroll", onScroll);
  }, []);

  if (!visible) return null;

  return (
    <button
      type="button"
      className="back-to-top"
      aria-label="Scroll to top"
      onClick={() => document.querySelector(".main")?.scrollTo({ top: 0, behavior: "smooth" })}
    >
      ↑
    </button>
  );
}
