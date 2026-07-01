import { useEffect } from "react";
import { useLocation } from "react-router-dom";

/** Scroll main content to top on route change. */
export function ScrollToTop() {
  const { pathname } = useLocation();

  useEffect(() => {
    const main = document.querySelector(".main");
    if (main) main.scrollTop = 0;
  }, [pathname]);

  return null;
}
