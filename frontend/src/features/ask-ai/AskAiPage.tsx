import { useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useAskAiUi } from "./AskAiContext";

/** Legacy `/ask` route opens the CVE analysis panel on the home page. */
export function AskAiPage() {
  const { setOpen } = useAskAiUi();
  const navigate = useNavigate();

  useEffect(() => {
    setOpen(true);
    navigate("/", { replace: true });
  }, [navigate, setOpen]);

  return null;
}
