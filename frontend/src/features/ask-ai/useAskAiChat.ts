import { useCallback, useEffect, useRef, useState } from "react";
import { postAskAi } from "./askAiApi";
import type { AskAiResponse, ChatMessage } from "./types";

const STORAGE_KEY = "df-ask-ai-chat-v1";

function uid(): string {
  return `${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
}

function loadHistory(): ChatMessage[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as ChatMessage[];
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function formatAssistantContent(data: AskAiResponse): string {
  if (data.summary?.trim()) return data.summary;
  if (data.markdown?.trim()) return data.markdown;
  return "Analysis complete.";
}

export function useAskAiChat() {
  const [messages, setMessages] = useState<ChatMessage[]>(() => loadHistory());
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  useEffect(() => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(messages.slice(-40)));
  }, [messages]);

  const clearChat = useCallback(() => {
    abortRef.current?.abort();
    setMessages([]);
    setError(null);
    setInput("");
    localStorage.removeItem(STORAGE_KEY);
  }, []);

  const send = useCallback(
    async (rawQuestion: string) => {
      const question = rawQuestion.trim();
      if (!question || loading) return;

      setError(null);
      setLoading(true);
      setInput("");

      const userMsg: ChatMessage = {
        id: uid(),
        role: "user",
        content: question,
        createdAt: Date.now(),
      };

      setMessages((prev) => [...prev, userMsg]);

      try {
        const history = [...messages, userMsg]
          .filter((m) => m.role === "user" || m.role === "assistant")
          .slice(-8)
          .map((m) => ({ role: m.role, content: m.content }));

        const data = await postAskAi({ question, history });
        const assistantMsg: ChatMessage = {
          id: uid(),
          role: "assistant",
          content: formatAssistantContent(data),
          structured: data,
          createdAt: Date.now(),
        };
        setMessages((prev) => [...prev, assistantMsg]);
      } catch (err) {
        const message = err instanceof Error ? err.message : "Ask AI request failed";
        setError(message);
        setMessages((prev) => [
          ...prev,
          {
            id: uid(),
            role: "assistant",
            content: `I could not complete that analysis. ${message}`,
            createdAt: Date.now(),
          },
        ]);
      } finally {
        setLoading(false);
      }
    },
    [loading, messages],
  );

  return {
    messages,
    input,
    setInput,
    loading,
    error,
    send,
    clearChat,
  };
}
