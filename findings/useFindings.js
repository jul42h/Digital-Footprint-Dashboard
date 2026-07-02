import { useEffect, useState } from "react";
 
export function useFindings(ip) {
  const [data, setData] = useState({ count: 0, items: [] });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
 
  useEffect(() => {
    setLoading(true);
    setError(null);
    const url = ip
      ? `/findings?ip=${encodeURIComponent(ip)}`
      : `/findings`;
    fetch(url)
      .then((r) => {
        if (!r.ok) throw new Error(`API returned ${r.status}`);
        return r.json();
      })
      .then(setData)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [ip]);
 
  return { items: data.items, count: data.count, loading, error };
}
import { useFindings } from "./useFindings";
 
function Dashboard() {
  const { items, count, loading, error } = useFindings();
 
  if (loading) return <p>Loading…</p>;
  if (error) return <p>Error: {error}</p>;
 
  return (
    <div>
      <h2>{count} findings</h2>
      {items.map((f) => (
        <div key={`${f.ip}|${f.cve_id}`}>
          {f.ip} — {f.cve_id} — CVSS {f.cvss ?? "n/a"} — {f.scan_type}
        </div>
      ))}
    </div>
  );
}
