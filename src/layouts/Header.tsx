import { useEffect, useRef, useState } from 'react';
import { Menu, RefreshCw, Search, Shield } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { useGlobalSearch } from '@/hooks/useGlobalSearch';
import type { DashboardData } from '@/types';

interface HeaderProps {
  data: DashboardData | null;
  refreshing: boolean;
  onRefresh: () => void;
  onOpenSidebar: () => void;
}

export function Header({ data, refreshing, onRefresh, onOpenSidebar }: HeaderProps) {
  const [query, setQuery] = useState('');
  const [showResults, setShowResults] = useState(false);
  const navigate = useNavigate();
  const containerRef = useRef<HTMLDivElement>(null);
  const results = useGlobalSearch(data, query);

  useEffect(() => {
    const handleClick = (event: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        setShowResults(false);
      }
    };
    document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, []);

  const handleSelect = (ip: string) => {
    setQuery('');
    setShowResults(false);
    navigate('/ips', { state: { selectedIP: ip } });
  };

  return (
    <header className="sticky top-0 z-30 border-b border-border bg-background/80 backdrop-blur-md">
      <div className="flex items-center gap-4 px-4 lg:px-6 py-3">
        <Button variant="ghost" size="icon" className="lg:hidden" onClick={onOpenSidebar}>
          <Menu className="h-5 w-5" />
        </Button>

        <div className="flex items-center gap-2 lg:hidden">
          <Shield className="h-5 w-5 text-blue-400" />
        </div>

        <div ref={containerRef} className="relative flex-1 max-w-xl">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search IP, Organization, Hostname, ASN, CVE, Country..."
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setShowResults(true);
            }}
            onFocus={() => setShowResults(true)}
            className="pl-9"
          />
          {showResults && query && results.length > 0 && (
            <div className="absolute top-full mt-1 w-full rounded-lg border border-border bg-popover shadow-xl z-50 overflow-hidden">
              {results.map((result) => (
                <button
                  key={`${result.type}-${result.value}`}
                  className="w-full px-4 py-2.5 text-left text-sm hover:bg-accent flex items-center justify-between gap-2"
                  onClick={() => result.ip && handleSelect(result.ip.ip)}
                >
                  <span>{result.label}</span>
                  <span className="text-xs text-muted-foreground capitalize">{result.type}</span>
                </button>
              ))}
            </div>
          )}
        </div>

        <div className="hidden md:flex items-center gap-3 text-xs text-muted-foreground">
          {data && (
            <>
              <span className={data.source === 'excel' ? 'text-green-400' : 'text-yellow-400'}>
                ● {data.source === 'excel' ? 'Excel' : 'Fallback'} data
              </span>
              <span>Updated {new Date(data.lastUpdated).toLocaleTimeString()}</span>
            </>
          )}
        </div>

        <Button variant="outline" size="sm" onClick={onRefresh} disabled={refreshing}>
          <RefreshCw className={`h-4 w-4 ${refreshing ? 'animate-spin' : ''}`} />
          <span className="hidden sm:inline">Refresh</span>
        </Button>
      </div>
    </header>
  );
}
