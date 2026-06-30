import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import type { IPRecord } from '@/types';
import { getSeverityBadgeClass } from '@/utils/riskColors';

interface TopRiskIPsProps {
  ips: Array<IPRecord & { riskScore: number }>;
}

export function TopRiskIPs({ ips }: TopRiskIPsProps) {
  return (
    <Card className="h-full">
      <CardHeader>
        <CardTitle className="text-base">Top Risk IPs</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          {ips.map((ip, index) => (
            <div
              key={ip.ip}
              className="flex items-center justify-between gap-3 rounded-lg border border-border/60 bg-secondary/30 px-3 py-2.5"
            >
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-xs text-muted-foreground w-5">#{index + 1}</span>
                  <span className="font-mono text-sm text-blue-400 truncate">{ip.ip}</span>
                </div>
                <p className="text-xs text-muted-foreground truncate mt-0.5">{ip.organization}</p>
              </div>
              <div className="text-right shrink-0">
                <div className="text-sm font-semibold">{ip.riskScore}</div>
                <div className="flex items-center gap-2 justify-end mt-1">
                  <span className="text-xs text-muted-foreground">{ip.cves.length} CVEs</span>
                  <span className={`px-2 py-0.5 rounded-full text-[10px] ${getSeverityBadgeClass(ip.riskLevel)}`}>
                    {ip.riskLevel}
                  </span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
