import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import type { CVEFlatRecord } from '@/types';
import { formatDate } from '@/utils/dateUtils';
import { getSeverityBadgeClass } from '@/utils/riskColors';

interface RecentVulnerabilitiesProps {
  records: CVEFlatRecord[];
}

export function RecentVulnerabilities({ records }: RecentVulnerabilitiesProps) {
  const newest = records.slice(0, 8);

  return (
    <Card className="h-full">
      <CardHeader>
        <CardTitle className="text-base">Newest CVEs</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-left text-xs text-muted-foreground">
                <th className="pb-2 pr-4 font-medium">CVE</th>
                <th className="pb-2 pr-4 font-medium">Score</th>
                <th className="pb-2 pr-4 font-medium">Severity</th>
                <th className="pb-2 pr-4 font-medium">Affected IP</th>
                <th className="pb-2 font-medium">Published</th>
              </tr>
            </thead>
            <tbody>
              {newest.map((record) => (
                <tr key={`${record.cve.id}-${record.ip}`} className="border-b border-border/50 last:border-0">
                  <td className="py-2.5 pr-4 font-mono text-blue-400">{record.cve.id}</td>
                  <td className="py-2.5 pr-4">{record.cve.score || '—'}</td>
                  <td className="py-2.5 pr-4">
                    <span className={`px-2 py-0.5 rounded-full text-xs ${getSeverityBadgeClass(record.cve.severity)}`}>
                      {record.cve.severity}
                    </span>
                  </td>
                  <td className="py-2.5 pr-4 font-mono">{record.ip}</td>
                  <td className="py-2.5 text-muted-foreground">{formatDate(record.cve.publishedDate)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  );
}
