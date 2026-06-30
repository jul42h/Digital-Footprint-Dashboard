import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

interface PortHeatmapProps {
  data: Array<{ port: string; count: number }>;
}

function getHeatColor(count: number, max: number) {
  const intensity = max > 0 ? count / max : 0;
  if (intensity > 0.75) return 'bg-red-500/80 border-red-500/50';
  if (intensity > 0.5) return 'bg-orange-500/75 border-orange-500/50';
  if (intensity > 0.25) return 'bg-yellow-500/75 border-yellow-500/50';
  return 'bg-blue-500/60 border-blue-500/40';
}

export function PortHeatmap({ data }: PortHeatmapProps) {
  const max = Math.max(...data.map((item) => item.count), 1);

  return (
    <Card className="h-full">
      <CardHeader>
        <CardTitle className="text-base">Ports vs Vulnerabilities</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-4 sm:grid-cols-5 gap-2">
          {data.map((item) => (
            <div
              key={item.port}
              className={`rounded-lg border p-3 text-center ${getHeatColor(item.count, max)}`}
              title={`Port ${item.port}: ${item.count} vulnerabilities`}
            >
              <div className="text-xs text-muted-foreground">Port</div>
              <div className="font-mono font-semibold text-sm">{item.port}</div>
              <div className="text-xs mt-1">{item.count}</div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
