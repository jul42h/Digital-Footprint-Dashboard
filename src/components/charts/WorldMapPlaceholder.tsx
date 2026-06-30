import { Globe2 } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

interface WorldMapPlaceholderProps {
  data: Array<{ country: string; count: number }>;
}

export function WorldMapPlaceholder({ data }: WorldMapPlaceholderProps) {
  const top = data.slice(0, 8);

  return (
    <Card className="h-full">
      <CardHeader>
        <CardTitle className="text-base">Countries with Vulnerable Assets</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="relative h-[220px] rounded-lg border border-dashed border-blue-500/30 bg-gradient-to-br from-blue-950/20 to-slate-950 flex items-center justify-center overflow-hidden">
          <Globe2 className="absolute h-32 w-32 text-blue-500/10" />
          <div className="relative z-10 grid grid-cols-2 gap-2 w-full px-4">
            {top.map((item) => (
              <div key={item.country} className="flex items-center justify-between rounded-md bg-slate-900/80 border border-border px-3 py-2 text-xs">
                <span className="truncate">{item.country}</span>
                <span className="font-semibold text-blue-400 ml-2">{item.count}</span>
              </div>
            ))}
          </div>
        </div>
        <p className="text-[11px] text-muted-foreground mt-3 text-center">
          World map visualization placeholder — integrate geo mapping library in production
        </p>
      </CardContent>
    </Card>
  );
}
