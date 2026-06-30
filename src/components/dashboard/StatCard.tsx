import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { cn } from '@/lib/utils';
import type { LucideIcon } from 'lucide-react';

interface StatCardProps {
  title: string;
  value: string | number;
  icon: LucideIcon;
  subtitle?: string;
  accent?: 'blue' | 'red' | 'orange' | 'yellow' | 'green' | 'slate';
}

const accentStyles = {
  blue: 'text-blue-400 bg-blue-500/10 border-blue-500/20',
  red: 'text-red-400 bg-red-500/10 border-red-500/20',
  orange: 'text-orange-400 bg-orange-500/10 border-orange-500/20',
  yellow: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
  green: 'text-green-400 bg-green-500/10 border-green-500/20',
  slate: 'text-slate-400 bg-slate-500/10 border-slate-500/20',
};

export function StatCard({ title, value, icon: Icon, subtitle, accent = 'blue' }: StatCardProps) {
  return (
    <Card className="bg-card/80 backdrop-blur-sm">
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
          {title}
        </CardTitle>
        <div className={cn('p-2 rounded-lg border', accentStyles[accent])}>
          <Icon className="h-4 w-4" />
        </div>
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-bold tracking-tight">{value}</div>
        {subtitle && <p className="text-xs text-muted-foreground mt-1">{subtitle}</p>}
      </CardContent>
    </Card>
  );
}
