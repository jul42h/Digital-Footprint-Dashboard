import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { SEVERITY_COLORS } from '@/utils/riskColors';
import type { Severity } from '@/types';
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip, Legend } from 'recharts';

interface SeverityPieChartProps {
  data: Array<{ name: Severity; value: number }>;
}

export function SeverityPieChart({ data }: SeverityPieChartProps) {
  const filtered = data.filter((item) => item.value > 0);

  return (
    <Card className="h-full">
      <CardHeader>
        <CardTitle className="text-base">CVEs by Severity</CardTitle>
      </CardHeader>
      <CardContent>
        <ResponsiveContainer width="100%" height={260}>
          <PieChart>
            <Pie data={filtered} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={90} innerRadius={45} paddingAngle={2}>
              {filtered.map((entry) => (
                <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name].chart} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: 8 }}
              labelStyle={{ color: '#e2e8f0' }}
            />
            <Legend />
          </PieChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  );
}
