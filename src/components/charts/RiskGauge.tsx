import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts';

interface RiskGaugeProps {
  score: number;
}

function getRiskLabel(score: number) {
  if (score >= 80) return 'Critical';
  if (score >= 60) return 'High';
  if (score >= 40) return 'Medium';
  if (score >= 20) return 'Low';
  return 'Minimal';
}

function getRiskColor(score: number) {
  if (score >= 80) return '#ef4444';
  if (score >= 60) return '#f97316';
  if (score >= 40) return '#eab308';
  if (score >= 20) return '#3b82f6';
  return '#64748b';
}

export function RiskGauge({ score }: RiskGaugeProps) {
  const gaugeData = [
    { name: 'Risk', value: score },
    { name: 'Remaining', value: Math.max(0, 100 - score) },
  ];

  return (
    <Card className="h-full">
      <CardHeader>
        <CardTitle className="text-base">Overall Network Risk Score</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="relative">
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie
                data={gaugeData}
                dataKey="value"
                cx="50%"
                cy="70%"
                startAngle={180}
                endAngle={0}
                innerRadius={70}
                outerRadius={95}
                paddingAngle={0}
              >
                <Cell fill={getRiskColor(score)} />
                <Cell fill="#1e293b" />
              </Pie>
              <Tooltip
                contentStyle={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: 8 }}
              />
            </PieChart>
          </ResponsiveContainer>
          <div className="absolute inset-x-0 bottom-8 text-center">
            <div className="text-3xl font-bold" style={{ color: getRiskColor(score) }}>
              {score}
            </div>
            <div className="text-sm text-muted-foreground">{getRiskLabel(score)} Risk</div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
