import { FileText } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

interface SummaryPanelProps {
  summary: string;
}

export function SummaryPanel({ summary }: SummaryPanelProps) {
  return (
    <Card className="bg-gradient-to-br from-blue-950/40 to-card border-blue-500/20">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <FileText className="h-4 w-4 text-blue-400" />
          Executive Summary
        </CardTitle>
      </CardHeader>
      <CardContent>
        <p className="text-sm leading-relaxed text-slate-300">{summary}</p>
      </CardContent>
    </Card>
  );
}
