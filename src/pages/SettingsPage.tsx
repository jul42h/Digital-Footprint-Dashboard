import { Settings } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

export function SettingsPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Settings</h1>
        <p className="text-sm text-muted-foreground mt-1">Configuration placeholder for future backend integration</p>
      </div>

      <Card className="max-w-2xl">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Settings className="h-4 w-4 text-blue-400" />
            Settings (Placeholder)
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4 text-sm text-muted-foreground">
          <p>
            This section is reserved for future configuration options when the dashboard connects to AWS backend services.
          </p>
          <ul className="list-disc list-inside space-y-1">
            <li>API Gateway endpoint configuration</li>
            <li>Data refresh intervals</li>
            <li>Alert thresholds and notifications</li>
            <li>Export and reporting preferences</li>
          </ul>
          {/* Future: Replace with authenticated settings backed by DynamoDB */}
        </CardContent>
      </Card>
    </div>
  );
}
