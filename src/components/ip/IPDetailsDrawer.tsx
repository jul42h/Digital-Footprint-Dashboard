import { Sheet, SheetContent, SheetHeader, SheetTitle } from '@/components/ui/sheet';
import { Separator } from '@/components/ui/separator';
import type { IPRecord } from '@/types';
import { formatDate, formatDateTime } from '@/utils/dateUtils';
import { getRiskScore } from '@/utils/dataTransformers';
import { getSeverityBadgeClass } from '@/utils/riskColors';
import { MapPin, Server, Shield } from 'lucide-react';

interface IPDetailsDrawerProps {
  ip: IPRecord | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function IPDetailsDrawer({ ip, open, onOpenChange }: IPDetailsDrawerProps) {
  if (!ip) return null;

  const riskScore = getRiskScore(ip);
  const sortedCVEs = [...ip.cves].sort((a, b) => b.score - a.score);

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent>
        <SheetHeader>
          <SheetTitle className="flex items-center gap-2 font-mono">
            <Server className="h-5 w-5 text-blue-400" />
            {ip.ip}
          </SheetTitle>
        </SheetHeader>

        <div className="p-6 space-y-6">
          <section className="grid grid-cols-2 gap-4 text-sm">
            <DetailItem label="Hostname" value={ip.hostnames.join(', ') || '—'} />
            <DetailItem label="Organization" value={ip.organization || '—'} />
            <DetailItem label="ASN" value={ip.asn || '—'} />
            <DetailItem label="Location" value={[ip.city, ip.country].filter(Boolean).join(', ') || '—'} />
            <DetailItem label="Operating System" value={ip.operatingSystem || '—'} />
            <DetailItem label="Risk Score" value={String(riskScore)} highlight />
            <DetailItem label="Open Ports" value={ip.openPorts.join(', ') || ip.ports.join(', ') || '—'} />
            <DetailItem label="Last Seen" value={formatDateTime(ip.lastSeen)} />
          </section>

          <Separator />

          <section>
            <h4 className="text-sm font-semibold mb-2">Services & Products</h4>
            <div className="grid grid-cols-1 gap-2 text-sm">
              <DetailItem label="Services" value={ip.services.join(', ') || '—'} />
              <DetailItem label="Products" value={ip.products.join(', ') || '—'} />
              <DetailItem label="Versions" value={ip.versions.join(', ') || '—'} />
            </div>
          </section>

          <Separator />

          <section>
            <h4 className="text-sm font-semibold mb-3 flex items-center gap-2">
              <Shield className="h-4 w-4 text-blue-400" />
              CVE Timeline ({sortedCVEs.length})
            </h4>
            <div className="space-y-3">
              {sortedCVEs.map((cve) => (
                <div key={cve.id} className="rounded-lg border border-border bg-secondary/20 p-4">
                  <div className="flex items-start justify-between gap-3">
                    <span className="font-mono text-sm text-blue-400">{cve.id}</span>
                    <span className={`px-2 py-0.5 rounded-full text-xs ${getSeverityBadgeClass(cve.severity)}`}>
                      {cve.severity}
                    </span>
                  </div>
                  <div className="mt-2 flex items-center gap-4 text-xs text-muted-foreground">
                    <span>CVSS: {cve.score || '—'}</span>
                    <span>Published: {formatDate(cve.publishedDate)}</span>
                  </div>
                  {cve.summary && (
                    <p className="mt-2 text-sm text-slate-300 leading-relaxed">{cve.summary}</p>
                  )}
                </div>
              ))}
            </div>
          </section>

          {ip.summary && (
            <>
              <Separator />
              <section>
                <h4 className="text-sm font-semibold mb-2 flex items-center gap-2">
                  <MapPin className="h-4 w-4" />
                  Host Summary
                </h4>
                <p className="text-sm text-slate-300">{ip.summary}</p>
              </section>
            </>
          )}
        </div>
      </SheetContent>
    </Sheet>
  );
}

function DetailItem({ label, value, highlight }: { label: string; value: string; highlight?: boolean }) {
  return (
    <div>
      <div className="text-xs text-muted-foreground mb-1">{label}</div>
      <div className={`text-sm ${highlight ? 'font-semibold text-orange-400' : ''}`}>{value}</div>
    </div>
  );
}
