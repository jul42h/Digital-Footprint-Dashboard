import { useMemo, useState } from 'react';
import {
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getSortedRowModel,
  useReactTable,
  type ColumnDef,
  type SortingState,
} from '@tanstack/react-table';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import type { IPRecord } from '@/types';
import { formatDateTime } from '@/utils/dateUtils';
import { getRiskScore } from '@/utils/dataTransformers';
import { getSeverityBadgeClass } from '@/utils/riskColors';
import { IPDetailsDrawer } from './IPDetailsDrawer';

interface IPAddressTableProps {
  ips: IPRecord[];
}

export function IPAddressTable({ ips }: IPAddressTableProps) {
  const [sorting, setSorting] = useState<SortingState>([]);
  const [globalFilter, setGlobalFilter] = useState('');
  const [riskFilter, setRiskFilter] = useState('all');
  const [selectedIP, setSelectedIP] = useState<IPRecord | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);

  const tableData = useMemo(
    () =>
      ips.map((ip) => ({
        ...ip,
        totalCVEs: ip.cves.length,
        highestCVSS: ip.cves.length ? Math.max(...ip.cves.map((cve) => cve.score)) : 0,
        riskScore: getRiskScore(ip),
      })),
    [ips],
  );

  const filteredData = useMemo(() => {
    if (riskFilter === 'all') return tableData;
    return tableData.filter((ip) => ip.riskLevel === riskFilter);
  }, [tableData, riskFilter]);

  const columns = useMemo<ColumnDef<(typeof tableData)[number]>[]>(
    () => [
      { accessorKey: 'ip', header: 'IP Address', cell: ({ getValue }) => <span className="font-mono text-blue-400">{String(getValue())}</span> },
      { accessorKey: 'organization', header: 'Organization' },
      { accessorKey: 'country', header: 'Country' },
      { accessorKey: 'operatingSystem', header: 'Operating System', cell: ({ getValue }) => getValue() || '—' },
      {
        accessorKey: 'openPorts',
        header: 'Open Ports',
        cell: ({ row }) => (row.original.openPorts.length ? row.original.openPorts.join(', ') : row.original.ports.join(', ') || '—'),
      },
      { accessorKey: 'totalCVEs', header: 'Total CVEs' },
      { accessorKey: 'highestCVSS', header: 'Highest CVSS' },
      {
        accessorKey: 'riskLevel',
        header: 'Risk Level',
        cell: ({ getValue }) => (
          <span className={`px-2 py-0.5 rounded-full text-xs ${getSeverityBadgeClass(String(getValue()))}`}>
            {String(getValue())}
          </span>
        ),
      },
      {
        accessorKey: 'lastSeen',
        header: 'Last Seen',
        cell: ({ getValue }) => formatDateTime(String(getValue() ?? '')),
      },
    ],
    [],
  );

  const table = useReactTable({
    data: filteredData,
    columns,
    state: { sorting, globalFilter },
    onSortingChange: setSorting,
    onGlobalFilterChange: setGlobalFilter,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
  });

  const openDetails = (ip: IPRecord) => {
    setSelectedIP(ip);
    setDrawerOpen(true);
  };

  return (
    <>
      <Card>
        <CardHeader className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <CardTitle className="text-base">IP Address Inventory</CardTitle>
          <div className="flex flex-col sm:flex-row gap-2 w-full sm:w-auto">
            <Input
              placeholder="Search IPs, orgs, countries..."
              value={globalFilter}
              onChange={(e) => setGlobalFilter(e.target.value)}
              className="sm:w-64"
            />
            <Select value={riskFilter} onValueChange={setRiskFilter}>
              <SelectTrigger className="sm:w-40">
                <SelectValue placeholder="Risk Level" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Risk Levels</SelectItem>
                <SelectItem value="Critical">Critical</SelectItem>
                <SelectItem value="High">High</SelectItem>
                <SelectItem value="Medium">Medium</SelectItem>
                <SelectItem value="Low">Low</SelectItem>
                <SelectItem value="Informational">Informational</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="w-full text-sm">
              <thead className="bg-secondary/40">
                {table.getHeaderGroups().map((headerGroup) => (
                  <tr key={headerGroup.id}>
                    {headerGroup.headers.map((header) => (
                      <th
                        key={header.id}
                        className="px-4 py-3 text-left text-xs font-medium text-muted-foreground cursor-pointer select-none"
                        onClick={header.column.getToggleSortingHandler()}
                      >
                        {flexRender(header.column.columnDef.header, header.getContext())}
                        {{ asc: ' ↑', desc: ' ↓' }[header.column.getIsSorted() as string] ?? null}
                      </th>
                    ))}
                  </tr>
                ))}
              </thead>
              <tbody>
                {table.getRowModel().rows.map((row) => (
                  <tr
                    key={row.id}
                    className="border-t border-border/60 hover:bg-accent/30 cursor-pointer transition-colors"
                    onClick={() => openDetails(row.original)}
                  >
                    {row.getVisibleCells().map((cell) => (
                      <td key={cell.id} className="px-4 py-3 whitespace-nowrap">
                        {flexRender(cell.column.columnDef.cell, cell.getContext())}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>

      <IPDetailsDrawer ip={selectedIP} open={drawerOpen} onOpenChange={setDrawerOpen} />
    </>
  );
}
