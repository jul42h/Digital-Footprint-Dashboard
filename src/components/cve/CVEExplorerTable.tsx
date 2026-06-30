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
import type { CVEFlatRecord } from '@/types';
import { formatDate } from '@/utils/dateUtils';
import { getSeverityBadgeClass } from '@/utils/riskColors';

interface CVEExplorerTableProps {
  records: CVEFlatRecord[];
}

export function CVEExplorerTable({ records }: CVEExplorerTableProps) {
  const [sorting, setSorting] = useState<SortingState>([{ id: 'publishedDate', desc: true }]);
  const [globalFilter, setGlobalFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [orgFilter, setOrgFilter] = useState('all');
  const [osFilter, setOsFilter] = useState('all');
  const [countryFilter, setCountryFilter] = useState('all');
  const [portFilter, setPortFilter] = useState('all');

  const organizations = useMemo(
    () => [...new Set(records.map((r) => r.organization).filter(Boolean))].sort(),
    [records],
  );
  const operatingSystems = useMemo(
    () => [...new Set(records.map((r) => r.operatingSystem).filter(Boolean))].sort(),
    [records],
  );
  const countries = useMemo(
    () => [...new Set(records.map((r) => r.country).filter(Boolean))].sort(),
    [records],
  );
  const ports = useMemo(
    () => [...new Set(records.map((r) => r.port).filter(Boolean))].sort((a, b) => Number(a) - Number(b)),
    [records],
  );

  const tableData = useMemo(
    () =>
      records.map((record) => ({
        cveId: record.cve.id,
        score: record.cve.score,
        severity: record.cve.severity,
        ip: record.ip,
        organization: record.organization,
        operatingSystem: record.operatingSystem ?? '',
        country: record.country,
        port: record.port ?? '',
        publishedDate: record.cve.publishedDate,
        summary: record.cve.summary ?? '',
      })),
    [records],
  );

  const filteredData = useMemo(() => {
    return tableData.filter((row) => {
      if (severityFilter !== 'all' && row.severity !== severityFilter) return false;
      if (orgFilter !== 'all' && row.organization !== orgFilter) return false;
      if (osFilter !== 'all' && row.operatingSystem !== osFilter) return false;
      if (countryFilter !== 'all' && row.country !== countryFilter) return false;
      if (portFilter !== 'all' && String(row.port) !== portFilter) return false;
      return true;
    });
  }, [tableData, severityFilter, orgFilter, osFilter, countryFilter, portFilter]);

  const columns = useMemo<ColumnDef<(typeof tableData)[number]>[]>(
    () => [
      { accessorKey: 'cveId', header: 'CVE', cell: ({ getValue }) => <span className="font-mono text-blue-400">{String(getValue())}</span> },
      { accessorKey: 'score', header: 'CVSS Score' },
      {
        accessorKey: 'severity',
        header: 'Severity',
        cell: ({ getValue }) => (
          <span className={`px-2 py-0.5 rounded-full text-xs ${getSeverityBadgeClass(String(getValue()))}`}>
            {String(getValue())}
          </span>
        ),
      },
      { accessorKey: 'ip', header: 'Affected IP', cell: ({ getValue }) => <span className="font-mono">{String(getValue())}</span> },
      { accessorKey: 'organization', header: 'Organization' },
      {
        accessorKey: 'publishedDate',
        header: 'Published Date',
        cell: ({ getValue }) => formatDate(String(getValue())),
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

  return (
    <Card>
      <CardHeader className="space-y-4">
        <CardTitle className="text-base">CVE Explorer</CardTitle>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-2">
          <Input
            placeholder="Search CVEs..."
            value={globalFilter}
            onChange={(e) => setGlobalFilter(e.target.value)}
          />
          <FilterSelect value={severityFilter} onChange={setSeverityFilter} placeholder="Severity" options={['Critical', 'High', 'Medium', 'Low', 'Informational']} />
          <FilterSelect value={orgFilter} onChange={setOrgFilter} placeholder="Organization" options={organizations} />
          <FilterSelect value={osFilter} onChange={setOsFilter} placeholder="Operating System" options={operatingSystems as string[]} />
          <FilterSelect value={countryFilter} onChange={setCountryFilter} placeholder="Country" options={countries} />
          <FilterSelect value={portFilter} onChange={setPortFilter} placeholder="Port" options={ports.map(String)} />
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
                <tr key={row.id} className="border-t border-border/60 hover:bg-accent/20">
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
  );
}

function FilterSelect({
  value,
  onChange,
  placeholder,
  options,
}: {
  value: string;
  onChange: (value: string) => void;
  placeholder: string;
  options: string[];
}) {
  return (
    <Select value={value} onValueChange={onChange}>
      <SelectTrigger>
        <SelectValue placeholder={placeholder} />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value="all">All {placeholder}s</SelectItem>
        {options.map((option) => (
          <SelectItem key={option} value={option}>
            {option}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}
