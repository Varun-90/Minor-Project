import React, { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ChevronLeft, ChevronRight, Search } from 'lucide-react';
import { netshieldApi, PaginatedEvents } from '../services/api.ts';

function formatTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

export function ThreatMonitoringPage() {
  const navigate = useNavigate();
  const [data, setData] = useState<PaginatedEvents | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [search, setSearch] = useState('');
  const [prediction, setPrediction] = useState('All');
  const [protocol, setProtocol] = useState('All');
  const [severity, setSeverity] = useState('All');
  const [page, setPage] = useState(1);

  const loadEvents = useCallback(async () => {
    setLoading(true);
    try {
      const res = await netshieldApi.getEvents({
        page,
        limit: 15,
        search: search.trim() || undefined,
        prediction: prediction !== 'All' ? prediction : undefined,
        protocol: protocol !== 'All' ? protocol : undefined,
        severity: severity !== 'All' ? severity : undefined,
      });
      setData(res);
      setError(null);
    } catch (err: any) {
      setError(err?.response?.data?.error || 'Failed to load network events.');
    } finally {
      setLoading(false);
    }
  }, [page, search, prediction, protocol, severity]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void loadEvents();
    }, 150);
    return () => window.clearTimeout(timer);
  }, [loadEvents]);

  return (
    <div className="space-y-6">
      <div className="pb-6 border-b border-neutral-200 flex flex-col sm:flex-row sm:items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-neutral-950">
            Threat Monitoring
          </h1>
          <p className="text-sm text-neutral-600 mt-1">
            Inspect historical network-flow events, predictions, and severity classifications.
          </p>
        </div>
        <p className="text-xs font-mono text-neutral-600 tabular-nums">
          {data ? `${data.total.toLocaleString()} matching records` : 'Loading records...'}
        </p>
      </div>

      {/* Filter Bar */}
      <div className="grid grid-cols-1 md:grid-cols-12 gap-3">
        <div className="md:col-span-5 relative">
          <Search className="w-4 h-4 text-neutral-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
          <input
            type="text"
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(1);
            }}
            placeholder="Search by source IP, destination IP, port, or attack class..."
            className="w-full pl-9 pr-3 py-2 text-sm border border-neutral-300 bg-white text-neutral-950 focus:outline-none focus:border-neutral-950"
          />
        </div>

        <div className="md:col-span-3 flex border border-neutral-300 bg-white">
          {['All', 'Attack', 'Normal'].map((opt) => (
            <button
              key={opt}
              type="button"
              onClick={() => {
                setPrediction(opt);
                setPage(1);
              }}
              className={`flex-1 py-2 text-xs font-medium transition-colors cursor-pointer whitespace-nowrap ${
                prediction === opt
                  ? 'bg-neutral-950 text-white'
                  : 'text-neutral-700 hover:bg-neutral-100'
              }`}
            >
              {opt}
            </button>
          ))}
        </div>

        <div className="md:col-span-2">
          <select
            aria-label="Filter by protocol"
            value={protocol}
            onChange={(e) => {
              setProtocol(e.target.value);
              setPage(1);
            }}
            className="w-full px-3 py-2 text-sm border border-neutral-300 bg-white text-neutral-950 focus:outline-none focus:border-neutral-950"
          >
            <option value="All">All Protocols</option>
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
            <option value="ICMP">ICMP</option>
            <option value="OTHER">OTHER</option>
          </select>
        </div>

        <div className="md:col-span-2">
          <select
            aria-label="Filter by severity"
            value={severity}
            onChange={(e) => {
              setSeverity(e.target.value);
              setPage(1);
            }}
            className="w-full px-3 py-2 text-sm border border-neutral-300 bg-white text-neutral-950 focus:outline-none focus:border-neutral-950"
          >
            <option value="All">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
            <option value="None">None</option>
          </select>
        </div>
      </div>

      {error && (
        <div className="border border-neutral-900 bg-neutral-100 px-4 py-3 text-sm text-neutral-950">
          {error}
        </div>
      )}

      {/* High-Density Events Table */}
      <div className="border border-neutral-200 bg-white overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-neutral-200 bg-neutral-50 text-xs font-medium text-neutral-600">
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4">Source IP</th>
                <th className="py-3 px-4">Destination IP</th>
                <th className="py-3 px-4">Protocol</th>
                <th className="py-3 px-4">Prediction</th>
                <th className="py-3 px-4">Attack Type</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4 text-right">Score</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-neutral-200 text-sm">
              {loading && !data ? (
                [1, 2, 3, 4, 5].map((n) => (
                  <tr key={n}>
                    <td colSpan={8} className="py-3.5 px-4 bg-neutral-50/50 text-xs text-neutral-400">
                      Loading...
                    </td>
                  </tr>
                ))
              ) : (data?.items ?? []).length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-sm text-neutral-500">
                    No network events match the current filters.
                  </td>
                </tr>
              ) : (
                data!.items.map((evt) => (
                  <tr
                    key={evt.id}
                    onClick={() => navigate(`/monitoring/${evt.id}`)}
                    className="hover:bg-neutral-50 cursor-pointer transition-colors"
                  >
                    <td className="py-3 px-4 font-mono text-xs text-neutral-600 whitespace-nowrap tabular-nums">
                      {formatTime(evt.eventTime)}
                    </td>
                    <td className="py-3 px-4 font-mono text-xs text-neutral-950 whitespace-nowrap tabular-nums">
                      {evt.srcIp}:{evt.srcPort}
                    </td>
                    <td className="py-3 px-4 font-mono text-xs text-neutral-950 whitespace-nowrap tabular-nums">
                      {evt.dstIp}:{evt.dstPort}
                    </td>
                    <td className="py-3 px-4 font-mono text-xs text-neutral-700">{evt.protocol}</td>
                    <td className="py-3 px-4 text-xs font-semibold text-neutral-950">
                      {evt.prediction}
                    </td>
                    <td className="py-3 px-4 text-xs text-neutral-700">{evt.attackType}</td>
                    <td className="py-3 px-4 font-mono text-xs">
                      {evt.severity === 'Critical' || evt.severity === 'High' ? (
                        <span className="font-semibold text-neutral-950 underline underline-offset-4">
                          {evt.severity}
                        </span>
                      ) : (
                        <span className="text-neutral-600">{evt.severity}</span>
                      )}
                    </td>
                    <td className="py-3 px-4 font-mono text-xs text-right tabular-nums text-neutral-900">
                      {(evt.score * 100).toFixed(1)}%
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Controls */}
        {data && data.totalPages > 1 && (
          <div className="px-4 py-3 border-t border-neutral-200 bg-neutral-50 flex items-center justify-between text-xs text-neutral-600">
            <span className="font-mono tabular-nums">
              Page {data.page} of {data.totalPages} ({data.total} total)
            </span>
            <div className="flex items-center gap-2">
              <button
                type="button"
                disabled={page <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                className="inline-flex items-center gap-1 px-3 py-1.5 border border-neutral-300 bg-white text-neutral-900 hover:bg-neutral-100 disabled:opacity-40 cursor-pointer"
              >
                <ChevronLeft className="w-3.5 h-3.5" />
                <span>Previous</span>
              </button>
              <button
                type="button"
                disabled={page >= data.totalPages}
                onClick={() => setPage((p) => Math.min(data.totalPages, p + 1))}
                className="inline-flex items-center gap-1 px-3 py-1.5 border border-neutral-300 bg-white text-neutral-900 hover:bg-neutral-100 disabled:opacity-40 cursor-pointer"
              >
                <span>Next</span>
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
