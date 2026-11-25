import React, { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search } from 'lucide-react';
import { netshieldApi } from '../services/api.ts';
import { useAuth } from '../context/AuthContext.tsx';
import { updateAlertStatusInFirestore } from '../lib/firebase.ts';
import type { StoredAlert } from '../server/store.ts';

function formatTime(iso: string): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function AlertManagementPage() {
  const { user, isFirebaseBacked } = useAuth();
  const navigate = useNavigate();

  const [alerts, setAlerts] = useState<StoredAlert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [updatingId, setUpdatingId] = useState<string | null>(null);

  const [statusFilter, setStatusFilter] = useState('All');
  const [severityFilter, setSeverityFilter] = useState('All');
  const [search, setSearch] = useState('');

  const canManage = user?.role === 'admin' || user?.role === 'analyst';

  const loadAlerts = useCallback(async () => {
    setLoading(true);
    try {
      const res = await netshieldApi.getAlerts({
        status: statusFilter !== 'All' ? statusFilter : undefined,
        severity: severityFilter !== 'All' ? severityFilter : undefined,
        search: search.trim() || undefined,
      });
      setAlerts(res.items);
      setError(null);
    } catch (err: any) {
      setError(err?.response?.data?.error || 'Failed to load alerts.');
    } finally {
      setLoading(false);
    }
  }, [statusFilter, severityFilter, search]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void loadAlerts();
    }, 150);
    return () => window.clearTimeout(timer);
  }, [loadAlerts]);

  const handleUpdateStatus = async (alertId: string, nextStatus: 'Open' | 'Investigating' | 'Resolved') => {
    setUpdatingId(alertId);
    setError(null);
    try {
      const res = await netshieldApi.updateAlertStatus(alertId, nextStatus);
      setAlerts((prev) => prev.map((a) => (a.id === alertId ? res.alert : a)));
      if (isFirebaseBacked) {
        await updateAlertStatusInFirestore(alertId, nextStatus, res.alert.resolvedAt);
      }
    } catch (err: any) {
      setError(err?.response?.data?.error || 'Failed to update alert status.');
    } finally {
      setUpdatingId(null);
    }
  };

  const openCount = alerts.filter((a) => a.status === 'Open').length;
  const investigatingCount = alerts.filter((a) => a.status === 'Investigating').length;
  const resolvedCount = alerts.filter((a) => a.status === 'Resolved').length;

  return (
    <div className="space-y-6">
      <div className="pb-6 border-b border-neutral-200 flex flex-col sm:flex-row sm:items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-neutral-950">
            Alert Management
          </h1>
          <p className="text-sm text-neutral-600 mt-1">
            Review security alerts triggered by the intrusion detection policy and update investigation status.
          </p>
        </div>
        <p className="text-xs font-mono text-neutral-600 tabular-nums">
          {openCount} Open · {investigatingCount} Investigating · {resolvedCount} Resolved
        </p>
      </div>

      {/* Filters */}
      <div className="grid grid-cols-1 md:grid-cols-12 gap-3">
        <div className="md:col-span-5 relative">
          <Search className="w-4 h-4 text-neutral-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search alerts by IP, attack type, or description..."
            className="w-full pl-9 pr-3 py-2 text-sm border border-neutral-300 bg-white text-neutral-950 focus:outline-none focus:border-neutral-950"
          />
        </div>

        <div className="md:col-span-4 flex border border-neutral-300 bg-white">
          {['All', 'Open', 'Investigating', 'Resolved'].map((st) => (
            <button
              key={st}
              type="button"
              onClick={() => setStatusFilter(st)}
              className={`flex-1 py-2 text-xs font-medium transition-colors cursor-pointer whitespace-nowrap ${
                statusFilter === st
                  ? 'bg-neutral-950 text-white'
                  : 'text-neutral-700 hover:bg-neutral-100'
              }`}
            >
              {st}
            </button>
          ))}
        </div>

        <div className="md:col-span-3">
          <select
            aria-label="Filter alerts by severity"
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="w-full px-3 py-2 text-sm border border-neutral-300 bg-white text-neutral-950 focus:outline-none focus:border-neutral-950"
          >
            <option value="All">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>
        </div>
      </div>

      {error && (
        <div className="border border-neutral-900 bg-neutral-100 px-4 py-3 text-sm text-neutral-950">
          {error}
        </div>
      )}

      {/* Alerts List Table */}
      <div className="border border-neutral-200 bg-white overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-neutral-200 bg-neutral-50 text-xs font-medium text-neutral-600">
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Alert Details</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Created</th>
                <th className="py-3 px-4">Resolved</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-neutral-200 text-sm">
              {loading && alerts.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-10 text-center text-sm text-neutral-500">
                    Loading alerts...
                  </td>
                </tr>
              ) : alerts.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-sm text-neutral-500">
                    No alerts match the current filter criteria.
                  </td>
                </tr>
              ) : (
                alerts.map((alert) => {
                  const lockedForNonAdmin = alert.status === 'Resolved' && user?.role !== 'admin';
                  return (
                    <tr key={alert.id} className="hover:bg-neutral-50 transition-colors">
                      <td className="py-3.5 px-4 font-mono text-xs whitespace-nowrap">
                        {alert.severity === 'Critical' || alert.severity === 'High' ? (
                          <span className="font-semibold text-neutral-950 underline underline-offset-4">
                            {alert.severity}
                          </span>
                        ) : (
                          <span className="text-neutral-700">{alert.severity}</span>
                        )}
                      </td>
                      <td className="py-3.5 px-4 max-w-md">
                        <p className="text-xs font-semibold text-neutral-950">{alert.attackType}</p>
                        <p className="text-xs text-neutral-600 mt-0.5 leading-relaxed">
                          {alert.description}
                        </p>
                        <button
                          type="button"
                          onClick={() => navigate(`/monitoring/${alert.eventId}`)}
                          className="text-[11px] font-mono text-neutral-700 underline underline-offset-2 mt-1 hover:text-neutral-950 cursor-pointer"
                        >
                          Inspect Event {alert.eventId}
                        </button>
                      </td>
                      <td className="py-3.5 px-4 font-mono text-xs font-medium text-neutral-900 whitespace-nowrap">
                        {alert.status}
                      </td>
                      <td className="py-3.5 px-4 font-mono text-xs text-neutral-600 whitespace-nowrap tabular-nums">
                        {formatTime(alert.createdAt)}
                      </td>
                      <td className="py-3.5 px-4 font-mono text-xs text-neutral-600 whitespace-nowrap tabular-nums">
                        {formatTime(alert.resolvedAt)}
                      </td>
                      <td className="py-3.5 px-4 text-right whitespace-nowrap">
                        {canManage ? (
                          <div className="inline-flex items-center border border-neutral-300 bg-white">
                            {(['Open', 'Investigating', 'Resolved'] as const).map((st) => (
                              <button
                                key={st}
                                type="button"
                                disabled={
                                  updatingId === alert.id ||
                                  alert.status === st ||
                                  (lockedForNonAdmin && st !== 'Resolved')
                                }
                                onClick={() => void handleUpdateStatus(alert.id, st)}
                                className={`px-2.5 py-1 text-[11px] font-medium transition-colors cursor-pointer ${
                                  alert.status === st
                                    ? 'bg-neutral-950 text-white'
                                    : 'text-neutral-700 hover:bg-neutral-100 disabled:opacity-35'
                                }`}
                              >
                                {st}
                              </button>
                            ))}
                          </div>
                        ) : (
                          <span className="text-xs text-neutral-500">Read-only</span>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
