import React, { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { ArrowRight, RefreshCw } from 'lucide-react';
import { DashboardSummary, netshieldApi } from '../services/api.ts';

function formatBytes(bytes: number): string {
  if (bytes >= 1_000_000) return `${(bytes / 1_000_000).toFixed(2)} MB`;
  if (bytes >= 1_000) return `${(bytes / 1_000).toFixed(1)} KB`;
  return `${bytes} B`;
}

function formatTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

export function DashboardPage() {
  const navigate = useNavigate();
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [pollSeconds, setPollSeconds] = useState<number>(30);
  const [lastSynced, setLastSynced] = useState<string>('');
  const [refreshing, setRefreshing] = useState(false);

  const loadSummary = useCallback(async (isManual = false) => {
    if (isManual) setRefreshing(true);
    try {
      const data = await netshieldApi.getDashboardSummary();
      setSummary(data);
      setError(null);
      setLastSynced(new Date().toLocaleTimeString());
    } catch (err: any) {
      setError(err?.response?.data?.error || 'Unable to load dashboard summary.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    void loadSummary();
  }, [loadSummary]);

  useEffect(() => {
    if (pollSeconds <= 0) return;
    const timer = window.setInterval(() => {
      void loadSummary(false);
    }, pollSeconds * 1000);
    return () => window.clearInterval(timer);
  }, [pollSeconds, loadSummary]);

  if (loading && !summary) {
    return (
      <div className="space-y-6">
        <div className="h-8 w-64 bg-neutral-100" />
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 border border-neutral-200 divide-y sm:divide-y-0 sm:divide-x divide-neutral-200">
          {[1, 2, 3, 4].map((n) => (
            <div key={n} className="p-6 h-28 bg-neutral-50" />
          ))}
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <div className="lg:col-span-7 h-80 border border-neutral-200 bg-neutral-50" />
          <div className="lg:col-span-5 h-80 border border-neutral-200 bg-neutral-50" />
        </div>
      </div>
    );
  }

  if (error && !summary) {
    return (
      <div className="border border-neutral-900 p-6 bg-neutral-50">
        <p className="text-sm font-medium text-neutral-950 mb-3">{error}</p>
        <button
          type="button"
          onClick={() => void loadSummary(true)}
          className="px-4 py-2 text-xs font-medium bg-neutral-950 text-white hover:bg-neutral-800 cursor-pointer"
        >
          Retry
        </button>
      </div>
    );
  }

  const attackRate =
    summary && summary.totalEvents > 0
      ? ((summary.suspiciousCount / summary.totalEvents) * 100).toFixed(1)
      : '0.0';

  return (
    <div className="space-y-8">
      {/* Page Title & Polling Toolbar */}
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4 pb-6 border-b border-neutral-200">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-neutral-950">
            Security Overview
          </h1>
          <p className="text-sm text-neutral-600 mt-1">
            Model {summary?.activeModelVersion} · Detection-only inspection ·{' '}
            {lastSynced ? `Updated ${lastSynced}` : 'Synchronized'}
          </p>
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex items-center border border-neutral-300 bg-white">
            <span className="px-3 py-1.5 text-xs text-neutral-600 border-r border-neutral-200">
              Auto-Refresh
            </span>
            {[
              { label: 'Off', val: 0 },
              { label: '10s', val: 10 },
              { label: '30s', val: 30 },
              { label: '60s', val: 60 },
            ].map((opt) => (
              <button
                key={opt.val}
                type="button"
                onClick={() => setPollSeconds(opt.val)}
                className={`px-2.5 py-1.5 text-xs font-mono transition-colors cursor-pointer whitespace-nowrap ${
                  pollSeconds === opt.val
                    ? 'bg-neutral-950 text-white'
                    : 'text-neutral-700 hover:bg-neutral-100'
                }`}
              >
                {opt.label}
              </button>
            ))}
          </div>

          <button
            type="button"
            onClick={() => void loadSummary(true)}
            disabled={refreshing}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium border border-neutral-300 bg-white text-neutral-900 hover:bg-neutral-100 transition-colors cursor-pointer whitespace-nowrap"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* 4-Column KPI Strip (Single Elevation, Hairline Dividers) */}
      <section
        aria-label="Key security metrics"
        className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 border border-neutral-200 divide-y sm:divide-y-0 sm:divide-x divide-neutral-200 bg-white"
      >
        <div className="p-6">
          <p className="text-xs font-medium text-neutral-600">Total Network Events</p>
          <p className="text-3xl font-semibold font-mono tabular-nums text-neutral-950 mt-2">
            {summary?.totalEvents.toLocaleString() ?? 0}
          </p>
          <p className="text-xs text-neutral-500 mt-2 font-mono tabular-nums">
            {summary?.totalPackets.toLocaleString() ?? 0} pkts · {formatBytes(summary?.totalBytes ?? 0)}
          </p>
        </div>

        <div className="p-6">
          <p className="text-xs font-medium text-neutral-600">Normal Traffic</p>
          <p className="text-3xl font-semibold font-mono tabular-nums text-neutral-950 mt-2">
            {summary?.normalCount.toLocaleString() ?? 0}
          </p>
          <p className="text-xs text-neutral-500 mt-2 font-mono tabular-nums">
            {summary && summary.totalEvents > 0
              ? `${((summary.normalCount / summary.totalEvents) * 100).toFixed(1)}% benign share`
              : '0.0% benign share'}
          </p>
        </div>

        <div className="p-6">
          <p className="text-xs font-medium text-neutral-600">Suspicious Traffic</p>
          <p className="text-3xl font-semibold font-mono tabular-nums text-neutral-950 mt-2">
            {summary?.suspiciousCount.toLocaleString() ?? 0}
          </p>
          <p className="text-xs text-neutral-500 mt-2 font-mono tabular-nums">
            {attackRate}% flagged rate
          </p>
        </div>

        <div className="p-6 bg-neutral-950 text-white">
          <p className="text-xs font-medium text-neutral-400">Open Alerts</p>
          <p className="text-3xl font-semibold font-mono tabular-nums text-white mt-2">
            {summary?.openAlerts.toLocaleString() ?? 0}
          </p>
          <p className="text-xs text-neutral-400 mt-2 font-mono tabular-nums">
            {summary?.investigatingAlerts ?? 0} investigating · {summary?.resolvedAlerts ?? 0} resolved
          </p>
        </div>
      </section>

      {/* Primary Charts Grid */}
      <section className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Traffic Activity Over Time */}
        <div className="lg:col-span-7 border border-neutral-200 p-6 bg-white">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h2 className="text-base font-semibold text-neutral-950">Traffic Activity</h2>
              <p className="text-xs text-neutral-500 mt-0.5">
                Normal vs. Attack flow volume across analyzed time windows
              </p>
            </div>
            <div className="flex items-center gap-4 text-xs text-neutral-600">
              <span className="inline-flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 bg-neutral-950 inline-block" />
                Attack
              </span>
              <span className="inline-flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 bg-neutral-300 inline-block" />
                Normal
              </span>
            </div>
          </div>

          <div className="h-72 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart
                data={summary?.activitySeries ?? []}
                margin={{ top: 8, right: 12, left: -16, bottom: 0 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#e4e4e7" vertical={false} />
                <XAxis
                  dataKey="time"
                  tick={{ fontSize: 11, fill: '#52525b', fontFamily: 'IBM Plex Mono' }}
                  axisLine={{ stroke: '#d4d4d8' }}
                  tickLine={false}
                />
                <YAxis
                  allowDecimals={false}
                  tick={{ fontSize: 11, fill: '#52525b', fontFamily: 'IBM Plex Mono' }}
                  axisLine={false}
                  tickLine={false}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#ffffff',
                    border: '1px solid #09090b',
                    borderRadius: 0,
                    fontSize: 12,
                    fontFamily: 'IBM Plex Mono',
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="normal"
                  name="Normal"
                  stackId="1"
                  stroke="#71717a"
                  fill="#e4e4e7"
                  strokeWidth={1.5}
                />
                <Area
                  type="monotone"
                  dataKey="attack"
                  name="Attack"
                  stackId="1"
                  stroke="#09090b"
                  fill="#18181b"
                  strokeWidth={1.5}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Threat Distribution */}
        <div className="lg:col-span-5 border border-neutral-200 p-6 bg-white">
          <div className="mb-6">
            <h2 className="text-base font-semibold text-neutral-950">Threat Distribution</h2>
            <p className="text-xs text-neutral-500 mt-0.5">
              Classification breakdown across benign and attack families
            </p>
          </div>

          <div className="h-72 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={summary?.threatDistribution ?? []}
                layout="vertical"
                margin={{ top: 4, right: 16, left: 16, bottom: 0 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#e4e4e7" horizontal={false} />
                <XAxis
                  type="number"
                  allowDecimals={false}
                  tick={{ fontSize: 11, fill: '#52525b', fontFamily: 'IBM Plex Mono' }}
                  axisLine={{ stroke: '#d4d4d8' }}
                  tickLine={false}
                />
                <YAxis
                  type="category"
                  dataKey="name"
                  width={92}
                  tick={{ fontSize: 11, fill: '#18181b', fontFamily: 'DM Sans' }}
                  axisLine={false}
                  tickLine={false}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#ffffff',
                    border: '1px solid #09090b',
                    borderRadius: 0,
                    fontSize: 12,
                    fontFamily: 'IBM Plex Mono',
                  }}
                />
                <Bar dataKey="count" name="Flows" fill="#18181b" barSize={18} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </section>

      {/* Recent Security Events Table */}
      <section className="border border-neutral-200 bg-white">
        <div className="px-6 py-4 border-b border-neutral-200 flex items-center justify-between gap-4">
          <div>
            <h2 className="text-base font-semibold text-neutral-950">Recent Security Events</h2>
            <p className="text-xs text-neutral-500 mt-0.5">
              Latest classified network-flow records from the Random Forest pipeline
            </p>
          </div>
          <button
            type="button"
            onClick={() => navigate('/monitoring')}
            className="inline-flex items-center gap-1.5 text-xs font-medium text-neutral-900 hover:underline cursor-pointer whitespace-nowrap"
          >
            <span>View All Events</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-neutral-200 bg-neutral-50 text-xs font-medium text-neutral-600">
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4">Source</th>
                <th className="py-3 px-4">Destination</th>
                <th className="py-3 px-4">Protocol</th>
                <th className="py-3 px-4">Prediction</th>
                <th className="py-3 px-4">Class</th>
                <th className="py-3 px-4 text-right">Score</th>
                <th className="py-3 px-4">Severity</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-neutral-200 text-sm">
              {(summary?.recentEvents ?? []).map((evt) => (
                <tr
                  key={evt.id}
                  onClick={() => navigate(`/monitoring/${evt.id}`)}
                  className="hover:bg-neutral-50 cursor-pointer transition-colors"
                >
                  <td className="py-3 px-4 font-mono text-xs text-neutral-600 whitespace-nowrap tabular-nums">
                    {formatTime(evt.eventTime)}
                  </td>
                  <td className="py-3 px-4 font-mono text-xs text-neutral-900 whitespace-nowrap tabular-nums">
                    {evt.srcIp}:{evt.srcPort}
                  </td>
                  <td className="py-3 px-4 font-mono text-xs text-neutral-900 whitespace-nowrap tabular-nums">
                    {evt.dstIp}:{evt.dstPort}
                  </td>
                  <td className="py-3 px-4 font-mono text-xs text-neutral-700">{evt.protocol}</td>
                  <td className="py-3 px-4 text-xs font-semibold text-neutral-950">
                    {evt.prediction === 'Attack' ? 'Attack' : 'Normal'}
                  </td>
                  <td className="py-3 px-4 text-xs text-neutral-700">{evt.attackType}</td>
                  <td className="py-3 px-4 font-mono text-xs text-right tabular-nums text-neutral-900">
                    {(evt.score * 100).toFixed(1)}%
                  </td>
                  <td className="py-3 px-4 font-mono text-xs text-neutral-900">
                    {evt.severity === 'Critical' || evt.severity === 'High' ? (
                      <span className="font-semibold text-neutral-950 underline underline-offset-4">
                        {evt.severity}
                      </span>
                    ) : (
                      <span className="text-neutral-600">{evt.severity}</span>
                    )}
                  </td>
                </tr>
              ))}
              {summary?.recentEvents.length === 0 && (
                <tr>
                  <td colSpan={8} className="py-10 text-center text-sm text-neutral-500">
                    No network events recorded yet. Upload a CIC-IDS2017 CSV in Traffic Analysis to begin.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
