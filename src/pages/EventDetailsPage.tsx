import React, { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';
import { netshieldApi } from '../services/api.ts';
import { useAuth } from '../context/AuthContext.tsx';
import { updateAlertStatusInFirestore } from '../lib/firebase.ts';
import { FEATURE_LABELS, FeatureName } from '../ml/schema.ts';
import type { StoredAlert, StoredNetworkEvent } from '../server/store.ts';

export function EventDetailsPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { user, isFirebaseBacked } = useAuth();

  const [event, setEvent] = useState<StoredNetworkEvent | null>(null);
  const [alert, setAlert] = useState<StoredAlert | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [updatingStatus, setUpdatingStatus] = useState(false);

  useEffect(() => {
    if (!id) return;
    setLoading(true);
    netshieldApi
      .getEventById(id)
      .then((res) => {
        setEvent(res.event);
        setAlert(res.alert);
        setError(null);
      })
      .catch((err: any) => {
        setError(err?.response?.data?.error || 'Unable to load network event details.');
      })
      .finally(() => setLoading(false));
  }, [id]);

  const handleStatusChange = async (nextStatus: 'Open' | 'Investigating' | 'Resolved') => {
    if (!alert) return;
    setUpdatingStatus(true);
    try {
      const res = await netshieldApi.updateAlertStatus(alert.id, nextStatus);
      setAlert(res.alert);
      if (isFirebaseBacked) {
        await updateAlertStatusInFirestore(alert.id, nextStatus, res.alert.resolvedAt);
      }
    } catch (err: any) {
      setError(err?.response?.data?.error || 'Failed to update alert status.');
    } finally {
      setUpdatingStatus(false);
    }
  };

  if (loading) {
    return <div className="py-12 text-sm text-neutral-500">Loading network event details...</div>;
  }

  if (error || !event) {
    return (
      <div className="space-y-4">
        <button
          type="button"
          onClick={() => navigate('/monitoring')}
          className="inline-flex items-center gap-1.5 text-xs font-medium text-neutral-700 hover:text-neutral-950 cursor-pointer"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>Back to Threat Monitoring</span>
        </button>
        <div className="border border-neutral-900 p-6 bg-neutral-50 text-sm text-neutral-950">
          {error || 'Event not found.'}
        </div>
      </div>
    );
  }

  const canManageAlert = user?.role === 'admin' || user?.role === 'analyst';

  return (
    <div className="space-y-8">
      <div className="pb-6 border-b border-neutral-200">
        <button
          type="button"
          onClick={() => navigate('/monitoring')}
          className="inline-flex items-center gap-1.5 text-xs font-medium text-neutral-600 hover:text-neutral-950 mb-4 cursor-pointer"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>Back to Threat Monitoring</span>
        </button>
        <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight text-neutral-950 font-mono">
              {event.srcIp}:{event.srcPort} → {event.dstIp}:{event.dstPort}
            </h1>
            <p className="text-xs text-neutral-600 mt-1.5 font-mono">
              Event {event.id} · {event.protocol} · Model {event.modelVersion} · {event.sourceBatch}
            </p>
          </div>
          <div className="text-left sm:text-right">
            <p className="text-xs text-neutral-500">Classification Outcome</p>
            <p className="text-lg font-semibold text-neutral-950 mt-0.5">
              {event.prediction} · {event.attackType} ({(event.score * 100).toFixed(1)}%)
            </p>
          </div>
        </div>
      </div>

      {/* Linked Security Alert Banner (if suspicious) */}
      {alert && (
        <section className="border border-neutral-950 bg-neutral-950 text-white p-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <p className="text-xs font-mono text-neutral-400">
              Linked Alert {alert.id} · Severity {alert.severity} · Status {alert.status}
            </p>
            <p className="text-sm text-white mt-1.5">{alert.description}</p>
          </div>

          {canManageAlert && (
            <div className="flex items-center gap-2 shrink-0">
              {(['Open', 'Investigating', 'Resolved'] as const).map((st) => {
                const locked = alert.status === 'Resolved' && user?.role !== 'admin' && st !== 'Resolved';
                return (
                  <button
                    key={st}
                    type="button"
                    disabled={updatingStatus || alert.status === st || locked}
                    onClick={() => void handleStatusChange(st)}
                    className={`px-3 py-1.5 text-xs font-medium border transition-colors cursor-pointer whitespace-nowrap ${
                      alert.status === st
                        ? 'bg-white text-neutral-950 border-white'
                        : 'border-neutral-700 text-neutral-300 hover:border-white hover:text-white disabled:opacity-40'
                    }`}
                  >
                    {st}
                  </button>
                );
              })}
            </div>
          )}
        </section>
      )}

      {/* Summary & Ensemble Votes */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <section className="lg:col-span-5 border border-neutral-200 p-6 bg-white space-y-5">
          <div>
            <h2 className="text-base font-semibold text-neutral-950">Random Forest Decision Votes</h2>
            <p className="text-xs text-neutral-500 mt-0.5">
              Per-tree vote tally from the active binary classifier ensemble
            </p>
          </div>

          <div className="space-y-3">
            {Object.entries(event.treeVotes).map(([label, votes]) => {
              const totalTrees = Object.values(event.treeVotes).reduce((a, b) => a + b, 0) || 1;
              const pct = ((votes / totalTrees) * 100).toFixed(1);
              return (
                <div key={label}>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="font-medium text-neutral-900">{label}</span>
                    <span className="font-mono tabular-nums text-neutral-600">
                      {votes} / {totalTrees} trees ({pct}%)
                    </span>
                  </div>
                  <div className="h-2 bg-neutral-100 w-full">
                    <div
                      className={label === 'Attack' ? 'h-full bg-neutral-950' : 'h-full bg-neutral-400'}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>

          <div className="pt-4 border-t border-neutral-200">
            <h3 className="text-xs font-semibold text-neutral-900 mb-3">
              Top Model Feature Drivers
            </h3>
            <div className="divide-y divide-neutral-200">
              {event.topContributors.map((c) => (
                <div key={c.feature} className="py-2 flex items-center justify-between text-xs">
                  <span className="text-neutral-700">{c.label}</span>
                  <span className="font-mono tabular-nums text-neutral-950">
                    {c.value.toLocaleString()} · {(c.importance * 100).toFixed(1)}% weight
                  </span>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Full CIC-IDS2017 Feature Vector */}
        <section className="lg:col-span-7 border border-neutral-200 bg-white">
          <div className="px-6 py-4 border-b border-neutral-200">
            <h2 className="text-base font-semibold text-neutral-950">
              CIC-IDS2017 Extracted Flow Features
            </h2>
            <p className="text-xs text-neutral-500 mt-0.5">
              Exact preprocessed feature vector passed into the inference pipeline
            </p>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 divide-y sm:divide-y-0 border-neutral-200">
            {(Object.keys(event.featureMap) as FeatureName[]).map((key) => (
              <div
                key={key}
                className="px-6 py-3 border-b border-neutral-200 flex items-center justify-between gap-4"
              >
                <span className="text-xs text-neutral-600">{FEATURE_LABELS[key] || key}</span>
                <span className="text-xs font-mono font-medium text-neutral-950 tabular-nums">
                  {event.featureMap[key].toLocaleString()}
                </span>
              </div>
            ))}
          </div>
        </section>
      </div>
    </div>
  );
}
